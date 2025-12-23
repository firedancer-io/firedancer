#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../vinyl/bstream/fd_vinyl_bstream.h"

#include "utils/fd_ssctrl.h"

#define NAME "snaplv"

#define IN_KIND_SNAPIN (0)
#define IN_KIND_SNAPLH (1)
#define MAX_IN_LINKS   (1 + FD_SNAPSHOT_MAX_SNAPLH_TILES)

/* TODO make this more robust */
#define OUT_LINK_LH (0)
#define OUT_LINK_CT (1)

#define VINYL_LTHASH_PENDING_MAX  (8UL)

struct out_link {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
};
typedef struct out_link out_link_t;

struct fd_snaplv_tile {
  int                 state;
  int                 full;

  ulong               num_hash_tiles;

  uchar               in_kind[ MAX_IN_LINKS ];
  ulong               adder_in_offset;

  out_link_t          out_link[ 2 ];

  struct {
    ulong const *     bstream_seq;
    ulong             bstream_seq_last;
    struct {
      int                     active[VINYL_LTHASH_PENDING_MAX];
      ulong                   seq   [VINYL_LTHASH_PENDING_MAX];
      fd_vinyl_bstream_phdr_t phdr  [VINYL_LTHASH_PENDING_MAX];
    } pending;
    ulong             pending_cnt;
  } vinyl;

  struct {
    fd_lthash_value_t expected_lthash;
    fd_lthash_value_t calculated_lthash;
    ulong             received_lthashes;
    ulong             ack_sig;
    int               awaiting_results;
    int               hash_check_done;
  } hash_accum;

  fd_lthash_value_t        running_lthash;

  struct {
    struct {
      ulong           accounts_hashed;
    } full;

    struct {
      ulong           accounts_hashed;
    } incremental;
  } metrics;

  struct {
    fd_wksp_t *       wksp;
    ulong             chunk0;
    ulong             wmark;
    ulong             mtu;
    ulong             pos;
  } in;

  struct {
    fd_wksp_t *       wksp;
    ulong             chunk0;
    ulong             wmark;
    ulong             mtu;
  } adder_in[ FD_SNAPSHOT_MAX_SNAPLH_TILES ];

  int                 incr_first;

  struct {
    struct {
      long  t_rd;
      long  t_ph;
      long  t_lt;
      long  cnt;
    } full;
    struct {
      long  t_rd;
      long  t_ph;
      long  t_lt;
      long  cnt;
    } incr;
  } stats;
};

typedef struct fd_snaplv_tile fd_snaplv_t;

static inline int
should_shutdown( fd_snaplv_t * ctx ) {
  return ctx->state==FD_SNAPSHOT_STATE_SHUTDOWN;
}

static ulong
scratch_align( void ) {
  return alignof(fd_snaplv_t);
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snaplv_t),     sizeof(fd_snaplv_t)       );
  return FD_LAYOUT_FINI( l, alignof(fd_snaplv_t) );
}

static void
metrics_write( fd_snaplv_t * ctx ) {
  (void)ctx;
  FD_MGAUGE_SET( SNAPLV, FULL_ACCOUNTS_HASHED,        ctx->metrics.full.accounts_hashed );
  FD_MGAUGE_SET( SNAPLV, INCREMENTAL_ACCOUNTS_HASHED, ctx->metrics.incremental.accounts_hashed );
  FD_MGAUGE_SET( SNAPLV, STATE,                       (ulong)(ctx->state) );
}

static void
transition_malformed( fd_snaplv_t *  ctx,
                      fd_stem_context_t * stem ) {
  ctx->state = FD_SNAPSHOT_STATE_ERROR;
  fd_stem_publish( stem, OUT_LINK_LH, FD_SNAPSHOT_MSG_CTRL_ERROR, 0UL, 0UL, 0UL, 0UL, 0UL );
  fd_stem_publish( stem, OUT_LINK_CT, FD_SNAPSHOT_MSG_CTRL_ERROR, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static void
handle_vinyl_lthash_request( fd_snaplv_t *             ctx,
                             fd_stem_context_t *       stem,
                             ulong                     seq,
                             fd_vinyl_bstream_phdr_t * acc_hdr ) {

  /* TODO schedule for after_credit? */
  /* TODO update link burst and stem burst! */
  out_link_t * o_link = &ctx->out_link[ OUT_LINK_LH ];
  uchar * data = fd_chunk_to_laddr( o_link->mem, o_link->chunk );
  memcpy( data, &seq, sizeof(ulong) );
  memcpy( data + sizeof(ulong), acc_hdr, sizeof(fd_vinyl_bstream_phdr_t) );
  ulong data_sz = sizeof(ulong)+sizeof(fd_vinyl_bstream_phdr_t);
  fd_stem_publish( stem, OUT_LINK_LH, FD_SNAPSHOT_HASH_MSG_SUB_VINYL_HDR, o_link->chunk, data_sz, 0UL, 0UL, 0UL );
  o_link->chunk = fd_dcache_compact_next( o_link->chunk, data_sz, o_link->chunk0, o_link->wmark );

  if( !!ctx->full ) ctx->stats.full.cnt++;
  else              ctx->stats.incr.cnt++;
}

static inline void
handle_vinyl_lthash_seq_sync( fd_snaplv_t * ctx ) {
  ctx->vinyl.bstream_seq_last = fd_mcache_seq_query( ctx->vinyl.bstream_seq );
}

static inline int
handle_vinyl_lthash_seq_check_fast( fd_snaplv_t * ctx,
                                    ulong              seq ) {
  return seq < ctx->vinyl.bstream_seq_last;
}

static inline int
handle_vinyl_lthash_seq_check_until_match( fd_snaplv_t * ctx,
                                           ulong         seq,
                                           int           do_sleep ) {
  ulong i = 0UL;
  for( ; i<ULONG_MAX; i++ ) {
    if( handle_vinyl_lthash_seq_check_fast( ctx, seq ) ) break;
    handle_vinyl_lthash_seq_sync( ctx );
    FD_SPIN_PAUSE();
    if( do_sleep ) fd_log_sleep( (long)1e3 ); /* 1 microsecond */
  }
  if( i==ULONG_MAX ) return 0;

  /* TODO consider minimum FD_VINYL_BSTREAM_BLOCK_SZ ? */
  return seq < ctx->vinyl.bstream_seq_last;
}

static inline void
handle_vinyl_lthash_request_drain_all( fd_snaplv_t *       ctx,
                                       fd_stem_context_t * stem ) {
  for( ulong i=0; i<VINYL_LTHASH_PENDING_MAX; i++ ) {
    if( !ctx->vinyl.pending.active[ i ] ) continue;
    FD_TEST( handle_vinyl_lthash_seq_check_until_match( ctx, ctx->vinyl.pending.seq[ i ], 1/*do_sleep*/ ) );
    handle_vinyl_lthash_request( ctx, stem, ctx->vinyl.pending.seq[ i ], &ctx->vinyl.pending.phdr[ i ] );
    ctx->vinyl.pending.active[ i ] = 0;
    ctx->vinyl.pending_cnt--;
  }
  FD_TEST( !ctx->vinyl.pending_cnt );
}

static void
handle_data_frag( fd_snaplv_t *       ctx,
                  fd_stem_context_t * stem,
                  ulong               sig,
                  ulong               chunk,
                  ulong               sz ) {
  (void)chunk; (void)sz;
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING );

  if( sig!=FD_SNAPSHOT_HASH_MSG_SUB_VINYL_HDR ) {
    FD_LOG_ERR(( "unexpected sig %lu in handle_data_frag", sig ));
    return;
  }

  ulong bstream_seq = fd_mcache_seq_query( ctx->vinyl.bstream_seq );
  if( ctx->vinyl.bstream_seq_last != bstream_seq ) {
    ctx->vinyl.bstream_seq_last = fd_mcache_seq_query( ctx->vinyl.bstream_seq );
  }

  /* TODO this is a prototype - it should be moved to snaplh */
  uchar const * indata = fd_chunk_to_laddr_const( ctx->in.wksp, chunk );

  #if 0
  /* simple version without bstream_seq - keep as reference */
  ulong seq;
  fd_vinyl_bstream_phdr_t phdr;
  memcpy( &seq,  indata, sizeof(ulong) );
  memcpy( &phdr, indata + sizeof(ulong), sizeof(fd_vinyl_bstream_phdr_t) );
  handle_vinyl_lthash_request( ctx, seq, &phdr );
  #else
  /* Find an empty slot in the pending list. */
  ulong seq_min_i = ULONG_MAX;
  ulong seq_min   = ULONG_MAX;
  ulong free_i    = ULONG_MAX;
  if( FD_UNLIKELY( ctx->vinyl.pending_cnt==VINYL_LTHASH_PENDING_MAX ) ) {
    /* an entry must be consumed to free a slot */
    for( ulong i=0; i<VINYL_LTHASH_PENDING_MAX; i++ ) {
      ulong seq = ctx->vinyl.pending.seq[ i ];
      seq_min_i = fd_ulong_if( seq_min > seq, i, seq_min_i );
      seq_min   = fd_ulong_min( seq_min, seq );
    }
    FD_TEST( handle_vinyl_lthash_seq_check_until_match( ctx, ctx->vinyl.pending.seq[ seq_min_i ], 1/*do_sleep*/ ) );
    handle_vinyl_lthash_request( ctx, stem, ctx->vinyl.pending.seq[ seq_min_i ], &ctx->vinyl.pending.phdr[ seq_min_i ] );
    ctx->vinyl.pending.active[ seq_min_i ] = 0;
    ctx->vinyl.pending_cnt--;
    free_i = seq_min_i;
  } else {
    /* Pick a free slot. */
    free_i = 0UL;
    for( ; free_i<VINYL_LTHASH_PENDING_MAX; free_i++ ) {
      if( !ctx->vinyl.pending.active[ free_i ] ) break;
    }
  }

  /* Populate the free slot. */
  memcpy( &ctx->vinyl.pending.seq[ free_i ],  indata, sizeof(ulong) );
  memcpy( &ctx->vinyl.pending.phdr[ free_i ], indata + sizeof(ulong), sizeof(fd_vinyl_bstream_phdr_t) );
  ctx->vinyl.pending.active[ free_i ] = 1;
  ctx->vinyl.pending_cnt++;

  /* Sync with the bstream seq. */
  handle_vinyl_lthash_seq_sync( ctx );

  /* Try to consume as many requests as possible. */
  for( ulong i=0; i<VINYL_LTHASH_PENDING_MAX; i++ ) {
    if( !ctx->vinyl.pending.active[ i ] ) continue;
    if( handle_vinyl_lthash_seq_check_fast( ctx, ctx->vinyl.pending.seq[ i ] ) ) {
      handle_vinyl_lthash_request( ctx, stem, ctx->vinyl.pending.seq[ i ], &ctx->vinyl.pending.phdr[ i ] );
      ctx->vinyl.pending.active[ i ] = 0;
      ctx->vinyl.pending_cnt--;
    }
  }
  FD_TEST( ctx->vinyl.pending_cnt<=VINYL_LTHASH_PENDING_MAX );
  #endif
}

static void
handle_control_frag( fd_snaplv_t *       ctx,
                     fd_stem_context_t * stem,
                     ulong               sig,
                     ulong               in_idx,
                     ulong               tsorig,
                     ulong               tspub ) {
  (void)in_idx;

  int forward_to_ct = 1UL;

  switch( sig ) {
    case FD_SNAPSHOT_MSG_CTRL_INIT_FULL:
    case FD_SNAPSHOT_MSG_CTRL_INIT_INCR: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      ctx->full  = sig==FD_SNAPSHOT_MSG_CTRL_INIT_FULL;
      ctx->state = FD_SNAPSHOT_STATE_PROCESSING;
      fd_lthash_zero( &ctx->running_lthash );
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_FAIL: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING ||
               ctx->state==FD_SNAPSHOT_STATE_FINISHING ||
               ctx->state==FD_SNAPSHOT_STATE_ERROR );
      ctx->state = FD_SNAPSHOT_STATE_IDLE;
      fd_lthash_zero( &ctx->running_lthash );
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_NEXT:
    case FD_SNAPSHOT_MSG_CTRL_DONE: {
      if( FD_UNLIKELY( ctx->state!=FD_SNAPSHOT_STATE_PROCESSING ) ) {
        transition_malformed( ctx, stem );
        break;
      }
      ctx->hash_accum.ack_sig          = sig;
      ctx->hash_accum.awaiting_results = 1;
      ctx->state = FD_SNAPSHOT_STATE_IDLE;
      forward_to_ct = 0UL;
      handle_vinyl_lthash_request_drain_all( ctx, stem );
      break; /* the ack is sent when all hashes are received */
    }

    case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      ctx->state = FD_SNAPSHOT_STATE_SHUTDOWN;
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_ERROR:
      ctx->state = FD_SNAPSHOT_STATE_ERROR;
      break;

    default:
      FD_LOG_ERR(( "unexpected control sig %lu", sig ));
      break;
  }

  /* Forward the control message down the pipeline */
  fd_stem_publish( stem, OUT_LINK_LH, sig, 0UL, 0UL, 0UL, tsorig, tspub );
  if( !forward_to_ct ) return;
  fd_stem_publish( stem, OUT_LINK_CT, sig, 0UL, 0UL, 0UL, tsorig, tspub );
}

static void
handle_hash_frag( fd_snaplv_t * ctx,
                  ulong              in_idx,
                  ulong              sig,
                  ulong              chunk,
                  ulong              sz ) {
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING || ctx->state==FD_SNAPSHOT_STATE_IDLE );
  switch( sig ) {
    case FD_SNAPSHOT_HASH_MSG_RESULT_ADD: {
      FD_TEST( sz==sizeof(fd_lthash_value_t) );
      fd_lthash_value_t const * result = fd_chunk_to_laddr_const( ctx->adder_in[ in_idx-ctx->adder_in_offset ].wksp, chunk );
      fd_lthash_add( &ctx->hash_accum.calculated_lthash, result );
      ctx->hash_accum.received_lthashes++;
      break;
    }
    case FD_SNAPSHOT_HASH_MSG_EXPECTED: {
      FD_TEST( sz==sizeof(fd_lthash_value_t) );
      FD_TEST( ctx->in_kind[ in_idx ]==IN_KIND_SNAPIN );
      fd_lthash_value_t const * result = fd_chunk_to_laddr_const( ctx->in.wksp, chunk );
      /* When the incremental snapshot is processed first, only update
         the expected lthash when the incremental part is received (the
         full version is superseded).  If the snapshots are processed
         in the traditional order (i.e. first full, then incremental),
         then always update the expected value. */
      if( !( ctx->incr_first && ctx->full ) ) fd_memcpy( &ctx->hash_accum.expected_lthash, result, sizeof(fd_lthash_value_t) );
      break;
    }
    default:
      FD_LOG_ERR(( "unexpected hash sig %lu", sig ));
      break;
  }

}

static inline int
returnable_frag( fd_snaplv_t *  ctx,
                 ulong               in_idx FD_PARAM_UNUSED,
                 ulong               seq    FD_PARAM_UNUSED,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl    FD_PARAM_UNUSED,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  FD_TEST( ctx->state!=FD_SNAPSHOT_STATE_SHUTDOWN );

  if( FD_LIKELY( sig==FD_SNAPSHOT_HASH_MSG_SUB_VINYL_HDR ) )   handle_data_frag( ctx, stem, sig, chunk, sz );
  else if( FD_LIKELY( sig==FD_SNAPSHOT_HASH_MSG_RESULT_ADD ||
                      sig==FD_SNAPSHOT_HASH_MSG_EXPECTED ) )   handle_hash_frag( ctx, in_idx, sig, chunk, sz );
  else                                                         handle_control_frag( ctx, stem, sig, in_idx, tsorig, tspub );

  return 0;
}

static void
after_credit( fd_snaplv_t *  ctx,
              fd_stem_context_t *  stem,
              int *                opt_poll_in FD_PARAM_UNUSED,
              int *                charge_busy FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( ctx->hash_accum.received_lthashes==ctx->num_hash_tiles && ctx->hash_accum.awaiting_results ) ) {
    fd_lthash_sub( &ctx->hash_accum.calculated_lthash, &ctx->running_lthash );

    /* The lthash of the incremental snapshot is computed on top of
       the corresponding one of the full counterpart.  Therefore, when
       the incremental is processed first, its lthash can only be
       validated after loading the full snapshot, and the check for
       lthash of the full snapshot in isolation becomes superseded. */
    int test = ( ctx->incr_first && !ctx->full ) ? 0 : memcmp( &ctx->hash_accum.expected_lthash, &ctx->hash_accum.calculated_lthash, sizeof(fd_lthash_value_t) );
    if( FD_UNLIKELY( test ) ) {
      FD_LOG_WARNING(( "calculated accounts lthash %s does not match accounts lthash %s in snapshot manifest",
                        FD_LTHASH_ENC_32_ALLOCA( &ctx->hash_accum.calculated_lthash ),
                        FD_LTHASH_ENC_32_ALLOCA( &ctx->hash_accum.expected_lthash ) ));
      transition_malformed( ctx, stem );
    } else {
      if( ctx->incr_first && !ctx->full ) {
        FD_LOG_NOTICE(( "skipping incremental lthash verfication until full snapshot is processed" ));
      } else {
        FD_LOG_NOTICE(( "calculated accounts lthash %s matches accounts lthash %s in snapshot manifest",
                        FD_LTHASH_ENC_32_ALLOCA( &ctx->hash_accum.calculated_lthash ),
                        FD_LTHASH_ENC_32_ALLOCA( &ctx->hash_accum.expected_lthash ) ));
        }
    }
    ctx->hash_accum.received_lthashes = 0UL;
    ctx->hash_accum.hash_check_done = 1;

    /* TODO this is only used for performance profiling. */
    FD_LOG_NOTICE(( "*** ctx->stats.full.t_rd %12ld", ctx->stats.full.t_rd ));
    FD_LOG_NOTICE(( "*** ctx->stats.full.t_ph %12ld", ctx->stats.full.t_ph ));
    FD_LOG_NOTICE(( "*** ctx->stats.full.t_lt %12ld", ctx->stats.full.t_lt ));
    FD_LOG_NOTICE(( "*** ctx->stats.full.cnt  %12ld", ctx->stats.full.cnt  ));
    FD_LOG_NOTICE(( "*** ctx->stats.incr.t_rd %12ld", ctx->stats.incr.t_rd ));
    FD_LOG_NOTICE(( "*** ctx->stats.incr.t_ph %12ld", ctx->stats.incr.t_ph ));
    FD_LOG_NOTICE(( "*** ctx->stats.incr.t_lt %12ld", ctx->stats.incr.t_lt ));
    FD_LOG_NOTICE(( "*** ctx->stats.incr.cnt  %12ld", ctx->stats.incr.cnt  ));
  }

  if( FD_UNLIKELY( ctx->hash_accum.awaiting_results && ctx->hash_accum.hash_check_done ) ) {
    fd_stem_publish( stem, OUT_LINK_CT, ctx->hash_accum.ack_sig, 0UL, 0UL, 0UL, 0UL, 0UL );
    ctx->hash_accum.awaiting_results = 0;
    ctx->hash_accum.hash_check_done  = 0;
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snaplv_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaplv_t), sizeof(fd_snaplv_t)         );

  ulong expected_in_cnt = 1UL + fd_topo_tile_name_cnt( topo, "snaplh" );
  if( FD_UNLIKELY( tile->in_cnt!=expected_in_cnt ) )  FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected %lu",  tile->in_cnt, expected_in_cnt ));
  if( FD_UNLIKELY( tile->out_cnt!=3UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 3", tile->out_cnt ));

  ulong adder_idx = 0UL;
  for( ulong i=0UL; i<(tile->in_cnt); i++ ) {
    fd_topo_link_t * in_link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * in_wksp = &topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ];

    if( FD_LIKELY( 0==strcmp( in_link->name, "snapin_lv" ) ) ) {
      ctx->in.wksp                   = in_wksp->wksp;
      ctx->in.chunk0                 = fd_dcache_compact_chunk0( ctx->in.wksp, in_link->dcache );
      ctx->in.wmark                  = fd_dcache_compact_wmark( ctx->in.wksp, in_link->dcache, in_link->mtu );
      ctx->in.mtu                    = in_link->mtu;
      ctx->in.pos                    = 0UL;
      ctx->in_kind[ i ]              = IN_KIND_SNAPIN;

    } else if( FD_LIKELY( 0==strcmp( in_link->name, "snaplh_lv" ) ) ) {
      ctx->adder_in[ adder_idx ].wksp    = in_wksp->wksp;
      ctx->adder_in[ adder_idx ].chunk0  = fd_dcache_compact_chunk0( ctx->adder_in[ adder_idx ].wksp, in_link->dcache );
      ctx->adder_in[ adder_idx ].wmark   = fd_dcache_compact_wmark ( ctx->adder_in[ adder_idx ].wksp, in_link->dcache, in_link->mtu );
      ctx->adder_in[ adder_idx ].mtu     = in_link->mtu;
      ctx->in_kind[ i ]                  = IN_KIND_SNAPLH;
      if( FD_LIKELY( adder_idx==0UL ) ) ctx->adder_in_offset = i;
      adder_idx++;

    } else {
      FD_LOG_ERR(( "tile `" NAME "` has unexpected in link name `%s`", in_link->name ));
    }
  }

  ctx->vinyl.bstream_seq      = NULL; /* set to NULL by default, before checking output links. */
  ctx->vinyl.bstream_seq_last = 0UL;

  for( uint i=0U; i<(tile->out_cnt); i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->out_link_id[ i ] ];

    if( 0==strcmp( link->name, "snaplv_ct" ) ) {
      out_link_t * o_link = &ctx->out_link[ OUT_LINK_CT ];
      o_link->mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      o_link->chunk0 = 0UL;
      o_link->wmark  = 0UL;
      o_link->chunk  = 0UL;

    } else if( 0==strcmp( link->name, "snaplv_lh" ) ) {
      out_link_t * o_link = &ctx->out_link[ OUT_LINK_LH ];
      o_link->mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      o_link->chunk0 = fd_dcache_compact_chunk0( o_link->mem, link->dcache );
      o_link->wmark  = fd_dcache_compact_wmark( o_link->mem, link->dcache, link->mtu );
      o_link->chunk  = o_link->chunk0;

    } else if( 0==strcmp( link->name, "snaplv_wr" ) ) {
      ctx->vinyl.bstream_seq = fd_mcache_seq_laddr( fd_mcache_join( fd_topo_obj_laddr( topo, link->mcache_obj_id ) ) );
    } else {
      FD_LOG_ERR(( "unexpected output link %s", link->name ));
    }
  }

  FD_TEST( !!ctx->vinyl.bstream_seq );
  memset( ctx->vinyl.pending.active, 0, VINYL_LTHASH_PENDING_MAX*sizeof(ulong) );
  ctx->vinyl.pending_cnt = 0;

  ctx->metrics.full.accounts_hashed        = 0UL;
  ctx->metrics.incremental.accounts_hashed = 0UL;

  ctx->state                        = FD_SNAPSHOT_STATE_IDLE;
  ctx->full                         = 1;

  ctx->num_hash_tiles               = fd_topo_tile_name_cnt( topo, "snaplh" );

  ctx->hash_accum.received_lthashes = 0UL;
  ctx->hash_accum.awaiting_results  = 0;
  ctx->hash_accum.hash_check_done   = 0;

  ctx->incr_first = !!tile->snaplv.process_incremental_snapshot_first;

  ctx->stats.full.t_rd = 0L;
  ctx->stats.full.t_ph = 0L;
  ctx->stats.full.t_lt = 0L;
  ctx->stats.full.cnt  = 0L;

  ctx->stats.incr.t_rd = 0L;
  ctx->stats.incr.t_ph = 0L;
  ctx->stats.incr.t_lt = 0L;
  ctx->stats.incr.cnt  = 0L;

  fd_lthash_zero( &ctx->hash_accum.calculated_lthash );
  fd_lthash_zero( &ctx->running_lthash );
}

/* TODO adjust */
#define STEM_BURST 2UL /* one control message and one malformed message */
#define STEM_LAZY  1000L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snaplv_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snaplv_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snaplv = {
  .name                     = NAME,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};

#undef NAME
