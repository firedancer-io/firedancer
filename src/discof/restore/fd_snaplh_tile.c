#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../ballet/lthash/fd_lthash_adder.h"
#include "../../vinyl/bstream/fd_vinyl_bstream.h"
// #include "../../flamenco/runtime/fd_hashes.h"
#include "generated/fd_snaplh_tile_seccomp.h"

#include "utils/fd_ssctrl.h"

#define NAME "snaplh"

#define FD_SNAPLH_OUT_CTRL 0UL

#define IN_KIND_SNAPLV (0UL)
#define IN_KIND_SNAPWH (1UL)

struct in_link_private {
  fd_wksp_t *  wksp;
  ulong        chunk0;
  ulong        wmark;
  ulong        mtu;
  void const * base;
  ulong *      seq_sync;  /* fseq->seq[0] */
};
typedef struct in_link_private in_link_t;

struct out_link_private {
  fd_wksp_t * wksp;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
  ulong       mtu;
};
typedef struct out_link_private out_link_t;

struct fd_snaplh_tile {
  int state;
  int full;

  ulong seed;
  int   hash_account;
  ulong num_hash_tiles;
  ulong hash_tile_idx;
  ulong pairs_seen;

  ulong  finish_fseq;

  fd_lthash_adder_t adder[1];
  uchar             data[ FD_RUNTIME_ACC_SZ_MAX ];
  ulong             acc_data_sz;

  fd_lthash_value_t        running_lthash;

  struct {
    uchar pubkey[ FD_HASH_FOOTPRINT ];
    uchar owner[ FD_HASH_FOOTPRINT ];
    ulong data_len;
    ulong lamports;
    int   executable;
  } account_hdr;

  struct {
    struct {
      ulong accounts_hashed;
    } full;

    struct {
      ulong accounts_hashed;
    } incremental;
  } metrics;

  ulong       last_wh_seq;
  in_link_t   in[2];
  uchar       in_kind[2];
  out_link_t  out;
};

typedef struct fd_snaplh_tile fd_snaplh_t;

static inline int
should_shutdown( fd_snaplh_t * ctx ) {
  return ctx->state==FD_SNAPSHOT_STATE_SHUTDOWN;
}

static ulong
scratch_align( void ) {
  return alignof(fd_snaplh_t);
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snaplh_t), sizeof(fd_snaplh_t) );
  return FD_LAYOUT_FINI( l, alignof(fd_snaplh_t) );
}

static void
metrics_write( fd_snaplh_t * ctx ) {
  FD_MGAUGE_SET( SNAPLH, FULL_ACCOUNTS_HASHED,        ctx->metrics.full.accounts_hashed );
  FD_MGAUGE_SET( SNAPLH, INCREMENTAL_ACCOUNTS_HASHED, ctx->metrics.incremental.accounts_hashed );
  FD_MGAUGE_SET( SNAPLH, STATE,                       (ulong)(ctx->state) );
}

// static void
// transition_malformed( fd_snaplh_t *  ctx,
//                       fd_stem_context_t * stem ) {
//   ctx->state = FD_SNAPSHOT_STATE_ERROR;
//   fd_stem_publish( stem, FD_SNAPLH_OUT_CTRL, FD_SNAPSHOT_MSG_CTRL_ERROR, 0UL, 0UL, 0UL, 0UL, 0UL );
// }

static int
should_hash_account( fd_snaplh_t * ctx ) {
  return (ctx->pairs_seen % ctx->num_hash_tiles)==ctx->hash_tile_idx;
}

static void
streamlined_hash( fd_snaplh_t * ctx,
                  uchar const * _pair ) {
  uchar const * pair = _pair;
  fd_vinyl_bstream_phdr_t const * phdr = (fd_vinyl_bstream_phdr_t const *)pair;
  pair += sizeof(fd_vinyl_bstream_phdr_t);
  fd_account_meta_t const * meta = (fd_account_meta_t const *)pair;
  pair += sizeof(fd_account_meta_t);
  uchar const * data = pair;
  
  ulong data_len   = meta->dlen;
  uchar pubkey[32];  memcpy( pubkey, phdr->key.c, 32UL );
  ulong lamports   = meta->lamports;
  uchar owner[32];   memcpy( owner, meta->owner, 32UL );
  uchar executable = (uchar)( !meta->executable ? 0U : 1U) ;

  if( FD_UNLIKELY( data_len > FD_RUNTIME_ACC_SZ_MAX ) ) FD_LOG_ERR(( "Found unusually large account (data_sz=%lu), aborting", data_len ));
  if( FD_UNLIKELY( lamports==0UL ) ) return;

  fd_lthash_adder_push_solana_account( ctx->adder,
                                       &ctx->running_lthash,
                                       pubkey,
                                       data,
                                       data_len,
                                       lamports,
                                       executable,
                                       owner );

  if( FD_LIKELY( ctx->full ) ) ctx->metrics.full.accounts_hashed++;
  else                         ctx->metrics.incremental.accounts_hashed++;
}

static void
handle_wh_data_frag( fd_snaplh_t * ctx,
                     ulong         in_idx,
                     ulong         seq,
                     ulong         chunk,      /* compressed input pointer */
                     ulong         sz_comp,    /* compressed input size */
                     fd_stem_context_t * stem ) { 
  
  FD_TEST( ctx->in_kind[ in_idx ]==IN_KIND_SNAPWH );

  uchar const * rem    = fd_chunk_to_laddr_const( ctx->in[ in_idx ].base, chunk );
  ulong         rem_sz = sz_comp<<FD_VINYL_BSTREAM_BLOCK_LG_SZ;
  FD_CRIT( fd_ulong_is_aligned( (ulong)rem, FD_VINYL_BSTREAM_BLOCK_SZ ), "misaligned write request" );
  FD_CRIT( fd_ulong_is_aligned( rem_sz, FD_VINYL_BSTREAM_BLOCK_SZ ),     "misaligned write request" );

  while( rem_sz ) {
    FD_CRIT( rem_sz>=FD_VINYL_BSTREAM_BLOCK_SZ, "corrupted bstream block" );
    fd_vinyl_bstream_phdr_t const * phdr = (fd_vinyl_bstream_phdr_t *)rem;
    ulong ctl      = phdr->ctl;
    int   ctl_type = fd_vinyl_bstream_ctl_type( ctl );
    switch( ctl_type ) {

      case FD_VINYL_BSTREAM_CTL_TYPE_PAIR: {
        uchar const * pair = rem;
        ulong val_esz = fd_vinyl_bstream_ctl_sz( ctl );
        ulong pair_sz = fd_vinyl_bstream_pair_sz( val_esz );
        rem    += pair_sz;
        rem_sz -= pair_sz;
        if( FD_LIKELY( should_hash_account( ctx ) ) ) {
          streamlined_hash( ctx, pair );
        }
        ctx->pairs_seen++;
        break;
      }

      case FD_VINYL_BSTREAM_CTL_TYPE_ZPAD: {
        rem    += FD_VINYL_BSTREAM_BLOCK_SZ;
        rem_sz -= FD_VINYL_BSTREAM_BLOCK_SZ;
        break;
      }

      default:
        FD_LOG_CRIT(( "unexpected vinyl bstream block ctl=%016lx", ctl ));
    }
  }

  ctx->last_wh_seq = seq;

  if( ctx->state==FD_SNAPSHOT_STATE_FINISHING ) {
    /* TODO this does not seem to happen here */
    fd_lthash_adder_flush( ctx->adder, &ctx->running_lthash );
    if( fd_seq_inc( ctx->last_wh_seq, 1UL )==ctx->finish_fseq ) {
      uchar * lthash_out = fd_chunk_to_laddr( ctx->out.wksp, ctx->out.chunk );
      fd_memcpy( lthash_out, &ctx->running_lthash, sizeof(fd_lthash_value_t) );
      /* TODO remove log when ready */
      FD_LOG_WARNING(( "*** sending back FD_SNAPSHOT_HASH_MSG_RESULT_ADD (A) %lu ( %s )", ctx->hash_tile_idx, FD_LTHASH_ENC_32_ALLOCA( &ctx->running_lthash ) ));
      fd_stem_publish( stem, 0UL, FD_SNAPSHOT_HASH_MSG_RESULT_ADD, ctx->out.chunk, FD_LTHASH_LEN_BYTES, 0UL, 0UL, 0UL );
      ctx->out.chunk = fd_dcache_compact_next( ctx->out.chunk, FD_LTHASH_LEN_BYTES, ctx->out.chunk0, ctx->out.wmark );
      ctx->state = FD_SNAPSHOT_STATE_IDLE;
    }
  }
}

static void
handle_lv_data_frag( fd_snaplh_t * ctx,
                     ulong         in_idx,
                     ulong         chunk,      /* compressed input pointer */
                     ulong         sz_comp ) { /* compressed input size */
  (void)ctx; (void)in_idx; (void)chunk; (void)sz_comp;
}

static void
handle_control_frag( fd_snaplh_t * ctx,
                     ulong         sig,
                     ulong         tsorig,
                     ulong         tspub,
                    fd_stem_context_t * stem  ) {
  switch( sig ) {
    case FD_SNAPSHOT_MSG_CTRL_INIT_FULL:
    case FD_SNAPSHOT_MSG_CTRL_INIT_INCR:
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      ctx->full  = sig==FD_SNAPSHOT_MSG_CTRL_INIT_FULL;
      ctx->state = FD_SNAPSHOT_STATE_PROCESSING;
      fd_lthash_zero( &ctx->running_lthash );
      fd_lthash_adder_new( ctx->adder );
      break;

    case FD_SNAPSHOT_MSG_CTRL_FAIL:
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING ||
               ctx->state==FD_SNAPSHOT_STATE_FINISHING ||
               ctx->state==FD_SNAPSHOT_STATE_ERROR );
      ctx->state = FD_SNAPSHOT_STATE_IDLE;
      fd_lthash_zero( &ctx->running_lthash );
      fd_lthash_adder_new( ctx->adder );
      break;

    case FD_SNAPSHOT_MSG_CTRL_NEXT:
    case FD_SNAPSHOT_MSG_CTRL_DONE:{
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING ||
               ctx->state==FD_SNAPSHOT_STATE_FINISHING  ||
               ctx->state==FD_SNAPSHOT_STATE_ERROR );
      // if( FD_UNLIKELY( ctx->state!=FD_SNAPSHOT_STATE_FINISHING ) ) {
      //   transition_malformed( ctx, stem );
      //   return;
      // }
      ulong fseq = (tspub<<32 ) | tsorig;
      ctx->finish_fseq = fseq;
      ctx->state = FD_SNAPSHOT_STATE_FINISHING;

      if( ctx->state==FD_SNAPSHOT_STATE_FINISHING ) {
        /* TODO this should be in after_credit */
        fd_lthash_adder_flush( ctx->adder, &ctx->running_lthash );
        if( fd_seq_inc( ctx->last_wh_seq, 1UL )==ctx->finish_fseq ) {
          uchar * lthash_out = fd_chunk_to_laddr( ctx->out.wksp, ctx->out.chunk );
          fd_memcpy( lthash_out, &ctx->running_lthash, sizeof(fd_lthash_value_t) );
          /* TODO remove log when ready */
          FD_LOG_NOTICE(( "*** sending back FD_SNAPSHOT_HASH_MSG_RESULT_ADD (B) %lu ( %s )", ctx->hash_tile_idx, FD_LTHASH_ENC_32_ALLOCA( &ctx->running_lthash ) ));
          fd_stem_publish( stem, 0UL, FD_SNAPSHOT_HASH_MSG_RESULT_ADD, ctx->out.chunk, FD_LTHASH_LEN_BYTES, 0UL, 0UL, 0UL );
          ctx->out.chunk = fd_dcache_compact_next( ctx->out.chunk, FD_LTHASH_LEN_BYTES, ctx->out.chunk0, ctx->out.wmark );
          ctx->state = FD_SNAPSHOT_STATE_IDLE;
        }
      }
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN:
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      ctx->state = FD_SNAPSHOT_STATE_SHUTDOWN;
      break;

    case FD_SNAPSHOT_MSG_CTRL_ERROR:
      ctx->state = FD_SNAPSHOT_STATE_ERROR;
      break;

    default:
      FD_LOG_ERR(( "unexpected control sig %lu", sig ));
      return;
  }
}

static inline int
returnable_frag( fd_snaplh_t *       ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl    FD_PARAM_UNUSED,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  FD_TEST( ctx->state!=FD_SNAPSHOT_STATE_SHUTDOWN );

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_SNAPWH ) ) handle_wh_data_frag( ctx, in_idx, seq, chunk, sz/*sz_comp*/, stem );
  else {
    if( FD_UNLIKELY( sig==FD_SNAPSHOT_HASH_MSG_SUB_VINYL_HDR ) ) handle_lv_data_frag( ctx, in_idx, chunk, sz );
    else                                                         handle_control_frag( ctx, sig, tsorig, tspub, stem );
  }

  /* Because snapwr pacing is so loose and this tile sleeps, fd_stem
     will not return flow control credits fast enough.
     So, always update fseq (consumer progress) here. */
  ulong idx = ctx->in_kind[ 0 ]==IN_KIND_SNAPWH ? 0UL : 1UL;
  fd_fseq_update( ctx->in[ idx ].seq_sync, fd_seq_inc( ctx->last_wh_seq, 1UL ) );

  return 0;
}


static ulong
populate_allowed_fds( fd_topo_t      const * topo FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2UL; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) {
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  }

  return out_cnt;
}

/* TODO seccomp needs revision here */
static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  populate_sock_filter_policy_fd_snaplh_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_snaplh_tile_instr_cnt;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snaplh_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaplh_t), sizeof(fd_snaplh_t) );

  FD_TEST( fd_rng_secure( &ctx->seed, 8UL ) );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snaplh_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaplh_t),   sizeof(fd_snaplh_t)        );

  if( FD_UNLIKELY( tile->in_cnt!=2UL ) )  FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 1",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 1", tile->out_cnt  ));

  for( ulong i=0UL; i<(tile->in_cnt); i++ ) {
    fd_topo_link_t * in_link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * in_wksp = &topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ];
    if( FD_LIKELY( 0==strcmp( in_link->name, "snaplv_lh" ) ) ) {
      ctx->in[ i ].wksp     = in_wksp->wksp;
      ctx->in[ i ].chunk0   = fd_dcache_compact_chunk0( ctx->in[ i ].wksp, in_link->dcache );
      ctx->in[ i ].wmark    = fd_dcache_compact_wmark( ctx->in[ i ].wksp, in_link->dcache, in_link->mtu );
      ctx->in[ i ].mtu      = in_link->mtu;
      ctx->in[ i ].base     = NULL;
      ctx->in[ i ].seq_sync = NULL;
      ctx->in_kind[ i ]     = IN_KIND_SNAPLV;
    } else if( FD_LIKELY( 0==strcmp( in_link->name, "snapwh_wr" ) ) ) {
      ctx->in[ i ].wksp     = in_wksp->wksp;
      ctx->in[ i ].chunk0   = 0;
      ctx->in[ i ].wmark    = 0;
      ctx->in[ i ].mtu      = in_link->mtu;
      ctx->in[ i ].base     = fd_dcache_join( fd_topo_obj_laddr( topo, tile->snapwr.dcache_obj_id ) );
      ctx->in[ i ].seq_sync = tile->in_link_fseq[ i ];
      ctx->last_wh_seq      = fd_fseq_query( tile->in_link_fseq[ i ] );
      ctx->in_kind[ i ]     = IN_KIND_SNAPWH;
      FD_TEST( ctx->in[ i ].base );
    } else {
      FD_LOG_ERR(( "tile `" NAME "` has unexpected in link name `%s`", in_link->name ));
    }
  }

  fd_topo_link_t * out_link = &topo->links[ tile->out_link_id[ 0UL ] ];
  ctx->out.wksp    = topo->workspaces[ topo->objs[ out_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->out.chunk0  = fd_dcache_compact_chunk0( fd_wksp_containing( out_link->dcache ), out_link->dcache );
  ctx->out.wmark   = fd_dcache_compact_wmark ( ctx->out.wksp, out_link->dcache, out_link->mtu );
  ctx->out.chunk   = ctx->out.chunk0;
  ctx->out.mtu     = out_link->mtu;
  FD_TEST( 0==strcmp( out_link->name, "snaplh_lv" ) );

  fd_lthash_adder_new( ctx->adder );

  ctx->metrics.full.accounts_hashed        = 0UL;
  ctx->metrics.incremental.accounts_hashed = 0UL;

  ctx->state                   = FD_SNAPSHOT_STATE_IDLE;
  ctx->full                    = 1;
  ctx->acc_data_sz             = 0UL;
  ctx->hash_account            = 0;
  ctx->num_hash_tiles          = fd_topo_tile_name_cnt( topo, "snaplh" );
  ctx->hash_tile_idx           = tile->kind_id;
  ctx->pairs_seen              = 0UL;
  fd_lthash_zero( &ctx->running_lthash );
  FD_LOG_NOTICE(( "*** hash_tile_idx %lu out of %lu", ctx->hash_tile_idx, ctx->num_hash_tiles ));
}

/* TODO should it be 1UL ? */
#define STEM_BURST 2UL /* one control message and one malformed message or one hash result message */
#define STEM_LAZY  1000L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snaplh_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snaplh_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snaplh = {
  .name                     = NAME,
  .populate_allowed_fds     = populate_allowed_fds,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};

#undef NAME
