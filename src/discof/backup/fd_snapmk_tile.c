#include "fd_snapmk.h"
#include "../replay/fd_replay_tile.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../funk/fd_funk.h"
#include "../../util/pod/fd_pod.h"
#include "fd_funk_scan.h"
//#include "../../util/archive/fd_tar.h"

union __attribute__((packed)) snap_acc_hdr {
  struct __attribute__((packed)) {
    /* 0x00 */ ulong       slot;
    /* 0x08 */ ulong       data_len;
    /* 0x10 */ fd_pubkey_t pubkey;
    /* 0x30 */ ulong       lamports;
    /* 0x38 */ ulong       rent_epoch;
    /* 0x40 */ fd_pubkey_t owner;
    /* 0x60 */ uchar       executable;
    /* 0x61 */ uchar       padding[7];
    /* 0x68 */ fd_hash_t   hash;
    /* 0x88 */
  };
  uchar raw[ 0x88 ];
};
typedef union snap_acc_hdr snap_acc_hdr_t;

/* Funk rooted record iterator (thread-safe) */

#define CHAIN_MAX (4096UL) /* ought to be enough */

/* Output link */

struct fd_snapmk_out {
  /* Out frag flow */
  ulong   out_idx;
  ulong * fseq;
  ulong   seq_cons;
  ulong   burst_max;

  /* Out data allocator */
  fd_wksp_t * base;
  ulong       chunk0;
  ulong       chunk;
  ulong       wmark;

  /* Out state */
  fd_funk_rec_t const * rec;
  ulong                 rec_off;
};
typedef struct fd_snapmk_out fd_snapmk_out_t;

struct fd_snapmk {
  fd_funk_t funk[1];

  uint state;
  fd_funk_scan_t scan[1];

  ulong out_meta_idx;
  ulong out_cnt;
  ulong out_ready; /* bit set */

  struct {
    ulong accounts_processed;
  } metrics;

  fd_snapmk_out_t out    [ SNAPZP_TILE_MAX ];
  ushort          in_kind[ FD_TOPO_MAX_TILE_IN_LINKS  ];
};
typedef struct fd_snapmk fd_snapmk_t;

#define IN_KIND_REPLAY 1

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  fd_snapmk_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  memset( ctx, 0, sizeof(fd_snapmk_t) );
  ctx->state = SNAPMK_STATE_IDLE;

  ulong funk_obj_id;  FD_TEST( (funk_obj_id  = fd_pod_query_ulong( topo->props, "funk",       ULONG_MAX ) )!=ULONG_MAX );
  ulong locks_obj_id; FD_TEST( (locks_obj_id = fd_pod_query_ulong( topo->props, "funk_locks", ULONG_MAX ) )!=ULONG_MAX );
  FD_TEST( fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, funk_obj_id ), fd_topo_obj_laddr( topo, locks_obj_id ) ) );

  for( ulong i=0UL; i < tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if( 0==strcmp( link->name, "replay_out" ) ) {
      FD_TEST( !ctx->in_kind[ i ] );
      ctx->in_kind[ i ] = IN_KIND_REPLAY;
    } else {
      FD_LOG_ERR(( "Unexpected input link \"%s\"", link->name ));
    }
  }

  FD_TEST( tile->out_cnt >= 2 );
  FD_TEST( tile->out_cnt <= SNAPZP_TILE_MAX );
  ctx->out_cnt = tile->out_cnt - 1UL;
  for( ulong i=0UL; i < tile->out_cnt - 1; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ i ] ];
    if( 0!=strcmp( link->name, "snapmk_zp" ) ) {
      FD_LOG_ERR(( "Unexpected output link \"%s\"", link->name ));
    }
    FD_TEST( link->mcache && link->dcache );
    fd_wksp_t * link_base = fd_wksp_containing( link );
    ctx->out[ i ] = (fd_snapmk_out_t) {
      .out_idx = i,
      .base    = link_base,
      .chunk0  = fd_dcache_compact_chunk0( link_base, link->dcache ),
      .chunk   = fd_dcache_compact_chunk0( link_base, link->dcache ),
      .wmark   = fd_dcache_compact_wmark ( link_base, link->dcache, link->mtu )
    };
    FD_TEST( fd_topo_find_reliable_consumers( topo, link, &ctx->out[ i ].fseq, 1UL )==1UL );
  }
  ctx->out_meta_idx = tile->out_cnt - 1UL;
  if( 0!=strcmp( topo->links[ tile->out_link_id[ ctx->out_meta_idx ] ].name, "snapmk_replay" ) ) {
    FD_LOG_ERR(( "Unexpected output link \"%s\"", topo->links[ tile->out_link_id[ ctx->out_meta_idx ] ].name ));
  }
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof(fd_snapmk_t);
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapmk_t), sizeof(fd_snapmk_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo; (void)tile;
  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

/* Output stream format
   - snapmk produces multiple independent byte streams of uncompressed
     snapshot data
   - each stream is an unterminated .tar stream (no 512-byte EOF record)
   - each stream is sent to a snapzp tile (for compression and writing)
   - output streams are chopped up into fragment sequences and sent over
     tango (mcache/dcache)
   - each frag sequence begins with ctl.som=1 and ends with ctl.eom=1
   - a frag sequence is aligned to tar stream boundaries
   - each frag carries up to 2^16 bytes data

   Output stream logic
   - uses dcache allocators
   - links are reliable
   - backpressure on each link is tracked separately
   - each produce burst can create multiple frags
   - when an output link is backpressured, switches to the next
   - links are prioritized by index (link 0 has highest priority) */

static void
update_flow_control( fd_snapmk_t *             ctx,
                     fd_stem_context_t const * stem ) {
  // for( ulong i=0UL; i < ctx->out_cnt; i++ ) {
  //   ulong cons_cr_avail = (ulong)fd_long_max( (long)stem->depths[ i ]-fd_long_max( fd_seq_diff( stem->seqs[ i ], fd_fseq_query( ctx->out[ i ].fseq ) ), 0L ), 0L );
  //   stem->cr_avail[ i ] = cons_cr_avail;
  //   stem->out_reliable[ i ] = 0;
  // }
  ulong out_ready = 0UL;
  for( ulong i=0UL; i < ctx->out_cnt; i++ ) {
    out_ready |= fd_ulong_if( !!stem->cr_avail[ i ], 1UL<<i, 0UL );
  }
  ctx->out_ready = out_ready;
}

/* check_credit is called every run loop iteration */

static void
check_credit( fd_snapmk_t *       ctx,
              fd_stem_context_t * stem,
              int *               charge_busy,
              int *               is_backpressured ) {
  (void)stem; (void)is_backpressured;
  switch( ctx->state ) {
  case SNAPMK_STATE_IDLE:
    fd_log_sleep( (long)1e6 );
    *charge_busy = 0;
    break;
  case SNAPMK_STATE_ACCOUNTS:
    *is_backpressured = 0;
    if( FD_UNLIKELY( !ctx->out_ready ) ) {
      update_flow_control( ctx, stem );
      if( FD_UNLIKELY( !ctx->out_ready ) ) {
        *is_backpressured = 1;
        return;
      }
    }
    break;
  }
}

__attribute__((noinline)) static void
send_account_frags( fd_snapmk_t *       ctx,
                    fd_stem_context_t * stem ) {
  ctx->out_ready = 1;
  ulong             out_idx = (ulong)fd_ulong_find_lsb( ctx->out_ready );
  fd_snapmk_out_t * out     = &ctx->out[ out_idx ];

  /* Concatenate accounts together into a frag burst
     FIXME: Burst more than one frag at a time */
  ulong   chunk   = out->chunk;
  uchar * buf     = fd_chunk_to_laddr( out->base, chunk );
  ulong   buf_max = 65536UL;
  ulong   buf_rem = buf_max;
# define BUF_APPEND( p, sz )    \
   do {                         \
    ulong sz_ = (sz);           \
    fd_memcpy( buf, (p), sz_ ); \
    buf     += sz_;             \
    buf_rem -= sz_;             \
  } while(0)

  do {
    /* Advance to new account, write account header */
    fd_account_meta_t const * val;
    if( !out->rec ) {
      if( FD_UNLIKELY( buf_rem < sizeof(snap_acc_hdr_t) ) ) break;
      ulong rec_idx = fd_funk_scan_next_rooted( ctx->scan );
      if( FD_UNLIKELY( rec_idx==ULONG_MAX ) ) {
        FD_LOG_NOTICE(( "chain=%lu rec_cnt=%lu", ctx->scan->chain, ctx->scan->rec_tot ));
        ctx->state = SNAPMK_STATE_ACCOUNTS_FLUSH;
        FD_LOG_NOTICE(( "DONE" ));
        break;
      }
      out->rec = ctx->scan->rec[ rec_idx ];
      ctx->metrics.accounts_processed++;
      val = ctx->scan->val[ rec_idx ];
      snap_acc_hdr_t hdr = {
        .slot       = val->slot,
        .data_len   = val->dlen,
        .pubkey     = FD_LOAD( fd_pubkey_t, out->rec->pair.key ),
        .lamports   = val->lamports,
        .rent_epoch = ULONG_MAX,
        .owner      = FD_LOAD( fd_pubkey_t, val->owner ),
        .executable = !!val->executable,
        .padding    = {0},
        .hash       = {{0}} /* FIXME? */
      };
      BUF_APPEND( hdr.raw, sizeof(snap_acc_hdr_t) );
      out->rec_off = 0UL;
    } else {
      val = fd_funk_val( out->rec, ctx->funk->wksp );
    }
    FD_TEST( val );

    /* Write account data
       FIXME: Consider using non-temporal memcpy for large accounts */
    uchar const * data     = fd_account_data( val );
    ulong         data_rem = val->dlen - out->rec_off;
    ulong data_chunk_sz = fd_ulong_min( buf_rem, data_rem );
    if( data_chunk_sz ) {
      BUF_APPEND( data+out->rec_off, data_chunk_sz );
      out->rec_off += data_chunk_sz;
      data_rem     -= data_chunk_sz;
    }
    if( !data_rem ) out->rec = NULL;
  } while( buf_rem );

  /* Send frag */
  ulong sz   = buf_max - buf_rem;
  ulong orig = SNAPMK_ORIG_DATA;
  int   som  = 0; /* FIXME */
  int   eom  = 0; /* FIXME */
  ulong ctl = fd_frag_meta_ctl( orig, som, eom, 0 );
  fd_stem_publish( stem, out_idx, 0UL, chunk, sz, ctl, 0UL, 0UL );
}

/* after_credit is called if we can publish at least one frag */

static void
after_credit( fd_snapmk_t *       ctx,
              fd_stem_context_t * stem,
              int *               poll_in,
              int *               charge_busy ) {
  (void)poll_in;
  switch( ctx->state ) {
  case SNAPMK_STATE_ACCOUNTS:
    send_account_frags( ctx, stem );
    *charge_busy = 1;
    break;
  case SNAPMK_STATE_ACCOUNTS_FLUSH: {
    FD_COMPILER_MFENCE();
    ulong ctl = fd_frag_meta_ctl( SNAPMK_ORIG_DONE, 0, 1, 0 );
    fd_stem_publish( stem, ctx->out_meta_idx, 0UL, 0UL, 0UL, ctl, 0UL, 0UL );
    ctx->state = SNAPMK_STATE_IDLE;
    break;
  }
  }
}

static void
snap_begin( fd_snapmk_t * ctx ) {
  if( FD_UNLIKELY( ctx->state != SNAPMK_STATE_IDLE ) ) {
    FD_LOG_ERR(( "invariant violation: snapshot creation requested state is %u", ctx->state ));
    return;
  }
  ctx->state = SNAPMK_STATE_ACCOUNTS;
  fd_funk_scan_init( ctx->scan, ctx->funk, 0UL, ULONG_MAX );
  FD_LOG_NOTICE(( "START" ));
}

static int
returnable_frag( fd_snapmk_t *       ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  (void)seq; (void)chunk; (void)sz; (void)ctl; (void)tsorig; (void)tspub; (void)stem;
  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_REPLAY:
    switch( sig ) {
    case REPLAY_SIG_SNAP_CREATE:
      snap_begin( ctx );
      break;
    default:
      break;
    }
    break;
  default:
    FD_LOG_CRIT(( "unexpected msg from link %lu with sig %lu", in_idx, sig ));
  }
  return 0;
}

static void
metrics_write( fd_snapmk_t * ctx ) {
  FD_MGAUGE_SET( SNAPMK, ACTIVE,             ctx->state!=SNAPMK_STATE_IDLE );
  FD_MCNT_SET  ( SNAPMK, ACCOUNTS_PROCESSED, ctx->metrics.accounts_processed );
}

#define STEM_BURST 1UL
#define STEM_LAZY  10000UL
#define STEM_CALLBACK_CONTEXT_TYPE    fd_snapmk_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(fd_snapmk_t)
#define STEM_CALLBACK_CHECK_CREDIT    check_credit
#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snapmk = {
  .name                     = "snapmk",
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run
};
