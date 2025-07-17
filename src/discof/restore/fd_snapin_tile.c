#include "utils/fd_ssctrl.h"
#include "utils/fd_ssparse.h"
#include "utils/fd_ssmsg.h"

#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"
#include "../../flamenco/types/fd_types.h"
#include "../../funk/fd_funk.h"

#define NAME "snapin"

/* The snapin tile is a state machine that parses and loads a full
   and optionally an incremental snapshot.  It is currently responsible
   for loading accounts into an in-memory database, though this may
   change. */

#define FD_SNAPIN_STATE_LOADING   (0) /* We are inserting accounts from a snapshot */
#define FD_SNAPIN_STATE_DONE      (1) /* We are done inserting accounts from a snapshot */
#define FD_SNAPIN_STATE_MALFORMED (1) /* The snapshot is malformed, we are waiting for a reset notification */
#define FD_SNAPIN_STATE_SHUTDOWN  (2) /* The tile is done, been told to shut down, and has likely already exited */

struct fd_snapin_tile {
  int full;
  int state;

  ulong frag_pos;

  ulong slot;

  fd_ssparse_t * ssparse;

  ulong seed;

  fd_funk_t       funk[1];
  fd_funk_txn_t * funk_txn;
  ulong           account_bytes_inserted;
  uchar *         insertion_account;

  struct {
    ulong full_bytes_read;
    ulong incremental_bytes_read;
    ulong accounts_inserted;
  } metrics;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
  } in;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       chunk;
    ulong       mtu;
  } manifest_out;
};

typedef struct fd_snapin_tile fd_snapin_tile_t;

static inline int
should_shutdown( fd_snapin_tile_t * ctx ) {
  return ctx->state==FD_SNAPIN_STATE_SHUTDOWN;
}

static ulong
scratch_align( void ) {
  return alignof(fd_snapin_tile_t);
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapin_tile_t),  sizeof(fd_snapin_tile_t) );
  l = FD_LAYOUT_APPEND( l, fd_ssparse_align(),         fd_ssparse_footprint()   );
  return FD_LAYOUT_FINI( l, alignof(fd_snapin_tile_t) );
}

static void
metrics_write( fd_snapin_tile_t * ctx ) {
  FD_MGAUGE_SET( SNAPIN, FULL_BYTES_READ, ctx->metrics.full_bytes_read );
  FD_MGAUGE_SET( SNAPIN, INCREMENTAL_BYTES_READ, ctx->metrics.incremental_bytes_read );

  FD_MGAUGE_SET( SNAPIN, ACCOUNTS_INSERTED, ctx->metrics.accounts_inserted );
  FD_MGAUGE_SET( SNAPIN, STATE, (ulong)ctx->state );
}

static void
transition_malformed( fd_snapin_tile_t * ctx,
                     fd_stem_context_t * stem ) {
  ctx->state = FD_SNAPIN_STATE_MALFORMED;
  fd_stem_publish( stem, 1UL, FD_SNAPSHOT_MSG_CTRL_MALFORMED, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static int
is_duplicate_account( fd_snapin_tile_t * ctx,
                      uchar const *      account_pubkey ) {
  fd_account_meta_t const * rec_meta = fd_funk_get_acc_meta_readonly( ctx->funk,
                                                                      ctx->funk_txn,
                                                                      (fd_pubkey_t*)account_pubkey,
                                                                      NULL,
                                                                      NULL,
                                                                      NULL );
  if( FD_UNLIKELY( rec_meta ) ) {
    if( FD_LIKELY( rec_meta->slot>ctx->slot ) ) return 1;

    /* TODO: Reaching here means the existing value is a duplicate
       account.  We need to hash the existing account and subtract that
       hash from the running lthash. */
  }

  return 0;
}

static int
handle_data_frag( fd_snapin_tile_t *  ctx,
                  ulong               chunk,
                  ulong               sz,
                  fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( ctx->state==FD_SNAPIN_STATE_MALFORMED ) ) return 0;

  FD_TEST( ctx->state==FD_SNAPIN_STATE_LOADING || ctx->state==FD_SNAPIN_STATE_DONE );
  FD_TEST( chunk>=ctx->in.chunk0 && chunk<=ctx->in.wmark && sz<=ctx->in.mtu );

  if( FD_UNLIKELY( ctx->state==FD_SNAPIN_STATE_DONE ) ) {
    FD_LOG_WARNING(( "received data fragment while in done state" ));
    transition_malformed( ctx, stem );
    return 0;
  }

  fd_ssparse_advance_result_t advance[1];
  int result = fd_ssparse_advance( ctx->ssparse,
                                   (uchar const *)fd_chunk_to_laddr_const( ctx->in.wksp, chunk )+ctx->frag_pos,
                                   sz-ctx->frag_pos,
                                   advance );

  if( FD_LIKELY( ctx->full ) ) ctx->metrics.full_bytes_read += advance->bytes_consumed;
  else                         ctx->metrics.incremental_bytes_read += advance->bytes_consumed;

  ctx->frag_pos += advance->bytes_consumed;

  switch( result ) {
    case FD_SSPARSE_ADVANCE_ERROR:
      transition_malformed( ctx, stem );
      break;
    case FD_SSPARSE_ADVANCE_AGAIN:
      break;
    case FD_SSPARSE_ADVANCE_DONE:
      ctx->state = FD_SNAPIN_STATE_DONE;
      break;
    case FD_SSPARSE_ADVANCE_MANIFEST: {
      ulong sz = fd_ulong_align_up( sizeof(fd_snapshot_manifest_t), FD_SOLANA_MANIFEST_GLOBAL_ALIGN ) + advance->manifest.size;
      FD_TEST( sz<=ctx->manifest_out.mtu );
      ctx->slot = advance->manifest.slot;
      ulong sig = ctx->full ? fd_ssmsg_sig( FD_SSMSG_MANIFEST_FULL, advance->manifest.size ) :
                              fd_ssmsg_sig( FD_SSMSG_MANIFEST_INCREMENTAL, advance->manifest.size );
      fd_stem_publish( stem, 0UL, sig, ctx->manifest_out.chunk, sz, 0UL, 0UL, 0UL );
      ctx->manifest_out.chunk = fd_dcache_compact_next( ctx->manifest_out.chunk, sz, ctx->manifest_out.chunk0, ctx->manifest_out.wmark );
      break;
    }
    case FD_SSPARSE_ADVANCE_ACCOUNT_HEADER: {
      if( FD_UNLIKELY( is_duplicate_account( ctx, advance->account_header.pubkey ) ) ) {
        ctx->insertion_account = NULL;
        break;
      }

      FD_TXN_ACCOUNT_DECL( rec );
      int err = fd_txn_account_init_from_funk_mutable( rec,
                                                      (fd_pubkey_t*)advance->account_header.pubkey,
                                                      ctx->funk,
                                                      ctx->funk_txn,
                                                      1,
                                                      advance->account_header.data_len );
      if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "failed to initialize account" ));
        transition_malformed( ctx, stem );
        break;
      }

      rec->vt->set_data_len( rec, advance->account_header.data_len );
      rec->vt->set_slot( rec, ctx->slot );
      rec->vt->set_hash( rec, (fd_hash_t*)advance->account_header.hash );

      fd_solana_account_meta_t info[1];
      info->lamports     = advance->account_header.lamports;
      info->rent_epoch   = advance->account_header.rent_epoch;
      fd_memcpy( info->owner, advance->account_header.owner, sizeof(info->owner) );
      info->executable   = (uchar)advance->account_header.executable;
      rec->vt->set_info( rec, info );

      ctx->insertion_account = rec->vt->get_data_mut( rec );
      FD_TEST( ctx->insertion_account );
      ctx->account_bytes_inserted = 0UL;
      fd_txn_account_mutable_fini( rec, ctx->funk, ctx->funk_txn );
      ctx->metrics.accounts_inserted++;
      break;
    }
    case FD_SSPARSE_ADVANCE_ACCOUNT_DATA:
      if( FD_UNLIKELY( !ctx->insertion_account ) ) break;

      fd_memcpy( ctx->insertion_account+ctx->account_bytes_inserted, advance->account_data.data, advance->account_data.len );
      ctx->account_bytes_inserted += advance->account_data.len;
      break;
    default:
      FD_LOG_ERR(( "unexpected advance result %d", result ));
  }

  int reprocess_frag = ctx->frag_pos<sz;
  if( FD_LIKELY( !reprocess_frag ) ) ctx->frag_pos = 0UL;
  return reprocess_frag;
}

static void
handle_control_frag( fd_snapin_tile_t *  ctx,
                     fd_stem_context_t * stem,
                     ulong               sig ) {
  switch( sig ) {
    case FD_SNAPSHOT_MSG_CTRL_RESET_FULL:
      ctx->full = 1;
      fd_ssparse_reset( ctx->ssparse, fd_chunk_to_laddr( ctx->manifest_out.wksp, ctx->manifest_out.chunk ), ctx->manifest_out.mtu );
      fd_funk_txn_cancel_root( ctx->funk );
      break;
    case FD_SNAPSHOT_MSG_CTRL_RESET_INCREMENTAL:
      ctx->full = 0;
      fd_ssparse_reset( ctx->ssparse, fd_chunk_to_laddr( ctx->manifest_out.wksp, ctx->manifest_out.chunk ), ctx->manifest_out.mtu );
      if( FD_UNLIKELY( !ctx->funk_txn ) ) fd_funk_txn_cancel_root( ctx->funk );
      else                                fd_funk_txn_cancel( ctx->funk, ctx->funk_txn, 0 );
      break;
    case FD_SNAPSHOT_MSG_CTRL_EOF_FULL:
      FD_TEST( ctx->full );
      if( FD_UNLIKELY( ctx->state!=FD_SNAPIN_STATE_DONE ) ) {
        FD_LOG_WARNING(( "unexpected end of snapshot when not done parsing" ));
        transition_malformed( ctx, stem );
        break;
      }

      fd_ssparse_reset( ctx->ssparse, fd_chunk_to_laddr( ctx->manifest_out.wksp, ctx->manifest_out.chunk ), ctx->manifest_out.mtu );

      fd_funk_txn_xid_t incremental_xid = fd_funk_generate_xid();
      ctx->funk_txn = fd_funk_txn_prepare( ctx->funk, ctx->funk_txn, &incremental_xid, 0 );
      ctx->full = 0;
      break;
    case FD_SNAPSHOT_MSG_CTRL_DONE:
      if( FD_UNLIKELY( ctx->state!=FD_SNAPIN_STATE_DONE ) ) {
        FD_LOG_WARNING(( "unexpected end of snapshot when not done parsing" ));
        transition_malformed( ctx, stem );
        break;
      }

      if( FD_LIKELY( ctx->funk_txn ) ) fd_funk_txn_publish_into_parent( ctx->funk, ctx->funk_txn, 0 );
      fd_stem_publish( stem, 0UL, fd_ssmsg_sig( FD_SSMSG_DONE, 0UL ), 0UL, 0UL, 0UL, 0UL, 0UL );
      break;
    case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN:
      ctx->state = FD_SNAPIN_STATE_SHUTDOWN;
      break;
    default:
      FD_LOG_ERR(( "unexpected control sig %lu", sig ));
      return;
  }

  /* We must acknowledge after handling the control frag, because if it
     causes us to generate a malformed transition, that must be sent
     back to the snaprd controller before the acknowledgement. */
  fd_stem_publish( stem, 1UL, FD_SNAPSHOT_MSG_CTRL_ACK, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static inline int
returnable_frag( fd_snapin_tile_t *  ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  (void)in_idx;
  (void)seq;
  (void)sig;
  (void)tsorig;
  (void)tspub;

  FD_TEST( ctx->state!=FD_SNAPIN_STATE_SHUTDOWN );

  if( FD_UNLIKELY( sig==FD_SNAPSHOT_MSG_DATA ) ) return handle_data_frag( ctx, chunk, sz, stem );
  else                                           handle_control_frag( ctx, stem, sig  );

  return 0;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapin_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapin_tile_t), sizeof(fd_snapin_tile_t) );

  FD_TEST( fd_rng_secure( &ctx->seed, sizeof(ctx->seed) ) );
}

FD_FN_UNUSED static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapin_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapin_tile_t), sizeof(fd_snapin_tile_t) );
  void * _ssparse        = FD_SCRATCH_ALLOC_APPEND( l, fd_ssparse_align(),        fd_ssparse_footprint()   );

  ctx->full = 1;
  ctx->state = FD_SNAPIN_STATE_LOADING;
  ctx->frag_pos = 0UL;

  FD_TEST( fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, tile->snapin.funk_obj_id ) ) );
  ctx->funk_txn = fd_funk_txn_query( fd_funk_root( ctx->funk ), ctx->funk->txn_map );

  ctx->ssparse = fd_ssparse_join( fd_ssparse_new( _ssparse, ctx->seed ) );
  FD_TEST( ctx->ssparse );

  fd_memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  if( FD_UNLIKELY( tile->kind_id ) ) FD_LOG_ERR(( "There can only be one `" NAME "` tile" ));
  if( FD_UNLIKELY( tile->in_cnt!=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 1",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=2UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 2",  tile->out_cnt  ));

  fd_topo_link_t * writer_link = &topo->links[ tile->out_link_id[ 0UL ] ];
  ctx->manifest_out.wksp    = topo->workspaces[ topo->objs[ writer_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->manifest_out.chunk0  = fd_dcache_compact_chunk0( fd_wksp_containing( writer_link->dcache ), writer_link->dcache );
  ctx->manifest_out.wmark   = fd_dcache_compact_wmark ( ctx->manifest_out.wksp, writer_link->dcache, writer_link->mtu );
  ctx->manifest_out.chunk   = ctx->manifest_out.chunk0;
  ctx->manifest_out.mtu     = writer_link->mtu;

  fd_ssparse_reset( ctx->ssparse, fd_chunk_to_laddr( ctx->manifest_out.wksp, ctx->manifest_out.chunk ), ctx->manifest_out.mtu );

  fd_topo_link_t const * in_link = &topo->links[ tile->in_link_id[ 0UL ] ];
  fd_topo_wksp_t const * in_wksp = &topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ];
  ctx->in.wksp                   = in_wksp->wksp;;
  ctx->in.chunk0                 = fd_dcache_compact_chunk0( ctx->in.wksp, in_link->dcache );
  ctx->in.wmark                  = fd_dcache_compact_wmark( ctx->in.wksp, in_link->dcache, in_link->mtu );
  ctx->in.mtu                    = in_link->mtu;
}

#define STEM_BURST 2UL /* For control fragments, one acknowledgement, and one malformed message */
#define STEM_LAZY  1000L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snapin_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snapin_tile_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snapin = {
  .name              = NAME,
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .privileged_init   = privileged_init,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run,
};

#undef NAME
