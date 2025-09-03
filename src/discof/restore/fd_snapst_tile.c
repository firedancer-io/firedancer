#include "utils/fd_ssctrl.h"

#include "../../disco/topo/fd_topo.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"
#include "../../funk/fd_funk.h"

#define NAME "snapst"

/* The snapst tile is a state machine that inserts accounts into funk,
   an in-memory accounts database.  It runs in lockstep with snard,
   snapdc, and snapin tiles.

   snapst starts by receiving an account stream from the full snapshot.
   It then waits for FD_SNAPSHOT_MSG_CTRL_EOF_FULL, indicating that the
   incremental snapshot account stream is starting or
   FD_SNAPSHOT_MSG_CTRL_DONE, which indicates the account stream is
   done. */

#define FD_SNAPST_STATE_WAITING   (0)
#define FD_SNAPST_STATE_INDEXING  (1)
#define FD_SNAPST_STATE_DONE      (2)
#define FD_SNAPST_STATE_SHUTDOWN  (3)

struct fd_snapst_tile {
  int state;
  int full;

  uchar * acc_data;

  long boot_timestamp;

  fd_funk_t       funk[1];
  fd_funk_txn_t * funk_txn;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
  } in;

  struct {
    struct {
      ulong accounts_inserted;
    } full;

    struct {
      ulong accounts_inserted;
    } incremental;
  } metrics;
};

typedef struct fd_snapst_tile fd_snapst_tile_t;

static inline int
should_shutdown( fd_snapst_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->state==FD_SNAPST_STATE_SHUTDOWN ) ) {
    FD_LOG_NOTICE(( "loaded %.1fM accounts from snapshot in %.1f seconds",
                    (double)ctx->metrics.full.accounts_inserted+(double)ctx->metrics.incremental.accounts_inserted/1e6,
                    (double)(fd_log_wallclock()-ctx->boot_timestamp)/1e9 ));
  }
  return ctx->state==FD_SNAPST_STATE_SHUTDOWN;
}

static ulong
scratch_align( void ) {
  return 128UL;
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapst_tile_t), sizeof(fd_snapst_tile_t) );
  return FD_LAYOUT_FINI( l, alignof(fd_snapst_tile_t) );
}

static void
metrics_write( fd_snapst_tile_t * ctx ) {
  FD_MGAUGE_SET( SNAPST, FULL_ACCOUNTS_INSERTED,        ctx->metrics.full.accounts_inserted );
  FD_MGAUGE_SET( SNAPST, INCREMENTAL_ACCOUNTS_INSERTED, ctx->metrics.incremental.accounts_inserted );
  FD_MGAUGE_SET( SNAPST, STATE, (ulong)(ctx->state) );
}

static int
is_duplicate_account( fd_snapst_tile_t * ctx,
                      uchar const *      account_pubkey,
                      ulong              slot ) {
  fd_account_meta_t const * rec_meta = fd_funk_get_acc_meta_readonly( ctx->funk,
                                                                      ctx->funk_txn,
                                                                      (fd_pubkey_t*)account_pubkey,
                                                                      NULL,
                                                                      NULL,
                                                                      NULL );
  if( FD_UNLIKELY( rec_meta ) ) {
    if( FD_LIKELY( rec_meta->slot>slot ) ) return 1;
  }

  return 0;
}

static int
handle_data_frag( fd_snapst_tile_t * ctx,
                  ulong              sig,
                  ulong              chunk,
                  ulong              sz ) {
  FD_TEST( ctx->state==FD_SNAPST_STATE_INDEXING );

  switch( sig ) {
    case FD_SNAPSHOT_MSG_ACCOUNT_HDR: {
      fd_snapshot_account_t * account = (fd_snapshot_account_t *)fd_chunk_to_laddr_const( ctx->in.wksp, chunk );
      if( FD_UNLIKELY( is_duplicate_account( ctx, account->pubkey, account->slot ) ) ) {
        ctx->acc_data = NULL;
        break;
      }

      FD_TXN_ACCOUNT_DECL( rec );
      fd_funk_rec_prepare_t prepare = {0};
      int err = fd_txn_account_init_from_funk_mutable( rec,
                                                       (fd_pubkey_t const *)account->pubkey,
                                                       ctx->funk,
                                                       ctx->funk_txn,
                                                       /* do_create */ 1,
                                                       account->data_len,
                                                       &prepare );
      if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) FD_LOG_ERR(( "fd_txn_account_init_from_funk_mutable failed (%d)", err ));

      fd_txn_account_set_data_len( rec, account->data_len );
      fd_txn_account_set_slot( rec, account->slot );
      fd_txn_account_set_lamports( rec, account->lamports );
      fd_txn_account_set_owner( rec, (fd_pubkey_t const *)account->owner );
      fd_txn_account_set_executable( rec, account->executable );
      fd_txn_account_set_rent_epoch( rec, account->rent_epoch ); /* ?? */

      ctx->acc_data = fd_txn_account_get_data_mut( rec );

      if( FD_LIKELY( ctx->full ) ) ctx->metrics.full.accounts_inserted++;
      else                         ctx->metrics.incremental.accounts_inserted++;
      fd_txn_account_mutable_fini( rec, ctx->funk, ctx->funk_txn, &prepare );
      break;
    }
    case FD_SNAPSHOT_MSG_ACCOUNT_DATA: {
      if( FD_LIKELY( ctx->acc_data ) ) {
        fd_memcpy( ctx->acc_data, fd_chunk_to_laddr_const( ctx->in.wksp, chunk ), sz );
        ctx->acc_data += sz;
      }
    }
  }
}

static void
handle_control_frag( fd_snapst_tile_t *  ctx,
                     fd_stem_context_t * stem,
                     ulong               sig ) {
  switch( sig ) {
    case FD_SNAPSHOT_MSG_CTRL_RESET_FULL:
      ctx->full = 1;
      fd_funk_txn_cancel_root( ctx->funk );
      ctx->state = FD_SNAPST_STATE_INDEXING;
      break;
    case FD_SNAPSHOT_MSG_CTRL_RESET_INCREMENTAL:
      ctx->full = 0;
      if( FD_UNLIKELY( !ctx->funk_txn ) ) fd_funk_txn_cancel_root( ctx->funk );
      else                                fd_funk_txn_cancel( ctx->funk, ctx->funk_txn, 0 );
      ctx->state = FD_SNAPST_STATE_INDEXING;
      break;
    case FD_SNAPSHOT_MSG_CTRL_EOF_FULL:
      FD_TEST( ctx->full );
      fd_funk_txn_xid_t incremental_xid = fd_funk_generate_xid();
      ctx->funk_txn = fd_funk_txn_prepare( ctx->funk, ctx->funk_txn, &incremental_xid, 0 );
      ctx->full     = 0;
      ctx->state    = FD_SNAPST_STATE_INDEXING;
      break;
    case FD_SNAPSHOT_MSG_CTRL_DONE:
      break;
    case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN:
      ctx->state = FD_SNAPST_STATE_SHUTDOWN;
      if( FD_LIKELY( ctx->funk_txn ) ) fd_funk_txn_publish_into_parent( ctx->funk, ctx->funk_txn, 0 );
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
returnable_frag( fd_snapst_tile_t *  ctx,
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
  (void)tsorig;
  (void)tspub;

  FD_TEST( ctx->state!=FD_SNAPST_STATE_SHUTDOWN );

  if( FD_UNLIKELY( sig==FD_SNAPSHOT_MSG_ACCOUNT_HDR ||
                   sig==FD_SNAPSHOT_MSG_ACCOUNT_DATA ) ) return handle_data_frag( ctx, chunk, sz );
  else                                                   handle_control_frag( ctx, stem, sig );

  return 0;
}

static void
unprivileged_init( fd_topo_t * topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapst_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapst_tile_t), sizeof(fd_snapst_tile_t) );

  ctx->state = FD_SNAPST_STATE_WAITING;
  ctx->full  = 1;

  ctx->boot_timestamp = fd_log_wallclock();

  FD_TEST( fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, tile->snapst.funk_obj_id ) ) );
  ctx->funk_txn = fd_funk_txn_query( fd_funk_root( ctx->funk ), ctx->funk->txn_map );
  FD_TEST( ctx->funk_txn );

  fd_topo_link_t const * in_link = &topo->links[ tile->in_link_id[ 0UL ] ];
  fd_topo_wksp_t const * in_wksp = &topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ];
  ctx->in.wksp                   = in_wksp->wksp;;
  ctx->in.chunk0                 = fd_dcache_compact_chunk0( ctx->in.wksp, in_link->dcache );
  ctx->in.wmark                  = fd_dcache_compact_wmark( ctx->in.wksp, in_link->dcache, in_link->mtu );
  ctx->in.mtu                    = in_link->mtu;
}

#define STEM_BURST 1UL
#define STEM_LAZY  1000L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snapst_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snapst_tile_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snapst = {
  .name              = NAME,
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run,
};

#undef NAME
