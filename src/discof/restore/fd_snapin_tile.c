#include "fd_restore_base.h"
#include "fd_snapshot_parser.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../util/archive/fd_tar.h"
#include "../../flamenco/runtime/fd_acc_mgr.h" /* FD_ACC_SZ_MAX */
#include "../../flamenco/types/fd_types.h"
#include "../../funk/fd_funk.h"
#include "stream/fd_stream_ctx.h"
#include "../../flamenco/runtime/fd_runtime_public.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#define NAME        "SnapIn"
#define LINK_IN_MAX  1UL

#define SNAP_IN_STATUS_WAITING 0UL
#define SNAP_IN_STATUS_FULL    1UL
#define SNAP_IN_STATUS_INC     2UL
#define SNAP_IN_STATUS_DONE    3UL

#define SNAP_FSEQ_NO_SNAPSHOT 1UL
#define SNAP_FSEQ_SNAPSHOT_LOADED 2UL

#define SNAP_STATE_IGNORE       ((uchar)0)  /* ignore file content */
#define SNAP_STATE_TAR          ((uchar)1)  /* reading tar header (buffered) */
#define SNAP_STATE_MANIFEST     ((uchar)2)  /* reading manifest (buffered) */
#define SNAP_STATE_ACCOUNT_HDR  ((uchar)3)  /* reading account hdr (buffered) */
#define SNAP_STATE_ACCOUNT_DATA ((uchar)4)  /* reading account data (zero copy) */
#define SNAP_STATE_DONE         ((uchar)5)  /* expect no more data */

struct fd_snapin_tile {
  /* Snapshot parser */

  fd_snapshot_parser_t * parser;

  /* Stream input */

  fd_stream_frag_meta_ctx_t in_state;

  /* Account insertion */

  fd_funk_t       funk[1];
  fd_funk_txn_t * funk_txn;
  uchar *         acc_data;

  /* Shared fseq with replay tile */
  ulong * replay_snapshot_fseq;
  ulong   num_accounts_inserted;

  struct {

    fd_snapshot_parser_metrics_t full;
    fd_snapshot_parser_metrics_t incremental;

    ulong status;
  } metrics;
};

typedef struct fd_snapin_tile fd_snapin_tile_t;

static void
fd_snapin_set_status( fd_snapin_tile_t * ctx,
                      ulong              status ) {
  ctx->metrics.status = status;
  FD_COMPILER_MFENCE();
  FD_MGAUGE_SET( SNAPIN, STATUS, status );
  FD_COMPILER_MFENCE();
}

static void
fd_snapin_shutdown( fd_snapin_tile_t * ctx ) {
  fd_snapin_set_status( ctx, SNAP_IN_STATUS_DONE );
  fd_snapshot_parser_close( ctx->parser );
  fd_fseq_update( ctx->replay_snapshot_fseq, SNAP_FSEQ_SNAPSHOT_LOADED );

  FD_COMPILER_MFENCE();
  FD_MGAUGE_SET( TILE, STATUS, 2UL );
  FD_COMPILER_MFENCE();
  
  FD_LOG_INFO(( "snapin: shutting down, inserted %lu accounts", ctx->metrics.full.accounts_processed ));
  FD_LOG_INFO(( "snapin: shutting down, inserted %lu accounts", ctx->num_accounts_inserted ));

  for(;;) pause();
}

__attribute__((unused)) static int
snapshot_is_duplicate_account_old( fd_snapshot_parser_t * parser,
                               fd_snapin_tile_t *     ctx,
                               fd_pubkey_t const *    account_key ) {
  /* Check if account exists */
  fd_account_meta_t const * rec_meta = fd_funk_get_acc_meta_readonly( ctx->funk, ctx->funk_txn, account_key, NULL, NULL, NULL );
  if( rec_meta ) {
    // FD_LOG_WARNING(("account exists with slot %lu", rec_meta->slot));
    if( rec_meta->slot > parser->accv_slot ) 
      return 1;
  }
  return 0;
}

__attribute__((unused)) static int
snapshot_is_duplicate_account( fd_snapshot_parser_t * parser,
                               fd_snapin_tile_t *     ctx,
                               fd_pubkey_t const *    account_key ) {
  /* Check if account exists */
  fd_account_meta_t const * rec_meta = fd_funk_find_account( ctx->funk, account_key );
  if( rec_meta ) {
    if( rec_meta->slot > parser->accv_slot ) 
      return 1;
  }
  return 0;
}

__attribute__((unused)) static void
snapshot_insert_account_old( fd_snapshot_parser_t *          parser,
                         fd_solana_account_hdr_t const * hdr,
                         void *                          _ctx ) {
  fd_snapin_tile_t * ctx = fd_type_pun( _ctx );
  fd_pubkey_t const * account_key  = fd_type_pun_const( hdr->meta.pubkey );

  if( !snapshot_is_duplicate_account( parser, ctx, account_key ) ) {
    FD_TXN_ACCOUNT_DECL( rec );
    int err = fd_txn_account_init_from_funk_mutable( rec, account_key, ctx->funk, ctx->funk_txn, /* do_create */ 1, hdr->meta.data_len );
    if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_ERR(( "fd_txn_account_init_from_funk_mutable failed (%d)", err ));
    }

    rec->vt->set_data_len( rec, hdr->meta.data_len );
    rec->vt->set_slot( rec, parser->accv_slot );
    rec->vt->set_hash( rec, &hdr->hash );
    rec->vt->set_info( rec, &hdr->info );

    ctx->acc_data = rec->vt->get_data_mut( rec );
    ctx->num_accounts_inserted++;
    fd_txn_account_mutable_fini( rec, ctx->funk, ctx->funk_txn);
  }
}

__attribute__((unused)) static void
snapshot_copy_acc_data( fd_snapshot_parser_t * parser FD_PARAM_UNUSED,
                        void *                 _ctx,
                        uchar const *          buf,
                        ulong                  data_sz ) {
  fd_snapin_tile_t * ctx = fd_type_pun( _ctx );

  if( ctx->acc_data ) {
    fd_memcpy( ctx->acc_data, buf, data_sz );
    ctx->acc_data += data_sz;
  }
}

__attribute__((unused)) static void
snapshot_reset_acc_data( fd_snapshot_parser_t * parser FD_PARAM_UNUSED,
                         void *                 _ctx ) {
  fd_snapin_tile_t * ctx = fd_type_pun( _ctx );
  ctx->acc_data = NULL;
}

static void
fd_snapin_reset( fd_snapin_tile_t * ctx ) {
  fd_snapshot_parser_reset( ctx->parser );
  ctx->in_state.in_skip = 0UL;
}

static void
fd_snapin_on_file_complete( fd_snapin_tile_t *   ctx,
                            fd_stream_reader_t * reader,
                            fd_stream_frag_meta_t const * frag ) {
  if( ctx->metrics.status == SNAP_IN_STATUS_FULL &&
      fd_frag_meta_ctl_orig( frag->ctl ) == 1UL ) {
    FD_LOG_INFO(("snapin: done processing full snapshot, now processing incremental snapshot"));
    fd_snapin_set_status( ctx, SNAP_IN_STATUS_INC );

    fd_snapin_reset( ctx );
    fd_stream_reader_reset_stream( reader );

  } else if( ctx->metrics.status == SNAP_IN_STATUS_INC ||
             !fd_frag_meta_ctl_orig( frag->ctl ) ) {
    fd_snapin_shutdown( ctx );

  } else {
    FD_LOG_ERR(("snapdc: unexpected status"));
  }
}

static void
fd_snapin_check_parser_failed( fd_snapshot_parser_t * parser ) {
  if( FD_UNLIKELY( parser->flags & SNAP_FLAG_FAILED ) ) {
    FD_LOG_ERR(( "Failed to restore snapshot" ));
  }
}

static ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_snapin_tile_t), fd_snapshot_parser_align() );
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapin_tile_t),  sizeof(fd_snapin_tile_t)       );
  l = FD_LAYOUT_APPEND( l, fd_snapshot_parser_align(), fd_snapshot_parser_footprint() );
  return l;
}

FD_FN_UNUSED static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  if( FD_UNLIKELY( tile->kind_id ) ) FD_LOG_ERR(( "There can only be one `" NAME "` tile" ));

  if( FD_UNLIKELY( tile->in_cnt !=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 1",  tile->in_cnt  ));
  /* FIXME check link names */

  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_snapin_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapin_tile_t), sizeof(fd_snapin_tile_t) );
  void * parser_mem      = FD_SCRATCH_ALLOC_APPEND( l, fd_snapshot_parser_align(), fd_snapshot_parser_footprint() );

  fd_exec_slot_ctx_t * slot_ctx = fd_exec_slot_ctx_join( fd_topo_obj_laddr( topo, tile->snapin.slot_ctx_obj_id ) );
  fd_runtime_public_t * runtime_public = fd_runtime_public_join( fd_topo_obj_laddr( topo, tile->snapin.runtime_pub_obj_id ) );
  fd_spad_t * runtime_spad = fd_runtime_public_spad( runtime_public );
  ctx->parser = fd_snapshot_parser_new( parser_mem,
                                        snapshot_insert_account_old,
                                        snapshot_copy_acc_data,
                                        snapshot_reset_acc_data,
                                        ctx,
                                        slot_ctx,
                                        runtime_spad );

  /* Join stream input */
  FD_TEST( fd_dcache_join( fd_topo_obj_laddr( topo, topo->links[ tile->in_link_id[ 0 ] ].dcache_obj_id ) ) );
  ctx->in_state.in_buf  = (uchar const *)topo->workspaces[ topo->objs[ topo->links[ tile->in_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->in_state.in_skip = 0UL;

  /* join funk */
  if( FD_UNLIKELY( !fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, tile->snapin.funk_obj_id ) ) ) ) {
    FD_LOG_ERR(( "Failed to join database cache" ));
  }

  /* join fseq */
  ctx->replay_snapshot_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, tile->snapin.fseq_obj_id ) );
  if( FD_UNLIKELY( !ctx->replay_snapshot_fseq ) ) {
    FD_LOG_ERR(( "Failed to join replay snapshot fseq" ));
  }

  ctx->funk_txn                              = fd_funk_txn_query( fd_funk_root( ctx->funk ), ctx->funk->txn_map );
  ctx->metrics.full.accounts_files_processed = 0UL;
  ctx->metrics.full.accounts_files_total     = 0UL;
  ctx->metrics.full.accounts_processed       = 0UL;

  ctx->metrics.incremental.accounts_files_processed = 0UL;
  ctx->metrics.incremental.accounts_files_total     = 0UL;
  ctx->metrics.incremental.accounts_processed       = 0UL;
  ctx->metrics.status                               = SNAP_IN_STATUS_FULL;

  ctx->num_accounts_inserted = 0UL;
}

static void
fd_snapin_accumulate_metrics( fd_snapin_tile_t * ctx ) {
  if( ctx->metrics.status == SNAP_IN_STATUS_FULL ) {
    ctx->metrics.full = fd_snapshot_parser_get_metrics( ctx->parser );
  } else if( ctx->metrics.status == SNAP_IN_STATUS_INC ) {
    ctx->metrics.incremental = fd_snapshot_parser_get_metrics( ctx->parser );
  } else {
    FD_LOG_ERR(("unexpected status"));
  }
}

static void
metrics_write( void * _ctx ) {
  fd_snapin_tile_t * ctx = fd_type_pun( _ctx );
  FD_MGAUGE_SET( SNAPIN, FULL_ACCOUNTS_FILES_PROCESSED,        ctx->metrics.full.accounts_files_processed );
  FD_MGAUGE_SET( SNAPIN, FULL_ACCOUNTS_FILES_TOTAL,            ctx->metrics.full.accounts_files_total );
  FD_MGAUGE_SET( SNAPIN, FULL_ACCOUNTS_PROCESSED,              ctx->metrics.full.accounts_processed );
  FD_MGAUGE_SET( SNAPIN, INCREMENTAL_ACCOUNTS_FILES_PROCESSED, ctx->metrics.incremental.accounts_files_processed );
  FD_MGAUGE_SET( SNAPIN, INCREMENTAL_ACCOUNTS_FILES_TOTAL,     ctx->metrics.incremental.accounts_files_total );
  FD_MGAUGE_SET( SNAPIN, INCREMENTAL_ACCOUNTS_PROCESSED,       ctx->metrics.incremental.accounts_processed );
}

/* on_stream_frag consumes an incoming stream data fragment.  This frag
   may be up to the dcache size (e.g. 8 MiB), therefore could contain
   thousands of accounts.  This function will publish a message for each
   account to consumers.  Slow consumers may cause backpressure and
   force this function to exit early (before all accounts in this frag
   were published).  In that case, this function is called repeatedly
   once the backpressure condition resolves (see in_skip). */

static int
on_stream_frag( void *                        _ctx,
                fd_stream_reader_t *          reader,
                fd_stream_frag_meta_t const * frag,
                ulong *                       sz ) {
  fd_snapin_tile_t * ctx = fd_type_pun( _ctx );

  /* poll file complete notification */
  if( FD_UNLIKELY( fd_frag_meta_ctl_eom( frag->ctl ) ) ) {
    fd_snapin_on_file_complete( ctx, reader, frag );
    *sz = frag->sz;
    return 1;
  }

  if( FD_UNLIKELY( ctx->parser->flags ) ) {
    fd_snapin_check_parser_failed( ctx->parser );
    /* don't consume the frag if blocked or done */
    return 0;
  }

  uchar const * const chunk0 = ctx->in_state.in_buf + frag->loff;
  uchar const * const chunk1 = chunk0 + frag->sz;
  uchar const * const start  = chunk0 + ctx->in_state.in_skip;
  uchar const *       cur    = start;

  fd_snapshot_parser_set_goff( ctx->parser, frag->goff );

  int consume_frag = 1;
  for(;;) {
    if( FD_UNLIKELY( cur>=chunk1 ) ) {
      ctx->in_state.in_skip = 0U;
      break;
    }
    cur = fd_snapshot_parser_process_chunk( ctx->parser, cur, (ulong)( chunk1-cur ) );
    if( FD_UNLIKELY( ctx->parser->flags ) ) {
      fd_snapin_check_parser_failed( ctx->parser );
    }
  }

  ulong consumed_sz = (ulong)( cur-start );
  *sz               = consumed_sz;
  fd_snapin_accumulate_metrics( ctx );

  return consume_frag;
}

/* fd_snapin_in_update gets called periodically synchronize flow control
   credits back to the stream producer.  Also updates link in metrics. */

static void
fd_snapin_in_update( fd_stream_reader_t * in ) {
  fd_stream_reader_update_upstream( in );
}

__attribute__((noinline)) static void
fd_snapin_run1(
    fd_snapin_tile_t *         ctx,
    fd_stream_ctx_t *          stream_ctx
) {
  fd_stream_ctx_run( stream_ctx,
    ctx,
    NULL,
    fd_snapin_in_update,
    NULL,
    metrics_write,
    NULL,
    on_stream_frag );
}

FD_FN_UNUSED static void
fd_snapin_run( fd_topo_t *      topo,
               fd_topo_tile_t * tile ) {
  fd_snapin_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  void * ctx_mem = fd_alloca_check( FD_STEM_SCRATCH_ALIGN, fd_stream_ctx_footprint( topo, tile ) );
  fd_stream_ctx_t * stream_ctx = fd_stream_ctx_new( ctx_mem, topo, tile );
  FD_TEST( stream_ctx );
  fd_snapin_run1( ctx, stream_ctx );
}

fd_topo_run_tile_t fd_tile_snapshot_restore_SnapIn = {
  .name              = "SnapIn",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = fd_snapin_run,
};

#undef LINK_IN_MAX
