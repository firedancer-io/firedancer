#include "fd_restore_base.h"
#include "fd_snapshot_parser.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../util/archive/fd_tar.h"
#include "../../flamenco/runtime/fd_acc_mgr.h" /* FD_ACC_SZ_MAX */
#include "../../flamenco/types/fd_types.h"
#include "../../funk/fd_funk.h"
#include "stream/fd_stream_ctx.h"
#include "stream/fd_frag_writer.h"
#include "fd_snapshot_messages.h"
#include "../../flamenco/runtime/fd_runtime_public.h"
#include <assert.h>
#include <stdio.h>
#include <unistd.h>

#define NAME        "SnapIn"
#define LINK_IN_MAX  1UL

#define MANIFEST_OUT_IDX 0UL

#define SNAP_FSEQ_NO_SNAPSHOT 1UL
#define SNAP_FSEQ_SNAPSHOT_LOADED 2UL

#define FD_SNAPIN_SCRATCH_MAX ( 1UL << 20UL )
#define FD_SNAPIN_SCRATCH_DEPTH (1UL << 5UL )

struct fd_snapin_tile {
  /* Snapshot parser */

  fd_snapshot_parser_t * parser;

  /* Stream input */

  fd_stream_frag_meta_ctx_t in_state;

  /* Account insertion */

  fd_funk_t       funk[1];
  fd_funk_txn_t * funk_txn;
  uchar *         acc_data;

  /* manifest out */
  fd_frag_writer_t * manifest_writer;

  struct {

    fd_snapshot_parser_metrics_t full;
    fd_snapshot_parser_metrics_t incremental;

    ulong   num_accounts_inserted;
    ulong   status;
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
  fd_snapin_set_status( ctx, STATUS_DONE );
  fd_snapshot_parser_close( ctx->parser );
  fd_frag_writer_notify( ctx->manifest_writer,
                                  fd_frag_meta_ctl( 0UL, 0, 1, 0 ) );

  FD_COMPILER_MFENCE();
  FD_MGAUGE_SET( TILE, STATUS, 2UL );
  FD_COMPILER_MFENCE();
  
  FD_LOG_INFO(( "snapin: shutting down, inserted %lu accounts", ctx->metrics.full.accounts_processed ));
  FD_LOG_INFO(( "snapin: shutting down, inserted %lu accounts", ctx->metrics.num_accounts_inserted ));

  for(;;) pause();
}

static void
send_manifest( fd_snapshot_parser_t * parser,
               void *                 _ctx,
               fd_solana_manifest_t * manifest ) {
  (void)parser;
  fd_snapin_tile_t * ctx = fd_type_pun( _ctx );

  fd_snapshot_manifest_t * snapshot_manifest_mem = fd_type_pun( fd_frag_writer_prepare( ctx->manifest_writer ) );

  fd_snapshot_manifest_init_from_solana_manifest(snapshot_manifest_mem, manifest );

  FD_LOG_NOTICE(( "Snapshot manifest loaded for slot %lu", snapshot_manifest_mem->slot ));

  /* TODO: indicate the message type through the signature field */
  fd_frag_writer_publish( ctx->manifest_writer,
                          sizeof(fd_snapshot_manifest_t),
                          FD_SNAPSHOT_MANIFEST_MESSAGE_ID,
                          0UL,
                          0UL,
                          0UL );
}

static int
snapshot_is_duplicate_account( fd_snapshot_parser_t * parser,
                                   fd_snapin_tile_t *     ctx,
                                   fd_pubkey_t const *    account_key ) {
  /* Check if account exists */
  fd_account_meta_t const * rec_meta = fd_funk_get_acc_meta_readonly( ctx->funk,
                                                                      ctx->funk_txn,
                                                                      account_key,
                                                                      NULL,
                                                                      NULL,
                                                                      NULL );
  if( rec_meta ) {
    if( rec_meta->slot > parser->accv_slot ) 
      return 1;
  }
  return 0;
}

static void
snapshot_insert_account( fd_snapshot_parser_t *          parser,
                         fd_solana_account_hdr_t const * hdr,
                         void *                          _ctx ) {
  fd_snapin_tile_t * ctx = fd_type_pun( _ctx );
  fd_pubkey_t const * account_key  = fd_type_pun_const( hdr->meta.pubkey );

  if( !snapshot_is_duplicate_account( parser, ctx, account_key ) ) {
    FD_TXN_ACCOUNT_DECL( rec );
    int err = fd_txn_account_init_from_funk_mutable( rec,
                                                     account_key,
                                                     ctx->funk,
                                                     ctx->funk_txn,
                                                     /* do_create */ 1,
                                                     hdr->meta.data_len );
    if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_ERR(( "fd_txn_account_init_from_funk_mutable failed (%d)", err ));
    }

    rec->vt->set_data_len( rec, hdr->meta.data_len );
    rec->vt->set_slot( rec, parser->accv_slot );
    rec->vt->set_hash( rec, &hdr->hash );
    rec->vt->set_info( rec, &hdr->info );

    ctx->acc_data = rec->vt->get_data_mut( rec );
    ctx->metrics.num_accounts_inserted++;
    fd_txn_account_mutable_fini( rec, ctx->funk, ctx->funk_txn);
  }
}

static void
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

static void
snapshot_reset_acc_data( fd_snapshot_parser_t * parser FD_PARAM_UNUSED,
                         void *                 _ctx ) {
  fd_snapin_tile_t * ctx = fd_type_pun( _ctx );
  ctx->acc_data = NULL;
}

static ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_snapin_tile_t), 
                       fd_ulong_max( fd_snapshot_parser_align(), fd_frag_writer_align() ) );
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapin_tile_t),  sizeof(fd_snapin_tile_t)       );
  l = FD_LAYOUT_APPEND( l, fd_snapshot_parser_align(), fd_snapshot_parser_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_frag_writer_align(),     fd_frag_writer_footprint()     );
  l = FD_LAYOUT_APPEND( l, fd_scratch_smem_align(),       fd_scratch_smem_footprint( FD_SNAPIN_SCRATCH_MAX ) );
  return FD_LAYOUT_FINI( l, alignof(fd_snapin_tile_t) );
}

FD_FN_UNUSED static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  if( FD_UNLIKELY( tile->kind_id ) ) FD_LOG_ERR(( "There can only be one `" NAME "` tile" ));

  if( FD_UNLIKELY( tile->in_cnt !=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 1",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt !=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 1",  tile->out_cnt  ));

  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_snapin_tile_t * ctx  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapin_tile_t), sizeof(fd_snapin_tile_t) );
  void * parser_mem       = FD_SCRATCH_ALLOC_APPEND( l, fd_snapshot_parser_align(), fd_snapshot_parser_footprint() );
  void * manifest_out_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_frag_writer_align(),     fd_frag_writer_footprint() );

  fd_snapshot_parser_process_manifest_fn_t manifest_cb     = NULL;
  if( 0==strcmp( topo->links[tile->out_link_id[ MANIFEST_OUT_IDX ]].name, "snap_replay"   ) ) {
    manifest_cb     = send_manifest;
  }

  ctx->parser = fd_snapshot_parser_new( parser_mem,
                                        manifest_cb,
                                        snapshot_insert_account,
                                        snapshot_copy_acc_data,
                                        snapshot_reset_acc_data,
                                        ctx );

  /* Join stream input */
  FD_TEST( fd_dcache_join( fd_topo_obj_laddr( topo, topo->links[ tile->in_link_id[ 0 ] ].dcache_obj_id ) ) );
  ctx->in_state.in_buf  = (uchar const *)topo->workspaces[ topo->objs[ topo->links[ tile->in_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->in_state.in_skip = 0UL;

  /* join funk */
  if( FD_UNLIKELY( !fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, tile->snapin.funk_obj_id ) ) ) ) {
    FD_LOG_ERR(( "Failed to join database cache" ));
  }

  /* init manifest out */
  fd_topo_link_t * manifest_out_link = &topo->links[ tile->out_link_id[ MANIFEST_OUT_IDX ] ];
  ctx->manifest_writer = fd_frag_writer_new( manifest_out_mem, manifest_out_link );

  void * smem = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( FD_SNAPIN_SCRATCH_MAX ) );
  void * fmem = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( FD_SNAPIN_SCRATCH_DEPTH ) );
  fd_scratch_attach( smem, fmem, FD_SNAPIN_SCRATCH_MAX, FD_SNAPIN_SCRATCH_DEPTH );

  ctx->funk_txn                              = fd_funk_txn_query( fd_funk_root( ctx->funk ), ctx->funk->txn_map );
  ctx->metrics.full.accounts_files_processed = 0UL;
  ctx->metrics.full.accounts_files_total     = 0UL;
  ctx->metrics.full.accounts_processed       = 0UL;

  ctx->metrics.incremental.accounts_files_processed = 0UL;
  ctx->metrics.incremental.accounts_files_total     = 0UL;
  ctx->metrics.incremental.accounts_processed       = 0UL;
  ctx->metrics.status                               = STATUS_FULL;

  ctx->metrics.num_accounts_inserted = 0UL;
}

static void
fd_snapin_accumulate_metrics( fd_snapin_tile_t * ctx ) {
  if( ctx->metrics.status == STATUS_FULL ) {
    ctx->metrics.full = fd_snapshot_parser_get_metrics( ctx->parser );
  } else if( ctx->metrics.status == STATUS_INC ) {
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
  FD_MGAUGE_SET( SNAPIN, ACCOUNTS_INSERTED,                    ctx->metrics.num_accounts_inserted );
}

static void
fd_snapin_reset( fd_snapin_tile_t *   ctx,
                 fd_stream_reader_t * reader ) {
  fd_snapshot_parser_reset( ctx->parser );
  fd_stream_reader_reset_stream( reader );
  ctx->in_state.in_skip = 0UL;
}

static void
fd_snapin_on_file_complete( fd_snapin_tile_t *   ctx,
                            fd_stream_reader_t * reader,
                            fd_stream_frag_meta_t const * frag ) {
  if( ctx->metrics.status == STATUS_FULL &&
      fd_frag_meta_ctl_orig( frag->ctl ) == 1UL ) {
    FD_LOG_INFO(("snapin: done processing full snapshot, now processing incremental snapshot"));
    fd_snapin_set_status( ctx, STATUS_INC );

    fd_snapin_reset( ctx, reader );

  } else if( ctx->metrics.status == STATUS_INC ||
             !fd_frag_meta_ctl_orig( frag->ctl ) ) {
    fd_snapin_shutdown( ctx );

  } else {
    FD_LOG_ERR(("snapin: unexpected status"));
  }
}

static void
fd_snapin_on_notification( fd_snapin_tile_t *            ctx,
                           fd_stream_reader_t *          reader,
                           fd_stream_frag_meta_t const * frag ) {
  if( FD_UNLIKELY( fd_frag_meta_ctl_eom( frag->ctl ) ) ) {
    /* file complete notification */
    fd_snapin_on_file_complete( ctx, reader, frag );
  } else if( FD_UNLIKELY( fd_frag_meta_ctl_err( frag->ctl ) ) ) {
    /* retry notification */
    /* TODO: notify manifest writer if needed */
    fd_snapin_reset( ctx, reader );

    /* clear contents of funk */
    fd_funk_txn_cancel_root( ctx->funk );
    /* TODO: why does this assertion fail??? */
    // FD_TEST( fd_funk_rec_pool_is_empty( fd_funk_rec_pool( ctx->funk ) ) );
  } else {
    FD_LOG_ERR(( "snapin: unknown notification ctl %u", frag->ctl ));
  }
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

  /* poll notifications */
  if( FD_UNLIKELY( frag->sz==0 ) ) {
    fd_snapin_on_notification( ctx, reader, frag );
    return 1;
  }

  if( FD_UNLIKELY( ctx->parser->flags & SNAP_FLAG_BLOCKED ||
                   ctx->parser->flags & SNAP_FLAG_DONE ) ) {
    /* Don't consume the frag if blocked or done */
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
      if( FD_UNLIKELY( ctx->parser->flags & SNAP_FLAG_FAILED ) ) {
        /* abort app if parser failed */
        FD_LOG_ERR(( "Failed to restore snapshot" ));
      }
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
                     on_stream_frag,
                     NULL );
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

#undef NAME
#undef LINK_IN_MAX
