#include "../../disco/topo/fd_topo.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../funk/fd_funk.h"
#include "../../flamenco/runtime/fd_hashes.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/snapshot/fd_snapshot_create.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/fd_runtime_public.h"

#include "generated/fd_batch_tile_seccomp.h"

#include <errno.h>
#include <unistd.h>

#define REPLAY_OUT_IDX     (0UL)
#define EAH_REPLAY_OUT_SIG (0UL)

#define MEM_FOOTPRINT      (8UL<<30)

struct fd_snapshot_tile_ctx {
  /* User defined parameters. */
  ulong           full_interval;
  ulong           incremental_interval;
  char const    * out_dir;

  /* Shared data structures. */
  fd_txncache_t * status_cache;
  ulong         * is_constipated;
  fd_funk_t       funk[1];

  /* File descriptors used for snapshot generation. */
  int             tmp_fd;
  int             tmp_inc_fd;
  int             full_snapshot_fd;
  int             incremental_snapshot_fd;

  /* Metadata from the full snapshot used for incremental snapshots. */
  ulong           last_full_snap_slot;
  fd_hash_t       last_hash;
  ulong           last_capitalization;

  /* Replay out link fields for epoch account hash. */
  fd_wksp_t *     replay_out_mem;
  ulong           replay_out_chunk;

  fd_wksp_t  *    runtime_public_wksp;
  fd_runtime_public_t * runtime_public;

  /* Bump allocator */
  fd_spad_t *     spad;
};
typedef struct fd_snapshot_tile_ctx fd_snapshot_tile_ctx_t;


FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapshot_tile_ctx_t), sizeof(fd_snapshot_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_spad_align(), fd_spad_footprint( MEM_FOOTPRINT ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
privileged_init( fd_topo_t      * topo FD_PARAM_UNUSED,
                 fd_topo_tile_t * tile ) {

  /* First open the relevant files here. TODO: We eventually want to extend
     this to support multiple files. */

  char tmp_dir_buf[ FD_SNAPSHOT_DIR_MAX ];
  int err = snprintf( tmp_dir_buf, FD_SNAPSHOT_DIR_MAX, "%s/%s", tile->batch.out_dir, FD_SNAPSHOT_TMP_ARCHIVE );
  if( FD_UNLIKELY( err<0 ) ) {
    FD_LOG_ERR(( "Failed to format directory string" ));
  }

  char tmp_inc_dir_buf[ FD_SNAPSHOT_DIR_MAX ];
  err = snprintf( tmp_inc_dir_buf, FD_SNAPSHOT_DIR_MAX, "%s/%s", tile->batch.out_dir, FD_SNAPSHOT_TMP_INCR_ARCHIVE );
  if( FD_UNLIKELY( err<0 ) ) {
    FD_LOG_ERR(( "Failed to format directory string" ));
  }

  char zstd_dir_buf[ FD_SNAPSHOT_DIR_MAX ];
  err = snprintf( zstd_dir_buf, FD_SNAPSHOT_DIR_MAX, "%s/%s", tile->batch.out_dir, FD_SNAPSHOT_TMP_FULL_ARCHIVE_ZSTD );
  if( FD_UNLIKELY( err<0 ) ) {
    FD_LOG_ERR(( "Failed to format directory string" ));
  }

  char zstd_inc_dir_buf[ FD_SNAPSHOT_DIR_MAX ];
  err = snprintf( zstd_inc_dir_buf, FD_SNAPSHOT_DIR_MAX, "%s/%s", tile->batch.out_dir, FD_SNAPSHOT_TMP_INCR_ARCHIVE_ZSTD );
  if( FD_UNLIKELY( err<0 ) ) {
    FD_LOG_ERR(( "Failed to format directory string" ));
  }

  /* Create and open the relevant files for snapshots. */

  tile->batch.tmp_fd = open( tmp_dir_buf, O_CREAT | O_RDWR | O_TRUNC, 0644 );
  if( FD_UNLIKELY( tile->batch.tmp_fd==-1 ) ) {
    FD_LOG_ERR(( "Failed to open and create tarball for file=%s (%i-%s)", tmp_dir_buf, errno, fd_io_strerror( errno ) ));
  }

  tile->batch.tmp_inc_fd = open( tmp_inc_dir_buf, O_CREAT | O_RDWR | O_TRUNC, 0644 );
  if( FD_UNLIKELY( tile->batch.tmp_inc_fd==-1 ) ) {
    FD_LOG_ERR(( "Failed to open and create tarball for file=%s (%i-%s)", tmp_inc_dir_buf, errno, fd_io_strerror( errno ) ));
  }

  tile->batch.full_snapshot_fd = open( zstd_dir_buf, O_RDWR | O_CREAT | O_TRUNC, 0644 );
  if( FD_UNLIKELY( tile->batch.full_snapshot_fd==-1 ) ) {
    FD_LOG_WARNING(( "Failed to open the snapshot file (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  tile->batch.incremental_snapshot_fd = open( zstd_inc_dir_buf, O_RDWR | O_CREAT | O_TRUNC, 0644 );
  if( FD_UNLIKELY( tile->batch.incremental_snapshot_fd==-1 ) ) {
    FD_LOG_WARNING(( "Failed to open the snapshot file (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}

static void
unprivileged_init( fd_topo_t      * topo,
                   fd_topo_tile_t * tile ) {

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  if( FD_UNLIKELY( tile->out_cnt!=1UL || strcmp( topo->links[ tile->out_link_id[ REPLAY_OUT_IDX ] ].name, "batch_replay" ) ) ) {
    FD_LOG_ERR(( "batch tile has none or unexpected output links %lu %s",
                 tile->out_cnt, topo->links[ tile->out_link_id[ REPLAY_OUT_IDX ] ].name ));
  }

  /**********************************************************************/
  /* scratch (bump)-allocate memory owned by the replay tile            */
  /**********************************************************************/

  /* Do not modify order! This is join-order in unprivileged_init. */

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapshot_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapshot_tile_ctx_t), sizeof(fd_snapshot_tile_ctx_t) );
  memset( ctx, 0, sizeof(fd_snapshot_tile_ctx_t) );
  void * spad_mem            = FD_SCRATCH_ALLOC_APPEND( l, fd_spad_align(), fd_spad_footprint( MEM_FOOTPRINT ) );
  ulong  scratch_alloc_mem   = FD_SCRATCH_ALLOC_FINI  ( l, scratch_align() );

  if( FD_UNLIKELY( scratch_alloc_mem > (ulong)scratch + scratch_footprint(tile) ) ) {
    FD_LOG_ERR(( "scratch overflow" ));
  }

  ctx->full_interval           = tile->batch.full_interval;
  ctx->incremental_interval    = tile->batch.incremental_interval;
  ctx->out_dir                 = tile->batch.out_dir;
  ctx->tmp_fd                  = tile->batch.tmp_fd;
  ctx->tmp_inc_fd              = tile->batch.tmp_inc_fd;
  ctx->full_snapshot_fd        = tile->batch.full_snapshot_fd;
  ctx->incremental_snapshot_fd = tile->batch.incremental_snapshot_fd;

  /**********************************************************************/
  /* spads                                                              */
  /**********************************************************************/
  /* FIXME: Define a bound for the size of the spad. It likely needs to be
     larger than this. */
  uchar * spad_mem_cur = spad_mem;
  ctx->spad = fd_spad_join( fd_spad_new( spad_mem_cur, MEM_FOOTPRINT ) );

  /**********************************************************************/
  /* funk                                                               */
  /**********************************************************************/

  if( FD_UNLIKELY( !fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, tile->batch.funk_obj_id ) ) ) ) {
    FD_LOG_ERR(( "Failed to join database cache" ));
  }

  /**********************************************************************/
  /* status cache                                                       */
  /**********************************************************************/

  ulong status_cache_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "txncache" );
  if( FD_UNLIKELY( status_cache_obj_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "no status cache object id" ));
  }

  ctx->status_cache = fd_txncache_join( fd_topo_obj_laddr( topo, status_cache_obj_id ) );
  if( FD_UNLIKELY( !ctx->status_cache ) ) {
    FD_LOG_ERR(( "no status cache" ));
  }

  /**********************************************************************/
  /* constipated fseq                                                   */
  /**********************************************************************/

  ulong constipated_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "constipate" );
  if( FD_UNLIKELY( constipated_obj_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "no constipated object id" ));
  }
  ctx->is_constipated = fd_fseq_join( fd_topo_obj_laddr( topo, constipated_obj_id ) );
  if( FD_UNLIKELY( !ctx->is_constipated ) ) {
    FD_LOG_ERR(( "replay tile has no constipated fseq" ));
  }
  fd_fseq_update( ctx->is_constipated, 0UL );
  if( FD_UNLIKELY( fd_fseq_query( ctx->is_constipated ) ) ) {
    FD_LOG_ERR(( "constipated fseq is not zero" ));
  }

  /**********************************************************************/
  /* snapshot                                                           */
  /**********************************************************************/

  /* Zero init all of the fields used for incremental snapshot generation
     that must be persisted across snapshot creation. */

  ctx->last_full_snap_slot = 0UL;
  ctx->last_capitalization = 0UL;
  fd_memset( &ctx->last_hash, 0, sizeof(fd_hash_t) );

  /****************************************************************************/
  /* Replay Tile Link                                                         */
  /****************************************************************************/

  /* Set up replay output */
  fd_topo_link_t * replay_out = &topo->links[ tile->out_link_id[ REPLAY_OUT_IDX ] ];
  ctx->replay_out_mem         = topo->workspaces[ topo->objs[ replay_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->replay_out_chunk       = fd_dcache_compact_chunk0( ctx->replay_out_mem, replay_out->dcache );;

  /* replay public setup */
  ulong replay_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "runtime_pub" );
  FD_TEST( replay_obj_id!=ULONG_MAX );
  ctx->runtime_public_wksp = topo->workspaces[ topo->objs[ replay_obj_id ].wksp_id ].wksp;

  if( ctx->runtime_public_wksp==NULL ) {
    FD_LOG_ERR(( "no runtime_public workspace" ));
  }

  ctx->runtime_public = fd_runtime_public_join( fd_topo_obj_laddr( topo, replay_obj_id ) );
  FD_TEST( ctx->runtime_public!=NULL );
}

static void
produce_snapshot( fd_snapshot_tile_ctx_t * ctx, ulong batch_fseq ) {

  ulong is_incremental = fd_batch_fseq_is_incremental( batch_fseq );
  ulong snapshot_slot  = fd_batch_fseq_get_slot( batch_fseq );

  if( !is_incremental ) {
    ctx->last_full_snap_slot = snapshot_slot;
  }

  FD_LOG_WARNING(( "Creating snapshot incremental=%lu slot=%lu", is_incremental, snapshot_slot ));

  fd_snapshot_ctx_t snapshot_ctx = {
    .features                 = &ctx->runtime_public->features,
    .slot                     = snapshot_slot,
    .out_dir                  = ctx->out_dir,
    .is_incremental           = (uchar)is_incremental,
    .funk                     = ctx->funk,
    .status_cache             = ctx->status_cache,
    .tmp_fd                   = is_incremental ? ctx->tmp_inc_fd              : ctx->tmp_fd,
    .snapshot_fd              = is_incremental ? ctx->incremental_snapshot_fd : ctx->full_snapshot_fd,
    /* These parameters are ignored if the snapshot is not incremental. */
    .last_snap_slot           = ctx->last_full_snap_slot,
    .last_snap_acc_hash       = &ctx->last_hash,
    .last_snap_capitalization = ctx->last_capitalization,
    .spad                     = ctx->spad
  };

  /* If this isn't the first snapshot that this tile is creating, the
      permissions should be made to not acessible by users and should be
      renamed to the constant file that is expected. */

  char proc_filename[ FD_SNAPSHOT_DIR_MAX ];
  char prev_filename[ FD_SNAPSHOT_DIR_MAX ];
  char new_filename [ FD_SNAPSHOT_DIR_MAX ];
  snprintf( proc_filename, FD_SNAPSHOT_DIR_MAX, "/proc/self/fd/%d", is_incremental ? ctx->incremental_snapshot_fd : ctx->full_snapshot_fd );
  long len = readlink( proc_filename, prev_filename, FD_SNAPSHOT_DIR_MAX );
  if( FD_UNLIKELY( len<=0L ) ) {
    FD_LOG_ERR(( "Failed to readlink the snapshot file" ));
  }
  prev_filename[ len ] = '\0';

  int err = snprintf( new_filename, FD_SNAPSHOT_DIR_MAX, "%s/%s", ctx->out_dir, is_incremental ? FD_SNAPSHOT_TMP_INCR_ARCHIVE_ZSTD : FD_SNAPSHOT_TMP_FULL_ARCHIVE_ZSTD );
  if( FD_UNLIKELY( err<0 ) ) {
    FD_LOG_ERR(( "Can't format filename" ));
    return;
  }

  err = rename( prev_filename, new_filename );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Failed to rename file from %s to %s", prev_filename, new_filename ));
  }
  FD_LOG_NOTICE(( "Renaming file from %s to %s", prev_filename, new_filename ));

  err = ftruncate( snapshot_ctx.tmp_fd, 0UL );
  if( FD_UNLIKELY( err==-1 ) ) {
    FD_LOG_ERR(( "Failed to truncate the temporary file (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  err = ftruncate( snapshot_ctx.snapshot_fd, 0UL );
  if( FD_UNLIKELY( err==-1 ) ) {
    FD_LOG_ERR(( "Failed to truncate the snapshot file (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  long seek = lseek( snapshot_ctx.tmp_fd, 0UL, SEEK_SET );
  if( FD_UNLIKELY( seek!=0L ) ) {
    FD_LOG_ERR(( "Failed to seek to the beginning of the file" ));
  }

  /* Now that the files are in an expected state, create the snapshot. */
  FD_SPAD_FRAME_BEGIN( snapshot_ctx.spad ) {
    fd_snapshot_create_new_snapshot( &snapshot_ctx, &ctx->last_hash, &ctx->last_capitalization );
  } FD_SPAD_FRAME_END;

  if( is_incremental ) {
    FD_LOG_NOTICE(( "Done creating a snapshot in %s", snapshot_ctx.out_dir ));
    FD_LOG_ERR(("Successful exit" ));
  }

  FD_LOG_NOTICE(( "Done creating a snapshot in %s", snapshot_ctx.out_dir ));

  /* At this point the snapshot has been successfully created, so we can
     unconstipate funk and any related data structures in the replay tile. */

  fd_fseq_update( ctx->is_constipated, 0UL );

}

static fd_funk_txn_t*
get_eah_txn( fd_funk_t * funk, ulong slot ) {

  fd_funk_txn_all_iter_t txn_iter[1];
  for( fd_funk_txn_all_iter_new( funk, txn_iter ); !fd_funk_txn_all_iter_done( txn_iter ); fd_funk_txn_all_iter_next( txn_iter ) ) {
    fd_funk_txn_t * txn = fd_funk_txn_all_iter_ele( txn_iter );
    if( txn->xid.ul[0]==slot ) {
      FD_LOG_NOTICE(( "Found transaction for eah" ));
      return txn;
    }
  }
  FD_LOG_NOTICE(( "Calculating eah from root" ));
  return NULL;
}

static void
produce_eah( fd_snapshot_tile_ctx_t * ctx, fd_stem_context_t * stem, ulong batch_fseq ) {
  ulong eah_slot = fd_batch_fseq_get_slot( batch_fseq );

  if( FD_FEATURE_ACTIVE_( eah_slot, ctx->runtime_public->features, accounts_lt_hash ) )
    return;

  ulong tsorig = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );

  FD_LOG_WARNING(( "Begining to produce epoch account hash in background for slot=%lu", eah_slot ));

  /* TODO: Perhaps it makes sense to factor this out into a function in the
     runtime as this could technically be considered a layering violation. */

  /* First, we must retrieve the corresponding slot_bank. We have the guarantee
     that the root record is frozen from the replay tile. */

  fd_funk_t *           funk     = ctx->funk;
  fd_funk_txn_t *       eah_txn  = get_eah_txn( funk, eah_slot );
  fd_funk_rec_key_t     slot_id  = fd_runtime_slot_bank_key();
  fd_funk_rec_query_t   query[1];
  fd_funk_rec_t const * slot_rec = fd_funk_rec_query_try( funk, eah_txn, &slot_id, query );
  if( FD_UNLIKELY( !slot_rec ) ) {
    FD_LOG_ERR(( "Failed to read slot bank record: missing record" ));
  }
  void * slot_val = fd_funk_val( slot_rec, fd_funk_wksp( funk ) );

  if( FD_UNLIKELY( fd_funk_val_sz( slot_rec )<sizeof(uint) ) ) {
    FD_LOG_ERR(( "Failed to read slot bank record: empty record" ));
  }

  uint slot_magic = *(uint*)slot_val;
  FD_SPAD_FRAME_BEGIN( ctx->spad ) {
    if( FD_UNLIKELY( slot_magic!=FD_RUNTIME_ENC_BINCODE ) ) {
      FD_LOG_ERR(( "Slot bank record has wrong magic" ));
    }

    int err;
    fd_slot_bank_t * slot_bank = fd_bincode_decode_spad( slot_bank, ctx->spad, (uchar *)slot_val+sizeof(uint), fd_funk_val_sz( slot_rec )-sizeof(uint), &err );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
      FD_LOG_ERR(( "Failed to read slot bank record: invalid decode" ));
      continue;
    }

    /* At this point, calculate the epoch account hash. */

    fd_hash_t epoch_account_hash = {0};

    fd_accounts_hash( funk, slot_bank, &epoch_account_hash, ctx->spad, &ctx->runtime_public->features, NULL, NULL );

    FD_LOG_NOTICE(( "Done computing epoch account hash (%s)", FD_BASE58_ENC_32_ALLOCA( &epoch_account_hash ) ));

    /* Once the hash is calculated, we are ready to push the computed hash
       onto the out link to replay. We don't need to add any other information
       as this is the only type of message that is transmitted. */

    uchar * out_buf = fd_chunk_to_laddr( ctx->replay_out_mem, ctx->replay_out_chunk );
    fd_memcpy( out_buf, epoch_account_hash.uc, sizeof(fd_hash_t) );
    ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
    fd_stem_publish( stem, 0UL, EAH_REPLAY_OUT_SIG, ctx->replay_out_chunk, sizeof(fd_hash_t), 0UL, tsorig, tspub );

    /* Reset the fseq allowing for the un-constipation of funk and allow for
       snapshots to be created again. */

    fd_fseq_update( ctx->is_constipated, 0UL );
  } FD_SPAD_FRAME_END;

  FD_TEST( !fd_funk_rec_query_test( query ) );
}

static void
after_credit( fd_snapshot_tile_ctx_t * ctx,
              fd_stem_context_t *      stem,
              int *                    opt_poll_in FD_PARAM_UNUSED,
              int *                    charge_busy FD_PARAM_UNUSED ) {

  ulong batch_fseq = fd_fseq_query( ctx->is_constipated );

  /* If batch_fseq == 0, this means that we don't want to calculate/produce
     anything. Keep this tile spinning. */
  if( !batch_fseq ) {
    return;
  }

  if( fd_batch_fseq_is_snapshot( batch_fseq ) ) {
    produce_snapshot( ctx, batch_fseq );
  } else {
    // We need features to disable this...
    produce_eah( ctx, stem, batch_fseq );
  }
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;

  populate_sock_filter_policy_fd_batch_tile( out_cnt,
                                             out,
                                             (uint)fd_log_private_logfile_fd(),
                                             (uint)tile->batch.tmp_fd,
                                             (uint)tile->batch.tmp_inc_fd,
                                             (uint)tile->batch.full_snapshot_fd,
                                             (uint)tile->batch.incremental_snapshot_fd );
  return sock_filter_policy_fd_batch_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) {
    FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  }

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */

  out_fds[ out_cnt++ ] = tile->batch.tmp_fd;
  out_fds[ out_cnt++ ] = tile->batch.tmp_inc_fd;
  out_fds[ out_cnt++ ] = tile->batch.full_snapshot_fd;
  out_fds[ out_cnt++ ] = tile->batch.incremental_snapshot_fd;
  return out_cnt;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE          fd_snapshot_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snapshot_tile_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT        after_credit

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_batch = {
  .name                     = "batch",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
