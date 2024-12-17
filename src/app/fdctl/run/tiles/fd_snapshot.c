/* Gossip verify tile sits before the gossip (dedup?) tile to verify incoming
   gossip packets */
#include <unistd.h>
#define _GNU_SOURCE

#include "../../../../disco/tiles.h"

#include "../../../../disco/topo/fd_pod_format.h"
#include "../../../../funk/fd_funk.h"
#include "../../../../flamenco/runtime/fd_txncache.h"
#include "../../../../flamenco/runtime/fd_runtime.h"
#include "../../../../flamenco/snapshot/fd_snapshot_create.h"
#include "../../../../funk/fd_funk_filemap.h"

#include "generated/snaps_seccomp.h"

#define SCRATCH_MAX    (1024UL << 24 )  /* 24 MiB */
#define SCRATCH_DEPTH  (256UL)          /* 256 scratch frames */
#define TPOOL_WORKER_MEM_SZ (1UL<<30UL) /* 256MB */

struct fd_snapshot_tile_ctx {
  /* User defined parameters. */
  ulong           full_interval;
  ulong           incremental_interval;
  char const    * out_dir;
  char            funk_file[ PATH_MAX ];

  /* Shared data structures. */
  fd_txncache_t * status_cache;
  ulong         * is_constipated;
  fd_funk_t     * funk;

  /* File descriptors used for snapshot generation. */
  int             tmp_fd;
  int             tmp_inc_fd;
  int             full_snapshot_fd;
  int             incremental_snapshot_fd;

  /* Thread pool used for account hash calculation. */
  uchar           tpool_mem[ FD_TPOOL_FOOTPRINT( FD_TILE_MAX ) ] __attribute__( ( aligned( FD_TPOOL_ALIGN ) ) );
  fd_tpool_t *    tpool;

  /* Only join funk after tiles start spinning. */
  int             is_funk_active;

  /* Metadata from the full snapshot used for incremental snapshots. */
  ulong           last_full_snap_slot;
  fd_hash_t       last_hash;
  ulong           last_capitalization;
};
typedef struct fd_snapshot_tile_ctx fd_snapshot_tile_ctx_t;

void FD_FN_UNUSED
tpool_snap_boot( fd_topo_t * topo, ulong total_thread_count ) {
  ushort tile_to_cpu[ FD_TILE_MAX ] = { 0 };
  ulong thread_count                = 0UL;
  ulong main_thread_seen            = 0UL;

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    if( !strcmp( topo->tiles[i].name, "stpool" ) ) {
      tile_to_cpu[ thread_count++ ] = (ushort)topo->tiles[ i ].cpu_idx;
    }
  }

  if( FD_UNLIKELY( thread_count!=total_thread_count ) ) {
    FD_LOG_ERR(( "thread count mismatch thread_count=%lu total_thread_count=%lu main_thread_seen=%lu", 
                 thread_count, 
                 total_thread_count, 
                 main_thread_seen ));
  }

  fd_tile_private_map_boot( tile_to_cpu, thread_count );
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapshot_tile_ctx_t), sizeof(fd_snapshot_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, FD_SCRATCH_ALIGN_DEFAULT, tile->snaps.hash_tpool_thread_count * TPOOL_WORKER_MEM_SZ );
  l = FD_LAYOUT_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( SCRATCH_MAX   ) );
  l = FD_LAYOUT_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( SCRATCH_DEPTH ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
privileged_init( fd_topo_t      * topo FD_PARAM_UNUSED,
                 fd_topo_tile_t * tile FD_PARAM_UNUSED ) {

  /* First open the relevant files here. TODO: We eventually want to extend
     this to support multiple files. */

  char tmp_dir_buf[ FD_SNAPSHOT_DIR_MAX ];
  int err = snprintf( tmp_dir_buf, FD_SNAPSHOT_DIR_MAX, "%s/%s", tile->snaps.out_dir, FD_SNAPSHOT_TMP_ARCHIVE );
  if( FD_UNLIKELY( err<0 ) ) {
    FD_LOG_ERR(( "Failed to format directory string" ));
  }

  char tmp_inc_dir_buf[ FD_SNAPSHOT_DIR_MAX ];
  err = snprintf( tmp_inc_dir_buf, FD_SNAPSHOT_DIR_MAX, "%s/%s", tile->snaps.out_dir, FD_SNAPSHOT_TMP_INCR_ARCHIVE );
  if( FD_UNLIKELY( err<0 ) ) {
    FD_LOG_ERR(( "Failed to format directory string" ));
  }

  char zstd_dir_buf[ FD_SNAPSHOT_DIR_MAX ];
  err = snprintf( zstd_dir_buf, FD_SNAPSHOT_DIR_MAX, "%s/%s", tile->snaps.out_dir, FD_SNAPSHOT_TMP_FULL_ARCHIVE_ZSTD );
  if( FD_UNLIKELY( err<0 ) ) {
    FD_LOG_ERR(( "Failed to format directory string" ));
  }

  char zstd_inc_dir_buf[ FD_SNAPSHOT_DIR_MAX ];
  err = snprintf( zstd_inc_dir_buf, FD_SNAPSHOT_DIR_MAX, "%s/%s", tile->snaps.out_dir, FD_SNAPSHOT_TMP_INCR_ARCHIVE_ZSTD );
  if( FD_UNLIKELY( err<0 ) ) {
    FD_LOG_ERR(( "Failed to format directory string" ));
  }

  /* Create and open the relevant files for snapshots. */

  tile->snaps.tmp_fd = open( tmp_dir_buf, O_CREAT | O_RDWR | O_TRUNC, 0644 );
  if( FD_UNLIKELY( tile->snaps.tmp_fd==-1 ) ) {
    FD_LOG_ERR(( "Failed to open and create tarball for file=%s (%i-%s)", tmp_dir_buf, errno, fd_io_strerror( errno ) ));
  }

  tile->snaps.tmp_inc_fd = open( tmp_inc_dir_buf, O_CREAT | O_RDWR | O_TRUNC, 0644 );
  if( FD_UNLIKELY( tile->snaps.tmp_inc_fd==-1 ) ) {
    FD_LOG_ERR(( "Failed to open and create tarball for file=%s (%i-%s)", tmp_dir_buf, errno, fd_io_strerror( errno ) ));
  }

  tile->snaps.full_snapshot_fd = open( zstd_dir_buf, O_RDWR | O_CREAT | O_TRUNC, 0644 );
  if( FD_UNLIKELY( tile->snaps.full_snapshot_fd==-1 ) ) {
    FD_LOG_WARNING(( "Failed to open the snapshot file (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  tile->snaps.incremental_snapshot_fd = open( zstd_inc_dir_buf, O_RDWR | O_CREAT | O_TRUNC, 0644 );
  if( FD_UNLIKELY( tile->snaps.incremental_snapshot_fd==-1 ) ) {
    FD_LOG_WARNING(( "Failed to open the snapshot file (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}

static void
unprivileged_init( fd_topo_t      * topo FD_PARAM_UNUSED,
                   fd_topo_tile_t * tile ) {

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  /**********************************************************************/
  /* scratch (bump)-allocate memory owned by the replay tile            */
  /**********************************************************************/

  /* Do not modify order! This is join-order in unprivileged_init. */

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapshot_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapshot_tile_ctx_t), sizeof(fd_snapshot_tile_ctx_t) );
  memset( ctx, 0, sizeof(fd_snapshot_tile_ctx_t) );
  void * tpool_worker_mem    = FD_SCRATCH_ALLOC_APPEND( l, FD_SCRATCH_ALIGN_DEFAULT, tile->snaps.hash_tpool_thread_count * TPOOL_WORKER_MEM_SZ );
  void * scratch_smem        = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( SCRATCH_MAX    ) );
  void * scratch_fmem        = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( SCRATCH_DEPTH ) );
  ulong  scratch_alloc_mem   = FD_SCRATCH_ALLOC_FINI  ( l, scratch_align() );

  ctx->full_interval           = tile->snaps.full_interval;
  ctx->incremental_interval    = tile->snaps.incremental_interval;
  ctx->out_dir                 = tile->snaps.out_dir;
  ctx->tmp_fd                  = tile->snaps.tmp_fd;
  ctx->tmp_inc_fd              = tile->snaps.tmp_inc_fd;
  ctx->full_snapshot_fd        = tile->snaps.full_snapshot_fd;
  ctx->incremental_snapshot_fd = tile->snaps.incremental_snapshot_fd;

  /**********************************************************************/
  /* tpool                                                              */
  /**********************************************************************/

  FD_LOG_NOTICE(( "Number of threads in hash tpool: %lu", tile->snaps.hash_tpool_thread_count ));

  if( FD_LIKELY( tile->snaps.hash_tpool_thread_count>1UL ) ) {
    tpool_snap_boot( topo, tile->snaps.hash_tpool_thread_count );
    ctx->tpool = fd_tpool_init( ctx->tpool_mem, tile->snaps.hash_tpool_thread_count );
  } else {
    ctx->tpool = NULL;
  }

  if( FD_LIKELY( tile->snaps.hash_tpool_thread_count>1UL ) ) {
    /* Start the tpool workers */
    for( ulong i=1UL; i<tile->snaps.hash_tpool_thread_count; i++ ) {
      if( FD_UNLIKELY( !fd_tpool_worker_push( ctx->tpool, i, (uchar *)tpool_worker_mem + TPOOL_WORKER_MEM_SZ*(i - 1U), TPOOL_WORKER_MEM_SZ ) ) ) {
        FD_LOG_ERR(( "failed to launch worker" ));
      }
    }
  }

  /**********************************************************************/
  /* funk                                                               */
  /**********************************************************************/

  /* We only want to join funk after it has been setup and joined in the 
     replay tile. 
     TODO: Eventually funk will be joined via a shared topology object. */
  ctx->is_funk_active = 0;
  memcpy( ctx->funk_file, tile->replay.funk_file, sizeof(tile->replay.funk_file) );

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
  /* scratch                                                            */
  /**********************************************************************/

  fd_scratch_attach( scratch_smem, scratch_fmem, SCRATCH_MAX, SCRATCH_DEPTH );

  if( FD_UNLIKELY( scratch_alloc_mem != ( (ulong)scratch + scratch_footprint( tile ) ) ) ) {
    FD_LOG_ERR(( "scratch_alloc_mem did not match scratch_footprint diff: %lu alloc: %lu footprint: %lu",
                 scratch_alloc_mem - (ulong)scratch - scratch_footprint( tile ),
                 scratch_alloc_mem,
                 (ulong)scratch + scratch_footprint( tile ) ));
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
}

static void
after_credit( fd_snapshot_tile_ctx_t * ctx         FD_PARAM_UNUSED,
              fd_stem_context_t *      stem        FD_PARAM_UNUSED,
              int *                    opt_poll_in FD_PARAM_UNUSED,
              int *                    charge_busy FD_PARAM_UNUSED ) {

  ulong is_constipated = fd_fseq_query( ctx->is_constipated );

  if( !is_constipated ) {
    return;
  }

  if( FD_UNLIKELY( !ctx->is_funk_active ) ) {
    ctx->funk = fd_funk_open_file( ctx->funk_file, 
                                   1, 
                                   0, 
                                   0, 
                                   0, 
                                   0,
                                   FD_FUNK_READONLY, 
                                   NULL );
    if( FD_UNLIKELY( !ctx->funk ) ) {
      FD_LOG_ERR(( "failed to join a funky" ));
    }
    ctx->is_funk_active = 1;

    FD_LOG_WARNING(( "Just joined funk at file=%s", ctx->funk_file ));
  }

  ulong is_incremental = fd_snapshot_create_get_is_incremental( is_constipated );
  ulong snapshot_slot  = fd_snapshot_create_get_slot( is_constipated );

  if( !is_incremental ) {
    ctx->last_full_snap_slot = snapshot_slot;
  }
  
  FD_LOG_WARNING(( "Creating snapshot incremental=%lu slot=%lu", is_incremental, snapshot_slot ));

  fd_snapshot_ctx_t snapshot_ctx = {
    .slot                     = snapshot_slot,
    .out_dir                  = ctx->out_dir,
    .is_incremental           = (uchar)is_incremental,
    .valloc                   = fd_scratch_virtual(),
    .funk                     = ctx->funk,
    .status_cache             = ctx->status_cache,
    .tmp_fd                   = is_incremental ? ctx->tmp_inc_fd              : ctx->tmp_fd,
    .snapshot_fd              = is_incremental ? ctx->incremental_snapshot_fd : ctx->full_snapshot_fd,
    .tpool                    = ctx->tpool,
    /* These parameters are ignored if the snapshot is not incremental. */
    .last_snap_slot           = ctx->last_full_snap_slot,
    .last_snap_acc_hash       = &ctx->last_hash,
    .last_snap_capitalization = ctx->last_capitalization
  };

  if( !is_incremental ) {
    ctx->last_full_snap_slot = snapshot_slot;
  }

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

  if( FD_UNLIKELY( fd_snapshot_create_new_snapshot( &snapshot_ctx, &ctx->last_hash, &ctx->last_capitalization ) ) ) {
    FD_LOG_ERR(( "Failed to create a new snapshot" ));
  }

  if( is_incremental ) {
    //FD_LOG_ERR(( "Terminating out" ));
    FD_LOG_NOTICE(( "Done creating a snapshot in %s", snapshot_ctx.out_dir ));
    FD_LOG_ERR(("Successful exit" ));
  }

  FD_LOG_NOTICE(( "Done creating a snapshot in %s", snapshot_ctx.out_dir ));

  fd_fseq_update( ctx->is_constipated, 0UL );

}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;

  populate_sock_filter_policy_snaps( out_cnt, 
                                     out,
                                     (uint)fd_log_private_logfile_fd(),
                                     (uint)tile->snaps.tmp_fd,
                                     (uint)tile->snaps.tmp_inc_fd,
                                     (uint)tile->snaps.full_snapshot_fd,
                                     (uint)tile->snaps.incremental_snapshot_fd );
  return sock_filter_policy_snaps_instr_cnt;
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

  out_fds[ out_cnt++ ] = tile->snaps.tmp_fd;
  out_fds[ out_cnt++ ] = tile->snaps.tmp_inc_fd;
  out_fds[ out_cnt++ ] = tile->snaps.full_snapshot_fd;
  out_fds[ out_cnt++ ] = tile->snaps.incremental_snapshot_fd;
  return out_cnt;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE          fd_snapshot_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snapshot_tile_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT        after_credit

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snaps = {
  .name                     = "snaps",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
