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

#define SCRATCH_MAX    (1024UL /*MiB*/ << 24)
#define SCRATCH_DEPTH  (256UL) /* 128 scratch frames */
#define TPOOL_WORKER_MEM_SZ (1UL<<30UL) /* 256MB */


struct fd_snapshot_tile_ctx {
  ulong           full_interval;
  ulong           incremental_interval;
  char const    * out_dir;
  fd_funk_t     * funk;
  fd_txncache_t * status_cache;
  fd_wksp_t     * status_cache_wksp;
  ulong         * is_constipated;

  int             tmp_fd;
  int             tmp_inc_fd;
  int             full_snapshot_fd;
  int             incremental_snapshot_fd;

  ulong           last_full_snap;

  uchar           tpool_mem[FD_TPOOL_FOOTPRINT( FD_TILE_MAX )] __attribute__( ( aligned( FD_TPOOL_ALIGN ) ) );
  fd_tpool_t *    tpool;

  int activated;

  fd_hash_t last_hash;
  ulong     last_capitalization;
};
typedef struct fd_snapshot_tile_ctx fd_snapshot_tile_ctx_t;

void FD_FN_UNUSED
tpool_snap_boot( fd_topo_t * topo, ulong total_thread_count ) {
  ushort tile_to_cpu[ FD_TILE_MAX ] = { 0 };
  ulong thread_count = 0;
  ulong main_thread_seen = 0;

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    if( strcmp( topo->tiles[i].name, "thread" ) == 0 ) {
      tile_to_cpu[ 1+thread_count ] = (ushort)topo->tiles[i].cpu_idx;
      thread_count++;
    }
    if( strcmp( topo->tiles[i].name, "snaps" ) == 0 ) {
      tile_to_cpu[ 0 ] = (ushort)topo->tiles[i].cpu_idx;
      main_thread_seen = 1;
    }
  }

  if( main_thread_seen ) {
    thread_count++;
  }

  if( thread_count != total_thread_count )
    FD_LOG_WARNING(( "thread count mismatch thread_count=%lu total_thread_count=%lu main_thread_seen=%lu", thread_count, total_thread_count, main_thread_seen ));

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
  l = FD_LAYOUT_APPEND( l, FD_SCRATCH_ALIGN_DEFAULT, tile->snaps.tpool_thread_count * TPOOL_WORKER_MEM_SZ );
  l = FD_LAYOUT_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( SCRATCH_MAX   ) );
  l = FD_LAYOUT_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( SCRATCH_DEPTH ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
privileged_init( fd_topo_t      * topo FD_PARAM_UNUSED,
                 fd_topo_tile_t * tile FD_PARAM_UNUSED ) {

  /* First open the relevant files here. */
  FD_LOG_WARNING(("DONE HERE 1"));

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

  return;
}

static void
unprivileged_init( fd_topo_t      * topo FD_PARAM_UNUSED,
                   fd_topo_tile_t * tile FD_PARAM_UNUSED ) {


  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  /**********************************************************************/
  /* scratch (bump)-allocate memory owned by the replay tile            */
  /**********************************************************************/

  /* Do not modify order! This is join-order in unprivileged_init. */

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapshot_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapshot_tile_ctx_t), sizeof(fd_snapshot_tile_ctx_t) );
  memset( ctx, 0, sizeof(fd_snapshot_tile_ctx_t) );
  void * tpool_worker_mem    = FD_SCRATCH_ALLOC_APPEND( l, FD_SCRATCH_ALIGN_DEFAULT, tile->snaps.tpool_thread_count * TPOOL_WORKER_MEM_SZ );
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

  FD_LOG_WARNING(("NUM THREADS: %lu", tile->snaps.tpool_thread_count));

  if( FD_LIKELY( tile->snaps.tpool_thread_count > 1 ) ) {
    tpool_snap_boot( topo, tile->snaps.tpool_thread_count );
  }
  ctx->tpool = fd_tpool_init( ctx->tpool_mem, tile->snaps.tpool_thread_count );

  if( FD_LIKELY( tile->snaps.tpool_thread_count > 1 ) ) {
    /* start the tpool workers */
    for( ulong i = 1UL; i<tile->snaps.tpool_thread_count; i++ ) {
      if( fd_tpool_worker_push( ctx->tpool, i, (uchar *)tpool_worker_mem + TPOOL_WORKER_MEM_SZ*(i - 1U), TPOOL_WORKER_MEM_SZ ) == NULL ) {
        FD_LOG_ERR(( "failed to launch worker" ));
      }
    }
  }

  /**********************************************************************/
  /* funk                                                               */
  /**********************************************************************/

  // ulong funk_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "funk" );
  // FD_TEST( funk_obj_id!=ULONG_MAX );
  // ctx->funk = fd_funk_join( fd_topo_obj_laddr( topo, funk_obj_id ) );
  // if( ctx->funk==NULL ) {
  //   FD_LOG_ERR(( "no funk" ));
  // }

  ctx->activated = 0;

  /* TODO: This below code needs to be shared as a topology object. */
  // fd_funk_t * funk;

  // FD_LOG_WARNING(("STARTING TO JOIN FUNK"));

  //   /* Create new funk database */
  // funk = fd_funk_open_file(
  //     "/data/ibhatt/funkfile", 1, 0UL, 0UL,
  //     0UL, 0UL,
  //     FD_FUNK_READONLY, NULL );
  // if( funk == NULL ) {
  //   FD_LOG_ERR(( "no funk loaded" ));
  // }

  // FD_LOG_WARNING(("JOINED FUNK"));
  // ctx->funk = funk;

  /**********************************************************************/
  /* status cache                                                       */
  /**********************************************************************/

  ulong status_cache_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "txncache" );
  FD_TEST( status_cache_obj_id!=ULONG_MAX );
  ctx->status_cache = fd_txncache_join( fd_topo_obj_laddr( topo, status_cache_obj_id ) );
  if( ctx->status_cache==NULL ) {
    FD_LOG_ERR(( "no status cache" ));
  }

  /**********************************************************************/
  /* scratch                                                            */
  /**********************************************************************/

  fd_scratch_attach( scratch_smem, scratch_fmem, SCRATCH_MAX, SCRATCH_DEPTH );

  if( FD_UNLIKELY( scratch_alloc_mem != ( (ulong)scratch + scratch_footprint( tile ) ) ) ) {
    FD_LOG_ERR( ( "scratch_alloc_mem did not match scratch_footprint diff: %lu alloc: %lu footprint: %lu",
          scratch_alloc_mem - (ulong)scratch - scratch_footprint( tile ),
          scratch_alloc_mem,
          (ulong)scratch + scratch_footprint( tile ) ) );
  }

  /**********************************************************************/
  /*  constipated fseq                                                  */
  /**********************************************************************/

  ulong constipated_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "constipate" );
  FD_TEST( constipated_obj_id!=ULONG_MAX );
  ctx->is_constipated = fd_fseq_join( fd_topo_obj_laddr( topo, constipated_obj_id ) );
  if( FD_UNLIKELY( !ctx->is_constipated ) ) {
    FD_LOG_ERR(( "replay tile has no constipated fseq" ));
  }
  fd_fseq_update( ctx->is_constipated, 0UL );
  FD_TEST( 0UL==fd_fseq_query( ctx->is_constipated ) );

  /* TODO:FIXME: document this */

  ctx->last_full_snap = 0UL;

}

static void
after_credit( fd_snapshot_tile_ctx_t * ctx         FD_PARAM_UNUSED,
              fd_stem_context_t *      stem        FD_PARAM_UNUSED,
              int *                    opt_poll_in FD_PARAM_UNUSED,
              int *                    charge_busy FD_PARAM_UNUSED ) {
    


  ulong is_constipated = fd_fseq_query( ctx->is_constipated );

  if( FD_UNLIKELY( is_constipated ) ) {

    if( FD_UNLIKELY( !ctx->activated ) ) {
      ctx->funk = fd_funk_open_file(
        "/data/ibhatt/funkfile", 1, 0, 0, 0, 0, FD_FUNK_READ_WRITE, NULL );
      if( ctx->funk == NULL ) {
        FD_LOG_ERR(( "failed to join a funky" ));
      }
      ctx->activated = 1;

      FD_LOG_WARNING(("JUST JOINED SNAPSHOT FUNK"));
    }

    ulong is_incremental = fd_snapshot_create_get_is_incremental( is_constipated );
    ulong snapshot_slot  = fd_snapshot_create_get_slot( is_constipated );

    if( ctx->last_full_snap != 0UL && !is_incremental ) {
      FD_LOG_ERR(("SUCCESSUFL EXIT"));
    }

    if( !is_incremental ) {
      ctx->last_full_snap = snapshot_slot;
    }
    
    FD_LOG_WARNING(("CREATING SNAPSHOT incremental=%lu %lu", is_incremental, snapshot_slot));

    uchar * mem = fd_valloc_malloc( fd_scratch_virtual(), FD_ACC_MGR_ALIGN, FD_ACC_MGR_FOOTPRINT );

    fd_snapshot_ctx_t snapshot_ctx = {
      .slot           = snapshot_slot,
      .out_dir        = ctx->out_dir,
      .is_incremental = (uchar)is_incremental,
      .valloc         = fd_scratch_virtual(),
      .acc_mgr        = fd_acc_mgr_new( mem, ctx->funk ),
      .status_cache   = ctx->status_cache,
      .tmp_fd         = is_incremental ? ctx->tmp_inc_fd              : ctx->tmp_fd,
      .snapshot_fd    = is_incremental ? ctx->incremental_snapshot_fd : ctx->full_snapshot_fd,
      .tpool          = ctx->tpool,
      .last_snap_slot = is_incremental ? ctx->last_full_snap : 0UL,
      .last_snap_hash = &ctx->last_hash,
      .last_snap_capitalization = ctx->last_capitalization
    };

    if( !is_incremental ) {
      ctx->last_full_snap = snapshot_slot;
    }

    /* If this isn't the first snapshot that this tile is creating, the
       permissions should be made to not acessible by users and should be
       renamed to the constant file that is expected. */

    char prev_filename[ FD_SNAPSHOT_DIR_MAX ];
    snprintf( prev_filename, FD_SNAPSHOT_DIR_MAX, "/proc/self/fd/%d", is_incremental ? ctx->incremental_snapshot_fd : ctx->full_snapshot_fd );
    char temp_filename[FD_SNAPSHOT_DIR_MAX]; // Temporary buffer for the path
    long len = readlink(prev_filename, temp_filename, FD_SNAPSHOT_DIR_MAX);
    if( FD_UNLIKELY( len<=0L ) ) {
      FD_LOG_ERR(( "Failed to readlink the snapshot file" ));
    }
    prev_filename[ len ] = '\0';

    char new_filename[ FD_SNAPSHOT_DIR_MAX ];
    snprintf( new_filename, FD_SNAPSHOT_DIR_MAX, "%s/%s", ctx->out_dir, is_incremental ? FD_SNAPSHOT_TMP_INCR_ARCHIVE_ZSTD : FD_SNAPSHOT_TMP_FULL_ARCHIVE_ZSTD );

    rename( temp_filename, new_filename );
    FD_LOG_WARNING(("PREV FILENAME %s %s", temp_filename, new_filename ));

    int err = ftruncate( snapshot_ctx.tmp_fd, 0UL );
    FD_TEST( err!=-1 );
    lseek( snapshot_ctx.tmp_fd, 0UL, SEEK_SET );

    if( FD_UNLIKELY( fd_snapshot_create_new_snapshot( &snapshot_ctx, &ctx->last_hash, &ctx->last_capitalization ) ) ) {
      FD_LOG_ERR(( "Failed to create a new snapshot" ));
    }

    if( is_incremental ) {
      FD_LOG_ERR(("ASDF"));
    }

    FD_LOG_NOTICE(( "Done creating a snapshot" ));

    fd_fseq_update( ctx->is_constipated, 0UL );

  }

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
  (void)tile;

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
