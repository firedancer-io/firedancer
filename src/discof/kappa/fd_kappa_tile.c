#define _GNU_SOURCE  /* Enable GNU and POSIX extensions */

#include "../../disco/topo/fd_topo.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <sys/socket.h>
#include <linux/if_xdp.h>
#include "generated/fd_kappa_tile_seccomp.h"

/* This is starting to look pretty similar to the archiver writer/feeder,
   but the end goal of this is to plug into the UI, so its chill . */

#define FD_ARCHIVER_WRITER_ALLOC_TAG   (3UL)
#define FD_ARCHIVER_WRITER_OUT_BUF_SZ  (4096UL)  /* My local filesystem block size */

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_capture_in_ctx_t;

struct fd_capture_tile_ctx {
  fd_capture_in_ctx_t in[ 32 ];

  ulong now;
  ulong  last_packet_ns;
  double tick_per_ns;

  fd_io_buffered_ostream_t shred_ostream;
  fd_io_buffered_ostream_t repair_ostream;

  int  shreds_fd;
  int  repairs_fd;

  uchar shred_buf[FD_ARCHIVER_WRITER_OUT_BUF_SZ];
  uchar repair_buf[FD_ARCHIVER_WRITER_OUT_BUF_SZ];
};
typedef struct fd_capture_tile_ctx fd_capture_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 1UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  populate_sock_filter_policy_fd_kappa_tile( out_cnt,
                                             out,
                                             (uint)fd_log_private_logfile_fd(),
                                             tile->kappa.shreds_fd,
                                             tile->kappa.requests_fd );
  return sock_filter_policy_fd_kappa_tile_instr_cnt;
}


FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_capture_tile_ctx_t), sizeof(fd_capture_tile_ctx_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
during_frag( fd_capture_tile_ctx_t * ctx,
             ulong                   in_idx,
             ulong                   seq     FD_PARAM_UNUSED,
             ulong                   sig     FD_PARAM_UNUSED,
             ulong                   chunk,
             ulong                   sz,
             ulong                   ctl FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));
  }
}

static inline void
after_frag( fd_capture_tile_ctx_t * ctx,
            ulong                   in_idx FD_PARAM_UNUSED,
            ulong                   seq    FD_PARAM_UNUSED,
            ulong                   sig    FD_PARAM_UNUSED,
            ulong                   sz,
            ulong                   tsorig FD_PARAM_UNUSED,
            ulong                   tspub  FD_PARAM_UNUSED,
            fd_stem_context_t *     stem   FD_PARAM_UNUSED ) {
  (void)in_idx;
  (void)ctx;
  (void)sz;
  /* Write frag to file */
  //int err = fd_io_buffered_ostream_write( &ctx->shred_ostream, ctx->frag_buf, sz );
  //if( FD_UNLIKELY( err != 0 ) ) {
  //  FD_LOG_WARNING(( "failed to write %lu bytes to output buffer. error: %d", sz, err ));
  //}
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)out_fds_cnt;

  ulong out_cnt = 0UL;

  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  if( FD_LIKELY( -1!=tile->kappa.shreds_fd ) )
    out_fds[ out_cnt++ ] = tile->kappa.shreds_fd; /* shred file */
  if( FD_LIKELY( -1!=tile->kappa.requests_fd ) )
    out_fds[ out_cnt++ ] = tile->kappa.requests_fd; /* request file */

  return out_cnt;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  (void)topo;
  char file_path[PATH_MAX];
  strcpy( file_path, tile->kappa.dump_path );
  strcat( file_path, "/shred_data.csv" );
  tile->kappa.shreds_fd = open( file_path, O_RDWR | O_CREAT | O_DIRECT, 0666 );

  if ( FD_UNLIKELY( tile->kappa.shreds_fd == -1 ) ) {
    FD_LOG_ERR(( "failed to open or create shred csv dump file %s %d %s", file_path, errno, strerror(errno) ));
  }

  strcpy( file_path, tile->kappa.dump_path );
  strcat( file_path, "/request_data.csv" );
  tile->kappa.requests_fd = open( file_path, O_RDWR | O_CREAT | O_DIRECT, 0666 );
  if ( FD_UNLIKELY( tile->kappa.requests_fd == -1 ) ) {
    FD_LOG_ERR(( "failed to open or create request csv dump file %s %d %s", file_path, errno, strerror(errno) ));
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_capture_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_capture_tile_ctx_t), sizeof(fd_capture_tile_ctx_t) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  /* Setup the csv files to be in the expected state */

  int err = ftruncate( tile->kappa.shreds_fd, 0UL );
  if( FD_UNLIKELY( err==-1 ) ) {
    FD_LOG_ERR(( "failed to truncate the shred file (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  long seek = lseek( tile->kappa.shreds_fd, 0UL, SEEK_SET );
  if( FD_UNLIKELY( seek!=0L ) ) {
    FD_LOG_ERR(( "failed to seek to the beginning of the shred file" ));
  }

  err = ftruncate( tile->kappa.requests_fd, 0UL );
  if( FD_UNLIKELY( err==-1 ) ) {
    FD_LOG_ERR(( "failed to truncate the shred file (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  seek = lseek( tile->kappa.requests_fd, 0UL, SEEK_SET );
  if( FD_UNLIKELY( seek!=0L ) ) {
    FD_LOG_ERR(( "failed to seek to the beginning of the shred file" ));
  }

  /* Input links */
  for( ulong i=0; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
  }

  /* Initialize output stream */
  if( FD_UNLIKELY( !fd_io_buffered_ostream_init(
    &ctx->shred_ostream,
    tile->kappa.shreds_fd,
    ctx->shred_buf,
    FD_ARCHIVER_WRITER_OUT_BUF_SZ ) ) ) {
    FD_LOG_ERR(( "failed to initialize ostream" ));
  }
  if( FD_UNLIKELY( !fd_io_buffered_ostream_init(
    &ctx->repair_ostream,
    tile->kappa.requests_fd,
    ctx->repair_buf,
    FD_ARCHIVER_WRITER_OUT_BUF_SZ ) ) ) {
    FD_LOG_ERR(( "failed to initialize ostream" ));
  }
}

#define STEM_BURST (1UL)
#define STEM_LAZY  (50UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_capture_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_capture_tile_ctx_t)

#define STEM_CALLBACK_DURING_FRAG          during_frag
#define STEM_CALLBACK_AFTER_FRAG           after_frag
#define STEM_CALLBACK_DURING_HOUSEKEEPING  during_housekeeping

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_kappa = {
  .name                     = "kappa",
  .loose_footprint          = loose_footprint,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
