#define _GNU_SOURCE  /* Enable GNU and POSIX extensions */

#include "../tiles.h"

#include "fd_archiver.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <sys/socket.h>
#include <linux/if_xdp.h>
#include "generated/archiver_writer_seccomp.h"

/* The archiver writer tile consumes from all input archiver feeder input links,
and writes these to the archive tile. It adds a timestamp to each fragment, so that
there is a total global order across the packets.

There should only ever be a single archiver writer tile. */

#define FD_ARCHIVER_WRITER_ALLOC_TAG   (3UL)
#define FD_ARCHIVER_WRITER_FRAG_BUF_SZ (4UL*FD_SHRED_STORE_MTU) /* MTU for shred_storei in fd_firedancer.c */
#define FD_ARCHIVER_WRITER_OUT_BUF_SZ  (FD_SHMEM_HUGE_PAGE_SZ)  /* Flush to the file system every 2MB */

struct fd_archiver_writer_stats {
  ulong net_shred_in_cnt;
  ulong net_repair_in_cnt;
};
typedef struct fd_archiver_writer_stats fd_archiver_writer_stats_t;

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_archiver_writer_in_ctx_t;

struct fd_archiver_writer_tile_ctx {
  void * out_buf;

  fd_archiver_writer_in_ctx_t in[ 32 ];

  fd_archiver_writer_stats_t stats;

  ulong now;
  ulong  last_packet_ns;
  double tick_per_ns;

  fd_io_buffered_ostream_t archive_ostream;

  uchar frag_buf[FD_ARCHIVER_WRITER_FRAG_BUF_SZ];
};
typedef struct fd_archiver_writer_tile_ctx fd_archiver_writer_tile_ctx_t;

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
  populate_sock_filter_policy_archiver_writer( out_cnt,
                                               out,
                                               (uint)fd_log_private_logfile_fd(),
                                               (uint)tile->archiver.archive_fd );
  return sock_filter_policy_archiver_writer_instr_cnt;
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
  if( FD_LIKELY( -1!=tile->archiver.archive_fd ) )
    out_fds[ out_cnt++ ] = tile->archiver.archive_fd; /* archive file */

  return out_cnt;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_archiver_writer_tile_ctx_t), sizeof(fd_archiver_writer_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, 4096, FD_ARCHIVER_WRITER_OUT_BUF_SZ );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
    void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

    FD_SCRATCH_ALLOC_INIT( l, scratch );
    fd_archiver_writer_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_archiver_writer_tile_ctx_t), sizeof(fd_archiver_writer_tile_ctx_t) );
    memset( ctx, 0, sizeof(fd_archiver_writer_tile_ctx_t) );
    ctx->out_buf = FD_SCRATCH_ALLOC_APPEND( l, 4096, FD_ARCHIVER_WRITER_OUT_BUF_SZ );
    FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

    tile->archiver.archive_fd = open( tile->archiver.rocksdb_path, O_RDWR | O_CREAT | O_DIRECT, 0666 );
    if ( FD_UNLIKELY( tile->archiver.archive_fd == -1 ) ) {
      FD_LOG_ERR(( "failed to open or create archive file %s %d %d %s", tile->archiver.rocksdb_path, tile->archiver.archive_fd, errno, strerror(errno) ));
    }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_archiver_writer_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_archiver_writer_tile_ctx_t), sizeof(fd_archiver_writer_tile_ctx_t) );
  ctx->out_buf = FD_SCRATCH_ALLOC_APPEND( l, 4096, FD_ARCHIVER_WRITER_OUT_BUF_SZ );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  /* Setup the archive tile to be in the expected state */
  int err = ftruncate( tile->archiver.archive_fd, 0UL );
  if( FD_UNLIKELY( err==-1 ) ) {
    FD_LOG_ERR(( "failed to truncate the archive file (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  long seek = lseek( tile->archiver.archive_fd, 0UL, SEEK_SET );
  if( FD_UNLIKELY( seek!=0L ) ) {
    FD_LOG_ERR(( "failed to seek to the beginning of the archive file" ));
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
    &ctx->archive_ostream,
    tile->archiver.archive_fd,
    ctx->out_buf,
    FD_ARCHIVER_WRITER_OUT_BUF_SZ ) ) ) {
    FD_LOG_ERR(( "failed to initialize ostream" ));
  }

  ctx->tick_per_ns = fd_tempo_tick_per_ns( NULL );
}

static void
during_housekeeping( fd_archiver_writer_tile_ctx_t * ctx ) {
  ctx->now =(ulong)((double)(fd_tickcount()) / ctx->tick_per_ns);
}

static inline void
during_frag( fd_archiver_writer_tile_ctx_t * ctx,
             ulong                           in_idx,
             ulong                           seq     FD_PARAM_UNUSED,
             ulong                           sig     FD_PARAM_UNUSED,
             ulong                           chunk,
             ulong                           sz,
             ulong                           ctl FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz<FD_ARCHIVER_FRAG_HEADER_FOOTPRINT ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));
  }

  /* Write the incoming fragment to the ostream */
  char * src = (char *)fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk );

  /* Update the timestamp of the fragment, so that we have a total ordering */
  fd_archiver_frag_header_t * header = fd_type_pun( src );
  FD_TEST(( header->magic == FD_ARCHIVER_HEADER_MAGIC ));

  /* Set the relative delay on the packet */
  ulong now_ns = ctx->now;
  if( ctx->last_packet_ns == 0UL ) {
    header->ns_since_prev_fragment = 0L;
  } else {
    header->ns_since_prev_fragment = now_ns - ctx->last_packet_ns;
  }
  ctx->last_packet_ns = now_ns;

  /* Copy fragment into buffer */
  fd_memcpy( ctx->frag_buf, src, sz );

  ctx->stats.net_shred_in_cnt   += header->tile_id == FD_ARCHIVER_TILE_ID_SHRED;
  ctx->stats.net_repair_in_cnt  += header->tile_id == FD_ARCHIVER_TILE_ID_REPAIR;
}

static inline void
after_frag( fd_archiver_writer_tile_ctx_t * ctx,
            ulong                           in_idx FD_PARAM_UNUSED,
            ulong                           seq    FD_PARAM_UNUSED,
            ulong                           sig    FD_PARAM_UNUSED,
            ulong                           sz,
            ulong                           tsorig FD_PARAM_UNUSED,
            ulong                           tspub  FD_PARAM_UNUSED,
            fd_stem_context_t *             stem   FD_PARAM_UNUSED ) {
  /* Write frag to file */
  int err = fd_io_buffered_ostream_write( &ctx->archive_ostream, ctx->frag_buf, sz );
  if( FD_UNLIKELY( err != 0 ) ) {
    FD_LOG_WARNING(( "failed to write %lu bytes to output buffer. error: %d", sz, err ));
  }
}

#define STEM_BURST (1UL)
#define STEM_LAZY  (50UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_archiver_writer_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_archiver_writer_tile_ctx_t)

#define STEM_CALLBACK_DURING_FRAG          during_frag
#define STEM_CALLBACK_AFTER_FRAG           after_frag
#define STEM_CALLBACK_DURING_HOUSEKEEPING  during_housekeeping

#include "../stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_archiver_writer = {
  .name                     = "arch_w",
  .loose_footprint          = loose_footprint,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
