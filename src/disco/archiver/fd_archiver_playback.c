#define _GNU_SOURCE  /* Enable GNU and POSIX extensions */

#include "../tiles.h"

#include "fd_archiver.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <sys/socket.h>
#include <linux/if_xdp.h>
#include "generated/archiver_playback_seccomp.h"

/* The archiver playback tile consumes from the archive file, adds artificial delay
to reproduce exactly the timing from the capture, and forwards these fragments to the
receiver tiles (shred/quic/gossip/repair).

There should be a single archiver playback tile, and it should replace the input links to the
receiver tiles.
*/

#define NET_SHRED_OUT_IDX  (0UL)
#define NET_QUIC_OUT_IDX   (1UL)
#define NET_GOSSIP_OUT_IDX (2UL)
#define NET_REPAIR_OUT_IDX (3UL)

#define FD_ARCHIVER_PLAYBACK_ALLOC_TAG   (3UL)

#define FD_ARCHIVER_STARTUP_DELAY_SECONDS (1)
#define FD_ARCHIVE_PLAYBACK_BUFFER_SZ      (FD_SHMEM_GIGANTIC_PAGE_SZ)

struct fd_archiver_playback_stats {
  ulong net_shred_out_cnt;
  ulong net_quic_out_cnt;
  ulong net_gossip_out_cnt;
  ulong net_repair_out_cnt;

};
typedef struct fd_archiver_playback_stats fd_archiver_playback_stats_t;

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
} fd_archiver_playback_out_ctx_t;

struct fd_archiver_playback_tile_ctx {
  fd_io_buffered_istream_t istream;
  uchar *                  istream_buf;

  fd_archiver_playback_stats_t stats;

  double tick_per_ns;

  ulong prev_publish_time;
  ulong now;

  fd_archiver_playback_out_ctx_t out[ 32 ];

  fd_alloc_t * alloc;
  fd_valloc_t  valloc;
};
typedef struct fd_archiver_playback_tile_ctx fd_archiver_playback_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 1UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;

  populate_sock_filter_policy_archiver_playback( out_cnt,
                                                 out,
                                                 (uint)fd_log_private_logfile_fd(),
                                                 (uint)tile->archiver.archive_fd );
  return sock_filter_policy_archiver_playback_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo        FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt FD_PARAM_UNUSED,
                      int *                  out_fds ) {
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
  l = FD_LAYOUT_APPEND( l, alignof(fd_archiver_playback_tile_ctx_t), sizeof(fd_archiver_playback_tile_ctx_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
    void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

    FD_SCRATCH_ALLOC_INIT( l, scratch );
    fd_archiver_playback_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_archiver_playback_tile_ctx_t), sizeof(fd_archiver_playback_tile_ctx_t) );
    memset( ctx, 0, sizeof(fd_archiver_playback_tile_ctx_t) );
    FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
    FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

    tile->archiver.archive_fd = open( tile->archiver.archive_path, O_RDONLY | O_DIRECT, 0666 );
    if ( FD_UNLIKELY( tile->archiver.archive_fd == -1 ) ) {
      FD_LOG_ERR(( "failed to open archive file %s %d %d %s", tile->archiver.archive_path, tile->archiver.archive_fd, errno, strerror(errno) ));
    }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_archiver_playback_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_archiver_playback_tile_ctx_t), sizeof(fd_archiver_playback_tile_ctx_t) );
  void * alloc_shmem                    = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  ctx->tick_per_ns = fd_tempo_tick_per_ns( NULL );

  /* Allocator */
  ctx->alloc = fd_alloc_join( fd_alloc_new( alloc_shmem, FD_ARCHIVER_PLAYBACK_ALLOC_TAG ), fd_tile_idx() );
  if( FD_UNLIKELY( !ctx->alloc ) ) {
    FD_LOG_ERR( ( "fd_alloc_join failed" ) );
  }
  ctx->valloc = fd_alloc_virtual( ctx->alloc );

  /* Allocate output buffer */
  ctx->istream_buf = fd_valloc_malloc( ctx->valloc, 4096, FD_ARCHIVE_PLAYBACK_BUFFER_SZ );
  if( FD_UNLIKELY( !ctx->istream_buf ) ) {
    FD_LOG_ERR(( "failed to allocate input buffer" ));
  }

  /* initialize the file reader */
  fd_io_buffered_istream_init( &ctx->istream, tile->archiver.archive_fd, ctx->istream_buf, FD_ARCHIVE_PLAYBACK_BUFFER_SZ );

  /* perform the initial read */
  if( FD_UNLIKELY(( !fd_io_buffered_istream_fetch( &ctx->istream ) )) ) {
    FD_LOG_WARNING(( "failed initial read" ));
  }

  /* Setup output links */
  for( ulong i=0; i<tile->out_cnt; i++ ) {
    fd_topo_link_t * link      = &topo->links[ tile->out_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->out[ i ].mem    = link_wksp->wksp;
    ctx->out[ i ].chunk0 = fd_dcache_compact_chunk0( link_wksp->wksp, link->dcache );
    ctx->out[ i ].wmark  = fd_dcache_compact_wmark( link_wksp->wksp, link->dcache, link->mtu );
    ctx->out[ i ].chunk  = ctx->out[ i ].chunk0;
  }
}

static void
during_housekeeping( fd_archiver_playback_tile_ctx_t * ctx ) {
  ctx->now =(ulong)((double)(fd_tickcount()) / ctx->tick_per_ns);
}

static inline void
after_credit( fd_archiver_playback_tile_ctx_t *     ctx,
              fd_stem_context_t *                   stem,
              int *                                 opt_poll_in FD_PARAM_UNUSED,
              int *                                 charge_busy FD_PARAM_UNUSED ) {
  /* Peek the header without consuming anything, to see if we need to wait */
  char const * peek = fd_io_buffered_istream_peek( &ctx->istream );
  if( FD_UNLIKELY(( !peek )) ) {
    FD_LOG_ERR(( "failed to peek" ));
  }

  /* Consume the header */
  fd_archiver_frag_header_t * header = fd_type_pun( (char *)peek );
  if( FD_UNLIKELY( header->magic != FD_ARCHIVER_HEADER_MAGIC ) ) {
    FD_LOG_ERR(( "bad magic in archive header: %lu", header->magic ));
  }

  /* Determine if we should wait before publishing this */
  /* need to delay if now > (when we should publish it)  */
  if( ctx->prev_publish_time != 0UL &&
    ( ctx->now < ( ctx->prev_publish_time + header->ns_since_prev_fragment - 500000000 ) )) {
    return;
  }

  /* Determine the output link on which to send the frag */
  ulong out_link_idx = 0UL;
  switch ( header->tile_id ) {
    case FD_ARCHIVER_TILE_ID_SHRED:
    out_link_idx = NET_SHRED_OUT_IDX;
    break;
    case FD_ARCHIVER_TILE_ID_QUIC:
    out_link_idx = NET_QUIC_OUT_IDX;
    break;
    case FD_ARCHIVER_TILE_ID_GOSSIP:
    out_link_idx = NET_GOSSIP_OUT_IDX;
    break;
    case FD_ARCHIVER_TILE_ID_REPAIR:
    out_link_idx = NET_REPAIR_OUT_IDX;
    break;
    default:
    FD_LOG_ERR(( "unsupported tile id" ));
  }

  /* Consume the header from the stream */
  fd_archiver_frag_header_t header_tmp;
  if( FD_UNLIKELY( fd_io_buffered_istream_read( &ctx->istream, &header_tmp, FD_ARCHIVER_FRAG_HEADER_FOOTPRINT ) )) {
    FD_LOG_ERR(( "failed to consume header" ));
  }

  /* Consume the fragment from the stream */
  uchar       * dst      = (uchar *)fd_chunk_to_laddr( ctx->out[ out_link_idx ].mem, ctx->out[ out_link_idx ].chunk );
  fd_io_buffered_istream_read( &ctx->istream, dst, header_tmp.sz );

  fd_stem_publish( stem, out_link_idx, header->sig, ctx->out[ out_link_idx ].chunk, header->sz, 0UL, 0UL, 0UL);
  ctx->out[ out_link_idx ].chunk = fd_dcache_compact_next( ctx->out[ out_link_idx ].chunk,
                                                                            header->sz,
                                                                        ctx->out[ out_link_idx ].chunk0,
                                                                        ctx->out[ out_link_idx ].wmark );
  ctx->prev_publish_time = ctx->now;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  (50UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_archiver_playback_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_archiver_playback_tile_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping

#include "../stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_archiver_playback = {
  .name                     = "arch_p",
  .loose_footprint          = loose_footprint,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
