#include "../../../../disco/tiles.h"

#include "fd_archiver.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <sys/socket.h>
#include <linux/if_xdp.h>
#include "generated/archiver_playback_seccomp.h"

#define NET_SHRED_OUT_IDX   (0UL)
#define QUIC_VERIFY_OUT_IDX (1UL)
#define NET_GOSSIP_OUT_IDX  (2UL)
#define NET_REPAIR_OUT_IDX  (3UL)

#define FD_ARCHIVER_PLAYBACK_ALLOC_TAG   (3UL)
#define FD_ARCHIVER_PLAYBACK_READ_BUF_SZ (10240UL)

struct fd_archiver_playback_stats {
  ulong net_shred_out_cnt;
  ulong quic_verify_out_cnt;
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
  void * read_buf;
  fd_io_buffered_istream_t archive_istream;

  fd_archiver_playback_stats_t stats;

  double tick_per_ns;

  fd_alloc_t * alloc;
  fd_valloc_t  valloc;

  long start_tile_ts_ns;
  long start_archive_frag_ts_ns;

  ulong pending_publish_link_idx;
  fd_archiver_frag_header_t pending_publish_header;

  fd_archiver_playback_out_ctx_t out[ 32 ];
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
  (void)tile;

  populate_sock_filter_policy_archiver_playback( out_cnt,
                                                 out,
                                                 (uint)fd_log_private_logfile_fd(),
                                                 (uint)tile->archiver.archive_fd );
  return sock_filter_policy_archiver_playback_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;
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
  l = FD_LAYOUT_APPEND( l, alignof(fd_archiver_playback_tile_ctx_t), sizeof(fd_archiver_playback_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
    (void)topo;
    (void)tile;

    void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

    FD_SCRATCH_ALLOC_INIT( l, scratch );
    fd_archiver_playback_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_archiver_playback_tile_ctx_t), sizeof(fd_archiver_playback_tile_ctx_t) ); 
    memset( ctx, 0, sizeof(fd_archiver_playback_tile_ctx_t) );
    FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
    FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

    tile->archiver.archive_fd = open( tile->archiver.archive_path, O_RDONLY, 0666 );
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
  void * alloc_shmem                  = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  ctx->tick_per_ns = fd_tempo_tick_per_ns( NULL );

  /* Setup output links */
  for( ulong i=0; i<tile->out_cnt; i++ ) {
    fd_topo_link_t * link      = &topo->links[ tile->out_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->out[ i ].mem    = link_wksp->wksp;
    ctx->out[ i ].chunk0 = fd_dcache_compact_chunk0( link_wksp->wksp, link->dcache );
    ctx->out[ i ].wmark  = fd_dcache_compact_wmark( link_wksp->wksp, link->dcache, link->mtu );
    ctx->out[ i ].chunk  = ctx->out[ i ].chunk0;
  }

  /* Allocator */
  ctx->alloc = fd_alloc_join( fd_alloc_new( alloc_shmem, FD_ARCHIVER_PLAYBACK_ALLOC_TAG ), fd_tile_idx() );
  if( FD_UNLIKELY( !ctx->alloc ) ) {
    FD_LOG_ERR( ( "fd_alloc_join failed" ) );
  }
  ctx->valloc = fd_alloc_virtual( ctx->alloc );

  /* Allocate output buffer */
  ctx->read_buf = fd_valloc_malloc( ctx->valloc, 1UL, FD_ARCHIVER_PLAYBACK_READ_BUF_SZ );
  if( FD_UNLIKELY( !ctx->read_buf ) ) {
    FD_LOG_ERR(( "failed to allocate read buffer" ));
  }

  /* Initialize output stream */
  if( FD_UNLIKELY( !fd_io_buffered_istream_init( 
    &ctx->archive_istream,
    tile->archiver.archive_fd,
    ctx->read_buf,
    FD_ARCHIVER_PLAYBACK_READ_BUF_SZ ) ) ) {
    FD_LOG_ERR(( "failed to initialize istream" ));
  }

}

static inline long 
now( fd_archiver_playback_tile_ctx_t * ctx ) {
  return (long)(((double)fd_tickcount()) / ctx->tick_per_ns);
}

static inline int
should_delay_publish( fd_archiver_playback_tile_ctx_t * ctx ) {
  if( FD_UNLIKELY(( ctx->start_tile_ts_ns == 0L )) ) {
    return 0;
  }

  long relative_tile_ts         = now( ctx ) - ctx->start_tile_ts_ns; /* FIXME: read timestamp out of archive file first? don't rely on this */
  long relative_archive_frag_ts = ctx->pending_publish_header.timestamp - ctx->start_archive_frag_ts_ns;

  /* TODO: maybe have some tolerance here? */
  return relative_tile_ts < relative_archive_frag_ts;
}

static inline void
publish( fd_archiver_playback_tile_ctx_t * ctx,
         fd_stem_context_t *               stem ) {
  /* Publish the pending fragment */
  fd_stem_publish( stem, ctx->pending_publish_link_idx, ctx->pending_publish_header.sig, ctx->out[ ctx->pending_publish_link_idx ].chunk, ctx->pending_publish_header.sz, 0UL, 0UL, 0UL);
  ctx->out[ ctx->pending_publish_link_idx ].chunk = fd_dcache_compact_next( ctx->out[ ctx->pending_publish_link_idx ].chunk,
                                                                               ctx->pending_publish_header.sz,
                                                                           ctx->out[ ctx->pending_publish_link_idx ].chunk0,
                                                                            ctx->out[ ctx->pending_publish_link_idx ].wmark );

  /* Reset the state */
  memset( &ctx->pending_publish_header, 0, FD_ARCHIVER_FRAG_HEADER_FOOTPRINT );
}
 
static inline void
after_credit( fd_archiver_playback_tile_ctx_t *     ctx,
              fd_stem_context_t *                   stem,
              int *                                 opt_poll_in,
              int *                                 charge_busy ) {
  (void)ctx;
  (void)stem;
  (void)opt_poll_in;
  (void)charge_busy;

  /* Check to see if we have a pending frag ready to publish */
  if( FD_LIKELY(( ctx->pending_publish_header.timestamp )) ) {
    /* If we should delay, do not consume any more fragments from the archive but instead return */
    if( FD_UNLIKELY( should_delay_publish( ctx ) )) {
      return;
    } else {
      /* If we have caught up, publish the fragment */
      publish( ctx, stem );
    }
  }

  /* Consume the header, to determine which output link to send the fragment on. */
  int fetch_err = fd_io_buffered_istream_fetch( &ctx->archive_istream );
  if( FD_UNLIKELY( fetch_err<0 ) ) {
    /* Hit EOF, nothing more to do */
    /* TODO: gracefully shut down validator in this case? */
    FD_LOG_WARNING(( "playback_stats net_shred_out_cnt=%lu, quic_verify_out_cnt=%lu, net_gossip_out_cnt=%lu, net_repair_out_cnt=%lu", ctx->stats.net_shred_out_cnt, ctx->stats.quic_verify_out_cnt, ctx->stats.net_gossip_out_cnt, ctx->stats.net_repair_out_cnt ));
    FD_LOG_ERR(( "EOF" ));
    return;
  } else if( FD_UNLIKELY( fetch_err>0 ) ) {
    FD_LOG_WARNING(( "playback_stats net_shred_out_cnt=%lu, quic_verify_out_cnt=%lu, net_gossip_out_cnt=%lu, net_repair_out_cnt=%lu", ctx->stats.net_shred_out_cnt, ctx->stats.quic_verify_out_cnt, ctx->stats.net_gossip_out_cnt, ctx->stats.net_repair_out_cnt ));
    FD_LOG_ERR(( "failed to fetch" ));
    return;
  }
  ulong peek_sz = fd_io_buffered_istream_peek_sz( &ctx->archive_istream );
  if( FD_UNLIKELY(( peek_sz < FD_ARCHIVER_FRAG_HEADER_FOOTPRINT )) ) {
    return;
  }
  char const * peek_header = fd_io_buffered_istream_peek( &ctx->archive_istream );
  if( FD_UNLIKELY(( !peek_header )) ) {
    FD_LOG_ERR(( "failed to peek header" ));
  }
  fd_memcpy( &ctx->pending_publish_header, peek_header, FD_ARCHIVER_FRAG_HEADER_FOOTPRINT );
  fd_io_buffered_istream_seek( &ctx->archive_istream, FD_ARCHIVER_FRAG_HEADER_FOOTPRINT );

  /* Sanity-check the header */
  if( FD_UNLIKELY(( ctx->pending_publish_header.magic != FD_ARCHIVER_HEADER_MAGIC )) ) {
    FD_LOG_WARNING(( "stats: net_shred_out_cnt=%lu, quic_verify_out_cnt=%lu, net_gossip_out_cnt=%lu, net_repair_out_cnt=%lu", ctx->stats.net_shred_out_cnt, ctx->stats.quic_verify_out_cnt, ctx->stats.net_gossip_out_cnt, ctx->stats.net_repair_out_cnt ));
    FD_LOG_ERR(( "bad magic: %lu", ctx->pending_publish_header.magic ));
  }
  if( FD_UNLIKELY(( ctx->start_tile_ts_ns == 0UL )) ) {
    ctx->start_tile_ts_ns         = now( ctx );
    ctx->start_archive_frag_ts_ns = ctx->pending_publish_header.timestamp;
  }

  /* Determine the output link on which to send the frag */
  ulong out_link_idx = 0UL;
  switch ( ctx->pending_publish_header.tile_id ) {
    case FD_ARCHIVER_TILE_ID_SHRED:
    out_link_idx = NET_SHRED_OUT_IDX;
    ctx->stats.net_shred_out_cnt += 1;
    break;
    case FD_ARCHIVER_TILE_ID_VERIFY:
    out_link_idx = QUIC_VERIFY_OUT_IDX;
    ctx->stats.quic_verify_out_cnt += 1;
    break;
    case FD_ARCHIVER_TILE_ID_GOSSIP:
    out_link_idx = NET_GOSSIP_OUT_IDX;
    ctx->stats.net_gossip_out_cnt += 1;
    break;
    case FD_ARCHIVER_TILE_ID_REPAIR:
    out_link_idx = NET_REPAIR_OUT_IDX;
    ctx->stats.net_repair_out_cnt += 1;
    break;
    default:
    FD_LOG_ERR(( "unsupported tile id" ));
  }

  /* Copy the frag into the output link */
  peek_sz = fd_io_buffered_istream_peek_sz( &ctx->archive_istream );
  if( FD_UNLIKELY(( peek_sz < ctx->pending_publish_header.sz )) ) {
    FD_LOG_ERR(( "frag too small in archive, possibly corrupt archive" ));
  }
  char const * peek_frag = fd_io_buffered_istream_peek( &ctx->archive_istream );
  if( FD_UNLIKELY(( !peek_frag )) ) {
    FD_LOG_ERR(( "failed to peek frag" ));
  }
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out[ out_link_idx ].mem, ctx->out[ out_link_idx ].chunk );
  fd_memcpy( dst, peek_frag, ctx->pending_publish_header.sz );
  fd_io_buffered_istream_seek( &ctx->archive_istream, ctx->pending_publish_header.sz );
  ctx->pending_publish_link_idx = out_link_idx;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_archiver_playback_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_archiver_playback_tile_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT        after_credit

#include "../../../../disco/stem/fd_stem.c"

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
