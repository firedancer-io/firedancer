#define _GNU_SOURCE
#include "utils/fd_ssarchive.h"
#include "utils/fd_ssctrl.h"
#include "utils/fd_sshttp.h"

#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../waltz/openssl/fd_openssl_tile.h"

#include <sys/mman.h> /* memfd_create */
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>

#include "generated/fd_snapld_tile_seccomp.h"

#define NAME "snapld"

/* The snapld tile is responsible for loading data from the local file
   or from an HTTP/TCP connection and sending it to the snapdc tile
   for later decompression. */

typedef struct fd_snapld_tile {

  struct {
    char path[ PATH_MAX ];
    uint min_download_speed_mibs;
  } config;

  int   state;
  ulong pending_ctrl_sig;
  int   load_full;
  int   load_file;
  int   sent_meta;

  ulong  bytes_in_batch;
  double download_speed_mibs;
  long   start_batch;
  long   end_batch;

  int local_full_fd;
  int local_incr_fd;
  int sockfd;

  int is_https;

  fd_sshttp_t * sshttp;

  struct {
    void const * base;
  } in_rd;

  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       chunk;
    ulong       mtu;
  } out_dc;

} fd_snapld_tile_t;

static ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_snapld_tile_t), fd_sshttp_align() );
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND(  l, alignof(fd_snapld_tile_t),  sizeof(fd_snapld_tile_t) );
  l = FD_LAYOUT_APPEND(  l, fd_sshttp_align(),          fd_sshttp_footprint()    );
  l = FD_LAYOUT_APPEND(  l, fd_alloc_align(),           fd_alloc_footprint()     );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline ulong
loose_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  /* Leftover space for OpenSSL allocations */
  return 1UL<<26UL; /* 64 MiB */
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapld_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapld_tile_t), sizeof(fd_snapld_tile_t) );
  void * _sshttp         = FD_SCRATCH_ALLOC_APPEND( l, fd_sshttp_align(),          fd_sshttp_footprint()    );

#if FD_HAS_OPENSSL
  void * _alloc = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( _alloc, 1UL ), tile->kind_id );
  fd_ossl_tile_init( alloc );
#endif

  ctx->sshttp = fd_sshttp_join( fd_sshttp_new( _sshttp ) );
  FD_TEST( ctx->sshttp );

  /* FIXME: Allow incremental_snapshots=0 config */
  ulong full_slot = ULONG_MAX;
  ulong incr_slot = ULONG_MAX;
  int full_is_zstd = 0;
  int incr_is_zstd = 0;
  char full_path[ PATH_MAX ] = { 0 };
  char incr_path[ PATH_MAX ] = { 0 };
  ctx->local_full_fd = -1;
  ctx->local_incr_fd = -1;
  if( FD_LIKELY( -1!=fd_ssarchive_latest_pair( tile->snapld.snapshots_path, 1,
                                               &full_slot,    &incr_slot,
                                                full_path,     incr_path,
                                               &full_is_zstd, &incr_is_zstd ) ) ) {
    FD_TEST( full_slot!=ULONG_MAX );

    ctx->local_full_fd = open( full_path, O_RDONLY|O_CLOEXEC|O_NONBLOCK );
    if( FD_UNLIKELY( -1==ctx->local_full_fd ) ) FD_LOG_ERR(( "open() failed `%s` (%i-%s)", full_path, errno, fd_io_strerror( errno ) ));

    if( FD_LIKELY( incr_slot!=ULONG_MAX ) ) {
      ctx->local_incr_fd = open( incr_path, O_RDONLY|O_CLOEXEC|O_NONBLOCK );
      if( FD_UNLIKELY( -1==ctx->local_incr_fd ) ) FD_LOG_ERR(( "open() failed `%s` (%i-%s)", incr_path, errno, fd_io_strerror( errno ) ));
    }
  }

  /* Create a temporary file descriptor for our socket file descriptor.
     It is closed later in unprivileged init so that the sandbox sees
     an existent file descriptor. */
  ctx->sockfd = memfd_create( "snapld.sockfd", 0 );
  if( FD_UNLIKELY( -1==ctx->sockfd ) ) FD_LOG_ERR(( "memfd_create() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<4UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2UL; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) {
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd();
  }

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapld_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapld_tile_t), sizeof(fd_snapld_tile_t) );
  if( FD_LIKELY( -1!=ctx->local_full_fd ) ) out_fds[ out_cnt++ ] = ctx->local_full_fd;
  if( FD_LIKELY( -1!=ctx->local_incr_fd ) ) out_fds[ out_cnt++ ] = ctx->local_incr_fd;
  out_fds[ out_cnt++ ] = ctx->sockfd;

  return out_cnt;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapld_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapld_tile_t), sizeof(fd_snapld_tile_t) );

  populate_sock_filter_policy_fd_snapld_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->local_full_fd, (uint)ctx->local_incr_fd, (uint)ctx->sockfd );
  return sock_filter_policy_fd_snapld_tile_instr_cnt;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapld_tile_t * ctx  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapld_tile_t),  sizeof(fd_snapld_tile_t) );

  fd_memcpy( ctx->config.path, tile->snapld.snapshots_path, PATH_MAX );
  ctx->config.min_download_speed_mibs = tile->snapld.min_download_speed_mibs;

  ctx->state            = FD_SNAPSHOT_STATE_IDLE;
  ctx->pending_ctrl_sig = 0UL;

  ctx->download_speed_mibs = 0.0;
  ctx->bytes_in_batch      = 0UL;
  ctx->start_batch         = 0L;
  ctx->end_batch           = 0L;

  FD_TEST( tile->in_cnt==1UL );
  fd_topo_link_t const * in_link = &topo->links[ tile->in_link_id[ 0 ] ];
  FD_TEST( 0==strcmp( in_link->name, "snapct_ld" ) );
  ctx->in_rd.base = fd_topo_obj_wksp_base( topo, in_link->dcache_obj_id );

  FD_TEST( tile->out_cnt==1UL );
  fd_topo_link_t const * out_link = &topo->links[ tile->out_link_id[ 0 ] ];
  FD_TEST( 0==strcmp( out_link->name, "snapld_dc" ) );
  ctx->out_dc.mem    = fd_topo_obj_wksp_base( topo, out_link->dcache_obj_id );
  ctx->out_dc.chunk0 = fd_dcache_compact_chunk0( ctx->out_dc.mem, out_link->dcache );
  ctx->out_dc.wmark  = fd_dcache_compact_wmark ( ctx->out_dc.mem, out_link->dcache, out_link->mtu );
  ctx->out_dc.chunk  = ctx->out_dc.chunk0;
  ctx->out_dc.mtu    = out_link->mtu;

  /* We can only close the temporary socket file descriptor after
     entering the sandbox because the sandbox checks all file
     descriptors are existent. */
  if( -1==close( ctx->sockfd ) ) FD_LOG_ERR((" close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static int
should_shutdown( fd_snapld_tile_t * ctx ) {
  return ctx->state==FD_SNAPSHOT_STATE_SHUTDOWN;
}

static void
metrics_write( fd_snapld_tile_t * ctx ) {
#if FD_HAS_OPENSSL
  FD_MCNT_SET(   SNAPLD, SSL_ALLOC_ERRORS, fd_ossl_alloc_errors );
#endif
  FD_MGAUGE_SET( SNAPLD, STATE,            (ulong)(ctx->state) );
}

static void
transition_malformed( fd_snapld_tile_t *  ctx,
                      fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_ERROR ) ) return;
  ctx->state = FD_SNAPSHOT_STATE_ERROR;
  fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_ERROR, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static void
after_credit( fd_snapld_tile_t *  ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in FD_PARAM_UNUSED,
              int *               charge_busy ) {
  if( FD_UNLIKELY( ctx->pending_ctrl_sig ) ) {
    FD_TEST( !ctx->load_file && ctx->is_https );
    FD_TEST( ctx->pending_ctrl_sig==FD_SNAPSHOT_MSG_CTRL_NEXT ||
             ctx->pending_ctrl_sig==FD_SNAPSHOT_MSG_CTRL_DONE );
    if( ctx->state==FD_SNAPSHOT_STATE_FINISHING || ctx->state==FD_SNAPSHOT_STATE_ERROR ) {
      fd_stem_publish( stem, 0UL, ctx->pending_ctrl_sig, 0UL, 0UL, 0UL, 0UL, 0UL );
      ctx->pending_ctrl_sig = 0UL;
      if( ctx->state!=FD_SNAPSHOT_STATE_ERROR ) ctx->state = FD_SNAPSHOT_STATE_IDLE;
      return;
    } else FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING );
  }

  if( ctx->state!=FD_SNAPSHOT_STATE_PROCESSING ) {
    fd_log_sleep( (long)1e6 );
    return;
  }

  uchar * out = fd_chunk_to_laddr( ctx->out_dc.mem, ctx->out_dc.chunk );

  if( ctx->load_file ) {
    long result = read( ctx->load_full ? ctx->local_full_fd : ctx->local_incr_fd, out, ctx->out_dc.mtu );
    if( FD_UNLIKELY( result<=0L ) ) {
      if( result==0L ) ctx->state = FD_SNAPSHOT_STATE_FINISHING;
      else if( FD_UNLIKELY( errno!=EAGAIN && errno!=EINTR ) ) {
        FD_LOG_WARNING(( "read() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        ctx->state = FD_SNAPSHOT_STATE_ERROR;
        fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_ERROR, 0UL, 0UL, 0UL, 0UL, 0UL );
      }
    } else {
      fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_DATA, ctx->out_dc.chunk, (ulong)result, 0UL, 0UL, 0UL );
      ctx->out_dc.chunk = fd_dcache_compact_next( ctx->out_dc.chunk, (ulong)result, ctx->out_dc.chunk0, ctx->out_dc.wmark );
      *charge_busy = 1;
    }
  } else {
    ulong data_len = ctx->out_dc.mtu;
    int   result   = fd_sshttp_advance( ctx->sshttp, &data_len, out, fd_log_wallclock() );
    switch( result ) {
      case FD_SSHTTP_ADVANCE_AGAIN:
        break;
      case FD_SSHTTP_ADVANCE_DATA: {
        if( FD_UNLIKELY( !ctx->sent_meta ) ) {
          /* On the first DATA return, the HTTP headers are available
             for use.  We need to send this metadata downstream, but
             need to do so before any data frags.  So, we copy any data
             we received with the headers (if any) to the next dcache
             chunk and then publish both in order. */
          ctx->start_batch = fd_log_wallclock();
          ctx->sent_meta = 1;
          fd_ssctrl_meta_t * meta = (fd_ssctrl_meta_t *)out;
          ulong next_chunk = fd_dcache_compact_next( ctx->out_dc.chunk, sizeof(fd_ssctrl_meta_t), ctx->out_dc.chunk0, ctx->out_dc.wmark );
          memmove( fd_chunk_to_laddr( ctx->out_dc.mem, next_chunk ), out, data_len );
          meta->total_sz = fd_sshttp_content_len( ctx->sshttp );
          FD_TEST( meta->total_sz!=ULONG_MAX );
          fd_memcpy( meta->name, fd_sshttp_snapshot_name( ctx->sshttp ), PATH_MAX );
          fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_META, ctx->out_dc.chunk, sizeof(fd_ssctrl_meta_t), 0UL, 0UL, 0UL );
          ctx->out_dc.chunk = next_chunk;
        }
        if( FD_LIKELY( data_len!=0UL ) ) {
          fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_DATA, ctx->out_dc.chunk, data_len, 0UL, 0UL, 0UL );
          ctx->out_dc.chunk = fd_dcache_compact_next( ctx->out_dc.chunk, data_len, ctx->out_dc.chunk0, ctx->out_dc.wmark );
          ctx->bytes_in_batch += data_len;

          /* measure download speed every 100 MiB */
          if(ctx->bytes_in_batch>=100<<20UL) {
            ctx->end_batch = fd_log_wallclock();
            /* download speed in MiB/s = bytes/nanoseconds * 1e9/(1 second) * 1/(1MiB = 1<<20UL) = 1e9/(1024*1024) ~= 954 */
            ctx->download_speed_mibs = (double)(ctx->bytes_in_batch*954) / (double)(ctx->end_batch - ctx->start_batch);
            if( FD_UNLIKELY( ctx->download_speed_mibs<ctx->config.min_download_speed_mibs ) ) {
              /* cancel the snapshot load if the download speed is less
                 than the minimum download speed. */
              FD_LOG_WARNING(( "download speed %.2f MiB/s is below the minimum threshold %.2f MiB/s, cancelling snapshot download",
                               ctx->download_speed_mibs, (double)(ctx->config.min_download_speed_mibs) ));
              transition_malformed(ctx, stem );
            }
            ctx->start_batch    = ctx->end_batch;
            ctx->bytes_in_batch = 0UL;
          }
        }
        *charge_busy = 1;
        break;
      }
      case FD_SSHTTP_ADVANCE_DONE:
        ctx->state = FD_SNAPSHOT_STATE_FINISHING;
        break;
      case FD_SSHTTP_ADVANCE_ERROR:
        ctx->state = FD_SNAPSHOT_STATE_ERROR;
        fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_ERROR, 0UL, 0UL, 0UL, 0UL, 0UL );
        fd_sshttp_cancel( ctx->sshttp );
        break;
      default: FD_LOG_ERR(( "unexpected fd_sshttp_advance result %d", result ));
    }
  }
}

static int
returnable_frag( fd_snapld_tile_t *  ctx,
                 ulong               in_idx FD_PARAM_UNUSED,
                 ulong               seq    FD_PARAM_UNUSED,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl    FD_PARAM_UNUSED,
                 ulong               tsorig FD_PARAM_UNUSED,
                 ulong               tspub  FD_PARAM_UNUSED,
                 fd_stem_context_t * stem ) {
  FD_TEST( !ctx->pending_ctrl_sig );

  switch( sig ) {

    case FD_SNAPSHOT_MSG_CTRL_INIT_FULL:
    case FD_SNAPSHOT_MSG_CTRL_INIT_INCR: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      FD_TEST( sz==sizeof(fd_ssctrl_init_t) && sz<=ctx->out_dc.mtu );
      fd_ssctrl_init_t const * msg_in = fd_chunk_to_laddr_const( ctx->in_rd.base, chunk );
      ctx->load_full = sig==FD_SNAPSHOT_MSG_CTRL_INIT_FULL;
      ctx->load_file = msg_in->file;
      ctx->state = FD_SNAPSHOT_STATE_PROCESSING;
      ctx->sent_meta = 0;
      ctx->is_https = msg_in->is_https;
      if( ctx->load_file ) {
        if( FD_UNLIKELY( 0!=lseek( ctx->load_full ? ctx->local_full_fd : ctx->local_incr_fd, 0, SEEK_SET ) ) )
          FD_LOG_ERR(( "lseek(0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      } else {
        if( ctx->load_full ) fd_sshttp_init( ctx->sshttp, msg_in->addr, msg_in->hostname, msg_in->is_https, "/snapshot.tar.bz2", 17UL, fd_log_wallclock() );
        else                 fd_sshttp_init( ctx->sshttp, msg_in->addr, msg_in->hostname, msg_in->is_https, "/incremental-snapshot.tar.bz2", 29UL, fd_log_wallclock() );
      }
      fd_ssctrl_init_t * msg_out = fd_chunk_to_laddr( ctx->out_dc.mem, ctx->out_dc.chunk );
      fd_memcpy( msg_out, msg_in, sz );
      fd_stem_publish( stem, 0UL, sig, ctx->out_dc.chunk, sz, 0UL, 0UL, 0UL );
      ctx->out_dc.chunk = fd_dcache_compact_next( ctx->out_dc.chunk, ctx->out_dc.mtu, ctx->out_dc.chunk0, ctx->out_dc.wmark );
      return 0;
    }

    case FD_SNAPSHOT_MSG_CTRL_FAIL:
      FD_TEST( ctx->state!=FD_SNAPSHOT_MSG_CTRL_SHUTDOWN );
      fd_sshttp_cancel( ctx->sshttp );
      ctx->state = FD_SNAPSHOT_STATE_IDLE;
      break;

    case FD_SNAPSHOT_MSG_CTRL_NEXT:
    case FD_SNAPSHOT_MSG_CTRL_DONE:
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING ||
               ctx->state==FD_SNAPSHOT_STATE_FINISHING  ||
               ctx->state==FD_SNAPSHOT_STATE_ERROR );
      if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_PROCESSING ) ) {
        /* snapld should be in the finishing state when reading from a
           file or downloading from http.  It is only allowed to still
           be in progress for shutting down an https connection. Save
           the sig here and send the message when snapld is in the
           finishing state. */
        FD_TEST( ctx->is_https );
        ctx->pending_ctrl_sig = sig;
        return 0; /* return directly to avoid fowarding the message */
      }
      else if( FD_LIKELY( ctx->state==FD_SNAPSHOT_STATE_FINISHING ) ) {
        ctx->state = FD_SNAPSHOT_STATE_IDLE;
      }
      break;

    case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN:
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      ctx->state = FD_SNAPSHOT_STATE_SHUTDOWN;
      break;

    /* FD_SNAPSHOT_MSG_CTRL_ERROR and FD_SNAPSHOT_MSG_DATA are not possible */
    default: FD_LOG_ERR(( "invalid sig %lu", sig ));
  }

  /* Forward the control message down the pipeline */
  fd_stem_publish( stem, 0UL, sig, 0UL, 0UL, 0UL, 0UL, 0UL );

  return 0;
}

/* Up to one frag from after_credit plus one from returnable_frag */
#define STEM_BURST 2UL

#define STEM_LAZY 1000L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snapld_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snapld_tile_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snapld = {
  .name                     = NAME,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .loose_footprint          = loose_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
  .keep_host_networking     = 1,
  .allow_connect            = 1,
  .rlimit_file_cnt          = 5UL, /* stderr, log, http, full/incr local files */
};

#undef NAME
