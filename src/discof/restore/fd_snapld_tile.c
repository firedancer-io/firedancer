#define _GNU_SOURCE
#include "utils/fd_ssarchive.h"
#include "utils/fd_ssctrl.h"
#include "utils/fd_sshttp.h"
#include "utils/fd_sspeer_selector.h"

#include "../../disco/topo/fd_topo.h"
#include "../../disco/topo/fd_dns_resolve.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/waker/fd_waker.h"
#include "../../disco/fd_clock_tile.h"

#include <sys/mman.h> /* memfd_create */
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>

#include <linux/futex.h>
#include "generated/fd_snapld_tile_seccomp.h"

#define NAME "snapld"

/* download progress in each 10 second window must be at
   min_download_speed_mibs * 10 seconds or higher.  Catches extremely
   slow download speeds where we may not get to 100 MiB downloaded for a
   while. */
#define FD_SNAPLD_DOWNLOAD_WINDOW_NS (10L*1000L*1000L*1000L) /* 10 seconds */

/* How long the stream downloader waits before asking the serving
   validator for more of the archive it is already reading. */
#define FD_SNAPLD_STREAM_RETRY_NANOS (100L*1000L*1000L) /* 100 ms */

/* A stream listed in the boot index must stay open for at least this
   long, or there is no point joining it. */
#define FD_SNAPLD_STREAM_MIN_LIFE_SECONDS (180L)

/* A failing request for the tail is retried until the stream has gone
   this long without delivering a single byte. */
#define FD_SNAPLD_STREAM_IDLE_NANOS (60L*1000L*1000L*1000L) /* 60 seconds */

/* The snapld tile is responsible for loading data from the local file
   or from an HTTP/TCP connection and sending it to the snapdc tile
   for later decompression. */

typedef struct fd_snapld_tile {

  struct {
    char path[ PATH_MAX ];
    uint min_download_speed_mibs;
    char stream_server[ FD_URL_MAX ];
  } config;

  int   state;
  int   pipeline_ready;
  int   load_full;
  int   load_file;
  int   sent_meta;
  int   is_redirect;
  ulong gossip_slot;
  ulong file_sz;

  ulong  bytes_in_batch;
  double download_speed_mibs;
  long   start_batch;
  long   end_batch;

  ulong  bytes_in_window;
  ulong  min_bytes_in_window;
  long   window_deadline;

  int local_full_fd;
  int local_incr_fd;
  int sockfd;

  /* Instant boot stream download.  The tile drives itself: it picks a
     stream out of the serving validator's boot index, then reads the
     archive over and over as it grows. */
  int           stream;
  int           stream_index_done; /* the boot index has been read */
  int           stream_done_seen;  /* a request for the archive has finished */
  ulong         stream_slot;
  ulong         stream_received;      /* archive bytes received so far */
  long          stream_retry_at;      /* wallclock of the next request */
  long          stream_idle_deadline; /* when a failed request turns fatal */
  ulong         stream_index_len;
  char          stream_index[ 4096UL ];
  fd_ip4_port_t stream_addr;
  char          stream_hostname[ FD_FQDN_BUF_MAX ];
  ulong *       done_fseq;

  ulong   waker_client_idx;
  ulong * waker_fseq;

  fd_clock_tile_t clock[1];

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
  ulong a = alignof(fd_snapld_tile_t);
  a = fd_ulong_max( a, fd_sshttp_align() );
  a = fd_ulong_max( a, fd_alloc_align() );
  return a;
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND(  l, alignof(fd_snapld_tile_t),  sizeof(fd_snapld_tile_t) );
  l = FD_LAYOUT_APPEND(  l, fd_sshttp_align(),          fd_sshttp_footprint()    );
  l = FD_LAYOUT_APPEND(  l, fd_alloc_align(),           fd_alloc_footprint()     );
  return FD_LAYOUT_FINI( l, scratch_align() );
}


static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapld_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapld_tile_t), sizeof(fd_snapld_tile_t) );
  void * _sshttp         = FD_SCRATCH_ALLOC_APPEND( l, fd_sshttp_align(),          fd_sshttp_footprint()    );

  ctx->sshttp = fd_sshttp_join( fd_sshttp_new( _sshttp, FD_WAKER_INNER_FD( tile->waker_client_idx ) ) );
  FD_TEST( ctx->sshttp );

  ulong full_slot = ULONG_MAX;
  ulong incr_slot = ULONG_MAX;
  int full_is_zstd = 0;
  int incr_is_zstd = 0;
  char full_path[ PATH_MAX ] = { 0 };
  char incr_path[ PATH_MAX ] = { 0 };
  uchar full_snapshot_hash[ FD_HASH_FOOTPRINT ] = { 0 };
  uchar incr_snapshot_hash[ FD_HASH_FOOTPRINT ] = { 0 };
  ctx->local_full_fd = -1;
  ctx->local_incr_fd = -1;
  /* The instant boot stream downloader reads no local snapshot. */
  int load_local = !tile->snapld.stream;
  /* fd_ssarchive_latest_pair needs to be invoked here, irrespective
     of whether snapct may do the same, because this information is
     needed here during privileged_init. */
  if( FD_LIKELY( load_local && -1!=fd_ssarchive_latest_pair( tile->snapld.snapshots_path,
                                                             tile->snapld.incremental_snapshots,
                                                             &full_slot,         &incr_slot,
                                                             full_path,          incr_path,
                                                             &full_is_zstd,      &incr_is_zstd,
                                                             full_snapshot_hash, incr_snapshot_hash ) ) ) {
    FD_TEST( full_slot!=ULONG_MAX );

    ctx->local_full_fd = open( full_path, O_RDONLY|O_CLOEXEC|O_NONBLOCK );
    if( FD_UNLIKELY( -1==ctx->local_full_fd ) ) FD_LOG_ERR(( "open() failed `%s` (%i-%s)", full_path, errno, fd_io_strerror( errno ) ));
    posix_fadvise( ctx->local_full_fd, 0L, 0L, POSIX_FADV_SEQUENTIAL );

    if( FD_LIKELY( incr_slot!=ULONG_MAX ) ) {
      ctx->local_incr_fd = open( incr_path, O_RDONLY|O_CLOEXEC|O_NONBLOCK );
      if( FD_UNLIKELY( -1==ctx->local_incr_fd ) ) FD_LOG_ERR(( "open() failed `%s` (%i-%s)", incr_path, errno, fd_io_strerror( errno ) ));
      posix_fadvise( ctx->local_incr_fd, 0L, 0L, POSIX_FADV_SEQUENTIAL );
    }
  }

  /* Load CA trust store while we still have filesystem access
     (before seccomp sandbox locks down). */
  fd_sshttp_load_ca_store( ctx->sshttp );

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
  if( FD_UNLIKELY( out_fds_cnt<7UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2UL; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) {
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd();
  }
  out_fds[ out_cnt++ ] = FD_WAKER_OUTER_FD;                           /* waker outer epoll fd (rearm) */
  out_fds[ out_cnt++ ] = FD_WAKER_INNER_FD( tile->waker_client_idx ); /* waker inner epoll fd */

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

  uint epoll_inner_fd = (uint)FD_WAKER_INNER_FD( tile->waker_client_idx );
  uint epoll_outer_fd = (uint)FD_WAKER_OUTER_FD;
  populate_sock_filter_policy_fd_snapld_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->local_full_fd, (uint)ctx->local_incr_fd, (uint)ctx->sockfd, epoll_inner_fd, epoll_outer_fd );
  return sock_filter_policy_fd_snapld_tile_instr_cnt;
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapld_tile_t * ctx  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapld_tile_t),  sizeof(fd_snapld_tile_t) );
  FD_SCRATCH_ALLOC_APPEND( l, fd_sshttp_align(),          fd_sshttp_footprint()    );
  FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(),           fd_alloc_footprint()     );

  fd_memcpy( ctx->config.path, tile->snapld.snapshots_path, PATH_MAX );
  ctx->config.min_download_speed_mibs = tile->snapld.min_download_speed_mibs;
  fd_cstr_ncpy( ctx->config.stream_server, tile->snapld.stream_server, sizeof(ctx->config.stream_server) );

  ctx->state          = FD_SNAPSHOT_STATE_IDLE;
  ctx->pipeline_ready = 0;

  /* The stream downloader has no control tile to start it, so it
     starts itself and runs until the background load is done. */
  ctx->stream               = tile->snapld.stream;
  ctx->stream_index_done    = 0;
  ctx->stream_done_seen     = 0;
  ctx->stream_slot          = ULONG_MAX;
  ctx->stream_received      = 0UL;
  ctx->stream_retry_at      = LONG_MAX;
  ctx->stream_idle_deadline = LONG_MAX;
  ctx->stream_index_len     = 0UL;
  ctx->done_fseq            = NULL;
  if( FD_UNLIKELY( ctx->stream ) ) {
    FD_TEST( tile->snapld.instant_boot_done_obj_id!=ULONG_MAX );
    ctx->done_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, tile->snapld.instant_boot_done_obj_id ) );
    FD_TEST( ctx->done_fseq );
    ctx->state           = FD_SNAPSHOT_STATE_PROCESSING;
    ctx->pipeline_ready  = 1;
    ctx->load_full       = 1;
    ctx->stream_retry_at = 0L; /* the index request is due right away */
  }

  ctx->waker_client_idx = tile->waker_client_idx;
  FD_TEST( ctx->waker_client_idx!=ULONG_MAX );
  ctx->waker_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, tile->waker_fseq_obj_id ) );
  FD_TEST( ctx->waker_fseq );
  fd_clock_tile_init( ctx->clock );

  ctx->download_speed_mibs = 0.0;
  ctx->bytes_in_batch      = 0UL;
  ctx->start_batch         = 0L;
  ctx->end_batch           = 0L;
  ctx->bytes_in_window     = 0UL;
  ctx->window_deadline     = LONG_MAX;
  ctx->min_bytes_in_window = ((ulong)ctx->config.min_download_speed_mibs * (FD_SNAPLD_DOWNLOAD_WINDOW_NS / (ulong)1e9))<<20UL;

  /* The instant boot downloader is not driven by the control tile, so
     it has no in link. */
  if( FD_LIKELY( !tile->snapld.stream ) ) {
    FD_TEST( tile->in_cnt==1UL );
    fd_topo_link_t const * in_link = &topo->links[ tile->in_link_id[ 0 ] ];
    FD_TEST( 0==strcmp( in_link->name, "snapct_ld" ) );
    ctx->in_rd.base = fd_topo_obj_wksp_base( topo, in_link->dcache_obj_id );
  } else {
    FD_TEST( tile->in_cnt==0UL );
  }

  FD_TEST( tile->out_cnt==1UL );
  fd_topo_link_t const * out_link = &topo->links[ tile->out_link_id[ 0 ] ];
  FD_TEST( 0==strcmp( out_link->name, tile->snapld.stream ? "strld_dc" : "snapld_dc" ) );
  ctx->out_dc.mem    = fd_topo_obj_wksp_base( topo, out_link->dcache_obj_id );
  ctx->out_dc.chunk0 = fd_dcache_compact_chunk0( ctx->out_dc.mem, out_link->dcache );
  ctx->out_dc.wmark  = fd_dcache_compact_wmark ( ctx->out_dc.mem, out_link->dcache, out_link->mtu );
  ctx->out_dc.chunk  = ctx->out_dc.chunk0;
  ctx->out_dc.mtu    = out_link->mtu;

  FD_TEST( sizeof(fd_ssctrl_meta_t)<=ctx->out_dc.mtu );

  /* We can only close the temporary socket file descriptor after
     entering the sandbox because the sandbox checks all file
     descriptors are existent. */
  if( -1==close( ctx->sockfd ) ) FD_LOG_ERR((" close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static int
should_shutdown( fd_snapld_tile_t * ctx ) {
  return ctx->state==FD_SNAPSHOT_STATE_SHUTDOWN;
}

static void
during_housekeeping( fd_snapld_tile_t * ctx ) {
  if( FD_UNLIKELY( fd_clock_tile_recal_due( ctx->clock ) ) ) fd_clock_tile_recal( ctx->clock );
}

static long
next_deadline( fd_snapld_tile_t * ctx ) {
  if( FD_LIKELY( ctx->state!=FD_SNAPSHOT_STATE_PROCESSING || ctx->load_file ) ) return LONG_MAX;
  long next = fd_long_min( fd_sshttp_deadline( ctx->sshttp ), ctx->window_deadline );
  if( FD_UNLIKELY( ctx->stream ) ) next = fd_long_min( next, ctx->stream_retry_at );
  return next==LONG_MAX ? LONG_MAX : fd_clock_tile_wallclock_to_tickcount( ctx->clock, next );
}

static void
metrics_write( fd_snapld_tile_t * ctx ) {
  FD_MGAUGE_SET( SNAPLD, STATE,            (ulong)(ctx->state) );
}

/* stream_tail tells whether the tile is reading the growing tail of a
   stream.  The tail is idle most of the time, so download speed stops
   saying anything useful there, and a failed request there is worth
   retrying. */

static int
stream_tail( fd_snapld_tile_t * ctx ) {
  return ctx->stream && ctx->stream_done_seen;
}

/* stream_fatal gives up on the stream.  If the background snapshot
   load has already finished there is nothing left to stream, so the
   tile shuts down cleanly instead of dying. */

static void
stream_fatal( fd_snapld_tile_t * ctx,
              char const *       reason ) {
  if( FD_UNLIKELY( fd_fseq_query( ctx->done_fseq )==1UL ) ) {
    ctx->state = FD_SNAPSHOT_STATE_SHUTDOWN;
    return;
  }
  FD_LOG_ERR(( "%s (server %s)", reason, ctx->config.stream_server ));
}

/* stream_retry handles a failed request for the stream.  A request
   for the growing tail can simply be made again in a moment.  The
   background load finishing, a failure anywhere else, or a tail that
   has stopped delivering bytes altogether all end the stream. */

static void
stream_retry( fd_snapld_tile_t * ctx,
              char const *       reason ) {
  long now = fd_clock_tile_now( ctx->clock );
  if( FD_UNLIKELY( fd_fseq_query( ctx->done_fseq )==1UL ||
                   !stream_tail( ctx ) ||
                   now>ctx->stream_idle_deadline ) ) {
    stream_fatal( ctx, reason );
    return;
  }
  fd_sshttp_cancel( ctx->sshttp );
  ctx->stream_retry_at = now+FD_SNAPLD_STREAM_RETRY_NANOS;
}

static void
transition_malformed( fd_snapld_tile_t *  ctx,
                      fd_stem_context_t * stem ) {
  /* The stream downloader has no control tile to recover it. */
  if( FD_UNLIKELY( ctx->stream ) ) {
    stream_retry( ctx, "instant boot stream download failed" );
    return;
  }
  if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_ERROR ) ) return;
  ctx->state = FD_SNAPSHOT_STATE_ERROR;
  fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_ERROR, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static int
check_download_progress( fd_snapld_tile_t *  ctx,
                         fd_stem_context_t * stem,
                         int                 downloading,
                         long                now ) {
  if( FD_UNLIKELY( stream_tail( ctx ) ) ) return 0;

  if( FD_UNLIKELY( ctx->window_deadline==LONG_MAX && downloading ) ) {
    ctx->window_deadline = now + FD_SNAPLD_DOWNLOAD_WINDOW_NS;
    ctx->bytes_in_window = 0UL;
  }

  if( FD_UNLIKELY( now>ctx->window_deadline ) ) {
    if( FD_UNLIKELY( ctx->bytes_in_window<ctx->min_bytes_in_window ) ) {
      /* cancel the download if the download progress speed in the last
         window is less than the minimum download speed. */
      double download_speed_mibs = (double)ctx->bytes_in_window / (double)(FD_SNAPLD_DOWNLOAD_WINDOW_NS / 1e9) / (double)(1<<20UL);
      FD_LOG_WARNING(( "download progress of %.2f MiB/s in the last %lu seconds for %s snapshot "
                       "is below the minimum download speed %u MiB/s, cancelling download",
                       download_speed_mibs, FD_SNAPLD_DOWNLOAD_WINDOW_NS / (ulong)1e9,
                       ctx->load_full ? "full" : "incremental", ctx->config.min_download_speed_mibs ));
      transition_malformed( ctx, stem );
      fd_sshttp_cancel( ctx->sshttp );
      return -1;
    }
    ctx->window_deadline = now + FD_SNAPLD_DOWNLOAD_WINDOW_NS;
    ctx->bytes_in_window = 0UL;
  }
  return 0;
}

/* stream_request asks the serving validator for the archive of the
   stream the tile joined, resuming range_start bytes in. */

static void
stream_request( fd_snapld_tile_t * ctx,
                ulong              range_start ) {
  char  path[ 64 ];
  ulong path_len;
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), &path_len, "/boot/%lu.tar.zst", ctx->stream_slot ) );
  if( FD_UNLIKELY( fd_sshttp_init( ctx->sshttp, ctx->stream_addr, ctx->stream_hostname, 0, path, path_len,
                                   4UL, fd_clock_tile_now( ctx->clock ), range_start ) ) ) {
    stream_retry( ctx, "could not request the instant boot archive" );
  }
}

/* stream_connect resolves the configured server and asks it for the
   index of the streams it is serving.  Only an IPv4 literal is
   accepted: the tile has no DNS client of its own. */

static void
stream_connect( fd_snapld_tile_t * ctx ) {
  ushort port;
  int    is_https;
  fd_dns_peer_parse( ctx->config.stream_server, "snapshots.instant_boot.server", ctx->stream_hostname, &port, &is_https );
  if( FD_UNLIKELY( is_https ) ) {
    FD_LOG_ERR(( "[snapshots.instant_boot] server \"%s\" must be plain http", ctx->config.stream_server ));
  }
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( ctx->stream_hostname, &ctx->stream_addr.addr ) ) ) {
    FD_LOG_ERR(( "[snapshots.instant_boot] server \"%s\" must give an IPv4 address", ctx->config.stream_server ));
  }
  ctx->stream_addr.port = port;

  if( FD_UNLIKELY( fd_sshttp_init( ctx->sshttp, ctx->stream_addr, ctx->stream_hostname, 0, "/boot/index", 11UL,
                                   4UL, fd_clock_tile_now( ctx->clock ), 0UL ) ) ) {
    stream_fatal( ctx, "could not request the instant boot index" );
  }
}

/* stream_parse_line reads one "<slot> <hash> <unix time it closes>"
   line of the boot index.  Returns 0 on success. */

static int
stream_parse_line( char *  line,
                   ulong * slot,
                   uchar   hash[ static FD_HASH_FOOTPRINT ],
                   long *  expires ) {
  char * cursor;
  *slot = strtoul( line, &cursor, 10 );
  if( FD_UNLIKELY( cursor==line || *cursor!=' ' ) ) return -1;

  char * encoded = cursor+1UL;
  char * space   = strchr( encoded, ' ' );
  if( FD_UNLIKELY( !space ) ) return -1;
  *space = '\0';
  if( FD_UNLIKELY( !fd_base58_decode_32( encoded, hash ) ) ) return -1;

  *expires = strtol( space+1UL, &cursor, 10 );
  if( FD_UNLIKELY( cursor==space+1UL ) ) return -1;
  return 0;
}

/* stream_select picks the newest stream in the boot index that will
   stay open long enough to be worth joining.  The index lists the
   newest stream first.  Returns 0 on success. */

static int
stream_select( fd_snapld_tile_t * ctx,
               uchar              hash[ static FD_HASH_FOOTPRINT ] ) {
  ctx->stream_index[ ctx->stream_index_len ] = '\0';
  long now = fd_clock_tile_now( ctx->clock )/(long)1e9;

  char * line = ctx->stream_index;
  while( *line ) {
    char * end  = strchr( line, '\n' );
    char * next = end ? end+1UL : line+strlen( line );
    if( FD_LIKELY( end ) ) *end = '\0';

    ulong slot;
    long  expires;
    if( FD_LIKELY( !stream_parse_line( line, &slot, hash, &expires ) &&
                   expires-now>FD_SNAPLD_STREAM_MIN_LIFE_SECONDS ) ) {
      ctx->stream_slot = slot;
      return 0;
    }
    line = next;
  }

  stream_fatal( ctx, "no instant boot stream stays open long enough" );
  return -1;
}

/* stream_index_advance reads the boot index, then announces the
   stream the tile joined and asks for its archive. */

static void
stream_index_advance( fd_snapld_tile_t *  ctx,
                      fd_stem_context_t * stem,
                      int *               charge_busy ) {
  /* An index that fills the buffer exactly is fine; only a response
     with more body than that is too large.  A full buffer still needs
     a byte of slack to hand to the reader, which returns the end of
     the response without touching it. */
  ulong room = sizeof(ctx->stream_index)-1UL-ctx->stream_index_len;
  if( FD_UNLIKELY( !room && fd_sshttp_content_len( ctx->sshttp )!=ctx->stream_index_len ) ) {
    stream_fatal( ctx, "instant boot index is too large" );
    return;
  }

  int   downloading = 0;
  ulong data_len    = fd_ulong_max( room, 1UL );
  long  now         = fd_clock_tile_now( ctx->clock );
  int   fired       = fd_fseq_query( ctx->waker_fseq )==1UL;
  if( FD_LIKELY( fired ) ) fd_fseq_update( ctx->waker_fseq, 0UL );
  int   result      = fd_sshttp_advance( ctx->sshttp, &data_len, (uchar *)ctx->stream_index+ctx->stream_index_len, &downloading, now );
  if( FD_LIKELY( fired ) ) fd_waker_client_rearm( ctx->waker_client_idx );

  switch( result ) {
    case FD_SSHTTP_ADVANCE_AGAIN:
      break;
    case FD_SSHTTP_ADVANCE_DATA:
      ctx->stream_index_len += data_len;
      *charge_busy = 1;
      break;
    case FD_SSHTTP_ADVANCE_DONE: {
      uchar hash[ FD_HASH_FOOTPRINT ];
      if( FD_UNLIKELY( stream_select( ctx, hash ) ) ) break;
      FD_LOG_INFO(( "joining the instant boot stream for slot %lu at %s", ctx->stream_slot, ctx->config.stream_server ));

      fd_ssctrl_init_t * init = fd_chunk_to_laddr( ctx->out_dc.mem, ctx->out_dc.chunk );
      fd_memset( init, 0, sizeof(fd_ssctrl_init_t) );
      init->zstd = 1;
      init->slot = ctx->stream_slot;
      fd_memcpy( init->snapshot_hash, hash, FD_HASH_FOOTPRINT );
      fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_INIT_FULL, ctx->out_dc.chunk, sizeof(fd_ssctrl_init_t), 0UL, 0UL, 0UL );
      ctx->out_dc.chunk = fd_dcache_compact_next( ctx->out_dc.chunk, sizeof(fd_ssctrl_init_t), ctx->out_dc.chunk0, ctx->out_dc.wmark );

      ctx->stream_index_done    = 1;
      ctx->stream_idle_deadline = now+FD_SNAPLD_STREAM_IDLE_NANOS;
      stream_request( ctx, 0UL );
      *charge_busy = 1;
      break;
    }
    default:
      stream_fatal( ctx, "could not read the instant boot index" );
  }
}

static void
after_credit( fd_snapld_tile_t *  ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in FD_PARAM_UNUSED,
              int *               charge_busy ) {
  if( ctx->state!=FD_SNAPSHOT_STATE_PROCESSING ) {
    if( FD_LIKELY( !stem->sleep ) ) fd_log_sleep( (long)1e6 );
    return;
  }

  if( FD_UNLIKELY( !ctx->pipeline_ready ) ) {
    return;
  }

  /* A request for the stream is due: the index on the first call, and
     the rest of the archive after each one finishes. */
  if( FD_UNLIKELY( ctx->stream && ctx->stream_retry_at!=LONG_MAX ) ) {
    if( FD_LIKELY( fd_clock_tile_now( ctx->clock )<ctx->stream_retry_at ) ) {
      /* Nothing to do until the next request falls due.  Clear a
         pending wake so the tile can park. */
      if( FD_LIKELY( !stem->sleep ) ) fd_log_sleep( (long)1e6 );
      if( FD_UNLIKELY( fd_fseq_query( ctx->waker_fseq )==1UL ) ) {
        fd_fseq_update( ctx->waker_fseq, 0UL );
        fd_waker_client_rearm( ctx->waker_client_idx );
      }
      return;
    }
    ctx->stream_retry_at = LONG_MAX;
    if( FD_UNLIKELY( !ctx->stream_index_done ) ) stream_connect( ctx );
    else                                         stream_request( ctx, ctx->stream_received );
    *charge_busy = 1;
    return;
  }

  if( FD_UNLIKELY( ctx->stream && !ctx->stream_index_done ) ) {
    stream_index_advance( ctx, stem, charge_busy );
    return;
  }

  uchar * out = fd_chunk_to_laddr( ctx->out_dc.mem, ctx->out_dc.chunk );

  if( ctx->load_file ) {
    if( FD_UNLIKELY( !ctx->sent_meta ) ) {
      FD_TEST( sizeof(fd_ssctrl_meta_t)<=ctx->out_dc.mtu );
      fd_ssctrl_meta_t * meta = (fd_ssctrl_meta_t *)out;
      meta->total_sz         = ctx->file_sz;
      meta->resolved_slot    = ULONG_MAX;
      fd_memset( meta->resolved_hash, 0, FD_HASH_FOOTPRINT );
      meta->resolved_name[0] = '\0';
      ctx->sent_meta = 1;
      fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_META, ctx->out_dc.chunk, sizeof(fd_ssctrl_meta_t), 0UL, 0UL, 0UL );
      ctx->out_dc.chunk = fd_dcache_compact_next( ctx->out_dc.chunk, sizeof(fd_ssctrl_meta_t), ctx->out_dc.chunk0, ctx->out_dc.wmark );
      return;
    }
    long result = read( ctx->load_full ? ctx->local_full_fd : ctx->local_incr_fd, out, ctx->out_dc.mtu );
    if( FD_UNLIKELY( result<=0L ) ) {
      if( result==0L ) {
        FD_LOG_INFO(( "finished reading %s snapshot from local file", ctx->load_full ? "full" : "incremental" ));
        ctx->state = FD_SNAPSHOT_STATE_FINISHING;
        fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_LOAD_COMPLETE, 0UL, 0UL, 0UL, 0UL, 0UL );
      } else if( FD_UNLIKELY( errno!=EAGAIN && errno!=EINTR ) ) {
        FD_LOG_WARNING(( "read() failed on %s snapshot file (%i-%s)", ctx->load_full ? "full" : "incremental", errno, fd_io_strerror( errno ) ));
        transition_malformed( ctx, stem );
        return; /* verbose return */
      }
    } else {
      fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_DATA, ctx->out_dc.chunk, (ulong)result, 0UL, 0UL, 0UL );
      ctx->out_dc.chunk = fd_dcache_compact_next( ctx->out_dc.chunk, (ulong)result, ctx->out_dc.chunk0, ctx->out_dc.wmark );
      *charge_busy = 1;
      return; /* verbose return */
    }
  } else {
    int   downloading = 0;
    ulong data_len    = ctx->out_dc.mtu;
    long  now         = fd_clock_tile_now( ctx->clock );
    int   fired       = fd_fseq_query( ctx->waker_fseq )==1UL;
    if( FD_LIKELY( fired ) ) fd_fseq_update( ctx->waker_fseq, 0UL );
    int   result      = fd_sshttp_advance( ctx->sshttp, &data_len, out, &downloading, now );
    if( FD_LIKELY( fired ) ) fd_waker_client_rearm( ctx->waker_client_idx );
    switch( result ) {
      case FD_SSHTTP_ADVANCE_AGAIN:
        /* Return value ignored: on failure, check_download_progress
           already calls transition_malformed and fd_sshttp_cancel. */
        check_download_progress( ctx, stem, downloading, now );
        break;
      case FD_SSHTTP_ADVANCE_DATA: {
        ctx->bytes_in_window += data_len;
        if( FD_UNLIKELY( -1==check_download_progress( ctx, stem, downloading, now ) ) ) break;
        if( FD_UNLIKELY( !ctx->sent_meta ) ) {
          /* On the first DATA return, the HTTP headers are available
             for use.  We need to send this metadata downstream, but
             need to do so before any data frags.  So, we copy any data
             we received with the headers (if any) to the next dcache
             chunk and then publish both in order. */
          ctx->start_batch = fd_clock_tile_now( ctx->clock );
          FD_TEST( sizeof(fd_ssctrl_meta_t)<=ctx->out_dc.mtu );
          fd_ssctrl_meta_t * meta = (fd_ssctrl_meta_t *)out;
          ulong next_chunk = fd_dcache_compact_next( ctx->out_dc.chunk, sizeof(fd_ssctrl_meta_t), ctx->out_dc.chunk0, ctx->out_dc.wmark );
          memmove( fd_chunk_to_laddr( ctx->out_dc.mem, next_chunk ), out, data_len );
          meta->total_sz = fd_sshttp_content_len( ctx->sshttp );
          if( FD_UNLIKELY( meta->total_sz==ULONG_MAX ) ) {
            FD_LOG_WARNING(( "HTTP response for %s snapshot is missing Content-Length header", ctx->load_full ? "full" : "incremental" ));
            transition_malformed( ctx, stem );
            fd_sshttp_cancel( ctx->sshttp );
            break;
          }

          /* Populate resolved redirect fields in META.  The stream
             downloader resolved its slot from the boot index. */
          meta->resolved_slot    = ctx->stream ? ctx->stream_slot : ULONG_MAX;
          meta->resolved_name[0] = '\0';
          fd_memset( meta->resolved_hash, 0, FD_HASH_FOOTPRINT );

          if( ctx->is_redirect ) {
            char const * resolved_name = fd_sshttp_snapshot_name( ctx->sshttp );
            if( FD_UNLIKELY( !resolved_name || resolved_name[0]=='\0' ) ) {
              FD_LOG_WARNING(( "redirect-based download did not resolve to a snapshot filename for %s snapshot",
                               ctx->load_full ? "full" : "incremental" ));
              transition_malformed( ctx, stem );
              fd_sshttp_cancel( ctx->sshttp );
              break;
            }
            int is_full_filename = !strncmp( resolved_name, "snapshot-", 9 );
            if( FD_UNLIKELY( is_full_filename!=ctx->load_full ) ) {
              FD_LOG_WARNING(( "resolved snapshot type mismatch: expected %s but got %s filename `%s`",
                               ctx->load_full ? "full" : "incremental", is_full_filename ? "full" : "incremental", resolved_name ));
              transition_malformed( ctx, stem );
              fd_sshttp_cancel( ctx->sshttp );
              break;
            }
            ulong resolved_slot = fd_sshttp_resolved_slot( ctx->sshttp );
            if( FD_UNLIKELY( resolved_slot<ctx->gossip_slot ) ) {
              FD_LOG_WARNING(( "resolved snapshot slot %lu is older than gossip slot %lu for %s snapshot, rejecting",
                               resolved_slot, ctx->gossip_slot, ctx->load_full ? "full" : "incremental" ));
              transition_malformed( ctx, stem );
              fd_sshttp_cancel( ctx->sshttp );
              break;
            }
            if( FD_UNLIKELY( resolved_slot>=FD_SSPEER_PLAUSIBLE_MAX_SLOT ) ) {
              FD_LOG_WARNING(( "resolved snapshot slot %lu exceeds plausibility bound for %s snapshot, rejecting",
                               resolved_slot, ctx->load_full ? "full" : "incremental" ));
              transition_malformed( ctx, stem );
              fd_sshttp_cancel( ctx->sshttp );
              break;
            }
            meta->resolved_slot = resolved_slot;
            fd_memcpy( meta->resolved_hash, fd_sshttp_resolved_hash( ctx->sshttp ), FD_HASH_FOOTPRINT );
            fd_cstr_ncpy( meta->resolved_name, resolved_name, PATH_MAX );
            FD_LOG_INFO(( "redirect resolved to `%s` (slot %lu) for %s snapshot",
                          resolved_name, resolved_slot, ctx->load_full ? "full" : "incremental" ));
          }

          /* For a stream total_sz is only the archive length at the
             first request, and nothing but a metric reads it. */
          ctx->sent_meta = 1;
          fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_META, ctx->out_dc.chunk, sizeof(fd_ssctrl_meta_t), 0UL, 0UL, 0UL );
          ctx->out_dc.chunk = next_chunk;
        }
        if( FD_LIKELY( data_len!=0UL ) ) {
          fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_DATA, ctx->out_dc.chunk, data_len, 0UL, 0UL, 0UL );
          ctx->out_dc.chunk = fd_dcache_compact_next( ctx->out_dc.chunk, data_len, ctx->out_dc.chunk0, ctx->out_dc.wmark );
          ctx->bytes_in_batch += data_len;
          if( FD_UNLIKELY( ctx->stream ) ) {
            ctx->stream_received     += data_len;
            ctx->stream_idle_deadline = now+FD_SNAPLD_STREAM_IDLE_NANOS;
          }

          /* measure download speed every 100 MiB */
          if( ctx->bytes_in_batch>=100<<20UL && !stream_tail( ctx ) ) {
            ctx->end_batch = fd_clock_tile_now( ctx->clock );
            /* as a precaution, make sure elapsed_batch is positive
               and larger than zero (to avoid division by zero). */
            long elapsed_batch = fd_long_if( ctx->end_batch > ctx->start_batch, ctx->end_batch - ctx->start_batch, 1L );
            /* download speed in MiB/s = bytes/nanoseconds * 1e9/(1 second) * 1/(1MiB = 1<<20UL) = 1e9/(1024*1024) ~= 954 */
            ctx->download_speed_mibs = (double)(ctx->bytes_in_batch*954) / (double)elapsed_batch;
            if( FD_UNLIKELY( ctx->download_speed_mibs<ctx->config.min_download_speed_mibs ) ) {
              /* cancel the snapshot load if the download speed is less
                 than the minimum download speed. */
              FD_LOG_WARNING(( "download speed %.2f MiB/s on a batch of %lu MiB for %s snapshot is below the minimum threshold %.2f MiB/s. "
                               "cancelling snapshot download",
                               ctx->download_speed_mibs, ctx->bytes_in_batch>>20UL, ctx->load_full ? "full" : "incremental",
                               (double)(ctx->config.min_download_speed_mibs) ));
              transition_malformed( ctx, stem );
              fd_sshttp_cancel( ctx->sshttp );
              break;
            }
            ctx->start_batch    = ctx->end_batch;
            ctx->bytes_in_batch = 0UL;
          }
        }
        *charge_busy = 1;
        break;
      }
      case FD_SSHTTP_ADVANCE_DONE:
        /* The stream archive is still growing, so finishing a request
           for it only means there is nothing more to read right now. */
        if( FD_UNLIKELY( ctx->stream ) ) {
          ctx->stream_done_seen = 1;
          ctx->window_deadline  = LONG_MAX;
          if( FD_UNLIKELY( fd_fseq_query( ctx->done_fseq )==1UL ) ) {
            FD_LOG_INFO(( "background snapshot load is done, leaving the instant boot stream" ));
            ctx->state = FD_SNAPSHOT_STATE_SHUTDOWN;
            break;
          }
          ctx->stream_retry_at = fd_clock_tile_now( ctx->clock )+FD_SNAPLD_STREAM_RETRY_NANOS;
          break;
        }
        if( FD_UNLIKELY( !ctx->sent_meta ) ) {
          FD_LOG_WARNING(( "zero-length HTTP response for %s snapshot", ctx->load_full ? "full" : "incremental" ));
          transition_malformed( ctx, stem );
          fd_sshttp_cancel( ctx->sshttp );
          break;
        }
        FD_LOG_INFO(( "finished downloading %s snapshot", ctx->load_full ? "full" : "incremental" ));
        ctx->state = FD_SNAPSHOT_STATE_FINISHING;
        fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_LOAD_COMPLETE, 0UL, 0UL, 0UL, 0UL, 0UL );
        break;
      case FD_SSHTTP_ADVANCE_ERROR:
        FD_LOG_WARNING(( "HTTP advance error during %s snapshot download, entering error state",
                         ctx->load_full ? "full" : "incremental" ));
        transition_malformed( ctx, stem );
        fd_sshttp_cancel( ctx->sshttp );
        break;
      default: FD_LOG_ERR(( "unexpected fd_sshttp_advance result %d for %s snapshot",
                            result, ctx->load_full ? "full" : "incremental" ));
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
  if( ctx->state==FD_SNAPSHOT_STATE_ERROR && sig!=FD_SNAPSHOT_MSG_CTRL_FAIL ) {
    /* Control messages move along the snapshot load pipeline.  Since
       error conditions can be triggered by any tile in the pipeline,
       it is possible to be in error state and still receive otherwise
       valid messages.  Only a fail message can revert this. */
    return 0;
  };

  int forward_msg = 1;

  switch( sig ) {

    case FD_SNAPSHOT_MSG_CTRL_INIT_FULL:
    case FD_SNAPSHOT_MSG_CTRL_INIT_INCR: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      ctx->state = FD_SNAPSHOT_STATE_PROCESSING;
      ctx->pipeline_ready = 0;
      FD_TEST( sz==sizeof(fd_ssctrl_init_t) && sz<=ctx->out_dc.mtu );
      fd_ssctrl_init_t const * msg_in = fd_chunk_to_laddr_const( ctx->in_rd.base, chunk );
      ctx->load_full   = sig==FD_SNAPSHOT_MSG_CTRL_INIT_FULL;
      ctx->load_file   = msg_in->file;
      ctx->sent_meta   = 0;
      ctx->gossip_slot = msg_in->slot;
      ctx->is_redirect = msg_in->is_redirect;
      ctx->file_sz     = msg_in->file_sz;

      ctx->window_deadline = LONG_MAX;
      ctx->bytes_in_window = 0UL;
      ctx->bytes_in_batch  = 0UL;
      if( ctx->load_file ) {
        if( FD_UNLIKELY( 0!=lseek( ctx->load_full ? ctx->local_full_fd : ctx->local_incr_fd, 0, SEEK_SET ) ) )
          FD_LOG_ERR(( "lseek(0) failed on %s snapshot file (%i-%s)",
                       ctx->load_full ? "full" : "incremental", errno, fd_io_strerror( errno ) ));
      }
      fd_ssctrl_init_t * msg_out = fd_chunk_to_laddr( ctx->out_dc.mem, ctx->out_dc.chunk );
      fd_memcpy( msg_out, msg_in, sz );
      fd_stem_publish( stem, 0UL, sig, ctx->out_dc.chunk, sz, 0UL, 0UL, 0UL );
      ctx->out_dc.chunk = fd_dcache_compact_next( ctx->out_dc.chunk, ctx->out_dc.mtu, ctx->out_dc.chunk0, ctx->out_dc.wmark );
      forward_msg = 0; // we are forwarding the control message in the `fd_sstrl_init_t` message
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_START: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING );
      if( !ctx->load_file ) {
        FD_TEST( sz==sizeof(fd_ssctrl_start_t) );
        fd_ssctrl_start_t const * msg = fd_chunk_to_laddr_const( ctx->in_rd.base, chunk );
        if( FD_UNLIKELY( fd_sshttp_init( ctx->sshttp, msg->addr, msg->hostname, msg->is_https, msg->path, msg->path_len, 4UL, fd_clock_tile_now( ctx->clock ), 0UL ) ) ) {
          transition_malformed( ctx, stem );
          forward_msg = 0;
          break;
        }
      }
      ctx->pipeline_ready = 1;
      forward_msg = 0;
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_FINI: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_FINISHING );
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_NEXT:
    case FD_SNAPSHOT_MSG_CTRL_DONE: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_FINISHING );
      ctx->state = FD_SNAPSHOT_STATE_IDLE;
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_ERROR: {
      FD_TEST( ctx->state!=FD_SNAPSHOT_STATE_SHUTDOWN );
      fd_sshttp_cancel( ctx->sshttp );
      ctx->state = FD_SNAPSHOT_STATE_ERROR;
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_FAIL:
      FD_TEST( ctx->state!=FD_SNAPSHOT_STATE_SHUTDOWN );
      fd_sshttp_cancel( ctx->sshttp );
      ctx->state = FD_SNAPSHOT_STATE_IDLE;
      ctx->pipeline_ready = 0;
      break;

    case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      ctx->state = FD_SNAPSHOT_STATE_SHUTDOWN;
      break;
    }

    /* FD_SNAPSHOT_MSG_DATA is not possible */
    default: {
      FD_LOG_ERR(( "unexpected control frag %s (%lu) in state %s (%lu)",
                   fd_ssctrl_msg_ctrl_str( sig ), sig,
                   fd_ssctrl_state_str( (ulong)ctx->state ), (ulong)ctx->state ));
      break;
    }
  }

  /* Forward the control message down the pipeline */
  if( FD_LIKELY( forward_msg ) ) {
    fd_stem_publish( stem, 0UL, sig, 0UL, 0UL, 0UL, 0UL, 0UL );
  }

  return 0;
}

/* Up to two frags from after_credit plus one from returnable_frag */
#define STEM_BURST 3UL

#define STEM_LAZY (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snapld_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snapld_tile_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN     should_shutdown
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_NEXT_DEADLINE       next_deadline
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG     returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snapld = {
  .name                     = NAME,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
  .keep_host_networking     = 1,
  .allow_connect            = 1,
  .rlimit_file_cnt          = 5UL, /* stderr, log, http, full/incr local files */
};

/* The instant boot stream downloader runs the same code as snapld. */

fd_topo_run_tile_t fd_tile_strld = {
  .name                     = "strld",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
  .keep_host_networking     = 1,
  .allow_connect            = 1,
  .rlimit_file_cnt          = 5UL, /* stderr, log, http, full/incr local files */
};

#undef NAME
