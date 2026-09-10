#define _GNU_SOURCE
#include "utils/fd_ssarchive.h"
#include "utils/fd_ssctrl.h"
#include "utils/fd_sshttp.h"
#include "utils/fd_sspeer_selector.h"

#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../waltz/openssl/fd_openssl_tile.h"

#include <sys/mman.h> /* memfd_create */
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/socket.h>

#include "generated/fd_snapld_tile_seccomp.h"

#define NAME "snapld"

/* download progress in each 10 second window must be at
   min_download_speed_mibs * 10 seconds or higher.  Catches extremely
   slow download speeds where we may not get to 100 MiB downloaded for a
   while. */
#define FD_SNAPLD_DOWNLOAD_WINDOW_NS (10L*1000L*1000L*1000L) /* 10 seconds */

/* The snapld tile is responsible for loading data from the local file
   or from an HTTP/TCP connection and sending it to the snapdc tile
   for later decompression. */

/* Upper bound on dcache slots filled by one read().  The actual count is
   clamped to the flow-control credits available at the time, so this is a
   ceiling and not a threshold the tile waits to reach. */
#define FD_SNAPLD_READ_MAX (1024UL)

typedef struct fd_snapld_tile {

  struct {
    char path[ PATH_MAX ];
    uint min_download_speed_mibs;
  } config;

  int   state;
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
  int direct_io;    /* snapshot fds were opened O_DIRECT */
  int direct_align; /* ...and the dcache ring is page-aligned, so we may use it */
  int sockfd;

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

FD_FN_CONST static inline ulong
loose_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  /* Leftover space for OpenSSL allocations */
  return 1UL<<26UL; /* 64 MiB */
}



  /* Report how much of a file is already in the page cache, as a percentage,
     by probing PROBES offsets spread evenly through it.  preadv2 with
     RWF_NOWAIT fails with EAGAIN instead of blocking when a page is not
     resident, so this costs a few microseconds and reads nothing.

     Returns 100 if the probe cannot be run at all (old kernel, ENOSYS,
     filesystem without RWF_NOWAIT support), which keeps the buffered path --
     the conservative choice, since buffered is never catastrophically wrong
     while O_DIRECT on a fully cached file gives up 6.3s. */

#define FD_SNAPLD_CACHE_PROBES (64UL)

static ulong
cached_pct( int   fd,
            ulong sz ) {
  if( FD_UNLIKELY( sz<FD_SNAPLD_CACHE_PROBES ) ) return 100UL;
  uchar buf[ 1 ];
  ulong hits = 0UL;
  ulong step = sz/FD_SNAPLD_CACHE_PROBES;
  for( ulong i=0UL; i<FD_SNAPLD_CACHE_PROBES; i++ ) {
    struct iovec iov = { .iov_base = buf, .iov_len = 1UL };
    long r = preadv2( fd, &iov, 1, (long)(i*step), RWF_NOWAIT );
    if( FD_UNLIKELY( r<0L && errno!=EAGAIN ) ) return 100UL; /* cannot tell */
    if( r>0L ) hits++;
  }
  return (100UL*hits)/FD_SNAPLD_CACHE_PROBES;
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
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
  /* fd_ssarchive_latest_pair needs to be invoked here, irrespective
     of whether snapct may do the same, because this information is
     needed here during privileged_init. */
  if( FD_LIKELY( -1!=fd_ssarchive_latest_pair( tile->snapld.snapshots_path,
                                               tile->snapld.incremental_snapshots,
                                               &full_slot,         &incr_slot,
                                               full_path,          incr_path,
                                               &full_is_zstd,      &incr_is_zstd,
                                               full_snapshot_hash, incr_snapshot_hash ) ) ) {
    FD_TEST( full_slot!=ULONG_MAX );

    /* O_DIRECT: the snapshot is read once, streamed straight into the dcache
       ring, and never looked at again, so there is nothing for the page cache
       to do except cost a copy -- two thirds of this tile's cycles.  Not every
       filesystem accepts it, so fall back rather than fail. */
    /* Open buffered, ask whether the archive is already resident, and only
       then decide.  O_DIRECT is worth ~15.7s when the file is cold and costs
       ~6.3s when it is hot, so the answer matters more than the default. */
    ctx->local_full_fd = open( full_path, O_RDONLY|O_CLOEXEC|O_NONBLOCK );
    ctx->direct_io     = 0;
    if( FD_LIKELY( -1!=ctx->local_full_fd ) ) {
      struct stat st;
      ulong pct = 100UL;
      if( FD_LIKELY( !fstat( ctx->local_full_fd, &st ) ) ) pct = cached_pct( ctx->local_full_fd, (ulong)st.st_size );
      if( pct<30UL ) { /* ldthresh30: crossover measured between 26% and 40% (SS7z145) */
        int dfd = open( full_path, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_DIRECT );
        if( FD_LIKELY( -1!=dfd ) ) {
          close( ctx->local_full_fd );
          ctx->local_full_fd = dfd;
          ctx->direct_io     = 1;
        } else {
          FD_LOG_NOTICE(( "open() with O_DIRECT failed `%s` (%i-%s), staying buffered", full_path, errno, fd_io_strerror( errno ) ));
        }
      }
      FD_LOG_NOTICE(( "snapshot %lu%% resident in page cache; using %s reads", pct, ctx->direct_io ? "O_DIRECT" : "buffered" ));
    }
    if( FD_UNLIKELY( -1==ctx->local_full_fd ) ) FD_LOG_ERR(( "open() failed `%s` (%i-%s)", full_path, errno, fd_io_strerror( errno ) ));
    posix_fadvise( ctx->local_full_fd, 0L, 0L, POSIX_FADV_SEQUENTIAL );

    if( FD_LIKELY( incr_slot!=ULONG_MAX ) ) {
      ctx->local_incr_fd = open( incr_path, O_RDONLY|O_CLOEXEC|O_NONBLOCK|(ctx->direct_io?O_DIRECT:0) );
      if( FD_UNLIKELY( -1==ctx->local_incr_fd ) ) FD_LOG_ERR(( "open() failed `%s` (%i-%s)", incr_path, errno, fd_io_strerror( errno ) ));
      posix_fadvise( ctx->local_incr_fd, 0L, 0L, POSIX_FADV_SEQUENTIAL );
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
  if( FD_UNLIKELY( out_fds_cnt<5UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

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
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapld_tile_t * ctx  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapld_tile_t),  sizeof(fd_snapld_tile_t) );
  FD_SCRATCH_ALLOC_APPEND( l, fd_sshttp_align(),          fd_sshttp_footprint()    );
  FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(),           fd_alloc_footprint()     );

  fd_memcpy( ctx->config.path, tile->snapld.snapshots_path, PATH_MAX );
  ctx->config.min_download_speed_mibs = tile->snapld.min_download_speed_mibs;

  ctx->state            = FD_SNAPSHOT_STATE_IDLE;

  ctx->download_speed_mibs = 0.0;
  ctx->bytes_in_batch      = 0UL;
  ctx->start_batch         = 0L;
  ctx->end_batch           = 0L;
  ctx->bytes_in_window     = 0UL;
  ctx->window_deadline     = LONG_MAX;
  ctx->min_bytes_in_window = ((ulong)ctx->config.min_download_speed_mibs * (FD_SNAPLD_DOWNLOAD_WINDOW_NS / (ulong)1e9))<<20UL;

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

  /* O_DIRECT reads go straight into the ring, so slot 0 must be page-aligned.
     Every subsequent read starts a multiple of 32 slots
     later, and that displacement is 4096-aligned by construction, so checking
     slot 0 is sufficient.  Check rather than assume: the dcache base depends
     on workspace layout, and silently doing unaligned O_DIRECT would mean
     EINVAL on every read. */
  ulong slot0_addr  = (ulong)fd_chunk_to_laddr( ctx->out_dc.mem, ctx->out_dc.chunk0 );
  ctx->direct_align = !(slot0_addr%4096UL) && !((32UL*ctx->out_dc.mtu)%4096UL);
  if( FD_UNLIKELY( ctx->direct_io && !ctx->direct_align ) ) {
    FD_LOG_NOTICE(( "snapld dcache slot 0 at %#lx is not 4096-aligned; using buffered reads", slot0_addr ));
  }
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
metrics_write( fd_snapld_tile_t * ctx ) {
#if FD_HAS_OPENSSL
  FD_MCNT_SET(   SNAPLD, SSL_ALLOC_FAILED, fd_ossl_alloc_errors );
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

static int
check_download_progress( fd_snapld_tile_t *  ctx,
                         fd_stem_context_t * stem,
                         int                 downloading,
                         long                now ) {
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

static void
after_credit( fd_snapld_tile_t *  ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in FD_PARAM_UNUSED,
              int *               charge_busy ) {
  if( ctx->state!=FD_SNAPSHOT_STATE_PROCESSING ) {
    fd_log_sleep( (long)1e6 );
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
    /* Fill as many consecutive dcache slots as we have credits for and as
       remain before the wmark, in a single read().  The slots are contiguous,
       so this needs no staging buffer and adds no copy.  Clamping to cr_avail
       is what keeps STEM_BURST small: the tile never waits for a large credit
       balance, it just reads less when downstream is behind. */
    ulong slots       = FD_SNAPLD_READ_MAX;
    ulong cr          = stem->cr_avail[ 0 ];
    if( FD_UNLIKELY( cr<slots ) ) slots = cr;
    ulong slot_chunks = ctx->out_dc.mtu >> FD_CHUNK_LG_SZ;
    ulong avail_slots = 1UL + ( (ctx->out_dc.wmark - ctx->out_dc.chunk) / slot_chunks );
    if( FD_UNLIKELY( avail_slots<slots ) ) slots = avail_slots;
    if( FD_UNLIKELY( ctx->direct_io && ctx->direct_align ) ) {
      /* Snap the cursor onto the 32-slot grid.  Both the buffer address and the
         read length must be 4096-aligned for O_DIRECT; 32 slots is the smallest
         unit for which slots*65408 is a whole number of pages.  Skipped slots
         are never published -- at most 31 slots of ring space per meta frag,
         twice per load. */
      ulong max_slot = (ctx->out_dc.wmark - ctx->out_dc.chunk0) / slot_chunks;
      ulong slot_idx = (ctx->out_dc.chunk - ctx->out_dc.chunk0 + slot_chunks - 1UL) / slot_chunks;
      ulong rem      = slot_idx % 32UL;
      if( rem ) slot_idx += 32UL - rem;
      if( FD_UNLIKELY( slot_idx+32UL-1UL>max_slot ) ) slot_idx = 0UL;
      ctx->out_dc.chunk = ctx->out_dc.chunk0 + slot_idx*slot_chunks;
      out               = fd_chunk_to_laddr( ctx->out_dc.mem, ctx->out_dc.chunk );
      /* re-derive headroom from the moved cursor, then quantise the length */
      avail_slots = 1UL + ( (ctx->out_dc.wmark - ctx->out_dc.chunk) / slot_chunks );
      if( FD_UNLIKELY( avail_slots<slots ) ) slots = avail_slots;
      slots -= slots % 32UL;
      if( FD_UNLIKELY( !slots ) ) return;
    }
    if( FD_UNLIKELY( !slots ) ) slots = 1UL;

    long result = read( ctx->load_full ? ctx->local_full_fd : ctx->local_incr_fd,
                        out, slots*ctx->out_dc.mtu );
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
      /* One frag per slot; sizes must stay <= mtu and the tail is the
         remainder.  cr_avail bounded the read, so a credit exists for each. */
      ulong left = (ulong)result;
      while( left ) {
        ulong psz = fd_ulong_min( left, ctx->out_dc.mtu );
        fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_DATA, ctx->out_dc.chunk, psz, 0UL, 0UL, 0UL );
        ctx->out_dc.chunk = fd_dcache_compact_next( ctx->out_dc.chunk, psz, ctx->out_dc.chunk0, ctx->out_dc.wmark );
        left -= psz;
      }
      *charge_busy = 1;
      return; /* verbose return */
    }
  } else {
    int   downloading = 0;
    ulong data_len    = ctx->out_dc.mtu;
    long  now         = fd_log_wallclock();
    int   result      = fd_sshttp_advance( ctx->sshttp, &data_len, out, &downloading, now );
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
          ctx->start_batch = fd_log_wallclock();
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

          /* Populate resolved redirect fields in META */
          meta->resolved_slot    = ULONG_MAX;
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

          ctx->sent_meta = 1;
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
      long now = fd_log_wallclock();
      if( ctx->load_file ) {
        if( FD_UNLIKELY( 0!=lseek( ctx->load_full ? ctx->local_full_fd : ctx->local_incr_fd, 0, SEEK_SET ) ) )
          FD_LOG_ERR(( "lseek(0) failed on %s snapshot file (%i-%s)",
                       ctx->load_full ? "full" : "incremental", errno, fd_io_strerror( errno ) ));
      } else {
        if( FD_UNLIKELY( fd_sshttp_init( ctx->sshttp, msg_in->addr, msg_in->hostname, msg_in->is_https, msg_in->path, msg_in->path_len, 4UL, now ) ) ) {
          transition_malformed( ctx, stem );
          forward_msg = 0;
          break;
        }
      }
      fd_ssctrl_init_t * msg_out = fd_chunk_to_laddr( ctx->out_dc.mem, ctx->out_dc.chunk );
      fd_memcpy( msg_out, msg_in, sz );
      fd_stem_publish( stem, 0UL, sig, ctx->out_dc.chunk, sz, 0UL, 0UL, 0UL );
      ctx->out_dc.chunk = fd_dcache_compact_next( ctx->out_dc.chunk, ctx->out_dc.mtu, ctx->out_dc.chunk0, ctx->out_dc.wmark );
      forward_msg = 0; // we are forwarding the control message in the `fd_sstrl_init_t` message
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
/* Entry gate only.  Reads are clamped to cr_avail, so the tile does not need
   a large credit balance before it may run -- which is the whole point. */
#define STEM_BURST 4UL

#define STEM_LAZY (128L*3000L)

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
