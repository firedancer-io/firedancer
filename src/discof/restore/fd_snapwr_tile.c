/* The snapwr tile dispatches O_DIRECT writes of large (~O(10MiB))
   blocks to a vinyl bstream file.  This tile practically only does
   blocking write(2) calls, which typically just yield to the kernel
   scheduler until I/O completes.

   Alternatives considered:
   - Doing blocking O_DIRECT writes in the snapin tile is possible, but
     starves the snapin tile off valuable CPU cycles while waiting for
     write completions.
   - Writing using the page cache (without O_DIRECT) similarly pipelines
     writes through background dirty cache flushing.  Has a noticeable
     throughput cost.
   - io_uring with O_DIRECT has significantly lower latency (due to
     fewer per-op overhead, and thus smaller possible block sizes), and
     slightly better throughput.  However, is much more complex, less
     portable, and less secure (harder to sandbox).

   While writing, under the hood, the following happens on a fast NVMe
   paired with an optimized file system (e.g. XFS):
   - Userland context switches to kernel context via pwrite64
   - Kernel sets up IOMMU page table entries, allowing NVMe device to
     read userland memory
   - Kernel sends write commands to NVMe device
   - Kernel suspends thread
     ...
   - NVMe device does DMA reads, writes to disk
     ...
   - NVMe device sends completions to kernel
   - Kernel removes IOMMU page table entries (might send IPIs ... sad)
   - Kernel swaps back to userland and resumes
   The above is a *lot* of overhead per-operation, which is the reason
   for multiple megabyte buffer sizes.

   The snapwr tile is thus expected to spend most of its time sleeping
   waiting for disk I/O to complete.  The snapwr tile typically runs in
   "floating" mode.  If there is no work to do, it saves power by going
   to sleep for 1 millisecond at a time.

   Accepted message descriptors:

   - ctl==FD_SNAPSHOT_MSG_DATA
     - chunk: compressed byte offset, relative to dcache data region (>>FD_CHUNK_LG_SZ)
     - sig:   file offset to write to
     - sz:    compressed write size (>>FD_VINYL_BSTREAM_BLOCK_LG_SZ)

   - ctl==FD_SNAPSHOT_MSG_CTRL_INIT_FULL

   - ctl==FD_SNAPSHOT_MSG_CTRL_INIT_INCR
     - sig:   file offset to rewind "bytes written" metric to

   - ctl==FD_SNAPSHOT_MSG_CTRL_SHUTDOWN */

#define _GNU_SOURCE /* O_DIRECT */
#include "utils/fd_ssctrl.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../vinyl/bstream/fd_vinyl_bstream.h"
#include "generated/fd_snapwr_tile_seccomp.h"

#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h> /* open */
#include <unistd.h> /* pwrite */

#define NAME "snapwr"

struct fd_snapwr {
  uint         state;
  int          dev_fd;
  ulong        dev_sz;
  void const * base;
  ulong *      seq_sync;  /* fseq->seq[0] */
  uint         idle_cnt;

  struct {
    ulong last_off;
  } metrics;
};

typedef struct fd_snapwr fd_snapwr_t;

static ulong
scratch_align( void ) {
  return alignof(fd_snapwr_t);
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  return sizeof(fd_snapwr_t);
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  fd_snapwr_t * snapwr = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  memset( snapwr, 0, sizeof(fd_snapwr_t) );

  char const * vinyl_path = tile->snapwr.vinyl_path;
  int vinyl_fd = open( vinyl_path, O_RDWR|O_DIRECT|O_CLOEXEC, 0644 );
  if( FD_UNLIKELY( vinyl_fd<0 ) ) FD_LOG_ERR(( "open(%s,O_RDWR|O_DIRECT|O_CLOEXEC,0644) failed (%i-%s)", vinyl_path, errno, strerror( errno ) ));

  struct stat st;
  if( FD_UNLIKELY( 0!=fstat( vinyl_fd, &st ) ) ) FD_LOG_ERR(( "fstat(%s) failed (%i-%s)", vinyl_path, errno, strerror( errno ) ));

  snapwr->dev_fd  = vinyl_fd;
  snapwr->dev_sz  = fd_ulong_align_dn( (ulong)st.st_size, FD_VINYL_BSTREAM_BLOCK_SZ );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  fd_snapwr_t * snapwr = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  memset( &snapwr->metrics, 0, sizeof(snapwr->metrics) );

  if( FD_UNLIKELY( tile->kind_id      ) ) FD_LOG_ERR(( "There can only be one `" NAME "` tile" ));
  if( FD_UNLIKELY( tile->in_cnt !=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 1",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=0UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 0", tile->out_cnt ));

  fd_topo_link_t const * in_link = &topo->links[ tile->in_link_id[ 0 ] ];
  if( FD_UNLIKELY( !tile->in_link_reliable[ 0 ] ) ) FD_LOG_ERR(( "tile `" NAME "` in link 0 must be reliable" ));
  ulong * fseq = tile->in_link_fseq[ 0 ];
  snapwr->base     = in_link->dcache;
  snapwr->seq_sync = &fseq[ 0 ];

  snapwr->state = FD_SNAPSHOT_STATE_IDLE;
}

static ulong
populate_allowed_fds( fd_topo_t      const * topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  fd_snapwr_t const * snapwr = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2UL; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) {
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  }
  out_fds[ out_cnt++ ] = snapwr->dev_fd;

  return out_cnt;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  fd_snapwr_t const * snapwr = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  populate_sock_filter_policy_fd_snapwr_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)snapwr->dev_fd );
  return sock_filter_policy_fd_snapwr_tile_instr_cnt;
}

static int
should_shutdown( fd_snapwr_t const * ctx ) {
  return ctx->state==FD_SNAPSHOT_STATE_SHUTDOWN;
}

static void
before_credit( fd_snapwr_t *       ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;
  if( ++ctx->idle_cnt >= 1024U ) {
    fd_log_sleep( (long)1e6 ); /* 1 millisecond */
    *charge_busy = 0;
    ctx->idle_cnt = 0U;
  }
}

static void
metrics_write( fd_snapwr_t * ctx ) {
  FD_MGAUGE_SET( SNAPWR, STATE,               ctx->state            );
  FD_MGAUGE_SET( SNAPWR, VINYL_BYTES_WRITTEN, ctx->metrics.last_off );
}

/* handle_control_frag handles an administrative frag from the snapin
   tile. */

static void
handle_control_frag( fd_snapwr_t * ctx,
                     ulong         meta_ctl,
                     ulong         meta_sig ) {
  switch( meta_ctl ) {
  case FD_SNAPSHOT_MSG_CTRL_INIT_FULL:
    ctx->metrics.last_off = 0UL;
    ctx->state = FD_SNAPSHOT_STATE_PROCESSING;
    break;
  case FD_SNAPSHOT_MSG_CTRL_INIT_INCR:
    ctx->metrics.last_off = meta_sig;
    ctx->state = FD_SNAPSHOT_STATE_PROCESSING;
    break;
  case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN:
    ctx->state = FD_SNAPSHOT_STATE_SHUTDOWN;
    metrics_write( ctx );
    break;
  default:
    FD_LOG_CRIT(( "received unexpected ssctrl msg type %lu", meta_ctl ));
  }
}

/* handle_data_frag handles a bstream block sz-aligned write request.
   Does a synchronous blocking O_DIRECT write. */

static void
handle_data_frag( fd_snapwr_t * ctx,
                  ulong         chunk,      /* compressed input pointer */
                  ulong         dev_off,    /* file offset */
                  ulong         sz_comp ) { /* compressed input size */
  ulong        src_sz = sz_comp<<FD_VINYL_BSTREAM_BLOCK_LG_SZ;
  void const * src    = fd_chunk_to_laddr_const( ctx->base, chunk );
  FD_CRIT( fd_ulong_is_aligned( (ulong)src, FD_VINYL_BSTREAM_BLOCK_SZ ), "misaligned write request" );
  FD_CRIT( fd_ulong_is_aligned( src_sz, FD_VINYL_BSTREAM_BLOCK_SZ ),     "misaligned write request" );
  if( FD_UNLIKELY( dev_off+src_sz > ctx->dev_sz ) ) {
    FD_LOG_CRIT(( "vinyl bstream log is out of space" ));
  }

  /* Do a synchronous write(2) */
  ssize_t write_sz = pwrite( ctx->dev_fd, src, src_sz, (off_t)dev_off );
  if( FD_UNLIKELY( write_sz<0 ) ) {
    FD_LOG_ERR(( "pwrite(off=%lu,sz=%lu) failed (%i-%s)", dev_off, src_sz, errno, strerror( errno ) ));
  }
  ctx->metrics.last_off = dev_off+src_sz;
}

static int
during_frag( fd_snapwr_t *       ctx,
             ulong               in_idx,
             ulong               meta_seq,
             ulong               meta_sig,
             ulong               meta_chunk,
             ulong               meta_sz,
             ulong               meta_ctl ) {
  (void)in_idx;
  ctx->idle_cnt = 0U;

  if( FD_UNLIKELY( meta_ctl==FD_SNAPSHOT_MSG_DATA ) ) {
    handle_data_frag( ctx, meta_chunk, meta_sig, meta_sz );
  } else {
    handle_control_frag( ctx, meta_ctl, meta_sig );
  }

  /* Because snapwr pacing is so loose and this tile sleeps, fd_stem
     will not return flow control credits fast enough.
     So, always update fseq (consumer progress) here. */
  ctx->seq_sync[ 0 ] = fd_seq_inc( meta_seq, 1UL );

  return 0;
}

#define STEM_BURST 1UL
#define STEM_LAZY  ((long)2e6)
#define STEM_CALLBACK_CONTEXT_TYPE    fd_snapwr_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(fd_snapwr_t)
#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_BEFORE_CREDIT   before_credit
#define STEM_CALLBACK_DURING_FRAG     during_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snapwr = {
  .name                     = NAME,
  .populate_allowed_fds     = populate_allowed_fds,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run
};

#undef NAME
