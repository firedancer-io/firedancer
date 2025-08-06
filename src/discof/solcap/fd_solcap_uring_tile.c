/* This is the 'io_uring' specialization of the 'solcap' tile.

   A solcap tile fans in messages received from a number of input
   links and produces a pcapng file stream.

   This tile schedules writes to an O_DIRECT file by dispatching many
   small (~64 KiB) write requests.  Periodically does an fallocate() to
   increase the size of the file in 16 MiB extents.  Bypasses the page
   cache entirely, so can theoretically work as fast as the underlying
   disk can write.  Uses small enough scratch space to be L3 cache
   friendly (<10 MiB).

   Tested at a rate of 2.5 GB/s (GCP instance). */

#include <liburing.h>
#include <liburing/io_uring.h>
#include <sys/uio.h> /* struct iovec */
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/topo/fd_topo.h"

#define FALLOCATE_SZ (16UL<<20) /* 16 MiB fallocate() size */

#define IN_MAX (16UL)

/* FIXME explicit input link switching */

/* FIXME power saving - go to sleep if device is busy for too long */

struct fd_solcap_buf {
  uchar * laddr;
  ulong   off;
  ulong   next;
};

typedef struct fd_solcap_buf fd_solcap_buf_t;

struct fd_solcap_tile_ctx {
  ulong             buf_max;
  ulong             buf_cnt_max;
  fd_solcap_buf_t * buf_pool;
  ulong             buf_free_head;
  ulong             buf_free_cnt;

  struct io_uring ring[1];
  ulong           sqe_pending;

  ulong file_max;  /* fallocated space */
  ulong file_off;  /* position to write next buffer to */
  int   file_fd;

  int   idle_cnt;
  uint  fallocate_pending : 1;

  void * in_base[ IN_MAX ];
};

typedef struct fd_solcap_tile_ctx fd_solcap_tile_ctx_t;

/* BUF_SENTINEL and BUF_BUSY are special values of a buffer's list
   'next' pointer.  BUF_SENTINEL is also value for the list's head.

   BUF_BUSY is used to detect data structure corruption, such as two
   SQEs referring to the same buf, or an invalid CQE being received. */

#define BUF_SENTINEL 0xffffffffffffffffUL /* NULL pointer */
#define BUF_BUSY     0x7fffffffffffffffUL /* buf awaiting CQE */

/* buf_complete is called when a CQE for a buf write request is found.
   Adds the buf back to the free list/stack.
   The caller is responsible for marking the CQE as 'seen'. */

static void
buf_complete( fd_solcap_tile_ctx_t * ctx,
              struct io_uring_cqe *  cqe ) {
  ulong buf_idx = io_uring_cqe_get_data64( cqe );
  FD_TEST( buf_idx<ctx->buf_cnt_max );
  fd_solcap_buf_t * buf = &ctx->buf_pool[ buf_idx ];
  FD_TEST( buf->next==BUF_BUSY );
  if( FD_UNLIKELY( cqe->res<0 ) ) {
    int err = -cqe->res;
    FD_LOG_ERR(( "io_uring write failed (%i-%s)", err, fd_io_strerror( err ) ));
  }
  buf->off           = 0UL;
  buf->next          = ctx->buf_free_head;
  ctx->buf_free_head = buf_idx;
  ctx->buf_free_cnt++;
}

/* uring_sq_flush submits a burst of SQEs to kernel. */

static void
uring_sq_flush( fd_solcap_tile_ctx_t * ctx ) {
  int res = io_uring_submit( ctx->ring );
  if( FD_UNLIKELY( res<0 ) ) FD_LOG_ERR(( "io_uring_submit() failed (%i-%s)", -res, fd_io_strerror( -res ) ));
  ctx->sqe_pending = 0UL;
}

/* allocate_submit submits a request to extend the size of a file via
   fallocate(). */

static void
allocate_submit( fd_solcap_tile_ctx_t * ctx ) {
  if( ctx->fallocate_pending ) return;
  struct io_uring_sqe * sqe = io_uring_get_sqe( ctx->ring );
  if( FD_UNLIKELY( !sqe ) ) return;
  ulong const alloc_sz = 16UL<<20; /* 16 MiB */
  io_uring_prep_fallocate( sqe, ctx->file_fd, 0, ctx->file_max, alloc_sz );
  io_uring_sqe_set_data64( sqe, ULONG_MAX );
  io_uring_submit( ctx->ring );
  ctx->fallocate_pending = 1;
}

/* allocate_complete is called when a CQE for an fallocate() request is
   found. */

static void
allocate_complete( fd_solcap_tile_ctx_t * ctx,
                   struct io_uring_cqe *  cqe ) {
  if( FD_UNLIKELY( cqe->res<0 ) ) {
    int err = -cqe->res;
    FD_LOG_ERR(( "io_uring fallocate failed (%i-%s)", err, fd_io_strerror( err ) ));
  }
  FD_TEST( ctx->fallocate_pending );
  ctx->file_max += FALLOCATE_SZ;
  ctx->fallocate_pending = 0;
}

/* uring_cq_drain consumes all visible CQEs. */

static void
uring_cq_drain( fd_solcap_tile_ctx_t * ctx,
                int *                  charge_busy ) {
  struct io_uring *     ring = ctx->ring;
  struct io_uring_cqe * cqe  = NULL;
  uint head;
  uint cnt = 0;
  io_uring_for_each_cqe( ring, head, cqe ) {
    if( FD_UNLIKELY( cqe->user_data==ULONG_MAX ) ) {
      allocate_complete( ctx, cqe );
    } else {
      buf_complete( ctx, cqe );
    }
    cnt++;
  }
  io_uring_cq_advance( ring, cnt );
  if( cnt ) *charge_busy = 1;
}

/* before_credit runs every run loop iteration. */

static void
before_credit( fd_solcap_tile_ctx_t * ctx,
               fd_stem_context_t *    stem,
               int *                  charge_busy ) {
  (void)stem;
  ctx->idle_cnt++;
  if( !ctx->buf_free_cnt ) {
    /* Blocked: Wait for CQEs */
    struct io_uring_cqe * cqe;
    int res = io_uring_wait_cqe( ctx->ring, &cqe );
    if( FD_UNLIKELY( res<0 ) ) FD_LOG_ERR(( "io_uring_wait_cqe() failed (%i-%s)", -res, fd_io_strerror( -res ) ));
    uring_cq_drain( ctx, charge_busy );
    *charge_busy = 1;
  }
  if( ctx->sqe_pending >= 128 || /* FIXME don't hardcode magic number */
      ctx->sqe_pending >= ctx->buf_free_cnt ) {
    uring_sq_flush( ctx );
  }
}

/* buf_submit moves the current buf to the uring submission queue. */

static void
buf_submit( fd_solcap_tile_ctx_t * ctx ) {

  /* Restore context */
  FD_TEST( (!!ctx->buf_free_cnt) & (ctx->buf_free_head!=BUF_SENTINEL) );
  struct io_uring_sqe * sqe = io_uring_get_sqe( ctx->ring );
  FD_TEST( sqe );
  ulong buf_idx = ctx->buf_free_head;

  /* Submit buf */
  fd_solcap_buf_t * buf = &ctx->buf_pool[ buf_idx ];
  ctx->buf_free_head = buf->next;
  buf->next = BUF_BUSY;
  io_uring_prep_write_fixed( sqe, ctx->file_fd, buf->laddr, (uint)ctx->buf_max, ctx->file_off, 0 );
  io_uring_sqe_set_data64( sqe, buf_idx );
  ctx->sqe_pending++;

  /* Wind up for next iteration */
  ctx->file_off += ctx->buf_max;
  ctx->buf_free_cnt--;
  if( ctx->buf_free_cnt==0 || ctx->sqe_pending>64 ) uring_sq_flush( ctx );

}

/* frag_append appends a data frag to the log file.  Does a scatter-copy
   of frag content out to internal buffers.  The internal buffers are
   L3 cache friendly, so this memory copy should not be a bottleneck. */

static int
frag_append( fd_solcap_tile_ctx_t * ctx,
             uchar const *          data,
             ulong                  sz ) {
  /* Is any buffer free? */
  if( FD_UNLIKELY( ctx->buf_free_head==BUF_SENTINEL ) ) return FD_STEM_FILT_RETRY;
  long const buf_max = (long)ctx->buf_max;

  /* Needs fragmentation? */
  fd_solcap_buf_t * buf = &ctx->buf_pool[ ctx->buf_free_head ];
  long const block_off  = (long)buf->off;
  long const cur_free   = buf_max - block_off;
  int const  fragmented = (long)sz >= cur_free;
  if( FD_LIKELY( !fragmented ) ) {
    /* Non-fragmented publish */
    uchar * dst = buf->laddr + block_off;
    fd_memcpy( dst, data, sz );
    buf->off += sz;
    return FD_STEM_FILT_ACCEPT;
  }

  /* Enough buffer space to scatter entire message? */
  long const sz_spill   = (long)sz - cur_free;
  long const tail_avail = (long)( ctx->buf_free_cnt-1 ) * buf_max;
  if( sz_spill>tail_avail ) return FD_STEM_FILT_RETRY;

  /* Enough space fallocated to write without expensive metadata append? */
  long const file_avail = (long)ctx->file_max - (long)ctx->file_off;
  if( sz_spill>file_avail ) {
    allocate_submit( ctx );
    return FD_STEM_FILT_RETRY;
  }

  /* Fragmented case follows ... */

  /* Copy message head frag */
  uchar * dst = buf->laddr + buf->off;
  fd_memcpy( dst, data, (ulong)cur_free );
  data += cur_free;
  buf_submit( ctx );

  /* Copy message body frags */
  long rem;
  for( rem=sz_spill; rem>=buf_max; rem-=buf_max ) {
    /* Next buf */
    FD_TEST( ctx->buf_free_head!=BUF_SENTINEL ); buf = &ctx->buf_pool[ ctx->buf_free_head ];

    /* Copy frag */
    long chunk_sz = fd_long_min( rem, (long)ctx->buf_max );
    fd_memcpy( buf->laddr, data, (ulong)chunk_sz );
    data += chunk_sz;

    /* Submit buf */
    buf_submit( ctx );
  } while( rem );

  /* Copy message tail frag */
  if( rem ) {
    /* Next buf */
    FD_TEST( ctx->buf_free_head!=BUF_SENTINEL ); buf = &ctx->buf_pool[ ctx->buf_free_head ];

    /* Copy frag */
    fd_memcpy( buf->laddr, data, (ulong)rem );
    buf->off = (ulong)rem;
  }

  return FD_STEM_FILT_ACCEPT;
}

/* returnable_frag is called when a new frag is available to consume.
   If the frag is unable to be copied to local memory for any reason,
   attempts to drive io_uring and marks the frag for retry in a future
   iteration. */

static int
returnable_frag( fd_solcap_tile_ctx_t * ctx,
                 ulong                  in_idx,
                 ulong                  seq,
                 ulong                  sig,
                 ulong                  chunk,
                 ulong                  sz,
                 ulong                  tsorig,
                 ulong                  tspub,
                 fd_stem_context_t *    stem ) {
  (void)in_idx; (void)seq; (void)sig; (void)sz; (void)tsorig; (void)tspub; (void)stem;
  ctx->idle_cnt = -1;
  uchar const * data = fd_chunk_to_laddr_const( ctx->in_base, chunk );
  int action = frag_append( ctx, data, sz );
  if( FD_UNLIKELY( action==FD_STEM_FILT_RETRY ) ) {
    FD_TEST( io_uring_get_events( ctx->ring )==0 );
    int _charge_busy;
    uring_cq_drain( ctx, &_charge_busy );
  }
  return action;
}

/* during_housekeeping does background tasks at a low-ish rate (10 us
   period). */

static void
during_housekeeping( fd_solcap_tile_ctx_t * ctx ) {
  FD_TEST( *ctx->ring->cq.koverflow==0 );
  if( ctx->sqe_pending ) {
    uring_sq_flush( ctx );
    int _charge_busy = 0;
    uring_cq_drain( ctx, &_charge_busy );
  }
}

static void
metrics_write( fd_solcap_tile_ctx_t * ctx ) {
  FD_MCNT_SET( SOLCAP, FILE_SIZE_BYTES, ctx->file_off );
  FD_MGAUGE_SET( SOLCAP, PREALLOCATED_BYTES, ctx->file_max - ctx->file_off );
  FD_MGAUGE_SET( SOLCAP, SQ_SPACE_LEFT, io_uring_sq_space_left( ctx->ring ) );
}

#define STEM_BURST                        1UL
#define STEM_LAZY                         (ulong)10e3
#define STEM_CALLBACK_CONTEXT_ALIGN       alignof(fd_solcap_tile_ctx_t)
#define STEM_CALLBACK_CONTEXT_TYPE        fd_solcap_tile_ctx_t
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_RETURNABLE_FRAG     returnable_frag
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#include "../../disco/stem/fd_stem.c"

static ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_solcap_tile_ctx_t), FD_SHMEM_NORMAL_PAGE_SZ );
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong const buf_cnt = tile->solcap.block_cnt;
  ulong bufs_max;
  if( FD_UNLIKELY( __builtin_umull_overflow( buf_cnt, tile->solcap.block_sz, &bufs_max ) ) ) return 0;
  if( FD_UNLIKELY( !bufs_max ) ) return 0;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_solcap_tile_ctx_t), sizeof(fd_solcap_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_solcap_buf_t),      buf_cnt * sizeof(fd_solcap_buf_t) );
  l = FD_LAYOUT_APPEND( l, FD_SHMEM_NORMAL_PAGE_SZ,       bufs_max );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
open_file( fd_solcap_tile_ctx_t * ctx ) {
  ctx->file_fd = open( "out.solcap", O_WRONLY|O_CREAT|O_TRUNC|O_DIRECT, 0644 );
  FD_TEST( ctx->file_fd!=-1 );
  ctx->file_off = 0UL;
  /* TODO chown */
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  ulong const buf_cnt  = tile->solcap.block_cnt;
  ulong const bufs_max = tile->solcap.block_cnt * tile->solcap.block_sz;
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_solcap_tile_ctx_t * const ctx  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_solcap_tile_ctx_t), sizeof(fd_solcap_tile_ctx_t) );
  fd_solcap_buf_t *      const desc = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_solcap_buf_t),      buf_cnt*sizeof(fd_solcap_buf_t) );
  uchar *                const bufs = FD_SCRATCH_ALLOC_APPEND( l, FD_SHMEM_NORMAL_PAGE_SZ,       bufs_max );
  ulong                  const end  = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  FD_TEST( end-(ulong)scratch == scratch_footprint( tile ) );
  FD_TEST( (ulong)ctx==(ulong)scratch );
  fd_memset( ctx, 0, sizeof(fd_solcap_tile_ctx_t) );
  ctx->buf_pool = desc;

  open_file( ctx );

  /* Setup io_uring instance */
  struct io_uring_params params = {0};
  params.flags      |= IORING_SETUP_CQSIZE;
  params.cq_entries  = (uint)buf_cnt;
  params.flags      |= IORING_SETUP_COOP_TASKRUN;
  params.flags      |= IORING_SETUP_SINGLE_ISSUER;
  params.features   |= IORING_SETUP_DEFER_TASKRUN;
  FD_TEST( io_uring_queue_init_params( (uint)tile->solcap.block_cnt, ctx->ring, &params )==0 );

  /* Setup io_uring file access */
  FD_TEST( 0==io_uring_register_files( ctx->ring, &ctx->file_fd, 1 ) );

  /* Setup io_uring DMA.  Only using one io_uring registered buffer:
     The block scratch memory region.  Guaranteed to be pinned memory by
     fd_topo. */
  struct iovec iovs[1] = {
    { .iov_base = bufs, .iov_len = bufs_max }
  };
  FD_TEST( 0==io_uring_register_buffers( ctx->ring, iovs, 1UL ) );

  /* Initialize buffer descriptors */
  uchar * cur = bufs;
  for( ulong i=0UL; i<buf_cnt; i++ ) {
    desc[ i ] = (struct fd_solcap_buf) {
      .laddr = cur,
      .off   = 0UL
    };
    cur += tile->solcap.block_sz;
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  fd_solcap_tile_ctx_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  ulong const buf_cnt = tile->solcap.block_cnt;

  ctx->buf_max     = tile->solcap.block_sz;
  ctx->buf_cnt_max = buf_cnt;

  /* Initialize free list */
  ctx->buf_free_head = BUF_SENTINEL;
  for( ulong i=tile->solcap.block_cnt; i>0UL; i-- ) {
    ulong idx = i-1UL;
    ctx->buf_pool[ idx ].next = ctx->buf_free_head;
    ctx->buf_free_head        = idx;
  }
  ctx->buf_free_cnt = buf_cnt;

  FD_TEST( tile->out_cnt==0 );
  ulong const in_cnt = tile->in_cnt;
  FD_TEST( in_cnt<=IN_MAX );
  for( ulong i=0UL; i<in_cnt; i++ ) {
    void * dcache = topo->links[ tile->in_link_id[ i ] ].dcache;
    ctx->in_base[ i ] = fd_wksp_containing( dcache );
  }
}

fd_topo_run_tile_t fd_tile_solcap_uring = {
  .name              = "solcap",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .privileged_init   = privileged_init,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run
};
