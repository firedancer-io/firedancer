#define _GNU_SOURCE
#include "fd_io_uring_setup.h"
#include "../shmem/fd_shmem.h"
#include <errno.h>
#include <sys/mman.h> /* mmap */
#include <unistd.h> /* close */

#define FD_IO_URING_SHMEM_HEADROOM (4096UL)

ulong
fd_io_uring_shmem_align( void ) {
  return FD_SHMEM_NORMAL_PAGE_SZ;
}

struct fd_io_uring_shmem_layout {
  /* offset to completion queue memory region
     This region contains registers (head/tail numbers), the submission
     queue array, and the completion queue (array of CQEs).
     (Do not assume this points to a CQE) */
  ulong cq_off;

  /* offset to SQE array */
  ulong sqe_off;
};

typedef struct fd_io_uring_shmem_layout fd_io_uring_shmem_layout_t;

static ulong
fd_io_uring_shmem_layout( fd_io_uring_shmem_layout_t * layout,
                          ulong                        sq_depth,
                          ulong                        cq_depth ) {
  memset( layout, 0, sizeof(fd_io_uring_shmem_layout_t) );

  if( FD_UNLIKELY( !fd_ulong_is_pow2( sq_depth ) ) ) return 0UL;
  if( FD_UNLIKELY( !fd_ulong_is_pow2( cq_depth ) ) ) return 0UL;
  if( FD_UNLIKELY( sq_depth>UINT_MAX             ) ) return 0UL;
  if( FD_UNLIKELY( cq_depth>UINT_MAX             ) ) return 0UL;

  ulong cq_sz;
  if( FD_UNLIKELY( __builtin_umull_overflow( cq_depth, sizeof(struct io_uring_cqe), &cq_sz ) ) ) return 0UL;
  ulong sqa_sz;
  if( FD_UNLIKELY( __builtin_umull_overflow( sq_depth, sizeof(uint), &sqa_sz ) ) ) return 0UL;

  /* io_uring CQ region

     This API matches Linux io_uring.c rings_size():
     https://elixir.bootlin.com/linux/v6.11.5/source/io_uring/io_uring.c#L2559 */

  FD_SCRATCH_ALLOC_INIT( l, NULL );

  /* The true footprint requirement depends on the kernel version.  The
     head part of this region is 'struct io_rings', which is not stable
     ABI.  We use a very conservative 4 KiB here. */

  layout->cq_off = (ulong)
      FD_SCRATCH_ALLOC_APPEND( l, FD_SHMEM_NORMAL_PAGE_SZ, FD_IO_URING_SHMEM_HEADROOM );

  /* Completion queue (cache line align) */

  FD_SCRATCH_ALLOC_APPEND( l, 128UL, cq_depth*sizeof(struct io_uring_cqe) );

  /* Submission queue index array (cache line align) */

  FD_SCRATCH_ALLOC_APPEND( l, 128UL, sq_depth*sizeof(uint) );

  /* io_uring SQEs region */

  layout->sqe_off = (ulong)FD_SCRATCH_ALLOC_APPEND(
      l, FD_SHMEM_NORMAL_PAGE_SZ, sq_depth*sizeof(struct io_uring_sqe) );

  return FD_SCRATCH_ALLOC_FINI( l, FD_SHMEM_NORMAL_PAGE_SZ );
}

ulong
fd_io_uring_shmem_footprint( ulong   sq_depth,
                             ulong   cq_depth ) {
  fd_io_uring_shmem_layout_t layout[1];
  return fd_io_uring_shmem_layout( layout, sq_depth, cq_depth );
}

struct io_uring_params *
fd_io_uring_shmem_setup( struct io_uring_params * params,
                         void *                   shmem,
                         ulong                    sq_depth,
                         ulong                    cq_depth ) {

  fd_io_uring_shmem_layout_t layout[1];
  ulong shmem_footprint = fd_io_uring_shmem_layout( layout, sq_depth, cq_depth );
  if( FD_UNLIKELY( !shmem_footprint ) ) {
    FD_LOG_WARNING(( "invalid sq_depth (%lu) or cq_depth (%lu)", sq_depth, cq_depth ));
    return NULL;
  }

  params->flags |= IORING_SETUP_NO_MMAP;
  params->sq_entries = (uint)sq_depth;
  params->cq_entries = (uint)cq_depth;

  /* cq_off points to the region containing the kernel private io_rings
     struct, the completion queue (array of CQEs), and the submission
     queue array (array of uints). */

  params->cq_off = (struct io_cqring_offsets) {
    .user_addr = (unsigned long long)( (uchar *)shmem ),
  };

  /* sq_off points to the table of submission queue entries. */

  params->sq_off = (struct io_sqring_offsets) {
    .user_addr = (unsigned long long)( (uchar *)shmem + layout->sqe_off ),
  };

  return params;
}

static void
fd_io_uring_init_rings(
    fd_io_uring_sq_t *       sq,
    fd_io_uring_cq_t *       cq,
    struct io_uring_params * params,
    void *                   sqe_mem,
    void *                   cq_mem
) {
  ulong sqe_laddr = (ulong)sqe_mem;
  ulong cq_laddr  = (ulong)cq_mem;

  FD_CRIT( fd_ulong_is_pow2( params->sq_entries ), "invalid params->sq_entries" );
  FD_CRIT( fd_ulong_is_pow2( params->cq_entries ), "invalid params->cq_entries" );

  *sq = (fd_io_uring_sq_t) {
    /* Confusingly, in Linux io_uring, submission queue registers are
       located in the completion queue memory region */
    .khead    = (void *)( cq_laddr + params->sq_off.head    ),
    .ktail    = (void *)( cq_laddr + params->sq_off.tail    ),
    .kflags   = (void *)( cq_laddr + params->sq_off.flags   ),
    .kdropped = (void *)( cq_laddr + params->sq_off.dropped ),

    .array = (void *)( cq_laddr + params->sq_off.array ),
    .sqes  = (void *)( sqe_laddr                       ),

    .sqe_head = 0,
    .sqe_tail = 0,
    .depth    = params->sq_entries
  };

  *cq = (fd_io_uring_cq_t) {
    .depth = params->cq_entries,

    .khead     = (void *)( cq_laddr + params->cq_off.head    ),
    .ktail     = (void *)( cq_laddr + params->cq_off.tail    ),
    .koverflow = (void *)( cq_laddr + params->cq_off.overflow ),

    .cqes = (void *)( cq_laddr + params->cq_off.cqes )
  };

  /* io_uring uses a rather useless indirection table to map queue slots
     to entries. */

  for( uint i=0; i<params->sq_entries; i++ ) {
    sq->array[ i ] = i;
  }
}

fd_io_uring_t *
fd_io_uring_init_shmem(
    fd_io_uring_t *          ring,
    struct io_uring_params * params,
    void *                   shmem,
    ulong                    sq_depth,
    ulong                    cq_depth
) {
  memset( ring, 0, sizeof(fd_io_uring_t) );
  ring->ioring_fd = -1;

  params->flags      |= IORING_SETUP_CQSIZE;
  params->sq_entries  = (uint)sq_depth;
  params->cq_entries  = (uint)cq_depth;

  fd_io_uring_shmem_setup( params, shmem, sq_depth, cq_depth );

  memset( shmem, 0, FD_IO_URING_SHMEM_HEADROOM );

  int ring_fd = fd_io_uring_setup( (uint)sq_depth, params );
  if( FD_UNLIKELY( ring_fd<0 ) ) return NULL;
  ring->ioring_fd = ring_fd;

  fd_io_uring_shmem_layout_t layout[1];
  fd_io_uring_shmem_layout( layout, sq_depth, cq_depth );

  fd_io_uring_init_rings(
      ring->sq,
      ring->cq,
      params,
      (void *)( (ulong)shmem + layout->sqe_off ),
      (void *)( (ulong)shmem + layout->cq_off  )
  );
  return ring;
}

fd_io_uring_t *
fd_io_uring_init_mmap(
    fd_io_uring_t *          ring,
    struct io_uring_params * params
) {
  memset( ring, 0, sizeof(fd_io_uring_t) );
  ring->ioring_fd = -1;

  uint sq_depth = params->sq_entries;
  uint cq_depth = params->cq_entries;

  int ring_fd = fd_io_uring_setup( params->sq_entries, params );
  if( FD_UNLIKELY( ring_fd<0 ) ) return NULL;
  ring->ioring_fd = ring_fd;

  if( FD_UNLIKELY( params->sq_entries != sq_depth ||
                   params->cq_entries != cq_depth ) ) {
    FD_LOG_WARNING(( "io_uring setup failed: requested (sq_depth=%u, cq_depth=%u) but kernel returned (sq_depth=%u, cq_depth=%u)",
                     params->sq_entries, params->cq_entries,
                     sq_depth,           cq_depth ));
    close( ring_fd );
    ring->ioring_fd = -1;
    return NULL;
  }

  ring->kern_sq_sz  = params->sq_off.array + params->sq_entries * sizeof(uint);
  ring->kern_sqe_sz = /*                  */ params->sq_entries * sizeof(struct io_uring_sqe);
  ring->kern_cq_sz  = params->cq_off.cqes  + params->cq_entries * sizeof(struct io_uring_cqe);

  ring->kern_sq_mem = mmap( NULL, ring->kern_sq_sz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, ring_fd, IORING_OFF_SQ_RING );
  if( FD_UNLIKELY( ring->kern_sq_mem==MAP_FAILED ) ) {
    FD_LOG_WARNING(( "mmap SQ ring failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    close( ring_fd );
    ring->ioring_fd = -1;
    return NULL;
  }

  ring->kern_sqe_mem = mmap( NULL, ring->kern_sqe_sz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, ring_fd, IORING_OFF_SQES );
  if( FD_UNLIKELY( ring->kern_sqe_mem==MAP_FAILED ) ) {
    munmap( ring->kern_sq_mem, ring->kern_sq_sz );
    close( ring_fd );
    ring->ioring_fd = -1;
    FD_LOG_WARNING(( "mmap SQEs failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  ring->kern_cq_mem = mmap( NULL, ring->kern_cq_sz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, ring_fd, IORING_OFF_CQ_RING );
  if( FD_UNLIKELY( ring->kern_cq_mem==MAP_FAILED ) ) {
    munmap( ring->kern_sqe_mem, ring->kern_sqe_sz );
    munmap( ring->kern_sq_mem,  ring->kern_sq_sz  );
    close( ring_fd );
    ring->ioring_fd = -1;
    FD_LOG_WARNING(( "mmap CQ ring failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  fd_io_uring_init_rings(
      ring->sq,
      ring->cq,
      params,
      ring->kern_sqe_mem,
      ring->kern_cq_mem
  );

  return ring;
}

void *
fd_io_uring_fini( fd_io_uring_t * ring ) {

  if( ring->kern_cq_mem ) {
    if( FD_UNLIKELY( munmap( ring->kern_cq_mem, ring->kern_cq_sz ) ) ) {
      FD_LOG_WARNING(( "munmap CQ ring failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    ring->kern_cq_mem = NULL;
    ring->kern_cq_sz  = 0UL;
  }

  if( ring->kern_sqe_mem ) {
    if( FD_UNLIKELY( munmap( ring->kern_sqe_mem, ring->kern_sqe_sz ) ) ) {
      FD_LOG_WARNING(( "munmap SQEs failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    ring->kern_sqe_mem = NULL;
    ring->kern_sqe_sz  = 0UL;
  }

  if( ring->kern_sq_mem ) {
    if( FD_UNLIKELY( munmap( ring->kern_sq_mem, ring->kern_sq_sz ) ) ) {
      FD_LOG_WARNING(( "munmap SQ ring failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    ring->kern_sq_mem = NULL;
    ring->kern_sq_sz  = 0UL;
  }

  if( ring->ioring_fd>=0 ) {
    if( FD_UNLIKELY( close( ring->ioring_fd ) ) ) {
      FD_LOG_WARNING(( "close(ring_fd) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    ring->ioring_fd = -1;
  }

  memset( ring->sq, 0, sizeof(fd_io_uring_sq_t) );
  memset( ring->cq, 0, sizeof(fd_io_uring_cq_t) );

  return ring;
}
