#ifndef HEADER_fd_src_vinyl_io_ur_fd_vinyl_io_ur_private_h
#define HEADER_fd_src_vinyl_io_ur_fd_vinyl_io_ur_private_h

/* io_uring-based I/O backend.  This backend implements a number of
   advanced optimizations:

   1. Write-back cache: all bstream writes are buffered in memory and
      confirmed instantly, before attempting actual write operations.
      This significantly reduces latency for append and commit ops.
   2. In-place writes: normal alloc/append/commit usage directly
      emplaces new blocks into the write buffer.
   3. Direct I/O: Writes bypass the page cache for improved performance
      (reads still use the page cache, though).
   4. Fully async: Reads and writes are enqueued via io_uring and can
      be arbitrarily interleaved.

   Consequently, this backend's methods behave differently than
   fd_vinyl_io.h documents:

   - commit does not empty the scratch pad */

#include "fd_vinyl_io_ur.h"
#include "wb_ring.h"
#include "wq_ring.h"
#include <errno.h>
#include <unistd.h> /* pread, pwrite */

/* WQ_DEPTH sets the max number of write queue jobs that io_ur can track
   at once.

   WQ_BLOCK_SZ sets the write block size.

   WQ_DEPTH*WQ_BLOCK_SZ is thus the write window size (bandwidth-delay
   product).  For example, with a 32 MiB window size, and 1ms write
   latency, the max write rate is ~ 32 GiB/s. */

#define WQ_DEPTH    (64UL)
#define WQ_BLOCK_SZ (1UL<<19) /* 512KiB */

/* fd_vinyl_io_ur_rd_t extends fd_vinyl_io_rd_t.  Describes an inflight
   read request.  Each object gets created with a fd_vinyl_io_read()
   call, has at least the lifetime of a io_uring SQE/CQE transaction,
   and gets destroyed with fd_vinyl_io_poll().

   Each fd_vinyl_io_rd_t describes a contiguous read in bstream seq
   space.  When mapped to the device, this typically results in a single
   contiguous read. */

struct fd_vinyl_io_ur_rd;
typedef struct fd_vinyl_io_ur_rd fd_vinyl_io_ur_rd_t;

struct fd_vinyl_io_ur_rd {
  ulong                 ctx;  /* Must mirror fd_vinyl_io_rd_t */
  ulong                 seq;  /* " */
  void *                dst;  /* " */
  ulong                 sz;   /* " */

  uint                  csz;  /* Chunk size */
  fd_vinyl_io_ur_rd_t * next; /* Next element in ur rd queue */
};

FD_STATIC_ASSERT( sizeof(fd_vinyl_io_ur_rd_t)<=sizeof(fd_vinyl_io_rd_t), layout );

/* fd_vinyl_io_ur_t extends fd_vinyl_io_t. */

struct fd_vinyl_io_ur {
  fd_vinyl_io_t            base[1];
  int                      dev_fd;       /* File descriptor of block device */
  ulong                    dev_sync;     /* Offset to block that holds bstream sync (BLOCK_SZ multiple) */
  ulong                    dev_base;     /* Offset to first block (BLOCK_SZ multiple) */
  ulong                    dev_sz;       /* Block store byte size (BLOCK_SZ multiple) */
  fd_vinyl_io_ur_rd_t *    rd_head;      /* Pointer to queue head */
  fd_vinyl_io_ur_rd_t **   rd_tail_next; /* Pointer to queue &tail->next or &rd_head if empty. */
  fd_vinyl_bstream_block_t sync[1];

  fd_io_uring_t * ring;

  ulong sqe_prep_cnt;     /* SQEs sent */
  ulong sqe_write_tot_sz; /* Total write size requests in SQEs */
  ulong sqe_sent_cnt;     /* SQEs submitted */
  ulong cqe_cnt;          /* CQEs received */

  uint cqe_pending;       /* Total CQEs pending */
  uint cqe_read_pending;  /* CQEs for reads  pending */
  uint cqe_write_pending; /* CQEs for writes pending */

  wb_ring_t wb; /* write buffer */
  ulong     seq_cache;
  ulong     seq_clean;
  ulong     seq_write;
  void *    last_alloc;

  struct {
    wq_ring_t wq; /* write queue */
    wq_desc_t _desc[ WQ_DEPTH ];
  };

  /* write-back cache contents follow */
};

typedef struct fd_vinyl_io_ur fd_vinyl_io_ur_t;

FD_PROTOTYPES_BEGIN

/* fd_vinyl_io_ur_wb_buf returns a pointer to the first byte of the
   write-back buffer.  Offsets returned by wb_ring.h are compatible with
   this base pointer. */

static inline uchar *
fd_vinyl_io_ur_wb_buf( fd_vinyl_io_ur_t * io ) {
  return (uchar *)( io+1 );
}

/* Blocking read/write APIs */

static inline void
bd_read( int    fd,
         ulong  off,
         void * buf,
         ulong  sz ) {
  ssize_t ssz = pread( fd, buf, sz, (off_t)off );
  if( FD_LIKELY( ssz==(ssize_t)sz ) ) return;
  if( ssz<(ssize_t)0 ) FD_LOG_CRIT(( "pread(fd %i,off %lu,sz %lu) failed (%i-%s)", fd, off, sz, errno, fd_io_strerror( errno ) ));
  /**/                 FD_LOG_CRIT(( "pread(fd %i,off %lu,sz %lu) failed (unexpected sz %li)", fd, off, sz, (long)ssz ));
}

static inline void
bd_write( int          fd,
          ulong        off,
          void const * buf,
          ulong        sz ) {
  ssize_t ssz = pwrite( fd, buf, sz, (off_t)off );
  if( FD_LIKELY( ssz==(ssize_t)sz ) ) return;
  if( ssz<(ssize_t)0 ) FD_LOG_CRIT(( "pwrite(fd %i,off %lu,sz %lu) failed (%i-%s)", fd, off, sz, errno, fd_io_strerror( errno ) ));
  else                 FD_LOG_CRIT(( "pwrite(fd %i,off %lu,sz %lu) failed (unexpected sz %li)", fd, off, sz, (long)ssz ));
}

/* vinyl_io read API, provided by fd_vinyl_io_ur_rd.c *****************/

/* fd_vinyl_io_ur_read_imm does a synchronous blocking read. */

void
fd_vinyl_io_ur_read_imm( fd_vinyl_io_t * io,
                         ulong           seq0,
                         void *          _dst,
                         ulong           sz );

/* fd_vinyl_io_ur_read enqueues an asynchronous read. */

void
fd_vinyl_io_ur_read( fd_vinyl_io_t *    io,
                     fd_vinyl_io_rd_t * _rd );

/* fd_vinyl_io_ur_poll polls for the next read completion. */

int
fd_vinyl_io_ur_poll( fd_vinyl_io_t *     io,
                     fd_vinyl_io_rd_t ** _rd,
                     int                 flags );

/* vinyl_io write API, provided by fd_vinyl_io_ur_wb.c ****************/

void *
fd_vinyl_io_ur_alloc( fd_vinyl_io_t * io,
                      ulong           sz,
                      int             flags );

ulong
fd_vinyl_io_ur_append( fd_vinyl_io_t * io,
                       void const *    _src,
                       ulong           sz );

ulong
fd_vinyl_io_ur_copy( fd_vinyl_io_t * io,
                     ulong           seq_src0,
                     ulong           sz );

int
fd_vinyl_io_ur_commit( fd_vinyl_io_t * io,
                       int             flags );

ulong
fd_vinyl_io_ur_hint( fd_vinyl_io_t * io,
                     ulong           sz );

int
fd_vinyl_io_ur_sync( fd_vinyl_io_t * io,
                     int             flags );

void
fd_vinyl_io_ur_forget( fd_vinyl_io_t * io,
                       ulong           seq );

void
fd_vinyl_io_ur_rewind( fd_vinyl_io_t * io,
                       ulong           seq );

/* Auxiliary write path functions */

void
fd_vinyl_io_wq_completion( fd_vinyl_io_ur_t * io );

/* io_uring userdata encoding ******************************************

   io_uring userdata are arbitrary 64-bit words that are provided in SQE
   and echoed back in corresponding CQE.  We use the userdata to encode
   which request completed upon CQE receipt.  We need to minimally pack
   the request type (read or write) and the request identifier.  For the
   write path, this is an index; for the read path, this is a pointer to
   the descriptor.  Pointers are compressed to 61 bits (since the low
   3 bits are always zero for 8 byte aligned pointers). */

#define UR_REQ_READ      0
#define UR_REQ_READ_PART 1
#define UR_REQ_WRITE     2

#define UR_REQ_TYPE_WIDTH 3
#define UR_REQ_TYPE_MASK ((1UL<<UR_REQ_TYPE_WIDTH)-1UL)

static inline ulong
ur_udata_pack_idx( ulong req_type, /* UR_REQ_* */
                   ulong idx ) {
  return (idx<<UR_REQ_TYPE_WIDTH) | (req_type & UR_REQ_TYPE_MASK);
}

static inline ulong
ur_udata_pack_ptr( ulong  req_type,
                   void * ptr ) {
  return ( ((ulong)ptr) & ~UR_REQ_TYPE_MASK ) | (req_type & UR_REQ_TYPE_MASK);
}

static inline ulong
ur_udata_req_type( ulong udata ) {
  return udata & UR_REQ_TYPE_MASK;
}

static inline ulong
ur_udata_idx( ulong udata ) {
  return udata >> UR_REQ_TYPE_WIDTH;
}

static inline void *
ur_udata_ptr( ulong udata ) {
  return (void *)( udata & ~UR_REQ_TYPE_MASK );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_vinyl_io_ur_fd_vinyl_io_ur_private_h */
