/* fd_vinyl_io_wd.h is a vinyl_io driver that does async O_DIRECT writes
   via the snapwr tile.  Implements a fast way to create a bstream on
   Linux (DMA under the hood).

   Internally manages a pool of DMA/LBA friendly blocks (i.e. 4 KiB
   aligned, O(16 MiB) size).  Blocks have either state IDLE, APPEND
   (currently being written to), or IOWAIT (waiting for snapwr
   completion). */

#include "../../../vinyl/io/fd_vinyl_io.h"

/* wd_buf describes an O_DIRECT append buf */

struct wd_buf;
typedef struct wd_buf wd_buf_t;

struct wd_buf {
  uchar *    buf;          /* pointer into dcache */
  uint       state;        /* WD_BUF_* */
  wd_buf_t * next;         /* next ele in linked list */
  ulong      io_seq;       /* mcache request sequence number */
  ulong      bstream_seq;  /* APPEND=bstream seq of first block */
                           /* IOWAIT=bstream seq after buffer is fully written */
};

/* WD_BUF_* give append buf states */

#define WD_BUF_IDLE   1U
#define WD_BUF_APPEND 2U
#define WD_BUF_IOWAIT 3U

/* fd_vinyl_io_wd implements the fd_vinyl_io_t interface */

struct fd_vinyl_io_wd {
  fd_vinyl_io_t base[1];
  ulong         dev_base;
  ulong         dev_sz;        /* Block store byte size (BLOCK_SZ multiple) */

  /* Buffer linked lists by state */
  wd_buf_t * buf_idle;         /* free stack */
  wd_buf_t * buf_append;       /* current wip block */
  wd_buf_t * buf_iowait_head;  /* least recently enqueued (seq increasing) */
  wd_buf_t * buf_iowait_tail;  /* most  recently enqueued */

  /* Work queue (snapwr) */
  fd_frag_meta_t * wr_mcache;  /* metadata ring */
  ulong            wr_seq;     /* next metadata seq no */
  ulong            wr_seqack;  /* next expected ACK seq */
  ulong            wr_depth;   /* metadata ring depth */
  uchar *          wr_base;    /* base pointer for data cache */
  uchar *          wr_chunk0;  /* [wr_chunk0,wr_chunk1) is the data cache data region */
  uchar *          wr_chunk1;
  ulong const *    wr_fseq;    /* completion notifications */
  ulong            wr_mtu;     /* max block byte size */
};

typedef struct fd_vinyl_io_wd fd_vinyl_io_wd_t;


/* fd_vinyl_io_wd_{align,footprint} specify the alignment and footprint
   needed for a bstream O_DIRECT writer with block_depth max blocks
   inflight.  align will be a reasonable power-of-2 and footprint will
   be a multiple of align.  Returns 0 for an invalid block_depth. */

ulong
fd_vinyl_io_wd_align( void );

ulong
fd_vinyl_io_wd_footprint( ulong block_depth );

/* fd_vinyl_io_wd_init creates a bstream fast append backend.  lmem
   points to a local memory region with suitable alignment and footprint
   to hold bstream's state.  io_seed is the bstream's data integrity
   hashing seed.

   block_queue is an mcache (request queue) used to submit write
   requests to a snapwr.  fd_mcache_depth(block_queue)==block_depth.
   block_dcache is a dcache (data cache) sized to block_depth*block_mtu
   data_sz.  block_mtu is a multiple of FD_VINYL_BSTREAM_BLOCK_SZ and
   determines the largest O_DIRECT write operation (typically between 2
   to 64 MiB).  block_fseq points to the snapwr tile's fseq (used to
   report write completions).

   Returns a handle to the bstream on success (has ownership of lmem and
   dev_fd, ownership returned on fini) and NULL on failure (logs
   details, no ownership changed). */

fd_vinyl_io_t *
fd_vinyl_io_wd_init( void *           lmem,
                     ulong            dev_sz,
                     ulong            io_seed,
                     fd_frag_meta_t * block_mcache,
                     uchar *          block_dcache,
                     ulong const *    block_fseq,
                     ulong            block_mtu );

/* API restrictions:

   - Any method is unsupported (crash application if called) unless
     otherwise specified
   - Supported methods: append, commit, alloc, fini
   - In-place append not supported.  All appends must use a buffer
     sourced from alloc as the input buffer.
   - append, commit, alloc require FD_VINYL_IO_FLAG_BLOCKING to be unset  */

extern fd_vinyl_io_impl_t fd_vinyl_io_wd_impl;

/* fd_vinyl_io_wd_alloc implements fd_vinyl_io_alloc. */

void *
fd_vinyl_io_wd_alloc( fd_vinyl_io_t * io,
                      ulong           sz,
                      int             flags );

/* fd_vinyl_io_wd_busy returns 1 if there is at least one buffer in use
   (either APPEND or IOWAIT state).  Returns 0 if all buffers are IDLE. */

int
fd_vinyl_io_wd_busy( fd_vinyl_io_t * io );

/* fd_vinyl_io_wd_ctrl sends a control message to the snapwr tile.
   Blocks until the message is acknowledged. */

void
fd_vinyl_io_wd_ctrl( fd_vinyl_io_t * io,
                     ulong           ctl,
                     ulong           sig );

/* fd_viny_io_wd_alloc_fast is an optimistic version of vinyl_io->alloc.
   If it fails (returns NULL), the caller should fall back to calling
   fd_vinyl_io_alloc normally. */

static inline void *
fd_vinyl_io_wd_alloc_fast( fd_vinyl_io_t * io,
                           ulong           sz ) {
  fd_vinyl_io_wd_t * wd = (fd_vinyl_io_wd_t *)io; /* Note: io must be non-NULL to have even been called */

  wd_buf_t * buf = wd->buf_append;
  if( FD_UNLIKELY( !buf ) ) return NULL;

  ulong buf_used = wd->base->seq_future - buf->bstream_seq;
  ulong buf_free = wd->wr_mtu - buf_used;
  if( FD_UNLIKELY( sz>buf_free ) ) return NULL;

  return buf->buf + buf_used;
}
