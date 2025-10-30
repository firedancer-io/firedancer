#include "fd_vinyl_io_wd.h"
#include "fd_ssctrl.h"
#include "../../../disco/trace/generated/fd_trace_snapwr.h"

/* fd_vinyl_io_wd manages a pool of DMA-friendly buffers.

   The system keeps an invariant that
   - There is a fixed amount of buffers in total.  Buffers transition
     atomically between either of 3 states:
   - IDLE:   queue of multiple buffers waiting to move to APPEND
   - APPEND: zero or one buffer currently being filled
   - IOWAIT: queue of multiple filled buffers sitting in a write queue
             waiting for snapwr to report them as complete

***********************************************************************/

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

/* wd_block_used returns the number of bytes already committed in an
   APPEND buffer. */

static ulong
wd_block_used( fd_vinyl_io_wd_t * wd ) {
  if( FD_UNLIKELY( !wd->buf_append ) ) return 0UL;
  wd_buf_t * buf = wd->buf_append;
  if( buf->state!=WD_BUF_APPEND ) FD_LOG_NOTICE(( "append buf state %u", buf->state ));
  FD_CRIT( buf->state==WD_BUF_APPEND, "append buf in invalid state" );

  FD_CRIT( fd_vinyl_seq_ge( wd->base->seq_future, wd->base->seq_present ), "corrupt bstream io state" );
  ulong block_sz = wd->base->seq_future - buf->bstream_seq;
  FD_CRIT( block_sz<=wd->wr_mtu, "corrupt bstream io state" );
  FD_CRIT( block_sz>0UL, "attempted to dispatch empty buf" );
  return block_sz;
}

/* wd_dispatch enqueues the current APPEND buffer for writing, moving it
   to IOWAIT. */

static void
wd_dispatch( fd_vinyl_io_wd_t * wd ) {

  /* Map the current buffer to a bstream sequence range */

  FD_CRIT( wd->buf_append, "no append buf to dispatch" );
  wd_buf_t * buf = wd->buf_append;
  FD_CRIT( buf->state==WD_BUF_APPEND, "append buf in invalid state" );

  FD_CRIT( fd_vinyl_seq_ge( wd->base->seq_future, wd->base->seq_present ), "corrupt bstream io state" );
  ulong block_sz = wd_block_used( wd );
  FD_CRIT( fd_ulong_is_aligned( block_sz, FD_VINYL_BSTREAM_BLOCK_SZ ), "misaligned block_sz (bad appends?)" );

  /* Align up block_sz to multiple of 4096 bytes.
     This step is critical for good O_DIRECT performance. */

  ulong aligned_sz = fd_ulong_align_up( block_sz, 4096UL );
  ulong pad_sz     = aligned_sz - block_sz;
  FD_CRIT( aligned_sz<=wd->wr_mtu, "corrupt bstream io state" );
  if( FD_UNLIKELY( pad_sz ) ) {
    FD_CRIT( fd_ulong_is_aligned( pad_sz, FD_VINYL_BSTREAM_BLOCK_SZ ), "misaligned zero padding computed" );
    for( ulong pad_rem=pad_sz; pad_rem>0UL; pad_rem-=FD_VINYL_BSTREAM_BLOCK_SZ ) {
      memset( buf->buf + block_sz, 0, FD_VINYL_BSTREAM_BLOCK_SZ );
      block_sz             += FD_VINYL_BSTREAM_BLOCK_SZ;
      wd->base->seq_future += FD_VINYL_BSTREAM_BLOCK_SZ;
    }
  }

  /* Map the bstream sequence range to the device */

  ulong dev_off = buf->bstream_seq;
  FD_CRIT( dev_off+block_sz==wd->base->seq_future, "corrupt bstream io state" );
  if( FD_UNLIKELY( wd->base->seq_future > wd->dev_sz ) ) {
    /* FIXME log vinyl instance name */
    FD_LOG_ERR(( "vinyl database is out of space (dev_sz=%lu)", wd->dev_sz ));
  }

  ulong seq   = wd->wr_seq;
  ulong sig   = dev_off;
  ulong ctl   = FD_SNAPSHOT_MSG_DATA;
  ulong chunk = fd_laddr_to_chunk( wd->wr_base, buf->buf );
  ulong sz    = block_sz>>FD_VINYL_BSTREAM_BLOCK_LG_SZ;
  FD_CRIT( sz<=USHORT_MAX, "block_sz too large" );
  fd_mcache_publish( wd->wr_mcache, wd->wr_depth, seq, sig, chunk, sz, ctl, 0UL, 0UL );
  wd->wr_seq = fd_seq_inc( seq, 1UL );

  buf->next           = NULL;
  buf->state          = WD_BUF_IOWAIT;
  buf->io_seq         = seq;
  buf->bstream_seq    = wd->base->seq_future;
  wd->buf_append      = NULL;
  if( wd->buf_iowait_tail  ) wd->buf_iowait_tail->next = buf;
  if( !wd->buf_iowait_head ) wd->buf_iowait_head       = buf;
  wd->buf_iowait_tail = buf;

  fd_trace_vinyl_io_wd_dispatch();
}

static void
fd_vinyl_io_wd_read_imm( fd_vinyl_io_t * io,
                         ulong           seq0,
                         void *          _dst,
                         ulong           sz ) {
  (void)io; (void)seq0; (void)_dst; (void)sz;
  FD_LOG_CRIT(( "vinyl_io_wd does not support read_imm" ));
}

static void
fd_vinyl_io_wd_read( fd_vinyl_io_t *    io,
                     fd_vinyl_io_rd_t * _rd ) {
  (void)io; (void)_rd;
  FD_LOG_CRIT(( "vinyl_io_wd does not support read" ));
}

static int
fd_vinyl_io_wd_poll( fd_vinyl_io_t *     io,
                     fd_vinyl_io_rd_t ** _rd,
                     int                 flags ) {
  (void)io; (void)_rd; (void)flags;
  FD_LOG_CRIT(( "vinyl_io_wd does not support poll" ));
}

/* fd_vinyl_io_wd_append starts an asynchronous append operation.  _src
   is assumed to be a pointer returned by the most recent alloc.
   Updates io->base->seq_future. */

static ulong
fd_vinyl_io_wd_append( fd_vinyl_io_t * io,
                       void const *    _src,
                       ulong           sz ) {
  fd_vinyl_io_wd_t * wd  = (fd_vinyl_io_wd_t *)io; /* Note: io must be non-NULL to have even been called */
  uchar const *      src = (uchar const *)_src;

  wd_buf_t * buf = wd->buf_append;
  FD_CRIT( buf, "no append buf" );
  FD_CRIT( buf->state==WD_BUF_APPEND, "corrupt wd_buf" );
  FD_CRIT( src>=buf->buf && (src+sz)<=buf->buf+wd->wr_mtu, "alloc invalidated" );

  /* Validate the input args. */

  ulong seq_future = wd->base->seq_future;
  if( FD_UNLIKELY( !sz ) ) return seq_future;

  int bad_src   = !src || src<wd->wr_chunk0 || (src+sz)>wd->wr_chunk1;
  int bad_align = !fd_ulong_is_aligned( (ulong)src, FD_VINYL_BSTREAM_BLOCK_SZ );
  int bad_sz    = !fd_ulong_is_aligned( sz,         FD_VINYL_BSTREAM_BLOCK_SZ );

  if( FD_UNLIKELY( bad_src | bad_align | bad_sz ) ) {
    if( bad_src   ) FD_LOG_CRIT(( "src not a valid alloc ptr ([%p,%p) not in [%p,%p))",
                                  (void *)src,           (void *)(src+sz),
                                  (void *)wd->wr_chunk0, (void *)wd->wr_chunk1 ));
    if( bad_align ) FD_LOG_CRIT(( "misaligned src %p", (void *)src ));
    if( bad_sz    ) FD_LOG_CRIT(( "misaligned sz %lu", sz ));
  }

  /* At this point, we appear to have a valid append request.  Map it to
     the bstream (updating seq_future). */

  ulong seq = seq_future;
  wd->base->seq_future = seq + sz;

  return seq;
}

/* wd_poll_write checks for write completions (fseq).  Returns
   FD_VINYL_SUCCESS if all writes completed, FD_VINYL_ERR_AGAIN
   otherwise.  Updates io->base->seq_present. */

static int
wd_poll_write( fd_vinyl_io_t * io ) {
  fd_vinyl_io_wd_t * wd = (fd_vinyl_io_wd_t *)io; /* Note: io must be non-NULL to have even been called */

  while( wd->buf_iowait_head ) {
    wd_buf_t * buf = wd->buf_iowait_head;
    FD_CRIT( buf->state==WD_BUF_IOWAIT, "corrupt wd_buf" );

    ulong comp_seq  = buf->io_seq;
    ulong found_seq = FD_VOLATILE_CONST( wd->wr_fseq[0] );
    if( fd_seq_lt( found_seq, comp_seq ) ) break;
    FD_CRIT( fd_seq_le( found_seq, wd->wr_seq ), "got completion for a sequence number not yet submitted" );
    FD_CRIT( fd_vinyl_seq_eq( comp_seq, wd->wr_seqack ), "out-of-order ACK polling" );

    /* Buffer completed, remove from IOWAIT list */
    wd->buf_iowait_head = buf->next;
    if( !wd->buf_iowait_head ) wd->buf_iowait_tail = NULL;

    /* Update seq_present (tracks last write) */
    wd->base->seq_present = fd_ulong_max( wd->base->seq_present, buf->bstream_seq );

    /* Return buffer to IDLE list */
    buf->state       = WD_BUF_IDLE;
    buf->next        = wd->buf_idle;
    buf->io_seq      = 0UL;
    buf->bstream_seq = 0UL;
    wd->buf_idle     = buf;
    wd->wr_seqack    = fd_seq_inc( comp_seq, 1UL );
  }

  return wd->buf_iowait_head ? FD_VINYL_ERR_AGAIN : FD_VINYL_SUCCESS;
}

/* fd_vinyl_io_wd_commit completes the dispatches the current APPEND
   block and polls for completions. */

static int
fd_vinyl_io_wd_commit( fd_vinyl_io_t * io,
                       int             flags ) {
  fd_vinyl_io_wd_t * wd = (fd_vinyl_io_wd_t *)io; /* Note: io must be non-NULL to have even been called */

  if( FD_UNLIKELY( fd_vinyl_seq_ne( wd->base->seq_present, wd->base->seq_future ) ) ) {
    FD_CRIT( wd->buf_append, "no append buf to commit, but seq_future indicates inflight write" );

    wd_dispatch( wd );

    wd->base->seq_present = wd->base->seq_future;
    wd->base->spad_used   = 0UL;
  }

  int poll_err;
  do {
    poll_err = wd_poll_write( io );
    if( FD_LIKELY( poll_err!=FD_VINYL_ERR_AGAIN ) ) break;
    FD_SPIN_PAUSE();
  } while( flags & FD_VINYL_IO_FLAG_BLOCKING );
  return poll_err;
}

static ulong
fd_vinyl_io_wd_hint( fd_vinyl_io_t * io,
                     ulong           sz ) {
  (void)io; (void)sz;
  FD_LOG_CRIT(( "vinyl_io_wd does not support hint" ));
}

/* fd_vinyl_io_wd_alloc reserves sz bytes from the current APPEND block
   (starting a new one or dispatching the previous one if needed).

   Note that the caller could do two allocs back-to-back, in which case
   the first alloc should be discarded and replaced by the first.  Also
   note that trim could reduce the size of an alloc. */

static void *
fd_vinyl_io_wd_alloc1( fd_vinyl_io_t * io,
                       ulong           sz ) {
  fd_vinyl_io_wd_t * wd = (fd_vinyl_io_wd_t *)io; /* Note: io must be non-NULL to have even been called */

  if( FD_UNLIKELY( sz > wd->wr_mtu ) ) {
    FD_LOG_CRIT(( "requested write sz (%lu) exceeds MTU (%lu)", sz, wd->wr_mtu ));
  }

  /* Acquire an append buffer */

  wd_buf_t * buf      = NULL;
  ulong      buf_used = 0UL;
  if( wd->buf_append ) {
    /* */ buf_used = wd_block_used( wd );
    ulong buf_free = wd->wr_mtu - buf_used;
    FD_CRIT( buf_used <= wd->wr_mtu, "corrupt wd_buf" );
    if( FD_LIKELY( sz <= buf_free ) ) {
      buf = wd->buf_append;
    } else {
      wd_dispatch( wd );  /* transition buf from APPEND to IOWAIT */
      buf      = NULL;
      buf_used = 0UL;
    }
  }
  if( FD_UNLIKELY( !buf ) ) {
    if( FD_LIKELY( wd->buf_idle ) ) {
      /* Start a new buffer */
      FD_CRIT( wd->buf_idle->state==WD_BUF_IDLE, "corrupt wd_buf" );
      wd->buf_append = wd->buf_idle;
      wd->buf_idle   = wd->buf_idle->next;
      buf            = wd->buf_append;

      wd->buf_append->next        = NULL;
      wd->buf_append->state       = WD_BUF_APPEND;
      wd->buf_append->bstream_seq = wd->base->seq_future;
    } else {
      /* All buffers are IOWAIT, cannot make progress */
      return NULL;
    }
  }

  /* At this point, we have an APPEND state buffer that is large enough
     to fit the alloc. */

  FD_CRIT( buf->state==WD_BUF_APPEND, "corrupt wd_buf" );
  return buf->buf + buf_used;
}

void *
fd_vinyl_io_wd_alloc( fd_vinyl_io_t * io,
                      ulong           sz,
                      int             flags ) {
  if( FD_UNLIKELY( !sz ) ) return NULL;
  _Bool poll = 0;
  for(;;) {
    void * p = fd_vinyl_io_wd_alloc1( io, sz );
    if( FD_LIKELY( p || !(flags & FD_VINYL_IO_FLAG_BLOCKING) ) ) {
      if( FD_UNLIKELY( poll ) ) fd_trace_vinyl_io_wd_blocked_exit();
      return p;
    }
    if( FD_UNLIKELY( !poll ) ) {
      fd_trace_vinyl_io_wd_blocked_enter();
      poll = 1;
    }
    wd_poll_write( io );
    FD_SPIN_PAUSE();
  }
}

static ulong
fd_vinyl_io_wd_copy( fd_vinyl_io_t * io,
                     ulong           seq_src0,
                     ulong           sz ) {
  (void)io; (void)seq_src0; (void)sz;
  FD_LOG_CRIT(( "vinyl_io_wd does not support copy" ));
}

static void
fd_vinyl_io_wd_forget( fd_vinyl_io_t * io,
                       ulong           seq ) {
  (void)io; (void)seq;
  FD_LOG_CRIT(( "vinyl_io_wd does not support forget" ));
}

static void
fd_vinyl_io_wd_rewind( fd_vinyl_io_t * io,
                       ulong           seq ) {
  (void)io; (void)seq;
  FD_LOG_CRIT(( "vinyl_io_wd does not support rewind" ));
}

static int
fd_vinyl_io_wd_sync( fd_vinyl_io_t * io,
                     int             flags ) {
  (void)io; (void)flags;
  FD_LOG_CRIT(( "vinyl_io_wd does not support sync" ));
}

static void *
fd_vinyl_io_wd_fini( fd_vinyl_io_t * io ) {
  fd_vinyl_io_wd_t * wd = (fd_vinyl_io_wd_t *)io; /* Note: io must be non-NULL to have even been called */

  ulong seq_present = wd->base->seq_present;
  ulong seq_future  = wd->base->seq_future;

  if( FD_UNLIKELY( fd_vinyl_seq_ne( seq_present, seq_future ) ) ) FD_LOG_WARNING(( "fini discarding uncommited blocks" ));

  return io;
}

fd_vinyl_io_impl_t fd_vinyl_io_wd_impl = {
  fd_vinyl_io_wd_read_imm,
  fd_vinyl_io_wd_read,
  fd_vinyl_io_wd_poll,
  fd_vinyl_io_wd_append,
  fd_vinyl_io_wd_commit,
  fd_vinyl_io_wd_hint,
  fd_vinyl_io_wd_alloc,
  fd_vinyl_io_wd_copy,
  fd_vinyl_io_wd_forget,
  fd_vinyl_io_wd_rewind,
  fd_vinyl_io_wd_sync,
  fd_vinyl_io_wd_fini
};

ulong
fd_vinyl_io_wd_align( void ) {
  return alignof(fd_vinyl_io_wd_t);
}

ulong
fd_vinyl_io_wd_footprint( ulong queue_depth ) {
  if( FD_UNLIKELY( !queue_depth || !fd_ulong_is_pow2( queue_depth ) || queue_depth>UINT_MAX ) )
    return 0UL;
  return sizeof(fd_vinyl_io_wd_t) + (queue_depth*sizeof(wd_buf_t));
}

fd_vinyl_io_t *
fd_vinyl_io_wd_init( void *           lmem,
                     ulong            dev_sz,
                     ulong            io_seed,
                     fd_frag_meta_t * block_mcache,
                     uchar *          block_dcache,
                     ulong const *    block_fseq,
                     ulong            block_mtu ) {
  /* Mostly copied from fd_vinyl_io_bd.c */

  fd_vinyl_io_wd_t * wd = (fd_vinyl_io_wd_t *)lmem;

  if( FD_UNLIKELY( !wd ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)wd, fd_vinyl_io_wd_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !block_mcache ) ) {
    FD_LOG_WARNING(( "NULL block_mcache" ));
    return NULL;
  }

  if( FD_UNLIKELY( !block_dcache ) ) {
    FD_LOG_WARNING(( "NULL block_dcache" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)block_dcache, FD_VINYL_BSTREAM_BLOCK_SZ ) ) ) {
    FD_LOG_WARNING(( "misaligned block_dcache (addr=%p)", (void *)block_dcache ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( block_mtu, FD_VINYL_BSTREAM_BLOCK_SZ ) ) ) {
    FD_LOG_WARNING(( "misaligned block_mtu (%lu)", block_mtu ));
    return NULL;
  }

  if( FD_UNLIKELY( block_mtu > (USHORT_MAX<<FD_VINYL_BSTREAM_BLOCK_LG_SZ) ) ) {
    FD_LOG_WARNING(( "oversz block_mtu (%lu)", block_mtu ));
    return NULL;
  }

  ulong block_depth = fd_mcache_depth( block_mcache );
  if( FD_UNLIKELY( !block_depth || !fd_ulong_is_pow2( block_depth ) || block_depth>UINT_MAX ) ) {
    FD_LOG_WARNING(( "block_mcache depth (%lu) invalid", block_depth ));
    return NULL;
  }

  ulong dcache_data_sz = fd_dcache_data_sz( block_dcache );
  if( FD_UNLIKELY( dcache_data_sz<(block_depth*block_mtu) ) ) {
    FD_LOG_WARNING(( "block_dcache size (%lu) too small for block_depth (%lu) and block_mtu (%lu), required at least %lu bytes",
                     dcache_data_sz, block_depth, block_mtu, block_depth*block_mtu ));
    return NULL;
  }

  ulong footprint = fd_vinyl_io_wd_footprint( block_depth );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad spad_max" ));
    return NULL;
  }

  memset( wd, 0, footprint );

  wd->base->type = FD_VINYL_IO_TYPE_BD;

  /* Base class members.  Note that vinyl_io does not have an actual
     scratch pad (emplaces writes directly into dcache).  Instead,
     spad_{used_max} track the space available in the current APPEND
     block. */

  wd->base->spad_max  = block_mtu;
  wd->base->spad_used = 0UL;
  wd->base->impl      = &fd_vinyl_io_wd_impl;

  wd->dev_sz = dev_sz;

  wd->buf_idle        = NULL;
  wd->buf_append      = NULL;
  wd->buf_iowait_head = NULL;
  wd->buf_iowait_tail = NULL;

  wd->wr_mcache = block_mcache;
  wd->wr_seq    = fd_mcache_seq0( block_mcache );
  wd->wr_seqack = wd->wr_seq;
  wd->wr_depth  = block_depth;
  wd->wr_base   = block_dcache;
  wd->wr_chunk0 = wd->wr_base;
  wd->wr_chunk1 = wd->wr_base + (block_depth*block_mtu);
  wd->wr_fseq   = block_fseq;
  wd->wr_mtu    = block_mtu;

  /* Set up initial buffer list state */

  wd_buf_t * buf_pool = (wd_buf_t *)(wd+1);
  for( long i=(long)block_depth-1L; i>=0L; i-- ) {
    uchar * block = wd->wr_base + (ulong)i*block_mtu;
    FD_CRIT( fd_ulong_is_aligned( (ulong)block, FD_VINYL_BSTREAM_BLOCK_SZ ), "misaligned wd_buf" );
    wd_buf_t * buf = buf_pool+i;
    *buf = (wd_buf_t) {
      .buf   = block,
      .next  = wd->buf_idle,
      .state = WD_BUF_IDLE
    };
    wd->buf_idle = buf;
  }

  /* We are starting a new bstream. */

  wd->base->seed        = io_seed;
  wd->base->seq_ancient = 0UL;
  wd->base->seq_past    = 0UL;
  wd->base->seq_present = 0UL;
  wd->base->seq_future  = 0UL;

  FD_LOG_INFO(( "IO config"
                "\n\ttype        wd"
                "\n\tblock_depth %lu"
                "\n\tblock_mtu   %lu bytes"
                "\n\treset       1"
                "\n\tio_seed     0x%016lx",
                block_depth, block_mtu,
                io_seed ));

  return wd->base;
}

int
fd_vinyl_io_wd_busy( fd_vinyl_io_t * io ) {
  fd_vinyl_io_wd_t * wd = (fd_vinyl_io_wd_t *)io;
  return !!wd->buf_append || !!wd->buf_iowait_head;
}

void
fd_vinyl_io_wd_ctrl( fd_vinyl_io_t * io,
                     ulong           ctl,
                     ulong           sig ) {
  fd_vinyl_io_wd_t * wd = (fd_vinyl_io_wd_t *)io;

  if( FD_UNLIKELY( fd_vinyl_io_wd_busy( io ) ) ) {
    FD_LOG_CRIT(( "Attempted to send control message via io_wd while still busy" ));
  }

  fd_mcache_publish( wd->wr_mcache, wd->wr_depth, wd->wr_seq, sig, 0UL, 0UL, ctl, 0UL, 0UL );
}
