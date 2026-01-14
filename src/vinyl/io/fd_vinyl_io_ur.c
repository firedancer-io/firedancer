#include "fd_vinyl_io_ur.h"

#if FD_HAS_LIBURING

#include <unistd.h> /* lseek */
#include <liburing.h>

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

  uint                  tsz;  /* Tail read size */
  fd_vinyl_io_ur_rd_t * next; /* Next element in ur rd queue */
};

FD_STATIC_ASSERT( sizeof(fd_vinyl_io_ur_rd_t)<=sizeof(fd_vinyl_io_rd_t), layout );

/* fd_vinyl_io_ur_t extends fd_viny_io_t. */

struct fd_vinyl_io_ur {
  fd_vinyl_io_t            base[1];
  int                      dev_fd;       /* File descriptor of block device */
  ulong                    dev_sync;     /* Offset to block that holds bstream sync (BLOCK_SZ multiple) */
  ulong                    dev_base;     /* Offset to first block (BLOCK_SZ multiple) */
  ulong                    dev_sz;       /* Block store byte size (BLOCK_SZ multiple) */
  fd_vinyl_io_ur_rd_t *    rd_head;      /* Pointer to queue head */
  fd_vinyl_io_ur_rd_t **   rd_tail_next; /* Pointer to queue &tail->next or &rd_head if empty. */
  fd_vinyl_bstream_block_t sync[1];

  struct io_uring * ring;

  ulong sq_prep_cnt;  /* io_uring SQEs sent */
  ulong sq_sent_cnt;  /* io_uring SQEs submitted */
  ulong cq_cnt;       /* io_uring CQEs received */

  /* spad_max bytes follow */
};

typedef struct fd_vinyl_io_ur fd_vinyl_io_ur_t;

/* fd_vinyl_io_ur_read_imm is identical to fd_vinyl_io_bd_read_imm. */

static void
fd_vinyl_io_ur_read_imm( fd_vinyl_io_t * io,
                         ulong           seq0,
                         void *          _dst,
                         ulong           sz ) {
  fd_vinyl_io_ur_t * ur = (fd_vinyl_io_ur_t *)io;  /* Note: io must be non-NULL to have even been called */

  /* If this is a request to read nothing, succeed immediately.  If
     this is a request to read outside the bstream's past, fail. */

  if( FD_UNLIKELY( !sz ) ) return;

  uchar * dst  = (uchar *)_dst;
  ulong   seq1 = seq0 + sz;

  ulong seq_past    = ur->base->seq_past;
  ulong seq_present = ur->base->seq_present;

  int bad_seq  = !fd_ulong_is_aligned( seq0, FD_VINYL_BSTREAM_BLOCK_SZ );
  int bad_dst  = (!fd_ulong_is_aligned( (ulong)dst, FD_VINYL_BSTREAM_BLOCK_SZ )) | !dst;
  int bad_sz   = !fd_ulong_is_aligned( sz,   FD_VINYL_BSTREAM_BLOCK_SZ );
  int bad_past = !(fd_vinyl_seq_le( seq_past, seq0 ) & fd_vinyl_seq_lt( seq0, seq1 ) & fd_vinyl_seq_le( seq1, seq_present ));

  if( FD_UNLIKELY( bad_seq | bad_dst | bad_sz | bad_past ) )
    FD_LOG_CRIT(( "bstream read_imm [%016lx,%016lx)/%lu failed (past [%016lx,%016lx)/%lu, %s)",
                  seq0, seq1, sz, seq_past, seq_present, seq_present-seq_past,
                  bad_seq ? "misaligned seq"         :
                  bad_dst ? "misaligned or NULL dst" :
                  bad_sz  ? "misaligned sz"          :
                            "not in past" ));

  /* At this point, we have a valid read request.  Map seq0 into the
     bstream store.  Read the lesser of sz bytes or until the store end.
     If we hit the store end with more to go, wrap around and finish the
     read at the store start. */

  int   dev_fd   = ur->dev_fd;
  ulong dev_base = ur->dev_base;
  ulong dev_sz   = ur->dev_sz;

  ulong dev_off = seq0 % dev_sz;

  ulong rsz = fd_ulong_min( sz, dev_sz - dev_off );
  bd_read( dev_fd, dev_base + dev_off, dst, rsz );
  sz -= rsz;

  if( FD_UNLIKELY( sz ) ) bd_read( dev_fd, dev_base, dst + rsz, sz );
}

/* ### Read pipeline explainer

   vinyl_io clients submit read jobs using vinyl_io_read, and poll for
   completions using vinyl_io_poll.  Reads may complete in arbitrary
   order.  On first sight, this cleanly translates to io_uring.

   Read job descriptors are user-allocated.  The client is not aware of
   any job queue depth limits in the vinyl_io backend's internals.  The
   vinyl_io backend is expected to queue up an infinitely deep backlog
   of read jobs.  However, the io_uring submission queue has a hard
   depth limit.

   The vinyl_io lifecycle therefore is as follows:
   - io_ur_read adds a read job to the 'staged' queue.  This is a linked
     list weaving through all user-submitted jobs.
   - io_ur_read/io_ur_poll move jobs from the 'staged' queue to the
     'wait' heap.  Each wait heap entry is shadowed by an io_uring
      submission queue entry.
   - io_ur_poll matches io_uring completions with corresponding 'wait'
     heap entries.  Each entry is removed from the 'wait' heap and
     returned back to the user.

   In rare cases, a bstream read may wrap around the end of the bstream.
   In this case, two linked SQEs are generated.

   ### Polling

   fd_vinyl_io_read registers work in userspace only but does not do any
   syscalls.  fd_vinyl_io_poll submits read jobs (calls kernel io_uring
   syscall) if there is any work pending, then polls for completions. */

/* ur_staged_push adds a read job to the staged queue. */

static void
ur_staged_push( fd_vinyl_io_ur_t *    ur,
                fd_vinyl_io_ur_rd_t * rd ) {
  rd->next          = NULL;
  *ur->rd_tail_next = rd;
  ur->rd_tail_next  = &rd->next;
}

/* ur_prep_read translates a staged read job into one (or rarely two)
   io_uring SQEs.  SQEs are allocated off the io_uring instance.
   Returns the number of SQEs prepared on success, and moves rd onto the
   wait heap.  On failure to allocate SQEs, behaves like a no-op (safe
   to retry) and returns 0.  */

static uint
ur_prep_read( fd_vinyl_io_ur_t *    ur,
              fd_vinyl_io_ur_rd_t * rd,
              ulong                 seq0,
              ulong                 sz ) {
  struct io_uring * ring = ur->ring;
  if( FD_UNLIKELY( sz>INT_MAX ) ) {
    FD_LOG_CRIT(( "Invalid read size 0x%lx bytes (exceeds max)", sz ));
  }
  if( FD_UNLIKELY( io_uring_sq_space_left( ring )<2U ) ) return 0U;

  /* Map seq0 into the bstream store. */

  ulong dev_base = ur->dev_base;
  ulong dev_sz   = ur->dev_sz;

  ulong dev_off = seq0 % dev_sz;

  ulong rsz = fd_ulong_min( sz, dev_sz - dev_off );
  sz -= rsz;

  /* Prepare the head SQE */
  rd->next = NULL;
  rd->tsz  = (uint)rsz;
  struct io_uring_sqe * sqe = io_uring_get_sqe( ring );
  if( FD_UNLIKELY( !sqe ) ) FD_LOG_CRIT(( "io_uring_get_sqe() returned NULL despite io_uring_sq_space_left()>=2" ));
  io_uring_prep_read( sqe, 0, rd->dst, (uint)rsz, dev_base+dev_off );
  io_uring_sqe_set_flags( sqe, IOSQE_FIXED_FILE );
  io_uring_sqe_set_data( sqe, rd );
  ur->sq_prep_cnt++;
  if( FD_LIKELY( !sz ) ) return 1U; /* optimize for the unfragmented case */

  /* Tail wraparound occurred.  Amend the head SQE to be linked to the
     tail SQE, detach it from the io_ur descriptor, and suppress the CQE
     for the head.  If we get a CQE for the tail read job, we know that
     the head read job also succeeded.  Also, set the low bit of the
     userdata to 1 (usually guaranteed to be 0 due to alignment), to
     indicate that this SQE is a head frag. */
  io_uring_sqe_set_flags( sqe, IOSQE_FIXED_FILE | IOSQE_IO_LINK | IOSQE_CQE_SKIP_SUCCESS );
  io_uring_sqe_set_data64( sqe, (ulong)rd+1UL );
  ur->cq_cnt++;  /* Treat as already-completed in metrics */

  /* Prepare the tail SQE */
  rd->tsz  = (uint)sz;
  sqe = io_uring_get_sqe( ring );
  if( FD_UNLIKELY( !sqe ) ) FD_LOG_CRIT(( "io_uring_get_sqe() returned NULL despite io_uring_sq_space_left()>=2" ));
  io_uring_prep_read( sqe, 0, (uchar *)rd->dst + rsz, (uint)sz, dev_base );
  io_uring_sqe_set_flags( sqe, IOSQE_FIXED_FILE );
  io_uring_sqe_set_data( sqe, rd );
  ur->sq_prep_cnt++;
  return 2U;
}

/* ur_staged_clean moves as many read jobs from the staged queue to the
   submission queue as possible. */

static void
ur_staged_clean( fd_vinyl_io_ur_t * ur ) {
  for(;;) {
    fd_vinyl_io_ur_rd_t * rd = ur->rd_head;
    if( !rd ) break;

    fd_vinyl_io_ur_rd_t ** rd_tail_next = ur->rd_tail_next;
    fd_vinyl_io_ur_rd_t *  rd_next      = rd->next;

    uint sqe_cnt = ur_prep_read( ur, rd, rd->seq, rd->sz );
    if( FD_UNLIKELY( !sqe_cnt ) ) break;

    ur->rd_head      = rd_next;
    ur->rd_tail_next = fd_ptr_if( !!rd_next, rd_tail_next, &ur->rd_head );
  }
}

static void
fd_vinyl_io_ur_read( fd_vinyl_io_t *    io,
                     fd_vinyl_io_rd_t * _rd ) {
  fd_vinyl_io_ur_t *    ur = (fd_vinyl_io_ur_t *)io;
  fd_vinyl_io_ur_rd_t * rd = (fd_vinyl_io_ur_rd_t *)_rd;
  ur_staged_push( ur, rd );
  ur_staged_clean( ur );
}

static int
fd_vinyl_io_ur_poll( fd_vinyl_io_t *     io,
                     fd_vinyl_io_rd_t ** _rd,
                     int                 flags ) {
  fd_vinyl_io_ur_t * ur       = (fd_vinyl_io_ur_t *)io;
  struct io_uring *  ring     = ur->ring;
  int                blocking = !!( flags & FD_VINYL_IO_FLAG_BLOCKING );
  *_rd = NULL;

  uint cq_cnt = io_uring_cq_ready( ring );
  if( FD_UNLIKELY( !cq_cnt ) ) {  /* no CQEs ready */
    /* Move staged work to submission queue */
    ur_staged_clean( ur );

    /* If no work is available to schedule, bail to avoid deadlock */
    int have_pending = ur->sq_prep_cnt > ur->sq_sent_cnt;
    int have_waiting = ur->sq_sent_cnt > ur->cq_cnt;
    if( FD_UNLIKELY( !have_pending && !have_waiting ) ) {
      return FD_VINYL_ERR_EMPTY;
    }

    /* Issue syscall to drive kernel */
    int submit_cnt;
    if( blocking ) {
      submit_cnt = io_uring_submit_and_wait( ring, 1U );
    } else {
      submit_cnt = io_uring_submit_and_get_events( ring );
    }
    if( FD_UNLIKELY( submit_cnt<0 ) ) {
      FD_LOG_ERR(( "%s failed (%i-%s)", blocking ? "io_uring_submit_and_wait" : "io_uring_submit_and_get_events", -submit_cnt, fd_io_strerror( -submit_cnt ) ));
    }
    ur->sq_sent_cnt += (ulong)submit_cnt;

    cq_cnt = io_uring_cq_ready( ring );
    if( !cq_cnt ) {
      if( FD_UNLIKELY( blocking ) ) FD_LOG_CRIT(( "io_uring_submit_and_wait() returned but no CQEs ready" ));
      return FD_VINYL_ERR_AGAIN;
    }
  }

  /* At this point, we have at least one CQE ready.
     It could come in one of these shapes:
     - Success (full read): implies that all fragments of a ur_rd read
       have been completed; only generated for the last frag
     - Short read: crash the app
     - Zero byte read: unexpected EOF reached, crash the app
     - Error (cancelled): a short read of the head frag broke the SQE
       chain, the tail got cancelled.  Crash the app
     - Error (other): crash the app */

  struct io_uring_cqe * cqe = NULL;
  io_uring_peek_cqe( ring, &cqe );
  if( FD_UNLIKELY( !cqe ) ) FD_LOG_CRIT(( "io_uring_peek_cqe() yielded NULL despite io_uring_cq_ready()=%u", cq_cnt ));
  ulong                 udata     = io_uring_cqe_get_data64( cqe );
  int                   last_frag = !fd_ulong_extract_bit( udata, 0 );
  fd_vinyl_io_ur_rd_t * rd        = (void *)fd_ulong_clear_bit( udata, 0 );
  if( FD_UNLIKELY( !rd ) ) FD_LOG_CRIT(( "io_uring_peek_cqe() yielded invalid user data" ));
  int cqe_res = cqe->res;
  if( cqe_res<0 ) {
    FD_LOG_ERR(( "io_uring read failed (%i-%s)", -cqe_res, fd_io_strerror( -cqe_res ) ));
  }
  if( FD_UNLIKELY( !last_frag ) ) {
    FD_LOG_ERR(( "io_uring read failed (short read or EOF)" ));
  }
  if( FD_UNLIKELY( rd->tsz!=(uint)cqe_res ) ) {
    FD_LOG_ERR(( "io_uring read failed (expected %u bytes, got %i bytes)", rd->tsz, cqe_res ));
  }
  io_uring_cq_advance( ring, 1U );
  ur->cq_cnt++;

  *_rd = (fd_vinyl_io_rd_t *)rd;
  return FD_VINYL_SUCCESS;
}

/* fd_vinyl_io_ur_append is identical to fd_vinyl_io_bd_append. */

static ulong
fd_vinyl_io_ur_append( fd_vinyl_io_t * io,
                       void const *    _src,
                       ulong           sz ) {
  fd_vinyl_io_ur_t * ur  = (fd_vinyl_io_ur_t *)io; /* Note: io must be non-NULL to have even been called */
  uchar const *      src = (uchar const *)_src;

  /* Validate the input args. */

  ulong seq_future  = ur->base->seq_future;  if( FD_UNLIKELY( !sz ) ) return seq_future;
  ulong seq_ancient = ur->base->seq_ancient;
  int   dev_fd      = ur->dev_fd;
  ulong dev_base    = ur->dev_base;
  ulong dev_sz      = ur->dev_sz;

  int bad_src      = !src;
  int bad_align    = !fd_ulong_is_aligned( (ulong)src, FD_VINYL_BSTREAM_BLOCK_SZ );
  int bad_sz       = !fd_ulong_is_aligned( sz,         FD_VINYL_BSTREAM_BLOCK_SZ );
  int bad_capacity = sz > (dev_sz - (seq_future-seq_ancient));

  if( FD_UNLIKELY( bad_src | bad_align | bad_sz | bad_capacity ) )
    FD_LOG_CRIT(( bad_src   ? "NULL src"       :
                  bad_align ? "misaligned src" :
                  bad_sz    ? "misaligned sz"  :
                              "device full" ));

  /* At this point, we appear to have a valid append request.  Map it to
     the bstream (updating seq_future) and map it to the device.  Then
     write the lesser of sz bytes or until the store end.  If we hit the
     store end with more to go, wrap around and finish the write at the
     store start. */

  ulong seq = seq_future;
  ur->base->seq_future = seq + sz;

  ulong dev_off = seq % dev_sz;

  ulong wsz = fd_ulong_min( sz, dev_sz - dev_off );
  bd_write( dev_fd, dev_base + dev_off, src, wsz );
  sz -= wsz;
  if( sz ) bd_write( dev_fd, dev_base, src + wsz, sz );

  return seq;
}

/* fd_vinyl_io_ur_commit is identical to fd_vinyl_io_bd_commit. */

static int
fd_vinyl_io_ur_commit( fd_vinyl_io_t * io,
                       int             flags ) {
  fd_vinyl_io_ur_t * ur = (fd_vinyl_io_ur_t *)io; /* Note: io must be non-NULL to have even been called */
  (void)flags;

  ur->base->seq_present = ur->base->seq_future;
  ur->base->spad_used   = 0UL;

  return FD_VINYL_SUCCESS;
}

/* fd_vinyl_io_ur_hint is identical to fd_vinyl_io_bd_hint. */

static ulong
fd_vinyl_io_ur_hint( fd_vinyl_io_t * io,
                     ulong           sz ) {
  fd_vinyl_io_ur_t * ur = (fd_vinyl_io_ur_t *)io; /* Note: io must be non-NULL to have even been called */

  ulong seq_future  = ur->base->seq_future;  if( FD_UNLIKELY( !sz ) ) return seq_future;
  ulong seq_ancient = ur->base->seq_ancient;
  ulong dev_sz      = ur->dev_sz;

  int bad_sz       = !fd_ulong_is_aligned( sz, FD_VINYL_BSTREAM_BLOCK_SZ );
  int bad_capacity = sz > (dev_sz - (seq_future-seq_ancient));

  if( FD_UNLIKELY( bad_sz | bad_capacity ) ) FD_LOG_CRIT(( bad_sz ? "misaligned sz" : "device full" ));

  return ur->base->seq_future;
}

/* fd_vinyl_io_ur_alloc is identical to fd_vinyl_io_bd_alloc. */

static void *
fd_vinyl_io_ur_alloc( fd_vinyl_io_t * io,
                      ulong           sz,
                      int             flags ) {
  fd_vinyl_io_ur_t * ur = (fd_vinyl_io_ur_t *)io; /* Note: io must be non-NULL to have even been called */

  ulong spad_max  = ur->base->spad_max;
  ulong spad_used = ur->base->spad_used; if( FD_UNLIKELY( !sz ) ) return ((uchar *)(ur+1)) + spad_used;

  int bad_align = !fd_ulong_is_aligned( sz, FD_VINYL_BSTREAM_BLOCK_SZ );
  int bad_sz    = sz > spad_max;

  if( FD_UNLIKELY( bad_align | bad_sz ) ) FD_LOG_CRIT(( bad_align ? "misaligned sz" : "sz too large" ));

  if( FD_UNLIKELY( sz > (spad_max - spad_used ) ) ) {
    if( FD_UNLIKELY( fd_vinyl_io_ur_commit( io, flags ) ) ) return NULL;
    spad_used = 0UL;
  }

  ur->base->spad_used = spad_used + sz;

  return ((uchar *)(ur+1)) + spad_used;
}

/* fd_vinyl_io_ur_copy is identical to fd_vinyl_io_bd_copy. */

static ulong
fd_vinyl_io_ur_copy( fd_vinyl_io_t * io,
                     ulong           seq_src0,
                     ulong           sz ) {
  fd_vinyl_io_ur_t * ur = (fd_vinyl_io_ur_t *)io; /* Note: io must be non-NULL to have even been called */

  /* Validate the input args */

  ulong seq_ancient = ur->base->seq_ancient;
  ulong seq_past    = ur->base->seq_past;
  ulong seq_present = ur->base->seq_present;
  ulong seq_future  = ur->base->seq_future;   if( FD_UNLIKELY( !sz ) ) return seq_future;
  ulong spad_max    = ur->base->spad_max;
  ulong spad_used   = ur->base->spad_used;
  int   dev_fd      = ur->dev_fd;
  ulong dev_base    = ur->dev_base;
  ulong dev_sz      = ur->dev_sz;

  ulong seq_src1 = seq_src0 + sz;

  int bad_past     = !( fd_vinyl_seq_le( seq_past, seq_src0    ) &
                        fd_vinyl_seq_lt( seq_src0, seq_src1    ) &
                        fd_vinyl_seq_le( seq_src1, seq_present ) );
  int bad_src      = !fd_ulong_is_aligned( seq_src0, FD_VINYL_BSTREAM_BLOCK_SZ );
  int bad_sz       = !fd_ulong_is_aligned( sz,       FD_VINYL_BSTREAM_BLOCK_SZ );
  int bad_capacity = sz > (dev_sz - (seq_future-seq_ancient));

  if( FD_UNLIKELY( bad_past | bad_src | bad_sz | bad_capacity ) )
    FD_LOG_CRIT(( bad_past ? "src is not in the past"    :
                  bad_src  ? "misaligned src_seq"        :
                  bad_sz   ? "misaligned sz"             :
                             "device full" ));

  /* At this point, we appear to have a valid copy request.  Get
     buffer space from the scratch pad (committing as necessary). */

  if( FD_UNLIKELY( sz>(spad_max-spad_used) ) ) {
    fd_vinyl_io_ur_commit( io, FD_VINYL_IO_FLAG_BLOCKING );
    spad_used = 0UL;
  }

  uchar * buf     = (uchar *)(ur+1) + spad_used;
  ulong   buf_max = spad_max - spad_used;

  /* Map the dst to the bstream (updating seq_future) and map the src
     and dst regions onto the device.  Then copy as much as we can at a
     time, handling device wrap around and copy buffering space. */

  ulong seq = seq_future;
  ur->base->seq_future = seq + sz;

  ulong seq_dst0 = seq;

  for(;;) {
    ulong src_off = seq_src0 % dev_sz;
    ulong dst_off = seq_dst0 % dev_sz;
    ulong csz     = fd_ulong_min( fd_ulong_min( sz, buf_max ), fd_ulong_min( dev_sz - src_off, dev_sz - dst_off ) );

    bd_read ( dev_fd, dev_base + src_off, buf, csz );
    bd_write( dev_fd, dev_base + dst_off, buf, csz );

    sz -= csz;
    if( !sz ) break;

    seq_src0 += csz;
    seq_dst0 += csz;
  }

  return seq;
}

/* fd_vinyl_io_ur_forget is identical to fd_vinyl_io_bd_forget. */

static void
fd_vinyl_io_ur_forget( fd_vinyl_io_t * io,
                       ulong           seq ) {
  fd_vinyl_io_ur_t * ur = (fd_vinyl_io_ur_t *)io; /* Note: io must be non-NULL to have even been called */

  /* Validate input arguments.  Note that we don't allow forgetting into
     the future even when we have no uncommitted blocks because the
     resulting [seq_ancient,seq_future) might contain blocks that were
     never written (which might not be an issue practically but it would
     be a bit strange for something to try to scan starting from
     seq_ancient and discover unwritten blocks). */

  ulong seq_past    = ur->base->seq_past;
  ulong seq_present = ur->base->seq_present;
  ulong seq_future  = ur->base->seq_future;

  int bad_seq    = !fd_ulong_is_aligned( seq, FD_VINYL_BSTREAM_BLOCK_SZ );
  int bad_dir    = !(fd_vinyl_seq_le( seq_past, seq ) & fd_vinyl_seq_le( seq, seq_present ));
  int bad_read   = !!ur->rd_head;
  int bad_append = fd_vinyl_seq_ne( seq_present, seq_future );

  if( FD_UNLIKELY( bad_seq | bad_dir | bad_read | bad_append ) )
    FD_LOG_CRIT(( "forget to seq %016lx failed (past [%016lx,%016lx)/%lu, %s)",
                  seq, seq_past, seq_present, seq_present-seq_past,
                  bad_seq  ? "misaligned seq"             :
                  bad_dir  ? "seq out of bounds"          :
                  bad_read ? "reads in progress"          :
                             "appends/copies in progress" ));

  ur->base->seq_past = seq;
}

/* fd_vinyl_io_ur_rewind is identical to fd_vinyl_io_bd_rewind. */

static void
fd_vinyl_io_ur_rewind( fd_vinyl_io_t * io,
                       ulong           seq ) {
  fd_vinyl_io_ur_t * ur = (fd_vinyl_io_ur_t *)io; /* Note: io must be non-NULL to have even been called */

  /* Validate input argments.  Unlike forgot, we do allow rewinding to
     before seq_ancient as the region of sequence space reported to the
     caller as written is still accurate. */

  ulong seq_ancient = ur->base->seq_ancient;
  ulong seq_past    = ur->base->seq_past;
  ulong seq_present = ur->base->seq_present;
  ulong seq_future  = ur->base->seq_future;

  int bad_seq    = !fd_ulong_is_aligned( seq, FD_VINYL_BSTREAM_BLOCK_SZ );
  int bad_dir    = fd_vinyl_seq_gt( seq, seq_present );
  int bad_read   = !!ur->rd_head;
  int bad_append = fd_vinyl_seq_ne( seq_present, seq_future );

  if( FD_UNLIKELY( bad_seq | bad_dir | bad_read | bad_append ) )
    FD_LOG_CRIT(( "rewind to seq %016lx failed (present %016lx, %s)", seq, seq_present,
                  bad_seq  ? "misaligned seq"             :
                  bad_dir  ? "seq after seq_present"      :
                  bad_read ? "reads in progress"          :
                             "appends/copies in progress" ));

  ur->base->seq_ancient = fd_ulong_if( fd_vinyl_seq_ge( seq, seq_ancient ), seq_ancient, seq );
  ur->base->seq_past    = fd_ulong_if( fd_vinyl_seq_ge( seq, seq_past    ), seq_past,    seq );
  ur->base->seq_present = seq;
  ur->base->seq_future  = seq;
}

/* fd_vinyl_io_ur_sync is identical to fd_vinyl_io_bd_sync. */

static int
fd_vinyl_io_ur_sync( fd_vinyl_io_t * io,
                     int             flags ) {
  fd_vinyl_io_ur_t * ur = (fd_vinyl_io_ur_t *)io; /* Note: io must be non-NULL to have even been called */
  (void)flags;

  ulong seed        = ur->base->seed;
  ulong seq_past    = ur->base->seq_past;
  ulong seq_present = ur->base->seq_present;

  int   dev_fd       = ur->dev_fd;
  ulong dev_sync     = ur->dev_sync;

  fd_vinyl_bstream_block_t * block = ur->sync;

  /* block->sync.ctl     current (static) */
  block->sync.seq_past    = seq_past;
  block->sync.seq_present = seq_present;
  /* block->sync.info_sz current (static) */
  /* block->sync.info    current (static) */

  block->sync.hash_trail  = 0UL;
  block->sync.hash_blocks = 0UL;
  fd_vinyl_bstream_block_hash( seed, block ); /* sets hash_trail back to seed */

  bd_write( dev_fd, dev_sync, block, FD_VINYL_BSTREAM_BLOCK_SZ );

  ur->base->seq_ancient = seq_past;

  return FD_VINYL_SUCCESS;
}

/* fd_vinyl_io_ur_fini is identical to fd_vinyl_io_bd_fini. */

static void *
fd_vinyl_io_ur_fini( fd_vinyl_io_t * io ) {
  fd_vinyl_io_ur_t * ur = (fd_vinyl_io_ur_t *)io; /* Note: io must be non-NULL to have even been called */

  ulong seq_present = ur->base->seq_present;
  ulong seq_future  = ur->base->seq_future;

  if( FD_UNLIKELY( ur->rd_head                                ) ) FD_LOG_WARNING(( "fini completing outstanding reads" ));
  if( FD_UNLIKELY( fd_vinyl_seq_ne( seq_present, seq_future ) ) ) FD_LOG_WARNING(( "fini discarding uncommited blocks" ));

  return io;
}

static fd_vinyl_io_impl_t fd_vinyl_io_ur_impl[1] = { {
  fd_vinyl_io_ur_read_imm,
  fd_vinyl_io_ur_read,
  fd_vinyl_io_ur_poll,
  fd_vinyl_io_ur_append,
  fd_vinyl_io_ur_commit,
  fd_vinyl_io_ur_hint,
  fd_vinyl_io_ur_alloc,
  fd_vinyl_io_ur_copy,
  fd_vinyl_io_ur_forget,
  fd_vinyl_io_ur_rewind,
  fd_vinyl_io_ur_sync,
  fd_vinyl_io_ur_fini
} };

FD_STATIC_ASSERT( alignof(fd_vinyl_io_ur_t)==FD_VINYL_BSTREAM_BLOCK_SZ, layout );

ulong
fd_vinyl_io_ur_align( void ) {
  return alignof(fd_vinyl_io_ur_t);
}

ulong
fd_vinyl_io_ur_footprint( ulong spad_max ) {
  if( FD_UNLIKELY( !((0UL<spad_max) & (spad_max<(1UL<<63)) & fd_ulong_is_aligned( spad_max, FD_VINYL_BSTREAM_BLOCK_SZ )) ) )
    return 0UL;
  return sizeof(fd_vinyl_io_ur_t) + spad_max;
}

fd_vinyl_io_t *
fd_vinyl_io_ur_init( void *            mem,
                     ulong             spad_max,
                     int               dev_fd,
                     struct io_uring * ring ) {
  fd_vinyl_io_ur_t * ur = (fd_vinyl_io_ur_t *)mem;

  if( FD_UNLIKELY( !ur ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ur, fd_vinyl_io_ur_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_vinyl_io_ur_footprint( spad_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad spad_max" ));
    return NULL;
  }

  off_t _dev_sz = lseek( dev_fd, (off_t)0, SEEK_END );
  if( FD_UNLIKELY( _dev_sz<(off_t)0 ) ) {
    FD_LOG_WARNING(( "lseek failed, bstream must be seekable (%i-%s)", errno, fd_io_strerror( errno ) ));
    return NULL;
  }
  ulong dev_sz = (ulong)_dev_sz;

  ulong dev_sz_min = 3UL*FD_VINYL_BSTREAM_BLOCK_SZ /* sync block, move block, closing partition */
                   + fd_vinyl_bstream_pair_sz( FD_VINYL_VAL_MAX ); /* worst case pair (FIXME: LZ4_COMPRESSBOUND?) */

  int too_small  = dev_sz < dev_sz_min;
  int too_large  = dev_sz > (ulong)LONG_MAX;
  int misaligned = !fd_ulong_is_aligned( dev_sz, FD_VINYL_BSTREAM_BLOCK_SZ );

  if( FD_UNLIKELY( too_small | too_large | misaligned ) ) {
    FD_LOG_WARNING(( "bstream size %s", too_small ? "too small" :
                                        too_large ? "too large" :
                                                    "not a block size multiple" ));
    return NULL;
  }

  memset( ur, 0, footprint );

  ur->base->type = FD_VINYL_IO_TYPE_UR;

  /* io_seed, seq_ancient, seq_past, seq_present, seq_future are init
     below */

  ur->base->spad_max  = spad_max;
  ur->base->spad_used = 0UL;
  ur->base->impl      = fd_vinyl_io_ur_impl;

  ur->dev_fd   = dev_fd;
  ur->dev_sync = 0UL;                            /* Use the beginning of the file for the sync block */
  ur->dev_base = FD_VINYL_BSTREAM_BLOCK_SZ;      /* Use the rest for the actual bstream store (at least 3.5 KiB) */
  ur->dev_sz   = dev_sz - FD_VINYL_BSTREAM_BLOCK_SZ;

  ur->rd_head      = NULL;
  ur->rd_tail_next = &ur->rd_head;

  ur->ring = ring;

  /* FIXME: Consider having the sync block on a completely separate
     device (to reduce seeking when syncing). */

  fd_vinyl_bstream_block_t * block = ur->sync;

  bd_read( dev_fd, ur->dev_sync, block, FD_VINYL_BSTREAM_BLOCK_SZ ); /* logs details */

  int          type        = fd_vinyl_bstream_ctl_type ( block->sync.ctl );
  int          version     = fd_vinyl_bstream_ctl_style( block->sync.ctl );
  ulong        val_max     = fd_vinyl_bstream_ctl_sz   ( block->sync.ctl );
  ulong        seq_past    = block->sync.seq_past;
  ulong        seq_present = block->sync.seq_present;
  ulong        info_sz     = block->sync.info_sz;    // overrides user info_sz
  void const * info        = block->sync.info;       // overrides user info
  ulong        io_seed     = block->sync.hash_trail; // overrides user io_seed

  int bad_type        = (type != FD_VINYL_BSTREAM_CTL_TYPE_SYNC);
  int bad_version     = (version != 0);
  int bad_val_max     = (val_max != FD_VINYL_VAL_MAX);
  int bad_seq_past    = !fd_ulong_is_aligned( seq_past,    FD_VINYL_BSTREAM_BLOCK_SZ );
  int bad_seq_present = !fd_ulong_is_aligned( seq_present, FD_VINYL_BSTREAM_BLOCK_SZ );
  int bad_info_sz     = (info_sz > FD_VINYL_BSTREAM_SYNC_INFO_MAX);
  int bad_past_order  = fd_vinyl_seq_gt( seq_past, seq_present );
  int bad_past_sz     = ((seq_present-seq_past) > ur->dev_sz);

  if( FD_UNLIKELY( bad_type | bad_version | bad_val_max | bad_seq_past | bad_seq_present | bad_info_sz |
                    bad_past_order | bad_past_sz ) ) {
    FD_LOG_WARNING(( "bad sync block when recovering bstream (%s)",
                      bad_type        ? "unexpected type"                             :
                      bad_version     ? "unexpected version"                          :
                      bad_val_max     ? "unexpected max pair value decoded byte size" :
                      bad_seq_past    ? "unaligned seq_past"                          :
                      bad_seq_present ? "unaligned seq_present"                       :
                      bad_info_sz     ? "unexpected info size"                        :
                      bad_past_order  ? "unordered seq_past and seq_present"          :
                                        "past size larger than bstream store" ));
    return NULL;
  }

  if( FD_UNLIKELY( fd_vinyl_bstream_block_test( io_seed, block ) ) ) {
    FD_LOG_WARNING(( "corrupt sync block when recovering bstream" ));
    return NULL;
  }

  ur->base->seed        = io_seed;
  ur->base->seq_ancient = seq_past;
  ur->base->seq_past    = seq_past;
  ur->base->seq_present = seq_present;
  ur->base->seq_future  = seq_present;

  FD_LOG_INFO(( "IO config"
                "\n\ttype     ur"
                "\n\tspad_max %lu bytes"
                "\n\tdev_sz   %lu bytes"
                "\n\tinfo     \"%s\" (info_sz %lu, discovered)"
                "\n\tio_seed  0x%016lx (discovered)"
                "\n\tsq depth %u entries",
                spad_max, dev_sz,
                (char const *)info, info_sz,
                io_seed,
                ring->sq.ring_entries ));

  return ur->base;
}

#else /* io_uring not supported */

ulong
fd_vinyl_io_ur_align( void ) {
  return 8UL;
}

ulong
fd_vinyl_io_ur_footprint( ulong spad_max ) {
  (void)spad_max;
  return 8UL;
}

fd_vinyl_io_t *
fd_vinyl_io_ur_init( void *            mem,
                     ulong             spad_max,
                     int               dev_fd,
                     struct io_uring * ring ) {
  (void)mem; (void)spad_max; (void)dev_fd; (void)ring;
  FD_LOG_WARNING(( "Sorry, this build does not support io_uring" ));
  return NULL;
}

#endif
