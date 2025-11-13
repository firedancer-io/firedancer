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

  int   dev_fd   = ur->dev_fd;
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
  io_uring_prep_read( sqe, dev_fd, rd->dst, (uint)rsz, dev_base+dev_off );
  io_uring_sqe_set_data( sqe, rd );
  ur->sq_prep_cnt++;
  if( FD_LIKELY( !sz ) ) return 1U; /* optimize for the unfragmented case */

  /* Tail wraparound occurred.  Amend the head SQE to be linked to the
     tail SQE, detach it from the io_ur descriptor, and suppress the CQE
     for the head.  If we get a CQE for the tail read job, we know that
     the head read job also succeeded.  Also, set the low bit of the
     userdata to 1 (usually guaranteed to be 0 due to alignment), to
     indicate that this SQE is a head frag. */
  io_uring_sqe_set_flags( sqe, IOSQE_IO_LINK | IOSQE_CQE_SKIP_SUCCESS );
  io_uring_sqe_set_data64( sqe, (ulong)rd+1UL );
  ur->cq_cnt++;  /* Treat as already-completed in metrics */

  /* Prepare the tail SQE */
  rd->tsz  = (uint)sz;
  sqe = io_uring_get_sqe( ring );
  if( FD_UNLIKELY( !sqe ) ) FD_LOG_CRIT(( "io_uring_get_sqe() returned NULL despite io_uring_sq_space_left()>=2" ));
  io_uring_prep_read( sqe, dev_fd, (uchar *)rd->dst + rsz, (uint)sz, dev_base );
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

static fd_vinyl_io_impl_t fd_vinyl_io_ur_impl[1] = { {
  NULL, // fd_vinyl_io_ur_read_imm,
  fd_vinyl_io_ur_read,
  fd_vinyl_io_ur_poll,
  NULL, // fd_vinyl_io_ur_append,
  NULL, // fd_vinyl_io_ur_commit,
  NULL, // fd_vinyl_io_ur_hint,
  NULL, // fd_vinyl_io_ur_alloc,
  NULL, // fd_vinyl_io_ur_copy,
  NULL, // fd_vinyl_io_ur_forget,
  NULL, // fd_vinyl_io_ur_rewind,
  NULL, // fd_vinyl_io_ur_sync,
  NULL, // fd_vinyl_io_ur_fini
} };

FD_STATIC_ASSERT( alignof(fd_vinyl_io_ur_t)==FD_VINYL_BSTREAM_BLOCK_SZ, layout );

ulong
fd_vinyl_io_ur_align( void ) {
  return alignof(fd_vinyl_io_ur_t);
}

ulong
fd_vinyl_io_ur_footprint( void ) {
  return sizeof(fd_vinyl_io_ur_t);
}

fd_vinyl_io_t *
fd_vinyl_io_ur_init( void *            mem,
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

  ulong footprint = fd_vinyl_io_ur_footprint();
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

  ur->base->spad_max  = 0UL;  /* FIXME */
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

  FD_LOG_NOTICE(( "IO config"
                  "\n\ttype     ur"
                  "\n\tdev_sz   %lu bytes"
                  "\n\tinfo     \"%s\" (info_sz %lu, discovered)"
                  "\n\tio_seed  0x%016lx (discovered)",
                  dev_sz,
                  (char const *)info, info_sz,
                  io_seed ));

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
