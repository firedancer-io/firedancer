/* fd_vinyl_io_ur_rd.c provides io_ur read methods. */

#include "fd_vinyl_io_ur_private.h"

/* io_ur reads are either served by the write-back cache or by disk,
   see the explanation in fd_vinyl_io_ur_wb.c.

   For a given request, the low part of the request is served by disk
   and the high part is served by the write-back cache.  wb_read handles
   the high part.

   [seq0,seq0+sz) is the requested bstream range (assumed to be in
   [seq_past,seq_present)).  wb_read identifies the pivot point retval
   where seq0<=retval<=seq0+sz and copies [retval,seq0+sz) to
   [dst0+retval,dst0+sz).

   Returns retval (the number of bytes that were not read).  I.e.
   [seq0,seq0+retval) gives the bstream range that should be fetched
   from the underlying store. */

static ulong
wb_read( fd_vinyl_io_ur_t * io,
         uchar *            dst0,  /* destination buffer */
         ulong              seq0,  /* request lower bound */
         ulong              sz ) { /* request size */
  if( FD_UNLIKELY( !sz ) ) return 0UL;

  /* validate that this request spans committed data */
  ulong seq_cache = io->seq_cache;
  ulong seq1      = seq0 + sz;

  if( FD_UNLIKELY( fd_vinyl_seq_lt( seq0, io->base->seq_past    ) |
                   fd_vinyl_seq_gt( seq1, io->base->seq_present ) ) ) {
    FD_LOG_CRIT(( "bstream write-back cache read [%016lx,%016lx)/%lu is out-of-bounds (past [%016lx,%016lx))",
                  seq0, seq1, sz,
                  io->base->seq_past, io->base->seq_present ));
  }

  /* expect most reads to hit disk (seq_cache marks the first seq that
     is present in cache) */
  if( FD_LIKELY( fd_vinyl_seq_le( seq1, seq_cache ) ) ) return sz;

  /* request seq range served by cache */
  ulong req0 = fd_ulong_max( seq0, seq_cache );
  ulong req1 = seq1;
  FD_CRIT( fd_vinyl_seq_ge( req0, wb_ring_seq0( &io->wb ) ), "invariant violation" );
  FD_CRIT( fd_vinyl_seq_le( req1, wb_ring_seq1( &io->wb ) ), "invariant violation" );

  /* output range */
  uchar * dst = dst0 + (req0-seq0);
  ulong   rsz = req1 - req0;
  FD_CRIT( dst>=dst0 && dst<dst0+sz && rsz<=sz, "invariant violation" );

  /* find source range, copy into output */
  uchar const *  spad = fd_vinyl_io_ur_wb_buf( io );
  wb_ring_span_t span = wb_ring_translate( &io->wb, req0, rsz );
  if( span.sz0 ) fd_memcpy( dst,          spad+span.off0, span.sz0 );
  if( span.sz1 ) fd_memcpy( dst+span.sz0, spad+span.off1, span.sz1 );
  io->base->cache_read_cnt    += (ulong)( !!span.sz0 + !!span.sz1 );
  io->base->cache_read_tot_sz +=            span.sz0 +   span.sz1;

  return sz-rsz;
}

/* fd_vinyl_io_ur_read_imm (vinyl_io interface) does a blocking read. */

void
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

  /* At this point, we have a valid read request.  Serve tail from
     write-back cache. */

  sz = wb_read( ur, dst, seq0, sz );
  if( !sz ) return;
  seq1 = seq0 + sz; /* unused */

  /* Read the rest from disk.  Map seq0 into the bstream store.  Read
     the lesser of sz bytes or until the store end.  If we hit the store
     end with more to go, wrap around and finish the read at the store
     start. */

  int   dev_fd   = ur->dev_fd;
  ulong dev_base = ur->dev_base;
  ulong dev_sz   = ur->dev_sz;

  ulong dev_off = seq0 % dev_sz;

  ulong rsz = fd_ulong_min( sz, dev_sz - dev_off );
  bd_read( dev_fd, dev_base + dev_off, dst, rsz );
  sz -= rsz;
  ur->base->file_read_cnt++;
  ur->base->file_read_tot_sz += rsz;

  if( FD_UNLIKELY( sz ) ) {
    bd_read( dev_fd, dev_base, dst + rsz, sz );
    ur->base->file_read_cnt++;
    ur->base->file_read_tot_sz += sz;
  }

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

/* rq_push adds a read job to the staged queue. */

static void
rq_push( fd_vinyl_io_ur_t *    ur,
         fd_vinyl_io_ur_rd_t * rd ) {
  rd->next          = NULL;
  *ur->rq_tail_next = rd;
  ur->rq_tail_next  = &rd->next;
}

/* rc_push adds a read job to the early-complete queue. */

static void
rc_push( fd_vinyl_io_ur_t *    ur,
         fd_vinyl_io_ur_rd_t * rd ) {
  rd->next          = NULL;
  *ur->rc_tail_next = rd;
  ur->rc_tail_next  = &rd->next;
}

static void
track_sqe_read( fd_vinyl_io_ur_t * ur,
                ulong              sz ) {
  ur->base->file_read_cnt++;
  ur->base->file_read_tot_sz += sz;
  ur->sqe_prep_cnt++;
  ur->cqe_pending++;
  ur->cqe_read_pending++;
}

/* rq_prep translates a staged read job into one (or rarely two)
   io_uring SQEs.  SQEs are allocated off the io_uring instance.
   Returns the number of SQEs prepared on success, and moves rd onto the
   wait heap.  Might not prepare any SQEs if the read request was served
   entirely from cache.  On failure to allocate SQEs, behaves like a
   no-op (safe to retry) and returns -1. */

static int
rq_prep( fd_vinyl_io_ur_t *    ur,
         fd_vinyl_io_ur_rd_t * rd,
         ulong                 seq0,
         ulong                 sz ) {

  fd_io_uring_t * ring = ur->ring;
  if( FD_UNLIKELY( sz>INT_MAX ) ) {
    FD_LOG_CRIT(( "Invalid read size 0x%lx bytes (exceeds max)", sz ));
  }
  if( FD_UNLIKELY( fd_io_uring_sq_space_left( ring->sq )<2U ) ) return -1;

  /* Serve tail from write-back cache */

  sz = wb_read( ur, rd->dst, seq0, sz );
  if( !sz ) {
    rc_push( ur, rd );
    return 0;
  }

  /* If the read was entirely served by cache (sz==0), generate an
     io_uring SQE regardless, since we don't have any data structure to
     hold early completions. */

  /* Map seq0 into the bstream store. */

  ulong dev_base = ur->dev_base;
  ulong dev_sz   = ur->dev_sz;

  ulong dev_off = seq0 % dev_sz;

  ulong rsz = fd_ulong_min( sz, dev_sz - dev_off );
  sz -= rsz;

  /* Prepare the head SQE */
  rd->next     = NULL;
  rd->head_off = 0U;
  rd->head_sz  = (uint)rsz;
  rd->tail_off = 0U;
  rd->tail_sz  = 0U;
  struct io_uring_sqe * sqe = fd_io_uring_get_sqe( ring->sq );
  if( FD_UNLIKELY( !sqe ) ) FD_LOG_CRIT(( "fd_io_uring_get_sqe() returned NULL despite io_uring_sq_space_left()>=2" ));
  *sqe = (struct io_uring_sqe) {
    .opcode    = IORING_OP_READ,
    .fd        = 0, /* fixed file index 0 */
    .off       = dev_base + dev_off,
    .addr      = (ulong)rd->dst,
    .len       = (uint)rsz,
    .flags     = IOSQE_FIXED_FILE,
    .user_data = ur_udata_pack_ptr( UR_REQ_READ, rd ),
  };
  track_sqe_read( ur, rsz );
  if( FD_LIKELY( !sz ) ) return 1; /* optimize for the unfragmented case */

  /* Prepare the tail SQE */
  rd->tail_sz = (uint)sz;
  sqe = fd_io_uring_get_sqe( ring->sq );
  if( FD_UNLIKELY( !sqe ) ) FD_LOG_CRIT(( "fd_io_uring_get_sqe() returned NULL despite io_uring_sq_space_left()>=2" ));
  *sqe = (struct io_uring_sqe) {
    .opcode    = IORING_OP_READ,
    .fd        = 0, /* fixed file index 0 */
    .off       = dev_base,
    .addr      = (ulong)rd->dst + rsz,
    .len       = (uint)sz,
    .flags     = IOSQE_FIXED_FILE,
    .user_data = ur_udata_pack_ptr( UR_REQ_READ_TAIL, rd ),
  };
  track_sqe_read( ur, sz );
  return 2;
}

/* rq_clean moves as many read jobs from the staged queue to the
   submission queue as possible. */

static void
rq_clean( fd_vinyl_io_ur_t * ur ) {
  for(;;) {
    fd_vinyl_io_ur_rd_t * rd = ur->rq_head;
    if( !rd ) break;

    fd_vinyl_io_ur_rd_t ** rq_tail_next = ur->rq_tail_next;
    fd_vinyl_io_ur_rd_t *  rq_next      = rd->next;

    if( FD_UNLIKELY( rq_prep( ur, rd, rd->seq, rd->sz )<0 ) ) break;

    ur->rq_head      = rq_next;
    ur->rq_tail_next = fd_ptr_if( !!rq_next, rq_tail_next, &ur->rq_head );
  }
}

void
fd_vinyl_io_ur_read( fd_vinyl_io_t *    io,
                     fd_vinyl_io_rd_t * _rd ) {
  fd_vinyl_io_ur_t *    ur = (fd_vinyl_io_ur_t *)io;
  fd_vinyl_io_ur_rd_t * rd = (fd_vinyl_io_ur_rd_t *)_rd;
  rq_push( ur, rd );
  rq_clean( ur );
}

/* rq_prep_retry re-enqueues a SQE after a short read */

static void
rq_prep_retry( fd_vinyl_io_ur_t *    ur,
               fd_vinyl_io_ur_rd_t * rd,
               ulong                 req_type ) {
  fd_io_uring_t * ring = ur->ring;

  ulong dev_base = ur->dev_base;
  ulong dev_sz   = ur->dev_sz;

  ulong   frag_dev_off;
  uchar * frag_dst;
  ulong   frag_sz;
  if( FD_LIKELY( req_type==UR_REQ_READ ) ) {
    frag_dev_off = dev_base + (rd->seq % dev_sz) + rd->head_off;
    frag_dst     = (uchar *)rd->dst + rd->head_off;
    frag_sz      = rd->head_sz - rd->head_off;
  } else { /* tail read */
    frag_dev_off = dev_base + rd->tail_off;
    frag_dst     = (uchar *)rd->dst + rd->head_sz + rd->tail_off;
    frag_sz      = rd->tail_sz - rd->tail_off;
  }

  struct io_uring_sqe * sqe = fd_io_uring_get_sqe( ring->sq );
  if( FD_UNLIKELY( !sqe ) ) FD_LOG_CRIT(( "no SQ space available; unbalanced SQ and CQ?" ));
  *sqe = (struct io_uring_sqe) {
    .opcode    = IORING_OP_READ,
    .fd        = 0, /* fixed file index 0 */
    .off       = frag_dev_off,
    .addr      = (ulong)frag_dst,
    .len       = (uint)frag_sz,
    .flags     = IOSQE_FIXED_FILE,
    .user_data = ur_udata_pack_ptr( req_type, rd ),
  };
  track_sqe_read( ur, frag_sz );
}

/* rq_completion consumes an io_uring CQE.  Returns io_rd if a read job
   completed, otherwise returns NULL. */

static fd_vinyl_io_ur_rd_t *
rq_completion( fd_vinyl_io_ur_t * ur ) {
  fd_io_uring_t * ring = ur->ring;

  /* The CQE could come in one of these shapes:
     - Success (full read)
     - Short read: re-enqueue
     - Zero byte read: unexpected EOF reached, crash the app
     - Error: crash the app */

  FD_CRIT( ur->cqe_pending     >0, "stray completion"      );
  FD_CRIT( ur->cqe_read_pending>0, "stray read completion" );

  struct io_uring_cqe * cqe      = fd_io_uring_cq_head( ring->cq );
  ulong                 req_type = ur_udata_req_type( cqe->user_data );
  fd_vinyl_io_ur_rd_t * rd       = ur_udata_ptr     ( cqe->user_data );

  if( FD_UNLIKELY( !rd ) ) FD_LOG_CRIT(( "io_uring_peek_cqe() yielded invalid user data" ));
  int cqe_res = cqe->res;
  if( cqe_res<0 ) {
    FD_LOG_ERR(( "io_uring read failed (%i-%s)", -cqe_res, fd_io_strerror( -cqe_res ) ));
  }
  if( FD_UNLIKELY( cqe_res==0 ) ) {
    FD_LOG_ERR(( "io_uring read failed (unexpected EOF)" ));
  }

  /* interpret CQE user data */
  uint * poff;
  uint * psz;
  if( FD_LIKELY( req_type==UR_REQ_READ ) ) {
    poff = &rd->head_off; psz = &rd->head_sz;
  } else if( req_type==UR_REQ_WRITE ) {
    poff = &rd->tail_off; psz = &rd->tail_sz;
  } else {
    FD_LOG_CRIT(( "unexpected CQE (user_data=0x%016llx)", cqe->user_data ));
  }
  FD_CRIT( *poff < *psz, "invariant violation" );
  ur->cqe_read_pending--;
  ur->cqe_pending--;
  ur->cqe_cnt++;
  fd_io_uring_cq_advance( ring->cq, 1U );

  /* was this a short read? */
  if( FD_UNLIKELY( (uint)cqe_res > *psz-*poff ) ) {
    FD_LOG_CRIT(( "io_uring read returned excess data (seq=%lu expected_sz=%u cqe_res=%d part=%s)",
                  rd->seq, *psz-*poff, cqe_res, req_type==UR_REQ_READ?"head":"tail" ));
  }
  *poff += (uint)cqe_res;
  if( FD_UNLIKELY( *poff < *psz ) ) {
    ur->cqe_read_short_cnt++;
    rq_prep_retry( ur, rd, req_type );
    return NULL;
  }

  /* did all reads complete? */
  if( FD_UNLIKELY( ( rd->head_off < rd->head_sz ) |
                   ( rd->tail_off < rd->tail_sz ) ) ) {
    /* need another CQE to make progress */
    return NULL;
  }

  return rd;
}

void
fd_vinyl_io_ur_rd_completion( fd_vinyl_io_ur_t * ur ) {
  fd_vinyl_io_ur_rd_t * rd = rq_completion( ur );
  rc_push( ur, rd );
}

/* fd_vinyl_io_ur_poll pops the next read completion.  May block. */

int
fd_vinyl_io_ur_poll( fd_vinyl_io_t *     io,
                     fd_vinyl_io_rd_t ** _rd,
                     int                 flags ) {
  fd_vinyl_io_ur_t * ur       = (fd_vinyl_io_ur_t *)io;
  fd_io_uring_t *    ring     = ur->ring;
  int                blocking = !!( flags & FD_VINYL_IO_FLAG_BLOCKING );
  *_rd = NULL;

  /* Pop early completions */
  if( ur->rc_head ) {
    fd_vinyl_io_ur_rd_t *  rd           = ur->rc_head;
    fd_vinyl_io_ur_rd_t ** rc_tail_next = ur->rc_tail_next;
    fd_vinyl_io_ur_rd_t *  rc_next      = rd->next;
    ur->rc_head      = rc_next;
    ur->rc_tail_next = fd_ptr_if( !!rc_next, rc_tail_next, &ur->rc_head );
    *_rd = (fd_vinyl_io_rd_t *)rd;
    return FD_VINYL_SUCCESS;
  }

  /* Drain completions until we find a read (skip writes). */
  for(;;) {
    if( FD_UNLIKELY( fd_io_uring_sq_dropped( ring->sq ) ) ) {
      FD_LOG_CRIT(( "io_uring submission queue overflowed" ));
    }

    uint cq_cnt = fd_io_uring_cq_ready( ring->cq );
    if( FD_UNLIKELY( !cq_cnt ) ) {  /* no CQEs ready */
      /* Move staged work to submission queue */
      rq_clean( ur );

      /* If no work is available to schedule, bail to avoid deadlock */
      int have_pending = ur->sqe_prep_cnt > ur->sqe_sent_cnt;
      int have_waiting = ur->sqe_sent_cnt > ur->cqe_cnt;
      if( FD_UNLIKELY( !have_pending && !have_waiting ) ) {
        return FD_VINYL_ERR_EMPTY;
      }

      /* Issue syscall to drive kernel */
      uint flags = blocking ? IORING_ENTER_GETEVENTS : 0U;
      int submit_cnt = fd_io_uring_submit( ring->sq, ring->ioring_fd, !!blocking, flags );
      if( FD_UNLIKELY( submit_cnt<0 ) ) {
        FD_LOG_ERR(( "io_uring_enter failed (%i-%s)", -submit_cnt, fd_io_strerror( -submit_cnt ) ));
      }
      ur->sqe_sent_cnt += (ulong)submit_cnt;

      cq_cnt = fd_io_uring_cq_ready( ring->cq );
      if( !cq_cnt ) {
        if( FD_UNLIKELY( blocking ) ) FD_LOG_CRIT(( "io_uring_submit_and_wait() returned but no CQEs ready" ));
        return FD_VINYL_ERR_AGAIN;
      }
    }

    struct io_uring_cqe * cqe = fd_io_uring_cq_head( ring->cq );
    if( FD_UNLIKELY( !cqe ) ) FD_LOG_CRIT(( "fd_io_uring_cq_head() returned NULL despite io_uring_cq_ready()>=1" ));
    if( ur_udata_req_type( cqe->user_data )==UR_REQ_WRITE ) {
      fd_vinyl_io_ur_completion( ur );
      continue;
    }

    fd_vinyl_io_ur_rd_t * rd = rq_completion( ur );
    if( FD_UNLIKELY( !rd ) ) continue;
    *_rd = (fd_vinyl_io_rd_t *)rd;
    return FD_VINYL_SUCCESS;
  }
}
