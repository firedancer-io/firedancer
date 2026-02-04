#include "fd_vinyl_io_ur_private.h"

#pragma GCC diagnostic ignored "-Wunused-function"

/* This backend uses scratch pad memory as a write-back cache.  Every
   byte in the scratch pad has one of the following states:

   - clean:  Written out to bstream
   - write:  Write job in progress
   - wait:   To be written out in the future
   - future: Written with append(), awaiting commit()
   - used:   Reserved with alloc(), awaiting trim()/append()
   - free:   Unused

   The write-back cache has a logical address space (bstream_seq),
   and a physical address space (offset).

   In logical space, each state covers a contiguous range of bytes in
   the following order.  Various bstream seq numbers mark the bounds
   between regions.

         [clean] [write] [wait] [future] [used] [free]
         ^       ^       ^      ^        ^      ^
      seq_cache  |   seq_write  |    seq_future |
             seq_clean     seq_present       wb.seq1

   The region [seq_past,seq_cache) is outside of the write cache.

   The region [seq_cache,seq_present), i.e. spanning 'clean', 'write',
   and 'wait', is part of the write cache.  Read requests that fall in
   this range are served from the write cache.

   The logical address space maps to the physical address space as a
   ring.  The ring mapping is not modulo, see wb_ring for details. */

void
fd_vinyl_io_wq_completion( fd_vinyl_io_ur_t * ur ) {
  fd_io_uring_t * ring = ur->ring;

  FD_CRIT( ur->cqe_pending      >0, "stray completion"       );
  FD_CRIT( ur->cqe_write_pending>0, "stray write completion" );

  /* interpret CQE */
  struct io_uring_cqe * cqe = fd_io_uring_cq_head( ring->cq );
  if( FD_UNLIKELY( !cqe ) ) FD_LOG_CRIT(( "no write completion found" ));
  if( ur_udata_req_type( cqe->user_data )!=UR_REQ_WRITE ) {
    FD_LOG_CRIT(( "unexpected CQE type while flushing write queue" ));
  }
  int cqe_res = cqe->res;
  if( cqe_res<0 ) {
    FD_LOG_ERR(( "io_uring write failed (%i-%s)", -cqe_res, fd_io_strerror( -cqe_res ) ));
  }

  /* advance write cursor */
  ulong       wq_idx  = ur_udata_idx( cqe->user_data );
  wq_desc_t * wq_desc = wq_ring_desc( &ur->wq, wq_idx );
  ulong       req_sz  = wq_desc->sz;
  if( FD_UNLIKELY( (uint)cqe_res != req_sz ) ) {
    FD_LOG_ERR(( "database write failed (short write): requested to write %lu bytes, but only wrote %i bytes (at bstream seq 0x%016lx)",
                 req_sz, cqe_res,
                 wq_desc->seq - req_sz ));
  }
  ur->seq_clean = wq_ring_complete( &ur->wq, wq_idx );

  fd_io_uring_cq_advance( ring->cq, 1U );
  ur->cqe_write_pending--;
  ur->cqe_pending--;
  ur->cqe_cnt++;
}

/* wq_clean polls for write completions. */

static void
wq_clean( fd_vinyl_io_ur_t * ur ) {
  fd_io_uring_t * ring = ur->ring;
  while( fd_io_uring_cq_ready( ring->cq ) ) {
    fd_vinyl_io_wq_completion( ur );
  }
}

/* wq_wait waits for one write completion. */

static void
wq_wait( fd_vinyl_io_ur_t * ur ) {
  fd_io_uring_t * ring = ur->ring;
  FD_CRIT( ur->cqe_write_pending>0, "stray write completion wait" );
  FD_CRIT( ur->cqe_pending      >0, "stray completion wait" );
  int err = fd_io_uring_enter( ring->ioring_fd, 0U, 1U, IORING_ENTER_GETEVENTS, NULL, 0UL );
  if( FD_UNLIKELY( err<0 ) ) {
    FD_LOG_ERR(( "io_uring_enter failed (%i-%s)", -err, fd_io_strerror( -err ) ));
  }
  FD_CRIT( fd_io_uring_cq_ready( ring->cq )>0, "io_uring_enter returned but no CQEs ready" );
}

/* wq_enqueue adds a buffer to the write queue. */

static void
wq_enqueue( fd_vinyl_io_ur_t * ur,
            ulong              seq,
            uchar const *      src,
            ulong              sz ) {

  fd_io_uring_t * ring     = ur->ring;
  ulong           cq_depth = ring->cq->depth;
  wq_ring_t *     wq       = &ur->wq;
  for(;;) {
    wq_clean( ur );
    if( wq_ring_free_cnt( wq )>=2 && ur->cqe_pending+2 <= cq_depth ) break;
    wq_wait( ur );
  }

  /* Map seq into the bstream store.  If we hit the store and with more
     to go, wrap around and finish the write at the store start. */

  ulong dev_base = ur->dev_base;
  ulong dev_sz   = ur->dev_sz;
  ulong dev_off  = seq % dev_sz;

  ulong wsz = fd_ulong_min( sz, dev_sz - dev_off );
  ulong wq0 = wq_ring_enqueue( wq, seq+wsz );
  wq_ring_desc( wq, wq0 )->sz = (uint)wsz; /* remember request size for CQE */
  struct io_uring_sqe * sqe = fd_io_uring_get_sqe( ring->sq );
  if( FD_UNLIKELY( !sqe ) ) FD_LOG_CRIT(( "unbalanced SQ" ));
  *sqe = (struct io_uring_sqe) {
    .opcode    = IORING_OP_WRITE,
    .fd        = 0, /* fixed file index 0 */
    .off       = dev_base + (seq % dev_sz),
    .addr      = (ulong)src,
    .len       = (uint)wsz,
    .flags     = IOSQE_FIXED_FILE,
    .user_data = ur_udata_pack_idx( UR_REQ_WRITE, wq0 ),
  };
  ur->sqe_prep_cnt++;
  ur->sqe_write_tot_sz += wsz;
  ur->cqe_pending++;
  ur->cqe_write_pending++;

  sz -= wsz;
  if( sz ) {
    ulong wq1 = wq_ring_enqueue( wq, seq+wsz+sz );
    wq_ring_desc( wq, wq1 )->sz = (uint)sz;
    sqe = fd_io_uring_get_sqe( ring->sq );
    if( FD_UNLIKELY( !sqe ) ) FD_LOG_CRIT(( "unbalanced SQ" ));
    *sqe = (struct io_uring_sqe) {
      .opcode    = IORING_OP_WRITE,
      .fd        = 0, /* fixed file index 0 */
      .off       = dev_base,
      .addr      = (ulong)( src + wsz ),
      .len       = (uint)sz,
      .flags     = IOSQE_FIXED_FILE,
      .user_data = ur_udata_pack_idx( UR_REQ_WRITE, wq1 ),
    };
    ur->sqe_prep_cnt++;
    ur->sqe_write_tot_sz += sz;
    ur->cqe_pending++;
    ur->cqe_write_pending++;
  }
}

/* wq_enqueue_seq adds jobs to the write queue until the given sequence
   number. */

static void
wq_enqueue_seq( fd_vinyl_io_ur_t * ur,
                ulong              seq1 ) {
  ulong seq0 = ur->seq_write;
  FD_CRIT( fd_vinyl_seq_lt( seq0, seq1 ), "invalid wq_enqueue_seq call" );
  ulong const   sz   = seq1 - seq0;
  uchar const * spad = fd_vinyl_io_ur_wb_buf( ur );

  wb_ring_span_t span = wb_ring_translate( &ur->wb, seq0, sz );
  if( span.sz0 ) wq_enqueue( ur, ur->seq_write,          spad+span.off0, span.sz0 );
  if( span.sz1 ) wq_enqueue( ur, ur->seq_write+span.sz0, spad+span.off1, span.sz1 );
  FD_CRIT( ur->seq_write+span.sz0+span.sz1==seq1, "invariant violation" );
  ur->seq_write = seq1;

  fd_io_uring_t * ring = ur->ring;
  int submit_cnt = fd_io_uring_submit( ring->sq, ring->ioring_fd, 0, 0U );
  if( FD_UNLIKELY( submit_cnt<0 ) ) FD_LOG_ERR(( "io_uring_submit failed (%i-%s)", -submit_cnt, fd_io_strerror( -submit_cnt ) ));
  ur->sqe_sent_cnt += (ulong)submit_cnt;
}

/* wb_flush_seq does a blocking flush of the write cache until the
   given sequence number. */

static void
wb_flush_seq( fd_vinyl_io_ur_t * ur,
              ulong              seq ) {
  if( FD_UNLIKELY( fd_vinyl_seq_gt( seq, ur->base->seq_present ) ) ) {
    FD_LOG_CRIT(( "pipeline depth exceeded (seq=%lu seq_present=%lu)", seq, ur->base->seq_present ));
  }
  if( fd_vinyl_seq_gt( seq, ur->seq_write ) ) {
    ulong write_sz = seq - ur->seq_write;
    if( FD_UNLIKELY( write_sz < WQ_BLOCK_SZ ) ) {
      /* required write is a bit small.  try to eagerly write more in
         order to reduce the amount of write ops. */
      ulong write_max = ur->base->seq_present - ur->seq_write;
      write_sz = fd_ulong_min( write_max, WQ_BLOCK_SZ );
    }
    ulong seq_write_new = ur->seq_write + write_sz;
    FD_CRIT( fd_vinyl_seq_ge( seq_write_new, seq ), "invariant violation" );
    wq_enqueue_seq( ur, seq_write_new );
  }
  for(;;) {
    wq_clean( ur );
    if( fd_vinyl_seq_ge( ur->seq_clean, seq ) ) break;
    wq_wait( ur );
  }
}

/* fd_vinyl_io_ur_alloc allocates space in the write-back ring buffer. */

void *
fd_vinyl_io_ur_alloc( fd_vinyl_io_t * io,
                      ulong           sz,
                      int             flags ) {
  fd_vinyl_io_ur_t * ur = (fd_vinyl_io_ur_t *)io; /* Note: io must be non-NULL to have even been called */

  int flag_blocking = !!( flags & FD_VINYL_IO_FLAG_BLOCKING );

  int bad_align = !fd_ulong_is_aligned( sz, FD_VINYL_BSTREAM_BLOCK_SZ );
  int bad_sz    = sz > ur->wb.max;

  if( FD_UNLIKELY( bad_align | bad_sz ) ) FD_LOG_CRIT(( bad_align ? "misaligned sz" : "sz too large" ));

  /* An alloc op discards a previous alloc */

  wb_ring_trim( &ur->wb, ur->base->seq_future );
  ur->base->spad_used = 0UL;

  /* Ensure that this alloc does not evict anything from the write cache
     that we cannot recover from the bstream file descriptor. */

  ulong seq_clean_new = wb_ring_alloc_seq0( &ur->wb, sz );
  if( FD_UNLIKELY( fd_vinyl_seq_gt( seq_clean_new, ur->seq_clean ) ) ) {
    /* This alloc cannot proceed until some writes happen */
    if( !flag_blocking ) return NULL;
    wb_flush_seq( ur, seq_clean_new );
  }

  /* At this point, we have enough clean space to alloc sz bytes. */

  ulong seq = ur->base->seq_future;
  if( FD_UNLIKELY( fd_vinyl_seq_ne( seq, wb_ring_seq1( &ur->wb ) ) ) ) {
    FD_LOG_CRIT(( "seq_future (%lu) and write-back buffer (%lu) out of sync", seq, wb_ring_seq1( &ur->wb ) ));
  }
  wb_ring_alloc( &ur->wb, sz );
  if( FD_UNLIKELY( fd_vinyl_seq_ne( seq+sz, wb_ring_seq1( &ur->wb ) ) ) ) {
    FD_LOG_CRIT(( "seq_future (%lu) and write-back buffer (%lu) out of sync", seq, wb_ring_seq1( &ur->wb ) ));
  }
  ur->base->spad_used = sz;
  if( fd_vinyl_seq_gt( ur->wb.seq0, ur->seq_cache ) ) ur->seq_cache = ur->wb.seq0;
  if( FD_UNLIKELY( !sz ) ) {
    ur->last_alloc = NULL;
    return NULL;
  }

  ulong off = wb_ring_seq_to_off( &ur->wb, seq );
  void * alloc = fd_vinyl_io_ur_wb_buf( ur ) + off;
  ur->last_alloc = alloc;
  return alloc;
}

/* fd_vinyl_io_ur_append appends to the write-back cache. */

ulong
fd_vinyl_io_ur_append( fd_vinyl_io_t * io,
                       void const *    _src,
                       ulong           sz ) {
  fd_vinyl_io_ur_t * ur   = (fd_vinyl_io_ur_t *)io; /* Note: io must be non-NULL to have even been called */
  uchar const *      src  = (uchar const *)_src;
  uchar *            spad = fd_vinyl_io_ur_wb_buf( ur );

  if( FD_UNLIKELY( ur->cqe_read_pending ) ) {
    FD_LOG_CRIT(( "attempted to enqueue a write while there are still inflight reads" ));
  }

  /* Validate the input args. */

  ulong seq_future  = ur->base->seq_future;  if( FD_UNLIKELY( !sz ) ) return seq_future;
  ulong seq_ancient = ur->base->seq_ancient;
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

  /* Is the request in-place?  If so, trim the allocation */

  ulong seq    = seq_future;

  ur->base->spad_used = 0UL;
  if( src==ur->last_alloc ) {
    FD_CRIT( seq+sz<=ur->wb.seq1+ur->wb.sz1, "seq_future and write-back buffer out of sync" );
    wb_ring_trim( &ur->wb, seq+sz );
  } else {
    /* src must not be in spad */
    if( FD_UNLIKELY( ( (ulong)src>=(ulong)(spad           ) ) &
                     ( (ulong)src<=(ulong)(spad+ur->wb.max) ) ) ) {
      FD_LOG_CRIT(( "src buffer overlaps write-back cache" ));
    }
    /* copy allocation into spad */
    wb_ring_trim( &ur->wb, seq );
    void * alloc = fd_vinyl_io_ur_alloc( io, sz, FD_VINYL_IO_FLAG_BLOCKING );
    fd_memcpy( alloc, src, sz );
  }

  /* At this point, the append request is at the correct position in the
     write-back cache.  Commit the allocation. */

  ur->base->seq_future = seq + sz;
  ur->base->spad_used  = 0UL;

  return seq;
}

/* fd_vinyl_io_ur_commit 'commits' previous appends, making them visible
   to subsequent read calls. */

int
fd_vinyl_io_ur_commit( fd_vinyl_io_t * io,
                       int             flags ) {
  fd_vinyl_io_ur_t * ur = (fd_vinyl_io_ur_t *)io; /* Note: io must be non-NULL to have even been called */
  (void)flags;

  wb_ring_trim( &ur->wb, ur->base->seq_future );
  ur->base->seq_present = ur->base->seq_future;
  ur->base->spad_used   = 0UL;

  /* Keep io_uring pipeline fed */

  if( ur->base->seq_present - ur->seq_write >= WQ_BLOCK_SZ ) {
    ulong seq_until = fd_ulong_align_dn( ur->base->seq_present, WQ_BLOCK_SZ );
    if( fd_vinyl_seq_gt( seq_until, ur->seq_write ) ) {
      wq_enqueue_seq( ur, seq_until );
    }
  }

  return FD_VINYL_SUCCESS;
}

/* fd_vinyl_io_ur_copy does a blocking read of an old block, then copies
   it out to the tail.  This is not ideal.  Instead, we should enqueue
   async background read/write jobs. */

ulong
fd_vinyl_io_ur_copy( fd_vinyl_io_t * io,
                     ulong           seq_src0,
                     ulong           sz ) {
  fd_vinyl_io_ur_t * ur = (fd_vinyl_io_ur_t *)io; /* Note: io must be non-NULL to have even been called */

  /* Validate the input args */

  ulong seq_past    = ur->base->seq_past;
  ulong seq_present = ur->base->seq_present;
  ulong seq_future  = ur->base->seq_future;   if( FD_UNLIKELY( !sz ) ) return seq_future;
  ulong spad_max    = ur->wb.max;

  ulong seq_src1 = seq_src0 + sz;

  int bad_past = !( fd_vinyl_seq_le( seq_past, seq_src0    ) &
                    fd_vinyl_seq_lt( seq_src0, seq_src1    ) &
                    fd_vinyl_seq_le( seq_src1, seq_present ) );
  int bad_src  = !fd_ulong_is_aligned( seq_src0, FD_VINYL_BSTREAM_BLOCK_SZ );
  int bad_sz   = !fd_ulong_is_aligned( sz,       FD_VINYL_BSTREAM_BLOCK_SZ );

  if( FD_UNLIKELY( bad_past | bad_src | bad_sz ) )
    FD_LOG_CRIT(( bad_past ? "src is not in the past" :
                  bad_src  ? "misaligned src_seq"     :
                             "misaligned sz" ));

  /* Map the dst to the bstream (updating seq_future) and map the src
     and dst regions onto the device.  Then copy as much as we can at a
     time, handling device wrap around and copy buffering space. */

  ulong seq = seq_future;

  for(;;) {
    ulong csz = fd_ulong_min( sz, spad_max );

    void * buf = fd_vinyl_io_ur_alloc( io, csz, FD_VINYL_IO_FLAG_BLOCKING );
    fd_vinyl_io_ur_read_imm( io, seq_src0, buf, csz );
    fd_vinyl_io_ur_append  ( io,           buf, csz );

    sz -= csz;
    if( !sz ) break;

    seq_src0 += csz;
  }

  return seq;
}

ulong
fd_vinyl_io_ur_hint( fd_vinyl_io_t * io,
                     ulong           sz ) {
  fd_vinyl_io_ur_t * ur = (fd_vinyl_io_ur_t *)io; /* Note: io must be non-NULL to have even been called */
  fd_vinyl_io_ur_alloc( io, sz, FD_VINYL_IO_FLAG_BLOCKING );
  fd_vinyl_io_trim( io, ur->base->seq_future );
  return io->seq_future;
}

int
fd_vinyl_io_ur_sync( fd_vinyl_io_t * io,
                     int             flags ) {
  fd_vinyl_io_ur_t * ur = (fd_vinyl_io_ur_t *)io; /* Note: io must be non-NULL to have even been called */
  (void)flags;

  ulong seed        = ur->base->seed;
  ulong seq_past    = ur->base->seq_past;
  ulong seq_present = ur->base->seq_present;

  wb_flush_seq( ur, seq_present );

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

/* fd_vinyl_io_ur_forget "forgets" old data, making it available to
   future allocations. */

void
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
  int bad_read   = !!ur->rq_head || !!ur->rc_head;
  int bad_append = fd_vinyl_seq_ne( seq_present, seq_future );

  if( FD_UNLIKELY( bad_seq | bad_dir | bad_read | bad_append ) )
    FD_LOG_CRIT(( "forget to seq %016lx failed (past [%016lx,%016lx)/%lu, %s)",
                  seq, seq_past, seq_present, seq_present-seq_past,
                  bad_seq  ? "misaligned seq"             :
                  bad_dir  ? "seq out of bounds"          :
                  bad_read ? "reads in progress"          :
                             "appends/copies in progress" ));

  /* Before we can forget data, we must have finished writing it first.
     Usually, this happens long after data has already been flushed, so
     this should be a no-op for practical purposes. */

  wb_flush_seq( ur, seq );

  ur->base->seq_past = seq;
}

/* fd_vinyl_io_ur_rewind "undoes" recent writes, allowing the user to
   overwrite a bstream range. */

void
fd_vinyl_io_ur_rewind( fd_vinyl_io_t * io,
                       ulong           seq ) {
  fd_vinyl_io_ur_t * ur = (fd_vinyl_io_ur_t *)io; /* Note: io must be non-NULL to have even been called */

  /* Validate input argments.  Unlike forgot, we do allow rewinding to
     before seq_ancient as the region of sequence space reported to the
     caller as written is still accurate. */

  ulong seq_ancient = ur->base->seq_ancient;
  ulong seq_past    = ur->base->seq_past;
  ulong seq_cache   = ur->      seq_cache;
  ulong seq_clean   = ur->      seq_clean;
  ulong seq_write   = ur->      seq_write;
  ulong seq_present = ur->base->seq_present;
  ulong seq_future  = ur->base->seq_future;

  int bad_seq    = !fd_ulong_is_aligned( seq, FD_VINYL_BSTREAM_BLOCK_SZ );
  int bad_past   = fd_vinyl_seq_lt( seq, seq_past    );
  int bad_dir    = fd_vinyl_seq_gt( seq, seq_present );
  int bad_read   = !!ur->rq_head || !!ur->rc_head;
  int bad_append = fd_vinyl_seq_ne( seq_present, seq_future );

  if( FD_UNLIKELY( bad_seq | bad_past | bad_dir | bad_read | bad_append ) )
    FD_LOG_CRIT(( "rewind to seq %016lx failed (present %016lx, %s)", seq, seq_present,
                  bad_seq  ? "misaligned seq"             :
                  bad_past ? "seq before seq_past"        :
                  bad_dir  ? "seq after seq_present"      :
                  bad_read ? "reads in progress"          :
                             "appends/copies in progress" ));

  /* Need to awkwardly unwind the write pipeline.  At this instant,
     there might be inflight writes for the range that is being
     rewinded.  So, we start at the right and walk to the left until we
     reach seq: unwind allocs, unwind uncommitted data, unwind dirty
     cache, unwind inflight writes, unwind clean cache, and finally free
     up log file space.

     See top of this file for a description of the various regions. */

  if( fd_vinyl_seq_lt( seq, seq_write ) ) {
    wb_ring_trim( &ur->wb, seq_write ); /* unwind "used", "future", "wait" */
    wb_flush_seq( ur,      seq_write ); /* wait for I/O completion (moves "write" to "clean") */
  }
  wb_ring_trim( &ur->wb, seq ); /* unwind rest */

  ur->base->seq_ancient = fd_ulong_if( fd_vinyl_seq_ge( seq, seq_ancient ), seq_ancient, seq );
  ur->base->seq_past    = fd_ulong_if( fd_vinyl_seq_ge( seq, seq_past    ), seq_past,    seq );
  ur->      seq_cache   = fd_ulong_if( fd_vinyl_seq_ge( seq, seq_cache   ), seq_cache,   seq );
  ur->      seq_clean   = fd_ulong_if( fd_vinyl_seq_ge( seq, seq_clean   ), seq_clean,   seq );
  ur->      seq_write   = fd_ulong_if( fd_vinyl_seq_ge( seq, seq_write   ), seq_write,   seq );
  ur->base->seq_present = seq;
  ur->base->seq_future  = seq;
}
