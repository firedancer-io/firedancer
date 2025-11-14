#include "fd_vinyl_io.h"

struct fd_vinyl_io_mm_rd;
typedef struct fd_vinyl_io_mm_rd fd_vinyl_io_mm_rd_t;

struct fd_vinyl_io_mm_rd {
  ulong                 ctx;  /* Must mirror fd_vinyl_io_rd_t */
  ulong                 seq;  /* " */
  void *                dst;  /* " */
  ulong                 sz;   /* " */
  fd_vinyl_io_mm_rd_t * next; /* Next element in mm rd queue */
};

struct fd_vinyl_io_mm {
  fd_vinyl_io_t            base[1];
  uchar *                  dev;          /* Memory mapped I/O memory region */
  ulong                    dev_sync;     /* Offset to the bstream's sync block (BLOCK_SZ multiple) */
  ulong                    dev_base;     /* Offset to first block (BLOCK_SZ multiple) */
  ulong                    dev_sz;       /* Block store byte size (BLOCK_SZ multiple) */
  fd_vinyl_io_mm_rd_t *    rd_head;      /* Pointer to queue head */
  fd_vinyl_io_mm_rd_t **   rd_tail_next; /* Pointer to queue &tail->next or &rd_head if empty. */
  fd_vinyl_bstream_block_t sync[1];
  /* spad_max bytes follow */
};

typedef struct fd_vinyl_io_mm fd_vinyl_io_mm_t;

static void
fd_vinyl_io_mm_read_imm( fd_vinyl_io_t * io,
                         ulong           seq0,
                         void *          _dst,
                         ulong           sz ) {
  fd_vinyl_io_mm_t * mm = (fd_vinyl_io_mm_t *)io;  /* Note: io must be non-NULL to have even been called */

  /* If this is a request to read nothing, succeed immediately.  If
     this is a request to read outside the bstream's past, fail. */

  if( FD_UNLIKELY( !sz ) ) return;

  uchar * dst  = (uchar *)_dst;
  ulong   seq1 = seq0 + sz;

  ulong seq_past    = mm->base->seq_past;
  ulong seq_present = mm->base->seq_present;

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

  uchar * dev      = mm->dev;
  ulong   dev_base = mm->dev_base;
  ulong   dev_sz   = mm->dev_sz;

  ulong dev_off = seq0 % dev_sz;

  ulong rsz = fd_ulong_min( sz, dev_sz - dev_off );
  memcpy( dst, dev + dev_base + dev_off, rsz );
  sz -= rsz;
  if( FD_UNLIKELY( sz ) ) memcpy( dst + rsz, dev + dev_base, sz );
}

static void
fd_vinyl_io_mm_read( fd_vinyl_io_t *    io,
                     fd_vinyl_io_rd_t * _rd ) {
  fd_vinyl_io_mm_t *    mm = (fd_vinyl_io_mm_t *)   io;  /* Note: io must be non-NULL to have even been called */
  fd_vinyl_io_mm_rd_t * rd = (fd_vinyl_io_mm_rd_t *)_rd;

  rd->next          = NULL;
  *mm->rd_tail_next = rd;
  mm->rd_tail_next  = &rd->next;

  ulong   seq0 =          rd->seq;
  uchar * dst  = (uchar *)rd->dst;
  ulong   sz   =          rd->sz;

  /* If this is a request to read nothing, succeed immediately.  If
     this is a request to read outside the bstream's past, fail. */

  if( FD_UNLIKELY( !sz ) ) return;

  ulong seq1 = seq0 + sz;

  ulong seq_past    = mm->base->seq_past;
  ulong seq_present = mm->base->seq_present;

  int bad_seq  = !fd_ulong_is_aligned( seq0, FD_VINYL_BSTREAM_BLOCK_SZ );
  int bad_dst  = (!fd_ulong_is_aligned( (ulong)dst, FD_VINYL_BSTREAM_BLOCK_SZ )) | !dst;
  int bad_sz   = !fd_ulong_is_aligned( sz,   FD_VINYL_BSTREAM_BLOCK_SZ );
  int bad_past = !(fd_vinyl_seq_le( seq_past, seq0 ) & fd_vinyl_seq_lt( seq0, seq1 ) & fd_vinyl_seq_le( seq1, seq_present ));

  if( FD_UNLIKELY( bad_seq | bad_dst | bad_sz | bad_past ) )
    FD_LOG_CRIT(( "bstream read [%016lx,%016lx)/%lu failed (past [%016lx,%016lx)/%lu, %s)",
                  seq0, seq1, sz, seq_past, seq_present, seq_present-seq_past,
                  bad_seq ? "misaligned seq"         :
                  bad_dst ? "misaligned or NULL dst" :
                  bad_sz  ? "misaligned sz"          :
                            "not in past" ));

  /* At this point, we have a valid read request.  Map seq0 into the
     bstream store.  Read the lesser of sz bytes or until the store end.
     If we hit the store end with more to go, wrap around and finish the
     read at the store start. */

  uchar const * dev      = mm->dev;
  ulong         dev_base = mm->dev_base;
  ulong         dev_sz   = mm->dev_sz;

  ulong dev_off = seq0 % dev_sz;

  ulong rsz = fd_ulong_min( sz, dev_sz - dev_off );
  memcpy( dst, dev + dev_base + dev_off, rsz );
  sz -= rsz;
  if( FD_UNLIKELY( sz ) ) memcpy( dst + rsz, dev + dev_base, sz );
}

static int
fd_vinyl_io_mm_poll( fd_vinyl_io_t *     io,
                     fd_vinyl_io_rd_t ** _rd,
                     int                 flags ) {
  fd_vinyl_io_mm_t * mm = (fd_vinyl_io_mm_t * )io; /* Note: io must be non-NULL to have even been called */
  (void)flags;

  fd_vinyl_io_mm_rd_t *  rd = mm->rd_head;

  if( FD_UNLIKELY( !rd ) ) {
    *_rd = NULL;
    return FD_VINYL_ERR_EMPTY;
  }

  fd_vinyl_io_mm_rd_t ** rd_tail_next = mm->rd_tail_next;
  fd_vinyl_io_mm_rd_t *  rd_next      = rd->next;

  mm->rd_head      = rd_next;
  mm->rd_tail_next = fd_ptr_if( !!rd_next, rd_tail_next, &mm->rd_head );

  *_rd = (fd_vinyl_io_rd_t *)rd;
  return FD_VINYL_SUCCESS;
}

static ulong
fd_vinyl_io_mm_append( fd_vinyl_io_t * io,
                       void const *    _src,
                       ulong           sz ) {
  fd_vinyl_io_mm_t * mm  = (fd_vinyl_io_mm_t *)io; /* Note: io must be non-NULL to have even been called */
  uchar const *      src = (uchar const *)_src;

  /* Validate the input args. */

  ulong   seq_future  = mm->base->seq_future;  if( FD_UNLIKELY( !sz ) ) return seq_future;
  ulong   seq_ancient = mm->base->seq_ancient;
  uchar * dev         = mm->dev;
  ulong   dev_base    = mm->dev_base;
  ulong   dev_sz      = mm->dev_sz;

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
  mm->base->seq_future = seq + sz;

  ulong dev_off = seq % dev_sz;

  ulong wsz = fd_ulong_min( sz, dev_sz - dev_off );
  memcpy( dev + dev_base + dev_off, src, wsz );
  sz -= wsz;
  if( sz ) memcpy( dev + dev_base, src + wsz, sz );

  return seq;
}

static int
fd_vinyl_io_mm_commit( fd_vinyl_io_t * io,
                       int             flags ) {
  fd_vinyl_io_mm_t * mm = (fd_vinyl_io_mm_t *)io; /* Note: io must be non-NULL to have even been called */
  (void)flags;

  mm->base->seq_present = mm->base->seq_future;
  mm->base->spad_used   = 0UL;

  return FD_VINYL_SUCCESS;
}

static ulong
fd_vinyl_io_mm_hint( fd_vinyl_io_t * io,
                     ulong           sz ) {
  fd_vinyl_io_mm_t * mm = (fd_vinyl_io_mm_t *)io; /* Note: io must be non-NULL to have even been called */

  ulong seq_future  = mm->base->seq_future;  if( FD_UNLIKELY( !sz ) ) return seq_future;
  ulong seq_ancient = mm->base->seq_ancient;
  ulong dev_sz      = mm->dev_sz;

  int bad_sz       = !fd_ulong_is_aligned( sz, FD_VINYL_BSTREAM_BLOCK_SZ );
  int bad_capacity = sz > (dev_sz - (seq_future-seq_ancient));

  if( FD_UNLIKELY( bad_sz | bad_capacity ) ) FD_LOG_CRIT(( bad_sz ? "misaligned sz" : "device full" ));

  return mm->base->seq_future;
}

static void *
fd_vinyl_io_mm_alloc( fd_vinyl_io_t * io,
                      ulong           sz,
                      int             flags ) {
  fd_vinyl_io_mm_t * mm = (fd_vinyl_io_mm_t *)io; /* Note: io must be non-NULL to have even been called */

  ulong spad_max  = mm->base->spad_max;
  ulong spad_used = mm->base->spad_used; if( FD_UNLIKELY( !sz ) ) return ((uchar *)(mm+1)) + spad_used;

  int bad_align = !fd_ulong_is_aligned( sz, FD_VINYL_BSTREAM_BLOCK_SZ );
  int bad_sz    = sz > spad_max;

  if( FD_UNLIKELY( bad_align | bad_sz ) ) FD_LOG_CRIT(( bad_align ? "misaligned sz" : "sz too large" ));

  if( FD_UNLIKELY( sz > (spad_max - spad_used ) ) ) {
    if( FD_UNLIKELY( fd_vinyl_io_mm_commit( io, flags ) ) ) return NULL;
    spad_used = 0UL;
  }

  mm->base->spad_used = spad_used + sz;

  return ((uchar *)(mm+1)) + spad_used;
}

static ulong
fd_vinyl_io_mm_copy( fd_vinyl_io_t * io,
                     ulong           seq_src0,
                     ulong           sz ) {
  fd_vinyl_io_mm_t * mm = (fd_vinyl_io_mm_t *)io; /* Note: io must be non-NULL to have even been called */

  /* Validate the input args */

  ulong   seq_ancient = mm->base->seq_ancient;
  ulong   seq_past    = mm->base->seq_past;
  ulong   seq_present = mm->base->seq_present;
  ulong   seq_future  = mm->base->seq_future;   if( FD_UNLIKELY( !sz ) ) return seq_future;
  ulong   spad_max    = mm->base->spad_max;
  ulong   spad_used   = mm->base->spad_used;
  uchar * dev         = mm->dev;
  ulong   dev_base    = mm->dev_base;
  ulong   dev_sz      = mm->dev_sz;

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
    fd_vinyl_io_mm_commit( io, FD_VINYL_IO_FLAG_BLOCKING );
    spad_used = 0UL;
  }

  uchar * buf     = (uchar *)(mm+1) + spad_used;
  ulong   buf_max = spad_max - spad_used;

  /* Map the dst to the bstream (updating seq_future) and map the src
     and dst regions onto the device.  Then copy as much as we can at a
     time, handling device wrap around and copy buffering space. */

  ulong seq = seq_future;
  mm->base->seq_future = seq + sz;

  ulong seq_dst0 = seq;

  for(;;) {
    ulong src_off = seq_src0 % dev_sz;
    ulong dst_off = seq_dst0 % dev_sz;
    ulong csz     = fd_ulong_min( fd_ulong_min( sz, buf_max ), fd_ulong_min( dev_sz - src_off, dev_sz - dst_off ) );

    memcpy( buf, dev + dev_base + src_off, csz );
    memcpy( dev + dev_base + dst_off, buf, csz );

    sz -= csz;
    if( !sz ) break;

    seq_src0 += csz;
    seq_dst0 += csz;
  }

  return seq;
}

static void
fd_vinyl_io_mm_forget( fd_vinyl_io_t * io,
                       ulong           seq ) {
  fd_vinyl_io_mm_t * mm = (fd_vinyl_io_mm_t *)io; /* Note: io must be non-NULL to have even been called */

  /* Validate input arguments.  Note that we don't allow forgetting into
     the future even when we have no uncommitted blocks because the
     resulting [seq_ancient,seq_future) might contain blocks that were
     never written (which might not be an issue practically but it would
     be a bit strange for something to try to scan starting from
     seq_ancient and discover unwritten blocks). */

  ulong seq_past    = mm->base->seq_past;
  ulong seq_present = mm->base->seq_present;
  ulong seq_future  = mm->base->seq_future;

  int bad_seq    = !fd_ulong_is_aligned( seq, FD_VINYL_BSTREAM_BLOCK_SZ );
  int bad_dir    = !(fd_vinyl_seq_le( seq_past, seq ) & fd_vinyl_seq_le( seq, seq_present ));
  int bad_read   = !!mm->rd_head;
  int bad_append = fd_vinyl_seq_ne( seq_present, seq_future );

  if( FD_UNLIKELY( bad_seq | bad_dir | bad_read | bad_append ) )
    FD_LOG_CRIT(( "forget to seq %016lx failed (past [%016lx,%016lx)/%lu, %s)",
                  seq, seq_past, seq_present, seq_present-seq_past,
                  bad_seq  ? "misaligned seq"             :
                  bad_dir  ? "seq out of bounds"          :
                  bad_read ? "reads in progress"          :
                             "appends/copies in progress" ));

  mm->base->seq_past = seq;
}

static void
fd_vinyl_io_mm_rewind( fd_vinyl_io_t * io,
                       ulong           seq ) {
  fd_vinyl_io_mm_t * mm = (fd_vinyl_io_mm_t *)io; /* Note: io must be non-NULL to have even been called */

  /* Validate input argments.  Unlike forgot, we do allow rewinding to
     before seq_ancient as the region of sequence space reported to the
     caller as written is still accurate. */

  ulong seq_ancient = mm->base->seq_ancient;
  ulong seq_past    = mm->base->seq_past;
  ulong seq_present = mm->base->seq_present;
  ulong seq_future  = mm->base->seq_future;

  int bad_seq    = !fd_ulong_is_aligned( seq, FD_VINYL_BSTREAM_BLOCK_SZ );
  int bad_dir    = fd_vinyl_seq_gt( seq, seq_present );
  int bad_read   = !!mm->rd_head;
  int bad_append = fd_vinyl_seq_ne( seq_present, seq_future );

  if( FD_UNLIKELY( bad_seq | bad_dir | bad_read | bad_append ) )
    FD_LOG_CRIT(( "rewind to seq %016lx failed (present %016lx, %s)", seq, seq_present,
                  bad_seq  ? "misaligned seq"             :
                  bad_dir  ? "seq after seq_present"      :
                  bad_read ? "reads in progress"          :
                             "appends/copies in progress" ));

  mm->base->seq_ancient = fd_ulong_if( fd_vinyl_seq_ge( seq, seq_ancient ), seq_ancient, seq );
  mm->base->seq_past    = fd_ulong_if( fd_vinyl_seq_ge( seq, seq_past    ), seq_past,    seq );
  mm->base->seq_present = seq;
  mm->base->seq_future  = seq;
}

static int
fd_vinyl_io_mm_sync( fd_vinyl_io_t * io,
                     int             flags ) {
  fd_vinyl_io_mm_t * mm = (fd_vinyl_io_mm_t *)io; /* Note: io must be non-NULL to have even been called */
  (void)flags;

  ulong   seed        = mm->base->seed;
  ulong   seq_past    = mm->base->seq_past;
  ulong   seq_present = mm->base->seq_present;
  uchar * dev         = mm->dev;
  ulong   dev_sync    = mm->dev_sync;

  fd_vinyl_bstream_block_t * block = mm->sync;

  /* block->sync.ctl     current (static) */
  block->sync.seq_past    = seq_past;
  block->sync.seq_present = seq_present;
  /* block->sync.info_sz current (static) */
  /* block->sync.info    current (static) */

  block->sync.hash_trail  = 0UL;
  block->sync.hash_blocks = 0UL;
  fd_vinyl_bstream_block_hash( seed, block ); /* sets hash_trail back to seed */

  memcpy( dev + dev_sync, block, FD_VINYL_BSTREAM_BLOCK_SZ );

  mm->base->seq_ancient = seq_past;

  return FD_VINYL_SUCCESS;
}

static void *
fd_vinyl_io_mm_fini( fd_vinyl_io_t * io ) {
  fd_vinyl_io_mm_t * mm = (fd_vinyl_io_mm_t *)io; /* Note: io must be non-NULL to have even been called */

  ulong seq_present = mm->base->seq_present;
  ulong seq_future  = mm->base->seq_future;

  if( FD_UNLIKELY( mm->rd_head                                ) ) FD_LOG_WARNING(( "fini completing outstanding reads" ));
  if( FD_UNLIKELY( fd_vinyl_seq_ne( seq_present, seq_future ) ) ) FD_LOG_WARNING(( "fini discarding uncommited blocks" ));

  return io;
}

static fd_vinyl_io_impl_t fd_vinyl_io_mm_impl[1] = { {
  fd_vinyl_io_mm_read_imm,
  fd_vinyl_io_mm_read,
  fd_vinyl_io_mm_poll,
  fd_vinyl_io_mm_append,
  fd_vinyl_io_mm_commit,
  fd_vinyl_io_mm_hint,
  fd_vinyl_io_mm_alloc,
  fd_vinyl_io_mm_copy,
  fd_vinyl_io_mm_forget,
  fd_vinyl_io_mm_rewind,
  fd_vinyl_io_mm_sync,
  fd_vinyl_io_mm_fini
} };

FD_STATIC_ASSERT( alignof(fd_vinyl_io_mm_t)==FD_VINYL_BSTREAM_BLOCK_SZ, layout );

ulong
fd_vinyl_io_mm_align( void ) {
  return alignof(fd_vinyl_io_mm_t);
}

ulong
fd_vinyl_io_mm_footprint( ulong spad_max ) {
  if( FD_UNLIKELY( !((0UL<spad_max) & (spad_max<(1UL<<63)) & fd_ulong_is_aligned( spad_max, FD_VINYL_BSTREAM_BLOCK_SZ )) ) )
    return 0UL;
  return sizeof(fd_vinyl_io_mm_t) + spad_max;
}

fd_vinyl_io_t *
fd_vinyl_io_mm_init( void *       mem,
                     ulong        spad_max,
                     void *       dev,
                     ulong        dev_sz,
                     int          reset,
                     void const * info,
                     ulong        info_sz,
                     ulong        io_seed ) {
  fd_vinyl_io_mm_t * mm = (fd_vinyl_io_mm_t *)mem;

  if( FD_UNLIKELY( !mm ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mm, fd_vinyl_io_mm_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_vinyl_io_mm_footprint( spad_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad spad_max" ));
    return NULL;
  }

  if( FD_UNLIKELY( !dev ) ) {
    FD_LOG_WARNING(( "NULL dev" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)dev, FD_VINYL_BSTREAM_BLOCK_SZ ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

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

  if( reset ) {
    if( FD_UNLIKELY( !info ) ) info_sz = 0UL;
    if( FD_UNLIKELY( info_sz>FD_VINYL_BSTREAM_SYNC_INFO_MAX ) ) {
      FD_LOG_WARNING(( "info_sz too large" ));
      return NULL;
    }
  }

  memset( mm, 0, footprint );

  mm->base->type = FD_VINYL_IO_TYPE_MM;

  /* io_seed, seq_ancient, seq_past, seq_present, seq_future are init
     below */

  mm->base->spad_max  = spad_max;
  mm->base->spad_used = 0UL;
  mm->base->impl      = fd_vinyl_io_mm_impl;

  mm->dev      = dev;
  mm->dev_sync = 0UL;                            /* Use the beginning of the file for the sync block */
  mm->dev_base = FD_VINYL_BSTREAM_BLOCK_SZ;      /* Use the rest for the actual bstream store (at least 4) */
  mm->dev_sz   = dev_sz - FD_VINYL_BSTREAM_BLOCK_SZ;

  mm->rd_head      = NULL;
  mm->rd_tail_next = &mm->rd_head;

  /* Note that [seq_ancient,seq_future) (cyclic) contains at most dev_sz
     bytes, bstream's antiquity, past and present are subsets of this
     range and dev_sz is less than 2^63 given the above (practically
     much much less).  As such, differences between two ordered bstream
     sequence numbers (e.g. ulong sz = seq_a - seq_b where a is
     logically not before b) will "just work" regardless of wrapping
     and/or amount of data stored. */

  fd_vinyl_bstream_block_t * block = mm->sync;

  if( reset ) {

    /* We are starting a new bstream.  Write the initial sync block. */

    mm->base->seed        = io_seed;
    mm->base->seq_ancient = 0UL;
    mm->base->seq_past    = 0UL;
    mm->base->seq_present = 0UL;
    mm->base->seq_future  = 0UL;

    memset( block, 0, FD_VINYL_BSTREAM_BLOCK_SZ ); /* bulk zero */

    block->sync.ctl         = fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_SYNC, 0, FD_VINYL_VAL_MAX );
  //block->sync.seq_past    = ...; /* init by sync */
  //block->sync.seq_present = ...; /* init by sync */
    block->sync.info_sz     = info_sz;
    if( info_sz ) memcpy( block->sync.info, info, info_sz );
  //block->sync.hash_trail  = ...; /* init by sync */
  //block->sync.hash_blocks = ...; /* init by sync */

    int err = fd_vinyl_io_mm_sync( mm->base, FD_VINYL_IO_FLAG_BLOCKING ); /* logs details */
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "sync block write failed (%i-%s)", err, fd_vinyl_strerror( err ) ));
      return NULL;
    }

  } else {

    /* We are resuming an existing bstream.  Read and validate the
       bstream's sync block. */

    memcpy( block, mm->dev + mm->dev_sync, FD_VINYL_BSTREAM_BLOCK_SZ ); /* logs details */

    int   type        = fd_vinyl_bstream_ctl_type ( block->sync.ctl );
    int   version     = fd_vinyl_bstream_ctl_style( block->sync.ctl );
    ulong val_max     = fd_vinyl_bstream_ctl_sz   ( block->sync.ctl );
    ulong seq_past    = block->sync.seq_past;
    ulong seq_present = block->sync.seq_present;
    /**/  info_sz     = block->sync.info_sz;    // overrides user info_sz
    /**/  info        = block->sync.info;       // overrides user info
    /**/  io_seed     = block->sync.hash_trail; // overrides user io_seed

    int bad_type        = (type != FD_VINYL_BSTREAM_CTL_TYPE_SYNC);
    int bad_version     = (version != 0);
    int bad_val_max     = (val_max != FD_VINYL_VAL_MAX);
    int bad_seq_past    = !fd_ulong_is_aligned( seq_past,    FD_VINYL_BSTREAM_BLOCK_SZ );
    int bad_seq_present = !fd_ulong_is_aligned( seq_present, FD_VINYL_BSTREAM_BLOCK_SZ );
    int bad_info_sz     = (info_sz > FD_VINYL_BSTREAM_SYNC_INFO_MAX);
    int bad_past_order  = fd_vinyl_seq_gt( seq_past, seq_present );
    int bad_past_sz     = ((seq_present-seq_past) > mm->dev_sz);

    if( FD_UNLIKELY( bad_type | bad_version | bad_val_max | bad_seq_past | bad_seq_present | bad_info_sz |
                     bad_past_order | bad_past_sz ) ) {
      FD_LOG_WARNING(( "bad sync block when recovering (%s)",
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
      FD_LOG_WARNING(( "corrupt sync block when recovering bstream store" ));
      return NULL;
    }

    mm->base->seed        = io_seed;
    mm->base->seq_ancient = seq_past;
    mm->base->seq_past    = seq_past;
    mm->base->seq_present = seq_present;
    mm->base->seq_future  = seq_present;

  }

  FD_LOG_NOTICE(( "IO config"
                  "\n\ttype     mm"
                  "\n\tspad_max %lu bytes"
                  "\n\tdev_sz   %lu bytes"
                  "\n\treset    %i"
                  "\n\tinfo     \"%s\" (info_sz %lu%s)"
                  "\n\tio_seed  0x%016lx%s",
                  spad_max, dev_sz, reset,
                  info ? (char const *)info : "", info_sz, reset ? "" : ", discovered",
                  io_seed, reset ? "" : " (discovered)" ));

  return mm->base;
}

void *
fd_vinyl_mmio( fd_vinyl_io_t * io ) {
  if( FD_UNLIKELY( io->type!=FD_VINYL_IO_TYPE_MM ) ) return NULL;
  fd_vinyl_io_mm_t * mm = (fd_vinyl_io_mm_t *)io;
  return mm->dev + mm->dev_base;
}

ulong
fd_vinyl_mmio_sz( fd_vinyl_io_t * io ) {
  if( FD_UNLIKELY( io->type!=FD_VINYL_IO_TYPE_MM ) ) return 0UL;
  fd_vinyl_io_mm_t * mm = (fd_vinyl_io_mm_t *)io;
  return mm->dev_sz;
}
