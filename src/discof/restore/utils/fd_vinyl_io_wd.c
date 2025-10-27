#include "fd_vinyl_io_wd.h"

#include <errno.h>
#include <unistd.h>

static inline void
wd_write( int          fd,
          ulong        off,
          void const * buf,
          ulong        sz ) {
  ssize_t ssz = pwrite( fd, buf, sz, (off_t)off );
  if( FD_LIKELY( ssz==(ssize_t)sz ) ) return;
  if( ssz<(ssize_t)0 ) FD_LOG_CRIT(( "pwrite(fd %i,off %lu,sz %lu) failed (%i-%s)", fd, off, sz, errno, fd_io_strerror( errno ) ));
  else                 FD_LOG_CRIT(( "pwrite(fd %i,off %lu,sz %lu) failed (unexpected sz %li)", fd, off, sz, (long)ssz ));
}

struct fd_vinyl_io_wd {
  fd_vinyl_io_t            base[1];
  int                      dev_fd;       /* File descriptor of block device */
  ulong                    dev_sync;     /* Offset to block that holds bstream sync (BLOCK_SZ multiple) */
  ulong                    dev_base;     /* Offset to first block (BLOCK_SZ multiple) */
  ulong                    dev_sz;       /* Block store byte size (BLOCK_SZ multiple) */
  fd_vinyl_bstream_block_t sync[1];
  /* spad_max bytes follow */
};

typedef struct fd_vinyl_io_wd fd_vinyl_io_wd_t;

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

static ulong
fd_vinyl_io_wd_append( fd_vinyl_io_t * io,
                       void const *    _src,
                       ulong           sz ) {
  fd_vinyl_io_wd_t * wd  = (fd_vinyl_io_wd_t *)io; /* Note: io must be non-NULL to have even been called */
  uchar const *      src = (uchar const *)_src;

  uchar const * spad_lo = (uchar const *)(wd+1);
  uchar const * spad_hi = spad_lo + wd->base->spad_max;
  FD_CRIT( src>=spad_lo && (src+sz)<=spad_hi, "fd_vinyl_io_wd_append can only write blocks gained via alloc" );

  /* Validate the input args. */

  ulong seq_future  = wd->base->seq_future;  if( FD_UNLIKELY( !sz ) ) return seq_future;
  ulong seq_ancient = wd->base->seq_ancient;
  ulong dev_sz      = wd->dev_sz;

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
  wd->base->seq_future = seq + sz;

  return seq;
}

static int
fd_vinyl_io_wd_commit( fd_vinyl_io_t * io,
                       int             flags ) {
  fd_vinyl_io_wd_t * wd = (fd_vinyl_io_wd_t *)io; /* Note: io must be non-NULL to have even been called */
  (void)flags;

  uchar const * src = (uchar *)(wd+1);
  ulong         sz  = wd->base->spad_used;

  /* Validate state */

  ulong seq_present = wd->base->seq_present;
  ulong seq_future  = wd->base->seq_future;
  int   dev_fd      = wd->dev_fd;
  ulong dev_base    = wd->dev_base;
  ulong dev_sz      = wd->dev_sz;

  int bad_sz = !fd_ulong_is_aligned( sz, FD_VINYL_BSTREAM_BLOCK_SZ );

  if( FD_UNLIKELY( bad_sz ) )
    FD_LOG_CRIT(( "misaligned sz" ));

  /* At this point, we appear to have a valid append request.  Map it to
     the bstream (updating seq_present) and map it to the device.  Then
     write the lesser of sz bytes or until the store end.  If we hit the
     store end with more to go, wrap around and finish the write at the
     store start. */

  ulong seq = seq_present;
  wd->base->seq_present = seq + sz;
  FD_CRIT( wd->base->seq_present==seq_future, "inconsistent seq_present and seq_future" );

  ulong dev_off = seq % dev_sz;

  ulong wsz = fd_ulong_min( sz, dev_sz - dev_off );
  wd_write( dev_fd, dev_base + dev_off, src, wsz );
  sz -= wsz;
  if( sz ) wd_write( dev_fd, dev_base, src + wsz, sz );

  wd->base->spad_used = 0UL;

  return FD_VINYL_SUCCESS;
}

static ulong
fd_vinyl_io_wd_hint( fd_vinyl_io_t * io,
                     ulong           sz ) {
  (void)io; (void)sz;
  FD_LOG_CRIT(( "vinyl_io_wd does not support hint" ));
}

static void *
fd_vinyl_io_wd_alloc( fd_vinyl_io_t * io,
                      ulong           sz,
                      int             flags ) {
  fd_vinyl_io_wd_t * wd = (fd_vinyl_io_wd_t *)io; /* Note: io must be non-NULL to have even been called */

  ulong spad_max  = wd->base->spad_max;
  ulong spad_used = wd->base->spad_used; if( FD_UNLIKELY( !sz ) ) return ((uchar *)(wd+1)) + spad_used;

  int bad_align = !fd_ulong_is_aligned( sz, FD_VINYL_BSTREAM_BLOCK_SZ );
  int bad_sz    = sz > spad_max;

  if( FD_UNLIKELY( bad_align | bad_sz ) ) FD_LOG_CRIT(( bad_align ? "misaligned sz" : "sz too large" ));

  if( FD_UNLIKELY( sz > (spad_max - spad_used ) ) ) {
    if( FD_UNLIKELY( fd_vinyl_io_wd_commit( io, flags ) ) ) return NULL;
    spad_used = 0UL;
  }

  wd->base->spad_used = spad_used + sz;

  return ((uchar *)(wd+1)) + spad_used;
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
  fd_vinyl_io_wd_t * wd = (fd_vinyl_io_wd_t *)io; /* Note: io must be non-NULL to have even been called */
  (void)flags;

  ulong seed        = wd->base->seed;
  ulong seq_past    = wd->base->seq_past;
  ulong seq_present = wd->base->seq_present;

  int   dev_fd       = wd->dev_fd;
  ulong dev_sync     = wd->dev_sync;

  fd_vinyl_bstream_block_t * block = wd->sync;

  /* block->sync.ctl     current (static) */
  block->sync.seq_past    = seq_past;
  block->sync.seq_present = seq_present;
  /* block->sync.info_sz current (static) */
  /* block->sync.info    current (static) */

  block->sync.hash_trail  = 0UL;
  block->sync.hash_blocks = 0UL;
  fd_vinyl_bstream_block_hash( seed, block ); /* sets hash_trail back to seed */

  wd_write( dev_fd, dev_sync, block, FD_VINYL_BSTREAM_BLOCK_SZ );

  wd->base->seq_ancient = seq_past;

  return FD_VINYL_SUCCESS;
}

static void *
fd_vinyl_io_wd_fini( fd_vinyl_io_t * io ) {
  fd_vinyl_io_wd_t * wd = (fd_vinyl_io_wd_t *)io; /* Note: io must be non-NULL to have even been called */

  ulong seq_present = wd->base->seq_present;
  ulong seq_future  = wd->base->seq_future;

  if( FD_UNLIKELY( fd_vinyl_seq_ne( seq_present, seq_future ) ) ) FD_LOG_WARNING(( "fini discarding uncommited blocks" ));

  return io;
}

static fd_vinyl_io_impl_t fd_vinyl_io_wd_impl[1] = { {
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
} };

FD_STATIC_ASSERT( alignof(fd_vinyl_io_wd_t)==FD_VINYL_BSTREAM_BLOCK_SZ, layout );

ulong
fd_vinyl_io_wd_align( void ) {
  return alignof(fd_vinyl_io_wd_t);
}

ulong
fd_vinyl_io_wd_footprint( ulong spad_max ) {
  if( FD_UNLIKELY( !((0UL<spad_max) & (spad_max<(1UL<<63)) & fd_ulong_is_aligned( spad_max, FD_VINYL_BSTREAM_BLOCK_SZ )) ) )
    return 0UL;
  return sizeof(fd_vinyl_io_wd_t) + spad_max;
}

fd_vinyl_io_t *
fd_vinyl_io_wd_init( void *       mem,
                     ulong        spad_max,
                     int          dev_fd,
                     void const * info,
                     ulong        info_sz,
                     ulong        io_seed ) {
  /* Mostly copied from fd_vinyl_io_bd.c */

  fd_vinyl_io_wd_t * wd = (fd_vinyl_io_wd_t *)mem;

  if( FD_UNLIKELY( !wd ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)wd, fd_vinyl_io_wd_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_vinyl_io_wd_footprint( spad_max );
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

  if( FD_UNLIKELY( !info ) ) info_sz = 0UL;
  if( FD_UNLIKELY( info_sz>FD_VINYL_BSTREAM_SYNC_INFO_MAX ) ) {
    FD_LOG_WARNING(( "info_sz too large (%lu bytes)", info_sz ));
    return NULL;
  }

  memset( wd, 0, footprint );

  wd->base->type = FD_VINYL_IO_TYPE_BD;

  /* io_seed, seq_ancient, seq_past, seq_present, seq_future are init
     below */

  wd->base->spad_max  = spad_max;
  wd->base->spad_used = 0UL;
  wd->base->impl      = fd_vinyl_io_wd_impl;

  wd->dev_fd   = dev_fd;
  wd->dev_sync = 0UL;                            /* Use the beginning of the file for the sync block */
  wd->dev_base = FD_VINYL_BSTREAM_BLOCK_SZ;      /* Use the rest for the actual bstream store (at least 3.5 KiB) */
  wd->dev_sz   = dev_sz - FD_VINYL_BSTREAM_BLOCK_SZ;

  /* Note that [seq_ancient,seq_future) (cyclic) contains at most dev_sz
     bytes, bstream's antiquity, past and present are subsets of this
     range and dev_sz is less than 2^63 given the above (practically
     much much less).  As such, differences between two ordered bstream
     sequence numbers (e.g. ulong sz = seq_a - seq_b where a is
     logically not before b) will "just work" regardless of wrapping
     and/or amount of data stored. */

  /* FIXME: Consider having the sync block on a completely separate
     device (to reduce seeking when syncing). */

  fd_vinyl_bstream_block_t * block = wd->sync;

  /* We are starting a new bstream.  Write the initial sync block. */

  wd->base->seed        = io_seed;
  wd->base->seq_ancient = 0UL;
  wd->base->seq_past    = 0UL;
  wd->base->seq_present = 0UL;
  wd->base->seq_future  = 0UL;

  memset( block, 0, FD_VINYL_BSTREAM_BLOCK_SZ ); /* bulk zero */

  block->sync.ctl         = fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_SYNC, 0, FD_VINYL_VAL_MAX );
//block->sync.seq_past    = ...; /* init by sync */
//block->sync.seq_present = ...; /* init by sync */
  block->sync.info_sz     = info_sz;
  if( info_sz ) memcpy( block->sync.info, info, info_sz );
//block->sync.hash_trail  = ...; /* init by sync */
//block->sync.hash_blocks = ...; /* init by sync */

  int err = fd_vinyl_io_wd_sync( wd->base, FD_VINYL_IO_FLAG_BLOCKING ); /* logs details */
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "sync block write failed (%i-%s)", err, fd_vinyl_strerror( err ) ));
    return NULL;
  }

  FD_LOG_NOTICE(( "IO config"
                  "\n\ttype     wd"
                  "\n\tspad_max %lu bytes"
                  "\n\tdev_sz   %lu bytes"
                  "\n\treset    1"
                  "\n\tinfo     \"%s\" (info_sz %lu)"
                  "\n\tio_seed  0x%016lx",
                  spad_max, dev_sz,
                  info ? (char const *)info : "", info_sz,
                  io_seed ));

  return wd->base;
}
