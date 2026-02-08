#define _GNU_SOURCE
#include "fd_vinyl_io_ur_private.h"

#include <errno.h>
#include <linux/io_uring.h>

/* fd_vinyl_io_ur_fini is identical to fd_vinyl_io_bd_fini. */

static void *
fd_vinyl_io_ur_fini( fd_vinyl_io_t * io ) {
  fd_vinyl_io_ur_t * ur = (fd_vinyl_io_ur_t *)io; /* Note: io must be non-NULL to have even been called */

  ulong seq_present = ur->base->seq_present;
  ulong seq_future  = ur->base->seq_future;

  if( FD_UNLIKELY( ur->rq_head                                ) ) FD_LOG_WARNING(( "fini completing outstanding reads" ));
  if( FD_UNLIKELY( ur->rc_head                                ) ) FD_LOG_WARNING(( "fini completing outstanding reads" ));
  if( FD_UNLIKELY( fd_vinyl_seq_ne( seq_present, seq_future ) ) ) FD_LOG_WARNING(( "fini discarding uncommited blocks" ));

  return io;
}

static fd_vinyl_io_impl_t fd_vinyl_io_ur_impl[1] = { {
  fd_vinyl_io_ur_read_imm, /* rd */
  fd_vinyl_io_ur_read,     /* rd */
  fd_vinyl_io_ur_poll,     /* rd */
  fd_vinyl_io_ur_append,   /* wb */
  fd_vinyl_io_ur_commit,   /* wb */
  fd_vinyl_io_ur_hint,     /* wb */
  fd_vinyl_io_ur_alloc,    /* wb */
  fd_vinyl_io_ur_copy,     /* wb */
  fd_vinyl_io_ur_forget,   /* wb */
  fd_vinyl_io_ur_rewind,   /* wb */
  fd_vinyl_io_ur_sync,     /* wb */
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
fd_vinyl_io_ur_init( void *          mem,
                     ulong           spad_max,
                     int             dev_fd,
                     fd_io_uring_t * ring ) {
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
  ur->base->spad_used = 0UL; /* unused */
  ur->base->impl      = fd_vinyl_io_ur_impl;

  ur->dev_fd   = dev_fd;
  ur->dev_sync = 0UL;                            /* Use the beginning of the file for the sync block */
  ur->dev_base = FD_VINYL_BSTREAM_BLOCK_SZ;      /* Use the rest for the actual bstream store (at least 3.5 KiB) */
  ur->dev_sz   = dev_sz - FD_VINYL_BSTREAM_BLOCK_SZ;

  ur->rq_head      = NULL;
  ur->rq_tail_next = &ur->rq_head;

  ur->rc_head      = NULL;
  ur->rc_tail_next = &ur->rc_head;

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
  ur->      seq_cache   = seq_present;
  ur->      seq_clean   = seq_present;
  ur->      seq_write   = seq_present;

  wb_ring_init( &ur->wb, seq_present, spad_max );
  wq_ring_init( &ur->wq, seq_present, WQ_DEPTH );

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
                ring->sq->depth ));

  return ur->base;
}
