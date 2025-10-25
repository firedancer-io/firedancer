#include "fd_vinyl_io.h"
#include <lz4.h>

/* Using a separate translation unit for fini is a little silly but
   compiler won't inline stuff with heavy operations like logging and
   we don't want to give up logging edge cases with constructors. */

void *
fd_vinyl_io_fini( fd_vinyl_io_t * io ) {
  if( !io ) {
    FD_LOG_WARNING(( "NULL io" ));
    return NULL;
  }
  return io->impl->fini( io );
}

ulong
fd_vinyl_io_spad_est( void ) {
  return 2UL*fd_vinyl_bstream_pair_sz( (ulong)LZ4_COMPRESSBOUND( (int)FD_VINYL_VAL_MAX ) );
}

ulong
fd_vinyl_io_append_pair_raw( fd_vinyl_io_t *         io,
                             fd_vinyl_key_t const *  key,
                             fd_vinyl_info_t const * info,
                             void const *            val ) {

  /* Allocate scratch to hold the formatted pair */

  ulong val_sz = (ulong)info->val_sz;
  FD_CRIT( val_sz<=FD_VINYL_VAL_MAX, "corruption detected" );

  ulong   pair_sz = fd_vinyl_bstream_pair_sz( val_sz );
  uchar * pair    = (uchar *)fd_vinyl_io_alloc( io, pair_sz, FD_VINYL_IO_FLAG_BLOCKING );

  uchar * dst     = pair;
  ulong   dst_rem = pair_sz;

  /* Gather the pair header */

  fd_vinyl_bstream_phdr_t * phdr = (fd_vinyl_bstream_phdr_t *)dst;

  phdr->ctl  = fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR, FD_VINYL_BSTREAM_CTL_STYLE_RAW, val_sz );
  phdr->key  = *key;
  phdr->info = *info;

  dst     += sizeof(fd_vinyl_bstream_phdr_t);
  dst_rem -= sizeof(fd_vinyl_bstream_phdr_t);

  /* Gather the pair value */

  if( val_sz ) memcpy( dst, val, val_sz );

  dst     += val_sz;
  dst_rem -= val_sz;

  fd_vinyl_bstream_pair_hash( fd_vinyl_io_seed( io ), (fd_vinyl_bstream_block_t *)pair );

  return fd_vinyl_io_append( io, pair, pair_sz );
}

ulong
fd_vinyl_io_append_dead( fd_vinyl_io_t *                 io,
                         fd_vinyl_bstream_phdr_t const * phdr,
                         void const *                    info,
                         ulong                           info_sz ) {

  if( !info ) info_sz = 0UL;
  FD_CRIT( info_sz<=FD_VINYL_BSTREAM_DEAD_INFO_MAX, "corruption detected" );

  fd_vinyl_bstream_block_t * block = (fd_vinyl_bstream_block_t *)
    fd_vinyl_io_alloc( io, FD_VINYL_BSTREAM_BLOCK_SZ, FD_VINYL_IO_FLAG_BLOCKING );

  memset( block, 0, FD_VINYL_BSTREAM_BLOCK_SZ ); /* bulk zero */

  block->dead.ctl     = fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_DEAD,
                                              FD_VINYL_BSTREAM_CTL_STYLE_RAW,
                                              FD_VINYL_BSTREAM_BLOCK_SZ );
  block->dead.seq     = io->seq_future;
  block->dead.phdr    = *phdr;
  block->dead.info_sz = info_sz;
  if( info_sz ) memcpy( block->dead.info, info, info_sz );

  fd_vinyl_bstream_block_hash( fd_vinyl_io_seed( io ), block );

  return fd_vinyl_io_append( io, block, FD_VINYL_BSTREAM_BLOCK_SZ );
}

ulong
fd_vinyl_io_append_move( fd_vinyl_io_t *                 io,
                         fd_vinyl_bstream_phdr_t const * src,
                         fd_vinyl_key_t const *          dst,
                         void const *                    info,
                         ulong                           info_sz ) {

  if( !info ) info_sz = 0UL;
  FD_CRIT( info_sz<=FD_VINYL_BSTREAM_MOVE_INFO_MAX, "corruption detected" );

  fd_vinyl_bstream_block_t * block = (fd_vinyl_bstream_block_t *)
    fd_vinyl_io_alloc( io, FD_VINYL_BSTREAM_BLOCK_SZ, FD_VINYL_IO_FLAG_BLOCKING );

  memset( block, 0, FD_VINYL_BSTREAM_BLOCK_SZ ); /* bulk zero */

  block->move.ctl     = fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_MOVE,
                                              FD_VINYL_BSTREAM_CTL_STYLE_RAW,
                                              FD_VINYL_BSTREAM_BLOCK_SZ );
  block->move.seq     = io->seq_future;
  block->move.src     = *src;
  block->move.dst     = *dst;
  block->move.info_sz = info_sz;
  if( info_sz ) memcpy( block->move.info, info, info_sz );

  fd_vinyl_bstream_block_hash( fd_vinyl_io_seed( io ), block );

  return fd_vinyl_io_append( io, block, FD_VINYL_BSTREAM_BLOCK_SZ );
}

ulong
fd_vinyl_io_append_part( fd_vinyl_io_t * io,
                         ulong           seq0,
                         ulong           dead_cnt,
                         ulong           move_cnt,
                         void const *    info,
                         ulong           info_sz ) {

  if( !info ) info_sz = 0UL;
  FD_CRIT( info_sz<=FD_VINYL_BSTREAM_PART_INFO_MAX, "corruption detected" );

  fd_vinyl_bstream_block_t * block = (fd_vinyl_bstream_block_t *)
    fd_vinyl_io_alloc( io, FD_VINYL_BSTREAM_BLOCK_SZ, FD_VINYL_IO_FLAG_BLOCKING );

  memset( block, 0, FD_VINYL_BSTREAM_BLOCK_SZ ); /* bulk zero */

  block->part.ctl      = fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PART,
                                               FD_VINYL_BSTREAM_CTL_STYLE_RAW,
                                               FD_VINYL_BSTREAM_BLOCK_SZ );
  block->part.seq      = io->seq_future;
  block->part.seq0     = seq0;
  block->part.dead_cnt = dead_cnt;
  block->part.move_cnt = move_cnt;
  block->part.info_sz  = info_sz;
  if( info_sz ) memcpy( block->part.info, info, info_sz );

  fd_vinyl_bstream_block_hash( fd_vinyl_io_seed( io ), block );

  return fd_vinyl_io_append( io, block, FD_VINYL_BSTREAM_BLOCK_SZ );
}

ulong
fd_vinyl_io_append_pair_inplace( fd_vinyl_io_t *           io,
                                 int                       style,
                                 fd_vinyl_bstream_phdr_t * phdr,
                                 int *                     _style,
                                 ulong *                   _val_esz ) {

  ulong val_sz = (ulong)phdr->info.val_sz;

  FD_CRIT( val_sz <= FD_VINYL_VAL_MAX, "corruption detected" );

  ulong pair_sz = fd_vinyl_bstream_pair_sz( val_sz );

  ulong phdr_ctl = phdr->ctl;

  FD_CRIT( fd_vinyl_bstream_ctl_style( phdr_ctl )==FD_VINYL_BSTREAM_CTL_STYLE_RAW, "corruption detected" );
  FD_CRIT( fd_vinyl_bstream_ctl_sz   ( phdr_ctl )==val_sz,                         "corruption detected" );

  switch( style ) {

  case FD_VINYL_BSTREAM_CTL_STYLE_RAW: break;

  case FD_VINYL_BSTREAM_CTL_STYLE_LZ4: {

    /* If the pair is already small enough, no point in compressing.
       Otherwise, allocate scratch from the io append spad for the worst
       case compressed size and compress the pair val into it.  If
       compression fails (shouldn't given use of LZ4_COMPRESSBOUND) or
       the value doesn't compress enough to make a difference in bstream
       usage, free the scratch allocation and append the uncompressed
       version. */

    if( FD_UNLIKELY( val_sz<=FD_VINYL_BSTREAM_LZ4_VAL_THRESH ) ) break;

    ulong                     cval_max  = (ulong)LZ4_COMPRESSBOUND( (int)val_sz );
    ulong                     cpair_max = fd_vinyl_bstream_pair_sz( cval_max );
    fd_vinyl_bstream_phdr_t * cphdr     = (fd_vinyl_bstream_phdr_t *)fd_vinyl_io_alloc( io, cpair_max, FD_VINYL_IO_FLAG_BLOCKING );

    ulong cval_sz  = (ulong)LZ4_compress_default( (char const *)(phdr+1), (char *)(cphdr+1), (int)val_sz, (int)cval_max );
    ulong cpair_sz = fd_vinyl_bstream_pair_sz( cval_sz );

    if( FD_UNLIKELY( (!cval_sz) | (cpair_sz>=pair_sz) ) ) {
      fd_vinyl_io_trim( io, cpair_max );
      break;
    }

    /* At this point, we usefully LZ4 compressed the pair val.  Trim
       the scratch allocation to compressed pair size, prepend the pair
       header, clear any zero padding, append the pair footer and start
       appending the compressed version to the bstream. */

    fd_vinyl_io_trim( io, cpair_max - cpair_sz );

    cphdr->ctl  = fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR, FD_VINYL_BSTREAM_CTL_STYLE_LZ4, cval_sz );
    cphdr->key  = phdr->key;
    cphdr->info = phdr->info;

    fd_vinyl_bstream_pair_hash( fd_vinyl_io_seed( io ), (fd_vinyl_bstream_block_t *)cphdr );

    *_style   = FD_VINYL_BSTREAM_CTL_STYLE_LZ4;
    *_val_esz = cval_sz;
    return fd_vinyl_io_append( io, cphdr, cpair_sz );

  }

  default:
    FD_LOG_CRIT(( "unsupported style" ));

  }

  /* Append in place */

  fd_vinyl_bstream_pair_hash( fd_vinyl_io_seed( io ), (fd_vinyl_bstream_block_t *)phdr );

  *_style   = FD_VINYL_BSTREAM_CTL_STYLE_RAW;
  *_val_esz = val_sz;
  return fd_vinyl_io_append( io, phdr, pair_sz );
}
