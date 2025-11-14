#include "../fd_vinyl.h"

#include "test_vinyl_io_common.c"

static ulong const dev_sz = FD_VINYL_BSTREAM_BLOCK_SZ + BCACHE_SZ;
static uchar       dev[ FD_VINYL_BSTREAM_BLOCK_SZ + BCACHE_SZ ] __attribute__((aligned(FD_VINYL_BSTREAM_BLOCK_SZ)));

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong spad_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--spad-max", 0UL,  131072UL );
  ulong seed     = fd_env_strip_cmdline_ulong( &argc, &argv, "--seed",     0UL,  1234UL   );

  FD_LOG_NOTICE(( "Testing with --spad-max %lu --seed %lu", spad_max, seed ));

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );

# define MEM_MAX (1048576UL)
  uchar mem[ MEM_MAX ] __attribute__((aligned(512)));

  FD_LOG_NOTICE(( "Testing construction" ));

  ulong align = fd_vinyl_io_mm_align();
  FD_TEST( fd_ulong_is_pow2( align ) );

  FD_TEST( !fd_vinyl_io_mm_footprint( ULONG_MAX ) );

  ulong footprint = fd_vinyl_io_mm_footprint( spad_max );
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );
  if( FD_UNLIKELY( (footprint>MEM_MAX) | (align>512UL) ) ) FD_LOG_ERR(( "update mem for this test" ));

  char const * info        = "info";
  ulong        info_sz     = strlen( info ) + 1UL;
  ulong        info_sz_bad = FD_VINYL_BSTREAM_SYNC_INFO_MAX + 1UL;

  FD_TEST( !fd_vinyl_io_mm_init( NULL,        spad_max,  dev,         dev_sz,     1, info, info_sz,     seed ) );
  FD_TEST( !fd_vinyl_io_mm_init( (void *)1UL, spad_max,  dev,         dev_sz,     1, info, info_sz,     seed ) );
  FD_TEST( !fd_vinyl_io_mm_init( mem,         0UL,       dev,         dev_sz,     1, info, info_sz,     seed ) );
  FD_TEST( !fd_vinyl_io_mm_init( mem,         1UL,       dev,         dev_sz,     1, info, info_sz,     seed ) );
  FD_TEST( !fd_vinyl_io_mm_init( mem,         1UL<<63,   dev,         dev_sz,     1, info, info_sz,     seed ) );
  FD_TEST( !fd_vinyl_io_mm_init( mem,         spad_max,  NULL,        dev_sz,     1, info, info_sz,     seed ) );
  FD_TEST( !fd_vinyl_io_mm_init( mem,         spad_max,  (void *)1UL, dev_sz,     1, info, info_sz,     seed ) );
  FD_TEST( !fd_vinyl_io_mm_init( mem,         spad_max,  dev,         3584UL,     1, info, info_sz,     seed ) );
  FD_TEST( !fd_vinyl_io_mm_init( mem,         spad_max,  dev,         dev_sz+1UL, 1, info, info_sz,     seed ) );
  FD_TEST( !fd_vinyl_io_mm_init( mem,         spad_max,  dev,         dev_sz,     1, info, info_sz_bad, seed ) );
  /* Note: info_sz, info and seed ignored with reset 0 */
  /* Note: info NULL implies info_sz zero */
  /* Note: seed arbitrary */

  fd_vinyl_io_t * io = fd_vinyl_io_mm_init( mem, spad_max, dev, dev_sz, 1, info, info_sz, seed );
  FD_TEST( io );

  FD_LOG_NOTICE(( "Testing accessors" ));

  FD_TEST( fd_vinyl_io_type        ( io )==FD_VINYL_IO_TYPE_MM );
  FD_TEST( fd_vinyl_io_seed        ( io )==seed                );
  FD_TEST( fd_vinyl_io_seq_ancient ( io )==seq_ancient         );
  FD_TEST( fd_vinyl_io_seq_past    ( io )==seq_past            );
  FD_TEST( fd_vinyl_io_seq_present ( io )==seq_present         );
  FD_TEST( fd_vinyl_io_seq_future  ( io )==seq_future          );

  FD_LOG_NOTICE(( "Testing operations" ));

  test( io, rng );

  FD_LOG_NOTICE(( "Aborting and resuming" ));

  FD_TEST( fd_vinyl_io_fini( io )==mem );

  io = fd_vinyl_io_mm_init( mem, spad_max, dev, dev_sz, 0, (void *)1UL, ULONG_MAX, ~seed ); /* info_sz, info, seed ignored on resume */
  FD_TEST( io );

  void * mmio    = fd_vinyl_mmio   ( io ); FD_TEST( mmio    && fd_ulong_is_aligned( (ulong)mmio, FD_VINYL_BSTREAM_BLOCK_SZ ) );
  ulong  mmio_sz = fd_vinyl_mmio_sz( io ); FD_TEST( mmio_sz && fd_ulong_is_aligned( mmio_sz,     FD_VINYL_BSTREAM_BLOCK_SZ ) );

  FD_LOG_NOTICE(( "Testing operations (after resume)" ));

  test( io, rng );

  FD_TEST( fd_vinyl_io_type        ( io )==FD_VINYL_IO_TYPE_MM );
  FD_TEST( fd_vinyl_io_seed        ( io )==seed                );
  FD_TEST( fd_vinyl_io_seq_ancient ( io )==seq_ancient         );
  FD_TEST( fd_vinyl_io_seq_past    ( io )==seq_past            );
  FD_TEST( fd_vinyl_io_seq_present ( io )==seq_present         );
  FD_TEST( fd_vinyl_io_seq_future  ( io )==seq_future          );

  FD_LOG_NOTICE(( "Testing scratch pad" ));

  FD_TEST( !fd_vinyl_io_commit( io, FD_VINYL_IO_FLAG_BLOCKING ) ); /* empty the spad */

  void * smem      = NULL;
  ulong  smem_sz   = 0UL;
  ulong  spad_used = 0UL;

  while( spad_used<spad_max ) {

    FD_TEST( fd_vinyl_io_spad_max ( io )==spad_max           );
    FD_TEST( fd_vinyl_io_spad_used( io )==spad_used          );
    FD_TEST( fd_vinyl_io_spad_free( io )==spad_max-spad_used );

    void * last    = smem;
    ulong  last_sz = smem_sz;

    smem_sz = fd_ulong_min( FD_VINYL_BSTREAM_BLOCK_SZ*fd_rng_coin_tosses( rng ), spad_max - spad_used );

    smem = fd_vinyl_io_alloc( io, smem_sz, 0 );

    FD_TEST( smem );
    FD_TEST( fd_ulong_is_aligned( (ulong)smem, FD_VINYL_BSTREAM_BLOCK_SZ ) );
    if( last ) FD_TEST( ((ulong)smem - (ulong)last)==last_sz );
    spad_used += smem_sz;
  }

  FD_TEST( fd_vinyl_io_spad_max ( io )==spad_max           );
  FD_TEST( fd_vinyl_io_spad_used( io )==spad_used          );
  FD_TEST( fd_vinyl_io_spad_free( io )==spad_max-spad_used );

  FD_LOG_NOTICE(( "Testing destruction" ));

  fd_vinyl_bstream_block_t block[1];
  memset( block, 0, FD_VINYL_BSTREAM_BLOCK_SZ );
  fd_vinyl_io_append( io, block, FD_VINYL_BSTREAM_BLOCK_SZ );

  FD_TEST( !fd_vinyl_io_fini( NULL ) );
  FD_TEST( fd_vinyl_io_fini( io )==mem ); /* fini with uncommitted bytes */

  FD_LOG_NOTICE(( "Testing invalid stores" ));

  memset( dev, 0, FD_VINYL_BSTREAM_BLOCK_SZ );
  FD_TEST( !fd_vinyl_io_mm_init( mem, spad_max, dev, dev_sz, 0, (void *)1UL, ULONG_MAX, ~seed ) ); /* bad meta block for resume */

  FD_LOG_NOTICE(( "Cleaning up" ));

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
