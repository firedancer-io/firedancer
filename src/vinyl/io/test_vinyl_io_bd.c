#include "../fd_vinyl.h"

#include <stdlib.h> /* For mkstemp */
#include <errno.h>  /* For errno */
#include <unistd.h> /* For ftruncate */
#include <fcntl.h>  /* For open */

#include "test_vinyl_io_common.c"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong        spad_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--spad-max", 0UL,  131072UL );
  char const * path     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--path",     NULL, NULL     );
  ulong        seed     = fd_env_strip_cmdline_ulong( &argc, &argv, "--seed",     0UL,  1234UL   );

  FD_LOG_NOTICE(( "Testing with --spad-max %lu --seed %lu", spad_max, seed ));

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );

  ulong store_sz = (off_t)(FD_VINYL_BSTREAM_BLOCK_SZ + BCACHE_SZ);

  char _path[]  = "/tmp/test_vinyl_io_bd.XXXXXX";

  int fd;
  if( FD_UNLIKELY( path ) ) {
    FD_LOG_NOTICE(( "Using --path %s for the test storage", path ));
    fd = open( path, O_RDWR | O_CREAT | O_EXCL, (mode_t)0644 );
    if( FD_UNLIKELY( fd==-1 ) ) FD_LOG_ERR(( "open failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  } else {
    FD_LOG_NOTICE(( "--path not specified, using a temp file for test storage" ));
    fd = mkstemp( _path );
    if( FD_UNLIKELY( fd==-1 ) ) FD_LOG_ERR(( "mkstemp failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    path = _path;
    FD_LOG_NOTICE(( "temp file at %s", path ));
  }

  if( FD_UNLIKELY( ftruncate( fd, (off_t)store_sz ) ) )
    FD_LOG_ERR(( "ftruncate failed (%i-%s)", errno, fd_io_strerror( errno ) ));

# define MEM_MAX (1048576UL)
  uchar mem[ MEM_MAX ] __attribute__((aligned(512)));

  FD_LOG_NOTICE(( "Testing construction" ));

  ulong align = fd_vinyl_io_bd_align();
  FD_TEST( fd_ulong_is_pow2( align ) );

  FD_TEST( !fd_vinyl_io_bd_footprint( ULONG_MAX ) );

  ulong footprint = fd_vinyl_io_bd_footprint( spad_max );
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );
  if( FD_UNLIKELY( (footprint>MEM_MAX) | (align>512UL) ) ) FD_LOG_ERR(( "update mem for this test" ));

  char const * info        = "info";
  ulong        info_sz     = strlen( info ) + 1UL;
  ulong        info_sz_bad = FD_VINYL_BSTREAM_SYNC_INFO_MAX + 1UL;

  FD_TEST( !fd_vinyl_io_bd_init( NULL,        spad_max,  fd, 1, info, info_sz,     seed ) );
  FD_TEST( !fd_vinyl_io_bd_init( (void *)1UL, spad_max,  fd, 1, info, info_sz,     seed ) );
  FD_TEST( !fd_vinyl_io_bd_init( mem,         0UL,       fd, 1, info, info_sz,     seed ) );
  FD_TEST( !fd_vinyl_io_bd_init( mem,         511UL,     fd, 1, info, info_sz,     seed ) );
  FD_TEST( !fd_vinyl_io_bd_init( mem,         1UL<<63,   fd, 1, info, info_sz,     seed ) );
  FD_TEST( !fd_vinyl_io_bd_init( mem,         spad_max,  -1, 1, info, info_sz,     seed ) );
  FD_TEST( !fd_vinyl_io_bd_init( mem,         spad_max,  fd, 1, info, info_sz_bad, seed ) );
  /* Note: info_sz, info and seed ignored with reset 0 */
  /* Note: info NULL implies info_sz zero */
  /* Note: seed arbitrary */

  fd_vinyl_io_t * io = fd_vinyl_io_bd_init( mem, spad_max, fd, 1, info, info_sz, seed );
  FD_TEST( io );

  FD_TEST( !fd_vinyl_mmio   ( io ) );
  FD_TEST( !fd_vinyl_mmio_sz( io ) );

  FD_LOG_NOTICE(( "Testing accessors" ));

  FD_TEST( fd_vinyl_io_type        ( io )==FD_VINYL_IO_TYPE_BD );
  FD_TEST( fd_vinyl_io_seed        ( io )==seed                );
  FD_TEST( fd_vinyl_io_seq_ancient ( io )==seq_ancient         );
  FD_TEST( fd_vinyl_io_seq_past    ( io )==seq_past            );
  FD_TEST( fd_vinyl_io_seq_present ( io )==seq_present         );
  FD_TEST( fd_vinyl_io_seq_future  ( io )==seq_future          );

  FD_LOG_NOTICE(( "Testing operations" ));

  test( io, rng );

  FD_LOG_NOTICE(( "Aborting and resuming" ));

  FD_TEST( fd_vinyl_io_fini( io )==mem );

  io = fd_vinyl_io_bd_init( mem, spad_max, fd, 0, (void *)1UL, ULONG_MAX, ~seed ); /* info_sz, info, seed ignored on resume */
  FD_TEST( io );

  FD_LOG_NOTICE(( "Testing operations (after resume)" ));

  test( io, rng );

  FD_TEST( fd_vinyl_io_type        ( io )==FD_VINYL_IO_TYPE_BD );
  FD_TEST( fd_vinyl_io_seed        ( io )==seed                );
  FD_TEST( fd_vinyl_io_seq_ancient ( io )==seq_ancient         );
  FD_TEST( fd_vinyl_io_seq_past    ( io )==seq_past            );
  FD_TEST( fd_vinyl_io_seq_present ( io )==seq_present         );
  FD_TEST( fd_vinyl_io_seq_future  ( io )==seq_future          );

  /* FIXME: TEST BSTREAM WRITE HELPERS */

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

  if( FD_UNLIKELY( ftruncate( fd, (off_t)0UL ) ) ) FD_LOG_ERR(( "ftruncate failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  FD_TEST( !fd_vinyl_io_bd_init( mem, spad_max, fd, 0, (void *)1UL, ULONG_MAX, ~seed ) ); /* store too small */

  /* Note: we don't test too large to protect the file system */

  if( FD_UNLIKELY( ftruncate( fd, (off_t)16777217UL) ) ) FD_LOG_ERR(( "ftruncate failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  FD_TEST( !fd_vinyl_io_bd_init( mem, spad_max, fd, 0, (void *)1UL, ULONG_MAX, ~seed ) ); /* store misaligned */

  if( FD_UNLIKELY( ftruncate( fd, (off_t)store_sz ) ) ) FD_LOG_ERR(( "ftruncate failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  FD_TEST( !fd_vinyl_io_bd_init( mem, spad_max, fd, 0, (void *)1UL, ULONG_MAX, ~seed ) ); /* bad meta block for resume */

  FD_TEST( !fd_vinyl_io_bd_init( mem, spad_max, 0, 0, (void *)1UL, ULONG_MAX, ~seed ) ); /* fd (stdin) not seekable */

  FD_LOG_NOTICE(( "Cleaning up" ));

  if( FD_UNLIKELY( unlink( path ) ) ) FD_LOG_WARNING(( "unlink failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
