#define _GNU_SOURCE
#include "fd_vinyl_io_ur.h"
#include "../../util/io_uring/fd_io_uring_setup.h"
#include "../../util/io_uring/fd_io_uring_register.h"

#include <stdlib.h> /* mkstemp */
#include <errno.h>
#include <unistd.h> /* ftruncate */
#include <fcntl.h>  /* open */
#include <linux/io_uring.h> /* io_uring_params */
#include <sys/mman.h> /* mmap */

#include "test_vinyl_io_common.c"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong        spad_max = fd_env_strip_cmdline_ulong   ( &argc, &argv, "--spad-max", NULL, 131072UL );
  char const * path     = fd_env_strip_cmdline_cstr    ( &argc, &argv, "--path",     NULL, NULL     );
  ulong        seed     = fd_env_strip_cmdline_ulong   ( &argc, &argv, "--seed",     NULL, 1234UL   );
  uint         depth    = fd_env_strip_cmdline_uint    ( &argc, &argv, "--depth",    NULL, 256U     );
  _Bool        umem     = fd_env_strip_cmdline_contains( &argc, &argv, "--umem"     );
  _Bool        defer_io = fd_env_strip_cmdline_contains( &argc, &argv, "--defer-io" );

  FD_LOG_NOTICE(( "Testing with --spad-max %lu --seed %lu", spad_max, seed ));

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );

  ulong store_sz = (off_t)(FD_VINYL_BSTREAM_BLOCK_SZ + BCACHE_SZ);

  char _path[]  = "/tmp/test_vinyl_io_ur.XXXXXX";

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
  static uchar mem[ MEM_MAX ] __attribute__((aligned(512)));

  FD_LOG_NOTICE(( "Testing construction" ));

  /* Create a bstream using io_bd */
  {
    char const * info    = "info";
    ulong        info_sz = strlen( info ) + 1UL;

    ulong align = fd_vinyl_io_bd_align();
    ulong footprint = fd_vinyl_io_bd_footprint( spad_max );
    if( FD_UNLIKELY( (footprint>MEM_MAX) | (align>512UL) ) ) FD_LOG_ERR(( "update mem for this test" ));
    fd_vinyl_io_t * io_bd = fd_vinyl_io_bd_init( mem, spad_max, fd, 1, info, info_sz, seed );
    FD_TEST( io_bd );
    FD_TEST( fd_vinyl_io_fini( io_bd )==mem );
  }

  void * ring_umem = NULL;
  if( umem ) {
    ulong ring_sz = fd_io_uring_shmem_footprint( depth, depth );
    ring_umem = mmap( NULL, ring_sz, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0 );
    if( FD_UNLIKELY( ring_umem==MAP_FAILED ) ) {
      FD_LOG_ERR(( "mmap ring_umem failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
  }

  /* Join the bstream using io_ur */
  fd_io_uring_t ring[1];
  fd_vinyl_io_t * io = NULL;
  {
    struct io_uring_params params[1];
    fd_io_uring_params_init( params, depth );
    if( defer_io ) {
      params->flags    |= IORING_SETUP_COOP_TASKRUN;
      params->features |= IORING_SETUP_DEFER_TASKRUN;
    }

    int map_ok;
    if( umem ) map_ok = !!fd_io_uring_init_shmem( ring, params, ring_umem, depth, depth );
    else       map_ok = !!fd_io_uring_init_mmap ( ring, params );
    if( FD_UNLIKELY( !map_ok ) ) {
      if( FD_UNLIKELY( errno==-EPERM ) ) {
        FD_LOG_WARNING(( "skip: unit test is missing privileges to setup io_uring" ));
        if( FD_UNLIKELY( unlink( path ) ) ) FD_LOG_WARNING(( "unlink failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        fd_rng_delete( fd_rng_leave( rng ) );
        return 0;
      } else {
        FD_LOG_ERR(( "fd_io_uring_init_mmap failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      }
    }

    FD_TEST( 0==fd_io_uring_register_files( ring->ioring_fd, &fd, 1 ) );

    FD_TEST( 0==fd_io_uring_enable_rings( ring->ioring_fd ) );

    ulong align = fd_vinyl_io_ur_align();
    FD_TEST( fd_ulong_is_pow2( align ) );
    ulong footprint = fd_vinyl_io_ur_footprint( spad_max );
    FD_TEST( fd_ulong_is_aligned( footprint, align ) );
    if( FD_UNLIKELY( (footprint>MEM_MAX) | (align>512UL) ) ) FD_LOG_ERR(( "update mem for this test" ));
    io = fd_vinyl_io_ur_init( mem, spad_max, fd, ring );
    FD_TEST( io );
  }

  FD_LOG_NOTICE(( "Testing accessors" ));

  FD_TEST( fd_vinyl_io_type        ( io )==FD_VINYL_IO_TYPE_UR );
  FD_TEST( fd_vinyl_io_seed        ( io )==seed                );
  FD_TEST( fd_vinyl_io_seq_ancient ( io )==seq_ancient         );
  FD_TEST( fd_vinyl_io_seq_past    ( io )==seq_past            );
  FD_TEST( fd_vinyl_io_seq_present ( io )==seq_present         );
  FD_TEST( fd_vinyl_io_seq_future  ( io )==seq_future          );

  FD_LOG_NOTICE(( "Testing operations" ));

  test( io, rng );

  FD_LOG_NOTICE(( "Aborting and resuming" ));

  FD_TEST( fd_vinyl_io_fini( io )==mem );

  io = fd_vinyl_io_ur_init( mem, spad_max, fd, ring );
  FD_TEST( io );

  FD_LOG_NOTICE(( "Testing operations (after resume)" ));

  test( io, rng );

  FD_TEST( fd_vinyl_io_type        ( io )==FD_VINYL_IO_TYPE_UR );
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

  FD_LOG_NOTICE(( "Cleaning up" ));

  if( ring_umem ) {
    if( FD_UNLIKELY( munmap( ring_umem, fd_io_uring_shmem_footprint( depth, depth ) ) ) ) {
      FD_LOG_WARNING(( "munmap ring_umem failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
  }
  (void)fd_io_uring_fini( ring );

  if( FD_UNLIKELY( unlink( path ) ) ) FD_LOG_WARNING(( "unlink failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
