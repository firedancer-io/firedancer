#define _DEFAULT_SOURCE

#include "fd_mlx5.h"
#include "../../util/fd_util.h"

#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>

static void
test_hardware( char const * rdma_name ) {
  ulong queue_footprint = fd_mlx5_queue_footprint( 16384U, 16384U );
  void * queue_memory = mmap( NULL, queue_footprint, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
  void * packet_memory = mmap( NULL, 4096UL, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
  if( FD_UNLIKELY( queue_memory==MAP_FAILED || packet_memory==MAP_FAILED ) )
    FD_LOG_ERR(( "mmap failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_mlx5_t mlx5[1];
  ulong rx_user_data[16384];
  ulong tx_user_data[16384];
  if( FD_UNLIKELY( !fd_mlx5_init( mlx5, rdma_name, 1U, queue_memory, 16384U, 16384U,
                                  rx_user_data, tx_user_data, packet_memory, 4096UL ) ) )
    FD_LOG_ERR(( "fd_mlx5_init failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_TEST( fd_mlx5_queue_footprint( 4U, 4U ) );
  FD_TEST( !fd_mlx5_queue_footprint( 3U, 4U ) );
  if( argc>1 ) test_hardware( argv[1] );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
