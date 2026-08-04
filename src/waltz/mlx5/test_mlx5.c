#define _DEFAULT_SOURCE

#include "fd_mlx5.h"
#include "../../util/fd_util.h"

#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>

#define TEST_MLX5_CQE_INVALID (15U)

static void
test_footprint( void ) {
  FD_TEST( !fd_mlx5_queue_footprint( 0U, 4U ) );
  FD_TEST( !fd_mlx5_queue_footprint( 4U, 0U ) );
  FD_TEST( !fd_mlx5_queue_footprint( 3U, 4U ) );
  FD_TEST( !fd_mlx5_queue_footprint( 4U, 3U ) );

  ulong footprint_1 = fd_mlx5_queue_footprint( 1U, 1U );
  ulong footprint_4 = fd_mlx5_queue_footprint( 4U, 4U );
  FD_TEST( footprint_1 && !(footprint_1 & (FD_MLX5_PAGE_SZ-1UL)) );
  FD_TEST( footprint_4>=footprint_1 && !(footprint_4 & (FD_MLX5_PAGE_SZ-1UL)) );
}

static void
test_hardware( char const * rdma_name,
               uint         port_num,
               uint         rx_depth,
               uint         tx_depth ) {
  ulong queue_footprint = fd_mlx5_queue_footprint( rx_depth, tx_depth );
  FD_TEST( queue_footprint );
  void * queue_memory = mmap( NULL, queue_footprint, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
  void * packet_memory = mmap( NULL, 4096UL, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
  if( FD_UNLIKELY( queue_memory==MAP_FAILED || packet_memory==MAP_FAILED ) )
    FD_LOG_ERR(( "mmap failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_mlx5_t mlx5[1];
  if( FD_UNLIKELY( !fd_mlx5_init( mlx5, rdma_name, port_num, queue_memory, rx_depth, tx_depth,
                                  packet_memory, 4096UL ) ) )
    FD_LOG_ERR(( "fd_mlx5_init failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  FD_TEST( mlx5->context.cmd_fd>=0 && mlx5->context.async_fd>=0 );
  FD_TEST( mlx5->uar.reg );
  FD_TEST( mlx5->rx_cq.entries && mlx5->rx_cq.control && mlx5->rx_cq.depth==rx_depth );
  FD_TEST( mlx5->tx_cq.entries && mlx5->tx_cq.control && mlx5->tx_cq.depth==tx_depth );
  FD_TEST( mlx5->qp.ctx==&mlx5->context && mlx5->qp.uar==&mlx5->uar );
  FD_TEST( mlx5->qp.rx_cq==&mlx5->rx_cq && mlx5->qp.tx_cq==&mlx5->tx_cq );
  FD_TEST( mlx5->qp.rq && mlx5->qp.sq && mlx5->qp.control );
  FD_TEST( mlx5->qp.qpn<=0xffffffU );
  FD_TEST( mlx5->qp.rx_depth==rx_depth && mlx5->qp.tx_depth==tx_depth );
  FD_TEST( mlx5->rx_cq.entries[ 0U ].bytes[ 63 ]==(uchar)(TEST_MLX5_CQE_INVALID<<4) );
  FD_TEST( mlx5->tx_cq.entries[ 0U ].bytes[ 63 ]==(uchar)(TEST_MLX5_CQE_INVALID<<4) );

  ulong out_of_buffer;
  FD_TEST( !fd_mlx5_qp_stats_read( &mlx5->qp_stats, &out_of_buffer ) );
  FD_LOG_NOTICE(( "initialized `%s` port %u with RX depth %u, TX depth %u, out_of_buffer %lu",
                  rdma_name, port_num, rx_depth, tx_depth, out_of_buffer ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_footprint();
  if( argc>1 ) {
    ulong port_num = argc>2 ? fd_cstr_to_ulong( argv[2] ) :     1UL;
    ulong rx_depth = argc>3 ? fd_cstr_to_ulong( argv[3] ) : 16384UL;
    ulong tx_depth = argc>4 ? fd_cstr_to_ulong( argv[4] ) : 16384UL;
    FD_TEST( port_num<=UINT_MAX && rx_depth<=UINT_MAX && tx_depth<=UINT_MAX );
    test_hardware( argv[1], (uint)port_num, (uint)rx_depth, (uint)tx_depth );
  }
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
