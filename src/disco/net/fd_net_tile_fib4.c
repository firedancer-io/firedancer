#include "fd_net_tile.h"
#include "../topo/fd_topo.h"

fd_fib4_t *
fd_net_tile_fib4_join( fd_fib4_t *            out,
                       fd_topo_t const *      topo,
                       fd_topo_tile_t const * net_tile,
                       int                    main_table ) {
  if( 0==strcmp( net_tile->name, "net" ) ) {
    return fd_xdp_tile_fib4_join( out, topo, net_tile, main_table );
  } else if( 0==strcmp( net_tile->name, "mlx5" ) ) {
    return fd_mlx5_tile_fib4_join( out, topo, net_tile, main_table );
  } else if( 0==strcmp( net_tile->name, "iavf" ) ) {
    return fd_iavf_tile_fib4_join( out, topo, net_tile, main_table );
  }
  FD_LOG_ERR(( "tile %s has no fib4", net_tile->name ));
}
