/* Include fd_neigh4_map prototypes */
#include "fd_neigh4_map.h"

#if FD_HAS_HOSTED

#include <errno.h>
#include <stdio.h>
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_eth.h"

int
fd_neigh4_hmap_fprintf( fd_neigh4_hmap_t const * map,
                        void *                   file_ ) {
  FILE * file = file_;

  ulong slot_cnt = fd_neigh4_hmap_ele_max( map );
  fd_neigh4_entry_t const * ele = fd_neigh4_hmap_ele0_const( map );

  for( ulong i=0UL; i<slot_cnt; i++ ) {
    if( fd_neigh4_hmap_ele_is_free( ele+i ) ) continue;

    fd_neigh4_entry_t tmp_val;
    fd_neigh4_entry_atomic_ld( &tmp_val, ele+i );

    int print_res = fprintf( file, FD_IP4_ADDR_FMT " " FD_ETH_MAC_FMT "\n",
                             FD_IP4_ADDR_FMT_ARGS( tmp_val.ip4_addr ), FD_ETH_MAC_FMT_ARGS( tmp_val.mac_addr ) );
    if( FD_UNLIKELY( print_res<0 ) ) return errno;
  }

  return 0;
}

#endif /* FD_HAS_HOSTED */
