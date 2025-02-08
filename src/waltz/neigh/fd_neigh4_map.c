/* Include fd_neigh4_map prototypes */
#include "fd_neigh4_map.h"

/* Generate fd_neigh4_map definitions */
#include "fd_neigh4_map_defines.h"
#define MAP_IMPL_STYLE 2
#include "../../util/tmpl/fd_map_slot_para.c"

#if FD_HAS_HOSTED && FD_HAS_SSE

#include <errno.h>
#include <stdio.h>
#include <xmmintrin.h>
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_eth.h"

int
fd_neigh4_hmap_fprintf( fd_neigh4_hmap_t const * map,
                        void *                   file_ ) {
  FILE * file = file_;

  ulong                     ele_max = fd_neigh4_hmap_ele_max( map );
  fd_neigh4_entry_t const * ele     = fd_neigh4_hmap_shele_const( map );

  for( ulong j=0UL; j<ele_max; j++ ) {
    union {
      fd_neigh4_entry_t e;
      __m128i           m128;
    } l;
    l.m128 = _mm_load_si128( (__m128i const *)(ele+j) );
    if( l.e.ip4_addr ) {
      int print_res = fprintf( file, FD_IP4_ADDR_FMT " " FD_ETH_MAC_FMT "\n",
                               FD_IP4_ADDR_FMT_ARGS( l.e.ip4_addr ), FD_ETH_MAC_FMT_ARGS( l.e.mac_addr ) );
      if( FD_UNLIKELY( print_res<0 ) ) return errno;
    }
  }

  return 0;
}

#endif /* FD_HAS_HOSTED && FD_HAS_SSE */
