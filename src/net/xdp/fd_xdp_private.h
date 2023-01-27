#ifndef HEADER_fd_xdp_private_h
#define HEADER_fd_xdp_private_h

#include "fd_xdp_ring_defs.h"

#include <linux/if_xdp.h>

/* define the structures used by fd_xdp */
FD_RING_ITER_TYPES(FD_RING_DEF,)

struct fd_xdp {
  fd_xdp_config_t         config;         // config used to initialize

  unsigned                ifindex;        // index of specified interface

  struct xdp_umem_reg     umem;           // XDP API structure
                                          // see linux/if_xdp.h

  int                     xdp_sock;       // xdp socket fd

  int                     xdp_map_fd;     // file descriptor for the xdp map
                                          // this is kept to add/remove keys
                                          // to/from the map

  int                     xdp_udp_map_fd; // file descriptor for the xdp udp map
                                          // this is kept to add/remove keys
                                          // to/from the map

  struct xdp_mmap_offsets offsets;

  void *                  owned_mem;  // NULL or address of memory we own

  /* define the ring members */
  FD_RING_ITER_TYPES(FD_RING_MEMBER,)
};

#endif // HEADER_fd_xdp_private_h

