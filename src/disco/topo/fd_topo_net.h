#ifndef HEADER_fd_src_disco_topo_fd_topo_net_h
#define HEADER_fd_src_disco_topo_fd_topo_net_h

/* fd_topo_install_xdp installs XDP programs to all interfaces in the
   topology.

   bind_addr is an optional IPv4 address to used for filtering RX
   packets by dst IP.

   For each interface, two file descriptors are created using
   fd_xdp_install: 'BPF map (XSKMAP)' and 'BPF program link'.
   The XSK map allows registering XSK sockets with the interface, and
   the BPF program link is a handle to the XDP program installation
   (so as long as this file descriptor exists in some process, the XDP
   program remains installed).  All newly created file descriptors are
   moved to a contiguous integer range starting at
   FD_TOPO_XDP_INHERIT_FD_MIN using dup2.  An installation can refer to
   up to FD_TOPO_XDP_DEVICES_MAX separate interfaces (typically one
   handle for loopback and the rest for slaves of a bond device). */

#include "fd_topo.h"
#include "../../waltz/xdp/fd_xdp1.h"

#define FD_TOPO_XDP_INHERIT_FD_MIN 123462 /* arbitrary fd number */
#define FD_TOPO_XDP_DEVICES_MAX 5

struct fd_xdp_multi_fds {
  struct {
    uint         if_idx;
    char         if_name[ 16 ];
    fd_xdp_fds_t fds;
  } device [ FD_TOPO_XDP_DEVICES_MAX ];
  uint device_cnt;
};
typedef struct fd_xdp_multi_fds fd_xdp_multi_fds_t;

FD_PROTOTYPES_BEGIN

/* fd_topo_install_xdp installs XDP programs and creates BPF maps.
   Fills in file descriptor numbers in the topo object. */

fd_xdp_multi_fds_t
fd_topo_install_xdp( fd_topo_t * topo,
                     uint        bind_addr );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_topo_fd_topo_net_h */
