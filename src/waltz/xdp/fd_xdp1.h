#ifndef HEADER_fd_src_waltz_xdp_fd_xdp1_h
#define HEADER_fd_src_waltz_xdp_fd_xdp1_h

#if defined(__linux__)

#include "../../util/fd_util.h"

FD_PROTOTYPES_BEGIN

/* fd_xdp_gen_program generates an XDP program that steers incoming
   Firedancer packets to AF_XDP sockets using XDP_REDIRECT.  Places the
   eBPF program bytecode at code_buf.  xsks_fd is the XSKMAP file
   descriptor.  If listen_ip_addr!=0, only redirects packets with a
   matching dst IP address.  ports is a list of UDP dst ports to
   redirect.  If allowed_gre==1, also forwards GRE-tunnelled packets. */

ulong
fd_xdp_gen_program( ulong          code_buf[ 512 ],
                    int            xsks_fd,
                    uint           listen_ip4_addr,
                    ushort const * ports,
                    ulong          ports_cnt,
                    int            allowed_gre );

/* fd_xdp_install installs a BPF program onto the given interface which
   only passes through UDP traffic on the provided ports to rings on an
   XSK map.  If listen_ip4_addr is not zero, specifies a net order IPv4
   address to filter the dest address for.  The XSK map is created and
   returned in the fd_xdp_fds_t, along with a bpf link file descriptor
   (from BPF_LINK_CREATE).  This link must not be closed or the XDP
   program will be uninstalled from the device, and no more packets will
   be received.  This happens automatically when the process exits.

   The XSK map returned in xsk_map_fd simply needs to have socket file
   descriptors inserted, one per each queue, with BPF_MAP_UPDATE_ELEM,
   where the sockets are correctly configured XSK sockets.

   This function will print a diagnostic error message and terminate the
   process if it fails, and will not return in failure cases. */

struct fd_xdp_fds {
  uint if_idx;
  int  xsk_map_fd;
  int  prog_link_fd;
};

typedef struct fd_xdp_fds fd_xdp_fds_t;

fd_xdp_fds_t
fd_xdp_install( uint           if_idx,
                uint           listen_ip4_addr,
                ulong          ports_cnt,
                ushort const * ports,
                char const *   xdp_mode );

FD_PROTOTYPES_END

#endif /* defined(__linux__) */

#endif /* HEADER_fd_src_waltz_xdp_fd_xdp1_h */
