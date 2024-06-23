#ifndef HEADER_fd_src_net_xdp_fd_xdp_redirect_user_h
#define HEADER_fd_src_net_xdp_fd_xdp_redirect_user_h

/* Userspace API for controlling the fd_xdp_redirect_prog program.

   ### XDP program

   This API is specific to the fd_xdp_redirect_prog.c program.
   Loading other XDP programs is unsupported.  In short, it is
   responsible for identifying and redirecting packets matching the
   app's listener to the app's XSKs (e.g. by IP address/UDP port).
   See the program's source for more info.

   ### XDP program installation

   The bpf(2) syscall allows loading a compiled eBPF program into the
   kernel.  It is recommended to enable the eBPF JIT compiler for better
   performance via `echo 1 >/proc/sys/net/core/bpf_jit_enable`.
   Manpage: https://man7.org/linux/man-pages/man2/bpf.2.html

   ### Lifecycle

   This API allows separating the XDP program installation from the app
   lifecycle, reducing the privileges/capabilities required at runtime.

   The step-by-step lifecycle looks as follows:

   - fd_xdp_session_init() (privileged)
   - For each interface to listen on
     - fd_xdp_hook_iface() (privileged)
     - For each RX/TX queue pair of this interface
       - fd_xsk_new()
       - fd_xsk_bind()
       - fd_xsk_join()
   - For each UDP/IP destination to listen on
     - fd_xdp_listen_udp_port()
   - ... Application run ... */

/* TODO: Support NUMA-aware eBPF maps */

#include "fd_xsk.h"
#include "../../util/fd_util.h"

/* FD_XDP_PIN_NAME_SZ: max number of chars in an eBPF pin dir name */
#define FD_XDP_PIN_NAME_SZ (255UL)

struct fd_xdp_session {
  int udp_dsts_map_fd;  /* BPF_MAP_TYPE_HASH */
};

typedef struct fd_xdp_session fd_xdp_session_t;

struct fd_xdp_link_session {
  int xsk_map_fd;    /* BPF_MAP_TYPE_XSKMAP */
  int prog_fd;       /* BPF_PROG_TYPE_XDP */
  int prog_link_fd;  /* BPF_LINK_CREATE */
};

typedef struct fd_xdp_link_session fd_xdp_link_session_t;

FD_PROTOTYPES_BEGIN

/* Install API (privileged) *******************************************/

/* fd_xdp_session_init: Prepare an XDP session.  Returns session on
   success and NULL on error.  Reasons for error are logged to
   FD_LOG_WARNING.  Requires CAP_SYS_ADMIN. */

fd_xdp_session_t *
fd_xdp_session_init( fd_xdp_session_t * session );

/* fd_xdp_fini: Destroy all kernel resources installed by fd_xdp
   corresponding to the given app name, including any XDP programs,
   installations, eBPF maps, and links.  Returns session on success
   and NULL on error.  Reasons for error are logged to FD_LOG_WARNING.
   Requires CAP_SYS_ADMIN. */

fd_xdp_session_t *
fd_xdp_session_fini( fd_xdp_session_t * session );

/* fd_xdp_hook_iface: Install the XDP redirect program to the network
   device with name ifname.  Installation lifetime is until a
   matching call to fd_xdp_unhook_iface() or until the system is
   shut down.  xdp_mode is the XDP install mode (as defined by
   XDP_FLAGS_{...}_MODE in <linux/if_link.h>).
   Returns link_session on success.  On error, logs reason to warning
   log and returns NULL.  Requires CAP_SYS_ADMIN.

   Valid values for xdp_mode:

     0                   kernel default mode
     XDP_FLAGS_SKB_MODE  sk_buff generic mode (hardware-agnostic)
     XDP_FLAGS_DRV_MODE  driver XDP (requires driver support)
     XDP_FLAGS_HW_MODE   hardware-accelerated XDP
                         (requires NIC and driver support) */

fd_xdp_link_session_t *
fd_xdp_link_session_init( fd_xdp_link_session_t *  link_session,
                          fd_xdp_session_t const * session,
                          uint                     if_idx,
                          uint                     xdp_mode );

/* fd_xdp_unhook_iface uninstalls the XDP redirect program from the
   network device with name ifname.  Requires CAP_SYS_ADMIN. */

void
fd_xdp_link_session_fini( fd_xdp_link_session_t * session );

/* Listen API (privileged) ********************************************/

/* fd_xdp_udp_dst_key returns a key for the fd_xdp_udp_dsts eBPF
   map given the IPv4 dest address and UDP port number.  ip4_addr is the
   network byte order IP address.  udp_port is the host byte order UDP
   port. */
static inline ulong
fd_xdp_udp_dst_key( uint ip4_addr,
                    uint udp_port ) {
  return ( (ulong)( ip4_addr )<<16 ) | fd_ushort_bswap( (ushort)udp_port );
}

/* fd_xdp_listen_udp_port installs a listener for protocol proto on IPv4
   destination addr ip4_dst_addr and UDP destination port udp_dst_ports.
   Installation lifetime is until a matching call to
   fd_xdp_release_udp_port() or until the system is shut down.
   On interfaces running the XDP redirect program, causes matching
   traffic to get redirected to active XSKs, and ceases processing of
   matching traffic in the Linux networking stack.  Returns 0 on success
   or if no redirect program installation was found, and -1 on error.
   Reasons for error are logged to FD_LOG_WARNING. */

int
fd_xdp_listen_udp_port( fd_xdp_session_t * session,
                        uint               ip4_dst_addr,
                        ushort             udp_dst_port,
                        uint               proto );

/* fd_xdp_release_udp_port uninstalls a listener that was previously
   installed with fd_xdp_listen_udp_port().  Restores processing of
   matching traffic in the Linux networking stack.  Returns 0 on success
   or if no redirect program installation was found, and -1 on error.
   Reasons for error are logged to FD_LOG_WARNING. */

int
fd_xdp_release_udp_port( fd_xdp_session_t * sesssion,
                         uint               ip4_dst_addr,
                         uint               udp_dst_port );

/* fd_xdp_clear_listeners uninstalls all listeners previously installed
   via fd_xdp_listen_udp_port(). */

int
fd_xdp_clear_listeners( fd_xdp_session_t * sesssion );

/* Runtime API (unprivileged) *****************************************/

/* fd_xsk_activate installs an XSK file descriptor into the XDP redirect
   program's XSKMAP for the network device with name fd_xsk_ifname(xsk)
   at key fd_xsk_ifqueue(xsk). If another XSK is already installed at
   this key, it will be silently replaced.  The given xsk must be a
   valid local join to fd_xsk_t.  When packets arrive on the netdev RX
   queue that the XSK is bound to, and the XDP program takes action
   XDP_REDIRECT, causes these packets to be written to the XSK RX queue.
   Similarly, packets written to the XSK's TX ring get sent to the
   corresponding netdev TX queue.  Such writes may get lost on
   congestion.  Returns xsk on success.  On error, logs reason to 
   warning log and returns NULL. */

fd_xsk_t *
fd_xsk_activate( fd_xsk_t * xsk,
                 int        xsk_map_fd );

/* fd_xsk_deactivate uninstalls an XSK file descriptor from the XDP
   redirect program's XSKMAP.  XSK will cease to receive traffic.
   Returns xsk on success or if no redirect program installation was
   found.  On error, logs reason to warning log and returns NULL. */

fd_xsk_t *
fd_xsk_deactivate( fd_xsk_t * xsk,
                   int        xsk_map_fd );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_net_xdp_fd_xdp_redirect_user_h */
