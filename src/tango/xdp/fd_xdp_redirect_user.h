#ifndef HEADER_fd_src_net_xdp_fd_xdp_redirect_user_h
#define HEADER_fd_src_net_xdp_fd_xdp_redirect_user_h

#include "fd_xsk.h"

FD_PROTOTYPES_BEGIN

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
   congestion.  Returns 0 on success or if no redirect program
   installation was found and -1 on error.  Reasons for error are logged
   to FD_LOG_WARNING. */
int
fd_xsk_activate( fd_xsk_t * xsk );

/* fd_xsk_deactivate uninstalls an XSK file descriptor from the XDP
   redirect program's XSKMAP.  XSK will cease to receive traffic.
   Returns 0 on success or if no redirect program installation was found
   and -1 on error.  Reasons for error are logged to FD_LOG_WARNING. */
int
fd_xsk_deactivate( fd_xsk_t * xsk );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_net_xdp_fd_xdp_redirect_user_h */

