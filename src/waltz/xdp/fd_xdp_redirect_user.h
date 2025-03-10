#ifndef HEADER_fd_src_waltz_xdp_fd_xdp_redirect_user_h
#define HEADER_fd_src_waltz_xdp_fd_xdp_redirect_user_h

#include "fd_xsk.h"
#include "../../util/fd_util.h"

FD_PROTOTYPES_BEGIN

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

#endif /* HEADER_fd_src_waltz_xdp_fd_xdp_redirect_user_h */
