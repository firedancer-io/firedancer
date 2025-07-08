#ifndef HEADER_fd_src_disco_net_fd_net_common_h
#define HEADER_fd_src_disco_net_fd_net_common_h

/* fd_net_common.h contains common definitions across net tile implementations. */

/* REPAIR_PING_SZ is the sz of a ping packet for the repair protocol.
   Because pings are routed to the same port as shreds without any
   discriminant encoding, we have to use the packet sz to interpret the
   payload.  Note that any valid shred must be either FD_SHRED_MAX_SZ
   or FD_SHRED_MIN_SZ ie. will never be FD_REPAIR_PING_SZ.*/

#define REPAIR_PING_SZ (174UL)

#endif /* HEADER_fd_src_disco_net_fd_net_common_h */
