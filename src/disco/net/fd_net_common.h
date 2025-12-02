#ifndef HEADER_fd_src_disco_net_fd_net_common_h
#define HEADER_fd_src_disco_net_fd_net_common_h

/* fd_net_common.h contains common definitions across net tile implementations. */

/* REPAIR_PING_SZ is the sz of a ping packet for the repair protocol.
   Because pings are routed to the same port as shreds without any
   discriminant encoding, we have to use the packet sz to interpret the
   payload.  Note that any valid shred must be either FD_SHRED_MAX_SZ
   or FD_SHRED_MIN_SZ ie. will never be FD_REPAIR_PING_SZ.*/

#define REPAIR_PING_SZ (174UL)

/* FD_NET_SUCCESS, FD_NET_ERR_* are error codes returned by network
   header validation APIs.  SUCCESS is zero, ERR_* are positive. */

#define FD_NET_SUCCESS                 (0)  /* Validation successful */
#define FD_NET_ERR_INVAL_IP4_HDR       (1)  /* Invalid IP4 header */
#define FD_NET_ERR_INVAL_UDP_HDR       (2)  /* Invalid UDP header */
#define FD_NET_ERR_INVAL_GRE_HDR       (3)  /* Invalid GRE header */
#define FD_NET_ERR_DISALLOW_IP_PROTO   (4)  /* Disallowed IP protocol */
#define FD_NET_ERR_DISALLOW_ETH_TYPE   (5)  /* Disallowed Ethernet net type */

/* FD_IP4_HDR_PROTO_MASK_* are bitmasks of allowed IP protocols for validation */

#define FD_IP4_HDR_PROTO_MASK_UDP  fd_ulong_mask_bit( FD_IP4_HDR_PROTOCOL_UDP )
#define FD_IP4_HDR_PROTO_MASK_GRE  fd_ulong_mask_bit( FD_IP4_HDR_PROTOCOL_GRE )
#define FD_IP4_HDR_PROTO_MASK_BOTH (FD_IP4_HDR_PROTO_MASK_UDP | FD_IP4_HDR_PROTO_MASK_GRE)

#endif /* HEADER_fd_src_disco_net_fd_net_common_h */
