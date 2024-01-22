#ifndef HEADER_fd_src_util_net_fd_igmp_h
#define HEADER_fd_src_util_net_fd_igmp_h

#include <string.h>

#include "fd_ip4.h"

/* FIXME: IGMP CRASH COURSE HERE */

/* FD_IGMP_TYPE_{QUERY,V1_REPORT,V2_REPORT,V2_LEAVE}:

   QUERY     - IGMP is a query (if to a specific ip4, specific query, if to
               224.0.0.1, general query) from LAN switch regarding host's
               mcast join status
   V1_REPORT - IGMP is a V1 report to router indicating to join / remain
               in mcast group (V1 IGMP host)
   V2_REPORT - IGMP is a V2 report to router indicating to join / remain
               in mcast group (V1 IGMP host)
   LEAVE     - IGMP is a V2 report to router indicating to leave mcast
               group (V2 IGMP host) */

#define FD_IGMP_TYPE_QUERY     ((uchar)0x11)
#define FD_IGMP_TYPE_V1_REPORT ((uchar)0x12)
#define FD_IGMP_TYPE_V2_REPORT ((uchar)0x16)
#define FD_IGMP_TYPE_V2_LEAVE  ((uchar)0x17)

union fd_igmp {
  struct {
    uchar  type;  /* IGMP type */
    uchar  resp;  /* v1 - 0 on send, ignore on recv, v2 - 0 on send, required response time in 0.1 s increments on recv */
    ushort check; /* IGMP checksum ("invariant" order) */
    uint   group; /* IGMP group (IP4 mcast addr), technically net order but all APIs below work with this directly */
  };
  uint u[2]; /* Used for checksum calcs */
};

typedef union fd_igmp fd_igmp_t;

/* FIXME: CONSIDER AN OVERALL IGMP PRETTY PRINTER? */

struct fd_ip4_igmp {
  fd_ip4_hdr_t ip4[1];
  uchar        opt[4];
  fd_igmp_t    igmp[1];
};

typedef struct fd_ip4_igmp fd_ip4_igmp_t;

FD_PROTOTYPES_BEGIN

/* fd_igmp_check is used for igmp check field computation and
   validation.  igmp points to the first byte a memory region containing
   an igmp message.  If the message has no checksum (check==0), this
   returns the value to use for check.  If the message has a checksum
   (check!=0), this returns 0 if message has a valid checksum or
   non-zero if not.  Reasonably fast O(1). */

FD_FN_PURE static inline ushort
fd_igmp_check( fd_igmp_t const * igmp ) {
  uint const * u = igmp->u;
  ulong        c = (ulong)u[0] + (ulong)u[1];
  c  = ( c>>32            ) +
       ((c>>16) & 0xffffUL) +
       ( c      & 0xffffUL);
  c += ( c>>16            );
  return (ushort)~c;
}

/* fd_ip4_igmp populates the memory region of size sizeof(fd_ip4_igmp_t)
   and whose first byte is pointed to by the non-NULL _msg with a well
   formed ip4 / igmp message.  The message is addressed as from
   ip4_saddr (assumed valid ip4 ucast on subnet) and to ip4_daddr
   (assumed valid ip4 mcast).  It be an igmp of the given type, with the
   given response and to the given igmp_group (usually igmp_group should
   be ip4_daddr).  Returns _msg. */

static inline fd_ip4_igmp_t *
fd_ip4_igmp( void * _msg,
             uint   ip4_saddr,
             uint   ip4_daddr,
             uchar  igmp_type,
             uchar  igmp_resp,
             uint   igmp_group ) {
  fd_ip4_igmp_t * msg = (fd_ip4_igmp_t *)_msg;

  msg->ip4->verihl       = FD_IP4_VERIHL(6U,4U);
  msg->ip4->tos          = FD_IP4_HDR_TOS_PREC_INTERNETCONTROL;
  msg->ip4->net_tot_len  = fd_ushort_bswap( (ushort)32 );
  msg->ip4->net_id       = (ushort)0;
  msg->ip4->net_frag_off = fd_ushort_bswap( FD_IP4_HDR_FRAG_OFF_DF );
  msg->ip4->ttl          = (uchar)1;
  msg->ip4->protocol     = FD_IP4_HDR_PROTOCOL_IGMP;
  msg->ip4->check        = (ushort)0; /* Computation completed below */

  memcpy( msg->ip4->saddr_c, &ip4_saddr, 4U );
  memcpy( msg->ip4->daddr_c, &ip4_daddr, 4U );

  msg->opt[0]            = FD_IP4_OPT_RA;
  msg->opt[1]            = (uchar)4;
  msg->opt[2]            = (uchar)0;
  msg->opt[3]            = (uchar)0;

  msg->igmp->type        = igmp_type;
  msg->igmp->resp        = igmp_resp;
  msg->igmp->check       = (ushort)0; /* Computation completed below */
  msg->igmp->group       = igmp_group;

  msg->ip4->check        = fd_ip4_hdr_check( msg->ip4  );
  msg->igmp->check       = fd_igmp_check   ( msg->igmp );

  return msg;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_net_fd_igmp_h */
