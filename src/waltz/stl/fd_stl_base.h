#ifndef HEADER_stl_base_h
#define HEADER_stl_base_h

#include "../../util/fd_util_base.h"
#include "../../util/log/fd_log.h"

/* Common structures **************************************************/

/* stl_net_ctx_t is the endpoint of the peer identified by IPv4
   address and UDP port.  Supports IPv4 via IPv4-mapped IPv6
   addresses (RFC 4291). */

typedef struct fd_stl fd_stl_t;
typedef struct fd_stl_conn fd_stl_conn_t;

union stl_net_ctx {
  struct __attribute__((packed)) stl_net_ctx_parts {
    uint  ip4;
    ushort port;
    ushort padding; /* WILL BE CLOBBERED */
  } parts;

  ulong b;
};

#define FD_STL_NET_CTX_T_EMPTY {.b = 0UL}

// struct __attribute__((packed)) stl_net_ctx {
//   uint  ip4; /* in host byte order */
//   ushort port;
// };

typedef union stl_net_ctx stl_net_ctx_t;

#endif /* HEADER_stl_base_h */
