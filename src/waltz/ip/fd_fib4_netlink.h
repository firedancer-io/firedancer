#ifndef HEADER_fd_src_waltz_ip_fd_fib4_netlink_h
#define HEADER_fd_src_waltz_ip_fd_fib4_netlink_h

/* fd_fib4_netlink.h provides APIs for importing routes from Linux netlink. */

#if defined(__linux__)

#include "fd_fib4.h"
#include "fd_netlink1.h"

/* FD_FIB_NETLINK_* gives error codes for netlink import operations. */

#define FD_FIB_NETLINK_SUCCESS   (0) /* success */
#define FD_FIB_NETLINK_ERR_OOPS  (1) /* unexpected internal error */
#define FD_FIB_NETLINK_ERR_IO    (2) /* netlink I/O error */
#define FD_FIB_NETLINK_ERR_INTR  (3) /* netlink read was interrupted */
#define FD_FIB_NETLINK_ERR_SPACE (4) /* fib is too small */

FD_PROTOTYPES_BEGIN

/* fd_fib4_netlink_load_table mirrors a route table from netlink to fib.
   The route table is requested via RTM_GETROUTE,NLM_F_REQUEST|NLM_F_DUMP.
   table_id is in [0,2^31).  table_id is typically RT_TABLE_LOCAL or
   RT_TABLE_MAIN.  These are 255 and 254 respectively on Linux.  Assumes
   netlink has a usable rtnetlink socket.  fib is a writable join to a fib4
   object.  Logs to debug level for diagnostics and warning level in case
   of error.

   Returns FD_FIB4_NETLINK_SUCCESS on success and leaves netlink ready
   for the next request.  fib is not guaranteed to mirror the route
   table precisely even on success.  (May turn routes with unsupported
   type or attribute into blackhole routes.)

   On failure, leaves a route table that blackholes all packets.
   Return values FD_FIB4_NETLINK_ERR_{...} in case of error as follows:

     OOPS:  Internal error (bug) occurred.
     IO:    Unrecoverable send/recv error or failed to parse MULTIPART msg.
     INTR:  Concurrent write overran read of the routing table.  Try again.
     SPACE: Routing table is too small to mirror the requested table.

   On return, the netlink socket is ready for the next request (even in
   case of error) unless the error is FD_FIB_NETLINK_ERR_IO. */

int
fd_fib4_netlink_load_table( fd_fib4_t *    fib,
                            fd_netlink_t * netlink,
                            uint           table_id );

FD_FN_CONST char const *
fd_fib4_netlink_strerror( int err );

FD_PROTOTYPES_END

#endif /* defined(__linux__) */

#endif /* HEADER_fd_src_waltz_ip_fd_fib4_netlink_h */
