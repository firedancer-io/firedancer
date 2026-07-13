#ifndef HEADER_fd_src_waltz_ip_fd_iproute_h
#define HEADER_fd_src_waltz_ip_fd_iproute_h

#include "fd_fib4.h"

#define FD_IPROUTE_OP_UPSERT (1U) /* Replace exact dst/prefix/prio, otherwise insert */
#define FD_IPROUTE_OP_DELETE (2U)
#define FD_IPROUTE_OP_FLUSH  (3U)

/* fd_iproute_msg_t is the payload of UPSERT and DELETE operations */

struct fd_iproute_msg {
  fd_fib4_hop_t hop;
  uint          dst_addr;
  uint          prio;
  uint          table_id;
  uchar         op;
  uchar         prefix;
};

typedef struct fd_iproute_msg fd_iproute_msg_t;

FD_STATIC_ASSERT( sizeof(fd_iproute_msg_t)==32UL, iproute_msg_sz );

#endif /* HEADER_fd_src_waltz_ip_fd_iproute_h */
