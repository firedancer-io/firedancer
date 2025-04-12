#ifndef HEADER_fd_src_waltz_snp_fd_snp_sesh_h
#define HEADER_fd_src_waltz_snp_fd_snp_sesh_h

#include "fd_snp_common.h"

struct fd_snp_sesh {
  ulong session_id; /* primary key */
  ulong socket_addr;
  int server; /* bool */
  ulong next;

  ushort            net_id;
  fd_ip4_udp_hdrs_t net_hdr[1];
};

typedef struct fd_snp_sesh fd_snp_sesh_t;

#endif
