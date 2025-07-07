#ifndef HEADER_fd_src_util_net_fd_gre_h
#define HEADER_fd_src_util_net_fd_gre_h

#include "../bits/fd_bits.h"

#define FD_GRE_HDR_FLG_VER_BASIC ((ushort)0x0000)

union fd_gre_hdr {
  struct {
    ushort flags_version; /* should be FD_GRE_HDR_FLG_VER_BASIC in net order */
    ushort protocol; /* should be FD_ETH_HDR_TYPE_IP in net order */
  };
  uchar uc[4];
};

typedef union fd_gre_hdr fd_gre_hdr_t;

#endif  /* HEADER_fd_src_util_net_fd_gre_h */
