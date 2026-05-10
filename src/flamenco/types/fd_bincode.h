#ifndef HEADER_fd_src_flamenco_types_fd_bincode_h
#define HEADER_fd_src_flamenco_types_fd_bincode_h

#include "../../util/fd_util.h"

/* fd_w_u128 is a wrapped "uint128" type providing basic 128-bit
   unsigned int functionality to fd_types, even if the compile target
   does not natively support uint128. */

union __attribute__((packed)) fd_w_u128 {
  uchar uc[16];
  ulong ul[2];
# if FD_HAS_INT128
  uint128 ud;
# endif
};

typedef union fd_w_u128 fd_w_u128_t;

#endif /* HEADER_fd_src_flamenco_types_fd_bincode_h */
