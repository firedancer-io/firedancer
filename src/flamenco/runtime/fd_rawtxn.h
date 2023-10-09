#ifndef HEADER_fd_src_flamenco_runtime_fd_rawtxn_h
#define HEADER_fd_src_flamenco_runtime_fd_rawtxn_h

#include "../../util/fd_util_base.h"

struct fd_rawtxn_b {
  /* Pointer to txn in local wksp */
  void * raw;

  /* Size of txn */
  ushort txn_sz;
};
typedef struct fd_rawtxn_b fd_rawtxn_b_t;

#endif /* HEADER_fd_src_flamenco_runtime_fd_rawtxn_h */
