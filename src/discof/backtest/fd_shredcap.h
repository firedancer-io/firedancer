#ifndef HEADER_fd_src_discof_backtest_fd_shredcap_h
#define HEADER_fd_src_discof_backtest_fd_shredcap_h

/* fd_shredcap.h provides C definitions for shredcap v0.2 file format
   bits. */

#include "../../util/fd_util_base.h"

#define FD_SHREDCAP_V0_IFNAME "shredcap0"

#define FD_SHREDCAP_TYPE_BANK_HASH_V0 (0x1u)

struct __attribute__((packed)) fd_shredcap_bank_hash_v0 {
  ulong slot;
  uchar bank_hash[32];
  ulong data_shred_cnt;
};
typedef struct fd_shredcap_bank_hash_v0 fd_shredcap_bank_hash_v0_t;

#endif /* HEADER_fd_src_discof_backtest_fd_shredcap_h */
