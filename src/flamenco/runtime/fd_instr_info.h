#ifndef HEADER_fd_src_flamenco_runtime_fd_instr_info_h
#define HEADER_fd_src_flamenco_runtime_fd_instr_info_h

#include "../../util/fd_util_base.h"

#include "../types/fd_types.h"

#include "fd_borrowed_account.h"


struct fd_instr_info {
  uchar                 program_id;
  ushort                data_sz;
  ushort                acct_cnt;

  uchar *               data;
  fd_pubkey_t           program_id_pubkey;

  uchar                 acct_txn_idxs[128];
  uchar                 acct_flags[128];
  fd_pubkey_t           acct_pubkeys[128];

  fd_borrowed_account_t * borrowed_accounts[128];
};
typedef struct fd_instr_info fd_instr_info_t;

#endif /* HEADER_fd_src_flamenco_runtime_fd_instr_info_h */
