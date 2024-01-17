#ifndef HEADER_fd_src_flamenco_runtime_info_fd_instr_info_h
#define HEADER_fd_src_flamenco_runtime_info_fd_instr_info_h

#include "../../../util/fd_util_base.h"
#include "../../types/fd_types.h"
#include "../fd_borrowed_account.h"


#define FD_INSTR_ACCT_FLAGS_IS_SIGNER   (0x01U)
#define FD_INSTR_ACCT_FLAGS_IS_WRITABLE (0x02U)

struct fd_instr_info {
  uchar                 program_id;
  ushort                data_sz;
  ushort                acct_cnt;

  uchar *               data;
  fd_pubkey_t           program_id_pubkey;

  uchar                 acct_flags[128];
  fd_pubkey_t           acct_pubkeys[128];

  fd_borrowed_account_t * borrowed_accounts[128];
};

typedef struct fd_instr_info fd_instr_info_t;

FD_PROTOTYPES_BEGIN

FD_FN_PURE static inline uint
fd_instr_acc_is_writable_idx( fd_instr_info_t const * instr,
                              uchar                   idx ) {
  return !!(instr->acct_flags[idx] & FD_INSTR_ACCT_FLAGS_IS_WRITABLE);
}

FD_FN_PURE static inline uint
fd_instr_acc_is_signer_idx(fd_instr_info_t const * instr, uchar idx) {
  return !!(instr->acct_flags[idx] & FD_INSTR_ACCT_FLAGS_IS_SIGNER);
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_info_fd_instr_info_h */
