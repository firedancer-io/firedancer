#ifndef HEADER_fd_src_flamenco_runtime_info_fd_instr_info_h
#define HEADER_fd_src_flamenco_runtime_info_fd_instr_info_h

#include "../../../util/fd_util_base.h"

#include "../../types/fd_types.h"

#include "../fd_borrowed_account.h"
#include "../fd_rawtxn.h"


#define FD_INSTR_ACCT_FLAGS_IS_SIGNER   (0x01)
#define FD_INSTR_ACCT_FLAGS_IS_WRITABLE (0x02)

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

FD_PROTOTYPES_BEGIN

void
fd_convert_txn_instr_to_instr( fd_txn_t const *        txn_descriptor,
                               fd_rawtxn_b_t const *   txn_raw,
                               fd_txn_instr_t const *  txn_instr,
                               fd_pubkey_t const *     accounts,
                               fd_borrowed_account_t * borrowed_accounts,
                               fd_instr_info_t *       instr );

static inline uint
fd_instr_acc_is_writable_idx(fd_instr_info_t const * instr, uchar idx) {
  return !!(instr->acct_flags[idx] & FD_INSTR_ACCT_FLAGS_IS_WRITABLE);
}

static inline uint
fd_instr_acc_is_writable(fd_instr_info_t const * instr, fd_pubkey_t const * acc) {
  for( uchar i = 0; i < instr->acct_cnt; i++ ) {
    if( memcmp( &instr->acct_pubkeys[i], acc, sizeof( fd_pubkey_t ) )==0 ) {
      return fd_instr_acc_is_writable_idx( instr, i );
    }
  }

  return 0;
}

static inline uint
fd_instr_acc_is_signer_idx(fd_instr_info_t const * instr, uchar idx) {
  return !!(instr->acct_flags[idx] & FD_INSTR_ACCT_FLAGS_IS_SIGNER);
}

static inline uint
fd_instr_acc_is_signer(fd_instr_info_t const * instr, fd_pubkey_t const * acc) {
  for( uchar i = 0; i < instr->acct_cnt; i++ ) {
    if( memcmp( &instr->acct_pubkeys[i], acc, sizeof( fd_pubkey_t ) )==0 ) {
      return fd_instr_acc_is_signer_idx( instr, i );
    }
  }

  return 0;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_info_fd_instr_info_h */
