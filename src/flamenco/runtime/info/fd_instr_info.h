#ifndef HEADER_fd_src_flamenco_runtime_info_fd_instr_info_h
#define HEADER_fd_src_flamenco_runtime_info_fd_instr_info_h

#include "../../fd_flamenco_base.h"
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

  uchar                 acct_txn_idxs[256];
  uchar                 acct_flags[256];
  fd_pubkey_t           acct_pubkeys[256];
  uchar                 is_duplicate[256];

  fd_borrowed_account_t * borrowed_accounts[256];

  ulong starting_lamports;
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

ulong
fd_instr_info_sum_account_lamports( fd_instr_info_t const * instr );

FD_FN_PURE static inline uint
fd_instr_acc_is_writable_idx( fd_instr_info_t const * instr,
                              uchar                   idx ) {
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

FD_FN_PURE static inline uint
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
