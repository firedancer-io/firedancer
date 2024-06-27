#ifndef HEADER_fd_src_flamenco_runtime_fd_account_old_h
#define HEADER_fd_src_flamenco_runtime_fd_account_old_h

#include "../../ballet/txn/fd_txn.h"
#include "program/fd_program_util.h"
#include "sysvar/fd_sysvar_rent.h"
#include "fd_system_ids.h"
#include "fd_runtime.h"
#include <assert.h>

/* Represents the lamport balance associated with an account. */
typedef ulong fd_acc_lamports_t;

// Once these settle out, we will switch almost everything to not be inlined

static inline void *
fd_account_get_data(fd_account_meta_t * m) {
  return ((char *) m) + m->hlen;
}

// TODO: Confirm if the program id pubkey actually corresponds to the last program id
// Returns true if the owner of this account is the current `InstructionContext`s last program (instruction wide)
static inline
int fd_account_is_owned_by_current_program2(const fd_exec_instr_ctx_t *ctx, const fd_account_meta_t * acct, FD_FN_UNUSED int *err) {
  return memcmp( &ctx->instr->program_id_pubkey, acct->info.owner, sizeof(fd_pubkey_t) ) == 0;
}

static inline
int fd_account_is_writable_idx( fd_txn_t const * txn_descriptor,
                                fd_pubkey_t const * accounts,
                                uchar program_id,
                                int idx ) {
  int acct_addr_cnt = txn_descriptor->acct_addr_cnt;
  if (txn_descriptor->transaction_version == FD_TXN_V0) {
    acct_addr_cnt += txn_descriptor->addr_table_adtl_cnt;
  }

  if (idx == acct_addr_cnt)
    return 0;

  // You just cannot write to a program...
  if (idx == program_id)
    return 0;

  if (fd_pubkey_is_builtin_program(&accounts[idx]) || fd_pubkey_is_sysvar_id(&accounts[idx])) {
    return 0;
  }

  return fd_txn_is_writable(txn_descriptor, idx);
}

#endif
