#include "fd_sysvar_instructions.h"
#include "../fd_borrowed_account.h"
#include "../fd_system_ids.h"

static ulong
instructions_serialized_size( fd_instr_info_t const *   instrs,
                              ushort                    instrs_cnt ) {
  ulong serialized_size = 0;

  serialized_size += sizeof(ushort)       // num_instructions
    + (sizeof(ushort) * instrs_cnt);      // instruction offsets

  for ( ushort i = 0; i < instrs_cnt; ++i ) {
    fd_instr_info_t const * instr = &instrs[i];

    serialized_size += sizeof(ushort); // num_accounts;

    serialized_size += instr->acct_cnt * (
      sizeof(uchar)               // flags (is_signer, is_writeable)
      + sizeof(fd_pubkey_t)         // pubkey
    );

    serialized_size += sizeof(fd_pubkey_t)  // program_id pubkey
        + sizeof(ushort)                    // instr_data_len;
        + instr->data_sz;                   // instr_data;

  }

  serialized_size += sizeof(ushort); // current_instr_idx

  return serialized_size;
}

/* https://github.com/anza-xyz/agave/blob/v2.1.1/svm/src/account_loader.rs#L547-L576 */
void
fd_sysvar_instructions_serialize_account( fd_exec_txn_ctx_t *      txn_ctx,
                                          fd_instr_info_t const *  instrs,
                                          ushort                   instrs_cnt ) {
  ulong serialized_sz = instructions_serialized_size( instrs, instrs_cnt );

  fd_txn_account_t * rec = NULL;
  int err = fd_exec_txn_ctx_get_account_with_key( txn_ctx,
                                                  &fd_sysvar_instructions_id,
                                                  &rec,
                                                  fd_txn_account_check_exists );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS && rec==NULL ) ) {
    /* The way we use this, this should NEVER hit since the borrowed accounts should be set up
       before this is called, and this is only called if the sysvar instructions account is in
       the borrowed accounts list. */
    FD_LOG_ERR(( "Failed to view sysvar instructions borrowed account. It may not be included in the txn account keys." ));
  }

  /* This stays within the FD spad allocation bounds because...
     1. Case 1: rec->meta!=NULL
        - rec->meta was set up in `fd_executor_setup_accounts_for_txn()` and data was allocated from the spad
        - No need to allocate meta and data here
     2. Case 2: rec->meta==NULL
        - `fd_executor_setup_accounts_for_txn()` did not make an spad allocation for this account
        - spad memory is sized out for allocations for 128 (max number) accounts
        - sizeof(fd_account_meta_t) + serialized_sz will always be less than FD_ACC_TOT_SZ_MAX
        - at most 127 accounts could be using spad memory right now, so this allocation is safe */
  if( !fd_txn_account_is_mutable( rec ) ) {
    uchar *             mem  = fd_spad_alloc( txn_ctx->spad, FD_TXN_ACCOUNT_ALIGN, sizeof(fd_account_meta_t) + serialized_sz );
    fd_account_meta_t * meta = (fd_account_meta_t *)mem;
    fd_txn_account_t *  acc  = fd_txn_account_new( rec, &fd_sysvar_instructions_id, meta, 1 );
    if( FD_UNLIKELY( !acc ) ) {
      FD_LOG_CRIT(( "Failed to join txn account" ));
    }
  }

  /* Agave sets up the borrowed account for the instructions sysvar to contain
     default values except for the data which is serialized into the account. */

  fd_txn_account_set_owner( rec, &fd_sysvar_owner_id );
  fd_txn_account_set_lamports( rec, 0UL );
  fd_txn_account_set_executable( rec, 0 );
  fd_txn_account_set_data_len( rec, serialized_sz );
  rec->starting_lamports = 0UL;

  uchar * serialized_instructions = fd_txn_account_get_data_mut( rec );
  ulong offset = 0;

  // TODO: do we needs bounds checking?
  // num_instructions
  FD_STORE( ushort, serialized_instructions + offset, instrs_cnt);
  offset += sizeof(ushort);

  // instruction offsets
  uchar * serialized_instruction_offsets = serialized_instructions + offset;
  offset += (ushort)(sizeof(ushort) * instrs_cnt);

  // serialize instructions
  for( ushort i = 0; i < instrs_cnt; ++i ) {
    // set the instruction offset
    FD_STORE( ushort, serialized_instruction_offsets, (ushort) offset );
    serialized_instruction_offsets += sizeof(ushort);

    fd_instr_info_t const * instr = &instrs[i];

    // num_accounts
    FD_STORE( ushort, serialized_instructions + offset, instr->acct_cnt );
    offset += sizeof(ushort);

    for ( ushort j = 0; j < instr->acct_cnt; j++ ) {
      // flags
      FD_STORE( uchar, serialized_instructions + offset, fd_instr_get_acc_flags( instr, j ) );
      offset += sizeof(uchar);

      // pubkey
      ushort idx_in_txn = instr->accounts[j].index_in_transaction;
      FD_STORE( fd_pubkey_t, serialized_instructions + offset, txn_ctx->account_keys[ idx_in_txn ] );
      offset += sizeof(fd_pubkey_t);
    }

    // program_id_pubkey
    FD_STORE( fd_pubkey_t, serialized_instructions + offset, txn_ctx->account_keys[ instr->program_id ] );
    offset += sizeof(fd_pubkey_t);

    // instr_data_len
    FD_STORE( ushort, serialized_instructions + offset, instr->data_sz );
    offset += sizeof(ushort);

    // instr_data
    fd_memcpy( serialized_instructions + offset, instr->data, instr->data_sz );
    offset += instr->data_sz;
  }

  //
  FD_STORE( ushort, serialized_instructions + offset, 0 );
  offset += sizeof(ushort);
}

/* Stores the current instruction index in the instructions sysvar account.
   https://github.com/anza-xyz/solana-sdk/blob/instructions-sysvar%40v2.2.1/instructions-sysvar/src/lib.rs#L164-L167 */
void
fd_sysvar_instructions_update_current_instr_idx( fd_txn_account_t * rec,
                                                 ushort             current_instr_idx ) {
  /* Extra safety checks */
  if( FD_UNLIKELY( fd_txn_account_get_data_len( rec )<sizeof(ushort) ) ) {
    return;
  }

  uchar * serialized_current_instr_idx = fd_txn_account_get_data_mut( rec ) + (fd_txn_account_get_data_len( rec ) - sizeof(ushort));
  FD_STORE( ushort, serialized_current_instr_idx, current_instr_idx );
}
