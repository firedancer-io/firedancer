#include "fd_sysvar_instructions.h"
#include "../fd_runtime.h"
#include "../fd_system_ids.h"

static ulong
instructions_serialized_size( fd_txn_t const * txn ) {
  ushort instr_cnt = txn->instr_cnt;
  ulong  serialized_size = sizeof(ushort)                // num_instructions
                           + (sizeof(ushort)*instr_cnt); // instruction offsets

  for( ushort i=0; i<instr_cnt; i++ ) {
    ushort data_sz  = txn->instr[i].data_sz;
    ushort acct_cnt = txn->instr[i].acct_cnt;

    serialized_size += sizeof(ushort); // num_accounts;

    serialized_size += acct_cnt * (
      sizeof(uchar)               // flags (is_signer, is_writeable)
      + sizeof(fd_pubkey_t)       // pubkey
    );

    serialized_size += sizeof(fd_pubkey_t)  // program_id pubkey
        + sizeof(ushort)                    // instr_data_len;
        + data_sz;                          // instr_data;

  }

  serialized_size += sizeof(ushort); // current_instr_idx

  return serialized_size;
}

/* https://github.com/anza-xyz/agave/blob/v2.1.1/svm/src/account_loader.rs#L547-L576 */
void
fd_sysvar_instructions_serialize_account( fd_runtime_t *      runtime,
                                          fd_bank_t *         bank,
                                          fd_txn_in_t const * txn_in,
                                          fd_txn_out_t *      txn_out,
                                          ulong               txn_idx ) {
  fd_txn_t const * txn           = TXN( txn_in->txn );
  ulong            serialized_sz = instructions_serialized_size( txn );

  int index;
  int err = fd_runtime_get_account_with_key( txn_in,
                                             txn_out,
                                             &fd_sysvar_instructions_id,
                                             &index,
                                             fd_runtime_account_check_exists );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS && index==-1 ) ) {
    /* The way we use this, this should NEVER hit since the borrowed accounts should be set up
       before this is called, and this is only called if the sysvar instructions account is in
       the borrowed accounts list. */
    FD_LOG_ERR(( "Failed to view sysvar instructions borrowed account. It may not be included in the txn account keys." ));
  }

  fd_account_meta_t * meta = txn_out->accounts.metas[ txn_idx ];
  /* Agave sets up the borrowed account for the instructions sysvar to contain
     default values except for the data which is serialized into the account. */

  fd_memcpy( meta->owner, &fd_sysvar_owner_id, sizeof(fd_pubkey_t) );
  meta->lamports   = 0UL;
  meta->executable = 0;
  meta->dlen       = (uint)serialized_sz;

  runtime->accounts.starting_lamports[txn_idx] = 0UL;
  runtime->accounts.starting_dlen[txn_idx]     = serialized_sz;

  uchar * serialized_instructions = fd_account_data( meta );
  ulong offset = 0;

  // num_instructions
  ushort instr_cnt = txn->instr_cnt;
  FD_STORE( ushort, serialized_instructions + offset, instr_cnt);
  offset += sizeof(ushort);

  // instruction offsets
  uchar * serialized_instruction_offsets = serialized_instructions + offset;
  offset += (ushort)(sizeof(ushort) * instr_cnt);

  // serialize instructions
  for( ushort i=0; i<instr_cnt; ++i ) {
    // set the instruction offset
    FD_STORE( ushort, serialized_instruction_offsets, (ushort) offset );
    serialized_instruction_offsets += sizeof(ushort);

    fd_txn_instr_t const * instr = &txn->instr[i];

    // num_accounts
    FD_STORE( ushort, serialized_instructions + offset, instr->acct_cnt );
    offset += sizeof(ushort);

    uchar const * instr_accts = fd_txn_get_instr_accts( instr, txn_in->txn->payload );
    for( ushort j=0; j<instr->acct_cnt; j++ ) {
      uchar idx_in_txn          = instr_accts[j];
      uchar is_writable         = (uchar)fd_runtime_account_is_writable_idx( txn_in, txn_out, bank, idx_in_txn );
      uchar is_signer           = (uchar)fd_txn_is_signer( txn, idx_in_txn );
      uchar flags               = ((!!is_signer)*FD_INSTR_ACCT_FLAGS_IS_SIGNER) | ((!!is_writable)*FD_INSTR_ACCT_FLAGS_IS_WRITABLE);

      // flags
      FD_STORE( uchar, serialized_instructions + offset, flags );
      offset += sizeof(uchar);

      // pubkey
      FD_STORE( fd_pubkey_t, serialized_instructions + offset, txn_out->accounts.keys[ idx_in_txn ] );
      offset += sizeof(fd_pubkey_t);
    }

    // program_id_pubkey
    FD_STORE( fd_pubkey_t, serialized_instructions + offset, txn_out->accounts.keys[ instr->program_id ] );
    offset += sizeof(fd_pubkey_t);

    // instr_data_len
    FD_STORE( ushort, serialized_instructions + offset, instr->data_sz );
    offset += sizeof(ushort);

    // instr_data
    uchar const * instr_data = fd_txn_get_instr_data( instr, txn_in->txn->payload );
    fd_memcpy( serialized_instructions + offset, instr_data, instr->data_sz );
    offset += instr->data_sz;
  }

  FD_STORE( ushort, serialized_instructions + offset, 0 );
  offset += sizeof(ushort);
}

/* Stores the current instruction index in the instructions sysvar account.
   https://github.com/anza-xyz/solana-sdk/blob/instructions-sysvar%40v2.2.1/instructions-sysvar/src/lib.rs#L164-L167 */
void
fd_sysvar_instructions_update_current_instr_idx( fd_account_meta_t * meta,
                                                 ushort              current_instr_idx ) {
  /* Extra safety checks */
  if( FD_UNLIKELY( meta->dlen<sizeof(ushort) ) ) {
    return;
  }

  uchar * serialized_current_instr_idx = fd_account_data( meta ) + (meta->dlen - sizeof(ushort));
  FD_STORE( ushort, serialized_current_instr_idx, current_instr_idx );
}
