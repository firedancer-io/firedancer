#include "fd_sysvar_instructions.h"
#include "../fd_acc_mgr.h"
#include "../fd_account.h"
#include "../fd_runtime.h"
#include "../fd_system_ids.h"

static ulong
instructions_serialized_size( fd_instr_info_t const *  instrs,
                              ushort              instrs_cnt ) {
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

int
fd_sysvar_instructions_serialize_account( fd_exec_txn_ctx_t *     txn_ctx,
                                          fd_instr_info_t const * instrs,
                                          ushort                  instrs_cnt ) {
  ulong serialized_sz = instructions_serialized_size( instrs, instrs_cnt );

  fd_borrowed_account_t * rec = NULL;
  int err = fd_txn_borrowed_account_view( txn_ctx, &fd_sysvar_instructions_id, &rec );
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS && rec == NULL ) )
    return FD_ACC_MGR_ERR_READ_FAILED;
  
  fd_account_meta_t * meta = fd_valloc_malloc( txn_ctx->valloc, FD_ACCOUNT_META_ALIGN, sizeof(fd_account_meta_t) + serialized_sz );
  void * data = (uchar *)meta + sizeof(fd_account_meta_t);

  rec->const_meta = rec->meta = meta;
  rec->const_data = rec->data = data;

  memcpy( rec->meta->info.owner, fd_sysvar_owner_id.key, sizeof(fd_pubkey_t) );
  rec->meta->info.lamports = 0; // TODO: This cannot be right... well, it gets destroyed almost instantly...
  rec->meta->info.executable = 0;
  rec->meta->info.rent_epoch = 0;
  rec->meta->dlen = serialized_sz;

  uchar * serialized_instructions = rec->data;
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
      FD_STORE( uchar, serialized_instructions + offset, instr->acct_flags[j] );
      offset += sizeof(uchar);

      // pubkey
      FD_STORE( fd_pubkey_t, serialized_instructions + offset, instr->acct_pubkeys[j] );
      offset += sizeof(fd_pubkey_t);
    }

    // program_id_pubkey
    FD_STORE( fd_pubkey_t, serialized_instructions + offset, instr->program_id_pubkey );
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

  return FD_ACC_MGR_SUCCESS;
}

int
fd_sysvar_instructions_cleanup_account( fd_exec_txn_ctx_t *  txn_ctx ) {
  fd_borrowed_account_t * rec = NULL;
  int err = fd_txn_borrowed_account_modify( txn_ctx, &fd_sysvar_instructions_id, 0, &rec );
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) )
    return FD_ACC_MGR_ERR_READ_FAILED;

  fd_valloc_free( txn_ctx->valloc, rec->meta );
  rec->const_meta = rec->meta = NULL;
  rec->const_data = rec->data = NULL;

  return FD_ACC_MGR_SUCCESS;
}

int
fd_sysvar_instructions_update_current_instr_idx( fd_exec_txn_ctx_t *  txn_ctx,
                                                 ushort             current_instr_idx ) {
  fd_borrowed_account_t * rec = NULL;
  int err = fd_txn_borrowed_account_modify( txn_ctx, &fd_sysvar_instructions_id, 0, &rec );
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) )
    return FD_ACC_MGR_ERR_READ_FAILED;

  uchar * serialized_current_instr_idx = rec->data + (rec->meta->dlen - sizeof(ushort));
  FD_STORE( ushort, serialized_current_instr_idx, current_instr_idx );

  return FD_ACC_MGR_SUCCESS;
}
