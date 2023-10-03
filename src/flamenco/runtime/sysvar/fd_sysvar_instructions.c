#include "fd_sysvar_instructions.h"
#include "../fd_acc_mgr.h"
#include "../fd_account.h"
#include "../fd_runtime.h"

static ulong
instructions_serialized_size( fd_instr_t const *  instrs,
                              ushort              instrs_cnt ) {
  ulong serialized_size = 0;

  serialized_size += sizeof(ushort)       // num_instructions
    + (sizeof(ushort) * instrs_cnt);      // instruction offsets

  for ( ushort i = 0; i < instrs_cnt; ++i ) {
    fd_instr_t const * instr = &instrs[i];

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
fd_sysvar_instructions_serialize_account( fd_global_ctx_t *   global,
                                          fd_instr_t const *  instrs,
                                          ushort              instrs_cnt ) {
  ulong serialized_sz = instructions_serialized_size( instrs, instrs_cnt );

  FD_BORROWED_ACCOUNT_DECL(rec);
  int err = fd_acc_mgr_modify(global->acc_mgr, global->funk_txn, (fd_pubkey_t const *)global->sysvar_instructions, 1, serialized_sz, rec);
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) )
    return FD_ACC_MGR_ERR_READ_FAILED;

  fd_memcpy( rec->meta->info.owner, global->sysvar_owner, sizeof(fd_pubkey_t) );
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

    fd_instr_t const * instr = &instrs[i];

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

  FD_LOG_DEBUG(( "SYSVAR INSTR SERIALIZE %u", offset ));
  FD_LOG_HEXDUMP_DEBUG(( "SYSVAR INSTR SERIALIZE dump", serialized_instructions, serialized_sz ));

  return FD_ACC_MGR_SUCCESS;
}

int
fd_sysvar_instructions_cleanup_account( fd_global_ctx_t * global ) {
  fd_funk_rec_t * acc_data_rec = NULL;
  int modify_err = FD_ACC_MGR_SUCCESS;

  // This uses the raw interface since we are also willing to kill dead accounts here...
  void * raw_acc_data = fd_acc_mgr_modify_raw( global->acc_mgr, global->funk_txn, (fd_pubkey_t const *)global->sysvar_instructions, 0, 0, NULL, &acc_data_rec, &modify_err );
  if( FD_UNLIKELY( NULL == raw_acc_data ) )
    return FD_ACC_MGR_ERR_READ_FAILED;

  int res = fd_funk_rec_remove(global->funk, acc_data_rec, 1);
  if( res != FD_FUNK_SUCCESS )
    return FD_ACC_MGR_ERR_WRITE_FAILED;

  return FD_ACC_MGR_SUCCESS;
}

int
fd_sysvar_instructions_update_current_instr_idx( fd_global_ctx_t *  global,
                                         ushort             current_instr_idx ) {
  FD_BORROWED_ACCOUNT_DECL(rec);
  int err = fd_acc_mgr_modify(global->acc_mgr, global->funk_txn, (fd_pubkey_t const *)global->sysvar_instructions, 0, 0, rec);
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) )
    return FD_ACC_MGR_ERR_READ_FAILED;

  uchar * serialized_current_instr_idx = rec->data + (rec->meta->dlen - sizeof(ushort));
  FD_STORE( ushort, serialized_current_instr_idx, current_instr_idx );

  return FD_ACC_MGR_SUCCESS;
}
