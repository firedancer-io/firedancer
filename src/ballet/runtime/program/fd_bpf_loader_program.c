#include "fd_bpf_loader_program.h"

#include "../../base58/fd_base58.h"
#include "../../../util/bits/fd_sat.h"

int fd_executor_bpf_loader_program_execute_instruction( instruction_ctx_t ctx ) {
  /* Deserialize the Stake instruction */
  uchar * data            = (uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->data_off; 

  fd_bpf_loader_program_instruction_t instruction;
  fd_bpf_loader_program_instruction_new( &instruction );
  fd_bincode_decode_ctx_t decode_ctx;
  decode_ctx.data = data;
  decode_ctx.dataend = &data[ctx.instr->data_sz];
  decode_ctx.allocf = ctx.global->allocf;
  decode_ctx.allocf_arg = ctx.global->allocf_arg;

  if( fd_bpf_loader_program_instruction_decode( &instruction, &decode_ctx ) ) {
    FD_LOG_WARNING(("fd_bpf_loader_program_instruction_decode failed"));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  if( ctx.instr->acct_cnt < 1 ) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }

  uchar * instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
  fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);

  /* Check that Instruction Account 0 is a signer */
  if(instr_acc_idxs[0] >= ctx.txn_ctx->txn_descriptor->signature_cnt) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

   /* FIXME: will need to actually find last program_acct in this instruction but practically no one does this. Yet another
       area where there seems to be a lot of overhead... See solana_runtime::Accounts::load_transaction_accounts */
  fd_pubkey_t * bpf_loader_acc = &txn_accs[ctx.txn_ctx->txn_descriptor->acct_addr_cnt - 1];
  if ( memcmp( bpf_loader_acc, ctx.global->solana_bpf_loader_program_with_jit, sizeof(fd_pubkey_t) ) != 0 ) {
    return FD_EXECUTOR_INSTR_ERR_EXECUTABLE_MODIFIED;
  }

  fd_pubkey_t * program_acc = &txn_accs[instr_acc_idxs[0]];
  fd_account_meta_t program_acc_metadata;
  int read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, program_acc, &program_acc_metadata );
  if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "failed to read account metadata" ));
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  if ( memcmp(program_acc_metadata.info.owner, bpf_loader_acc, sizeof(fd_pubkey_t) ) != 0 ) {
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
  }

  if( fd_bpf_loader_program_instruction_is_write( &instruction ) ) {
    ulong write_end = fd_ulong_sat_add( instruction.inner.write.offset, instruction.inner.write.bytes_len );
    if( program_acc_metadata.dlen < write_end ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    }

    /* Read the current data in the account */
    uchar * program_acc_data = (uchar *)(ctx.global->allocf)(ctx.global->allocf_arg, 8UL, program_acc_metadata.dlen);
    read_result = fd_acc_mgr_get_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, program_acc, (uchar*)program_acc_data, sizeof(fd_account_meta_t), program_acc_metadata.dlen );
    if ( read_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to read account data" ));
      return read_result;
    }

    fd_memcpy( program_acc_data + instruction.inner.write.offset, instruction.inner.write.bytes, instruction.inner.write.bytes_len );

    int write_result = fd_acc_mgr_write_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, program_acc, &program_acc_metadata, sizeof(program_acc_metadata), program_acc_data, program_acc_metadata.dlen, 0 );
    if ( write_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to write account data" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }
    fd_acc_mgr_update_hash ( ctx.global->acc_mgr, &program_acc_metadata, ctx.global->funk_txn, ctx.global->bank.solana_bank.slot, program_acc, program_acc_data, program_acc_metadata.dlen );

    return FD_EXECUTOR_INSTR_SUCCESS;
  } else if( fd_bpf_loader_program_instruction_is_finalize( &instruction ) ) {
    // TODO: check for rent exemption
    // TODO: check for writable

    fd_acc_mgr_set_metadata(ctx.global->acc_mgr, ctx.global->funk_txn, ctx.global->bank.solana_bank.slot, program_acc, &program_acc_metadata);

    return FD_EXECUTOR_INSTR_SUCCESS;
  } else {
    FD_LOG_WARNING(( "unsupported bpf loader program instruction: discriminant: %d", instruction.discriminant ));
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }
}