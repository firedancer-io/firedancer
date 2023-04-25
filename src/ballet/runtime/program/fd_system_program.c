#include "../fd_executor.h"
#include "fd_system_program.h"
#include "../fd_acc_mgr.h"
#include "../fd_runtime.h"

int transfer(
    ulong requested_lamports,
    instruction_ctx_t ctx
) {
    /* Pull out sender (acc idx 0) and recipient (acc idx 1) */
    uchar * instr_acc_idxs = ((uchar *)ctx.txn_raw->raw + ctx.instr->acct_off);
    fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_raw->raw + ctx.txn_descriptor->acct_addr_off);
    fd_pubkey_t * sender   = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t * receiver = &txn_accs[instr_acc_idxs[1]];

    /* Check sender has signed the transaction */
    uchar sender_is_signer = 0;
    for ( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
      if ( instr_acc_idxs[i] < ctx.txn_descriptor->signature_cnt ) {
        fd_pubkey_t * signer = &txn_accs[instr_acc_idxs[i]];
        if ( memcmp( signer, sender, sizeof(fd_pubkey_t) ) == 0 ) {
          sender_is_signer = 1;
          break;
        }
      }
    }
    if ( !sender_is_signer ) {
      FD_LOG_WARNING( ( " sender has not authorized transfer " ) );
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    /* Check sender account has enough balance to execute this transaction */
    fd_acc_lamports_t sender_lamports = 0;
    int read_result = fd_acc_mgr_get_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, sender, &sender_lamports );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to get lamports" ));
      /* TODO: correct error messages */
      return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
    }
    if ( FD_UNLIKELY( sender_lamports < requested_lamports ) ) {
      FD_LOG_WARNING(( "sender only has %lu lamports, needs %lu", sender_lamports, requested_lamports ));
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    /* Determine the receiver's current balance, creating the account if it does not exist */
    fd_acc_lamports_t receiver_lamports = 0;
    read_result = fd_acc_mgr_get_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, receiver, &receiver_lamports );
    if ( FD_UNLIKELY( read_result == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) {

      /* Create new account if it doesn't exist */
      FD_LOG_DEBUG(( "transfer to unknown account: creating new account" ));
      fd_account_meta_t metadata;
      fd_account_meta_init(&metadata);
      struct iovec vec[1];
      vec[0].iov_base = &metadata;
      vec[0].iov_len = sizeof(metadata);
      int write_result = fd_acc_mgr_write_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, receiver, vec, 1, 0 );
      if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "failed to create new account" ));
        return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
      }

    }
    else if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to get lamports" ));
      return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
    }
    FD_LOG_DEBUG(("transfer: sender balance before transfer: %lu", sender_lamports));
    FD_LOG_DEBUG(("transfer: receiver balance before transfer: %lu", receiver_lamports));

    /* Execute the transfer */
    int write_result = fd_acc_mgr_set_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, ctx.global->bank.solana_bank.slot , sender, sender_lamports - requested_lamports );
    if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to set sender lamports" ));
      return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
    }
    write_result = fd_acc_mgr_set_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, ctx.global->bank.solana_bank.slot, receiver, receiver_lamports + requested_lamports );
    if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to set receiver lamports" ));
      return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
    }

    FD_LOG_INFO(( "successfully executed transfer of %lu lamports", requested_lamports ));

    return FD_EXECUTOR_INSTR_SUCCESS;
}

int fd_executor_system_program_execute_instruction(
    instruction_ctx_t ctx
) {
    /* Deserialize the SystemInstruction enum */
    uchar *data            = (uchar *)ctx.txn_raw->raw + ctx.instr->data_off;
    void* input            = (void *)data;
    const void** input_ptr = (const void **)&input;
    void* dataend          = (void*)&data[ctx.instr->data_sz];

    fd_system_program_instruction_t instruction;
    fd_system_program_instruction_decode( &instruction, input_ptr, dataend, ctx.global->allocf, ctx.global->allocf_arg );

    if ( !fd_system_program_instruction_is_transfer( &instruction ) ) { /* transfer instruction */
        /* TODO: support other instruction types */
        FD_LOG_ERR(( "unsupported system program instruction: discrimant: %d", instruction.discriminant ));
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    ulong requested_lamports = instruction.inner.transfer;

    return transfer( requested_lamports, ctx );
}


