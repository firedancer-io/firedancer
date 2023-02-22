#include "fd_system_program.h"
#include "fd_acc_mgr.h"

void transfer(
    ulong requested_lamports,
    instruction_ctx_t ctx
) {
    /* Pull out sender (acc idx 0) and recipient (acc idx 1) */
    uchar * instr_acc_idxs = ((uchar *)ctx.txn_raw->raw + ctx.instr->acct_off);
    fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_raw->raw + ctx.txn_descriptor->acct_addr_off);
    fd_pubkey_t * sender   = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t * receiver = &txn_accs[instr_acc_idxs[1]];

    /* Check sender has signed the transaction */
    uchar sender_is_signer = 0; /* TODO: bool representation? */
    for ( uchar i = 0; i < ctx.txn_descriptor->signature_cnt; i++ ) {
        fd_pubkey_t * signer = &txn_accs[instr_acc_idxs[i]];
        if ( !memcmp( sender, signer, sizeof(fd_pubkey_t) ) ) {
            sender_is_signer = 1;
            break;
        }
    }
    if ( FD_UNLIKELY( !sender_is_signer ) ) {
        FD_LOG_ERR( ( " sender has not authorized transfer " ) );
        return;
    }

    /* Check sender account has enough balance to execute this transaction */
    fd_acc_lamports_t sender_lamports = 0;
    int read_result = fd_acc_mgr_get_lamports( ctx.acc_mgr, sender, &sender_lamports );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to get lamports" ));
      return;
    }
    if ( FD_UNLIKELY( sender_lamports < requested_lamports ) ) {
      FD_LOG_WARNING(( "sender only has %lu lamports, needs %lu", sender_lamports, requested_lamports ));
      return;
    }

    /* Determine the receiver's current balance, creating the account if it does not exist */
    fd_acc_lamports_t receiver_lamports = 0;
    read_result = fd_acc_mgr_get_lamports( ctx.acc_mgr, receiver, &receiver_lamports );
    if ( FD_UNLIKELY( read_result == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) {

      /* Create new account if it doesn't exist */
      FD_LOG_DEBUG(( "transfer to unknown account: creating new account" ));
      fd_account_meta_t metadata;
      fd_memset(&metadata, 0, sizeof(metadata));
      int write_result = fd_acc_mgr_write_account( ctx.acc_mgr, receiver, (uchar *)&metadata, sizeof(metadata) );
      if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "failed to create new account" ));
        return;
      }

    }
    else if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to get lamports" ));
      return;
    }
    FD_LOG_DEBUG(("transfer: sender balance before transfer: %lu", sender_lamports));
    FD_LOG_DEBUG(("transfer: receiver balance before transfer: %lu", receiver_lamports));

    /* Execute the transfer */
    int write_result = fd_acc_mgr_set_lamports( ctx.acc_mgr, sender, sender_lamports - requested_lamports );
    if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to set sender lamports" ));
      return;
    }
    write_result = fd_acc_mgr_set_lamports( ctx.acc_mgr, receiver, receiver_lamports + requested_lamports );
    if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to set receiver lamports" ));
      /* TODO: recover sender amount, to make this instruction atomic */
      return;
    }
}

void fd_executor_system_program_execute_instruction(
    instruction_ctx_t ctx
) {
    /* Deserialize the SystemInstruction enum */
    uchar *data            = (uchar *)ctx.txn_raw->raw + ctx.instr->data_off;
    void* input            = (void *)data;
    const void** input_ptr = (const void **)&input;
    void* dataend          = (void*)&data[ctx.instr->data_sz];

    uint discrimant  = 0;
    fd_bincode_uint32_decode( &discrimant, input_ptr, dataend );
    if ( discrimant != 2 ) {
        /* TODO: support other instruction types */
        FD_LOG_ERR(( "unsupported system program instruction: discrimant: %d", discrimant ));
        return;
    }

    ulong requested_lamports = 0;
    fd_bincode_uint64_decode( &requested_lamports, input_ptr, dataend );

    transfer( requested_lamports, ctx );
}


