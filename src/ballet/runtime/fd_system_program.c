#include "fd_system_program.h"
#include "fd_account_mgr.h"

void invoke_instruction(
    instruction_ctx_t ctx
) {
   /* Decode the SystemInstruction - intially only support a simple Transfer */
   uint discrimant = 0;
   void** data    = (void **)((uchar *)ctx.txn + ctx.instr->data_off);
   const void* dataend = data[ctx.instr->data_sz];
   fd_bincode_uint32_decode( &discrimant, (const void **)data, dataend );
    if ( discrimant != 2 ) {
        FD_LOG_ERR( ( " unsupported system instruction " ) );
        return;
    }
    ulong lamports = 0;
    fd_bincode_uint64_decode( &lamports, (const void **)data, dataend );

    /* Pull out sender (acc idx 0) and recipient (acc idx 1) */
    /* TODO: convenience functions for these */
    fd_txn_acct_addr_t * accs   = (fd_txn_acct_addr_t *)((uchar *) ctx.txn + ctx.instr->acct_off);
    fd_txn_acct_addr_t * sender   = &accs[0];
    fd_txn_acct_addr_t * receiver = &accs[1];
    
    /* Check sender has signed the transaction */
    ushort sender_is_signer = 0; /* TODO: bool representation? */
    for ( uchar i = 0; i < ctx.txn->signature_cnt; i++ ) {
        fd_txn_acct_addr_t * signer = &accs[i];
        if ( memcmp( sender, signer, sizeof(fd_txn_acct_addr_t) ) ) {
            sender_is_signer = 1;
            break;
        }
    }
    if ( !sender_is_signer ) {
        FD_LOG_ERR( ( " sender has not authorized transfer " ) );
        return;
    }

    /* Check sender account has enough lamports to execute this transaction */
    if ( get_lamports( sender ) < lamports ) {
        FD_LOG_ERR( ( " sender doesn't have enough lamports " ) );
        return;
    }

    /* Execute the transfer */
    set_lamports( sender, get_lamports(sender) - lamports );
    set_lamports( receiver, get_lamports(receiver) + lamports );    
}
