#include "fd_executor.h"

instruction_invocation_func_t
fd_executor_lookup_native_program(
    fd_txn_acct_addr_t key
) {
    // TODO: support for multiple programs

}

void
fd_execute_txn( fd_txn_t * txn ) {
    for (ushort i = 0; i < txn->instr_cnt; ++i) {
        fd_txn_instr_t instr = txn->instr[i];

        fd_txn_acct_addr_t *tx_accs        = (fd_txn_acct_addr_t *)(((uchar *)txn) + txn->acct_addr_off);
        instruction_invocation_func_t func = fd_executor_lookup_native_program( tx_accs[instr.program_id] );

        instruction_ctx_t ctx = {
            .txn   = txn,
            .instr = &instr,
        };

        func( ctx );
    }
}
