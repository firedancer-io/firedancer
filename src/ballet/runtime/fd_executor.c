#include "fd_executor.h"
#include "fd_system_program.h"

#define UNUSED(x) (void)(x)

void* fd_executor_new(void* mem,
                      fd_acc_mgr_t* acc_mgr,
                      ulong footprint) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  fd_memset( mem, 0, footprint );

  fd_executor_t *executor = (fd_executor_t*)mem;
  executor->acc_mgr = acc_mgr;

  return mem;
}

fd_executor_t *fd_executor_join(void* mem) {
  return (fd_executor_t*)mem;
}

void *fd_executor_leave(fd_executor_t* executor) {
  return (void*)executor;
}

void* fd_executor_delete(void* mem) {
  return mem;
}

/* Known native programs */
static uchar system_program_pubkey[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static uchar vote_program_pubkey[]   = { 0x07, 0x61, 0x48, 0x1d, 0x35, 0x74, 0x74, 0xbb, 0x7c, 0x4d, 0x76, 0x24, 0xeb, 0xd3, 0xbd, 0xb3,
                                         0xd8, 0x35, 0x5e, 0x73, 0xd1, 0x10, 0x43, 0xfc, 0x0d, 0xa3, 0x53, 0x80, 0x00, 0x00, 0x00, 0x00 };

void fd_vote_program_invoke_instruction( instruction_ctx_t ctx ) {
    UNUSED(ctx);
    /* TODO */
    FD_LOG_INFO(("vote program instruction: skipping...")); 
}

/* Look up a native program given it's pubkey key */
execute_instruction_func_t
fd_executor_lookup_native_program( fd_pubkey_t *pubkey ) {
    /* TODO: replace with proper lookup table */
    if ( !memcmp( pubkey, &vote_program_pubkey, sizeof( fd_pubkey_t ) ) ) {
        return fd_vote_program_invoke_instruction;
    }
    else if ( !memcmp( pubkey, &system_program_pubkey, sizeof( fd_pubkey_t ) ) ) {
        return fd_system_program_invoke_instruction;
    } else {
        FD_LOG_ERR(( "unknown program" ));
        return NULL; /* FIXME */
    }
}

void
fd_execute_txn( fd_executor_t* executor, fd_txn_t * txn_descriptor, fd_rawtxn_b_t* txn_raw ) {
    fd_pubkey_t *tx_accs   = (fd_pubkey_t *)((uchar *)txn_raw->raw + txn_descriptor->acct_addr_off);

    /* TODO: track compute budget used within execution */
    /* TODO: store stack of instructions to detect reentrancy */

    /* TODO: execute within a transaction context, which can be reverted */

    for ( ushort i = 0; i < txn_descriptor->instr_cnt; ++i ) {
        fd_txn_instr_t * instr = &txn_descriptor->instr[i];
        instruction_ctx_t ctx = {
            .instr          = instr,
            .txn_descriptor = txn_descriptor,
            .txn_raw        = txn_raw,
            .acc_mgr        = executor->acc_mgr,
        };

        /* TODO: allow instructions to be failed, and the transaction to be reverted */
        execute_instruction_func_t exec_func = fd_executor_lookup_native_program( &tx_accs[instr->program_id] );
        exec_func( ctx );

        /* TODO: sanity before/after checks: total lamports unchanged etc */
    }
}
