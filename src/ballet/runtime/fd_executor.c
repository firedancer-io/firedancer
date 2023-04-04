#include "fd_executor.h"
#include "fd_runtime.h"

#include "program/fd_system_program.h"
#include "program/fd_vote_program.h"

#include "../base58/fd_base58.h"

void* fd_executor_new(void* mem,
                      fd_global_ctx_t* global,
                      ulong footprint) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  fd_memset( mem, 0, footprint );

  fd_executor_t *executor = (fd_executor_t*)mem;
  executor->global = global;

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

/* Look up a native program given it's pubkey key */
execute_instruction_func_t
fd_executor_lookup_native_program( fd_global_ctx_t* global,  fd_pubkey_t *pubkey ) {
  /* TODO: replace with proper lookup table */
  if ( !memcmp( pubkey, global->solana_vote_program, sizeof( fd_pubkey_t ) ) ) {
    return          fd_executor_vote_program_execute_instruction;
  } else if ( !memcmp( pubkey, global->solana_system_program, sizeof( fd_pubkey_t ) ) ) {
    return                 fd_executor_system_program_execute_instruction;
  } else if ( !memcmp( pubkey, global->solana_config_program, sizeof( fd_pubkey_t ) ) ) {
    FD_LOG_ERR(( "config program not implemented yet" ));
  } else if ( !memcmp( pubkey, global->solana_stake_program, sizeof( fd_pubkey_t ) ) ) {
    FD_LOG_ERR(( "stake program not implemented yet" ));
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
            .global         = executor->global,
            .instr          = instr,
            .txn_descriptor = txn_descriptor,
            .txn_raw        = txn_raw,
        };

        /* TODO: allow instructions to be failed, and the transaction to be reverted */
        execute_instruction_func_t exec_instr_func = fd_executor_lookup_native_program( executor->global, &tx_accs[instr->program_id] );
        int exec_result = exec_instr_func( ctx );
        if ( FD_UNLIKELY( exec_result != FD_EXECUTOR_INSTR_SUCCESS ) ) {
          FD_LOG_ERR(( "instruction executed unsuccessfully: error code %d", exec_result ));
          /* TODO: revert transaction context */
        }

        /* TODO: sanity before/after checks: total lamports unchanged etc */
    }
}
