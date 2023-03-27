#include "fd_executor.h"

#include "fd_system_program.h"
#include "fd_vote_program.h"

#include "../base58/fd_base58.h"

fd_pubkey_t solana_config_program;
fd_pubkey_t solana_stake_program;
fd_pubkey_t solana_system_program;
fd_pubkey_t solana_vote_program;
fd_pubkey_t solana_bpf_loader_program;
fd_pubkey_t solana_ed25519_sig_verify_program;
fd_pubkey_t solana_keccak_secp_256k_program;

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

 // https://docs.solana.com/developing/runtime-facilities/programs

  // We could make these local to the executor... but, they are also unchanging for all time...
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  solana_config_program.key );
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  solana_stake_program.key);
  fd_base58_decode_32( "11111111111111111111111111111111",             solana_system_program.key);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  solana_vote_program.key);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  solana_bpf_loader_program.key);
  fd_base58_decode_32( "Ed25519SigVerify111111111111111111111111111",  solana_ed25519_sig_verify_program.key);
  fd_base58_decode_32( "KeccakSecp256k11111111111111111111111111111",  solana_keccak_secp_256k_program.key);

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
fd_executor_lookup_native_program( fd_pubkey_t *pubkey ) {
  /* TODO: replace with proper lookup table */
  if ( !memcmp( pubkey, &solana_vote_program, sizeof( fd_pubkey_t ) ) ) {
    return          fd_executor_vote_program_execute_instruction;
  } else if ( !memcmp( pubkey, &solana_system_program, sizeof( fd_pubkey_t ) ) ) {
    return                 fd_executor_system_program_execute_instruction;
  } else if ( !memcmp( pubkey, &solana_config_program, sizeof( fd_pubkey_t ) ) ) {
    FD_LOG_ERR(( "config program not implemented yet" ));
  } else if ( !memcmp( pubkey, &solana_stake_program, sizeof( fd_pubkey_t ) ) ) {
    FD_LOG_ERR(( "stake program not implemented yet" ));
  } else {
    FD_LOG_ERR(( "unknown program" ));
    return NULL; /* FIXME */
  }
}

static
char* local_allocf(FD_FN_UNUSED void* arg, unsigned long align, unsigned long len) {
  char * ptr = malloc(fd_ulong_align_up(sizeof(char *) + len, align));
  char * ret = (char *) fd_ulong_align_up( (ulong) (ptr + sizeof(char *)), align );
  *((char **)(ret - sizeof(char *))) = ptr;
  return ret;
}

static
void local_freef(FD_FN_UNUSED void* arg, void *ptr) {
  free(*((char **)((char *) ptr - sizeof(char *))));
}

void
fd_execute_txn( fd_executor_t* executor, fd_txn_t * txn_descriptor, fd_rawtxn_b_t* txn_raw ) {
    fd_pubkey_t *tx_accs   = (fd_pubkey_t *)((uchar *)txn_raw->raw + txn_descriptor->acct_addr_off);

    global_ctx_t global = {
      .allocf = &local_allocf,
      .allocf_arg = NULL,
      .freef = &local_freef,
      .freef_arg = NULL
    };

    /* TODO: track compute budget used within execution */
    /* TODO: store stack of instructions to detect reentrancy */

    /* TODO: execute within a transaction context, which can be reverted */

    for ( ushort i = 0; i < txn_descriptor->instr_cnt; ++i ) {
        fd_txn_instr_t * instr = &txn_descriptor->instr[i];
        instruction_ctx_t ctx = {
            .global         = &global,
            .instr          = instr,
            .txn_descriptor = txn_descriptor,
            .txn_raw        = txn_raw,
            .acc_mgr        = executor->acc_mgr,
        };

        /* TODO: allow instructions to be failed, and the transaction to be reverted */
        execute_instruction_func_t exec_instr_func = fd_executor_lookup_native_program( &tx_accs[instr->program_id] );
        int exec_result = exec_instr_func( ctx );
        if ( FD_UNLIKELY( exec_result != FD_EXECUTOR_INSTR_SUCCESS ) ) {
          FD_LOG_ERR(( "instruction executed unsuccessfully: error code %d", exec_result ));
          /* TODO: revert transaction context */
        }

        /* TODO: sanity before/after checks: total lamports unchanged etc */
    }
}
