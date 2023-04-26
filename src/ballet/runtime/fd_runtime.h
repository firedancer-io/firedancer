#ifndef HEADER_fd_src_ballet_runtime_fd_runtime_h
#define HEADER_fd_src_ballet_runtime_fd_runtime_h

#include "fd_rocksdb.h"
#include "fd_acc_mgr.h"
#include "fd_executor.h"
#include "../poh/fd_poh.h"
#include "program/fd_builtin_programs.h"

#define FD_RUNTIME_EXECUTE_SUCCESS                               ( 0 )  /* Slot executed successfully */
#define FD_RUNTIME_EXECUTE_GENERIC_ERR                          ( -1 ) /* The Slot execute returned an error */

#define FD_GLOBAL_CTX_ALIGN (32UL)
struct __attribute__((aligned(FD_GLOBAL_CTX_ALIGN))) fd_global_ctx {
  // TODO: We need to organize this structure in a cache line aware way?

  ulong                      magic;       /* ==FD_GLOBAL_CTX_MAGIC */

  fd_alloc_fun_t             allocf;
  void *                     allocf_arg;
  fd_free_fun_t              freef;
  fd_acc_mgr_t*              acc_mgr;

  fd_genesis_solana_t        genesis_block;
  uchar                      genesis_hash[FD_SHA256_HASH_SZ];

  fd_rng_t                   rnd_mem;

  fd_wksp_t *                wksp;
  fd_funk_t*                 funk;
  fd_executor_t              executor;  // Amusingly, it is just a pointer to this...
  fd_rng_t*                  rng;

  unsigned char              sysvar_recent_block_hashes[32];
  unsigned char              sysvar_clock[32];
  unsigned char              sysvar_slot_history[32];
  unsigned char              sysvar_slot_hashes[32];
  unsigned char              sysvar_epoch_schedule[32];
  unsigned char              sysvar_fees[32];
  unsigned char              sysvar_rent[32];
  unsigned char              sysvar_stake_history[32];
  unsigned char              sysvar_owner[32];
  unsigned char              solana_native_loader[32];
  unsigned char              solana_config_program[32];
  unsigned char              solana_stake_program[32];
  unsigned char              solana_stake_program_config[32];
  unsigned char              solana_system_program[32];
  unsigned char              solana_vote_program[32];
  unsigned char              solana_bpf_loader_deprecated_program[32];
  unsigned char              solana_bpf_loader_program_with_jit[32];
  unsigned char              solana_bpf_loader_upgradeable_program_with_jit[32];
  unsigned char              solana_ed25519_sig_verify_program[32];
  unsigned char              solana_keccak_secp_256k_program[32];
  unsigned char              solana_compute_budget_program[32];
  unsigned char              solana_zk_token_proof_program[32];
  unsigned char              solana_address_lookup_table_program[32];
  unsigned char              solana_spl_native_mint[32];
  unsigned char              solana_spl_token[32];

  // This state needs to be commited to funk so that we can roll it back?
  fd_firedancer_banks_t      bank;

  fd_poh_state_t             poh;
  fd_funk_txn_t*             funk_txn_tower[32];
  fd_funk_txn_t*             funk_txn;
  ushort                     funk_txn_index;
  uchar                      block_hash[FD_SHA256_HASH_SZ];
  fd_hash_t                  banks_hash;
  ulong                      signature_cnt;
  fd_hash_t                  account_delta_hash;
  fd_hash_t                  prev_banks_hash;

  fd_pubkey_t                collector_id;
  ulong                      collected;

  fd_fee_rate_governor_t     fee_rate_governor;
  fd_recent_block_hashes_t   recent_block_hashes;

  // TODO: should we instead remember which slot the poh is valid for?
  fd_clock_timestamp_votes_t timestamp_votes;

  uchar                      poh_booted;
  uchar                      collector_set;
  uchar                      log_level;
};
typedef struct fd_global_ctx fd_global_ctx_t;

#define FD_GLOBAL_CTX_FOOTPRINT ( sizeof(fd_global_ctx_t) )
#define FD_GLOBAL_CTX_MAGIC (0xBBB3CB3B91A2FB96UL) /* random */

FD_PROTOTYPES_BEGIN

void *            fd_global_ctx_new        ( void * );
fd_global_ctx_t * fd_global_ctx_join       ( void * );
void *            fd_global_ctx_leave      ( fd_global_ctx_t *  );
void *            fd_global_ctx_delete     ( void *  );

ulong             fd_runtime_txn_lamports_per_signature( fd_global_ctx_t *global, fd_txn_t * txn_descriptor, fd_rawtxn_b_t* txn_raw );
void              fd_runtime_boot_slot_zero( fd_global_ctx_t *global );
int               fd_runtime_block_execute ( fd_global_ctx_t *global, fd_slot_blocks_t *slot_data );
int               fd_runtime_block_verify  ( fd_global_ctx_t *global, fd_slot_blocks_t *slot_data );
int               fd_runtime_block_eval    ( fd_global_ctx_t *global, fd_slot_blocks_t *slot_data );

ulong             fd_runtime_calculate_fee ( fd_global_ctx_t *global, fd_txn_t * txn_descriptor, fd_rawtxn_b_t* txn_raw );
void              fd_runtime_freeze        ( fd_global_ctx_t *global );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_runtime_fd_runtime_h */
