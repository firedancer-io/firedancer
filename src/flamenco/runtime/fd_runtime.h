#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_h

#include "fd_rocksdb.h"
#include "fd_acc_mgr.h"
#include "fd_executor.h"
#include "../features/fd_features.h"
#include "fd_rent_lists.h"
#include "../../ballet/poh/fd_poh.h"
#include "program/fd_builtin_programs.h"
#include "../leaders/fd_leaders.h"
#include "../capture/fd_solcap_writer.h"
#include "sysvar/fd_sysvar.h"

#define FD_RUNTIME_EXECUTE_SUCCESS                               ( 0 )  /* Slot executed successfully */
#define FD_RUNTIME_EXECUTE_GENERIC_ERR                          ( -1 ) /* The Slot execute returned an error */
#define MAX_PERMITTED_DATA_LENGTH ( 10 * 1024 * 1024 )

#define FD_FEATURE_ACTIVE(_g, _y)  (_g->bank.slot >= _g->features. _y)

#define FD_GLOBAL_CTX_ALIGN (32UL)

#define VECT_NAME fd_stake_rewards
#define VECT_ELEMENT fd_stake_reward_t*
#include "../runtime/fd_vector.h"
#undef VECT_NAME
#undef VECT_ELEMENT

#define VECT_NAME fd_stake_rewards_vector
#define VECT_ELEMENT fd_stake_rewards_t
#include "../runtime/fd_vector.h"
#undef VECT_NAME
#undef VECT_ELEMENT

struct fd_epoch_reward_status {
  uint is_active;
  ulong start_block_height;
  fd_stake_rewards_vector_t * stake_rewards_by_partition;
};
typedef struct fd_epoch_reward_status fd_epoch_reward_status_t;

struct __attribute__((aligned(FD_GLOBAL_CTX_ALIGN))) fd_global_ctx {
  // TODO: We need to organize this structure in a cache line aware way?

  ulong                      magic;       /* ==FD_GLOBAL_CTX_MAGIC */

  fd_valloc_t                valloc;
  fd_acc_mgr_t*              acc_mgr;

  fd_rng_t                   rnd_mem;

  fd_wksp_t *                funk_wksp; // Workspace dedicated to funk, KEEP YOUR GRUBBY MITS OFF!
  fd_funk_t*                 funk;
  fd_wksp_t *                local_wksp; // Workspace for allocs local to this process
  fd_rng_t*                  rng;

  fd_solcap_writer_t *       capture;
  int                        trace_mode;
  int                        trace_dirfd;

# define FD_RUNTIME_TRACE_NONE   (0)
# define FD_RUNTIME_TRACE_SAVE   (1)
# define FD_RUNTIME_TRACE_REPLAY (2)

  fd_features_t              features;

  unsigned char              sysvar_recent_block_hashes[32];
  unsigned char              sysvar_clock[32];
  unsigned char              sysvar_slot_history[32];
  unsigned char              sysvar_slot_hashes[32];
  unsigned char              sysvar_epoch_schedule[32];
  unsigned char              sysvar_epoch_rewards[32];
  unsigned char              sysvar_fees[32];
  unsigned char              sysvar_rent[32];
  unsigned char              sysvar_stake_history[32];
  unsigned char              sysvar_owner[32];
  unsigned char              sysvar_last_restart_slot[32];
  unsigned char              sysvar_instructions[32];
  unsigned char              solana_native_loader[32];
  unsigned char              solana_feature_program[32];
  unsigned char              solana_config_program[32];
  unsigned char              solana_stake_program[32];
  unsigned char              solana_stake_program_config[32];
  unsigned char              solana_system_program[32];
  unsigned char              solana_vote_program[32];
  unsigned char              solana_bpf_loader_deprecated_program[32];
  unsigned char              solana_bpf_loader_program[32];
  unsigned char              solana_bpf_loader_upgradeable_program[32];
  fd_pubkey_t                solana_bpf_loader_v4_program[1];
  unsigned char              solana_ed25519_sig_verify_program[32];
  unsigned char              solana_keccak_secp_256k_program[32];
  unsigned char              solana_compute_budget_program[32];
  unsigned char              solana_zk_token_proof_program[32];
  unsigned char              solana_address_lookup_table_program[32];
  unsigned char              solana_spl_native_mint[32];
  unsigned char              solana_spl_token[32];

  // This state needs to be commited to funk so that we can roll it back?
  fd_firedancer_banks_t      bank;

  fd_funk_txn_t*             funk_txn_tower[32];
  fd_funk_txn_t*             funk_txn;
  ushort                     funk_txn_index;
  ulong                      signature_cnt;
  fd_hash_t                  account_delta_hash;
  fd_hash_t                  prev_banks_hash;

  uchar                      log_level;
  uchar                      abort_on_mismatch;

  fd_epoch_leaders_t *       leaders;  /* Current epoch only */
  fd_pubkey_t const *        leader;   /* Current leader */

  fd_rent_lists_t *          rentlists;
  ulong                      rent_epoch;
  fd_epoch_reward_status_t   epoch_reward_status;

};

#define FD_GLOBAL_CTX_FOOTPRINT ( sizeof(fd_global_ctx_t) )
#define FD_GLOBAL_CTX_MAGIC (0xBBB3CB3B91A2FB96UL) /* random */

#define FD_ACC_MGR_KEY_TYPE ((uchar)0)
#define FD_BLOCK_KEY_TYPE ((uchar)1)
#define FD_BLOCK_META_KEY_TYPE ((uchar)2)

/* FD_BLOCK_BANKS_TYPE stores fd_firedancer_banks_t bincode encoded */
#define FD_BLOCK_BANKS_TYPE ((uchar)3)

/* FD_BANK_HASH_TYPE stores the bank hash of each slot */
#define FD_BANK_HASH_TYPE ((uchar)4)

/* FD_BLOCK_TXNSTATUS_TYPE stores the transaction metadata for a block */
#define FD_BLOCK_TXNSTATUS_TYPE ((uchar)5)

FD_PROTOTYPES_BEGIN

void *            fd_global_ctx_new        ( void * );
fd_global_ctx_t * fd_global_ctx_join       ( void * );
void *            fd_global_ctx_leave      ( fd_global_ctx_t *  );
void *            fd_global_ctx_delete     ( void *  );

ulong             fd_runtime_lamports_per_signature( fd_global_ctx_t *global );

ulong             fd_runtime_txn_lamports_per_signature( fd_global_ctx_t *global, transaction_ctx_t * txn_ctx, fd_txn_t * txn_descriptor, fd_rawtxn_b_t const * txn_raw );
void              fd_runtime_init_bank_from_genesis( fd_global_ctx_t * global, fd_genesis_solana_t * genesis_block, uchar genesis_hash[FD_SHA256_HASH_SZ] );
void              fd_runtime_init_program( fd_global_ctx_t * global );
int               fd_runtime_block_execute ( fd_global_ctx_t *global, fd_slot_meta_t *m, const void* block, ulong blocklen );
int               fd_runtime_block_verify  ( fd_global_ctx_t *global, fd_slot_meta_t *m, const void* block, ulong blocklen );
int               fd_runtime_block_verify_tpool( fd_global_ctx_t *global, fd_slot_meta_t *m, const void* block, ulong blocklen, fd_tpool_t * tpool, ulong max_workers );
int               fd_runtime_block_eval    ( fd_global_ctx_t *global, fd_slot_meta_t *m, const void* block, ulong blocklen );

ulong             fd_runtime_calculate_fee ( fd_global_ctx_t *global, transaction_ctx_t * txn_ctx, fd_txn_t * txn_descriptor, fd_rawtxn_b_t const * txn_raw );
void              fd_runtime_freeze        ( fd_global_ctx_t *global );

ulong             fd_runtime_lamports_per_signature_for_blockhash( fd_global_ctx_t *global, FD_FN_UNUSED fd_hash_t *blockhash );

fd_funk_rec_key_t fd_runtime_block_key     (ulong slot);
fd_funk_rec_key_t fd_runtime_block_meta_key(ulong slot);
fd_funk_rec_key_t fd_runtime_banks_key     (void);

static inline fd_funk_rec_key_t
fd_runtime_bank_hash_key( ulong slot ) {
  fd_funk_rec_key_t id = {0};
  id.ul[ 0 ] = slot;
  id.c[ FD_FUNK_REC_KEY_FOOTPRINT - 1 ] = FD_BANK_HASH_TYPE;
  return id;
}

static inline fd_funk_rec_key_t
fd_runtime_block_txnstatus_key( ulong slot ) {
  fd_funk_rec_key_t id = {0};
  id.ul[ 0 ] = slot;
  id.c[ FD_FUNK_REC_KEY_FOOTPRINT - 1 ] = FD_BLOCK_TXNSTATUS_TYPE;
  return id;
}

int
fd_pubkey_create_with_seed( uchar const  base [ static 32 ],
                            char const * seed,
                            ulong        seed_sz,
                            uchar const  owner[ static 32 ],
                            uchar        out  [ static 32 ] );

int               fd_runtime_save_banks    ( fd_global_ctx_t *global );
int               fd_global_import_solana_manifest(fd_global_ctx_t *global, fd_solana_manifest_t* manifest);

/* fd_features_restore loads all known feature accounts from the
   accounts database.  This is used when initializing bank from a
   snapshot. */

void
fd_features_restore( fd_global_ctx_t * global );

static inline ulong fd_rent_exempt(fd_global_ctx_t *global, ulong sz) {
  return (sz + 128) * ((ulong) ((double)global->bank.rent.lamports_per_uint8_year * global->bank.rent.exemption_threshold));
}

void
fd_process_new_epoch(
    fd_global_ctx_t * global,
    ulong parent_epoch
);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_h */
