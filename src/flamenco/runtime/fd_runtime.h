#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_h

#include "fd_rocksdb.h"
#include "fd_acc_mgr.h"
#include "fd_executor.h"
#include "fd_features.h"
#include "../../ballet/poh/fd_poh.h"
#include "program/fd_builtin_programs.h"
#include "../leaders/fd_leaders.h"

#define FD_RUNTIME_EXECUTE_SUCCESS                               ( 0 )  /* Slot executed successfully */
#define FD_RUNTIME_EXECUTE_GENERIC_ERR                          ( -1 ) /* The Slot execute returned an error */
#define MAX_PERMITTED_DATA_LENGTH ( 10 * 1024 * 1024 )

#define FD_GLOBAL_CTX_ALIGN (32UL)
struct __attribute__((aligned(FD_GLOBAL_CTX_ALIGN))) fd_global_ctx {
  // TODO: We need to organize this structure in a cache line aware way?

  ulong                      magic;       /* ==FD_GLOBAL_CTX_MAGIC */

  fd_valloc_t                valloc;
  fd_acc_mgr_t*              acc_mgr;

  fd_rng_t                   rnd_mem;

  fd_wksp_t *                wksp;
  fd_funk_t*                 funk;
  fd_executor_t              executor;  // Amusingly, it is just a pointer to this...
  fd_rng_t*                  rng;

  fd_features_t              features;

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

  fd_funk_txn_t*             funk_txn_tower[32];
  fd_funk_txn_t*             funk_txn;
  ushort                     funk_txn_index;
  ulong                      signature_cnt;
  fd_hash_t                  account_delta_hash;
  fd_hash_t                  prev_banks_hash;

  uchar                      collector_set;
  uchar                      log_level;

  fd_epoch_leaders_t *       leaders;  /* Current epoch only */
};
typedef struct fd_global_ctx fd_global_ctx_t;

#define FD_GLOBAL_CTX_FOOTPRINT ( sizeof(fd_global_ctx_t) )
#define FD_GLOBAL_CTX_MAGIC (0xBBB3CB3B91A2FB96UL) /* random */

#define FD_ACC_MGR_KEY_TYPE ((uchar)0)
#define FD_BLOCK_KEY_TYPE ((uchar)1)
#define FD_BLOCK_META_KEY_TYPE ((uchar)2)

/* FD_BLOCK_BANKS_TYPE stores fd_firedancer_banks_t bincode encoded */
#define FD_BLOCK_BANKS_TYPE ((uchar)3)

/* FD_BANK_HASH_TYPE stores the bank hash of each slot */
#define FD_BANK_HASH_TYPE ((uchar)4)

FD_PROTOTYPES_BEGIN

void *            fd_global_ctx_new        ( void * );
fd_global_ctx_t * fd_global_ctx_join       ( void * );
void *            fd_global_ctx_leave      ( fd_global_ctx_t *  );
void *            fd_global_ctx_delete     ( void *  );

ulong             fd_runtime_lamports_per_signature( fd_global_ctx_t *global );

ulong             fd_runtime_txn_lamports_per_signature( fd_global_ctx_t *global, fd_txn_t * txn_descriptor, fd_rawtxn_b_t* txn_raw );
void              fd_runtime_init_bank_from_genesis( fd_global_ctx_t * global, fd_genesis_solana_t * genesis_block, uchar genesis_hash[FD_SHA256_HASH_SZ] );
void              fd_runtime_init_program( fd_global_ctx_t * global );
int               fd_runtime_block_execute ( fd_global_ctx_t *global, fd_slot_meta_t *m, const void* block, ulong blocklen );
int               fd_runtime_block_verify  ( fd_global_ctx_t *global, fd_slot_meta_t *m, const void* block, ulong blocklen );
int               fd_runtime_block_verify_tpool( fd_global_ctx_t *global, fd_slot_meta_t *m, const void* block, ulong blocklen, fd_tpool_t * tpool, ulong max_workers );
int               fd_runtime_block_eval    ( fd_global_ctx_t *global, fd_slot_meta_t *m, const void* block, ulong blocklen );

ulong             fd_runtime_calculate_fee ( fd_global_ctx_t *global, transaction_ctx_t * txn_ctx, fd_txn_t * txn_descriptor, fd_rawtxn_b_t* txn_raw );
void              fd_runtime_freeze        ( fd_global_ctx_t *global );

void              fd_printer_walker        (void *arg, const char* name, int type, const char *type_name, int level);

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

int               fd_pubkey_create_with_seed(fd_pubkey_t const * base, char const * seed, fd_pubkey_t const *owner, fd_pubkey_t *out );

int               fd_runtime_save_banks    ( fd_global_ctx_t *global );
int               fd_global_import_solana_manifest(fd_global_ctx_t *global, fd_solana_manifest_t* manifest);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_h */
