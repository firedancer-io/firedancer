#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_h

#include "../fd_flamenco_base.h"
#include "fd_rocksdb.h"
#include "fd_acc_mgr.h"
#include "../features/fd_features.h"
#include "fd_rent_lists.h"
#include "../../ballet/poh/fd_poh.h"
#include "../leaders/fd_leaders.h"
#include "context/fd_exec_epoch_ctx.h"
#include "context/fd_exec_slot_ctx.h"
#include "context/fd_capture_ctx.h"
#include "info/fd_block_info.h"
#include "info/fd_instr_info.h"
#include "../gossip/fd_gossip.h"
#include "../repair/fd_repair.h"
#include "../../ballet/pack/fd_microblock.h"

#define FD_RUNTIME_EXECUTE_SUCCESS                               ( 0 )  /* Slot executed successfully */
#define FD_RUNTIME_EXECUTE_GENERIC_ERR                          ( -1 ) /* The Slot execute returned an error */
#define MAX_PERMITTED_DATA_LENGTH ( 10 * 1024 * 1024 )

#define DEFAULT_HASHES_PER_TICK  12500
#define UPDATED_HASHES_PER_TICK2  17500
#define UPDATED_HASHES_PER_TICK3  27500
#define UPDATED_HASHES_PER_TICK4  47500
#define UPDATED_HASHES_PER_TICK5  57500
#define UPDATED_HASHES_PER_TICK6  62500


#define FD_RUNTIME_TRACE_NONE   (0)
#define FD_RUNTIME_TRACE_SAVE   (1)
#define FD_RUNTIME_TRACE_REPLAY (2)

#define FD_FEATURE_ACTIVE(_slot_ctx, _feature_name)  (_slot_ctx->slot_bank.slot >= _slot_ctx->epoch_ctx->features. _feature_name)

/* FD_BLOCK_BANKS_TYPE stores fd_firedancer_banks_t bincode encoded (obsolete)*/
#define FD_BLOCK_BANKS_TYPE ((uchar)3)

/* FD_BLOCK_SLOT_BANK_TYPE stores fd_slot_bank_t bincode encoded */
#define FD_BLOCK_SLOT_BANK_TYPE ((uchar)6)

/* FD_BLOCK_EPOCH_BANK_TYPE stores fd_epoch_bank_t bincode encoded */
#define FD_BLOCK_EPOCH_BANK_TYPE ((uchar)7)

#define FD_BLOCKHASH_QUEUE_MAX_ENTRIES       (300UL)
#define FD_RECENT_BLOCKHASHES_MAX_ENTRIES    (150UL)

/* Transaction errors */
#define FD_RUNTIME_TXN_ERR_ACCOUNT_IN_USE                            -1
#define FD_RUNTIME_TXN_ERR_ACCOUNT_LOADED_TWICE                      -2
#define FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND                         -3
#define FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND                 -4
#define FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE                -5
#define FD_RUNTIME_TXN_ERR_INVALID_ACCOUNT_FOR_FEE                   -6
#define FD_RUNTIME_TXN_ERR_ALREADY_PROCESSED                         -7
#define FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND                       -8
#define FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR                         -9
#define FD_RUNTIME_TXN_ERR_CALL_CHAIN_TOO_DEEP                       -10
#define FD_RUNTIME_TXN_ERR_MISSING_SIGNATURE_FOR_FEE                 -11
#define FD_RUNTIME_TXN_ERR_INVALID_ACCOUNT_INDEX                     -12
#define FD_RUNTIME_TXN_ERR_SIGNATURE_FAILURE                         -13
#define FD_RUNTIME_TXN_ERR_INVALID_PROGRAM_FOR_EXECUTION             -14
#define FD_RUNTIME_TXN_ERR_SANITIZE_FAILURE                          -15
#define FD_RUNTIME_TXN_ERR_CLUSTER_MAINTENANCE                       -16
#define FD_RUNTIME_TXN_ERR_ACCOUNT_BORROW_OUTSTANDING                -17
#define FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_BLOCK_COST_LIMIT         -18
#define FD_RUNTIME_TXN_ERR_UNSUPPORTED_VERSION                       -19
#define FD_RUNTIME_TXN_ERR_INVALID_WRITABLE_ACCOUNT                  -20
#define FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_ACCOUNT_COST_LIMIT       -21
#define FD_RUNTIME_TXN_ERR_WOULD_EXCEED_ACCOUNT_DATA_BLOCK_LIMIT     -22
#define FD_RUNTIME_TXN_ERR_TOO_MANY_ACCOUNT_LOCKS                    -23
#define FD_RUNTIME_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND            -24
#define FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_OWNER        -25
#define FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA         -26
#define FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX        -27
#define FD_RUNTIME_TXN_ERR_INVALID_RENT_PAYING_ACCOUNT               -28
#define FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_VOTE_COST_LIMIT          -29
#define FD_RUNTIME_TXN_ERR_WOULD_EXCEED_ACCOUNT_DATA_TOTAL_LIMIT     -30
#define FD_RUNTIME_TXN_ERR_DUPLICATE_INSTRUCTION                     -31
#define FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_RENT               -32
#define FD_RUNTIME_TXN_ERR_MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED    -33
#define FD_RUNTIME_TXN_ERR_INVALID_LOADED_ACCOUNTS_DATA_SIZE_LIMIT   -34
#define FD_RUNTIME_TXN_ERR_RESANITIZATION_NEEDED                     -35
#define FD_RUNTIME_TXN_ERR_PROGRAM_EXECUTION_TEMPORARILY_RESTRICTED  -36
#define FD_RUNTIME_TXN_ERR_UNBALANCED_TRANSACTION                    -37

struct fd_runtime_ctx {
  /* Private variables needed to construct objects */
  uchar                 epoch_ctx_mem[FD_EXEC_EPOCH_CTX_FOOTPRINT] __attribute__( ( aligned( FD_EXEC_EPOCH_CTX_ALIGN ) ) );
  fd_exec_epoch_ctx_t * epoch_ctx;
  uchar                 slot_ctx_mem[FD_EXEC_SLOT_CTX_FOOTPRINT] __attribute__( ( aligned( FD_EXEC_SLOT_CTX_ALIGN ) ) );
  fd_exec_slot_ctx_t *  slot_ctx;
  fd_acc_mgr_t          _acc_mgr[1];
  fd_repair_config_t    repair_config;
  uchar                 tpool_mem[FD_TPOOL_FOOTPRINT( FD_TILE_MAX )] __attribute__( ( aligned( FD_TPOOL_ALIGN ) ) );
  fd_tpool_t           *tpool;
  fd_alloc_t           *alloc;
  fd_gossip_config_t    gossip_config;
  fd_gossip_peer_addr_t gossip_peer_addr;
  uchar                 private_key[32]; 
  fd_pubkey_t           public_key;

  /* Public variables */
  int                   blowup;
  int                   live;
  fd_gossip_t *         gossip;
  fd_repair_t *         repair;
  volatile int          need_incr_snap;

  // random crap
  FILE *                 capture_file;
  fd_capture_ctx_t *     capture_ctx;
  fd_wksp_t           * local_wksp;
  ulong                  max_workers;
  uchar                  abort_on_mismatch;
};
typedef struct fd_runtime_ctx fd_runtime_ctx_t;

struct fd_runtime_args {
  char const * blockstore_wksp_name;
  char const * funk_wksp_name;
  char const * gossip_peer_addr;
  char const * incremental_snapshot;
  char const * load;
  char const * my_gossip_addr;
  char const * my_repair_addr;
  char const * repair_peer_addr;
  char const * repair_peer_id;
  char const * tvu_addr;
  char const * tvu_fwd_addr;
  char const * snapshot;
  char const * cmd;
  char const * reset;
  char const * capitalization_file;
  char const * allocator;
  char const * validate_db;
  char const * validate_snapshot;
  char const * capture_fpath;
  char const * capture_txns;
  char const * shred_cap;
  char const * trace_fpath;
  char const * check_hash;
  int          retrace;
  int          abort_on_mismatch;
  ulong        end_slot;
  ulong        index_max;
  ulong        page_cnt;
  ulong        tcnt;
  ulong        txn_max;
  ushort       rpc_port;
  ulong        checkpt_slot;
  char const * checkpt_path;
};
typedef struct fd_runtime_args fd_runtime_args_t;

struct fd_execute_txn_task_info {
  fd_exec_txn_ctx_t * txn_ctx;
  fd_txn_p_t * txn;
  int exec_res;
};
typedef struct fd_execute_txn_task_info fd_execute_txn_task_info_t;

FD_PROTOTYPES_BEGIN

ulong
fd_runtime_lamports_per_signature( fd_slot_bank_t const * slot_bank );

ulong
fd_runtime_txn_lamports_per_signature( fd_exec_txn_ctx_t * txn_ctx,
                                       fd_txn_t const * txn_descriptor,
                                       fd_rawtxn_b_t const * txn_raw );

void
fd_runtime_init_bank_from_genesis( fd_exec_slot_ctx_t * slot_ctx,
                                   fd_genesis_solana_t * genesis_block,
                                   fd_hash_t const * genesis_hash );

void
fd_runtime_init_program( fd_exec_slot_ctx_t * slot_ctx );

int
fd_runtime_block_execute_prepare( fd_exec_slot_ctx_t *slot_ctx );

int
fd_runtime_block_execute( fd_exec_slot_ctx_t * slot_ctx,
                          fd_capture_ctx_t * capture_ctx,
                          fd_block_info_t const * block_info );

int
fd_runtime_microblock_verify( fd_microblock_info_t const * microblock_info,
                              fd_hash_t const * in_poh_hash,
                              fd_hash_t * out_poh_hash );

int
fd_runtime_block_verify( fd_block_info_t const * block_info,
                         fd_hash_t const * in_poh_hash,
                         fd_hash_t * out_poh_hash );

int
fd_runtime_block_verify_tpool( fd_block_info_t const * block_info,
                               fd_hash_t const * in_poh_hash,
                               fd_hash_t * out_poh_hash,
                               fd_valloc_t valloc,
                               fd_tpool_t * tpool,
                               ulong max_workers );

int
fd_runtime_block_prepare( void const * buf,
                          ulong buf_sz,
                          fd_valloc_t valloc,
                          fd_block_info_t * out_block_info );

ulong
fd_runtime_block_collect_txns( fd_block_info_t const * block_info,
                               fd_txn_p_t * out_txns );

int
fd_runtime_block_eval_tpool( fd_exec_slot_ctx_t * slot_ctx,
                             fd_capture_ctx_t * capture_ctx,
                             const void * block,
                             ulong blocklen,
                             fd_tpool_t * tpool,
                             ulong max_workers,
                             ulong scheduler,
                             ulong * txn_cnt );

ulong
fd_runtime_calculate_fee ( fd_exec_txn_ctx_t * txn_ctx,
                           fd_txn_t const * txn_descriptor,
                           fd_rawtxn_b_t const * txn_raw );
void
fd_runtime_freeze( fd_exec_slot_ctx_t * slot_ctx );

ulong
fd_runtime_lamports_per_signature_for_blockhash( fd_exec_slot_ctx_t const * slot_ctx,
                                                 fd_hash_t const * blockhash );

fd_funk_rec_key_t
fd_runtime_firedancer_bank_key( void );

fd_funk_rec_key_t
fd_runtime_epoch_bank_key( void );

fd_funk_rec_key_t
fd_runtime_slot_bank_key( void );

int
fd_runtime_save_slot_bank( fd_exec_slot_ctx_t * slot_ctx );

int
fd_runtime_save_epoch_bank( fd_exec_slot_ctx_t * slot_ctx );

int
fd_global_import_solana_manifest( fd_exec_slot_ctx_t * slot_ctx,
                                  fd_solana_manifest_t * manifest);

/* fd_features_restore loads all known feature accounts from the
   accounts database.  This is used when initializing bank from a
   snapshot. */

void
fd_features_restore( fd_exec_slot_ctx_t * slot_ctx );

static inline ulong
fd_rent_exempt( fd_rent_t const * rent,
                ulong             sz ) {
  return (sz + 128) * ((ulong) ((double)rent->lamports_per_uint8_year * rent->exemption_threshold));
}

void
fd_process_new_epoch( fd_exec_slot_ctx_t * slot_ctx,
                      ulong parent_epoch );

void
fd_runtime_update_leaders( fd_exec_slot_ctx_t * slot_ctx, ulong slot );

/* rollback runtime to the state where the given slot just FINISHED executing */
int
fd_runtime_rollback_to( fd_exec_slot_ctx_t * slot_ctx, ulong slot );

/* Recover slot_bank and epoch_bnck from funky */
void
fd_runtime_recover_banks( fd_exec_slot_ctx_t * slot_ctx, int delete_first );

void
fd_runtime_delete_banks( fd_exec_slot_ctx_t * slot_ctx );

/* Recover slot_ctx from funky */
void
fd_runtime_recover_slot_ctx( fd_exec_slot_ctx_t * slot_ctx );

/* fd_runtime_ctx_{align,footprint} return FD_REPLAY_STATE_{ALIGN,FOOTPRINT}. */

FD_FN_CONST ulong
fd_runtime_ctx_align( void );

FD_FN_CONST ulong
fd_runtime_ctx_footprint( void );

void *
fd_runtime_ctx_new( void * shmem );

/* fd_runtime_ctx_join returns the local join to the wksp backing the funk.
   The lifetime of the returned pointer is at least as long as the
   lifetime of the local join.  Assumes funk is a current local join. */

fd_runtime_ctx_t *
fd_runtime_ctx_join( void * state );

/* fd_runtime_ctx_leave leaves an existing join.  Returns the underlying
   shfunk on success and NULL on failure.  (logs details). */

void *
fd_runtime_ctx_leave( fd_runtime_ctx_t * state );

/* fd_runtime_ctx_delete unformats a wksp allocation used as a replay_state */
void *
fd_runtime_ctx_delete( void * state );

int
fd_runtime_replay( fd_runtime_ctx_t * state, fd_runtime_args_t *args );

int
fd_runtime_sysvar_cache_load( fd_exec_slot_ctx_t * slot_ctx );

void
fd_runtime_cleanup_incinerator( fd_exec_slot_ctx_t * slot_ctx );

int
fd_runtime_prepare_txns( fd_exec_slot_ctx_t * slot_ctx,
                         fd_execute_txn_task_info_t * task_info,
                         fd_txn_p_t * txns,
                         ulong txn_cnt );
                        
int
fd_runtime_execute_txns_tpool( fd_exec_slot_ctx_t * slot_ctx,
                               fd_capture_ctx_t * capture_ctx,
                               fd_txn_p_t * txns,
                               ulong txn_cnt,
                               fd_execute_txn_task_info_t * task_infos,
                               fd_tpool_t * tpool,
                               ulong max_workers );

int
fd_runtime_block_execute_finalize_tpool( fd_exec_slot_ctx_t * slot_ctx,
                                         fd_capture_ctx_t * capture_ctx,
                                         fd_block_info_t const * block_info,
                                         fd_tpool_t * tpool,
                                         ulong max_workers );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_h */
