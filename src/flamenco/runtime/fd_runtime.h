#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_h

#include "../fd_flamenco_base.h"
#include "fd_runtime_err.h"
#include "fd_runtime_init.h"
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

#define DEFAULT_HASHES_PER_TICK   12500
#define UPDATED_HASHES_PER_TICK2  17500
#define UPDATED_HASHES_PER_TICK3  27500
#define UPDATED_HASHES_PER_TICK4  47500
#define UPDATED_HASHES_PER_TICK5  57500
#define UPDATED_HASHES_PER_TICK6  62500

#define FD_RUNTIME_TRACE_NONE   (0)
#define FD_RUNTIME_TRACE_SAVE   (1)
#define FD_RUNTIME_TRACE_REPLAY (2)

#define FD_RUNTIME_NUM_ROOT_BLOCKS (32UL)

#define FD_FEATURE_ACTIVE(_slot_ctx, _feature_name)  (_slot_ctx->slot_bank.slot >= _slot_ctx->epoch_ctx->features. _feature_name)

#define FD_BLOCKHASH_QUEUE_MAX_ENTRIES       (300UL)
#define FD_RECENT_BLOCKHASHES_MAX_ENTRIES    (150UL)

#define FD_RENT_EXEMPT_RENT_EPOCH (ULONG_MAX)

#define SECONDS_PER_YEAR ((double)(365.242199 * 24.0 * 60.0 * 60.0))

/* TODO: increase this to default once we have enough memory to support a 95G status cache. */
#define MAX_CACHE_TXNS_PER_SLOT (FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT / 8)

struct fd_execute_txn_task_info {
  fd_spad_t * * spads;
  fd_exec_txn_ctx_t * txn_ctx;
  fd_txn_p_t * txn;
  int exec_res;
};
typedef struct fd_execute_txn_task_info fd_execute_txn_task_info_t;

typedef ulong fd_microblock_txn_iter_t;

struct fd_microblock_batch_txn_iter {
  ulong curr_microblock;
  fd_microblock_txn_iter_t microblock_iter;
};

typedef struct fd_microblock_batch_txn_iter fd_microblock_batch_txn_iter_t;

struct fd_block_txn_iter {
  ulong curr_batch;
  fd_microblock_batch_txn_iter_t microblock_batch_iter;
};

typedef struct fd_block_txn_iter fd_block_txn_iter_t;

struct fd_raw_block_txn_iter {
  ulong remaining_microblocks;
  ulong remaining_txns;
  ulong curr_offset;
  ulong data_sz;

  ulong curr_txn_sz;
};

typedef struct fd_raw_block_txn_iter fd_raw_block_txn_iter_t;

/* The prevailing layout we have in the runtime is the meta followed by
   the account's data. This struct encodes that layout and asserts that
   the alignment requirements of the constituents are satisfied. */
// TODO: Use this struct at allocation sites so it's clear we use this layout
struct __attribute__((packed)) fd_account_rec {
  fd_account_meta_t meta;
  uchar data[];
};
typedef struct fd_account_rec fd_account_rec_t;
#define FD_ACCOUNT_REC_ALIGN      (8UL)
#define FD_ACCOUNT_REC_DATA_ALIGN (8UL)
FD_STATIC_ASSERT( FD_ACCOUNT_REC_ALIGN>=FD_ACCOUNT_META_ALIGN,     account_rec_meta_align );
FD_STATIC_ASSERT( FD_ACCOUNT_REC_ALIGN>=FD_ACCOUNT_REC_DATA_ALIGN, account_rec_data_align );
FD_STATIC_ASSERT( (offsetof(fd_account_rec_t, meta)%FD_ACCOUNT_META_ALIGN)==0,     account_rec_meta_offset );
FD_STATIC_ASSERT( (offsetof(fd_account_rec_t, data)%FD_ACCOUNT_REC_DATA_ALIGN)==0, account_rec_data_offset );

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
                               fd_tpool_t * tpool );

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
                             ulong scheduler,
                             ulong * txn_cnt,
                             fd_spad_t * * spads,
                             ulong spads_cnt );

int
fd_runtime_execute_pack_txns( fd_exec_slot_ctx_t * slot_ctx,
                              fd_spad_t * spad,
                              fd_capture_ctx_t * capture_ctx,
                              fd_txn_p_t * txns,
                              ulong txn_cnt );

int
fd_runtime_execute_txns_in_waves_tpool( fd_exec_slot_ctx_t * slot_ctx,
                                        fd_capture_ctx_t * capture_ctx,
                                        fd_txn_p_t * txns,
                                        ulong txn_cnt,
                                        fd_tpool_t * tpool,
                                        fd_spad_t * * spads, 
                                        ulong spads_cnt );

void
fd_runtime_calculate_fee ( fd_exec_txn_ctx_t * txn_ctx,
                           fd_txn_t const * txn_descriptor,
                           fd_rawtxn_b_t const * txn_raw,
                           ulong *execution_fee,
                           ulong *priority_fee );
void
fd_runtime_freeze( fd_exec_slot_ctx_t * slot_ctx );

ulong
fd_runtime_lamports_per_signature_for_blockhash( fd_exec_slot_ctx_t const * slot_ctx,
                                                 fd_hash_t const * blockhash );

// int
// fd_global_import_solana_manifest( fd_exec_slot_ctx_t * slot_ctx,
//                                   fd_solana_manifest_t * manifest);


void
fd_process_new_epoch( fd_exec_slot_ctx_t * slot_ctx,
                      ulong parent_epoch );

void
fd_runtime_update_leaders( fd_exec_slot_ctx_t * slot_ctx, ulong slot );

/* rollback runtime to the state where the given slot just FINISHED executing */
int
fd_runtime_rollback_to( fd_exec_slot_ctx_t * slot_ctx, ulong slot );

int
fd_runtime_sysvar_cache_load( fd_exec_slot_ctx_t * slot_ctx );

void
fd_runtime_cleanup_incinerator( fd_exec_slot_ctx_t * slot_ctx );

int
fd_runtime_prep_and_exec_txns_tpool( fd_exec_slot_ctx_t * slot_ctx,
                                     fd_execute_txn_task_info_t * task_info,
                                     ulong txn_cnt,
                                     fd_tpool_t * tpool );

int
fd_runtime_prepare_txns( fd_exec_slot_ctx_t * slot_ctx,
                         fd_execute_txn_task_info_t * task_info,
                         fd_txn_p_t * txns,
                         ulong txn_cnt );

int
fd_runtime_prepare_txns_start( fd_exec_slot_ctx_t *         slot_ctx,
                               fd_execute_txn_task_info_t * task_info,
                               fd_txn_p_t *                 txns,
                               ulong                        txn_cnt );

int
fd_runtime_prepare_txns_phase3( fd_exec_slot_ctx_t * slot_ctx,
                                fd_execute_txn_task_info_t * task_info,
                                ulong txn_cnt );

int
fd_runtime_prepare_execute_finalize_txn( fd_exec_slot_ctx_t *         slot_ctx,
                                         fd_spad_t *                  spad,
                                         fd_capture_ctx_t *           capture_ctx,
                                         fd_txn_p_t *                 txn,
                                         fd_execute_txn_task_info_t * task_info );

int
fd_runtime_block_execute_finalize_tpool( fd_exec_slot_ctx_t * slot_ctx,
                                         fd_capture_ctx_t * capture_ctx,
                                         fd_block_info_t const * block_info,
                                         fd_tpool_t * tpool );

ulong
fd_runtime_collect_rent_from_account( fd_exec_slot_ctx_t const * slot_ctx,
                                      fd_account_meta_t  *       acc,
                                      fd_pubkey_t const  *       key,
                                      ulong                      epoch );

void
fd_runtime_execute_txn( fd_execute_txn_task_info_t * task_info );

void
fd_runtime_pre_execute_check( fd_execute_txn_task_info_t * task_info );

int
fd_runtime_finalize_txns_tpool( fd_exec_slot_ctx_t * slot_ctx,
                                fd_capture_ctx_t * capture_ctx,
                                fd_execute_txn_task_info_t * task_info,
                                ulong txn_cnt,
                                fd_tpool_t * tpool );

int
fd_runtime_finalize_txn( fd_exec_slot_ctx_t *         slot_ctx,
                         fd_capture_ctx_t *           capture_ctx,
                         fd_execute_txn_task_info_t * task_info );

void
fd_runtime_collect_rent_accounts_prune( ulong slot,
                                        fd_exec_slot_ctx_t * slot_ctx,
                                        fd_capture_ctx_t * capture_ctx );

void
fd_runtime_read_genesis( fd_exec_slot_ctx_t * slot_ctx,
                         char const * genesis_filepath,
                         uchar is_snapshot,
                         fd_capture_ctx_t   * capture_ctx );

void
fd_runtime_checkpt( fd_capture_ctx_t * capture_ctx,
                    fd_exec_slot_ctx_t * slot_ctx,
                    ulong slot );

fd_microblock_txn_iter_t
fd_microblock_txn_iter_init( fd_microblock_info_t const * microblock_info );

ulong
fd_microblock_txn_iter_done( fd_microblock_info_t const * microblock_info, fd_microblock_txn_iter_t iter );

fd_microblock_txn_iter_t
fd_microblock_txn_iter_next( fd_microblock_info_t const * microblock_info FD_PARAM_UNUSED, fd_microblock_txn_iter_t iter );

fd_txn_p_t *
fd_microblock_txn_iter_ele( fd_microblock_info_t const * microblock_info, fd_microblock_txn_iter_t iter );

fd_microblock_batch_txn_iter_t
fd_microblock_batch_txn_iter_init( fd_microblock_batch_info_t const * microblock_batch_info );

ulong
fd_microblock_batch_txn_iter_done( fd_microblock_batch_info_t const * microblock_batch_info, fd_microblock_batch_txn_iter_t iter );

fd_microblock_batch_txn_iter_t
fd_microblock_batch_txn_iter_next( fd_microblock_batch_info_t const * microblock_batch_info, fd_microblock_batch_txn_iter_t iter );

fd_txn_p_t *
fd_microblock_batch_txn_iter_ele( fd_microblock_batch_info_t const * microblock_batch_info, fd_microblock_batch_txn_iter_t iter );

fd_block_txn_iter_t
fd_block_txn_iter_init( fd_block_info_t const * block_info );

ulong
fd_block_txn_iter_done( fd_block_info_t const * block_info, fd_block_txn_iter_t iter );

fd_block_txn_iter_t
fd_block_txn_iter_next( fd_block_info_t const * block_info, fd_block_txn_iter_t iter );

fd_txn_p_t *
fd_block_txn_iter_ele( fd_block_info_t const * block_info, fd_block_txn_iter_t iter );

fd_raw_block_txn_iter_t
fd_raw_block_txn_iter_init( uchar const * data, ulong data_sz );

ulong
fd_raw_block_txn_iter_done( fd_raw_block_txn_iter_t iter );

fd_raw_block_txn_iter_t
fd_raw_block_txn_iter_next( uchar const * data, fd_raw_block_txn_iter_t iter );

void
fd_raw_block_txn_iter_ele( uchar const * data, fd_raw_block_txn_iter_t iter, fd_txn_p_t * out_txn );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_h */
