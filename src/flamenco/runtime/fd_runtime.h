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
#include "sysvar/fd_sysvar.h"
#include "context/fd_exec_slot_ctx.h"
#include "context/fd_exec_txn_ctx.h"
#include "info/fd_block_info.h"
#include "info/fd_instr_info.h"

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

#define FD_ACC_MGR_KEY_TYPE ((uchar)0)

/* FD_BLOCK_BANKS_TYPE stores fd_firedancer_banks_t bincode encoded (obsolete)*/
#define FD_BLOCK_BANKS_TYPE ((uchar)3)

/* FD_BLOCK_SLOT_BANK_TYPE stores fd_slot_bank_t bincode encoded */
#define FD_BLOCK_SLOT_BANK_TYPE ((uchar)6)

/* FD_BLOCK_EPOCH_BANK_TYPE stores fd_epoch_bank_t bincode encoded */
#define FD_BLOCK_EPOCH_BANK_TYPE ((uchar)7)

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

int
fd_runtime_block_eval_tpool( fd_exec_slot_ctx_t * slot_ctx,
                             fd_capture_ctx_t * capture_ctx,
                             const void * block,
                             ulong blocklen,
                             fd_tpool_t * tpool,
                             ulong max_workers,
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
fd_runtime_update_leaders( fd_exec_slot_ctx_t * slot_ctx, ulong slot);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_h */
