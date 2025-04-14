#include <stdio.h>
#include "../fd_acc_mgr.h"
#include "../fd_hashes.h"
#include "fd_sysvar.h"
#include "../fd_runtime.h"
#include "../fd_system_ids.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../fd_bank_mgr.h"

#define FD_RECENT_BLOCKHASHES_ACCOUNT_MAX_SIZE  sizeof(ulong) + FD_RECENT_BLOCKHASHES_MAX_ENTRIES * (sizeof(fd_hash_t) + sizeof(ulong))

/* Skips fd_types encoding preflight checks and directly serializes the blockhash queue into a buffer representing
   account data for the recent blockhashes sysvar. */
static void
encode_rbh_from_blockhash_queue( fd_exec_slot_ctx_t * slot_ctx, uchar * enc ) {
  /* recent_blockhashes_account::update_account's `take` call takes at most 150 elements
     https://github.com/anza-xyz/agave/blob/v2.1.6/runtime/src/bank/recent_blockhashes_account.rs#L15-L28 */
  fd_block_hash_queue_t const * queue = &slot_ctx->slot_bank.block_hash_queue;
  ulong queue_sz                      = fd_hash_hash_age_pair_t_map_size( queue->ages_pool, queue->ages_root );
  ulong hashes_len                    = fd_ulong_min( queue_sz, FD_RECENT_BLOCKHASHES_MAX_ENTRIES );
  fd_memcpy( enc, &hashes_len, sizeof(ulong) );
  enc += sizeof(ulong);

  /* Iterate over blockhash queue and encode the recent blockhashes. We can do direct memcpying
     and avoid redundant checks from fd_types encoders since the enc buffer is already sized out to
     the worst-case bound. */
  fd_hash_hash_age_pair_t_mapnode_t const * nn;
  for( fd_hash_hash_age_pair_t_mapnode_t const * n = fd_hash_hash_age_pair_t_map_minimum_const( queue->ages_pool, queue->ages_root ); n; n = nn ) {
    nn = fd_hash_hash_age_pair_t_map_successor_const( queue->ages_pool, n );
    ulong enc_idx = queue->last_hash_index - n->elem.val.hash_index;
    if( enc_idx>=hashes_len ) {
      continue;
    }
    fd_hash_t hash = n->elem.key;
    ulong     lps  = n->elem.val.fee_calculator.lamports_per_signature;

    fd_memcpy( enc + enc_idx * (FD_HASH_FOOTPRINT + sizeof(ulong)), &hash, FD_HASH_FOOTPRINT );
    fd_memcpy( enc + enc_idx * (FD_HASH_FOOTPRINT + sizeof(ulong)) + sizeof(fd_hash_t), &lps, sizeof(ulong) );
  }
}

// https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/fee_calculator.rs#L110
void
fd_sysvar_recent_hashes_init( fd_exec_slot_ctx_t * slot_ctx,
                              fd_spad_t *          runtime_spad ) {

  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

  if( slot_ctx->slot_bank.slot != 0 ) {
    return;
  }

  ulong   sz  = FD_RECENT_BLOCKHASHES_ACCOUNT_MAX_SIZE;
  uchar * enc = fd_spad_alloc( runtime_spad, FD_SPAD_ALIGN, sz );
  fd_memset( enc, 0, sz );
  encode_rbh_from_blockhash_queue( slot_ctx, enc );
  fd_sysvar_set( slot_ctx, &fd_sysvar_owner_id, &fd_sysvar_recent_block_hashes_id, enc, sz, slot_ctx->slot_bank.slot );

  } FD_SPAD_FRAME_END;
}

// https://github.com/anza-xyz/agave/blob/e8750ba574d9ac7b72e944bc1227dc7372e3a490/accounts-db/src/blockhash_queue.rs#L113
static void
register_blockhash( fd_exec_slot_ctx_t *           slot_ctx,
                    fd_block_hash_queue_global_t * block_hash_queue_global,
                    fd_hash_t const *              hash ) {

  (void)block_hash_queue_global;
  // block_hash_queue_global->last_hash_index++;
  // fd_hash_hash_age_pair_t_mapnode_t * ages_pool       = fd_hash_hash_age_pair_t_map_join( fd_wksp_laddr_fast( slot_ctx->funk_wksp, block_hash_queue_global->ages_pool_gaddr ) );
  // fd_hash_hash_age_pair_t_mapnode_t * ages_root       = fd_wksp_laddr_fast( slot_ctx->funk_wksp, block_hash_queue_global->ages_root_gaddr );
  // ulong                               max_age         = block_hash_queue_global->max_age;
  // ulong                               last_hash_index = block_hash_queue_global->last_hash_index;

  // if( fd_hash_hash_age_pair_t_map_size( ages_pool, ages_root ) >= max_age ) {
  //   fd_hash_hash_age_pair_t_mapnode_t * nn;
  //   for( fd_hash_hash_age_pair_t_mapnode_t * n = fd_hash_hash_age_pair_t_map_minimum( ages_pool, ages_root ); n; n = nn ) {
  //     nn = fd_hash_hash_age_pair_t_map_successor( ages_pool, n );
  //     /* NOTE: Yes, this check is incorrect. It should be >= which caps the blockhash queue at max_age
  //       entries, but instead max_age + 1 entries are allowed to exist in the queue at once. This mimics
  //       Agave to stay conformant with their implementation.
  //       https://github.com/anza-xyz/agave/blob/e8750ba574d9ac7b72e944bc1227dc7372e3a490/accounts-db/src/blockhash_queue.rs#L109 */
  //     if( last_hash_index - n->elem.val.hash_index > max_age ) {
  //       fd_hash_hash_age_pair_t_map_remove( ages_pool, &ages_root, n );
  //       fd_hash_hash_age_pair_t_map_release( ages_pool, n );
  //     }
  //   }
  // }
  // fd_hash_hash_age_pair_t_mapnode_t * node = fd_hash_hash_age_pair_t_map_acquire( ages_pool );
  // node->elem = (fd_hash_hash_age_pair_t) {
  //   .key = *hash,
  //   .val = (fd_hash_age_t){ .hash_index     = last_hash_index,
  //                           .fee_calculator = (fd_fee_calculator_t){ .lamports_per_signature = slot_ctx->slot_bank.lamports_per_signature },
  //                           .timestamp      = (ulong)fd_log_wallclock() }
  // };
  // // https://github.com/anza-xyz/agave/blob/e8750ba574d9ac7b72e944bc1227dc7372e3a490/accounts-db/src/blockhash_queue.rs#L121-L128
  // fd_hash_hash_age_pair_t_map_insert( slot_ctx->slot_bank.block_hash_queue.ages_pool, &slot_ctx->slot_bank.block_hash_queue.ages_root, node );
  // // https://github.com/anza-xyz/agave/blob/e8750ba574d9ac7b72e944bc1227dc7372e3a490/accounts-db/src/blockhash_queue.rs#L130
  // fd_hash_t * last_hash = fd_wksp_laddr_fast( slot_ctx->funk_wksp, block_hash_queue_global->last_hash_gaddr );
  // fd_memcpy( last_hash, hash, sizeof(fd_hash_t) );


  fd_block_hash_queue_t * queue = &slot_ctx->slot_bank.block_hash_queue;
  // https://github.com/anza-xyz/agave/blob/e8750ba574d9ac7b72e944bc1227dc7372e3a490/accounts-db/src/blockhash_queue.rs#L114
  queue->last_hash_index++;
  if( fd_hash_hash_age_pair_t_map_size( queue->ages_pool, queue->ages_root ) >= queue->max_age ) {
    fd_hash_hash_age_pair_t_mapnode_t * nn;
    for ( fd_hash_hash_age_pair_t_mapnode_t * n = fd_hash_hash_age_pair_t_map_minimum( queue->ages_pool, queue->ages_root ); n; n = nn ) {
      nn = fd_hash_hash_age_pair_t_map_successor( queue->ages_pool, n );
      /* NOTE: Yes, this check is incorrect. It should be >= which caps the blockhash queue at max_age
         entries, but instead max_age + 1 entries are allowed to exist in the queue at once. This mimics
         Agave to stay conformant with their implementation.
         https://github.com/anza-xyz/agave/blob/e8750ba574d9ac7b72e944bc1227dc7372e3a490/accounts-db/src/blockhash_queue.rs#L109 */
      if ( queue->last_hash_index - n->elem.val.hash_index > queue->max_age ) {
        fd_hash_hash_age_pair_t_map_remove( queue->ages_pool, &queue->ages_root, n );
        fd_hash_hash_age_pair_t_map_release( queue->ages_pool, n );
      }
    }
  }

  fd_hash_hash_age_pair_t_mapnode_t * node = fd_hash_hash_age_pair_t_map_acquire( queue->ages_pool );
  node->elem = (fd_hash_hash_age_pair_t){
    .key = *hash,
    .val = (fd_hash_age_t){ .hash_index = queue->last_hash_index, .fee_calculator = (fd_fee_calculator_t){.lamports_per_signature = slot_ctx->slot_bank.lamports_per_signature}, .timestamp = (ulong)fd_log_wallclock() }
  };
  // https://github.com/anza-xyz/agave/blob/e8750ba574d9ac7b72e944bc1227dc7372e3a490/accounts-db/src/blockhash_queue.rs#L121-L128
  fd_hash_hash_age_pair_t_map_insert( slot_ctx->slot_bank.block_hash_queue.ages_pool, &slot_ctx->slot_bank.block_hash_queue.ages_root, node );
  // https://github.com/anza-xyz/agave/blob/e8750ba574d9ac7b72e944bc1227dc7372e3a490/accounts-db/src/blockhash_queue.rs#L130
  fd_memcpy( queue->last_hash, hash, sizeof(fd_hash_t) );
}

/* This implementation is more consistent with Agave's bank implementation for updating the block hashes sysvar:
   1. Update the block hash queue with the latest poh
   2. Take the first 150 blockhashes from the queue (or fewer if there are)
   3. Manually serialize the recent blockhashes
   4. Set the sysvar account with the new data */
void
fd_sysvar_recent_hashes_update( fd_exec_slot_ctx_t * slot_ctx, fd_spad_t * runtime_spad ) {
  FD_SPAD_FRAME_BEGIN( runtime_spad ) {
  /* Update the blockhash queue */

  ulong total_bhq_sz = sizeof(fd_block_hash_queue_global_t) +
                       alignof(fd_block_hash_queue_global_t) +
                       sizeof(fd_hash_t) +
                       alignof(fd_hash_t) +
                       fd_hash_hash_age_pair_t_map_footprint( 400 ) +
                       fd_hash_hash_age_pair_t_map_align();

  fd_bank_mgr_prepare_t bank_mgr_prepare = {0};
  int err = fd_bank_mgr_prepare_entry( slot_ctx->funk,
                                       slot_ctx->funk_txn,
                                       BLOCK_HASH_QUEUE_ID,
                                       total_bhq_sz,
                                       &bank_mgr_prepare );
  FD_TEST( err == FD_BANK_MGR_SUCCESS );

  register_blockhash( slot_ctx,
                      (fd_block_hash_queue_global_t *)bank_mgr_prepare.data,
                      &slot_ctx->slot_bank.poh );

  /* Derive the new sysvar recent blockhashes from the blockhash queue */
  ulong   sz        = FD_RECENT_BLOCKHASHES_ACCOUNT_MAX_SIZE;
  uchar * enc       = fd_spad_alloc( runtime_spad, FD_SPAD_ALIGN, sz );
  uchar * enc_start = enc;
  fd_memset( enc, 0, sz );

  /* Encode the recent blockhashes */
  encode_rbh_from_blockhash_queue( slot_ctx, enc );

  /* Set the sysvar from the encoded data */
  fd_sysvar_set( slot_ctx,
                 &fd_sysvar_owner_id,
                 &fd_sysvar_recent_block_hashes_id,
                 enc_start,
                 sz,
                 slot_ctx->slot_bank.slot );
  } FD_SPAD_FRAME_END;
}
