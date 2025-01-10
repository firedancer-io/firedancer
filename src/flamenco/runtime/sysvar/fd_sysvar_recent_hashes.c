#include <stdio.h>
#include "../fd_acc_mgr.h"
#include "../fd_hashes.h"
#include "fd_sysvar.h"
#include "../fd_runtime.h"
#include "../fd_system_ids.h"
#include "../context/fd_exec_slot_ctx.h"

#define FD_RECENT_BLOCKHASHES_ACCOUNT_MAX_SIZE  sizeof(ulong) + FD_RECENT_BLOCKHASHES_MAX_ENTRIES * (sizeof(fd_hash_t) + sizeof(ulong))

// run --ledger /home/jsiegel/test-ledger --db /home/jsiegel/funk --cmd accounts --accounts /home/jsiegel/test-ledger/accounts/ --pages 15 --index-max 120000000 --start-slot 2 --end-slot 2 --start-id 35 --end-id 37
// run --ledger /home/jsiegel/test-ledger --db /home/jsiegel/funk --cmd replay --pages 15 --index-max 120000000 --start-slot 0 --end-slot 3

// {meta = {write_version_obsolete = 137,
// data_len = 6008, pubkey = "\006\247\325\027\031,V\216\340\212\204_sҗ\210\317\003\\1E\262\032\263D\330\006.\251@\000"}, info = {lamports = 42706560, rent_epoch = 0, owner = "\006\247\325\027\030u\367)\307=\223@\217!a \006~،v\340\214(\177\301\224`\000\000\000", executable = 0 '\000', padding = "K\000\f\376\177\000"}, hash = {value = "\302Q\316\035qTY\347\352]\260\335\213\224R\227ԯ\366R\273\063H\345֑c\377\207/k\275"}}

// owner:      Sysvar1111111111111111111111111111111111111 pubkey:      SysvarRecentB1ockHashes11111111111111111111 hash:     E5YSehyvJ7xXcNnQjWCH9UhMJ1dxDBJ1RuuPh1Y3RZgg file: /home/jsiegel/test-ledger/accounts//2.37
//   {blockhash = JCidNXtcMXMWQwMDM3ZQq5pxaw3hQpNbeHg1KcstjuF4,  fee_calculator={lamports_per_signature = 5000}}
//   {blockhash = GQN3oV8G1Ra3GCX76dE1YYJ6UjMyDreNCEWM4tZ39zj1,  fee_calculator={lamports_per_signature = 5000}}
//   {blockhash = Ha5DVgnD1xSA8oQc337jtA3atEfQ4TFX1ajeZG1Y2tUx,  fee_calculator={lamports_per_signature = 0}}

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
void fd_sysvar_recent_hashes_init( fd_exec_slot_ctx_t * slot_ctx ) {
FD_SCRATCH_SCOPE_BEGIN {
  if( slot_ctx->slot_bank.slot != 0 ) {
    return;
  }

  ulong sz = FD_RECENT_BLOCKHASHES_ACCOUNT_MAX_SIZE;
  uchar * enc = fd_scratch_alloc( 1UL, sz );
  fd_memset( enc, 0, sz );
  encode_rbh_from_blockhash_queue( slot_ctx, enc );
  fd_sysvar_set( slot_ctx, fd_sysvar_owner_id.key, &fd_sysvar_recent_block_hashes_id, enc, sz, slot_ctx->slot_bank.slot );
} FD_SCRATCH_SCOPE_END;
}

// https://github.com/anza-xyz/agave/blob/e8750ba574d9ac7b72e944bc1227dc7372e3a490/accounts-db/src/blockhash_queue.rs#L113
static void
register_blockhash( fd_exec_slot_ctx_t* slot_ctx, fd_hash_t const * hash ) {
  fd_block_hash_queue_t * queue = &slot_ctx->slot_bank.block_hash_queue;
  // https://github.com/anza-xyz/agave/blob/e8750ba574d9ac7b72e944bc1227dc7372e3a490/accounts-db/src/blockhash_queue.rs#L114
  queue->last_hash_index++;
  if ( fd_hash_hash_age_pair_t_map_size( queue->ages_pool, queue->ages_root ) >= queue->max_age ) {
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
void fd_sysvar_recent_hashes_update( fd_exec_slot_ctx_t * slot_ctx ) {
FD_SCRATCH_SCOPE_BEGIN {
  /* Update the blockhash queue */
  register_blockhash( slot_ctx, &slot_ctx->slot_bank.poh );

  /* Derive the new sysvar recent blockhashes from the blockhash queue */
  ulong   sz        = FD_RECENT_BLOCKHASHES_ACCOUNT_MAX_SIZE;
  uchar * enc       = fd_scratch_alloc( 1UL, sz );
  uchar * enc_start = enc;
  fd_memset( enc, 0, sz );

  /* Encode the recent blockhashes */
  encode_rbh_from_blockhash_queue( slot_ctx, enc );

  /* Set the sysvar from the encoded data */
  fd_sysvar_set( slot_ctx, fd_sysvar_owner_id.key, &fd_sysvar_recent_block_hashes_id, enc_start, sz, slot_ctx->slot_bank.slot );
} FD_SCRATCH_SCOPE_END;
}

#undef UNCHECKED_ENC
