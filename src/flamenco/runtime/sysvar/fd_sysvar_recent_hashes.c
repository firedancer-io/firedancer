#include <stdio.h>
#include "../fd_acc_mgr.h"
#include "../fd_hashes.h"
#include "fd_sysvar.h"
#include "../fd_runtime.h"
#include "../fd_system_ids.h"

#define FD_RECENT_BLOCKHASHES_ACCOUNT_MAX_SIZE  sizeof(ulong) + FD_RECENT_BLOCKHASHES_MAX_ENTRIES * (sizeof(fd_hash_t) + sizeof(ulong))

// run --ledger /home/jsiegel/test-ledger --db /home/jsiegel/funk --cmd accounts --accounts /home/jsiegel/test-ledger/accounts/ --pages 15 --index-max 120000000 --start-slot 2 --end-slot 2 --start-id 35 --end-id 37
// run --ledger /home/jsiegel/test-ledger --db /home/jsiegel/funk --cmd replay --pages 15 --index-max 120000000 --start-slot 0 --end-slot 3

// {meta = {write_version_obsolete = 137,
// data_len = 6008, pubkey = "\006\247\325\027\031,V\216\340\212\204_sҗ\210\317\003\\1E\262\032\263D\330\006.\251@\000"}, info = {lamports = 42706560, rent_epoch = 0, owner = "\006\247\325\027\030u\367)\307=\223@\217!a \006~،v\340\214(\177\301\224`\000\000\000", executable = 0 '\000', padding = "K\000\f\376\177\000"}, hash = {value = "\302Q\316\035qTY\347\352]\260\335\213\224R\227ԯ\366R\273\063H\345֑c\377\207/k\275"}}

// owner:      Sysvar1111111111111111111111111111111111111 pubkey:      SysvarRecentB1ockHashes11111111111111111111 hash:     E5YSehyvJ7xXcNnQjWCH9UhMJ1dxDBJ1RuuPh1Y3RZgg file: /home/jsiegel/test-ledger/accounts//2.37
//   {blockhash = JCidNXtcMXMWQwMDM3ZQq5pxaw3hQpNbeHg1KcstjuF4,  fee_calculator={lamports_per_signature = 5000}}
//   {blockhash = GQN3oV8G1Ra3GCX76dE1YYJ6UjMyDreNCEWM4tZ39zj1,  fee_calculator={lamports_per_signature = 5000}}
//   {blockhash = Ha5DVgnD1xSA8oQc337jtA3atEfQ4TFX1ajeZG1Y2tUx,  fee_calculator={lamports_per_signature = 0}}

void fd_sysvar_recent_hashes_init( fd_exec_slot_ctx_t* slot_ctx ) {
  // https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/fee_calculator.rs#L110

  if (slot_ctx->slot_bank.slot != 0)
    return;

  ulong sz = fd_recent_block_hashes_size(&slot_ctx->slot_bank.recent_block_hashes);
  if (sz < FD_RECENT_BLOCKHASHES_ACCOUNT_MAX_SIZE)
    sz = FD_RECENT_BLOCKHASHES_ACCOUNT_MAX_SIZE;
  unsigned char *enc = fd_alloca(1, sz);
  memset(enc, 0, sz);
  fd_bincode_encode_ctx_t ctx;
  ctx.data = enc;
  ctx.dataend = enc + sz;
  if ( fd_recent_block_hashes_encode(&slot_ctx->slot_bank.recent_block_hashes, &ctx) )
    FD_LOG_ERR(("fd_recent_block_hashes_encode failed"));

  fd_sysvar_set(slot_ctx, fd_sysvar_owner_id.key, &fd_sysvar_recent_block_hashes_id, enc, sz, slot_ctx->slot_bank.slot, 0UL );
}

void register_blockhash( fd_exec_slot_ctx_t* slot_ctx, fd_hash_t const * hash ) {
  fd_block_hash_queue_t * queue = &slot_ctx->slot_bank.block_hash_queue;
  queue->last_hash_index++;
  if ( fd_hash_hash_age_pair_t_map_size( queue->ages_pool, queue->ages_root ) >= queue->max_age ) {
    fd_hash_hash_age_pair_t_mapnode_t * nn;
    for ( fd_hash_hash_age_pair_t_mapnode_t * n = fd_hash_hash_age_pair_t_map_minimum( queue->ages_pool, queue->ages_root ); n; n = nn ) {
      nn = fd_hash_hash_age_pair_t_map_successor( queue->ages_pool, n );
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
  fd_hash_hash_age_pair_t_map_insert( slot_ctx->slot_bank.block_hash_queue.ages_pool, &slot_ctx->slot_bank.block_hash_queue.ages_root, node );
  fd_memcpy( queue->last_hash, hash, sizeof(fd_hash_t) );
}

void fd_sysvar_recent_hashes_update( fd_exec_slot_ctx_t* slot_ctx ) {
  if (slot_ctx->slot_bank.slot == 0)  // we already set this... as part of boot
    return;

  fd_block_block_hash_entry_t * hashes = slot_ctx->slot_bank.recent_block_hashes.hashes;
  fd_bincode_destroy_ctx_t ctx2 = { .valloc = slot_ctx->valloc };
  while (deq_fd_block_block_hash_entry_t_cnt(hashes) >= FD_RECENT_BLOCKHASHES_MAX_ENTRIES)
    fd_block_block_hash_entry_destroy( deq_fd_block_block_hash_entry_t_pop_tail_nocopy( hashes ), &ctx2 );

  FD_TEST( !deq_fd_block_block_hash_entry_t_full(hashes) );
  fd_block_block_hash_entry_t * elem = deq_fd_block_block_hash_entry_t_push_head_nocopy(hashes);
  fd_block_block_hash_entry_new(elem);
  // bank.poh is updated in fd_runtime_block_verify
  fd_memcpy(elem->blockhash.hash, &slot_ctx->slot_bank.poh, sizeof(slot_ctx->slot_bank.poh));

  elem->fee_calculator.lamports_per_signature = slot_ctx->slot_bank.lamports_per_signature;

  ulong sz = fd_recent_block_hashes_size(&slot_ctx->slot_bank.recent_block_hashes);
  if (sz < FD_RECENT_BLOCKHASHES_ACCOUNT_MAX_SIZE)
    sz = FD_RECENT_BLOCKHASHES_ACCOUNT_MAX_SIZE;
  unsigned char *enc = fd_alloca(1, sz);
  memset(enc, 0, sz);
  fd_bincode_encode_ctx_t ctx;
  ctx.data = enc;
  ctx.dataend = enc + sz;
  if ( fd_recent_block_hashes_encode(&slot_ctx->slot_bank.recent_block_hashes, &ctx) )
    FD_LOG_ERR(("fd_recent_block_hashes_encode failed"));

  fd_sysvar_set(slot_ctx, fd_sysvar_owner_id.key, &fd_sysvar_recent_block_hashes_id, enc, sz, slot_ctx->slot_bank.slot, 0UL);

  register_blockhash( slot_ctx, &slot_ctx->slot_bank.poh );
}
