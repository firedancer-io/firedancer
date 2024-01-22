#include "fd_replay.h"
#include "../fd_flamenco.h"
#include "fd_account.h"

void *
fd_replay_new( void * mem, ulong slot_max, ulong seed ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING( ( "NULL mem" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_replay_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned mem" ) );
    return NULL;
  }

  ulong footprint = fd_replay_footprint( slot_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING( ( "bad slot_max (%lu)", slot_max ) );
    return NULL;
  }

  fd_memset( mem, 0, footprint );

  ulong laddr = (ulong)mem;

  fd_replay_t * replay = (fd_replay_t *)mem;
  laddr                = fd_ulong_align_up( laddr + sizeof( fd_replay_t ), fd_replay_pool_align() );
  replay->pool         = fd_replay_pool_new( (void *)laddr, slot_max );
  laddr =
      fd_ulong_align_up( laddr + fd_replay_pool_footprint( slot_max ), fd_replay_frontier_align() );
  replay->frontier = fd_replay_frontier_new( (void *)laddr, slot_max, seed );

  return mem;
}

/* TODO only safe for local joins */
fd_replay_t *
fd_replay_join( void * replay ) {

  if( FD_UNLIKELY( !replay ) ) {
    FD_LOG_WARNING( ( "NULL replay" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)replay, fd_replay_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned replay" ) );
    return NULL;
  }

  fd_replay_t * replay_ = (fd_replay_t *)replay;
  replay_->pool         = fd_replay_pool_join( replay_->pool );
  replay_->frontier     = fd_replay_frontier_join( replay_->frontier );

  return replay_;
}

void *
fd_replay_leave( fd_replay_t const * replay ) {

  if( FD_UNLIKELY( !replay ) ) {
    FD_LOG_WARNING( ( "NULL replay" ) );
    return NULL;
  }

  return (void *)replay;
}

void *
fd_replay_delete( void * replay ) {

  if( FD_UNLIKELY( !replay ) ) {
    FD_LOG_WARNING( ( "NULL replay" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)replay, fd_replay_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned replay" ) );
    return NULL;
  }

  return replay;
}

// TODO lock inside here vs. caller
void
fd_replay_slot_execute( fd_replay_t * replay, ulong slot, fd_replay_slot_t * parent ) {
  FD_LOG_NOTICE( ( "executing replay" ) );
  fd_blockstore_block_t * block = fd_blockstore_block_query( replay->blockstore, slot );
  if( block == NULL ) { /* we have the metadata but not the actual block */
    FD_LOG_ERR( ( "programming error: calling fd_replay_slot_execute when block isn't there." ) );
  }
  uchar const * block_data = fd_blockstore_block_data_laddr( replay->blockstore, block );

  ulong txn_cnt = 0;
  parent->slot_ctx.slot_bank.prev_slot = parent->slot;
  parent->slot_ctx.slot_bank.slot = slot;
  parent->slot_ctx.slot_bank.collected_fees = 0;
  parent->slot_ctx.slot_bank.collected_rent = 0;

  FD_TEST( fd_runtime_block_eval_tpool( &parent->slot_ctx,
                                        NULL,
                                        block_data,
                                        block->sz,
                                        replay->tpool,
                                        replay->max_workers,
                                        &txn_cnt ) == FD_RUNTIME_EXECUTE_SUCCESS );
  (void)txn_cnt;

  /* parent->slot_ctx is now child->slot_ctx, so re-insert into the map keyed by child slot */
  fd_replay_slot_t * child =
      fd_replay_frontier_ele_remove( replay->frontier, &parent->slot, NULL, replay->pool );
  child->slot = child->slot_ctx.slot_bank.prev_slot; /* this is a hack to fix the fact eval is setting +1 */
  fd_replay_frontier_ele_insert( replay->frontier, child, replay->pool );
  FD_LOG_NOTICE(
      ( "bank hash for slot %lu: %32J", child->slot, child->slot_ctx.slot_bank.banks_hash.hash ) );
}

void
fd_replay_slot_restore( fd_replay_t * replay, ulong slot, fd_exec_slot_ctx_t * slot_ctx ) {
  fd_funk_txn_t *   txn_map    = fd_funk_txn_map( replay->funk, fd_funk_wksp( replay->funk ) );
  fd_hash_t const * block_hash = fd_blockstore_block_hash_query( replay->blockstore, slot );
  if( !block_hash ) FD_LOG_ERR( ( "missing block hash of slot we're trying to restore" ) );
  fd_funk_txn_xid_t xid;
  fd_memcpy( xid.uc, block_hash, sizeof( fd_funk_txn_xid_t ) );
  fd_funk_rec_key_t id  = fd_runtime_slot_bank_key();
  fd_funk_txn_t *   txn = fd_funk_txn_query( &xid, txn_map );
  if( !txn ) FD_LOG_ERR( ( "missing txn" ) );
  slot_ctx->funk_txn        = txn;
  fd_funk_rec_t const * rec = fd_funk_rec_query_global( replay->funk, slot_ctx->funk_txn, &id );
  if( rec == NULL ) FD_LOG_ERR( ( "failed to read banks record" ) );
  void *                  val = fd_funk_val( rec, fd_funk_wksp( replay->funk ) );
  fd_bincode_decode_ctx_t ctx;
  ctx.data    = val;
  ctx.dataend = (uchar *)val + fd_funk_val_sz( rec );
  ctx.valloc  = slot_ctx->valloc;
  FD_TEST( fd_slot_bank_decode( &slot_ctx->slot_bank, &ctx ) == FD_BINCODE_SUCCESS );

  FD_LOG_NOTICE( ( "recovered slot_bank for slot=%ld banks_hash=%32J poh_hash %32J",
                   (long)slot_ctx->slot_bank.slot,
                   slot_ctx->slot_bank.banks_hash.hash,
                   slot_ctx->slot_bank.poh.hash ) );
  slot_ctx->slot_bank.collected_fees = 0;
  slot_ctx->slot_bank.collected_rent = 0;
}
