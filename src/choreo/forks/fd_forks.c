#include "fd_forks.h"
#include "../../flamenco/runtime/context/fd_exec_slot_ctx.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"
#include "../../flamenco/runtime/fd_borrowed_account.h"
#include "../../flamenco/runtime/program/fd_program_util.h"
#include "../../flamenco/runtime/program/fd_vote_program.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

void *
fd_forks_new( void * shmem, ulong max, ulong seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING( ( "NULL mem" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_forks_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned mem" ) );
    return NULL;
  }

  ulong footprint = fd_forks_footprint( max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING( ( "bad mem" ) );
    return NULL;
  }

  fd_memset( shmem, 0, footprint );
  ulong        laddr = (ulong)shmem;

  laddr = fd_ulong_align_up( laddr, alignof( fd_forks_t ) );
  laddr += sizeof( fd_forks_t );

  laddr       = fd_ulong_align_up( laddr, fd_fork_pool_align() );
  fd_fork_pool_new( (void *)laddr, max );
  laddr += fd_fork_pool_footprint( max );

  laddr           = fd_ulong_align_up( laddr, fd_fork_frontier_align() );
  fd_fork_frontier_new( (void *)laddr, max, seed );
  laddr += fd_fork_frontier_footprint( max );

  return shmem;
}

fd_forks_t *
fd_forks_join( void * shforks ) {

  if( FD_UNLIKELY( !shforks ) ) {
    FD_LOG_WARNING( ( "NULL forks" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shforks, fd_forks_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned forks" ) );
    return NULL;
  }

  ulong        laddr = (ulong)shforks;
  fd_forks_t * forks = (void *)laddr;

  laddr = fd_ulong_align_up( laddr, alignof( fd_forks_t ) );
  laddr += sizeof( fd_forks_t );

  laddr       = fd_ulong_align_up( laddr, fd_fork_pool_align() );
  forks->pool = fd_fork_pool_join( (void *)laddr );
  ulong max   = fd_fork_pool_max( forks->pool );
  laddr += fd_fork_pool_footprint( max );

  laddr           = fd_ulong_align_up( laddr, fd_fork_frontier_align() );
  forks->frontier = fd_fork_frontier_join( (void *)laddr );
  laddr += fd_fork_frontier_footprint( max );

  return (fd_forks_t *)shforks;
}

void *
fd_forks_leave( fd_forks_t const * forks ) {

  if( FD_UNLIKELY( !forks ) ) {
    FD_LOG_WARNING( ( "NULL forks" ) );
    return NULL;
  }

  return (void *)forks;
}

void *
fd_forks_delete( void * forks ) {

  if( FD_UNLIKELY( !forks ) ) {
    FD_LOG_WARNING( ( "NULL forks" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)forks, fd_forks_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned forks" ) );
    return NULL;
  }

  return forks;
}

// fd_fork_t *
// fd_forks_insert( fd_forks_t * forks ) {
//   fd_fork_t * fork = fd_fork_pool_ele_acquire( forks->pool );
//   fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( &fork->slot_ctx ) );

//   if( FD_UNLIKELY( !fork ) ) {
//     FD_LOG_ERR( ( "failed to acquire fork" ) );
//     return NULL;
//   }

//   return fork;
// }

fd_fork_t *
fd_forks_rollback( fd_forks_t * forks, ulong slot ) {
  fd_fork_t *          fork     = fd_fork_pool_ele_acquire( forks->pool );
  fd_exec_slot_ctx_t * slot_ctx = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( &fork->slot_ctx ) );
  if( FD_UNLIKELY( !slot_ctx ) ) FD_LOG_ERR( ( "failed to new and join slot_ctx" ) );
  fork->slot = slot;

  fd_funk_txn_t *   txn_map    = fd_funk_txn_map( forks->funk, fd_funk_wksp( forks->funk ) );
  fd_hash_t const * block_hash = fd_blockstore_block_hash_query( forks->blockstore, slot );
  FD_LOG_NOTICE( ( "trying to restore %lu", slot_ctx->slot_bank.slot ) );
  if( !block_hash ) FD_LOG_ERR( ( "missing block hash of slot we're trying to restore" ) );
  fd_funk_txn_xid_t xid;
  fd_memcpy( xid.uc, block_hash, sizeof( fd_funk_txn_xid_t ) );
  xid.ul[0]             = slot;
  fd_funk_rec_key_t id  = fd_runtime_slot_bank_key();
  fd_funk_txn_t *   txn = fd_funk_txn_query( &xid, txn_map );
  if( !txn ) FD_LOG_ERR( ( "missing txn, parent slot %lu", slot ) );
  fd_funk_rec_t const * rec = fd_funk_rec_query_global( forks->funk, txn, &id );
  if( rec == NULL ) FD_LOG_ERR( ( "failed to read banks record" ) );
  void *                  val = fd_funk_val( rec, fd_funk_wksp( forks->funk ) );
  fd_bincode_decode_ctx_t ctx;
  ctx.data    = val;
  ctx.dataend = (uchar *)val + fd_funk_val_sz( rec );
  ctx.valloc  = forks->valloc;

  FD_TEST( slot_ctx->magic == FD_EXEC_SLOT_CTX_MAGIC );

  slot_ctx->epoch_ctx = forks->epoch_ctx;

  slot_ctx->funk_txn   = txn;
  slot_ctx->acc_mgr    = forks->acc_mgr;
  slot_ctx->blockstore = forks->blockstore;
  slot_ctx->valloc     = forks->valloc;

  FD_TEST( fd_slot_bank_decode( &slot_ctx->slot_bank, &ctx ) == FD_BINCODE_SUCCESS );
  FD_TEST( !fd_runtime_sysvar_cache_load( slot_ctx ) );
  slot_ctx->leader = fd_epoch_leaders_get( slot_ctx->epoch_ctx->leaders, slot );

  // TODO how do i get this info, ignoring rewards for now
  // slot_ctx->epoch_reward_status = ???

  // signature_cnt, account_delta_hash, prev_banks_hash are used for the banks hash calculation and
  // not needed when restoring parent

  FD_LOG_NOTICE( ( "recovered slot_bank for slot=%lu banks_hash=%32J poh_hash %32J",
                   slot_ctx->slot_bank.slot,
                   slot_ctx->slot_bank.banks_hash.hash,
                   slot_ctx->slot_bank.poh.hash ) );

  /* Prepare bank for next slot */
  slot_ctx->slot_bank.slot           = slot;
  slot_ctx->slot_bank.collected_fees = 0;
  slot_ctx->slot_bank.collected_rent = 0;

  /* FIXME epoch boundary stuff when forking */
  // fd_features_restore( slot_ctx );
  // fd_runtime_update_leaders( slot_ctx, slot_ctx->slot_bank.slot );
  // fd_calculate_epoch_accounts_hash_values( slot_ctx );

  return fork;
}
