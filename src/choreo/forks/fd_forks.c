#include "fd_forks.h"
#include "../../flamenco/runtime/context/fd_exec_slot_ctx.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"
#include "../../flamenco/runtime/fd_borrowed_account.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/program/fd_program_util.h"
#include "../../flamenco/runtime/program/fd_vote_program.h"

void *
fd_forks_new( void * shmem, ulong max, ulong seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_forks_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_forks_footprint( max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad mem" ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );
  ulong laddr = (ulong)shmem;

  laddr = fd_ulong_align_up( laddr, alignof( fd_forks_t ) );
  laddr += sizeof( fd_forks_t );

  laddr = fd_ulong_align_up( laddr, fd_fork_pool_align() );
  fd_fork_pool_new( (void *)laddr, max );
  laddr += fd_fork_pool_footprint( max );

  laddr = fd_ulong_align_up( laddr, fd_fork_frontier_align() );
  fd_fork_frontier_new( (void *)laddr, max, seed );
  laddr += fd_fork_frontier_footprint( max );

  return shmem;
}

fd_forks_t *
fd_forks_join( void * shforks ) {

  if( FD_UNLIKELY( !shforks ) ) {
    FD_LOG_WARNING(( "NULL forks" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shforks, fd_forks_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned forks" ));
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
    FD_LOG_WARNING(( "NULL forks" ));
    return NULL;
  }

  return (void *)forks;
}

void *
fd_forks_delete( void * forks ) {

  if( FD_UNLIKELY( !forks ) ) {
    FD_LOG_WARNING(( "NULL forks" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)forks, fd_forks_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned forks" ));
    return NULL;
  }

  return forks;
}

fd_fork_t *
fd_forks_init( fd_forks_t * forks, fd_exec_slot_ctx_t const * slot_ctx ) {

  if( FD_UNLIKELY( !forks ) ) {
    FD_LOG_WARNING(( "NULL forks" ));
    return NULL;
  }

  if( FD_UNLIKELY( !slot_ctx ) ) {
    FD_LOG_WARNING(( "NULL slot_ctx" ));
    return NULL;
  }

  fd_fork_t * fork = fd_fork_pool_ele_acquire( forks->pool );
  fork->slot       = slot_ctx->slot_bank.slot;
  fork->prev       = fd_fork_pool_idx_null( forks->pool );
  fork->lock       = 0;
  fork->slot_ctx   = *slot_ctx; /* this shallow copy is only safe if
                                   the lifetimes of slot_ctx's pointers
                                   are as long as fork */
  if( FD_UNLIKELY( !fd_fork_frontier_ele_insert( forks->frontier, fork, forks->pool ) ) ) {
    FD_LOG_WARNING(( "Failed to insert fork into frontier" ));
  }

  return fork;
}

fd_fork_t *
fd_forks_query( fd_forks_t * forks, ulong slot ) {
  return fd_fork_frontier_ele_query( forks->frontier, &slot, NULL, forks->pool );
}

fd_fork_t const *
fd_forks_query_const( fd_forks_t const * forks, ulong slot ) {
  return fd_fork_frontier_ele_query_const( forks->frontier, &slot, NULL, forks->pool );
}

// fd_fork_t *
// fd_forks_advance( fd_forks_t *          forks,
//                   fd_fork_t *           fork,
//                   ulong                 slot,
//                   fd_acc_mgr_t *        acc_mgr,
//                   fd_blockstore_t *     blockstore,
//                   fd_exec_epoch_ctx_t * epoch_ctx,
//                   fd_funk_t *           funk,
//                   fd_valloc_t           valloc ) {
//   // Remove slot ctx from frontier
//   fd_fork_t * child = fd_fork_frontier_ele_remove( forks->frontier,
//                                                    &fork->slot,
//                                                    NULL,
//                                                    forks->pool );
//   child->slot       = curr_slot;
//   if( FD_UNLIKELY( fd_fork_frontier_ele_query( forks->frontier,
//                                                &curr_slot,
//                                                NULL,
//                                                forks->pool ) ) ) {
//         FD_LOG_ERR( ( "invariant violation: child slot %lu was already in the
//         frontier", curr_slot ) );
//   }
//   fd_fork_frontier_ele_insert( forks->frontier, child, forks->pool );
//   FD_TEST( fork == child );

//   // fork is advancing
//   FD_LOG_DEBUG(( "new block execution - slot: %lu, parent_slot: %lu", curr_slot, parent_slot ));

//   fork->slot_ctx.slot_bank.prev_slot = fork->slot_ctx.slot_bank.slot;
//   fork->slot_ctx.slot_bank.slot      = curr_slot;

//   fork->slot_ctx.status_cache = status_cache;
//   fd_funk_txn_xid_t xid;

//   fd_memcpy( xid.uc, blockhash.uc, sizeof( fd_funk_txn_xid_t));
//   xid.ul[0] = fork->slot_ctx.slot_bank.slot;
//   /* push a new transaction on the stack */
//   fd_funk_start_write( funk );
//   fork->slot_ctx.funk_txn = fd_funk_txn_prepare( funk, fork->slot_ctx.funk_txn, &xid, 1 );
//   fd_funk_end_write( funk );

//   int res = fd_runtime_publish_old_txns( &fork->slot_ctx, capture_ctx );
//   if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
//     FD_LOG_ERR(( "txn publishing failed" ));
//   }
// }

static void
slot_ctx_restore( ulong                 slot,
                  fd_acc_mgr_t *        acc_mgr,
                  fd_blockstore_t *     blockstore,
                  fd_exec_epoch_ctx_t * epoch_ctx,
                  fd_funk_t *           funk,
                  fd_valloc_t           valloc,
                  fd_exec_slot_ctx_t *  slot_ctx_out ) {
  fd_funk_txn_t *   txn_map    = fd_funk_txn_map( funk, fd_funk_wksp( funk ) );
  fd_block_map_t *  block = fd_block_map_query( fd_blockstore_block_map( blockstore ), &slot, NULL );
  FD_LOG_DEBUG(( "Current slot %lu", slot ));
  if( !block || !block->block_gaddr ) FD_LOG_ERR(( "missing block at slot we're trying to restore" ));
  fd_funk_txn_xid_t xid;
  memcpy( xid.uc, block->block_hash.uc, sizeof(fd_funk_txn_xid_t) );
  xid.ul[0]             = slot;
  fd_funk_rec_key_t id  = fd_runtime_slot_bank_key();
  fd_funk_txn_t *   txn = fd_funk_txn_query( &xid, txn_map );
  if( !txn ) {
    memset( xid.uc, 0, sizeof(fd_funk_txn_xid_t) );
    xid.ul[0]             = slot;
    txn = fd_funk_txn_query( &xid, txn_map );
    if( !txn ) {
      FD_LOG_ERR(( "missing txn, parent slot %lu", slot ));
    }
  }
  fd_funk_rec_t const * rec = fd_funk_rec_query_global( funk, txn, &id, NULL );
  if( rec == NULL ) FD_LOG_ERR(( "failed to read banks record" ));
  void * val = fd_funk_val( rec, fd_funk_wksp( funk ) );

  uint magic = *(uint*)val;

  fd_bincode_decode_ctx_t decode_ctx;
  decode_ctx.data    = (uchar *)val + sizeof( uint );
  decode_ctx.dataend = (uchar *)val + fd_funk_val_sz( rec );
  decode_ctx.valloc  = valloc;

  FD_TEST( slot_ctx_out->magic == FD_EXEC_SLOT_CTX_MAGIC );

  slot_ctx_out->funk_txn = txn;

  slot_ctx_out->acc_mgr    = acc_mgr;
  slot_ctx_out->blockstore = blockstore;
  slot_ctx_out->epoch_ctx  = epoch_ctx;
  slot_ctx_out->valloc     = valloc;

  fd_bincode_destroy_ctx_t destroy_ctx = {
      .valloc = valloc,
  };

  fd_slot_bank_destroy( &slot_ctx_out->slot_bank, &destroy_ctx );
  if( magic == FD_RUNTIME_ENC_BINCODE ) {
    FD_TEST( fd_slot_bank_decode( &slot_ctx_out->slot_bank, &decode_ctx ) == FD_BINCODE_SUCCESS );
  } else if( magic == FD_RUNTIME_ENC_ARCHIVE ) {
    FD_TEST( fd_slot_bank_decode_archival( &slot_ctx_out->slot_bank, &decode_ctx )==FD_BINCODE_SUCCESS );
  } else {
    FD_LOG_ERR(( "failed to read banks record: invalid magic number" ));
  }
  FD_TEST( !fd_runtime_sysvar_cache_load( slot_ctx_out ) );
  slot_ctx_out->leader = fd_epoch_leaders_get( fd_exec_epoch_ctx_leaders( slot_ctx_out->epoch_ctx ),
                                               slot );

  // TODO how do i get this info, ignoring rewards for now
  // slot_ctx_out->epoch_reward_status = ???

  // signature_cnt, account_delta_hash, prev_banks_hash are used for the banks
  // hash calculation and not needed when restoring parent

  FD_LOG_NOTICE(( "recovered slot_bank for slot=%lu banks_hash=%s poh_hash %s",
                   slot_ctx_out->slot_bank.slot,
                   FD_BASE58_ENC_32_ALLOCA( slot_ctx_out->slot_bank.banks_hash.hash ),
                   FD_BASE58_ENC_32_ALLOCA( slot_ctx_out->slot_bank.poh.hash ) ));

  /* Prepare bank for next slot */
  slot_ctx_out->slot_bank.slot                     = slot;
  slot_ctx_out->slot_bank.collected_execution_fees = 0;
  slot_ctx_out->slot_bank.collected_priority_fees  = 0;
  slot_ctx_out->slot_bank.collected_rent           = 0;

  /* FIXME epoch boundary stuff when replaying */
  // fd_features_restore( slot_ctx );
  // fd_runtime_update_leaders( slot_ctx, slot_ctx->slot_bank.slot );
  // fd_calculate_epoch_accounts_hash_values( slot_ctx );
}

fd_fork_t *
fd_forks_prepare( fd_forks_t const *    forks,
                  ulong                 parent_slot,
                  fd_acc_mgr_t *        acc_mgr,
                  fd_blockstore_t *     blockstore,
                  fd_exec_epoch_ctx_t * epoch_ctx,
                  fd_funk_t *           funk,
                  fd_valloc_t           valloc ) {

  /* Check the parent block is present in the blockstore and executed. */

  fd_block_t * block = fd_blockstore_block_query( blockstore, parent_slot );
  if( FD_UNLIKELY( !block ) ) {
    FD_LOG_WARNING(( "fd_forks_prepare missing parent_slot %lu", parent_slot ));
  }

  /* Query for parent_slot in the frontier. */

  fd_fork_t * fork = fd_fork_frontier_ele_query( forks->frontier, &parent_slot, NULL, forks->pool );

  /* If the parent block is both present and executed, but isn't in the
     frontier, that means this block is starting a new fork and needs to
     be added to the frontier. This requires recovering the slot_ctx
     as of that parent_slot by executing a funky rollback. */

  if( FD_UNLIKELY( !fork ) ) {

    /* Alloc a new slot_ctx */

    fork         = fd_fork_pool_ele_acquire( forks->pool );
    fork->prev   = fd_fork_pool_idx_null( forks->pool );
    fork->slot   = parent_slot;
    fork->lock = 1;

    /* Format and join the slot_ctx */

    fd_exec_slot_ctx_t * slot_ctx =
        fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( &fork->slot_ctx, valloc ) );
    if( FD_UNLIKELY( !slot_ctx ) ) {
      FD_LOG_ERR(( "failed to new and join slot_ctx" ));
    }

    /* Restore and decode w/ funk */

    slot_ctx_restore( fork->slot, acc_mgr, blockstore, epoch_ctx, funk, valloc, slot_ctx );

    /* Add to frontier */

    fd_fork_frontier_ele_insert( forks->frontier, fork, forks->pool );
  }

  return fork;
}

void
fd_forks_publish( fd_forks_t * forks, ulong slot, fd_ghost_t const * ghost ) {
  fd_fork_t * tail = NULL;
  fd_fork_t * curr = NULL;

  for( fd_fork_frontier_iter_t iter = fd_fork_frontier_iter_init( forks->frontier, forks->pool );
       !fd_fork_frontier_iter_done( iter, forks->frontier, forks->pool );
       iter = fd_fork_frontier_iter_next( iter, forks->frontier, forks->pool ) ) {
    fd_fork_t * fork = fd_fork_frontier_iter_ele( iter, forks->frontier, forks->pool );

    /* Prune any forks not in the ancestry from root.

       Optimize for unlikely because there is usually just one fork. */

    int stale = fork->slot < slot || !fd_ghost_is_descendant( ghost, fork->slot, slot );
    if( FD_UNLIKELY( !fork->lock && stale ) ) {
      FD_LOG_NOTICE(( "adding %lu to prune. root %lu", fork->slot, slot ));
      if( FD_LIKELY( !curr ) ) {
        tail = fork;
        curr = fork;
      } else {
        curr->prev = fd_fork_pool_idx( forks->pool, fork );
        curr       = fd_fork_pool_ele( forks->pool, curr->prev );
      }
    }
  }

  while( FD_UNLIKELY( tail ) ) {
    fd_fork_t * fork = fd_fork_frontier_ele_query( forks->frontier,
                                                   &tail->slot,
                                                   NULL,
                                                   forks->pool );
    if( FD_UNLIKELY( !fd_exec_slot_ctx_delete( fd_exec_slot_ctx_leave( &fork->slot_ctx ) ) ) ) {
      FD_LOG_ERR(( "could not delete fork slot ctx" ));
    }
    ulong remove = fd_fork_frontier_idx_remove( forks->frontier,
                                                &tail->slot,
                                                fd_fork_pool_idx_null( forks->pool ),
                                                forks->pool );
#if FD_FORKS_USE_HANDHOLDING
    if( FD_UNLIKELY( remove == fd_fork_pool_idx_null( forks->pool ) ) ) {
      FD_LOG_ERR(( "failed to remove fork we added to prune." ));
    }
#endif

    /* pool_idx_release cannot fail given we just removed this from the
      frontier directly above. */
    fd_fork_pool_idx_release( forks->pool, remove );
    tail = fd_ptr_if( tail->prev != fd_fork_pool_idx_null( forks->pool ),
                      fd_fork_pool_ele( forks->pool, tail->prev ),
                      NULL );
  }
}
