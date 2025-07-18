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

fd_fork_t *
fd_forks_init( fd_forks_t * forks, ulong slot ) {

  if( FD_UNLIKELY( !forks ) ) {
    FD_LOG_WARNING( ( "NULL forks" ) );
    return NULL;
  }

  fd_fork_t * fork = fd_fork_pool_ele_acquire( forks->pool );
  fork->slot       = slot;
  fork->prev       = fd_fork_pool_idx_null( forks->pool );
  fork->lock       = 0;
  if( FD_UNLIKELY( !fd_fork_frontier_ele_insert( forks->frontier, fork, forks->pool ) ) ) {
    FD_LOG_WARNING( ( "Failed to insert fork into frontier" ) );
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
//                   fd_funk_t *           funk,
//                   fd_blockstore_t *     blockstore,
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

fd_fork_t *
fd_forks_prepare( fd_forks_t const * forks, ulong parent_slot ) {

  /* Query for parent_slot in the frontier. */

  fd_fork_t * fork = fd_fork_frontier_ele_query( forks->frontier, &parent_slot, NULL, forks->pool );

  /* If the parent block is both present and executed, but isn't in the
     frontier, that means this block is starting a new fork and needs to
     be added to the frontier. This requires recovering the slot_ctx
     as of that parent_slot by executing a funky rollback. */

  if( FD_UNLIKELY( !fork ) ) {

    /* Alloc a new slot_ctx */

    fork       = fd_fork_pool_ele_acquire( forks->pool );
    fork->prev = fd_fork_pool_idx_null( forks->pool );
    fork->slot = parent_slot;
    fork->lock = 1;

    /* Add to frontier */

    fd_fork_frontier_ele_insert( forks->frontier, fork, forks->pool );
  }

  return fork;
}

void
fd_forks_publish( fd_forks_t * forks, ulong slot ) {
  fd_fork_t * tail = NULL;
  fd_fork_t * curr = NULL;

  for( fd_fork_frontier_iter_t iter = fd_fork_frontier_iter_init( forks->frontier, forks->pool );
       !fd_fork_frontier_iter_done( iter, forks->frontier, forks->pool );
       iter = fd_fork_frontier_iter_next( iter, forks->frontier, forks->pool ) ) {
    fd_fork_t * fork = fd_fork_frontier_iter_ele( iter, forks->frontier, forks->pool );

    /* Prune any forks not in the ancestry from root.

       Optimize for unlikely because there is usually just one fork. */

    if( FD_UNLIKELY( !fork->lock && fork->slot < slot ) ) {
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
    ulong remove = fd_fork_frontier_idx_remove( forks->frontier,
                                                &tail->slot,
                                                fd_fork_pool_idx_null( forks->pool ),
                                                forks->pool );
#if FD_FORKS_USE_HANDHOLDING
    if( FD_UNLIKELY( remove == fd_fork_pool_idx_null( forks->pool ) ) ) {
      FD_LOG_ERR( ( "failed to remove fork we added to prune." ) );
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

#include <stdio.h>

void
fd_forks_print( fd_forks_t const * forks ) {
  FD_LOG_NOTICE( ( "\n\n[Forks]" ) );
  for( fd_fork_frontier_iter_t iter = fd_fork_frontier_iter_init( forks->frontier, forks->pool );
       !fd_fork_frontier_iter_done( iter, forks->frontier, forks->pool );
       iter = fd_fork_frontier_iter_next( iter, forks->frontier, forks->pool ) ) {
    printf( "%lu\n", fd_fork_frontier_iter_ele_const( iter, forks->frontier, forks->pool )->slot );
  }
  printf( "\n" );
}
