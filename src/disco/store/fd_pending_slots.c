#include "fd_pending_slots.h"

void *
fd_pending_slots_new( void * mem, uint seed ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING( ( "NULL mem" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_pending_slots_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned mem" ) );
    return NULL;
  }

  fd_memset( mem, 0, fd_pending_slots_footprint() );

  fd_pending_slots_t * pending_slots = mem;
  ulong                laddr         = (ulong)(mem) + sizeof( fd_pending_slots_t );

  laddr                = fd_ulong_align_up( laddr, fd_rng_align() );
  pending_slots->rng   = fd_rng_join( fd_rng_new( (void *)(laddr), seed, 0UL ) );
  laddr               += fd_rng_footprint();

  laddr                = fd_ulong_align_up( laddr, fd_pending_slots_treap_align() );
  pending_slots->treap = fd_pending_slots_treap_join( fd_pending_slots_treap_new( (void *)(laddr), FD_BLOCK_MAX ) );
  laddr               += fd_pending_slots_treap_footprint( FD_BLOCK_MAX );

  laddr                = fd_ulong_align_up( laddr, fd_pending_slots_pool_align() );
  pending_slots->pool  = fd_pending_slots_pool_join( fd_pending_slots_pool_new( (void *)(laddr), FD_BLOCK_MAX ) );
  laddr               += fd_pending_slots_pool_footprint( FD_BLOCK_MAX );

  FD_TEST( laddr==(ulong)mem + fd_pending_slots_footprint() );
  return mem;
}

fd_pending_slots_t *
fd_pending_slots_join( void * pending_slots ) {
  if( FD_UNLIKELY( !pending_slots ) ) {
    FD_LOG_WARNING( ( "NULL pending_slots" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)pending_slots, fd_pending_slots_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned pending_slots" ) );
    return NULL;
  }

  fd_pending_slots_t * pending_slots_ = pending_slots;
  ulong                laddr          = (ulong)pending_slots + sizeof( fd_pending_slots_t );

  laddr                 = fd_ulong_align_up( laddr, fd_rng_align() );
  pending_slots_->rng   = fd_rng_join( (void *)laddr );
  laddr                += fd_rng_footprint();

  laddr                 = fd_ulong_align_up( laddr, fd_pending_slots_treap_align() );
  pending_slots_->treap = fd_pending_slots_treap_join( (void *)laddr );
  laddr                += fd_pending_slots_treap_footprint( FD_BLOCK_MAX );

  laddr                 = fd_ulong_align_up( laddr, fd_pending_slots_pool_align() );
  pending_slots_->pool  = fd_pending_slots_pool_join( (void *)laddr );
  laddr                += fd_pending_slots_pool_footprint( FD_BLOCK_MAX );

  FD_TEST( laddr==(ulong)pending_slots + fd_pending_slots_footprint() );

  return pending_slots_;
}

void *
fd_pending_slots_leave( fd_pending_slots_t const * pending_slots ) {
  if( FD_UNLIKELY( !pending_slots ) ) {
    FD_LOG_WARNING( ( "NULL pending_slots" ) );
    return NULL;
  }

  FD_TEST( fd_pending_slots_treap_leave( pending_slots->treap )==pending_slots->treap );
  FD_TEST( fd_pending_slots_pool_leave( pending_slots->pool )==pending_slots->pool );

  return (void *)pending_slots;
}

void *
fd_pending_slots_delete( void * pending_slots ) {
  if( FD_UNLIKELY( !pending_slots ) ) {
    FD_LOG_WARNING( ( "NULL pending_slots" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)pending_slots, fd_pending_slots_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned pending_slots" ) );
    return NULL;
  }

  fd_pending_slots_t * pending_slots_ = pending_slots;
  FD_TEST( fd_pending_slots_treap_delete( pending_slots_->treap )==pending_slots_->treap );
  FD_TEST( fd_pending_slots_pool_delete( pending_slots_->pool )==pending_slots_->pool );
  return pending_slots;
}

void
fd_pending_slots_add( fd_pending_slots_t * pending_slots,
                      ulong slot,
                      long when) {
  fd_pending_slots_treap_ele_t * ele = fd_pending_slots_treap_ele_query( pending_slots->treap, slot, pending_slots->pool );
  if( FD_LIKELY( ele ) ) {
    if( FD_LIKELY( ele->time>when ) ) ele->time = when;
  } else {
    if( FD_UNLIKELY( fd_pending_slots_pool_free( pending_slots->pool )==0 ) ) {
      FD_LOG_ERR(( "pending_slots (size=%lu) is full during insertion", FD_BLOCK_MAX ));
    }

    ele       = fd_pending_slots_pool_ele_acquire( pending_slots->pool );
    ele->slot = slot;
    ele->time = when;
    ele->prio = fd_rng_ulong( pending_slots->rng );
    fd_pending_slots_treap_ele_insert( pending_slots->treap, ele, pending_slots->pool );
  }
}

long
fd_pending_slots_get( fd_pending_slots_t * pending_slots,
                      ulong                slot ) {
  fd_pending_slots_treap_ele_t * ele = fd_pending_slots_treap_ele_query( pending_slots->treap, slot, pending_slots->pool );
  return ele ? ele->time : LONG_MAX;
}

void
fd_pending_slots_set_lo_wmark( fd_pending_slots_t * pending_slots,
                               ulong lo_wmark ) {
  for( fd_pending_slots_treap_fwd_iter_t iter =
          fd_pending_slots_treap_fwd_iter_init( pending_slots->treap, pending_slots->pool );
        !fd_pending_slots_treap_fwd_iter_done( iter ); ) {
    fd_pending_slots_treap_ele_t * prev = fd_pending_slots_treap_fwd_iter_ele( iter, pending_slots->pool );
    if( FD_UNLIKELY( prev->slot>lo_wmark ) ) break;

    /* Advance the iterator before removing element prev from the treap;
     * it is safe to remove the previous element while iterating a treap;
     * an example is given in the test_iteration() function of test_treap.c */
    iter = fd_pending_slots_treap_fwd_iter_next( iter, pending_slots->pool );
    fd_pending_slots_treap_ele_remove( pending_slots->treap, prev, pending_slots->pool );
    fd_pending_slots_pool_ele_release( pending_slots->pool, prev );
  }
}
