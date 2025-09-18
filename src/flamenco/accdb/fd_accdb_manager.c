#include "fd_accdb_manager.h"

ulong
fd_accdb_manager_align( void ) {
  return alignof(fd_accdb_manager_t);
}

ulong
fd_accdb_manager_footprint( void ) {
  return sizeof(fd_accdb_manager_t);
}

fd_accdb_manager_t *
fd_accdb_manager_new( void *              lmem,
                      void *              funk_shmem,
                      fd_accdb_sestab_t * sestab ) {

  if( FD_UNLIKELY( !lmem ) ) {
    FD_LOG_WARNING(( "NULL lmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)lmem, fd_accdb_manager_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned lmem" ));
    return NULL;
  }

  fd_accdb_manager_t * mgr = lmem;
  memset( mgr, 0, sizeof(fd_accdb_manager_t) );
  if( FD_UNLIKELY( !fd_accdb_client_new( &mgr->client, funk_shmem, 0UL, 0UL ) ) ) {
    /* unreachable */
    FD_LOG_ERR(( "fd_accdb_client_new failed" ));
  }

  mgr->sestab = sestab;

  return mgr;
}

fd_accdb_manager_t *
fd_accdb_manager_join( fd_accdb_manager_t * mgr ) {

  /* Register a session for the manager */
  fd_accdb_sestab_t * sestab = mgr->sestab;
  if( FD_UNLIKELY( !fd_accdb_client_join( &mgr->client, sestab ) ) ) {
    return NULL;
  }

  uint session_idx = fd_accdb_client_session_idx( &mgr->client );
  if( FD_UNLIKELY( session_idx==UINT_MAX ) ) {
    FD_LOG_ERR(( "fd_accdb_client_session_idx failed" )); /* unreachable */
  }

  /* Promote this session to manager */
#if FD_HAS_ATOMIC
  int cas_ok = __sync_bool_compare_and_swap( &sestab->mgr_session_idx, UINT_MAX, session_idx );
#else
  int cas_ok = sestab->mgr_session_idx==UINT_MAX;
  if( cas_ok ) sestab->mgr_session_idx = session_idx;
#endif
  if( FD_UNLIKELY( !cas_ok ) ) {
    FD_LOG_WARNING(( "Failed to join accdb_manager to accdb_sestab: there is already another manager instance" ));
    if( FD_UNLIKELY( !fd_accdb_client_leave( &mgr->client ) ) ) {
      FD_LOG_ERR(( "fd_accdb_client_leave failed" )); /* memory corruption? */
    }
    return NULL;
  }

  return mgr;
}

fd_accdb_manager_t *
fd_accdb_manager_leave( fd_accdb_manager_t * mgr ) {

  uint session_idx = fd_accdb_client_session_idx( &mgr->client );
  if( FD_UNLIKELY( session_idx==UINT_MAX ) ) {
    /* FIXME explicitly allow idempotency? */
    FD_LOG_WARNING(( "double leave detected" ));
    return NULL;
  }

  /* Leave spot as accdb_manager */
#if FD_HAS_ATOMIC
  int cas_ok = __sync_bool_compare_and_swap( &mgr->sestab->mgr_session_idx, session_idx, UINT_MAX );
#else
  int cas_ok = mgr->sestab->mgr_session_idx==session_idx;
  if( cas_ok ) mgr->sestab->mgr_session_idx = UINT_MAX;
#endif
  if( FD_UNLIKELY( !cas_ok ) ) {
    FD_LOG_WARNING(( "Failed to detach accdb_manager from accdb_sestab: not currently a manager (memory corruption?)" ));
  }

  /* Unregister session */
  if( FD_UNLIKELY( !fd_accdb_client_leave( &mgr->client ) ) ) return NULL; /* logs warning */

  return cas_ok ? mgr : NULL;
}

void *
fd_accdb_manager_delete( fd_accdb_manager_t * mgr ) {
  return mgr;
}

void
fd_accdb_manager_txn_create( fd_accdb_manager_t *      mgr,
                             fd_funk_txn_xid_t const * xid_parent,
                             fd_funk_txn_xid_t const * xid_new ) {
  /* FIXME if xid_parent refers to the persistent store, do a
           funk_txn_preapre with xid_parent==NULL */
  if( FD_UNLIKELY( !fd_funk_txn_prepare( mgr->funk, xid_parent, xid_new, 1 ) ) ) {
    FD_LOG_ERR(( "Failed to create funk txn %lu:%lu at parent %lu:%lu",
                 xid_new   ->ul[0], xid_new   ->ul[1],
                 xid_parent->ul[0], xid_parent->ul[1] ));
  }
}

void
fd_accdb_manager_txn_freeze( fd_accdb_manager_t *      mgr,
                             fd_funk_txn_xid_t const * txn_xid ) {
  (void)mgr; (void)txn_xid;
  /* FIXME writable -> freeze in funk is currently implicit ... */
}


static fd_funk_txn_t *
txn_retire( fd_accdb_manager_t *      mgr,
            fd_funk_txn_xid_t const * txn_xid ) {
  fd_funk_txn_map_t * txn_map = fd_funk_txn_map( mgr->funk );
  fd_funk_txn_t *     txn     = fd_funk_txn_query( txn_xid, txn_map );
  if( FD_UNLIKELY( !txn ) ) {
    FD_LOG_ERR(( "Unknown database transaction: %016lx %016lx",
                 fd_ulong_bswap( txn_xid->ul[0] ), fd_ulong_bswap( txn_xid->ul[1] ) ));
  }

  FD_VOLATILE( txn->state ) = FD_FUNK_TXN_STATE_RETIRING;
  _mm_mfence();

  /* Wait for clients in session table to drain */
  for(;;) {
    if( FD_LIKELY( !fd_accdb_sestab_is_used( mgr->sestab, *txn_xid ) ) ) break;
    FD_SPIN_PAUSE();
  }

  return txn;
}

void
fd_accdb_manager_txn_root( fd_accdb_manager_t *      mgr,
                           fd_funk_txn_xid_t const * txn_xid ) {

}

void
fd_accdb_manager_txn_cancel( fd_accdb_manager_t *      mgr,
                             fd_funk_txn_xid_t const * txn_xid ) {

}
