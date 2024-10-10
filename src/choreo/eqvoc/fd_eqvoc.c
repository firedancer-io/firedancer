#include "fd_eqvoc.h"

void *
fd_eqvoc_new( void * shmem, ulong key_max, ulong seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING( ( "NULL mem" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_eqvoc_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned mem" ) );
    return NULL;
  }

  ulong footprint = fd_eqvoc_footprint( key_max );

  fd_memset( shmem, 0, footprint );
  ulong        laddr = (ulong)shmem;
  fd_eqvoc_t * eqvoc = (void *)laddr;
  laddr += sizeof( fd_eqvoc_t );

  laddr       = fd_ulong_align_up( laddr, fd_eqvoc_pool_align() );
  eqvoc->pool = fd_eqvoc_pool_new( (void *)laddr, key_max );
  laddr += fd_eqvoc_pool_footprint( key_max );

  laddr      = fd_ulong_align_up( laddr, fd_eqvoc_map_align() );
  eqvoc->map = fd_eqvoc_map_new( (void *)laddr, key_max, seed );
  laddr += fd_eqvoc_map_footprint( key_max );

  laddr = fd_ulong_align_up( laddr, fd_eqvoc_align() );
  FD_TEST( laddr == (ulong)shmem + footprint );

  return shmem;
}

fd_eqvoc_t *
fd_eqvoc_join( void * sheqvoc ) {

  if( FD_UNLIKELY( !sheqvoc ) ) {
    FD_LOG_WARNING( ( "NULL eqvoc" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)sheqvoc, fd_eqvoc_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned eqvoc" ) );
    return NULL;
  }

  ulong        laddr = (ulong)sheqvoc; /* offset from a memory region */
  fd_eqvoc_t * eqvoc = (void *)sheqvoc;
  laddr += sizeof( fd_eqvoc_t );

  laddr         = fd_ulong_align_up( laddr, fd_eqvoc_pool_align() );
  eqvoc->pool   = fd_eqvoc_pool_join( (void *)laddr );
  ulong key_max = fd_eqvoc_pool_max( eqvoc->pool );
  laddr += fd_eqvoc_pool_footprint( key_max );

  laddr      = fd_ulong_align_up( laddr, fd_eqvoc_map_align() );
  eqvoc->map = fd_eqvoc_map_join( (void *)laddr );
  laddr += fd_eqvoc_map_footprint( key_max );

  laddr = fd_ulong_align_up( laddr, fd_eqvoc_align() );
  FD_TEST( laddr == (ulong)sheqvoc + fd_eqvoc_footprint( key_max ) );

  return eqvoc;
}

void *
fd_eqvoc_leave( fd_eqvoc_t const * eqvoc ) {

  if( FD_UNLIKELY( !eqvoc ) ) {
    FD_LOG_WARNING( ( "NULL eqvoc" ) );
    return NULL;
  }

  return (void *)eqvoc;
}

void *
fd_eqvoc_delete( void * eqvoc ) {

  if( FD_UNLIKELY( !eqvoc ) ) {
    FD_LOG_WARNING( ( "NULL eqvoc" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)eqvoc, fd_eqvoc_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned eqvoc" ) );
    return NULL;
  }

  return eqvoc;
}

void
fd_eqvoc_insert( fd_eqvoc_t * eqvoc, fd_shred_t const * shred ) {
  fd_eqvoc_entry_t * entry = fd_eqvoc_pool_ele_acquire( eqvoc->pool );
  entry->key.slot          = shred->slot;
  entry->key.fec_set_idx   = shred->fec_set_idx;
  memcpy( entry->sig, shred->signature, FD_ED25519_SIG_SZ );

  if( FD_LIKELY( fd_shred_is_code( fd_shred_type( shred->variant ) ) ) ) {

    /* optimize for coding shreds (code_cnt >= data_cnt) */

    entry->code_cnt = shred->code.code_cnt;
    entry->data_cnt = shred->code.data_cnt;
  }

  fd_eqvoc_map_ele_insert( eqvoc->map, entry, eqvoc->pool );
}

int
fd_eqvoc_test( fd_eqvoc_t const * eqvoc, fd_shred_t const * shred ) {
  fd_eqvoc_key_t key = { shred->slot, shred->fec_set_idx };

  /* If we've already received a shred for this FEC set, check this new
     shred's signature matches. */

  fd_eqvoc_entry_t const * entry = fd_eqvoc_map_ele_query_const( eqvoc->map,
                                                                 &key,
                                                                 NULL,
                                                                 eqvoc->pool );

  /* If we've already seen a shred in this FEC set, make sure the
     signature matches. */

  if( FD_UNLIKELY( entry && 0 != memcmp( entry->sig, shred->signature, FD_ED25519_SIG_SZ ) ) ) {
    return 0;
  }

  /* Look backward FEC_MAX idxs for overlap. */

  for( uint i = 1; shred->fec_set_idx >= i && i < FD_EQVOC_FEC_MAX; i++ ) {
    fd_eqvoc_key_t           key   = { shred->slot, shred->fec_set_idx - i };
    fd_eqvoc_entry_t const * entry = fd_eqvoc_map_ele_query_const( eqvoc->map,
                                                                   &key,
                                                                   NULL,
                                                                   eqvoc->pool );

    if( FD_UNLIKELY( entry && entry->data_cnt > 0 &&
                     entry->key.fec_set_idx + entry->data_cnt > shred->fec_set_idx ) ) {
      return 0; /* Equivocation detected */
    }
  }

  /* Look forward data_cnt idxs for overlap. */

  for( uint i = 1; entry && i < entry->data_cnt; i++ ) {
    fd_eqvoc_key_t           key   = { shred->slot, shred->fec_set_idx + i };
    fd_eqvoc_entry_t const * entry = fd_eqvoc_map_ele_query_const( eqvoc->map,
                                                                   &key,
                                                                   NULL,
                                                                   eqvoc->pool );
    if( FD_UNLIKELY( entry ) ) return 0; /* Equivocation detected */
  }

  return 1;
}
