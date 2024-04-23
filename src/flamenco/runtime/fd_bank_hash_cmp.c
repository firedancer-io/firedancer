#include "fd_bank_hash_cmp.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

void *
fd_bank_hash_cmp_new( void * mem, int lg_slot_cnt ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING( ( "NULL mem" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_bank_hash_cmp_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned mem" ) );
    return NULL;
  }

  ulong footprint = fd_bank_hash_cmp_footprint( lg_slot_cnt );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING( ( "bad lg_slot_cnt (%d)", lg_slot_cnt ) );
    return NULL;
  }

  fd_memset( mem, 0, footprint );

  ulong laddr = (ulong)mem;
  laddr += sizeof( fd_bank_hash_cmp_t );

  laddr = fd_ulong_align_up( laddr, fd_bank_hash_cmp_map_align() );
  fd_bank_hash_cmp_map_new( (void *)laddr, lg_slot_cnt );
  laddr += fd_bank_hash_cmp_map_footprint( lg_slot_cnt );

  laddr = fd_ulong_align_up( laddr, fd_bank_hash_cmp_align() );
  FD_TEST( laddr == (ulong)mem + fd_bank_hash_cmp_footprint( lg_slot_cnt ) );

  return mem;
}

fd_bank_hash_cmp_t *
fd_bank_hash_cmp_join( void * bank_hash_cmp ) {
  if( FD_UNLIKELY( !bank_hash_cmp ) ) {
    FD_LOG_WARNING( ( "NULL bank_hash_cmp" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)bank_hash_cmp, fd_bank_hash_cmp_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned bank_hash_cmp" ) );
    return NULL;
  }

  ulong laddr = (ulong)bank_hash_cmp;
  laddr += sizeof( fd_bank_hash_cmp_t );

  fd_bank_hash_cmp_t * bank_hash_cmp_ = (fd_bank_hash_cmp_t *)bank_hash_cmp;
  bank_hash_cmp_->map                 = fd_bank_hash_cmp_map_join( (void *)laddr );

  return bank_hash_cmp;
}

void *
fd_bank_hash_cmp_leave( fd_bank_hash_cmp_t const * bank_hash_cmp ) {

  if( FD_UNLIKELY( !bank_hash_cmp ) ) {
    FD_LOG_WARNING( ( "NULL bank_hash_cmp" ) );
    return NULL;
  }

  return (void *)bank_hash_cmp;
}

void *
fd_bank_hash_cmp_delete( void * bank_hash_cmp ) {

  if( FD_UNLIKELY( !bank_hash_cmp ) ) {
    FD_LOG_WARNING( ( "NULL bank_hash_cmp" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)bank_hash_cmp, fd_bank_hash_cmp_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned bank_hash_cmp" ) );
    return NULL;
  }

  return bank_hash_cmp;
}

void
fd_bank_hash_cmp_lock( fd_bank_hash_cmp_t * bank_hash_cmp ) {
  volatile int * lock = &bank_hash_cmp->lock;
  for( ;; ) {
    if( FD_LIKELY( !FD_ATOMIC_CAS( lock, 0UL, 1UL ) ) ) break;
    FD_SPIN_PAUSE();
  }
  FD_COMPILER_MFENCE();
}

void
fd_bank_hash_cmp_unlock( fd_bank_hash_cmp_t * bank_hash_cmp ) {
  volatile int * lock = &bank_hash_cmp->lock;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *lock ) = 0UL;
}

void
fd_bank_hash_cmp_insert( fd_bank_hash_cmp_t * bank_hash_cmp,
                         ulong                slot,
                         fd_hash_t const *    hash,
                         int                  ours ) {
  fd_bank_hash_cmp_entry_t * curr = fd_bank_hash_cmp_map_query( bank_hash_cmp->map, slot, NULL );
  fd_hash_t                  null_hash = { 0 };

  if( !curr ) {

    /* If full, make room for new bank hashes */

    if( FD_UNLIKELY( fd_bank_hash_cmp_map_key_cnt( bank_hash_cmp->map ) ==
                     fd_bank_hash_cmp_map_key_max( bank_hash_cmp->map ) ) ) {
      FD_LOG_WARNING( ( "Bank matches unexpectedly full. Clearing. " ) );
      fd_bank_hash_cmp_map_clear( bank_hash_cmp->map );
    }

    /* Save the bank hash for later, to check it matches our own bank hash */

    curr = fd_bank_hash_cmp_map_insert( bank_hash_cmp->map, slot );

  } else if( FD_UNLIKELY( !ours &&
                          ( 0 != memcmp( &curr->theirs, &null_hash, sizeof( fd_hash_t ) ) ) &&
                          ( 0 != memcmp( &curr->theirs, hash, sizeof( fd_hash_t ) ) ) ) ) {
    // TODO support equivocating hashes
    FD_LOG_WARNING( ( "overwriting equivocating hash for slot %lu %32J vs. %32J",
                      slot,
                      curr->theirs.hash,
                      hash->hash ) );
  }

  if( ours ) memcpy( &curr->ours, hash, sizeof( fd_hash_t ) );
  else memcpy( &curr->theirs, hash, sizeof( fd_hash_t ) );
}

int
fd_bank_hash_cmp_check( fd_bank_hash_cmp_t * bank_hash_cmp, ulong slot ) {
  fd_bank_hash_cmp_entry_t * cmp = fd_bank_hash_cmp_map_query( bank_hash_cmp->map, slot, NULL );
  fd_hash_t                  null_hash = { 0 };
  if( FD_LIKELY( cmp && cmp->rooted && 0 != memcmp( &cmp->ours, &null_hash, sizeof( fd_hash_t ) ) &&
                 0 != memcmp( &cmp->theirs, &null_hash, sizeof( fd_hash_t ) ) ) ) {
    if( FD_UNLIKELY( 0 != memcmp( &cmp->ours, &cmp->theirs, sizeof( fd_hash_t ) ) ) ) {
      FD_LOG_WARNING( ( "Bank hash mismatch on rooted slot: %lu. ours: %32J, theirs: %32J",
                        cmp->slot,
                        cmp->ours.hash,
                        cmp->theirs.hash ) );
      if( ++bank_hash_cmp->mismatch_cnt >= 5U ) {
        FD_LOG_WARNING( ( "Too many mismatches, shutting down!" ) );
        //fd_tile_shutdown_flag = 2;
      }
    } else {
      FD_LOG_NOTICE( ( "Bank hash match on rooted slot: %lu. hash: %32J",
                       cmp->slot,
                       cmp->ours.hash ) );
    }

    /* Remove so we don't check it again. */

    fd_bank_hash_cmp_map_remove( bank_hash_cmp->map, cmp );
    return 1;
  } else {
    return 0;
  }
}
