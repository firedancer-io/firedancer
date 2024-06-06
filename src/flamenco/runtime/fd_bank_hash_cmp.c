#include "fd_bank_hash_cmp.h"
#include <unistd.h>

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
                         int                  ours,
                         ulong                stake ) {
  if( FD_UNLIKELY( slot <= bank_hash_cmp->slot ) ) { return; }
  fd_bank_hash_cmp_entry_t * cmp = fd_bank_hash_cmp_map_query( bank_hash_cmp->map, slot, NULL );

  if( !cmp ) {

    /* If full, make room for new bank hashes */

    if( FD_UNLIKELY( fd_bank_hash_cmp_map_key_cnt( bank_hash_cmp->map ) ==
                     fd_bank_hash_cmp_map_key_max( bank_hash_cmp->map ) ) ) {
      FD_LOG_WARNING( ( "Bank matches unexpectedly full. Clearing. " ) );
      for( ulong i = 0; i < fd_bank_hash_cmp_map_key_max( bank_hash_cmp->map ); i++ ) {
        fd_bank_hash_cmp_entry_t * entry = &bank_hash_cmp->map[i];
        if( FD_LIKELY( !fd_bank_hash_cmp_map_key_inval( entry->slot ) &&
                       entry->slot < bank_hash_cmp->slot ) ) {
          fd_bank_hash_cmp_map_remove( bank_hash_cmp->map, entry );
        }
      }
      fd_bank_hash_cmp_map_clear( bank_hash_cmp->map );
    }

    cmp      = fd_bank_hash_cmp_map_insert( bank_hash_cmp->map, slot );
    cmp->cnt = 0;
  }

  if( FD_UNLIKELY( ours ) ) {
    cmp->ours = *hash;
    return;
  }

  for( ulong i = 0; i < cmp->cnt; i++ ) {
    if( FD_LIKELY( 0 == memcmp( &cmp->theirs[i], hash, sizeof( fd_hash_t ) ) ) ) {
      cmp->stakes[i] += stake;
      return;
    }
  }

  ulong max = sizeof( cmp->stakes ) / sizeof( ulong );
  if( FD_UNLIKELY( cmp->cnt == max ) ) {
    if( !cmp->overflow ) {
      FD_LOG_WARNING( ( "[Bank Hash Comparison] more than %lu equivocating hashes for slot %lu. "
                        "new hash: %32J. ignoring.",
                        max,
                        slot,
                        hash ) );
      cmp->overflow = 1;
    }
    return;
  }
  cmp->cnt++;
  cmp->theirs[cmp->cnt - 1] = *hash;
  cmp->stakes[cmp->cnt - 1] = stake;
  if( FD_UNLIKELY( cmp->cnt > 1 ) ) {
    for( ulong i = 0; i < cmp->cnt; i++ ) {
      FD_LOG_WARNING( ( "slot: %lu. equivocating hash (#%lu): %32J. stake: %lu",
                        cmp->slot,
                        i,
                        cmp->theirs[i].hash,
                        cmp->stakes[i] ) );
    }
  }
}

int
fd_bank_hash_cmp_check( fd_bank_hash_cmp_t * bank_hash_cmp, ulong slot ) {
  fd_bank_hash_cmp_entry_t * cmp = fd_bank_hash_cmp_map_query( bank_hash_cmp->map, slot, NULL );

  if( FD_UNLIKELY( !cmp ) ) return 0;

  // if( FD_UNLIKELY( !cmp->rooted ) ) return 0;

  fd_hash_t null_hash = { 0 };
  if( FD_LIKELY( 0 == memcmp( &cmp->ours, &null_hash, sizeof( fd_hash_t ) ) ) ) return 0;

  if( FD_UNLIKELY( cmp->cnt == 0 ) ) return 0;

  fd_hash_t * theirs = &cmp->theirs[0];
  ulong       stake  = cmp->stakes[0];
  for( ulong i = 1; i < cmp->cnt; i++ ) {
    if( FD_UNLIKELY( cmp->stakes[i] > stake ) ) {
      theirs = &cmp->theirs[i];
      stake  = cmp->stakes[i];
    }
  }

  double pct = (double)stake / (double)bank_hash_cmp->total_stake;
  if( FD_LIKELY( pct > 0.52 ) ) {
    if( FD_UNLIKELY( 0 != memcmp( &cmp->ours, theirs, sizeof( fd_hash_t ) ) ) ) {
      FD_LOG_WARNING( ( "\n\n[Bank Hash Comparison]\n"
                        "slot:   %lu\n"
                        "ours:   %32J\n"
                        "theirs: %32J\n"
                        "stake:  %.0lf%%\n"
                        "result: mismatch!\n",
                        cmp->slot,
                        cmp->ours.hash,
                        theirs->hash,
                        pct * 100 ) );
      if( FD_UNLIKELY( cmp->cnt > 1 ) ) {
        for( ulong i = 0; i < cmp->cnt; i++ ) {
          FD_LOG_WARNING( ( "slot: %lu. hash (#%lu): %32J. stake: %lu",
                            cmp->slot,
                            i,
                            cmp->theirs[i].hash,
                            cmp->stakes[i] ) );
        }
      }
      FD_LOG_ERR( ( "bank hash mismatch on %lu, shutting down!", cmp->slot ) );
    } else {
      FD_LOG_NOTICE( ( "\n\n[Bank Hash Comparison]\n"
                       "slot:   %lu\n"
                       "ours:   %32J\n"
                       "theirs: %32J\n"
                       "stake:  %.0lf%%\n"
                       "result: match!\n",
                       cmp->slot,
                       cmp->ours.hash,
                       theirs->hash,
                       pct * 100 ) );
    }
    fd_bank_hash_cmp_map_remove( bank_hash_cmp->map, cmp );
    return 1;
  }
  return 0;
}
