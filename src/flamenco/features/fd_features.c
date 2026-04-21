#include "fd_features.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"

FD_STATIC_ASSERT( sizeof  ( fd_feature_t                  )==9UL, layout );
FD_STATIC_ASSERT( offsetof( fd_feature_t, is_active       )==0UL, layout );
FD_STATIC_ASSERT( offsetof( fd_feature_t, activation_slot )==1UL, layout );

fd_feature_t *
fd_feature_decode( fd_feature_t * feature,
                   uchar const *  data,
                   ulong          data_sz ) {
  if( FD_UNLIKELY( data_sz < sizeof(fd_feature_t) ) ) return NULL;
  *feature = FD_LOAD( fd_feature_t, data );
  if( FD_UNLIKELY( feature->is_active>1 ) ) return NULL;
  return feature;
}

void
fd_features_enable_all( fd_features_t * f ) {
  for( fd_feature_id_t const * id = fd_feature_iter_init();
       !fd_feature_iter_done( id );
       id = fd_feature_iter_next( id ) ) {
    fd_features_set( f, id, 0UL );
  }
}

void
fd_features_disable_all( fd_features_t * f ) {
  for( fd_feature_id_t const * id = fd_feature_iter_init();
       !fd_feature_iter_done( id );
       id = fd_feature_iter_next( id ) ) {
    fd_features_set( f, id, FD_FEATURE_DISABLED );
  }
}

void
fd_features_enable_cleaned_up( fd_features_t * f ) {
  for( fd_feature_id_t const * id = fd_feature_iter_init();
       !fd_feature_iter_done( id );
       id = fd_feature_iter_next( id ) ) {
    if( FD_LIKELY( id->cleaned_up ) ) {
      fd_features_set( f, id, 0UL );
    } else {
      fd_features_set( f, id, FD_FEATURE_DISABLED );
    }
  }
}

void
fd_features_enable_one_offs( fd_features_t * f, char const * * one_offs, uint one_offs_cnt, ulong slot ) {
  uchar pubkey[32];
  for( uint i=0U; i<one_offs_cnt; i++ ) {
    fd_base58_decode_32( one_offs[i], pubkey );
    for( fd_feature_id_t const * id = fd_feature_iter_init();
         !fd_feature_iter_done( id );
         id = fd_feature_iter_next( id ) ) {
      if( !memcmp( &id->id, pubkey, sizeof(fd_pubkey_t) ) ) {
        fd_features_set( f, id, slot );
        break;
      }
    }
  }
}

static void
fd_feature_restore( fd_bank_t *             bank,
                    fd_accdb_t *            accdb,
                    fd_feature_id_t const * id,
                    fd_pubkey_t const *     addr ) {

  fd_features_t *             features       = &bank->f.features;
  fd_epoch_schedule_t const * epoch_schedule = &bank->f.epoch_schedule;
  ulong                       slot           = bank->f.slot;

  /* Skip reverted features */
  if( FD_UNLIKELY( id->reverted ) ) return;

  fd_accdb_entry_t entry = fd_accdb_read_one( accdb, bank->accdb_fork_id, addr->uc );
  if( FD_UNLIKELY( !entry.lamports ) ) return;

  /* Skip accounts that are not owned by the feature program
     https://github.com/anza-xyz/solana-sdk/blob/6512aca61167088ce10f2b545c35c9bcb1400e70/feature-gate-interface/src/lib.rs#L42-L44 */
  if( FD_UNLIKELY( memcmp( entry.owner, fd_solana_feature_program_id.uc, 32UL ) ) ) {
    fd_accdb_unread_one( accdb, &entry );
    return;
  }

  /* Account data size must be >= FD_FEATURE_SIZEOF (9 bytes)
     https://github.com/anza-xyz/solana-sdk/blob/6512aca61167088ce10f2b545c35c9bcb1400e70/feature-gate-interface/src/lib.rs#L45-L47 */
  if( FD_UNLIKELY( entry.data_len<sizeof(fd_feature_t) ) ) {
    fd_accdb_unread_one( accdb, &entry );
    return;
  }

  /* Deserialize the feature account data
     https://github.com/anza-xyz/solana-sdk/blob/6512aca61167088ce10f2b545c35c9bcb1400e70/feature-gate-interface/src/lib.rs#L48-L50 */
  fd_feature_t feature[1];
  if( FD_UNLIKELY( !fd_feature_decode( feature, entry.data, entry.data_len ) ) ) {
    fd_accdb_unread_one( accdb, &entry );
    return;
  }
  fd_accdb_unread_one( accdb, &entry );

  FD_BASE58_ENCODE_32_BYTES( addr->uc, addr_b58 );
  if( feature->is_active ) {
    FD_LOG_DEBUG(( "feature %s activated at slot %lu", addr_b58, feature->activation_slot ));
    fd_features_set( features, id, feature->activation_slot );
  } else if( fd_slot_to_epoch( epoch_schedule, slot, NULL )!=fd_slot_to_epoch( epoch_schedule, slot+1UL, NULL ) ) {
    ulong activation_slot = slot+1UL;
    FD_LOG_DEBUG(( "feature %s pending, pre-populating activation at slot %lu", addr_b58, activation_slot ));
    fd_features_set( features, id, activation_slot );
  } else {
    FD_LOG_DEBUG(( "feature %s not activated at slot %lu", addr_b58, feature->activation_slot ));
  }
}

void
fd_features_restore( fd_bank_t *  bank,
                     fd_accdb_t * accdb ) {
  for( fd_feature_id_t const * id = fd_feature_iter_init();
                                   !fd_feature_iter_done( id );
                               id = fd_feature_iter_next( id ) ) {
    fd_feature_restore( bank, accdb, id, &id->id );
  }
}
