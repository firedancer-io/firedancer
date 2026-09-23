#include "fd_features.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../accdb/fd_accdb_cache.h"

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

static uchar one_off_forced[ FD_FEATURE_ID_CNT ];

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
        one_off_forced[ id->index ] = (uchar)( slot!=FD_FEATURE_DISABLED );
        break;
      }
    }
  }
}

/* fd_feature_restore sets the activation slot of feature id given its
   account acc (acc->lamports==0 if the account does not exist). */

static void
fd_feature_restore( fd_features_t *             features,
                    fd_acc_t const *            acc,
                    ulong                       slot,
                    fd_epoch_schedule_t const * epoch_schedule,
                    fd_feature_id_t const *     id ) {
  fd_features_set( features, id, FD_FEATURE_DISABLED );

  if( FD_UNLIKELY( !acc->lamports ) ) return;

  /* Skip accounts that are not owned by the feature program
     https://github.com/anza-xyz/solana-sdk/blob/6512aca61167088ce10f2b545c35c9bcb1400e70/feature-gate-interface/src/lib.rs#L42-L44 */
  if( FD_UNLIKELY( memcmp( acc->owner, fd_solana_feature_program_id.uc, 32UL ) ) ) return;

  /* Account data size must be >= FD_FEATURE_SIZEOF (9 bytes)
     https://github.com/anza-xyz/solana-sdk/blob/6512aca61167088ce10f2b545c35c9bcb1400e70/feature-gate-interface/src/lib.rs#L45-L47 */
  if( FD_UNLIKELY( acc->data_len<sizeof(fd_feature_t) ) ) return;

  /* Deserialize the feature account data
     https://github.com/anza-xyz/solana-sdk/blob/6512aca61167088ce10f2b545c35c9bcb1400e70/feature-gate-interface/src/lib.rs#L48-L50 */
  fd_feature_t feature[1];
  if( FD_UNLIKELY( !fd_feature_decode( feature, acc->data, acc->data_len ) ) ) return;

  FD_BASE58_ENCODE_32_BYTES( id->id.uc, addr_b58 );
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
fd_features_restore_chunk( fd_features_t *             features,
                           fd_accdb_t *                accdb,
                           fd_accdb_fork_id_t          fork_id,
                           ulong                       slot,
                           fd_epoch_schedule_t const * epoch_schedule,
                           ulong                       chunk_idx,
                           ulong                       chunk_cnt ) {
  FD_TEST( chunk_cnt>0UL );
  FD_TEST( chunk_idx<chunk_cnt );

  ulong begin = chunk_idx     * FD_FEATURE_ID_CNT / chunk_cnt;
  ulong end   = (chunk_idx+1) * FD_FEATURE_ID_CNT / chunk_cnt;

  fd_feature_id_t const * id = ids+begin;
  while( id<ids+end ) {
    fd_feature_id_t const * batch_ids[ FD_ACCDB_MAX_TX_ACCOUNT_LOCKS ];
    uchar const *           pubkeys  [ FD_ACCDB_MAX_TX_ACCOUNT_LOCKS ];
    int                     writable [ FD_ACCDB_MAX_TX_ACCOUNT_LOCKS ];
    fd_acc_t                accs     [ FD_ACCDB_MAX_TX_ACCOUNT_LOCKS ];
    ulong batch_cnt = 0UL;
    for( ; id<ids+end && batch_cnt<FD_ACCDB_MAX_TX_ACCOUNT_LOCKS; id++ ) {
      if( FD_UNLIKELY( id->cleaned_up ) ) {
        fd_features_set( features, id, 0UL );
      } else if( FD_UNLIKELY( id->reverted ) ) {
        fd_features_set( features, id, FD_FEATURE_DISABLED );
      } else {
        batch_ids[ batch_cnt ] = id;
        pubkeys  [ batch_cnt ] = id->id.uc;
        writable [ batch_cnt ] = 0;
        batch_cnt++;
        continue;
      }
      if( FD_UNLIKELY( one_off_forced[ id->index ] ) ) fd_features_set( features, id, 0UL );
    }
    if( !batch_cnt ) continue;

    fd_accdb_acquire( accdb, fork_id, batch_cnt, pubkeys, writable, accs );
    for( ulong i=0UL; i<batch_cnt; i++ ) {
      fd_feature_restore( features, &accs[ i ], slot, epoch_schedule, batch_ids[ i ] );
      if( FD_UNLIKELY( one_off_forced[ batch_ids[ i ]->index ] ) ) fd_features_set( features, batch_ids[ i ], 0UL );
    }
    fd_accdb_release( accdb, batch_cnt, accs );
  }
}

void
fd_features_restore( fd_features_t *             features,
                     fd_accdb_t *                accdb,
                     fd_accdb_fork_id_t          fork_id,
                     ulong                       slot,
                     fd_epoch_schedule_t const * epoch_schedule ) {
  fd_features_restore_chunk( features, accdb, fork_id, slot, epoch_schedule, 0UL, 1UL );
}
