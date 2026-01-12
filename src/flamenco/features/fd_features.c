#include "fd_features.h"
#include "../runtime/fd_bank.h"
#include "../runtime/fd_system_ids.h"
#include "../accdb/fd_accdb_sync.h"

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
fd_features_enable_cleaned_up( fd_features_t * f, fd_cluster_version_t const * cluster_version ) {
  for( fd_feature_id_t const * id = fd_feature_iter_init();
       !fd_feature_iter_done( id );
       id = fd_feature_iter_next( id ) ) {
    if( ( id->cleaned_up[0]<cluster_version->major ) ||
        ( id->cleaned_up[0]==cluster_version->major && id->cleaned_up[1]<cluster_version->minor ) ||
        ( id->cleaned_up[0]==cluster_version->major && id->cleaned_up[1]==cluster_version->minor && id->cleaned_up[2]<=cluster_version->patch ) ) {
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
fd_feature_restore( fd_bank_t *               bank,
                    fd_accdb_user_t *         accdb,
                    fd_funk_txn_xid_t const * xid,
                    fd_feature_id_t const *   id,
                    fd_pubkey_t const *       addr ) {

  fd_features_t * features = fd_bank_features_modify( bank );

  /* https://github.com/anza-xyz/solana-sdk/blob/6512aca61167088ce10f2b545c35c9bcb1400e70/feature-gate-interface/src/lib.rs#L36-L38 */
  #define FD_FEATURE_SIZEOF      (9UL)

  /* Skip reverted features */
  if( FD_UNLIKELY( id->reverted ) ) return;

  fd_accdb_ro_t ro[1];
  if( FD_UNLIKELY( !fd_accdb_open_ro( accdb, ro, xid, addr ) ) )  {
    return;
  }

  /* Skip accounts that are not owned by the feature program
     https://github.com/anza-xyz/solana-sdk/blob/6512aca61167088ce10f2b545c35c9bcb1400e70/feature-gate-interface/src/lib.rs#L42-L44 */
  if( FD_UNLIKELY( memcmp( fd_accdb_ref_owner( ro ), fd_solana_feature_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    fd_accdb_close_ro( accdb, ro );
    return;
  }

  /* Account data size must be >= FD_FEATURE_SIZEOF (9 bytes)
     https://github.com/anza-xyz/solana-sdk/blob/6512aca61167088ce10f2b545c35c9bcb1400e70/feature-gate-interface/src/lib.rs#L45-L47 */
  if( FD_UNLIKELY( fd_accdb_ref_data_sz( ro )<FD_FEATURE_SIZEOF ) ) {
    fd_accdb_close_ro( accdb, ro );
    return;
  }

  /* Deserialize the feature account data
     https://github.com/anza-xyz/solana-sdk/blob/6512aca61167088ce10f2b545c35c9bcb1400e70/feature-gate-interface/src/lib.rs#L48-L50 */
  fd_feature_t feature[1];
  if( FD_UNLIKELY( !fd_bincode_decode_static(
      feature, feature,
      fd_accdb_ref_data_const( ro ),
      fd_accdb_ref_data_sz   ( ro ),
      NULL ) ) ) {
    fd_accdb_close_ro( accdb, ro );
    return;
  }
  fd_accdb_close_ro( accdb, ro );

  FD_BASE58_ENCODE_32_BYTES( addr->uc, addr_b58 );
  if( feature->has_activated_at ) {
    FD_LOG_DEBUG(( "Feature %s activated at %lu", addr_b58, feature->activated_at ));
    fd_features_set( features, id, feature->activated_at );
  } else {
    FD_LOG_DEBUG(( "Feature %s not activated at %lu", addr_b58, feature->activated_at ));
  }
}

void
fd_features_restore( fd_bank_t *               bank,
                     fd_accdb_user_t *         accdb,
                     fd_funk_txn_xid_t const * xid ) {

  for( fd_feature_id_t const * id = fd_feature_iter_init();
                                   !fd_feature_iter_done( id );
                               id = fd_feature_iter_next( id ) ) {
    fd_feature_restore( bank, accdb, xid, id, &id->id );
  }
}
