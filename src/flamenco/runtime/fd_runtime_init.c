#include "fd_runtime_init.h"
#include "fd_acc_mgr.h"
#include "../types/fd_types.h"
#include "context/fd_exec_slot_ctx.h"
#include "fd_system_ids.h"
#include "../accdb/fd_accdb_sync.h"

/* fd_feature_restore loads a feature from the accounts database and
   updates the bank's feature activation state, given a feature account
   address. */

static void
fd_feature_restore( fd_features_t *         features,
                    fd_exec_slot_ctx_t *    slot_ctx,
                    fd_feature_id_t const * id,
                    uchar const             acct[ static 32 ] ) {

  /* Skip reverted features */
  if( FD_UNLIKELY( id->reverted ) ) {
    return;
  }

  fd_feature_t feature[1];
  int db_err = FD_ACCDB_READ_BEGIN( slot_ctx->accdb, acct, rec ) {
    /* Skip accounts that are not owned by the feature program
       https://github.com/anza-xyz/solana-sdk/blob/6512aca61167088ce10f2b545c35c9bcb1400e70/feature-gate-interface/src/lib.rs#L42-L44 */
    if( FD_UNLIKELY( memcmp( fd_accdb_ref_owner( rec ), fd_solana_feature_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
      return;
    }

    /* Account data size must be >= FD_FEATURE_SIZEOF (9 bytes)
       https://github.com/anza-xyz/solana-sdk/blob/6512aca61167088ce10f2b545c35c9bcb1400e70/feature-gate-interface/src/lib.rs#L45-L47 */
    if( FD_UNLIKELY( fd_accdb_ref_data_sz( rec )<FD_FEATURE_SIZEOF ) ) {
      return;
    }

    if( FD_UNLIKELY( !fd_bincode_decode_static(
        feature, feature,
        fd_accdb_ref_data_const( rec ),
        fd_accdb_ref_data_sz   ( rec ),
        NULL ) ) ) {
      return; /* decode error */
    }
  }
  FD_ACCDB_READ_END;
  if( db_err!=FD_ACCDB_SUCCESS ) {
    if( FD_UNLIKELY( db_err!=FD_ACCDB_ERR_KEY ) ) {
      FD_BASE58_ENCODE_32_BYTES( acct, acct_b58 );
      FD_LOG_ERR(( "Failed to peek feature account %s: database error (%i-%s)", acct_b58, db_err, fd_accdb_strerror( db_err ) ));
    }
    /* Feature account does not exist */
    return;
  }

  /* Deserialize the feature account data
     https://github.com/anza-xyz/solana-sdk/blob/6512aca61167088ce10f2b545c35c9bcb1400e70/feature-gate-interface/src/lib.rs#L48-L50 */
  if( feature->has_activated_at ) {
    FD_LOG_INFO(( "Feature %s activated at %lu", FD_BASE58_ENC_32_ALLOCA( acct ), feature->activated_at ));
    fd_features_set( features, id, feature->activated_at );
  } else {
    FD_LOG_DEBUG(( "Feature %s not activated at %lu", FD_BASE58_ENC_32_ALLOCA( acct ), feature->activated_at ));
  }
}

void
fd_features_restore( fd_exec_slot_ctx_t * slot_ctx ) {
  fd_features_t * features = fd_bank_features_modify( slot_ctx->bank );

  for( fd_feature_id_t const * id = fd_feature_iter_init();
                                   !fd_feature_iter_done( id );
                               id = fd_feature_iter_next( id ) ) {
    fd_feature_restore( features, slot_ctx, id, id->id.key );
  }
}
