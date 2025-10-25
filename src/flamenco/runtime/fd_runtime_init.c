#include "fd_runtime_init.h"
#include "fd_acc_mgr.h"
#include "fd_bank.h"
#include "../types/fd_types.h"
#include "fd_system_ids.h"

/* fd_feature_restore loads a feature from the accounts database and
   updates the bank's feature activation state, given a feature account
   address. */

static void
fd_feature_restore( fd_bank_t *               bank,
                    fd_funk_t *               funk,
                    fd_funk_txn_xid_t const * xid,
                    fd_feature_id_t const *   id,
                    fd_pubkey_t const *       addr ) {

  fd_features_t * features = fd_bank_features_modify( bank );

  /* Skip reverted features */
  if( FD_UNLIKELY( id->reverted ) ) return;

  fd_txn_account_t acct_rec[1];
  int err = fd_txn_account_init_from_funk_readonly( acct_rec,
                                                    addr,
                                                    funk,
                                                    xid );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    return;
  }

  /* Skip accounts that are not owned by the feature program
     https://github.com/anza-xyz/solana-sdk/blob/6512aca61167088ce10f2b545c35c9bcb1400e70/feature-gate-interface/src/lib.rs#L42-L44 */
  if( FD_UNLIKELY( memcmp( fd_txn_account_get_owner( acct_rec ), fd_solana_feature_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    return;
  }

  /* Account data size must be >= FD_FEATURE_SIZEOF (9 bytes)
     https://github.com/anza-xyz/solana-sdk/blob/6512aca61167088ce10f2b545c35c9bcb1400e70/feature-gate-interface/src/lib.rs#L45-L47 */
  if( FD_UNLIKELY( fd_txn_account_get_data_len( acct_rec )<FD_FEATURE_SIZEOF ) ) {
    return;
  }

  /* Deserialize the feature account data
     https://github.com/anza-xyz/solana-sdk/blob/6512aca61167088ce10f2b545c35c9bcb1400e70/feature-gate-interface/src/lib.rs#L48-L50 */
  fd_feature_t feature[1];
  if( FD_UNLIKELY( !fd_bincode_decode_static(
      feature, feature,
      fd_txn_account_get_data( acct_rec ),
      fd_txn_account_get_data_len( acct_rec ),
      NULL ) ) ) {
    return;
  }

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
                     fd_funk_t *               funk,
                     fd_funk_txn_xid_t const * xid ) {

  for( fd_feature_id_t const * id = fd_feature_iter_init();
                                   !fd_feature_iter_done( id );
                               id = fd_feature_iter_next( id ) ) {
    fd_feature_restore( bank, funk, xid, id, &id->id );
  }
}
