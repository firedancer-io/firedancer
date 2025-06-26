#include "fd_runtime_init.h"
#include "fd_runtime_err.h"
#include <stdio.h>
#include "../types/fd_types.h"
#include "context/fd_exec_slot_ctx.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "fd_system_ids.h"

/* fd_feature_restore loads a feature from the accounts database and
   updates the bank's feature activation state, given a feature account
   address. */

static void
fd_feature_restore( fd_features_t *         features,
                    fd_exec_slot_ctx_t *    slot_ctx,
                    fd_feature_id_t const * id,
                    uchar const             acct[ static 32 ],
                    fd_spad_t *             runtime_spad ) {

  /* Skip reverted features */
  if( FD_UNLIKELY( id->reverted ) ) {
    return;
  }

  FD_TXN_ACCOUNT_DECL( acct_rec );
  int err = fd_txn_account_init_from_funk_readonly( acct_rec,
                                                    (fd_pubkey_t *)acct,
                                                    slot_ctx->funk,
                                                    slot_ctx->funk_txn );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    return;
  }

  /* Skip accounts that are not owned by the feature program
     https://github.com/anza-xyz/solana-sdk/blob/6512aca61167088ce10f2b545c35c9bcb1400e70/feature-gate-interface/src/lib.rs#L42-L44 */
  if( FD_UNLIKELY( memcmp( acct_rec->vt->get_owner( acct_rec ), fd_solana_feature_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    return;
  }

  /* Account data size must be >= FD_FEATURE_SIZEOF (9 bytes)
     https://github.com/anza-xyz/solana-sdk/blob/6512aca61167088ce10f2b545c35c9bcb1400e70/feature-gate-interface/src/lib.rs#L45-L47 */
  if( FD_UNLIKELY( acct_rec->vt->get_data_len( acct_rec )<FD_FEATURE_SIZEOF ) ) {
    return;
  }

  /* Deserialize the feature account data
     https://github.com/anza-xyz/solana-sdk/blob/6512aca61167088ce10f2b545c35c9bcb1400e70/feature-gate-interface/src/lib.rs#L48-L50 */
  FD_SPAD_FRAME_BEGIN( runtime_spad ) {
    int decode_err;
    fd_feature_t * feature = fd_bincode_decode_spad(
        feature, runtime_spad,
        acct_rec->vt->get_data( acct_rec ),
        acct_rec->vt->get_data_len( acct_rec ),
        &decode_err );
    if( FD_UNLIKELY( decode_err ) ) {
      return;
    }

    if( feature->has_activated_at ) {
      FD_LOG_INFO(( "Feature %s activated at %lu", FD_BASE58_ENC_32_ALLOCA( acct ), feature->activated_at ));
      fd_features_set( features, id, feature->activated_at );
    } else {
      FD_LOG_DEBUG(( "Feature %s not activated at %lu", FD_BASE58_ENC_32_ALLOCA( acct ), feature->activated_at ));
    }
    /* No need to call destroy, since we are using fd_spad allocator. */
  } FD_SPAD_FRAME_END;
}

void
fd_features_restore( fd_exec_slot_ctx_t * slot_ctx, fd_spad_t * runtime_spad ) {
  fd_features_t * features = fd_bank_features_modify( slot_ctx->bank );

  for( fd_feature_id_t const * id = fd_feature_iter_init();
                                   !fd_feature_iter_done( id );
                               id = fd_feature_iter_next( id ) ) {
    fd_feature_restore( features, slot_ctx, id, id->id.key, runtime_spad );
  }
}
