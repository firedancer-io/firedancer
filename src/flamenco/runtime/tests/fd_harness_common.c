#include "fd_solfuzz_private.h"
#include "generated/context.pb.h"
#include "../fd_acc_mgr.h"
#include "../../features/fd_features.h"
#include <assert.h>

int
fd_solfuzz_pb_load_account( fd_txn_account_t *                acc,
                            fd_accdb_user_t *                 accdb,
                            fd_funk_txn_xid_t const *         xid,
                            fd_exec_test_acct_state_t const * state,
                            uchar                             reject_zero_lamports ) {
  if( reject_zero_lamports && state->lamports==0UL ) {
    return 0;
  }

  ulong size = 0UL;
  if( state->data ) size = state->data->size;

  fd_pubkey_t pubkey[1];  memcpy( pubkey, state->address, sizeof(fd_pubkey_t) );

  /* Account must not yet exist */
  if( FD_UNLIKELY( fd_funk_get_acc_meta_readonly( accdb->funk, xid, pubkey, NULL, NULL, NULL) ) ) {
    return 0;
  }

  fd_funk_rec_prepare_t prepare = {0};

  int ok = !!fd_txn_account_init_from_funk_mutable( /* acc         */ acc,
                                                    /* pubkey      */ pubkey,
                                                    /* funk        */ accdb,
                                                    /* xid         */ xid,
                                                    /* do_create   */ 1,
                                                    /* min_data_sz */ size,
                                                    /* prepare     */ &prepare );
  assert( ok );

  if( state->data ) {
    fd_txn_account_set_data( acc, state->data->bytes, size );
  }

  acc->starting_lamports = state->lamports;
  acc->starting_dlen     = size;
  fd_txn_account_set_lamports( acc, state->lamports );
  fd_txn_account_set_executable( acc, state->executable );
  fd_txn_account_set_owner( acc, (fd_pubkey_t const *)state->owner );

  /* make the account read-only by default */
  fd_txn_account_set_readonly( acc );

  fd_txn_account_mutable_fini( acc, accdb, &prepare );

  return 1;
}

int
fd_solfuzz_pb_restore_features( fd_features_t *                    features,
                                fd_exec_test_feature_set_t const * feature_set ) {
  fd_features_disable_all( features );
  for( ulong j=0UL; j < feature_set->features_count; j++ ) {
    ulong                   prefix = feature_set->features[j];
    fd_feature_id_t const * id     = fd_feature_id_query( prefix );
    if( FD_UNLIKELY( !id ) ) {
      FD_LOG_WARNING(( "unsupported feature ID 0x%016lx", prefix ));
      return 0;
    }
    /* Enabled since genesis */
    fd_features_set( features, id, 0UL );
  }
  return 1;
}

#ifdef FD_HAS_FLATCC
void
fd_solfuzz_fb_restore_features( fd_features_t *                    features,
                                SOL_COMPAT_NS(FeatureSet_table_t)  feature_set ) {
  if( FD_UNLIKELY( !feature_set ) ) return;

  fd_features_disable_all( features );
  flatbuffers_uint64_vec_t input_features     = SOL_COMPAT_NS(FeatureSet_features( feature_set ));
  ulong                    input_features_cnt = flatbuffers_uint64_vec_len( input_features );
  for( ulong i=0UL; i<input_features_cnt; i++ ) {
    ulong                   prefix = flatbuffers_uint64_vec_at( input_features, i );
    fd_feature_id_t const * id     = fd_feature_id_query( prefix );
    if( FD_UNLIKELY( !id ) ) {
      FD_LOG_ERR(( "unsupported feature ID 0x%016lx", prefix ));
    }
    /* Enabled since genesis */
    fd_features_set( features, id, 0UL );
  }
}
#endif
