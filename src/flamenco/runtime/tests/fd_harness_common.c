#include "fd_solfuzz_private.h"
#include "generated/context.pb.h"
#include "../fd_runtime.h"
#include "../../features/fd_features.h"
#include "../../accdb/fd_accdb_sync.h"
#include <assert.h>

int
fd_solfuzz_pb_load_account( fd_runtime_t *                    runtime,
                            fd_accdb_user_t *                 accdb,
                            fd_funk_txn_xid_t const *         xid,
                            fd_exec_test_acct_state_t const * state,
                            ulong                             acc_idx ) {
  if( state->lamports==0UL ) return 0;

  ulong size = 0UL;
  if( state->data ) size = state->data->size;

  fd_pubkey_t pubkey[1];  memcpy( pubkey, state->address, sizeof(fd_pubkey_t) );

  /* Account must not yet exist */
  fd_accdb_ro_t ro[1];
  if( FD_UNLIKELY( fd_accdb_open_ro( accdb, ro, xid, pubkey ) ) ) {
    fd_accdb_close_ro( accdb, ro );
    return 0;
  }

  fd_accdb_rw_t rw[1];
  fd_accdb_open_rw( accdb, rw, xid, pubkey, size, FD_ACCDB_FLAG_CREATE );
  if( state->data ) {
    fd_accdb_ref_data_set( accdb, rw, state->data->bytes, size );
  }
  runtime->accounts.starting_lamports[ acc_idx ] = state->lamports;
  runtime->accounts.starting_dlen    [ acc_idx ] = size;
  fd_accdb_ref_lamports_set( rw, state->lamports   );
  fd_accdb_ref_exec_bit_set( rw, state->executable );
  fd_accdb_ref_owner_set   ( rw, state->owner      );
  fd_accdb_close_rw( accdb, rw );

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

#if FD_HAS_FLATCC

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

#endif /* FD_HAS_FLATCC */
