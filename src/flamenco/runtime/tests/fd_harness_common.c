#include "../program/fd_program_cache.h"
#include "generated/context.pb.h"
#include <assert.h>

int
fd_runtime_fuzz_load_account( fd_txn_account_t *                acc,
                              fd_funk_t *                       funk,
                              fd_funk_txn_t *                   funk_txn,
                              fd_exec_test_acct_state_t const * state,
                              uchar                             reject_zero_lamports ) {
  if( reject_zero_lamports && state->lamports==0UL ) {
    return 0;
  }

  ulong size = 0UL;
  if( state->data ) size = state->data->size;

  fd_pubkey_t pubkey[1];  memcpy( pubkey, state->address, sizeof(fd_pubkey_t) );

  /* Account must not yet exist */
  if( FD_UNLIKELY( fd_funk_get_acc_meta_readonly( funk, funk_txn, pubkey, NULL, NULL, NULL) ) ) {
    return 0;
  }

  fd_funk_rec_prepare_t prepare = {0};

  assert( funk );
  int err = fd_txn_account_init_from_funk_mutable( /* acc         */ acc,
                                                   /* pubkey      */ pubkey,
                                                   /* funk        */ funk,
                                                   /* txn         */ funk_txn,
                                                   /* do_create   */ 1,
                                                   /* min_data_sz */ size,
                                                   /* prepare     */ &prepare );
  assert( err==FD_ACC_MGR_SUCCESS );

  if( state->data ) {
    fd_txn_account_set_data( acc, state->data->bytes, size );
  }

  acc->starting_lamports = state->lamports;
  acc->starting_dlen     = size;
  fd_txn_account_set_lamports( acc, state->lamports );
  fd_txn_account_set_executable( acc, state->executable );
  fd_txn_account_set_rent_epoch( acc, state->rent_epoch );
  fd_txn_account_set_owner( acc, (fd_pubkey_t const *)state->owner );

  /* make the account read-only by default */
  fd_txn_account_set_readonly( acc );

  fd_txn_account_mutable_fini( acc, funk, funk_txn, &prepare );

  return 1;
}

int
fd_runtime_fuzz_restore_features( fd_features_t *                    features,
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

void
fd_runtime_fuzz_refresh_program_cache( fd_exec_slot_ctx_t *              slot_ctx,
                                       fd_exec_test_acct_state_t const * acct_states,
                                       ulong                             acct_states_count,
                                       fd_spad_t *                       runtime_spad ) {
  for( ushort i=0; i<acct_states_count; i++ ) {
    fd_pubkey_t pubkey[1] = {0};
    memcpy( &pubkey, acct_states[i].address, sizeof(fd_pubkey_t) );
    fd_program_cache_update_program( slot_ctx, pubkey, runtime_spad );
  }
}
