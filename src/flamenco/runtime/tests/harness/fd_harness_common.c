#include "fd_harness_common.h"

ulong
fd_runtime_fuzz_runner_align( void ) {
  return alignof(fd_runtime_fuzz_runner_t);
}

ulong
fd_runtime_fuzz_runner_footprint( void ) {
  ulong txn_max = 4+fd_tile_cnt();
  uint rec_max  = 1024;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_runtime_fuzz_runner_align(), sizeof(fd_runtime_fuzz_runner_t) );
  l = FD_LAYOUT_APPEND( l, fd_funk_align(),                fd_funk_footprint( txn_max, rec_max ) );
  /* Spad memory is not included in the footprint since its allocated separately at the beginning of a fuzzing run */
  return FD_LAYOUT_FINI( l, fd_runtime_fuzz_runner_align() );
}

fd_runtime_fuzz_runner_t *
fd_runtime_fuzz_runner_new( void *      mem,
                            void *      spad_mem,
                            fd_bank_t * bank,
                            ulong       wksp_tag ) {
  ulong txn_max = 4+fd_tile_cnt();
  uint rec_max  = 1024;

  FD_SCRATCH_ALLOC_INIT( l, mem );
  void * runner_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_runtime_fuzz_runner_align(), sizeof(fd_runtime_fuzz_runner_t) );
  void * funk_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_funk_align(),                fd_funk_footprint( txn_max, rec_max ) );
  FD_SCRATCH_ALLOC_FINI( l, fd_runtime_fuzz_runner_align() );

  fd_runtime_fuzz_runner_t * runner = runner_mem;

  fd_funk_t * funk = fd_funk_join( runner->funk, fd_funk_new( funk_mem, wksp_tag, (ulong)fd_tickcount(), txn_max, rec_max ) );
  if( FD_UNLIKELY( !funk ) ) {
    FD_LOG_WARNING(( "fd_funk_new() failed" ));
    return NULL;
  }

  /* Create spad */
  runner->spad = fd_spad_join( fd_spad_new( spad_mem, FD_RUNTIME_TRANSACTION_EXECUTION_FOOTPRINT_FUZZ ) );
  runner->wksp = fd_wksp_containing( runner->spad );

  /* Reuse the same bank for each iteration of the fuzzer */
  runner->bank = bank;

  return runner;
}

void *
fd_runtime_fuzz_runner_delete( fd_runtime_fuzz_runner_t * runner ) {
  if( FD_UNLIKELY( !runner ) ) return NULL;
  void * shfunk;
  fd_funk_leave( runner->funk, &shfunk );
  fd_funk_delete( shfunk );
  if( FD_UNLIKELY( fd_spad_verify( runner->spad ) ) ) {
    FD_LOG_ERR(( "fd_spad_verify() failed" ));
  }
  if( FD_UNLIKELY( fd_spad_frame_used( runner->spad )!=0 ) ) {
    FD_LOG_ERR(( "stray spad frame frame_used=%lu", fd_spad_frame_used( runner->spad ) ));
  }
  runner->spad = NULL;
  return runner;
}

int
fd_runtime_fuzz_load_account( fd_txn_account_t *                acc,
                              fd_funk_t *                       funk,
                              fd_funk_txn_t *                   funk_txn,
                              fd_exec_test_acct_state_t const * state,
                              uchar                             reject_zero_lamports ) {
  if( reject_zero_lamports && state->lamports==0UL ) {
    return 0;
  }

  fd_txn_account_init( acc );
  ulong size = 0UL;
  if( state->data ) size = state->data->size;

  fd_pubkey_t pubkey[1];  memcpy( pubkey, state->address, sizeof(fd_pubkey_t) );

  /* Account must not yet exist */
  if( FD_UNLIKELY( fd_funk_get_acc_meta_readonly( funk, funk_txn, pubkey, NULL, NULL, NULL) ) ) {
    return 0;
  }

  assert( funk );
  int err = fd_txn_account_init_from_funk_mutable( /* acc         */ acc,
                                                   /* pubkey      */ pubkey,
                                                   /* funk        */ funk,
                                                   /* txn         */ funk_txn,
                                                   /* do_create   */ 1,
                                                   /* min_data_sz */ size );
  assert( err==FD_ACC_MGR_SUCCESS );
  if( state->data ) {
    acc->vt->set_data( acc, state->data->bytes, size );
  }

  acc->starting_lamports = state->lamports;
  acc->starting_dlen     = size;
  acc->vt->set_lamports( acc, state->lamports );
  acc->vt->set_executable( acc, state->executable );
  acc->vt->set_rent_epoch( acc, state->rent_epoch );
  acc->vt->set_owner( acc, (fd_pubkey_t const *)state->owner );

  /* make the account read-only by default */
  acc->vt->set_readonly( acc );

  fd_txn_account_mutable_fini( acc, funk, funk_txn );

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
