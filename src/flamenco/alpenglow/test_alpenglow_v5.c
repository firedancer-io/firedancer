#include "fd_alpenglow.c"
#include "../runtime/tests/fd_svm_mini.h"

static fd_validator_location_t const LOC_FRA = { 4051542, 618526, 4870645 };

static void
random_v4( fd_vote_state_versioned_t * vsv,
           fd_rng_t *                  rng ) {
  FD_TEST( fd_vote_state_versioned_new( vsv, fd_vote_state_versioned_enum_v4 ) );
  fd_vote_state_v4_t * s = &vsv->v4;
  s->has_bls_pubkey_compressed = 1;
  s->has_root_slot             = (uchar)( fd_rng_uint( rng )&1U );
  s->root_slot                 = fd_rng_ulong_roll( rng, 1000UL );
  s->last_timestamp            = (fd_vote_block_timestamp_t){ .slot=fd_rng_ulong_roll( rng, 1000UL ), .timestamp=(long)fd_rng_ulong_roll( rng, 1000UL ) };

  ulong vote_cnt = fd_rng_ulong_roll( rng, MAX_LOCKOUT_HISTORY+1UL );
  ulong slot     = fd_rng_ulong_roll( rng, 1000UL );
  for( ulong i=0UL; i<vote_cnt; i++ ) {
    slot += 1UL+fd_rng_ulong_roll( rng, 4UL );
    deq_fd_landed_vote_t_push_tail( s->votes, (fd_landed_vote_t){ .lockout={ .slot=slot, .confirmation_count=1U } } );
  }

  ulong ec_cnt  = fd_rng_ulong_roll( rng, MAX_EPOCH_CREDITS_HISTORY+1UL );
  ulong marker  = ( fd_rng_uint( rng )&1U ) ? fd_rng_ulong_roll( rng, ec_cnt+1UL ) : ULONG_MAX;
  ulong credits = 0UL;
  for( ulong i=0UL; i<ec_cnt; i++ ) {
    if( i==marker ) {
      deq_fd_vote_epoch_credits_t_push_tail( s->epoch_credits, (fd_vote_epoch_credits_t){ .epoch=ULONG_MAX, .credits=ULONG_MAX, .prev_credits=ULONG_MAX } );
      continue;
    }
    ulong prev = credits;
    credits += 100UL*fd_rng_ulong_roll( rng, 3UL );
    deq_fd_vote_epoch_credits_t_push_tail( s->epoch_credits, (fd_vote_epoch_credits_t){ .epoch=i, .credits=credits, .prev_credits=prev } );
  }
}

static void
convert_copy( fd_vote_state_versioned_t const * src,
              fd_vote_state_versioned_t *       dst,
              uchar *                           data ) {
  FD_TEST( !fd_vote_state_versioned_serialize( src, data, FD_VOTE_STATE_V4_SZ ) );
  FD_TEST( fd_vote_state_versioned_deserialize( dst, data, FD_VOTE_STATE_V4_SZ ) );
  FD_TEST( !fd_vsv_try_convert_to_v5( dst, &LOC_FRA, 0UL ) );
}

static void
test_v5_update_matches_v4( fd_rng_t * rng ) {
  static fd_vote_state_versioned_t v4[1], scratch[1];
  static fd_vote_state_v5_t        v5[1];
  static uchar                     data[ FD_VOTE_STATE_V4_SZ ];

  for( ulong iter=0UL; iter<2000UL; iter++ ) {
    random_v4( v4, rng );
    convert_copy( v4, scratch, data );
    *v5 = scratch->v5;

    ulong epoch = fd_rng_ulong_roll( rng, 80UL );
    for( ulong step=0UL; step<32UL; step++ ) {
      epoch += fd_rng_ulong_roll( rng, 2UL );
      vote_update_t upd = {
        .update_votes    = (int)( fd_rng_uint( rng )&1U ),
        .vote_slot       = fd_rng_ulong_roll( rng, 2000UL ),
        .vote_ts_ns      = (long)fd_rng_ulong_roll( rng, 2000UL )*1000000000L,
        .update_root     = (int)( fd_rng_uint( rng )&1U ),
        .root_slot       = fd_rng_ulong_roll( rng, 2000UL ),
        .credits         = fd_rng_ulong_roll( rng, 3UL )*fd_rng_ulong_roll( rng, 1000UL ),
        .migration_epoch = ( fd_rng_uint( rng )&1U ) ? epoch : ULONG_MAX,
        .current_epoch   = epoch,
      };
      vote_update_apply( v4,   NULL, &upd );
      vote_update_apply( NULL, v5,   &upd );
      convert_copy( v4, scratch, data );
      FD_TEST( fd_memeq( &scratch->v5, v5, sizeof(fd_vote_state_v5_t) ) );
    }
  }
}

static void
put_vote_account( fd_svm_mini_t *     mini,
                  fd_pubkey_t const * pubkey,
                  uchar *             data ) {
  fd_acc_t acc = { .lamports = 1000000000UL, .data = data, .data_len = FD_VOTE_STATE_V5_SZ };
  memcpy( acc.pubkey, pubkey->uc,                   32UL );
  memcpy( acc.owner,  fd_solana_vote_program_id.uc, 32UL );
  fd_svm_mini_put_account_rooted( mini, &acc );
}

static void
test_v5_in_place( fd_svm_mini_t * mini,
                  fd_rng_t *      rng ) {
  static fd_vote_state_versioned_t v4[1], scratch[1];
  static uchar                     tmp   [ FD_VOTE_STATE_V4_SZ ];
  static uchar                     data4 [ FD_VOTE_STATE_V4_SZ ];
  static uchar                     data5 [ FD_VOTE_STATE_V5_SZ ];
  static uchar                     bad5  [ FD_VOTE_STATE_V5_SZ ];
  static uchar                     expect[ FD_VOTE_STATE_V5_SZ ];
  static uchar                     q_mem [ FD_VOTE_QUEUE_FOOTPRINT ] __attribute__((aligned(FD_VOTE_QUEUE_ALIGN)));

  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  ulong root_idx = fd_svm_mini_reset( mini, params );

  random_v4( v4, rng );
  FD_TEST( !fd_vote_state_versioned_serialize( v4, data4, sizeof(data4) ) );
  convert_copy( v4, scratch, tmp );
  FD_TEST( !fd_vote_state_versioned_serialize( scratch, data5, sizeof(data5) ) );
  fd_memcpy( bad5, data5, sizeof(bad5) );
  bad5[ FD_VOTE_STATE_V5_SZ-1UL ] = 1;

  fd_pubkey_t key4   = { .ul = { 4UL } };
  fd_pubkey_t key5   = { .ul = { 5UL } };
  fd_pubkey_t keybad = { .ul = { 6UL } };
  put_vote_account( mini, &key4,   data4 );
  put_vote_account( mini, &key5,   data5 );
  put_vote_account( mini, &keybad, bad5  );

  fd_bank_t *  bank  = fd_svm_mini_bank( mini, fd_svm_mini_attach_child( mini, root_idx, params->root_slot+1UL ) );
  fd_accdb_t * accdb = mini->runtime->accdb;

  vote_update_t upd = {
    .update_votes    = 1, .vote_slot = 5000UL, .vote_ts_ns = 1800000000L*1000000000L,
    .update_root     = 1, .root_slot = 4000UL,
    .credits         = 500UL,
    .migration_epoch = ULONG_MAX,
    .current_epoch   = 90UL,
  };
  fd_vote_queue_t * q = fd_vote_queue_init( q_mem );
  vote_account_modify( bank, accdb, NULL, &key4,   &upd, NULL, q );
  vote_account_modify( bank, accdb, NULL, &key5,   &upd, NULL, q );
  vote_account_modify( bank, accdb, NULL, &keybad, &upd, NULL, q );
  fd_vote_queue_fini( q );

  fd_acc_t acc = fd_accdb_read_one( accdb, bank->accdb_fork_id, key4.uc );
  FD_TEST( fd_vote_state_versioned_deserialize( scratch, acc.data, acc.data_len ) );
  fd_accdb_unread_one( accdb, &acc );
  FD_TEST( !fd_vsv_try_convert_to_v5( scratch, &LOC_FRA, 0UL ) );
  FD_TEST( !fd_vote_state_versioned_serialize( scratch, expect, sizeof(expect) ) );
  FD_TEST( !fd_memeq( expect, data5, sizeof(expect) ) );

  acc = fd_accdb_read_one( accdb, bank->accdb_fork_id, key5.uc );
  FD_TEST( acc.data_len==FD_VOTE_STATE_V5_SZ && fd_memeq( acc.data, expect, sizeof(expect) ) );
  fd_accdb_unread_one( accdb, &acc );

  acc = fd_accdb_read_one( accdb, bank->accdb_fork_id, keybad.uc );
  FD_TEST( acc.data_len==FD_VOTE_STATE_V5_SZ && fd_memeq( acc.data, bad5, sizeof(bad5) ) );
  fd_accdb_unread_one( accdb, &acc );
}

int
main( int     argc,
      char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );
  FD_TEST( mini );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 1234U, 0UL ) );

  test_v5_update_matches_v4( rng );
  for( ulong iter=0UL; iter<16UL; iter++ ) test_v5_in_place( mini, rng );

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
