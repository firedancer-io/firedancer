#include "fd_alpenglow.c"
#include "../runtime/tests/fd_svm_mini.h"

static fd_validator_location_t const LOC_FRA = { 4051542, 618526, 4870645 };

static int
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
  return marker<ec_cnt;
}

static void
convert_copy( fd_vote_state_versioned_t const * src,
              fd_vote_state_versioned_t *       dst,
              uchar *                           data ) {
  FD_TEST( !fd_vote_state_versioned_serialize( src, data, FD_VOTE_STATE_V4_SZ ) );
  FD_TEST( fd_vote_state_versioned_deserialize( dst, data, FD_VOTE_STATE_V4_SZ ) );
  FD_TEST( !fd_vsv_try_convert_to_v5( dst, 0UL ) );
  dst->v5.location = LOC_FRA;
}

static void
test_v5_update_matches_v4( fd_rng_t * rng ) {
  static fd_vote_state_versioned_t v4[1], scratch[1];
  static fd_vote_state_v5_t        v5[1];
  static uchar                     data[ FD_VOTE_STATE_V4_SZ ];

  for( ulong iter=0UL; iter<2000UL; iter++ ) {
    int has_marker = random_v4( v4, rng );
    convert_copy( v4, scratch, data );
    *v5 = scratch->v5;

    ulong epoch           = fd_rng_ulong_roll( rng, 80UL );
    ulong migration_epoch = ( has_marker || ( fd_rng_uint( rng )&1U ) ) ? ULONG_MAX : epoch+fd_rng_ulong_roll( rng, 16UL );
    for( ulong step=0UL; step<32UL; step++ ) {
      epoch += fd_rng_ulong_roll( rng, 2UL );
      vote_update_t upd = {
        .update_votes    = (int)( fd_rng_uint( rng )&1U ),
        .vote_slot       = fd_rng_ulong_roll( rng, 2000UL ),
        .vote_ts_ns      = (long)fd_rng_ulong_roll( rng, 2000UL )*1000000000L,
        .update_root     = (int)( fd_rng_uint( rng )&1U ),
        .root_slot       = fd_rng_ulong_roll( rng, 2000UL ),
        .credits         = fd_rng_ulong_roll( rng, 3UL )*fd_rng_ulong_roll( rng, 1000UL ),
        .migration_epoch = migration_epoch,
        .current_epoch   = epoch,
      };
      fd_acc_t acc4 = { .data = data, .data_len = FD_VOTE_STATE_V4_SZ };
      vote_update_apply( v4, &acc4, &upd );
      vote_update_apply_v5( v5, &upd );
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
modify_vote_account( fd_bank_t *           bank,
                     fd_accdb_t *          accdb,
                     fd_pubkey_t const *   pk,
                     vote_update_t const * upd,
                     fd_vote_queue_t *     q ) {
  static fd_vote_state_versioned_t vs[1];
  fd_acc_t acc;
  if( !vote_account_open( bank, accdb, pk, vs, &acc ) ) return;
  vote_update_apply( vs, &acc, upd );
  vote_account_store( bank, accdb, &acc, vs, NULL, q );
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
  modify_vote_account( bank, accdb, &key4,   &upd, q );
  modify_vote_account( bank, accdb, &key5,   &upd, q );
  modify_vote_account( bank, accdb, &keybad, &upd, q );
  fd_vote_queue_fini( q );

  fd_acc_t acc = fd_accdb_read_one( accdb, bank->accdb_fork_id, key4.uc );
  FD_TEST( fd_vote_state_versioned_deserialize( scratch, acc.data, acc.data_len ) );
  fd_accdb_unread_one( accdb, &acc );
  FD_TEST( !fd_vsv_try_convert_to_v5( scratch, 0UL ) );
  scratch->v5.location = LOC_FRA;
  FD_TEST( !fd_vote_state_versioned_serialize( scratch, expect, sizeof(expect) ) );
  FD_TEST( !fd_memeq( expect, data5, sizeof(expect) ) );

  acc = fd_accdb_read_one( accdb, bank->accdb_fork_id, key5.uc );
  FD_TEST( acc.data_len==FD_VOTE_STATE_V5_SZ && fd_memeq( acc.data, expect, sizeof(expect) ) );
  fd_accdb_unread_one( accdb, &acc );

  acc = fd_accdb_read_one( accdb, bank->accdb_fork_id, keybad.uc );
  FD_TEST( acc.data_len==FD_VOTE_STATE_V5_SZ && fd_memeq( acc.data, bad5, sizeof(bad5) ) );
  fd_accdb_unread_one( accdb, &acc );
}

/* test_rewards_slices applies one plan to the same accounts in one
   slice on one fork and in several slices on another, and expects the
   same lthash change, leader credits and account images.  The leader
   is a signer of both certs, so its own share and its signer updates
   go through the leader path. */

#define SLICE_TEST_VAL_CNT (9UL)

static void
test_rewards_slices( fd_svm_mini_t * mini,
                     fd_rng_t *      rng ) {
  static fd_vote_state_versioned_t v4[1], v5[1];
  static uchar                     tmp [ FD_VOTE_STATE_V4_SZ ];
  static uchar                     data[ SLICE_TEST_VAL_CNT ][ FD_VOTE_STATE_V5_SZ ];

  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  ulong root_idx = fd_svm_mini_reset( mini, params );

  /* ranked validators with V4 and V5 images, in the rooted state */
  fd_pubkey_t vote[ SLICE_TEST_VAL_CNT ];
  for( ulong i=0UL; i<SLICE_TEST_VAL_CNT; i++ ) {
    vote[ i ] = (fd_pubkey_t){ .ul = { 0x5000UL+i, 7UL } };
    memset( data[ i ], 0, FD_VOTE_STATE_V5_SZ );
    random_v4( v4, rng );
    if( i&1UL ) { convert_copy( v4, v5, tmp ); FD_TEST( !fd_vote_state_versioned_serialize( v5, data[ i ], FD_VOTE_STATE_V5_SZ ) ); }
    else        {                              FD_TEST( !fd_vote_state_versioned_serialize( v4, data[ i ], FD_VOTE_STATE_V4_SZ ) ); }
    put_vote_account( mini, vote+i, data[ i ] );
  }

  fd_bank_t *        bank_a      = fd_svm_mini_bank( mini, fd_svm_mini_attach_child( mini, root_idx, params->root_slot+1UL ) );
  fd_accdb_t *       accdb       = mini->runtime->accdb;
  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank_a );
  ushort             fork_id     = bank_a->vote_stakes_fork_id;
  ulong              total_stake = 0UL;
  for( ulong i=0UL; i<SLICE_TEST_VAL_CNT; i++ ) {
    fd_pubkey_t node = { .ul = { 0x6000UL+i } };
    uchar ikm[ 32 ] = { 0 };
    FD_STORE( ulong, ikm, 0x700UL+i );
    fd_bls_sec_t sk; fd_bls_sec_derive( &sk, ikm, sizeof(ikm) );
    fd_bls_pub_t pub[1]; fd_bls_sec_to_pub( &sk, pub );
    uchar bls[ FD_BLS_PUBKEY_COMPRESSED_SZ ]; fd_bls_pub_compress( pub, bls );
    fd_vote_stakes_snap_insert_t_2( vote_stakes, fork_id, vote+i, &node, 100UL*(i+1UL), 0U, bls, FD_VOTE_DEFAULT_BLOCK_REVENUE_COMMISSION_BPS, 0UL, NULL, NULL, &LOC_FRA );
    total_stake += 100UL*(i+1UL);
  }
  fd_vote_stakes_finalize( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_2 );

  /* every validator signs both certs but 2 (reward) and 5 (final), and
     7 signs neither.  3 leads */
  fd_alpenglow_rewards_plan_t plan[1];
  memset( plan, 0, sizeof(fd_alpenglow_rewards_plan_t) );
  plan->has_reward  = 1;
  plan->has_final   = 1;
  plan->reward_kind = plan->final_kind = plan->memo_kind = FD_VOTE_STAKES_ITER_T_2;
  fd_bls_set_null( plan->reward_set );
  fd_bls_set_null( plan->final_set );
  for( ulong i=0UL; i<SLICE_TEST_VAL_CNT; i++ ) {
    fd_vote_stakes_ele_t ele[1];
    FD_TEST( fd_vote_stakes_query_t_2( vote_stakes, fork_id, vote+i, ele ) && ele->rank!=FD_VOTE_STAKES_ALPENGLOW_RANK_NULL );
    if( i!=2UL && i!=7UL ) fd_bls_set_insert( plan->reward_set, ele->rank );
    if( i!=5UL && i!=7UL ) fd_bls_set_insert( plan->final_set,  ele->rank );
  }
  plan->reward_slot        = 1000UL;
  plan->max_reward         = 1000000000UL;
  plan->slots_per_epoch    = 432000UL;
  plan->total_stake        = total_stake;
  plan->reward_ts_ns       = 1700000000L*1000000000L;
  plan->migration_epoch    = ULONG_MAX;
  plan->current_epoch      = fd_slot_to_epoch( &bank_a->f.epoch_schedule, bank_a->f.slot, NULL );
  plan->final_slot         = 1007UL;
  plan->final_ts_ns        = plan->reward_ts_ns+400000000L;
  plan->leader_vote_pubkey = vote[ 3 ];
  plan->slice_seed         = fd_rng_ulong( rng );

  /* one slice on the first fork */
  fd_lthash_value_t delta_a[1];
  fd_lthash_zero( delta_a );
  ulong credits_a = 0UL;
  FD_TEST( !fd_alpenglow_rewards_apply_slice( bank_a, accdb, NULL, plan, 0UL, 1UL, delta_a, &credits_a ) );
  FD_TEST( credits_a );
  fd_alpenglow_rewards_apply_leader( bank_a, accdb, NULL, plan, credits_a, delta_a );
  for( ulong i=0UL; i<SLICE_TEST_VAL_CNT; i++ ) {
    fd_acc_t acc = fd_accdb_read_one( accdb, bank_a->accdb_fork_id, vote[ i ].uc );
    FD_TEST( acc.data_len==FD_VOTE_STATE_V5_SZ && fd_memeq( acc.data, data[ i ], FD_VOTE_STATE_V5_SZ )==( i==7UL ) );
    fd_accdb_unread_one( accdb, &acc );
  }

  /* 2 to 5 slices on sibling forks.  The two-slice run has a footer
     cache with memo use off and must leave it empty.  The three-slice
     run has memo use on and must fill a slot per signer stored. */
  static fd_footer_cache_t cache_mem[ 1 ];
  fd_footer_cache_t * cache = fd_footer_cache_join( fd_footer_cache_new( cache_mem ) );
  for( ulong slice_cnt=2UL; slice_cnt<=5UL; slice_cnt++ ) {
    fd_bank_t * bank_b = fd_svm_mini_bank( mini, fd_svm_mini_attach_child( mini, root_idx, params->root_slot+slice_cnt ) );
    fd_footer_cache_t * run_cache = slice_cnt<=3UL ? cache : NULL;
    plan->use_memo = slice_cnt!=2UL;
    fd_lthash_value_t delta_b[1];
    fd_lthash_zero( delta_b );
    ulong credits_b = 0UL;
    for( ulong i=0UL; i<slice_cnt; i++ ) FD_TEST( !fd_alpenglow_rewards_apply_slice( bank_b, accdb, run_cache, plan, i, slice_cnt, delta_b, &credits_b ) );
    FD_TEST( credits_b==credits_a );
    fd_alpenglow_rewards_apply_leader( bank_b, accdb, run_cache, plan, credits_b, delta_b );
    ulong memo_cnt = 0UL;
    for( ulong r=0UL; r<AG_VAT_MAX; r++ ) memo_cnt += !!cache->memo[ r ].lamports;
    FD_TEST( memo_cnt==( slice_cnt==2UL ? 0UL : SLICE_TEST_VAL_CNT-1UL ) );
    FD_TEST( fd_lthash_eq( delta_a, delta_b ) );
    for( ulong i=0UL; i<SLICE_TEST_VAL_CNT; i++ ) {
      static uchar image_a[ FD_VOTE_STATE_V5_SZ ];
      fd_acc_t acc = fd_accdb_read_one( accdb, bank_a->accdb_fork_id, vote[ i ].uc );
      ulong lamports_a = acc.lamports;
      FD_TEST( acc.data_len==FD_VOTE_STATE_V5_SZ );
      fd_memcpy( image_a, acc.data, FD_VOTE_STATE_V5_SZ );
      fd_accdb_unread_one( accdb, &acc );
      acc = fd_accdb_read_one( accdb, bank_b->accdb_fork_id, vote[ i ].uc );
      FD_TEST( acc.lamports==lamports_a && acc.data_len==FD_VOTE_STATE_V5_SZ && fd_memeq( acc.data, image_a, FD_VOTE_STATE_V5_SZ ) );
      fd_accdb_unread_one( accdb, &acc );
    }
  }
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
  for( ulong iter=0UL; iter<4UL;  iter++ ) test_rewards_slices( mini, rng );

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
