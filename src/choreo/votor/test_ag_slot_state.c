#include "ag_slot_state.c"
#include "test_ag_cert_builder.h"

#define TEST_SHRED_VERSION   ((ushort)514)
#define TEST_HASH_STAKE_SEED (42UL)

#include <stdlib.h>

#define VAT_MAX 64UL /* smaller for tests */

static ag_slot_state_t  slot_state_mem;
static ag_slot_states_t g_states;

static fd_bls_sig_ele_t * g_bls_sig_pool;

static fd_bls_sec_t        g_sk  [ VAT_MAX ];
static ag_validator_info_t g_info[ VAT_MAX ];

static void
generate_validators( ulong n ) {
  FD_TEST( n<=VAT_MAX );
  for( ulong i=0UL; i<n; i++ ) {
    fd_memset( &g_sk[i], (int)(i*7UL+1UL), FD_BLS_SEC_SZ );
    memset( &g_info[i], 0, sizeof(ag_validator_info_t) );
    g_info[i].id    = i;
    g_info[i].stake = 1UL;
    bls_key_from_sec( g_info[i].bls_key, &g_sk[i] );
  }
}

static ag_epoch_info_t *
make_epoch( ulong   n,
            void ** out_mem ) {
  ag_epoch_info_t * epoch_info = aligned_alloc( alignof(ag_epoch_info_t), sizeof(ag_epoch_info_t) );
  FD_TEST( epoch_info );
  *out_mem = epoch_info;
  epoch_info_build( epoch_info, g_info, n );
  return epoch_info;
}

static void
random_hash( ag_block_hash_t out ) {
  static ulong ctr = 1UL;
  memset( out, 0, sizeof(ag_block_hash_t) );
  ctr += 0x9E3779B97F4A7C15UL;
  memcpy( out, &ctr, sizeof(ulong) );
  out[ 31 ] = 0xAB;
}

static ulong
hash_stake_cnt( ag_vote_stake_map_t const * map,
                ag_vote_stake_ele_t const * pool ) {
  ulong cnt = 0UL;
  for( ag_vote_stake_map_iter_t iter = ag_vote_stake_map_iter_init( map, pool );
       !ag_vote_stake_map_iter_done( iter, map, pool );
       iter = ag_vote_stake_map_iter_next( iter, map, pool ) ) cnt++;
  return cnt;
}

static ulong
hash_stake_idx( ag_vote_stake_map_t const * map,
                ag_vote_stake_ele_t const * pool,
                ulong                       slot,
                uchar const *               hash ) {
  ag_block_id_t key = ag_block_id( slot, hash );
  return ag_vote_stake_map_idx_query_const( map, &key, ULONG_MAX, pool );
}

static ulong
hash_stake_insert( ag_vote_stake_map_t * map,
                   ag_vote_stake_ele_t * pool,
                   ulong *               head,
                   ulong *               cnt,
                   ag_block_id_t         key ) {
  FD_TEST( ag_vote_stake_pool_free( pool ) );
  ulong id = ag_vote_stake_pool_idx_acquire( pool );
  ag_vote_stake_pool_ele( pool, id )->block_id = key;
  ag_vote_stake_pool_ele( pool, id )->stake    = 0UL;
  ag_vote_stake_pool_ele( pool, id )->prev     = *cnt ? *head : ag_vote_stake_pool_idx_null( pool );
  ag_vote_stake_map_idx_insert( map, id, pool );
  *head = id;
  (*cnt)++;
  return id;
}

static void
hash_stake_remove( ag_vote_stake_map_t * map,
                   ag_vote_stake_ele_t * pool,
                   ulong *               head,
                   ulong *               cnt,
                   ulong                 id ) {
  ulong * link = head;
  ulong   j;
  for( j=0UL; j<*cnt; j++ ) {
    if( FD_UNLIKELY( *link==id ) ) break;
    link = &ag_vote_stake_pool_ele( pool, *link )->prev;
  }
  FD_TEST( j<*cnt );
  *link = ag_vote_stake_pool_ele( pool, id )->prev;
  (*cnt)--;
  ag_block_id_t key     = ag_vote_stake_pool_ele( pool, id )->block_id;
  ulong         removed = ag_vote_stake_map_idx_remove( map, &key, ULONG_MAX, pool );
  FD_TEST( removed==id );
  ag_vote_stake_pool_idx_release( pool, id );
}

static ulong
notar_hash_stake_query( ag_slot_state_t const * ss,
                        uchar const *           hash ) {
  ulong id = hash_stake_idx( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool, ss->slot, hash );
  return id==ULONG_MAX ? ULONG_MAX : ag_vote_stake_pool_ele_const( g_states.notar_hash_stake_pool, id )->stake;
}

static ulong
notar_fallback_hash_stake_query( ag_slot_state_t const * ss,
                                 uchar const *           hash ) {
  ulong id = hash_stake_idx( g_states.notar_fallback_hash_stake_map, g_states.notar_fallback_hash_stake_pool, ss->slot, hash );
  return id==ULONG_MAX ? ULONG_MAX : ag_vote_stake_pool_ele_const( g_states.notar_fallback_hash_stake_pool, id )->stake;
}

static void
assert_maps_empty( ag_slot_state_t const * ss ) {
  FD_TEST( !ss->votes.notar_hash_stake_cnt          && !hash_stake_cnt( g_states.notar_hash_stake_map,          g_states.notar_hash_stake_pool          ) && ag_vote_stake_pool_free( g_states.notar_hash_stake_pool          )==AG_VAT_MAX                 );
  FD_TEST( !ss->votes.notar_fallback_hash_stake_cnt && !hash_stake_cnt( g_states.notar_fallback_hash_stake_map, g_states.notar_fallback_hash_stake_pool ) && ag_vote_stake_pool_free( g_states.notar_fallback_hash_stake_pool )==AG_NOTAR_FALLBACK_HASH_MAX );
}

static ag_slot_state_t *
make_state( ulong                   slot,
            ag_epoch_info_t const * epoch_info ) {
  ag_slot_state_t * slot_state = &slot_state_mem;
  ag_slot_state_null( slot_state, &g_states );
  assert_maps_empty( slot_state );
  g_states.notar_hash_stake_pool          = ag_vote_stake_pool_join( ag_vote_stake_pool_new( ag_vote_stake_pool_leave( g_states.notar_hash_stake_pool          ), AG_VAT_MAX                 ) );
  g_states.notar_hash_stake_map           = ag_vote_stake_map_join ( ag_vote_stake_map_new ( ag_vote_stake_map_leave ( g_states.notar_hash_stake_map           ), ag_vote_stake_map_chain_cnt_est( AG_VAT_MAX                 ), TEST_HASH_STAKE_SEED ) );
  g_states.notar_fallback_hash_stake_pool = ag_vote_stake_pool_join( ag_vote_stake_pool_new( ag_vote_stake_pool_leave( g_states.notar_fallback_hash_stake_pool ), AG_NOTAR_FALLBACK_HASH_MAX ) );
  g_states.notar_fallback_hash_stake_map  = ag_vote_stake_map_join ( ag_vote_stake_map_new ( ag_vote_stake_map_leave ( g_states.notar_fallback_hash_stake_map  ), ag_vote_stake_map_chain_cnt_est( AG_NOTAR_FALLBACK_HASH_MAX ), TEST_HASH_STAKE_SEED ) );
  g_states.curr_epoch_info                = epoch_info;

  slot_state->slot     = slot;
  slot_state->own_rank = 0UL;
  return slot_state;
}

static fd_bls_agg_t *
notar_agg( ag_slot_state_t const * state,
           ag_block_hash_t const   hash,
           fd_bls_agg_t *          agg ) {
  fd_bls_set_t set[ fd_bls_set_word_cnt ];
  fd_bls_set_null( set );
  for( ulong rank=0UL; rank<AG_VAT_MAX; rank++ ) {
    if( FD_LIKELY( fd_bls_set_test( state->votes.notar_set, rank ) && !memcmp( ag_vote_stake_pool_ele_const( g_states.notar_hash_stake_pool, state->votes.notar_hash_stake_idx[ rank ] )->block_id.hash, hash, sizeof(ag_block_hash_t) ) ) ) fd_bls_set_insert( set, rank );
  }
  fd_bls_sig_t sigs[ AG_VAT_MAX ];
  ag_slot_state_sigs( state, &g_states, AG_VOTE_KIND_NOTAR, hash, set, sigs );
  fd_bls_agg_null( agg );
  return fd_bls_agg_construct( agg, g_states.curr_epoch_info->pubkeys, sigs, set );
}

typedef struct {
  struct {
    ag_cert_t     certs          [ AG_SLOT_STATE_OUT_CERT_MAX   ]; ulong certs_cnt;
    ag_block_id_t safe_to_notar  [ AG_SLOT_STATE_OUT_EVENT_MAX  ]; ulong safe_to_notar_cnt;
    ulong         safe_to_skip   [ AG_SLOT_STATE_OUT_EVENT_MAX  ]; ulong safe_to_skip_cnt;
    ag_block_id_t block_to_repair[ AG_SLOT_STATE_OUT_REPAIR_MAX ]; ulong block_to_repair_cnt;
    fd_bls_set_t  bad            [ fd_bls_set_word_cnt          ];
  } o;
  int ok;
} out_t;

static void
add_vote_helper( ag_slot_state_t *       ss,
                 ag_vote_t const *       vote,
                 ag_epoch_info_t const * epoch_info,
                 out_t *                 t ) {
  ulong stake = ag_epoch_info_validator( epoch_info, ag_vote_rank( vote ) )->stake;
  t->ok = ag_slot_state_add_vote( ss, &g_states, vote, stake, t->o.certs, &t->o.certs_cnt, t->o.safe_to_notar, &t->o.safe_to_notar_cnt, t->o.safe_to_skip, &t->o.safe_to_skip_cnt, t->o.block_to_repair, &t->o.block_to_repair_cnt, t->o.bad );
}

/* src/consensus/pool/slot_state.rs::add_cert */

static void
test_add_cert( void ) {
  ulong n = 11UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  ag_block_hash_t hash; random_hash( hash );
  ag_slot_state_t * ss = make_state( slot, epoch_info );

  ag_vote_notar_t nv[ 11 ];
  for( ulong i=0UL; i<n; i++ ) nv[i] = ag_vote_construct_notar( sec_sign_fn, &g_sk[i], test_bls_public_key, slot, hash, (ushort)i, TEST_SHRED_VERSION ).notar;
  ag_cert_t c = cert_build_notar( nv, n, epoch_info );

  FD_TEST( ss->certs.notar.slot==ULONG_MAX );
  ag_slot_state_add_cert( ss, &c );
  FD_TEST( ss->certs.notar.slot==slot );

  free( em );
}

/* src/consensus/pool/slot_state.rs::add_vote */

static void
test_add_vote( void ) {
  ulong n = 11UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  ag_block_hash_t hash; random_hash( hash );
  ag_slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;

  for( ulong i=0UL; i<n; i++ ) {
    ag_vote_t vote = ag_vote_construct_notar( sec_sign_fn, &g_sk[i], test_bls_public_key, slot, hash, (ushort)i, TEST_SHRED_VERSION );
    FD_TEST( !fd_bls_set_test( ss->votes.notar_set, i ) );
    add_vote_helper( ss, &vote, epoch_info, &t );
    FD_TEST( fd_bls_set_test( ss->votes.notar_set, i ) && !memcmp( ag_vote_stake_pool_ele_const( g_states.notar_hash_stake_pool, ss->votes.notar_hash_stake_idx[ i ] )->block_id.hash, hash, sizeof(ag_block_hash_t) ) );
    FD_TEST( notar_hash_stake_query( ss, hash )==i+1UL );
  }

  free( em );
}

/* src/consensus/pool/slot_state.rs::safe_to_notar */

static void
test_safe_to_notar( void ) {
  ulong n = 3UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  ag_block_hash_t hash; random_hash( hash );
  ag_slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;

  ag_slot_state_notify_parent_known( ss, hash );
  ag_slot_state_notify_parent_certified( ss, &g_states, hash, t.o.bad );

  ag_vote_t notar_vote = ag_vote_construct_notar( sec_sign_fn, &g_sk[1], test_bls_public_key, slot, hash, 1UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &notar_vote, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==0UL );
  FD_TEST( t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL );
  FD_TEST( t.o.block_to_repair_cnt==0UL );

  ag_vote_t skip_vote = ag_vote_construct_skip( sec_sign_fn, &g_sk[0], test_bls_public_key, slot, 0UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &skip_vote, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==0UL );
  FD_TEST( t.o.safe_to_notar_cnt==1UL && t.o.safe_to_skip_cnt==0UL );
  FD_TEST( t.o.block_to_repair_cnt==0UL );
  FD_TEST( t.o.safe_to_notar[0].slot==slot );
  FD_TEST( !memcmp( t.o.safe_to_notar[0].hash, hash, sizeof(ag_block_hash_t) ) );

  free( em );
}

/* src/consensus/pool/slot_state.rs::slashable_skip_and_notarize */

static void
test_slashable_skip_and_notarize( void ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  ag_block_hash_t hash; random_hash( hash );
  ag_slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;

  ag_vote_t s1 = ag_vote_construct_skip( sec_sign_fn, &g_sk[1], test_bls_public_key, slot, 1UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &s1, epoch_info, &t );
  ag_vote_t notar_vote = ag_vote_construct_notar( sec_sign_fn, &g_sk[1], test_bls_public_key, slot, hash, 1UL, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &g_states, &notar_vote )==AG_SLASHABLE_SKIP_AND_NOTARIZE );

  ag_vote_t n2 = ag_vote_construct_notar( sec_sign_fn, &g_sk[2], test_bls_public_key, slot, hash, 2UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &n2, epoch_info, &t );
  ag_vote_t skip_vote = ag_vote_construct_skip( sec_sign_fn, &g_sk[2], test_bls_public_key, slot, 2UL, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &g_states, &skip_vote )==AG_SLASHABLE_SKIP_AND_NOTARIZE );

  free( em );
}

/* src/consensus/pool/slot_state.rs::slashable_notar_different_hash */

static void
test_slashable_notar_different_hash( void ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  ag_block_hash_t hash_a; random_hash( hash_a );
  ag_block_hash_t hash_b; random_hash( hash_b );
  ag_slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;

  ag_vote_t notar_a = ag_vote_construct_notar( sec_sign_fn, &g_sk[1], test_bls_public_key, slot, hash_a, 1UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &notar_a, epoch_info, &t );

  ag_vote_t notar_b = ag_vote_construct_notar( sec_sign_fn, &g_sk[1], test_bls_public_key, slot, hash_b, 1UL, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &g_states, &notar_b )==AG_SLASHABLE_NOTAR_DIFFERENT_HASH );

  FD_TEST( ag_slot_state_check_slashable_offence( ss, &g_states, &notar_a )==AG_SLASHABLE_NONE );

  free( em );
}

/* src/consensus/pool/slot_state.rs::slashable_skip_and_finalize */

static void
test_slashable_skip_and_finalize( void ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  ag_slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;

  ag_vote_t f1 = ag_vote_construct_final( sec_sign_fn, &g_sk[1], test_bls_public_key, slot, 1UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &f1, epoch_info, &t );
  ag_vote_t s1 = ag_vote_construct_skip( sec_sign_fn, &g_sk[1], test_bls_public_key, slot, 1UL, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &g_states, &s1 )==AG_SLASHABLE_SKIP_AND_FINALIZE );
  ag_vote_t sf1 = ag_vote_construct_skip_fallback( sec_sign_fn, &g_sk[1], test_bls_public_key, slot, 1UL, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &g_states, &sf1 )==AG_SLASHABLE_SKIP_AND_FINALIZE );

  ag_vote_t s2 = ag_vote_construct_skip( sec_sign_fn, &g_sk[2], test_bls_public_key, slot, 2UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &s2, epoch_info, &t );
  ag_vote_t f2 = ag_vote_construct_final( sec_sign_fn, &g_sk[2], test_bls_public_key, slot, 2UL, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &g_states, &f2 )==AG_SLASHABLE_SKIP_AND_FINALIZE );

  ag_vote_t sf3 = ag_vote_construct_skip_fallback( sec_sign_fn, &g_sk[3], test_bls_public_key, slot, 3UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &sf3, epoch_info, &t );
  ag_vote_t f3 = ag_vote_construct_final( sec_sign_fn, &g_sk[3], test_bls_public_key, slot, 3UL, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &g_states, &f3 )==AG_SLASHABLE_SKIP_AND_FINALIZE );

  free( em );
}

/* src/consensus/pool/slot_state.rs::slashable_notar_fallback_and_finalize */

static void
test_slashable_notar_fallback_and_finalize( void ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  ag_block_hash_t hash; random_hash( hash );
  ag_slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;

  ag_vote_t f1 = ag_vote_construct_final( sec_sign_fn, &g_sk[1], test_bls_public_key, slot, 1UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &f1, epoch_info, &t );
  ag_vote_t nf1 = ag_vote_construct_notar_fallback( sec_sign_fn, &g_sk[1], test_bls_public_key, slot, hash, 1UL, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &g_states, &nf1 )==AG_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE );

  ag_vote_t nf2 = ag_vote_construct_notar_fallback( sec_sign_fn, &g_sk[2], test_bls_public_key, slot, hash, 2UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &nf2, epoch_info, &t );
  ag_vote_t f2 = ag_vote_construct_final( sec_sign_fn, &g_sk[2], test_bls_public_key, slot, 2UL, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &g_states, &f2 )==AG_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE );

  free( em );
}

/* src/consensus/pool/slot_state.rs::slashable_offence_none */

static void
test_slashable_offence_none( void ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  ag_block_hash_t hash; random_hash( hash );
  ag_slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;
  ulong v = 1UL;

  ag_vote_t notar_vote = ag_vote_construct_notar( sec_sign_fn, &g_sk[1], test_bls_public_key, slot, hash, (ushort)v, TEST_SHRED_VERSION );
  ag_vote_t skip_vote = ag_vote_construct_skip( sec_sign_fn, &g_sk[1], test_bls_public_key, slot, (ushort)v, TEST_SHRED_VERSION );
  ag_vote_t final_vote = ag_vote_construct_final( sec_sign_fn, &g_sk[1], test_bls_public_key, slot, (ushort)v, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &g_states, &notar_vote )==AG_SLASHABLE_NONE );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &g_states, &skip_vote )==AG_SLASHABLE_NONE );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &g_states, &final_vote )==AG_SLASHABLE_NONE );

  add_vote_helper( ss, &notar_vote, epoch_info, &t );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &g_states, &final_vote )==AG_SLASHABLE_NONE );

  free( em );
}

/* src/consensus/pool/slot_state.rs::should_ignore_duplicate_votes */

static void
test_should_ignore_duplicate_votes( void ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  ag_block_hash_t hash;       random_hash( hash       );
  ag_block_hash_t other_hash; random_hash( other_hash );
  ag_slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;

  ag_vote_t v1n = ag_vote_construct_notar( sec_sign_fn, &g_sk[1], test_bls_public_key, slot, hash, 1UL, TEST_SHRED_VERSION );
  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &g_states, &v1n ) );

  add_vote_helper( ss, &v1n, epoch_info, &t );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &g_states, &v1n ) );
  ag_vote_t v1n_other = ag_vote_construct_notar( sec_sign_fn, &g_sk[1], test_bls_public_key, slot, other_hash, 1UL, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &g_states, &v1n_other ) );

  ag_vote_t v2s = ag_vote_construct_skip( sec_sign_fn, &g_sk[2], test_bls_public_key, slot, 2UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &v2s, epoch_info, &t );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &g_states, &v2s ) );
  ag_vote_t v2sf = ag_vote_construct_skip_fallback( sec_sign_fn, &g_sk[2], test_bls_public_key, slot, 2UL, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &g_states, &v2sf ) );

  ag_vote_t v3f = ag_vote_construct_final( sec_sign_fn, &g_sk[3], test_bls_public_key, slot, 3UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &v3f, epoch_info, &t );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &g_states, &v3f ) );

  ag_vote_t v4nf = ag_vote_construct_notar_fallback( sec_sign_fn, &g_sk[4], test_bls_public_key, slot, hash, 4UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &v4nf, epoch_info, &t );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &g_states, &v4nf ) );
  ag_vote_t v4nf_other = ag_vote_construct_notar_fallback( sec_sign_fn, &g_sk[4], test_bls_public_key, slot, other_hash, 4UL, TEST_SHRED_VERSION );
  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &g_states, &v4nf_other ) );

  free( em );
}

/* ag_slot_state_null leaves the per-rank signature indices alone, so a
   recycled slot state must not read stale signatures as votes. */

static void
test_null_ignores_stale_sigs( void ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  ag_block_hash_t hash; random_hash( hash );
  out_t t;

  ag_slot_state_null( &slot_state_mem, &g_states );
  fd_memset( &slot_state_mem.votes, 0x5a, sizeof(slot_state_mem.votes) );
  fd_memset( slot_state_mem.votes.notar_fallback_sig_cnt, 0, sizeof(slot_state_mem.votes.notar_fallback_sig_cnt) );
  slot_state_mem.votes.notar_hash_stake_cnt          = 0UL;
  slot_state_mem.votes.notar_fallback_hash_stake_cnt = 0UL;
  fd_bls_set_null( slot_state_mem.votes.notar_set );
  fd_bls_agg_null( &slot_state_mem.votes.skip_agg          );
  fd_bls_agg_null( &slot_state_mem.votes.skip_fallback_agg );
  fd_bls_agg_null( &slot_state_mem.votes.finalize_agg      );
  for( ulong rank=0UL; rank<n; rank++ ) {
    slot_state_mem.votes.notar_sig_idx        [ rank ] = (uint)fd_bls_sig_pool_idx_acquire( g_bls_sig_pool );
    slot_state_mem.votes.skip_sig_idx         [ rank ] = (uint)fd_bls_sig_pool_idx_acquire( g_bls_sig_pool );
    slot_state_mem.votes.skip_fallback_sig_idx[ rank ] = (uint)fd_bls_sig_pool_idx_acquire( g_bls_sig_pool );
    slot_state_mem.votes.finalize_sig_idx     [ rank ] = (uint)fd_bls_sig_pool_idx_acquire( g_bls_sig_pool );
    for( ulong j=0UL; j<AG_NOTAR_FALLBACK_VOTE_MAX; j++ ) slot_state_mem.votes.notar_fallback_sig_idx[ rank ][ j ] = (uint)fd_bls_sig_pool_idx_acquire( g_bls_sig_pool );
    slot_state_mem.votes.notar_fallback_sig_cnt[ rank ] = (uchar)AG_NOTAR_FALLBACK_VOTE_MAX;
    fd_bls_set_insert( slot_state_mem.votes.notar_set,              rank );
    fd_bls_set_insert( slot_state_mem.votes.skip_agg.set,          rank );
    fd_bls_set_insert( slot_state_mem.votes.skip_fallback_agg.set, rank );
    fd_bls_set_insert( slot_state_mem.votes.finalize_agg.set,      rank );
  }
  FD_TEST( fd_bls_sig_pool_free( g_bls_sig_pool )==fd_bls_sig_pool_max( g_bls_sig_pool )-n*(4UL+AG_NOTAR_FALLBACK_VOTE_MAX) );
  ag_slot_state_t * ss = make_state( slot, epoch_info );
  assert_maps_empty( ss );
  FD_TEST( fd_bls_set_is_null( ss->votes.notar_set ) && fd_bls_set_is_null( ss->votes.skip_agg.set ) && fd_bls_set_is_null( ss->votes.skip_fallback_agg.set ) && fd_bls_set_is_null( ss->votes.finalize_agg.set ) );
  for( ulong rank=0UL; rank<AG_VAT_MAX; rank++ ) FD_TEST( !ss->votes.notar_fallback_sig_cnt[ rank ] );
  FD_TEST( fd_bls_sig_pool_free( g_bls_sig_pool )==fd_bls_sig_pool_max( g_bls_sig_pool ) );

  ag_vote_t n1 = ag_vote_construct_notar( sec_sign_fn, &g_sk[1], test_bls_public_key, slot, hash, 1UL, TEST_SHRED_VERSION );
  ag_vote_t s1 = ag_vote_construct_skip ( sec_sign_fn, &g_sk[1], test_bls_public_key, slot, 1UL,       TEST_SHRED_VERSION );
  ag_vote_t f1 = ag_vote_construct_final( sec_sign_fn, &g_sk[1], test_bls_public_key, slot, 1UL,       TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &g_states, &n1 )==AG_SLASHABLE_NONE );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &g_states, &s1 )==AG_SLASHABLE_NONE );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &g_states, &f1 )==AG_SLASHABLE_NONE );
  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &g_states, &n1 ) );
  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &g_states, &s1 ) );

  add_vote_helper( ss, &n1, epoch_info, &t );
  FD_TEST( t.ok && ag_slot_state_should_ignore_vote( ss, &g_states, &n1 ) );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &g_states, &s1 )==AG_SLASHABLE_SKIP_AND_NOTARIZE );

  ag_vote_t s2 = ag_vote_construct_skip( sec_sign_fn, &g_sk[2], test_bls_public_key, slot, 2UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &s2, epoch_info, &t );
  FD_TEST( t.ok && ag_slot_state_should_ignore_vote( ss, &g_states, &s2 ) );
  ag_vote_t f2 = ag_vote_construct_final( sec_sign_fn, &g_sk[2], test_bls_public_key, slot, 2UL, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &g_states, &f2 )==AG_SLASHABLE_SKIP_AND_FINALIZE );

  free( em );
}

/* src/consensus/pool/slot_state.rs::count_finalize_creates_cert_at_quorum */

static void
test_count_finalize_creates_cert_at_quorum( void ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  ag_slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;

  for( ulong i=1UL; i<=3UL; i++ ) {
    ag_vote_t fv = ag_vote_construct_final( sec_sign_fn, &g_sk[i], test_bls_public_key, slot, (ushort)i, TEST_SHRED_VERSION );
    add_vote_helper( ss, &fv, epoch_info, &t );
    FD_TEST( t.o.certs_cnt==0UL );
    FD_TEST( t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL );
    FD_TEST( t.o.block_to_repair_cnt==0UL );
  }

  ag_vote_t fv4 = ag_vote_construct_final( sec_sign_fn, &g_sk[4], test_bls_public_key, slot, 4UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &fv4, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==1UL );
  FD_TEST( t.o.certs[0].kind==AG_CERT_KIND_FINAL );

  ag_slot_state_add_cert( ss, &t.o.certs[0] );
  ag_vote_t fv5 = ag_vote_construct_final( sec_sign_fn, &g_sk[5], test_bls_public_key, slot, 5UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &fv5, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==0UL );

  free( em );
}

static void
test_poisoned_notar_aggregate( void ) {
  ulong n = 11UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 5UL;
  ag_block_hash_t hash; random_hash( hash );
  out_t t;

  ag_slot_state_t * ss = make_state( slot, epoch_info );
  ag_vote_t bad = ag_vote_construct_notar( sec_sign_fn, &g_sk[4], test_bls_public_key, slot, hash, 3UL, TEST_SHRED_VERSION );
  for( ulong i=0UL; i<6UL; i++ ) {
    ag_vote_t v = i==3UL ? bad : ag_vote_construct_notar( sec_sign_fn, &g_sk[i], test_bls_public_key, slot, hash, (ushort)i, TEST_SHRED_VERSION );
    add_vote_helper( ss, &v, epoch_info, &t );
    FD_TEST( t.o.certs_cnt==0UL && t.ok );
  }
  ag_vote_t v6 = ag_vote_construct_notar( sec_sign_fn, &g_sk[6], test_bls_public_key, slot, hash, 6UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &v6, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==0UL && t.ok && fd_bls_set_cnt( t.o.bad )==1UL && fd_bls_set_test( t.o.bad, 3UL ) );
  FD_TEST( hash_stake_cnt( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool )==1UL && notar_hash_stake_query( ss, hash )==6UL && !fd_bls_set_test( ss->votes.notar_set, 3UL ) );
  ag_vote_t v7 = ag_vote_construct_notar( sec_sign_fn, &g_sk[7], test_bls_public_key, slot, hash, 7UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &v7, epoch_info, &t );
  { int has_notar = 0; for( ulong i=0UL; i<t.o.certs_cnt; i++ ) has_notar |= t.o.certs[i].kind==AG_CERT_KIND_NOTAR; FD_TEST( has_notar && t.ok ); }

  ss = make_state( slot, epoch_info );
  for( ulong i=0UL; i<7UL; i++ ) {
    ag_vote_t v = ag_vote_construct_notar( sec_sign_fn, &g_sk[i], test_bls_public_key, slot, hash, (ushort)i, TEST_SHRED_VERSION );
    add_vote_helper( ss, &v, epoch_info, &t );
  }
  int has_notar = 0; for( ulong i=0UL; i<t.o.certs_cnt; i++ ) has_notar |= t.o.certs[i].kind==AG_CERT_KIND_NOTAR;
  FD_TEST( has_notar && t.ok );

  ss = make_state( slot, epoch_info );
  for( ulong i=0UL; i<6UL; i++ ) {
    ag_vote_t v = ag_vote_construct_notar( sec_sign_fn, &g_sk[i], test_bls_public_key, slot, hash, (ushort)i, TEST_SHRED_VERSION );
    add_vote_helper( ss, &v, epoch_info, &t );
  }
  ag_vote_t bad6 = ag_vote_construct_notar( sec_sign_fn, &g_sk[4], test_bls_public_key, slot, hash, 6UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &bad6, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==0UL && !t.ok && fd_bls_set_cnt( t.o.bad )==1UL && fd_bls_set_test( t.o.bad, 6UL ) );
  FD_TEST( notar_hash_stake_query( ss, hash )==6UL && !fd_bls_set_test( ss->votes.notar_set, 6UL ) );
  add_vote_helper( ss, &v7, epoch_info, &t );
  has_notar = 0; for( ulong i=0UL; i<t.o.certs_cnt; i++ ) has_notar |= t.o.certs[i].kind==AG_CERT_KIND_NOTAR;
  FD_TEST( has_notar && t.ok && fd_bls_set_is_null( t.o.bad ) );
  free( em );

  generate_validators( n );
  g_info[0].stake = 3UL;
  epoch_info = make_epoch( n, &em );
  ss = make_state( slot, epoch_info );
  for( ulong i=1UL; i<7UL; i++ ) {
    ag_vote_t v = i==3UL ? bad : ag_vote_construct_notar( sec_sign_fn, &g_sk[i], test_bls_public_key, slot, hash, (ushort)i, TEST_SHRED_VERSION );
    add_vote_helper( ss, &v, epoch_info, &t );
    FD_TEST( t.o.certs_cnt==0UL && t.ok );
  }
  ag_vote_t v0 = ag_vote_construct_notar( sec_sign_fn, &g_sk[0], test_bls_public_key, slot, hash, 0UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &v0, epoch_info, &t );
  has_notar = 0; for( ulong i=0UL; i<t.o.certs_cnt; i++ ) has_notar |= t.o.certs[i].kind==AG_CERT_KIND_NOTAR;
  FD_TEST( has_notar && t.ok && fd_bls_set_cnt( t.o.bad )==1UL && fd_bls_set_test( t.o.bad, 3UL ) );
  FD_TEST( notar_hash_stake_query( ss, hash )==8UL && !fd_bls_set_test( ss->votes.notar_set, 3UL ) );
  free( em );
}

static void
test_identity_partition( void ) {
  ulong n = 11UL;
  generate_validators( n );
  fd_bls_pub_t neg; FD_TEST( !fd_bls_pub_de( &neg, g_info[3].bls_key, sizeof(ag_bls_key_t) ) );
  blst_p1_cneg( &neg, 1 ); blst_p1_compress( g_info[4].bls_key, &neg );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 5UL;
  ag_block_hash_t hash; random_hash( hash );
  out_t t;

  ag_slot_state_t * ss = make_state( slot, epoch_info );
  ag_vote_t v3 = ag_vote_construct_notar( sec_sign_fn, &g_sk[3], test_bls_public_key, slot, hash, 3UL, TEST_SHRED_VERSION );
  ag_vote_t v4 = ag_vote_construct_notar( sec_sign_fn, &g_sk[3], test_bls_public_key, slot, hash, 4UL, TEST_SHRED_VERSION ); blst_fp2_cneg( &v4.notar.sig.y, &v4.notar.sig.y, 1 );
  add_vote_helper( ss, &v3, epoch_info, &t ); FD_TEST( t.ok && t.o.certs_cnt==0UL );
  add_vote_helper( ss, &v4, epoch_info, &t ); FD_TEST( t.ok && t.o.certs_cnt==0UL );
  fd_bls_agg_t notar[1];
  notar_agg( ss, hash, notar );
  FD_TEST( blst_p1_is_inf( &notar->pub ) && blst_p2_is_inf( &notar->sig ) && fd_bls_set_cnt( notar->set )==2UL && notar_hash_stake_query( ss, hash )==2UL );

  ulong nf_ranks[7] = { 0UL, 1UL, 2UL, 5UL, 6UL, 7UL, 8UL };
  for( ulong i=0UL; i<6UL; i++ ) {
    ag_vote_t nf = ag_vote_construct_notar_fallback( sec_sign_fn, &g_sk[ nf_ranks[i] ], test_bls_public_key, slot, hash, (ushort)nf_ranks[i], TEST_SHRED_VERSION );
    add_vote_helper( ss, &nf, epoch_info, &t );
    FD_TEST( t.ok && t.o.certs_cnt==0UL && fd_bls_set_is_null( t.o.bad ) );
  }
  ag_vote_t nf8 = ag_vote_construct_notar_fallback( sec_sign_fn, &g_sk[8], test_bls_public_key, slot, hash, 8UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &nf8, epoch_info, &t );
  FD_TEST( t.ok && fd_bls_set_is_null( t.o.bad ) && t.o.certs_cnt==1UL && t.o.certs[0].kind==AG_CERT_KIND_NOTAR_FALLBACK );
  ag_cert_notar_fallback_t const * cert = &t.o.certs[0].notar_fallback;
  FD_TEST( cert->stake==7UL && fd_bls_set_is_null( cert->agg_notar.set ) && fd_bls_set_cnt( cert->agg_notar_fallback.set )==7UL );
  FD_TEST( ag_cert_verify( &t.o.certs[0], epoch_info )==AG_CERT_VERIFY_SUCCESS );

  ag_vote_t v9 = ag_vote_construct_notar( sec_sign_fn, &g_sk[9], test_bls_public_key, slot, hash, 9UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &v9, epoch_info, &t );
  notar_agg( ss, hash, notar );
  FD_TEST( t.ok && fd_bls_set_is_null( t.o.bad ) && notar_hash_stake_query( ss, hash )==3UL && !blst_p1_is_inf( &notar->pub ) );
  free( em );
}

static void
test_safe_to_events_verify( void ) {
  ulong n = 11UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 5UL;
  ag_block_hash_t hash; random_hash( hash );
  out_t t;

  ag_slot_state_t * ss = make_state( slot, epoch_info );
  ag_vote_t own_notar = ag_vote_construct_notar( sec_sign_fn, &g_sk[0], test_bls_public_key, slot, hash, 0UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &own_notar, epoch_info, &t ); FD_TEST( t.ok );
  for( ulong i=1UL; i<5UL; i++ ) {
    ag_vote_t v = ag_vote_construct_skip( sec_sign_fn, &g_sk[i], test_bls_public_key, slot, (ushort)i, TEST_SHRED_VERSION );
    add_vote_helper( ss, &v, epoch_info, &t );
    FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL );
  }
  ag_vote_t bad_skip = ag_vote_construct_skip( sec_sign_fn, &g_sk[7], test_bls_public_key, slot, 5UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &bad_skip, epoch_info, &t );
  FD_TEST( !t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL && !ss->sent_safe_to_skip && fd_bls_set_cnt( t.o.bad )==1UL && fd_bls_set_test( t.o.bad, 5UL ) && ss->votes.skip_stake==4UL );
  ag_vote_t skip6 = ag_vote_construct_skip( sec_sign_fn, &g_sk[6], test_bls_public_key, slot, 6UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &skip6, epoch_info, &t );
  FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==1UL && ss->sent_safe_to_skip && fd_bls_set_is_null( t.o.bad ) );

  ss = make_state( slot, epoch_info );
  add_vote_helper( ss, &own_notar, epoch_info, &t );
  add_vote_helper( ss, &bad_skip,  epoch_info, &t ); FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL && fd_bls_set_is_null( t.o.bad ) );
  for( ulong i=1UL; i<4UL; i++ ) {
    ag_vote_t v = ag_vote_construct_skip( sec_sign_fn, &g_sk[i], test_bls_public_key, slot, (ushort)i, TEST_SHRED_VERSION );
    add_vote_helper( ss, &v, epoch_info, &t );
    FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL );
  }
  ag_vote_t skip4 = ag_vote_construct_skip( sec_sign_fn, &g_sk[4], test_bls_public_key, slot, 4UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &skip4, epoch_info, &t );
  FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL && !ss->sent_safe_to_skip && fd_bls_set_cnt( t.o.bad )==1UL && fd_bls_set_test( t.o.bad, 5UL ) && ss->votes.skip_stake==4UL );
  add_vote_helper( ss, &skip6, epoch_info, &t );
  FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==1UL && ss->sent_safe_to_skip );

  ss = make_state( slot, epoch_info );
  ag_slot_state_notify_parent_known( ss, hash );
  ag_slot_state_notify_parent_certified( ss, &g_states, hash, t.o.bad );
  ag_vote_t own_skip = ag_vote_construct_skip( sec_sign_fn, &g_sk[0], test_bls_public_key, slot, 0UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &own_skip, epoch_info, &t ); FD_TEST( t.ok );
  for( ulong i=1UL; i<5UL; i++ ) {
    ag_vote_t v = ag_vote_construct_notar( sec_sign_fn, &g_sk[i], test_bls_public_key, slot, hash, (ushort)i, TEST_SHRED_VERSION );
    add_vote_helper( ss, &v, epoch_info, &t );
    FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL );
  }
  ag_vote_t bad_notar = ag_vote_construct_notar( sec_sign_fn, &g_sk[8], test_bls_public_key, slot, hash, 5UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &bad_notar, epoch_info, &t );
  FD_TEST( !t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL && fd_bls_set_cnt( t.o.bad )==1UL && fd_bls_set_test( t.o.bad, 5UL ) && notar_hash_stake_query( ss, hash )==4UL );
  ag_vote_t notar6 = ag_vote_construct_notar( sec_sign_fn, &g_sk[6], test_bls_public_key, slot, hash, 6UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &notar6, epoch_info, &t );
  FD_TEST( t.ok && t.o.safe_to_notar_cnt==1UL && t.o.safe_to_skip_cnt==0UL && fd_bls_set_is_null( t.o.bad ) );
  free( em );
}

static void
test_safe_to_skip_removes_forged_notar( void ) {
  ulong n = 11UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 5UL;
  ag_block_hash_t x; random_hash( x );
  ag_block_hash_t y; random_hash( y );
  out_t t;

  ag_slot_state_t * ss = make_state( slot, epoch_info );
  ag_vote_t own_notar = ag_vote_construct_notar( sec_sign_fn, &g_sk[0], test_bls_public_key, slot, y, 0UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &own_notar, epoch_info, &t ); FD_TEST( t.ok );
  for( ulong rank=1UL; rank<4UL; rank++ ) {
    ag_vote_t forged = ag_vote_construct_notar( sec_sign_fn, &g_sk[ rank+7UL ], test_bls_public_key, slot, x, (ushort)rank, TEST_SHRED_VERSION );
    add_vote_helper( ss, &forged, epoch_info, &t );
    FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL && fd_bls_set_is_null( t.o.bad ) );
  }
  FD_TEST( notar_hash_stake_query( ss, x )==3UL && ss->votes.top_notar_stake==3UL );
  for( ulong rank=4UL; rank<8UL; rank++ ) {
    ag_vote_t skip = ag_vote_construct_skip( sec_sign_fn, &g_sk[ rank ], test_bls_public_key, slot, (ushort)rank, TEST_SHRED_VERSION );
    add_vote_helper( ss, &skip, epoch_info, &t );
    FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL );
  }
  FD_TEST( fd_bls_set_cnt( t.o.bad )==3UL && fd_bls_set_test( t.o.bad, 1UL ) && fd_bls_set_test( t.o.bad, 2UL ) && fd_bls_set_test( t.o.bad, 3UL ) );
  FD_TEST( notar_hash_stake_query( ss, x )==ULONG_MAX );
  FD_TEST( notar_hash_stake_query( ss, y )==1UL );
  FD_TEST( ss->votes.notar_or_skip_stake==5UL && ss->votes.top_notar_stake==1UL && !ss->sent_safe_to_skip );
  ag_vote_t skip8 = ag_vote_construct_skip( sec_sign_fn, &g_sk[8], test_bls_public_key, slot, 8UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &skip8, epoch_info, &t );
  FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==1UL && ss->sent_safe_to_skip && fd_bls_set_is_null( t.o.bad ) );
  free( em );
}

static void
test_map_capacity( void ) {
  ulong n = 11UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ag_slot_state_t * ss = make_state( 5UL, epoch_info );

  ag_block_hash_t notar_hash[ AG_VAT_MAX ];
  for( ulong i=0UL; i<AG_VAT_MAX; i++ ) {
    random_hash( notar_hash[ i ] );
    ulong id = hash_stake_insert( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool, &ss->votes.notar_hash_stake_head, &ss->votes.notar_hash_stake_cnt, ag_block_id( ss->slot, notar_hash[ i ] ) );
    FD_TEST( id==i );
    FD_TEST( hash_stake_idx( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool, ss->slot, notar_hash[ i ] )==i );
  }
  for( ulong i=0UL; i<AG_NOTAR_FALLBACK_HASH_MAX; i++ ) {
    ag_block_hash_t hash; random_hash( hash );
    ulong id = hash_stake_insert( g_states.notar_fallback_hash_stake_map, g_states.notar_fallback_hash_stake_pool, &ss->votes.notar_fallback_hash_stake_head, &ss->votes.notar_fallback_hash_stake_cnt, ag_block_id( ss->slot, hash ) );
    FD_TEST( id==i );
    FD_TEST( hash_stake_idx( g_states.notar_fallback_hash_stake_map, g_states.notar_fallback_hash_stake_pool, ss->slot, hash )==i );
  }
  FD_TEST( !ag_vote_stake_pool_free( g_states.notar_hash_stake_pool ) && !ag_vote_stake_pool_free( g_states.notar_fallback_hash_stake_pool ) );
  FD_TEST( hash_stake_cnt( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool )==AG_VAT_MAX && hash_stake_cnt( g_states.notar_fallback_hash_stake_map, g_states.notar_fallback_hash_stake_pool )==AG_NOTAR_FALLBACK_HASH_MAX );

  hash_stake_remove( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool, &ss->votes.notar_hash_stake_head, &ss->votes.notar_hash_stake_cnt, 7UL    );
  hash_stake_remove( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool, &ss->votes.notar_hash_stake_head, &ss->votes.notar_hash_stake_cnt, 1234UL );
  FD_TEST( ag_vote_stake_pool_free( g_states.notar_hash_stake_pool )==2UL );
  FD_TEST( hash_stake_idx( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool, ss->slot, notar_hash[ 7    ] )==ULONG_MAX );
  FD_TEST( hash_stake_idx( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool, ss->slot, notar_hash[ 1234 ] )==ULONG_MAX );
  for( ulong i=0UL; i<AG_VAT_MAX; i++ ) FD_TEST( i==7UL || i==1234UL || hash_stake_idx( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool, ss->slot, notar_hash[ i ] )==i );
  ag_block_hash_t a; random_hash( a );
  ag_block_hash_t b; random_hash( b );
  ulong id_a = hash_stake_insert( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool, &ss->votes.notar_hash_stake_head, &ss->votes.notar_hash_stake_cnt, ag_block_id( ss->slot, a ) );
  ulong id_b = hash_stake_insert( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool, &ss->votes.notar_hash_stake_head, &ss->votes.notar_hash_stake_cnt, ag_block_id( ss->slot, b ) );
  FD_TEST( id_a==1234UL && id_b==7UL && !ag_vote_stake_pool_free( g_states.notar_hash_stake_pool ) );
  FD_TEST( hash_stake_idx( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool, ss->slot, a )==1234UL && hash_stake_idx( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool, ss->slot, b )==7UL );

  ag_slot_state_null( ss, &g_states );
  assert_maps_empty( ss );
  free( em );
}

/* Four notar hashes share one map chain and the forged one sits in the
   middle of it and of the slot's sibling list.  check_safe_to_skip
   removes it while iterating the sibling list and must still verify
   every chain mate exactly once. */

static void
test_safe_to_skip_removes_chain_mate( void ) {
  ulong n = 11UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 5UL;
  out_t t;

  ag_slot_state_t * ss = make_state( slot, epoch_info );
  ag_block_hash_t   hash[ 4 ];
  random_hash( hash[0] );
  ulong         seed      = ag_vote_stake_map_seed     ( g_states.notar_hash_stake_map );
  ulong         chain_cnt = ag_vote_stake_map_chain_cnt( g_states.notar_hash_stake_map );
  ag_block_id_t key0      = ag_block_id( slot, hash[0] );
  ulong         chain     = ag_vote_stake_map_key_hash( &key0, seed ) & (chain_cnt-1UL);
  for( ulong i=1UL; i<4UL; i++ ) {
    for(;;) {
      random_hash( hash[i] );
      ag_block_id_t key = ag_block_id( slot, hash[i] );
      if( ( ag_vote_stake_map_key_hash( &key, seed ) & (chain_cnt-1UL) )==chain ) break;
    }
  }
  ag_vote_t v0 = ag_vote_construct_notar( sec_sign_fn, &g_sk[0], test_bls_public_key, slot, hash[0], 0UL, TEST_SHRED_VERSION );
  ag_vote_t v1 = ag_vote_construct_notar( sec_sign_fn, &g_sk[8], test_bls_public_key, slot, hash[1], 1UL, TEST_SHRED_VERSION );
  ag_vote_t v2 = ag_vote_construct_notar( sec_sign_fn, &g_sk[2], test_bls_public_key, slot, hash[2], 2UL, TEST_SHRED_VERSION );
  ag_vote_t v3 = ag_vote_construct_notar( sec_sign_fn, &g_sk[3], test_bls_public_key, slot, hash[3], 3UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &v0, epoch_info, &t ); FD_TEST( t.ok );
  add_vote_helper( ss, &v1, epoch_info, &t ); FD_TEST( t.ok );
  add_vote_helper( ss, &v2, epoch_info, &t ); FD_TEST( t.ok );
  add_vote_helper( ss, &v3, epoch_info, &t ); FD_TEST( t.ok );
  for( ulong i=0UL; i<4UL; i++ ) FD_TEST( hash_stake_idx( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool, ss->slot, hash[i] )==i );
  FD_TEST( hash_stake_cnt( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool )==4UL && ag_vote_stake_pool_free( g_states.notar_hash_stake_pool )==AG_VAT_MAX-4UL );
  for( ulong rank=4UL; rank<6UL; rank++ ) {
    ag_vote_t skip = ag_vote_construct_skip( sec_sign_fn, &g_sk[ rank ], test_bls_public_key, slot, (ushort)rank, TEST_SHRED_VERSION );
    add_vote_helper( ss, &skip, epoch_info, &t );
    FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL );
  }
  FD_TEST( fd_bls_set_cnt( t.o.bad )==1UL && fd_bls_set_test( t.o.bad, 1UL ) );
  FD_TEST( notar_hash_stake_query( ss, hash[1] )==ULONG_MAX );
  FD_TEST( hash_stake_cnt( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool )==3UL && ss->votes.notar_hash_stake_cnt==3UL && ag_vote_stake_pool_free( g_states.notar_hash_stake_pool )==AG_VAT_MAX-3UL );
  FD_TEST( hash_stake_idx( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool, ss->slot, hash[0] )==0UL );
  FD_TEST( hash_stake_idx( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool, ss->slot, hash[2] )==2UL );
  FD_TEST( hash_stake_idx( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool, ss->slot, hash[3] )==3UL );
  ag_vote_stake_ele_t * notar_hash_stake_pool = g_states.notar_hash_stake_pool;
  FD_TEST( ag_vote_stake_pool_idx_acquire( notar_hash_stake_pool )==1UL );
  ag_vote_stake_pool_idx_release( notar_hash_stake_pool, 1UL );
  FD_TEST( notar_hash_stake_query( ss, hash[0] )==1UL );
  FD_TEST( notar_hash_stake_query( ss, hash[2] )==1UL );
  FD_TEST( notar_hash_stake_query( ss, hash[3] )==1UL );
  FD_TEST( ss->votes.notar_or_skip_stake==5UL && ss->votes.top_notar_stake==1UL && !ss->sent_safe_to_skip );
  ag_vote_t skip6 = ag_vote_construct_skip( sec_sign_fn, &g_sk[6], test_bls_public_key, slot, 6UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &skip6, epoch_info, &t );
  FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==1UL && ss->sent_safe_to_skip && fd_bls_set_is_null( t.o.bad ) );
  ag_slot_state_null( ss, &g_states );
  assert_maps_empty( ss );
  free( em );
}

static void
test_safe_to_skip_removes_head_middle_tail( void ) {
  ulong n = 11UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 5UL;
  out_t t;

  ag_slot_state_t *     ss   = make_state( slot, epoch_info );
  ag_vote_stake_ele_t * pool = g_states.notar_hash_stake_pool;
  ag_block_hash_t       hash[ 6 ];
  for( ulong i=0UL; i<6UL; i++ ) random_hash( hash[i] );
  ag_vote_t v0 = ag_vote_construct_notar( sec_sign_fn, &g_sk[8],  test_bls_public_key, slot, hash[0], 1UL, TEST_SHRED_VERSION );
  ag_vote_t v1 = ag_vote_construct_notar( sec_sign_fn, &g_sk[0],  test_bls_public_key, slot, hash[1], 0UL, TEST_SHRED_VERSION );
  ag_vote_t v2 = ag_vote_construct_notar( sec_sign_fn, &g_sk[9],  test_bls_public_key, slot, hash[2], 2UL, TEST_SHRED_VERSION );
  ag_vote_t v3 = ag_vote_construct_notar( sec_sign_fn, &g_sk[3],  test_bls_public_key, slot, hash[3], 3UL, TEST_SHRED_VERSION );
  ag_vote_t v4 = ag_vote_construct_notar( sec_sign_fn, &g_sk[10], test_bls_public_key, slot, hash[4], 4UL, TEST_SHRED_VERSION );
  ag_vote_t v5 = ag_vote_construct_notar( sec_sign_fn, &g_sk[6],  test_bls_public_key, slot, hash[1], 6UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &v0, epoch_info, &t ); FD_TEST( t.ok );
  add_vote_helper( ss, &v1, epoch_info, &t ); FD_TEST( t.ok );
  add_vote_helper( ss, &v2, epoch_info, &t ); FD_TEST( t.ok );
  add_vote_helper( ss, &v3, epoch_info, &t ); FD_TEST( t.ok );
  add_vote_helper( ss, &v4, epoch_info, &t ); FD_TEST( t.ok );
  add_vote_helper( ss, &v5, epoch_info, &t ); FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL && fd_bls_set_is_null( t.o.bad ) );
  for( ulong i=0UL; i<5UL; i++ ) FD_TEST( hash_stake_idx( g_states.notar_hash_stake_map, pool, ss->slot, hash[i] )==i );
  for( ulong i=1UL; i<5UL; i++ ) FD_TEST( ag_vote_stake_pool_ele_const( pool, i )->prev==i-1UL );
  FD_TEST( ss->votes.notar_hash_stake_cnt==5UL && ss->votes.notar_hash_stake_head==4UL && ag_vote_stake_pool_ele_const( pool, 0UL )->prev==ag_vote_stake_pool_idx_null( pool ) );

  ag_vote_t skip5 = ag_vote_construct_skip( sec_sign_fn, &g_sk[5], test_bls_public_key, slot, 5UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &skip5, epoch_info, &t );
  FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL && !ss->sent_safe_to_skip );
  FD_TEST( fd_bls_set_cnt( t.o.bad )==3UL && fd_bls_set_test( t.o.bad, 1UL ) && fd_bls_set_test( t.o.bad, 2UL ) && fd_bls_set_test( t.o.bad, 4UL ) );
  FD_TEST( ss->votes.notar_hash_stake_cnt==2UL && ss->votes.notar_hash_stake_head==3UL );
  FD_TEST( ag_vote_stake_pool_ele_const( pool, 3UL )->prev==1UL && ag_vote_stake_pool_ele_const( pool, 1UL )->prev==ag_vote_stake_pool_idx_null( pool ) );
  FD_TEST( hash_stake_cnt( g_states.notar_hash_stake_map, pool )==2UL && ag_vote_stake_pool_free( pool )==AG_VAT_MAX-2UL );
  FD_TEST( notar_hash_stake_query( ss, hash[0] )==ULONG_MAX && notar_hash_stake_query( ss, hash[2] )==ULONG_MAX && notar_hash_stake_query( ss, hash[4] )==ULONG_MAX );
  FD_TEST( notar_hash_stake_query( ss, hash[1] )==2UL && notar_hash_stake_query( ss, hash[3] )==1UL );
  FD_TEST( ss->votes.notar_or_skip_stake==4UL && ss->votes.top_notar_stake==2UL && !memcmp( ss->votes.top_notar_hash, hash[1], sizeof(ag_block_hash_t) ) );

  ag_vote_t v6 = ag_vote_construct_notar( sec_sign_fn, &g_sk[7], test_bls_public_key, slot, hash[5], 7UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &v6, epoch_info, &t );
  FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL && fd_bls_set_is_null( t.o.bad ) && hash_stake_idx( g_states.notar_hash_stake_map, pool, ss->slot, hash[5] )==0UL );
  FD_TEST( ss->votes.notar_hash_stake_cnt==3UL && ss->votes.notar_hash_stake_head==0UL && ag_vote_stake_pool_ele_const( pool, 0UL )->prev==3UL );
  ag_vote_t skip8 = ag_vote_construct_skip( sec_sign_fn, &g_sk[8], test_bls_public_key, slot, 8UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &skip8, epoch_info, &t );
  FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL && fd_bls_set_is_null( t.o.bad ) );
  ag_vote_t skip9 = ag_vote_construct_skip( sec_sign_fn, &g_sk[9], test_bls_public_key, slot, 9UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &skip9, epoch_info, &t );
  FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==1UL && ss->sent_safe_to_skip && fd_bls_set_is_null( t.o.bad ) );
  FD_TEST( ss->votes.notar_hash_stake_cnt==3UL && hash_stake_cnt( g_states.notar_hash_stake_map, pool )==3UL );
  ag_slot_state_null( ss, &g_states );
  assert_maps_empty( ss );
  free( em );
}

static void
test_notar_fallback_removes_head_middle_tail( void ) {
  ulong n = 11UL;
  generate_validators( n );
  g_info[1].stake = 20UL;
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 5UL;
  out_t t;

  ag_slot_state_t *     ss   = make_state( slot, epoch_info );
  ag_vote_stake_ele_t * pool = g_states.notar_fallback_hash_stake_pool;
  ag_block_hash_t       hash[ 5 ];
  for( ulong i=0UL; i<5UL; i++ ) random_hash( hash[i] );
  ag_vote_t v0 = ag_vote_construct_notar_fallback( sec_sign_fn, &g_sk[8], test_bls_public_key, slot, hash[0], 2UL, TEST_SHRED_VERSION );
  ag_vote_t v1 = ag_vote_construct_notar_fallback( sec_sign_fn, &g_sk[3], test_bls_public_key, slot, hash[1], 3UL, TEST_SHRED_VERSION );
  ag_vote_t v2 = ag_vote_construct_notar_fallback( sec_sign_fn, &g_sk[9], test_bls_public_key, slot, hash[2], 4UL, TEST_SHRED_VERSION );
  ag_vote_t v3 = ag_vote_construct_notar_fallback( sec_sign_fn, &g_sk[5], test_bls_public_key, slot, hash[3], 5UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &v0, epoch_info, &t ); FD_TEST( t.ok );
  add_vote_helper( ss, &v1, epoch_info, &t ); FD_TEST( t.ok );
  add_vote_helper( ss, &v2, epoch_info, &t ); FD_TEST( t.ok );
  add_vote_helper( ss, &v3, epoch_info, &t ); FD_TEST( t.ok && t.o.certs_cnt==0UL && fd_bls_set_is_null( t.o.bad ) );
  for( ulong i=0UL; i<4UL; i++ ) FD_TEST( hash_stake_idx( g_states.notar_fallback_hash_stake_map, pool, ss->slot, hash[i] )==i );
  for( ulong i=1UL; i<4UL; i++ ) FD_TEST( ag_vote_stake_pool_ele_const( pool, i )->prev==i-1UL );
  FD_TEST( ss->votes.notar_fallback_hash_stake_cnt==4UL && ss->votes.notar_fallback_hash_stake_head==3UL && ag_vote_stake_pool_ele_const( pool, 0UL )->prev==ag_vote_stake_pool_idx_null( pool ) );

  ag_vote_t forged_middle = ag_vote_construct_notar_fallback( sec_sign_fn, &g_sk[10], test_bls_public_key, slot, hash[2], 1UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &forged_middle, epoch_info, &t );
  FD_TEST( !t.ok && t.o.certs_cnt==0UL && fd_bls_set_cnt( t.o.bad )==2UL && fd_bls_set_test( t.o.bad, 1UL ) && fd_bls_set_test( t.o.bad, 4UL ) );
  FD_TEST( ss->votes.notar_fallback_hash_stake_cnt==3UL && ss->votes.notar_fallback_hash_stake_head==3UL );
  FD_TEST( ag_vote_stake_pool_ele_const( pool, 3UL )->prev==1UL && ag_vote_stake_pool_ele_const( pool, 1UL )->prev==0UL && ag_vote_stake_pool_ele_const( pool, 0UL )->prev==ag_vote_stake_pool_idx_null( pool ) );

  ag_vote_t forged_tail = ag_vote_construct_notar_fallback( sec_sign_fn, &g_sk[10], test_bls_public_key, slot, hash[0], 1UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &forged_tail, epoch_info, &t );
  FD_TEST( !t.ok && t.o.certs_cnt==0UL && fd_bls_set_cnt( t.o.bad )==2UL && fd_bls_set_test( t.o.bad, 1UL ) && fd_bls_set_test( t.o.bad, 2UL ) );
  FD_TEST( ss->votes.notar_fallback_hash_stake_cnt==2UL && ss->votes.notar_fallback_hash_stake_head==3UL );
  FD_TEST( ag_vote_stake_pool_ele_const( pool, 3UL )->prev==1UL && ag_vote_stake_pool_ele_const( pool, 1UL )->prev==ag_vote_stake_pool_idx_null( pool ) );

  ag_vote_t forged_head = ag_vote_construct_notar_fallback( sec_sign_fn, &g_sk[10], test_bls_public_key, slot, hash[4], 1UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &forged_head, epoch_info, &t );
  FD_TEST( !t.ok && t.o.certs_cnt==0UL && fd_bls_set_cnt( t.o.bad )==1UL && fd_bls_set_test( t.o.bad, 1UL ) );
  FD_TEST( ss->votes.notar_fallback_hash_stake_cnt==2UL && ss->votes.notar_fallback_hash_stake_head==3UL );
  FD_TEST( ag_vote_stake_pool_ele_const( pool, 3UL )->prev==1UL && ag_vote_stake_pool_ele_const( pool, 1UL )->prev==ag_vote_stake_pool_idx_null( pool ) );
  FD_TEST( hash_stake_cnt( g_states.notar_fallback_hash_stake_map, pool )==2UL && ag_vote_stake_pool_free( pool )==AG_NOTAR_FALLBACK_HASH_MAX-2UL );
  FD_TEST( notar_fallback_hash_stake_query( ss, hash[0] )==ULONG_MAX && notar_fallback_hash_stake_query( ss, hash[2] )==ULONG_MAX && notar_fallback_hash_stake_query( ss, hash[4] )==ULONG_MAX );
  FD_TEST( notar_fallback_hash_stake_query( ss, hash[1] )==1UL && notar_fallback_hash_stake_query( ss, hash[3] )==1UL );
  FD_TEST( !ss->votes.notar_fallback_sig_cnt[ 1 ] && !ss->votes.notar_fallback_sig_cnt[ 2 ] && !ss->votes.notar_fallback_sig_cnt[ 4 ] );

  ag_vote_t honest = ag_vote_construct_notar_fallback( sec_sign_fn, &g_sk[1], test_bls_public_key, slot, hash[1], 1UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &honest, epoch_info, &t );
  FD_TEST( t.ok && fd_bls_set_is_null( t.o.bad ) && t.o.certs_cnt==1UL && t.o.certs[0].kind==AG_CERT_KIND_NOTAR_FALLBACK && t.o.certs[0].notar_fallback.stake==21UL );
  FD_TEST( ag_cert_verify( &t.o.certs[0], epoch_info )==AG_CERT_VERIFY_SUCCESS );
  ag_slot_state_null( ss, &g_states );
  assert_maps_empty( ss );
  free( em );
}

/* src/consensus/pool/slot_state.rs::count_notar_fallback_creates_cert_at_quorum */

static void
test_count_notar_fallback_creates_cert_at_quorum( void ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  ag_block_hash_t hash; random_hash( hash );
  ag_slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;

  for( ulong i=1UL; i<=2UL; i++ ) {
    ag_vote_t nv = ag_vote_construct_notar( sec_sign_fn, &g_sk[i], test_bls_public_key, slot, hash, (ushort)i, TEST_SHRED_VERSION );
    add_vote_helper( ss, &nv, epoch_info, &t );
    FD_TEST( t.o.certs_cnt==0UL );
  }

  ag_vote_t nf3 = ag_vote_construct_notar_fallback( sec_sign_fn, &g_sk[3], test_bls_public_key, slot, hash, 3UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &nf3, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==0UL );
  FD_TEST( t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL );
  FD_TEST( t.o.block_to_repair_cnt==0UL );
  FD_TEST( notar_fallback_hash_stake_query( ss, hash )==1UL );

  ag_vote_t nf4 = ag_vote_construct_notar_fallback( sec_sign_fn, &g_sk[4], test_bls_public_key, slot, hash, 4UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &nf4, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==1UL );
  FD_TEST( t.o.certs[0].kind==AG_CERT_KIND_NOTAR_FALLBACK );
  FD_TEST( ag_cert_block_hash( &t.o.certs[0] ) && !memcmp( ag_cert_block_hash( &t.o.certs[0] ), hash, sizeof(ag_block_hash_t) ) );

  ag_slot_state_add_cert( ss, &t.o.certs[0] );
  ag_vote_t nf5 = ag_vote_construct_notar_fallback( sec_sign_fn, &g_sk[5], test_bls_public_key, slot, hash, 5UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &nf5, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==0UL );

  free( em );
}

/* src/consensus/pool/slot_state.rs::skip_skip_fallback_conflict */

static void
test_skip_skip_fallback_conflict( void ) {
  ulong n = 3UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  ag_slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;
  ulong v = 0UL;

  ag_vote_t skip = ag_vote_construct_skip( sec_sign_fn, &g_sk[v], test_bls_public_key, slot, (ushort)v, TEST_SHRED_VERSION );
  ag_vote_t skip_fallback = ag_vote_construct_skip_fallback( sec_sign_fn, &g_sk[v], test_bls_public_key, slot, (ushort)v, TEST_SHRED_VERSION );

  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &g_states, &skip          ) );
  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &g_states, &skip_fallback ) );

  add_vote_helper( ss, &skip, epoch_info, &t );

  FD_TEST( ag_slot_state_should_ignore_vote( ss, &g_states, &skip_fallback ) );

  FD_TEST( ag_slot_state_should_ignore_vote( ss, &g_states, &skip ) );

  FD_TEST( ag_slot_state_check_slashable_offence( ss, &g_states, &skip_fallback )==AG_SLASHABLE_NONE );

  ag_slot_state_null( ss, &g_states );
  ss->slot     = slot;
  ss->own_rank = 0UL;
  add_vote_helper( ss, &skip_fallback, epoch_info, &t );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &g_states, &skip          ) );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &g_states, &skip_fallback ) );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &g_states, &skip )==AG_SLASHABLE_NONE );

  free( em );
}

/* src/consensus/pool/slot_state.rs::notar_notar_fallback_conflict */

static void
test_notar_notar_fallback_conflict( void ) {
  ulong n = 3UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  ag_block_hash_t hash;       random_hash( hash       );
  ag_block_hash_t other_hash; random_hash( other_hash );
  ag_slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;
  ulong v = 0UL;

  ag_vote_t notar = ag_vote_construct_notar( sec_sign_fn, &g_sk[v], test_bls_public_key, slot, hash, (ushort)v, TEST_SHRED_VERSION );
  ag_vote_t notar_fallback = ag_vote_construct_notar_fallback( sec_sign_fn, &g_sk[v], test_bls_public_key, slot, hash, (ushort)v, TEST_SHRED_VERSION );
  ag_vote_t nf_other = ag_vote_construct_notar_fallback( sec_sign_fn, &g_sk[v], test_bls_public_key, slot, other_hash, (ushort)v, TEST_SHRED_VERSION );

  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &g_states, &notar          ) );
  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &g_states, &notar_fallback ) );

  add_vote_helper( ss, &notar, epoch_info, &t );

  FD_TEST( ag_slot_state_should_ignore_vote( ss, &g_states, &notar_fallback ) );

  FD_TEST( ag_slot_state_should_ignore_vote( ss, &g_states, &notar ) );

  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &g_states, &nf_other ) );

  FD_TEST( ag_slot_state_check_slashable_offence( ss, &g_states, &notar_fallback )==AG_SLASHABLE_NONE );

  ag_slot_state_null( ss, &g_states );
  ss->slot     = slot;
  ss->own_rank = 0UL;
  add_vote_helper( ss, &notar_fallback, epoch_info, &t );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &g_states, &notar          ) );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &g_states, &notar_fallback ) );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &g_states, &notar )==AG_SLASHABLE_NONE );

  free( em );
}

/* src/consensus/pool/sorted_vec.rs::set_insert_contains_iter */

static void
test_set_insert_contains_iter( void ) {
  ag_block_hash_t h1, h3, h5, h2;
  random_hash( h1 ); random_hash( h3 ); random_hash( h5 ); random_hash( h2 );

  ag_block_hash_set_t set; set.cnt = 0UL;

  block_hash_set_insert( &set, h3 ); FD_TEST( set.cnt==1UL );
  block_hash_set_insert( &set, h1 ); FD_TEST( set.cnt==2UL );
  block_hash_set_insert( &set, h5 ); FD_TEST( set.cnt==3UL );
  block_hash_set_insert( &set, h3 ); FD_TEST( set.cnt==3UL );

  FD_TEST(  block_hash_set_contains( &set, h1 ) );
  FD_TEST( !block_hash_set_contains( &set, h2 ) );

  block_hash_set_remove( &set, h1 ); FD_TEST( set.cnt==2UL );
  block_hash_set_remove( &set, h1 ); FD_TEST( set.cnt==2UL );
  FD_TEST( !block_hash_set_contains( &set, h1 ) );

  FD_TEST( block_hash_set_contains( &set, h3 ) );
  FD_TEST( block_hash_set_contains( &set, h5 ) );
}

static void
assert_tally( ag_vote_stake_map_t const * map,
              ag_vote_stake_ele_t const * pool,
              ulong                       slot,
              uchar const * const *       hash,
              ulong const *               stake,
              ulong                       expected_cnt ) {
  FD_TEST( hash_stake_cnt( map, pool )==expected_cnt );
  for( ulong i=0UL; i<expected_cnt; i++ ) {
    ulong id = hash_stake_idx( map, pool, slot, hash[i] );
    FD_TEST( id!=ULONG_MAX );
    FD_TEST( ag_vote_stake_pool_ele_const( pool, id )->stake==stake[i] );
  }
}

/* src/consensus/pool/sorted_vec.rs::map_get_or_insert_with */

static void
test_notar_stake_tally( void ) {
  ulong n = 12UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  ag_slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;

  ag_block_hash_t a, b, c, d;
  random_hash( a ); random_hash( b ); random_hash( c ); random_hash( d );

  ulong rank = 0UL;
  ag_vote_t v;
  v = ag_vote_construct_notar( sec_sign_fn, &g_sk[rank], test_bls_public_key, slot, a, (ushort)rank, TEST_SHRED_VERSION ); rank++;
  add_vote_helper( ss, &v, epoch_info, &t );
  assert_tally( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool, ss->slot, (uchar const *[]){ a }, (ulong[]){ 1UL }, 1UL );

  v = ag_vote_construct_notar( sec_sign_fn, &g_sk[rank], test_bls_public_key, slot, b, (ushort)rank, TEST_SHRED_VERSION ); rank++;
  add_vote_helper( ss, &v, epoch_info, &t );
  assert_tally( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool, ss->slot, (uchar const *[]){ a, b }, (ulong[]){ 1UL, 1UL }, 2UL );

  v = ag_vote_construct_notar( sec_sign_fn, &g_sk[rank], test_bls_public_key, slot, b, (ushort)rank, TEST_SHRED_VERSION ); rank++;
  add_vote_helper( ss, &v, epoch_info, &t );
  assert_tally( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool, ss->slot, (uchar const *[]){ b, a }, (ulong[]){ 2UL, 1UL }, 2UL );

  for( ulong i=0UL; i<3UL; i++ ) {
    v = ag_vote_construct_notar( sec_sign_fn, &g_sk[rank], test_bls_public_key, slot, c, (ushort)rank, TEST_SHRED_VERSION ); rank++;
    add_vote_helper( ss, &v, epoch_info, &t );
  }
  assert_tally( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool, ss->slot, (uchar const *[]){ c, b, a }, (ulong[]){ 3UL, 2UL, 1UL }, 3UL );

  for( ulong i=0UL; i<4UL; i++ ) {
    v = ag_vote_construct_notar( sec_sign_fn, &g_sk[rank], test_bls_public_key, slot, d, (ushort)rank, TEST_SHRED_VERSION ); rank++;
    add_vote_helper( ss, &v, epoch_info, &t );
  }
  FD_TEST( rank<=n );
  assert_tally( g_states.notar_hash_stake_map, g_states.notar_hash_stake_pool, ss->slot, (uchar const *[]){ d, c, b, a }, (ulong[]){ 4UL, 3UL, 2UL, 1UL }, 4UL );
  FD_TEST( ss->votes.top_notar_stake==4UL ); /* d, the most supported hash */

  free( em );
}

/* src/consensus/pool/sorted_vec.rs::map_get_or_insert_with */

static void
test_notar_fallback_stake_tally( void ) {
  ulong n = 12UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  ag_slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;

  ag_block_hash_t own[ AG_NOTAR_FALLBACK_VOTE_MAX ];
  for( ulong i=0UL; i<AG_NOTAR_FALLBACK_VOTE_MAX; i++ ) {
    random_hash( own[i] );
    ag_vote_t v = ag_vote_construct_notar_fallback( sec_sign_fn, &g_sk[0], test_bls_public_key, slot, own[i], 0UL, TEST_SHRED_VERSION );
    FD_TEST( ss->votes.notar_fallback_sig_cnt[ 0 ]<AG_NOTAR_FALLBACK_VOTE_MAX );
    add_vote_helper( ss, &v, epoch_info, &t );
    FD_TEST( notar_fallback_hash_stake_query( ss, own[i] )==1UL );
  }

  /* the cap itself is enforced in ag_pool_add_vote; see test_ag_pool */
  FD_TEST( ss->votes.notar_fallback_sig_cnt[ 0 ]==AG_NOTAR_FALLBACK_VOTE_MAX );

  for( ulong i=0UL; i<2UL; i++ ) {
    ag_vote_t v = ag_vote_construct_notar_fallback( sec_sign_fn, &g_sk[1UL+i], test_bls_public_key, slot, own[2], (ushort)(1UL+i), TEST_SHRED_VERSION );
    add_vote_helper( ss, &v, epoch_info, &t );
  }
  ag_vote_t v_mid = ag_vote_construct_notar_fallback( sec_sign_fn, &g_sk[3], test_bls_public_key, slot, own[1], 3UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &v_mid, epoch_info, &t );

  assert_tally( g_states.notar_fallback_hash_stake_map, g_states.notar_fallback_hash_stake_pool, ss->slot,
                (uchar const *[]){ own[2], own[1], own[0] }, (ulong[]){ 3UL, 2UL, 1UL }, 3UL );

  free( em );
}

/* Drive both pools and a reference through random inserts, removes
   and nulls on keys that collide in the first CLEAR_WIN chains.  A live
   hash keeps the id it was given, freed ids are reused before a new id
   is taken, and a null leaves both pools empty. */

#define CLEAR_KEY_CNT (48UL)
#define CLEAR_WIN     (8UL)

static void
collide_key( fd_rng_t *                  rng,
             ag_vote_stake_map_t const * map,
             ulong                       slot,
             ag_block_id_t *             key ) {
  key->slot = slot;
  for(;;) {
    for( ulong i=0UL; i<4UL; i++ ) FD_STORE( ulong, key->hash+8UL*i, fd_rng_ulong( rng ) );
    if( ( ag_vote_stake_map_key_hash( key, ag_vote_stake_map_seed( map ) ) & (ag_vote_stake_map_chain_cnt( map )-1UL) )<CLEAR_WIN ) return;
  }
}

static void
hash_stake_step( ag_vote_stake_map_t * map,
                 ag_vote_stake_ele_t * pool,
                 ulong *               head,
                 ulong *               cnt,
                 ulong                 pool_max,
                 ag_block_id_t *       key,
                 ulong *               ref_id,
                 ulong *               ref_stake,
                 ulong *               peak,
                 ulong                 k,
                 ulong                 iter ) {
  if( ref_id[ k ]!=ULONG_MAX ) {
    hash_stake_remove( map, pool, head, cnt, ref_id[ k ] );
    ref_id[ k ] = ULONG_MAX;
  } else {
    ulong used = ag_vote_stake_pool_used( pool );
    ulong id   = hash_stake_insert( map, pool, head, cnt, key[ k ] );
    FD_TEST( used<*peak ? id<*peak : id==*peak );
    ag_vote_stake_pool_ele( pool, id )->stake = iter;
    ref_id   [ k ] = id;
    ref_stake[ k ] = iter;
  }
  ulong live = 0UL;
  for( ulong i=0UL; i<CLEAR_KEY_CNT; i++ ) {
    FD_TEST( ag_vote_stake_map_idx_query_const( map, &key[ i ], ULONG_MAX, pool )==ref_id[ i ] );
    if( ref_id[ i ]==ULONG_MAX ) continue;
    FD_TEST( ag_vote_stake_pool_ele( pool, ref_id[ i ] )->stake==ref_stake[ i ] );
    live++;
  }
  *peak = fd_ulong_max( *peak, live );
  FD_TEST( hash_stake_cnt( map, pool )==live && *cnt==live && ag_vote_stake_pool_free( pool )==pool_max-live );
  ulong i = *head;
  for( ulong j=0UL; j<*cnt; j++ ) {
    FD_TEST( ag_vote_stake_map_idx_query_const( map, &ag_vote_stake_pool_ele( pool, i )->block_id, ULONG_MAX, pool )==i );
    i = ag_vote_stake_pool_ele( pool, i )->prev;
  }
  FD_TEST( !*cnt || i==ag_vote_stake_pool_idx_null( pool ) );
}

static void
test_pool_ids_stable( void ) {
  ulong n = 3UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * epoch_info = make_epoch( n, &em );
  ag_slot_state_t * ss = make_state( 1UL, epoch_info );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 1234U, 0UL ) );
  ag_block_id_t notar_key[ CLEAR_KEY_CNT ];
  ag_block_id_t nf_key   [ CLEAR_KEY_CNT ];
  for( ulong i=0UL; i<CLEAR_KEY_CNT; i++ ) {
    collide_key( rng, g_states.notar_hash_stake_map,          ss->slot, &notar_key[ i ] );
    collide_key( rng, g_states.notar_fallback_hash_stake_map, ss->slot, &nf_key   [ i ] );
  }
  ulong notar_ref_id[ CLEAR_KEY_CNT ]; ulong notar_ref_stake[ CLEAR_KEY_CNT ]; ulong notar_peak = 0UL;
  ulong nf_ref_id   [ CLEAR_KEY_CNT ]; ulong nf_ref_stake   [ CLEAR_KEY_CNT ]; ulong nf_peak    = 0UL;
  for( ulong i=0UL; i<CLEAR_KEY_CNT; i++ ) { notar_ref_id[ i ] = ULONG_MAX; nf_ref_id[ i ] = ULONG_MAX; }

  ulong null_cnt = 0UL;
  for( ulong iter=0UL; iter<200000UL; iter++ ) {
    uint r = fd_rng_uint( rng );
    if( FD_UNLIKELY( !(r&255U) ) ) {
      ag_slot_state_null( ss, &g_states );
      assert_maps_empty( ss );
      for( ulong i=0UL; i<CLEAR_KEY_CNT; i++ ) {
        FD_TEST( hash_stake_idx( g_states.notar_hash_stake_map,          g_states.notar_hash_stake_pool,          ss->slot, notar_key[ i ].hash )==ULONG_MAX );
        FD_TEST( hash_stake_idx( g_states.notar_fallback_hash_stake_map, g_states.notar_fallback_hash_stake_pool, ss->slot, nf_key   [ i ].hash )==ULONG_MAX );
        notar_ref_id[ i ] = ULONG_MAX; nf_ref_id[ i ] = ULONG_MAX;
      }
      null_cnt++;
      continue;
    }
    ulong k = (ulong)( (r>>8)%CLEAR_KEY_CNT );
    if( r&(1U<<31) ) hash_stake_step( g_states.notar_hash_stake_map,          g_states.notar_hash_stake_pool,          &ss->votes.notar_hash_stake_head,          &ss->votes.notar_hash_stake_cnt,          AG_VAT_MAX,                 notar_key, notar_ref_id, notar_ref_stake, &notar_peak, k, iter );
    else             hash_stake_step( g_states.notar_fallback_hash_stake_map, g_states.notar_fallback_hash_stake_pool, &ss->votes.notar_fallback_hash_stake_head, &ss->votes.notar_fallback_hash_stake_cnt, AG_NOTAR_FALLBACK_HASH_MAX, nf_key,    nf_ref_id,    nf_ref_stake,    &nf_peak,    k, iter );
  }
  FD_TEST( null_cnt>100UL );

  fd_rng_delete( fd_rng_leave( rng ) );
  free( em );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  void * bls_sig_pool_mem = aligned_alloc( fd_bls_sig_pool_align(), fd_bls_sig_pool_footprint( AG_VAT_MAX*AG_SLOT_VOTE_SIG_MAX ) );
  FD_TEST( bls_sig_pool_mem );
  g_bls_sig_pool = fd_bls_sig_pool_join( fd_bls_sig_pool_new( bls_sig_pool_mem, AG_VAT_MAX*AG_SLOT_VOTE_SIG_MAX ) );
  g_states.bls_sig_pool    = g_bls_sig_pool;
  g_states.prev_epoch_info = NULL;
  g_states.prev_epoch_rank = USHORT_MAX;
  g_states.prev_epoch_slot = ULONG_MAX;
  g_states.curr_epoch_info = NULL;
  g_states.curr_epoch_rank = USHORT_MAX;
  g_states.curr_epoch_slot = 0UL;
  g_states.next_epoch_info = NULL;
  g_states.next_epoch_rank = USHORT_MAX;
  g_states.next_epoch_slot = ULONG_MAX;
  void * notar_hash_stake_pool_mem          = aligned_alloc( ag_vote_stake_pool_align(), ag_vote_stake_pool_footprint( AG_VAT_MAX                                                  ) );
  void * notar_hash_stake_map_mem           = aligned_alloc( ag_vote_stake_map_align(),  ag_vote_stake_map_footprint ( ag_vote_stake_map_chain_cnt_est( AG_VAT_MAX                 ) ) );
  void * notar_fallback_hash_stake_pool_mem = aligned_alloc( ag_vote_stake_pool_align(), ag_vote_stake_pool_footprint( AG_NOTAR_FALLBACK_HASH_MAX                                  ) );
  void * notar_fallback_hash_stake_map_mem  = aligned_alloc( ag_vote_stake_map_align(),  ag_vote_stake_map_footprint ( ag_vote_stake_map_chain_cnt_est( AG_NOTAR_FALLBACK_HASH_MAX ) ) );
  FD_TEST( notar_hash_stake_pool_mem && notar_hash_stake_map_mem && notar_fallback_hash_stake_pool_mem && notar_fallback_hash_stake_map_mem );
  g_states.notar_hash_stake_pool          = ag_vote_stake_pool_join( ag_vote_stake_pool_new( notar_hash_stake_pool_mem,          AG_VAT_MAX                                                                         ) );
  g_states.notar_hash_stake_map           = ag_vote_stake_map_join ( ag_vote_stake_map_new ( notar_hash_stake_map_mem,           ag_vote_stake_map_chain_cnt_est( AG_VAT_MAX                 ), TEST_HASH_STAKE_SEED ) );
  g_states.notar_fallback_hash_stake_pool = ag_vote_stake_pool_join( ag_vote_stake_pool_new( notar_fallback_hash_stake_pool_mem, AG_NOTAR_FALLBACK_HASH_MAX                                                         ) );
  g_states.notar_fallback_hash_stake_map  = ag_vote_stake_map_join ( ag_vote_stake_map_new ( notar_fallback_hash_stake_map_mem,  ag_vote_stake_map_chain_cnt_est( AG_NOTAR_FALLBACK_HASH_MAX ), TEST_HASH_STAKE_SEED ) );

  test_add_cert();
  test_add_vote();
  test_safe_to_notar();
  test_slashable_skip_and_notarize();
  test_slashable_notar_different_hash();
  test_slashable_skip_and_finalize();
  test_slashable_notar_fallback_and_finalize();
  test_slashable_offence_none();
  test_should_ignore_duplicate_votes();
  test_null_ignores_stale_sigs();
  test_count_finalize_creates_cert_at_quorum();
  test_count_notar_fallback_creates_cert_at_quorum();
  test_poisoned_notar_aggregate();
  test_identity_partition();
  test_safe_to_events_verify();
  test_safe_to_skip_removes_forged_notar();
  test_map_capacity();
  test_safe_to_skip_removes_chain_mate();
  test_safe_to_skip_removes_head_middle_tail();
  test_notar_fallback_removes_head_middle_tail();
  test_skip_skip_fallback_conflict();
  test_notar_notar_fallback_conflict();

  test_set_insert_contains_iter();

  test_notar_stake_tally();
  test_notar_fallback_stake_tally();

  test_pool_ids_stable();

  free( fd_bls_sig_pool_delete( fd_bls_sig_pool_leave( g_bls_sig_pool ) ) );
  free( ag_vote_stake_pool_delete( ag_vote_stake_pool_leave( g_states.notar_hash_stake_pool          ) ) );
  free( ag_vote_stake_map_delete ( ag_vote_stake_map_leave ( g_states.notar_hash_stake_map           ) ) );
  free( ag_vote_stake_pool_delete( ag_vote_stake_pool_leave( g_states.notar_fallback_hash_stake_pool ) ) );
  free( ag_vote_stake_map_delete ( ag_vote_stake_map_leave ( g_states.notar_fallback_hash_stake_map  ) ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
