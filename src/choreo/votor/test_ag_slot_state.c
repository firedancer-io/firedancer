#include "ag_slot_state.c"

#define TEST_SHRED_VERSION ((ushort)514)

#include <stdlib.h>

#define VAT_MAX 64UL /* smaller for tests */

static ag_slot_state_t slot_state_mem;

static ag_slot_state_cert_builder_t g_scratch;

static ag_bls_sec_t        g_sk  [ VAT_MAX ];
static ag_validator_info_t g_info[ VAT_MAX ];

static void
generate_validators( ulong n ) {
  FD_TEST( n<=VAT_MAX );
  for( ulong i=0UL; i<n; i++ ) {
    fd_memset( g_sk[i], (int)(i*7UL+1UL), AG_BLS_SEC_SZ );
    memset( &g_info[i], 0, sizeof(ag_validator_info_t) );
    g_info[i].id    = i;
    g_info[i].stake = 1UL;
    ag_bls_sec_to_pub( g_sk[i], &g_info[i].bls_key );
  }
}

static ag_epoch_info_t *
make_epoch( ulong   n,
            void ** out_mem ) {
  ag_epoch_info_t * epoch_info = aligned_alloc( alignof(ag_epoch_info_t), sizeof(ag_epoch_info_t) );
  FD_TEST( epoch_info );
  *out_mem = epoch_info;
  ag_epoch_info( epoch_info, g_info, n );
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

static ag_slot_state_t *
make_state( ulong                   slot,
            ag_epoch_info_t const * epoch_info ) {
  ag_slot_state_t * slot_state = &slot_state_mem;
  ag_slot_state_zero( slot_state, slot, epoch_info, 0UL );
  slot_state->cert_builder = &g_scratch;
  return slot_state;
}

typedef struct {
  ag_slot_state_outputs_t o;
} out_t;

static void
add_vote_helper( ag_slot_state_t *       ss,
                 ag_vote_t const *       vote,
                 ag_epoch_info_t const * epoch_info,
                 out_t *                 t ) {
  ulong stake = ag_epoch_info_validator( epoch_info, ag_vote_rank( vote ) )->stake;
  t->o = ag_slot_state_add_vote( ss, vote, stake );
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
  for( ulong i=0UL; i<n; i++ ) nv[i] = ag_vote_construct_notar( slot, hash, g_sk[i], (ushort)i, TEST_SHRED_VERSION ).notar;
  ag_cert_t c = ag_cert_construct_notar( nv, n, epoch_info );

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
    ag_vote_t vote = ag_vote_construct_notar( slot, hash, g_sk[i], (ushort)i, TEST_SHRED_VERSION );
    FD_TEST( ss->votes.notar[i].slot==ULONG_MAX );
    add_vote_helper( ss, &vote, epoch_info, &t );
    FD_TEST( ss->votes.notar[i].slot==slot );
    FD_TEST(  ag_slot_state_stake( ss->voted_stakes.notar, ss->voted_stakes.notar_cnt, hash )==i+1UL );
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
  ag_slot_state_notify_parent_certified( ss, hash );

  ag_vote_t notar_vote = ag_vote_construct_notar( slot, hash, g_sk[1], 1UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &notar_vote, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==0UL );
  FD_TEST( t.o.votor_events_cnt==0UL );
  FD_TEST( t.o.block_to_repair_cnt==0UL );

  ag_vote_t skip_vote = ag_vote_construct_skip( slot, g_sk[0], 0UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &skip_vote, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==0UL );
  FD_TEST( t.o.votor_events_cnt==1UL );
  FD_TEST( t.o.block_to_repair_cnt==0UL );
  FD_TEST( t.o.votor_events[0].kind==AG_EVENT_POOL_SAFE_TO_NOTAR );
  FD_TEST( t.o.votor_events[0].safe_to_notar.slot==slot );
  FD_TEST( !memcmp( t.o.votor_events[0].safe_to_notar.hash, hash, sizeof(ag_block_hash_t) ) );

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

  ag_vote_t s1 = ag_vote_construct_skip( slot, g_sk[1], 1UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &s1, epoch_info, &t );
  ag_vote_t notar_vote = ag_vote_construct_notar( slot, hash, g_sk[1], 1UL, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &notar_vote )==AG_SLASHABLE_SKIP_AND_NOTARIZE );

  ag_vote_t n2 = ag_vote_construct_notar( slot, hash, g_sk[2], 2UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &n2, epoch_info, &t );
  ag_vote_t skip_vote = ag_vote_construct_skip( slot, g_sk[2], 2UL, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &skip_vote )==AG_SLASHABLE_SKIP_AND_NOTARIZE );

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

  ag_vote_t notar_a = ag_vote_construct_notar( slot, hash_a, g_sk[1], 1UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &notar_a, epoch_info, &t );

  ag_vote_t notar_b = ag_vote_construct_notar( slot, hash_b, g_sk[1], 1UL, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &notar_b )==AG_SLASHABLE_NOTAR_DIFFERENT_HASH );

  FD_TEST( ag_slot_state_check_slashable_offence( ss, &notar_a )==AG_SLASHABLE_NONE );

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

  ag_vote_t f1 = ag_vote_construct_final( slot, g_sk[1], 1UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &f1, epoch_info, &t );
  ag_vote_t s1 = ag_vote_construct_skip( slot, g_sk[1], 1UL, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &s1 )==AG_SLASHABLE_SKIP_AND_FINALIZE );
  ag_vote_t sf1 = ag_vote_construct_skip_fallback( slot, g_sk[1], 1UL, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &sf1 )==AG_SLASHABLE_SKIP_AND_FINALIZE );

  ag_vote_t s2 = ag_vote_construct_skip( slot, g_sk[2], 2UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &s2, epoch_info, &t );
  ag_vote_t f2 = ag_vote_construct_final( slot, g_sk[2], 2UL, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &f2 )==AG_SLASHABLE_SKIP_AND_FINALIZE );

  ag_vote_t sf3 = ag_vote_construct_skip_fallback( slot, g_sk[3], 3UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &sf3, epoch_info, &t );
  ag_vote_t f3 = ag_vote_construct_final( slot, g_sk[3], 3UL, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &f3 )==AG_SLASHABLE_SKIP_AND_FINALIZE );

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

  ag_vote_t f1 = ag_vote_construct_final( slot, g_sk[1], 1UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &f1, epoch_info, &t );
  ag_vote_t nf1 = ag_vote_construct_notar_fallback( slot, hash, g_sk[1], 1UL, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &nf1 )==AG_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE );

  ag_vote_t nf2 = ag_vote_construct_notar_fallback( slot, hash, g_sk[2], 2UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &nf2, epoch_info, &t );
  ag_vote_t f2 = ag_vote_construct_final( slot, g_sk[2], 2UL, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &f2 )==AG_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE );

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

  ag_vote_t notar_vote = ag_vote_construct_notar( slot, hash, g_sk[1], (ushort)v, TEST_SHRED_VERSION );
  ag_vote_t skip_vote = ag_vote_construct_skip( slot, g_sk[1], (ushort)v, TEST_SHRED_VERSION );
  ag_vote_t final_vote = ag_vote_construct_final( slot, g_sk[1], (ushort)v, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &notar_vote )==AG_SLASHABLE_NONE );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &skip_vote )==AG_SLASHABLE_NONE );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &final_vote )==AG_SLASHABLE_NONE );

  add_vote_helper( ss, &notar_vote, epoch_info, &t );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &final_vote )==AG_SLASHABLE_NONE );

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

  ag_vote_t v1n = ag_vote_construct_notar( slot, hash, g_sk[1], 1UL, TEST_SHRED_VERSION );
  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &v1n ) );

  add_vote_helper( ss, &v1n, epoch_info, &t );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &v1n ) );
  ag_vote_t v1n_other = ag_vote_construct_notar( slot, other_hash, g_sk[1], 1UL, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &v1n_other ) );

  ag_vote_t v2s = ag_vote_construct_skip( slot, g_sk[2], 2UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &v2s, epoch_info, &t );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &v2s ) );
  ag_vote_t v2sf = ag_vote_construct_skip_fallback( slot, g_sk[2], 2UL, TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &v2sf ) );

  ag_vote_t v3f = ag_vote_construct_final( slot, g_sk[3], 3UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &v3f, epoch_info, &t );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &v3f ) );

  ag_vote_t v4nf = ag_vote_construct_notar_fallback( slot, hash, g_sk[4], 4UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &v4nf, epoch_info, &t );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &v4nf ) );
  ag_vote_t v4nf_other = ag_vote_construct_notar_fallback( slot, other_hash, g_sk[4], 4UL, TEST_SHRED_VERSION );
  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &v4nf_other ) );

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
    ag_vote_t fv = ag_vote_construct_final( slot, g_sk[i], (ushort)i, TEST_SHRED_VERSION );
    add_vote_helper( ss, &fv, epoch_info, &t );
    FD_TEST( t.o.certs_cnt==0UL );
    FD_TEST( t.o.votor_events_cnt==0UL );
    FD_TEST( t.o.block_to_repair_cnt==0UL );
  }

  ag_vote_t fv4 = ag_vote_construct_final( slot, g_sk[4], 4UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &fv4, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==1UL );
  FD_TEST( t.o.certs[0].kind==AG_CERT_KIND_FINAL );

  ag_slot_state_add_cert( ss, &t.o.certs[0] );
  ag_vote_t fv5 = ag_vote_construct_final( slot, g_sk[5], 5UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &fv5, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==0UL );

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
    ag_vote_t nv = ag_vote_construct_notar( slot, hash, g_sk[i], (ushort)i, TEST_SHRED_VERSION );
    add_vote_helper( ss, &nv, epoch_info, &t );
    FD_TEST( t.o.certs_cnt==0UL );
  }

  ag_vote_t nf3 = ag_vote_construct_notar_fallback( slot, hash, g_sk[3], 3UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &nf3, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==0UL );
  FD_TEST( t.o.votor_events_cnt==0UL );
  FD_TEST( t.o.block_to_repair_cnt==0UL );
  FD_TEST( ag_slot_state_stake( ss->voted_stakes.notar_fallback, ss->voted_stakes.notar_fallback_cnt, hash )==1UL );

  ag_vote_t nf4 = ag_vote_construct_notar_fallback( slot, hash, g_sk[4], 4UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &nf4, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==1UL );
  FD_TEST( t.o.certs[0].kind==AG_CERT_KIND_NOTAR_FALLBACK );
  FD_TEST( ag_cert_block_hash( &t.o.certs[0] ) && !memcmp( ag_cert_block_hash( &t.o.certs[0] ), hash, sizeof(ag_block_hash_t) ) );

  ag_slot_state_add_cert( ss, &t.o.certs[0] );
  ag_vote_t nf5 = ag_vote_construct_notar_fallback( slot, hash, g_sk[5], 5UL, TEST_SHRED_VERSION );
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

  ag_vote_t skip = ag_vote_construct_skip( slot, g_sk[v], (ushort)v, TEST_SHRED_VERSION );
  ag_vote_t skip_fallback = ag_vote_construct_skip_fallback( slot, g_sk[v], (ushort)v, TEST_SHRED_VERSION );

  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &skip          ) );
  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &skip_fallback ) );

  add_vote_helper( ss, &skip, epoch_info, &t );

  FD_TEST( ag_slot_state_should_ignore_vote( ss, &skip_fallback ) );

  FD_TEST( ag_slot_state_should_ignore_vote( ss, &skip ) );

  FD_TEST( ag_slot_state_check_slashable_offence( ss, &skip_fallback )==AG_SLASHABLE_NONE );

  ag_slot_state_zero( ss, slot, epoch_info, 0UL );
  ss->cert_builder = &g_scratch;
  add_vote_helper( ss, &skip_fallback, epoch_info, &t );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &skip          ) );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &skip_fallback ) );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &skip )==AG_SLASHABLE_NONE );

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

  ag_vote_t notar = ag_vote_construct_notar( slot, hash, g_sk[v], (ushort)v, TEST_SHRED_VERSION );
  ag_vote_t notar_fallback = ag_vote_construct_notar_fallback( slot, hash, g_sk[v], (ushort)v, TEST_SHRED_VERSION );
  ag_vote_t nf_other = ag_vote_construct_notar_fallback( slot, other_hash, g_sk[v], (ushort)v, TEST_SHRED_VERSION );

  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &notar          ) );
  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &notar_fallback ) );

  add_vote_helper( ss, &notar, epoch_info, &t );

  FD_TEST( ag_slot_state_should_ignore_vote( ss, &notar_fallback ) );

  FD_TEST( ag_slot_state_should_ignore_vote( ss, &notar ) );

  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &nf_other ) );

  FD_TEST( ag_slot_state_check_slashable_offence( ss, &notar_fallback )==AG_SLASHABLE_NONE );

  ag_slot_state_zero( ss, slot, epoch_info, 0UL );
  ss->cert_builder = &g_scratch;
  add_vote_helper( ss, &notar_fallback, epoch_info, &t );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &notar          ) );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &notar_fallback ) );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &notar )==AG_SLASHABLE_NONE );

  free( em );
}

/* src/consensus/pool/sorted_vec.rs::set_insert_contains_iter */

static void
test_set_insert_contains_iter( void ) {
  ag_block_hash_t h1, h3, h5, h2;
  random_hash( h1 ); random_hash( h3 ); random_hash( h5 ); random_hash( h2 );

  ag_hash_set_t set; set.cnt = 0UL;

  set_insert( &set, h3 ); FD_TEST( set.cnt==1UL );
  set_insert( &set, h1 ); FD_TEST( set.cnt==2UL );
  set_insert( &set, h5 ); FD_TEST( set.cnt==3UL );
  set_insert( &set, h3 ); FD_TEST( set.cnt==3UL );

  FD_TEST(  set_contains( &set, h1 ) );
  FD_TEST( !set_contains( &set, h2 ) );

  set_remove( &set, h1 ); FD_TEST( set.cnt==2UL );
  set_remove( &set, h1 ); FD_TEST( set.cnt==2UL );
  FD_TEST( !set_contains( &set, h1 ) );

  FD_TEST( set_contains( &set, h3 ) );
  FD_TEST( set_contains( &set, h5 ) );
}

static void
assert_tally( ag_hashstake_t const * ele,
              ulong                  cnt,
              uchar const * const *  hash,
              ulong const *          stake,
              ulong                  expected_cnt ) {
  FD_TEST( cnt==expected_cnt );
  for( ulong i=0UL; i<expected_cnt; i++ ) { /* the tally is unordered, so search for each hash */
    ulong j;
    for( j=0UL; j<cnt; j++ ) if( !memcmp( ele[j].hash, hash[i], sizeof(ag_block_hash_t) ) ) break;
    FD_TEST( j<cnt );
    FD_TEST( ele[j].stake==stake[i] );
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
  ag_hashstake_t const * tally = ss->voted_stakes.notar;

  ulong rank = 0UL;
  ag_vote_t v;
  v = ag_vote_construct_notar( slot, a, g_sk[rank], (ushort)rank, TEST_SHRED_VERSION ); rank++;
  add_vote_helper( ss, &v, epoch_info, &t );
  assert_tally( tally, ss->voted_stakes.notar_cnt, (uchar const *[]){ a }, (ulong[]){ 1UL }, 1UL );

  v = ag_vote_construct_notar( slot, b, g_sk[rank], (ushort)rank, TEST_SHRED_VERSION ); rank++;
  add_vote_helper( ss, &v, epoch_info, &t );
  assert_tally( tally, ss->voted_stakes.notar_cnt, (uchar const *[]){ a, b }, (ulong[]){ 1UL, 1UL }, 2UL );

  v = ag_vote_construct_notar( slot, b, g_sk[rank], (ushort)rank, TEST_SHRED_VERSION ); rank++;
  add_vote_helper( ss, &v, epoch_info, &t );
  assert_tally( tally, ss->voted_stakes.notar_cnt, (uchar const *[]){ b, a }, (ulong[]){ 2UL, 1UL }, 2UL );

  for( ulong i=0UL; i<3UL; i++ ) {
    v = ag_vote_construct_notar( slot, c, g_sk[rank], (ushort)rank, TEST_SHRED_VERSION ); rank++;
    add_vote_helper( ss, &v, epoch_info, &t );
  }
  assert_tally( tally, ss->voted_stakes.notar_cnt, (uchar const *[]){ c, b, a }, (ulong[]){ 3UL, 2UL, 1UL }, 3UL );

  for( ulong i=0UL; i<4UL; i++ ) {
    v = ag_vote_construct_notar( slot, d, g_sk[rank], (ushort)rank, TEST_SHRED_VERSION ); rank++;
    add_vote_helper( ss, &v, epoch_info, &t );
  }
  FD_TEST( rank<=n );
  assert_tally( tally, ss->voted_stakes.notar_cnt, (uchar const *[]){ d, c, b, a }, (ulong[]){ 4UL, 3UL, 2UL, 1UL }, 4UL );
  FD_TEST( ss->voted_stakes.top_notar==4UL ); /* d, the most supported hash */

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
    ag_vote_t v = ag_vote_construct_notar_fallback( slot, own[i], g_sk[0], 0UL, TEST_SHRED_VERSION );
    FD_TEST( ss->votes.notar_fallback_cnt[ 0 ]<AG_NOTAR_FALLBACK_VOTE_MAX );
    add_vote_helper( ss, &v, epoch_info, &t );
    FD_TEST( ss->voted_stakes.notar_fallback_cnt==i+1UL );
  }

  /* the cap itself is enforced in ag_pool_add_vote; see test_ag_pool */
  FD_TEST( ss->votes.notar_fallback_cnt[ 0 ]==AG_NOTAR_FALLBACK_VOTE_MAX );

  for( ulong i=0UL; i<2UL; i++ ) {
    ag_vote_t v = ag_vote_construct_notar_fallback( slot, own[2], g_sk[1UL+i], (ushort)(1UL+i), TEST_SHRED_VERSION );
    add_vote_helper( ss, &v, epoch_info, &t );
  }
  ag_vote_t v_mid = ag_vote_construct_notar_fallback( slot, own[1], g_sk[3], 3UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &v_mid, epoch_info, &t );

  assert_tally( ss->voted_stakes.notar_fallback, ss->voted_stakes.notar_fallback_cnt,
                (uchar const *[]){ own[2], own[1], own[0] }, (ulong[]){ 3UL, 2UL, 1UL }, 3UL );

  free( em );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_add_cert();
  test_add_vote();
  test_safe_to_notar();
  test_slashable_skip_and_notarize();
  test_slashable_notar_different_hash();
  test_slashable_skip_and_finalize();
  test_slashable_notar_fallback_and_finalize();
  test_slashable_offence_none();
  test_should_ignore_duplicate_votes();
  test_count_finalize_creates_cert_at_quorum();
  test_count_notar_fallback_creates_cert_at_quorum();
  test_skip_skip_fallback_conflict();
  test_notar_notar_fallback_conflict();

  test_set_insert_contains_iter();

  test_notar_stake_tally();
  test_notar_fallback_stake_tally();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
