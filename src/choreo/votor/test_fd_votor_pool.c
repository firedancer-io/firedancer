#define _GNU_SOURCE
#include "fd_votor_pool.c"
#include "test_fd_cert_builder.h"
#include "fd_cert_serde.h"
#include "fd_vote_serde.h"

#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>

/* Slot state */

#define STATE_SHRED_VERSION  ((ushort)514)
#define TEST_HASH_STAKE_SEED (42UL)

#define VAT_MAX 200UL /* smaller for tests, still spans 4 sig pages */

static slot_state_t  slot_state_mem;
static slot_states_t g_states;

static uchar        g_sig_pg[ SLOT_SIG_PG_MAX*SIG_PG_SZ ];
static uint         g_sig_pg_free[ SLOT_SIG_PG_MAX ];
static int          g_disk; /* 0 all sig pages in RAM, 1 all in the spill file, 2 one RAM page then spill */
static fd_bls_sec_t        g_state_sk  [ VAT_MAX ];
static fd_validator_info_t g_state_info[ VAT_MAX ];
static void
generate_validators( ulong n ) {
  FD_TEST( n<=VAT_MAX );
  for( ulong i=0UL; i<n; i++ ) {
    fd_memset( &g_state_sk[i], (int)(i*7UL+1UL), FD_BLS_SEC_SZ );
    if( i>=12UL ) { fd_memset( &g_state_sk[i], 0, FD_BLS_SEC_SZ ); ((uchar *)&g_state_sk[i])[ 16 ] = (uchar)i; } /* 7i+1 bytes can exceed the group order */
    memset( &g_state_info[i], 0, sizeof(fd_validator_info_t) );
    g_state_info[i].id    = i;
    g_state_info[i].stake = 1UL;
    bls_key_from_sec( g_state_info[i].bls_key, &g_state_sk[i] );
  }
}

static fd_epoch_info_t *
make_epoch( ulong   n,
            void ** out_mem ) {
  fd_epoch_info_t * epoch_info = aligned_alloc( alignof(fd_epoch_info_t), sizeof(fd_epoch_info_t) );
  FD_TEST( epoch_info );
  *out_mem = epoch_info;
  epoch_info_build( epoch_info, g_state_info, n );
  return epoch_info;
}

static void
state_random_hash( fd_block_hash_t * out ) {
  static ulong ctr = 1UL;
  memset( out, 0, sizeof(fd_block_hash_t) );
  ctr += 0x9E3779B97F4A7C15UL;
  memcpy( out, &ctr, sizeof(ulong) );
  out->uc[ 31 ] = 0xAB;
}

static ulong
hash_stake_cnt( slot_state_t const * ss,
                int                     nf ) {
  hash_stakes_t const * tbl = nf ? &ss->votes.notar_fallback_hash_stake : &ss->votes.notar_hash_stake;
  return (ulong)fd_uint_popcnt( tbl->used )+tbl->spill_cnt;
}




static ulong
notar_hash_stake_query( slot_state_t const *    ss,
                        fd_block_hash_t const * hash ) {
  ulong id = hash_stake_query( ss, g_states.spill_fd, 0, hash );
  return id==ULONG_MAX ? ULONG_MAX : hash_stake_get( ss, g_states.spill_fd, 0, id, NULL );
}

static ulong
notar_fallback_hash_stake_query( slot_state_t const *    ss,
                                 fd_block_hash_t const * hash ) {
  ulong id = hash_stake_query( ss, g_states.spill_fd, 1, hash );
  return id==ULONG_MAX ? ULONG_MAX : hash_stake_get( ss, g_states.spill_fd, 1, id, NULL );
}

static void
assert_maps_empty( slot_state_t const * ss ) {
  FD_TEST( !ss->votes.notar_hash_stake.used          && !ss->votes.notar_hash_stake.spill_cnt          && !ss->votes.notar_hash_stake.spill_hwm          );
  FD_TEST( !ss->votes.notar_fallback_hash_stake.used && !ss->votes.notar_fallback_hash_stake.spill_cnt && !ss->votes.notar_fallback_hash_stake.spill_hwm );
}

static slot_state_t *
make_state( ulong                   slot,
            fd_epoch_info_t const * epoch_info ) {
  slot_state_t * slot_state = &slot_state_mem;
  slot_state_null( slot_state, &g_states );
  assert_maps_empty( slot_state );
  g_states.curr_epoch_info = epoch_info;

  slot_state->slot     = slot;
  slot_state->own_rank = 0UL;
  return slot_state;
}

static fd_bls_agg_t *
state_notar_agg( slot_state_t const *    state,
                 fd_block_hash_t const * hash,
                 fd_bls_agg_t *          agg ) {
  fd_bls_set_t set[ fd_bls_set_word_cnt ];
  fd_bls_set_null( set );
  for( ulong rank=0UL; rank<FD_VOTOR_VAT_MAX; rank++ ) {
    if( FD_LIKELY( fd_bls_set_test( state->votes.notar_set, rank ) && hash_stake_eq( state, g_states.spill_fd, 0, state->votes.notar_hash_stake_idx[ rank ], hash ) ) ) fd_bls_set_insert( set, rank );
  }
  fd_bls_sig_t sigs[ FD_VOTOR_VAT_MAX ];
  slot_state_sigs( state, &g_states, FD_VOTE_KIND_NOTAR, hash, set, sigs );
  fd_bls_agg_null( agg );
  return fd_bls_agg_construct( agg, g_states.curr_epoch_info->pubkeys, sigs, set );
}

/* Every inline running sig sum equals the sum of its votes' stored
   sigs, bad ones subtracted. */

static void
check_sig_sums( slot_state_t const * ss ) {
  for( int nf=0; nf<2; nf++ ) {
    hash_stakes_t const * tbl = nf ? &ss->votes.notar_fallback_hash_stake : &ss->votes.notar_hash_stake;
    for( uint m=tbl->used; m; m=fd_uint_pop_lsb( m ) ) {
      ulong id = (ulong)fd_uint_find_lsb( m );
      fd_bls_set_t set[ fd_bls_set_word_cnt ]; fd_bls_set_null( set );
      for( ulong rank=0UL; rank<FD_VOTOR_VAT_MAX; rank++ ) {
        if( !nf ) { if( fd_bls_set_test( ss->votes.notar_set, rank ) && ss->votes.notar_hash_stake_idx[ rank ]==id ) fd_bls_set_insert( set, rank ); continue; }
        for( ulong j=0UL; j<ss->votes.notar_fallback_sig_cnt[ rank ]; j++ ) if( ss->votes.notar_fallback_hash_stake_idx[ rank ][ j ]==id ) fd_bls_set_insert( set, rank );
      }
      fd_bls_sig_t sigs[ FD_VOTOR_VAT_MAX ];
      slot_state_sigs( ss, &g_states, nf ? FD_VOTE_KIND_NOTAR_FALLBACK : FD_VOTE_KIND_NOTAR, &tbl->ele[ id ].hash, set, sigs );
      fd_bls_agg_t agg[1]; fd_bls_agg_null( agg );
      fd_bls_agg_construct( agg, g_states.curr_epoch_info->pubkeys, sigs, set );
      FD_TEST( fd_bls_sig_eq( &agg->sig, &tbl->sig_sum[ id ] ) );
    }
  }
}

typedef struct {
  struct {
    fd_cert_t     certs          [ SLOT_STATE_OUT_CERT_MAX   ]; ulong certs_cnt;
    fd_block_id_t safe_to_notar  [ SLOT_STATE_OUT_EVENT_MAX  ]; ulong safe_to_notar_cnt;
    ulong         safe_to_skip   [ SLOT_STATE_OUT_EVENT_MAX  ]; ulong safe_to_skip_cnt;
    fd_block_id_t block_to_repair[ SLOT_STATE_OUT_REPAIR_MAX ]; ulong block_to_repair_cnt;
    fd_bls_set_t  bad            [ fd_bls_set_word_cnt       ];
  } o;
  int ok;
} out_t;

static void
add_vote_helper( slot_state_t *       ss,
                 fd_vote_t const *       vote,
                 fd_epoch_info_t const * epoch_info,
                 out_t *                 t ) {
  ulong stake = fd_epoch_info_validator( epoch_info, fd_vote_rank( vote ) )->stake;
  t->ok = slot_state_add_vote( ss, &g_states, vote, stake, t->o.certs, &t->o.certs_cnt, t->o.safe_to_notar, &t->o.safe_to_notar_cnt, t->o.safe_to_skip, &t->o.safe_to_skip_cnt, t->o.block_to_repair, &t->o.block_to_repair_cnt, t->o.bad );
  check_sig_sums( ss );
  ulong ram = 0UL, disk = 0UL;
  for( ulong ks=0UL; ks<FD_VOTOR_VOTES_PER_SLOT_MAX; ks++ ) for( ulong w=0UL; w<fd_bls_set_word_cnt; w++ ) { uint pg = ss->sig_pg[ ks ][ w ]; ram += pg && pg!=SIG_PG_DISK; disk += pg==SIG_PG_DISK; }
  switch( g_disk ) {
  case 0: FD_TEST( !disk && ram+g_states.sig_pg_free_cnt==SLOT_SIG_PG_MAX ); break;
  case 1: FD_TEST( !ram && disk );                                              break;
  case 2: FD_TEST( ram==1UL && !g_states.sig_pg_free_cnt );                     break;
  }
}

/* src/consensus/pool/slot_state.rs::add_cert */

static void
test_add_cert( void ) {
  ulong n = 11UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_block_hash_t hash; state_random_hash( &hash );
  slot_state_t * ss = make_state( slot, epoch_info );

  fd_vote_notar_t nv[ 11 ];
  for( ulong i=0UL; i<n; i++ ) nv[i] = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[i], test_bls_public_key, slot, &hash, (ushort)i, STATE_SHRED_VERSION ).notar;
  fd_cert_t c = cert_build_notar( nv, n, epoch_info );

  FD_TEST( ss->certs.notar.slot==ULONG_MAX );
  slot_state_add_cert( ss, &c );
  FD_TEST( ss->certs.notar.slot==slot );

  free( em );
}

/* src/consensus/pool/slot_state.rs::add_vote */

static void
test_add_vote( void ) {
  ulong n = 11UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_block_hash_t hash; state_random_hash( &hash );
  slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;

  for( ulong i=0UL; i<n; i++ ) {
    fd_vote_t vote = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[i], test_bls_public_key, slot, &hash, (ushort)i, STATE_SHRED_VERSION );
    FD_TEST( !fd_bls_set_test( ss->votes.notar_set, i ) );
    add_vote_helper( ss, &vote, epoch_info, &t );
    FD_TEST( fd_bls_set_test( ss->votes.notar_set, i ) && hash_stake_eq( ss, g_states.spill_fd, 0, ss->votes.notar_hash_stake_idx[ i ], &hash ) );
    FD_TEST( notar_hash_stake_query( ss, &hash )==i+1UL );
  }

  free( em );
}

/* src/consensus/pool/slot_state.rs::safe_to_notar */

static void
test_safe_to_notar( void ) {
  ulong n = 3UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_block_hash_t hash; state_random_hash( &hash );
  slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;

  slot_state_notify_parent_known( ss, &g_states, &hash, t.o.bad );
  slot_state_notify_parent_certified( ss, &g_states, &hash, t.o.bad );

  fd_vote_t notar_vote = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[1], test_bls_public_key, slot, &hash, 1UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &notar_vote, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==0UL );
  FD_TEST( t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL );
  FD_TEST( t.o.block_to_repair_cnt==0UL );

  fd_vote_t skip_vote = fd_vote_construct_skip( sec_sign_fn, &g_state_sk[0], test_bls_public_key, slot, 0UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &skip_vote, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==0UL );
  FD_TEST( t.o.safe_to_notar_cnt==1UL && t.o.safe_to_skip_cnt==0UL );
  FD_TEST( t.o.block_to_repair_cnt==0UL );
  FD_TEST( t.o.safe_to_notar[0].slot==slot );
  FD_TEST( !memcmp( &t.o.safe_to_notar[0].hash, &hash, sizeof(fd_block_hash_t) ) );

  free( em );
}

/* src/consensus/pool/slot_state.rs::slashable_skip_and_notarize */

static void
test_slashable_skip_and_notarize( void ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_block_hash_t hash; state_random_hash( &hash );
  slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;

  fd_vote_t s1 = fd_vote_construct_skip( sec_sign_fn, &g_state_sk[1], test_bls_public_key, slot, 1UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &s1, epoch_info, &t );
  fd_vote_t notar_vote = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[1], test_bls_public_key, slot, &hash, 1UL, STATE_SHRED_VERSION );
  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &notar_vote )==SLASHABLE_OFFENCE_SKIP_AND_NOTARIZE );

  fd_vote_t n2 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[2], test_bls_public_key, slot, &hash, 2UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &n2, epoch_info, &t );
  fd_vote_t skip_vote = fd_vote_construct_skip( sec_sign_fn, &g_state_sk[2], test_bls_public_key, slot, 2UL, STATE_SHRED_VERSION );
  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &skip_vote )==SLASHABLE_OFFENCE_SKIP_AND_NOTARIZE );

  free( em );
}

/* src/consensus/pool/slot_state.rs::slashable_notar_different_hash */

static void
test_slashable_notar_different_hash( void ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_block_hash_t hash_a; state_random_hash( &hash_a );
  fd_block_hash_t hash_b; state_random_hash( &hash_b );
  slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;

  fd_vote_t notar_a = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[1], test_bls_public_key, slot, &hash_a, 1UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &notar_a, epoch_info, &t );

  fd_vote_t notar_b = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[1], test_bls_public_key, slot, &hash_b, 1UL, STATE_SHRED_VERSION );
  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &notar_b )==SLASHABLE_OFFENCE_NOTAR_DIFFERENT_HASH );

  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &notar_a )==SLASHABLE_OFFENCE_NONE );

  free( em );
}

/* src/consensus/pool/slot_state.rs::slashable_skip_and_finalize */

static void
test_slashable_skip_and_finalize( void ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;

  fd_vote_t f1 = fd_vote_construct_final( sec_sign_fn, &g_state_sk[1], test_bls_public_key, slot, 1UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &f1, epoch_info, &t );
  fd_vote_t s1 = fd_vote_construct_skip( sec_sign_fn, &g_state_sk[1], test_bls_public_key, slot, 1UL, STATE_SHRED_VERSION );
  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &s1 )==SLASHABLE_OFFENCE_SKIP_AND_FINALIZE );
  fd_vote_t sf1 = fd_vote_construct_skip_fallback( sec_sign_fn, &g_state_sk[1], test_bls_public_key, slot, 1UL, STATE_SHRED_VERSION );
  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &sf1 )==SLASHABLE_OFFENCE_SKIP_AND_FINALIZE );

  fd_vote_t s2 = fd_vote_construct_skip( sec_sign_fn, &g_state_sk[2], test_bls_public_key, slot, 2UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &s2, epoch_info, &t );
  fd_vote_t f2 = fd_vote_construct_final( sec_sign_fn, &g_state_sk[2], test_bls_public_key, slot, 2UL, STATE_SHRED_VERSION );
  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &f2 )==SLASHABLE_OFFENCE_SKIP_AND_FINALIZE );

  fd_vote_t sf3 = fd_vote_construct_skip_fallback( sec_sign_fn, &g_state_sk[3], test_bls_public_key, slot, 3UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &sf3, epoch_info, &t );
  fd_vote_t f3 = fd_vote_construct_final( sec_sign_fn, &g_state_sk[3], test_bls_public_key, slot, 3UL, STATE_SHRED_VERSION );
  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &f3 )==SLASHABLE_OFFENCE_SKIP_AND_FINALIZE );

  free( em );
}

/* src/consensus/pool/slot_state.rs::slashable_notar_fallback_and_finalize */

static void
test_slashable_notar_fallback_and_finalize( void ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_block_hash_t hash; state_random_hash( &hash );
  slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;

  fd_vote_t f1 = fd_vote_construct_final( sec_sign_fn, &g_state_sk[1], test_bls_public_key, slot, 1UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &f1, epoch_info, &t );
  fd_vote_t nf1 = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[1], test_bls_public_key, slot, &hash, 1UL, STATE_SHRED_VERSION );
  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &nf1 )==SLASHABLE_OFFENCE_NOTAR_FALLBACK_AND_FINALIZE );

  fd_vote_t nf2 = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[2], test_bls_public_key, slot, &hash, 2UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &nf2, epoch_info, &t );
  fd_vote_t f2 = fd_vote_construct_final( sec_sign_fn, &g_state_sk[2], test_bls_public_key, slot, 2UL, STATE_SHRED_VERSION );
  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &f2 )==SLASHABLE_OFFENCE_NOTAR_FALLBACK_AND_FINALIZE );

  free( em );
}

/* src/consensus/pool/slot_state.rs::slashable_offence_none */

static void
test_slashable_offence_none( void ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_block_hash_t hash; state_random_hash( &hash );
  slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;
  ulong v = 1UL;

  fd_vote_t notar_vote = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[1], test_bls_public_key, slot, &hash, (ushort)v, STATE_SHRED_VERSION );
  fd_vote_t skip_vote = fd_vote_construct_skip( sec_sign_fn, &g_state_sk[1], test_bls_public_key, slot, (ushort)v, STATE_SHRED_VERSION );
  fd_vote_t final_vote = fd_vote_construct_final( sec_sign_fn, &g_state_sk[1], test_bls_public_key, slot, (ushort)v, STATE_SHRED_VERSION );
  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &notar_vote )==SLASHABLE_OFFENCE_NONE );
  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &skip_vote )==SLASHABLE_OFFENCE_NONE );
  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &final_vote )==SLASHABLE_OFFENCE_NONE );

  add_vote_helper( ss, &notar_vote, epoch_info, &t );
  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &final_vote )==SLASHABLE_OFFENCE_NONE );

  free( em );
}

/* src/consensus/pool/slot_state.rs::should_ignore_duplicate_votes */

static void
test_should_ignore_duplicate_votes( void ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_block_hash_t hash;       state_random_hash( &hash       );
  fd_block_hash_t other_hash; state_random_hash( &other_hash );
  slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;

  fd_vote_t v1n = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[1], test_bls_public_key, slot, &hash, 1UL, STATE_SHRED_VERSION );
  FD_TEST( !slot_state_should_ignore_vote( ss, &g_states, &v1n ) );

  add_vote_helper( ss, &v1n, epoch_info, &t );
  FD_TEST( slot_state_should_ignore_vote( ss, &g_states, &v1n ) );
  fd_vote_t v1n_other = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[1], test_bls_public_key, slot, &other_hash, 1UL, STATE_SHRED_VERSION );
  FD_TEST( slot_state_should_ignore_vote( ss, &g_states, &v1n_other ) );

  fd_vote_t v2s = fd_vote_construct_skip( sec_sign_fn, &g_state_sk[2], test_bls_public_key, slot, 2UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &v2s, epoch_info, &t );
  FD_TEST( slot_state_should_ignore_vote( ss, &g_states, &v2s ) );
  fd_vote_t v2sf = fd_vote_construct_skip_fallback( sec_sign_fn, &g_state_sk[2], test_bls_public_key, slot, 2UL, STATE_SHRED_VERSION );
  FD_TEST( slot_state_should_ignore_vote( ss, &g_states, &v2sf ) );

  fd_vote_t v3f = fd_vote_construct_final( sec_sign_fn, &g_state_sk[3], test_bls_public_key, slot, 3UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &v3f, epoch_info, &t );
  FD_TEST( slot_state_should_ignore_vote( ss, &g_states, &v3f ) );

  fd_vote_t v4nf = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[4], test_bls_public_key, slot, &hash, 4UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &v4nf, epoch_info, &t );
  FD_TEST( slot_state_should_ignore_vote( ss, &g_states, &v4nf ) );
  fd_vote_t v4nf_other = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[4], test_bls_public_key, slot, &other_hash, 4UL, STATE_SHRED_VERSION );
  FD_TEST( !slot_state_should_ignore_vote( ss, &g_states, &v4nf_other ) );

  for( ulong i=0UL; i<FD_VOTOR_NOTAR_FALLBACK_VOTE_MAX; i++ ) {
    fd_block_hash_t nf_hash; state_random_hash( &nf_hash );
    fd_vote_t v5nf = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[5], test_bls_public_key, slot, &nf_hash, 5UL, STATE_SHRED_VERSION );
    FD_TEST( !slot_state_should_ignore_vote( ss, &g_states, &v5nf ) );
    add_vote_helper( ss, &v5nf, epoch_info, &t );
  }
  fd_block_hash_t over_hash; state_random_hash( &over_hash );
  fd_vote_t v5nf_over = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[5], test_bls_public_key, slot, &over_hash, 5UL, STATE_SHRED_VERSION );
  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &v5nf_over )==SLASHABLE_OFFENCE_NONE );
  FD_TEST( slot_state_should_ignore_vote( ss, &g_states, &v5nf_over ) );

  free( em );
}

/* slot_state_null leaves the sig block contents alone, so a
   recycled slot state must not read stale signatures as votes. */

static void
test_null_ignores_stale_sigs( void ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_block_hash_t hash; state_random_hash( &hash );
  out_t t;

  slot_state_null( &slot_state_mem, &g_states );
  fd_memset( &slot_state_mem.votes, 0x5a, sizeof(slot_state_mem.votes) );
  fd_memset( slot_state_mem.votes.notar_fallback_sig_cnt, 0, sizeof(slot_state_mem.votes.notar_fallback_sig_cnt) );
  fd_bls_set_null( slot_state_mem.votes.notar_set );
  fd_bls_agg_null( &slot_state_mem.votes.skip_agg          );
  fd_bls_agg_null( &slot_state_mem.votes.skip_fallback_agg );
  fd_bls_agg_null( &slot_state_mem.votes.final_agg      );
  ulong free0 = g_states.sig_pg_free_cnt;
  if( free0 ) slot_state_mem.sig_pg[ 4 ][ 0 ] = g_states.sig_pg_free[ --g_states.sig_pg_free_cnt ]+1U;
  fd_memset( g_sig_pg, 0x5a, sizeof(g_sig_pg) );
  for( ulong rank=0UL; rank<n; rank++ ) {
    slot_state_mem.votes.notar_fallback_sig_cnt[ rank ] = (uchar)FD_VOTOR_NOTAR_FALLBACK_VOTE_MAX;
    fd_bls_set_insert( slot_state_mem.votes.notar_set,              rank );
    fd_bls_set_insert( slot_state_mem.votes.skip_agg.set,          rank );
    fd_bls_set_insert( slot_state_mem.votes.skip_fallback_agg.set, rank );
    fd_bls_set_insert( slot_state_mem.votes.final_agg.set,         rank );
  }
  slot_state_t * ss = make_state( slot, epoch_info );
  assert_maps_empty( ss );
  FD_TEST( fd_bls_set_is_null( ss->votes.notar_set ) && fd_bls_set_is_null( ss->votes.skip_agg.set ) && fd_bls_set_is_null( ss->votes.skip_fallback_agg.set ) && fd_bls_set_is_null( ss->votes.final_agg.set ) );
  for( ulong rank=0UL; rank<FD_VOTOR_VAT_MAX; rank++ ) FD_TEST( !ss->votes.notar_fallback_sig_cnt[ rank ] );
  for( ulong ks=0UL; ks<FD_VOTOR_VOTES_PER_SLOT_MAX; ks++ ) for( ulong w=0UL; w<fd_bls_set_word_cnt; w++ ) FD_TEST( !ss->sig_pg[ ks ][ w ] );
  FD_TEST( g_states.sig_pg_free_cnt==free0 );

  fd_vote_t n1 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[1], test_bls_public_key, slot, &hash, 1UL, STATE_SHRED_VERSION );
  fd_vote_t s1 = fd_vote_construct_skip ( sec_sign_fn, &g_state_sk[1], test_bls_public_key, slot, 1UL,        STATE_SHRED_VERSION );
  fd_vote_t f1 = fd_vote_construct_final( sec_sign_fn, &g_state_sk[1], test_bls_public_key, slot, 1UL,        STATE_SHRED_VERSION );
  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &n1 )==SLASHABLE_OFFENCE_NONE );
  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &s1 )==SLASHABLE_OFFENCE_NONE );
  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &f1 )==SLASHABLE_OFFENCE_NONE );
  FD_TEST( !slot_state_should_ignore_vote( ss, &g_states, &n1 ) );
  FD_TEST( !slot_state_should_ignore_vote( ss, &g_states, &s1 ) );

  add_vote_helper( ss, &n1, epoch_info, &t );
  FD_TEST( t.ok && slot_state_should_ignore_vote( ss, &g_states, &n1 ) );
  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &s1 )==SLASHABLE_OFFENCE_SKIP_AND_NOTARIZE );

  fd_vote_t s2 = fd_vote_construct_skip( sec_sign_fn, &g_state_sk[2], test_bls_public_key, slot, 2UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &s2, epoch_info, &t );
  FD_TEST( t.ok && slot_state_should_ignore_vote( ss, &g_states, &s2 ) );
  fd_vote_t f2 = fd_vote_construct_final( sec_sign_fn, &g_state_sk[2], test_bls_public_key, slot, 2UL, STATE_SHRED_VERSION );
  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &f2 )==SLASHABLE_OFFENCE_SKIP_AND_FINALIZE );

  free( em );
}

/* src/consensus/pool/slot_state.rs::count_finalize_creates_cert_at_quorum */

static void
test_count_finalize_creates_cert_at_quorum( void ) {
  ulong n = VAT_MAX; /* 6 heavy voters on 4 sig pages, the rest stake 0 */
  generate_validators( n );
  static ulong const heavy[ 6 ] = { 0UL, 1UL, 63UL, 64UL, 130UL, 199UL };
  for( ulong i=0UL; i<n; i++ ) g_state_info[ i ].stake = 0UL;
  for( ulong i=0UL; i<6UL; i++ ) g_state_info[ heavy[ i ] ].stake = 1UL;
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;

  for( ulong i=1UL; i<=3UL; i++ ) {
    fd_vote_t fv = fd_vote_construct_final( sec_sign_fn, &g_state_sk[ heavy[ i ] ], test_bls_public_key, slot, (ushort)heavy[ i ], STATE_SHRED_VERSION );
    add_vote_helper( ss, &fv, epoch_info, &t );
    FD_TEST( t.o.certs_cnt==0UL );
    FD_TEST( t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL );
    FD_TEST( t.o.block_to_repair_cnt==0UL );
  }

  fd_vote_t fv4 = fd_vote_construct_final( sec_sign_fn, &g_state_sk[ heavy[ 4 ] ], test_bls_public_key, slot, (ushort)heavy[ 4 ], STATE_SHRED_VERSION );
  add_vote_helper( ss, &fv4, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==1UL );
  FD_TEST( t.o.certs[0].kind==FD_CERT_KIND_FINAL && fd_bls_set_cnt( t.o.certs[0].final.agg.set )==4UL && fd_bls_set_is_null( t.o.bad ) );
  for( ulong i=1UL; i<=4UL; i++ ) {
    fd_bls_sig_t sig;
    fd_vote_t    want = fd_vote_construct_final( sec_sign_fn, &g_state_sk[ heavy[ i ] ], test_bls_public_key, slot, (ushort)heavy[ i ], STATE_SHRED_VERSION );
    FD_TEST( !memcmp( slot_state_vote_sig( ss, &g_states, FD_VOTE_KIND_FINAL, heavy[ i ], 0UL, &sig ), &want.final.sig, sizeof(fd_bls_sig_t) ) );
  }

  slot_state_add_cert( ss, &t.o.certs[0] );
  fd_vote_t fv5 = fd_vote_construct_final( sec_sign_fn, &g_state_sk[ heavy[ 5 ] ], test_bls_public_key, slot, (ushort)heavy[ 5 ], STATE_SHRED_VERSION );
  add_vote_helper( ss, &fv5, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==0UL );

  free( em );
}

static void
test_poisoned_notar_aggregate( void ) {
  ulong n = 11UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 5UL;
  fd_block_hash_t hash; state_random_hash( &hash );
  out_t t;

  slot_state_t * ss = make_state( slot, epoch_info );
  fd_vote_t bad = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[4], test_bls_public_key, slot, &hash, 3UL, STATE_SHRED_VERSION );
  for( ulong i=0UL; i<6UL; i++ ) {
    fd_vote_t v = i==3UL ? bad : fd_vote_construct_notar( sec_sign_fn, &g_state_sk[i], test_bls_public_key, slot, &hash, (ushort)i, STATE_SHRED_VERSION );
    add_vote_helper( ss, &v, epoch_info, &t );
    FD_TEST( t.o.certs_cnt==0UL && t.ok );
  }
  fd_vote_t v6 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[6], test_bls_public_key, slot, &hash, 6UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &v6, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==0UL && t.ok && fd_bls_set_cnt( t.o.bad )==1UL && fd_bls_set_test( t.o.bad, 3UL ) );
  FD_TEST( hash_stake_cnt( ss, 0 )==1UL && notar_hash_stake_query( ss, &hash )==6UL && !fd_bls_set_test( ss->votes.notar_set, 3UL ) );
  fd_vote_t v7 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[7], test_bls_public_key, slot, &hash, 7UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &v7, epoch_info, &t );
  { int has_notar = 0; for( ulong i=0UL; i<t.o.certs_cnt; i++ ) has_notar |= t.o.certs[i].kind==FD_CERT_KIND_NOTAR; FD_TEST( has_notar && t.ok ); }

  ss = make_state( slot, epoch_info );
  for( ulong i=0UL; i<7UL; i++ ) {
    fd_vote_t v = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[i], test_bls_public_key, slot, &hash, (ushort)i, STATE_SHRED_VERSION );
    add_vote_helper( ss, &v, epoch_info, &t );
  }
  int has_notar = 0; for( ulong i=0UL; i<t.o.certs_cnt; i++ ) has_notar |= t.o.certs[i].kind==FD_CERT_KIND_NOTAR;
  FD_TEST( has_notar && t.ok );

  ss = make_state( slot, epoch_info );
  for( ulong i=0UL; i<6UL; i++ ) {
    fd_vote_t v = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[i], test_bls_public_key, slot, &hash, (ushort)i, STATE_SHRED_VERSION );
    add_vote_helper( ss, &v, epoch_info, &t );
  }
  fd_vote_t bad6 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[4], test_bls_public_key, slot, &hash, 6UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &bad6, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==0UL && !t.ok && fd_bls_set_cnt( t.o.bad )==1UL && fd_bls_set_test( t.o.bad, 6UL ) );
  FD_TEST( notar_hash_stake_query( ss, &hash )==6UL && !fd_bls_set_test( ss->votes.notar_set, 6UL ) );
  add_vote_helper( ss, &v7, epoch_info, &t );
  has_notar = 0; for( ulong i=0UL; i<t.o.certs_cnt; i++ ) has_notar |= t.o.certs[i].kind==FD_CERT_KIND_NOTAR;
  FD_TEST( has_notar && t.ok && fd_bls_set_is_null( t.o.bad ) );
  free( em );

  generate_validators( n );
  g_state_info[0].stake = 3UL;
  epoch_info = make_epoch( n, &em );
  ss = make_state( slot, epoch_info );
  for( ulong i=1UL; i<7UL; i++ ) {
    fd_vote_t v = i==3UL ? bad : fd_vote_construct_notar( sec_sign_fn, &g_state_sk[i], test_bls_public_key, slot, &hash, (ushort)i, STATE_SHRED_VERSION );
    add_vote_helper( ss, &v, epoch_info, &t );
    FD_TEST( t.o.certs_cnt==0UL && t.ok );
  }
  fd_vote_t v0 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[0], test_bls_public_key, slot, &hash, 0UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &v0, epoch_info, &t );
  has_notar = 0; for( ulong i=0UL; i<t.o.certs_cnt; i++ ) has_notar |= t.o.certs[i].kind==FD_CERT_KIND_NOTAR;
  FD_TEST( has_notar && t.ok && fd_bls_set_cnt( t.o.bad )==1UL && fd_bls_set_test( t.o.bad, 3UL ) );
  FD_TEST( notar_hash_stake_query( ss, &hash )==8UL && !fd_bls_set_test( ss->votes.notar_set, 3UL ) );
  free( em );
}

static void
test_identity_partition( void ) {
  ulong n = 11UL;
  generate_validators( n );
  fd_bls_pub_t neg; FD_TEST( !fd_bls_pub_de( &neg, g_state_info[3].bls_key, FD_BLS_PUB_COMPRESSED_SZ ) );
  fd_bls_pub_neg( &neg, &neg ); fd_bls_pub_compress( &neg, g_state_info[4].bls_key );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 5UL;
  fd_block_hash_t hash; state_random_hash( &hash );
  out_t t;

  slot_state_t * ss = make_state( slot, epoch_info );
  fd_vote_t v3 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[3], test_bls_public_key, slot, &hash, 3UL, STATE_SHRED_VERSION );
  fd_vote_t v4 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[3], test_bls_public_key, slot, &hash, 4UL, STATE_SHRED_VERSION ); fd_bls_sig_neg( &v4.notar.sig, &v4.notar.sig );
  add_vote_helper( ss, &v3, epoch_info, &t ); FD_TEST( t.ok && t.o.certs_cnt==0UL );
  add_vote_helper( ss, &v4, epoch_info, &t ); FD_TEST( t.ok && t.o.certs_cnt==0UL );
  fd_bls_agg_t notar[1];
  state_notar_agg( ss, &hash, notar );
  FD_TEST( fd_bls_pub_is_inf( &notar->pub ) && fd_bls_sig_is_inf( &notar->sig ) && fd_bls_set_cnt( notar->set )==2UL && notar_hash_stake_query( ss, &hash )==2UL );

  ulong nf_ranks[7] = { 0UL, 1UL, 2UL, 5UL, 6UL, 7UL, 8UL };
  for( ulong i=0UL; i<6UL; i++ ) {
    fd_vote_t nf = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[ nf_ranks[i] ], test_bls_public_key, slot, &hash, (ushort)nf_ranks[i], STATE_SHRED_VERSION );
    add_vote_helper( ss, &nf, epoch_info, &t );
    FD_TEST( t.ok && t.o.certs_cnt==0UL && fd_bls_set_is_null( t.o.bad ) );
  }
  fd_vote_t nf8 = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[8], test_bls_public_key, slot, &hash, 8UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &nf8, epoch_info, &t );
  FD_TEST( t.ok && fd_bls_set_is_null( t.o.bad ) && t.o.certs_cnt==1UL && t.o.certs[0].kind==FD_CERT_KIND_NOTAR_FALLBACK );
  fd_cert_notar_fallback_t const * cert = &t.o.certs[0].notar_fallback;
  FD_TEST( cert->stake==7UL && fd_bls_set_is_null( cert->agg_notar.set ) && fd_bls_set_cnt( cert->agg_notar_fallback.set )==7UL );
  FD_TEST( fd_cert_verify( &t.o.certs[0], epoch_info )==FD_CERT_VERIFY_SUCCESS );

  fd_vote_t v9 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[9], test_bls_public_key, slot, &hash, 9UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &v9, epoch_info, &t );
  state_notar_agg( ss, &hash, notar );
  FD_TEST( t.ok && fd_bls_set_is_null( t.o.bad ) && notar_hash_stake_query( ss, &hash )==3UL && !fd_bls_pub_is_inf( &notar->pub ) );
  free( em );
}

static void
test_safe_to_events_verify( void ) {
  ulong n = 11UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 5UL;
  fd_block_hash_t hash; state_random_hash( &hash );
  out_t t;

  slot_state_t * ss = make_state( slot, epoch_info );
  fd_vote_t own_notar = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[0], test_bls_public_key, slot, &hash, 0UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &own_notar, epoch_info, &t ); FD_TEST( t.ok );
  for( ulong i=1UL; i<5UL; i++ ) {
    fd_vote_t v = fd_vote_construct_skip( sec_sign_fn, &g_state_sk[i], test_bls_public_key, slot, (ushort)i, STATE_SHRED_VERSION );
    add_vote_helper( ss, &v, epoch_info, &t );
    FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL );
  }
  fd_vote_t bad_skip = fd_vote_construct_skip( sec_sign_fn, &g_state_sk[7], test_bls_public_key, slot, 5UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &bad_skip, epoch_info, &t );
  FD_TEST( !t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL && !ss->sent_safe_to_skip && fd_bls_set_cnt( t.o.bad )==1UL && fd_bls_set_test( t.o.bad, 5UL ) && ss->votes.skip_stake==4UL );
  fd_vote_t skip6 = fd_vote_construct_skip( sec_sign_fn, &g_state_sk[6], test_bls_public_key, slot, 6UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &skip6, epoch_info, &t );
  FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==1UL && ss->sent_safe_to_skip && fd_bls_set_is_null( t.o.bad ) );

  ss = make_state( slot, epoch_info );
  add_vote_helper( ss, &own_notar, epoch_info, &t );
  add_vote_helper( ss, &bad_skip,  epoch_info, &t ); FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL && fd_bls_set_is_null( t.o.bad ) );
  for( ulong i=1UL; i<4UL; i++ ) {
    fd_vote_t v = fd_vote_construct_skip( sec_sign_fn, &g_state_sk[i], test_bls_public_key, slot, (ushort)i, STATE_SHRED_VERSION );
    add_vote_helper( ss, &v, epoch_info, &t );
    FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL );
  }
  fd_vote_t skip4 = fd_vote_construct_skip( sec_sign_fn, &g_state_sk[4], test_bls_public_key, slot, 4UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &skip4, epoch_info, &t );
  FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL && !ss->sent_safe_to_skip && fd_bls_set_cnt( t.o.bad )==1UL && fd_bls_set_test( t.o.bad, 5UL ) && ss->votes.skip_stake==4UL );
  add_vote_helper( ss, &skip6, epoch_info, &t );
  FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==1UL && ss->sent_safe_to_skip );

  ss = make_state( slot, epoch_info );
  slot_state_notify_parent_known( ss, &g_states, &hash, t.o.bad );
  slot_state_notify_parent_certified( ss, &g_states, &hash, t.o.bad );
  fd_vote_t own_skip = fd_vote_construct_skip( sec_sign_fn, &g_state_sk[0], test_bls_public_key, slot, 0UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &own_skip, epoch_info, &t ); FD_TEST( t.ok );
  for( ulong i=1UL; i<5UL; i++ ) {
    fd_vote_t v = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[i], test_bls_public_key, slot, &hash, (ushort)i, STATE_SHRED_VERSION );
    add_vote_helper( ss, &v, epoch_info, &t );
    FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL );
  }
  fd_vote_t bad_notar = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[8], test_bls_public_key, slot, &hash, 5UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &bad_notar, epoch_info, &t );
  FD_TEST( !t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL && fd_bls_set_cnt( t.o.bad )==1UL && fd_bls_set_test( t.o.bad, 5UL ) && notar_hash_stake_query( ss, &hash )==4UL );
  fd_vote_t notar6 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[6], test_bls_public_key, slot, &hash, 6UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &notar6, epoch_info, &t );
  FD_TEST( t.ok && t.o.safe_to_notar_cnt==1UL && t.o.safe_to_skip_cnt==0UL && fd_bls_set_is_null( t.o.bad ) );
  free( em );
}

static void
test_safe_to_skip_removes_forged_notar( void ) {
  ulong n = 11UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 5UL;
  fd_block_hash_t x; state_random_hash( &x );
  fd_block_hash_t y; state_random_hash( &y );
  out_t t;

  slot_state_t * ss = make_state( slot, epoch_info );
  fd_vote_t own_notar = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[0], test_bls_public_key, slot, &y, 0UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &own_notar, epoch_info, &t ); FD_TEST( t.ok );
  for( ulong rank=1UL; rank<4UL; rank++ ) {
    fd_vote_t forged = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[ rank+7UL ], test_bls_public_key, slot, &x, (ushort)rank, STATE_SHRED_VERSION );
    add_vote_helper( ss, &forged, epoch_info, &t );
    FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL && fd_bls_set_is_null( t.o.bad ) );
  }
  FD_TEST( notar_hash_stake_query( ss, &x )==3UL && ss->votes.top_notar_stake==3UL );
  for( ulong rank=4UL; rank<8UL; rank++ ) {
    fd_vote_t skip = fd_vote_construct_skip( sec_sign_fn, &g_state_sk[ rank ], test_bls_public_key, slot, (ushort)rank, STATE_SHRED_VERSION );
    add_vote_helper( ss, &skip, epoch_info, &t );
    FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL );
  }
  FD_TEST( fd_bls_set_cnt( t.o.bad )==3UL && fd_bls_set_test( t.o.bad, 1UL ) && fd_bls_set_test( t.o.bad, 2UL ) && fd_bls_set_test( t.o.bad, 3UL ) );
  FD_TEST( notar_hash_stake_query( ss, &x )==ULONG_MAX );
  FD_TEST( notar_hash_stake_query( ss, &y )==1UL );
  FD_TEST( ss->votes.notar_or_skip_stake==5UL && ss->votes.top_notar_stake==1UL && !ss->sent_safe_to_skip );
  fd_vote_t skip8 = fd_vote_construct_skip( sec_sign_fn, &g_state_sk[8], test_bls_public_key, slot, 8UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &skip8, epoch_info, &t );
  FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==1UL && ss->sent_safe_to_skip && fd_bls_set_is_null( t.o.bad ) );
  free( em );
}

/* Firedancer-only test.

   Skip stake alone meeting the threshold is enough for SafeToSkip, so
   the notar hashes, one verify each, are left unverified. */

static void
test_safe_to_skip_verifies_skip_first( void ) {
  ulong n = 11UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 5UL;
  out_t t;

  slot_state_t * ss = make_state( slot, epoch_info );
  for( ulong rank=4UL; rank<9UL; rank++ ) {
    fd_vote_t skip = fd_vote_construct_skip( sec_sign_fn, &g_state_sk[ rank ], test_bls_public_key, slot, (ushort)rank, STATE_SHRED_VERSION );
    add_vote_helper( ss, &skip, epoch_info, &t );
    FD_TEST( t.ok && t.o.safe_to_skip_cnt==0UL );
  }
  fd_block_hash_t x[ 3 ];
  for( ulong rank=1UL; rank<4UL; rank++ ) {
    state_random_hash( &x[ rank-1UL ] );
    fd_vote_t forged = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[ rank+7UL ], test_bls_public_key, slot, &x[ rank-1UL ], (ushort)rank, STATE_SHRED_VERSION );
    add_vote_helper( ss, &forged, epoch_info, &t );
    FD_TEST( t.ok && t.o.safe_to_skip_cnt==0UL );
  }
  ulong verify_cnt = g_states.bls_verify_cnt;
  fd_block_hash_t y; state_random_hash( &y );
  fd_vote_t own_notar = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[0], test_bls_public_key, slot, &y, 0UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &own_notar, epoch_info, &t );
  FD_TEST( t.ok && t.o.safe_to_skip_cnt==1UL && ss->sent_safe_to_skip && fd_bls_set_is_null( t.o.bad ) );
  FD_TEST( g_states.bls_verify_cnt==verify_cnt+1UL );
  for( ulong i=0UL; i<3UL; i++ ) FD_TEST( notar_hash_stake_query( ss, &x[i] )==1UL );
  free( em );
}

static void
test_map_capacity( void ) {
  ulong n = 11UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  slot_state_t * ss = make_state( 5UL, epoch_info );
  int               fd = g_states.spill_fd;

  static fd_block_hash_t notar_hash[ FD_VOTOR_VAT_MAX ];
  for( ulong i=0UL; i<FD_VOTOR_VAT_MAX; i++ ) {
    state_random_hash( &notar_hash[ i ] );
    FD_TEST( hash_stake_insert( ss, fd, 0, &notar_hash[ i ] )==i );
  }
  for( ulong i=0UL; i<NOTAR_FALLBACK_HASH_MAX; i++ ) {
    fd_block_hash_t hash; state_random_hash( &hash );
    FD_TEST( hash_stake_insert( ss, fd, 1, &hash )==i );
    hash_stake_set( ss, fd, 1, i, i );
    if( !(i%61UL) ) FD_TEST( hash_stake_query( ss, fd, 1, &hash )==i && hash_stake_get( ss, fd, 1, i, NULL )==i );
  }
  for( ulong i=0UL; i<FD_VOTOR_VAT_MAX; i++ ) FD_TEST( hash_stake_query( ss, fd, 0, &notar_hash[ i ] )==i );
  FD_TEST( hash_stake_cnt( ss, 0 )==FD_VOTOR_VAT_MAX && hash_stake_cnt( ss, 1 )==NOTAR_FALLBACK_HASH_MAX );
  FD_TEST( ss->votes.notar_hash_stake.spill_hwm==NOTAR_SPILL_MAX && ss->votes.notar_fallback_hash_stake.spill_hwm==NF_SPILL_MAX );

  hash_stake_remove( ss, fd, 0, 7UL    );
  hash_stake_remove( ss, fd, 0, 1234UL );
  FD_TEST( hash_stake_cnt( ss, 0 )==FD_VOTOR_VAT_MAX-2UL );
  FD_TEST( hash_stake_query( ss, fd, 0, &notar_hash[ 7    ] )==ULONG_MAX );
  FD_TEST( hash_stake_query( ss, fd, 0, &notar_hash[ 1234 ] )==ULONG_MAX );
  for( ulong i=0UL; i<FD_VOTOR_VAT_MAX; i++ ) FD_TEST( i==7UL || i==1234UL || hash_stake_query( ss, fd, 0, &notar_hash[ i ] )==i );
  fd_block_hash_t a; state_random_hash( &a );
  fd_block_hash_t b; state_random_hash( &b );
  ulong id_a = hash_stake_insert( ss, fd, 0, &a ); /* inline before spill */
  ulong id_b = hash_stake_insert( ss, fd, 0, &b );
  FD_TEST( id_a==7UL && id_b==1234UL && hash_stake_cnt( ss, 0 )==FD_VOTOR_VAT_MAX && ss->votes.notar_hash_stake.spill_hwm==NOTAR_SPILL_MAX );
  FD_TEST( hash_stake_query( ss, fd, 0, &a )==7UL && hash_stake_query( ss, fd, 0, &b )==1234UL );

  slot_state_null( ss, &g_states );
  assert_maps_empty( ss );
  FD_TEST( hash_stake_query( ss, fd, 0, &a )==ULONG_MAX && hash_stake_query( ss, fd, 0, &notar_hash[ 1999 ] )==ULONG_MAX );
  free( em );
}

/* The forged one of four notar hashes sits in the middle of the slot's
   table.  check_safe_to_skip removes it while iterating the table and
   must still verify every other hash exactly once. */

static void
test_safe_to_skip_removes_table_mate( void ) {
  ulong n = 11UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 5UL;
  out_t t;

  slot_state_t * ss = make_state( slot, epoch_info );
  fd_block_hash_t   hash[ 4 ];
  for( ulong i=0UL; i<4UL; i++ ) state_random_hash( &hash[i] );
  fd_vote_t v0 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[0], test_bls_public_key, slot, &hash[0], 0UL, STATE_SHRED_VERSION );
  fd_vote_t v1 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[8], test_bls_public_key, slot, &hash[1], 1UL, STATE_SHRED_VERSION );
  fd_vote_t v2 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[2], test_bls_public_key, slot, &hash[2], 2UL, STATE_SHRED_VERSION );
  fd_vote_t v3 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[3], test_bls_public_key, slot, &hash[3], 3UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &v0, epoch_info, &t ); FD_TEST( t.ok );
  add_vote_helper( ss, &v1, epoch_info, &t ); FD_TEST( t.ok );
  add_vote_helper( ss, &v2, epoch_info, &t ); FD_TEST( t.ok );
  add_vote_helper( ss, &v3, epoch_info, &t ); FD_TEST( t.ok );
  for( ulong i=0UL; i<4UL; i++ ) FD_TEST( hash_stake_query( ss, g_states.spill_fd, 0, &hash[i] )==i );
  FD_TEST( hash_stake_cnt( ss, 0 )==4UL && ss->votes.notar_hash_stake.used==0xfU );
  for( ulong rank=4UL; rank<6UL; rank++ ) {
    fd_vote_t skip = fd_vote_construct_skip( sec_sign_fn, &g_state_sk[ rank ], test_bls_public_key, slot, (ushort)rank, STATE_SHRED_VERSION );
    add_vote_helper( ss, &skip, epoch_info, &t );
    FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL );
  }
  FD_TEST( fd_bls_set_cnt( t.o.bad )==1UL && fd_bls_set_test( t.o.bad, 1UL ) );
  FD_TEST( notar_hash_stake_query( ss, &hash[1] )==ULONG_MAX );
  FD_TEST( hash_stake_cnt( ss, 0 )==3UL && ss->votes.notar_hash_stake.used==0xdU );
  FD_TEST( hash_stake_query( ss, g_states.spill_fd, 0, &hash[0] )==0UL );
  FD_TEST( hash_stake_query( ss, g_states.spill_fd, 0, &hash[2] )==2UL );
  FD_TEST( hash_stake_query( ss, g_states.spill_fd, 0, &hash[3] )==3UL );
  FD_TEST( notar_hash_stake_query( ss, &hash[0] )==1UL );
  FD_TEST( notar_hash_stake_query( ss, &hash[2] )==1UL );
  FD_TEST( notar_hash_stake_query( ss, &hash[3] )==1UL );
  FD_TEST( ss->votes.notar_or_skip_stake==5UL && ss->votes.top_notar_stake==1UL && !ss->sent_safe_to_skip );
  fd_vote_t skip6 = fd_vote_construct_skip( sec_sign_fn, &g_state_sk[6], test_bls_public_key, slot, 6UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &skip6, epoch_info, &t );
  FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==1UL && ss->sent_safe_to_skip && fd_bls_set_is_null( t.o.bad ) );
  slot_state_null( ss, &g_states );
  assert_maps_empty( ss );
  free( em );
}

static void
test_safe_to_skip_removes_head_middle_tail( void ) {
  ulong n = 11UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 5UL;
  out_t t;

  slot_state_t * ss = make_state( slot, epoch_info );
  fd_block_hash_t   hash[ 6 ];
  for( ulong i=0UL; i<6UL; i++ ) state_random_hash( &hash[i] );
  fd_vote_t v0 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[8],  test_bls_public_key, slot, &hash[0], 1UL, STATE_SHRED_VERSION );
  fd_vote_t v1 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[0],  test_bls_public_key, slot, &hash[1], 0UL, STATE_SHRED_VERSION );
  fd_vote_t v2 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[9],  test_bls_public_key, slot, &hash[2], 2UL, STATE_SHRED_VERSION );
  fd_vote_t v3 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[3],  test_bls_public_key, slot, &hash[3], 3UL, STATE_SHRED_VERSION );
  fd_vote_t v4 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[10], test_bls_public_key, slot, &hash[4], 4UL, STATE_SHRED_VERSION );
  fd_vote_t v5 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[6],  test_bls_public_key, slot, &hash[1], 6UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &v0, epoch_info, &t ); FD_TEST( t.ok );
  add_vote_helper( ss, &v1, epoch_info, &t ); FD_TEST( t.ok );
  add_vote_helper( ss, &v2, epoch_info, &t ); FD_TEST( t.ok );
  add_vote_helper( ss, &v3, epoch_info, &t ); FD_TEST( t.ok );
  add_vote_helper( ss, &v4, epoch_info, &t ); FD_TEST( t.ok );
  add_vote_helper( ss, &v5, epoch_info, &t ); FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL && fd_bls_set_is_null( t.o.bad ) );
  for( ulong i=0UL; i<5UL; i++ ) FD_TEST( hash_stake_query( ss, g_states.spill_fd, 0, &hash[i] )==i );
  FD_TEST( ss->votes.notar_hash_stake.used==0x1fU );

  fd_vote_t skip5 = fd_vote_construct_skip( sec_sign_fn, &g_state_sk[5], test_bls_public_key, slot, 5UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &skip5, epoch_info, &t );
  FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL && !ss->sent_safe_to_skip );
  FD_TEST( fd_bls_set_cnt( t.o.bad )==3UL && fd_bls_set_test( t.o.bad, 1UL ) && fd_bls_set_test( t.o.bad, 2UL ) && fd_bls_set_test( t.o.bad, 4UL ) );
  FD_TEST( ss->votes.notar_hash_stake.used==0xaU && hash_stake_cnt( ss, 0 )==2UL );
  FD_TEST( notar_hash_stake_query( ss, &hash[0] )==ULONG_MAX && notar_hash_stake_query( ss, &hash[2] )==ULONG_MAX && notar_hash_stake_query( ss, &hash[4] )==ULONG_MAX );
  FD_TEST( notar_hash_stake_query( ss, &hash[1] )==2UL && notar_hash_stake_query( ss, &hash[3] )==1UL );
  FD_TEST( ss->votes.notar_or_skip_stake==4UL && ss->votes.top_notar_stake==2UL && !memcmp( &ss->votes.top_notar_hash, &hash[1], sizeof(fd_block_hash_t) ) );

  fd_vote_t v6 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[7], test_bls_public_key, slot, &hash[5], 7UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &v6, epoch_info, &t );
  FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL && fd_bls_set_is_null( t.o.bad ) && hash_stake_query( ss, g_states.spill_fd, 0, &hash[5] )==0UL );
  FD_TEST( ss->votes.notar_hash_stake.used==0xbU );
  fd_vote_t skip8 = fd_vote_construct_skip( sec_sign_fn, &g_state_sk[8], test_bls_public_key, slot, 8UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &skip8, epoch_info, &t );
  FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL && fd_bls_set_is_null( t.o.bad ) );
  fd_vote_t skip9 = fd_vote_construct_skip( sec_sign_fn, &g_state_sk[9], test_bls_public_key, slot, 9UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &skip9, epoch_info, &t );
  FD_TEST( t.ok && t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==1UL && ss->sent_safe_to_skip && fd_bls_set_is_null( t.o.bad ) );
  FD_TEST( hash_stake_cnt( ss, 0 )==3UL );
  slot_state_null( ss, &g_states );
  assert_maps_empty( ss );
  free( em );
}

static void
test_notar_fallback_removes_head_middle_tail( void ) {
  ulong n = 11UL;
  generate_validators( n );
  g_state_info[1].stake = 20UL;
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 5UL;
  out_t t;

  slot_state_t * ss = make_state( slot, epoch_info );
  fd_block_hash_t   hash[ 5 ];
  for( ulong i=0UL; i<5UL; i++ ) state_random_hash( &hash[i] );
  fd_vote_t v0 = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[8], test_bls_public_key, slot, &hash[0], 2UL, STATE_SHRED_VERSION );
  fd_vote_t v1 = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[3], test_bls_public_key, slot, &hash[1], 3UL, STATE_SHRED_VERSION );
  fd_vote_t v2 = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[9], test_bls_public_key, slot, &hash[2], 4UL, STATE_SHRED_VERSION );
  fd_vote_t v3 = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[5], test_bls_public_key, slot, &hash[3], 5UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &v0, epoch_info, &t ); FD_TEST( t.ok );
  add_vote_helper( ss, &v1, epoch_info, &t ); FD_TEST( t.ok );
  add_vote_helper( ss, &v2, epoch_info, &t ); FD_TEST( t.ok );
  add_vote_helper( ss, &v3, epoch_info, &t ); FD_TEST( t.ok && t.o.certs_cnt==0UL && fd_bls_set_is_null( t.o.bad ) );
  for( ulong i=0UL; i<4UL; i++ ) FD_TEST( hash_stake_query( ss, g_states.spill_fd, 1, &hash[i] )==i );
  FD_TEST( ss->votes.notar_fallback_hash_stake.used==0xfU );

  fd_vote_t forged_middle = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[10], test_bls_public_key, slot, &hash[2], 1UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &forged_middle, epoch_info, &t );
  FD_TEST( !t.ok && t.o.certs_cnt==0UL && fd_bls_set_cnt( t.o.bad )==2UL && fd_bls_set_test( t.o.bad, 1UL ) && fd_bls_set_test( t.o.bad, 4UL ) );
  FD_TEST( ss->votes.notar_fallback_hash_stake.used==0xbU );

  fd_vote_t forged_tail = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[10], test_bls_public_key, slot, &hash[0], 1UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &forged_tail, epoch_info, &t );
  FD_TEST( !t.ok && t.o.certs_cnt==0UL && fd_bls_set_cnt( t.o.bad )==2UL && fd_bls_set_test( t.o.bad, 1UL ) && fd_bls_set_test( t.o.bad, 2UL ) );
  FD_TEST( ss->votes.notar_fallback_hash_stake.used==0xaU );

  fd_vote_t forged_head = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[10], test_bls_public_key, slot, &hash[4], 1UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &forged_head, epoch_info, &t );
  FD_TEST( !t.ok && t.o.certs_cnt==0UL && fd_bls_set_cnt( t.o.bad )==1UL && fd_bls_set_test( t.o.bad, 1UL ) );
  FD_TEST( ss->votes.notar_fallback_hash_stake.used==0xaU && hash_stake_cnt( ss, 1 )==2UL );
  FD_TEST( notar_fallback_hash_stake_query( ss, &hash[0] )==ULONG_MAX && notar_fallback_hash_stake_query( ss, &hash[2] )==ULONG_MAX && notar_fallback_hash_stake_query( ss, &hash[4] )==ULONG_MAX );
  FD_TEST( notar_fallback_hash_stake_query( ss, &hash[1] )==1UL && notar_fallback_hash_stake_query( ss, &hash[3] )==1UL );
  FD_TEST( !ss->votes.notar_fallback_sig_cnt[ 1 ] && !ss->votes.notar_fallback_sig_cnt[ 2 ] && !ss->votes.notar_fallback_sig_cnt[ 4 ] );

  fd_vote_t honest = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[1], test_bls_public_key, slot, &hash[1], 1UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &honest, epoch_info, &t );
  FD_TEST( t.ok && fd_bls_set_is_null( t.o.bad ) && t.o.certs_cnt==1UL && t.o.certs[0].kind==FD_CERT_KIND_NOTAR_FALLBACK && t.o.certs[0].notar_fallback.stake==21UL );
  FD_TEST( fd_cert_verify( &t.o.certs[0], epoch_info )==FD_CERT_VERIFY_SUCCESS );
  slot_state_null( ss, &g_states );
  assert_maps_empty( ss );

  /* removing a rank's first notar fallback moves its second sig down */
  ss = make_state( slot, epoch_info );
  fd_vote_t forged = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[8], test_bls_public_key, slot, &hash[0], 2UL, STATE_SHRED_VERSION );
  fd_vote_t valid  = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[2], test_bls_public_key, slot, &hash[1], 2UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &forged, epoch_info, &t ); FD_TEST( t.ok );
  add_vote_helper( ss, &valid,  epoch_info, &t ); FD_TEST( t.ok && ss->votes.notar_fallback_sig_cnt[ 2 ]==2U );
  fd_vote_t heavy = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[1], test_bls_public_key, slot, &hash[0], 1UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &heavy, epoch_info, &t );
  FD_TEST( t.ok && fd_bls_set_cnt( t.o.bad )==1UL && fd_bls_set_test( t.o.bad, 2UL ) && t.o.certs_cnt==1UL );
  FD_TEST( ss->votes.notar_fallback_sig_cnt[ 2 ]==1U );
  fd_block_hash_t got; FD_TEST( !memcmp( slot_state_vote_hash( ss, &g_states, FD_VOTE_KIND_NOTAR_FALLBACK, 2UL, 0UL, &got ), &hash[1], sizeof(fd_block_hash_t) ) );
  fd_bls_sig_t sig; FD_TEST( !memcmp( slot_state_vote_sig( ss, &g_states, FD_VOTE_KIND_NOTAR_FALLBACK, 2UL, 0UL, &sig ), &valid.notar_fallback.sig, sizeof(fd_bls_sig_t) ) );
  slot_state_null( ss, &g_states );
  free( em );
}

/* src/consensus/pool/slot_state.rs::count_notar_fallback_creates_cert_at_quorum */

static void
test_count_notar_fallback_creates_cert_at_quorum( void ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_block_hash_t hash; state_random_hash( &hash );
  slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;

  for( ulong i=1UL; i<=2UL; i++ ) {
    fd_vote_t nv = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[i], test_bls_public_key, slot, &hash, (ushort)i, STATE_SHRED_VERSION );
    add_vote_helper( ss, &nv, epoch_info, &t );
    FD_TEST( t.o.certs_cnt==0UL );
  }

  fd_vote_t nf3 = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[3], test_bls_public_key, slot, &hash, 3UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &nf3, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==0UL );
  FD_TEST( t.o.safe_to_notar_cnt==0UL && t.o.safe_to_skip_cnt==0UL );
  FD_TEST( t.o.block_to_repair_cnt==0UL );
  FD_TEST( notar_fallback_hash_stake_query( ss, &hash )==1UL );

  fd_vote_t nf4 = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[4], test_bls_public_key, slot, &hash, 4UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &nf4, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==1UL );
  FD_TEST( t.o.certs[0].kind==FD_CERT_KIND_NOTAR_FALLBACK );
  FD_TEST( fd_cert_block_hash( &t.o.certs[0] ) && !memcmp( fd_cert_block_hash( &t.o.certs[0] ), &hash, sizeof(fd_block_hash_t) ) );

  slot_state_add_cert( ss, &t.o.certs[0] );
  fd_vote_t nf5 = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[5], test_bls_public_key, slot, &hash, 5UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &nf5, epoch_info, &t );
  FD_TEST( t.o.certs_cnt==0UL );

  free( em );
}

/* Firedancer-only test.

   The reference also makes a notar-fallback cert when notar votes
   alone reach quorum.  Agave does not, a notar or fast-final cert
   already certifies the block as notar-fallback or stronger
   (Definition 13), so the pool makes one only when notar votes alone
   fall short. */

static void
test_notar_cert_implies_notar_fallback( void ) {
  ulong n = 5UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_block_hash_t hash; state_random_hash( &hash );
  slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;

  for( ulong i=0UL; i<2UL; i++ ) {
    fd_vote_t nv = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[i], test_bls_public_key, slot, &hash, (ushort)i, STATE_SHRED_VERSION );
    add_vote_helper( ss, &nv, epoch_info, &t );
    FD_TEST( t.ok && t.o.certs_cnt==0UL );
  }
  fd_vote_t nv2 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[2], test_bls_public_key, slot, &hash, 2UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &nv2, epoch_info, &t );
  FD_TEST( t.ok && t.o.certs_cnt==1UL && t.o.certs[0].kind==FD_CERT_KIND_NOTAR );
  slot_state_add_cert( ss, &t.o.certs[0] );

  fd_vote_t nf3 = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[3], test_bls_public_key, slot, &hash, 3UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &nf3, epoch_info, &t );
  FD_TEST( t.ok && t.o.certs_cnt==0UL );

  fd_vote_t nv4 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[4], test_bls_public_key, slot, &hash, 4UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &nv4, epoch_info, &t );
  FD_TEST( t.ok && t.o.certs_cnt==1UL && t.o.certs[0].kind==FD_CERT_KIND_FAST_FINAL );
  FD_TEST( !slot_state_is_notar_fallback( ss, &hash ) && slot_state_is_notar_fallback_or_stronger( ss, &hash ) );

  slot_state_null( ss, &g_states );
  ss->slot = slot;
  fd_vote_t nf0 = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[0], test_bls_public_key, slot, &hash, 0UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &nf0, epoch_info, &t );
  FD_TEST( t.ok && t.o.certs_cnt==0UL );
  fd_vote_t nv1 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[1], test_bls_public_key, slot, &hash, 1UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &nv1, epoch_info, &t );
  FD_TEST( t.ok && t.o.certs_cnt==0UL );
  add_vote_helper( ss, &nv2, epoch_info, &t );
  FD_TEST( t.ok && t.o.certs_cnt==1UL && t.o.certs[0].kind==FD_CERT_KIND_NOTAR_FALLBACK && t.o.certs[0].notar_fallback.stake==3UL );
  FD_TEST( fd_cert_verify( &t.o.certs[0], epoch_info )==FD_CERT_VERIFY_SUCCESS );

  fd_vote_t nv3 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[3], test_bls_public_key, slot, &hash, 3UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &nv3, epoch_info, &t );
  FD_TEST( t.ok && t.o.certs_cnt==1UL && t.o.certs[0].kind==FD_CERT_KIND_NOTAR );

  free( em );
}

/* src/consensus/pool/slot_state.rs::skip_skip_fallback_conflict */

static void
test_skip_skip_fallback_conflict( void ) {
  ulong n = 3UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;
  ulong v = 0UL;

  fd_vote_t skip = fd_vote_construct_skip( sec_sign_fn, &g_state_sk[v], test_bls_public_key, slot, (ushort)v, STATE_SHRED_VERSION );
  fd_vote_t skip_fallback = fd_vote_construct_skip_fallback( sec_sign_fn, &g_state_sk[v], test_bls_public_key, slot, (ushort)v, STATE_SHRED_VERSION );

  FD_TEST( !slot_state_should_ignore_vote( ss, &g_states, &skip          ) );
  FD_TEST( !slot_state_should_ignore_vote( ss, &g_states, &skip_fallback ) );

  add_vote_helper( ss, &skip, epoch_info, &t );

  FD_TEST( slot_state_should_ignore_vote( ss, &g_states, &skip_fallback ) );

  FD_TEST( slot_state_should_ignore_vote( ss, &g_states, &skip ) );

  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &skip_fallback )==SLASHABLE_OFFENCE_NONE );

  slot_state_null( ss, &g_states );
  ss->slot     = slot;
  ss->own_rank = 0UL;
  add_vote_helper( ss, &skip_fallback, epoch_info, &t );
  FD_TEST( slot_state_should_ignore_vote( ss, &g_states, &skip          ) );
  FD_TEST( slot_state_should_ignore_vote( ss, &g_states, &skip_fallback ) );
  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &skip )==SLASHABLE_OFFENCE_NONE );

  free( em );
}

/* src/consensus/pool/slot_state.rs::notar_notar_fallback_conflict */

static void
test_notar_notar_fallback_conflict( void ) {
  ulong n = 3UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_block_hash_t hash;       state_random_hash( &hash       );
  fd_block_hash_t other_hash; state_random_hash( &other_hash );
  slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;
  ulong v = 0UL;

  fd_vote_t notar = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[v], test_bls_public_key, slot, &hash, (ushort)v, STATE_SHRED_VERSION );
  fd_vote_t notar_fallback = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[v], test_bls_public_key, slot, &hash, (ushort)v, STATE_SHRED_VERSION );
  fd_vote_t nf_other = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[v], test_bls_public_key, slot, &other_hash, (ushort)v, STATE_SHRED_VERSION );

  FD_TEST( !slot_state_should_ignore_vote( ss, &g_states, &notar          ) );
  FD_TEST( !slot_state_should_ignore_vote( ss, &g_states, &notar_fallback ) );

  add_vote_helper( ss, &notar, epoch_info, &t );

  FD_TEST( slot_state_should_ignore_vote( ss, &g_states, &notar_fallback ) );

  FD_TEST( slot_state_should_ignore_vote( ss, &g_states, &notar ) );

  FD_TEST( !slot_state_should_ignore_vote( ss, &g_states, &nf_other ) );

  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &notar_fallback )==SLASHABLE_OFFENCE_NONE );

  slot_state_null( ss, &g_states );
  ss->slot     = slot;
  ss->own_rank = 0UL;
  add_vote_helper( ss, &notar_fallback, epoch_info, &t );
  FD_TEST( slot_state_should_ignore_vote( ss, &g_states, &notar          ) );
  FD_TEST( slot_state_should_ignore_vote( ss, &g_states, &notar_fallback ) );
  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &notar )==SLASHABLE_OFFENCE_NONE );

  free( em );
}

/* src/consensus/pool/sorted_vec.rs::set_insert_contains_iter */

static void
test_set_insert_contains_iter( void ) {
  fd_block_hash_t h1, h3, h5, h2;
  state_random_hash( &h1 ); state_random_hash( &h3 ); state_random_hash( &h5 ); state_random_hash( &h2 );

  block_hash_set_t set; set.cnt = 0UL;

  block_hash_set_insert( &set, &h3 ); FD_TEST( set.cnt==1UL );
  block_hash_set_insert( &set, &h1 ); FD_TEST( set.cnt==2UL );
  block_hash_set_insert( &set, &h5 ); FD_TEST( set.cnt==3UL );
  block_hash_set_insert( &set, &h3 ); FD_TEST( set.cnt==3UL );

  FD_TEST(  block_hash_set_contains( &set, &h1 ) );
  FD_TEST( !block_hash_set_contains( &set, &h2 ) );

  block_hash_set_remove( &set, &h1 ); FD_TEST( set.cnt==2UL );
  block_hash_set_remove( &set, &h1 ); FD_TEST( set.cnt==2UL );
  FD_TEST( !block_hash_set_contains( &set, &h1 ) );

  FD_TEST( block_hash_set_contains( &set, &h3 ) );
  FD_TEST( block_hash_set_contains( &set, &h5 ) );
}

static void
assert_tally( slot_state_t const *            ss,
              int                             nf,
              fd_block_hash_t const * const * hash,
              ulong const *           stake,
              ulong                   expected_cnt ) {
  FD_TEST( hash_stake_cnt( ss, nf )==expected_cnt );
  for( ulong i=0UL; i<expected_cnt; i++ ) {
    ulong id = hash_stake_query( ss, g_states.spill_fd, nf, hash[i] );
    FD_TEST( id!=ULONG_MAX );
    FD_TEST( hash_stake_get( ss, g_states.spill_fd, nf, id, NULL )==stake[i] );
  }
}

/* src/consensus/pool/sorted_vec.rs::map_get_or_insert_with */

static void
test_notar_stake_tally( void ) {
  ulong n = 12UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;

  fd_block_hash_t a, b, c, d;
  state_random_hash( &a ); state_random_hash( &b ); state_random_hash( &c ); state_random_hash( &d );

  ulong rank = 0UL;
  fd_vote_t v;
  v = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[rank], test_bls_public_key, slot, &a, (ushort)rank, STATE_SHRED_VERSION ); rank++;
  add_vote_helper( ss, &v, epoch_info, &t );
  assert_tally( ss, 0, (fd_block_hash_t const *[]){ &a }, (ulong[]){ 1UL }, 1UL );

  v = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[rank], test_bls_public_key, slot, &b, (ushort)rank, STATE_SHRED_VERSION ); rank++;
  add_vote_helper( ss, &v, epoch_info, &t );
  assert_tally( ss, 0, (fd_block_hash_t const *[]){ &a, &b }, (ulong[]){ 1UL, 1UL }, 2UL );

  v = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[rank], test_bls_public_key, slot, &b, (ushort)rank, STATE_SHRED_VERSION ); rank++;
  add_vote_helper( ss, &v, epoch_info, &t );
  assert_tally( ss, 0, (fd_block_hash_t const *[]){ &b, &a }, (ulong[]){ 2UL, 1UL }, 2UL );

  for( ulong i=0UL; i<3UL; i++ ) {
    v = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[rank], test_bls_public_key, slot, &c, (ushort)rank, STATE_SHRED_VERSION ); rank++;
    add_vote_helper( ss, &v, epoch_info, &t );
  }
  assert_tally( ss, 0, (fd_block_hash_t const *[]){ &c, &b, &a }, (ulong[]){ 3UL, 2UL, 1UL }, 3UL );

  for( ulong i=0UL; i<4UL; i++ ) {
    v = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[rank], test_bls_public_key, slot, &d, (ushort)rank, STATE_SHRED_VERSION ); rank++;
    add_vote_helper( ss, &v, epoch_info, &t );
  }
  FD_TEST( rank<=n );
  assert_tally( ss, 0, (fd_block_hash_t const *[]){ &d, &c, &b, &a }, (ulong[]){ 4UL, 3UL, 2UL, 1UL }, 4UL );
  FD_TEST( ss->votes.top_notar_stake==4UL ); /* d, the most supported hash */

  free( em );
}

/* src/consensus/pool/sorted_vec.rs::map_get_or_insert_with */

static void
test_notar_fallback_stake_tally( void ) {
  ulong n = 12UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 1UL;
  slot_state_t * ss = make_state( slot, epoch_info );
  out_t t;

  fd_block_hash_t own[ FD_VOTOR_NOTAR_FALLBACK_VOTE_MAX ];
  for( ulong i=0UL; i<FD_VOTOR_NOTAR_FALLBACK_VOTE_MAX; i++ ) {
    state_random_hash( &own[i] );
    fd_vote_t v = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[0], test_bls_public_key, slot, &own[i], 0UL, STATE_SHRED_VERSION );
    FD_TEST( ss->votes.notar_fallback_sig_cnt[ 0 ]<FD_VOTOR_NOTAR_FALLBACK_VOTE_MAX );
    add_vote_helper( ss, &v, epoch_info, &t );
    FD_TEST( notar_fallback_hash_stake_query( ss, &own[i] )==1UL );
  }

  /* the cap itself is enforced in fd_votor_pool_add_vote */
  FD_TEST( ss->votes.notar_fallback_sig_cnt[ 0 ]==FD_VOTOR_NOTAR_FALLBACK_VOTE_MAX );

  for( ulong i=0UL; i<2UL; i++ ) {
    fd_vote_t v = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[1UL+i], test_bls_public_key, slot, &own[2], (ushort)(1UL+i), STATE_SHRED_VERSION );
    add_vote_helper( ss, &v, epoch_info, &t );
  }
  fd_vote_t v_mid = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[3], test_bls_public_key, slot, &own[1], 3UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &v_mid, epoch_info, &t );

  assert_tally( ss, 1, (fd_block_hash_t const *[]){ &own[2], &own[1], &own[0] }, (ulong[]){ 3UL, 2UL, 1UL }, 3UL );

  free( em );
}

/* Drive both tables and a reference through random inserts, removes
   and nulls on CLEAR_KEY_CNT keys, more than fit inline.  A live hash
   keeps the id it was given, freed ids are reused before a new id is
   taken, and a null leaves both tables empty. */

#define CLEAR_KEY_CNT (48UL)

static void
random_key( fd_rng_t *        rng,
            fd_block_hash_t * hash ) {
  for( ulong i=0UL; i<4UL; i++ ) FD_STORE( ulong, hash->uc+8UL*i, fd_rng_ulong( rng ) );
}

static void
hash_stake_step( slot_state_t * ss,
                 int               nf,
                 fd_block_hash_t * key,
                 ulong *           ref_id,
                 ulong *           ref_stake,
                 ulong *           peak,
                 ulong             k,
                 ulong             iter ) {
  int fd = g_states.spill_fd;
  if( ref_id[ k ]!=ULONG_MAX ) {
    hash_stake_remove( ss, fd, nf, ref_id[ k ] );
    ref_id[ k ] = ULONG_MAX;
  } else {
    ulong used = hash_stake_cnt( ss, nf );
    ulong id   = hash_stake_insert( ss, fd, nf, &key[ k ] );
    FD_TEST( used<*peak ? id<*peak : id==*peak );
    hash_stake_set( ss, fd, nf, id, iter );
    ref_id   [ k ] = id;
    ref_stake[ k ] = iter;
  }
  ulong live = 0UL;
  for( ulong i=0UL; i<CLEAR_KEY_CNT; i++ ) {
    FD_TEST( hash_stake_query( ss, fd, nf, &key[ i ] )==ref_id[ i ] );
    if( ref_id[ i ]==ULONG_MAX ) continue;
    FD_TEST( hash_stake_get( ss, fd, nf, ref_id[ i ], NULL )==ref_stake[ i ] );
    live++;
  }
  *peak = fd_ulong_max( *peak, live );
  FD_TEST( hash_stake_cnt( ss, nf )==live );
  ulong           seen = 0UL;
  fd_block_hash_t hash;
  for( ulong id = hash_stake_next( ss, fd, nf, 0UL, &hash ); id!=ULONG_MAX; id = hash_stake_next( ss, fd, nf, id+1UL, &hash ) ) {
    FD_TEST( hash_stake_query( ss, fd, nf, &hash )==id );
    seen++;
  }
  FD_TEST( seen==live );
}

static void
test_pool_ids_stable( void ) {
  ulong n = 3UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  slot_state_t * ss = make_state( 1UL, epoch_info );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 1234U, 0UL ) );
  fd_block_hash_t notar_key[ CLEAR_KEY_CNT ];
  fd_block_hash_t nf_key   [ CLEAR_KEY_CNT ];
  for( ulong i=0UL; i<CLEAR_KEY_CNT; i++ ) {
    random_key( rng, &notar_key[ i ] );
    random_key( rng, &nf_key   [ i ] );
  }
  ulong notar_ref_id[ CLEAR_KEY_CNT ]; ulong notar_ref_stake[ CLEAR_KEY_CNT ]; ulong notar_peak = 0UL;
  ulong nf_ref_id   [ CLEAR_KEY_CNT ]; ulong nf_ref_stake   [ CLEAR_KEY_CNT ]; ulong nf_peak    = 0UL;
  for( ulong i=0UL; i<CLEAR_KEY_CNT; i++ ) { notar_ref_id[ i ] = ULONG_MAX; nf_ref_id[ i ] = ULONG_MAX; }

  ulong null_cnt = 0UL;
  for( ulong iter=0UL; iter<50000UL; iter++ ) {
    uint r = fd_rng_uint( rng );
    if( FD_UNLIKELY( !(r&255U) ) ) {
      slot_state_null( ss, &g_states );
      assert_maps_empty( ss );
      for( ulong i=0UL; i<CLEAR_KEY_CNT; i++ ) {
        FD_TEST( hash_stake_query( ss, g_states.spill_fd, 0, &notar_key[ i ] )==ULONG_MAX );
        FD_TEST( hash_stake_query( ss, g_states.spill_fd, 1, &nf_key   [ i ] )==ULONG_MAX );
        notar_ref_id[ i ] = ULONG_MAX; nf_ref_id[ i ] = ULONG_MAX;
      }
      null_cnt++;
      continue;
    }
    ulong k = (ulong)( (r>>8)%CLEAR_KEY_CNT );
    if( r&(1U<<31) ) hash_stake_step( ss, 0, notar_key, notar_ref_id, notar_ref_stake, &notar_peak, k, iter );
    else             hash_stake_step( ss, 1, nf_key,    nf_ref_id,    nf_ref_stake,    &nf_peak,    k, iter );
  }
  FD_TEST( null_cnt>100UL && notar_peak>HASH_STAKE_INLINE_MAX && nf_peak>HASH_STAKE_INLINE_MAX );

  fd_rng_delete( fd_rng_leave( rng ) );
  free( em );
}

/* Firedancer-only.  More distinct hashes than fit inline, from votes:
   the spilled ones are tallied, verified, removed and reused through
   the spill file like inline ones. */

static void
test_hash_stake_spill( void ) {
  ulong n = 64UL;
  generate_validators( n );
  g_state_info[ 40 ].stake = 200UL; /* alone a quorum */
  void * em; fd_epoch_info_t * epoch_info = make_epoch( n, &em );
  ulong slot = 3UL;
  slot_state_t * ss = make_state( slot, epoch_info );
  int               fd = g_states.spill_fd;
  out_t t;

  fd_block_hash_t hash[ 42 ];
  for( ulong i=0UL; i<42UL; i++ ) state_random_hash( &hash[i] );
  for( ulong rank=1UL; rank<40UL; rank++ ) { /* own rank 0 does not notar: no safe-to-skip */
    fd_vote_t v = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[ rank ], test_bls_public_key, slot, &hash[ rank ], (ushort)rank, STATE_SHRED_VERSION );
    add_vote_helper( ss, &v, epoch_info, &t );
    FD_TEST( t.ok && fd_bls_set_is_null( t.o.bad ) && !t.o.certs_cnt );
    if( rank==HASH_STAKE_INLINE_MAX ) FD_TEST( !ss->votes.notar_hash_stake.spill_hwm ); /* 8 versions stay inline */
  }
  ulong sp = 39UL-HASH_STAKE_INLINE_MAX;
  FD_TEST( ss->votes.notar_hash_stake.used==(1U<<HASH_STAKE_INLINE_MAX)-1U && ss->votes.notar_hash_stake.spill_cnt==sp && ss->votes.notar_hash_stake.spill_hwm==sp );
  for( ulong rank=1UL; rank<40UL; rank++ ) FD_TEST( hash_stake_query( ss, fd, 0, &hash[ rank ] )==rank-1UL && notar_hash_stake_query( ss, &hash[ rank ] )==1UL );
  struct stat st; FD_TEST( !fstat( fd, &st ) && st.st_size>0L );

  fd_vote_t same = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[ 39 ], test_bls_public_key, slot, &hash[ 39 ], 39UL, STATE_SHRED_VERSION );
  fd_vote_t diff = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[ 39 ], test_bls_public_key, slot, &hash[ 1  ], 39UL, STATE_SHRED_VERSION );
  FD_TEST( slot_state_should_ignore_vote( ss, &g_states, &same ) );
  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &same )==SLASHABLE_OFFENCE_NONE );
  FD_TEST( slot_state_check_slashable_offence( ss, &g_states, &diff )==SLASHABLE_OFFENCE_NOTAR_DIFFERENT_HASH );
  fd_block_hash_t got; FD_TEST( !memcmp( slot_state_vote_hash( ss, &g_states, FD_VOTE_KIND_NOTAR, 39UL, 0UL, &got ), &hash[ 39 ], sizeof(fd_block_hash_t) ) );

  /* a forged quorum on a new spilled hash is verified away and its
     record reused */
  fd_vote_t forged = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[ 41 ], test_bls_public_key, slot, &hash[ 40 ], 40UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &forged, epoch_info, &t );
  FD_TEST( !t.ok && fd_bls_set_cnt( t.o.bad )==1UL && fd_bls_set_test( t.o.bad, 40UL ) && !t.o.certs_cnt );
  FD_TEST( hash_stake_query( ss, fd, 0, &hash[ 40 ] )==ULONG_MAX && ss->votes.notar_hash_stake.spill_cnt==sp && ss->votes.notar_hash_stake.spill_hwm==sp+1UL );
  FD_TEST( ss->votes.top_notar_stake==1UL && ss->votes.notar_or_skip_stake==39UL );
  fd_vote_t v41 = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[ 41 ], test_bls_public_key, slot, &hash[ 41 ], 41UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &v41, epoch_info, &t );
  FD_TEST( t.ok && hash_stake_query( ss, fd, 0, &hash[ 41 ] )==HASH_STAKE_INLINE_MAX+sp && ss->votes.notar_hash_stake.spill_hwm==sp+1UL );

  /* an honest quorum on a spilled hash certifies it */
  fd_vote_t heavy = fd_vote_construct_notar( sec_sign_fn, &g_state_sk[ 40 ], test_bls_public_key, slot, &hash[ 39 ], 40UL, STATE_SHRED_VERSION );
  add_vote_helper( ss, &heavy, epoch_info, &t );
  int has_notar = 0; for( ulong i=0UL; i<t.o.certs_cnt; i++ ) has_notar |= t.o.certs[i].kind==FD_CERT_KIND_NOTAR && !memcmp( &t.o.certs[i].notar.block_hash, &hash[ 39 ], sizeof(fd_block_hash_t) ) && t.o.certs[i].notar.stake==201UL;
  FD_TEST( t.ok && fd_bls_set_is_null( t.o.bad ) && has_notar && ss->votes.top_notar_stake==201UL );
  fd_bls_agg_t reward[1]; FD_TEST( slot_state_notar_reward_agg( ss, &g_states, reward ) && fd_bls_set_cnt( reward->set )==2UL );

  /* notar fallback: 12 ranks x 3 hashes */
  for( ulong rank=1UL; rank<13UL; rank++ ) {
    for( ulong j=0UL; j<FD_VOTOR_NOTAR_FALLBACK_VOTE_MAX; j++ ) {
      fd_block_hash_t h; state_random_hash( &h );
      fd_vote_t v = fd_vote_construct_notar_fallback( sec_sign_fn, &g_state_sk[ rank ], test_bls_public_key, slot, &h, (ushort)rank, STATE_SHRED_VERSION );
      add_vote_helper( ss, &v, epoch_info, &t );
      FD_TEST( t.ok && notar_fallback_hash_stake_query( ss, &h )==1UL );
      FD_TEST( slot_state_should_ignore_vote( ss, &g_states, &v ) );
      FD_TEST( !memcmp( slot_state_vote_hash( ss, &g_states, FD_VOTE_KIND_NOTAR_FALLBACK, rank, j, &got ), &h, sizeof(fd_block_hash_t) ) );
      fd_bls_set_t set[ fd_bls_set_word_cnt ]; fd_bls_set_null( set ); fd_bls_set_insert( set, rank );
      fd_bls_sig_t sigs[ FD_VOTOR_VAT_MAX ];
      slot_state_sigs( ss, &g_states, FD_VOTE_KIND_NOTAR_FALLBACK, &h, set, sigs );
      FD_TEST( !memcmp( &sigs[ rank ], &v.notar_fallback.sig, sizeof(fd_bls_sig_t) ) );
    }
  }
  FD_TEST( hash_stake_cnt( ss, 1 )==36UL && ss->votes.notar_fallback_hash_stake.spill_cnt==36UL-HASH_STAKE_INLINE_MAX );

  slot_state_null( ss, &g_states );
  assert_maps_empty( ss );
  FD_TEST( hash_stake_query( ss, fd, 0, &hash[ 39 ] )==ULONG_MAX );
  free( em );
}

static void
test_slot_state( void ) {

  g_states.sig_pg          = g_sig_pg;
  g_states.sig_pg_free     = g_sig_pg_free;
  g_states.prev_epoch_info = NULL;
  g_states.prev_epoch_rank = USHORT_MAX;
  g_states.prev_epoch_slot = ULONG_MAX;
  g_states.curr_epoch_info = NULL;
  g_states.curr_epoch_rank = USHORT_MAX;
  g_states.curr_epoch_slot = 0UL;
  g_states.next_epoch_info = NULL;
  g_states.next_epoch_rank = USHORT_MAX;
  g_states.next_epoch_slot = ULONG_MAX;
  g_states.spill_fd        = memfd_create( "votor_spill", 0 );
  FD_TEST( g_states.spill_fd>=0 );

  for( g_disk=0; g_disk<3; g_disk++ ) {
    slot_state_null( &slot_state_mem, &g_states );
    g_states.sig_pg_free_cnt = g_disk==0 ? SLOT_SIG_PG_MAX : g_disk==1 ? 0UL : 1UL;
    for( ulong i=0UL; i<SLOT_SIG_PG_MAX; i++ ) g_sig_pg_free[ i ] = (uint)i;
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
    test_notar_cert_implies_notar_fallback();
    test_poisoned_notar_aggregate();
    test_identity_partition();
    test_safe_to_events_verify();
    test_safe_to_skip_removes_forged_notar();
    test_safe_to_skip_verifies_skip_first();
    test_map_capacity();
    test_safe_to_skip_removes_table_mate();
    test_safe_to_skip_removes_head_middle_tail();
    test_notar_fallback_removes_head_middle_tail();
    test_skip_skip_fallback_conflict();
    test_notar_notar_fallback_conflict();

    test_set_insert_contains_iter();

    test_notar_stake_tally();
    test_notar_fallback_stake_tally();

    test_pool_ids_stable();
    test_hash_stake_spill();
  }
}

static int g_spill_fd = -1;


static ulong
notar_cnt( slot_state_t const *  state,
           slot_states_t const * states ) {
  ulong           cnt = 0UL;
  fd_block_hash_t hash;
  for( ulong id = hash_stake_next( state, states->spill_fd, 0, 0UL, &hash );
             id!=ULONG_MAX;
             id = hash_stake_next( state, states->spill_fd, 0, id+1UL, &hash ) ) {
    FD_TEST( hash_stake_query( state, states->spill_fd, 0, &hash )==id );
    cnt++;
  }
  FD_TEST( cnt==(ulong)fd_uint_popcnt( state->votes.notar_hash_stake.used )+state->votes.notar_hash_stake.spill_cnt );
  return cnt;
}

static fd_block_hash_t const *
own_notar_hash( slot_state_t const *  state,
                slot_states_t const * states ) {
  static fd_block_hash_t hash;
  if( FD_UNLIKELY( state->own_rank==USHORT_MAX || !fd_bls_set_test( state->votes.notar_set, state->own_rank ) ) ) return &fd_block_hash_null;
  return slot_state_vote_hash( state, states, FD_VOTE_KIND_NOTAR, state->own_rank, 0UL, &hash );
}

static fd_bls_agg_t *
notar_agg( slot_state_t const *    state,
           slot_states_t const *   states,
           fd_block_hash_t const * hash,
           fd_bls_agg_t *          agg ) {
  fd_bls_set_t set[ fd_bls_set_word_cnt ];
  fd_bls_set_null( set );
  for( ulong rank=0UL; rank<FD_VOTOR_VAT_MAX; rank++ ) {
    if( FD_LIKELY( fd_bls_set_test( state->votes.notar_set, rank ) && hash_stake_eq( state, states->spill_fd, 0, state->votes.notar_hash_stake_idx[ rank ], hash ) ) ) fd_bls_set_insert( set, rank );
  }
  fd_bls_sig_t sigs[ FD_VOTOR_VAT_MAX ];
  slot_state_sigs( state, states, FD_VOTE_KIND_NOTAR, hash, set, sigs );
  fd_bls_agg_null( agg );
  return fd_bls_agg_construct( agg, fd_ptr_if( state->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( state->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) )->pubkeys, sigs, set );
}

static int
has_notar_cert( fd_votor_pool_t const * pool,
                ulong                   slot ) {
  slot_state_ele_t const * e = slot_state_map_ele_query_const( pool->slot_states->map, &slot, NULL, pool->slot_states->pool );
  return e && e->slot_state.certs.notar.slot!=ULONG_MAX;
}

static int
has_skip_cert( fd_votor_pool_t const * pool,
               ulong                   slot ) {
  slot_state_ele_t const * e = slot_state_map_ele_query_const( pool->slot_states->map, &slot, NULL, pool->slot_states->pool );
  return e && e->slot_state.certs.skip.slot!=ULONG_MAX;
}

static int
has_final_cert( fd_votor_pool_t const * pool,
                ulong                   slot ) {
  slot_state_ele_t const * e = slot_state_map_ele_query_const( pool->slot_states->map, &slot, NULL, pool->slot_states->pool );
  return e && ( e->slot_state.certs.fast_final.slot!=ULONG_MAX ||
                e->slot_state.certs.final.slot     !=ULONG_MAX );
}

static int
contains_slot( fd_votor_pool_t const * pool,
               ulong                   slot ) {
  return slot_state_map_ele_query_const( pool->slot_states->map, &slot, NULL, pool->slot_states->pool )!=NULL;
}

static int
s2n_waiting( fd_votor_pool_t const * pool,
             fd_block_id_t const *   parent,
             fd_block_id_t const *   child ) {
  for( s2n_waiting_parent_cert_ele_t const * ele = s2n_waiting_parent_cert_map_ele_query_const( pool->s2n_waiting_parent_cert->map, &parent->slot, NULL, pool->s2n_waiting_parent_cert->pool );
                                             ele;
                                             ele = s2n_waiting_parent_cert_map_ele_next_const( ele, NULL, pool->s2n_waiting_parent_cert->pool ) ) {
    if( fd_block_id_eq( &ele->parent, parent ) && fd_block_id_eq( &ele->child, child ) ) return 1;
  }
  return 0;
}

static ulong
s2n_waiting_cnt( fd_votor_pool_t const * pool ) {
  return s2n_waiting_parent_cert_pool_used( pool->s2n_waiting_parent_cert->pool );
}

static fd_epoch_info_t const *
epoch_info( fd_votor_pool_t const * pool,
            ulong                   slot ) {
  return fd_ptr_if( slot>=pool->slot_states->next_epoch_slot, pool->slot_states->next_epoch_info, fd_ptr_if( slot>=pool->slot_states->curr_epoch_slot, pool->slot_states->curr_epoch_info, pool->slot_states->prev_epoch_info ) );
}

static ulong
pool_first_unpruned_slot( fd_votor_pool_t const * pool ) {
  return fd_finality_tracker_first_unpruned_slot( pool->finality_tracker );
}

static ulong
min_live_slot( fd_votor_pool_t const * pool ) {
  slot_state_map_t const * map = pool->slot_states->map;
  slot_state_ele_t const * ele = pool->slot_states->pool;
  ulong min = ULONG_MAX;
  for( slot_state_map_iter_t iter = slot_state_map_iter_init( map, ele );
                                   !slot_state_map_iter_done( iter, map, ele );
                             iter = slot_state_map_iter_next( iter, map, ele ) ) {
    min = fd_ulong_min( min, slot_state_map_iter_ele_const( iter, map, ele )->slot );
  }
  return min;
}

#define FD_TEST_PRUNED_TO_WATERMARK( pool ) \
  FD_TEST( min_live_slot( pool )+FD_VOTOR_REWARD_SLOT_DELTA>=pool_first_unpruned_slot( pool ) )

static int
is_parent_ready( fd_votor_pool_t *     pool,
                 ulong                 slot,
                 fd_block_id_t const * parent ) {
  fd_block_id_t ready[ 64 ];
  ulong         cnt = fd_votor_pool_parents_ready( pool, slot, ready, 64UL );
  FD_TEST( cnt<=64UL );
  for( ulong i=0UL; i<cnt; i++ ) if( fd_block_id_eq( &ready[i], parent ) ) return 1;
  return 0;
}

static int
votor_event_pop( fd_votor_pool_t *       pool,
                 fd_votor_pool_event_t * out ) {
  return fd_votor_pool_poll_pool_event( pool, out );
}

static void
drain_events( fd_votor_pool_t * pool ) {
  fd_votor_pool_event_t event;
  while( fd_votor_pool_poll_pool_event( pool, &event ) );
  repair_events_remove_all( pool->repair_events );
}

#define SLOTS_PER_WINDOW FD_VOTOR_SLOTS_PER_WINDOW
#define NV               (11UL)

#define TEST_SLOT_MAX    (64UL)
#define TEST_BURST       (9UL)

#define TEST_SHRED_VERSION ((ushort)0x5a5a)

static fd_bls_set_t bad[ fd_bls_set_word_cnt ];
static uchar        quorum_reached;

#define SCRATCH_MAX (TEST_SLOT_MAX*(sizeof(slot_state_t)+SLOT_SIG_PG_MAX*(SIG_PG_SZ+sizeof(uint))+1024UL)+(4UL<<20))

static ulong g_sig_pg_max = TEST_SLOT_MAX*SLOT_SIG_PG_MAX; /* small: most sig pages live in the spill file */

static uchar scratch[ SCRATCH_MAX ] __attribute__((aligned(128)));
static fd_bls_sec_t      g_sk  [ NV ];
static fd_validator_info_t g_info[ NV ];
static void
genesis_hash( fd_block_hash_t * out ) {
  fd_memset( out, 1, sizeof(fd_block_hash_t) );
}

static ulong g_hash_ctr = 0UL;

static void
random_hash( fd_block_hash_t * out ) {
  fd_memset( out, 0, sizeof(fd_block_hash_t) );
  FD_STORE( ulong, out->uc,     0x9000UL + (++g_hash_ctr) );
  FD_STORE( ulong, out->uc+8UL, 0xc0ffee00UL ^ g_hash_ctr );
}

static fd_block_id_t
random_block_id( ulong slot ) {
  fd_block_id_t b; b.slot = slot; random_hash( &b.hash );
  return b;
}

static void
create_validators( void ) {
  for( ulong i=0UL; i<NV; i++ ) {
    fd_memset( &g_sk[i], (int)(i*7UL+1UL), FD_BLS_SEC_SZ );
    memset( &g_info[i], 0, sizeof(fd_validator_info_t) );
    g_info[i].id    = i;
    g_info[i].stake = 1UL;
    bls_key_from_sec( g_info[i].bls_key, &g_sk[i] );
  }
}

static fd_votor_pool_event_t g_event[ TEST_SLOT_MAX ];

static ulong
take_events( fd_votor_pool_t * pool ) {
  ulong cnt = 0UL;
  while( cnt<TEST_SLOT_MAX && votor_event_pop( pool, &g_event[ cnt ] ) ) cnt++;
  FD_TEST( pool_events_empty( pool->pool_events ) );
  return cnt;
}

static fd_votor_pool_event_t const *
event( ulong i ) {
  return &g_event[ i ];
}

/* src/consensus/pool.rs::recover_from_standstill, collected from
   fd_votor_pool_standstill_iter into the reference's bundle so the tests
   ported from the reference still apply. */

#define STANDSTILL_CERT_MAX (TEST_SLOT_MAX*8UL)
#define STANDSTILL_VOTE_MAX (TEST_SLOT_MAX*7UL)

static fd_cert_t g_standstill_cert[ STANDSTILL_CERT_MAX ];
static fd_vote_t g_standstill_vote[ STANDSTILL_VOTE_MAX ];

static fd_standstill_t
recover_from_standstill( fd_votor_pool_t const * pool ) {
  fd_standstill_t standstill = { .slot = fd_votor_pool_finalized_slot( pool )+1UL, .certs = g_standstill_cert, .votes = g_standstill_vote };
  fd_votor_pool_standstill_iter_t iter_[1];
  for( fd_votor_pool_standstill_iter_t * iter = fd_votor_pool_standstill_iter_init( iter_, pool ); !fd_votor_pool_standstill_iter_done( iter ); fd_votor_pool_standstill_iter_next( iter, pool ) ) {
    if( iter->is_vote ) { FD_TEST( standstill.vote_cnt<STANDSTILL_VOTE_MAX ); standstill.votes[ standstill.vote_cnt++ ] = iter->vote; }
    else                { FD_TEST( standstill.cert_cnt<STANDSTILL_CERT_MAX ); standstill.certs[ standstill.cert_cnt++ ] = iter->cert; }
  }
  return standstill;
}

/* At most three epoch infos are live at once: a, b and c in
   test_retired_epoch_already_pruned.  They are ~281 KiB apiece and the
   tests compare them by address, so each needs its own storage. */

#define EPOCH_INFO_MAX (4UL)

static fd_epoch_info_t epoch_info_mem[ EPOCH_INFO_MAX ];

static fd_epoch_info_t *
make_epoch_info( ulong                       idx,
                 fd_validator_info_t const * info,
                 ulong                       cnt ) {
  FD_TEST( idx<EPOCH_INFO_MAX );
  fd_epoch_info_t * epoch_info = &epoch_info_mem[ idx ];
  epoch_info_build( epoch_info, info, cnt );
  return epoch_info;
}

static fd_epoch_info_t * g_epoch_info = NULL;

static fd_votor_pool_t *
setup_pool( void ) {
  create_validators();
  ulong slot_max = TEST_SLOT_MAX;
  FD_TEST( fd_votor_pool_footprint( slot_max, TEST_BURST, g_sig_pg_max )<=sizeof(scratch) );
  fd_votor_pool_t * pool = fd_votor_pool_join( fd_votor_pool_new( scratch, slot_max, TEST_BURST, g_sig_pg_max, 42UL, g_spill_fd ) );
  FD_TEST( pool );
  fd_votor_pool_from_genesis( pool, &(fd_block_id_t){ .slot = 0UL } );

  g_epoch_info = make_epoch_info( 0UL, g_info, NV );
  fd_votor_pool_advance_epoch( pool, g_epoch_info, 0UL, 0UL );
  return pool;
}

/* Every RAM sig page is free or owned by exactly one live slot. */

static uchar g_pg_own[ TEST_SLOT_MAX*SLOT_SIG_PG_MAX ];

static void
check_sig_pgs( fd_votor_pool_t const * pool ) {
  slot_states_t const * ss  = pool->slot_states;
  ulong                 cnt = ss->sig_pg_free_cnt;
  fd_memset( g_pg_own, 0, sizeof(g_pg_own) );
  for( ulong i=0UL; i<cnt; i++ ) { FD_TEST( ss->sig_pg_free[ i ]<g_sig_pg_max && !g_pg_own[ ss->sig_pg_free[ i ] ] ); g_pg_own[ ss->sig_pg_free[ i ] ] = 1; }
  for( ulong i=0UL; i<slot_state_pool_max( ss->pool ); i++ ) {
    slot_state_ele_t const * ele = ss->pool+i;
    if( slot_state_map_ele_query_const( ss->map, &ele->slot, NULL, ss->pool )!=ele ) continue;
    for( ulong ks=0UL; ks<FD_VOTOR_VOTES_PER_SLOT_MAX; ks++ ) {
      for( ulong w=0UL; w<fd_bls_set_word_cnt; w++ ) {
        uint pg = ele->slot_state.sig_pg[ ks ][ w ];
        if( !pg || pg==SIG_PG_DISK ) continue;
        FD_TEST( pg-1U<g_sig_pg_max && !g_pg_own[ pg-1U ] ); g_pg_own[ pg-1U ] = 1;
        cnt++;
      }
    }
  }
  FD_TEST( cnt==g_sig_pg_max );
}
static ulong
ram_pg_cnt( slot_state_t const * state ) {
  ulong cnt = 0UL;
  for( ulong ks=0UL; ks<FD_VOTOR_VOTES_PER_SLOT_MAX; ks++ ) for( ulong w=0UL; w<fd_bls_set_word_cnt; w++ ) cnt += state->sig_pg[ ks ][ w ] && state->sig_pg[ ks ][ w ]!=SIG_PG_DISK;
  return cnt;
}

static void
teardown_pool_only( fd_votor_pool_t * pool ) {
  check_sig_pgs( pool );
  fd_votor_pool_delete( fd_votor_pool_leave( pool ) );
}

static void
teardown_pool( fd_votor_pool_t * pool ) {
  check_sig_pgs( pool );
  fd_votor_pool_delete( fd_votor_pool_leave( pool ) );
  g_epoch_info = NULL;
}

static void
add_notar_votes( fd_votor_pool_t *       pool,
                 ulong                   slot,
                 fd_block_hash_t const * hash,
                 ulong                   lo,
                 ulong                   hi ) {
  for( ulong v=lo; v<hi; v++ ) {
    fd_vote_t vote = fd_vote_construct_notar( sec_sign_fn, &g_sk[v], test_bls_public_key, slot, hash, (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( fd_votor_pool_add_vote( pool, &vote, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
    drain_events( pool );
  }
}

static void
add_notar_fallback_votes( fd_votor_pool_t *       pool,
                          ulong                   slot,
                          fd_block_hash_t const * hash,
                          ulong                   lo,
                          ulong                   hi ) {
  for( ulong v=lo; v<hi; v++ ) {
    fd_vote_t vote = fd_vote_construct_notar_fallback( sec_sign_fn, &g_sk[v], test_bls_public_key, slot, hash, (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( fd_votor_pool_add_vote( pool, &vote, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
    drain_events( pool );
  }
}

static void
add_skip_votes( fd_votor_pool_t * pool,
                ulong             slot,
                ulong             lo,
                ulong             hi ) {
  for( ulong v=lo; v<hi; v++ ) {
    fd_vote_t vote = fd_vote_construct_skip( sec_sign_fn, &g_sk[v], test_bls_public_key, slot, (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( fd_votor_pool_add_vote( pool, &vote, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
    drain_events( pool );
  }
}

static void
add_final_votes( fd_votor_pool_t * pool,
                 ulong             slot,
                 ulong             lo,
                 ulong             hi ) {
  for( ulong v=lo; v<hi; v++ ) {
    fd_vote_t vote = fd_vote_construct_final( sec_sign_fn, &g_sk[v], test_bls_public_key, slot, (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( fd_votor_pool_add_vote( pool, &vote, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
    drain_events( pool );
  }
}

static void
notar_cert( fd_votor_pool_t *       pool,
            ulong                   slot,
            fd_block_hash_t const * hash,
            ulong                   signers ) {
  FD_TEST( signers<=NV );
  fd_vote_notar_t nv[ NV ];
  for( ulong v=0UL; v<signers; v++ ) nv[v] = fd_vote_construct_notar( sec_sign_fn, &g_sk[v], test_bls_public_key, slot, hash, (ushort)v, TEST_SHRED_VERSION ).notar;
  fd_cert_t c = cert_build_notar( nv, signers, g_epoch_info );
  FD_TEST( fd_votor_pool_add_cert( pool, &c, 0, bad )==FD_VOTOR_POOL_SUCCESS );
  drain_events( pool );
}

static int
drained_safe_to_notar( fd_votor_pool_t *       pool,
                       ulong                   slot,
                       fd_block_hash_t const * hash ) {
  ulong cnt = take_events( pool );
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_votor_pool_event_t const * e = event( i );
    if( e->kind!=FD_VOTOR_POOL_EVENT_SAFE_TO_NOTAR ) continue;
    if( e->safe_to_notar.slot==slot &&
        !memcmp( &e->safe_to_notar.hash, hash, sizeof(fd_block_hash_t) ) ) return 1;
  }
  return 0;
}

static void
fast_finalize( fd_votor_pool_t *       pool,
               ulong                   slot,
               fd_block_hash_t const * hash ) {
  fd_vote_notar_t nv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) nv[v] = fd_vote_construct_notar( sec_sign_fn, &g_sk[v], test_bls_public_key, slot, hash, (ushort)v, TEST_SHRED_VERSION ).notar;
  fd_cert_t c = cert_build_fast_final( nv, NV, g_epoch_info );
  FD_TEST( fd_votor_pool_add_cert( pool, &c, 0, bad )==FD_VOTOR_POOL_SUCCESS );
  drain_events( pool );
}

/* src/consensus/pool.rs::notarize_block */

static void
test_notarize_block( void ) {
  fd_votor_pool_t * pool = setup_pool();
  fd_block_hash_t gh; genesis_hash( &gh );

  FD_TEST( !has_notar_cert( pool, 0UL ) );
  add_notar_votes( pool, 0UL, &gh, 0UL, 11UL );
  FD_TEST(  has_notar_cert( pool, 0UL ) );

  FD_TEST( !has_notar_cert( pool, 1UL ) );
  add_notar_votes( pool, 1UL, &gh, 0UL, 7UL );
  FD_TEST(  has_notar_cert( pool, 1UL ) );
  FD_TEST(  fd_uchar_extract_bit( quorum_reached, FD_VOTOR_POOL_QUORUM_REACHED_NOTAR ) );

  FD_TEST( !has_notar_cert( pool, 2UL ) );
  add_notar_votes( pool, 2UL, &gh, 0UL, 6UL );
  FD_TEST( !has_notar_cert( pool, 2UL ) );
  FD_TEST( !quorum_reached );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::skip_block */

static void
test_skip_block( void ) {
  fd_votor_pool_t * pool = setup_pool();

  FD_TEST( !has_skip_cert( pool, 0UL ) );
  add_skip_votes( pool, 0UL, 0UL, 11UL );
  FD_TEST(  has_skip_cert( pool, 0UL ) );

  FD_TEST( !has_skip_cert( pool, 1UL ) );
  add_skip_votes( pool, 1UL, 0UL, 7UL );
  FD_TEST(  has_skip_cert( pool, 1UL ) );

  FD_TEST( !has_skip_cert( pool, 2UL ) );
  add_skip_votes( pool, 2UL, 0UL, 6UL );
  FD_TEST( !has_skip_cert( pool, 2UL ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::finalize_block */

static void
test_finalize_block( void ) {
  fd_votor_pool_t * pool = setup_pool();

  ulong slot1 = 1UL;
  fd_block_hash_t hash1; random_hash( &hash1 );
  add_notar_votes( pool, slot1, &hash1, 0UL, 7UL );
  FD_TEST( !has_final_cert( pool, slot1 ) );
  FD_TEST( fd_votor_pool_finalized_slot( pool )==0UL );

  add_final_votes( pool, slot1, 0UL, 7UL );
  FD_TEST( has_final_cert( pool, slot1 ) );
  FD_TEST( fd_votor_pool_finalized_slot( pool )==slot1 );

  ulong slot2 = 2UL;
  add_final_votes( pool, slot2, 0UL, 7UL );
  FD_TEST( has_final_cert( pool, slot2 ) );
  FD_TEST( fd_votor_pool_finalized_slot( pool )==slot1 );

  fd_block_hash_t hash2; random_hash( &hash2 );
  add_notar_votes( pool, slot2, &hash2, 0UL, 7UL );
  FD_TEST( has_final_cert( pool, slot2 ) );
  FD_TEST( fd_votor_pool_finalized_slot( pool )==slot2 );

  ulong slot3 = 3UL;
  fd_block_hash_t hash3; random_hash( &hash3 );
  add_notar_votes( pool, slot3, &hash3, 0UL, 6UL );
  add_final_votes( pool, slot3, 0UL, 6UL );
  FD_TEST( !has_final_cert( pool, slot3 ) );
  FD_TEST( fd_votor_pool_finalized_slot( pool )==slot2 );

  teardown_pool( pool );
}

static void
test_cert_and_agg_rewards( void ) {
  fd_votor_pool_t * pool = setup_pool();

  ulong           slot = 1UL;
  fd_cert_notar_t notar_cert;
  fd_cert_final_t final_cert;
  fd_bls_agg_t    notar;
  fd_bls_agg_t    skip;
  FD_TEST( !fd_votor_pool_notar_cert ( pool, slot, &notar_cert ) );
  FD_TEST( !fd_votor_pool_agg_rewards( pool, slot, &notar, &skip, bad ) );
  FD_TEST( fd_bls_set_is_null( notar.set ) && fd_bls_set_is_null( skip.set ) && fd_bls_set_is_null( bad ) );

  fd_block_hash_t notar_hash; random_hash( &notar_hash );
  add_notar_votes( pool, slot, &notar_hash, 0UL, 7UL );
  FD_TEST( fd_votor_pool_notar_cert( pool, slot, &notar_cert )==&notar_cert );
  FD_TEST( notar_cert.slot==slot && fd_memeq( &notar_cert.block_hash, &notar_hash, sizeof(fd_block_hash_t) ) );
  FD_TEST( !fd_votor_pool_final_cert( pool, slot, &final_cert ) );
  add_final_votes( pool, slot, 0UL, 7UL );
  FD_TEST( fd_votor_pool_final_cert( pool, slot, &final_cert )==&final_cert );
  FD_TEST( final_cert.slot==slot );
  fd_block_hash_t const * hash = fd_votor_pool_agg_rewards( pool, slot, &notar, &skip, bad );
  FD_TEST( hash && fd_memeq( hash, &notar_hash, sizeof(fd_block_hash_t) ) && fd_bls_set_cnt( notar.set )==7UL && fd_bls_set_is_null( skip.set ) && fd_bls_set_is_null( bad ) );

  add_skip_votes( pool, slot, 7UL, 8UL );
  hash = fd_votor_pool_agg_rewards( pool, slot, &notar, &skip, bad );
  FD_TEST( hash && fd_bls_set_cnt( notar.set )==7UL && fd_bls_set_cnt( skip.set )==1UL && fd_bls_set_is_null( bad ) );

  teardown_pool( pool );
}

static void
test_reward_readback_window( void ) {
  fd_votor_pool_t * pool = setup_pool();

  ulong slot = 1UL;
  fd_block_hash_t hash; random_hash( &hash );
  add_notar_votes( pool, slot, &hash, 0UL, 7UL );
  add_final_votes( pool, slot, 0UL, 7UL );
  FD_TEST( has_final_cert( pool, slot ) );
  add_notar_votes( pool, slot, &hash, 7UL, 10UL );
  add_skip_votes( pool, slot, 10UL, 11UL );

  slot_state_t const * state = slot_state_query( pool, slot );
  FD_TEST( state );
  slot_votes_t const * votes = &state->votes;
  FD_TEST( notar_cnt( state, pool->slot_states )==1UL );
  fd_bls_agg_t notar[1];
  notar_agg( state, pool->slot_states, &hash, notar );
  FD_TEST( fd_bls_set_cnt( notar->set )==10UL );
  FD_TEST( fd_bls_set_cnt( votes->skip_agg.set )==1UL );

  uchar msg[ FD_VOTE_SIGNING_SER_MAX ];
  ulong msg_sz = fd_vote_signing_ser( FD_VOTE_KIND_NOTAR, slot, &hash, TEST_SHRED_VERSION, msg );
  FD_TEST( fd_bls_agg_verify( msg, msg_sz, &notar->pub, &notar->sig ) );
  msg_sz = fd_vote_signing_ser( FD_VOTE_KIND_SKIP, slot, NULL, TEST_SHRED_VERSION, msg );
  FD_TEST( fd_bls_agg_verify( msg, msg_sz, &votes->skip_agg.pub, &votes->skip_agg.sig ) );

  for( ulong s=slot+1UL; s<=slot+FD_VOTOR_REWARD_SLOT_DELTA; s++ ) {
    fd_block_hash_t hash2; random_hash( &hash2 );
    add_notar_votes( pool, s, &hash2, 0UL, 7UL );
    add_final_votes( pool, s, 0UL, 7UL );
    FD_TEST( slot_state_query( pool, slot ) ); /* retained for the reward certs */
  }
  fd_block_hash_t hash2; random_hash( &hash2 );
  add_notar_votes( pool, slot+FD_VOTOR_REWARD_SLOT_DELTA+1UL, &hash2, 0UL, 7UL );
  add_final_votes( pool, slot+FD_VOTOR_REWARD_SLOT_DELTA+1UL, 0UL, 7UL );
  FD_TEST( !slot_state_query( pool, slot ) );

  teardown_pool( pool );
}

static void
test_reward_late_skip_unverified( void ) {
  fd_votor_pool_t * pool = setup_pool();

  ulong slot = 1UL;
  add_skip_votes( pool, slot, 0UL, 7UL );
  FD_TEST( has_skip_cert( pool, slot ) );
  fd_vote_t poisoned = fd_vote_construct_skip( sec_sign_fn, &g_sk[4], test_bls_public_key, slot, (ushort)8, TEST_SHRED_VERSION );
  FD_TEST( fd_votor_pool_add_vote( pool, &poisoned, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
  FD_TEST( fd_bls_set_is_null( bad ) );
  drain_events( pool );

  slot_state_t const * state = slot_state_query( pool, slot );
  FD_TEST( state );
  FD_TEST( fd_bls_set_cnt( state->votes.skip_agg.set )==8UL );
  FD_TEST( fd_bls_set_cnt( state->certs.skip.agg_skip.set )==7UL );
  fd_bls_sig_t skip_sig[ FD_VOTOR_VAT_MAX ];
  slot_state_sigs( state, pool->slot_states, FD_VOTE_KIND_SKIP, NULL, state->votes.skip_agg.set, skip_sig );

  uchar msg[ FD_VOTE_SIGNING_SER_MAX ];
  ulong msg_sz = fd_vote_signing_ser( FD_VOTE_KIND_SKIP, slot, NULL, TEST_SHRED_VERSION, msg );
  FD_TEST( !fd_bls_agg_verify( msg, msg_sz, &state->votes.skip_agg.pub, &state->votes.skip_agg.sig ) );

  fd_bls_agg_t base = state->certs.skip.agg_skip;
  memset( &base.pub, 0, sizeof(fd_bls_pub_t) );
  for( ulong rank = fd_bls_set_const_iter_init( base.set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( base.set, rank ) ) {
    fd_bls_pub_add( &base.pub, &base.pub, g_epoch_info->pubkeys+rank );
  }
  fd_bls_agg_t extra = { 0 };
  for( ulong rank = fd_bls_set_const_iter_init( state->votes.skip_agg.set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( state->votes.skip_agg.set, rank ) ) {
    if( FD_UNLIKELY( fd_bls_set_test( base.set, rank ) ) ) continue;
    fd_bls_set_insert( extra.set, rank );
    fd_bls_pub_add( &extra.pub, &extra.pub, g_epoch_info->pubkeys       +rank );
    fd_bls_sig_add( &extra.sig, &extra.sig, skip_sig+rank );
  }
  FD_TEST( fd_bls_set_cnt( extra.set )==1UL && fd_bls_set_test( extra.set, 8UL ) );
  fd_bls_agg_t agg = base;
  fd_bls_pub_add( &agg.pub, &agg.pub, &extra.pub );
  fd_bls_sig_add( &agg.sig, &agg.sig, &extra.sig );
  fd_bls_set_union( agg.set, agg.set, extra.set );
  FD_TEST( fd_bls_set_cnt( agg.set )==8UL );
  FD_TEST( !fd_bls_agg_verify( msg, msg_sz, &agg.pub, &agg.sig ) );

  fd_bls_agg_t extra_sub = extra;
  FD_TEST( fd_bls_agg_verify_subtract( &extra_sub, msg, msg_sz, g_epoch_info->pubkeys, skip_sig, bad ) );
  FD_TEST( fd_bls_set_cnt( bad )==1UL && fd_bls_set_test( bad, 8UL ) );
  for( ulong rank = fd_bls_set_const_iter_init( bad );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( bad, rank ) ) {
    fd_bls_pub_t neg_pub; fd_bls_pub_neg( &neg_pub, g_epoch_info->pubkeys+rank );
    fd_bls_sig_t neg_sig; fd_bls_sig_neg( &neg_sig, skip_sig+rank );
    fd_bls_pub_add( &agg.pub, &agg.pub, &neg_pub );
    fd_bls_sig_add( &agg.sig, &agg.sig, &neg_sig );
    fd_bls_set_remove( agg.set, rank );
  }
  FD_TEST( fd_bls_agg_verify( msg, msg_sz, &agg.pub, &agg.sig ) );
  FD_TEST( fd_bls_set_cnt( agg.set )==7UL );

  fd_block_hash_t hash; random_hash( &hash );
  add_notar_votes( pool, slot+1UL, &hash, 0UL, 7UL );
  FD_TEST( has_notar_cert( pool, slot+1UL ) );
  poisoned = fd_vote_construct_notar( sec_sign_fn, &g_sk[4], test_bls_public_key, slot+1UL, &hash, (ushort)8, TEST_SHRED_VERSION );
  FD_TEST( fd_votor_pool_add_vote( pool, &poisoned, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
  FD_TEST( fd_bls_set_is_null( bad ) );
  drain_events( pool );
  state = slot_state_query( pool, slot+1UL );
  FD_TEST( state );
  fd_bls_agg_t notar[1];
  notar_agg( state, pool->slot_states, &hash, notar );
  FD_TEST( notar_cnt( state, pool->slot_states )==1UL && fd_bls_set_cnt( notar->set )==8UL );
  FD_TEST( fd_bls_set_cnt( state->certs.notar.agg.set )==7UL );
  msg_sz = fd_vote_signing_ser( FD_VOTE_KIND_NOTAR, slot+1UL, &hash, TEST_SHRED_VERSION, msg );
  FD_TEST( !fd_bls_agg_verify( msg, msg_sz, &notar->pub, &notar->sig ) );

  teardown_pool( pool );
}

static void
test_reward_wire_cert_base( void ) {
  fd_votor_pool_t * pool = setup_pool();

  ulong slot = 1UL;
  fd_vote_skip_t          sv [ 5 ];
  fd_vote_skip_fallback_t sfv[ 4 ];
  for( ulong v=0UL; v<5UL; v++ ) sv [v] = fd_vote_construct_skip         ( sec_sign_fn, &g_sk[v],     test_bls_public_key, slot, (ushort)v,       TEST_SHRED_VERSION ).skip;
  for( ulong v=0UL; v<4UL; v++ ) sfv[v] = fd_vote_construct_skip_fallback( sec_sign_fn, &g_sk[v+5UL], test_bls_public_key, slot, (ushort)(v+5UL), TEST_SHRED_VERSION ).skip_fallback;
  fd_cert_t cert = cert_build_skip( sv, 5UL, sfv, 4UL, g_epoch_info );
  uchar buf[ FD_CERT_SER_MAX ];
  ulong buf_sz = fd_cert_ser( &cert, buf );
  ulong bit_cnt;
  FD_TEST( fd_cert_de( &cert, &bit_cnt, buf, buf_sz )==FD_CERT_DE_SUCCESS );
  FD_TEST( fd_votor_pool_add_cert( pool, &cert, 0, bad )==FD_VOTOR_POOL_SUCCESS );
  drain_events( pool );
  add_skip_votes( pool, slot, 0UL,  3UL  );
  add_skip_votes( pool, slot, 9UL,  11UL );

  slot_state_t const * state = slot_state_query( pool, slot );
  FD_TEST( state );
  FD_TEST( fd_bls_set_cnt( state->certs.skip.agg_skip.set )==5UL && fd_bls_set_cnt( state->certs.skip.agg_skip_fallback.set )==4UL );
  FD_TEST( fd_bls_set_cnt( state->votes.skip_agg.set )==5UL );
  fd_bls_sig_t skip_sig[ FD_VOTOR_VAT_MAX ];
  slot_state_sigs( state, pool->slot_states, FD_VOTE_KIND_SKIP, NULL, state->votes.skip_agg.set, skip_sig );

  uchar msg[ FD_VOTE_SIGNING_SER_MAX ];
  ulong msg_sz = fd_vote_signing_ser( FD_VOTE_KIND_SKIP, slot, NULL, TEST_SHRED_VERSION, msg );
  fd_bls_agg_t base = state->certs.skip.agg_skip;
  memset( &base.pub, 0, sizeof(fd_bls_pub_t) );
  for( ulong rank = fd_bls_set_const_iter_init( base.set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( base.set, rank ) ) {
    fd_bls_pub_add( &base.pub, &base.pub, g_epoch_info->pubkeys+rank );
  }
  FD_TEST( !fd_bls_agg_verify( msg, msg_sz, &base.pub, &base.sig ) );

  memset( &base, 0, sizeof(fd_bls_agg_t) );
  fd_bls_agg_t extra = { 0 };
  for( ulong rank = fd_bls_set_const_iter_init( state->votes.skip_agg.set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( state->votes.skip_agg.set, rank ) ) {
    if( FD_UNLIKELY( fd_bls_set_test( base.set, rank ) ) ) continue;
    fd_bls_set_insert( extra.set, rank );
    fd_bls_pub_add( &extra.pub, &extra.pub, g_epoch_info->pubkeys       +rank );
    fd_bls_sig_add( &extra.sig, &extra.sig, skip_sig+rank );
  }
  fd_bls_agg_t agg = base;
  fd_bls_pub_add( &agg.pub, &agg.pub, &extra.pub );
  fd_bls_sig_add( &agg.sig, &agg.sig, &extra.sig );
  fd_bls_set_union( agg.set, agg.set, extra.set );
  FD_TEST( fd_bls_set_cnt( agg.set )==5UL );
  FD_TEST( fd_bls_agg_verify( msg, msg_sz, &agg.pub, &agg.sig ) );

  fd_block_hash_t hash; random_hash( &hash );
  fd_vote_notar_t nv[ 7 ];
  for( ulong v=0UL; v<7UL; v++ ) nv[v] = fd_vote_construct_notar( sec_sign_fn, &g_sk[v], test_bls_public_key, slot+1UL, &hash, (ushort)v, TEST_SHRED_VERSION ).notar;
  cert   = cert_build_notar( nv, 7UL, g_epoch_info );
  buf_sz = fd_cert_ser( &cert, buf );
  FD_TEST( fd_cert_de( &cert, &bit_cnt, buf, buf_sz )==FD_CERT_DE_SUCCESS );
  FD_TEST( fd_votor_pool_add_cert( pool, &cert, 0, bad )==FD_VOTOR_POOL_SUCCESS );
  drain_events( pool );
  state = slot_state_query( pool, slot+1UL );
  FD_TEST( state && notar_cnt( state, pool->slot_states )==0UL && state->certs.notar.slot==slot+1UL );
  base = state->certs.notar.agg;
  FD_TEST( fd_bls_pub_is_inf( &base.pub ) );
  for( ulong rank = fd_bls_set_const_iter_init( base.set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( base.set, rank ) ) {
    fd_bls_pub_add( &base.pub, &base.pub, g_epoch_info->pubkeys+rank );
  }
  msg_sz = fd_vote_signing_ser( FD_VOTE_KIND_NOTAR, slot+1UL, &hash, TEST_SHRED_VERSION, msg );
  FD_TEST( fd_bls_set_cnt( base.set )==7UL );
  FD_TEST( fd_bls_agg_verify( msg, msg_sz, &base.pub, &base.sig ) );

  teardown_pool( pool );
}

static void
test_finalized_block_hash( void ) {
  fd_votor_pool_t * pool = setup_pool();

  FD_TEST( !fd_votor_pool_finalized_block_hash( pool ) ); /* nothing finalized */

  fd_block_hash_t hash1; random_hash( &hash1 );
  add_notar_votes( pool, 1UL, &hash1, 0UL, 7UL );
  add_final_votes( pool, 1UL, 0UL, 7UL );
  FD_TEST( fd_votor_pool_finalized_slot( pool )==1UL );
  FD_TEST( !memcmp( fd_votor_pool_finalized_block_hash( pool ), &hash1, sizeof(fd_block_hash_t) ) );

  /* the hash tracks the finalized slot as it advances */

  fd_block_hash_t hash2; random_hash( &hash2 );
  add_notar_votes( pool, 2UL, &hash2, 0UL, 11UL ); /* fast finalize */
  FD_TEST( fd_votor_pool_finalized_slot( pool )==2UL );
  FD_TEST( !memcmp( fd_votor_pool_finalized_block_hash( pool ), &hash2, sizeof(fd_block_hash_t) ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::fast_finalize_block */

static void
test_fast_finalize_block( void ) {
  fd_votor_pool_t * pool = setup_pool();
  fd_block_hash_t gh; genesis_hash( &gh );

  FD_TEST( !has_final_cert( pool, 0UL ) );
  add_notar_votes( pool, 0UL, &gh, 0UL, 11UL );
  FD_TEST(  has_final_cert( pool, 0UL ) );
  FD_TEST( fd_votor_pool_finalized_slot( pool )==0UL );

  FD_TEST( !has_final_cert( pool, 1UL ) );
  add_notar_votes( pool, 1UL, &gh, 0UL, 9UL );
  FD_TEST(  has_final_cert( pool, 1UL ) );
  FD_TEST( fd_votor_pool_finalized_slot( pool )==1UL );

  FD_TEST( !has_final_cert( pool, 2UL ) );
  add_notar_votes( pool, 2UL, &gh, 0UL, 8UL );
  FD_TEST( !has_final_cert( pool, 2UL ) );
  FD_TEST( fd_votor_pool_finalized_slot( pool )==1UL );

  teardown_pool( pool );
}

/* Firedancer-only test: a finalization reports the blocks it implicitly
   finalizes and the slots it implicitly skips as pool events. */

static void
test_implicit_finalization_events( void ) {
  fd_votor_pool_t * pool = setup_pool();

  fd_block_id_t b5 = random_block_id( 5UL );
  fd_block_id_t b7 = random_block_id( 7UL );
  FD_TEST( fd_votor_pool_add_block( pool, &b7, &b5, bad )==FD_VOTOR_POOL_SUCCESS );
  drain_events( pool );

  fd_vote_notar_t nv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) nv[v] = fd_vote_construct_notar( sec_sign_fn, &g_sk[v], test_bls_public_key, b7.slot, &b7.hash, (ushort)v, TEST_SHRED_VERSION ).notar;
  fd_cert_t c = cert_build_fast_final( nv, NV, g_epoch_info );
  FD_TEST( fd_votor_pool_add_cert( pool, &c, 0, bad )==FD_VOTOR_POOL_SUCCESS );

  ulong finalized = 0UL;
  ulong skipped   = 0UL;
  ulong cnt       = take_events( pool );
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_votor_pool_event_t const * e = event( i );
    finalized += e->kind==FD_VOTOR_POOL_EVENT_IMPLICITLY_FINALIZED && fd_block_id_eq( &e->implicitly_finalized, &b5 );
    skipped   += e->kind==FD_VOTOR_POOL_EVENT_IMPLICITLY_SKIPPED   && e->implicitly_skipped==6UL;
  }
  FD_TEST( finalized==1UL && skipped==1UL );

  teardown_pool( pool );
}

/* votor/src/event_handler.rs::Finalized request_repair */

static void
test_fast_final_cert_requests_repair( void ) {
  fd_votor_pool_t * pool = setup_pool();
  fd_block_hash_t hash; random_hash( &hash );

  fd_vote_notar_t nv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) nv[v] = fd_vote_construct_notar( sec_sign_fn, &g_sk[v], test_bls_public_key, 1UL, &hash, (ushort)v, TEST_SHRED_VERSION ).notar;
  fd_cert_t c = cert_build_fast_final( nv, NV, g_epoch_info );
  FD_TEST( fd_votor_pool_add_cert( pool, &c, 0, bad )==FD_VOTOR_POOL_SUCCESS );

  fd_block_id_t repair;
  FD_TEST( fd_votor_pool_poll_repair_event( pool, &repair ) );
  FD_TEST( repair.slot==1UL );
  FD_TEST( !memcmp( &repair.hash, &hash, sizeof(fd_block_hash_t) ) );
  FD_TEST( !fd_votor_pool_poll_repair_event( pool, &repair ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::simple_branch_certified */

static void
test_simple_branch_certified( void ) {
  fd_votor_pool_t * pool = setup_pool();

  fd_block_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) random_hash( &hashes[s] );
  for( ulong s=1UL; s<SLOTS_PER_WINDOW; s++ ) add_notar_votes( pool, s, &hashes[s], 0UL, 7UL );

  ulong slot = SLOTS_PER_WINDOW-1UL;
  ulong next = slot+1UL;
  fd_block_id_t parent = fd_block_id( slot, hashes[ next-1UL ].uc );
  FD_TEST( is_parent_ready( pool, next, &parent ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::branch_certified_notar_fallback */

static void
test_branch_certified_notar_fallback( void ) {
  fd_votor_pool_t * pool = setup_pool();

  fd_block_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) random_hash( &hashes[s] );
  for( ulong s=1UL; s<SLOTS_PER_WINDOW; s++ ) {
    fd_block_id_t parent = fd_block_id( s, hashes[s].uc );
    FD_TEST( !is_parent_ready( pool, s+1UL, &parent ) );
    add_notar_votes         ( pool, s, &hashes[s], 0UL, 4UL );
    add_notar_fallback_votes( pool, s, &hashes[s], 4UL, 7UL );
  }
  ulong slot = SLOTS_PER_WINDOW-1UL;
  ulong next = slot+1UL;
  fd_block_id_t parent = fd_block_id( slot, hashes[ next-1UL ].uc );
  FD_TEST( is_parent_ready( pool, next, &parent ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::branch_certified_out_of_order */

static void
test_branch_certified_out_of_order( void ) {
  fd_votor_pool_t * pool = setup_pool();

  for( ulong s=2UL; s<SLOTS_PER_WINDOW; s++ ) add_skip_votes( pool, s, 0UL, 7UL );

  ulong next = SLOTS_PER_WINDOW;
  ulong cnt = fd_votor_pool_parents_ready( pool, next, NULL, 0UL );
  FD_TEST( cnt==0UL );

  ulong slot1 = 1UL;
  fd_block_hash_t hash1; random_hash( &hash1 );
  add_notar_votes( pool, slot1, &hash1, 0UL, 7UL );

  fd_block_id_t parent = fd_block_id( slot1, hash1.uc );
  FD_TEST( is_parent_ready( pool, next, &parent ) );
  cnt = fd_votor_pool_parents_ready( pool, next, NULL, 0UL );
  FD_TEST( cnt==1UL );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::branch_certified_late_cert */

static void
test_branch_certified_late_cert( void ) {
  fd_votor_pool_t * pool = setup_pool();

  for( ulong s=2UL; s<SLOTS_PER_WINDOW; s++ ) add_skip_votes( pool, s, 0UL, 7UL );

  ulong next = SLOTS_PER_WINDOW;
  ulong cnt = fd_votor_pool_parents_ready( pool, next, NULL, 0UL );
  FD_TEST( cnt==0UL );

  ulong slot1 = 1UL;
  fd_block_hash_t hash1; random_hash( &hash1 );
  fd_vote_notar_t nv[7];
  for( ulong v=0UL; v<7UL; v++ ) nv[v] = fd_vote_construct_notar( sec_sign_fn, &g_sk[v], test_bls_public_key, slot1, &hash1, (ushort)v, TEST_SHRED_VERSION ).notar;
  fd_cert_t c = cert_build_notar( nv, 7UL, g_epoch_info );
  FD_TEST( fd_votor_pool_add_cert( pool, &c, 0, bad )==FD_VOTOR_POOL_SUCCESS );

  fd_block_id_t parent = fd_block_id( slot1, hash1.uc );
  FD_TEST( is_parent_ready( pool, next, &parent ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::regular_handover */

static void
test_regular_handover( void ) {
  fd_votor_pool_t * pool = setup_pool();
  fd_block_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) random_hash( &hashes[s] );

  for( ulong s=1UL; s<SLOTS_PER_WINDOW; s++ ) add_notar_votes( pool, s, &hashes[s], 0UL, 7UL );

  fd_block_id_t parent = fd_block_id( SLOTS_PER_WINDOW-1UL, hashes[ SLOTS_PER_WINDOW-1UL ].uc );
  FD_TEST( is_parent_ready( pool, SLOTS_PER_WINDOW, &parent ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::one_skip_handover */

static void
test_one_skip_handover( void ) {
  fd_votor_pool_t * pool = setup_pool();
  fd_block_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) random_hash( &hashes[s] );

  for( ulong s=1UL; s<SLOTS_PER_WINDOW-1UL; s++ ) add_notar_votes( pool, s, &hashes[s], 0UL, 7UL );
  add_skip_votes( pool, SLOTS_PER_WINDOW-1UL, 0UL, 7UL );

  fd_block_id_t parent = fd_block_id( SLOTS_PER_WINDOW-2UL, hashes[ SLOTS_PER_WINDOW-2UL ].uc );
  FD_TEST( is_parent_ready( pool, SLOTS_PER_WINDOW, &parent ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::two_skip_handover */

static void
test_two_skip_handover( void ) {
  fd_votor_pool_t * pool = setup_pool();
  fd_block_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) random_hash( &hashes[s] );

  for( ulong s=1UL; s<SLOTS_PER_WINDOW-2UL; s++ ) add_notar_votes( pool, s, &hashes[s], 0UL, 7UL );
  add_skip_votes( pool, SLOTS_PER_WINDOW-2UL, 0UL, 7UL );
  add_skip_votes( pool, SLOTS_PER_WINDOW-1UL, 0UL, 7UL );

  fd_block_id_t parent = fd_block_id( SLOTS_PER_WINDOW-3UL, hashes[ SLOTS_PER_WINDOW-3UL ].uc );
  FD_TEST( is_parent_ready( pool, SLOTS_PER_WINDOW, &parent ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::skip_window_handover */

static void
test_skip_window_handover( void ) {
  fd_votor_pool_t * pool = setup_pool();
  fd_block_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) random_hash( &hashes[s] );

  for( ulong s=1UL; s<SLOTS_PER_WINDOW; s++ ) add_notar_votes( pool, s, &hashes[s], 0UL, 7UL );
  for( ulong s=SLOTS_PER_WINDOW; s<2UL*SLOTS_PER_WINDOW; s++ ) add_skip_votes( pool, s, 0UL, 7UL );

  fd_block_id_t parent = fd_block_id( SLOTS_PER_WINDOW-1UL, hashes[ SLOTS_PER_WINDOW-1UL ].uc );
  FD_TEST( is_parent_ready( pool, 2UL*SLOTS_PER_WINDOW, &parent ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::pruning */

static void
test_pruning( void ) {
  fd_votor_pool_t * pool = setup_pool();

  ulong total = 3UL*SLOTS_PER_WINDOW + 10UL;
  fd_block_hash_t hashes[ 3UL*SLOTS_PER_WINDOW + 10UL ];
  for( ulong s=0UL; s<total; s++ ) random_hash( &hashes[s] );

  for( ulong s=1UL; s<3UL*SLOTS_PER_WINDOW; s++ ) {
    FD_TEST( !has_final_cert( pool, s ) );
    add_notar_votes( pool, s, &hashes[s], 0UL, 11UL );
    FD_TEST(  has_final_cert( pool, s ) );
  }
  ulong last_slot = 3UL*SLOTS_PER_WINDOW - 1UL;
  FD_TEST( fd_votor_pool_finalized_slot( pool )==last_slot );

  for( ulong s=0UL; s<last_slot; s++ ) FD_TEST( contains_slot( pool, s )==(s+FD_VOTOR_REWARD_SLOT_DELTA>=pool_first_unpruned_slot( pool )) );
  FD_TEST( contains_slot( pool, last_slot ) );
  FD_TEST_PRUNED_TO_WATERMARK( pool );

  for( ulong i=0UL; i<10UL; i++ ) {
    ulong s = last_slot + 1UL + i;
    add_notar_votes( pool, s, &hashes[s], 0UL, 8UL );
    FD_TEST( !has_final_cert( pool, s ) );
  }
  FD_TEST( fd_votor_pool_finalized_slot( pool )==last_slot );

  for( ulong s=0UL; s<=10UL; s++ ) FD_TEST( contains_slot( pool, last_slot+s ) );
  FD_TEST_PRUNED_TO_WATERMARK( pool );

  for( ulong i=0UL; i<10UL; i++ ) {
    ulong s = last_slot + 1UL + i;
    add_notar_votes( pool, s, &hashes[s], 8UL, 9UL );
    FD_TEST( has_final_cert( pool, s ) );
  }
  FD_TEST( fd_votor_pool_finalized_slot( pool )==last_slot+10UL );

  for( ulong s=0UL; s<10UL; s++ ) FD_TEST( contains_slot( pool, last_slot+s )==(last_slot+s+FD_VOTOR_REWARD_SLOT_DELTA>=pool_first_unpruned_slot( pool )) );
  FD_TEST( contains_slot( pool, last_slot+10UL ) );
  FD_TEST_PRUNED_TO_WATERMARK( pool );

  teardown_pool( pool );
}
static void
test_sig_pg_released_on_prune( void ) {
  fd_votor_pool_t *        pool   = setup_pool();
  slot_states_t * states = pool->slot_states;
  FD_TEST( states->sig_pg_free_cnt==g_sig_pg_max );

  ulong           slot   = 1UL;
  ulong           voters = 6UL; /* below quorum, so no cert is created */
  fd_block_hash_t hash[ 1UL+FD_VOTOR_NOTAR_FALLBACK_VOTE_MAX ];
  for( ulong i=0UL; i<1UL+FD_VOTOR_NOTAR_FALLBACK_VOTE_MAX; i++ ) random_hash( &hash[ i ] );
  add_notar_votes( pool, slot, &hash[ 0 ], 0UL, voters );
  for( ulong i=1UL; i<1UL+FD_VOTOR_NOTAR_FALLBACK_VOTE_MAX; i++ ) add_notar_fallback_votes( pool, slot, &hash[ i ], 0UL, voters );
  for( ulong v=0UL; v<voters; v++ ) {
    fd_vote_t vote = fd_vote_construct_skip_fallback( sec_sign_fn, &g_sk[v], test_bls_public_key, slot, (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( fd_votor_pool_add_vote( pool, &vote, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS && fd_bls_set_is_null( bad ) );
    drain_events( pool );
  }

  slot_state_t const * state = slot_state_query( pool, slot );
  FD_TEST( state && state->certs.notar.slot==ULONG_MAX && !state->certs.notar_fallback_cnt && state->certs.skip.slot==ULONG_MAX );
  FD_TEST( fd_bls_set_cnt( state->votes.notar_set )==voters && fd_bls_set_cnt( state->votes.skip_fallback_agg.set )==voters );
  for( ulong v=0UL; v<voters; v++ ) FD_TEST( state->votes.notar_fallback_sig_cnt[ v ]==FD_VOTOR_NOTAR_FALLBACK_VOTE_MAX );
  FD_TEST( ram_pg_cnt( state )==FD_VOTOR_VOTES_PER_SLOT_MAX && states->sig_pg_free_cnt==g_sig_pg_max-FD_VOTOR_VOTES_PER_SLOT_MAX ); /* NV ranks: one page per kind slot */
  FD_TEST( fd_uint_popcnt( state->votes.notar_hash_stake.used )==1 && fd_uint_popcnt( state->votes.notar_fallback_hash_stake.used )==(int)FD_VOTOR_NOTAR_FALLBACK_VOTE_MAX );
  for( ulong v=0UL; v<voters; v++ ) {
    fd_bls_sig_t sig;
    fd_vote_t    want = fd_vote_construct_notar( sec_sign_fn, &g_sk[v], test_bls_public_key, slot, &hash[ 0 ], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( !memcmp( slot_state_vote_sig( state, states, FD_VOTE_KIND_NOTAR, v, 0UL, &sig ), &want.notar.sig, sizeof(fd_bls_sig_t) ) );
    want = fd_vote_construct_skip_fallback( sec_sign_fn, &g_sk[v], test_bls_public_key, slot, (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( !memcmp( slot_state_vote_sig( state, states, FD_VOTE_KIND_SKIP_FALLBACK, v, 0UL, &sig ), &want.skip_fallback.sig, sizeof(fd_bls_sig_t) ) );
    for( ulong j=0UL; j<FD_VOTOR_NOTAR_FALLBACK_VOTE_MAX; j++ ) {
      want = fd_vote_construct_notar_fallback( sec_sign_fn, &g_sk[v], test_bls_public_key, slot, &hash[ 1UL+j ], (ushort)v, TEST_SHRED_VERSION );
      FD_TEST( !memcmp( slot_state_vote_sig( state, states, FD_VOTE_KIND_NOTAR_FALLBACK, v, j, &sig ), &want.notar_fallback.sig, sizeof(fd_bls_sig_t) ) );
    }
  }

  fd_block_hash_t other; random_hash( &other );
  for( ulong v=0UL; v<voters; v++ ) {
    fd_vote_t notar = fd_vote_construct_notar         ( sec_sign_fn, &g_sk[v], test_bls_public_key, slot, &other, (ushort)v, TEST_SHRED_VERSION );
    fd_vote_t nf    = fd_vote_construct_notar_fallback( sec_sign_fn, &g_sk[v], test_bls_public_key, slot, &other, (ushort)v, TEST_SHRED_VERSION );
    fd_vote_t skip  = fd_vote_construct_skip          ( sec_sign_fn, &g_sk[v], test_bls_public_key, slot,        (ushort)v, TEST_SHRED_VERSION );
    fd_vote_t sf    = fd_vote_construct_skip_fallback ( sec_sign_fn, &g_sk[v], test_bls_public_key, slot,        (ushort)v, TEST_SHRED_VERSION );
    fd_vote_t final = fd_vote_construct_final         ( sec_sign_fn, &g_sk[v], test_bls_public_key, slot,        (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( fd_votor_pool_add_vote( pool, &notar, 0, bad, &quorum_reached )==FD_VOTOR_POOL_ERR_SLASHABLE );
    FD_TEST( fd_votor_pool_add_vote( pool, &nf, 0,    bad, &quorum_reached )==FD_VOTOR_POOL_ERR_DUPLICATE );
    FD_TEST( fd_votor_pool_add_vote( pool, &skip, 0,  bad, &quorum_reached )==FD_VOTOR_POOL_ERR_SLASHABLE );
    FD_TEST( fd_votor_pool_add_vote( pool, &sf, 0,    bad, &quorum_reached )==FD_VOTOR_POOL_ERR_DUPLICATE );
    FD_TEST( fd_votor_pool_add_vote( pool, &final, 0, bad, &quorum_reached )==FD_VOTOR_POOL_ERR_SLASHABLE );
  }

  /* a cert-only slot takes no page; with every page taken a voted
     slot keeps its sigs in the spill file */
  ulong           far = TEST_SLOT_MAX-FD_VOTOR_REWARD_SLOT_DELTA-1UL;
  fd_block_hash_t far_hash; random_hash( &far_hash );
  fd_vote_notar_t nv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) nv[v] = fd_vote_construct_notar( sec_sign_fn, &g_sk[v], test_bls_public_key, far, &far_hash, (ushort)v, TEST_SHRED_VERSION ).notar;
  fd_cert_t far_cert = cert_build_notar( nv, NV, g_epoch_info );
  FD_TEST( fd_votor_pool_add_cert( pool, &far_cert, 0, bad )==FD_VOTOR_POOL_SUCCESS );
  drain_events( pool );
  ulong free1 = g_sig_pg_max-FD_VOTOR_VOTES_PER_SLOT_MAX;
  FD_TEST( !ram_pg_cnt( slot_state_query( pool, far ) ) && states->sig_pg_free_cnt==free1 );
  if( free1<far-slot-1UL ) {
    for( ulong s=slot+1UL; s<=slot+1UL+free1; s++ ) {
      fd_vote_t vote = fd_vote_construct_skip( sec_sign_fn, &g_sk[0], test_bls_public_key, s, 0, TEST_SHRED_VERSION );
      FD_TEST( fd_votor_pool_add_vote( pool, &vote, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS && fd_bls_set_is_null( bad ) );
      drain_events( pool );
      uint pg = slot_state_query( pool, s )->sig_pg[ 0 ][ 0 ];
      FD_TEST( s<=slot+free1 ? pg && pg!=SIG_PG_DISK : pg==SIG_PG_DISK );
    }
    slot_state_t const * disk = slot_state_query( pool, slot+1UL+free1 );
    FD_TEST( disk->sig_pg[ 0 ][ 0 ]==SIG_PG_DISK && !states->sig_pg_free_cnt );
    fd_bls_sig_t sig;
    fd_vote_t    want = fd_vote_construct_skip( sec_sign_fn, &g_sk[0], test_bls_public_key, slot+1UL+free1, 0, TEST_SHRED_VERSION );
    FD_TEST( !memcmp( slot_state_vote_sig( disk, states, FD_VOTE_KIND_SKIP, 0UL, 0UL, &sig ), &want.skip.sig, sizeof(fd_bls_sig_t) ) );
  }
  check_sig_pgs( pool );

  fast_finalize( pool, slot, &hash[ 0 ] );
  FD_TEST( contains_slot( pool, slot ) );
  for( ulong s=slot+1UL; s<=far+FD_VOTOR_REWARD_SLOT_DELTA+1UL; s++ ) {
    fd_block_hash_t h; random_hash( &h );
    fast_finalize( pool, s, s==far ? &far_hash : &h );
    if( s==slot+FD_VOTOR_REWARD_SLOT_DELTA+1UL ) { FD_TEST( !contains_slot( pool, slot ) ); check_sig_pgs( pool ); }
  }
  FD_TEST( !contains_slot( pool, far ) && states->sig_pg_free_cnt==g_sig_pg_max );

  teardown_pool( pool );
}

/* Firedancer-only test.

   Fill a slot with the most signatures the acceptance rules admit per
   rank (notar, three notar-fallback, skip-fallback), check every further
   vote from those ranks is refused and every sig reads back, take every
   other RAM page so the next voted slot keeps its sigs in the spill
   file, then prune and require every RAM page to be free. */


/* src/consensus/pool.rs::duplicate_votes */

static void
test_duplicate_votes( void ) {
  fd_votor_pool_t * pool = setup_pool();
  fd_block_hash_t gh; genesis_hash( &gh );
  ulong slot = 0UL;

  fd_vote_t v1 = fd_vote_construct_notar( sec_sign_fn, &g_sk[0], test_bls_public_key, slot, &gh, 0, TEST_SHRED_VERSION );
  FD_TEST( fd_votor_pool_add_vote( pool, &v1, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );

  fd_vote_t v2 = fd_vote_construct_skip( sec_sign_fn, &g_sk[1], test_bls_public_key, slot, 1, TEST_SHRED_VERSION );
  FD_TEST( fd_votor_pool_add_vote( pool, &v2, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );

  FD_TEST( fd_votor_pool_add_vote( pool, &v1, 0, bad, &quorum_reached )==FD_VOTOR_POOL_ERR_DUPLICATE );
  FD_TEST( fd_votor_pool_add_vote( pool, &v2, 0, bad, &quorum_reached )==FD_VOTOR_POOL_ERR_DUPLICATE );

  teardown_pool( pool );
}

/* auditor-internal#673: the subgroup check runs after the cheap
   admission checks, and a failing signature is rejected */

static void
test_vote_subgroup_after_duplicate( void ) {
  fd_votor_pool_t * pool = setup_pool();
  fd_block_hash_t gh; genesis_hash( &gh );
  ulong slot = 0UL;

  fd_vote_t good = fd_vote_construct_notar( sec_sign_fn, &g_sk[0], test_bls_public_key, slot, &gh, 0, TEST_SHRED_VERSION );
  fd_vote_t evil = good;
  test_bls_torsion( &evil.notar.sig );

  FD_TEST( fd_votor_pool_add_vote( pool, &evil, 0, bad, &quorum_reached )==FD_VOTOR_POOL_ERR_VOTE_VERIFY );
  FD_TEST( fd_bls_set_is_null( bad ) );

  FD_TEST( fd_votor_pool_add_vote( pool, &good, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
  FD_TEST( fd_bls_set_is_null( bad ) );

  FD_TEST( fd_votor_pool_add_vote( pool, &evil, 0, bad, &quorum_reached )==FD_VOTOR_POOL_ERR_DUPLICATE );
  FD_TEST( fd_bls_set_is_null( bad ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::duplicate_certs */

static void
test_duplicate_certs( void ) {
  fd_votor_pool_t * pool = setup_pool();

  ulong first_slot = 1UL;
  fd_block_hash_t hash; random_hash( &hash );
  fd_vote_notar_t nv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) nv[v] = fd_vote_construct_notar( sec_sign_fn, &g_sk[v], test_bls_public_key, first_slot, &hash, (ushort)v, TEST_SHRED_VERSION ).notar;
  fd_cert_t notar = cert_build_notar( nv, NV, g_epoch_info );
  FD_TEST( fd_votor_pool_add_cert( pool, &notar, 0, bad )==FD_VOTOR_POOL_SUCCESS );

  ulong second_slot = 2UL;
  fd_vote_skip_t sv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) sv[v] = fd_vote_construct_skip( sec_sign_fn, &g_sk[v], test_bls_public_key, second_slot, (ushort)v, TEST_SHRED_VERSION ).skip;
  fd_cert_t skip = cert_build_skip( sv, NV, NULL, 0UL, g_epoch_info );
  FD_TEST( fd_votor_pool_add_cert( pool, &skip, 0, bad )==FD_VOTOR_POOL_SUCCESS );

  FD_TEST( fd_votor_pool_add_cert( pool, &notar, 0, bad )==FD_VOTOR_POOL_ERR_DUPLICATE );
  FD_TEST( fd_votor_pool_add_cert( pool, &skip, 0, bad )==FD_VOTOR_POOL_ERR_DUPLICATE );

  teardown_pool( pool );
}

/* A verified cert skips only the signature check: a cert that fails it
   is accepted, and duplicates are still rejected. */

static void
test_add_verified_cert( void ) {
  fd_votor_pool_t * pool = setup_pool();

  fd_block_hash_t hash; random_hash( &hash );
  fd_vote_notar_t nv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) nv[v] = fd_vote_construct_notar( sec_sign_fn, &g_sk[v], test_bls_public_key, 1UL, &hash, (ushort)v, TEST_SHRED_VERSION ).notar;
  fd_cert_t notar = cert_build_notar( nv, NV, g_epoch_info );
  notar.notar.block_hash.uc[ 0 ] ^= 1;

  FD_TEST( fd_votor_pool_add_cert( pool, &notar, 0, bad )==FD_VOTOR_POOL_ERR_CERT_VERIFY );
  FD_TEST( fd_votor_pool_add_cert( pool, &notar, 1, bad )==FD_VOTOR_POOL_SUCCESS         );
  FD_TEST( fd_votor_pool_add_cert( pool, &notar, 1, bad )==FD_VOTOR_POOL_ERR_DUPLICATE   );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::out_of_bounds_votes */

static void
test_out_of_bounds_votes( void ) {
  fd_votor_pool_t * pool = setup_pool();
  fd_block_hash_t gh; genesis_hash( &gh );

  ulong slot = 3UL*SLOTS_PER_WINDOW - 1UL;
  for( ulong s=1UL; s<=slot; s++ ) add_notar_votes( pool, s, &gh, 0UL, 11UL );
  FD_TEST( fd_votor_pool_finalized_slot( pool )==slot );
  FD_TEST( pool_first_unpruned_slot( pool )==slot );

  for( ulong s=0UL; s<slot-FD_VOTOR_REWARD_SLOT_DELTA; s++ ) {
    for( ulong v=0UL; v<11UL; v++ ) {
      fd_vote_t vote = fd_vote_construct_final( sec_sign_fn, &g_sk[v], test_bls_public_key, s, (ushort)v, TEST_SHRED_VERSION );
      FD_TEST( fd_votor_pool_add_vote( pool, &vote, 0, bad, &quorum_reached )==FD_VOTOR_POOL_ERR_SLOT_TOO_OLD );
    }
  }

  for( ulong s=slot-FD_VOTOR_REWARD_SLOT_DELTA; s<slot; s++ ) {
    fd_vote_t vote = fd_vote_construct_final( sec_sign_fn, &g_sk[0], test_bls_public_key, s, (ushort)0, TEST_SHRED_VERSION );
    FD_TEST( fd_votor_pool_add_vote( pool, &vote, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
  }

  ulong future = 5UL*TEST_SLOT_MAX;
  for( ulong v=0UL; v<11UL; v++ ) {
    fd_vote_t vote = fd_vote_construct_final( sec_sign_fn, &g_sk[v], test_bls_public_key, future, (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( fd_votor_pool_add_vote( pool, &vote, 0, bad, &quorum_reached )==FD_VOTOR_POOL_ERR_SLOT_TOO_NEW );
  }

  teardown_pool( pool );
}

/* src/consensus/pool.rs::out_of_bounds_certs */

static void
test_out_of_bounds_certs( void ) {
  fd_votor_pool_t * pool = setup_pool();
  fd_block_hash_t gh; genesis_hash( &gh );

  ulong slot = 3UL*SLOTS_PER_WINDOW - 1UL;
  for( ulong s=1UL; s<=slot; s++ ) {
    fd_vote_notar_t nv[ NV ];
    for( ulong v=0UL; v<NV; v++ ) nv[v] = fd_vote_construct_notar( sec_sign_fn, &g_sk[v], test_bls_public_key, s, &gh, (ushort)v, TEST_SHRED_VERSION ).notar;
    fd_cert_t c = cert_build_fast_final( nv, NV, g_epoch_info );
    FD_TEST( fd_votor_pool_add_cert( pool, &c, 0, bad )==FD_VOTOR_POOL_SUCCESS );
    drain_events( pool );
  }
  FD_TEST( pool_first_unpruned_slot( pool )==slot );

  for( ulong s=0UL; s<3UL*SLOTS_PER_WINDOW-1UL; s++ ) {
    fd_vote_skip_t sv[ NV ];
    for( ulong v=0UL; v<NV; v++ ) sv[v] = fd_vote_construct_skip( sec_sign_fn, &g_sk[v], test_bls_public_key, s, (ushort)v, TEST_SHRED_VERSION ).skip;
    fd_cert_t c = cert_build_skip( sv, NV, NULL, 0UL, g_epoch_info );
    FD_TEST( fd_votor_pool_add_cert( pool, &c, 0, bad )==FD_VOTOR_POOL_ERR_SLOT_TOO_OLD );
  }

  ulong future = 3UL*TEST_SLOT_MAX;
  fd_vote_skip_t sv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) sv[v] = fd_vote_construct_skip( sec_sign_fn, &g_sk[v], test_bls_public_key, future, (ushort)v, TEST_SHRED_VERSION ).skip;
  fd_cert_t c = cert_build_skip( sv, NV, NULL, 0UL, g_epoch_info );
  FD_TEST( fd_votor_pool_add_cert( pool, &c, 0, bad )==FD_VOTOR_POOL_ERR_SLOT_TOO_NEW );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::slow_finalize_closing_gap_no_double_parent_ready */

static void
test_slow_finalize_closing_gap_no_double_parent_ready( void ) {
  fd_votor_pool_t * pool = setup_pool();
  fd_block_hash_t gh; genesis_hash( &gh );

  ulong next_start     = SLOTS_PER_WINDOW;
  ulong gap_slot       = next_start - 1UL;
  ulong watermark_slot = gap_slot - 1UL;

  for( ulong s=1UL; s<gap_slot; s++ ) fast_finalize( pool, s, &gh );
  FD_TEST( pool_first_unpruned_slot( pool )==watermark_slot );
  FD_TEST_PRUNED_TO_WATERMARK( pool );

  fd_block_hash_t gap_hash; random_hash( &gap_hash );
  add_final_votes( pool, gap_slot, 0UL, 7UL );
  FD_TEST( has_final_cert( pool, gap_slot ) );
  FD_TEST( pool_first_unpruned_slot( pool )==watermark_slot );
  FD_TEST_PRUNED_TO_WATERMARK( pool );

  fast_finalize( pool, next_start, &gh );
  FD_TEST( fd_votor_pool_finalized_slot( pool )==next_start );
  FD_TEST( pool_first_unpruned_slot( pool )==watermark_slot );
  FD_TEST( min_live_slot( pool )<=watermark_slot && min_live_slot( pool )+FD_VOTOR_REWARD_SLOT_DELTA>=watermark_slot );

  add_notar_votes( pool, gap_slot, &gap_hash, 0UL, 7UL );
  FD_TEST( pool_first_unpruned_slot( pool )==next_start );
  FD_TEST( min_live_slot( pool )<=next_start && min_live_slot( pool )+FD_VOTOR_REWARD_SLOT_DELTA>=next_start );

  ulong cnt = fd_votor_pool_parents_ready( pool, next_start, NULL, 0UL );
  FD_TEST( cnt==1UL );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::standstill_recovery */

static void
test_standstill_recovery( void ) {
  fd_votor_pool_t * pool = setup_pool();

  ulong slot1 = 1UL;
  fd_block_hash_t hash1; random_hash( &hash1 );
  add_notar_votes( pool, slot1, &hash1, 0UL, 11UL );

  ulong slot2 = 2UL;
  add_final_votes( pool, slot2, 0UL, 7UL );

  ulong slot3 = 3UL;
  fd_block_hash_t hash3; random_hash( &hash3 );
  add_notar_votes( pool, slot3, &hash3, 0UL, 1UL );

  fd_standstill_t         standstill = recover_from_standstill( pool );
  fd_standstill_t const * ss         = &standstill;
  FD_TEST( ss->slot==slot2 );

  fd_cert_t const * certs     = ss->certs;
  ulong             certs_cnt = ss->cert_cnt;
  fd_vote_t const * votes     = ss->votes;
  ulong             votes_cnt = ss->vote_cnt;

  FD_TEST( certs_cnt==2UL );
  for( ulong i=0UL; i<certs_cnt; i++ ) {
    if( certs[i].kind==FD_CERT_KIND_FAST_FINAL )  FD_TEST( fd_cert_slot( &certs[i] )==slot1 );
    else if( certs[i].kind==FD_CERT_KIND_FINAL )  FD_TEST( fd_cert_slot( &certs[i] )==slot2 );
    else FD_TEST( 0 );
  }

  fd_vote_t final2 = fd_vote_construct_final( sec_sign_fn, &g_sk[0], test_bls_public_key, slot2,         (ushort)0, TEST_SHRED_VERSION );
  fd_vote_t notar3 = fd_vote_construct_notar( sec_sign_fn, &g_sk[0], test_bls_public_key, slot3, &hash3, (ushort)0, TEST_SHRED_VERSION );
  FD_TEST( votes_cnt==2UL );
  for( ulong i=0UL; i<votes_cnt; i++ ) {
    FD_TEST( fd_vote_rank( &votes[i] )==0UL );
    FD_TEST( fd_vote_shred_version( &votes[i] )==TEST_SHRED_VERSION );
    if( votes[i].kind==FD_VOTE_KIND_FINAL ) {
      FD_TEST( fd_vote_slot( &votes[i] )==slot2 );
      FD_TEST( !memcmp( fd_vote_sig( &votes[i] ), fd_vote_sig( &final2 ), sizeof(fd_bls_sig_t) ) );
    } else if( votes[i].kind==FD_VOTE_KIND_NOTAR ) {
      FD_TEST( fd_vote_slot( &votes[i] )==slot3 );
      FD_TEST( !memcmp( &votes[i].notar.block_hash, &hash3, sizeof(fd_block_hash_t) ) );
      FD_TEST( !memcmp( fd_vote_sig( &votes[i] ), fd_vote_sig( &notar3 ), sizeof(fd_bls_sig_t) ) );
    } else FD_TEST( 0 );
  }

  for( ulong i=0UL; i<certs_cnt; i++ ) {
    uchar buf[ FD_CERT_SER_MAX ];
    ulong sz;
    sz = fd_cert_ser( &certs[i], buf );
    fd_cert_t rt;
    ulong bit_cnt;
    FD_TEST( fd_cert_de( &rt, &bit_cnt, buf, sz )==FD_CERT_DE_SUCCESS );
    FD_TEST( rt.kind==certs[i].kind );
    FD_TEST( fd_cert_slot( &rt )==fd_cert_slot( &certs[i] ) );
    FD_TEST( fd_cert_shred_version( &rt )==TEST_SHRED_VERSION );

    /* Votor rebroadcasts certificates it learned from a peer, so a cert
       that came out of fd_cert_de has to reserialize to the same bytes. */

    uchar rebroadcast[ FD_CERT_SER_MAX ];
    ulong rebroadcast_sz;
    rebroadcast_sz = fd_cert_ser( &rt, rebroadcast );
    FD_TEST( rebroadcast_sz==sz );
    FD_TEST( !memcmp( rebroadcast, buf, sz ) );

    fd_cert_t bad;
    FD_TEST( fd_cert_de( &bad, &bit_cnt, buf, sz-1UL )==FD_CERT_DE_ERR_SZ ); /* too few  */
    FD_TEST( fd_cert_de( &bad, &bit_cnt, buf, sz+1UL )==FD_CERT_DE_SUCCESS ); /* trailing */
  }

  teardown_pool( pool );
}

/* A parent link that jumps the root past the block being added must not
   leave that block's slot state behind, below the retained window. */

static void
test_add_block_root_jump( void ) {
  fd_votor_pool_t * pool = setup_pool();
  fd_block_hash_t gh; genesis_hash( &gh );

  fd_block_id_t genesis = fd_block_id( 0UL, gh.uc );
  fd_block_id_t block1  = fd_block_id( 1UL, gh.uc );
  fd_votor_pool_add_block( pool, &block1, &genesis, bad );
  fast_finalize( pool, 1UL, &gh );
  for( ulong s=3UL; s<=40UL; s++ ) fast_finalize( pool, s, &gh );
  FD_TEST( pool_first_unpruned_slot( pool )==1UL );

  fd_block_id_t block3 = fd_block_id( 3UL, gh.uc );
  FD_TEST( fd_votor_pool_add_block( pool, &block3, &block1, bad )==FD_VOTOR_POOL_SUCCESS );
  FD_TEST( pool_first_unpruned_slot( pool )==40UL );
  FD_TEST( !slot_state_query( pool, 3UL ) );
  FD_TEST_PRUNED_TO_WATERMARK( pool );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::parent_ready_upon_finalization.  Diverges
   from the reference on purpose: block0 is finalized only implicitly,
   through replayed parent links, and the pool holds no notarization or
   notar-fallback cert for it, so Definition 15 makes it no parent until
   one arrives. */

static void
test_parent_ready_upon_finalization( void ) {
  fd_votor_pool_t * pool = setup_pool();

  ulong slot1 = SLOTS_PER_WINDOW;
  fd_block_id_t block0 = random_block_id( slot1-1UL );
  fd_block_id_t block1 = random_block_id( slot1 );
  fd_block_id_t block2 = random_block_id( slot1+1UL );

  drain_events( pool );

  for( ulong v=0UL; v<11UL; v++ ) {
    fd_vote_t vote = fd_vote_construct_notar( sec_sign_fn, &g_sk[v], test_bls_public_key, block2.slot, &block2.hash, (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( fd_votor_pool_add_vote( pool, &vote, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
  }

  ulong cert_created = 0UL, parent_ready_cnt = 0UL;
  ulong event_cnt = take_events( pool );
  for( ulong i=0UL; i<event_cnt; i++ ) {
    if( event( i )->kind==FD_VOTOR_POOL_EVENT_CERT_CREATED ) cert_created++;
    if( event( i )->kind==FD_VOTOR_POOL_EVENT_PARENT_READY ) parent_ready_cnt++;
  }
  FD_TEST( cert_created==2UL );
  FD_TEST( parent_ready_cnt==0UL );

  drain_events( pool );
  fd_votor_pool_add_block( pool, &block2, &block1, bad );
  fd_votor_pool_add_block( pool, &block1, &block0, bad );

  event_cnt = take_events( pool );
  for( ulong i=0UL; i<event_cnt; i++ ) FD_TEST( event( i )->kind!=FD_VOTOR_POOL_EVENT_PARENT_READY );

  int found = 0;
  for( ulong v=0UL; v<7UL; v++ ) {
    fd_vote_t vote = fd_vote_construct_notar( sec_sign_fn, &g_sk[v], test_bls_public_key, block0.slot, &block0.hash, (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( fd_votor_pool_add_vote( pool, &vote, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
    event_cnt = take_events( pool );
    for( ulong i=0UL; i<event_cnt; i++ ) {
      if( event( i )->kind==FD_VOTOR_POOL_EVENT_PARENT_READY ) {
        FD_TEST( event( i )->parent_ready.slot==slot1 );
        FD_TEST( fd_block_id_eq( &event( i )->parent_ready.parent, &block0 ) );
        found++;
      }
    }
  }
  FD_TEST( found==1 );
  FD_TEST( is_parent_ready( pool, slot1, &block0 ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::safe_to_notar_notar_cert_only */

static void
test_safe_to_notar_notar_cert_only( void ) {
  fd_votor_pool_t * pool = setup_pool();

  ulong     slot1 = 1UL;
  ulong     slot2 = 2UL;
  fd_block_hash_t hash1; random_hash( &hash1 );
  fd_block_hash_t hash2; random_hash( &hash2 );

  notar_cert( pool, slot1, &hash1, 7UL );

  fd_block_id_t child  = fd_block_id( slot2, hash2.uc );
  fd_block_id_t parent = fd_block_id( slot1, hash1.uc );
  fd_votor_pool_add_block( pool, &child, &parent, bad );
  drain_events( pool );

  fd_vote_t skip = fd_vote_construct_skip( sec_sign_fn, &g_sk[0], test_bls_public_key, slot2, 0, TEST_SHRED_VERSION );
  FD_TEST( fd_votor_pool_add_vote( pool, &skip, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
  for( ulong v=1UL; v<6UL; v++ ) {
    fd_vote_t vote = fd_vote_construct_notar( sec_sign_fn, &g_sk[v], test_bls_public_key, slot2, &hash2, (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( fd_votor_pool_add_vote( pool, &vote, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
  }

  FD_TEST( drained_safe_to_notar( pool, slot2, &hash2 ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::safe_to_notar_fast_final_cert_only */

static void
test_safe_to_notar_fast_final_cert_only( void ) {
  fd_votor_pool_t * pool = setup_pool();

  ulong     slot1 = 1UL;
  ulong     slot2 = 2UL;
  fd_block_hash_t hash1; random_hash( &hash1 );
  fd_block_hash_t hash2; random_hash( &hash2 );

  fast_finalize( pool, slot1, &hash1 );

  fd_block_id_t child  = fd_block_id( slot2, hash2.uc );
  fd_block_id_t parent = fd_block_id( slot1, hash1.uc );
  fd_votor_pool_add_block( pool, &child, &parent, bad );
  drain_events( pool );

  fd_vote_t skip = fd_vote_construct_skip( sec_sign_fn, &g_sk[0], test_bls_public_key, slot2, 0, TEST_SHRED_VERSION );
  FD_TEST( fd_votor_pool_add_vote( pool, &skip, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
  for( ulong v=1UL; v<6UL; v++ ) {
    fd_vote_t vote = fd_vote_construct_notar( sec_sign_fn, &g_sk[v], test_bls_public_key, slot2, &hash2, (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( fd_votor_pool_add_vote( pool, &vote, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
  }

  FD_TEST( drained_safe_to_notar( pool, slot2, &hash2 ) );

  teardown_pool( pool );
}

/* Firedancer-only test.

   Votes for a block are verified once they reach the safe-to-notar
   threshold, before its parent is certified, so a forged vote is
   reported by the vote that reaches it.  Votes after that, and the
   parent cert releasing the block, verify nothing. */

static void
test_safe_to_notar_verifies_before_parent_cert( void ) {
  fd_votor_pool_t * pool = setup_pool();

  ulong     slot1 = 1UL;
  ulong     slot2 = 2UL;
  fd_block_hash_t hash1; random_hash( &hash1 );
  fd_block_hash_t hash2; random_hash( &hash2 );

  fd_block_id_t child  = fd_block_id( slot2, hash2.uc );
  fd_block_id_t parent = fd_block_id( slot1, hash1.uc );
  fd_votor_pool_add_block( pool, &child, &parent, bad );
  drain_events( pool );

  fd_vote_t skip = fd_vote_construct_skip( sec_sign_fn, &g_sk[0], test_bls_public_key, slot2, 0, TEST_SHRED_VERSION );
  FD_TEST( fd_votor_pool_add_vote( pool, &skip, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
  int forged_reported = 0;
  for( ulong v=1UL; v<7UL; v++ ) {
    fd_vote_t vote = fd_vote_construct_notar( sec_sign_fn, &g_sk[ v==3UL ? 4UL : v ], test_bls_public_key, slot2, &hash2, (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( fd_votor_pool_add_vote( pool, &vote, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
    forged_reported |= fd_bls_set_test( bad, 3UL );
  }
  FD_TEST( forged_reported );
  FD_TEST( !drained_safe_to_notar( pool, slot2, &hash2 ) );

  ulong parked_cnt = fd_votor_pool_metrics( pool ).bls_verify_cnt;
  for( ulong v=7UL; v<9UL; v++ ) {
    fd_vote_t late = fd_vote_construct_skip( sec_sign_fn, &g_sk[v], test_bls_public_key, slot2, (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( fd_votor_pool_add_vote( pool, &late, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
  }
  FD_TEST( fd_votor_pool_metrics( pool ).bls_verify_cnt==parked_cnt );

  fd_vote_notar_t nv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) nv[v] = fd_vote_construct_notar( sec_sign_fn, &g_sk[v], test_bls_public_key, slot1, &hash1, (ushort)v, TEST_SHRED_VERSION ).notar;
  fd_cert_t c = cert_build_fast_final( nv, NV, g_epoch_info );
  ulong verify_cnt = fd_votor_pool_metrics( pool ).bls_verify_cnt;
  FD_TEST( fd_votor_pool_add_cert( pool, &c, 1, bad )==FD_VOTOR_POOL_SUCCESS );
  FD_TEST( fd_bls_set_is_null( bad ) && fd_votor_pool_metrics( pool ).bls_verify_cnt==verify_cnt );
  FD_TEST( drained_safe_to_notar( pool, slot2, &hash2 ) );

  teardown_pool( pool );
}

/* Firedancer-only test */

static void
test_safe_to_notar_awaiting_votes( void ) {
  fd_votor_pool_t * pool = setup_pool();

  ulong     slot1 = 1UL;
  ulong     slot2 = 2UL;
  fd_block_hash_t hash1; random_hash( &hash1 );
  fd_block_hash_t hash2; random_hash( &hash2 );

  notar_cert( pool, slot1, &hash1, 7UL );

  fd_block_id_t child  = fd_block_id( slot2, hash2.uc );
  fd_block_id_t parent = fd_block_id( slot1, hash1.uc );
  fd_votor_pool_add_block( pool, &child, &parent, bad );

  FD_TEST( !drained_safe_to_notar( pool, slot2, &hash2 ) );
  FD_TEST( !s2n_waiting_cnt( pool ) );

  fd_vote_t skip = fd_vote_construct_skip( sec_sign_fn, &g_sk[0], test_bls_public_key, slot2, 0, TEST_SHRED_VERSION );
  FD_TEST( fd_votor_pool_add_vote( pool, &skip, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
  for( ulong v=1UL; v<6UL; v++ ) {
    fd_vote_t vote = fd_vote_construct_notar( sec_sign_fn, &g_sk[v], test_bls_public_key, slot2, &hash2, (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( fd_votor_pool_add_vote( pool, &vote, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
  }
  FD_TEST( drained_safe_to_notar( pool, slot2, &hash2 ) );

  teardown_pool( pool );
}

/* Firedancer-only test */

static void
test_safe_to_notar_not_queued_for_parent_cert( void ) {
  fd_votor_pool_t * pool = setup_pool();

  ulong     slot1  = 1UL;
  ulong     slot2  = 2UL;
  fd_block_hash_t hash1;  random_hash( &hash1  );
  fd_block_hash_t hash_a; random_hash( &hash_a );
  fd_block_hash_t hash_b; random_hash( &hash_b );

  notar_cert( pool, slot1, &hash1, 7UL );

  /* Our own skip vote plus a weak quorum notarizing hash_a makes
     hash_a safe-to-notar the instant its parent is known certified.
     hash_b has no votes, so it is merely awaiting votes. */

  fd_vote_t skip = fd_vote_construct_skip( sec_sign_fn, &g_sk[0], test_bls_public_key, slot2, 0, TEST_SHRED_VERSION );
  FD_TEST( fd_votor_pool_add_vote( pool, &skip, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
  add_notar_votes( pool, slot2, &hash_a, 1UL, 6UL );
  drain_events( pool );

  fd_block_id_t parent  = fd_block_id( slot1, hash1.uc  );
  fd_block_id_t child_a = fd_block_id( slot2, hash_a.uc );
  fd_block_id_t child_b = fd_block_id( slot2, hash_b.uc );
  fd_votor_pool_add_block( pool, &child_b, &parent, bad );
  fd_votor_pool_add_block( pool, &child_a, &parent, bad );

  FD_TEST( drained_safe_to_notar( pool, slot2, &hash_a ) );
  FD_TEST( !s2n_waiting_cnt( pool ) );

  teardown_pool( pool );
}

/* Firedancer-only test */

static void
test_s2n_waiting_every_child( void ) {
  fd_votor_pool_t * pool = setup_pool();

  ulong slot1 = 1UL;
  ulong slot2 = 2UL;
  ulong slot5 = 5UL;
  fd_block_hash_t hash1; random_hash( &hash1 );
  fd_block_hash_t hash2; random_hash( &hash2 );
  fd_block_hash_t hash5; random_hash( &hash5 );

  fd_block_id_t parent  = fd_block_id( slot1, hash1.uc );
  fd_block_id_t child_2 = fd_block_id( slot2, hash2.uc );
  fd_block_id_t child_5 = fd_block_id( slot5, hash5.uc );

  fd_vote_t skip2 = fd_vote_construct_skip( sec_sign_fn, &g_sk[0], test_bls_public_key, slot2, 0, TEST_SHRED_VERSION );
  fd_vote_t skip5 = fd_vote_construct_skip( sec_sign_fn, &g_sk[0], test_bls_public_key, slot5, 0, TEST_SHRED_VERSION );
  FD_TEST( fd_votor_pool_add_vote( pool, &skip2, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
  FD_TEST( fd_votor_pool_add_vote( pool, &skip5, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
  add_notar_votes( pool, slot2, &hash2, 1UL, 6UL );
  add_notar_votes( pool, slot5, &hash5, 1UL, 6UL );

  ulong verify_cnt = fd_votor_pool_metrics( pool ).bls_verify_cnt;
  fd_votor_pool_add_block( pool, &child_2, &parent, bad );
  fd_votor_pool_add_block( pool, &child_5, &parent, bad );
  fd_votor_pool_add_block( pool, &child_2, &parent, bad );
  drain_events( pool );
  FD_TEST( s2n_waiting_cnt( pool )==2UL );
  FD_TEST( s2n_waiting( pool, &parent, &child_2 ) );
  FD_TEST( s2n_waiting( pool, &parent, &child_5 ) );
  FD_TEST( fd_votor_pool_metrics( pool ).bls_verify_cnt>verify_cnt );

  fd_vote_notar_t nv[ NV ];
  for( ulong v=0UL; v<7UL; v++ ) nv[v] = fd_vote_construct_notar( sec_sign_fn, &g_sk[v], test_bls_public_key, slot1, &hash1, (ushort)v, TEST_SHRED_VERSION ).notar;
  fd_cert_t c = cert_build_notar( nv, 7UL, g_epoch_info );
  verify_cnt = fd_votor_pool_metrics( pool ).bls_verify_cnt;
  FD_TEST( fd_votor_pool_add_cert( pool, &c, 1, bad )==FD_VOTOR_POOL_SUCCESS );
  FD_TEST( fd_votor_pool_metrics( pool ).bls_verify_cnt==verify_cnt );

  int   got_2 = 0;
  int   got_5 = 0;
  ulong cnt   = take_events( pool );
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_votor_pool_event_t const * e = event( i );
    if( e->kind!=FD_VOTOR_POOL_EVENT_SAFE_TO_NOTAR ) continue;
    got_2 |= fd_block_id_eq( &e->safe_to_notar, &child_2 );
    got_5 |= fd_block_id_eq( &e->safe_to_notar, &child_5 );
  }
  FD_TEST( got_2 && got_5 );
  FD_TEST( !s2n_waiting_cnt( pool ) );

  teardown_pool( pool );
}

/* Firedancer-only test */

static void
test_s2n_waiting_fast_final_parent( void ) {
  fd_votor_pool_t * pool = setup_pool();

  ulong slot1 = 1UL;
  ulong slot2 = 2UL;
  fd_block_hash_t hash1; random_hash( &hash1 );
  fd_block_hash_t hash2; random_hash( &hash2 );

  fd_block_id_t parent = fd_block_id( slot1, hash1.uc );
  fd_block_id_t child  = fd_block_id( slot2, hash2.uc );

  fd_vote_t skip = fd_vote_construct_skip( sec_sign_fn, &g_sk[0], test_bls_public_key, slot2, 0, TEST_SHRED_VERSION );
  FD_TEST( fd_votor_pool_add_vote( pool, &skip, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
  add_notar_votes( pool, slot2, &hash2, 1UL, 6UL );

  fd_votor_pool_add_block( pool, &child, &parent, bad );
  drain_events( pool );
  FD_TEST( s2n_waiting( pool, &parent, &child ) );

  fd_vote_notar_t nv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) nv[v] = fd_vote_construct_notar( sec_sign_fn, &g_sk[v], test_bls_public_key, slot1, &hash1, (ushort)v, TEST_SHRED_VERSION ).notar;
  fd_cert_t c = cert_build_fast_final( nv, NV, g_epoch_info );
  FD_TEST( fd_votor_pool_add_cert( pool, &c, 0, bad )==FD_VOTOR_POOL_SUCCESS );

  FD_TEST( drained_safe_to_notar( pool, slot2, &hash2 ) );
  FD_TEST( !s2n_waiting_cnt( pool ) );

  teardown_pool( pool );
}

/* Firedancer-only test */

static void
test_s2n_waiting_pruned( void ) {
  fd_votor_pool_t * pool = setup_pool();
  fd_block_hash_t gh; genesis_hash( &gh );

  fd_block_hash_t hash1; random_hash( &hash1 );
  fd_block_hash_t hash2; random_hash( &hash2 );
  fd_block_id_t   parent = fd_block_id( 1UL, hash1.uc );
  fd_block_id_t   child  = fd_block_id( 2UL, hash2.uc );

  fd_votor_pool_add_block( pool, &child, &parent, bad );
  drain_events( pool );
  FD_TEST( s2n_waiting( pool, &parent, &child ) );

  ulong slot = 3UL*SLOTS_PER_WINDOW - 1UL;
  for( ulong s=1UL; s<=slot; s++ ) fast_finalize( pool, s, &gh );
  FD_TEST( pool_first_unpruned_slot( pool )==slot );
  FD_TEST_PRUNED_TO_WATERMARK( pool );
  FD_TEST( !s2n_waiting_cnt( pool ) );

  fd_block_id_t late = random_block_id( slot+1UL );
  FD_TEST( fd_votor_pool_add_block( pool, &late, &parent, bad )==FD_VOTOR_POOL_SUCCESS );
  drain_events( pool );
  FD_TEST( !s2n_waiting_cnt( pool ) );

  teardown_pool( pool );
}

static void
test_handle_invalid_votes( void ) {
  fd_votor_pool_t * pool = setup_pool();

  fd_block_hash_t gh; genesis_hash( &gh );
  fd_vote_t vote = fd_vote_construct_notar( sec_sign_fn, &g_sk[0], test_bls_public_key, 0UL, &gh, 0, TEST_SHRED_VERSION );
  FD_TEST( fd_votor_pool_add_vote( pool, &vote, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );

  teardown_pool( pool );
}

static void
test_hash_capacity( void ) {
  fd_votor_pool_t * pool = setup_pool();
  ulong slot = 0UL;

  fd_block_hash_t hash[ NV ];
  for( ulong i=0UL; i<NV; i++ ) {
    random_hash( &hash[i] );
    fd_vote_t v = fd_vote_construct_notar( sec_sign_fn, &g_sk[i], test_bls_public_key, slot, &hash[i], (ushort)i, TEST_SHRED_VERSION );
    FD_TEST( fd_votor_pool_add_vote( pool, &v, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
    drain_events( pool );
  }

  fd_block_hash_t nf[ FD_VOTOR_NOTAR_FALLBACK_VOTE_MAX ];
  for( ulong i=0UL; i<FD_VOTOR_NOTAR_FALLBACK_VOTE_MAX; i++ ) {
    random_hash( &nf[i] );
    fd_vote_t v = fd_vote_construct_notar_fallback( sec_sign_fn, &g_sk[0], test_bls_public_key, slot, &nf[i], (ushort)0, TEST_SHRED_VERSION );
    FD_TEST( fd_votor_pool_add_vote( pool, &v, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
    drain_events( pool );
  }

  fd_block_hash_t past; random_hash( &past );
  fd_vote_t v_past;
  v_past = fd_vote_construct_notar_fallback( sec_sign_fn, &g_sk[0], test_bls_public_key, slot, &past, (ushort)0, TEST_SHRED_VERSION );
  FD_TEST( fd_votor_pool_add_vote( pool, &v_past, 0, bad, &quorum_reached )==FD_VOTOR_POOL_ERR_DUPLICATE );
  FD_TEST( fd_votor_pool_add_vote( pool, &v_past, 0, bad, &quorum_reached )==FD_VOTOR_POOL_ERR_DUPLICATE );

  fd_vote_t v_other;
  v_other = fd_vote_construct_notar_fallback( sec_sign_fn, &g_sk[1], test_bls_public_key, slot, &past, (ushort)1, TEST_SHRED_VERSION );
  FD_TEST( fd_votor_pool_add_vote( pool, &v_other, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );

  teardown_pool( pool );
}

/* src/consensus/validated_vote.rs::unknown_signer */

static void
test_unknown_signer_votes( void ) {
  fd_votor_pool_t * pool = setup_pool();
  fd_block_hash_t gh; genesis_hash( &gh );
  ulong slot = 0UL;

  fd_epoch_info_t const * epoch = epoch_info( pool, slot );
  FD_TEST( epoch );

  fd_vote_t v1 = fd_vote_construct_notar( sec_sign_fn, &g_sk[0], test_bls_public_key, slot, &gh, (ushort)NV, TEST_SHRED_VERSION );
  FD_TEST( fd_vote_rank( &v1 )>=epoch->validator_cnt );

  fd_vote_t v2 = fd_vote_construct_skip( sec_sign_fn, &g_sk[0], test_bls_public_key, slot, USHORT_MAX, TEST_SHRED_VERSION );
  FD_TEST( fd_vote_rank( &v2 )>=epoch->validator_cnt );

  teardown_pool( pool );
}

static void
test_wait_for_parent_ready( void ) {
  fd_votor_pool_t * pool = setup_pool();

  ulong slot1 = SLOTS_PER_WINDOW;
  fd_block_id_t block0 = random_block_id( slot1-1UL );
  fd_block_id_t block1 = random_block_id( slot1 );
  fd_block_id_t block2 = random_block_id( slot1+1UL );

  drain_events( pool );

  fd_block_id_t parent;
  parent = fd_votor_pool_wait_for_parent_ready( pool, slot1 );
  FD_TEST( parent.slot==ULONG_MAX );

  for( ulong v=0UL; v<11UL; v++ ) {
    fd_vote_t vote = fd_vote_construct_notar( sec_sign_fn, &g_sk[v], test_bls_public_key, block2.slot, &block2.hash, (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( fd_votor_pool_add_vote( pool, &vote, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
  }
  drain_events( pool );
  fd_votor_pool_add_block( pool, &block2, &block1, bad );
  fd_votor_pool_add_block( pool, &block1, &block0, bad );

  parent = fd_votor_pool_wait_for_parent_ready( pool, slot1 ); /* block0 has no cert, see test_parent_ready_upon_finalization */
  FD_TEST( parent.slot==ULONG_MAX );

  add_notar_votes( pool, block0.slot, &block0.hash, 0UL, 7UL );
  parent = fd_votor_pool_wait_for_parent_ready( pool, slot1 );
  FD_TEST( parent.slot!=ULONG_MAX );
  FD_TEST( fd_block_id_eq( &parent, &block0 ) );

  fd_block_id_t ready[ 4 ];
  ulong         cnt = fd_votor_pool_parents_ready( pool, slot1, ready, 4UL );
  FD_TEST( cnt==1UL );
  FD_TEST( fd_block_id_eq( &ready[0], &parent ) );

  fd_block_id_t again;
  again = fd_votor_pool_wait_for_parent_ready( pool, slot1 );
  FD_TEST( again.slot!=ULONG_MAX );
  FD_TEST( fd_block_id_eq( &again, &parent ) );

  teardown_pool( pool );
}

#define EPOCH_A_LO (0UL)
#define EPOCH_B_LO (32UL)
#define EPOCH_B_HI (63UL)

#define HEAVY_CNT   (4UL)
#define HEAVY_STAKE (3UL)

static fd_votor_pool_t *
setup_two_epoch_pool( fd_epoch_info_t ** out_a,
                      fd_epoch_info_t ** out_b,
                      int                install_b ) {
  create_validators();
  ulong slot_max = TEST_SLOT_MAX;

  FD_TEST( fd_votor_pool_footprint( slot_max, TEST_BURST, g_sig_pg_max )<=sizeof(scratch) );
  fd_votor_pool_t * pool = fd_votor_pool_join( fd_votor_pool_new( scratch, slot_max, TEST_BURST, g_sig_pg_max, 42UL, g_spill_fd ) );
  FD_TEST( pool );
  fd_votor_pool_from_genesis( pool, &(fd_block_id_t){ .slot = 0UL } );

  fd_validator_info_t heavy[ NV ];
  for( ulong i=0UL; i<NV; i++ ) {
    heavy[ i ]       = g_info[ i ];
    heavy[ i ].stake = i<HEAVY_CNT ? HEAVY_STAKE : 1UL;
  }

  fd_epoch_info_t * a = make_epoch_info( 0UL, g_info, NV );
  fd_epoch_info_t * b = make_epoch_info( 1UL, heavy,  NV );
  FD_TEST( a->total_stake==NV );
  FD_TEST( b->total_stake==HEAVY_CNT*HEAVY_STAKE + (NV-HEAVY_CNT) );

  fd_votor_pool_advance_epoch( pool, a, 0UL, EPOCH_A_LO );
  if( install_b ) fd_votor_pool_advance_epoch( pool, b, 0UL, EPOCH_B_LO );

  *out_a = a; *out_b = b;
  return pool;
}

static void
test_stake_resolved_per_slot_epoch( void ) {
  fd_epoch_info_t * a; fd_epoch_info_t * b;
  fd_votor_pool_t * pool = setup_two_epoch_pool( &a, &b, 1 );

  ulong     slot_a = EPOCH_A_LO + 4UL;
  ulong     slot_b = EPOCH_B_LO + 4UL;
  fd_block_hash_t hash_a; random_hash( &hash_a );
  fd_block_hash_t hash_b; random_hash( &hash_b );

  add_notar_votes( pool, slot_a, &hash_a, 0UL, HEAVY_CNT );
  FD_TEST( !has_notar_cert( pool, slot_a ) );

  add_notar_votes( pool, slot_b, &hash_b, 0UL, HEAVY_CNT );
  FD_TEST( has_notar_cert( pool, slot_b ) );

  add_notar_votes( pool, slot_a, &hash_a, HEAVY_CNT, 7UL );
  FD_TEST( has_notar_cert( pool, slot_a ) );

  teardown_pool_only( pool );
}

static void
test_epoch_boundary_slot( void ) {
  fd_epoch_info_t * a; fd_epoch_info_t * b;
  fd_votor_pool_t * pool = setup_two_epoch_pool( &a, &b, 1 );

  fd_block_hash_t hash_lo; random_hash( &hash_lo );
  fd_block_hash_t hash_hi; random_hash( &hash_hi );

  add_notar_votes( pool, EPOCH_B_LO-1UL, &hash_lo, 0UL, HEAVY_CNT );
  FD_TEST( !has_notar_cert( pool, EPOCH_B_LO-1UL ) );

  add_notar_votes( pool, EPOCH_B_LO, &hash_hi, 0UL, HEAVY_CNT );
  FD_TEST( has_notar_cert( pool, EPOCH_B_LO ) );

  teardown_pool_only( pool );
}

static void
test_epoch_installed_late( void ) {
  fd_epoch_info_t * a; fd_epoch_info_t * b;
  fd_votor_pool_t * pool = setup_two_epoch_pool( &a, &b, 0 );

  ulong           beyond = EPOCH_B_LO + 4UL;
  fd_block_hash_t hash; random_hash( &hash );

  fd_vote_t v = fd_vote_construct_notar( sec_sign_fn, &g_sk[0], test_bls_public_key, beyond, &hash, (ushort)0, TEST_SHRED_VERSION );
  FD_TEST( epoch_info( pool, beyond )==a );
  FD_TEST( !contains_slot( pool, beyond ) );

  fd_votor_pool_advance_epoch( pool, b, 0UL, EPOCH_B_LO );
  FD_TEST( epoch_info( pool, beyond         )==b );
  FD_TEST( epoch_info( pool, EPOCH_B_LO-1UL )==a );
  FD_TEST( fd_votor_pool_add_vote( pool, &v, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
  FD_TEST( contains_slot( pool, beyond ) );

  teardown_pool_only( pool );
}
static void
test_retired_epoch_already_pruned( void ) {
  fd_epoch_info_t * a; fd_epoch_info_t * b;
  fd_votor_pool_t * pool = setup_two_epoch_pool( &a, &b, 1 );

  for( ulong s=EPOCH_A_LO+1UL; s<=EPOCH_B_LO; s++ ) {
    fd_block_hash_t hash; random_hash( &hash );
    add_notar_votes( pool, s, &hash, 0UL, NV );
  }
  FD_TEST( fd_votor_pool_finalized_slot( pool )==EPOCH_B_LO );

  FD_TEST( contains_slot( pool, EPOCH_B_LO-1UL ) ); /* retained for the reward certs */
  FD_TEST( contains_slot( pool, EPOCH_B_LO     ) );
  FD_TEST( pool_first_unpruned_slot( pool )==EPOCH_B_LO );
  FD_TEST( min_live_slot( pool )<=EPOCH_B_LO && min_live_slot( pool )+FD_VOTOR_REWARD_SLOT_DELTA>=EPOCH_B_LO );

  fd_epoch_info_t * c = make_epoch_info( 2UL, g_info, NV );
  fd_votor_pool_advance_epoch( pool, c, 0UL, EPOCH_B_HI+1UL );

  FD_TEST( epoch_info( pool, EPOCH_B_LO-1UL )==a );
  FD_TEST( epoch_info( pool, EPOCH_B_LO     )==b );
  FD_TEST( epoch_info( pool, EPOCH_B_HI+1UL )==c );
  FD_TEST( contains_slot( pool, EPOCH_B_LO ) );

  fd_vote_t v_late = fd_vote_construct_final( sec_sign_fn, &g_sk[0], test_bls_public_key, EPOCH_B_LO-1UL, (ushort)0, TEST_SHRED_VERSION );
  FD_TEST( fd_votor_pool_add_vote( pool, &v_late, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
  FD_TEST( slot_state_query( pool, EPOCH_B_LO-1UL ) && epoch_info( pool, EPOCH_B_LO-1UL )==a ); /* retained, verified against its own epoch */

  for( ulong s=EPOCH_B_LO+1UL; s<=EPOCH_B_LO+FD_VOTOR_REWARD_SLOT_DELTA; s++ ) {
    fd_block_hash_t hash; random_hash( &hash );
    add_notar_votes( pool, s, &hash, 0UL, NV );
  }
  FD_TEST( !contains_slot( pool, EPOCH_B_LO-1UL ) ); /* nothing retained in a any more, so a may be retired */

  fd_epoch_info_t * d = make_epoch_info( 3UL, g_info, NV );
  fd_votor_pool_advance_epoch( pool, d, 0UL, EPOCH_B_HI+1UL+(EPOCH_B_HI+1UL-EPOCH_B_LO) );

  FD_TEST( epoch_info( pool, EPOCH_B_LO                                  )==b );
  FD_TEST( epoch_info( pool, EPOCH_B_HI+1UL                              )==c );
  FD_TEST( epoch_info( pool, EPOCH_B_HI+1UL+(EPOCH_B_HI+1UL-EPOCH_B_LO) )==d );

  teardown_pool_only( pool );
}

/* Firedancer-only test.

   fd_votor_pool_from_snapshot names a finalized slot straight from the
   block replay booted on, so on snapshot boot that slot has no slot
   state and no certificate behind it -- certificates only reach the
   pool over the network or from our own votor.  Standstill recovery
   must emit an empty bundle for it rather than reach through the absent
   state.  The reference cannot hit this: it always starts at genesis
   and asserts a final cert is present. */

static void
test_standstill_recovery_no_final_cert( void ) {
  fd_votor_pool_t * pool = setup_pool(); /* fd_votor_pool_from_genesis( pool, 0UL ), no certs */

  FD_TEST(  fd_votor_pool_finalized_slot( pool )==0UL );
  FD_TEST( !contains_slot( pool, 0UL ) );

  fd_standstill_t         standstill = recover_from_standstill( pool );
  fd_standstill_t const * ss         = &standstill;
  FD_TEST( ss->slot    ==1UL ); /* finalized slot + 1 */
  FD_TEST( ss->cert_cnt==0UL );
  FD_TEST( ss->vote_cnt==0UL );

  teardown_pool_only( pool );
}

/* Firedancer-only test.

   fd_votor_pool_standstill_iter walks the bundle in kind order: the
   finalized slot's final and notar certs, then each later slot's final,
   fast-final, notar, notar-fallback and skip certs followed by our
   notar, final, skip, notar-fallback and skip-fallback votes.  Slot 8
   fills every notar-fallback cert and vote position.  Our votes in the
   finalized slot are not part of it, and its fast-final cert, once
   there, replaces its final and notar certs. */

static void
test_standstill_iter_order( void ) {
  fd_votor_pool_t * pool = setup_pool();

  fd_block_hash_t h1;  random_hash( &h1  );
  fd_block_hash_t h3;  random_hash( &h3  );
  fd_block_hash_t h3b; random_hash( &h3b );
  fd_block_hash_t h5;  random_hash( &h5  );

  notar_cert( pool, 1UL, &h1, 7UL );
  add_final_votes( pool, 1UL, 0UL, 7UL );
  FD_TEST( fd_votor_pool_finalized_slot( pool )==1UL );

  add_skip_votes( pool, 2UL, 0UL, 7UL );

  add_notar_votes( pool, 3UL, &h3,  0UL, 1UL );
  add_notar_votes( pool, 3UL, &h3b, 1UL, 5UL );
  add_notar_fallback_votes( pool, 3UL, &h3b, 0UL, 1UL );
  add_notar_fallback_votes( pool, 3UL, &h3b, 5UL, 9UL );

  add_notar_votes( pool, 5UL, &h5, 0UL, 1UL );
  fd_vote_t sf5 = fd_vote_construct_skip_fallback( sec_sign_fn, &g_sk[0], test_bls_public_key, 5UL, (ushort)0, TEST_SHRED_VERSION );
  FD_TEST( fd_votor_pool_add_vote( pool, &sf5, 0, bad, &quorum_reached )==FD_VOTOR_POOL_SUCCESS );
  drain_events( pool );

  add_final_votes( pool, 6UL, 0UL, 7UL );

  fd_block_hash_t h7; random_hash( &h7 );
  add_notar_votes( pool, 7UL, &h7, 0UL, 7UL ); /* notar cert, no notar-fallback cert */
  add_final_votes( pool, 7UL, 0UL, 1UL );

  fd_block_hash_t h8[ 4 ]; for( ulong i=0UL; i<4UL; i++ ) random_hash( &h8[ i ] );
  add_notar_votes( pool, 8UL, &h8[ 0 ], 0UL, 3UL  );
  add_notar_votes( pool, 8UL, &h8[ 1 ], 3UL, 6UL  );
  add_notar_votes( pool, 8UL, &h8[ 2 ], 6UL, 9UL  );
  add_notar_votes( pool, 8UL, &h8[ 3 ], 9UL, NV   );
  add_notar_fallback_votes( pool, 8UL, &h8[ 0 ], 3UL, NV  ); /* each hash reaches 60%, in order */
  add_notar_fallback_votes( pool, 8UL, &h8[ 1 ], 0UL, 3UL );
  add_notar_fallback_votes( pool, 8UL, &h8[ 1 ], 6UL, NV  );
  add_notar_fallback_votes( pool, 8UL, &h8[ 2 ], 0UL, 6UL );
  add_notar_fallback_votes( pool, 8UL, &h8[ 2 ], 9UL, NV  );
  add_notar_fallback_votes( pool, 8UL, &h8[ 3 ], 0UL, 9UL );

  struct { ulong slot; int is_vote; uint kind; fd_block_hash_t const * hash; } expected[] = {
    { 1UL, 0, FD_CERT_KIND_FINAL,          NULL   },
    { 1UL, 0, FD_CERT_KIND_NOTAR,          &h1    },
    { 2UL, 0, FD_CERT_KIND_SKIP,           NULL   },
    { 2UL, 1, FD_VOTE_KIND_SKIP,           NULL   },
    { 3UL, 0, FD_CERT_KIND_NOTAR_FALLBACK, &h3b   },
    { 3UL, 1, FD_VOTE_KIND_NOTAR,          &h3    },
    { 3UL, 1, FD_VOTE_KIND_NOTAR_FALLBACK, &h3b   },
    { 5UL, 1, FD_VOTE_KIND_NOTAR,          &h5    },
    { 5UL, 1, FD_VOTE_KIND_SKIP_FALLBACK,  NULL   },
    { 6UL, 0, FD_CERT_KIND_FINAL,          NULL   },
    { 6UL, 1, FD_VOTE_KIND_FINAL,          NULL   },
    { 7UL, 0, FD_CERT_KIND_NOTAR,          &h7    },
    { 7UL, 1, FD_VOTE_KIND_NOTAR,          &h7    },
    { 7UL, 1, FD_VOTE_KIND_FINAL,          NULL   },
    { 8UL, 0, FD_CERT_KIND_NOTAR_FALLBACK, &h8[0] },
    { 8UL, 0, FD_CERT_KIND_NOTAR_FALLBACK, &h8[1] },
    { 8UL, 0, FD_CERT_KIND_NOTAR_FALLBACK, &h8[2] },
    { 8UL, 0, FD_CERT_KIND_NOTAR_FALLBACK, &h8[3] },
    { 8UL, 1, FD_VOTE_KIND_NOTAR,          &h8[0] },
    { 8UL, 1, FD_VOTE_KIND_NOTAR_FALLBACK, &h8[1] },
    { 8UL, 1, FD_VOTE_KIND_NOTAR_FALLBACK, &h8[2] },
    { 8UL, 1, FD_VOTE_KIND_NOTAR_FALLBACK, &h8[3] },
  };
  ulong cnt = 0UL;
  fd_votor_pool_standstill_iter_t iter_[1];
  for( fd_votor_pool_standstill_iter_t * iter = fd_votor_pool_standstill_iter_init( iter_, pool ); !fd_votor_pool_standstill_iter_done( iter ); fd_votor_pool_standstill_iter_next( iter, pool ) ) {
    FD_TEST( cnt<sizeof(expected)/sizeof(expected[0]) );
    FD_TEST( iter->is_vote==expected[ cnt ].is_vote );
    if( iter->is_vote ) {
      FD_TEST( fd_vote_slot( &iter->vote )==expected[ cnt ].slot );
      FD_TEST( iter->vote.kind==expected[ cnt ].kind );
      FD_TEST( fd_vote_rank( &iter->vote )==0UL );
      FD_TEST( fd_vote_shred_version( &iter->vote )==TEST_SHRED_VERSION );
      if( expected[ cnt ].kind==FD_VOTE_KIND_NOTAR          ) FD_TEST( !memcmp( &iter->vote.notar.block_hash,          expected[ cnt ].hash, sizeof(fd_block_hash_t) ) );
      if( expected[ cnt ].kind==FD_VOTE_KIND_NOTAR_FALLBACK ) FD_TEST( !memcmp( &iter->vote.notar_fallback.block_hash, expected[ cnt ].hash, sizeof(fd_block_hash_t) ) );
    } else {
      FD_TEST( fd_cert_slot( &iter->cert )==expected[ cnt ].slot );
      FD_TEST( iter->cert.kind==expected[ cnt ].kind );
      if( expected[ cnt ].hash ) FD_TEST( !memcmp( fd_cert_block_hash( &iter->cert ), expected[ cnt ].hash, sizeof(fd_block_hash_t) ) );
    }
    cnt++;
  }
  FD_TEST( cnt==sizeof(expected)/sizeof(expected[0]) );

  fd_vote_t skip2 = fd_vote_construct_skip          ( sec_sign_fn, &g_sk[0], test_bls_public_key, 2UL,           (ushort)0, TEST_SHRED_VERSION );
  fd_vote_t nf8   = fd_vote_construct_notar_fallback( sec_sign_fn, &g_sk[0], test_bls_public_key, 8UL, &h8[ 3 ], (ushort)0, TEST_SHRED_VERSION );
  fd_standstill_t standstill = recover_from_standstill( pool );
  FD_TEST( standstill.cert_cnt==10UL && standstill.vote_cnt==12UL );
  FD_TEST( !memcmp( fd_vote_sig( &standstill.votes[  0 ] ), fd_vote_sig( &skip2 ), sizeof(fd_bls_sig_t) ) );
  FD_TEST( !memcmp( fd_vote_sig( &standstill.votes[  4 ] ), fd_vote_sig( &sf5   ), sizeof(fd_bls_sig_t) ) );
  FD_TEST( !memcmp( fd_vote_sig( &standstill.votes[ 11 ] ), fd_vote_sig( &nf8   ), sizeof(fd_bls_sig_t) ) );

  add_notar_votes( pool, 1UL, &h1, 0UL, 10UL ); /* fast-finalizes slot 1 too */
  standstill = recover_from_standstill( pool );
  FD_TEST( standstill.cert_cnt==9UL && standstill.vote_cnt==12UL );
  FD_TEST( standstill.certs[ 0 ].kind==FD_CERT_KIND_FAST_FINAL && fd_cert_slot( &standstill.certs[ 0 ] )==1UL );
  FD_TEST( fd_cert_slot( &standstill.certs[ 1 ] )==2UL );

  teardown_pool( pool );
}

/* Firedancer-only test.

   On snapshot boot the finalized slot is the replayed root, and a vote
   or cert for it can give it a slot state without a finalization pair.
   The bundle then starts at the next slot.  The reference asserts a
   final cert is present; here a peer's vote must not crash us. */

static void
test_standstill_iter_partial_root( void ) {
  fd_votor_pool_t * pool = setup_pool(); /* finalized slot 0, no slot state */

  fd_block_hash_t h0; random_hash( &h0 );
  add_notar_votes( pool, 0UL, &h0, 3UL, 4UL );
  FD_TEST( contains_slot( pool, 0UL ) );
  fd_standstill_t standstill = recover_from_standstill( pool );
  FD_TEST( standstill.cert_cnt==0UL && standstill.vote_cnt==0UL );

  add_final_votes( pool, 0UL, 0UL, 7UL ); /* a final cert, still no notar cert */
  FD_TEST( has_final_cert( pool, 0UL ) && !has_notar_cert( pool, 0UL ) );
  FD_TEST( fd_votor_pool_finalized_slot( pool )==0UL );

  fd_block_hash_t h1; random_hash( &h1 );
  add_notar_votes( pool, 1UL, &h1, 0UL, 1UL );
  standstill = recover_from_standstill( pool );
  FD_TEST( standstill.cert_cnt==0UL && standstill.vote_cnt==1UL );
  FD_TEST( fd_vote_slot( &standstill.votes[ 0 ] )==1UL && standstill.votes[ 0 ].kind==FD_VOTE_KIND_NOTAR );

  teardown_pool( pool );
}

/* Firedancer-only test.

   The tile steps the iterator across passes, so the pool can finalize
   and prune the slots ahead of it between steps.  The iterator skips
   the pruned slots and carries on from the live ones. */

static void
test_standstill_iter_prune( void ) {
  fd_votor_pool_t * pool = setup_pool();

  fd_block_hash_t h[ 31 ];
  for( ulong slot=1UL; slot<=30UL; slot++ ) random_hash( &h[ slot ] );
  for( ulong slot=1UL; slot<=30UL; slot++ ) add_notar_votes( pool, slot, &h[ slot ], 0UL, 1UL );

  fd_votor_pool_standstill_iter_t iter[1];
  fd_votor_pool_standstill_iter_init( iter, pool );
  FD_TEST( !fd_votor_pool_standstill_iter_done( iter ) && iter->is_vote && fd_vote_slot( &iter->vote )==1UL );
  fd_votor_pool_standstill_iter_next( iter, pool );
  FD_TEST( !fd_votor_pool_standstill_iter_done( iter ) && iter->is_vote && fd_vote_slot( &iter->vote )==2UL );

  for( ulong slot=1UL; slot<=20UL; slot++ ) add_notar_votes( pool, slot, &h[ slot ], 1UL, NV ); /* fast-finalizes 1..20 */
  FD_TEST( fd_votor_pool_finalized_slot( pool )==20UL );
  FD_TEST( !contains_slot( pool, 3UL ) && min_live_slot( pool )==12UL );

  uint const kind[ 2 ] = { FD_CERT_KIND_FAST_FINAL, FD_CERT_KIND_NOTAR }; /* 11 notar votes certify both, notar-fallback is implied */
  ulong cnt = 0UL;
  for( fd_votor_pool_standstill_iter_next( iter, pool ); !fd_votor_pool_standstill_iter_done( iter ); fd_votor_pool_standstill_iter_next( iter, pool ) ) {
    ulong slot = 12UL + fd_ulong_if( cnt<27UL, cnt/3UL, 9UL+cnt-27UL );
    ulong pos  = fd_ulong_if( cnt<27UL, cnt%3UL, 2UL );
    if( pos==2UL ) {
      FD_TEST( iter->is_vote && iter->vote.kind==FD_VOTE_KIND_NOTAR && fd_vote_slot( &iter->vote )==slot );
      FD_TEST( !memcmp( &iter->vote.notar.block_hash, &h[ slot ], sizeof(fd_block_hash_t) ) );
    } else {
      FD_TEST( !iter->is_vote && fd_cert_slot( &iter->cert )==slot && iter->cert.kind==kind[ pos ] );
    }
    cnt++;
  }
  FD_TEST( cnt==9UL*3UL+10UL );

  fd_standstill_t standstill = recover_from_standstill( pool );
  FD_TEST( standstill.slot==21UL && standstill.cert_cnt==1UL && standstill.vote_cnt==10UL );
  FD_TEST( standstill.certs[ 0 ].kind==FD_CERT_KIND_FAST_FINAL && fd_cert_slot( &standstill.certs[ 0 ] )==20UL );
  for( ulong i=0UL; i<10UL; i++ ) FD_TEST( fd_vote_slot( &standstill.votes[ i ] )==21UL+i );

  teardown_pool( pool );
}

/* Firedancer-only test.

   Popping a ParentReady clears its state's ready flag.  A finalization
   processed while the event was queued can prune that state, so the pop
   finds none and still delivers the event. */

static void
test_parent_ready_pruned_while_queued( void ) {
  fd_votor_pool_t * pool = setup_pool();
  drain_events( pool );

  ulong slot = 12344UL;
  FD_TEST( !fd_parent_ready_state_map_ele_query_const( pool->parent_ready_tracker->states.map, &slot, NULL, pool->parent_ready_tracker->states.pool ) );
  pool_events_push( pool->pool_events, (fd_votor_pool_event_t){ .kind = FD_VOTOR_POOL_EVENT_PARENT_READY, .parent_ready = { .slot = slot } } );

  fd_votor_pool_event_t event;
  FD_TEST(  fd_votor_pool_poll_pool_event( pool, &event ) );
  FD_TEST(  event.kind==FD_VOTOR_POOL_EVENT_PARENT_READY && event.parent_ready.slot==slot );
  FD_TEST( !fd_votor_pool_poll_pool_event( pool, &event ) );

  teardown_pool( pool );
}

/* Firedancer-only test.

   A block replayed after its slot was pruned (replay lagging the cert
   stream during catch-up) is out of bounds like a vote or cert would be
   and must not take a slot state below the watermark, and the next
   finalization must still leave nothing below it.  The reference split_off()s a BTreeMap on every prune; here the
   fixed-capacity pool would run dry. */

static void
test_add_block_below_watermark( void ) {
  fd_votor_pool_t * pool = setup_pool();
  fd_block_hash_t gh; genesis_hash( &gh );

  ulong slot = 3UL*SLOTS_PER_WINDOW - 1UL;
  for( ulong s=1UL; s<=slot; s++ ) fast_finalize( pool, s, &gh );
  FD_TEST( pool_first_unpruned_slot( pool )==slot );
  FD_TEST_PRUNED_TO_WATERMARK( pool );

  ulong free_cnt = slot_state_pool_free( pool->slot_states->pool );

  fd_block_id_t stale  = random_block_id( slot-2UL );
  fd_block_id_t parent = random_block_id( slot-3UL );
  FD_TEST( fd_votor_pool_add_block( pool, &stale, &parent, bad )==FD_VOTOR_POOL_ERR_SLOT_TOO_OLD );
  drain_events( pool );

  FD_TEST( contains_slot( pool, slot-2UL ) ); /* retained, untouched */
  FD_TEST( slot_state_pool_free( pool->slot_states->pool )==free_cnt );
  FD_TEST_PRUNED_TO_WATERMARK( pool );

  /* and the same window bound as votes and certs on the far side */
  fd_block_id_t far = random_block_id( slot+pool->slot_max );
  FD_TEST( fd_votor_pool_add_block( pool, &far, &stale, bad )==FD_VOTOR_POOL_ERR_SLOT_TOO_NEW );
  FD_TEST( !contains_slot( pool, slot+pool->slot_max ) );
  FD_TEST( slot_state_pool_free( pool->slot_states->pool )==free_cnt );

  fast_finalize( pool, slot+1UL, &gh );
  FD_TEST( pool_first_unpruned_slot( pool )==slot+1UL );
  FD_TEST_PRUNED_TO_WATERMARK( pool );

  teardown_pool( pool );
}
static slot_state_t const *
slot_state_at( fd_votor_pool_t const * pool,
               ulong                   slot ) {
  slot_state_ele_t const * e = slot_state_map_ele_query_const( pool->slot_states->map, &slot, NULL, pool->slot_states->pool );
  FD_TEST( e );
  return &e->slot_state;
}

/* Our rank changes mid-epoch on set-identity.  Live slot states in that
   epoch then treat the new rank's votes as ours, and the other epochs
   keep theirs. */

static void
test_update_own_rank( void ) {
  fd_votor_pool_t * pool = setup_pool();
  fd_votor_pool_advance_epoch( pool, make_epoch_info( 1UL, g_info, NV ), 0UL, 8UL );

  fd_block_hash_t a; random_hash( &a );
  fd_block_hash_t b; random_hash( &b );
  add_notar_votes( pool, 1UL, &a, 0UL, 1UL );
  add_notar_votes( pool, 1UL, &b, 1UL, 2UL );
  add_notar_votes( pool, 2UL, &a, 0UL, 1UL );
  add_notar_votes( pool, 9UL, &a, 0UL, 1UL );
  slot_state_t const * s1 = slot_state_at( pool, 1UL );
  slot_state_t const * s2 = slot_state_at( pool, 2UL );
  slot_state_t const * s9 = slot_state_at( pool, 9UL );
  FD_TEST( s1->own_rank==0UL && !memcmp( own_notar_hash( s1, pool->slot_states ), &a, sizeof(fd_block_hash_t) ) );

  fd_votor_pool_update_own_rank( pool, 0UL, 1UL );
  FD_TEST( s1->own_rank==1UL && !memcmp( own_notar_hash( s1, pool->slot_states ), &b,                  sizeof(fd_block_hash_t) ) );
  FD_TEST( s2->own_rank==1UL && !memcmp( own_notar_hash( s2, pool->slot_states ), &fd_block_hash_null, sizeof(fd_block_hash_t) ) );
  FD_TEST( s9->own_rank==0UL && !memcmp( own_notar_hash( s9, pool->slot_states ), &a,                  sizeof(fd_block_hash_t) ) );

  add_notar_votes( pool, 2UL, &b, 1UL, 2UL );
  FD_TEST( !memcmp( own_notar_hash( s2, pool->slot_states ), &b, sizeof(fd_block_hash_t) ) );
  add_notar_votes( pool, 3UL, &b, 1UL, 2UL );
  slot_state_t const * s3 = slot_state_at( pool, 3UL );
  FD_TEST( s3->own_rank==1UL && !memcmp( own_notar_hash( s3, pool->slot_states ), &b, sizeof(fd_block_hash_t) ) );

  fd_votor_pool_update_own_rank( pool, 8UL, USHORT_MAX );
  FD_TEST( s9->own_rank==USHORT_MAX && !memcmp( own_notar_hash( s9, pool->slot_states ), &fd_block_hash_null, sizeof(fd_block_hash_t) ) );

  teardown_pool( pool );
}
static void
test_bls_verify_cnt( void ) {
  fd_votor_pool_t * pool = setup_pool();
  fd_block_hash_t h; random_hash( &h );
  fd_vote_notar_t nv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) nv[v] = fd_vote_construct_notar( sec_sign_fn, &g_sk[v], test_bls_public_key, 1UL, &h, (ushort)v, TEST_SHRED_VERSION ).notar;

  fd_cert_t c = cert_build_notar( nv, 1UL, g_epoch_info );
  FD_TEST( fd_votor_pool_add_cert( pool, &c, 0, bad )==FD_VOTOR_POOL_ERR_CERT_VERIFY );
  FD_TEST( fd_votor_pool_metrics( pool ).bls_verify_cnt==0UL );

  c = cert_build_notar( nv, NV, g_epoch_info );
  fd_cert_t forged = c; forged.notar.slot = 2UL;
  FD_TEST( fd_votor_pool_add_cert( pool, &forged, 0, bad )==FD_VOTOR_POOL_ERR_CERT_VERIFY );
  FD_TEST( fd_votor_pool_metrics( pool ).bls_verify_cnt==1UL );

  FD_TEST( fd_votor_pool_add_cert( pool, &c, 0, bad )==FD_VOTOR_POOL_SUCCESS );
  FD_TEST( fd_votor_pool_metrics( pool ).bls_verify_cnt==2UL );

  teardown_pool( pool );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_slot_state();

  g_spill_fd = memfd_create( "votor_spill", 0 );
  FD_TEST( g_spill_fd>=0 );

  ulong sig_pg_max[ 2 ] = { TEST_SLOT_MAX*SLOT_SIG_PG_MAX, FD_VOTOR_VOTES_PER_SLOT_MAX+2UL }; /* RAM, then mostly spill file */
  for( ulong r=0UL; r<2UL; r++ ) {
    g_sig_pg_max = sig_pg_max[ r ];
    test_notarize_block();
    test_skip_block();
    test_finalize_block();
    test_reward_readback_window();
    test_cert_and_agg_rewards();
    test_reward_late_skip_unverified();
    test_reward_wire_cert_base();
    test_fast_finalize_block();
    test_implicit_finalization_events();
    test_fast_final_cert_requests_repair();
    test_finalized_block_hash();
    test_simple_branch_certified();
    test_branch_certified_notar_fallback();
    test_branch_certified_out_of_order();
    test_branch_certified_late_cert();
    test_regular_handover();
    test_one_skip_handover();
    test_two_skip_handover();
    test_skip_window_handover();
    test_pruning();
    test_sig_pg_released_on_prune();
    test_duplicate_votes();
    test_vote_subgroup_after_duplicate();
    test_duplicate_certs();
    test_add_verified_cert();
    test_out_of_bounds_votes();
    test_out_of_bounds_certs();
    test_slow_finalize_closing_gap_no_double_parent_ready();
    test_standstill_recovery();
    test_parent_ready_upon_finalization();
    test_add_block_root_jump();
    test_safe_to_notar_notar_cert_only();
    test_safe_to_notar_fast_final_cert_only();
    test_safe_to_notar_verifies_before_parent_cert();
    test_safe_to_notar_awaiting_votes();
    test_safe_to_notar_not_queued_for_parent_cert();
    test_s2n_waiting_every_child();
    test_s2n_waiting_fast_final_parent();
    test_s2n_waiting_pruned();

    test_handle_invalid_votes();
    test_hash_capacity();
    test_unknown_signer_votes();
    test_wait_for_parent_ready();
    test_stake_resolved_per_slot_epoch();
    test_epoch_boundary_slot();
    test_epoch_installed_late();
    test_retired_epoch_already_pruned();
    test_standstill_recovery_no_final_cert();
    test_standstill_iter_order();
    test_standstill_iter_partial_root();
    test_standstill_iter_prune();
    test_parent_ready_pruned_while_queued();
    test_add_block_below_watermark();
    test_update_own_rank();
    test_bls_verify_cnt();
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
