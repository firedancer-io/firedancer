#include "fd_slot_state.h"

/* Ports alpenglow/src/consensus/pool/slot_state.rs mod tests.  Stake / quorum
   come from a unit-stake epoch_info of n validators (generate_validators);
   own_id is validator 0 (wrap_epoch_info).  The signature-validity negative
   cases are not relevant here (the stub aggsig accepts all structurally valid
   sigs); we exercise the full vote/cert accumulation, threshold, safe-to-notar
   and slashing logic. */

#include <stdlib.h>

#define MAXV 64UL

static fd_aggsig_sk_t      g_sk  [ MAXV ];
static fd_validator_info_t g_info[ MAXV ];

/* generate_validators(n): n unit-stake validators with deterministic keys. */
static void
generate_validators( ulong n ) {
  FD_TEST( n<=MAXV );
  for( ulong i=0UL; i<n; i++ ) {
    fd_memset( g_sk[i].v, (int)(i*7UL+1UL), FD_AGGSIG_SECKEY_SZ );
    memset( &g_info[i], 0, sizeof(fd_validator_info_t) );
    g_info[i].id    = i;
    g_info[i].stake = 1UL;
    fd_aggsig_sk_to_pk( &g_info[i].voting_pubkey, &g_sk[i] );
  }
}

static fd_epoch_info_t *
make_epoch( ulong n, void ** out_mem ) {
  void * mem = aligned_alloc( fd_epoch_info_align(), fd_epoch_info_footprint( n ) );
  FD_TEST( mem );
  *out_mem = mem;
  return fd_epoch_info_join( fd_epoch_info_new( mem, g_info, n ) );
}

/* random_block_id: a deterministic-but-distinct hash per call. */
static fd_hash_t
random_hash( void ) {
  static ulong ctr = 1UL;
  fd_hash_t h; memset( h.uc, 0, sizeof(fd_hash_t) );
  ctr += 0x9E3779B97F4A7C15UL;
  memcpy( h.uc, &ctr, sizeof(ulong) );
  h.uc[ 31 ] = 0xAB; /* keep non-zero so it never collides with the genesis hash */
  return h;
}

static fd_slot_state_t *
make_state( fd_wksp_t * wksp, ulong slot, ulong validator_max, void ** out_mem ) {
  void * mem = fd_wksp_alloc_laddr( wksp, fd_slot_state_align(), fd_slot_state_footprint( validator_max ), 1UL );
  FD_TEST( mem );
  *out_mem = mem;
  return fd_slot_state_join( fd_slot_state_new( mem, slot, 0UL, validator_max, 42UL ) );
}

/* outputs sink with generous fixed capacity. */
typedef struct {
  fd_cert_t       certs  [ 8 ];
  fd_pool_event_t events [ 8 ];
  fd_block_id_t   repairs[ 8 ];
  fd_slot_state_outputs_t o;
} out_t;

static void
out_reset( out_t * t ) {
  t->o.certs       = t->certs;   t->o.certs_cnt   = 0UL; t->o.certs_max   = 8UL;
  t->o.events      = t->events;  t->o.events_cnt  = 0UL; t->o.events_max  = 8UL;
  t->o.repairs     = t->repairs; t->o.repairs_cnt = 0UL; t->o.repairs_max = 8UL;
}

/* add(state, vote): look up voter stake (=1) and add it. */
static void
add_vote_helper( fd_slot_state_t * ss, fd_ag_vote_t const * vote, fd_epoch_info_t const * ei, out_t * t ) {
  ulong stake = fd_epoch_info_validator( ei, fd_vote_signer( vote ) )->stake;
  out_reset( t );
  fd_slot_state_add_vote( ss, vote, stake, ei, &t->o );
}

/* ------------------------------------------------------------------ add_cert */

static void
test_add_cert( fd_wksp_t * wksp ) {
  ulong n = 11UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash = random_hash();
  void * sm; fd_slot_state_t * ss = make_state( wksp, slot, MAXV, &sm );

  fd_notar_vote_t nv[ 11 ];
  for( ulong i=0UL; i<n; i++ ) fd_notar_vote_new( &nv[i], slot, &hash, &g_sk[i], (ushort)i );
  fd_cert_t c; c.discriminant = FD_CERT_TYPE_NOTAR;
  FD_TEST( fd_notar_cert_try_new( &c.inner.notar, nv, n,
                                  fd_epoch_info_validators( ei ), ei->validator_cnt )==FD_CERT_SUCCESS );

  FD_TEST( !fd_slot_state_has_notar_cert( ss ) );
  fd_slot_state_add_cert( ss, &c );
  FD_TEST(  fd_slot_state_has_notar_cert( ss ) );

  fd_wksp_free_laddr( fd_slot_state_delete( fd_slot_state_leave( ss ) ) );
  free( em );
}

/* ------------------------------------------------------------------ add_vote */

static void
test_add_vote( fd_wksp_t * wksp ) {
  ulong n = 11UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash = random_hash();
  void * sm; fd_slot_state_t * ss = make_state( wksp, slot, MAXV, &sm );
  out_t t;

  for( ulong i=0UL; i<n; i++ ) {
    fd_ag_vote_t vote; fd_vote_new_notar( &vote, slot, &hash, &g_sk[i], (ushort)i );
    FD_TEST( !fd_slot_state_has_notar_vote( ss, i ) );
    add_vote_helper( ss, &vote, ei, &t );
    FD_TEST(  fd_slot_state_has_notar_vote( ss, i ) );
    FD_TEST(  fd_slot_state_notar_stake( ss, &hash )==i+1UL );
  }

  fd_wksp_free_laddr( fd_slot_state_delete( fd_slot_state_leave( ss ) ) );
  free( em );
}

/* ------------------------------------------------------------- safe_to_notar */

static void
test_safe_to_notar( fd_wksp_t * wksp ) {
  ulong n = 3UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash = random_hash();
  void * sm; fd_slot_state_t * ss = make_state( wksp, slot, MAXV, &sm );
  out_t t;

  /* mark parent as notarized(-fallback) */
  fd_slot_state_notify_parent_known( ss, &hash );
  fd_slot_state_notify_parent_certified( ss, &hash, ei );

  /* 33% notar alone has no effect */
  fd_ag_vote_t notar_vote; fd_vote_new_notar( &notar_vote, slot, &hash, &g_sk[1], 1UL );
  add_vote_helper( ss, &notar_vote, ei, &t );
  FD_TEST( t.o.certs_cnt==0UL );
  FD_TEST( t.o.events_cnt==0UL );
  FD_TEST( t.o.repairs_cnt==0UL );

  /* additional 33% skip should lead to safe-to-notar (own validator 0 skips) */
  fd_ag_vote_t skip_vote; fd_vote_new_skip( &skip_vote, slot, &g_sk[0], 0UL );
  add_vote_helper( ss, &skip_vote, ei, &t );
  FD_TEST( t.o.certs_cnt==0UL );
  FD_TEST( t.o.events_cnt==1UL );
  FD_TEST( t.o.repairs_cnt==0UL );
  FD_TEST( t.events[0].kind==FD_POOL_EVENT_SAFE_TO_NOTAR );
  FD_TEST( t.events[0].block.slot==slot );
  FD_TEST( !memcmp( t.events[0].block.hash.uc, hash.uc, sizeof(fd_hash_t) ) );

  fd_wksp_free_laddr( fd_slot_state_delete( fd_slot_state_leave( ss ) ) );
  free( em );
}

/* ---------------------------------------------------- slashable offences */

static void
test_slashable_skip_and_notarize( fd_wksp_t * wksp ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash = random_hash();
  void * sm; fd_slot_state_t * ss = make_state( wksp, slot, MAXV, &sm );
  out_t t;

  /* validator 1 skips first, so a later notarization is slashable */
  fd_ag_vote_t s1; fd_vote_new_skip( &s1, slot, &g_sk[1], 1UL );
  add_vote_helper( ss, &s1, ei, &t );
  fd_ag_vote_t notar_vote; fd_vote_new_notar( &notar_vote, slot, &hash, &g_sk[1], 1UL );
  fd_slashable_offence_t o = fd_slot_state_check_slashable_offence( ss, &notar_vote );
  FD_TEST( o.kind==FD_SLASHABLE_SKIP_AND_NOTARIZE && o.validator==1UL && o.slot==slot );

  /* validator 2 notarizes first, so a later skip is slashable */
  fd_ag_vote_t n2; fd_vote_new_notar( &n2, slot, &hash, &g_sk[2], 2UL );
  add_vote_helper( ss, &n2, ei, &t );
  fd_ag_vote_t skip_vote; fd_vote_new_skip( &skip_vote, slot, &g_sk[2], 2UL );
  o = fd_slot_state_check_slashable_offence( ss, &skip_vote );
  FD_TEST( o.kind==FD_SLASHABLE_SKIP_AND_NOTARIZE && o.validator==2UL && o.slot==slot );

  fd_wksp_free_laddr( fd_slot_state_delete( fd_slot_state_leave( ss ) ) );
  free( em );
}

static void
test_slashable_notar_different_hash( fd_wksp_t * wksp ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash_a = random_hash();
  fd_hash_t hash_b = random_hash();
  void * sm; fd_slot_state_t * ss = make_state( wksp, slot, MAXV, &sm );
  out_t t;

  fd_ag_vote_t notar_a; fd_vote_new_notar( &notar_a, slot, &hash_a, &g_sk[1], 1UL );
  add_vote_helper( ss, &notar_a, ei, &t );

  /* notarizing a different hash for the same slot is slashable */
  fd_ag_vote_t notar_b; fd_vote_new_notar( &notar_b, slot, &hash_b, &g_sk[1], 1UL );
  fd_slashable_offence_t o = fd_slot_state_check_slashable_offence( ss, &notar_b );
  FD_TEST( o.kind==FD_SLASHABLE_NOTAR_DIFFERENT_HASH && o.validator==1UL && o.slot==slot );

  /* re-notarizing the same hash is a benign duplicate, not slashable */
  o = fd_slot_state_check_slashable_offence( ss, &notar_a );
  FD_TEST( o.kind==FD_SLASHABLE_NONE );

  fd_wksp_free_laddr( fd_slot_state_delete( fd_slot_state_leave( ss ) ) );
  free( em );
}

static void
test_slashable_skip_and_finalize( fd_wksp_t * wksp ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  void * sm; fd_slot_state_t * ss = make_state( wksp, slot, MAXV, &sm );
  out_t t;

  /* finalize first, then skip / skip-fallback are slashable */
  fd_ag_vote_t f1; fd_vote_new_final( &f1, slot, &g_sk[1], 1UL );
  add_vote_helper( ss, &f1, ei, &t );
  fd_ag_vote_t s1; fd_vote_new_skip( &s1, slot, &g_sk[1], 1UL );
  fd_slashable_offence_t o = fd_slot_state_check_slashable_offence( ss, &s1 );
  FD_TEST( o.kind==FD_SLASHABLE_SKIP_AND_FINALIZE && o.validator==1UL && o.slot==slot );
  fd_ag_vote_t sf1; fd_vote_new_skip_fallback( &sf1, slot, &g_sk[1], 1UL );
  o = fd_slot_state_check_slashable_offence( ss, &sf1 );
  FD_TEST( o.kind==FD_SLASHABLE_SKIP_AND_FINALIZE && o.validator==1UL && o.slot==slot );

  /* skip first, then finalize is slashable */
  fd_ag_vote_t s2; fd_vote_new_skip( &s2, slot, &g_sk[2], 2UL );
  add_vote_helper( ss, &s2, ei, &t );
  fd_ag_vote_t f2; fd_vote_new_final( &f2, slot, &g_sk[2], 2UL );
  o = fd_slot_state_check_slashable_offence( ss, &f2 );
  FD_TEST( o.kind==FD_SLASHABLE_SKIP_AND_FINALIZE && o.validator==2UL && o.slot==slot );

  /* skip-fallback first, then finalize is slashable */
  fd_ag_vote_t sf3; fd_vote_new_skip_fallback( &sf3, slot, &g_sk[3], 3UL );
  add_vote_helper( ss, &sf3, ei, &t );
  fd_ag_vote_t f3; fd_vote_new_final( &f3, slot, &g_sk[3], 3UL );
  o = fd_slot_state_check_slashable_offence( ss, &f3 );
  FD_TEST( o.kind==FD_SLASHABLE_SKIP_AND_FINALIZE && o.validator==3UL && o.slot==slot );

  fd_wksp_free_laddr( fd_slot_state_delete( fd_slot_state_leave( ss ) ) );
  free( em );
}

static void
test_slashable_notar_fallback_and_finalize( fd_wksp_t * wksp ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash = random_hash();
  void * sm; fd_slot_state_t * ss = make_state( wksp, slot, MAXV, &sm );
  out_t t;

  /* finalize first, then a notar-fallback is slashable */
  fd_ag_vote_t f1; fd_vote_new_final( &f1, slot, &g_sk[1], 1UL );
  add_vote_helper( ss, &f1, ei, &t );
  fd_ag_vote_t nf1; fd_vote_new_notar_fallback( &nf1, slot, &hash, &g_sk[1], 1UL );
  fd_slashable_offence_t o = fd_slot_state_check_slashable_offence( ss, &nf1 );
  FD_TEST( o.kind==FD_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE && o.validator==1UL && o.slot==slot );

  /* notar-fallback first, then finalize is slashable */
  fd_ag_vote_t nf2; fd_vote_new_notar_fallback( &nf2, slot, &hash, &g_sk[2], 2UL );
  add_vote_helper( ss, &nf2, ei, &t );
  fd_ag_vote_t f2; fd_vote_new_final( &f2, slot, &g_sk[2], 2UL );
  o = fd_slot_state_check_slashable_offence( ss, &f2 );
  FD_TEST( o.kind==FD_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE && o.validator==2UL && o.slot==slot );

  fd_wksp_free_laddr( fd_slot_state_delete( fd_slot_state_leave( ss ) ) );
  free( em );
}

static void
test_slashable_offence_none( fd_wksp_t * wksp ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash = random_hash();
  void * sm; fd_slot_state_t * ss = make_state( wksp, slot, MAXV, &sm );
  out_t t;
  ulong v = 1UL;

  /* no prior votes -> nothing is slashable */
  fd_ag_vote_t notar_vote; fd_vote_new_notar( &notar_vote, slot, &hash, &g_sk[1], (ushort)v );
  fd_ag_vote_t skip_vote;  fd_vote_new_skip ( &skip_vote,  slot,        &g_sk[1], (ushort)v );
  fd_ag_vote_t final_vote; fd_vote_new_final( &final_vote, slot,        &g_sk[1], (ushort)v );
  FD_TEST( fd_slot_state_check_slashable_offence( ss, &notar_vote ).kind==FD_SLASHABLE_NONE );
  FD_TEST( fd_slot_state_check_slashable_offence( ss, &skip_vote  ).kind==FD_SLASHABLE_NONE );
  FD_TEST( fd_slot_state_check_slashable_offence( ss, &final_vote ).kind==FD_SLASHABLE_NONE );

  /* notarizing then finalizing the same block is the happy path, not slashable */
  add_vote_helper( ss, &notar_vote, ei, &t );
  FD_TEST( fd_slot_state_check_slashable_offence( ss, &final_vote ).kind==FD_SLASHABLE_NONE );

  fd_wksp_free_laddr( fd_slot_state_delete( fd_slot_state_leave( ss ) ) );
  free( em );
}

/* --------------------------------------------- should_ignore_duplicate_votes */

static void
test_should_ignore_duplicate_votes( fd_wksp_t * wksp ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash       = random_hash();
  fd_hash_t other_hash = random_hash();
  void * sm; fd_slot_state_t * ss = make_state( wksp, slot, MAXV, &sm );
  out_t t;

  /* fresh validator: nothing to ignore */
  fd_ag_vote_t v1n; fd_vote_new_notar( &v1n, slot, &hash, &g_sk[1], 1UL );
  FD_TEST( !fd_slot_state_should_ignore_vote( ss, &v1n ) );

  /* only one notar vote per validator counts, regardless of the hash */
  add_vote_helper( ss, &v1n, ei, &t );
  FD_TEST( fd_slot_state_should_ignore_vote( ss, &v1n ) );
  fd_ag_vote_t v1n_other; fd_vote_new_notar( &v1n_other, slot, &other_hash, &g_sk[1], 1UL );
  FD_TEST( fd_slot_state_should_ignore_vote( ss, &v1n_other ) );

  /* should ignore skip and skip-fallback after skip */
  fd_ag_vote_t v2s; fd_vote_new_skip( &v2s, slot, &g_sk[2], 2UL );
  add_vote_helper( ss, &v2s, ei, &t );
  FD_TEST( fd_slot_state_should_ignore_vote( ss, &v2s ) );
  fd_ag_vote_t v2sf; fd_vote_new_skip_fallback( &v2sf, slot, &g_sk[2], 2UL );
  FD_TEST( fd_slot_state_should_ignore_vote( ss, &v2sf ) );

  /* ignore duplicate finalization votes */
  fd_ag_vote_t v3f; fd_vote_new_final( &v3f, slot, &g_sk[3], 3UL );
  add_vote_helper( ss, &v3f, ei, &t );
  FD_TEST( fd_slot_state_should_ignore_vote( ss, &v3f ) );

  /* notar-fallback is tracked per (validator, hash) */
  fd_ag_vote_t v4nf; fd_vote_new_notar_fallback( &v4nf, slot, &hash, &g_sk[4], 4UL );
  add_vote_helper( ss, &v4nf, ei, &t );
  FD_TEST( fd_slot_state_should_ignore_vote( ss, &v4nf ) );
  fd_ag_vote_t v4nf_other; fd_vote_new_notar_fallback( &v4nf_other, slot, &other_hash, &g_sk[4], 4UL );
  FD_TEST( !fd_slot_state_should_ignore_vote( ss, &v4nf_other ) );

  fd_wksp_free_laddr( fd_slot_state_delete( fd_slot_state_leave( ss ) ) );
  free( em );
}

/* ----------------------------------------- count_finalize_creates_cert_at_quorum */

static void
test_count_finalize_creates_cert_at_quorum( fd_wksp_t * wksp ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  void * sm; fd_slot_state_t * ss = make_state( wksp, slot, MAXV, &sm );
  out_t t;

  /* 3/6 final votes, below 60% quorum, no cert yet (validators 1,2,3) */
  for( ulong i=1UL; i<=3UL; i++ ) {
    fd_ag_vote_t fv; fd_vote_new_final( &fv, slot, &g_sk[i], (ushort)i );
    add_vote_helper( ss, &fv, ei, &t );
    FD_TEST( t.o.certs_cnt==0UL );
    FD_TEST( t.o.events_cnt==0UL );
    FD_TEST( t.o.repairs_cnt==0UL );
  }
  FD_TEST( fd_slot_state_finalize_stake( ss )==3UL );

  /* 4/6 final votes, quorum reached, produce final cert (validator 4) */
  fd_ag_vote_t fv4; fd_vote_new_final( &fv4, slot, &g_sk[4], 4UL );
  add_vote_helper( ss, &fv4, ei, &t );
  FD_TEST( t.o.certs_cnt==1UL );
  FD_TEST( t.certs[0].discriminant==FD_CERT_TYPE_FINAL );

  /* more final votes do not emit new cert */
  fd_slot_state_add_cert( ss, &t.certs[0] );
  fd_ag_vote_t fv5; fd_vote_new_final( &fv5, slot, &g_sk[5], 5UL );
  add_vote_helper( ss, &fv5, ei, &t );
  FD_TEST( t.o.certs_cnt==0UL );

  fd_wksp_free_laddr( fd_slot_state_delete( fd_slot_state_leave( ss ) ) );
  free( em );
}

/* -------------------------------- count_notar_fallback_creates_cert_at_quorum */

static void
test_count_notar_fallback_creates_cert_at_quorum( fd_wksp_t * wksp ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; fd_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash = random_hash();
  void * sm; fd_slot_state_t * ss = make_state( wksp, slot, MAXV, &sm );
  out_t t;

  /* two notar votes for the block, not enough for any cert (validators 1,2) */
  for( ulong i=1UL; i<=2UL; i++ ) {
    fd_ag_vote_t nv; fd_vote_new_notar( &nv, slot, &hash, &g_sk[i], (ushort)i );
    add_vote_helper( ss, &nv, ei, &t );
    FD_TEST( t.o.certs_cnt==0UL );
  }

  /* one notar-fallback vote: notar(2) + nf(1) = 3 < quorum(4), still no cert */
  fd_ag_vote_t nf3; fd_vote_new_notar_fallback( &nf3, slot, &hash, &g_sk[3], 3UL );
  add_vote_helper( ss, &nf3, ei, &t );
  FD_TEST( t.o.certs_cnt==0UL );
  FD_TEST( t.o.events_cnt==0UL );
  FD_TEST( t.o.repairs_cnt==0UL );
  FD_TEST( fd_slot_state_notar_fallback_stake( ss, &hash )==1UL );

  /* second notar-fallback vote: notar(2) + nf(2) = 4 = quorum -> nf cert */
  fd_ag_vote_t nf4; fd_vote_new_notar_fallback( &nf4, slot, &hash, &g_sk[4], 4UL );
  add_vote_helper( ss, &nf4, ei, &t );
  FD_TEST( t.o.certs_cnt==1UL );
  FD_TEST( t.certs[0].discriminant==FD_CERT_TYPE_NOTAR_FALLBACK );
  FD_TEST( fd_cert_block_hash( &t.certs[0] ) && !memcmp( fd_cert_block_hash( &t.certs[0] )->uc, hash.uc, sizeof(fd_hash_t) ) );

  /* more notar-fallback votes do not emit new cert */
  fd_slot_state_add_cert( ss, &t.certs[0] );
  fd_ag_vote_t nf5; fd_vote_new_notar_fallback( &nf5, slot, &hash, &g_sk[5], 5UL );
  add_vote_helper( ss, &nf5, ei, &t );
  FD_TEST( t.o.certs_cnt==0UL );

  fd_wksp_free_laddr( fd_slot_state_delete( fd_slot_state_leave( ss ) ) );
  free( em );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong       page_cnt = 512UL; /* ~2 MiB of normal pages: ample for several slot_states */
  char *      page_sz  = "normal";
  ulong       numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp     = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( page_sz ),
                                                page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_add_cert                              ( wksp );
  test_add_vote                              ( wksp );
  test_safe_to_notar                         ( wksp );
  test_slashable_skip_and_notarize           ( wksp );
  test_slashable_notar_different_hash        ( wksp );
  test_slashable_skip_and_finalize           ( wksp );
  test_slashable_notar_fallback_and_finalize ( wksp );
  test_slashable_offence_none                ( wksp );
  test_should_ignore_duplicate_votes         ( wksp );
  test_count_finalize_creates_cert_at_quorum ( wksp );
  test_count_notar_fallback_creates_cert_at_quorum( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
