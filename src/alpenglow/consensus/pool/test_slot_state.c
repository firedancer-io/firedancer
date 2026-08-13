/* The .c, not the header: test_set_insert_contains_iter reaches
   ag_hash_set_t's private set_insert / set_contains / set_remove, the same
   way test_pool.c and test_parent_ready_tracker.c reach their subjects'
   internals. */

#include "ag_slot_state.c"

#define TEST_SHRED_VERSION ((ushort)514)

#include <stdlib.h>

#define MAXV 64UL

static ag_aggsig_sk_t      g_sk  [ MAXV ];
static ag_validator_info_t g_info[ MAXV ];

static void
generate_validators( ulong n ) {
  FD_TEST( n<=MAXV );
  for( ulong i=0UL; i<n; i++ ) {
    fd_memset( g_sk[i].v, (int)(i*7UL+1UL), AG_AGGSIG_SECKEY_SZ );
    memset( &g_info[i], 0, sizeof(ag_validator_info_t) );
    g_info[i].id    = i;
    g_info[i].stake = 1UL;
    ag_aggsig_sk_to_pk( &g_info[i].voting_pubkey, &g_sk[i] );
  }
}

static ag_epoch_info_t *
make_epoch( ulong   n,
            void ** out_mem ) {
  ag_epoch_info_t * ei = aligned_alloc( alignof(ag_epoch_info_t), sizeof(ag_epoch_info_t) );
  FD_TEST( ei );
  *out_mem = ei;
  ag_epoch_info_init( ei, g_info, n );
  return ei;
}

static fd_hash_t
random_hash( void ) {
  static ulong ctr = 1UL;
  fd_hash_t h; memset( h.uc, 0, sizeof(fd_hash_t) );
  ctr += 0x9E3779B97F4A7C15UL;
  memcpy( h.uc, &ctr, sizeof(ulong) );
  h.uc[ 31 ] = 0xAB;
  return h;
}

/* ag_slot_state_t is a plain fixed-size struct; init is its whole
   lifecycle.  It is allocated out of the wksp only because it is far too
   big for the stack. */

static ag_slot_state_t *
make_state( fd_wksp_t *             wksp,
            ulong                   slot,
            ag_epoch_info_t const * ei ) {
  ag_slot_state_t * slot_state = fd_wksp_alloc_laddr( wksp, alignof(ag_slot_state_t), sizeof(ag_slot_state_t), 1UL );
  FD_TEST( slot_state );
  ag_slot_state_init( slot_state, slot, ei, 0UL );
  return slot_state;
}

typedef struct {
  ag_slot_state_outputs_t o;
} out_t;

static void
add_vote_helper( ag_slot_state_t *       ss,
                 ag_vote_t const *       vote,
                 ag_epoch_info_t const * ei,
                 out_t *                 t ) {
  ulong stake = ag_epoch_info_validator( ei, ag_vote_signer( vote ) )->stake;
  t->o = ag_slot_state_add_vote( ss, vote, stake );
}

static void
test_add_cert( fd_wksp_t * wksp ) {
  ulong n = 11UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash = random_hash();
  ag_slot_state_t * ss = make_state( wksp, slot, ei );

  ag_notar_vote_t nv[ 11 ];
  for( ulong i=0UL; i<n; i++ ) ag_notar_vote_new( &nv[i], slot, &hash, &g_sk[i], (ushort)i , TEST_SHRED_VERSION );
  ag_cert_t c; c.kind = AG_CERT_TYPE_NOTAR;
  FD_TEST( ag_notar_cert_try_new( &c.inner.notar, nv, n,
                                  ag_epoch_info_validators( ei ), ei->validator_cnt )==AG_CERT_SUCCESS );

  FD_TEST( ss->certificates.notar.slot==ULONG_MAX );
  ag_slot_state_add_cert( ss, &c );
  FD_TEST( ss->certificates.notar.slot==slot );

  fd_wksp_free_laddr( ss );
  free( em );
}

static void
test_add_vote( fd_wksp_t * wksp ) {
  ulong n = 11UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash = random_hash();
  ag_slot_state_t * ss = make_state( wksp, slot, ei );
  out_t t;

  for( ulong i=0UL; i<n; i++ ) {
    ag_vote_t vote; ag_vote_new_notar( &vote, slot, &hash, &g_sk[i], (ushort)i , TEST_SHRED_VERSION );
    FD_TEST( ss->votes.notar[i].slot==ULONG_MAX );
    add_vote_helper( ss, &vote, ei, &t );
    FD_TEST( ss->votes.notar[i].slot==slot );
    FD_TEST(  ag_slot_state_stake( ss->voted_stakes.notar, ss->voted_stakes.notar_cnt, &hash )==i+1UL );
  }

  fd_wksp_free_laddr( ss );
  free( em );
}

static void
test_safe_to_notar( fd_wksp_t * wksp ) {
  ulong n = 3UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash = random_hash();
  ag_slot_state_t * ss = make_state( wksp, slot, ei );
  out_t t;

  ag_slot_state_notify_parent_known( ss, &hash );
  ag_slot_state_notify_parent_certified( ss, &hash );

  ag_vote_t notar_vote; ag_vote_new_notar( &notar_vote, slot, &hash, &g_sk[1], 1UL , TEST_SHRED_VERSION );
  add_vote_helper( ss, &notar_vote, ei, &t );
  FD_TEST( t.o.certs_cnt==0UL );
  FD_TEST( t.o.pool_events_cnt==0UL );
  FD_TEST( t.o.block_repairs_cnt==0UL );

  ag_vote_t skip_vote; ag_vote_new_skip( &skip_vote, slot, &g_sk[0], 0UL , TEST_SHRED_VERSION );
  add_vote_helper( ss, &skip_vote, ei, &t );
  FD_TEST( t.o.certs_cnt==0UL );
  FD_TEST( t.o.pool_events_cnt==1UL );
  FD_TEST( t.o.block_repairs_cnt==0UL );
  FD_TEST( t.o.pool_events[0].kind==AG_POOL_EVENT_SAFE_TO_NOTAR );
  FD_TEST( t.o.pool_events[0].inner.safe_to_notar.slot==slot );
  FD_TEST( !memcmp( t.o.pool_events[0].inner.safe_to_notar.hash.uc, hash.uc, sizeof(fd_hash_t) ) );

  fd_wksp_free_laddr( ss );
  free( em );
}

static void
test_slashable_skip_and_notarize( fd_wksp_t * wksp ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash = random_hash();
  ag_slot_state_t * ss = make_state( wksp, slot, ei );
  out_t t;

  ag_vote_t s1; ag_vote_new_skip( &s1, slot, &g_sk[1], 1UL , TEST_SHRED_VERSION );
  add_vote_helper( ss, &s1, ei, &t );
  ag_vote_t notar_vote; ag_vote_new_notar( &notar_vote, slot, &hash, &g_sk[1], 1UL , TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &notar_vote )==AG_SLASHABLE_SKIP_AND_NOTARIZE );

  ag_vote_t n2; ag_vote_new_notar( &n2, slot, &hash, &g_sk[2], 2UL , TEST_SHRED_VERSION );
  add_vote_helper( ss, &n2, ei, &t );
  ag_vote_t skip_vote; ag_vote_new_skip( &skip_vote, slot, &g_sk[2], 2UL , TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &skip_vote )==AG_SLASHABLE_SKIP_AND_NOTARIZE );

  fd_wksp_free_laddr( ss );
  free( em );
}

static void
test_slashable_notar_different_hash( fd_wksp_t * wksp ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash_a = random_hash();
  fd_hash_t hash_b = random_hash();
  ag_slot_state_t * ss = make_state( wksp, slot, ei );
  out_t t;

  ag_vote_t notar_a; ag_vote_new_notar( &notar_a, slot, &hash_a, &g_sk[1], 1UL , TEST_SHRED_VERSION );
  add_vote_helper( ss, &notar_a, ei, &t );

  ag_vote_t notar_b; ag_vote_new_notar( &notar_b, slot, &hash_b, &g_sk[1], 1UL , TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &notar_b )==AG_SLASHABLE_NOTAR_DIFFERENT_HASH );

  FD_TEST( ag_slot_state_check_slashable_offence( ss, &notar_a )==AG_SLASHABLE_NONE );

  fd_wksp_free_laddr( ss );
  free( em );
}

static void
test_slashable_skip_and_finalize( fd_wksp_t * wksp ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  ag_slot_state_t * ss = make_state( wksp, slot, ei );
  out_t t;

  ag_vote_t f1; ag_vote_new_final( &f1, slot, &g_sk[1], 1UL , TEST_SHRED_VERSION );
  add_vote_helper( ss, &f1, ei, &t );
  ag_vote_t s1; ag_vote_new_skip( &s1, slot, &g_sk[1], 1UL , TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &s1 )==AG_SLASHABLE_SKIP_AND_FINALIZE );
  ag_vote_t sf1; ag_vote_new_skip_fallback( &sf1, slot, &g_sk[1], 1UL , TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &sf1 )==AG_SLASHABLE_SKIP_AND_FINALIZE );

  ag_vote_t s2; ag_vote_new_skip( &s2, slot, &g_sk[2], 2UL , TEST_SHRED_VERSION );
  add_vote_helper( ss, &s2, ei, &t );
  ag_vote_t f2; ag_vote_new_final( &f2, slot, &g_sk[2], 2UL , TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &f2 )==AG_SLASHABLE_SKIP_AND_FINALIZE );

  ag_vote_t sf3; ag_vote_new_skip_fallback( &sf3, slot, &g_sk[3], 3UL , TEST_SHRED_VERSION );
  add_vote_helper( ss, &sf3, ei, &t );
  ag_vote_t f3; ag_vote_new_final( &f3, slot, &g_sk[3], 3UL , TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &f3 )==AG_SLASHABLE_SKIP_AND_FINALIZE );

  fd_wksp_free_laddr( ss );
  free( em );
}

static void
test_slashable_notar_fallback_and_finalize( fd_wksp_t * wksp ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash = random_hash();
  ag_slot_state_t * ss = make_state( wksp, slot, ei );
  out_t t;

  ag_vote_t f1; ag_vote_new_final( &f1, slot, &g_sk[1], 1UL , TEST_SHRED_VERSION );
  add_vote_helper( ss, &f1, ei, &t );
  ag_vote_t nf1; ag_vote_new_notar_fallback( &nf1, slot, &hash, &g_sk[1], 1UL , TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &nf1 )==AG_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE );

  ag_vote_t nf2; ag_vote_new_notar_fallback( &nf2, slot, &hash, &g_sk[2], 2UL , TEST_SHRED_VERSION );
  add_vote_helper( ss, &nf2, ei, &t );
  ag_vote_t f2; ag_vote_new_final( &f2, slot, &g_sk[2], 2UL , TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &f2 )==AG_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE );

  fd_wksp_free_laddr( ss );
  free( em );
}

static void
test_slashable_offence_none( fd_wksp_t * wksp ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash = random_hash();
  ag_slot_state_t * ss = make_state( wksp, slot, ei );
  out_t t;
  ulong v = 1UL;

  ag_vote_t notar_vote; ag_vote_new_notar( &notar_vote, slot, &hash, &g_sk[1], (ushort)v , TEST_SHRED_VERSION );
  ag_vote_t skip_vote;  ag_vote_new_skip( &skip_vote,  slot,        &g_sk[1], (ushort)v , TEST_SHRED_VERSION );
  ag_vote_t final_vote; ag_vote_new_final( &final_vote, slot,        &g_sk[1], (ushort)v , TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &notar_vote )==AG_SLASHABLE_NONE );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &skip_vote )==AG_SLASHABLE_NONE );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &final_vote )==AG_SLASHABLE_NONE );

  add_vote_helper( ss, &notar_vote, ei, &t );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &final_vote )==AG_SLASHABLE_NONE );

  fd_wksp_free_laddr( ss );
  free( em );
}

static void
test_should_ignore_duplicate_votes( fd_wksp_t * wksp ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash       = random_hash();
  fd_hash_t other_hash = random_hash();
  ag_slot_state_t * ss = make_state( wksp, slot, ei );
  out_t t;

  ag_vote_t v1n; ag_vote_new_notar( &v1n, slot, &hash, &g_sk[1], 1UL , TEST_SHRED_VERSION );
  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &v1n ) );

  add_vote_helper( ss, &v1n, ei, &t );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &v1n ) );
  ag_vote_t v1n_other; ag_vote_new_notar( &v1n_other, slot, &other_hash, &g_sk[1], 1UL , TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &v1n_other ) );

  ag_vote_t v2s; ag_vote_new_skip( &v2s, slot, &g_sk[2], 2UL , TEST_SHRED_VERSION );
  add_vote_helper( ss, &v2s, ei, &t );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &v2s ) );
  ag_vote_t v2sf; ag_vote_new_skip_fallback( &v2sf, slot, &g_sk[2], 2UL , TEST_SHRED_VERSION );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &v2sf ) );

  ag_vote_t v3f; ag_vote_new_final( &v3f, slot, &g_sk[3], 3UL , TEST_SHRED_VERSION );
  add_vote_helper( ss, &v3f, ei, &t );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &v3f ) );

  ag_vote_t v4nf; ag_vote_new_notar_fallback( &v4nf, slot, &hash, &g_sk[4], 4UL , TEST_SHRED_VERSION );
  add_vote_helper( ss, &v4nf, ei, &t );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &v4nf ) );
  ag_vote_t v4nf_other; ag_vote_new_notar_fallback( &v4nf_other, slot, &other_hash, &g_sk[4], 4UL , TEST_SHRED_VERSION );
  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &v4nf_other ) );

  fd_wksp_free_laddr( ss );
  free( em );
}

static void
test_count_finalize_creates_cert_at_quorum( fd_wksp_t * wksp ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  ag_slot_state_t * ss = make_state( wksp, slot, ei );
  out_t t;

  for( ulong i=1UL; i<=3UL; i++ ) {
    ag_vote_t fv; ag_vote_new_final( &fv, slot, &g_sk[i], (ushort)i , TEST_SHRED_VERSION );
    add_vote_helper( ss, &fv, ei, &t );
    FD_TEST( t.o.certs_cnt==0UL );
    FD_TEST( t.o.pool_events_cnt==0UL );
    FD_TEST( t.o.block_repairs_cnt==0UL );
  }

  ag_vote_t fv4; ag_vote_new_final( &fv4, slot, &g_sk[4], 4UL , TEST_SHRED_VERSION );
  add_vote_helper( ss, &fv4, ei, &t );
  FD_TEST( t.o.certs_cnt==1UL );
  FD_TEST( t.o.certs[0].kind==AG_CERT_TYPE_FINAL );

  ag_slot_state_add_cert( ss, &t.o.certs[0] );
  ag_vote_t fv5; ag_vote_new_final( &fv5, slot, &g_sk[5], 5UL , TEST_SHRED_VERSION );
  add_vote_helper( ss, &fv5, ei, &t );
  FD_TEST( t.o.certs_cnt==0UL );

  fd_wksp_free_laddr( ss );
  free( em );
}

static void
test_count_notar_fallback_creates_cert_at_quorum( fd_wksp_t * wksp ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash = random_hash();
  ag_slot_state_t * ss = make_state( wksp, slot, ei );
  out_t t;

  for( ulong i=1UL; i<=2UL; i++ ) {
    ag_vote_t nv; ag_vote_new_notar( &nv, slot, &hash, &g_sk[i], (ushort)i , TEST_SHRED_VERSION );
    add_vote_helper( ss, &nv, ei, &t );
    FD_TEST( t.o.certs_cnt==0UL );
  }

  ag_vote_t nf3; ag_vote_new_notar_fallback( &nf3, slot, &hash, &g_sk[3], 3UL , TEST_SHRED_VERSION );
  add_vote_helper( ss, &nf3, ei, &t );
  FD_TEST( t.o.certs_cnt==0UL );
  FD_TEST( t.o.pool_events_cnt==0UL );
  FD_TEST( t.o.block_repairs_cnt==0UL );
  FD_TEST( ag_slot_state_stake( ss->voted_stakes.notar_fallback, ss->voted_stakes.notar_fallback_cnt, &hash )==1UL );

  ag_vote_t nf4; ag_vote_new_notar_fallback( &nf4, slot, &hash, &g_sk[4], 4UL , TEST_SHRED_VERSION );
  add_vote_helper( ss, &nf4, ei, &t );
  FD_TEST( t.o.certs_cnt==1UL );
  FD_TEST( t.o.certs[0].kind==AG_CERT_TYPE_NOTAR_FALLBACK );
  FD_TEST( ag_cert_block_hash( &t.o.certs[0] ) && !memcmp( ag_cert_block_hash( &t.o.certs[0] )->uc, hash.uc, sizeof(fd_hash_t) ) );

  ag_slot_state_add_cert( ss, &t.o.certs[0] );
  ag_vote_t nf5; ag_vote_new_notar_fallback( &nf5, slot, &hash, &g_sk[5], 5UL , TEST_SHRED_VERSION );
  add_vote_helper( ss, &nf5, ei, &t );
  FD_TEST( t.o.certs_cnt==0UL );

  fd_wksp_free_laddr( ss );
  free( em );
}

/* The reference's should_ignore_vote returns an IgnoreReason, and these two
   tests assert on the specific variant.  ag_slot_state_should_ignore_vote
   returns a plain 0/1: the reference only reads the variant to pick which
   debug! line to log -- add_vote's control flow is the same for all three --
   so the ignored-or-not answer is the whole behavioural content, and the
   assertions below drop the reason rather than model it. */

static void
test_skip_skip_fallback_conflict( fd_wksp_t * wksp ) {
  ulong n = 3UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  ag_slot_state_t * ss = make_state( wksp, slot, ei );
  out_t t;
  ulong v = 0UL;

  ag_vote_t skip;          ag_vote_new_skip         ( &skip,          slot, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
  ag_vote_t skip_fallback; ag_vote_new_skip_fallback( &skip_fallback, slot, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );

  /* neither should be ignored before anything is recorded */
  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &skip          ) );
  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &skip_fallback ) );

  /* record the skip vote */
  add_vote_helper( ss, &skip, ei, &t );
  /* should now ignore the skip-fallback vote (as conflict) */
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &skip_fallback ) );
  /* should now ignore the same skip vote (as duplicate) */
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &skip ) );
  /* and the skip-fallback vote should NOT be slashable */
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &skip_fallback )==AG_SLASHABLE_NONE );

  /* the conflict is symmetric */
  ag_slot_state_init( ss, slot, ei, 0UL );
  add_vote_helper( ss, &skip_fallback, ei, &t );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &skip          ) );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &skip_fallback ) );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &skip )==AG_SLASHABLE_NONE );

  fd_wksp_free_laddr( ss );
  free( em );
}

static void
test_notar_notar_fallback_conflict( fd_wksp_t * wksp ) {
  ulong n = 3UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash       = random_hash();
  fd_hash_t other_hash = random_hash();
  ag_slot_state_t * ss = make_state( wksp, slot, ei );
  out_t t;
  ulong v = 0UL;

  ag_vote_t notar;          ag_vote_new_notar         ( &notar,          slot, &hash,       &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
  ag_vote_t notar_fallback; ag_vote_new_notar_fallback( &notar_fallback, slot, &hash,       &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
  ag_vote_t nf_other;       ag_vote_new_notar_fallback( &nf_other,       slot, &other_hash, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );

  /* neither should be ignored before anything is recorded */
  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &notar          ) );
  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &notar_fallback ) );

  /* record the notar vote */
  add_vote_helper( ss, &notar, ei, &t );
  /* should now ignore the notar-fallback vote (as conflict) */
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &notar_fallback ) );
  /* should now ignore the same notar vote (as duplicate) */
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &notar ) );
  /* a notar-fallback for a DIFFERENT block is honest and still counts */
  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &nf_other ) );
  /* and the same-block conflict should NOT be slashable */
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &notar_fallback )==AG_SLASHABLE_NONE );

  /* the conflict is symmetric */
  ag_slot_state_init( ss, slot, ei, 0UL );
  add_vote_helper( ss, &notar_fallback, ei, &t );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &notar          ) );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &notar_fallback ) );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &notar )==AG_SLASHABLE_NONE );

  fd_wksp_free_laddr( ss );
  free( em );
}

/* sorted_vec::set_insert_contains_iter in the reference.  There is no
   sorted_vec module here: the SortedVecSet role is ag_hash_set_t, whose
   set_insert / set_contains / set_remove are private to ag_slot_state.c --
   which is why this file includes the .c rather than the header.

   One divergence the assertions have to respect: SortedVecSet is sorted and
   iterates in order, while ag_hash_set_t is an unordered array whose remove
   swaps the last entry down.  So the survivors are checked by membership,
   not by position. */

static void
test_set_insert_contains_iter( void ) {
  fd_hash_t h1 = random_hash(), h3 = random_hash(), h5 = random_hash(), h2 = random_hash();

  ag_hash_set_t set; set.cnt = 0UL;

  set_insert( &set, &h3 ); FD_TEST( set.cnt==1UL );
  set_insert( &set, &h1 ); FD_TEST( set.cnt==2UL );
  set_insert( &set, &h5 ); FD_TEST( set.cnt==3UL );
  set_insert( &set, &h3 ); FD_TEST( set.cnt==3UL ); /* duplicate */

  FD_TEST(  set_contains( &set, &h1 ) );
  FD_TEST( !set_contains( &set, &h2 ) );

  set_remove( &set, &h1 ); FD_TEST( set.cnt==2UL );
  set_remove( &set, &h1 ); FD_TEST( set.cnt==2UL ); /* already gone */
  FD_TEST( !set_contains( &set, &h1 ) );

  /* h3 and h5 survive, with the removed entry gone */
  FD_TEST( set_contains( &set, &h3 ) );
  FD_TEST( set_contains( &set, &h5 ) );
}

/* The stake tallies are held in descending stake order, so the leading
   entries are the contenders: index 0 for notar (the safe-to-skip check
   reads the top hash's stake) and the leading few for notar-fallback.
   Every validator here has stake 1, so an entry's stake is its vote count
   and the order is exercised by voting the hashes unevenly. */

static void
assert_tally( ag_hashstake_t const * ele,
              ulong                  cnt,
              fd_hash_t const *      hash,
              ulong const *          stake,
              ulong                  expected_cnt ) {
  FD_TEST( cnt==expected_cnt );
  for( ulong i=0UL; i<cnt; i++ ) {
    FD_TEST( !memcmp( ele[i].hash.uc, hash[i].uc, sizeof(fd_hash_t) ) );
    FD_TEST( ele[i].stake==stake[i] );
    if( i ) FD_TEST( ele[i-1].stake>=ele[i].stake );
  }
}

static void
test_notar_stake_order( fd_wksp_t * wksp ) {
  ulong n = 12UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  ag_slot_state_t * ss = make_state( wksp, slot, ei );
  out_t t;

  fd_hash_t a = random_hash(), b = random_hash(), c = random_hash(), d = random_hash();
  ag_hashstake_t const * tally = ss->voted_stakes.notar;

  /* One notar vote per rank, so a hash grows only by picking up new
     ranks.  a leads on the first vote. */
  ulong rank = 0UL;
  ag_vote_t v;
  ag_vote_new_notar( &v, slot, &a, &g_sk[rank], (ushort)rank, TEST_SHRED_VERSION ); rank++;
  add_vote_helper( ss, &v, ei, &t );
  assert_tally( tally, ss->voted_stakes.notar_cnt, (fd_hash_t[]){ a }, (ulong[]){ 1UL }, 1UL );

  /* A tie does not displace the incumbent: b matches a but does not beat
     it, so a keeps index 0. */
  ag_vote_new_notar( &v, slot, &b, &g_sk[rank], (ushort)rank, TEST_SHRED_VERSION ); rank++;
  add_vote_helper( ss, &v, ei, &t );
  assert_tally( tally, ss->voted_stakes.notar_cnt, (fd_hash_t[]){ a, b }, (ulong[]){ 1UL, 1UL }, 2UL );

  /* Now b outweighs a and sifts past it. */
  ag_vote_new_notar( &v, slot, &b, &g_sk[rank], (ushort)rank, TEST_SHRED_VERSION ); rank++;
  add_vote_helper( ss, &v, ei, &t );
  assert_tally( tally, ss->voted_stakes.notar_cnt, (fd_hash_t[]){ b, a }, (ulong[]){ 2UL, 1UL }, 2UL );

  /* c arrives last and climbs the whole tally, one rank at a time. */
  for( ulong i=0UL; i<3UL; i++ ) {
    ag_vote_new_notar( &v, slot, &c, &g_sk[rank], (ushort)rank, TEST_SHRED_VERSION ); rank++;
    add_vote_helper( ss, &v, ei, &t );
  }
  assert_tally( tally, ss->voted_stakes.notar_cnt, (fd_hash_t[]){ c, b, a }, (ulong[]){ 3UL, 2UL, 1UL }, 3UL );

  /* d takes the lead, leaving a full descending tally: the top-1 the
     notar tally is read for, and the ordered tail behind it. */
  for( ulong i=0UL; i<4UL; i++ ) {
    ag_vote_new_notar( &v, slot, &d, &g_sk[rank], (ushort)rank, TEST_SHRED_VERSION ); rank++;
    add_vote_helper( ss, &v, ei, &t );
  }
  FD_TEST( rank<=n );
  assert_tally( tally, ss->voted_stakes.notar_cnt, (fd_hash_t[]){ d, c, b, a }, (ulong[]){ 4UL, 3UL, 2UL, 1UL }, 4UL );

  fd_wksp_free_laddr( ss );
  free( em );
}

/* The notar-fallback tally takes an entry per distinct hash voted for, and
   a rank may cast AG_NOTAR_FALLBACK_VOTE_MAX of those votes -- which is
   why AG_NOTAR_FALLBACK_STAKE_MAX is that many times AG_VAT_MAX and not
   any bound on how many block hashes a slot can legitimately have. */

static void
test_notar_fallback_stake_order( fd_wksp_t * wksp ) {
  ulong n = 12UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  ag_slot_state_t * ss = make_state( wksp, slot, ei );
  out_t t;

  /* A single rank naming a distinct hash in each of its votes costs the
     tally one entry apiece. */
  fd_hash_t own[ AG_NOTAR_FALLBACK_VOTE_MAX ];
  for( ulong i=0UL; i<AG_NOTAR_FALLBACK_VOTE_MAX; i++ ) {
    own[i] = random_hash();
    ag_vote_t v; ag_vote_new_notar_fallback( &v, slot, &own[i], &g_sk[0], 0UL, TEST_SHRED_VERSION );
    FD_TEST( ag_slot_state_vote_fits( ss, &v ) );
    add_vote_helper( ss, &v, ei, &t );
    FD_TEST( ss->voted_stakes.notar_fallback_cnt==i+1UL );
  }

  /* And its next one does not fit -- the per-rank cap, not the tally, is
     what turns a vote away. */
  fd_hash_t past = random_hash();
  ag_vote_t v_past; ag_vote_new_notar_fallback( &v_past, slot, &past, &g_sk[0], 0UL, TEST_SHRED_VERSION );
  FD_TEST( !ag_slot_state_vote_fits( ss, &v_past ) );

  /* Rank 1 lifts the last of rank 0's hashes to the front, and rank 2
     lifts the middle one to second, so the tally reorders under votes
     from a rank that has cast none of the leaders before. */
  for( ulong i=0UL; i<2UL; i++ ) {
    ag_vote_t v; ag_vote_new_notar_fallback( &v, slot, &own[2], &g_sk[1UL+i], (ushort)(1UL+i), TEST_SHRED_VERSION );
    add_vote_helper( ss, &v, ei, &t );
  }
  ag_vote_t v_mid; ag_vote_new_notar_fallback( &v_mid, slot, &own[1], &g_sk[3], 3UL, TEST_SHRED_VERSION );
  add_vote_helper( ss, &v_mid, ei, &t );

  assert_tally( ss->voted_stakes.notar_fallback, ss->voted_stakes.notar_fallback_cnt,
                (fd_hash_t[]){ own[2], own[1], own[0] }, (ulong[]){ 3UL, 2UL, 1UL }, 3UL );

  fd_wksp_free_laddr( ss );
  free( em );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong       page_cnt = 8192UL; /* a slot state is ~3 MiB now that votes are retained per validator */
  char *      page_sz  = "normal";
  ulong       numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp     = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( page_sz ),
                                                page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  /* slot_state.rs, in its order */
  test_add_cert                                   ( wksp );
  test_add_vote                                   ( wksp );
  test_safe_to_notar                              ( wksp );
  test_slashable_skip_and_notarize                ( wksp );
  test_slashable_notar_different_hash             ( wksp );
  test_slashable_skip_and_finalize                ( wksp );
  test_slashable_notar_fallback_and_finalize      ( wksp );
  test_slashable_offence_none                     ( wksp );
  test_should_ignore_duplicate_votes              ( wksp );
  test_count_finalize_creates_cert_at_quorum      ( wksp );
  test_count_notar_fallback_creates_cert_at_quorum( wksp );
  test_skip_skip_fallback_conflict                ( wksp );
  test_notar_notar_fallback_conflict              ( wksp );

  /* sorted_vec.rs, whose set role lives in this module here */
  test_set_insert_contains_iter                   ();

  /* no reference counterpart */
  test_notar_stake_order                          ( wksp );
  test_notar_fallback_stake_order                 ( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
