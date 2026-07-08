#include "ag_slot_state.h"

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
  void * mem = aligned_alloc( ag_epoch_info_align(), ag_epoch_info_footprint( n ) );
  FD_TEST( mem );
  *out_mem = mem;
  return ag_epoch_info_join( ag_epoch_info_new( mem, g_info, n ) );
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

static ag_slot_state_t *
make_state( fd_wksp_t *             wksp,
            ulong                   slot,
            ulong                   validator_max,
            ag_epoch_info_t const * ei,
            void **                 out_mem ) {
  void * mem = fd_wksp_alloc_laddr( wksp, ag_slot_state_align(), ag_slot_state_footprint( validator_max ), 1UL );
  FD_TEST( mem );
  *out_mem = mem;
  return ag_slot_state_join( ag_slot_state_new( mem, slot, 0UL, validator_max, 42UL, ei ) );
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
  void * sm; ag_slot_state_t * ss = make_state( wksp, slot, MAXV, ei, &sm );

  ag_notar_vote_t nv[ 11 ];
  for( ulong i=0UL; i<n; i++ ) ag_notar_vote_new( &nv[i], slot, &hash, &g_sk[i], (ushort)i );
  ag_cert_t c; c.kind = AG_CERT_TYPE_NOTAR;
  FD_TEST( ag_notar_cert_try_new( &c.inner.notar, nv, n,
                                  ag_epoch_info_validators( ei ), ei->validator_cnt )==AG_CERT_SUCCESS );

  FD_TEST( !ag_slot_state_has_notar_cert( ss ) );
  ag_slot_state_add_cert( ss, &c );
  FD_TEST(  ag_slot_state_has_notar_cert( ss ) );

  fd_wksp_free_laddr( ag_slot_state_delete( ag_slot_state_leave( ss ) ) );
  free( em );
}

static void
test_add_vote( fd_wksp_t * wksp ) {
  ulong n = 11UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash = random_hash();
  void * sm; ag_slot_state_t * ss = make_state( wksp, slot, MAXV, ei, &sm );
  out_t t;

  for( ulong i=0UL; i<n; i++ ) {
    ag_vote_t vote; ag_vote_new_notar( &vote, slot, &hash, &g_sk[i], (ushort)i );
    FD_TEST( !ag_slot_state_has_notar_vote( ss, i ) );
    add_vote_helper( ss, &vote, ei, &t );
    FD_TEST(  ag_slot_state_has_notar_vote( ss, i ) );
    FD_TEST(  ag_slot_state_notar_stake( ss, &hash )==i+1UL );
  }

  fd_wksp_free_laddr( ag_slot_state_delete( ag_slot_state_leave( ss ) ) );
  free( em );
}

static void
test_safe_to_notar( fd_wksp_t * wksp ) {
  ulong n = 3UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash = random_hash();
  void * sm; ag_slot_state_t * ss = make_state( wksp, slot, MAXV, ei, &sm );
  out_t t;

  ag_slot_state_notify_parent_known( ss, &hash );
  ag_slot_state_notify_parent_certified( ss, &hash );

  ag_vote_t notar_vote; ag_vote_new_notar( &notar_vote, slot, &hash, &g_sk[1], 1UL );
  add_vote_helper( ss, &notar_vote, ei, &t );
  FD_TEST( t.o.certs_cnt==0UL );
  FD_TEST( t.o.pool_events_cnt==0UL );
  FD_TEST( t.o.block_repairs_cnt==0UL );

  ag_vote_t skip_vote; ag_vote_new_skip( &skip_vote, slot, &g_sk[0], 0UL );
  add_vote_helper( ss, &skip_vote, ei, &t );
  FD_TEST( t.o.certs_cnt==0UL );
  FD_TEST( t.o.pool_events_cnt==1UL );
  FD_TEST( t.o.block_repairs_cnt==0UL );
  FD_TEST( t.o.pool_events[0].kind==AG_POOL_EVENT_SAFE_TO_NOTAR );
  FD_TEST( t.o.pool_events[0].inner.safe_to_notar.slot==slot );
  FD_TEST( !memcmp( t.o.pool_events[0].inner.safe_to_notar.hash.uc, hash.uc, sizeof(fd_hash_t) ) );

  fd_wksp_free_laddr( ag_slot_state_delete( ag_slot_state_leave( ss ) ) );
  free( em );
}

static void
test_slashable_skip_and_notarize( fd_wksp_t * wksp ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash = random_hash();
  void * sm; ag_slot_state_t * ss = make_state( wksp, slot, MAXV, ei, &sm );
  out_t t;

  ag_vote_t s1; ag_vote_new_skip( &s1, slot, &g_sk[1], 1UL );
  add_vote_helper( ss, &s1, ei, &t );
  ag_vote_t notar_vote; ag_vote_new_notar( &notar_vote, slot, &hash, &g_sk[1], 1UL );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &notar_vote )==AG_SLASHABLE_SKIP_AND_NOTARIZE );

  ag_vote_t n2; ag_vote_new_notar( &n2, slot, &hash, &g_sk[2], 2UL );
  add_vote_helper( ss, &n2, ei, &t );
  ag_vote_t skip_vote; ag_vote_new_skip( &skip_vote, slot, &g_sk[2], 2UL );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &skip_vote )==AG_SLASHABLE_SKIP_AND_NOTARIZE );

  fd_wksp_free_laddr( ag_slot_state_delete( ag_slot_state_leave( ss ) ) );
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
  void * sm; ag_slot_state_t * ss = make_state( wksp, slot, MAXV, ei, &sm );
  out_t t;

  ag_vote_t notar_a; ag_vote_new_notar( &notar_a, slot, &hash_a, &g_sk[1], 1UL );
  add_vote_helper( ss, &notar_a, ei, &t );

  ag_vote_t notar_b; ag_vote_new_notar( &notar_b, slot, &hash_b, &g_sk[1], 1UL );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &notar_b )==AG_SLASHABLE_NOTAR_DIFFERENT_HASH );

  FD_TEST( ag_slot_state_check_slashable_offence( ss, &notar_a )==AG_SLASHABLE_NONE );

  fd_wksp_free_laddr( ag_slot_state_delete( ag_slot_state_leave( ss ) ) );
  free( em );
}

static void
test_slashable_skip_and_finalize( fd_wksp_t * wksp ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  void * sm; ag_slot_state_t * ss = make_state( wksp, slot, MAXV, ei, &sm );
  out_t t;

  ag_vote_t f1; ag_vote_new_final( &f1, slot, &g_sk[1], 1UL );
  add_vote_helper( ss, &f1, ei, &t );
  ag_vote_t s1; ag_vote_new_skip( &s1, slot, &g_sk[1], 1UL );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &s1 )==AG_SLASHABLE_SKIP_AND_FINALIZE );
  ag_vote_t sf1; ag_vote_new_skip_fallback( &sf1, slot, &g_sk[1], 1UL );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &sf1 )==AG_SLASHABLE_SKIP_AND_FINALIZE );

  ag_vote_t s2; ag_vote_new_skip( &s2, slot, &g_sk[2], 2UL );
  add_vote_helper( ss, &s2, ei, &t );
  ag_vote_t f2; ag_vote_new_final( &f2, slot, &g_sk[2], 2UL );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &f2 )==AG_SLASHABLE_SKIP_AND_FINALIZE );

  ag_vote_t sf3; ag_vote_new_skip_fallback( &sf3, slot, &g_sk[3], 3UL );
  add_vote_helper( ss, &sf3, ei, &t );
  ag_vote_t f3; ag_vote_new_final( &f3, slot, &g_sk[3], 3UL );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &f3 )==AG_SLASHABLE_SKIP_AND_FINALIZE );

  fd_wksp_free_laddr( ag_slot_state_delete( ag_slot_state_leave( ss ) ) );
  free( em );
}

static void
test_slashable_notar_fallback_and_finalize( fd_wksp_t * wksp ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash = random_hash();
  void * sm; ag_slot_state_t * ss = make_state( wksp, slot, MAXV, ei, &sm );
  out_t t;

  ag_vote_t f1; ag_vote_new_final( &f1, slot, &g_sk[1], 1UL );
  add_vote_helper( ss, &f1, ei, &t );
  ag_vote_t nf1; ag_vote_new_notar_fallback( &nf1, slot, &hash, &g_sk[1], 1UL );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &nf1 )==AG_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE );

  ag_vote_t nf2; ag_vote_new_notar_fallback( &nf2, slot, &hash, &g_sk[2], 2UL );
  add_vote_helper( ss, &nf2, ei, &t );
  ag_vote_t f2; ag_vote_new_final( &f2, slot, &g_sk[2], 2UL );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &f2 )==AG_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE );

  fd_wksp_free_laddr( ag_slot_state_delete( ag_slot_state_leave( ss ) ) );
  free( em );
}

static void
test_slashable_offence_none( fd_wksp_t * wksp ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash = random_hash();
  void * sm; ag_slot_state_t * ss = make_state( wksp, slot, MAXV, ei, &sm );
  out_t t;
  ulong v = 1UL;

  ag_vote_t notar_vote; ag_vote_new_notar( &notar_vote, slot, &hash, &g_sk[1], (ushort)v );
  ag_vote_t skip_vote;  ag_vote_new_skip ( &skip_vote,  slot,        &g_sk[1], (ushort)v );
  ag_vote_t final_vote; ag_vote_new_final( &final_vote, slot,        &g_sk[1], (ushort)v );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &notar_vote )==AG_SLASHABLE_NONE );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &skip_vote )==AG_SLASHABLE_NONE );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &final_vote )==AG_SLASHABLE_NONE );

  add_vote_helper( ss, &notar_vote, ei, &t );
  FD_TEST( ag_slot_state_check_slashable_offence( ss, &final_vote )==AG_SLASHABLE_NONE );

  fd_wksp_free_laddr( ag_slot_state_delete( ag_slot_state_leave( ss ) ) );
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
  void * sm; ag_slot_state_t * ss = make_state( wksp, slot, MAXV, ei, &sm );
  out_t t;

  ag_vote_t v1n; ag_vote_new_notar( &v1n, slot, &hash, &g_sk[1], 1UL );
  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &v1n ) );

  add_vote_helper( ss, &v1n, ei, &t );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &v1n ) );
  ag_vote_t v1n_other; ag_vote_new_notar( &v1n_other, slot, &other_hash, &g_sk[1], 1UL );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &v1n_other ) );

  ag_vote_t v2s; ag_vote_new_skip( &v2s, slot, &g_sk[2], 2UL );
  add_vote_helper( ss, &v2s, ei, &t );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &v2s ) );
  ag_vote_t v2sf; ag_vote_new_skip_fallback( &v2sf, slot, &g_sk[2], 2UL );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &v2sf ) );

  ag_vote_t v3f; ag_vote_new_final( &v3f, slot, &g_sk[3], 3UL );
  add_vote_helper( ss, &v3f, ei, &t );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &v3f ) );

  ag_vote_t v4nf; ag_vote_new_notar_fallback( &v4nf, slot, &hash, &g_sk[4], 4UL );
  add_vote_helper( ss, &v4nf, ei, &t );
  FD_TEST( ag_slot_state_should_ignore_vote( ss, &v4nf ) );
  ag_vote_t v4nf_other; ag_vote_new_notar_fallback( &v4nf_other, slot, &other_hash, &g_sk[4], 4UL );
  FD_TEST( !ag_slot_state_should_ignore_vote( ss, &v4nf_other ) );

  fd_wksp_free_laddr( ag_slot_state_delete( ag_slot_state_leave( ss ) ) );
  free( em );
}

static void
test_count_finalize_creates_cert_at_quorum( fd_wksp_t * wksp ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  void * sm; ag_slot_state_t * ss = make_state( wksp, slot, MAXV, ei, &sm );
  out_t t;

  for( ulong i=1UL; i<=3UL; i++ ) {
    ag_vote_t fv; ag_vote_new_final( &fv, slot, &g_sk[i], (ushort)i );
    add_vote_helper( ss, &fv, ei, &t );
    FD_TEST( t.o.certs_cnt==0UL );
    FD_TEST( t.o.pool_events_cnt==0UL );
    FD_TEST( t.o.block_repairs_cnt==0UL );
  }

  ag_vote_t fv4; ag_vote_new_final( &fv4, slot, &g_sk[4], 4UL );
  add_vote_helper( ss, &fv4, ei, &t );
  FD_TEST( t.o.certs_cnt==1UL );
  FD_TEST( t.o.certs[0].kind==AG_CERT_TYPE_FINAL );

  ag_slot_state_add_cert( ss, &t.o.certs[0] );
  ag_vote_t fv5; ag_vote_new_final( &fv5, slot, &g_sk[5], 5UL );
  add_vote_helper( ss, &fv5, ei, &t );
  FD_TEST( t.o.certs_cnt==0UL );

  fd_wksp_free_laddr( ag_slot_state_delete( ag_slot_state_leave( ss ) ) );
  free( em );
}

static void
test_count_notar_fallback_creates_cert_at_quorum( fd_wksp_t * wksp ) {
  ulong n = 6UL;
  generate_validators( n );
  void * em; ag_epoch_info_t * ei = make_epoch( n, &em );
  ulong slot = 1UL;
  fd_hash_t hash = random_hash();
  void * sm; ag_slot_state_t * ss = make_state( wksp, slot, MAXV, ei, &sm );
  out_t t;

  for( ulong i=1UL; i<=2UL; i++ ) {
    ag_vote_t nv; ag_vote_new_notar( &nv, slot, &hash, &g_sk[i], (ushort)i );
    add_vote_helper( ss, &nv, ei, &t );
    FD_TEST( t.o.certs_cnt==0UL );
  }

  ag_vote_t nf3; ag_vote_new_notar_fallback( &nf3, slot, &hash, &g_sk[3], 3UL );
  add_vote_helper( ss, &nf3, ei, &t );
  FD_TEST( t.o.certs_cnt==0UL );
  FD_TEST( t.o.pool_events_cnt==0UL );
  FD_TEST( t.o.block_repairs_cnt==0UL );
  FD_TEST( ag_slot_state_notar_fallback_stake( ss, &hash )==1UL );

  ag_vote_t nf4; ag_vote_new_notar_fallback( &nf4, slot, &hash, &g_sk[4], 4UL );
  add_vote_helper( ss, &nf4, ei, &t );
  FD_TEST( t.o.certs_cnt==1UL );
  FD_TEST( t.o.certs[0].kind==AG_CERT_TYPE_NOTAR_FALLBACK );
  FD_TEST( ag_cert_block_hash( &t.o.certs[0] ) && !memcmp( ag_cert_block_hash( &t.o.certs[0] )->uc, hash.uc, sizeof(fd_hash_t) ) );

  ag_slot_state_add_cert( ss, &t.o.certs[0] );
  ag_vote_t nf5; ag_vote_new_notar_fallback( &nf5, slot, &hash, &g_sk[5], 5UL );
  add_vote_helper( ss, &nf5, ei, &t );
  FD_TEST( t.o.certs_cnt==0UL );

  fd_wksp_free_laddr( ag_slot_state_delete( ag_slot_state_leave( ss ) ) );
  free( em );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong       page_cnt = 512UL;
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
