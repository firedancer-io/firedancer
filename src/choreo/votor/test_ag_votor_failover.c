#include "ag_votor.c"
#include "test_ag_cert_builder.h"

#define NV                 (2UL)
#define TEST_SLOT_MAX      (16UL)
#define TEST_SHRED_VERSION ((ushort)0x5a5a)

#define TEST_NS_PER_SLOT       (400000000L)

#define FD_TEST_NO_MSG( votor ) do {           \
    ag_vote_t unused_;                         \
    FD_TEST( !try_recv( (votor), &unused_ ) ); \
  } while( 0 )

#define SCRATCH_MAX (1UL<<23)

static uchar scratch_a[ SCRATCH_MAX ] __attribute__((aligned(128)));
static uchar scratch_b[ SCRATCH_MAX ] __attribute__((aligned(128)));

static fd_bls_sec_t g_sk[ NV ];
static ulong        g_hash_ctr = 0UL;

static void
genesis_hash( ag_block_hash_t out ) {
  fd_memset( out, 0, sizeof(ag_block_hash_t) );
}

static void
random_hash( ag_block_hash_t out ) {
  fd_memset( out, 0, sizeof(ag_block_hash_t) );
  FD_STORE( ulong, out,     0x9000UL + (++g_hash_ctr) );
  FD_STORE( ulong, out+8UL, 0xc0ffee00UL ^ g_hash_ctr );
}

static ag_block_id_t
genesis_block_id( void ) {
  ag_block_id_t b; b.slot = 0UL; genesis_hash( b.hash );
  return b;
}

static void
create_validators( void ) {
  for( ulong i=0UL; i<NV; i++ ) fd_memset( &g_sk[i], (int)(i*7UL+1UL), FD_BLS_SEC_SZ );
}

static int
try_recv( ag_votor_t * votor,
          ag_vote_t *  out ) {
  uchar reason;
  return ag_votor_poll_vote( votor, out, &reason );
}

static ag_vote_t
recv( ag_votor_t * votor ) {
  ag_vote_t vote;
  FD_TEST( try_recv( votor, &vote ) );
  return vote;
}

static ag_votor_t *
setup_votor( void * mem,
             long   now ) {
  create_validators();
  FD_TEST( ag_votor_footprint( TEST_SLOT_MAX )<=SCRATCH_MAX );
  ag_votor_t * votor = ag_votor_join( ag_votor_new( mem, TEST_SLOT_MAX, 42UL ) );
  FD_TEST( votor );
  ag_bls_key_t bls_key; bls_key_from_sec( bls_key, &g_sk[0] );
  ag_block_id_t root = genesis_block_id();
  ag_votor_init         ( votor, &root, now, TEST_NS_PER_SLOT, TEST_SHRED_VERSION, sec_sign_fn, &g_sk[0] );
  ag_votor_advance_epoch( votor, TEST_NS_PER_SLOT, 0UL, 0UL, bls_key );
  return votor;
}

static void
teardown_votor( ag_votor_t * votor ) {
  ag_votor_delete( ag_votor_leave( votor ) );
}

static ag_vote_t
send_block_and_expect_notar( ag_votor_t *          votor,
                             ulong                 slot,
                             ag_block_id_t const * parent ) {
  ag_block_info_t block = {0};
  random_hash( block.hash );
  block.parent = *parent;
  ag_votor_process_replay( votor, slot, &block );

  ag_vote_t msg = recv( votor );
  FD_TEST( msg.kind==AG_VOTE_KIND_NOTAR );
  FD_TEST( ag_vote_slot( &msg )==slot );
  return msg;
}

static void
expect_rec( ag_hist_t const * hist,
            ulong             idx,
            ulong             slot,
            uint              flags,
            uchar const *     notar_hash ) {
  FD_TEST( idx<hist->rec_cnt );
  ag_hist_rec_t const * rec = &hist->rec[ idx ];
  FD_TEST( rec->slot ==slot         );
  FD_TEST( rec->flags==(uchar)flags );
  if( notar_hash ) FD_TEST( fd_memeq( rec->notar_hash, notar_hash, sizeof(ag_block_hash_t) ) );
}

static void
round_trip( ag_hist_t const * hist ) {
  uchar buf[ AG_HIST_SER_MAX ];
  ulong sz = 0UL;
  FD_TEST( !ag_hist_ser( hist, buf, sizeof(buf), &sz ) );

  ag_hist_t out; fd_memset( &out, 0xAA, sizeof(ag_hist_t) );
  FD_TEST( !ag_hist_de( buf, sz, &out ) );
  FD_TEST( out.anchor          ==hist->anchor           );
  FD_TEST( out.last_leader_slot==hist->last_leader_slot );
  FD_TEST( out.vote_bound      ==hist->vote_bound       );
  FD_TEST( out.rec_cnt         ==hist->rec_cnt          );
  for( ulong i=0UL; i<hist->rec_cnt; i++ ) {
    FD_TEST( out.rec[ i ].slot ==hist->rec[ i ].slot  );
    FD_TEST( out.rec[ i ].flags==hist->rec[ i ].flags );
    if( hist->rec[ i ].flags & AG_HIST_FLAG_VOTED_NOTAR ) FD_TEST( fd_memeq( out.rec[ i ].notar_hash, hist->rec[ i ].notar_hash, sizeof(ag_block_hash_t) ) );
  }
}

static void
test_export_shape( void ) {
  ag_votor_t *  votor  = setup_votor( scratch_a, 0L );
  ag_block_id_t parent = genesis_block_id();

  ag_block_hash_t hash[ 4 ];
  genesis_hash( hash[ 0 ] );
  for( ulong s=1UL; s<=3UL; s++ ) {
    ag_vote_t vote = send_block_and_expect_notar( votor, s, &parent );
    fd_memcpy( hash[ s ], vote.notar.block_hash, sizeof(ag_block_hash_t) );
    parent = ag_block_id( s, hash[ s ] );
  }
  FD_TEST_NO_MSG( votor );

  ag_hist_t hist;
  FD_TEST( !ag_votor_hist_export( votor, 42UL, &hist ) );
  FD_TEST( hist.anchor          ==0UL  );
  FD_TEST( hist.last_leader_slot==42UL );
  FD_TEST( hist.vote_bound      ==ULONG_MAX );
  FD_TEST( hist.rec_cnt         ==4UL  );
  expect_rec( &hist, 0UL, 0UL, AG_HIST_FLAG_VOTED|AG_HIST_FLAG_VOTED_NOTAR|AG_HIST_FLAG_RETIRED, hash[ 0 ] );
  for( ulong s=1UL; s<=3UL; s++ ) expect_rec( &hist, s, s, AG_HIST_FLAG_VOTED|AG_HIST_FLAG_VOTED_NOTAR, hash[ s ] );
  round_trip( &hist );

  teardown_votor( votor );
  FD_LOG_NOTICE(( "pass: export_shape" ));
}

static void
test_mark_unsent_notar( void ) {
  ag_votor_t *  votor  = setup_votor( scratch_a, 0L );
  ag_block_id_t parent = genesis_block_id();

  ag_vote_t notar = send_block_and_expect_notar( votor, 1UL, &parent );
  ag_block_hash_t h1; fd_memcpy( h1, notar.notar.block_hash, sizeof(ag_block_hash_t) );
  FD_TEST_NO_MSG( votor );

  /* A discarded notar must not appear as sent or become a parent. */
  ag_votor_mark_unsent( votor, &notar );

  ag_block_hash_t zero; fd_memset( zero, 0, sizeof(ag_block_hash_t) );
  ag_hist_t hist;
  FD_TEST( !ag_votor_hist_export( votor, 42UL, &hist ) );
  expect_rec( &hist, 1UL, 1UL, AG_HIST_FLAG_VOTED|AG_HIST_FLAG_BAD_WINDOW, zero );

  ag_block_info_t block = {0};
  random_hash( block.hash );
  block.parent = ag_block_id( 1UL, h1 );
  ag_votor_process_replay( votor, 2UL, &block );
  FD_TEST_NO_MSG( votor );

  teardown_votor( votor );

  FD_LOG_NOTICE(( "pass: mark_unsent_notar" ));
}

/* The bound a votor holds goes out with its history, and the adopter
   casts nothing at or below it even where the adopted records would
   allow a vote. */

static void
test_bound_travels( void ) {
  ag_votor_t *  a      = setup_votor( scratch_a, 0L );
  ag_block_id_t parent = genesis_block_id();
  ag_vote_t     notar  = send_block_and_expect_notar( a, 1UL, &parent );
  ag_block_id_t tip    = ag_block_id( 1UL, notar.notar.block_hash );
  FD_TEST_NO_MSG( a );

  ag_hist_t plain;
  FD_TEST( !ag_votor_hist_export( a, ULONG_MAX, &plain ) );
  FD_TEST( plain.vote_bound==ULONG_MAX );
  ag_votor_set_vote_bound( a, 5UL );
  ag_hist_t bounded;
  FD_TEST( !ag_votor_hist_export( a, ULONG_MAX, &bounded ) );
  FD_TEST( bounded.vote_bound==5UL );
  round_trip( &bounded );
  teardown_votor( a );

  /* Without a bound the adopted notar on slot 1 lets slot 2 vote. */
  ag_votor_t * b = setup_votor( scratch_b, 0L );
  FD_TEST( !ag_votor_hist_adopt( b, &plain ) );
  FD_TEST( ag_votor_vote_bound( b )==ULONG_MAX );
  send_block_and_expect_notar( b, 2UL, &tip );
  teardown_votor( b );

  b = setup_votor( scratch_b, 0L );
  FD_TEST( !ag_votor_hist_adopt( b, &bounded ) );
  FD_TEST( ag_votor_vote_bound( b )==5UL );
  ag_block_info_t block = {0};
  random_hash( block.hash );
  block.parent = tip;
  ag_votor_process_replay( b, 2UL, &block );
  FD_TEST_NO_MSG( b );

  /* A lower bound from a later history never lowers ours. */
  bounded.vote_bound = 3UL;
  ag_votor_hist_adopt( b, &bounded );
  FD_TEST( ag_votor_vote_bound( b )==5UL );
  teardown_votor( b );

  FD_LOG_NOTICE(( "pass: bound_travels" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_export_shape();
  test_mark_unsent_notar();
  test_bound_travels();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
