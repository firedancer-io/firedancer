#include "fd_epoch_stakes_digest.h"
#include "../runtime/fd_runtime_const.h"
#include "../../ballet/sha256/fd_sha256.h"

#include <stdlib.h>

static fd_pubkey_t
key( ulong x ) {
  return (fd_pubkey_t){ .ul = { x } };
}

/* Independently rebuild the canonical byte stream and hash it.  This
   is deliberately not written in terms of fd_epoch_stakes_digest's
   helpers so that a layout or ordering bug in the emitter shows up as
   a mismatch rather than being mirrored by the check. */

static void
reference_digest( fd_vote_stake_weight_t const * entries, /* already in vote key order */
                  ulong                          entry_cnt,
                  ulong                          epoch,
                  fd_hash_t *                    hash_out ) {
  uchar * buf = malloc( 16UL + entry_cnt*72UL );
  FD_TEST( buf );
  uchar * p = buf;

# define PUT_ULONG(v) do { FD_STORE( ulong, p, (v) ); p += 8UL; } while(0)
# define PUT_KEY(k)   do { fd_memcpy( p, (k).uc, 32UL ); p += 32UL; } while(0)
  PUT_ULONG( epoch     );
  PUT_ULONG( entry_cnt );
  for( ulong i=0UL; i<entry_cnt; i++ ) {
    PUT_KEY  ( entries[i].vote_key );
    PUT_KEY  ( entries[i].id_key   );
    PUT_ULONG( entries[i].stake    );
  }
# undef PUT_KEY
# undef PUT_ULONG

  FD_TEST( (ulong)(p-buf)==16UL + entry_cnt*72UL );
  fd_sha256_hash( buf, (ulong)(p-buf), hash_out->hash );
  free( buf );
}

/* A three element set, listed in canonical (vote key ascending) order. */

static ulong const N = 3UL;

static void
canonical_set( fd_vote_stake_weight_t out[ 3 ] ) {
  out[0] = (fd_vote_stake_weight_t){ .vote_key = key( 1UL ), .id_key = key( 11UL ), .stake = 100UL };
  out[1] = (fd_vote_stake_weight_t){ .vote_key = key( 2UL ), .id_key = key( 12UL ), .stake = 300UL };
  out[2] = (fd_vote_stake_weight_t){ .vote_key = key( 3UL ), .id_key = key( 13UL ), .stake = 200UL };
}

static void
test_matches_reference( void ) {
  FD_LOG_NOTICE(( "test_matches_reference" ));

  fd_vote_stake_weight_t canon[ 3 ];
  canonical_set( canon );

  fd_hash_t expected[1];
  reference_digest( canon, N, 7UL, expected );

  fd_vote_stake_weight_t work[ 3 ];
  canonical_set( work );
  fd_hash_t got[1];
  fd_epoch_stakes_digest( work, N, 7UL, got );

  FD_TEST( !memcmp( got, expected, sizeof(fd_hash_t) ) );
}

/* The gather order must not matter: the digest sorts into canonical
   order itself.  This is the property that actually protects us, since
   the fd_vote_stakes maps iterate in a seed dependent order. */

static void
test_order_independent( void ) {
  FD_LOG_NOTICE(( "test_order_independent" ));

  fd_vote_stake_weight_t canon[ 3 ];
  canonical_set( canon );
  fd_hash_t expected[1];
  fd_epoch_stakes_digest( canon, N, 7UL, expected );

  /* All 6 permutations of the 3 entries. */
  static ulong const perms[6][3] = {
    {0,1,2},{0,2,1},{1,0,2},{1,2,0},{2,0,1},{2,1,0}
  };
  for( ulong p=0UL; p<6UL; p++ ) {
    fd_vote_stake_weight_t src[ 3 ];
    canonical_set( src );
    fd_vote_stake_weight_t shuffled[ 3 ];
    for( ulong i=0UL; i<N; i++ ) shuffled[ i ] = src[ perms[p][i] ];

    fd_hash_t got[1];
    fd_epoch_stakes_digest( shuffled, N, 7UL, got );
    FD_TEST( !memcmp( got, expected, sizeof(fd_hash_t) ) );
  }
}

/* Every hashed field must actually change the digest, otherwise the
   commitment does not cover it. */

static void
test_every_field_covered( void ) {
  FD_LOG_NOTICE(( "test_every_field_covered" ));

  fd_vote_stake_weight_t base[ 3 ];
  canonical_set( base );
  fd_hash_t expected[1];
  fd_epoch_stakes_digest( base, N, 7UL, expected );

# define EXPECT_DIFFERS(setup) do {                                  \
    fd_vote_stake_weight_t e[ 3 ];                                   \
    canonical_set( e );                                              \
    ulong  epoch = 7UL;                                              \
    ulong  cnt   = N;                                                \
    setup;                                                           \
    fd_hash_t got[1];                                                \
    fd_epoch_stakes_digest( e, cnt, epoch, got );                    \
    FD_TEST( memcmp( got, expected, sizeof(fd_hash_t) ) );           \
  } while(0)

  EXPECT_DIFFERS( epoch = 8UL                );
  EXPECT_DIFFERS( cnt   = 2UL                );
  EXPECT_DIFFERS( e[1].stake    = 301UL      );
  EXPECT_DIFFERS( e[1].vote_key = key( 99UL ) );
  EXPECT_DIFFERS( e[1].id_key   = key( 99UL ) );

# undef EXPECT_DIFFERS
}

/* An empty set must still be a well defined commitment, and must not
   collide with a different epoch's empty set. */

static void
test_empty( void ) {
  FD_LOG_NOTICE(( "test_empty" ));

  fd_hash_t zero[1]; memset( zero, 0, sizeof(fd_hash_t) );

  fd_hash_t e7[1], e8[1], ref[1];
  fd_epoch_stakes_digest( NULL, 0UL, 7UL, e7 );
  fd_epoch_stakes_digest( NULL, 0UL, 8UL, e8 );
  reference_digest( NULL, 0UL, 7UL, ref );

  FD_TEST( memcmp( e7, zero, sizeof(fd_hash_t) ) ); /* not the zero hash */
  FD_TEST( memcmp( e7, e8,   sizeof(fd_hash_t) ) ); /* epoch is bound in */
  FD_TEST( !memcmp( e7, ref, sizeof(fd_hash_t) ) );
}

/* Walk a real tier, across several map seeds.  The seed drives the
   iteration order, so agreement here is what proves the sort is doing
   its job end to end. */

static void
test_tier_seed_independent( void ) {
  FD_LOG_NOTICE(( "test_tier_seed_independent" ));

  ulong const vote_cnt = 512UL;

  fd_vote_stake_weight_t * scratch = malloc( FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS*sizeof(fd_vote_stake_weight_t) );
  FD_TEST( scratch );

  /* Recorded so the test can prove the seeds really do produce
     different iteration orders.  Without this the agreement below
     could hold vacuously. */
  fd_pubkey_t raw_first[ 4 ];

  fd_hash_t first[1];
  for( ulong s=0UL; s<4UL; s++ ) {
    ulong footprint = fd_vote_stakes_footprint( 16UL, 4UL );
    void * mem = aligned_alloc( fd_vote_stakes_align(), footprint );
    FD_TEST( mem );
    fd_vote_stakes_t * vs = fd_vote_stakes_join( fd_vote_stakes_new( mem, 16UL, 4UL, 1000UL+s ) );
    FD_TEST( vs );

    ulong fork_id = fd_vote_stakes_init( vs, 0UL );

    uchar bls[ FD_BLS_PUBKEY_COMPRESSED_SZ ] = {0};
    for( ulong i=0UL; i<vote_cnt; i++ ) {
      /* Insert in an order that varies with the seed so that both the
         insertion order and the bucket layout differ per iteration. */
      ulong j = (i*7UL + s*13UL) % vote_cnt;
      fd_pubkey_t vote = key( j+1UL );
      fd_pubkey_t node = key( j+1UL+100000UL );
      ulong stake = 1000UL + j;
      fd_vote_stakes_snap_insert_t_1( vs, fork_id, &vote, &node, stake, (ushort)j, bls );
    }

    /* Peek at the raw, pre-sort iteration order. */
    {
      uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
      fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vs, fork_id, FD_VOTE_STAKES_ITER_T_1, iter_mem );
      FD_TEST( !fd_vote_stakes_iter_done( vs, fork_id, FD_VOTE_STAKES_ITER_T_1, iter ) );
      fd_vote_stakes_iter_ele( vs, fork_id, FD_VOTE_STAKES_ITER_T_1, iter, &raw_first[ s ],
                               NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL );
    }

    fd_hash_t got[1];
    fd_epoch_stakes_digest_tier( vs, fork_id, FD_VOTE_STAKES_ITER_T_1, 5UL, scratch, got );

    if( !s ) *first = *got;
    else     FD_TEST( !memcmp( got, first, sizeof(fd_hash_t) ) );

    free( mem );
  }

  int orders_differ = 0;
  for( ulong s=1UL; s<4UL; s++ ) {
    if( memcmp( &raw_first[s], &raw_first[0], sizeof(fd_pubkey_t) ) ) { orders_differ = 1; break; }
  }
  FD_TEST( orders_differ );

  free( scratch );
}

/* The t-3 tier is empty by construction at epoch 0.  It must digest,
   not trip an assert. */

static void
test_tier_not_resident( void ) {
  FD_LOG_NOTICE(( "test_tier_not_resident" ));

  ulong footprint = fd_vote_stakes_footprint( 16UL, 4UL );
  void * mem = aligned_alloc( fd_vote_stakes_align(), footprint );
  FD_TEST( mem );
  fd_vote_stakes_t * vs = fd_vote_stakes_join( fd_vote_stakes_new( mem, 16UL, 4UL, 1234UL ) );
  FD_TEST( vs );
  ulong fork_id = fd_vote_stakes_init( vs, 0UL );

  fd_vote_stake_weight_t * scratch = malloc( FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS*sizeof(fd_vote_stake_weight_t) );
  FD_TEST( scratch );

  fd_hash_t got[1], expected[1];
  fd_epoch_stakes_digest_tier( vs, fork_id, FD_VOTE_STAKES_ITER_T_3, 0UL, scratch, got );
  fd_epoch_stakes_digest( NULL, 0UL, 0UL, expected );
  FD_TEST( !memcmp( got, expected, sizeof(fd_hash_t) ) );

  free( scratch );
  free( mem );
}

/* The VAT bound is the sizing contract for every scratch buffer that
   feeds the digest. */

static void
test_saturated( void ) {
  FD_LOG_NOTICE(( "test_saturated" ));

  ulong const vote_cnt = FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS;

  ulong footprint = fd_vote_stakes_footprint( 16UL, 4UL );
  void * mem = aligned_alloc( fd_vote_stakes_align(), footprint );
  FD_TEST( mem );
  fd_vote_stakes_t * vs = fd_vote_stakes_join( fd_vote_stakes_new( mem, 16UL, 4UL, 42UL ) );
  FD_TEST( vs );
  ulong fork_id = fd_vote_stakes_init( vs, 0UL );

  uchar bls[ FD_BLS_PUBKEY_COMPRESSED_SZ ] = {0};
  for( ulong i=0UL; i<vote_cnt; i++ ) {
    fd_pubkey_t vote = key( i+1UL );
    fd_pubkey_t node = key( i+1UL+100000UL );
    fd_vote_stakes_snap_insert_t_1( vs, fork_id, &vote, &node, 1000UL+i, (ushort)i, bls );
  }
  FD_TEST( fd_vote_stakes_cnt_t_1( vs, fork_id )==vote_cnt );

  fd_vote_stake_weight_t * scratch = malloc( FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS*sizeof(fd_vote_stake_weight_t) );
  FD_TEST( scratch );

  fd_hash_t got[1];
  fd_epoch_stakes_digest_tier( vs, fork_id, FD_VOTE_STAKES_ITER_T_1, 5UL, scratch, got );

  /* Cross check against the reference over the same set built by hand. */
  fd_vote_stake_weight_t * canon = malloc( vote_cnt*sizeof(fd_vote_stake_weight_t) );
  FD_TEST( canon );
  for( ulong i=0UL; i<vote_cnt; i++ ) {
    canon[i].vote_key = key( i+1UL );
    canon[i].id_key   = key( i+1UL+100000UL );
    canon[i].stake    = 1000UL+i;
  }
  sort_vote_weights_by_vote_key_inplace( canon, vote_cnt );
  fd_hash_t expected[1];
  reference_digest( canon, vote_cnt, 5UL, expected );
  FD_TEST( !memcmp( got, expected, sizeof(fd_hash_t) ) );

  free( canon );
  free( scratch );
  free( mem );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_matches_reference();
  test_order_independent();
  test_every_field_covered();
  test_empty();
  test_tier_seed_independent();
  test_tier_not_resident();
  test_saturated();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
