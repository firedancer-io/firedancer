#include "fd_shredder.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../ballet/bmtree/fd_bmtree.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "fd_fec_samp.h"
#include <math.h>

#define TEST_SZ (1024UL*1024UL)
uchar test_entry_batch[TEST_SZ];

/* First 32B of what Solana calls the private key is what we call the
   private key, second 32B are what we call the public key. */
FD_IMPORT_BINARY( test_private_key, "src/disco/shred/fixtures/demo-shreds.key"  );

fd_shredder_t _shredder[ 1 ];

struct signer_ctx {
  fd_sha512_t sha512[ 1 ];

  uchar const * public_key;
  uchar const * private_key;
};
typedef struct signer_ctx signer_ctx_t;

void
signer_ctx_init( signer_ctx_t * ctx,
                 uchar const *  private_key ) {
  FD_TEST( fd_sha512_init( fd_sha512_new( ctx->sha512 ) ) );
  ctx->public_key  = private_key + 32UL;
  ctx->private_key = private_key;
}

static void
test_signer( void *        _ctx,
             uchar *       signature,
             uchar const * merkle_root ) {
  signer_ctx_t * ctx = (signer_ctx_t *)_ctx;
  fd_ed25519_sign( signature, merkle_root, 32UL, ctx->public_key, ctx->private_key, ctx->sha512 );
}


static void
test_normal( void ) {
  signer_ctx_t signer_ctx[ 1 ];
  signer_ctx_init( signer_ctx, test_private_key );
  fd_shredder_t shredder[1];

  fd_shredder_join( fd_shredder_new( shredder, test_signer, signer_ctx ) );
  fd_entry_batch_meta_t meta[1] = {{ 0 }};

  for( ulong slot=100UL; slot<1100UL; slot++ ) {
    fd_shredder_init_batch( shredder, test_entry_batch, TEST_SZ, slot, meta );

    ulong sets_cnt = fd_shredder_count_fec_sets( TEST_SZ, FD_SHRED_TYPE_MERKLE_DATA );
    fd_fec_set_t _set[ 1 ];
    uchar chained_merkle_root[ 32 ] = { 0 };
    for( ulong j=0UL; j<sets_cnt; j++ ) {
      fd_shredder_next_fec_set( shredder, _set, chained_merkle_root );

      fd_fec_samp_t samp[1];
      fd_shred_t const * shred0 = _set->data_shreds->s;
      fd_fec_samp_derive( samp, 11111UL, slot, shred0->fec_set_idx, shred0->signature, (fd_bmtree_node_t const *)chained_merkle_root, &shredder->bmtree );

      for( ulong i=0UL; i<32UL; i++ ) FD_TEST( fd_fec_samp_matches( samp, 11111UL, _set->data_shreds[i].s   ) );
      for( ulong i=0UL; i<32UL; i++ ) FD_TEST( fd_fec_samp_matches( samp, 11111UL, _set->parity_shreds[i].s ) );
    }
    fd_shredder_fini_batch( shredder );
  }
}

static void
test_equivoc( void ) {
  signer_ctx_t signer_ctx[ 1 ];
  signer_ctx_init( signer_ctx, test_private_key );
  fd_shredder_t shredder[1];
  fd_shredder_t shredder2[1];

  fd_shredder_join( fd_shredder_new( shredder,  test_signer, signer_ctx ) );
  fd_shredder_join( fd_shredder_new( shredder2, test_signer, signer_ctx ) );
  fd_entry_batch_meta_t meta[1] = {{ 0 }};

  ulong failures = 0UL;
  ulong total_fecs = 0UL;

  for( ulong slot=100UL; slot<3100UL; slot++ ) {
    fd_shredder_init_batch( shredder,  test_entry_batch, TEST_SZ, slot, meta );
    fd_shredder_init_batch( shredder2, test_entry_batch, TEST_SZ, slot, meta );

    ulong sets_cnt = fd_shredder_count_fec_sets( TEST_SZ, FD_SHRED_TYPE_MERKLE_DATA );
    fd_fec_set_t _set[ 1 ];
    uchar chained_merkle_root [ 32 ] = { 0 };
    uchar chained_merkle_root2[ 32 ] = { 2, 1, 0 };
    for( ulong j=0UL; j<sets_cnt; j++ ) {
      fd_shredder_next_fec_set( shredder, _set, chained_merkle_root );

      fd_fec_samp_t samp[1];
      fd_shred_t const * shred0 = _set->data_shreds->s;
      fd_fec_samp_derive( samp, 11111UL, slot, shred0->fec_set_idx, shred0->signature, (fd_bmtree_node_t const *)chained_merkle_root, &shredder->bmtree );

      fd_shredder_next_fec_set( shredder2, _set, chained_merkle_root2 );

      /* detection of this type of equivocation is mostly based on the
         Merkle tree, which means we're likely to fail on a while FEC
         set, so just test the first shred. */
      failures += !!fd_fec_samp_matches( samp, 11111UL, _set->data_shreds->s   );
      failures += !!fd_fec_samp_matches( samp, 11111UL, _set->parity_shreds->s );
      total_fecs++;
    }
    fd_shredder_fini_batch( shredder  );
    fd_shredder_fini_batch( shredder2 );
  }
  /* Is that consistent with a binomial distribution with n=2*total_fecs
     and p=2^-14?  That's a small p, but we have enough trials to use
     the Z test approximation.  At 3 standard deviations, this gives:
          3*sqrt(N) * sqrt(p(1-p)) + n*p */
  ulong acceptable_failures = (ulong)(0.5f + (float)(2UL*total_fecs)*0.00006103515625f + 0.0234367847333f*sqrtf( (float)(2UL*total_fecs) ));
  FD_LOG_NOTICE(( "%lu failures out of %lu shreds. Acceptable %lu", failures, 2UL*total_fecs, acceptable_failures ));
  FD_TEST( failures<=acceptable_failures );
}

static void
test_clone_proof( void ) {
  signer_ctx_t signer_ctx[ 1 ];
  signer_ctx_init( signer_ctx, test_private_key );
  fd_shredder_t shredder[1];
  fd_shredder_t shredder2[1];

  fd_shredder_join( fd_shredder_new( shredder,  test_signer, signer_ctx ) );
  fd_shredder_join( fd_shredder_new( shredder2, test_signer, signer_ctx ) );
  fd_entry_batch_meta_t meta[1] = {{ 0 }};

  ulong failures = 0UL;
  ulong total_fecs = 0UL;

  for( ulong slot=100UL; slot<1100UL; slot++ ) {
    fd_shredder_init_batch( shredder,  test_entry_batch, TEST_SZ, slot, meta );
    fd_shredder_init_batch( shredder2, test_entry_batch, TEST_SZ, slot, meta );

    ulong sets_cnt = fd_shredder_count_fec_sets( TEST_SZ, FD_SHRED_TYPE_MERKLE_DATA );
    fd_fec_set_t _set[ 1 ], _set2[ 1 ];
    uchar chained_merkle_root [ 32 ] = { 0 };
    uchar chained_merkle_root2[ 32 ] = { 2, 1, 0 };
    for( ulong j=0UL; j<sets_cnt; j++ ) {
      fd_shredder_next_fec_set( shredder, _set, chained_merkle_root );

      fd_fec_samp_t samp[1];
      fd_shred_t const * shred0 = _set->data_shreds->s;
      fd_fec_samp_derive( samp, 11111UL, slot, shred0->fec_set_idx, shred0->signature, (fd_bmtree_node_t const *)chained_merkle_root, &shredder->bmtree );

      fd_shredder_next_fec_set( shredder2, _set2, chained_merkle_root2 );

      for( ulong i=0UL; i<32UL; i++ ) {
        fd_memcpy( _set2->data_shreds[i].b   + fd_shred_merkle_off( _set2->data_shreds[i].s   ),
                   fd_shred_merkle_nodes( _set->data_shreds[i].s   ), fd_shred_merkle_sz( _set->data_shreds[i].s->variant   ) );
        fd_memcpy( _set2->parity_shreds[i].b + fd_shred_merkle_off( _set2->parity_shreds[i].s ),
                   fd_shred_merkle_nodes( _set->parity_shreds[i].s ), fd_shred_merkle_sz( _set->parity_shreds[i].s->variant ) );
        failures += !!fd_fec_samp_matches( samp, 11111UL, _set2->data_shreds[i].s   );
        failures += !!fd_fec_samp_matches( samp, 11111UL, _set2->parity_shreds[i].s );
      }
      total_fecs++;
    }
    fd_shredder_fini_batch( shredder  );
    fd_shredder_fini_batch( shredder2 );
  }
  /* Is that consistent with a binomial distribution with n=64*total_fecs
     and p=31/32?  Here we're worried about p being too large, but we
     still have way more than enough trials to use the Z test
     approximation.  At 3 standard deviations, as before, we have this
     gives:
          3*sqrt(N) * sqrt(p(1-p)) + N*p
     Subbing in N=64*f and p=31/32, this simplifies nicely to
          24*sqrt(f)*sqrt(31)/32 + 64 * f * 31/32
          3 sqrt(31)/4 * sqrt(f) + 62 f
     */
  ulong acceptable_failures = (ulong)(0.5f + (float)(62UL*total_fecs) + 4.1758232721f*sqrtf( (float)(total_fecs) ));
  FD_LOG_NOTICE(( "%lu failures out of %lu shreds. Acceptable %lu", failures, 64UL*total_fecs, acceptable_failures ));
  FD_TEST( acceptable_failures<=64UL*total_fecs     );
  FD_TEST(            failures<=acceptable_failures );
}

static void
test_validator_independence( void ) {
  signer_ctx_t signer_ctx[ 1 ];
  signer_ctx_init( signer_ctx, test_private_key );
  fd_shredder_t shredder[1];
  fd_shredder_t shredder2[1];

  fd_shredder_join( fd_shredder_new( shredder,  test_signer, signer_ctx ) );
  fd_shredder_join( fd_shredder_new( shredder2, test_signer, signer_ctx ) );
  fd_entry_batch_meta_t meta[1] = {{ 0 }};

  ulong total_fecs = 0UL;
  ulong cross_table[2][2] = {{0}};

  for( ulong slot=100UL; slot<3100UL; slot++ ) {
    fd_shredder_init_batch( shredder,  test_entry_batch, TEST_SZ, slot, meta );
    fd_shredder_init_batch( shredder2, test_entry_batch, TEST_SZ, slot, meta );

    ulong sets_cnt = fd_shredder_count_fec_sets( TEST_SZ, FD_SHRED_TYPE_MERKLE_DATA );
    fd_fec_set_t _set[ 1 ], _set2[ 1 ];
    uchar chained_merkle_root [ 32 ] = { 0 };
    uchar chained_merkle_root2[ 32 ] = { 2, 1, 0 };
    for( ulong j=0UL; j<sets_cnt; j++ ) {
      fd_shredder_next_fec_set( shredder, _set, chained_merkle_root );

      fd_fec_samp_t samp[1];
      fd_fec_samp_t samp2[1];
      fd_shred_t const * shred0 = _set->data_shreds->s;
      fd_fec_samp_derive( samp,  11111UL, slot, shred0->fec_set_idx, shred0->signature, (fd_bmtree_node_t const *)chained_merkle_root, &shredder->bmtree );
      fd_fec_samp_derive( samp2, 22222UL, slot, shred0->fec_set_idx, shred0->signature, (fd_bmtree_node_t const *)chained_merkle_root, &shredder->bmtree );

      fd_shredder_next_fec_set( shredder2, _set2, chained_merkle_root2 );

      if( FD_UNLIKELY( fd_fec_samp_matches( samp, 11111UL, _set2->data_shreds->s ) ) ) {
        /* This could fail, but with p=2^-14, so I'm not worried */
        FD_TEST( !fd_fec_samp_matches( samp2, 22222UL, _set2->data_shreds->s ) );
      }
      for( ulong i=0UL; i<32UL; i++ ) {
        fd_memcpy( _set2->data_shreds[i].b   + fd_shred_merkle_off( _set2->data_shreds[i].s   ),
                   fd_shred_merkle_nodes( _set->data_shreds[i].s   ), fd_shred_merkle_sz( _set->data_shreds[i].s->variant   ) );
        fd_memcpy( _set2->parity_shreds[i].b + fd_shred_merkle_off( _set2->parity_shreds[i].s ),
                   fd_shred_merkle_nodes( _set->parity_shreds[i].s ), fd_shred_merkle_sz( _set->parity_shreds[i].s->variant ) );

        cross_table[ fd_fec_samp_matches( samp,  11111UL, _set2->data_shreds[i].s   ) ]
                   [ fd_fec_samp_matches( samp2, 22222UL, _set2->data_shreds[i].s   ) ]++;
        cross_table[ fd_fec_samp_matches( samp,  11111UL, _set2->parity_shreds[i].s ) ]
                   [ fd_fec_samp_matches( samp2, 22222UL, _set2->parity_shreds[i].s ) ]++;
      }
      total_fecs++;
    }
    fd_shredder_fini_batch( shredder  );
    fd_shredder_fini_batch( shredder2 );
  }
  /* Use a chi-squared test of independence */
  float chi2 = 0.0f;
  for( ulong i=0UL; i<2UL; i++ ) for( ulong j=0UL; j<2UL; j++ ) {
    /*                                       0 -> 1, 1 -> 31 */
    float expected = (float)(total_fecs*(30UL*i+1UL)*(30UL*j+1UL))/16.0f;
    float delta = (float)cross_table[i][j] - expected;
    chi2 += delta*delta/expected;
  }
  FD_LOG_NOTICE(( "%lu\t%lu", cross_table[0][0], cross_table[0][1] ));
  FD_LOG_NOTICE(( "%lu\t%lu", cross_table[1][0], cross_table[1][1] ));
  FD_LOG_NOTICE(( "chi^2 value %f", (double)chi2 ));
  FD_TEST( chi2 < 3.841f ); /* 1 dof at p<.05 */
}

static void
test_force( void ) {
  signer_ctx_t signer_ctx[ 1 ];
  signer_ctx_init( signer_ctx, test_private_key );
  fd_shredder_t shredder[1];
  fd_shredder_t shredder2[1];

  fd_shredder_join( fd_shredder_new( shredder,  test_signer, signer_ctx ) );
  fd_shredder_join( fd_shredder_new( shredder2, test_signer, signer_ctx ) );
  fd_entry_batch_meta_t meta[1] = {{ 0 }};

  for( ulong slot=100UL; slot<3100UL; slot++ ) {
    fd_shredder_init_batch( shredder,  test_entry_batch, TEST_SZ, slot, meta );
    fd_shredder_init_batch( shredder2, test_entry_batch, TEST_SZ, slot, meta );

    ulong sets_cnt = fd_shredder_count_fec_sets( TEST_SZ, FD_SHRED_TYPE_MERKLE_DATA );
    fd_fec_set_t _set[ 1 ], _set2[ 1 ];
    uchar chained_merkle_root [ 32 ] = { 0 };
    uchar chained_merkle_root2[ 32 ] = { 2, 1, 0 };
    for( ulong j=0UL; j<sets_cnt; j++ ) {
      fd_shredder_next_fec_set( shredder, _set, chained_merkle_root );

      fd_fec_samp_t samp[1];
      fd_shred_t const * shred0 = _set->data_shreds->s;
      fd_fec_samp_derive( samp, 11111UL, slot, shred0->fec_set_idx, shred0->signature, (fd_bmtree_node_t const *)chained_merkle_root, &shredder->bmtree );
      fd_fec_samp_set_force_match( samp );


      fd_shredder_next_fec_set( shredder2, _set2, chained_merkle_root2 );

      FD_TEST( fd_fec_samp_matches( samp, 11111UL, _set2->data_shreds->s   ) );
      FD_TEST( fd_fec_samp_matches( samp, 11111UL, _set2->parity_shreds->s ) );

      fd_memcpy( _set2->data_shreds->b   + fd_shred_merkle_off( _set2->data_shreds->s   ),
          fd_shred_merkle_nodes( _set->data_shreds->s   ), fd_shred_merkle_sz( _set->data_shreds->s->variant   ) );
      fd_memcpy( _set2->parity_shreds->b + fd_shred_merkle_off( _set2->parity_shreds->s ),
          fd_shred_merkle_nodes( _set->parity_shreds->s ), fd_shred_merkle_sz( _set->parity_shreds->s->variant ) );
      FD_TEST( fd_fec_samp_matches( samp, 11111UL, _set2->data_shreds->s   ) );
      FD_TEST( fd_fec_samp_matches( samp, 11111UL, _set2->parity_shreds->s ) );

    }
    fd_shredder_fini_batch( shredder  );
    fd_shredder_fini_batch( shredder2 );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_normal();
  test_equivoc();
  test_clone_proof();
  test_validator_independence();
  test_force();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

