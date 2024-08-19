#include "fd_shredder.h"
#include "fd_fec_resolver.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../ballet/shred/fd_fec_set.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../util/archive/fd_ar.h"

#include "../../disco/metrics/fd_metrics.h"

/* An entry batch of 64 entries with 20 transactions per entry takes up
   about 256 kB, for about 200B/txn, which seems reasonable.  We'll do a
   10 MB entry batch, which is about 50k transactions. */
#define PERF_TEST_SZ (10UL*1024UL*1024UL)
uchar perf_test_entry_batch[ PERF_TEST_SZ ];

uchar fec_set_memory[ 16UL*2048UL * (FD_REEDSOL_DATA_SHREDS_MAX+FD_REEDSOL_PARITY_SHREDS_MAX) ];

uchar res_mem[ 1024UL*1024UL ] __attribute__((aligned(FD_FEC_RESOLVER_ALIGN)));

/* First 32B of what Solana calls the private key is what we call the
   private key, second 32B are what we call the public key. */
FD_IMPORT_BINARY( test_private_key, "src/disco/shred/fixtures/demo-shreds.key"  );

FD_IMPORT_BINARY( test_bin,         "src/disco/shred/fixtures/demo-shreds.bin"  );

FD_IMPORT_BINARY( chained_test,     "src/disco/shred/fixtures/chained-5XDmMEZpXM2GBXNjhgRCti4qLGeFQvx4RnzWeRgfupYk.ar"  );
FD_IMPORT_BINARY( resigned_test,    "src/disco/shred/fixtures/resigned-AmKFVSAQ7DyhiW94pWfDexYDCSn8GB6SG2zbQqLhuufU.ar" );

uchar metrics_scratch[ FD_METRICS_FOOTPRINT( 0, 0 ) ] __attribute__((aligned(FD_METRICS_ALIGN)));

fd_shredder_t _shredder[ 1 ];

#define SHRED_VER   (ushort)6051 /* An arbitary value */
#define MAX         (32UL*1024UL)

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

void
test_signer( void *        _ctx,
             uchar *       signature,
             uchar const * merkle_root ) {
  signer_ctx_t * ctx = (signer_ctx_t *)_ctx;

  fd_ed25519_sign( signature, merkle_root, 32UL, ctx->public_key, ctx->private_key, ctx->sha512 );
}

static int
sets_eq( fd_fec_set_t const * a, fd_fec_set_t const * b ) {
  if( (a==NULL) ^ (b==NULL) ) return 0;

  if( a->data_shred_cnt   != b->data_shred_cnt   ) return 0;
  if( a->parity_shred_cnt != b->parity_shred_cnt ) return 0;

  for( ulong i=0UL; i<a->data_shred_cnt; i++ ) if( !fd_memeq( a->data_shreds[i], b->data_shreds[i], FD_SHRED_MIN_SZ ) ) {
    FD_LOG_NOTICE(( "data shred %lu not equal", i ));
    FD_LOG_HEXDUMP_NOTICE(( "a:", a->data_shreds[i], FD_SHRED_MIN_SZ ));
    FD_LOG_HEXDUMP_NOTICE(( "b:", b->data_shreds[i], FD_SHRED_MIN_SZ ));
    return 0;
  }
  for( ulong i=0UL; i<a->parity_shred_cnt; i++ ) if( !fd_memeq( a->parity_shreds[i], b->parity_shreds[i], FD_SHRED_MAX_SZ ) ) {
    FD_LOG_NOTICE(( "parity shred %lu not equal", i ));
    FD_LOG_HEXDUMP_NOTICE(( "a:", a->parity_shreds[i], FD_SHRED_MAX_SZ ));
    FD_LOG_HEXDUMP_NOTICE(( "b:", b->parity_shreds[i], FD_SHRED_MAX_SZ ));
    return 0;
  }

  return 1;
}

static inline uchar *
allocate_fec_set( fd_fec_set_t * set, uchar * ptr ) {
  for( ulong j=0UL; j<FD_REEDSOL_DATA_SHREDS_MAX;   j++ ) { set->data_shreds[   j ] = ptr;     ptr += 2048UL; }
  for( ulong j=0UL; j<FD_REEDSOL_PARITY_SHREDS_MAX; j++ ) { set->parity_shreds[ j ] = ptr;     ptr += 2048UL; }
  FD_TEST( ptr<=fec_set_memory + sizeof(fec_set_memory) );
  return ptr;
}


static void
test_one_batch( void ) {
  signer_ctx_t signer_ctx[ 1 ];
  signer_ctx_init( signer_ctx, test_private_key );

  FD_TEST( _shredder==fd_shredder_new( _shredder, test_signer, signer_ctx, SHRED_VER ) );
  fd_shredder_t * shredder = fd_shredder_join( _shredder );           FD_TEST( shredder );

  uchar const * pubkey = test_private_key+32UL;

  fd_entry_batch_meta_t meta[1];
  fd_memset( meta, 0, sizeof(fd_entry_batch_meta_t) );
  meta->block_complete = 1;

  FD_TEST( fd_shredder_init_batch( shredder, test_bin, test_bin_sz, 0UL, meta ) );

  fd_fec_set_t _set[ 1 ];
  fd_fec_set_t out_sets[ 12UL ];
  uchar * ptr = fec_set_memory;
  ptr = allocate_fec_set( _set, ptr );

  for( ulong i=0UL; i<12UL; i++ )  ptr = allocate_fec_set( out_sets+i, ptr );

  ulong foot = fd_fec_resolver_footprint( 4UL, 1UL, 1UL, 1UL );
  fd_fec_resolver_t *r1, *r2, *r3;
  r1 = fd_fec_resolver_join( fd_fec_resolver_new( res_mem+0UL*foot, NULL, NULL, 2UL, 1UL, 1UL, 1UL, out_sets,     SHRED_VER, MAX ) );
  r2 = fd_fec_resolver_join( fd_fec_resolver_new( res_mem+1UL*foot, NULL, NULL, 2UL, 1UL, 1UL, 1UL, out_sets+4UL, SHRED_VER, MAX ) );
  r3 = fd_fec_resolver_join( fd_fec_resolver_new( res_mem+2UL*foot, NULL, NULL, 2UL, 1UL, 1UL, 1UL, out_sets+8UL, SHRED_VER, MAX ) );

  fd_fec_set_t const * out_fec[1];
  fd_shred_t   const * out_shred[1];


#define ADD_SHRED( resolver, shred, expected ) do { \
      fd_shred_t const * __parsed = fd_shred_parse( (shred), 2048UL ); \
      int retval = fd_fec_resolver_add_shred( resolver, __parsed, 2048UL, pubkey, out_fec, out_shred ); \
      FD_TEST( retval==FD_FEC_RESOLVER_SHRED_ ## expected ); \
      } while( 0 )
  /* To complete an FEC set, you need at least (# of data shreds) total
     shreds and at least one parity shred. */
  for( ulong i=0UL; i<7UL; i++ ) {
    fd_fec_set_t * set = fd_shredder_next_fec_set( shredder, _set );

    for( ulong j=0UL; j<set->data_shred_cnt;       j++ ) ADD_SHRED( r1, set->data_shreds  [ j ], OKAY    );
    ADD_SHRED( r1, set->parity_shreds[ 0 ], COMPLETES );
    FD_TEST( *out_fec==out_sets+(i%4UL) );
    FD_TEST( sets_eq( set, *out_fec ) );

    for( ulong j=0UL; j<set->parity_shred_cnt-1UL; j++ ) ADD_SHRED( r2, set->parity_shreds[ j ], OKAY    );
    for( ulong j=0UL; j<10UL;                      j++ ) ADD_SHRED( r2, set->parity_shreds[ 0 ], IGNORED );
    ADD_SHRED( r2, set->data_shreds[ 0 ], COMPLETES );
    FD_TEST( *out_fec==out_sets+4UL+(i%4UL) );
    FD_TEST( sets_eq( set, *out_fec ) );

    for( ulong j=1UL; j<set->parity_shred_cnt;     j++ ) ADD_SHRED( r3, set->parity_shreds[ j ], OKAY    );
    ADD_SHRED( r3, set->parity_shreds[ 0 ], COMPLETES );
    FD_TEST( *out_fec==out_sets+8UL+(i%4UL) );
    FD_TEST( sets_eq( set, *out_fec ) );
  }
  FD_TEST( fd_shredder_fini_batch( shredder ) );

  fd_fec_resolver_delete( fd_fec_resolver_leave( r3 ) );
  fd_fec_resolver_delete( fd_fec_resolver_leave( r2 ) );
  fd_fec_resolver_delete( fd_fec_resolver_leave( r1 ) );
}

static void
test_interleaved( void ) {
  signer_ctx_t signer_ctx[ 1 ];
  signer_ctx_init( signer_ctx, test_private_key );

  FD_TEST( _shredder==fd_shredder_new( _shredder, test_signer, signer_ctx, SHRED_VER ) );
  fd_shredder_t * shredder = fd_shredder_join( _shredder );           FD_TEST( shredder );

  uchar const * pubkey = test_private_key+32UL;
  fd_entry_batch_meta_t meta[1];
  fd_memset( meta, 0, sizeof(fd_entry_batch_meta_t) );
  meta->block_complete = 1;

  FD_TEST( fd_shredder_init_batch( shredder, test_bin, test_bin_sz, 0UL, meta ) );

  fd_fec_set_t _set[ 2 ];
  uchar * ptr = fec_set_memory;
  ptr = allocate_fec_set( _set+0, ptr );
  ptr = allocate_fec_set( _set+1, ptr );

  fd_fec_set_t out_sets[ 4UL ];
  for( ulong i=0UL; i<4UL; i++ ) ptr = allocate_fec_set( out_sets+i, ptr );


  fd_fec_set_t * set0 = fd_shredder_next_fec_set( shredder, _set     );
  fd_fec_set_t * set1 = fd_shredder_next_fec_set( shredder, _set+1UL );
  FD_TEST( fd_shredder_fini_batch( shredder ) );

  fd_fec_set_t const * out_fec[1];
  fd_shred_t   const * out_shred[1];

  fd_fec_resolver_t * resolver = fd_fec_resolver_join( fd_fec_resolver_new( res_mem, NULL, NULL, 2UL, 1UL, 1UL, 1UL, out_sets, SHRED_VER, MAX ) );
  for( ulong j=0UL; j<set0->data_shred_cnt; j++ ) {
    ADD_SHRED( resolver, set0->data_shreds[ j ], OKAY );
    ADD_SHRED( resolver, set1->data_shreds[ j ], OKAY );
  }
  ADD_SHRED( resolver, set0->parity_shreds[ 0 ], COMPLETES ); FD_TEST( *out_fec==out_sets+0 ); FD_TEST( sets_eq( set0, *out_fec ) );
  ADD_SHRED( resolver, set1->parity_shreds[ 1 ], COMPLETES ); FD_TEST( *out_fec==out_sets+1 ); FD_TEST( sets_eq( set1, *out_fec ) );

  fd_fec_resolver_delete( fd_fec_resolver_leave( resolver ) );
}


static void
test_rolloff( void ) {
  signer_ctx_t signer_ctx[ 1 ];
  signer_ctx_init( signer_ctx, test_private_key );

  FD_TEST( _shredder==fd_shredder_new( _shredder, test_signer, signer_ctx, SHRED_VER ) );
  fd_shredder_t * shredder = fd_shredder_join( _shredder );           FD_TEST( shredder );
  uchar const * pubkey = test_private_key+32UL;
  fd_fec_set_t const * out_fec[1];
  fd_shred_t   const * out_shred[1];


  fd_entry_batch_meta_t meta[1];
  fd_memset( meta, 0, sizeof(fd_entry_batch_meta_t) );
  meta->block_complete = 1;

  FD_TEST( fd_shredder_init_batch( shredder, test_bin, test_bin_sz, 0UL, meta ) );

  fd_fec_set_t _set[ 3 ];
  uchar * ptr = fec_set_memory;
  ptr = allocate_fec_set( _set+0, ptr );
  ptr = allocate_fec_set( _set+1, ptr );
  ptr = allocate_fec_set( _set+2, ptr );

  fd_fec_set_t out_sets[ 4UL ];
  for( ulong i=0UL; i<4UL; i++ ) ptr = allocate_fec_set( out_sets+i, ptr );


  fd_fec_set_t * set0 = fd_shredder_next_fec_set( shredder, _set     );
  fd_fec_set_t * set1 = fd_shredder_next_fec_set( shredder, _set+1UL );
  fd_fec_set_t * set2 = fd_shredder_next_fec_set( shredder, _set+2UL );
  FD_TEST( fd_shredder_fini_batch( shredder ) );

  fd_fec_resolver_t * resolver;
  resolver = fd_fec_resolver_join( fd_fec_resolver_new( res_mem, NULL, NULL, 2UL, 1UL, 1UL, 8UL, out_sets, SHRED_VER, MAX ) );
  for( ulong j=0UL; j<set0->data_shred_cnt; j++ ) { ADD_SHRED( resolver, set0->data_shreds[ j ], OKAY ); }

  for( ulong j=0UL; j<set1->data_shred_cnt; j++ ) { ADD_SHRED( resolver, set1->data_shreds[ j ], OKAY ); }

  /* At this point we have set0, set1 as the two in progress sets */

  for( ulong j=0UL; j<set2->data_shred_cnt; j++ ) { ADD_SHRED( resolver, set2->data_shreds[ j ], OKAY ); }

  /* Now, set0 kicked out and added to done so it'll be ignored. set1
     and set2 are in progress. */
  ADD_SHRED( resolver, set0->parity_shreds[ 0 ], IGNORED );
  ADD_SHRED( resolver, set1->parity_shreds[ 1 ], COMPLETES ); FD_TEST( *out_fec==out_sets+1 ); FD_TEST( sets_eq( set1, *out_fec ) );
  ADD_SHRED( resolver, set2->parity_shreds[ 1 ], COMPLETES ); FD_TEST( *out_fec==out_sets+2 ); FD_TEST( sets_eq( set2, *out_fec ) );
  ADD_SHRED( resolver, set0->parity_shreds[ 0 ], IGNORED );

  fd_fec_resolver_delete( fd_fec_resolver_leave( resolver ) );
}

static void
perf_test( void ) {
  for( ulong i=0UL; i<PERF_TEST_SZ; i++ )  perf_test_entry_batch[ i ] = (uchar)i;

  fd_entry_batch_meta_t meta[1];
  fd_memset( meta, 0, sizeof(fd_entry_batch_meta_t) );
  meta->block_complete = 1;

  signer_ctx_t signer_ctx[ 1 ];
  signer_ctx_init( signer_ctx, test_private_key );

  FD_TEST( _shredder==fd_shredder_new( _shredder, test_signer, signer_ctx, SHRED_VER ) );
  fd_shredder_t * shredder = fd_shredder_join( _shredder );           FD_TEST( shredder );

  fd_fec_set_t _set[ 1 ];
  uchar * ptr = fec_set_memory;
  for( ulong j=0UL; j<FD_REEDSOL_DATA_SHREDS_MAX;   j++ ) { _set->data_shreds[   j ] = ptr;     ptr += 2048UL; }
  for( ulong j=0UL; j<FD_REEDSOL_PARITY_SHREDS_MAX; j++ ) { _set->parity_shreds[ j ] = ptr;     ptr += 2048UL; }

  ulong iterations = 100UL;
  long dt = -fd_log_wallclock();
  for( ulong iter=0UL; iter<iterations; iter++ ) {
    fd_shredder_init_batch( shredder, perf_test_entry_batch, PERF_TEST_SZ, 0UL, meta );

    ulong sets_cnt = fd_shredder_count_fec_sets( PERF_TEST_SZ );
    for( ulong j=0UL; j<sets_cnt; j++ ) {
      fd_shredder_next_fec_set( shredder, _set );
    }
    fd_shredder_fini_batch( shredder );
  }
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "%li ns/10 MB entry batch = %.3f Gbps", dt/(long)iterations, (double)(8UL * iterations * PERF_TEST_SZ)/(double)dt ));

}

static void
test_new_formats( void ) {
  signer_ctx_t signer_ctx[ 1 ];
  signer_ctx_init( signer_ctx, test_private_key );
  uchar * ptr = fec_set_memory;

  fd_fec_set_t out_sets[ 4UL ];
  for( ulong i=0UL; i<4UL; i++ ) ptr = allocate_fec_set( out_sets+i, ptr );

  fd_fec_resolver_t * resolver;
  resolver = fd_fec_resolver_join( fd_fec_resolver_new( res_mem, test_signer, signer_ctx, 2UL, 1UL, 1UL, 8UL, out_sets, 1, MAX ) );

  uchar pubkey[32];
  fd_base58_decode_32( "5XDmMEZpXM2GBXNjhgRCti4qLGeFQvx4RnzWeRgfupYk", pubkey );

  fd_ar_meta_t meta[1];

  FILE * file = fmemopen( (void *)chained_test, chained_test_sz, "rb" );
  FD_TEST( file );
  FD_TEST( !fd_ar_read_init( file ) );

  ulong fec_sets = 0UL;
  int   fec_done = 0;
  while( !fd_ar_read_next( file, meta ) ) {
    uchar shred[ 2048 ];
    fd_fec_set_t const * out_fec[1];
    fd_shred_t   const * out_shred[1];
    FD_TEST( 1==fread( shred, (ulong)meta->filesz, 1UL, file ) );
    fd_shred_t const * parsed = fd_shred_parse( shred, 2048UL );
    int retval = fd_fec_resolver_add_shred( resolver, parsed, 2048UL, pubkey, out_fec, out_shred );
    if( FD_UNLIKELY( retval==FD_FEC_RESOLVER_SHRED_COMPLETES ) ) {
      fec_sets++;
      fec_done = 1;
    } else if( retval==FD_FEC_RESOLVER_SHRED_IGNORED ) {
      FD_TEST( fec_done );
    } else {
      FD_TEST( retval==FD_FEC_RESOLVER_SHRED_OKAY );
      fec_done = 0;
    }
  }
  FD_TEST( fec_sets==4UL );
  FD_TEST( !fclose( file ) );


  fd_base58_decode_32( "AmKFVSAQ7DyhiW94pWfDexYDCSn8GB6SG2zbQqLhuufU", pubkey );

  file = fmemopen( (void *)resigned_test, resigned_test_sz, "rb" );
  FD_TEST( file );
  FD_TEST( !fd_ar_read_init( file ) );

  fec_done = 0;
  fec_sets = 0UL;
  while( !fd_ar_read_next( file, meta ) ) {
    uchar shred[ 2048 ];
    fd_fec_set_t const * out_fec[1];
    fd_shred_t   const * out_shred[1];
    FD_TEST( 1==fread( shred, (ulong)meta->filesz, 1UL, file ) );
    fd_shred_t const * parsed = fd_shred_parse( shred, 2048UL );
    int retval = fd_fec_resolver_add_shred( resolver, parsed, 2048UL, pubkey, out_fec, out_shred );
    if( FD_UNLIKELY( retval==FD_FEC_RESOLVER_SHRED_COMPLETES ) ) {
      fec_sets++;
      fec_done = 1;
    } else if( retval==FD_FEC_RESOLVER_SHRED_IGNORED ) {
      FD_TEST( fec_done );
    } else {
      FD_TEST( retval==FD_FEC_RESOLVER_SHRED_OKAY );
      fec_done = 0;
    }
  }
  FD_TEST( fec_sets==1UL );
  FD_TEST( !fclose( file ) );

  fd_fec_resolver_delete( fd_fec_resolver_leave( resolver ) );
}


static void
test_shred_version( void ) {
  signer_ctx_t signer_ctx[ 1 ];
  signer_ctx_init( signer_ctx, test_private_key );

  FD_TEST( _shredder==fd_shredder_new( _shredder, test_signer, signer_ctx, (ushort)~SHRED_VER ) );
  fd_shredder_t * shredder = fd_shredder_join( _shredder );           FD_TEST( shredder );

  uchar const * pubkey = test_private_key+32UL;

  fd_entry_batch_meta_t meta[1];
  fd_memset( meta, 0, sizeof(fd_entry_batch_meta_t) );
  meta->block_complete = 1;

  FD_TEST( fd_shredder_init_batch( shredder, test_bin, test_bin_sz, 0UL, meta ) );

  fd_fec_set_t _set[ 1 ];
  fd_fec_set_t out_sets[ 4UL ];
  uchar * ptr = fec_set_memory;
  ptr = allocate_fec_set( _set, ptr );

  for( ulong i=0UL; i<4UL; i++ )  ptr = allocate_fec_set( out_sets+i, ptr );

  fd_fec_resolver_t * r = fd_fec_resolver_join( fd_fec_resolver_new( res_mem, NULL, NULL, 2UL, 1UL, 1UL, 1UL, out_sets, SHRED_VER, MAX ) );

  fd_fec_set_t const * out_fec[1];
  fd_shred_t   const * out_shred[1];

  fd_fec_set_t * set = fd_shredder_next_fec_set( shredder, _set );
  fd_shred_t const * shred = fd_shred_parse( set->data_shreds[ 0 ], 2048UL );
  FD_TEST( shred );
  FD_TEST( FD_FEC_RESOLVER_SHRED_REJECTED==fd_fec_resolver_add_shred( r, shred, 2048UL, pubkey, out_fec, out_shred ) );

  fd_fec_resolver_delete( fd_fec_resolver_leave( r ) );
}

static void
fake_resign( fd_shred_t   * shred,
             signer_ctx_t * sign_ctx ) {

  uchar variant     = shred->variant;
  uchar shred_type  = fd_shred_type( variant );
  int is_data_shred = fd_shred_is_data( shred_type );
  ulong in_type_idx = fd_ulong_if( is_data_shred, shred->idx - shred->fec_set_idx, shred->code.idx );
  ulong shred_idx   = fd_ulong_if( is_data_shred, in_type_idx, in_type_idx + shred->code.data_cnt  );

  ulong tree_depth           = fd_shred_merkle_cnt( variant ); /* In [0, 15] */
  ulong reedsol_protected_sz = 1115UL + FD_SHRED_DATA_HEADER_SZ - FD_SHRED_SIGNATURE_SZ - FD_SHRED_MERKLE_NODE_SZ*tree_depth
    - FD_SHRED_MERKLE_ROOT_SZ*fd_shred_is_chained ( shred_type )
    - FD_SHRED_SIGNATURE_SZ  *fd_shred_is_resigned( shred_type); /* In [743, 1139] conservatively*/
  ulong data_merkle_protected_sz   = reedsol_protected_sz + FD_SHRED_MERKLE_ROOT_SZ*fd_shred_is_chained ( shred_type );
  ulong parity_merkle_protected_sz = reedsol_protected_sz + FD_SHRED_MERKLE_ROOT_SZ*fd_shred_is_chained ( shred_type )+0x59UL-0x40UL;
  ulong merkle_protected_sz  = fd_ulong_if( is_data_shred, data_merkle_protected_sz, parity_merkle_protected_sz );

  uchar bmtree_mem[ fd_bmtree_commit_footprint( 10UL ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  fd_bmtree_node_t root[1];
  fd_bmtree_node_t leaf[1];
  fd_bmtree_hash_leaf( leaf, (uchar const *)shred + sizeof(fd_ed25519_sig_t), merkle_protected_sz, FD_BMTREE_LONG_PREFIX_SZ );
  fd_shred_merkle_t const * proof = fd_shred_merkle_nodes( shred );
  fd_bmtree_commit_t * tree;
  tree = fd_bmtree_commit_init( bmtree_mem, FD_SHRED_MERKLE_NODE_SZ, FD_BMTREE_LONG_PREFIX_SZ, 10UL );
  int rv = fd_bmtree_commitp_insert_with_proof( tree, shred_idx, leaf, (uchar const *)proof, tree_depth, root );
  FD_TEST( rv );

  test_signer( sign_ctx, shred->signature, root->hash );
}

static void
test_shred_reject( void ) {
  signer_ctx_t signer_ctx[ 1 ];
  signer_ctx_init( signer_ctx, test_private_key );

  FD_TEST( _shredder==fd_shredder_new( _shredder, test_signer, signer_ctx, (ushort)SHRED_VER ) );
  fd_shredder_t * shredder = fd_shredder_join( _shredder );           FD_TEST( shredder );

  uchar const * pubkey = test_private_key+32UL;

  fd_entry_batch_meta_t meta[1];
  fd_memset( meta, 0, sizeof(fd_entry_batch_meta_t) );
  meta->parent_offset  = 1UL;
  meta->block_complete = 1;

  FD_TEST( fd_shredder_init_batch( shredder, test_bin, test_bin_sz, 2UL, meta ) );

  fd_fec_set_t _set[ 1 ];
  fd_fec_set_t out_sets[ 4UL ];
  uchar * ptr = fec_set_memory;
  ptr = allocate_fec_set( _set, ptr );

  for( ulong i=0UL; i<4UL; i++ )  ptr = allocate_fec_set( out_sets+i, ptr );

  fd_fec_resolver_t * r = fd_fec_resolver_join( fd_fec_resolver_new( res_mem, NULL, NULL, 2UL, 1UL, 1UL, 1UL, out_sets, SHRED_VER, MAX ) );

  fd_fec_set_t const * out_fec[1];
  fd_shred_t   const * out_shred[1];

#define SIGN_ACCEPT( shred )                                                                                        \
  fake_resign( shred, signer_ctx );                                                                                 \
  FD_TEST( fd_shred_parse( (uchar const *)shred, 2048UL ) );                                                        \
  FD_TEST( FD_FEC_RESOLVER_SHRED_OKAY==fd_fec_resolver_add_shred( r, shred, 2048UL, pubkey, out_fec, out_shred ) );

#define SIGN_REJECT( shred )                                                                                           \
  fake_resign( shred, signer_ctx );                                                                                    \
  FD_TEST( NULL==fd_shred_parse( (uchar const *)shred, 2048UL ) ||                                                     \
           FD_FEC_RESOLVER_SHRED_REJECTED==fd_fec_resolver_add_shred( r, shred, 2048UL, pubkey, out_fec, out_shred ) );

  fd_fec_set_t * set = fd_shredder_next_fec_set( shredder, _set );
  fd_shred_t * shred;
  shred = (fd_shred_t *)fd_shred_parse( set->data_shreds[ 0 ], 2048UL );   FD_TEST( shred );
  /* Test basic setup is working. */
  FD_TEST( FD_FEC_RESOLVER_SHRED_OKAY==fd_fec_resolver_add_shred( r, shred, 2048UL, pubkey, out_fec, out_shred ) );

  shred = (fd_shred_t *)fd_shred_parse( set->data_shreds[ 1 ], 2048UL );   FD_TEST( shred );
  (*(uchar *)fd_shred_data_payload( shred ))++;
  /* Data modified but signature not updated */
  FD_TEST( FD_FEC_RESOLVER_SHRED_REJECTED==fd_fec_resolver_add_shred( r, shred, 2048UL, pubkey, out_fec, out_shred ) );

  /* fake_resign fixed up the signature. */
  SIGN_ACCEPT( shred );

  shred = (fd_shred_t *)fd_shred_parse( set->data_shreds[ 2 ], 2048UL );   FD_TEST( shred );
  shred->idx = MAX-1UL;  shred->fec_set_idx = MAX-20UL;  SIGN_ACCEPT( shred );
  shred->idx = MAX;      shred->fec_set_idx = MAX-20UL;  SIGN_REJECT( shred );
  shred->idx = MAX+1UL;  shred->fec_set_idx = MAX-20UL;  SIGN_REJECT( shred );

  shred = (fd_shred_t *)fd_shred_parse( set->data_shreds[ 3 ], 2048UL );   FD_TEST( shred );
  shred->data.flags = 0x80;    SIGN_REJECT( shred );/* block complete but not batch complete */

  shred = (fd_shred_t *)fd_shred_parse( set->data_shreds[ 4 ], 2048UL );   FD_TEST( shred );
  shred->data.parent_off = 2;                    SIGN_ACCEPT( shred ); /* Slot == 2 */
  shred->data.parent_off = 0;                    SIGN_REJECT( shred );
  shred->data.parent_off = 3;                    SIGN_REJECT( shred );
  shred->data.parent_off = 0; shred->slot = 0UL; SIGN_ACCEPT( shred );
  shred->data.parent_off = 1;                    SIGN_REJECT( shred );

  shred = (fd_shred_t *)fd_shred_parse( set->data_shreds[ 5 ], 2048UL );   FD_TEST( shred );
  shred->idx = 1U; shred->fec_set_idx = 1U;     SIGN_ACCEPT( shred );
  shred->idx = 8U; shred->fec_set_idx = 1U;     SIGN_ACCEPT( shred );
  /* The following two are so malformed that fake_resign chokes on them.
     No matter, because shred_parse rejects them. */
  shred->idx = 1U; shred->fec_set_idx = 8U;     FD_TEST( NULL==fd_shred_parse( (uchar const *)shred, 2048UL ) );
  shred->idx = 7U; shred->fec_set_idx = 8U;     FD_TEST( NULL==fd_shred_parse( (uchar const *)shred, 2048UL ) );

  /* Now parity shred tests */
  shred = (fd_shred_t *)fd_shred_parse( set->parity_shreds[ 0 ], 2048UL );   FD_TEST( shred );
  shred->idx = MAX-2UL;  shred->code.code_cnt = 1UL;  SIGN_ACCEPT( shred );
  shred->idx = MAX;      shred->code.code_cnt = 1UL;  SIGN_REJECT( shred );
  shred->idx = MAX+1UL;  shred->code.code_cnt = 1UL;  SIGN_REJECT( shred );

  shred = (fd_shred_t *)fd_shred_parse( set->parity_shreds[ 1 ], 2048UL );   FD_TEST( shred );
  shred->code.data_cnt =  68UL;  shred->code.code_cnt =  68UL;  SIGN_REJECT( shred );
  shred->code.data_cnt = 256UL;  shred->code.code_cnt = 256UL;  SIGN_REJECT( shred );
  shred->code.data_cnt =   0UL;  shred->code.code_cnt =  32UL;  SIGN_REJECT( shred );
  shred->code.data_cnt =  32UL;  shred->code.code_cnt =   0UL;  SIGN_REJECT( shred );

  shred = (fd_shred_t *)fd_shred_parse( set->parity_shreds[ 2 ], 2048UL );   FD_TEST( shred );
  shred->fec_set_idx = 12U;                                         SIGN_ACCEPT( shred );
  shred->fec_set_idx = MAX-3UL;  shred->code.data_cnt = 2UL;        SIGN_ACCEPT( shred );
  shred->fec_set_idx = MAX-2UL;  shred->code.data_cnt = 3UL;        SIGN_REJECT( shred );
  /* This one is also so malformed that fake_resign can't sign it.  The
     Merkle tree required to sign an FEC set that large wouldn't fit. */
  shred->fec_set_idx = UINT_MAX; shred->code.data_cnt = USHORT_MAX; FD_TEST( NULL==fd_shred_parse( (uchar const *)shred, 2048UL ) );

  shred = (fd_shred_t *)fd_shred_parse( set->parity_shreds[ 3 ], 2048UL );   FD_TEST( shred );
  shred->idx = shred->code.idx - 1U;                                      SIGN_REJECT( shred );
  shred->idx = MAX-5UL;  shred->code.idx = 0;  shred->code.code_cnt = 4U; SIGN_ACCEPT( shred );
  shred->idx = MAX-5UL;  shred->code.idx = 0;  shred->code.code_cnt = 5U; SIGN_REJECT( shred );
  shred->idx = MAX-5UL;  shred->code.idx = 1;  shred->code.code_cnt = 5U; SIGN_ACCEPT( shred );

  shred = (fd_shred_t *)fd_shred_parse( set->parity_shreds[ 4 ], 2048UL );   FD_TEST( shred );
  shred->code.idx = 4; shred->code.code_cnt = 5;            SIGN_ACCEPT( shred );
  shred->code.idx = 4; shred->code.code_cnt = 4;            SIGN_REJECT( shred );
}


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_metrics_register( (ulong *)fd_metrics_new( metrics_scratch, 0UL, 0UL ) );

  (void)perf_test;

  test_interleaved();
  test_one_batch();
  test_rolloff();
  test_new_formats();
  test_shred_version();
  test_shred_reject();


  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
