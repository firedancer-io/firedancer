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
  r1 = fd_fec_resolver_join( fd_fec_resolver_new( res_mem+0UL*foot, NULL, NULL, 2UL, 1UL, 1UL, 1UL, out_sets,     SHRED_VER ) );
  r2 = fd_fec_resolver_join( fd_fec_resolver_new( res_mem+1UL*foot, NULL, NULL, 2UL, 1UL, 1UL, 1UL, out_sets+4UL, SHRED_VER ) );
  r3 = fd_fec_resolver_join( fd_fec_resolver_new( res_mem+2UL*foot, NULL, NULL, 2UL, 1UL, 1UL, 1UL, out_sets+8UL, SHRED_VER ) );

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

  fd_fec_resolver_t * resolver = fd_fec_resolver_join( fd_fec_resolver_new( res_mem, NULL, NULL, 2UL, 1UL, 1UL, 1UL, out_sets, SHRED_VER ) );
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
  resolver = fd_fec_resolver_join( fd_fec_resolver_new( res_mem, NULL, NULL, 2UL, 1UL, 1UL, 8UL, out_sets, SHRED_VER ) );
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
  resolver = fd_fec_resolver_join( fd_fec_resolver_new( res_mem, test_signer, signer_ctx, 2UL, 1UL, 1UL, 8UL, out_sets, 1 ) );

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

  fd_fec_resolver_t * r = fd_fec_resolver_join( fd_fec_resolver_new( res_mem, NULL, NULL, 2UL, 1UL, 1UL, 1UL, out_sets, SHRED_VER ) );

  fd_fec_set_t const * out_fec[1];
  fd_shred_t   const * out_shred[1];

  fd_fec_set_t * set = fd_shredder_next_fec_set( shredder, _set );
  fd_shred_t const * shred = fd_shred_parse( set->data_shreds[ 0 ], 2048UL );
  FD_TEST( shred );
  FD_TEST( FD_FEC_RESOLVER_SHRED_REJECTED==fd_fec_resolver_add_shred( r, shred, 2048UL, pubkey, out_fec, out_shred ) );

  fd_fec_resolver_delete( fd_fec_resolver_leave( r ) );
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


  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
