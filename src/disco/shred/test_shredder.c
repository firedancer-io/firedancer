#include "fd_shredder.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../ballet/hex/fd_hex.h"


/* An entry batch of 64 entries with 20 transactions per entry takes up
   about 256 kB, for about 200B/txn, which seems reasonable.  We'll do a
   10 MB entry batch, which is about 50k transactions. */
#define PERF_TEST_SZ (10UL*1024UL*1024UL)
#define PERF_TEST2_SZ (1UL*1024UL*1024UL)
uchar perf_test_entry_batch[ PERF_TEST_SZ ];

/* Data used in test_skip_batch */
#define SKIP_TEST_SZ (1024UL*1024UL)
uchar skip_test_data[ SKIP_TEST_SZ ];

uchar fec_set_memory_1[ 2048UL * FD_REEDSOL_DATA_SHREDS_MAX   ];
uchar fec_set_memory_2[ 2048UL * FD_REEDSOL_PARITY_SHREDS_MAX ];

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

#if FD_HAS_HOSTED
#include "../../util/net/fd_pcap.h"
#include <stdio.h>

FD_IMPORT_BINARY( test_pcap,        "src/disco/shred/fixtures/demo-shreds.pcap" );
FD_IMPORT_BINARY( test_bin,         "src/disco/shred/fixtures/demo-shreds.bin"  );

static void
test_shredder_pcap( void ) {
  signer_ctx_t signer_ctx[ 1 ];
  signer_ctx_init( signer_ctx, test_private_key );

  FD_TEST( _shredder==fd_shredder_new( _shredder, test_signer, signer_ctx, (ushort)0 ) );
  fd_shredder_t * shredder = fd_shredder_join( _shredder );           FD_TEST( shredder );

  /* Manually counted values from the pcap */
  FD_TEST( fd_shredder_count_fec_sets(      test_bin_sz, FD_SHRED_TYPE_MERKLE_DATA ) ==   7UL );
  FD_TEST( fd_shredder_count_data_shreds(   test_bin_sz, FD_SHRED_TYPE_MERKLE_DATA ) == 240UL );
  FD_TEST( fd_shredder_count_parity_shreds( test_bin_sz, FD_SHRED_TYPE_MERKLE_DATA ) == 240UL );


  FILE * file = fmemopen( (void *)test_pcap, test_pcap_sz, "rb" );    FD_TEST( file );

  fd_pcap_iter_t * pcap = fd_pcap_iter_new( file );                   FD_TEST( pcap );

  fd_entry_batch_meta_t meta[1];
  fd_memset( meta, 0, sizeof(fd_entry_batch_meta_t) );
  meta->block_complete = 1;

  /* The pcap has all the data shreds before the parity shreds, so we'll
     make two passes over the data, one to check the data shreds, and
     the other to check the parity shreds. */
  FD_TEST( fd_shredder_init_batch( shredder, test_bin, test_bin_sz, 0UL, meta ) );
  for( ulong i=0UL; i<7UL; i++ ) {
    fd_fec_set_t _set[ 1 ];

    for( ulong j=0UL; j<FD_REEDSOL_DATA_SHREDS_MAX;   j++ ) _set->data_shreds[   j ] = fec_set_memory_1 + 2048UL*j;
    for( ulong j=0UL; j<FD_REEDSOL_PARITY_SHREDS_MAX; j++ ) _set->parity_shreds[ j ] = fec_set_memory_2 + 2048UL*j;

    fd_fec_set_t * set = fd_shredder_next_fec_set( shredder, _set, /* chained */ NULL );
    FD_TEST( set );

    FD_TEST( set->data_shred_cnt  ==(i<6UL ? 32UL : 48UL) );

    uchar packet[ 2048UL ];
    long ts[ 1 ];
    for( ulong j=0UL; j<set->data_shred_cnt; j++ ) {
      ulong pkt_sz = fd_pcap_iter_next( pcap, packet, 2048UL, ts );   FD_TEST( pkt_sz );

      if( !fd_memeq( packet+42UL, set->data_shreds[ j ], pkt_sz-42UL ) ) {
        FD_LOG_HEXDUMP_NOTICE(( "pcap",      packet+42UL,         pkt_sz-42UL ));
        FD_LOG_HEXDUMP_NOTICE(( "generated", set->data_shreds[j], pkt_sz-42UL ));
        FD_LOG_ERR(( "Batch %lu, data shred %lu did not match.", i, j ));
      }
    }
  }
  FD_TEST( fd_shredder_fini_batch( shredder ) );

  /* Start a dummy batch with a different slot number to reset all the
     indices. */
  FD_TEST( fd_shredder_init_batch( shredder, test_bin, test_bin_sz, 1UL, meta ) );
  FD_TEST( fd_shredder_fini_batch( shredder ) );

  FD_TEST( fd_shredder_init_batch( shredder, test_bin, test_bin_sz, 0UL, meta ) );
  for( ulong i=0UL; i<7UL; i++ ) {
    fd_fec_set_t _set[ 1 ];

    for( ulong j=0UL; j<FD_REEDSOL_DATA_SHREDS_MAX;   j++ ) _set->data_shreds[   j ] = fec_set_memory_1 + 2048UL*j;
    for( ulong j=0UL; j<FD_REEDSOL_PARITY_SHREDS_MAX; j++ ) _set->parity_shreds[ j ] = fec_set_memory_2 + 2048UL*j;

    fd_fec_set_t * set = fd_shredder_next_fec_set( shredder, _set, /* chained */ NULL );
    FD_TEST( set );

    FD_TEST( set->parity_shred_cnt==(i<6UL ? 32UL : 48UL) );

    uchar packet[ 2048UL ];
    long ts[ 1 ];
    for( ulong j=0UL; j<set->parity_shred_cnt; j++ ) {
      ulong pkt_sz = fd_pcap_iter_next( pcap, packet, 2048UL, ts );   FD_TEST( pkt_sz );

      if( !fd_memeq( packet+42UL, set->parity_shreds[ j ], pkt_sz-42UL ) ) {
        FD_LOG_HEXDUMP_NOTICE(( "pcap",      packet+42UL,           pkt_sz-42UL ));
        FD_LOG_HEXDUMP_NOTICE(( "generated", set->parity_shreds[j], pkt_sz-42UL ));
        FD_LOG_ERR(( "Batch %lu, parity shred %lu did not match.", i, j ));
      }
    }
  }
  FD_TEST( fd_shredder_fini_batch( shredder ) );



  FD_TEST( fd_pcap_iter_delete( pcap ) );
  FD_TEST( !fclose( file ) );
}

#endif /* FD_HAS_HOSTED */


static void
test_skip_batch( void ) {
  fd_rng_t _rng[ 1 ]; fd_rng_t * r = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  signer_ctx_t signer_ctx[ 1 ];
  signer_ctx_init( signer_ctx, test_private_key );

  #define SHREDDERS 4

  FD_TEST( SHREDDERS>0 );

  fd_shredder_t   _shredders[ SHREDDERS ];
  fd_shredder_t *  shredders[ SHREDDERS ];
  /* Initialize all the shredders */
  for( ulong i=0; i<SHREDDERS; i++ ) {
    FD_TEST( &_shredders[ i ]==fd_shredder_new( &_shredders[ i ], test_signer, signer_ctx, (ushort)0 ) );
    shredders[ i ] = fd_shredder_join( &_shredders[ i ] );
    FD_TEST( shredders[ i ] );
  }

  fd_entry_batch_meta_t meta[ 1 ];
  fd_memset( meta, 0, sizeof( fd_entry_batch_meta_t ) );

  uchar data_shreds  [ 2048UL*FD_REEDSOL_DATA_SHREDS_MAX   ] = { 0 };
  uchar parity_shreds[ 2048UL*FD_REEDSOL_PARITY_SHREDS_MAX ] = { 0 };

  fd_fec_set_t _set[ 1 ];
  for( ulong j=0UL; j<FD_REEDSOL_DATA_SHREDS_MAX;   j++ ) _set->data_shreds[   j ] = data_shreds + 2048UL*j;
  for( ulong j=0UL; j<FD_REEDSOL_PARITY_SHREDS_MAX; j++ ) _set->parity_shreds[ j ] = parity_shreds + 2048UL*j;

  ulong data_shred_cnt   = 0;
  ulong parity_shred_cnt = 0;
  ulong idx  = 0UL;
  ulong slot = 1UL;

  for( ulong i=0; i<SKIP_TEST_SZ; i++ ) skip_test_data[ i ] = fd_rng_uchar( r );

  /* Randomly choose a shredder to process a batch until the data buffer is exhausted. */
  while( idx<SKIP_TEST_SZ ) {
    ulong sz        = fd_rng_ulong_roll( r, 100000UL )+1UL;
    ulong batch_sz  = fd_ulong_if( idx+sz>SKIP_TEST_SZ, SKIP_TEST_SZ-idx, sz );
    ulong shredder  = fd_rng_ulong_roll( r, SHREDDERS );
    for( ulong i=0; i<SHREDDERS; i++ ) {
      if( FD_UNLIKELY( i==shredder ) ) {
        FD_TEST( fd_shredder_init_batch( shredders[ i ], skip_test_data+idx, batch_sz, slot, meta ) );
        ulong fec_sets = fd_shredder_count_fec_sets( batch_sz, FD_SHRED_TYPE_MERKLE_DATA );
        for( ulong j=0; j<fec_sets; j++ ) {
          FD_TEST( fd_shredder_next_fec_set( shredders[ i ], _set, /* chained */ NULL ) );
          data_shred_cnt   += _set->data_shred_cnt;
          parity_shred_cnt += _set->parity_shred_cnt;
        }
        FD_TEST( fd_shredder_fini_batch( shredders[ i ] ) );
      } else {
        FD_TEST( fd_shredder_skip_batch( shredders[ i ], batch_sz, slot, FD_SHRED_TYPE_MERKLE_DATA ));
      }
    }
    for( ulong i=0; i<SHREDDERS; i++ ) {
      FD_TEST( shredders[ i ]->data_idx_offset==data_shred_cnt );
      FD_TEST( shredders[ i ]->parity_idx_offset==parity_shred_cnt );
    }
    idx  += batch_sz;
    /* Increment the slot every 200_000 bytes. */
    if( FD_UNLIKELY( idx/200000UL>=slot ) ) {
      slot++;
      data_shred_cnt   = 0;
      parity_shred_cnt = 0;
    }
  }

  /* Process a set with the first shredder. */
  memset( data_shreds,   0, FD_REEDSOL_DATA_SHREDS_MAX*2048UL );
  memset( parity_shreds, 0, FD_REEDSOL_PARITY_SHREDS_MAX*2048UL );
  FD_TEST( fd_shredder_init_batch( shredders[ 0 ], skip_test_data, idx, slot, meta ) );
  FD_TEST( fd_shredder_next_fec_set( shredders[ 0 ], _set, /* chained */ NULL ) );
  FD_TEST( fd_shredder_fini_batch( shredders[ 0 ] ) );

  /* Make all the other shredders process the same data and compare the outputs. */
  fd_fec_set_t _temp_set[ 1 ];
  uchar temp_data_shreds  [ 2048UL*FD_REEDSOL_DATA_SHREDS_MAX   ] = { 0 };
  uchar temp_parity_shreds[ 2048UL*FD_REEDSOL_PARITY_SHREDS_MAX ] = { 0 };
  for( ulong j=0UL; j<FD_REEDSOL_DATA_SHREDS_MAX;   j++ ) _temp_set->data_shreds[   j ] = temp_data_shreds + 2048UL*j;
  for( ulong j=0UL; j<FD_REEDSOL_PARITY_SHREDS_MAX; j++ ) _temp_set->parity_shreds[ j ] = temp_parity_shreds + 2048UL*j;
  for( ulong i=1UL; i<SHREDDERS; i++ ) {
    memset( temp_data_shreds,   0, FD_REEDSOL_DATA_SHREDS_MAX*2048UL );
    memset( temp_parity_shreds, 0, FD_REEDSOL_PARITY_SHREDS_MAX*2048UL );
    FD_TEST( fd_shredder_init_batch( shredders[ i ], skip_test_data, idx, slot, meta ) );
    FD_TEST( fd_shredder_next_fec_set( shredders[ i ], _temp_set, /* chained */ NULL ) );
    FD_TEST( fd_shredder_fini_batch( shredders[ i ] ) );

    FD_TEST( _set->data_shred_cnt==_temp_set->data_shred_cnt );
    FD_TEST( _set->parity_shred_cnt==_temp_set->parity_shred_cnt );

    for( ulong j=0UL; j<_temp_set->data_shred_cnt; j++ )
      FD_TEST( !memcmp( _set->data_shreds[ j ], _temp_set->data_shreds[ j ], 2048UL ) );
    for( ulong j=0UL; j<_temp_set->parity_shred_cnt; j++ )
      FD_TEST( !memcmp( _set->parity_shreds[ j ], _temp_set->parity_shreds[ j ], 2048UL ) );
  }

  #undef SHREDDERS
}

static void
_internal_test_shredder_count( ulong type ) {
  FD_TEST( fd_shredder_count_data_shreds(   0UL, type ) ==  1UL );
  FD_TEST( fd_shredder_count_parity_shreds( 0UL, type ) == 17UL );
  FD_TEST( fd_shredder_count_fec_sets(      0UL, type ) ==  1UL );

  int is_chained  = fd_shred_is_chained( type );
  int is_resigned = fd_shred_is_resigned( type );

  ulong overhead = ( (ulong)is_chained*32UL + (ulong)is_resigned*64UL );

  for( ulong data_sz=1UL; data_sz<1000000UL; data_sz++ ) {
    ulong fec_sets = 0UL;
    ulong data_shreds = 0UL;
    ulong parity_shreds = 0UL;
    ulong x = data_sz;
    /* Reference implementation taken from make_shreds_from_data in Rust
       code */
    ulong data_buffer_size = 995UL - overhead;
    ulong chunk_size = 31840UL - overhead*32UL;
    while( x>=2UL*chunk_size || x==chunk_size ) {
      fec_sets++;
      data_shreds += (chunk_size + data_buffer_size - 1UL) / data_buffer_size;
      parity_shreds += (chunk_size + data_buffer_size - 1UL) / data_buffer_size;
      x -= chunk_size;
    }
    if( x>0UL || data_shreds==0UL ) {
      ulong num_data_shreds, num_parity_shreds;
      for( ulong proof_size=1UL; proof_size<32UL; proof_size++ ) {
        data_buffer_size = 1115UL - 20UL * proof_size - overhead;
        num_data_shreds   = fd_ulong_max( 1UL, (x + data_buffer_size-1UL)/data_buffer_size );
        num_parity_shreds = (num_data_shreds>32UL ? num_data_shreds : fd_shredder_data_to_parity_cnt[ num_data_shreds ] );
        if( fd_bmtree_depth( num_data_shreds+num_parity_shreds )-1UL == proof_size ) break;
      }
      data_shreds   += num_data_shreds;
      parity_shreds += num_parity_shreds;
      fec_sets++;
    }

    FD_TEST( fd_shredder_count_data_shreds(   data_sz, type ) ==   data_shreds );
    FD_TEST( fd_shredder_count_parity_shreds( data_sz, type ) == parity_shreds );
    FD_TEST( fd_shredder_count_fec_sets(      data_sz, type ) ==      fec_sets );
  }

  ulong _data_sz=0UL;
  while( fd_shredder_count_fec_sets( _data_sz, type )==1UL ) {
    FD_TEST( fd_shredder_count_data_shreds( _data_sz, type ) <= FD_REEDSOL_DATA_SHREDS_MAX );
    FD_TEST( fd_shredder_count_parity_shreds( _data_sz, type ) <= FD_REEDSOL_PARITY_SHREDS_MAX );
    _data_sz++;
  }

  /* Now check to make sure the shredder always produces that many
     shreds. */

  fd_entry_batch_meta_t meta[1];
  fd_memset( meta, 0, sizeof(fd_entry_batch_meta_t) );
  signer_ctx_t signer_ctx[ 1 ];
  signer_ctx_init( signer_ctx, test_private_key );

  FD_TEST( _shredder==fd_shredder_new( _shredder, test_signer, signer_ctx, (ushort)0 ) );
  fd_shredder_t * shredder = fd_shredder_join( _shredder );           FD_TEST( shredder );

  fd_fec_set_t _set[ 1 ];
  for( ulong j=0UL; j<FD_REEDSOL_DATA_SHREDS_MAX;   j++ ) _set->data_shreds[   j ] = fec_set_memory_1 + 2048UL*j;
  for( ulong j=0UL; j<FD_REEDSOL_PARITY_SHREDS_MAX; j++ ) _set->parity_shreds[ j ] = fec_set_memory_2 + 2048UL*j;

  uchar _chained_merkle_root[32] = { 0 };
  uchar * chained_merkle_root = is_chained ? _chained_merkle_root : NULL;
  meta->block_complete = is_resigned;

  ulong slot=0UL;
  for( ulong sz=1UL; sz<100000UL; sz++ ) {
    fd_shredder_init_batch( shredder, perf_test_entry_batch, sz, slot++, meta );

    ulong data_shred_cnt   = 0UL;
    ulong parity_shred_cnt = 0UL;
    ulong sets_cnt = fd_shredder_count_fec_sets( sz, type );
    for( ulong j=0UL; j<sets_cnt; j++ ) {
      fd_fec_set_t * set = fd_shredder_next_fec_set( shredder, _set, chained_merkle_root );
      FD_TEST( set );

      data_shred_cnt   += set->data_shred_cnt;
      parity_shred_cnt += set->parity_shred_cnt;
    }
    FD_TEST( !fd_shredder_next_fec_set( shredder, _set, chained_merkle_root ) );
    fd_shredder_fini_batch( shredder );

    FD_TEST( data_shred_cnt  ==fd_shredder_count_data_shreds  ( sz, type ) );
    FD_TEST( parity_shred_cnt==fd_shredder_count_parity_shreds( sz, type ) );
  }
}

static void
test_shredder_count( void ) {
  _internal_test_shredder_count( FD_SHRED_TYPE_MERKLE_DATA );
}

static void
test_shredder_count_chained( void ) {
  _internal_test_shredder_count( FD_SHRED_TYPE_MERKLE_DATA_CHAINED );
}

static void
test_shredder_count_resigned( void ) {
  _internal_test_shredder_count( FD_SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED );
}

static void
test_chained_merkle_shreds( void ) {
  uchar expected_final_chained_merkle_root[ 32 ] = { 0 };
  uchar chained_merkle_root[ 32 ] = { 0 };

  const uchar canary = 0x42;

  /* Initial and expected final merkle root */
  fd_hex_decode( chained_merkle_root, "0102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00", 32 );
  fd_hex_decode( expected_final_chained_merkle_root, "cb030876030cf4d3a1e5b667c08a8c35d3073ab3d1fb19679e29603d75fc2529", 32 );

  /* Settings so that we get 32 data + 32 parity shreds */
  ulong data_sz = 30000;
  FD_TEST( fd_shredder_count_data_shreds(   data_sz, FD_SHRED_TYPE_MERKLE_DATA_CHAINED ) == 32 );
  FD_TEST( fd_shredder_count_parity_shreds( data_sz, FD_SHRED_TYPE_MERKLE_DATA_CHAINED ) == 32 );
  FD_TEST( fd_shredder_count_fec_sets(      data_sz, FD_SHRED_TYPE_MERKLE_DATA_CHAINED ) ==  1 );

  /* Initialize all the things */
  for( ulong i=0UL; i<data_sz; i++ )  perf_test_entry_batch[ i ] = (uchar)i;

  fd_entry_batch_meta_t meta[1];
  fd_memset( meta, 0, sizeof(fd_entry_batch_meta_t) );
  signer_ctx_t signer_ctx[ 1 ];
  signer_ctx_init( signer_ctx, test_private_key );

  FD_TEST( _shredder==fd_shredder_new( _shredder, test_signer, signer_ctx, (ushort)6051 ) );
  fd_shredder_t * shredder = fd_shredder_join( _shredder );           FD_TEST( shredder );

  fd_fec_set_t _set[ 1 ];
  for( ulong j=0UL; j<FD_REEDSOL_DATA_SHREDS_MAX;   j++ ) _set->data_shreds[   j ] = fec_set_memory_1 + 2048UL*j;
  for( ulong j=0UL; j<FD_REEDSOL_PARITY_SHREDS_MAX; j++ ) _set->parity_shreds[ j ] = fec_set_memory_2 + 2048UL*j;

  /* memset with canary */
  memset( fec_set_memory_1, canary, sizeof( fec_set_memory_1 ) );
  memset( fec_set_memory_2, canary, sizeof( fec_set_memory_2 ) );

#define MAX_SLOTS (4UL)
#define MAX_SETS (10UL)

  /* Actual test: create shreds for n slots, the same way the shred tile does it */
  fd_fec_set_t * set = NULL;
  for( ulong slot=10UL; slot<10UL+MAX_SLOTS; slot++ ) {

    /* Simulate skipping slot #1 */
    if( slot==11UL ) slot=12UL;
    meta->parent_offset = slot==12UL ? 2 : 1;

    for( ulong setid=0UL; setid<MAX_SETS; setid++ ) {
      meta->block_complete = (setid==(MAX_SETS-1));

      /* Create set like shred tile does.
         This should take care of numbering shreds correctly, updating chained_merkle_root,
         etc. */
      fd_shredder_init_batch( shredder, perf_test_entry_batch, data_sz, slot, meta );
      set = fd_shredder_next_fec_set( shredder, _set, chained_merkle_root );
      fd_shredder_fini_batch( shredder );

      /* Per-slot checks */
      FD_TEST( set );
      FD_TEST( set->data_shred_cnt>=32 );
      FD_TEST( set->parity_shred_cnt>=32 );

      for( ulong j=0; j<set->data_shred_cnt; j++ ) {
        fd_shred_t const * shred;

        /* Simple test that we didn't overflow */
        FD_TEST( *(set->data_shreds[ j ]+FD_SHRED_MIN_SZ) == canary );

        /* Test that data indexes are correct */
        shred = (fd_shred_t const *)set->data_shreds[ j ];
        FD_TEST( shred->idx==setid*32 + j );
        FD_TEST( shred->fec_set_idx==setid*32 );
        FD_TEST( fd_shred_is_resigned( fd_shred_type( shred->variant ) )==(setid==(MAX_SETS-1)) );

        FD_TEST( fd_shred_parse( (const uchar *)shred, FD_SHRED_MIN_SZ ) );
      }

      for( ulong j=0; j<set->parity_shred_cnt; j++ ) {
        fd_shred_t const * shred;

        /* Simple test that we didn't overflow */
        FD_TEST( *(set->parity_shreds[ j ]+FD_SHRED_MAX_SZ) == canary );

        /* Test that parity indexes are correct */
        shred = (fd_shred_t const *)set->parity_shreds[ j ];
        FD_TEST( shred->idx==setid*32 + j );
        FD_TEST( shred->fec_set_idx==setid*32 );
        FD_TEST( fd_shred_is_resigned( fd_shred_type( shred->variant ) )==(setid==(MAX_SETS-1)) );

        FD_TEST( fd_shred_parse( (const uchar *)shred, FD_SHRED_MAX_SZ ) );
      }
    }
  }

  /* Final checks */
  FD_TEST( fd_memeq( chained_merkle_root, expected_final_chained_merkle_root, 32 ) );
}

static void
perf_test( void ) {
  for( ulong i=0UL; i<PERF_TEST_SZ; i++ )  perf_test_entry_batch[ i ] = (uchar)i;

  fd_entry_batch_meta_t meta[1];
  fd_memset( meta, 0, sizeof(fd_entry_batch_meta_t) );

  signer_ctx_t signer_ctx[ 1 ];
  signer_ctx_init( signer_ctx, test_private_key );

  FD_TEST( _shredder==fd_shredder_new( _shredder, test_signer, signer_ctx, (ushort)0 ) );
  fd_shredder_t * shredder = fd_shredder_join( _shredder );           FD_TEST( shredder );

  fd_fec_set_t _set[ 1 ];
  for( ulong j=0UL; j<FD_REEDSOL_DATA_SHREDS_MAX;   j++ ) _set->data_shreds[   j ] = fec_set_memory_1 + 2048UL*j;
  for( ulong j=0UL; j<FD_REEDSOL_PARITY_SHREDS_MAX; j++ ) _set->parity_shreds[ j ] = fec_set_memory_2 + 2048UL*j;

  ulong iterations = 100UL;
  long dt = -fd_log_wallclock();
  for( ulong iter=0UL; iter<iterations; iter++ ) {
    fd_shredder_init_batch( shredder, perf_test_entry_batch, PERF_TEST_SZ, 0UL, meta );

    ulong sets_cnt = fd_shredder_count_fec_sets( PERF_TEST_SZ, FD_SHRED_TYPE_MERKLE_DATA );
    for( ulong j=0UL; j<sets_cnt; j++ ) {
      fd_shredder_next_fec_set( shredder, _set, /* chained */ NULL );
    }
    fd_shredder_fini_batch( shredder );
  }
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "%li ns/10 MB entry batch = %.3f Gbps", dt/(long)iterations, (double)(8UL * iterations * PERF_TEST_SZ)/(double)dt ));

}


static void
perf_test2( void ) {
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( "gigantic" ), 1UL, 0UL, "perf_test2", 0UL );
  FD_TEST( wksp );
  uchar * entry_batch = fd_wksp_laddr_fast( wksp, fd_wksp_alloc( wksp, 128UL, PERF_TEST2_SZ, 2UL ) );
  uchar * fec_memory  = fd_wksp_laddr_fast( wksp, fd_wksp_alloc( wksp, 128UL, (FD_REEDSOL_DATA_SHREDS_MAX + FD_REEDSOL_PARITY_SHREDS_MAX)*1800UL, 3UL ) );

  for( ulong i=0UL; i<PERF_TEST2_SZ; i++ )  entry_batch[ i ] = (uchar)i;

  fd_entry_batch_meta_t meta[1];
  fd_memset( meta, 0, sizeof(fd_entry_batch_meta_t) );

  signer_ctx_t signer_ctx[ 1 ];
  signer_ctx_init( signer_ctx, test_private_key );

  FD_TEST( _shredder==fd_shredder_new( _shredder, test_signer, signer_ctx, (ushort)0 ) );
  fd_shredder_t * shredder = fd_shredder_join( _shredder );           FD_TEST( shredder );

  fd_fec_set_t _set[ 1 ];
  for( ulong j=0UL; j<FD_REEDSOL_DATA_SHREDS_MAX;   j++ ) _set->data_shreds[   j ] = fec_memory + 1800UL*j;
  for( ulong j=0UL; j<FD_REEDSOL_PARITY_SHREDS_MAX; j++ ) _set->parity_shreds[ j ] = fec_memory + 1800UL*j + 1800*FD_REEDSOL_DATA_SHREDS_MAX;

  ulong iterations = 30UL;
  ulong bytes_produced = 0UL;
  long dt = -fd_log_wallclock();
  for( ulong iter=0UL; iter<iterations; iter++ ) {
    fd_shredder_init_batch( shredder, entry_batch, PERF_TEST2_SZ, 0UL, meta );

    ulong sets_cnt = fd_shredder_count_fec_sets( PERF_TEST2_SZ, FD_SHRED_TYPE_MERKLE_DATA );
    for( ulong j=0UL; j<sets_cnt; j++ ) {
      fd_shredder_next_fec_set( shredder, _set, /* chained */ NULL );
      bytes_produced += _set->data_shred_cnt * FD_SHRED_MIN_SZ + _set->parity_shred_cnt * FD_SHRED_MAX_SZ;
    }
    fd_shredder_fini_batch( shredder );
  }
  dt += fd_log_wallclock();

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "%li ns/1 MB entry batch = consuming %.3f Gbps and producing %.3f Gbps", dt/(long)iterations, (double)(8UL * iterations * PERF_TEST2_SZ)/(double)dt, (double)(8UL*bytes_produced)/(double)dt ));

}


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( FD_FEC_SET_MAX_BMTREE_DEPTH == fd_bmtree_depth( FD_REEDSOL_DATA_SHREDS_MAX + FD_REEDSOL_PARITY_SHREDS_MAX ) );

  if( sizeof(fd_shredder_t) != fd_shredder_footprint() )
    FD_LOG_WARNING(( "sizeof() %lu, footprint: %lu", sizeof(fd_shredder_t), fd_shredder_footprint() ));
  FD_TEST( sizeof(fd_shredder_t) == fd_shredder_footprint() );

  test_skip_batch();
  test_shredder_count();
  test_shredder_count_chained();
  test_shredder_count_resigned();
  test_chained_merkle_shreds();
  perf_test();
  perf_test2();

#if FD_HAS_HOSTED
  test_shredder_pcap();
#endif

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
