#include "fd_shredder.h"
#include "fd_shred.h"


/* An entry batch of 64 entries with 20 transactions per entry takes up
   about 256 kB, for about 200B/txn, which seems reasonable.  We'll do a
   10 MB entry batch, which is about 50k transactions. */
#define PERF_TEST_SZ (10UL*1024UL*1024UL)
#define PERF_TEST2_SZ (1UL*1024UL*1024UL)
uchar perf_test_entry_batch[ PERF_TEST_SZ ];

uchar fec_set_memory_1[ 2048UL * FD_REEDSOL_DATA_SHREDS_MAX   ];
uchar fec_set_memory_2[ 2048UL * FD_REEDSOL_PARITY_SHREDS_MAX ];

/* First 32B of what Solana calls the private key is what we call the
   private key, second 32B are what we call the public key. */
FD_IMPORT_BINARY( test_private_key, "src/ballet/shred/fixtures/demo-shreds.key"  );

#if FD_HAS_HOSTED
#include "../../util/net/fd_pcap.h"
#include <stdio.h>

FD_IMPORT_BINARY( test_pcap,        "src/ballet/shred/fixtures/demo-shreds.pcap" );
FD_IMPORT_BINARY( test_bin,         "src/ballet/shred/fixtures/demo-shreds.bin"  );

fd_shredder_t _shredder[ 1 ];

static void
test_shredder_pcap( void ) {
  FD_TEST( _shredder==fd_shredder_new( _shredder, test_private_key+32UL, (ushort)0 ) );
  fd_shredder_t * shredder = fd_shredder_join( _shredder );           FD_TEST( shredder );

  /* Manually counted values from the pcap */
  FD_TEST( fd_shredder_count_fec_sets(      test_bin_sz ) ==   7UL );
  FD_TEST( fd_shredder_count_data_shreds(   test_bin_sz ) == 240UL );
  FD_TEST( fd_shredder_count_parity_shreds( test_bin_sz ) == 240UL );


  FILE * file = fmemopen( (void *)test_pcap, test_pcap_sz, "rb" );    FD_TEST( file );

  fd_pcap_iter_t * pcap = fd_pcap_iter_new( file );                   FD_TEST( pcap );

  fd_entry_batch_meta_t meta[1];
  fd_memset( meta, 0, sizeof(fd_entry_batch_meta_t) );

  /* The pcap has all the data shreds before the parity shreds, so we'll
     make two passes over the data, one to check the data shreds, and
     the other to check the parity shreds. */
  FD_TEST( fd_shredder_init_batch( shredder, test_bin, test_bin_sz, meta ) );
  for( ulong i=0UL; i<7UL; i++ ) {
    fd_fec_set_t _set[ 1 ];

    for( ulong j=0UL; j<FD_REEDSOL_DATA_SHREDS_MAX;   j++ ) _set->data_shreds[   j ] = fec_set_memory_1 + 2048UL*j;
    for( ulong j=0UL; j<FD_REEDSOL_PARITY_SHREDS_MAX; j++ ) _set->parity_shreds[ j ] = fec_set_memory_2 + 2048UL*j;

    fd_fec_set_t * set = fd_shredder_next_fec_set( shredder, test_private_key, _set );
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
  meta->slot++;
  FD_TEST( fd_shredder_init_batch( shredder, test_bin, test_bin_sz, meta ) );
  FD_TEST( fd_shredder_fini_batch( shredder ) );
  meta->slot--;

  FD_TEST( fd_shredder_init_batch( shredder, test_bin, test_bin_sz, meta ) );
  for( ulong i=0UL; i<7UL; i++ ) {
    fd_fec_set_t _set[ 1 ];

    for( ulong j=0UL; j<FD_REEDSOL_DATA_SHREDS_MAX;   j++ ) _set->data_shreds[   j ] = fec_set_memory_1 + 2048UL*j;
    for( ulong j=0UL; j<FD_REEDSOL_PARITY_SHREDS_MAX; j++ ) _set->parity_shreds[ j ] = fec_set_memory_2 + 2048UL*j;

    fd_fec_set_t * set = fd_shredder_next_fec_set( shredder, test_private_key, _set );
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
test_shredder_count( void ) {
  FD_TEST( fd_shredder_count_data_shreds(   0UL ) ==  1UL );
  FD_TEST( fd_shredder_count_parity_shreds( 0UL ) == 17UL );
  FD_TEST( fd_shredder_count_fec_sets(      0UL ) ==  1UL );

  for( ulong data_sz=1UL; data_sz<1000000UL; data_sz++ ) {
    ulong fec_sets = 0UL;
    ulong data_shreds = 0UL;
    ulong parity_shreds = 0UL;
    ulong x = data_sz;
    /* Reference implementation taken from make_shreds_from_data in Rust
       code */
    ulong data_buffer_size = 995UL;
    ulong chunk_size = 31840UL;
    while( x>=2UL*chunk_size || x==chunk_size ) {
      fec_sets++;
      data_shreds += (chunk_size + data_buffer_size - 1UL) / data_buffer_size;
      parity_shreds += (chunk_size + data_buffer_size - 1UL) / data_buffer_size;
      x -= chunk_size;
    }
    if( x>0UL || data_shreds==0UL ) {
      ulong num_data_shreds, num_parity_shreds;
      for( ulong proof_size=1UL; proof_size<32UL; proof_size++ ) {
        data_buffer_size = 1115UL - 20UL * proof_size;
        num_data_shreds   = fd_ulong_max( 1UL, (x + data_buffer_size-1UL)/data_buffer_size );
        num_parity_shreds = (num_data_shreds>32UL ? num_data_shreds : fd_shredder_data_to_parity_cnt[ num_data_shreds ] );
        if( fd_bmtree_depth( num_data_shreds+num_parity_shreds )-1UL == proof_size ) break;
      }
      data_shreds   += num_data_shreds;
      parity_shreds += num_parity_shreds;
      fec_sets++;
    }

    FD_TEST( fd_shredder_count_data_shreds(   data_sz ) ==   data_shreds );
    FD_TEST( fd_shredder_count_parity_shreds( data_sz ) == parity_shreds );
    FD_TEST( fd_shredder_count_fec_sets(      data_sz ) ==      fec_sets );
  }
}

static void
perf_test( void ) {
  for( ulong i=0UL; i<PERF_TEST_SZ; i++ )  perf_test_entry_batch[ i ] = (uchar)i;

  fd_entry_batch_meta_t meta[1];
  fd_memset( meta, 0, sizeof(fd_entry_batch_meta_t) );

  FD_TEST( _shredder==fd_shredder_new( _shredder, test_private_key+32UL, (ushort)0 ) );
  fd_shredder_t * shredder = fd_shredder_join( _shredder );           FD_TEST( shredder );

  fd_fec_set_t _set[ 1 ];
  for( ulong j=0UL; j<FD_REEDSOL_DATA_SHREDS_MAX;   j++ ) _set->data_shreds[   j ] = fec_set_memory_1 + 2048UL*j;
  for( ulong j=0UL; j<FD_REEDSOL_PARITY_SHREDS_MAX; j++ ) _set->parity_shreds[ j ] = fec_set_memory_2 + 2048UL*j;

  ulong iterations = 100UL;
  long dt = -fd_log_wallclock();
  for( ulong iter=0UL; iter<iterations; iter++ ) {
    fd_shredder_init_batch( shredder, perf_test_entry_batch, PERF_TEST_SZ, meta );

    ulong sets_cnt = fd_shredder_count_fec_sets( PERF_TEST_SZ );
    for( ulong j=0UL; j<sets_cnt; j++ ) {
      fd_shredder_next_fec_set( shredder, test_private_key, _set );
    }
    fd_shredder_fini_batch( shredder );
  }
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "%li ns/10 MB entry batch = %.3f Gbps", dt/(long)iterations, (double)(8UL * iterations * PERF_TEST_SZ)/(double)dt ));

}
static void
perf_test2( void ) {
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( "huge" ), 1UL, 0UL, "perf_test2", 0UL );
  uchar * entry_batch = fd_wksp_laddr_fast( wksp, fd_wksp_alloc( wksp, 128UL, PERF_TEST2_SZ, 2UL ) );
  uchar * fec_memory  = fd_wksp_laddr_fast( wksp, fd_wksp_alloc( wksp, 128UL, (FD_REEDSOL_DATA_SHREDS_MAX + FD_REEDSOL_PARITY_SHREDS_MAX)*1800UL, 3UL ) );

  for( ulong i=0UL; i<PERF_TEST2_SZ; i++ )  entry_batch[ i ] = (uchar)i;

  fd_entry_batch_meta_t meta[1];
  fd_memset( meta, 0, sizeof(fd_entry_batch_meta_t) );

  FD_TEST( _shredder==fd_shredder_new( _shredder, test_private_key+32UL, (ushort)0 ) );
  fd_shredder_t * shredder = fd_shredder_join( _shredder );           FD_TEST( shredder );

  fd_fec_set_t _set[ 1 ];
  for( ulong j=0UL; j<FD_REEDSOL_DATA_SHREDS_MAX;   j++ ) _set->data_shreds[   j ] = fec_memory + 1800UL*j;
  for( ulong j=0UL; j<FD_REEDSOL_PARITY_SHREDS_MAX; j++ ) _set->parity_shreds[ j ] = fec_memory + 1800UL*j + 1800*FD_REEDSOL_DATA_SHREDS_MAX;

  ulong iterations = 10000UL;
  ulong bytes_produced = 0UL;
  long dt = -fd_log_wallclock();
  for( ulong iter=0UL; iter<iterations; iter++ ) {
    fd_shredder_init_batch( shredder, entry_batch, PERF_TEST2_SZ, meta );

    ulong sets_cnt = fd_shredder_count_fec_sets( PERF_TEST2_SZ );
    for( ulong j=0UL; j<sets_cnt; j++ ) {
      fd_shredder_next_fec_set( shredder, test_private_key, _set );
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

  if( sizeof(fd_shredder_t) != FD_SHREDDER_FOOTPRINT )
    FD_LOG_WARNING(( "sizeof() %lu, footprint: %lu", sizeof(fd_shredder_t), FD_SHREDDER_FOOTPRINT ));
  FD_TEST( sizeof(fd_shredder_t) == FD_SHREDDER_FOOTPRINT );


  test_shredder_count();
  perf_test();
  perf_test2();

#if FD_HAS_HOSTED
  test_shredder_pcap();
#endif

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
