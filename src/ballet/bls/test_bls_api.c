/* Benchmark the public fd_bls API against whichever backend is compiled in
   (AVX512 native when FD_HAS_AVX512, blst wrappers otherwise).  Run the same
   test binary built under both machine configs to compare backends:

     make -j unit-test MACHINE=native
     $(make --silent objdir MACHINE=native)/unit-test/test_bls_api --bench
     make -j unit-test MACHINE=linux_gcc_x86_64
     $(make --silent objdir MACHINE=linux_gcc_x86_64)/unit-test/test_bls_api --bench */

#include "fd_bls.h"
#include "../../util/fd_util.h"

#define SAMPLES    21
#define MIN_DT_NS  3000000L /* calibrate until a timed batch takes >= 3 ms */
#define PUB_CNT    64UL

static uchar          g_msg[ 32 ];
static fd_bls_sec_t   g_sec;
static fd_bls_pub_t   g_pub, g_pubs[ PUB_CNT ];
static fd_bls_sig_t   g_sig, g_sigs[ PUB_CNT ];
static fd_bls_hash_t  g_hash;
static fd_bls_pub_t   g_pub_out;
static fd_bls_sig_t   g_sig_out;
static fd_bls_set_t   g_set[ fd_bls_set_word_cnt ];
static uchar           g_pub_buf[ FD_BLS_PUB_SZ ];
static uchar           g_pub_cbuf[ FD_BLS_PUB_COMPRESSED_SZ ];
static uchar           g_sig_buf[ FD_BLS_SIG_SZ ];
static uchar           g_sig_cbuf[ FD_BLS_SIG_COMPRESSED_SZ ];
static volatile ulong g_sink;

typedef void (* bench_fn_t)( void );

static void op_sec_derive   ( void ) { fd_bls_sec_derive( &g_sec, g_msg, sizeof(g_msg) ); }
static void op_sec_to_pub   ( void ) { fd_bls_sec_to_pub( &g_sec, &g_pub ); }
static void op_hash_msg     ( void ) { fd_bls_hash_msg( g_msg, sizeof(g_msg), &g_hash ); }
static void op_sign         ( void ) { fd_bls_sec_sign( &g_sec, g_msg, sizeof(g_msg), &g_sig ); }
static void op_verify       ( void ) { g_sink += (ulong)fd_bls_agg_verify( g_msg, sizeof(g_msg), &g_pub, &g_sig ); }
static void op_verify_hashed( void ) { g_sink += (ulong)fd_bls_agg_verify_hashed( &g_hash, &g_pub, &g_sig ); }
static void op_verify_pair  ( void ) {
  g_sink += (ulong)fd_bls_agg_verify_pair( g_msg, sizeof(g_msg), &g_pubs[0],
                                           g_msg, sizeof(g_msg), &g_pubs[1], &g_sig );
}
static void op_pub_de       ( void ) { g_sink += (ulong)( fd_bls_pub_de( &g_pub_out, g_pub_buf, FD_BLS_PUB_SZ )==0 ); }
static void op_pub_de_c     ( void ) { g_sink += (ulong)( fd_bls_pub_de( &g_pub_out, g_pub_cbuf, FD_BLS_PUB_COMPRESSED_SZ )==0 ); }
static void op_sig_de       ( void ) { g_sink += (ulong)( fd_bls_sig_de( &g_sig_out, g_sig_buf )==0 ); }
static void op_sig_de_c     ( void ) { g_sink += (ulong)( fd_bls_sig_de_compressed( &g_sig_out, g_sig_cbuf )==0 ); }
static void op_pub_compress ( void ) { fd_bls_pub_compress( &g_pub, g_pub_cbuf ); }
static void op_sig_compress ( void ) { fd_bls_sig_compress( &g_sig, g_sig_cbuf ); }
static void op_pub_add      ( void ) { fd_bls_pub_add( &g_pub_out, &g_pubs[0], &g_pubs[1] ); }
static void op_sig_add      ( void ) { fd_bls_sig_add( &g_sig_out, &g_sigs[0], &g_sigs[1] ); }
static void op_sig_validate ( void ) { g_sink += (ulong)fd_bls_sig_validate( &g_sig ); }
static void op_pub_sum      ( void ) { fd_bls_pub_sum( &g_pub_out, g_pubs, g_set ); }
static void op_sig_add_many ( void ) {
  fd_bls_sig_t const * sigs[ PUB_CNT ];
  for( ulong i=0UL; i<PUB_CNT; i++ ) sigs[ i ] = g_sigs+i;
  for( ulong i=1UL; i<PUB_CNT; i++ ) fd_bls_sig_add( &g_sig_out, &g_sig_out, sigs[ i ] );
}

/* Double iters until a batch takes long enough to time reliably. */

static ulong
bench_calibrate( bench_fn_t fn ) {
  ulong iters = 1UL;
  for( ;; ) {
    long then = fd_log_wallclock();
    for( ulong i=0UL; i<iters; i++ ) fn();
    long dt = fd_log_wallclock() - then;
    if( dt>=MIN_DT_NS || iters>=(1UL<<22) ) return iters;
    iters *= 2UL;
  }
}

static long g_samples[ SAMPLES ];

static long
bench_median( void ) {
  for( int i=1; i<SAMPLES; i++ ) for( int j=i; j && g_samples[j-1]>g_samples[j]; j-- ) {
    long tmp=g_samples[j-1]; g_samples[j-1]=g_samples[j]; g_samples[j]=tmp;
  }
  return g_samples[ SAMPLES/2 ];
}

static void
bench_run( char const * name,
           bench_fn_t   fn ) {
  ulong iters = bench_calibrate( fn );
  for( int s=0; s<SAMPLES; s++ ) {
    long then = fd_log_wallclock();
    for( ulong i=0UL; i<iters; i++ ) fn();
    g_samples[ s ] = fd_log_wallclock() - then;
  }
  double ns_op = (double)bench_median() / (double)iters;
  FD_LOG_NOTICE(( "%-30s %10.3f us/op (median of %d x %lu iters)",
                  name, ns_op/1e3, SAMPLES, iters ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  int bench = fd_env_strip_cmdline_contains( &argc, &argv, "--bench" );

  for( ulong i=0UL; i<sizeof(g_msg); i++ ) g_msg[ i ] = (uchar)( i*17UL+3UL );

  /* correctness across the exact ops being benchmarked */
  fd_bls_sec_derive( &g_sec, g_msg, sizeof(g_msg) );
  fd_bls_sec_to_pub( &g_sec, &g_pub );
  fd_bls_sec_sign( &g_sec, g_msg, sizeof(g_msg), &g_sig );
  fd_bls_hash_msg( g_msg, sizeof(g_msg), &g_hash );
  FD_TEST( fd_bls_agg_verify( g_msg, sizeof(g_msg), &g_pub, &g_sig )==1 );
  FD_TEST( fd_bls_agg_verify_hashed( &g_hash, &g_pub, &g_sig )==1 );
  uchar bad_msg[ sizeof(g_msg) ];
  for( ulong i=0UL; i<sizeof(bad_msg); i++ ) bad_msg[ i ] = g_msg[ i ]^0xffU;
  FD_TEST( fd_bls_agg_verify( bad_msg, sizeof(bad_msg), &g_pub, &g_sig )==0 );

  fd_bls_pub_compress( &g_pub, g_pub_cbuf );
  FD_TEST( fd_bls_pub_de( &g_pub_out, g_pub_cbuf, FD_BLS_PUB_COMPRESSED_SZ )==0 );
  FD_TEST( fd_bls_pub_eq( &g_pub_out, &g_pub ) );
  fd_bls_pub_add( &g_pub_out, &g_pub_out, &g_pub ); /* affine doubling on sum path */
  FD_TEST( fd_bls_pub_de( &g_pub_out, g_pub_cbuf, FD_BLS_PUB_COMPRESSED_SZ )==0 );

  fd_bls_sig_compress( &g_sig, g_sig_cbuf );
  FD_TEST( fd_bls_sig_de_compressed( &g_sig_out, g_sig_cbuf )==0 );
  FD_TEST( fd_bls_sig_eq( &g_sig_out, &g_sig ) );
  fd_bls_sig_ser( &g_sig, g_sig_buf );
  FD_TEST( fd_bls_sig_de( &g_sig_out, g_sig_buf )==0 );
  FD_TEST( fd_bls_sig_validate( &g_sig ) );

  /* multi-signer aggregate: sum of pubs / sigs verifies once */
  fd_bls_set_null( g_set );
  for( ulong i=0UL; i<PUB_CNT; i++ ) {
    fd_bls_sec_t sec[1];
    uchar ikm[ 32 ];
    for( ulong j=0UL; j<sizeof(ikm); j++ ) ikm[ j ] = (uchar)( (i*131UL+j*7UL) | 1UL );
    fd_bls_sec_derive( sec, ikm, sizeof(ikm) );
    fd_bls_sec_to_pub( sec, g_pubs+i );
    fd_bls_sec_sign( sec, g_msg, sizeof(g_msg), g_sigs+i );
    fd_bls_set_insert( g_set, (uint)i );
  }
  fd_bls_pub_sum( &g_pub_out, g_pubs, g_set );
  g_sig_out = g_sigs[0];
  for( ulong i=1UL; i<PUB_CNT; i++ ) fd_bls_sig_add( &g_sig_out, &g_sig_out, g_sigs+i );
  FD_TEST( fd_bls_agg_verify( g_msg, sizeof(g_msg), &g_pub_out, &g_sig_out )==1 );
  FD_TEST( fd_bls_pub_eq( &g_pubs[0], &g_pubs[0] ) ); /* silence unused warnings on ref types */

  if( FD_LIKELY( bench ) ) {
    bench_run( "keygen (sec_derive)",      op_sec_derive );
    bench_run( "sk->pk (sec_to_pub)",      op_sec_to_pub );
    bench_run( "hash_msg (hash-to-G2)",    op_hash_msg );
    bench_run( "sign (hash+G2 mul)",       op_sign );
    bench_run( "agg_verify (hash+pair)",   op_verify );
    bench_run( "agg_verify_hashed (pair)", op_verify_hashed );
    bench_run( "agg_verify_pair (3 pairs)",op_verify_pair );
    bench_run( "pub_de 96B (+subgrp)",     op_pub_de );
    bench_run( "pub_de 48B compressed",    op_pub_de_c );
    bench_run( "sig_de 192B (+subgrp)",    op_sig_de );
    bench_run( "sig_de 96B compressed",    op_sig_de_c );
    bench_run( "pub_compress",             op_pub_compress );
    bench_run( "sig_compress",             op_sig_compress );
    bench_run( "pub_add",                  op_pub_add );
    bench_run( "sig_add",                  op_sig_add );
    bench_run( "sig_validate (G2 chk)",    op_sig_validate );
    bench_run( "pub_sum (64 pubs)",        op_pub_sum );
    bench_run( "sig_add (64 sigs)",        op_sig_add_many );
  }

  FD_LOG_NOTICE(( "pass (sink %lu)", g_sink ));
  fd_halt();
  return 0;
}
