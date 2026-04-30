/* test_lthash2: correctness + bench for fd_lthash2.
 *
 *   - Smoke: deterministic, non-zero output.
 *   - Self-consistency: batch16(x,x,...,x)[k] == compute(x) for all k.
 *   - Add/sub group axioms.
 *   - Bench: ns/lthash for sequential and batch16.  Compared to the
 *     blake3-based fd_lthash baseline (~381 ns/lthash on Zen 4 AVX-512).
 */

#include "fd_lthash2.h"
#include <string.h>

#if FD_HAS_AVX512

static void
test_smoke( fd_rng_t * rng ) {
  uchar input[ 256 ] __attribute__((aligned(64)));
  for( ulong i=0; i<256; i++ ) input[ i ] = fd_rng_uchar( rng );

  fd_lthash2_value_t out;
  fd_lthash2_compute( input, 64UL, &out );

  /* Should not be all-zero. */
  ulong sum = 0;
  for( ulong i=0; i<FD_LTHASH2_LEN_BYTES; i++ ) sum += out.bytes[i];
  FD_TEST( sum > 0 );

  /* Determinism: second run matches. */
  fd_lthash2_value_t out2;
  fd_lthash2_compute( input, 64UL, &out2 );
  FD_TEST( fd_lthash2_eq( &out, &out2 ) );

  /* Different inputs → different outputs. */
  input[ 0 ] ^= 1;
  fd_lthash2_compute( input, 64UL, &out2 );
  FD_TEST( !fd_lthash2_eq( &out, &out2 ) );

  FD_LOG_NOTICE(( "smoke test pass" ));
}

static void
test_batch16_consistency( fd_rng_t * rng ) {
  /* batch16(x_0, x_1, ..., x_15)[i] must equal compute(x_i) for each i. */
  uchar inputs_buf[ 16 ][ 256 ] __attribute__((aligned(64)));
  void const * inputs[ 16 ];
  uint sizes[ 16 ];
  fd_lthash2_value_t out_seq [ 16 ] __attribute__((aligned(64)));
  fd_lthash2_value_t out_batch[ 16 ] __attribute__((aligned(64)));
  fd_lthash2_value_t * outptrs[ 16 ];

  for( ulong i=0; i<16; i++ ) {
    /* Variable sizes 0..255 to exercise multi-block + tail padding. */
    sizes [ i ] = (uint)fd_rng_uint_roll( rng, 256U );
    inputs[ i ] = inputs_buf[ i ];
    for( ulong j=0; j<256; j++ ) inputs_buf[ i ][ j ] = fd_rng_uchar( rng );
    outptrs[ i ] = &out_batch[ i ];
  }

  /* Sequential reference. */
  for( ulong i=0; i<16; i++ ) {
    fd_lthash2_compute( inputs[ i ], (ulong)sizes[ i ], &out_seq[ i ] );
  }
  /* Batch path. */
  fd_lthash2_batch16( inputs, sizes, outptrs );

  for( ulong i=0; i<16; i++ ) {
    if( !fd_lthash2_eq( &out_seq[ i ], &out_batch[ i ] ) ) {
      FD_LOG_ERR(( "fd_lthash2_batch16 mismatch at lane %lu (sz=%u)", i, sizes[ i ] ));
    }
  }
  FD_LOG_NOTICE(( "batch16 self-consistency pass (variable sizes)" ));
}

static void
test_group_ops( fd_rng_t * rng ) {
  /* a + b - b == a (mod 2^16 per element). */
  uchar in_a[ 64 ], in_b[ 64 ];
  for( ulong i=0; i<64; i++ ) { in_a[ i ] = fd_rng_uchar( rng ); in_b[ i ] = fd_rng_uchar( rng ); }
  fd_lthash2_value_t a, b, sum;
  fd_lthash2_compute( in_a, 64UL, &a );
  fd_lthash2_compute( in_b, 64UL, &b );
  memcpy( &sum, &a, sizeof(a) );
  fd_lthash2_add( &sum, &b );
  fd_lthash2_sub( &sum, &b );
  FD_TEST( fd_lthash2_eq( &sum, &a ) );
  FD_LOG_NOTICE(( "group axioms pass (a+b-b == a)" ));
}

static void
bench_sequential( fd_rng_t * rng ) {
  enum { N = 4096 };
  uchar inputs[ N ][ 64 ] __attribute__((aligned(64)));
  for( ulong i=0; i<N; i++ ) for( ulong j=0; j<64; j++ ) inputs[ i ][ j ] = fd_rng_uchar( rng );
  fd_lthash2_value_t out __attribute__((aligned(64)));

  /* Warmup. */
  for( ulong w=0; w<256; w++ ) fd_lthash2_compute( inputs[ w & (N-1) ], 64UL, &out );

  ulong const iter = 200000UL;
  double best = 1e30;
  for( int t=0; t<3; t++ ) {
    long dt = -fd_log_wallclock();
    for( ulong r=0; r<iter; r++ ) {
      void * _o = &out; FD_COMPILER_FORGET( _o );
      fd_lthash2_compute( inputs[ r & (N-1) ], 64UL, &out );
    }
    dt += fd_log_wallclock();
    double ns = (double)dt / (double)iter;
    if( ns < best ) best = ns;
  }
  FD_LOG_NOTICE(( "fd_lthash2_compute  (sequential, 64-byte input)  : %.1f ns/lthash", best ));
}

static void
bench_batch8( fd_rng_t * rng ) {
  enum { N = 256 };
  uchar inputs_buf[ N ][ 8 ][ 64 ] __attribute__((aligned(64)));
  for( ulong b=0; b<N; b++ ) for( ulong i=0; i<8; i++ ) for( ulong j=0; j<64; j++ ) inputs_buf[ b ][ i ][ j ] = fd_rng_uchar( rng );
  void const * inputs[ 8 ];
  uint sizes[ 8 ];
  for( ulong i=0; i<8; i++ ) sizes[ i ] = 64U;
  fd_lthash2_value_t outs[ 8 ] __attribute__((aligned(64)));
  fd_lthash2_value_t * outptrs[ 8 ];
  for( ulong i=0; i<8; i++ ) outptrs[ i ] = &outs[ i ];

  for( ulong w=0; w<32; w++ ) {
    for( ulong i=0; i<8; i++ ) inputs[ i ] = inputs_buf[ w & (N-1) ][ i ];
    fd_lthash2_batch8( inputs, sizes, outptrs );
  }
  ulong const iter = 25000UL;  /* 8 lthashes per call * 25000 = 200000 lthashes */
  double best = 1e30;
  for( int t=0; t<3; t++ ) {
    long dt = -fd_log_wallclock();
    for( ulong r=0; r<iter; r++ ) {
      for( ulong i=0; i<8; i++ ) inputs[ i ] = inputs_buf[ r & (N-1) ][ i ];
      void const ** _i = inputs; FD_COMPILER_FORGET( _i );
      fd_lthash2_batch8( inputs, sizes, outptrs );
    }
    dt += fd_log_wallclock();
    double ns_per_lthash = (double)dt / (double)iter / 8.0;
    if( ns_per_lthash < best ) best = ns_per_lthash;
  }
  FD_LOG_NOTICE(( "fd_lthash2_batch8   (batched,    64-byte inputs) : %.1f ns/lthash", best ));
}

static void
bench_batch16( fd_rng_t * rng ) {
  enum { N = 256 };  /* slots of 16 inputs each */
  uchar inputs_buf[ N ][ 16 ][ 64 ] __attribute__((aligned(64)));
  for( ulong b=0; b<N; b++ ) for( ulong i=0; i<16; i++ ) for( ulong j=0; j<64; j++ ) inputs_buf[ b ][ i ][ j ] = fd_rng_uchar( rng );

  void const * inputs[ 16 ];
  uint sizes[ 16 ];
  for( ulong i=0; i<16; i++ ) sizes[ i ] = 64U;

  fd_lthash2_value_t outs[ 16 ] __attribute__((aligned(64)));
  fd_lthash2_value_t * outptrs[ 16 ];
  for( ulong i=0; i<16; i++ ) outptrs[ i ] = &outs[ i ];

  /* Warmup. */
  for( ulong w=0; w<32; w++ ) {
    for( ulong i=0; i<16; i++ ) inputs[ i ] = inputs_buf[ w & (N-1) ][ i ];
    fd_lthash2_batch16( inputs, sizes, outptrs );
  }

  ulong const iter = 12500UL;  /* 16 lthashes per call * 12500 = 200000 lthashes */
  double best = 1e30;
  for( int t=0; t<3; t++ ) {
    long dt = -fd_log_wallclock();
    for( ulong r=0; r<iter; r++ ) {
      for( ulong i=0; i<16; i++ ) inputs[ i ] = inputs_buf[ r & (N-1) ][ i ];
      void const ** _i = inputs; FD_COMPILER_FORGET( _i );
      fd_lthash2_batch16( inputs, sizes, outptrs );
    }
    dt += fd_log_wallclock();
    double ns_per_call = (double)dt / (double)iter;
    double ns_per_lthash = ns_per_call / 16.0;
    if( ns_per_lthash < best ) best = ns_per_lthash;
  }
  FD_LOG_NOTICE(( "fd_lthash2_batch16  (batched,    64-byte inputs) : %.1f ns/lthash", best ));
}

#endif /* FD_HAS_AVX512 */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

#if FD_HAS_AVX512
  test_smoke( rng );
  test_group_ops( rng );
  test_batch16_consistency( rng );

  FD_LOG_NOTICE(( "==============================================================" ));
  FD_LOG_NOTICE(( "  fd_lthash2 perf summary  (Keccak-p[1600,12], AVX-512)" ));
  FD_LOG_NOTICE(( "  best of 3 timings; reference: blake3 lthash ~381 ns/lthash" ));
  FD_LOG_NOTICE(( "==============================================================" ));
  bench_sequential( rng );
  bench_batch8    ( rng );
  bench_batch16   ( rng );
  FD_LOG_NOTICE(( "==============================================================" ));
#else
  (void)rng;
  FD_LOG_NOTICE(( "fd_lthash2: skipped (no AVX-512 support)" ));
#endif

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
