/* test_lthash2: correctness + bench for fd_lthash2.
 *
 *   - Smoke: deterministic, non-zero output.
 *   - Self-consistency: batch16(x,x,...,x)[k] == compute(x) for all k.
 *   - Add/sub group axioms.
 *   - Bench: ns/lthash for sequential and batch16.  Compared to the
 *     blake3-based fd_lthash baseline (~381 ns/lthash on Zen 4 AVX-512).
 */

#include "fd_lthash2.h"
#include "../keccak256/fd_keccak256_avx512_internal.h"
#include <string.h>

#if FD_HAS_AVX512

extern ulong const fd_keccak256_rc[24];

/* ---- fully-scalar KangarooTwelve(KTP12) reference --------------------- *
   Independent of the vectorized impl: scalar single-state sponge, scalar
   leaf CVs, scalar counter-squeeze.  Used to validate the tree path. */
#define R_RATE 168UL
typedef struct { ulong s[25]; uchar buf[168]; ulong blen; } refsp_t;
static void refsp_init( refsp_t * sp ){ memset(sp->s,0,sizeof(sp->s)); sp->blen=0; }
static void refsp_blk( refsp_t * sp ){
  for( ulong z=0;z<21;z++){ ulong w; memcpy(&w,sp->buf+8*z,8); sp->s[z]^=w; }
  fd_keccak256_avx512_keccak1_f1600_12r( sp->s, fd_keccak256_rc ); sp->blen=0;
}
static void refsp_absorb( refsp_t * sp, void const * d, ulong len ){
  uchar const * p=d; while(len){ ulong t=R_RATE-sp->blen; if(t>len)t=len;
    memcpy(sp->buf+sp->blen,p,t); sp->blen+=t; p+=t; len-=t; if(sp->blen==R_RATE) refsp_blk(sp);} }
static void refsp_fini( refsp_t * sp, uchar ds ){
  memset(sp->buf+sp->blen,0,R_RATE-sp->blen);
  sp->buf[sp->blen]=(uchar)(sp->buf[sp->blen]^ds); sp->buf[167]=(uchar)(sp->buf[167]^0x80);
  for( ulong z=0;z<21;z++){ ulong w; memcpy(&w,sp->buf+8*z,8); sp->s[z]^=w; }
  fd_keccak256_avx512_keccak1_f1600_12r( sp->s, fd_keccak256_rc ); }
static ulong ref_renc( uchar o[9], ulong x ){ ulong n=1,t=x; while(t>=256){t>>=8;n++;}
  uchar be[8]; for(ulong i=0;i<8;i++) be[i]=(uchar)(x>>(8*(7-i))); memcpy(o,be+(8-n),n); o[n]=(uchar)n; return n+1; }
static void ref_compute( uchar out[2048], void const * input, ulong sz ){
  uchar const * p=input; ulong st[25];
  if( sz<=8192 ){ refsp_t sp; refsp_init(&sp); refsp_absorb(&sp,p,sz); refsp_fini(&sp,0x07); memcpy(st,sp.s,200); }
  else {
    ulong n=(sz+8191)/8192, nleaf=n-1;
    refsp_t sp; refsp_init(&sp); refsp_absorb(&sp,p,8192);
    uchar sep[8]={0x03,0,0,0,0,0,0,0}; refsp_absorb(&sp,sep,8);
    for( ulong i=1;i<n;i++ ){ ulong off=i*8192, csz=(off+8192<=sz)?8192:(sz-off);
      refsp_t lf; refsp_init(&lf); refsp_absorb(&lf,p+off,csz); refsp_fini(&lf,0x0B);
      refsp_absorb(&sp,(uchar*)lf.s,32); }
    uchar re[9]; ulong rl=ref_renc(re,nleaf); refsp_absorb(&sp,re,rl);
    uchar ff[2]={0xFF,0xFF}; refsp_absorb(&sp,ff,2); refsp_fini(&sp,0x06); memcpy(st,sp.s,200);
  }
  for( ulong ctr=0;ctr<13;ctr++){ ulong w[25]; memcpy(w,st,200); w[21]^=ctr;
    fd_keccak256_avx512_keccak1_f1600_12r(w,fd_keccak256_rc);
    ulong nb=(ctr<12)?168:32; memcpy(out+ctr*168,(uchar*)w,nb); }
}

static void
test_tree( fd_rng_t * rng ) {
  ulong const szs[] = { 1, 168, 8191, 8192, 8193, 16384, 16385, 24576, 100000, 1000003 };
  ulong nszs = sizeof(szs)/sizeof(szs[0]);
  ulong maxsz = 1000003;
  uchar * buf = aligned_alloc( 64, maxsz );
  FD_TEST( buf );
  for( ulong i=0;i<maxsz;i++ ) buf[i] = fd_rng_uchar( rng );
  for( ulong k=0;k<nszs;k++ ) {
    ulong sz = szs[k];
    fd_lthash2_value_t got; fd_lthash2_compute( buf, sz, &got );
    uchar want[2048]; ref_compute( want, buf, sz );
    if( memcmp( got.bytes, want, 2048 ) )
      FD_LOG_ERR(( "tree mismatch at sz=%lu (%s)", sz, sz<=8192?"single-node":"tree" ));
  }
  free( buf );
  FD_LOG_NOTICE(( "tree self-validation pass (scalar K12 ref, sizes 1..1M spanning chunk boundary)" ));
}

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
test_batch8_consistency( fd_rng_t * rng ) {
  /* batch8(x_0..x_{n-1})[i] must equal compute(x_i) for each i, for every
     partial count n in 1..8 (exercises lane masking too). */
  uchar inputs_buf[ 8 ][ 256 ] __attribute__((aligned(64)));
  void const * inputs[ 8 ];
  uint sizes[ 8 ];
  fd_lthash2_value_t out_seq [ 8 ] __attribute__((aligned(64)));
  fd_lthash2_value_t out_batch[ 8 ] __attribute__((aligned(64)));
  fd_lthash2_value_t * outptrs[ 8 ];

  for( ulong i=0; i<8; i++ ) {
    sizes [ i ] = (uint)fd_rng_uint_roll( rng, 512U ); /* multi-block + tail */
    inputs[ i ] = inputs_buf[ i ];
    for( ulong j=0; j<256; j++ ) inputs_buf[ i ][ j ] = fd_rng_uchar( rng );
    outptrs[ i ] = &out_batch[ i ];
  }
  for( ulong i=0; i<8; i++ )
    fd_lthash2_compute( inputs[ i ], (ulong)(sizes[i]>256U?256U:sizes[i]), &out_seq[ i ] );
  /* clamp sizes to buffer for both paths */
  for( ulong i=0; i<8; i++ ) if( sizes[i]>256U ) sizes[i]=256U;
  for( ulong i=0; i<8; i++ )
    fd_lthash2_compute( inputs[ i ], (ulong)sizes[ i ], &out_seq[ i ] );

  for( ulong n=1; n<=8; n++ ) {
    memset( out_batch, 0, sizeof(out_batch) );
    fd_lthash2_batch8( inputs, sizes, outptrs, n );
    for( ulong i=0; i<n; i++ )
      if( !fd_lthash2_eq( &out_seq[ i ], &out_batch[ i ] ) )
        FD_LOG_ERR(( "fd_lthash2_batch8 mismatch n=%lu lane %lu (sz=%u)", n, i, sizes[ i ] ));
  }
  FD_LOG_NOTICE(( "batch8 self-consistency pass (variable sizes, n=1..8 masking)" ));
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
    fd_lthash2_batch8( inputs, sizes, outptrs, 8UL );
  }
  ulong const iter = 25000UL;  /* 8 lthashes per call * 25000 = 200000 lthashes */
  double best = 1e30;
  for( int t=0; t<3; t++ ) {
    long dt = -fd_log_wallclock();
    for( ulong r=0; r<iter; r++ ) {
      for( ulong i=0; i<8; i++ ) inputs[ i ] = inputs_buf[ r & (N-1) ][ i ];
      void const ** _i = inputs; FD_COMPILER_FORGET( _i );
      fd_lthash2_batch8( inputs, sizes, outptrs, 8UL );
    }
    dt += fd_log_wallclock();
    double ns_per_lthash = (double)dt / (double)iter / 8.0;
    if( ns_per_lthash < best ) best = ns_per_lthash;
  }
  FD_LOG_NOTICE(( "fd_lthash2_batch8   (batched,    64-byte inputs) : %.1f ns/lthash", best ));
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
  test_batch8_consistency( rng );
  test_tree( rng );

  FD_LOG_NOTICE(( "==============================================================" ));
  FD_LOG_NOTICE(( "  fd_lthash2 perf summary  (Keccak-p[1600,12], AVX-512)" ));
  FD_LOG_NOTICE(( "  best of 3 timings; reference: blake3 lthash ~381 ns/lthash" ));
  FD_LOG_NOTICE(( "==============================================================" ));
  bench_sequential( rng );
  bench_batch8    ( rng );
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
