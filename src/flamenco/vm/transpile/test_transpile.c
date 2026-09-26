#include "fd_transpile_idiv.h"

#include "fd_transpile.h"
#include "../../../util/tmpl/fd_unit_test.c"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* udiv magic reference values (Hacker's Delight / Granlund-Montgomery) */

FD_UNIT_TEST( udiv32_magic_known ) {
  struct { uint d; ulong m; int k; } const cases[] = {
    { 3U,          0xaaaaaaabUL,  33 },
    { 5U,          0xcccccccdUL,  34 },
    { 6U,          0xaaaaaaabUL,  34 },
    { 7U,          0x124924925UL, 35 },
    { 9U,          0x38e38e39UL,  33 },
    { 10U,         0xcccccccdUL,  35 },
    { 11U,         0xba2e8ba3UL,  35 },
    { 12U,         0xaaaaaaabUL,  35 },
    { 25U,         0x51eb851fUL,  35 },
    { 125U,        0x10624dd3UL,  35 },
    { 641U,        0x663d81UL,    32 }, /* 641 | 2^32+1 */
    { 6700417U,    0x281UL,       32 }, /* 6700417 | 2^32+1 */
    { 0x7fffffffU, 0x100000003UL, 63 },
    { 0x80000001U, 0xffffffffUL,  63 },
    { 0xffffffffU, 0x80000001UL,  63 },
  };
  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    int k = -1;
    ulong m = fd_transpile_udiv32_magic( cases[i].d, &k );
    FD_TEST( m==cases[i].m );
    FD_TEST( k==cases[i].k );
  }
}

FD_UNIT_TEST( udiv64_magic_known ) {
  struct { ulong d; uint128 m; int k; } const cases[] = {
    { 3UL,                  (uint128)0xaaaaaaaaaaaaaaabUL,                65 },
    { 5UL,                  (uint128)0xcccccccccccccccdUL,                66 },
    { 7UL,                  ((uint128)1<<64) | 0x2492492492492493UL,      67 },
    { 10UL,                 (uint128)0xcccccccccccccccdUL,                67 },
    { 641UL,                (uint128)0xcc7b01ff3384fe01UL,                73 },
    { 274177UL,             (uint128)0x3d30f19cd101UL,                    64 }, /* 274177 | 2^64+1 */
    { 67280421310721UL,     (uint128)0x42f01UL,                           64 }, /* 67280421310721 | 2^64+1 */
    { 0x7fffffffUL,         ((uint128)1<<64) | 0x0000000200000005UL,      95 },
    { 0x7fffffffffffffffUL, ((uint128)1<<64) | 0x0000000000000003UL,     127 },
    { 0x8000000000000001UL, (uint128)0xffffffffffffffffUL,               127 },
    { 0xffffffffffffffffUL, (uint128)0x8000000000000001UL,               127 },
  };
  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    int k = -1;
    uint128 m = fd_transpile_udiv64_magic( cases[i].d, &k );
    FD_TEST( m==cases[i].m );
    FD_TEST( k==cases[i].k );
  }
}

/* check_udiv{32,64}_contract verifies the documented postconditions of
   the magic derivation for one divisor: m==ceil(2^k/d), k lies in
   [W,W+ceil(log2 d)] and is the smallest shift satisfying the error
   bound m*d<=2^k+2^(k-W), and m fits in W+1 bits. */

static int
ceil_log2_ulong( ulong d ) {
  int l = 0;
  while( l<63 && (1UL<<l)<d ) l++;
  return l;
}

static void
check_udiv32_contract( uint d ) {
  int   k = -1;
  ulong m = fd_transpile_udiv32_magic( d, &k );
  int   l = ceil_log2_ulong( d );

  FD_TEST( k>=32 && k<=32+l );
  FD_TEST( m<(1UL<<33) ); /* at most 33 bits */

  uint128 p = (uint128)1<<k;
  FD_TEST( (uint128)m==(p+d-1U)/d );
  FD_TEST( (uint128)m*d>p );                   /* d not a power of 2 */
  FD_TEST( (uint128)m*d<=p+(p>>32) );
  FD_TEST( m&1UL );                            /* implied by minimality */

  if( k>32 ) {
    /* k-1 must violate the error bound */
    uint128 p1 = (uint128)1<<(k-1);
    uint128 m1 = (p1+d-1U)/d;
    FD_TEST( m1*d>p1+(p1>>32) );
  }
}

static void
check_udiv64_contract( ulong d ) {
  int     k = -1;
  uint128 m = fd_transpile_udiv64_magic( d, &k );
  int     l = ceil_log2_ulong( d );

  FD_TEST( k>=64 && k<=64+l );
  FD_TEST( (m>>64)<=1U ); /* at most 65 bits */

  uint128 p = (uint128)1<<k;
  FD_TEST( m==(p+d-1U)/d );
  /* m*d may exceed 128 bits for k=127; compare via the remainder */
  uint128 r = (uint128)(m*d - p);              /* wraps mod 2^128, but true value < 2^128 */
  FD_TEST( r>0U );                             /* d not a power of 2 */
  FD_TEST( r<=(p>>64) );
  FD_TEST( (ulong)m&1UL );                     /* implied by minimality */

  if( k>64 ) {
    uint128 p1 = (uint128)1<<(k-1);
    uint128 m1 = (p1+d-1U)/d;
    uint128 r1 = (uint128)(m1*d - p1);
    FD_TEST( r1>(p1>>64) );
  }
}

/* The reductions below mirror the exact instruction sequences emitted
   by emit_udiv{32,64}_imm in fd_transpile_x86.dasc, including their
   intermediate-width assumptions. */

static uint
x86_udiv32( uint n, ulong m, int k ) {
  ulong rdi = (ulong)n;
  if( m<=(ulong)UINT_MAX ) {
    /* mov r15d, m; imul rdi, r15; shr rdi, k */
    FD_TEST( (uint128)rdi*m<((uint128)1<<64) );
    rdi = (rdi*m)>>k;
  } else {
    /* mov r15d, (uint)m; imul r15, rdi; shr r15, 32; add rdi, r15; shr rdi, k-32 */
    ulong r15 = (ulong)(uint)m;
    r15 = (r15*rdi)>>32;
    FD_TEST( k>32 );
    FD_TEST( rdi+r15<(1UL<<33) );  /* no carry out of the add */
    rdi = (rdi+r15)>>(k-32);
  }
  FD_TEST( rdi<=(ulong)UINT_MAX );
  return (uint)rdi;
}

static uint
x86_umod32( uint n, uint d, ulong m, int k ) {
  uint q = x86_udiv32( n, m, k );
  /* imul edi, edi, d; sub reg, edi */
  return n - q*d;
}

static ulong
x86_udiv64( ulong n, uint128 m, int k ) {
  /* mulx rdi, rdi, rdi with rdx=n, rdi=(ulong)m */
  ulong rdi = (ulong)(((uint128)n*(ulong)m)>>64);
  if( m>>64 ) {
    /* add rdi, n; rcr rdi, 1; shr rdi, k-65 */
    uint128 sum = (uint128)rdi+n;
    FD_TEST( sum<((uint128)1<<65) );
    rdi = (ulong)(sum>>1);
    FD_TEST( k>=65 );
    if( k>65 ) rdi >>= (k-65);
  } else {
    if( k>64 ) rdi >>= (k-64);
  }
  return rdi;
}

static ulong
x86_umod64( ulong n, ulong d, uint128 m, int k ) {
  ulong q = x86_udiv64( n, m, k );
  /* imul rdi, rdi, (int)imm; sub reg, rdi */
  return n - q*d;
}

/* check_udiv32_n / check_udiv64_n compare the reduced division and
   modulo against the hardware for a single dividend. */

static inline void
check_udiv32_n( uint n, uint d, ulong m, int k ) {
  FD_TEST( x86_udiv32( n,    m, k )==n/d );
  FD_TEST( x86_umod32( n, d, m, k )==n%d );
  FD_TEST( (uint)(((uint128)n*m)>>k)==n/d ); /* generic identity */
}

static inline void
check_udiv64_n( ulong n, ulong d, uint128 m, int k ) {
  FD_TEST( x86_udiv64( n,    m, k )==n/d );
  FD_TEST( x86_umod64( n, d, m, k )==n%d );
}

/* Interesting dividends for a divisor d: near 0, near multiples of d
   (the hard cases for a round-up multiplier), and near the top of the
   range. */

static void
check_udiv32_edges( uint d, fd_rng_t * rng ) {
  int   k;
  ulong m = fd_transpile_udiv32_magic( d, &k );

  uint const fixed[] = { 0U, 1U, 2U, d-1U, d, d+1U, 2U*d-1U, 2U*d, 2U*d+1U,
                         UINT_MAX, UINT_MAX-1U, UINT_MAX-d+1U, UINT_MAX-d, UINT_MAX-d-1U,
                         UINT_MAX-(UINT_MAX%d), UINT_MAX-(UINT_MAX%d)-1U, UINT_MAX-(UINT_MAX%d)+1U,
                         0x7fffffffU, 0x80000000U, 0x80000001U };
  for( ulong i=0UL; i<sizeof(fixed)/sizeof(fixed[0]); i++ ) check_udiv32_n( fixed[i], d, m, k );

  /* multiples of d and their neighbours */
  for( ulong i=0UL; i<64UL; i++ ) {
    uint q = fd_rng_uint( rng ) % ( UINT_MAX/d + 1U );
    uint n = q*d;
    check_udiv32_n( n, d, m, k );
    if( n>0U ) check_udiv32_n( n-1U, d, m, k );
    if( n<UINT_MAX ) check_udiv32_n( n+1U, d, m, k );
  }
  for( ulong i=0UL; i<64UL; i++ ) check_udiv32_n( fd_rng_uint( rng ), d, m, k );
}

static void
check_udiv64_edges( ulong d, fd_rng_t * rng ) {
  int     k;
  uint128 m = fd_transpile_udiv64_magic( d, &k );

  ulong const fixed[] = { 0UL, 1UL, 2UL, d-1UL, d, d+1UL, 2UL*d-1UL, 2UL*d, 2UL*d+1UL,
                          ULONG_MAX, ULONG_MAX-1UL, ULONG_MAX-d+1UL, ULONG_MAX-d, ULONG_MAX-d-1UL,
                          ULONG_MAX-(ULONG_MAX%d), ULONG_MAX-(ULONG_MAX%d)-1UL, ULONG_MAX-(ULONG_MAX%d)+1UL,
                          0x7fffffffffffffffUL, 0x8000000000000000UL, 0x8000000000000001UL,
                          0xffffffffUL, 0x100000000UL, 0x100000001UL };
  for( ulong i=0UL; i<sizeof(fixed)/sizeof(fixed[0]); i++ ) check_udiv64_n( fixed[i], d, m, k );

  for( ulong i=0UL; i<64UL; i++ ) {
    ulong q = fd_rng_ulong( rng ) % ( ULONG_MAX/d + 1UL );
    ulong n = q*d;
    check_udiv64_n( n, d, m, k );
    if( n>0UL ) check_udiv64_n( n-1UL, d, m, k );
    if( n<ULONG_MAX ) check_udiv64_n( n+1UL, d, m, k );
  }
  for( ulong i=0UL; i<64UL; i++ ) check_udiv64_n( fd_rng_ulong( rng ), d, m, k );
}

/* Exhaustive over all 2^32 dividends for a handful of divisors that
   exercise each emitted code path. */

static void
test_udiv32_exhaustive( uint d ) {
  int   k;
  ulong m = fd_transpile_udiv32_magic( d, &k );
  ulong m_lo = (ulong)(uint)m;
  int   wide = m>(ulong)UINT_MAX;
  uint n = 0U;
  do {
    ulong q;
    if( wide ) q = ( (ulong)n + (((ulong)n*m_lo)>>32) ) >> (k-32);
    else       q = ( (ulong)n*m ) >> k;
    if( FD_UNLIKELY( q!=(ulong)(n/d) ) ) FD_LOG_ERR(( "udiv32 mismatch: n=%u d=%u m=%#lx k=%d q=%lu", n, d, m, k, q ));
    n++;
  } while( n!=0U );
}

FD_UNIT_TEST( udiv_contract ) {
  /* every non-pow2 divisor up to 2^20, both widths */
  for( ulong d=3UL; d<(1UL<<20); d++ ) {
    if( fd_ulong_is_pow2( d ) ) continue;
    check_udiv32_contract( (uint)d );
    check_udiv64_contract( d );
  }
}

FD_UNIT_TEST( udiv_boundaries ) {
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* every non-pow2 divisor in the top 2^16 of the 32-bit range */
  for( ulong d=(1UL<<32)-(1UL<<16); d<(1UL<<32); d++ ) {
    if( fd_ulong_is_pow2( d ) ) continue;
    check_udiv32_contract( (uint)d );
    check_udiv64_contract( d );
  }
  /* divisors straddling each power of two */
  for( int b=2; b<32; b++ ) {
    for( long o=-3L; o<=3L; o++ ) {
      ulong d = (1UL<<b) + (ulong)o;
      if( fd_ulong_is_pow2( d ) || d<3UL ) continue;
      check_udiv32_contract( (uint)d );
      check_udiv64_contract( d );
      check_udiv32_edges( (uint)d, rng );
      check_udiv64_edges( d, rng );
    }
  }
  /* fd_transpile_udiv64_magic caps k at 127 and therefore has no
     solution for many d>=2^63 (e.g. 2^64-8).  emit_udiv64_imm never
     asks for those since a sign extended imm32 divisor >=2^63 takes a
     compare-based path instead, so the sweep stops at 2^63. */
  for( int b=32; b<63; b++ ) {
    for( long o=-3L; o<=3L; o++ ) {
      ulong d = (1UL<<b) + (ulong)o;
      if( fd_ulong_is_pow2( d ) ) continue;
      check_udiv64_contract( d );
      check_udiv64_edges( d, rng );
    }
  }
  for( long o=-3L; o<0L; o++ ) {
    ulong d = (1UL<<63) + (ulong)o;
    check_udiv64_contract( d );
    check_udiv64_edges( d, rng );
  }

  fd_rng_delete( fd_rng_leave( rng ) );
}

FD_UNIT_TEST( udiv_dividend_sweeps ) {
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* dividend sweeps for small divisors and random divisors */
  for( ulong d=3UL; d<4096UL; d++ ) {
    if( fd_ulong_is_pow2( d ) ) continue;
    check_udiv32_edges( (uint)d, rng );
    check_udiv64_edges( d, rng );
  }
  for( ulong i=0UL; i<100000UL; i++ ) {
    uint d32 = fd_rng_uint( rng );
    if( d32>=3U && !fd_uint_is_pow2( d32 ) ) {
      check_udiv32_contract( d32 );
      check_udiv32_edges( d32, rng );
    }
    /* imm32 divisors as emitted by emit_udiv64_imm: 1..2^31-1 */
    ulong d64 = (ulong)(fd_rng_uint( rng )>>1);
    if( d64>=3UL && !fd_ulong_is_pow2( d64 ) ) {
      check_udiv64_contract( d64 );
      check_udiv64_edges( d64, rng );
    }
    d64 = fd_rng_ulong( rng ) >> ( 1U + (fd_rng_uint( rng ) % 63U) );
    if( d64>=3UL && !fd_ulong_is_pow2( d64 ) ) {
      check_udiv64_contract( d64 );
      check_udiv64_edges( d64, rng );
    }
  }

  fd_rng_delete( fd_rng_leave( rng ) );
}

FD_UNIT_TEST( udiv32_exhaustive ) {
  /* exhaustive dividend coverage: narrow m (3), wide m (7), and the
     largest divisor (all n>=d give q=1) */
  test_udiv32_exhaustive( 3U );
  test_udiv32_exhaustive( 7U );
  test_udiv32_exhaustive( 0xffffffffU );
}

FD_UNIT_TEST( transpile_meta ) {
  fd_transpiler_t * t = aligned_alloc( 64UL, sizeof(fd_transpiler_t) );
  FD_TEST( t );

  ulong bpf_text[ 2 ] = {
    0x0000002a000000b7UL, /* mov64 r0, 42 */
    0x0000000000000095UL  /* exit */
  };

  FD_TEST( !fd_vm_transpile_code( t, FD_SBPF_V0, (uchar const *)bpf_text, 2UL, 0UL, NULL, NULL, NULL, 0UL, 0UL ) );
  FD_TEST( t->code_sz > 0UL );
  FD_TEST( t->entrypoint_off == 0UL );
  FD_TEST( t->meta.text_cnt == 2UL );
  FD_TEST( t->meta.text_sz == 16UL );
  FD_TEST( t->meta.entry_pc == 0UL );
  FD_TEST( t->meta.sbpf_version == FD_SBPF_V0 );

  uchar zero[ 32 ] = { 0 };
  FD_TEST( !memcmp( t->meta.prog_id, zero, 32UL ) );
  FD_TEST( !memcmp( t->meta.elf_hash, zero, 32UL ) );

  FD_TEST( !fd_vm_transpile_code( t, FD_SBPF_V1, (uchar const *)bpf_text, 2UL, 1UL, NULL, NULL, NULL, 0UL, 0UL ) );
  FD_TEST( t->code_sz > 0UL );
  FD_TEST( t->entrypoint_off == 0UL );
  FD_TEST( t->meta.text_cnt == 2UL );
  FD_TEST( t->meta.text_sz == 16UL );
  FD_TEST( t->meta.entry_pc == 1UL );
  FD_TEST( t->meta.sbpf_version == FD_SBPF_V1 );

  free( t );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_unit_tests( argc, argv );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
