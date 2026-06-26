#include "../fd_ballet.h"
#include "fd_keccak256.h"
#include "fd_keccak256_avx2_keccak8_eo_asm.h"
#include "fd_keccak256_keccak1eo_asm.h"
#include "fd_keccak256_avx512_keccak4a_asm.h"
#include "fd_keccak256_avx512_keccak8a_asm.h"
#include "fd_keccak256_avx512_keccak8b_asm.h"
#include "fd_keccak256_test_vector.c"
#include <string.h>
#include <immintrin.h>  /* for _pext_u64 / _pdep_u64 in keccak1eo bench helpers */

extern ulong const fd_keccak256_rc[24];

#if FD_HAS_S2NBIGNUM
#include <stdint.h>
#include <s2n-bignum.h>
#endif

FD_STATIC_ASSERT( FD_KECCAK256_ALIGN    ==128UL, unit_test );
FD_STATIC_ASSERT( FD_KECCAK256_FOOTPRINT==256UL, unit_test );

FD_STATIC_ASSERT( FD_KECCAK256_ALIGN    ==alignof(fd_keccak256_t), unit_test );
FD_STATIC_ASSERT( FD_KECCAK256_FOOTPRINT==sizeof (fd_keccak256_t), unit_test );

FD_STATIC_ASSERT( FD_KECCAK256_HASH_SZ==32UL, unit_test );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_TEST( fd_keccak256_align    ()==FD_KECCAK256_ALIGN     );
  FD_TEST( fd_keccak256_footprint()==FD_KECCAK256_FOOTPRINT );

  fd_keccak256_t mem[1];

  FD_TEST( fd_keccak256_new( NULL          )==NULL ); /* null shmem       */
  FD_TEST( fd_keccak256_new( (void *)0x1UL )==NULL ); /* misaligned shmem */

  void * obj = fd_keccak256_new( mem ); FD_TEST( obj );

  FD_TEST( fd_keccak256_join( NULL           )==NULL ); /* null shsha       */
  FD_TEST( fd_keccak256_join( (void *) 0x1UL )==NULL ); /* misaligned shsha */

  fd_keccak256_t * sha = fd_keccak256_join( obj ); FD_TEST( sha );

  uchar hash[ 32 ] __attribute__((aligned(32)));

  for( fd_keccak256_test_vector_t const * vec = fd_keccak256_test_vector; vec->msg; vec++ ) {
    char const *  msg      = vec->msg;
    ulong         sz       = vec->sz;
    uchar const * expected = vec->hash;

    /* test single shot hashing */

    FD_TEST( fd_keccak256_init( sha )==sha );
    FD_TEST( fd_keccak256_append( sha, msg, sz )==sha );
    FD_TEST( fd_keccak256_fini( sha, hash )==hash );
    if( FD_UNLIKELY( memcmp( hash, expected, 32UL ) ) )
      FD_LOG_ERR(( "FAIL (sz %lu)"
                   "\n\tGot"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                   "\n\tExpected"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT, sz,
                   FD_LOG_HEX16_FMT_ARGS(     hash    ), FD_LOG_HEX16_FMT_ARGS(     hash+16 ),
                   FD_LOG_HEX16_FMT_ARGS( expected    ), FD_LOG_HEX16_FMT_ARGS( expected+16 ) ));

    /* test incremental hashing */

    memset( hash, 0, 32UL );
    FD_TEST( fd_keccak256_init( sha )==sha );

    char const * nxt = msg;
    ulong        rem = sz;
    while( rem ) {
      ulong nxt_sz = fd_ulong_min( rem, fd_rng_ulong_roll( rng, sz+1UL ) );
      FD_TEST( fd_keccak256_append( sha, nxt, nxt_sz )==sha );
      nxt += nxt_sz;
      rem -= nxt_sz;
      if( fd_rng_uint( rng ) & 1UL ) FD_TEST( fd_keccak256_append( sha, NULL, 0UL )==sha ); /* test zero append too */
    }

    FD_TEST( fd_keccak256_fini( sha, hash )==hash );

    if( FD_UNLIKELY( memcmp( hash, expected, 32UL ) ) )
      FD_LOG_ERR(( "FAIL (sz %lu)"
                   "\n\tGot"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                   "\n\tExpected"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT, sz,
                   FD_LOG_HEX16_FMT_ARGS(     hash    ), FD_LOG_HEX16_FMT_ARGS(     hash+16 ),
                   FD_LOG_HEX16_FMT_ARGS( expected    ), FD_LOG_HEX16_FMT_ARGS( expected+16 ) ));

  }

#if FD_HAS_S2NBIGNUM
  /* Correctness: batched sha3_keccak4_f1600 vs four sha3_keccak_f1600 */
  do {
    ulong a4[ 100 ];
    for( ulong i=0UL; i<100UL; i++ ) a4[ i ] = (ulong)(0x9e3779b97f4a7c15UL + i*0x517cc1b727220a95UL);
    fd_s2n_sha3_keccak4_f1600( a4 );
    for( ulong lane=0UL; lane<4UL; lane++ ) {
      ulong ref[ 25 ];
      for( ulong j=0UL; j<25UL; j++ ) ref[ j ] = (ulong)(0x9e3779b97f4a7c15UL + (25UL*lane + j)*0x517cc1b727220a95UL);
      sha3_keccak_f1600( (uint64_t *)ref, (uint64_t const *)fd_keccak256_rc );
      FD_TEST( 0==memcmp( ref, a4 + 25UL*(ulong)lane, 25UL*sizeof(ulong) ) );
    }
  } while(0);

  FD_LOG_NOTICE(( "Benchmarking s2n sha3_keccak4_f1600 (4 lanes) vs 4× sha3_keccak_f1600" ));
  do {
    ulong a4[ 100 ] __attribute__((aligned(64)));
    ulong s0[ 25 ] __attribute__((aligned(64)));
    ulong s1[ 25 ] __attribute__((aligned(64)));
    ulong s2[ 25 ] __attribute__((aligned(64)));
    ulong s3[ 25 ] __attribute__((aligned(64)));
    for( ulong i=0UL; i<100UL; i++ ) a4[ i ] = fd_rng_ulong( rng );
    for( ulong i=0UL; i<25UL; i++ ) {
      s0[ i ] = a4[ i       ];
      s1[ i ] = a4[ i+25UL  ];
      s2[ i ] = a4[ i+50UL  ];
      s3[ i ] = a4[ i+75UL  ];
    }
    ulong const iter = 200000UL;
    for( ulong w=0UL; w<10UL; w++ ) fd_s2n_sha3_keccak4_f1600( a4 );
    long dt4 = -fd_log_wallclock();
    for( ulong r=iter; r; r-- ) {
      ulong * _a4 = a4;
      FD_COMPILER_FORGET( _a4 );
      fd_s2n_sha3_keccak4_f1600( a4 );
    }
    dt4 += fd_log_wallclock();
    for( ulong w=0UL; w<10UL; w++ ) {
      sha3_keccak_f1600( (uint64_t *)s0, (uint64_t const *)fd_keccak256_rc );
      sha3_keccak_f1600( (uint64_t *)s1, (uint64_t const *)fd_keccak256_rc );
      sha3_keccak_f1600( (uint64_t *)s2, (uint64_t const *)fd_keccak256_rc );
      sha3_keccak_f1600( (uint64_t *)s3, (uint64_t const *)fd_keccak256_rc );
    }
    long dt1 = -fd_log_wallclock();
    for( ulong r=iter; r; r-- ) {
      ulong * _s0 = s0; ulong * _s1 = s1; ulong * _s2 = s2; ulong * _s3 = s3;
      FD_COMPILER_FORGET( _s0 ); FD_COMPILER_FORGET( _s1 ); FD_COMPILER_FORGET( _s2 ); FD_COMPILER_FORGET( _s3 );
      sha3_keccak_f1600( (uint64_t *)s0, (uint64_t const *)fd_keccak256_rc );
      sha3_keccak_f1600( (uint64_t *)s1, (uint64_t const *)fd_keccak256_rc );
      sha3_keccak_f1600( (uint64_t *)s2, (uint64_t const *)fd_keccak256_rc );
      sha3_keccak_f1600( (uint64_t *)s3, (uint64_t const *)fd_keccak256_rc );
    }
    dt1 += fd_log_wallclock();
    double ns4 = (double)dt4 / (double)iter;
    double ns1 = (double)dt1 / (double)(4UL*iter);
    FD_LOG_NOTICE(( "keccak4_f1600: %.2f ns/call (4 states); 4×keccak_f1600: %.2f ns per state (same iter count)",
                    ns4, ns1 ));
  } while(0);
#endif /* FD_HAS_S2NBIGNUM */

#if FD_HAS_AVX
  /* Correctness: AVX2 keccak8 vs eight sha3_keccak_f1600 (needs s2n ref). */
# if FD_HAS_S2NBIGNUM
  do {
    ulong a8[ 200 ];
    for( ulong i=0UL; i<200UL; i++ ) a8[ i ] = (ulong)(0x9e3779b97f4a7c15UL + i*0x517cc1b727220a95UL);
    ulong ref[ 200 ];
    memcpy( ref, a8, sizeof(a8) );
    fd_keccak256_avx2_keccak8_f1600( a8, fd_keccak256_rc );
    for( ulong lane=0UL; lane<8UL; lane++ ) {
      sha3_keccak_f1600( (uint64_t *)(ref + 25UL*lane), (uint64_t const *)fd_keccak256_rc );
    }
    FD_TEST( 0==memcmp( ref, a8, sizeof(a8) ) );
  } while(0);

  /* Correctness: even/odd bit-interleaved keccak8 vs reference */
  do {
    ulong a8[ 200 ];
    for( ulong i=0UL; i<200UL; i++ ) a8[ i ] = (ulong)(0x9e3779b97f4a7c15UL + i*0x517cc1b727220a95UL);
    ulong ref[ 200 ];
    memcpy( ref, a8, sizeof(a8) );
    fd_keccak256_avx2_keccak8_eo_f1600( a8, fd_keccak256_rc );
    for( ulong lane=0UL; lane<8UL; lane++ ) {
      sha3_keccak_f1600( (uint64_t *)(ref + 25UL*lane), (uint64_t const *)fd_keccak256_rc );
    }
    FD_TEST( 0==memcmp( ref, a8, sizeof(a8) ) );
  } while(0);

# if FD_HAS_AVX512
  /* Correctness: AVX-512 keccak8 (64-bit lanes) vs eight sha3_keccak_f1600. */
  extern void fd_keccak256_avx512_keccak8_f1600( ulong * state, ulong const * rc );
  do {
    ulong a8[ 200 ] __attribute__((aligned(64)));
    for( ulong i=0UL; i<200UL; i++ ) a8[ i ] = (ulong)(0x9e3779b97f4a7c15UL + i*0x517cc1b727220a95UL);
    ulong ref[ 200 ] __attribute__((aligned(64)));
    memcpy( ref, a8, sizeof(a8) );
    fd_keccak256_avx512_keccak8_f1600( a8, fd_keccak256_rc );
    for( ulong lane=0UL; lane<8UL; lane++ ) {
      sha3_keccak_f1600( (uint64_t *)(ref + 25UL*lane), (uint64_t const *)fd_keccak256_rc );
    }
    FD_TEST( 0==memcmp( ref, a8, sizeof(a8) ) );
    FD_LOG_NOTICE(( "fd_keccak256_avx512_keccak8: correct vs sha3_keccak_f1600 reference (8 lanes)" ));
  } while(0);

  /* Correctness: keccak4a (asm, mechanical lift of s2n keccak4 to AVX-512). */
  do {
    ulong a4[ 100 ] __attribute__((aligned(64)));
    for( ulong i=0UL; i<100UL; i++ ) a4[ i ] = (ulong)(0x9e3779b97f4a7c15UL + i*0x517cc1b727220a95UL);
    ulong ref4[ 100 ] __attribute__((aligned(64)));
    memcpy( ref4, a4, sizeof(a4) );
    fd_keccak256_avx512_keccak4a_f1600_asm( a4, fd_keccak256_rc );
    for( ulong lane=0UL; lane<4UL; lane++ ) {
      sha3_keccak_f1600( (uint64_t *)(ref4 + 25UL*lane), (uint64_t const *)fd_keccak256_rc );
    }
    FD_TEST( 0==memcmp( ref4, a4, sizeof(a4) ) );
    FD_LOG_NOTICE(( "fd_keccak256_avx512_keccak4a (asm): correct vs sha3_keccak_f1600 reference (4 lanes)" ));
  } while(0);
# if FD_HAS_S2NBIGNUM
  /* Stronger correctness: keccak4a (asm) and s2n's sha3_keccak4_f1600
     must produce bit-identical output for any input.  Fuzzes 1000 random
     states and 1..N round iterations to catch any divergence between the
     mechanical lift and its source. */
  do {
    ulong a_lift[ 100 ] __attribute__((aligned(64)));
    ulong a_s2n [ 100 ] __attribute__((aligned(64)));
    ulong const niter = 1000UL;
    for( ulong it=0UL; it<niter; it++ ) {
      for( ulong i=0UL; i<100UL; i++ ) a_lift[ i ] = a_s2n[ i ] = fd_rng_ulong( rng );
      fd_keccak256_avx512_keccak4a_f1600_asm( a_lift, fd_keccak256_rc );
      sha3_keccak4_f1600( (uint64_t *)a_s2n, (uint64_t const *)fd_keccak256_rc );
      if( FD_UNLIKELY( 0!=memcmp( a_lift, a_s2n, sizeof(a_lift) ) ) ) {
        for( int i=0; i<100; i++ ) if( a_lift[i]!=a_s2n[i] ) {
          FD_LOG_ERR(( "iter %lu: divergence at u64 %d (state %d, lane %d): lift=%016lx s2n=%016lx",
                       it, i, i/25, i%25, a_lift[i], a_s2n[i] ));
        }
      }
    }
    /* Also: re-running the asm K times should match s2n called K times. */
    for( ulong i=0UL; i<100UL; i++ ) a_lift[ i ] = a_s2n[ i ] = fd_rng_ulong( rng );
    for( int k=0; k<10; k++ ) {
      fd_keccak256_avx512_keccak4a_f1600_asm( a_lift, fd_keccak256_rc );
      sha3_keccak4_f1600( (uint64_t *)a_s2n, (uint64_t const *)fd_keccak256_rc );
      FD_TEST( 0==memcmp( a_lift, a_s2n, sizeof(a_lift) ) );
    }
    FD_LOG_NOTICE(( "fd_keccak256_avx512_keccak4a (asm): bit-identical to sha3_keccak4_f1600 over %lu random states + 10 chained perms", niter ));
  } while(0);
  /* keccak8a (asm): correctness vs 8x sha3_keccak_f1600 reference. */
  do {
    ulong a8[ 200 ] __attribute__((aligned(64)));
    for( ulong i=0UL; i<200UL; i++ ) a8[ i ] = (ulong)(0x9e3779b97f4a7c15UL + i*0x517cc1b727220a95UL);
    ulong ref8[ 200 ] __attribute__((aligned(64)));
    memcpy( ref8, a8, sizeof(a8) );
    fd_keccak256_avx512_keccak8a_f1600_asm( a8, fd_keccak256_rc );
    for( ulong lane=0UL; lane<8UL; lane++ ) {
      sha3_keccak_f1600( (uint64_t *)(ref8 + 25UL*lane), (uint64_t const *)fd_keccak256_rc );
    }
    FD_TEST( 0==memcmp( ref8, a8, sizeof(a8) ) );
    FD_LOG_NOTICE(( "fd_keccak256_avx512_keccak8a (asm): correct vs sha3_keccak_f1600 reference (8 lanes)" ));
  } while(0);
  /* keccak8a (asm): equivalence with two keccak4a invocations on the
     state halves.  This guarantees the 8a boundary correctly transposes
     8 states without cross-lane contamination — anything that mishandles
     any of the 8 input/output offsets shows up as a memcmp mismatch. */
  do {
    ulong full [ 200 ] __attribute__((aligned(64)));
    ulong split[ 200 ] __attribute__((aligned(64)));
    ulong const niter = 1000UL;
    for( ulong it=0UL; it<niter; it++ ) {
      for( ulong i=0UL; i<200UL; i++ ) full[ i ] = split[ i ] = fd_rng_ulong( rng );
      fd_keccak256_avx512_keccak8a_f1600_asm( full, fd_keccak256_rc );
      fd_keccak256_avx512_keccak4a_f1600_asm( split,        fd_keccak256_rc );
      fd_keccak256_avx512_keccak4a_f1600_asm( split + 100,  fd_keccak256_rc );
      if( FD_UNLIKELY( 0!=memcmp( full, split, sizeof(full) ) ) ) {
        for( int i=0; i<200; i++ ) if( full[i]!=split[i] ) {
          FD_LOG_ERR(( "iter %lu: 8a vs 2x4a divergence at u64 %d (state %d, lane %d): 8a=%016lx 4a=%016lx",
                       it, i, i/25, i%25, full[i], split[i] ));
        }
      }
    }
    FD_LOG_NOTICE(( "fd_keccak256_avx512_keccak8a (asm): bit-identical to 2x keccak4a over %lu random states", niter ));
  } while(0);
  /* keccak8b (asm): correctness vs 8x sha3_keccak_f1600 reference. */
  do {
    ulong a8[ 200 ] __attribute__((aligned(64)));
    for( ulong i=0UL; i<200UL; i++ ) a8[ i ] = (ulong)(0x9e3779b97f4a7c15UL + i*0x517cc1b727220a95UL);
    ulong ref8[ 200 ] __attribute__((aligned(64)));
    memcpy( ref8, a8, sizeof(a8) );
    fd_keccak256_avx512_keccak8b_f1600_asm( a8, fd_keccak256_rc );
    for( ulong lane=0UL; lane<8UL; lane++ ) {
      sha3_keccak_f1600( (uint64_t *)(ref8 + 25UL*lane), (uint64_t const *)fd_keccak256_rc );
    }
    FD_TEST( 0==memcmp( ref8, a8, sizeof(a8) ) );
    FD_LOG_NOTICE(( "fd_keccak256_avx512_keccak8b (asm): correct vs sha3_keccak_f1600 reference (8 lanes)" ));
  } while(0);
  /* keccak8b (asm): bit-identical to keccak8a (vprolq is the only diff). */
  do {
    ulong a8a[ 200 ] __attribute__((aligned(64)));
    ulong a8b[ 200 ] __attribute__((aligned(64)));
    ulong const niter = 1000UL;
    for( ulong it=0UL; it<niter; it++ ) {
      for( ulong i=0UL; i<200UL; i++ ) a8a[ i ] = a8b[ i ] = fd_rng_ulong( rng );
      fd_keccak256_avx512_keccak8a_f1600_asm( a8a, fd_keccak256_rc );
      fd_keccak256_avx512_keccak8b_f1600_asm( a8b, fd_keccak256_rc );
      if( FD_UNLIKELY( 0!=memcmp( a8a, a8b, sizeof(a8a) ) ) ) {
        for( int i=0; i<200; i++ ) if( a8a[i]!=a8b[i] ) {
          FD_LOG_ERR(( "iter %lu: 8a vs 8b divergence at u64 %d (state %d, lane %d): 8a=%016lx 8b=%016lx",
                       it, i, i/25, i%25, a8a[i], a8b[i] ));
        }
      }
    }
    FD_LOG_NOTICE(( "fd_keccak256_avx512_keccak8b (asm): bit-identical to keccak8a over %lu random states", niter ));
  } while(0);
# endif
# endif
# endif

  FD_LOG_NOTICE(( "Benchmarking fd_keccak256_avx2_keccak8_f1600 (8 states, AVX2 interleaved) vs keccak4 vs 8×keccak_f1600" ));
  do {
    ulong a8[ 200 ] __attribute__((aligned(64)));
    ulong a4[ 100 ] __attribute__((aligned(64)));
    ulong s0[ 25 ] __attribute__((aligned(64)));
    ulong s1[ 25 ] __attribute__((aligned(64)));
    ulong s2[ 25 ] __attribute__((aligned(64)));
    ulong s3[ 25 ] __attribute__((aligned(64)));
    ulong s4[ 25 ] __attribute__((aligned(64)));
    ulong s5[ 25 ] __attribute__((aligned(64)));
    ulong s6[ 25 ] __attribute__((aligned(64)));
    ulong s7[ 25 ] __attribute__((aligned(64)));
    for( ulong i=0UL; i<200UL; i++ ) a8[ i ] = fd_rng_ulong( rng );
    for( ulong i=0UL; i<100UL; i++ ) a4[ i ] = a8[ i ];
    for( ulong i=0UL; i<25UL; i++ ) {
      s0[ i ] = a8[ i       ]; s1[ i ] = a8[ i+25UL  ]; s2[ i ] = a8[ i+50UL  ]; s3[ i ] = a8[ i+75UL  ];
      s4[ i ] = a8[ i+100UL ]; s5[ i ] = a8[ i+125UL ]; s6[ i ] = a8[ i+150UL ]; s7[ i ] = a8[ i+175UL ];
    }
    ulong const iter = 200000UL;
    for( ulong w=0UL; w<10UL; w++ ) fd_keccak256_avx2_keccak8_f1600( a8, fd_keccak256_rc );
    long dt8 = -fd_log_wallclock();
    for( ulong r=iter; r; r-- ) {
      ulong * _a8 = a8;
      FD_COMPILER_FORGET( _a8 );
      fd_keccak256_avx2_keccak8_f1600( a8, fd_keccak256_rc );
    }
    dt8 += fd_log_wallclock();

    /* Even/odd variant (with boundary pack/unpack) */
    ulong a8eo[ 200 ] __attribute__((aligned(64)));
    for( ulong i=0UL; i<200UL; i++ ) a8eo[ i ] = a8[ i ];
    for( ulong w=0UL; w<10UL; w++ ) fd_keccak256_avx2_keccak8_eo_f1600( a8eo, fd_keccak256_rc );
    long dt8eo = -fd_log_wallclock();
    for( ulong r=iter; r; r-- ) {
      ulong * _a8eo = a8eo;
      FD_COMPILER_FORGET( _a8eo );
      fd_keccak256_avx2_keccak8_eo_f1600( a8eo, fd_keccak256_rc );
    }
    dt8eo += fd_log_wallclock();

    /* Even/odd variant RAW (no boundary pack/unpack — pure round-loop cost).
       state_eo: 50 ymm = 1600 bytes; rc_eo: pre-deinterleaved 48 uint32. */
    uint state_eo[ 400 ] __attribute__((aligned(32))); /* 50 ymm * 8 uints = 400 uints = 1600 B */
    memset( state_eo, 0, sizeof(state_eo) ); /* arbitrary state — only timing */
    static uint rc_eo_table[ 48 ] __attribute__((aligned(32)));
    for( int rr=0; rr<24; rr++ ) {
      ulong const w = fd_keccak256_rc[ rr ];
      rc_eo_table[ 2*rr   ] = (uint)_pext_u64( w, 0x5555555555555555UL );
      rc_eo_table[ 2*rr+1 ] = (uint)_pext_u64( w, 0xAAAAAAAAAAAAAAAAUL );
    }
    for( ulong w=0UL; w<10UL; w++ ) fd_keccak256_avx2_keccak8_eo_f1600_raw( state_eo, rc_eo_table );
    long dt8eo_raw = -fd_log_wallclock();
    for( ulong r=iter; r; r-- ) {
      void * _s = state_eo;
      FD_COMPILER_FORGET( _s );
      fd_keccak256_avx2_keccak8_eo_f1600_raw( state_eo, rc_eo_table );
    }
    dt8eo_raw += fd_log_wallclock();

    /* Asm version (.inc-based, inlined) — same semantics as e/o raw. */
    uint state_eo_asm[ 400 ] __attribute__((aligned(32)));
    memcpy( state_eo_asm, state_eo, sizeof(state_eo_asm) );
    for( ulong w=0UL; w<10UL; w++ ) fd_keccak256_avx2_keccak8_eo_f1600_raw_asm( state_eo_asm, rc_eo_table );
    long dt8eo_asm = -fd_log_wallclock();
    for( ulong r=iter; r; r-- ) {
      void * _s = state_eo_asm;
      FD_COMPILER_FORGET( _s );
      fd_keccak256_avx2_keccak8_eo_f1600_raw_asm( state_eo_asm, rc_eo_table );
    }
    dt8eo_asm += fd_log_wallclock();

    /* Cross-check: asm and C raw must produce identical output starting from same state. */
    uint chk_c[ 400 ] __attribute__((aligned(32)));
    uint chk_a[ 400 ] __attribute__((aligned(32)));
    memset( chk_c, 0xa5, sizeof(chk_c) );
    memcpy( chk_a, chk_c, sizeof(chk_c) );
    fd_keccak256_avx2_keccak8_eo_f1600_raw    ( chk_c, rc_eo_table );
    fd_keccak256_avx2_keccak8_eo_f1600_raw_asm( chk_a, rc_eo_table );
    int first_diff = -1;
    for( int i=0; i<400; i++ ) if( chk_c[i] != chk_a[i] ) { first_diff = i; break; }
    if( first_diff >= 0 ) {
      FD_LOG_NOTICE(( "DIFF first at uint %d (slot=%d, lane=%d): C=%08x ASM=%08x",
        first_diff, first_diff/8, first_diff%8, chk_c[first_diff], chk_a[first_diff] ));
      /* Show first 16 uints from each, side-by-side */
      for( int i=0; i<16; i++ ) {
        FD_LOG_NOTICE(( "  uint %2d  C=%08x  ASM=%08x  %s", i, chk_c[i], chk_a[i],
                        chk_c[i]==chk_a[i] ? "" : "DIFF" ));
      }
    }
    FD_TEST( 0 == memcmp( chk_c, chk_a, sizeof(chk_c) ) );

#if FD_HAS_AVX512
    /* ====================================================================
       AVX-512 keccak8 (64-bit lanes, no EO encoding) bench.
       ==================================================================== */
    do {
      ulong a8z[ 200 ] __attribute__((aligned(64)));
      memcpy( a8z, a8, sizeof(a8z) );
      for( ulong w=0UL; w<10UL; w++ ) fd_keccak256_avx512_keccak8_f1600( a8z, fd_keccak256_rc );
      long dtz = -fd_log_wallclock();
      for( ulong r=iter; r; r-- ) {
        ulong * _a = a8z;
        FD_COMPILER_FORGET( _a );
        fd_keccak256_avx512_keccak8_f1600( a8z, fd_keccak256_rc );
      }
      dtz += fd_log_wallclock();
      FD_LOG_NOTICE(( "fd_keccak256_avx512_keccak8 (8 lanes, AoS in/out) : %.1f ns/state",
                      (double)dtz / (double)(iter * 8UL) ));

      /* Raw variant (state already in lane-major SoA, no boundary conversion). */
      extern void fd_keccak256_avx512_keccak8_f1600_raw( void * state_soa, ulong const * rc );
      ulong state_soa[ 200 ] __attribute__((aligned(64)));
      memset( state_soa, 0, sizeof(state_soa) );
      for( ulong w=0UL; w<10UL; w++ ) fd_keccak256_avx512_keccak8_f1600_raw( state_soa, fd_keccak256_rc );
      long dtzr = -fd_log_wallclock();
      for( ulong r=iter; r; r-- ) {
        void * _s = state_soa;
        FD_COMPILER_FORGET( _s );
        fd_keccak256_avx512_keccak8_f1600_raw( state_soa, fd_keccak256_rc );
      }
      dtzr += fd_log_wallclock();
      FD_LOG_NOTICE(( "fd_keccak256_avx512_keccak8 (8 lanes, raw SoA)    : %.1f ns/state",
                      (double)dtzr / (double)(iter * 8UL) ));
    } while(0);

    /* ====================================================================
       AVX-512 keccak16 EO (16 lanes, EO bit-interleaved).
       ==================================================================== */
    extern void fd_keccak256_avx512_keccak16_eo_f1600( ulong * state, ulong const * rc );
    extern void fd_keccak256_avx512_keccak16_eo_f1600_raw( void * state_eo, uint const * rc_eo );
    do {
      /* Correctness: 16 deterministic states vs 16x sha3_keccak_f1600. */
      ulong a16[ 400 ] __attribute__((aligned(64)));
      for( ulong i=0UL; i<400UL; i++ ) a16[ i ] = (ulong)(0x9e3779b97f4a7c15UL + i*0x517cc1b727220a95UL);
      ulong ref16[ 400 ] __attribute__((aligned(64)));
      memcpy( ref16, a16, sizeof(a16) );
      fd_keccak256_avx512_keccak16_eo_f1600( a16, fd_keccak256_rc );
      for( ulong lane=0UL; lane<16UL; lane++ ) {
        sha3_keccak_f1600( (uint64_t *)(ref16 + 25UL*lane), (uint64_t const *)fd_keccak256_rc );
      }
      FD_TEST( 0==memcmp( ref16, a16, sizeof(a16) ) );
      FD_LOG_NOTICE(( "fd_keccak256_avx512_keccak16_eo: correct vs sha3_keccak_f1600 reference (16 lanes)" ));

      /* Bench: AoS-in/out path. */
      for( ulong w=0UL; w<10UL; w++ ) fd_keccak256_avx512_keccak16_eo_f1600( a16, fd_keccak256_rc );
      long dt16 = -fd_log_wallclock();
      for( ulong r=iter; r; r-- ) {
        ulong * _a = a16;
        FD_COMPILER_FORGET( _a );
        fd_keccak256_avx512_keccak16_eo_f1600( a16, fd_keccak256_rc );
      }
      dt16 += fd_log_wallclock();
      FD_LOG_NOTICE(( "fd_keccak256_avx512_keccak16_eo (16 lanes, AoS)   : %.1f ns/state",
                      (double)dt16 / (double)(iter * 16UL) ));

      /* Bench: raw SoA path (no boundary conversion). */
      uint state_eo16[ 800 ] __attribute__((aligned(64))); /* 50 zmm * 16 u32 = 800 u32 */
      memset( state_eo16, 0, sizeof(state_eo16) );
      for( ulong w=0UL; w<10UL; w++ ) fd_keccak256_avx512_keccak16_eo_f1600_raw( state_eo16, rc_eo_table );
      long dt16r = -fd_log_wallclock();
      for( ulong r=iter; r; r-- ) {
        void * _s = state_eo16;
        FD_COMPILER_FORGET( _s );
        fd_keccak256_avx512_keccak16_eo_f1600_raw( state_eo16, rc_eo_table );
      }
      dt16r += fd_log_wallclock();
      FD_LOG_NOTICE(( "fd_keccak256_avx512_keccak16_eo (16 lanes, raw)   : %.1f ns/state",
                      (double)dt16r / (double)(iter * 16UL) ));

    } while(0);
#endif

    /* ====================================================================
       Phase 1 / keccak1eo: scalar reference, mirrors keccak8eo line-by-line.
       Verify against sha3_keccak_f1600 reference and bench a single state.
       ==================================================================== */
    do {
      /* Random initial state. */
      ulong init[ 25 ];
      for( ulong i=0; i<25; i++ ) init[ i ] = fd_rng_ulong( rng );

      /* Reference: 24 rounds of standard keccak. */
      ulong ref[ 25 ];
      memcpy( ref, init, sizeof(ref) );
      sha3_keccak_f1600( (uint64_t *)ref, (uint64_t const *)fd_keccak256_rc );

      /* Pack init into (E,O) form for keccak1eo. */
      uint state1[ 50 ] __attribute__((aligned(32)));
      for( ulong z=0; z<25; z++ ) {
        state1[ z      ] = (uint)_pext_u64( init[z], 0x5555555555555555UL );
        state1[ 25 + z ] = (uint)_pext_u64( init[z], 0xAAAAAAAAAAAAAAAAUL );
      }

      /* Run keccak1eo. */
      fd_keccak256_keccak1eo_f1600_raw_asm( state1, rc_eo_table );

      /* Unpack and compare. */
      for( ulong z=0; z<25; z++ ) {
        ulong got = _pdep_u64( (ulong)state1[ z ],      0x5555555555555555UL )
                  | _pdep_u64( (ulong)state1[ 25 + z ], 0xAAAAAAAAAAAAAAAAUL );
        if( got != ref[ z ] ) {
          FD_LOG_ERR(( "keccak1eo MISMATCH at lane %lu: got=%016lx expected=%016lx",
                       z, got, ref[ z ] ));
        }
      }
      FD_LOG_NOTICE(( "keccak1eo: correct vs sha3_keccak_f1600 reference" ));

      /* Bench keccak1eo (1 state, 24 rounds). */
      for( ulong w=0; w<10; w++ ) fd_keccak256_keccak1eo_f1600_raw_asm( state1, rc_eo_table );
      long dt1eo = -fd_log_wallclock();
      for( ulong r=iter; r; r-- ) {
        void * _s = state1;
        FD_COMPILER_FORGET( _s );
        fd_keccak256_keccak1eo_f1600_raw_asm( state1, rc_eo_table );
      }
      dt1eo += fd_log_wallclock();
      double ns1eo = (double)dt1eo / (double)iter;
      FD_LOG_NOTICE(( "keccak1eo (scalar asm) : %.2f ns/state (1 state)", ns1eo ));
    } while(0);

    /* Persistent (E,O) sponge: absorb one block + f1600_raw, repeated.
       Represents a long-message sponge where state stays in EO form across
       blocks; only input absorption pays per-block boundary cost. */
    ulong block_in[ 8*17 ] __attribute__((aligned(64)));
    for( ulong i=0UL; i<8UL*17UL; i++ ) block_in[ i ] = fd_rng_ulong( rng );
    for( ulong w=0UL; w<10UL; w++ ) {
      fd_keccak256_avx2_keccak8_eo_absorb_block( block_in, state_eo );
      fd_keccak256_avx2_keccak8_eo_f1600_raw( state_eo, rc_eo_table );
    }
    long dt8eo_blk = -fd_log_wallclock();
    for( ulong r=iter; r; r-- ) {
      void * _s = state_eo;
      FD_COMPILER_FORGET( _s );
      fd_keccak256_avx2_keccak8_eo_absorb_block( block_in, state_eo );
      fd_keccak256_avx2_keccak8_eo_f1600_raw( state_eo, rc_eo_table );
    }
    dt8eo_blk += fd_log_wallclock();

# if FD_HAS_S2NBIGNUM
    for( ulong w=0UL; w<10UL; w++ ) fd_s2n_sha3_keccak4_f1600( a4 );
    long dt4 = -fd_log_wallclock();
    for( ulong r=iter; r; r-- ) {
      ulong * _a4 = a4;
      FD_COMPILER_FORGET( _a4 );
      fd_s2n_sha3_keccak4_f1600( a4 );
    }
    dt4 += fd_log_wallclock();

    for( ulong w=0UL; w<10UL; w++ ) {
      sha3_keccak_f1600( (uint64_t *)s0, (uint64_t const *)fd_keccak256_rc );
      sha3_keccak_f1600( (uint64_t *)s1, (uint64_t const *)fd_keccak256_rc );
      sha3_keccak_f1600( (uint64_t *)s2, (uint64_t const *)fd_keccak256_rc );
      sha3_keccak_f1600( (uint64_t *)s3, (uint64_t const *)fd_keccak256_rc );
      sha3_keccak_f1600( (uint64_t *)s4, (uint64_t const *)fd_keccak256_rc );
      sha3_keccak_f1600( (uint64_t *)s5, (uint64_t const *)fd_keccak256_rc );
      sha3_keccak_f1600( (uint64_t *)s6, (uint64_t const *)fd_keccak256_rc );
      sha3_keccak_f1600( (uint64_t *)s7, (uint64_t const *)fd_keccak256_rc );
    }
    long dt1 = -fd_log_wallclock();
    for( ulong r=iter; r; r-- ) {
      ulong * _s0 = s0; ulong * _s1 = s1; ulong * _s2 = s2; ulong * _s3 = s3;
      ulong * _s4 = s4; ulong * _s5 = s5; ulong * _s6 = s6; ulong * _s7 = s7;
      FD_COMPILER_FORGET( _s0 ); FD_COMPILER_FORGET( _s1 ); FD_COMPILER_FORGET( _s2 ); FD_COMPILER_FORGET( _s3 );
      FD_COMPILER_FORGET( _s4 ); FD_COMPILER_FORGET( _s5 ); FD_COMPILER_FORGET( _s6 ); FD_COMPILER_FORGET( _s7 );
      sha3_keccak_f1600( (uint64_t *)s0, (uint64_t const *)fd_keccak256_rc );
      sha3_keccak_f1600( (uint64_t *)s1, (uint64_t const *)fd_keccak256_rc );
      sha3_keccak_f1600( (uint64_t *)s2, (uint64_t const *)fd_keccak256_rc );
      sha3_keccak_f1600( (uint64_t *)s3, (uint64_t const *)fd_keccak256_rc );
      sha3_keccak_f1600( (uint64_t *)s4, (uint64_t const *)fd_keccak256_rc );
      sha3_keccak_f1600( (uint64_t *)s5, (uint64_t const *)fd_keccak256_rc );
      sha3_keccak_f1600( (uint64_t *)s6, (uint64_t const *)fd_keccak256_rc );
      sha3_keccak_f1600( (uint64_t *)s7, (uint64_t const *)fd_keccak256_rc );
    }
    dt1 += fd_log_wallclock();

    double ns8 = (double)dt8 / (double)iter;
    double ns8_per = ns8 / 8.0;
    double ns8eo = (double)dt8eo / (double)iter;
    double ns8eo_per = ns8eo / 8.0;
    double ns8eo_raw = (double)dt8eo_raw / (double)iter;
    double ns8eo_raw_per = ns8eo_raw / 8.0;
    double ns4 = (double)dt4 / (double)iter;
    double ns4_per = ns4 / 4.0;
    double ns1 = (double)dt1 / (double)(8UL*iter);
    double ns8eo_blk = (double)dt8eo_blk / (double)iter;
    double ns8eo_blk_per = ns8eo_blk / 8.0;
    double ns8eo_asm = (double)dt8eo_asm / (double)iter;
    double ns8eo_asm_per = ns8eo_asm / 8.0;
    FD_LOG_NOTICE(( "keccak8_avx2 (lo/hi)         : %.2f ns/call, %.2f ns/state", ns8,         ns8_per         ));
    FD_LOG_NOTICE(( "keccak8_avx2 (e/o)           : %.2f ns/call, %.2f ns/state", ns8eo,       ns8eo_per       ));
    FD_LOG_NOTICE(( "keccak8_avx2 (e/o, raw)      : %.2f ns/call, %.2f ns/state", ns8eo_raw,   ns8eo_raw_per   ));
    FD_LOG_NOTICE(( "keccak8_avx2 (e/o, raw asm)  : %.2f ns/call, %.2f ns/state", ns8eo_asm,   ns8eo_asm_per   ));
    FD_LOG_NOTICE(( "keccak8_avx2 (e/o, absrb+rw) : %.2f ns/call, %.2f ns/state", ns8eo_blk,   ns8eo_blk_per   ));
    FD_LOG_NOTICE(( "keccak4 (s2n asm)            : %.2f ns/call, %.2f ns/state", ns4,         ns4_per         ));
    FD_LOG_NOTICE(( "1xkeccak (avg)               : %.2f ns/state", ns1 ));
# else
    double ns8 = (double)dt8 / (double)iter;
    double ns8_per = ns8 / 8.0;
    FD_LOG_NOTICE(( "keccak8_avx2: %.2f ns/call (8 states), %.2f ns/state (s2n keccak4 / 8×keccak bench skipped without FD_HAS_S2NBIGNUM)",
                    ns8, ns8_per ));
# endif
  } while(0);
#endif /* FD_HAS_AVX */

  /* do a quick benchmark of keccak-256 on small and large UDP payload
     packets from UDP/IP4/VLAN/Ethernet */

  static ulong const bench_sz[2] = { 14UL, 1472UL };

  uchar buf[ 1472 ] __attribute__((aligned(128)));
  for( ulong b=0UL; b<1472UL; b++ ) buf[b] = fd_rng_uchar( rng );

  FD_LOG_NOTICE(( "Benchmarking incremental (best case)" ));
  for( ulong idx=0U; idx<2UL; idx++ ) {
    ulong sz = bench_sz[ idx ];
  
    /* warmup */
    for( ulong rem=10UL; rem; rem-- ) fd_keccak256_fini( fd_keccak256_append( fd_keccak256_init( sha ), buf, sz ), hash );
  
    /* for real */
    ulong iter = 100000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_keccak256_fini( fd_keccak256_append( fd_keccak256_init( sha ), buf, sz ), hash );
    dt += fd_log_wallclock();
    float gbps = ((float)(8UL*(70UL+sz)*iter)) / ((float)dt);
    FD_LOG_NOTICE(( "~%.3f Gbps Ethernet equiv throughput / core (sz %4lu)", (double)gbps, sz ));
  }

  FD_LOG_NOTICE(( "Benchmarking streamlined" ));
  for( ulong idx=0U; idx<2UL; idx++ ) {
    ulong sz = bench_sz[ idx ];

    /* warmup */
    for( ulong rem=10UL; rem; rem-- ) fd_keccak256_hash( buf, sz, hash );

    /* for real */
    ulong iter = 100000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_keccak256_hash( buf, sz, hash );
    dt += fd_log_wallclock();
    float gbps = ((float)(8UL*(70UL+sz)*iter)) / ((float)dt);
    FD_LOG_NOTICE(( "~%.3f Gbps Ethernet equiv throughput / core (sz %4lu)", (double)gbps, sz ));
  }

  /* ====================================================================
     UNIFIED PERMUTATION BENCHMARK SUMMARY
     ====================================================================
     Runs every available Keccak-f[1600] permutation variant under a
     single uniform harness and prints a portable summary table at the
     end.  Results above this section are kept for per-bench detail; the
     table below is what to compare across machines.

     Each variant is benchmarked twice and the BETTER result is reported
     to filter out scheduling jitter.  ns/state is the per-Keccak-state
     cost (= ns/call divided by lanes); for raw variants this is the
     pure round-loop cost (no boundary conversion). */

  do {
    enum { CAP = 32 };
    char const * names[ CAP ];
    char const * tags [ CAP ];   /* short variant tag, e.g. "AVX-512", "asm" */
    int          lanes[ CAP ];
    double       ns_st[ CAP ];   /* ns per state */
    double       ns_cl[ CAP ];   /* ns per call (= ns_state * lanes) */
    int          n = 0;

#   define BENCH_RECORD( NAME, TAG, LANES, NS_PER_CALL ) do {        \
      if( n < CAP ) {                                                \
        names[ n ] = (NAME);                                         \
        tags [ n ] = (TAG);                                          \
        lanes[ n ] = (LANES);                                        \
        ns_cl[ n ] = (NS_PER_CALL);                                  \
        ns_st[ n ] = (NS_PER_CALL) / (double)(LANES);                \
        n++;                                                         \
      }                                                              \
    } while(0)

#   define BENCH_TIME_BEST( ITER, CALL, OUT_NS_CALL ) do {           \
      double _best = 1e30;                                           \
      for( int _t=0; _t<3; _t++ ) {                                  \
        for( ulong _w=0UL; _w<10UL; _w++ ) { CALL; }                 \
        long _dt = -fd_log_wallclock();                              \
        for( ulong _r=(ITER); _r; _r-- ) { CALL; }                   \
        _dt += fd_log_wallclock();                                   \
        double _ns = (double)_dt / (double)(ITER);                   \
        if( _ns < _best ) _best = _ns;                               \
      }                                                              \
      *(OUT_NS_CALL) = _best;                                        \
    } while(0)

    ulong const ITER = 200000UL;
    double t;

    /* -- 1-state baselines -------------------------------------------- */
#   if FD_HAS_S2NBIGNUM
    {
      ulong s[ 25 ] __attribute__((aligned(64)));
      for( ulong i=0; i<25; i++ ) s[ i ] = fd_rng_ulong( rng );
      ulong * _s = s; FD_COMPILER_FORGET( _s );
      BENCH_TIME_BEST( ITER,
        sha3_keccak_f1600( (uint64_t *)s, (uint64_t const *)fd_keccak256_rc ),
        &t );
      BENCH_RECORD( "sha3_keccak_f1600", "s2n asm,scalar",  1, t );
    }
#   endif

    /* keccak1eo (our scalar EO asm).  Builds rc_eo locally so the bench
       is independent of the AVX2 section above. */
    {
      uint rc_eo[ 48 ] __attribute__((aligned(64)));
      for( int rr=0; rr<24; rr++ ) {
        ulong const w = fd_keccak256_rc[ rr ];
        rc_eo[ 2*rr   ] = (uint)_pext_u64( w, 0x5555555555555555UL );
        rc_eo[ 2*rr+1 ] = (uint)_pext_u64( w, 0xAAAAAAAAAAAAAAAAUL );
      }
      uint s[ 50 ] __attribute__((aligned(64)));
      for( ulong i=0; i<50; i++ ) s[ i ] = fd_rng_uint( rng );
      void * _s = s; FD_COMPILER_FORGET( _s );
      BENCH_TIME_BEST( ITER,
        fd_keccak256_keccak1eo_f1600_raw_asm( s, rc_eo ),
        &t );
      BENCH_RECORD( "keccak1eo (EO 32b)", "our asm,scalar", 1, t );
    }

    /* -- 4-state batch ------------------------------------------------ */
#   if FD_HAS_S2NBIGNUM
    {
      ulong s[ 100 ] __attribute__((aligned(64)));
      for( ulong i=0; i<100; i++ ) s[ i ] = fd_rng_ulong( rng );
      ulong * _s = s; FD_COMPILER_FORGET( _s );
      BENCH_TIME_BEST( ITER,
        fd_s2n_sha3_keccak4_f1600( s ),
        &t );
      BENCH_RECORD( "sha3_keccak4_f1600", "s2n asm,AVX2",   4, t );
    }
#   endif

    /* -- 8-state batch (AVX2) ----------------------------------------- */
#   if FD_HAS_AVX
    {
      ulong s[ 200 ] __attribute__((aligned(64)));
      for( ulong i=0; i<200; i++ ) s[ i ] = fd_rng_ulong( rng );
      ulong * _s = s; FD_COMPILER_FORGET( _s );

      /* AVX2 keccak8 lo/hi limb method, with boundary conversion. */
      BENCH_TIME_BEST( ITER,
        fd_keccak256_avx2_keccak8_f1600( s, fd_keccak256_rc ),
        &t );
      BENCH_RECORD( "avx2_keccak8 (lo/hi)", "C, w/bound",   8, t );

      /* AVX2 keccak8 EO with boundary conversion. */
      for( ulong i=0; i<200; i++ ) s[ i ] = fd_rng_ulong( rng );
      BENCH_TIME_BEST( ITER,
        fd_keccak256_avx2_keccak8_eo_f1600( s, fd_keccak256_rc ),
        &t );
      BENCH_RECORD( "avx2_keccak8_eo", "C, w/bound",        8, t );
    }
    {
      /* AVX2 keccak8 EO raw (C, no boundary). */
      uint rc_eo[ 48 ] __attribute__((aligned(64)));
      for( int rr=0; rr<24; rr++ ) {
        ulong const w = fd_keccak256_rc[ rr ];
        rc_eo[ 2*rr   ] = (uint)_pext_u64( w, 0x5555555555555555UL );
        rc_eo[ 2*rr+1 ] = (uint)_pext_u64( w, 0xAAAAAAAAAAAAAAAAUL );
      }
      uint s[ 400 ] __attribute__((aligned(64)));
      for( ulong i=0; i<400; i++ ) s[ i ] = fd_rng_uint( rng );
      void * _s = s; FD_COMPILER_FORGET( _s );
      BENCH_TIME_BEST( ITER,
        fd_keccak256_avx2_keccak8_eo_f1600_raw( s, rc_eo ),
        &t );
      BENCH_RECORD( "avx2_keccak8_eo (raw)", "C, raw",      8, t );

      /* AVX2 keccak8 EO raw asm (.inc-based, hand-rolled). */
      for( ulong i=0; i<400; i++ ) s[ i ] = fd_rng_uint( rng );
      BENCH_TIME_BEST( ITER,
        fd_keccak256_avx2_keccak8_eo_f1600_raw_asm( s, rc_eo ),
        &t );
      BENCH_RECORD( "avx2_keccak8_eo (raw)", "our asm,raw", 8, t );
    }
#   endif

    /* -- 8-state batch (AVX-512) -------------------------------------- */
#   if FD_HAS_AVX512
    {
      ulong s[ 200 ] __attribute__((aligned(64)));
      for( ulong i=0; i<200; i++ ) s[ i ] = fd_rng_ulong( rng );
      ulong * _s = s; FD_COMPILER_FORGET( _s );
      BENCH_TIME_BEST( ITER,
        fd_keccak256_avx512_keccak8_f1600( s, fd_keccak256_rc ),
        &t );
      BENCH_RECORD( "avx512_keccak8 (64b)", "C, w/bound",   8, t );

      ulong soa[ 200 ] __attribute__((aligned(64)));
      memset( soa, 0, sizeof(soa) );
      void * _soa = soa; FD_COMPILER_FORGET( _soa );
      extern void fd_keccak256_avx512_keccak8_f1600_raw( void * state_soa, ulong const * rc );
      BENCH_TIME_BEST( ITER,
        fd_keccak256_avx512_keccak8_f1600_raw( soa, fd_keccak256_rc ),
        &t );
      BENCH_RECORD( "avx512_keccak8 (64b)", "C, raw",       8, t );

      /* 12-round variant (KangarooTwelve / Keccak-p[1600,12]). */
      extern void fd_keccak256_avx512_keccak8_f1600_12r_raw( void * state_soa, ulong const * rc );
      memset( soa, 0, sizeof(soa) );
      BENCH_TIME_BEST( ITER,
        fd_keccak256_avx512_keccak8_f1600_12r_raw( soa, fd_keccak256_rc ),
        &t );
      BENCH_RECORD( "avx512_keccak8 (64b,12r)", "C, raw",   8, t );
    }
#   endif

    /* -- progression: keccak4a / keccak8a / keccak8b ------------------ */
#   if FD_HAS_AVX512
    {
      /* 4a: 4 states, AVX-512 ops, top 4 zmm lanes zero, shift+or, andn+xor */
      ulong s4[ 100 ] __attribute__((aligned(64)));
      for( ulong i=0; i<100; i++ ) s4[ i ] = fd_rng_ulong( rng );
      ulong * _s4 = s4; FD_COMPILER_FORGET( _s4 );
      /* 4a (asm): mechanical AVX-512 lift of s2n keccak4 — same instructions,
         same register allocation, same stack layout (slots widened to 64 B). */
      ulong s4a[ 100 ] __attribute__((aligned(64)));
      for( ulong i=0; i<100; i++ ) s4a[ i ] = fd_rng_ulong( rng );
      ulong * _s4a = s4a; FD_COMPILER_FORGET( _s4a );
      BENCH_TIME_BEST( ITER,
        fd_keccak256_avx512_keccak4a_f1600_asm( s4a, fd_keccak256_rc ),
        &t );
      BENCH_RECORD( "avx512_keccak4a",          "asm, s2n-lift",   4, t );

      /* 8a (asm): keccak4a round body extended with 8-state boundary. */
      ulong s8a[ 200 ] __attribute__((aligned(64)));
      for( ulong i=0; i<200; i++ ) s8a[ i ] = fd_rng_ulong( rng );
      ulong * _s8a = s8a; FD_COMPILER_FORGET( _s8a );
      BENCH_TIME_BEST( ITER,
        fd_keccak256_avx512_keccak8a_f1600_asm( s8a, fd_keccak256_rc ),
        &t );
      BENCH_RECORD( "avx512_keccak8a",          "asm, shl/or+andn",8, t );

      /* 8b (asm): same as 8a but with native vprolq rotates. */
      ulong s8b[ 200 ] __attribute__((aligned(64)));
      for( ulong i=0; i<200; i++ ) s8b[ i ] = fd_rng_ulong( rng );
      ulong * _s8b = s8b; FD_COMPILER_FORGET( _s8b );
      BENCH_TIME_BEST( ITER,
        fd_keccak256_avx512_keccak8b_f1600_asm( s8b, fd_keccak256_rc ),
        &t );
      BENCH_RECORD( "avx512_keccak8b",          "asm, vprolq+andn",8, t );
    }
#   endif

    /* -- 16-state batch (AVX-512 EO) ---------------------------------- */
#   if FD_HAS_AVX512
    extern void fd_keccak256_avx512_keccak16_eo_f1600( ulong * state, ulong const * rc );
    extern void fd_keccak256_avx512_keccak16_eo_f1600_raw( void * state_eo, uint const * rc_eo );
    {
      ulong s[ 400 ] __attribute__((aligned(64)));
      for( ulong i=0; i<400; i++ ) s[ i ] = fd_rng_ulong( rng );
      ulong * _s = s; FD_COMPILER_FORGET( _s );
      BENCH_TIME_BEST( ITER,
        fd_keccak256_avx512_keccak16_eo_f1600( s, fd_keccak256_rc ),
        &t );
      BENCH_RECORD( "avx512_keccak16_eo", "C, w/bound",    16, t );

      uint rc_eo[ 48 ] __attribute__((aligned(64)));
      for( int rr=0; rr<24; rr++ ) {
        ulong const w = fd_keccak256_rc[ rr ];
        rc_eo[ 2*rr   ] = (uint)_pext_u64( w, 0x5555555555555555UL );
        rc_eo[ 2*rr+1 ] = (uint)_pext_u64( w, 0xAAAAAAAAAAAAAAAAUL );
      }
      uint eo16[ 800 ] __attribute__((aligned(64)));
      memset( eo16, 0, sizeof(eo16) );
      void * _eo = eo16; FD_COMPILER_FORGET( _eo );
      BENCH_TIME_BEST( ITER,
        fd_keccak256_avx512_keccak16_eo_f1600_raw( eo16, rc_eo ),
        &t );
      BENCH_RECORD( "avx512_keccak16_eo", "C, raw",       16, t );
    }
#   endif

    /* ---- print the table -------------------------------------------- */
    FD_LOG_NOTICE(( "==================================================================" ));
    FD_LOG_NOTICE(( "  Keccak-f[1600] permutation benchmark summary" ));
    FD_LOG_NOTICE(( "  (best of 3 timing runs; ns/state = ns/call / lanes)" ));
    FD_LOG_NOTICE(( "==================================================================" ));
    FD_LOG_NOTICE(( "  %-26s %-15s %5s %10s %10s",
                    "variant", "kind", "lanes", "ns/call", "ns/state" ));
    FD_LOG_NOTICE(( "  ---------------------------------------------------------------" ));
    for( int i=0; i<n; i++ ) {
      FD_LOG_NOTICE(( "  %-26s %-15s %5d %10.1f %10.1f",
                      names[i], tags[i], lanes[i], ns_cl[i], ns_st[i] ));
    }
    FD_LOG_NOTICE(( "==================================================================" ));

    /* ---- KTP12 / TurboSHAKE128 XOF throughput ----------------------- *
       The in-ballet keccak8 12r is a faithful port of XKCP's times8
       AVX-512 permutation (same register-renamed round structure, XOR5
       theta, vpternlogq chi).  KTP12 = KangarooTwelve construction on
       Keccak-p[1600,12]; TurboSHAKE128 rate = 168 B over 8 lanes.  This
       is the headline number to compare across machines: expect
       ~41 Gbps/core on Zen 4 and ~118 Gbps/core on Zen 5. */
#   if FD_HAS_AVX512
    {
      extern void fd_keccak256_avx512_keccak8_f1600_12r_raw( void * state_soa, ulong const * rc );
      ulong soa12[ 200 ] __attribute__((aligned(64))); memset( soa12, 0, sizeof(soa12) );
      void * _s12 = soa12; FD_COMPILER_FORGET( _s12 );
      BENCH_TIME_BEST( ITER,
        fd_keccak256_avx512_keccak8_f1600_12r_raw( soa12, fd_keccak256_rc ), &t );
      double const gbps168 = (8.0*168.0*8.0)/t;   /* TurboSHAKE128 rate */
      double const gbps136 = (8.0*136.0*8.0)/t;   /* TurboSHAKE256 rate */
      FD_LOG_NOTICE(( "==================================================================" ));
      FD_LOG_NOTICE(( "  KTP12 XOF throughput (Keccak-p[1600,12] times8, faithful XKCP port)" ));
      FD_LOG_NOTICE(( "  keccak8 12r: %.1f ns/call (8 states), %.2f ns/state", t, t/8.0 ));
      FD_LOG_NOTICE(( "  TurboSHAKE128 (rate 168): %6.2f Gbps/core  (expect ~41 Zen4, ~118 Zen5)", gbps168 ));
      FD_LOG_NOTICE(( "  TurboSHAKE256 (rate 136): %6.2f Gbps/core", gbps136 ));
      FD_LOG_NOTICE(( "==================================================================" ));
    }
#   endif

#   undef BENCH_RECORD
#   undef BENCH_TIME_BEST
  } while(0);

  /* clean up */

  FD_TEST( fd_keccak256_leave( NULL )==NULL ); /* null sha */
  FD_TEST( fd_keccak256_leave( sha  )==obj  ); /* ok */

  FD_TEST( fd_keccak256_delete( NULL          )==NULL ); /* null shsha       */
  FD_TEST( fd_keccak256_delete( (void *)0x1UL )==NULL ); /* misaligned shsha */
  FD_TEST( fd_keccak256_delete( obj           )==mem  ); /* ok */

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

