#include "../fd_ballet.h"
#include "fd_chacha.h"
#include "fd_chacha_rng.h"


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Create a fd_chacha_rng */

  fd_chacha_rng_t _rng[1];
  FD_TEST( alignof( fd_chacha_rng_t )==fd_chacha_rng_align()     );
  FD_TEST( sizeof ( _rng            )==fd_chacha_rng_footprint() );

  FD_TEST( fd_chacha_rng_new( NULL, FD_CHACHA_RNG_MODE_MOD )==NULL ); /* invalid mem */
  FD_TEST( fd_chacha_rng_new( (void *)((ulong)_rng+1UL), FD_CHACHA_RNG_MODE_MOD )==NULL ); /* misaligned mem */
  FD_TEST( fd_chacha_rng_new( _rng, 42 )==NULL ); /* invalid mode */

  FD_TEST( fd_chacha_rng_new( _rng, FD_CHACHA_RNG_MODE_MOD )==_rng );
  FD_TEST( fd_chacha_rng_join( NULL )==NULL ); /* invalid mem */
  fd_chacha_rng_t * rng = fd_chacha_rng_join( _rng );
  FD_TEST( (ulong)rng == (ulong)_rng );

  /* Initialize it with a key */

  uchar key[ 32 ] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
  };
  FD_TEST( fd_chacha_rng_init( rng, key, FD_CHACHA_RNG_ALGO_CHACHA20 ) );

  /* Test output */

  FD_TEST( fd_chacha_rng_ulong( rng )==0x6a19c5d97d2bfd39UL );
  ulong x = 0UL;
  for( ulong i=0UL; i<100000UL; i++ ) x ^= fd_chacha_rng_ulong( rng );
  FD_TEST( x==0xb425be48c89d4f75UL );

#define RNG_TEST( name, algo ) \
  do { \
    FD_LOG_NOTICE(( "Benchmarking " #name )); \
    key[ 0 ]++; \
    FD_TEST( fd_chacha_rng_init( rng, key, algo ) ); \
 \
    /* warmup */ \
    for( ulong rem=1000000UL; rem; rem-- ) name( rng ); \
 \
    /* for real */ \
    ulong iter = 10000000UL; \
    long  dt   = -fd_log_wallclock(); \
    for( ulong rem=iter; rem; rem-- ) name( rng ); \
    dt += fd_log_wallclock(); \
    double gbps    = ((double)(8UL*sizeof(ulong)*iter)) / ((double)dt); \
    double ulongps = ((double)iter / (double)dt) * 1000.0; \
    double ns      = (double)dt / (double)iter; \
    FD_LOG_NOTICE(( "  ~%7.3f Gbps            / core", gbps    )); \
    FD_LOG_NOTICE(( "  ~%6.3f Mulong / second / core", ulongps )); \
    FD_LOG_NOTICE(( "  ~%6.3f ns / ulong",             ns      )); \
  } while(0);

  RNG_TEST( fd_chacha_rng_ulong, FD_CHACHA_RNG_ALGO_CHACHA8 );
  RNG_TEST( fd_chacha_rng_ulong, FD_CHACHA_RNG_ALGO_CHACHA20 );

#define REFILL_TEST( name, stride, algo )                              \
  do {                                                                 \
    FD_LOG_NOTICE(( "Benchmarking " #name ));                          \
    key[ 0 ]++;                                                        \
    FD_TEST( fd_chacha_rng_init( rng, key, algo ) );                   \
                                                                       \
    /* warmup */                                                       \
    for( ulong rem=100000UL; rem; rem-- ) {                            \
      rng->buf_off += (stride);                                        \
      name( rng );                                                     \
    }                                                                  \
                                                                       \
    /* for real */                                                     \
    ulong iter = 1000000UL;                                            \
    long  dt   = -fd_log_wallclock();                                  \
    for( ulong rem=iter; rem; rem-- ) {                                \
      rng->buf_off += (stride);                                        \
      name( rng );                                                     \
    }                                                                  \
    dt += fd_log_wallclock();                                          \
    double gbps = ((double)(8UL*(stride)*iter)) / ((double)dt);        \
    FD_LOG_NOTICE(( "  ~%7.3f Gbps / core", gbps ));                   \
  } while(0);

# if FD_HAS_AVX512
  REFILL_TEST( fd_chacha8_rng_refill_avx512,  16*FD_CHACHA_BLOCK_SZ, FD_CHACHA_RNG_ALGO_CHACHA8  );
  REFILL_TEST( fd_chacha20_rng_refill_avx512, 16*FD_CHACHA_BLOCK_SZ, FD_CHACHA_RNG_ALGO_CHACHA20 );
# endif
# if FD_HAS_AVX
  REFILL_TEST( fd_chacha8_rng_refill_avx,      8*FD_CHACHA_BLOCK_SZ, FD_CHACHA_RNG_ALGO_CHACHA8  );
  REFILL_TEST( fd_chacha20_rng_refill_avx,     8*FD_CHACHA_BLOCK_SZ, FD_CHACHA_RNG_ALGO_CHACHA20 );
# endif
  REFILL_TEST( fd_chacha8_rng_refill_seq,      1*FD_CHACHA_BLOCK_SZ, FD_CHACHA_RNG_ALGO_CHACHA8  );
  REFILL_TEST( fd_chacha20_rng_refill_seq,     1*FD_CHACHA_BLOCK_SZ, FD_CHACHA_RNG_ALGO_CHACHA20 );

  /* Test 64-bit counter: verify all backends produce identical output
     at a block index > 2^32.  Without the 64-bit counter fix, the high
     bits are lost and the output would match block index 48 instead. */
  {
    ulong idx = (1UL<<32) + 48UL; /* block index > 2^32, aligned to 16 */
    ulong pos = idx * FD_CHACHA_BLOCK_SZ;
    uchar key_ref[ 32 ];
    for( ulong i=0UL; i<32UL; i++ ) key_ref[ i ] = (uchar)i;

    /* Compute reference block using the scalar block function with a
       proper 64-bit counter in idx_nonce[0..1]. */
    uchar ref_block[64] __attribute__((aligned(64)));
    uint idx_nonce[4] __attribute__((aligned(16))) =
      { (uint)idx, (uint)(idx>>32), 0U, 0U };
    fd_chacha20_block( ref_block, key_ref, idx_nonce );

    /* Golden vector from agave/rand_chacha 0.9.0:
       ChaCha20Rng::from_seed(key); set_word_pos(((1<<32)+48)*16);
       fill_bytes(out64). */
    uchar expect_block[64] = {
      0xa6, 0x45, 0x77, 0x19, 0xda, 0x5a, 0x7f, 0x54, 0xf9, 0xc6, 0x2f, 0xe3, 0x14, 0xdf, 0x8f, 0x3a,
      0x65, 0xdc, 0x34, 0xb9, 0x7e, 0xd7, 0x80, 0x3c, 0xc4, 0xaf, 0x38, 0x72, 0x04, 0x9b, 0x64, 0xf5,
      0xa4, 0x72, 0x8a, 0xa0, 0x73, 0x60, 0x10, 0x7a, 0x23, 0xe4, 0x5d, 0xf4, 0x55, 0x9a, 0xc3, 0xb5,
      0x8b, 0xff, 0x9b, 0xac, 0x99, 0x63, 0x17, 0x76, 0xb6, 0x02, 0x3d, 0x79, 0x62, 0x82, 0x20, 0x1d
    };
    FD_TEST( !memcmp( ref_block, expect_block, 64 ) );

    /* Also compute what the old (broken) 32-bit counter would produce,
       to make sure the 64-bit version is actually different. */
    uchar bad_block[64] __attribute__((aligned(64)));
    uint bad_idx_nonce[4] __attribute__((aligned(16))) =
      { (uint)idx, 0U, 0U, 0U };
    fd_chacha20_block( bad_block, key_ref, bad_idx_nonce );
    FD_TEST( memcmp( ref_block, bad_block, 64 )!=0 );

    /* Test seq backend */
    FD_TEST( fd_chacha_rng_init( rng, key_ref, FD_CHACHA_RNG_ALGO_CHACHA20 ) );
    rng->buf_off  = pos;
    rng->buf_fill = pos;
    fd_chacha20_rng_refill_seq( rng );
    FD_TEST( !memcmp( rng->buf, ref_block, 64 ) );

#   if FD_HAS_AVX
    FD_TEST( fd_chacha_rng_init( rng, key_ref, FD_CHACHA_RNG_ALGO_CHACHA20 ) );
    rng->buf_off  = pos;
    rng->buf_fill = pos;
    fd_chacha20_rng_refill_avx( rng );
    FD_TEST( !memcmp( rng->buf, ref_block, 64 ) );
#   endif

#   if FD_HAS_AVX512
    FD_TEST( fd_chacha_rng_init( rng, key_ref, FD_CHACHA_RNG_ALGO_CHACHA20 ) );
    rng->buf_off  = pos;
    rng->buf_fill = pos;
    fd_chacha20_rng_refill_avx512( rng );
    FD_TEST( !memcmp( rng->buf, ref_block, 64 ) );
#   endif

    FD_LOG_NOTICE(( "OK: 64-bit counter" ));
  }

  /* Test leave/delete */

  FD_TEST( fd_chacha_rng_leave( NULL )==NULL ); /* invalid mem */
  FD_TEST( fd_chacha_rng_leave( rng )==_rng );
  FD_TEST( fd_chacha_rng_delete( NULL )==NULL ); /* invalid mem */
  FD_TEST( fd_chacha_rng_delete( rng )==_rng );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

