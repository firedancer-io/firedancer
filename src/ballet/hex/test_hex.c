#include "fd_hex.h"
#include "../fd_ballet.h"

struct fd_hex_test_vec {
  ulong        raw_len;
  uchar const * raw;
  char const *  hex;
};

typedef struct fd_hex_test_vec fd_hex_test_vec_t;

static fd_hex_test_vec_t const test_vector[] = {
  { 0UL, (uchar const *)"",
    "" },
  { 1UL, (uchar const *)"\x00",
    "00" },
  { 1UL, (uchar const *)"\xff",
    "ff" },
  { 1UL, (uchar const *)"\xab",
    "ab" },
  { 3UL, (uchar const *)"\xde\xad\xbe",
    "deadbe" },
  { 4UL, (uchar const *)"\xca\xfe\xba\xbe",
    "cafebabe" },
  { 8UL, (uchar const *)"\x01\x23\x45\x67\x89\xab\xcd\xef",
    "0123456789abcdef" },
  { 16UL, (uchar const *)"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
    "00112233445566778899aabbccddeeff" },
  { 32UL, (uchar const *)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
                          "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" },
  { .raw_len = ULONG_MAX }
};

static char const * const test_decode_upper[] = {
  "DEADBEEF",
  "0123456789ABCDEF",
  "00112233445566778899AABBCCDDEEFF",
  NULL
};

static uchar const test_decode_upper_raw[][16] = {
  { 0xde, 0xad, 0xbe, 0xef },
  { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
  { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
};

static ulong const test_decode_upper_len[] = { 4, 8, 16 };

static char const * const test_corrupt[] = {
  "0g",
  "g0",
  "zz",
  "0!",
  " 0",
  "0\n",
  NULL
};

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  for( fd_hex_test_vec_t const * test = test_vector; test->raw_len != ULONG_MAX; test++ ) {

    ulong sz = test->raw_len;

    do {
      char enc[ 256 ];
      char * end = fd_hex_encode( enc, test->raw, sz );
      FD_TEST( (ulong)(end - enc) == sz*2UL );
      FD_TEST( 0==memcmp( enc, test->hex, sz*2UL ) );
    } while(0);

    do {
      uchar dec[ 128 ];
      ulong ret = fd_hex_decode( dec, test->hex, sz );
      FD_TEST( ret == sz );
      FD_TEST( 0==memcmp( dec, test->raw, sz ) );
    } while(0);
  }

  for( ulong i=0UL; test_decode_upper[i]; i++ ) {
    uchar dec[ 128 ];
    ulong sz  = test_decode_upper_len[i];
    ulong ret = fd_hex_decode( dec, test_decode_upper[i], sz );
    FD_TEST( ret == sz );
    FD_TEST( 0==memcmp( dec, test_decode_upper_raw[i], sz ) );
  }

  for( char const * const * corrupt = test_corrupt; *corrupt; corrupt++ ) {
    uchar dec[ 128 ];
    ulong ret = fd_hex_decode( dec, *corrupt, 1UL );
    if( FD_UNLIKELY( ret==1UL ) ) FD_LOG_ERR(( "decode should have failed: \"%s\"", *corrupt ));
  }

  for( ulong corrupt_idx=0UL; corrupt_idx<160UL; corrupt_idx++ ) {
    char  enc[ 160 ];
    uchar dec[ 80 ];
    memset( enc, 'a', sizeof(enc) );
    enc[ corrupt_idx ] = 'g';

    ulong ret = fd_hex_decode( dec, enc, sizeof(dec) );
    FD_TEST( ret == corrupt_idx/2UL );
  }

  for( ulong iter=0UL; iter<100000UL; iter++ ) {
    uchar raw[ 256 ];
    uchar dec[ 256 ];
    char  enc[ 512 ];
    ulong sz = fd_rng_uint_roll( rng, sizeof(raw) );
    for( ulong j=0UL; j<sz; j++ ) raw[j] = (uchar)fd_rng_uchar( rng );
    fd_hex_encode( enc, raw, sz );
    ulong ret = fd_hex_decode( dec, enc, sz );
    FD_TEST( ret == sz );
    FD_TEST( fd_memeq( raw, dec, sz ) );
  }

  do {
#if FD_HAS_AVX512
#define BENCH_SIZE (32768UL)
#else
#define BENCH_SIZE (4096UL)
#endif
    static uchar raw[ BENCH_SIZE ];
    static char  enc[ 2UL*BENCH_SIZE ];

    for( ulong j=0; j<sizeof(raw); j++ ) raw[j] = (uchar)fd_rng_uchar( rng );
    fd_hex_encode( enc, raw, sizeof(raw) );

    ulong const sz = sizeof(raw);

    /* Encode */
    for( ulong rem=10000UL; rem; rem-- ) fd_hex_encode( enc, raw, sz );

    ulong iter = 100000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_hex_encode( enc, raw, sz );
    dt += fd_log_wallclock();
    double gbps = ((double)(8UL * sz * iter)) / ((double)dt);
    double ns   = (double)dt / ((double)iter * (double)sz);
    FD_LOG_NOTICE(( "encode %5lu B: ~%6.3f Gbps / core, ~%6.3f ns / byte", sz, gbps, ns ));

    /* Decode */
    for( ulong rem=10000UL; rem; rem-- ) fd_hex_decode( raw, enc, sz );

    dt = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_hex_decode( raw, enc, sz );
    dt += fd_log_wallclock();
    gbps = ((double)(8UL * sz * iter)) / ((double)dt);
    ns   = (double)dt / ((double)iter * (double)sz);
    FD_LOG_NOTICE(( "decode %5lu B: ~%6.3f Gbps / core, ~%6.3f ns / byte", sz, gbps, ns ));
#undef BENCH_SIZE
  } while(0);

  do {
#define MAX_SMALL_BENCH (512UL)
    ulong const sizes[] = { 32UL, 64UL, 128UL, 256UL, 512UL };
    ulong const n_sizes = sizeof(sizes) / sizeof(sizes[0]);

    for( ulong si=0UL; si<n_sizes; si++ ) {
      ulong sz = sizes[si];
      uchar raw[ MAX_SMALL_BENCH ];
      char  enc[ 2UL*MAX_SMALL_BENCH ];
      for( ulong j=0; j<sz; j++ ) raw[j] = (uchar)fd_rng_uchar( rng );
      fd_hex_encode( enc, raw, sz );

      ulong iter = 1000000UL;

      /* Encode */
      for( ulong rem=10000UL; rem; rem-- ) fd_hex_encode( enc, raw, sz );
      long dt = -fd_log_wallclock();
      for( ulong rem=iter; rem; rem-- ) fd_hex_encode( enc, raw, sz );
      dt += fd_log_wallclock();
      double gbps = ((double)(8UL * sz * iter)) / ((double)dt);
      double ns   = (double)dt / ((double)iter * (double)sz);
      FD_LOG_NOTICE(( "encode %5lu B: ~%6.3f Gbps / core, ~%6.3f ns / byte", sz, gbps, ns ));

      /* Decode */
      for( ulong rem=10000UL; rem; rem-- ) fd_hex_decode( raw, enc, sz );
      dt = -fd_log_wallclock();
      for( ulong rem=iter; rem; rem-- ) fd_hex_decode( raw, enc, sz );
      dt += fd_log_wallclock();
      gbps = ((double)(8UL * sz * iter)) / ((double)dt);
      ns   = (double)dt / ((double)iter * (double)sz);
      FD_LOG_NOTICE(( "decode %5lu B: ~%6.3f Gbps / core, ~%6.3f ns / byte", sz, gbps, ns ));
    }
#undef MAX_SMALL_BENCH
  } while(0);

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
