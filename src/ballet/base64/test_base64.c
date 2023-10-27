#include "fd_base64.h"
#include "../fd_ballet.h"

/* test_base64 verifies Base64 encoding and decoding against a hardcoded
   test vector and runs benchmarks. */

struct fd_base64_test_vec {
  ulong        raw_len;
  char const * raw;
  ulong        enc_len;
  char const * enc;
};

typedef struct fd_base64_test_vec fd_base64_test_vec_t;


/* https://datatracker.ietf.org/doc/html/rfc4648#section-10 */

static uchar const test_long_raw[] = {
  0x12, 0xdf, 0x43, 0x1b, 0xe4, 0x6a, 0xaa, 0xed, 0x0c, 0xcf, 0xd2, 0x53,
  0x5d, 0x8f, 0x72, 0x89, 0xe2, 0x17, 0x06, 0x0c, 0x78, 0xb8, 0x4a, 0xc5,
  0xe7, 0x23, 0xed, 0xda, 0xd4, 0x00, 0xf4, 0xd2, 0x6a, 0x29, 0x25, 0x39,
  0xcb, 0xb0, 0xf9, 0xb0, 0x29, 0xbe, 0x6d, 0x8a, 0x18, 0x9c, 0x14, 0x13,
  0x3f, 0x5c, 0xb6, 0x14, 0x28, 0x94, 0xaf, 0x5b, 0x55, 0xda, 0xbf, 0x0a,
  0xd9, 0x3f, 0x89, 0xd3, 0x07
};

static fd_base64_test_vec_t const test_vector[] = {
  { 0UL, "",       0UL, ""         },
  { 1UL, "f",      4UL, "Zg=="     },
  { 2UL, "fo",     4UL, "Zm8="     },
  { 3UL, "foo",    4UL, "Zm9v"     },
  { 4UL, "foob",   8UL, "Zm9vYg==" },
  { 5UL, "fooba",  8UL, "Zm9vYmE=" },
  { 6UL, "foobar", 8UL, "Zm9vYmFy" },

  { 3UL, "\x00\x00\x00", 4UL, "AAAA"                 },
  { 2UL, "\x00\x00",     4UL, "AAA="                 },
  { 1UL, "\x00",         4UL, "AA=="                 },

  { 65UL, (char const *)test_long_raw,
    88UL, "Et9DG+Rqqu0Mz9JTXY9yieIXBgx4uErF5yPt2tQA9NJqKSU5y7D5sCm+bYoYnBQTP1y2FCiUr1tV2r8K2T+J0wc=" },

  { 14UL, "system_program", 20UL, "c3lzdGVtX3Byb2dyYW0=" },

  { .raw_len = ULONG_MAX }
};

/* https://cs.opensource.google/go/go/+/refs/tags/go1.20.7:src/encoding/base64/base64_test.go */
static char const * const test_corrupt[] = {
	"!!!!",
	"====",
	"x===",
	"=AAA",
	"A=AA",
	"AA=A",
	"AA==A",
	"AAA=AAAA",
	"AAAAA",
	"AAAAAA",
	"A=",
	"A==",
	"AA=",
	"AAAAAA=",
	"YWJjZA=====",
	"A!\n",
	"A=\n",
  NULL
};

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* Unit tests */

  for( fd_base64_test_vec_t const * test = test_vector;
       test->raw_len != ULONG_MAX;
       test++ ) {

    /* decode */
    do {
      uchar raw[ 128UL ];
      long  raw_sz = fd_base64_decode( raw, test->enc, test->enc_len );
      FD_TEST( raw_sz==(long)test->raw_len );
      FD_TEST( 0==memcmp( raw, test->raw, test->raw_len ) );
    } while(0);

    /* encode */
    do {
      char  enc[ 128UL ];
      ulong enc_sz = fd_base64_encode( enc, test->raw, test->raw_len );
      FD_TEST( enc_sz==test->enc_len );
      FD_TEST( 0==memcmp( enc, test->enc, test->enc_len ) );
    } while(0);

  }

  for( char const * const * corrupt = test_corrupt; *corrupt; corrupt++ ) {
    uchar raw[ 128UL ];
    long  raw_sz = fd_base64_decode( raw, *corrupt, strlen( *corrupt ) );
    if( FD_UNLIKELY( raw_sz>=0L ) ) FD_LOG_ERR(( "decode should have failed but didn't: \"%s\"", *corrupt ));
  }

  /* Throughput test */

  static uchar raw[ 32768UL ];
  static ulong enc_sz = 32768UL;
  char         enc[ enc_sz ];

  memset( enc, 'A', enc_sz );
  long raw_sz = fd_base64_decode( raw, enc, enc_sz );
  FD_TEST( raw_sz>=0L );

  /* warmup */
  for( ulong rem=10000UL; rem; rem-- ) fd_base64_decode( raw, enc, enc_sz );

  /* for real */
  ulong iter = 100000UL;
  long  dt   = -fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) fd_base64_decode( raw, enc, enc_sz );
  dt += fd_log_wallclock();
  double gbps = ((double)(8UL * (ulong)raw_sz * iter)) / ((double)dt);
  double ns   = (double)dt / ((double)iter * (double)raw_sz);
  FD_LOG_NOTICE(( "decode: ~%6.3f Gbps  / core", gbps ));
  FD_LOG_NOTICE(( "decode: ~%6.3f ns / byte",    ns   ));

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
