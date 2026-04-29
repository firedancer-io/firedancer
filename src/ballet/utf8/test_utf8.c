#include "fd_utf8.h"
#include <assert.h>

struct fd_utf8_test_vector {
  char const * input;
  uint         sz;
  int          result;
};
typedef struct fd_utf8_test_vector fd_utf8_test_vector_t;

struct fd_utf8_patch {
  ushort idx;
  uchar  val;
};
typedef struct fd_utf8_patch fd_utf8_patch_t;

struct fd_utf8_buf_case {
  char const *    name;
  ushort          sz;
  uchar           fill;
  uchar           patch_cnt;
  uchar           expect;
  fd_utf8_patch_t patch[ 8 ];
};
typedef struct fd_utf8_buf_case fd_utf8_buf_case_t;


static void
run_utf8_buf_cases( uchar *                    buf,
                    fd_utf8_buf_case_t const * tc,
                    ulong                      tc_cnt ) {
  for( ulong i=0UL; i<tc_cnt; i++ ) {
    fd_utf8_buf_case_t const * c = tc + i;
    fd_memset( buf, c->fill, c->sz );
    for( ulong j=0UL; j<c->patch_cnt; j++ ) buf[ c->patch[j].idx ] = c->patch[j].val;

    int got = fd_utf8_verify( (char const *)buf, c->sz );
    if( FD_UNLIKELY( got!=c->expect ) )
      FD_LOG_ERR(( "%s (sz=%u got=%d expect=%u)", c->name, (uint)c->sz, got, (uint)c->expect ));
    }
}

/* Test vectors imported from
   https://github.com/rust-lang/rust/blob/8b86f48958be8c3473c979e0b5504c2d2e0fd4fd/library/alloctests/tests/str.rs#L860 */

static fd_utf8_test_vector_t const _single_glyph_vec[] = {
  { "\xc0\x80",         2UL, 0 },
  { "\xc0\xae",         2UL, 0 },
  { "\xe0\x80\x80",     3UL, 0 },
  { "\xe0\x80\xaf",     3UL, 0 },
  { "\xe0\x81\x81",     3UL, 0 },
  { "\xf0\x82\x82\xac", 4UL, 0 },
  { "\xf4\x90\x80\x80", 4UL, 0 },
  { "\xED\xA0\x80",     3UL, 0 },
  { "\xED\xBF\xBF",     3UL, 0 },
  { "\xC2\x80",         2UL, 1 },
  { "\xDF\xBF",         2UL, 1 },
  { "\xE1\x9B\x89",     3UL, 1 },
  { "\xE0\xA0\x80",     3UL, 1 },
  { "\xED\x9F\xBF",     3UL, 1 },
  { "\xEE\x80\x80",     3UL, 1 },
  { "\xEF\xBF\xBF",     3UL, 1 },
  { "\xF0\x90\x80\x80", 4UL, 1 },
  { "\xF4\x8F\xBF\xBF", 4UL, 1 },
  {0}
};

static void
test_single_glyphs( void ) {
  FD_TEST( fd_utf8_verify( NULL, 0UL )==1 );
  for( fd_utf8_test_vector_t const * vec = _single_glyph_vec; vec->input; vec++ ) {
    FD_TEST( fd_utf8_verify( vec->input, vec->sz ) == vec->result );

    for( ulong sz=1UL; sz < vec->sz; sz++ ) {
      FD_TEST( fd_utf8_verify( vec->input, sz )==0 );
      char input[ 8 ];
      fd_memcpy( input, vec->input, vec->sz );
      input[ sz-1UL ] = '\0';
      FD_TEST( fd_utf8_verify( input, vec->sz )==0 );
    }
  }
}

static void
test_glyph_pairs( void ) {
  for( fd_utf8_test_vector_t const * vec0 = _single_glyph_vec; vec0->input; vec0++ ) {
    for( fd_utf8_test_vector_t const * vec1 = _single_glyph_vec; vec1->input; vec1++ ) {
      char  input[8];
      ulong input_sz = 0UL;

      assert( vec0->sz + vec1->sz <= sizeof(input) );

      fd_memcpy( input, vec0->input, vec0->sz );
      input_sz += vec0->sz;
      fd_memcpy( input+input_sz, vec1->input, vec1->sz );
      input_sz += vec1->sz;

      FD_TEST( fd_utf8_verify( input, input_sz ) == (vec0->result & vec1->result) );
    }
  }
}

static void
test_oob( void ) {
  for( ulong j=0UL; j<=UCHAR_MAX; j++ ) {
    uchar oob[1] = { (uchar)j };
    int res = fd_utf8_verify( (char const *)oob, 1 );
    FD_TEST( res==0 || res==1 );
  }

  uchar t0[17] = { 0x67, 0x72, 0xc3, 0xbc, 0x65, 0x7a, 0x69, 0x00, 0x0a, 0xf0, 0x9f, 0x94, 0xa5, 0xf0, 0x9f, 0x92, 0x83 };
  FD_TEST( fd_utf8_verify( (char const *)t0, 17 ) );

  uchar oob2[1] = { (uchar)0xdf };
  FD_TEST( !fd_utf8_verify( (char const *)oob2, 1 ) );

  uchar oob3[2] = { (uchar)0xe0, (uchar)0xa0 };
  FD_TEST( !fd_utf8_verify( (char const *)oob3, 2 ) );

  uchar oob4[3] = { (uchar)0xf0, (uchar)0x90, (uchar)0x80 };
  FD_TEST( !fd_utf8_verify( (char const *)oob4, 3 ) );
}

static void
test_avx512_boundaries( void ) {
  uchar buf[ 256 ];
  static fd_utf8_buf_case_t const tc[] = {
    { "lane boundary 15-16 2-byte",   64U, 'A', 2U, 1U, {{15U,0xC3U},{16U,0xA9U}} },
    { "lane boundary 14-16 3-byte",   64U, 'A', 3U, 1U, {{14U,0xE1U},{15U,0x9BU},{16U,0x89U}} },
    { "lane boundary 13-16 4-byte",   64U, 'A', 4U, 1U, {{13U,0xF0U},{14U,0x90U},{15U,0x80U},{16U,0x80U}} },
    { "lane boundary 31-32 2-byte",   64U, 'A', 2U, 1U, {{31U,0xC3U},{32U,0xA9U}} },
    { "lane boundary 47-48 2-byte",   64U, 'A', 2U, 1U, {{47U,0xC3U},{48U,0xA9U}} },
    { "tail boundary 63-64 2-byte",   66U, 'A', 2U, 1U, {{63U,0xC3U},{64U,0xA9U}} },
    { "tail boundary 62-64 3-byte",   66U, 'A', 3U, 1U, {{62U,0xE1U},{63U,0x9BU},{64U,0x89U}} },
    { "tail boundary 61-64 4-byte",   66U, 'A', 4U, 1U, {{61U,0xF0U},{62U,0x90U},{63U,0x80U},{64U,0x80U}} },
    { "chunk boundary 63-64 2-byte", 128U, 'A', 2U, 1U, {{63U,0xC3U},{64U,0xA9U}} },
    { "stray continuation in SIMD",   64U, 'A', 1U, 0U, {{20U,0x80U}} },
    { "incomplete 2-byte at sz 64",   64U, 'A', 1U, 0U, {{63U,0xC3U}} },
    { "overlong E0 80 80",            64U, 'A', 3U, 0U, {{20U,0xE0U},{21U,0x80U},{22U,0x80U}} },
    { "surrogate ED A0 80",           64U, 'A', 3U, 0U, {{20U,0xEDU},{21U,0xA0U},{22U,0x80U}} },
    { "too large F4 A0 80 80",        64U, 'A', 4U, 0U, {{20U,0xF4U},{21U,0xA0U},{22U,0x80U},{23U,0x80U}} },
    { "too large F4 BF 80 80",        64U, 'A', 4U, 0U, {{20U,0xF4U},{21U,0xBFU},{22U,0x80U},{23U,0x80U}} },
    { "max valid F4 8F BF BF",        64U, 'A', 4U, 1U, {{20U,0xF4U},{21U,0x8FU},{22U,0xBFU},{23U,0xBFU}} },
    { "invalid lead F5",              64U, 'A', 4U, 0U, {{20U,0xF5U},{21U,0x80U},{22U,0x80U},{23U,0x80U}} },
    { "invalid lead F7",              64U, 'A', 4U, 0U, {{20U,0xF7U},{21U,0x80U},{22U,0x80U},{23U,0x80U}} },
    { "invalid lead FE",              64U, 'A', 4U, 0U, {{20U,0xFEU},{21U,0x80U},{22U,0x80U},{23U,0x80U}} },
    { "invalid lead FF",              64U, 'A', 4U, 0U, {{20U,0xFFU},{21U,0x80U},{22U,0x80U},{23U,0x80U}} },
    { "invalid C0",                   64U, 'A', 1U, 0U, {{20U,0xC0U}} },
    { "invalid C1",                   64U, 'A', 1U, 0U, {{20U,0xC1U}} },
  };

  run_utf8_buf_cases( buf, tc, sizeof(tc)/sizeof(tc[0]) );

  FD_LOG_NOTICE(( "test_avx512_boundaries passed" ));
}

/* Exhaustive edge-case tests derived from comparison with the simdutf
   reference implementation (icelake_utf8_validation.inl.cpp). */
static void
test_edge_cases( void ) {
  uchar buf[ 512 ];
  static fd_utf8_buf_case_t const tc[] = {
    { "eof 64 incomplete C3",             64U, 'A', 1U, 0U, {{63U,0xC3U}} },
    { "eof 64 incomplete E1",             64U, 'A', 1U, 0U, {{63U,0xE1U}} },
    { "eof 64 incomplete F1",             64U, 'A', 1U, 0U, {{63U,0xF1U}} },
    { "eof 64 incomplete E1 9B",          64U, 'A', 2U, 0U, {{62U,0xE1U},{63U,0x9BU}} },
    { "eof 64 incomplete F0 90",          64U, 'A', 2U, 0U, {{62U,0xF0U},{63U,0x90U}} },
    { "eof 64 incomplete F0 90 80",       64U, 'A', 3U, 0U, {{61U,0xF0U},{62U,0x90U},{63U,0x80U}} },
    { "eof 64 complete C3 A9",            64U, 'A', 2U, 1U, {{62U,0xC3U},{63U,0xA9U}} },
    { "eof 64 complete E1 9B 89",         64U, 'A', 3U, 1U, {{61U,0xE1U},{62U,0x9BU},{63U,0x89U}} },
    { "eof 64 complete F0 90 80 80",      64U, 'A', 4U, 1U, {{60U,0xF0U},{61U,0x90U},{62U,0x80U},{63U,0x80U}} },
    { "eof 128 incomplete C3",           128U, 'A', 1U, 0U, {{127U,0xC3U}} },
    { "eof 128 incomplete E1",           128U, 'A', 1U, 0U, {{127U,0xE1U}} },
    { "eof 128 incomplete F1",           128U, 'A', 1U, 0U, {{127U,0xF1U}} },
    { "eof 128 incomplete E1 9B",        128U, 'A', 2U, 0U, {{126U,0xE1U},{127U,0x9BU}} },
    { "eof 128 incomplete F0 90 80",     128U, 'A', 3U, 0U, {{125U,0xF0U},{126U,0x90U},{127U,0x80U}} },
    { "cross chunk C3 A9",               128U, 'A', 2U, 1U, {{63U,0xC3U},{64U,0xA9U}} },
    { "cross chunk E1 9B 89 from 62",    128U, 'A', 3U, 1U, {{62U,0xE1U},{63U,0x9BU},{64U,0x89U}} },
    { "cross chunk E1 9B 89 from 63",    128U, 'A', 3U, 1U, {{63U,0xE1U},{64U,0x9BU},{65U,0x89U}} },
    { "cross chunk F0 from 61",          128U, 'A', 4U, 1U, {{61U,0xF0U},{62U,0x90U},{63U,0x80U},{64U,0x80U}} },
    { "cross chunk F0 from 62",          128U, 'A', 4U, 1U, {{62U,0xF0U},{63U,0x90U},{64U,0x80U},{65U,0x80U}} },
    { "cross chunk F0 from 63",          128U, 'A', 4U, 1U, {{63U,0xF0U},{64U,0x90U},{65U,0x80U},{66U,0x80U}} },
    { "cross chunk missing cont",        128U, 'A', 1U, 0U, {{63U,0xC3U}} },
    { "cross chunk missing 3rd",         128U, 'A', 2U, 0U, {{63U,0xE1U},{64U,0x9BU}} },
    { "cross chunk missing 4th",         128U, 'A', 3U, 0U, {{63U,0xF0U},{64U,0x90U},{65U,0x80U}} },
    { "ascii after incomplete C3",       128U, 'A', 3U, 0U, {{10U,0xC3U},{11U,0xA9U},{63U,0xC3U}} },
    { "ascii after incomplete E1",       128U, 'A', 4U, 0U, {{10U,0xC3U},{11U,0xA9U},{62U,0xE1U},{63U,0x9BU}} },
    { "ascii after incomplete F0",       128U, 'A', 5U, 0U, {{10U,0xC3U},{11U,0xA9U},{61U,0xF0U},{62U,0x90U},{63U,0x80U}} },
    { "tail 65 C3 A9",                    65U, 'A', 2U, 1U, {{63U,0xC3U},{64U,0xA9U}} },
    { "tail 67 E1 9B 89",                 67U, 'A', 3U, 1U, {{63U,0xE1U},{64U,0x9BU},{65U,0x89U}} },
    { "tail 67 F0 90 80 80",              67U, 'A', 4U, 1U, {{63U,0xF0U},{64U,0x90U},{65U,0x80U},{66U,0x80U}} },
    { "tail 65 incomplete E1 9B",         65U, 'A', 2U, 0U, {{63U,0xE1U},{64U,0x9BU}} },
    { "tail 66 incomplete F0 90 80",      66U, 'A', 3U, 0U, {{63U,0xF0U},{64U,0x90U},{65U,0x80U}} },
    { "bare continuation at 0",           64U, 'A', 1U, 0U, {{ 0U,0x80U}} },
    { "bare continuation at 63",          64U, 'A', 1U, 0U, {{63U,0x80U}} },
    { "bare continuation at 64",         128U, 'A', 1U, 0U, {{64U,0x80U}} },
    { "multiple stray continuations",     64U, 'A', 3U, 0U, {{10U,0x80U},{11U,0x80U},{12U,0x80U}} },
    { "bare continuation BF",             64U, 'A', 1U, 0U, {{30U,0xBFU}} },
    { "C3 followed by ASCII",             64U, 'A', 1U, 0U, {{20U,0xC3U}} },
    { "E1 followed by ASCII",             64U, 'A', 1U, 0U, {{20U,0xE1U}} },
    { "E1 9B followed by ASCII",          64U, 'A', 2U, 0U, {{20U,0xE1U},{21U,0x9BU}} },
    { "F0 followed by ASCII",             64U, 'A', 1U, 0U, {{20U,0xF0U}} },
    { "F0 90 80 followed by ASCII",       64U, 'A', 3U, 0U, {{20U,0xF0U},{21U,0x90U},{22U,0x80U}} },
    { "lead followed by lead",            64U, 'A', 3U, 0U, {{20U,0xC3U},{21U,0xC3U},{22U,0xA9U}} },
    { "C0 80",                            64U, 'A', 2U, 0U, {{20U,0xC0U},{21U,0x80U}} },
    { "C1 BF",                            64U, 'A', 2U, 0U, {{20U,0xC1U},{21U,0xBFU}} },
    { "C0 followed by ASCII",             64U, 'A', 1U, 0U, {{20U,0xC0U}} },
    { "C1 at end of 64-byte chunk",       64U, 'A', 1U, 0U, {{63U,0xC1U}} },
    { "C0 across chunk boundary",        128U, 'A', 2U, 0U, {{63U,0xC0U},{64U,0x80U}} },
    { "E0 9F BF",                         64U, 'A', 3U, 0U, {{20U,0xE0U},{21U,0x9FU},{22U,0xBFU}} },
    { "E0 A0 80",                         64U, 'A', 3U, 1U, {{20U,0xE0U},{21U,0xA0U},{22U,0x80U}} },
    { "ED 9F BF",                         64U, 'A', 3U, 1U, {{20U,0xEDU},{21U,0x9FU},{22U,0xBFU}} },
    { "ED A0 80",                         64U, 'A', 3U, 0U, {{20U,0xEDU},{21U,0xA0U},{22U,0x80U}} },
    { "ED BF BF",                         64U, 'A', 3U, 0U, {{20U,0xEDU},{21U,0xBFU},{22U,0xBFU}} },
    { "F0 8F BF BF",                      64U, 'A', 4U, 0U, {{20U,0xF0U},{21U,0x8FU},{22U,0xBFU},{23U,0xBFU}} },
    { "F0 90 80 80",                      64U, 'A', 4U, 1U, {{20U,0xF0U},{21U,0x90U},{22U,0x80U},{23U,0x80U}} },
    { "F4 8F BF BF",                      64U, 'A', 4U, 1U, {{20U,0xF4U},{21U,0x8FU},{22U,0xBFU},{23U,0xBFU}} },
    { "F4 90 80 80",                      64U, 'A', 4U, 0U, {{20U,0xF4U},{21U,0x90U},{22U,0x80U},{23U,0x80U}} },
  };

  run_utf8_buf_cases( buf, tc, sizeof(tc)/sizeof(tc[0]) );

  for( uint lead = 0xF5U; lead <= 0xFFU; lead++ ) {
    fd_memset( buf, 'A', 64 );
    buf[20] = (uchar)lead; buf[21] = 0x80; buf[22] = 0x80; buf[23] = 0x80;
    FD_TEST( fd_utf8_verify( (char const *)buf, 64 )==0 );
  }

  /* Small inputs. */
  FD_TEST( fd_utf8_verify( "", 0 )==1 );
  FD_TEST( fd_utf8_verify( "A", 1 )==1 );
  FD_TEST( fd_utf8_verify( "\xC3\xA9", 2 )==1 );
  FD_TEST( fd_utf8_verify( "\xE1\x9B\x89", 3 )==1 );
  FD_TEST( fd_utf8_verify( "\xF0\x90\x80\x80", 4 )==1 );
  FD_TEST( fd_utf8_verify( "\x80", 1 )==0 );
  FD_TEST( fd_utf8_verify( "\xC3", 1 )==0 );
  FD_TEST( fd_utf8_verify( "\xE1\x9B", 2 )==0 );
  FD_TEST( fd_utf8_verify( "\xF0\x90\x80", 3 )==0 );

  {
    /* Fill 64 bytes with valid 2-byte sequences (32 of them) */
    for( ulong i=0; i<64; i+=2 ) { buf[i] = 0xC3; buf[i+1] = 0xA9; }
    FD_TEST( fd_utf8_verify( (char const *)buf, 64 )==1 );
  }
  {
    /* Fill 192 bytes with valid 3-byte sequences */
    for( ulong i=0; i<192; i+=3 ) { buf[i] = 0xE1; buf[i+1] = 0x9B; buf[i+2] = 0x89; }
    FD_TEST( fd_utf8_verify( (char const *)buf, 192 )==1 );
  }
  {
    /* Fill 256 bytes with valid 4-byte sequences */
    for( ulong i=0; i<256; i+=4 ) { buf[i] = 0xF0; buf[i+1] = 0x90; buf[i+2] = 0x80; buf[i+3] = 0x80; }
    FD_TEST( fd_utf8_verify( (char const *)buf, 256 )==1 );
  }

  {
    fd_memset( buf, 'A', 256 );
    /* Sprinkle valid multi-byte at various positions */
    buf[10] = 0xC3; buf[11] = 0xA9;       /* 2-byte in chunk 0 */
    buf[50] = 0xE1; buf[51] = 0x9B; buf[52] = 0x89; /* 3-byte in chunk 0 */
    buf[63] = 0xC3; buf[64] = 0xA9;       /* 2-byte crossing chunk 0-1 */
    buf[100] = 0xF0; buf[101] = 0x90; buf[102] = 0x80; buf[103] = 0x80; /* 4-byte in chunk 1 */
    buf[127] = 0xE1; buf[128] = 0x9B; buf[129] = 0x89; /* 3-byte crossing chunk 1-2 */
    buf[200] = 0xC3; buf[201] = 0xA9;     /* 2-byte in chunk 3 */
    FD_TEST( fd_utf8_verify( (char const *)buf, 256 )==1 );
  }

  {
    fd_memset( buf, 'A', 64 );
    buf[20] = 0x00;
    FD_TEST( fd_utf8_verify( (char const *)buf, 64 )==1 );
  }
  {
    fd_memset( buf, 0x00, 64 );
    FD_TEST( fd_utf8_verify( (char const *)buf, 64 )==1 );
  }

  for( uint b=0; b<=0xFF; b++ ) {
    uchar byte = (uchar)b;
    int expect = (b < 0x80) ? 1 : 0;
    FD_TEST( fd_utf8_verify( (char const *)&byte, 1 )==expect );
  }

  FD_LOG_NOTICE(( "test_edge_cases passed" ));
}

static void
test_null_input_semantics( void ) {
  FD_TEST( fd_utf8_verify( NULL, 0UL )==1 );
  FD_TEST( fd_utf8_verify( NULL, 1UL )==0 );
  FD_TEST( fd_utf8_verify( NULL, 64UL )==0 );
}

static void
bench_utf8_verify( uchar const * buf,
                   ulong         buf_sz,
                   char const *  label ) {
  static ulong const sizes[] = { 32UL, 128UL, 512UL, 1024UL, 4096UL };

  FD_LOG_NOTICE(( "Benchmarking fd_utf8_verify (%s)", label ));
  for( ulong idx=0UL; idx<sizeof(sizes)/sizeof(sizes[0]); idx++ ) {
    ulong sz = sizes[ idx ];
    if( sz>buf_sz ) break;

    for( ulong rem=1000UL; rem; rem-- ) {
      int r = fd_utf8_verify( (char const *)buf, sz );
      FD_COMPILER_UNPREDICTABLE( r );
    }

    ulong iter = 1000000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      int r = fd_utf8_verify( (char const *)buf, sz );
      FD_COMPILER_UNPREDICTABLE( r );
    }
    dt += fd_log_wallclock();
    double ns_per_call = (double)dt / (double)iter;
    double gbps        = ((double)(8UL*sz*iter)) / ((double)dt);
    FD_LOG_NOTICE(( "  sz %4lu: ~%8.3f ns/call  ~%6.3f Gbps", sz, ns_per_call, gbps ));
  }
}

static void
fill_ascii( uchar * buf, ulong sz, fd_rng_t * rng ) {
  for( ulong i=0UL; i<sz; i++ ) buf[i] = (uchar)( 0x20U + (fd_rng_uint( rng ) % 0x5fU) );
}

static void
fill_mixed_utf8( uchar * buf, ulong sz, fd_rng_t * rng ) {
  ulong j = 0UL;
  while( j<sz ) {
    ulong j0 = j;
    uint  r  = fd_rng_uint( rng ) % 4U;
    if( r==0U ) {
      buf[j++] = (uchar)(0x20U + (fd_rng_uint( rng ) % 0x5fU));
    } else if( r==1U && j+1UL<sz ) {
      buf[j++] = (uchar)(0xc2U + (fd_rng_uint( rng ) % 0x1eU));
      buf[j++] = (uchar)(0x80U + (fd_rng_uint( rng ) % 0x40U));
    } else if( r==2U && j+2UL<sz ) {
      buf[j++] = (uchar)0xe1U;
      buf[j++] = (uchar)(0x80U + (fd_rng_uint( rng ) % 0x40U));
      buf[j++] = (uchar)(0x80U + (fd_rng_uint( rng ) % 0x40U));
    } else if( r==3U && j+3UL<sz ) {
      buf[j++] = (uchar)0xf1U;
      buf[j++] = (uchar)(0x80U + (fd_rng_uint( rng ) % 0x40U));
      buf[j++] = (uchar)(0x80U + (fd_rng_uint( rng ) % 0x40U));
      buf[j++] = (uchar)(0x80U + (fd_rng_uint( rng ) % 0x40U));
    }
    if( j==j0 ) {
      buf[j++] = (uchar)(0x20U + (fd_rng_uint( rng ) % 0x5fU));
    }
  }
}

static void
bench_early_reject( uchar const * ascii_buf ) {
  uchar bad_buf[ 4096 ];
  fd_memcpy( bad_buf, ascii_buf, sizeof(bad_buf) );
  bad_buf[0] = 0x80U;

  FD_LOG_NOTICE(( "Benchmarking fd_utf8_verify (early reject)" ));

  for( ulong rem=1000UL; rem; rem-- ) {
    int r = fd_utf8_verify( (char const *)bad_buf, 4096UL );
    FD_COMPILER_UNPREDICTABLE( r );
  }

  ulong iter = 10000000UL;
  long  dt   = -fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    int r = fd_utf8_verify( (char const *)bad_buf, 4096UL );
    FD_COMPILER_UNPREDICTABLE( r );
  }
  dt += fd_log_wallclock();
  double ns_per_call = (double)dt / (double)iter;
  FD_LOG_NOTICE(( "  ~%8.3f ns/call", ns_per_call ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  test_single_glyphs();
  test_glyph_pairs();
  test_oob();
  test_null_input_semantics();
  test_avx512_boundaries();
  test_edge_cases();

  uchar ascii_buf[ 4096 ];
  fill_ascii( ascii_buf, sizeof(ascii_buf), rng );

  uchar mixed_buf[ 4096 ];
  fill_mixed_utf8( mixed_buf, sizeof(mixed_buf), rng );

  if( FD_HAS_AVX512 ) {
    bench_utf8_verify( ascii_buf, sizeof(ascii_buf), "pure ASCII" );
    bench_utf8_verify( mixed_buf, sizeof(mixed_buf), "mixed UTF-8" );
    bench_early_reject( ascii_buf );
  }

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
