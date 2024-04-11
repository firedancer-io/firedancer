#include "fd_utf8.h"
#include <assert.h>

struct fd_utf8_test_vector {
  char const * input;
  uint         sz;
  int          result;
};

typedef struct fd_utf8_test_vector fd_utf8_test_vector_t;

/* Test vectors imported from
   https://github.com/rust-lang/rust/blob/master/library/alloc/tests/str.rs */

static fd_utf8_test_vector_t const _single_glyph_vec[] = {
  { NULL,               0UL, 1 },
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
  { "\xE0\xA0\x80",     3UL, 1 },
  { "\xED\x9F\xBF",     3UL, 1 },
  { "\xEE\x80\x80",     3UL, 1 },
  { "\xEF\xBF\xBF",     3UL, 1 },
  { "\xF0\x90\x80\x80", 4UL, 1 },
  { "\xF4\x8F\xBF\xBF", 4UL, 1 },
  {0}
};

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Check single glyphs */

  for( fd_utf8_test_vector_t const * vec = _single_glyph_vec; vec->input; vec++ ) {
    FD_TEST( fd_utf8_verify( vec->input, vec->sz ) == vec->result );

    for( ulong sz=1UL; sz < vec->sz; sz++ ) {
      /* Smaller size */
      FD_TEST( fd_utf8_verify( vec->input, sz ) == -1 );
      /* Insert null byte */
      char input[ 8 ];
      fd_memcpy( input, vec->input, vec->sz );
      input[ sz-1UL ] = '\0';
      FD_TEST( fd_utf8_verify( input, vec->sz ) == -1 );
    }
  }

  /* Check any combination of (single glyph, single glyph) -- O(n^2) */

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

  /* Prevent OOB reads (caught by ASan) */

  for( ulong j=0UL; j<=UCHAR_MAX; j++ ) {
    uchar oob[1] = { (uchar)j };
    int res = fd_utf8_verify( (char const *)oob, 1 );
    FD_TEST( res==0 || res==1 );  /* prevent optimizing out value */
  }

  uchar oob2[1] = { (uchar)0xdf };
  FD_TEST( !fd_utf8_verify( (char const *)oob2, 1 ) );

  uchar oob3[2] = { (uchar)0xe0, (uchar)0xa0 };
  FD_TEST( !fd_utf8_verify( (char const *)oob3, 2 ) );

  uchar oob4[3] = { (uchar)0xf0, (uchar)0x90, (uchar)0x80 };
  FD_TEST( !fd_utf8_verify( (char const *)oob4, 3 ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

