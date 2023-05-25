#include "fd_utf8.h"

struct fd_utf8_test_vector {
  char const * input;
  ulong        sz;
  long         result;
};

typedef struct fd_utf8_test_vector fd_utf8_test_vector_t;

/* Test vectors imported from
   https://github.com/rust-lang/rust/blob/master/library/alloc/tests/str.rs */

static fd_utf8_test_vector_t const _single_glyph_vec[] = {
  { NULL,               0UL, -1L },
  { "\xc0\x80",         3UL, -1L },
  { "\xc0\xae",         3UL, -1L },
  { "\xe0\x80\x80",     4UL, -1L },
  { "\xe0\x80\xaf",     4UL, -1L },
  { "\xe0\x81\x81",     4UL, -1L },
  { "\xf0\x82\x82\xac", 5UL, -1L },
  { "\xf4\x90\x80\x80", 5UL, -1L },
  { "\xED\xA0\x80",     4UL, -1L },
  { "\xED\xBF\xBF",     4UL, -1L },
  { "\xC2\x80",         3UL,  2L },
  { "\xDF\xBF",         3UL,  2L },
  { "\xE0\xA0\x80",     4UL,  3L },
  { "\xED\x9F\xBF",     4UL,  3L },
  { "\xEE\x80\x80",     4UL,  3L },
  { "\xEF\xBF\xBF",     4UL,  3L },
  { "\xF0\x90\x80\x80", 5UL,  4L },
  { "\xF4\x8F\xBF\xBF", 5UL,  4L },
  {0}
};

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  for( fd_utf8_test_vector_t const * vec = _single_glyph_vec; vec->input; vec++ ) {
    for( ulong sz=1UL; sz < vec->sz; sz++ ) {
      /* Smaller size */
      FD_TEST( fd_utf8_check_cstr( vec->input, sz ) == -1 );
      /* Insert null byte */
      char input[ 8 ];
      fd_memcpy( input, vec->input, vec->sz );
      input[ sz-1UL ] = '\0';
      FD_TEST( fd_utf8_check_cstr( input, vec->sz ) == -1 );
    }
    FD_TEST( fd_utf8_check_cstr( vec->input, vec->sz ) == vec->result );
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

