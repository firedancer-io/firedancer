#include "fd_csv.h"
#include "fd_csv_private.h"

#include "../../fd_util.h"
#include "../../sanitize/fd_sanitize.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

struct fd_csv_read_test_vec {
  char const * line;
  ulong        n;
  int          err;
  char const * cols[4];
};
typedef struct fd_csv_read_test_vec fd_csv_read_test_vec_t;

static fd_csv_read_test_vec_t const csv_read_tests[] = {
  { /* Simple */
    .line = "a,b,c\n",
    .n    = 3,
    .cols = { "a", "b", "c" }
  },
  { /* No EOL */
    .line = "a,b,c",
    .n    = 3,
    .cols = { "a", "b", "c" }
  },
  { /* Multiline */
    .line = "\"two\nline\",\"one line\",\"three\r\nline\rfield\"",
    .n    = 3,
    .cols = { "two\nline", "one line", "three\r\nline\rfield" }
  },
  { /* Random UTF-8 */
    .line = "戩p􆴂,㫢ﵦ赽􃡄툪,𢥽׳Ĝ޶wԖ",
    .n    = 3,
    .cols = { "戩p􆴂","㫢ﵦ赽􃡄툪","𢥽׳Ĝ޶wԖ" }
  },
  { /* CRLF */
    .line = "a,b\r\nc,d\r\n",
    .n    = 2,
    .cols = { "a", "b", "c", "d" }
  },
  {
    /* Skip whitespace */
    .line = "\r\n\r\n\r\n\n     \t\t\t           a,b,c\n       ",
    .n    = 3,
    .cols = { "a", "b", "c" }
  },
  {
    /* Not enough cols */
    .line = "a,b",
    .n    = 3,
    .err  = EPROTO
  },
  {
    /* Too many cols */
    .line = "a,b,c,d",
    .n    = 3,
    .err  = EPROTO
  },
  {0}
};

void
test_csv_read( fd_csv_read_test_vec_t const * t ) {
  /* Create virtual file handle */
  FILE * stream = fmemopen( (void *)t->line, strlen( t->line ), "r" );
  FD_TEST( stream );

  /* Ensure that fd_csv_read_record doesn't write out-of-bounds */
  fd_asan_poison  ( csv_buf, FD_CSV_BUFSZ          );
  /* TODO: Is unposion out-of-bounds safe? */
  fd_asan_unpoison( csv_buf, strlen( t->line )+1UL );

  /* Output buffer storing columns */
  char * cols[4] = {0};
  FD_TEST( t->n <= 4 ); /* sanity check */

  int err = fd_csv_read_record( cols, t->n, ',', '"', stream );
  if( FD_UNLIKELY( err!=t->err ) )
    FD_LOG_ERR(( "%s given test `%s`", fd_csv_strerror(), t->line ));

  int test_matches = err==t->err;

  FD_LOG_INFO(( "Parsing test %p: \"%s\"", (void *)t, t->line ));

  if( FD_LIKELY( err==0 ) ) {
    for( ulong i=0; i < t->n; i++ ) {
      FD_LOG_DEBUG(( "  Col %lu: %s", i, cols[i] ));
      test_matches &= (0==strcmp( cols[i], t->cols[i] ));
    }
  }
  FD_LOG_INFO(( "Result: %s", fd_csv_strerror() ));

  if( FD_UNLIKELY( !test_matches ) ) {
    FD_LOG_ERR(( "Test %p failed", (void *)t ));
  }

  /* Clean up */
  fclose( stream );
# undef BUF_SZ
}

void
test_csv_invalid( void ) {
  /* Valid dummy parameters */

  char * col_cstrs[ 4 ] =  {0};
  ulong  col_cnt        =  4UL;
  int    sep            =  ',';
  int    quote          =  '"';

  /* Dummy stream */

  FILE * stream = fopen( "/dev/null", "r" );
  FD_TEST( stream );

  /* Test EINVAL branches */

  FD_TEST( EINVAL==fd_csv_read_record( NULL,      col_cnt, sep,  quote, stream ) ); /* NULL col_cstrs      */
  FD_TEST( EINVAL==fd_csv_read_record( col_cstrs, 0UL,     sep,  quote, stream ) ); /* Zero cols           */
  FD_TEST( EINVAL==fd_csv_read_record( col_cstrs, col_cnt, '\0', quote, stream ) ); /* nul sep             */
  FD_TEST( EINVAL==fd_csv_read_record( col_cstrs, col_cnt, sep,  '\0',  stream ) ); /* nul quote           */
  FD_TEST( EINVAL==fd_csv_read_record( col_cstrs, col_cnt, sep,  sep,   stream ) ); /* ambiguous quote/sep */

  /* Test whitespace quote/sep */

  for( char const * x = " \t\r\n"; *x; x++ ) {
    FD_TEST( EINVAL==fd_csv_read_record( col_cstrs, col_cnt, *x,  quote, stream ) );
    FD_TEST( EINVAL==fd_csv_read_record( col_cstrs, col_cnt, sep, *x,    stream ) );
  }

  /* Clean up */
  FD_TEST( 0==fclose( stream ) );
}

void
test_csv_strerror( void ) {
  /* Ensure that no errno can overflow the `fd_csv_strerror` buf. */

  for( int err=-1; err<1024; err++ ) {
    int srcln = INT_MIN; /* int that results in longest str via %d */
    FD_TEST( err==fd_csv_seterr( err, srcln ) );

    char const * err_cstr     = fd_csv_strerror();
    ulong        err_cstr_len = strlen( err_cstr );
    FD_TEST( err_cstr_len>0UL && err_cstr_len<128UL );

    FD_LOG_DEBUG(( "fd_csv_strerror: %s", err_cstr ));
  }
}

void
test_csv_long_line( void ) {
  /* Test behavior when line overflows parse buffer. */
# define LINE_SZ (2UL*FD_CSV_BUFSZ+1UL)
  char line[ LINE_SZ ];
  fd_memset( line, 'A', 2UL*FD_CSV_BUFSZ );
  line[ 2UL*FD_CSV_BUFSZ ] = '\0';

  FILE * file = fmemopen( line, LINE_SZ, "rb" );
  FD_TEST( file );

  //char * col_cstrs[ 1UL ];
  //FD_TEST( /*ENOMEM==*/0==fd_csv_read_record( col_cstrs, 1UL, ',', '"', file ) );

  FD_TEST( 0==fclose( file ) );

# undef LINE_SZ
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_csv_invalid();
  test_csv_strerror();
  test_csv_long_line();

  /* Test vectors */

  fd_csv_read_test_vec_t const * read_test = csv_read_tests;
  while( read_test->line != NULL ) test_csv_read( read_test++ );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
