#include "fd_http.h"
#include "../../util/fd_util.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong val;

  /* Valid decimal inputs */

  val = 999UL;
  FD_TEST( !fd_http_parse_content_len( "0", 1UL, &val ) );
  FD_TEST( val==0UL );

  val = 0UL;
  FD_TEST( !fd_http_parse_content_len( "123456789", 9UL, &val ) );
  FD_TEST( val==123456789UL );

  val = 0UL;
  FD_TEST( !fd_http_parse_content_len( "007", 3UL, &val ) );
  FD_TEST( val==7UL );

  /* ULONG_MAX boundary */

  val = 0UL;
  FD_TEST( !fd_http_parse_content_len( "18446744073709551615", 20UL, &val ) );
  FD_TEST( val==ULONG_MAX );

  /* Empty input */

  val = 42UL;
  FD_TEST( fd_http_parse_content_len( "", 0UL, &val )==FD_HTTP_PARSE_CONTENT_LEN_MALFORMED );
  FD_TEST( val==42UL ); /* unchanged on failure */

  /* Leading non-digit */

  val = 42UL;
  FD_TEST( fd_http_parse_content_len( " 1", 2UL, &val )==FD_HTTP_PARSE_CONTENT_LEN_MALFORMED );
  FD_TEST( val==42UL );

  /* Trailing garbage */

  val = 42UL;
  FD_TEST( fd_http_parse_content_len( "0abc", 4UL, &val )==FD_HTTP_PARSE_CONTENT_LEN_MALFORMED );
  FD_TEST( val==42UL );

  /* Overflow */

  val = 42UL;
  FD_TEST( fd_http_parse_content_len( "18446744073709551616", 20UL, &val )==FD_HTTP_PARSE_CONTENT_LEN_OVERFLOW );
  FD_TEST( val==42UL );

  /* Sub-range of a larger buffer */

  val = 0UL;
  FD_TEST( !fd_http_parse_content_len( "123abc", 3UL, &val ) );
  FD_TEST( val==123UL );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
