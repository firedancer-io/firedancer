#include "fd_url.h"
#include "../../util/fd_util.h"

#include <string.h>

static void
test_url_unescape( void ) {

  /* Valid cases */

  { /* No escapes */
    char buf[] = "hello";
    FD_TEST( fd_url_unescape( buf, 5 )==5 );
    FD_TEST( !memcmp( buf, "hello", 5 ) );
  }

  { /* Empty string */
    char buf[] = "";
    FD_TEST( fd_url_unescape( buf, 0 )==0 );
  }

  { /* Single escape */
    char buf[] = "%2F";
    FD_TEST( fd_url_unescape( buf, 3 )==1 );
    FD_TEST( buf[0]=='/' );
  }

  { /* Mixed content */
    char buf[] = "hello%20world";
    FD_TEST( fd_url_unescape( buf, 13 )==11 );
    FD_TEST( !memcmp( buf, "hello world", 11 ) );
  }

  { /* Multiple escapes */
    char buf[] = "%48%65%6C%6C%6F";
    FD_TEST( fd_url_unescape( buf, 15 )==5 );
    FD_TEST( !memcmp( buf, "Hello", 5 ) );
  }

  { /* Lowercase hex */
    char buf[] = "%2f%3a";
    FD_TEST( fd_url_unescape( buf, 6 )==2 );
    FD_TEST( buf[0]=='/' );
    FD_TEST( buf[1]==':' );
  }

  { /* Null byte escape */
    char buf[] = "%00";
    FD_TEST( fd_url_unescape( buf, 3 )==1 );
    FD_TEST( buf[0]=='\0' );
  }

  { /* 0xFF */
    char buf[] = "%FF";
    FD_TEST( fd_url_unescape( buf, 3 )==1 );
    FD_TEST( (uchar)buf[0]==0xFF );
  }

  /* Invalid cases — must return 0 */

  { /* Invalid hex: %ZZ */
    char buf[] = "%ZZ";
    FD_TEST( fd_url_unescape( buf, 3 )==0 );
  }

  { /* Invalid hex: %GG */
    char buf[] = "%GG";
    FD_TEST( fd_url_unescape( buf, 3 )==0 );
  }

  { /* Invalid first nibble */
    char buf[] = "%G0";
    FD_TEST( fd_url_unescape( buf, 3 )==0 );
  }

  { /* Invalid second nibble */
    char buf[] = "%0G";
    FD_TEST( fd_url_unescape( buf, 3 )==0 );
  }

  { /* Truncated: lone % at end */
    char buf[] = "abc%";
    FD_TEST( fd_url_unescape( buf, 4 )==0 );
  }

  { /* Truncated: %A at end */
    char buf[] = "abc%A";
    FD_TEST( fd_url_unescape( buf, 5 )==0 );
  }

  { /* Truncated: just % */
    char buf[] = "%";
    FD_TEST( fd_url_unescape( buf, 1 )==0 );
  }

  { /* Truncated: %A alone */
    char buf[] = "%A";
    FD_TEST( fd_url_unescape( buf, 2 )==0 );
  }

  { /* Invalid hex after valid content */
    char buf[] = "hello%ZZworld";
    FD_TEST( fd_url_unescape( buf, 13 )==0 );
  }

  FD_LOG_NOTICE(( "test_url_unescape: pass" ));
}

static void
test_url_parse( void ) {

  { /* Basic http URL */
    fd_url_t url;
    int err;
    FD_TEST( fd_url_parse_cstr( &url, "http://example.com/path", 23, &err ) );
    FD_TEST( err==FD_URL_SUCCESS );
    FD_TEST( url.scheme_len==7 );
    FD_TEST( url.host_len==11 );
    FD_TEST( !memcmp( url.host, "example.com", 11 ) );
  }

  { /* https URL */
    fd_url_t url;
    int err;
    FD_TEST( fd_url_parse_cstr( &url, "https://example.com/path", 24, &err ) );
    FD_TEST( err==FD_URL_SUCCESS );
    FD_TEST( url.scheme_len==8 );
  }

  { /* URL with port */
    fd_url_t url;
    int err;
    FD_TEST( fd_url_parse_cstr( &url, "http://localhost:8080/", 21, &err ) );
    FD_TEST( err==FD_URL_SUCCESS );
    FD_TEST( url.host_len==9 );
    FD_TEST( !memcmp( url.host, "localhost", 9 ) );
    FD_TEST( url.port_len==4 );
    FD_TEST( !memcmp( url.port, "8080", 4 ) );
  }

  { /* Invalid scheme */
    fd_url_t url;
    int err;
    FD_TEST( !fd_url_parse_cstr( &url, "ftp://example.com/", 18, &err ) );
    FD_TEST( err==FD_URL_ERR_SCHEME );
  }

  { /* Userinfo rejected */
    fd_url_t url;
    int err;
    FD_TEST( !fd_url_parse_cstr( &url, "http://user@example.com/", 24, &err ) );
    FD_TEST( err==FD_URL_ERR_USERINFO );
  }

  FD_LOG_NOTICE(( "test_url_parse: pass" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_url_unescape();
  test_url_parse();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
