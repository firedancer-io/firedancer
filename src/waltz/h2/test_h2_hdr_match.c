#include "fd_h2_hdr_match.h"
#include "fd_hpack.h"
#include "fd_hpack_private.h"

#include <unistd.h> /* fork */
#include <stdlib.h> /* exit */
#include <sys/wait.h> /* wait */
#include <sys/syscall.h> /* syscall */

FD_STATIC_ASSERT( FD_H2_HDR_UNKNOWN==0, num );

static void
check_hpack_idx( int          idx,
                 char const * name,
                 ulong        name_idx ) {
  switch( idx ) {
# define _(idx,lit) \
  case idx: \
    FD_TEST( name_idx==sizeof(lit)-1 && fd_memeq( name, lit, sizeof(lit)-1 ) ); \
    break;
  _( FD_H2_HDR_AUTHORITY,                   ":authority"                  );
  _( FD_H2_HDR_METHOD,                      ":method"                     );
  _( FD_H2_HDR_PATH,                        ":path"                       );
  _( FD_H2_HDR_SCHEME,                      ":scheme"                     );
  _( FD_H2_HDR_STATUS,                      ":status"                     );
  _( FD_H2_HDR_ACCEPT_CHARSET,              "accept-charset"              );
  _( FD_H2_HDR_ACCEPT_ENCODING,             "accept-encoding"             );
  _( FD_H2_HDR_ACCEPT_LANGUAGE,             "accept-language"             );
  _( FD_H2_HDR_ACCEPT_RANGES,               "accept-ranges"               );
  _( FD_H2_HDR_ACCEPT,                      "accept"                      );
  _( FD_H2_HDR_ACCESS_CONTROL_ALLOW_ORIGIN, "access-control-allow-origin" );
  _( FD_H2_HDR_AGE,                         "age"                         );
  _( FD_H2_HDR_ALLOW,                       "allow"                       );
  _( FD_H2_HDR_AUTHORIZATION,               "authorization"               );
  _( FD_H2_HDR_CACHE_CONTROL,               "cache-control"               );
  _( FD_H2_HDR_CONTENT_DISPOSITION,         "content-disposition"         );
  _( FD_H2_HDR_CONTENT_ENCODING,            "content-encoding"            );
  _( FD_H2_HDR_CONTENT_LANGUAGE,            "content-language"            );
  _( FD_H2_HDR_CONTENT_LENGTH,              "content-length"              );
  _( FD_H2_HDR_CONTENT_LOCATION,            "content-location"            );
  _( FD_H2_HDR_CONTENT_RANGE,               "content-range"               );
  _( FD_H2_HDR_CONTENT_TYPE,                "content-type"                );
  _( FD_H2_HDR_COOKIE,                      "cookie"                      );
  _( FD_H2_HDR_DATE,                        "date"                        );
  _( FD_H2_HDR_ETAG,                        "etag"                        );
  _( FD_H2_HDR_EXPECT,                      "expect"                      );
  _( FD_H2_HDR_EXPIRES,                     "expires"                     );
  _( FD_H2_HDR_FROM,                        "from"                        );
  _( FD_H2_HDR_HOST,                        "host"                        );
  _( FD_H2_HDR_IF_MATCH,                    "if-match"                    );
  _( FD_H2_HDR_IF_MODIFIED_SINCE,           "if-modified-since"           );
  _( FD_H2_HDR_IF_NONE_MATCH,               "if-none-match"               );
  _( FD_H2_HDR_IF_RANGE,                    "if-range"                    );
  _( FD_H2_HDR_IF_UNMODIFIED_SINCE,         "if-unmodified-since"         );
  _( FD_H2_HDR_LAST_MODIFIED,               "last-modified"               );
  _( FD_H2_HDR_LINK,                        "link"                        );
  _( FD_H2_HDR_LOCATION,                    "location"                    );
  _( FD_H2_HDR_MAX_FORWARDS,                "max-forwards"                );
  _( FD_H2_HDR_PROXY_AUTHENTICATE,          "proxy-authenticate"          );
  _( FD_H2_HDR_PROXY_AUTHORIZATION,         "proxy-authorization"         );
  _( FD_H2_HDR_RANGE,                       "range"                       );
  _( FD_H2_HDR_REFERER,                     "referer"                     );
  _( FD_H2_HDR_REFRESH,                     "refresh"                     );
  _( FD_H2_HDR_RETRY_AFTER,                 "retry-after"                 );
  _( FD_H2_HDR_SERVER,                      "server"                      );
  _( FD_H2_HDR_SET_COOKIE,                  "set-cookie"                  );
  _( FD_H2_HDR_STRICT_TRANSPORT_SECURITY,   "strict-transport-security"   );
  _( FD_H2_HDR_TRANSFER_ENCODING,           "transfer-encoding"           );
  _( FD_H2_HDR_USER_AGENT,                  "user-agent"                  );
  _( FD_H2_HDR_VARY,                        "vary"                        );
  _( FD_H2_HDR_VIA,                         "via"                         );
  _( FD_H2_HDR_WWW_AUTHENTICATE,            "www-authenticate"            );
  default:
    FD_LOG_ERR(( "invalid idx %d", idx ));
  }
# undef EXPECT_NAME
}

void
test_h2_hdr_match( void ) {
  fd_h2_hdr_matcher_t matcher[1];
  FD_TEST( fd_h2_hdr_matcher_init( matcher, 1UL )==matcher );

  /* Test sanity checks */
  int log_lvl = fd_log_level_stderr();
  fd_log_level_stderr_set( 4 );
  FD_TEST( !fd_h2_hdr_matcher_init( NULL,               0UL ) );
  FD_TEST( !fd_h2_hdr_matcher_init( (uchar *)matcher+1, 0UL ) );
  fd_log_level_stderr_set( log_lvl );

  /* Test query */
  fd_h2_hdr_match_seed = 123UL;
  for( uint i=1U; i<=61U; i++ ) {
    char const * name     = fd_hpack_static_table[ i ].entry;
    ulong        name_len = fd_hpack_static_table[ i ].name_len;

    int idx = fd_h2_hdr_match( matcher, NULL, 0UL, FD_H2_HDR_HINT_NAME_INDEXED|i );
    check_hpack_idx( idx, name, name_len );

    idx = fd_h2_hdr_match( matcher, name, name_len, 0UL );
    check_hpack_idx( idx, name, name_len );
  }

  FD_TEST( fd_h2_hdr_match( matcher, "sec-websocket-key",        17UL, 0U )==-53 );
  FD_TEST( fd_h2_hdr_match( matcher, "sec-websocket-extensions", 24UL, 0U )==-54 );
  FD_TEST( fd_h2_hdr_match( matcher, "sec-websocket-accept",     20UL, 0U )==-55 );
  FD_TEST( fd_h2_hdr_match( matcher, "sec-websocket-protocol",   22UL, 0U )==-56 );
  FD_TEST( fd_h2_hdr_match( matcher, "sec-websocket-version",    21UL, 0U )==-57 );

  FD_TEST( !fd_h2_hdr_match( matcher, NULL, 0UL, 0U ) );

  fd_h2_hdr_match_seed = 123UL;
  FD_TEST( !fd_h2_hdr_match( matcher, "foo", 3UL, 0U ) );
  fd_h2_hdr_match_seed = 123UL;
  fd_h2_hdr_matcher_insert( matcher, 1, "foo", 3UL );
  FD_TEST( matcher->entry_cnt==1 );
  fd_h2_hdr_matcher_insert( matcher, 1, "foo", 3UL );
  FD_TEST( matcher->entry_cnt==1 );
  fd_h2_hdr_match_seed = 123UL;
  FD_TEST( fd_h2_hdr_match( matcher, "foo", 3UL, 0U )==1 );
  FD_TEST( fd_h2_hdr_match( matcher, "foo", 2UL, 0U )==0 );
  FD_TEST( fd_h2_hdr_match( matcher, "foo", 4UL, 0U )==0 );

  /* Hash collision */
  static uchar const collision_u[8] = { 0xae, 0x73, 0x65, 0x0d, 0x01, 0x00, 0x00, 0x00 };
  char const * collision = (char const *)collision_u;
  fd_h2_hdr_matcher_insert( matcher, 2, collision, 8UL );
  fd_h2_hdr_match_entry_t const * entry1 = fd_h2_hdr_map_query_const( matcher->entry, (fd_h2_hdr_match_key_t){ .hdr="foo",     .hdr_len=3 }, NULL );
  fd_h2_hdr_match_entry_t const * entry2 = fd_h2_hdr_map_query_const( matcher->entry, (fd_h2_hdr_match_key_t){ .hdr=collision, .hdr_len=8 }, NULL );
  FD_TEST( entry1->hash == entry2->hash );
  FD_TEST( fd_h2_hdr_match( matcher, "foo",     3UL, 0U )==1 );
  FD_TEST( fd_h2_hdr_match( matcher, collision, 8UL, 0U )==2 );
  FD_TEST( matcher->entry_cnt==2 );

#if FD_HAS_HOSTED && defined(__linux__)
  #define FD_TEST_FAIL( ACTION ) do {                       \
    pid_t pid = fork();                                     \
    FD_TEST( pid >= 0 );                                    \
    if( pid==0 ) {                                          \
      fd_log_enable_unclean_exit();                         \
      fd_log_level_stderr_set( 5 );                         \
      ACTION;                                               \
      exit( 0 );                                            \
    }                                                       \
    int status = 0;                                         \
    wait( &status );                                        \
    FD_TEST( WIFEXITED(status) && WEXITSTATUS(status)==1 ); \
  } while( 0 )

  FD_TEST_FAIL( fd_h2_hdr_matcher_insert( matcher,     0, "bla", 3UL        ) );
  FD_TEST_FAIL( fd_h2_hdr_matcher_insert( matcher,    -1, "bla", 3UL        ) );
  FD_TEST_FAIL( fd_h2_hdr_matcher_insert( matcher, 65536, "bla", 3UL        ) );
  FD_TEST_FAIL( fd_h2_hdr_matcher_insert( matcher,     3, NULL,  0UL        ) );
  FD_TEST_FAIL( fd_h2_hdr_matcher_insert( matcher,     3, NULL,  ULONG_MAX  ) );
#endif

  /* Fill hash map */
  for( uint rem=FD_H2_HDR_MATCH_MAX-2; rem; rem-- ) {
    char key[4]; FD_STORE( uint, key, rem );
    fd_h2_hdr_matcher_insert( matcher, 2, key, 4UL );
  }
  FD_TEST( matcher->entry_cnt==FD_H2_HDR_MATCH_MAX );
#if FD_HAS_HOSTED && defined(__linux__)
  FD_TEST_FAIL( fd_h2_hdr_matcher_insert( matcher, 4, "overflow", 8UL ) );
#endif

  fd_h2_hdr_matcher_fini( matcher );
}
