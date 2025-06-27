#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include "fd_grpc_codec.h"
#include "../h2/fd_h2_rbuf.h"

int
LLVMFuzzerInitialize( int *argc,
                      char ***argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  (void) atexit( fd_halt );
  fd_log_level_core_set( 1 ); /* crash on info log */
  return 0;
}

static void
expect_hdr( fd_hpack_rd_t *hpack_rd, fd_h2_hdr_t *hdr, uchar **scratch,
            const char *expected_name, const char *expected_value ) {
  FD_TEST( !fd_hpack_rd_done( hpack_rd ));
  FD_TEST( !fd_hpack_rd_next( hpack_rd, hdr, scratch, 0UL ));
  ulong name_len  = strlen( expected_name );
  ulong value_len = strlen( expected_value );
  FD_TEST( hdr->name_len==name_len );
  FD_TEST( fd_memeq( hdr->name, expected_name, name_len ));
  FD_TEST( hdr->value_len==value_len );
  FD_TEST( fd_memeq( hdr->value, expected_value, value_len ));
}

int
LLVMFuzzerTestOneInput( uchar const *data,
                        ulong size ) {
  char host[256], path[256], bearer_auth[256], version[256];
  char host_port[512], user_agent[512];
  ulong minimum_len = sizeof( ushort )+ // port
                      sizeof( char )+ // https
                      4UL; // lengths of strings
  if( FD_UNLIKELY( size < minimum_len )) {
    return 1;
  }
  ulong remaining = size-minimum_len;

  uchar host_len        = data[ 0 ];
  uchar path_len        = data[ 1 ];
  uchar bearer_auth_len = data[ 2 ];
  uchar version_len     = data[ 3 ];
  uchar https           = data[ 4 ];
  ushort port           = (ushort)(data[ 5 ] << 8 | data[ 6 ]);
  if( FD_UNLIKELY( (ulong)host_len+(ulong)path_len+(ulong)bearer_auth_len+(ulong)version_len>remaining )) {
    return 1;
  }
  const char *content = (const char *) (data+minimum_len);
  const char *p = content;

  strncpy( host, p, host_len );
  host[ host_len ] = '\0';
  p += host_len;

  strncpy( path, p, path_len );
  path[ path_len ] = '\0';
  p += path_len;

  strncpy( bearer_auth, p, bearer_auth_len );
  bearer_auth[ bearer_auth_len ] = '\0';
  p += bearer_auth_len;

  strncpy( version, p, version_len );
  version[ version_len ] = '\0';

  /* update length if there is a null byte in the middle */
  host_len = (uchar)strlen( host );
  path_len = (uchar)strlen( path );
  bearer_auth_len = (uchar)strlen( bearer_auth );
  version_len = (uchar)strlen( version );
  if( FD_UNLIKELY((host_len==0) | (path_len==0) | (bearer_auth_len==0) | (version_len==0))) {
    return 1;
  }

  snprintf( host_port, sizeof(host_port), "%s:%d", host, port );

  snprintf( user_agent, sizeof(user_agent), "grpc-firedancer/%s", version );

  fd_grpc_req_hdrs_t req = {
      .host            = host,
      .host_len        = host_len,
      .port            = port,
      .path            = path,
      .path_len        = path_len,
      .https           = (uint)https%2,
      .bearer_auth     = bearer_auth,
      .bearer_auth_len = bearer_auth_len,
  };
  uchar buf[2048];
  fd_h2_rbuf_t rbuf_tx[1];
  fd_h2_rbuf_init( rbuf_tx, buf, sizeof(buf));
  FD_TEST( fd_grpc_h2_gen_request_hdrs( &req, rbuf_tx, version, version_len ) == 1 );
  FD_TEST((rbuf_tx->lo_off == 0) & (rbuf_tx->lo == buf));

  fd_hpack_rd_t hpack_rd[1];
  fd_hpack_rd_init( hpack_rd, buf, rbuf_tx->hi_off );
  fd_h2_hdr_t hdr[1];
  uchar *scratch = NULL;
  expect_hdr( hpack_rd, hdr, &scratch, ":method", "POST" );
  expect_hdr( hpack_rd, hdr, &scratch, ":scheme", "https" );
  expect_hdr( hpack_rd, hdr, &scratch, ":path", path );
  expect_hdr( hpack_rd, hdr, &scratch, ":authority", host_port );
  expect_hdr( hpack_rd, hdr, &scratch, "te", "trailers" );
  expect_hdr( hpack_rd, hdr, &scratch, "content-type", "application/grpc+proto" );
  expect_hdr( hpack_rd, hdr, &scratch, "user-agent", user_agent );
  FD_TEST( !fd_hpack_rd_done( hpack_rd ));
  FD_TEST( !fd_hpack_rd_next( hpack_rd, hdr, &scratch, 0UL ));
  FD_TEST( hdr->name_len == 13 );
  FD_TEST( fd_memeq( hdr->name, "authorization", 13UL ));
  FD_TEST( hdr->value_len == 7+req.bearer_auth_len );
  FD_TEST( fd_memeq( hdr->value, "Bearer ", 7UL ));
  FD_TEST( fd_memeq( hdr->value+7, req.bearer_auth, req.bearer_auth_len ));
  FD_TEST( fd_hpack_rd_done( hpack_rd ));

  return 0;
}
