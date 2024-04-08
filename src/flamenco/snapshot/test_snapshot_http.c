#include "fd_snapshot_http.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_snapshot_http_t _http[1];
  fd_snapshot_http_t * http = fd_snapshot_http_new( _http, 0x01010101, 80 );
  FD_TEST( http );
  FD_TEST( 0==memcmp( http->req_buf + http->req_tail,
      "GET /snapshot.tar.bz2 HTTP/1.1\r\n"
      "user-agent: Firedancer\r\n"
      "accept: */*\r\n"
      "host: 1.1.1.1:80\r\n"
      "\r\n",
      (ulong)( http->req_head - http->req_tail ) ) );
  FD_TEST( fd_snapshot_http_delete( http )==_http );

  fd_halt();
  return 0;
}
