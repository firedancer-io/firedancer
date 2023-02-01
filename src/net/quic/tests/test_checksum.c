#include "../../util/fd_net_util.h"
#include "../../../util/fd_util.h"

#include <stdlib.h>
#include <stdio.h>

/* some real example ipv4 headers with correct checksums */
uchar pkt0[] = "\x45\x00\x00\x7f\x85\x96\x40\x00\x40\x11\xb6\xd5\x7f\x00\x00\x01"
               "\x7f\x00\x00\x01";

uchar pkt1[] = "\x45\x00\x00\x73\x00\x00\x40\x00\x40\x11\xb8\x61\xc0\xa8\x00\x01"
               "\xc0\xa8\x00\xc7";

uchar pkt2[] = "\x45\x00\x05\x1c\x85\x94\x40\x00\x40\x11\xb2\x3a\x7f\x00\x00\x01"
               "\x7f\x00\x00\x01";

uchar pkt3[] = "\x45\x00\x00\x6c\x85\xbd\x40\x00\x40\x11\xb6\xc1\x7f\x00\x00\x01"
               "\x7f\x00\x00\x01";

/* a test with particularly high intermediates */
uchar pkt4[] = "\xff\xff\xfe\xff\xff\xff\xff\xff\xff\xff\x01\x00\xff\xff\xff\xff"
               "\xff\xff\xff\xff";

void
test( uchar const * pkt ) {
  uchar tmp[20];
  fd_memcpy( tmp, pkt, 20 );
  fd_memset( tmp + 10, -1, 2 ); /* corrupt checksum field */

  fd_quic_net_ipv4_checksum( tmp );

  FD_LOG_NOTICE(( "Before:" ));
  FD_LOG_NOTICE(( FD_LOG_HEX20_FMT, FD_LOG_HEX20_FMT_ARGS( pkt ) ));

  FD_LOG_NOTICE(( "After:" ));
  FD_LOG_NOTICE(( FD_LOG_HEX20_FMT, FD_LOG_HEX20_FMT_ARGS( tmp ) ));

  FD_TEST( 0==memcmp( tmp, pkt, 20 ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test( pkt0 );
  test( pkt1 );
  test( pkt2 );
  test( pkt3 );
  test( pkt4 );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

