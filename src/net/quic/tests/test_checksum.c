#include "../../util/fd_net_util.h"

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
dump( uchar const * ptr ) {
  for( size_t j = 0; j < 20; ++j ) {
    printf( "%2.2x ", (unsigned)ptr[j] );
  }
  printf( "\n" );
}

int
test( uchar const * pkt ) {
  uchar tmp[20];
  memcpy( tmp, pkt, 20 );
  memset( tmp + 10, -1, 2 ); /* corrupt checksum field */

  fd_quic_net_ipv4_checksum( tmp );

  printf( "\nBefore:\n" );
  dump( pkt );

  printf( "After:\n" );
  dump( tmp );

  int pass = memcmp( tmp, pkt, 20 ) == 0;
  printf( "%s\n", pass ? "PASSED" : "FAILED" );

  return pass;
}


int
main( ) {
  int pass_all = 1;

  pass_all &= test( pkt0 );
  pass_all &= test( pkt1 );
  pass_all &= test( pkt2 );
  pass_all &= test( pkt3 );
  pass_all &= test( pkt4 );

  return pass_all;
}

