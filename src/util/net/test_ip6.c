#include "fd_ip6.h"
#include "fd_ip4.h"
#include "../../util/fd_util.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  uchar ip6_addr[16];
  fd_ip6_addr_ip4_mapped( ip6_addr, FD_IP4_ADDR( 10,1,2,3 ) );
  FD_TEST( fd_memeq( ip6_addr, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x0a\x01\x02\x03", 16 ) );
  FD_TEST( fd_ip6_addr_is_ip4_mapped( ip6_addr )==1 );
  for( ulong i=0UL; i<10UL; i++ ) {
    for( ulong k=0UL; k<8UL; k++ ) {
      ip6_addr[ i ] = (uchar)( ip6_addr[ i ]^(1U<<k) );
      FD_TEST( fd_ip6_addr_is_ip4_mapped( ip6_addr )==0 );
      ip6_addr[ i ] = (uchar)( ip6_addr[ i ]^(1U<<k) );
    }
  }
  FD_TEST( fd_ip6_addr_to_ip4( ip6_addr )==FD_IP4_ADDR( 10,1,2,3 ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

