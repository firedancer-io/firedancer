#include "fd_net_sock.h"
#include "../../util/tmpl/fd_unit_test.c"

#include <errno.h>

#define MOCK_FD (3)

/* calls records every mocked syscall.  Unit tests run serially, so a
   global is fine.  Each test calls calls_reset first. */

static struct {
  ulong              socket_cnt;
  ulong              sendto_cnt;
  void const *       sendto_buf;
  ulong              sendto_len;
  int                sendto_flags;
  socklen_t          sendto_addr_len;
  struct sockaddr_in sendto_addr;
} calls;

static void
calls_reset( void ) {
  memset( &calls, 0, sizeof(calls) );
}

/* Mocks *************************************************************/

static int
mock_socket_ok( int domain,
                int type,
                int protocol ) {
  FD_TEST( domain==AF_INET );
  FD_TEST( type==(SOCK_RAW|SOCK_CLOEXEC) );
  FD_TEST( protocol==IPPROTO_RAW );
  calls.socket_cnt++;
  return MOCK_FD;
}

static int
mock_socket_eperm( int domain,
                   int type,
                   int protocol ) {
  (void)domain; (void)type; (void)protocol;
  calls.socket_cnt++;
  errno = EPERM;
  return -1;
}

static void
record_sendto( int                     sock,
               void const *            buf,
               ulong                   len,
               int                     flags,
               struct sockaddr const * addr,
               socklen_t               addr_len ) {
  FD_TEST( sock==MOCK_FD );
  FD_TEST( addr_len==sizeof(struct sockaddr_in) );
  calls.sendto_cnt++;
  calls.sendto_buf      = buf;
  calls.sendto_len      = len;
  calls.sendto_flags    = flags;
  calls.sendto_addr_len = addr_len;
  memcpy( &calls.sendto_addr, addr, sizeof(struct sockaddr_in) );
}

static long
mock_sendto_ok( int                     sock,
                void const *            buf,
                ulong                   len,
                int                     flags,
                struct sockaddr const * addr,
                socklen_t               addr_len ) {
  record_sendto( sock, buf, len, flags, addr, addr_len );
  return (long)len;
}

static long
mock_sendto_short( int                     sock,
                   void const *            buf,
                   ulong                   len,
                   int                     flags,
                   struct sockaddr const * addr,
                   socklen_t               addr_len ) {
  record_sendto( sock, buf, len, flags, addr, addr_len );
  return (long)len-1L;
}

static long
mock_sendto_enobufs( int                     sock,
                     void const *            buf,
                     ulong                   len,
                     int                     flags,
                     struct sockaddr const * addr,
                     socklen_t               addr_len ) {
  record_sendto( sock, buf, len, flags, addr, addr_len );
  errno = ENOBUFS;
  return -1L;
}

/* Helpers ***********************************************************/

static fd_net_sock_t net_sock[1];

/* pkt fills buf with an IPv4 packet of sz bytes addressed to daddr.
   The payload bytes are derived from seed. */

static fd_ip4_hdr_t const *
pkt( uchar * buf,
     ulong   sz,
     uint    daddr,
     uchar   seed ) {
  FD_TEST( sz>=sizeof(fd_ip4_hdr_t) );
  for( ulong i=0UL; i<sz; i++ ) buf[ i ] = (uchar)( seed+i );
  fd_ip4_hdr_t * ip4 = (fd_ip4_hdr_t *)buf;
  ip4->daddr = daddr;
  return ip4;
}

static fd_net_sock_t *
init_mock( fd_net_sock_ops_t const * ops ) {
  calls_reset();
  FD_TEST( fd_net_sock_init_ops( net_sock, ops )==net_sock );
  FD_TEST( net_sock->sock==MOCK_FD );
  return net_sock;
}

/* Init **************************************************************/

FD_UNIT_TEST( init_ok ) {
  static fd_net_sock_ops_t const ops = {
    .socket = mock_socket_ok,
    .sendto = mock_sendto_ok
  };
  calls_reset();
  FD_TEST( fd_net_sock_init_ops( net_sock, &ops )==net_sock );
  FD_TEST( net_sock->ops==&ops );
  FD_TEST( net_sock->sock==MOCK_FD );
  FD_TEST( calls.socket_cnt==1UL );
  FD_TEST( calls.sendto_cnt==0UL );
}

FD_UNIT_TEST( init_null ) {
  static fd_net_sock_ops_t const ops = {
    .socket = mock_socket_ok,
    .sendto = mock_sendto_ok
  };
  calls_reset();
  errno = 0;
  FD_TEST( !fd_net_sock_init( NULL ) );
  FD_TEST( errno==EINVAL );
  errno = 0;
  FD_TEST( !fd_net_sock_init_ops( NULL, &ops ) );
  FD_TEST( errno==EINVAL );
  errno = 0;
  FD_TEST( !fd_net_sock_init_ops( net_sock, NULL ) );
  FD_TEST( errno==EINVAL );

  static fd_net_sock_ops_t const ops_no_socket = { .sendto = mock_sendto_ok };
  errno = 0;
  FD_TEST( !fd_net_sock_init_ops( net_sock, &ops_no_socket ) );
  FD_TEST( errno==EINVAL );

  static fd_net_sock_ops_t const ops_no_sendto = { .socket = mock_socket_ok };
  errno = 0;
  FD_TEST( !fd_net_sock_init_ops( net_sock, &ops_no_sendto ) );
  FD_TEST( errno==EINVAL );
  FD_TEST( calls.socket_cnt==0UL ); /* rejected before opening a socket */
}

FD_UNIT_TEST( init_socket_fail ) {
  static fd_net_sock_ops_t const ops = {
    .socket = mock_socket_eperm,
    .sendto = mock_sendto_ok
  };
  calls_reset();
  errno = 0;
  FD_TEST( !fd_net_sock_init_ops( net_sock, &ops ) );
  FD_TEST( errno==EPERM );
  FD_TEST( calls.socket_cnt==1UL );
}

/* Send **************************************************************/

FD_UNIT_TEST( send_builds_args ) {
  static fd_net_sock_ops_t const ops = {
    .socket = mock_socket_ok,
    .sendto = mock_sendto_ok
  };
  static ulong const szs[] = { 100UL, FD_NET_MTU };
  for( ulong j=0UL; j<sizeof(szs)/sizeof(szs[0]); j++ ) {
    ulong const     sz = szs[ j ];
    fd_net_sock_t * ns = init_mock( &ops );

    uchar buf[ FD_NET_MTU ];
    uint  daddr = FD_IP4_ADDR( 10,1,2,(uchar)j );
    fd_ip4_hdr_t const * ip4 = pkt( buf, sz, daddr, (uchar)j );

    FD_TEST( fd_net_sock_send( ns, ip4, sz )==1 );
    FD_TEST( calls.sendto_cnt==1UL );
    FD_TEST( calls.sendto_buf==ip4 ); /* sent from the caller's buffer */
    FD_TEST( calls.sendto_len==sz );
    FD_TEST( calls.sendto_flags==0 ); /* blocking */
    FD_TEST( calls.sendto_addr_len==sizeof(struct sockaddr_in) );
    FD_TEST( calls.sendto_addr.sin_family     ==AF_INET );
    FD_TEST( calls.sendto_addr.sin_addr.s_addr==daddr );
  }
}

FD_UNIT_TEST( send_many ) {
  static fd_net_sock_ops_t const ops = {
    .socket = mock_socket_ok,
    .sendto = mock_sendto_ok
  };
  fd_net_sock_t * ns = init_mock( &ops );

  uchar buf[ FD_NET_MTU ];
  for( uint i=0U; i<10U; i++ ) {
    ulong sz    = 100UL+i;
    uint  daddr = FD_IP4_ADDR( 10,0,0,(uchar)i );
    FD_TEST( fd_net_sock_send( ns, pkt( buf, sz, daddr, (uchar)i ), sz )==1 );
    FD_TEST( calls.sendto_cnt==i+1UL );
    FD_TEST( calls.sendto_len==sz );
    FD_TEST( calls.sendto_addr.sin_addr.s_addr==daddr );
  }
}

FD_UNIT_TEST( send_error ) {
  static fd_net_sock_ops_t const ops = {
    .socket = mock_socket_ok,
    .sendto = mock_sendto_enobufs
  };
  fd_net_sock_t * ns = init_mock( &ops );

  uchar buf[ FD_NET_MTU ];
  FD_TEST( fd_net_sock_send( ns, pkt( buf, 100UL, 1U, 0 ), 100UL )==0 );
  FD_TEST( calls.sendto_cnt==1UL );
}

FD_UNIT_TEST( send_short ) {
  static fd_net_sock_ops_t const ops = {
    .socket = mock_socket_ok,
    .sendto = mock_sendto_short
  };
  fd_net_sock_t * ns = init_mock( &ops );

  uchar buf[ FD_NET_MTU ];
  FD_TEST( fd_net_sock_send( ns, pkt( buf, 100UL, 1U, 0 ), 100UL )==0 );
  FD_TEST( calls.sendto_cnt==1UL );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_unit_tests( argc, argv );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
