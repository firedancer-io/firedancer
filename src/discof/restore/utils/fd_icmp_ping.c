#include "fd_icmp_ping.h"
#include "../../../util/log/fd_log.h"
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
 #include <sys/socket.h>

int
fd_icmp_send_ping( int                   sockfd,
                   fd_ip4_port_t const * dest,
                   ushort                sequence,
                   long *                ping_send_time_nanos ) {
  if( sockfd<0 ) {
    FD_LOG_WARNING(( "Socket does not exist!" ));
    return -1;
  }

  struct sockaddr addr;
  fd_memset( &addr, 0, sizeof(addr) );
  socklen_t addr_len = sizeof(struct sockaddr_in);

  /* check if socket already connected */
  if( FD_UNLIKELY( getpeername( sockfd, &addr , &addr_len )!=0 ) ) {
    struct sockaddr_in connect_addr;
    fd_memset( &connect_addr, 0, sizeof(connect_addr) );
    /* set up dest address */
    connect_addr.sin_family      = AF_INET;
    connect_addr.sin_addr.s_addr = dest->addr;

    /* connect socket to dest address */
    int connect_res = connect( sockfd, fd_type_pun_const( &connect_addr ), sizeof(struct sockaddr_in) );
    if( FD_UNLIKELY( connect_res<0 ) ) {
      FD_LOG_WARNING(( "connect(%d,"FD_IP4_ADDR_FMT":%u) failed (%i-%s)",
                      sockfd, FD_IP4_ADDR_FMT_ARGS(dest->addr), dest->port,
                      errno, fd_io_strerror( errno ) ));
      return -1;
    }
  }

  struct icmphdr icmp_hdr;
  fd_memset( &icmp_hdr, 0, sizeof(icmp_hdr) );
  icmp_hdr.type             = ICMP_ECHO;
  icmp_hdr.un.echo.sequence = sequence;

  /* keep trying to send as long as the socket is blocked */
  for (;;) {
    long res = send( sockfd, &icmp_hdr, sizeof(icmp_hdr), 0 );
    if( FD_UNLIKELY( res<0 ) ) {
      if( errno == EWOULDBLOCK ) {
        continue;
      }
      FD_LOG_WARNING(( "sendto(%d) failed (%i-%s)",
                       sockfd, errno, fd_io_strerror( errno ) ));
      return -1;
    }

    FD_COMPILER_MFENCE();
    *ping_send_time_nanos = fd_log_wallclock();
    FD_COMPILER_MFENCE();

    return 0;
  }
}

int
fd_icmp_recv_ping_resp( int                   sockfd,
                        fd_ip4_port_t const * dest,
                        ushort                sequence,
                        long *                ping_recv_time_nanos ) {
  (void)dest;
  if( FD_UNLIKELY( sockfd<0 ) ) {
    FD_LOG_WARNING(( "Socket %d is not open!", sockfd ));
    return -1;
  }

  struct icmphdr icmp_hdr;
  fd_memset( &icmp_hdr, 0, sizeof(icmp_hdr) );

  ulong received_bytes = 0UL;
  for(;;) {
    long res = recv( sockfd, &icmp_hdr, sizeof(icmp_hdr), 0 );
    if( FD_UNLIKELY( res<0 ) ) {
      if( errno == EWOULDBLOCK || errno == EAGAIN ) {
        return (int)res;
      }

      FD_LOG_ERR(( "recvfrom(%d) failed (%i-%s)",
                      sockfd, errno, fd_io_strerror( errno ) ));
    }

    received_bytes += (ulong)res;
    if( received_bytes < sizeof(icmp_hdr) ) {
      continue;
    }

    FD_COMPILER_MFENCE();
    *ping_recv_time_nanos = fd_log_wallclock();
    FD_COMPILER_MFENCE();

    break;
  }

  if( icmp_hdr.type != ICMP_ECHOREPLY ) {
    FD_LOG_WARNING(( "Received non-echo reply ICMP packet: type %d", icmp_hdr.type ));
    return -1;
  }

  if( icmp_hdr.un.echo.sequence != sequence ) {
    FD_LOG_WARNING(( "Received ICMP packet with unexpected sequence: %u, expected: %u",
                 icmp_hdr.un.echo.sequence, (uint)0xA ));
    return -1;
  }

  return 0;
}
