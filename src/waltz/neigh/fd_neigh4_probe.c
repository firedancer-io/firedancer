#include "fd_neigh4_probe.h"
#include "../../tango/tempo/fd_tempo.h" /* fd_tempo_tick_per_ns */

#include <errno.h>
#include <sys/socket.h> /* socket(2) */
#include <netinet/in.h> /* IPPROTO_IP */
#include <unistd.h> /* close(2) */

void
fd_neigh4_prober_init( fd_neigh4_prober_t * prober,
                       float                max_probes_per_second,
                       ulong                max_probe_burst,
                       float                probe_delay_seconds ) {

  int sock_fd = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( sock_fd<0 ) ) {
    FD_LOG_ERR(( "socket(AF_INET,SOCK_DGRAM,0) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
  }

  int ip_ttl = 0;
  if( FD_UNLIKELY( 0!=setsockopt( sock_fd, IPPROTO_IP, IP_TTL, &ip_ttl, sizeof(int) ) ) ) {
    (void)close( sock_fd );
    FD_LOG_ERR(( "setsockopt(%i,IPPROTO_IP,IP_TTL,0) failed (%i-%s)",
                 sock_fd, errno, fd_io_strerror( errno ) ));
  }

  float tick_per_ns = (float)fd_tempo_tick_per_ns( NULL );

  *prober = (fd_neigh4_prober_t) {
    .sock_fd     = sock_fd,
    .probe_delay = (long)( tick_per_ns * probe_delay_seconds * 1e9f ),
    .rate_limit  = (fd_token_bucket_t) {
      .ts      = fd_tickcount(),
      .rate    = tick_per_ns * (max_probes_per_second / 1e9f),
      .burst   = (float)max_probe_burst,
      .balance = 0.f
    }
  };
}

void
fd_neigh4_prober_fini( fd_neigh4_prober_t * prober ) {
  if( FD_UNLIKELY( 0!=close( prober->sock_fd ) ) ) {
    FD_LOG_ERR(( "close(%i) failed (%i-%s)",
                 prober->sock_fd, errno, fd_io_strerror( errno ) ));
  }
  prober->sock_fd = -1;
}

int
fd_neigh4_probe( fd_neigh4_prober_t * prober,
                 fd_neigh4_entry_t *  entry,
                 uint                 ip4_addr,
                 long                 now ) {

  struct sockaddr_in dst = {
    .sin_family = AF_INET,
    .sin_port   = (ushort)0xFFFF,
    .sin_addr   = { .s_addr = ip4_addr }
  };
  int const flags = MSG_DONTWAIT|MSG_DONTROUTE;
  if( FD_UNLIKELY( sendto( prober->sock_fd, NULL, 0UL, flags, fd_type_pun_const( &dst ), sizeof(struct sockaddr_in) )<0 ) ) {
    return errno;
  }

  entry->probe_suppress_until = now + prober->probe_delay;

  return 0;
}
