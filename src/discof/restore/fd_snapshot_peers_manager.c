#include "fd_snapshot_peers_manager.h"
#include "../../util/log/fd_log.h"
#include "fd_icmp_ping.h"
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>

#define SORT_NAME sort_peers
#define SORT_KEY_T fd_snapshot_peer_t
#define SORT_BEFORE(a,b) ((a).latency < (b).latency)
#include "../../util/tmpl/fd_sort.c"

fd_snapshot_peers_manager_t *
fd_snapshot_peers_manager_new( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_snapshot_peers_manager_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }

  fd_memset( mem, 0, fd_snapshot_peers_manager_footprint() );

  fd_snapshot_peers_manager_t * self = (fd_snapshot_peers_manager_t *)mem;
  fd_memset( self->sockets, -1, sizeof(self->sockets) );

  for( ulong i=0UL; i<FD_SNAPSHOT_PEERS_MAX; i++ ) {
    self->sockets[ i ] = socket( PF_INET, SOCK_DGRAM, IPPROTO_ICMP );
    if( FD_UNLIKELY( self->sockets[ i ]<0 ) ) {
      FD_LOG_WARNING(( "Failed to create socket (%i-%s)", errno, fd_io_strerror( errno ) ));
      return NULL;
    }

    /* make the socket non blocking so that we can poll for data */
    int nonblock_res = fcntl( self->sockets[ i ], F_SETFL, 0 | O_NONBLOCK );
    if( FD_UNLIKELY( nonblock_res<0 ) ) {
      FD_LOG_WARNING(( "fcntl(%d,O_NONBLOCK) failed (%i-%s)", self->sockets[ i ], errno, fd_io_strerror( errno ) ));
      return NULL;
    }
  }

  return self;
}

void
fd_snapshot_peers_managers_set_peers( fd_snapshot_peers_manager_t * self,
                                      fd_ip4_port_t const *         peers,
                                      ulong                         peers_cnt ) {
  /* Copy peers into peers manager */
  for( ulong i=0UL; i<peers_cnt; i++ ) {
    fd_snapshot_peer_t * peer = &self->peers[ i ];
    peer->dest.addr = peers[ i ].addr;
    peer->dest.port = peers[ i ].port;
    peer->latency   = ULONG_MAX;
    peer->valid     = 1;
  }

  self->peers_cnt = peers_cnt;
}

void
fd_snapshot_peers_managers_set_peers_testing( fd_snapshot_peers_manager_t * self,
                                              fd_snapshot_peer_t const *         peers,
                                              ulong                         peers_cnt ) {
  /* Copy peers into peers manager */
  for( ulong i=0UL; i<peers_cnt; i++ ) {
    fd_snapshot_peer_t * peer = &self->peers[ i ];
    fd_memcpy( peer, &peers[ i ], sizeof(fd_snapshot_peer_t) );
    peer->latency   = ULONG_MAX;
    peer->valid     = 1;
  }

  self->peers_cnt = peers_cnt;
}

int
fd_snapshot_peers_manager_send_pings( fd_snapshot_peers_manager_t * self ) {
  for( ulong i=0UL; i<self->peers_cnt; i++ ) {
    if( !self->peers[ i ].ping_sent ) {
      int res = fd_icmp_send_ping( &self->sockets[ i ],
                                   &self->peers[ i ].dest,
                                   (ushort)i,
                                   &self->ping_send_time_nanos[ i ] );
      if( FD_UNLIKELY( res<0 ) ) {
        /* Sendings pings should not fail */
        FD_LOG_WARNING(( "fd_icmp_send_ping() failed for peer %lu (%d-%s)",
                         i, res, fd_io_strerror( res ) ));
        return 0;
      }

      self->peers[ i ].ping_sent = 1;
      self->sent_pings++;
    }
  }

  return self->sent_pings == self->peers_cnt ? 1 : 0;
}

int
fd_snapshot_peers_maanger_collect_responses( fd_snapshot_peers_manager_t * self ) {
  for( ulong i=0UL; i<self->peers_cnt; i++ ) {
    if( !self->peers[ i ].ping_received || self->peers[ i ].valid ) {

      /* Mark a peer invalid if its ping response timed out */
      long now = fd_log_wallclock();
      if( now > self->ping_send_time_nanos[ i ] + FD_SNAPSHOT_PING_TIMEOUT ) {
        self->peers[ i ].valid                     = 0;
        self->peers[ i ].marked_invalid_time_nanos = now;
        self->processed_responses++;
        FD_LOG_WARNING(("Peer %lu timed out after %ld nanos, marking invalid", i, now - self->ping_send_time_nanos[ i ]));
        continue;
      }

      int res = fd_icmp_recv_ping_resp( &self->sockets[ i ],
                                        &self->peers[ i ].dest,
                                        (ushort)i,
                                        &self->ping_recv_time_nanos[ i ] );
      if( FD_UNLIKELY( res==0 ) ) {
        self->peers[ i ].ping_received = 1;
        self->peers[ i ].latency       = (ulong)( self->ping_recv_time_nanos[ i ] - self->ping_send_time_nanos[ i ] );
        self->processed_responses++;
      }
    }
  }

  return self->processed_responses == self->peers_cnt ? 1 : 0;
}

static ulong
fd_snapshot_peers_manager_get_valid_peers_cnt( fd_snapshot_peers_manager_t const * self ) {
  ulong valid_peers_cnt = 0UL;
  for( ulong i=0UL; i<self->peers_cnt; i++ ) {
    if( self->peers[ i ].valid ) {
      valid_peers_cnt++;
    }

  }
  return valid_peers_cnt;
}

ulong
fd_snapshot_peers_manager_sort_peers( fd_snapshot_peers_manager_t * self ) {
  /* TODO: sort peers by latency and snapshot age */
  /* For now, we sort peers by latency only */
  FD_LOG_WARNING(("Sorting peers by latency "));
  sort_peers_inplace( self->peers, self->peers_cnt );

  for( ulong i=0UL; i<self->peers_cnt; i++ ) {
    if( self->peers[ i ].valid ) {
      FD_LOG_WARNING(( "peer i %lu has ip addr "FD_IP4_ADDR_FMT" and port %u and latency %lu",
                       i, FD_IP4_ADDR_FMT_ARGS( self->peers[ i ].dest.addr ), self->peers[ i ].dest.port, self->peers[ i ].latency ));
    }
  }
  return fd_snapshot_peers_manager_get_valid_peers_cnt( self );
}

void *
fd_snapshot_peers_manager_delete( fd_snapshot_peers_manager_t * self ) {
  fd_memset( self, 0, fd_snapshot_peers_manager_footprint() );
  return (void *)self;
}
