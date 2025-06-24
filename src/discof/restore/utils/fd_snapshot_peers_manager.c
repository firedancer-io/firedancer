#include "fd_snapshot_peers_manager.h"
#include "../../../util/log/fd_log.h"
#include "fd_icmp_ping.h"
#include "fd_snapshot_peer.h"
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>

#define FD_SNAPSHOT_PING_TIMEOUT_NANOS         1000000000L   /* 1 second */
#define FD_SNAPSHOT_PEER_INVALID_TIMEOUT_NANOS 180000000000L /* 3 minutes */

#define SORT_NAME sort_peers
#define SORT_KEY_T fd_snapshot_peer_t
#define SORT_BEFORE(a,b) ((a).latency < (b).latency)
#include "../../../util/tmpl/fd_sort.c"

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

  self->current_peer_idx = ULONG_MAX;
  return self;
}

void
fd_snapshot_peers_manager_set_peers( fd_snapshot_peers_manager_t * self,
                                      fd_ip4_port_t const *         peers,
                                      ulong                         peers_cnt ) {
  if( peers_cnt > FD_SNAPSHOT_PEERS_MAX ) {
    FD_LOG_WARNING(( "Too many peers (%lu), truncating to %lu", peers_cnt, FD_SNAPSHOT_PEERS_MAX ));
    peers_cnt = FD_SNAPSHOT_PEERS_MAX;
  }

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
fd_snapshot_peers_manager_set_peers_testing( fd_snapshot_peers_manager_t * self,
                                             fd_snapshot_peer_t const *    peers,
                                             ulong                         peers_cnt ) {
  if( peers_cnt > FD_SNAPSHOT_PEERS_MAX ) {
    FD_LOG_WARNING(( "Too many peers (%lu), truncating to %lu", peers_cnt, FD_SNAPSHOT_PEERS_MAX ));
    peers_cnt = FD_SNAPSHOT_PEERS_MAX;
  }

  /* Copy peers into peers manager */
  for( ulong i=0UL; i<peers_cnt; i++ ) {
    fd_snapshot_peer_t * peer = &self->peers[ i ];
    fd_memcpy( peer, &peers[ i ], sizeof(fd_snapshot_peer_t) );
    peer->latency   = ULONG_MAX;
    peer->valid     = 1;
  }

  self->peers_cnt = peers_cnt;
}

fd_snapshot_peer_t const *
fd_snapshot_peers_manager_get_next_peer( fd_snapshot_peers_manager_t * self ) {
  if( FD_UNLIKELY( !self->peers_cnt ) ) {
    return NULL;
  }

  if( self->current_peer_idx == ULONG_MAX ) {
    self->current_peer_idx = 0UL;
    return &self->peers[ self->current_peer_idx ];
  }

  /* Skip over invalid peers and return the next valid peer */
  for (;;) {
    self->current_peer_idx++;
    if( self->current_peer_idx >= self->peers_cnt ) {
      FD_LOG_WARNING(( "Exhausted all peers" ));
      return NULL;
    }

    if( !self->peers[ self->current_peer_idx ].valid ) {
      continue;
    } else {
      return &self->peers[ self->current_peer_idx ];
    }
  }
}

void
fd_snapshot_peers_manager_set_peer_invalid( fd_snapshot_peers_manager_t * self,
                                            ulong                         peer_idx ) {
  fd_snapshot_peer_t * peer = &self->peers[ peer_idx ];
  peer->valid = 0;
  peer->marked_invalid_time_nanos = fd_log_wallclock();
  FD_LOG_WARNING(( "Marking peer %lu with ip address "FD_IP4_ADDR_FMT" and port %u invalid",
                   peer_idx,
                   FD_IP4_ADDR_FMT_ARGS( peer->dest.addr ),
                   peer->dest.port ));
}

void
fd_snapshot_peers_manager_set_current_peer_invalid( fd_snapshot_peers_manager_t * self ) {
  if( FD_UNLIKELY( !self->peers_cnt ) ) {
    FD_LOG_WARNING(("No peers" ));
    return;
  }

  if( self->current_peer_idx >= self->peers_cnt ) {
    FD_LOG_WARNING(( "Exhausted all peers" ));
    return;
  }

  fd_snapshot_peers_manager_set_peer_invalid( self, self->current_peer_idx );
}

void
fd_snapshot_peers_manager_reset_pings( fd_snapshot_peers_manager_t * self ) {
  self->processed_responses = 0UL;

  fd_memset( self->ping_send_time_nanos, 0, sizeof(self->ping_send_time_nanos) );
  fd_memset( self->ping_recv_time_nanos, 0, sizeof(self->ping_recv_time_nanos) );

  for( ulong i=0UL; i<self->peers_cnt; i++ ) {
    self->peers[ i ].ping_sent     = 0;
    self->peers[ i ].ping_received = 0;
  }
}

void
fd_snapshot_peers_manager_update_peer_state( fd_snapshot_peers_manager_t * self ) {
  if( !self->peers_cnt ) return;

  long now = fd_log_wallclock();

  for( ulong i=0UL; i<self->peers_cnt; i++ ) {
    if( !self->peers[ i ].valid ) {
      /* Mark peer valid again if the invalid timeout has passed */
      if( now > self->peers[ i ].marked_invalid_time_nanos + FD_SNAPSHOT_PEER_INVALID_TIMEOUT_NANOS ) {
        self->peers[ i ].valid = 1;
        self->peers[ i ].latency = ULONG_MAX; /* Reset latency */
        self->peers[ i ].ping_sent = 0;
        self->peers[ i ].ping_received = 0;
        FD_LOG_WARNING(( "Peer %lu with ip address "FD_IP4_ADDR_FMT" and port %u is now valid again",
                         i,
                         FD_IP4_ADDR_FMT_ARGS( self->peers[ i ].dest.addr ),
                         self->peers[ i ].dest.port ));
      }
    }
  }
}

/* TODO: eventually we need to just send http requests because pings
   aren't representative of snapshot peer eligibility and may even be
   filtered by firewalls or the http server on a particular port may
   go down and the ping will still go through. */
int
fd_snapshot_peers_manager_send_pings( fd_snapshot_peers_manager_t * self ) {
  for( ulong i=0UL; i<self->peers_cnt; i++ ) {
    if( !self->peers[ i ].ping_sent ) {
      int res = fd_icmp_send_ping( self->sockets[ i ],
                                   &self->peers[ i ].dest,
                                   (ushort)i,
                                   &self->ping_send_time_nanos[ i ] );
      if( FD_UNLIKELY( res<0 ) ) {
        /* Sendings pings should not fail.  If they do fail, skip them
           and mark the peer invalid. */
        FD_LOG_WARNING(( "fd_icmp_send_ping() failed for peer %lu (%d-%s)",
                         i, res, fd_io_strerror( res ) ));
        self->peers[ i ].valid                     = 0;
        self->peers[ i ].marked_invalid_time_nanos = fd_log_wallclock();
      }

      self->peers[ i ].ping_sent = 1;
    }
  }

  return 1;
}

int
fd_snapshot_peers_maanger_collect_responses( fd_snapshot_peers_manager_t * self ) {
  for( ulong i=0UL; i<self->peers_cnt; i++ ) {
    if( !self->peers[ i ].ping_received || self->peers[ i ].valid ) {

      /* Mark a peer invalid if its ping response timed out */
      long now = fd_log_wallclock();
      if( now > self->ping_send_time_nanos[ i ] + FD_SNAPSHOT_PING_TIMEOUT_NANOS ) {
        self->peers[ i ].valid                     = 0;
        self->peers[ i ].marked_invalid_time_nanos = now;
        self->processed_responses++;
        FD_LOG_WARNING(("Peer %lu timed out after %ld nanos, marking invalid", i, now - self->ping_send_time_nanos[ i ]));
        continue;
      }

      int res = fd_icmp_recv_ping_resp( self->sockets[ i ],
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

ulong
fd_snapshot_peers_manager_get_valid_peers_cnt( fd_snapshot_peers_manager_t const * self ) {
  ulong valid_peers_cnt = 0UL;
  for( ulong i=0UL; i<self->peers_cnt; i++ ) {
    if( self->peers[ i ].valid ) {
      valid_peers_cnt++;
    }

  }
  return valid_peers_cnt;
}

void
fd_snapshot_peers_manager_sort_peers( fd_snapshot_peers_manager_t * self ) {
  /* TODO: sort peers by latency and snapshot age */
  /* For now, we sort peers by latency only */
  FD_LOG_INFO(("Sorting peers by latency "));
  sort_peers_inplace( self->peers, self->peers_cnt );

  for( ulong i=0UL; i<self->peers_cnt; i++ ) {
    if( self->peers[ i ].valid ) {
      FD_LOG_INFO(( "peer i %lu has ip addr "FD_IP4_ADDR_FMT" and port %u and latency %lu",
                       i, FD_IP4_ADDR_FMT_ARGS( self->peers[ i ].dest.addr ), self->peers[ i ].dest.port, self->peers[ i ].latency ));
    }
  }
}

void *
fd_snapshot_peers_manager_delete( fd_snapshot_peers_manager_t * self ) {
  fd_memset( self, 0, fd_snapshot_peers_manager_footprint() );
  return (void *)self;
}
