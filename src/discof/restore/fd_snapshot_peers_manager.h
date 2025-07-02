#ifndef HEADER_fd_src_discof_restore_fd_snapshot_peers_manager_h
#define HEADER_fd_src_discof_restore_fd_snapshot_peers_manager_h

#include "fd_snapshot_peer.h"

/* TODO: bound this out */
#define FD_SNAPSHOT_PEERS_MAX 2048UL

/* fd_snapshot_peers_manager_t validates the eligibility of each
   discovered peer from gossip by pinging the peer and waiting for its
   response.  Peers are marked eligible or ineligible for snapshot
   downloading and sorted by lowest latency and snapshot age. */

struct fd_snapshot_peers_manager {
  fd_snapshot_peer_t peers[ FD_SNAPSHOT_PEERS_MAX ];
  ulong              peers_cnt;
  ulong              processed_responses;
  ulong              current_peer_idx;

  int                sockets[ FD_SNAPSHOT_PEERS_MAX ];
  ulong              sockets_cnt;

  long               ping_send_time_nanos[ FD_SNAPSHOT_PEERS_MAX ];
  long               ping_recv_time_nanos[ FD_SNAPSHOT_PEERS_MAX ];
};

typedef struct fd_snapshot_peers_manager fd_snapshot_peers_manager_t;

FD_FN_CONST static inline ulong
fd_snapshot_peers_manager_align( void ) {
  return alignof(fd_snapshot_peers_manager_t);
}

FD_FN_CONST static inline ulong
fd_snapshot_peers_manager_footprint( void ) {
  return sizeof(fd_snapshot_peers_manager_t);
}

fd_snapshot_peers_manager_t *
fd_snapshot_peers_manager_new( void * mem );

void
fd_snapshot_peers_manager_set_peers( fd_snapshot_peers_manager_t * self,
                                      fd_ip4_port_t const *         peers,
                                      ulong                         peers_cnt );

void
fd_snapshot_peers_manager_set_peers_testing( fd_snapshot_peers_manager_t * self,
                                              fd_snapshot_peer_t const *         peers,
                                              ulong                         peers_cnt );

ulong
fd_snapshot_peers_manager_get_valid_peers_cnt( fd_snapshot_peers_manager_t const * self );

fd_snapshot_peer_t const *
fd_snapshot_peers_manager_get_next_peer( fd_snapshot_peers_manager_t * self );

void
fd_snapshot_peers_manager_set_current_peer_invalid( fd_snapshot_peers_manager_t * self );

void
fd_snapshot_peers_manager_update_peer_state( fd_snapshot_peers_manager_t * self );

void
fd_snapshot_peers_manager_reset_pings( fd_snapshot_peers_manager_t * self );

int
fd_snapshot_peers_manager_send_pings( fd_snapshot_peers_manager_t * self );

int
fd_snapshot_peers_maanger_collect_responses( fd_snapshot_peers_manager_t * self );

void
fd_snapshot_peers_manager_sort_peers( fd_snapshot_peers_manager_t * self );

void *
fd_snapshot_peers_manager_delete( fd_snapshot_peers_manager_t * self );

#endif /* HEADER_fd_src_discof_restore_fd_snapshot_peers_manager_h */
