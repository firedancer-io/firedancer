#ifndef HEADER_fd_src_discof_restore_fd_snapshot_peer_h
#define HEADER_fd_src_discof_restore_fd_snapshot_peer_h

#include "../../../util/net/fd_net_headers.h"

/* fd_snapshot_peer_t defines a gossip peer and manages whether the
   peer is eligible for snapshot downloading.  The internals of this
   struct may change as the snapshot peer selection algorithm changes. */
struct fd_snapshot_peer {
  fd_ip4_port_t dest;
  int           valid;
  int           ping_sent;
  int           ping_received;
  ulong         latency;
  long          marked_invalid_time_nanos;
};

typedef struct fd_snapshot_peer fd_snapshot_peer_t;

#endif /* HEADER_fd_src_discof_restore_fd_snapshot_peer_h */
