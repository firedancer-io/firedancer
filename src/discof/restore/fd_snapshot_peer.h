#ifndef HEADER_fd_src_discof_restore_fd_snapshot_peer_h
#define HEADER_fd_src_discof_restore_fd_snapshot_peer_h

#include "../../util/net/fd_net_headers.h"

struct fd_snapshot_peer {
  fd_ip4_port_t dest;
  int           has_authentication_token;
  char          authentication_token[ PATH_MAX ];
  int           requires_host_domain;
  char          host_domain_name[ PATH_MAX ];
  int           valid;
  int           ping_sent;
  int           ping_received;
  ulong         latency;
  long          marked_invalid_time_nanos;
};

typedef struct fd_snapshot_peer fd_snapshot_peer_t;

#endif /* HEADER_fd_src_discof_restore_fd_snapshot_peer_h */
