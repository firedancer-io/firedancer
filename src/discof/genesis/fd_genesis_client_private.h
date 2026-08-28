#ifndef HEADER_fd_src_discof_genesis_fd_genesis_client_private_h
#define HEADER_fd_src_discof_genesis_fd_genesis_client_private_h

#include "fd_genesis_client.h"
#include "../../disco/topo/fd_topo.h"
#include <poll.h>

struct fd_genesis_client_peer {
  fd_ip4_port_t addr;

  int writing;
  ulong request_bytes_sent;
  ulong response_bytes_read;
  uchar * response; /* response_max byte buffer, tail of the client region */
};

typedef struct fd_genesis_client_peer fd_genesis_client_peer_t;

struct fd_genesis_client_private {
  long start_time_nanos;
  ulong peer_cnt;
  ulong remaining_peer_cnt;
  ulong peer_max;
  ulong response_max;

  struct pollfd pollfds[ FD_TOPO_GOSSIP_ENTRYPOINTS_MAX ];

  ulong magic;

  fd_genesis_client_peer_t peers[]; /* peer_max entries, then peer_max response buffers */
};

#endif /* HEADER_fd_src_discof_genesis_fd_genesis_client_private_h */
