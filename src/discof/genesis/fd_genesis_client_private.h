#ifndef HEADER_fd_src_discof_genesis_fd_genesis_client_private_h
#define HEADER_fd_src_discof_genesis_fd_genesis_client_private_h

#include "fd_genesis_client.h"
#include "../../disco/topo/fd_topo.h"
#include <sys/poll.h>

struct fd_genesis_client_peer {
  fd_ip4_port_t addr;

  int writing;
  ulong request_bytes_sent;
  ulong response_bytes_read;
  uchar response[ 10UL*1024UL*1024UL ]; /* 10 MiB max response */
};

typedef struct fd_genesis_client_peer fd_genesis_client_peer_t;

struct fd_genesis_client_private {
  long start_time_nanos;
  ulong peer_cnt;
  ulong remaining_peer_cnt;

  struct pollfd pollfds[ FD_TOPO_GOSSIP_ENTRYPOINTS_MAX ];
  fd_genesis_client_peer_t peers[ FD_TOPO_GOSSIP_ENTRYPOINTS_MAX ];

  ulong magic;
};

#endif /* HEADER_fd_src_discof_genesis_fd_genesis_client_private_h */
