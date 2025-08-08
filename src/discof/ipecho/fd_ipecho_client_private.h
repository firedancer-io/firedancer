#ifndef HEADER_fd_src_discof_ipecho_fd_ipecho_client_private_h
#define HEADER_fd_src_discof_ipecho_fd_ipecho_client_private_h

#include "../../util/fd_util_base.h"

#include <sys/poll.h>

struct fd_ipecho_client_peer {
  int writing;
  ulong request_bytes_sent;

  ulong response_bytes_read;
  uchar response[ 28UL ];
};

typedef struct fd_ipecho_client_peer fd_ipecho_client_peer_t;

struct fd_ipecho_client_private {
  long start_time_nanos;
  ulong peer_cnt;

  struct pollfd pollfds[ 16UL ];
  fd_ipecho_client_peer_t peers[ 16UL ];

  ulong magic;
};

#define FD_IPECHO_PARSE_OK  ( 0)
#define FD_IPECHO_PARSE_ERR (-1)

int
fd_ipecho_client_parse_response( uchar const * response,
                                 ulong         response_len,
                                 ushort *      shred_version );

#endif /* HEADER_fd_src_discof_ipecho_fd_ipecho_client_private_h */
