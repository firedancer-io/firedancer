#ifndef HEADER_fd_src_waltz_grpc_fd_grpc_h
#define HEADER_fd_src_waltz_grpc_fd_grpc_h

/* fd_grpc.h provides helpers for gRPC over HTTP/2.

   https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md */

#include "../h2/fd_h2_base.h"

/* fd_grpc_hdr_t is the header part of a Length-Prefixed-Message. */

struct fd_grpc_hdr {
  uchar compressed; /* in [0,1] */
  uint  msg_sz;     /* net order */
  /* msg_sz bytes follow ... */
};

typedef struct fd_grpc_hdr fd_grpc_hdr_t;

struct fd_grpc_req {
  char const * path;
  ulong        path_len;
  uint         https : 1; /* 1 if https, 0 if http */
};

typedef struct fd_grpc_req fd_grpc_req_t;

FD_PROTOTYPES_BEGIN

/* fd_grpc_h2_gen_request_hdr generates a HEADERS frame with gRPC
   request headers. */

int
fd_grpc_h2_gen_request_hdr( fd_grpc_req_t const * req,
                            fd_h2_rbuf_t *        rbuf_tx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_grpc_fd_grpc_h */
