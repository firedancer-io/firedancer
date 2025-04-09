#ifndef HEADER_fd_src_waltz_grpc_fd_grpc_codec_h
#define HEADER_fd_src_waltz_grpc_fd_grpc_codec_h

/* fd_grpc_codec.h provides helpers for gRPC over HTTP/2.

   https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md */

#include "../h2/fd_h2_base.h"
#include "../h2/fd_h2_hdr_match.h"

/* fd_grpc_hdr_t is the header part of a Length-Prefixed-Message. */

struct __attribute__((packed)) fd_grpc_hdr {
  uchar compressed; /* in [0,1] */
  uint  msg_sz;     /* net order */
  /* msg_sz bytes follow ... */
};

typedef struct fd_grpc_hdr fd_grpc_hdr_t;

struct fd_grpc_req_hdrs {
  char const * path;
  ulong        path_len;
  uint         https : 1; /* 1 if https, 0 if http */
  char const * bearer_auth;
  ulong        bearer_auth_len;
};

typedef struct fd_grpc_req_hdrs fd_grpc_req_hdrs_t;

struct fd_grpc_resp_hdrs {
  uint is_status_ok  : 1;
  uint is_grpc_proto : 1;
};

typedef struct fd_grpc_resp_hdrs fd_grpc_resp_hdrs_t;

FD_PROTOTYPES_BEGIN

/* fd_grpc_h2_gen_request_hdrs generates a HEADERS frame with gRPC
   request headers.  Returns FD_H2_SUCCESS on success.  On failure,
   returns FD_H2_INTERNAL_ERROR (insufficient space in rbuf_tx). */

int
fd_grpc_h2_gen_request_hdrs( fd_grpc_req_hdrs_t const * req,
                             fd_h2_rbuf_t *             rbuf_tx );

/* fd_grpc_h2_rec_response_hdrs consumes a HEADERS frame and recovers
   selected gRPC request headers.  Ignores unknown headers.  Returns
   FD_H2_SUCCESS on success, or FD_H2_ERR_PROTOCOL on parse failure.
   Logs reason for failure. */

int
fd_grpc_h2_read_response_hdrs( fd_grpc_resp_hdrs_t *       resp,
                               fd_h2_hdr_matcher_t const * matcher,
                               uchar const *               payload,
                               ulong                       payload_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_grpc_fd_grpc_codec_h */
