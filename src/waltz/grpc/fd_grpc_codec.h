#ifndef HEADER_fd_src_waltz_grpc_fd_grpc_codec_h
#define HEADER_fd_src_waltz_grpc_fd_grpc_codec_h

/* fd_grpc_codec.h provides helpers for gRPC over HTTP/2.

   https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md */

#include "../h2/fd_h2_base.h"
#include "../h2/fd_h2_hdr_match.h"

/* gRPC protocol status codes
   https://github.com/grpc/grpc/blob/v1.71.0/doc/statuscodes.md */

#define FD_GRPC_STATUS_OK                        0
#define FD_GRPC_STATUS_CANCELLED                 1
#define FD_GRPC_STATUS_UNKNOWN                   2
#define FD_GRPC_STATUS_INVALID_ARGUMENT          3
#define FD_GRPC_STATUS_DEADLINE_EXCEEDED         4
#define FD_GRPC_STATUS_NOT_FOUND                 5
#define FD_GRPC_STATUS_ALREADY_EXISTS            6
#define FD_GRPC_STATUS_PERMISSION_DENIED         7
#define FD_GRPC_STATUS_RESOURCE_EXHAUSTED        8
#define FD_GRPC_STATUS_FAILED_PRECONDITION       9
#define FD_GRPC_STATUS_ABORTED                  10
#define FD_GRPC_STATUS_OUT_OF_RANGE             11
#define FD_GRPC_STATUS_UNIMPLEMENTED            12
#define FD_GRPC_STATUS_INTERNAL                 13
#define FD_GRPC_STATUS_UNAVAILABLE              14
#define FD_GRPC_STATUS_DATA_LOSS                15
#define FD_GRPC_STATUS_UNAUTHENTICATED          16

/* Internal IDs for gRPC headers */

#define FD_GRPC_HDR_STATUS  0x101
#define FD_GRPC_HDR_MESSAGE 0x102

/* fd_grpc_hdr_t is the header part of a Length-Prefixed-Message. */

struct __attribute__((packed)) fd_grpc_hdr {
  uchar compressed; /* in [0,1] */
  uint  msg_sz;     /* net order */
  /* msg_sz bytes follow ... */
};

typedef struct fd_grpc_hdr fd_grpc_hdr_t;

struct fd_grpc_req_hdrs {
  char const * host; /* excluding port */
  ulong        host_len; /* <=255 */
  ushort       port;
  char const * path;
  ulong        path_len;
  uint         https : 1; /* 1 if https, 0 if http */
  char const * bearer_auth;
  ulong        bearer_auth_len;
};

typedef struct fd_grpc_req_hdrs fd_grpc_req_hdrs_t;

struct fd_grpc_resp_hdrs {
  /* Headers */

  uint h2_status;   /* 0 implies invalid */
  uint is_grpc_proto : 1;

  /* Trailers */

  uint grpc_status; /* 0 implies invalid */
  char grpc_msg[ 1008 ];
  uint grpc_msg_len;
};

typedef struct fd_grpc_resp_hdrs fd_grpc_resp_hdrs_t;

FD_PROTOTYPES_BEGIN

/* fd_grpc_h2_gen_request_hdrs generates a HEADERS frame with gRPC
   request headers.  Returns 1 on success and 0 on failure */

int
fd_grpc_h2_gen_request_hdrs( fd_grpc_req_hdrs_t const * req,
                             fd_h2_rbuf_t *             rbuf_tx,
                             char const *               version,
                             ulong                      version_len );

/* fd_grpc_h2_rec_response_hdrs consumes a HEADERS frame and recovers
   selected gRPC request headers.  Ignores unknown headers.  Returns
   FD_H2_SUCCESS on success, or FD_H2_ERR_PROTOCOL on parse failure.
   Logs reason for failure. */

int
fd_grpc_h2_read_response_hdrs( fd_grpc_resp_hdrs_t *       resp,
                               fd_h2_hdr_matcher_t const * matcher,
                               uchar const *               payload,
                               ulong                       payload_sz );

char const *
fd_grpc_status_cstr( uint status );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_grpc_fd_grpc_codec_h */
