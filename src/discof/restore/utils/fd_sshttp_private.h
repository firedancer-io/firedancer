#ifndef HEADER_fd_src_discof_restore_utils_fd_sshttp_private_h
#define HEADER_fd_src_discof_restore_utils_fd_sshttp_private_h

#include "fd_sshttp.h"

#if FD_HAS_OPENSSL
#include <openssl/ssl.h>
#endif

#define FD_SSHTTP_MAGIC (0xF17EDA2CE5811900) /* FIREDANCE HTTP V0 */

#define FD_SSHTTP_STATE_INIT          (0) /* start */
#define FD_SSHTTP_STATE_CONNECT       (1) /* connecting ssl */
#define FD_SSHTTP_STATE_REQ           (2) /* sending request */
#define FD_SSHTTP_STATE_RESP          (3) /* receiving response headers */
#define FD_SSHTTP_STATE_DL            (4) /* downloading response body */
#define FD_SSHTTP_STATE_SHUTTING_DOWN (5) /* shutting down ssl */
#define FD_SSHTTP_STATE_REDIRECT      (6) /* redirect after shutting down ssl */
#define FD_SSHTTP_STATE_DONE          (7) /* done */

#define FD_SSHTTP_DEADLINE_NANOS (1L*1000L*1000L*1000L) /* 1 second  */

struct fd_sshttp_private {
  int   state;
  int   next_state; /* used for state transitions in https connection */
  long  deadline;
  ulong empty_recvs;

  int   hops;

  char  location[ PATH_MAX ];
  ulong location_len;

  fd_ip4_port_t addr;
  char const *  hostname;
  int           is_https;
  int           sockfd;

  char  request[ 4096UL ];
  ulong request_len;
  ulong request_sent;

  ulong response_len;
  char  response[ USHORT_MAX ];

  char  snapshot_name[ PATH_MAX ];
  ulong snapshot_slot;

#if FD_HAS_OPENSSL
  SSL_CTX * ssl_ctx;
  SSL *     ssl;
#endif

  ulong content_len;
  ulong content_read;

  ulong magic;
};

#endif /* HEADER_fd_src_discof_restore_utils_fd_sshttp_private_h */
