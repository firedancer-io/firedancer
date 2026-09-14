#ifndef HEADER_fd_src_discof_restore_utils_fd_sshttp_private_h
#define HEADER_fd_src_discof_restore_utils_fd_sshttp_private_h

#include "fd_sshttp.h"

#include "../../../waltz/tls/fd_tls.h"
#include "../../../waltz/tlsrec/fd_tlsrec_sock.h"
#include "../../../ballet/x509/fd_x509_ca_store.h"
#include "../../../ballet/x509/fd_x509_verify.h"

#define FD_SSHTTP_MAGIC (0xF17EDA2CE5811900) /* FIREDANCE HTTP V0 */

#define FD_SSHTTP_STATE_INIT          (0) /* start */
#define FD_SSHTTP_STATE_CONNECT       (1) /* connecting ssl */
#define FD_SSHTTP_STATE_REQ           (2) /* sending request */
#define FD_SSHTTP_STATE_RESP          (3) /* receiving response headers */
#define FD_SSHTTP_STATE_DL            (4) /* downloading response body */
#define FD_SSHTTP_STATE_REDIRECT      (5) /* following a redirect */
#define FD_SSHTTP_STATE_DONE          (6) /* done */

#define FD_SSHTTP_DEADLINE_NANOS (1L*1000L*1000L*1000L) /* 1 second  */

struct fd_sshttp_private {
  int   state;
  long  deadline;
  ulong empty_recvs;

  ulong hops;

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
  ulong resolved_slot;       /* effective slot from redirect filename */
  uchar resolved_hash[ 32 ]; /* binary hash from redirect filename */

  fd_tls_t          tls;
  fd_chacha_rng_t   rng[1];
  fd_tlsrec_conn_t  tls_conn;

  fd_x509_ca_store_t ca_store;
  int                ca_store_loaded;

  fd_tlsrec_sock_t  tls_sock[1];

  ulong content_len;
  ulong content_read;

  ulong magic;
};

#endif /* HEADER_fd_src_discof_restore_utils_fd_sshttp_private_h */
