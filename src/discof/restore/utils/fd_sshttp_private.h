#ifndef HEADER_fd_src_discof_restore_utils_fd_sshttp_private_h
#define HEADER_fd_src_discof_restore_utils_fd_sshttp_private_h

#include "fd_sshttp.h"

#include "../../../waltz/tls/fd_tls.h"
#include "../../../waltz/tlsrec/fd_tlsrec.h"
#include "../../../ballet/x509/fd_x509_ca_store.h"
#include "../../../ballet/x509/fd_x509_verify.h"

#define FD_SSHTTP_MAGIC (0xF17EDA2CE5811900) /* FIREDANCE HTTP V0 */

#define FD_SSHTTP_STATE_INIT          (0) /* start */
#define FD_SSHTTP_STATE_CONNECT       (1) /* connecting TLS */
#define FD_SSHTTP_STATE_REQ           (2) /* sending request */
#define FD_SSHTTP_STATE_RESP          (3) /* receiving response headers */
#define FD_SSHTTP_STATE_DL            (4) /* downloading response body */
#define FD_SSHTTP_STATE_SHUTTING_DOWN (5) /* shutting down TLS */
#define FD_SSHTTP_STATE_REDIRECT      (6) /* redirecting */
#define FD_SSHTTP_STATE_DONE          (7) /* done */

#define FD_SSHTTP_DEADLINE_NANOS (1L*1000L*1000L*1000L) /* 1 second  */

#define FD_SSHTTP_TLS_BUF_SZ (4096UL)

struct fd_sshttp_private {
  int   state;
  int   next_state;
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
  ulong resolved_slot;
  uchar resolved_hash[ 32 ];

  fd_tls_t          tls;
  fd_tlsrec_conn_t  tls_conn;

  fd_x509_ca_store_t ca_store;
  int                ca_store_loaded;

  uchar tls_app_buf[ FD_SSHTTP_TLS_BUF_SZ ];
  ulong tls_app_buf_off;
  ulong tls_app_buf_sz;

  uchar tls_tx_buf[ FD_SSHTTP_TLS_BUF_SZ ];
  ulong tls_tx_buf_off;
  ulong tls_tx_buf_sz;

  ulong content_len;
  ulong content_read;

  ulong magic;
};

#endif /* HEADER_fd_src_discof_restore_utils_fd_sshttp_private_h */
