#ifndef HEADER_fd_src_ballet_tls_fd_tls_keylog_h
#define HEADER_fd_src_ballet_tls_fd_tls_keylog_h

#include "../fd_ballet_base.h"

/* fd_tls_keylog implements the SSLKEYLOGFILE format for TLS 1.3,
   a widely supported standard for logging TLS encryption keys.

   This API should only be used for testing and debugging purposes.
   It is not intended for production use.

   Supports LF newline style only.

   IETF tracker for proposed standard:
   https://datatracker.ietf.org/doc/draft-thomson-tls-keylogfile/ */

#define FD_TLS_KEYLOG_LABEL_COMMENT                         (0U)
#define FD_TLS_KEYLOG_LABEL_CLIENT_EARLY_TRAFFIC_SECRET     (1U)
#define FD_TLS_KEYLOG_LABEL_EARLY_EXPORTER_MASTER_SECRET    (2U)
#define FD_TLS_KEYLOG_LABEL_CLIENT_HANDSHAKE_TRAFFIC_SECRET (3U)
#define FD_TLS_KEYLOG_LABEL_SERVER_HANDSHAKE_TRAFFIC_SECRET (4U)
#define FD_TLS_KEYLOG_LABEL_CLIENT_TRAFFIC_SECRET           (5U)
#define FD_TLS_KEYLOG_LABEL_SERVER_TRAFFIC_SECRET           (6U)
#define FD_TLS_KEYLOG_LABEL_EXPORTER_SECRET                 (7U)

struct fd_tls_keylog {
  ushort label;
  ushort secret_sz;
  uint   counter;
  uchar  client_random[ 32 ];
  uchar  secret[ 64 ];
};
typedef struct fd_tls_keylog fd_tls_keylog_t;

/* fd_tls_keylog_parse parses a keylog entry in text format to the given
   pointer.  str is a cstr of at least str_sz ASCII characters (with
   NUL terminator).  On success, the number of chars parsed and writes
   info to keylog.  On failure, returns zero and leaves keylog in
   an undefined state. */

ulong
fd_tls_keylog_parse( fd_tls_keylog_t * keylog,
                     char const *      str,
                     ulong             str_sz );

#endif /* HEADER_fd_src_ballet_tls_fd_tls_keylog_h */
