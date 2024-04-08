#ifndef HEADER_fd_src_tango_quic_fd_quic_common_h
#define HEADER_fd_src_tango_quic_fd_quic_common_h

#include "../../util/fd_util.h"

#define FD_QUIC_PARSE_FAIL (~(ulong)0)
#define FD_QUIC_ENCODE_FAIL ( ~(ulong)0)

/* the max supported versions we could receive in a version packet */
#define FD_QUIC_MAX_VERSIONS 8

#include <stddef.h>

#include "tls/fd_quic_tls_enum.h"

/* forward decls */
typedef struct fd_quic_tls_cfg     fd_quic_tls_cfg_t;
typedef struct fd_quic_tls         fd_quic_tls_t;
typedef struct fd_quic_tls_hs      fd_quic_tls_hs_t;
typedef struct fd_quic_tls_secret  fd_quic_tls_secret_t;
typedef struct fd_quic_tls_hs_data fd_quic_tls_hs_data_t;

#endif /* HEADER_fd_src_tango_quic_fd_quic_common_h */

