#ifndef HEADER_fd_src_tango_quic_fd_quic_common_h
#define HEADER_fd_src_tango_quic_fd_quic_common_h

#include "../../util/fd_util.h"

#define FD_QUIC_PARSE_FAIL (~(ulong)0)
#define FD_QUIC_ENCODE_FAIL ( ~(ulong)0)

/* the max supported versions we could receive in a version packet */
#define FD_QUIC_MAX_VERSIONS 8

/* sparsity factor used by fixed sized hashmaps */
#define FD_QUIC_SPARSITY 2.5

#include <stddef.h>

#include "tls/fd_quic_tls_enum.h"

#endif /* HEADER_fd_src_tango_quic_fd_quic_common_h */

