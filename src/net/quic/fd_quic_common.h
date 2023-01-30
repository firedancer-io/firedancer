#ifndef HEADER_fd_quic_common_h
#define HEADER_fd_quic_common_h

#include "../../util/fd_util.h"

#define FD_QUIC_PARSE_FAIL (~(ulong)0)
#define FD_QUIC_ENCODE_FAIL ( ~(ulong)0)

/* round up for pow(2) alignment */
#define FD_QUIC_POW2_ALIGN( x, a ) (((x)+((a)-1)) & (~((a)-1)))

/* the max supported versions we could reeive in a version packet */
#define FD_QUIC_MAX_VERSIONS 8

/* TODO find a better place */
/* INITIAL packets must be padded by spec - see rfc9000 14.1 */
#define FD_QUIC_MIN_INITIAL_PKT_SZ 1200

#include <stddef.h>

#include "tls/fd_quic_tls_enum.h"

#endif

