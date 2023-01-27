#ifndef HEADER_fd_quic_common_h
#define HEADER_fd_quic_common_h

// TODO find good places for these
#define FD_RESTRICT restrict

typedef unsigned char uchar;

#define FD_DEBUG(...) \
  fprintf( stderr, __VA_ARGS__ )

#define FD_QUIC_PARSE_FAIL (~(size_t)0)
#define FD_QUIC_ENCODE_FAIL ( ~(size_t)0 )

#define FD_QUIC_FMT_uint8 "u"
#define FD_QUIC_FMT_uint16 "u"
#define FD_QUIC_FMT_uint32 "u"
#define FD_QUIC_FMT_uint64 "lu"

#define FD_QUIC_HEX_FMT_uint8 "x"
#define FD_QUIC_HEX_FMT_uint16 "x"
#define FD_QUIC_HEX_FMT_uint32 "x"
#define FD_QUIC_HEX_FMT_uint64 "lx"

/* round up for pow(2) alignment */
#define FD_QUIC_POW2_ALIGN( x, a ) (((x)+((a)-1)) & (~((a)-1)))

/* the max supported versions we could reeive in a version packet */
#define FD_QUIC_MAX_VERSIONS 8

/* TODO find a better place */
/* INITIAL packets must be padded by spec - see rfc9000 14.1 */
#define FD_QUIC_MIN_INITIAL_PKT_SZ 1200

#include <stdint.h>
#include <stddef.h>

#include "tls/fd_quic_tls_enum.h"

#endif

