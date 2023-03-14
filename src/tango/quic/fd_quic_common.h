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
/* This is also, currently, used as the initial max size for datagrams */
#define FD_QUIC_MIN_INITIAL_PKT_SZ 1200

#define FD_QUIC_INITIAL_MAX_UDP_PAYLOAD_SZ 1200

/* basing this off of an MTU of 1500
   -20 for IP header (with no options)
   -8  for udp header */
#define FD_QUIC_MAX_UDP_PAYLOAD_SZ         ( 1500 - 20 - 8 )

/* sparsity factor used by fixed sized hashmaps */
#define FD_QUIC_SPARSITY 2.5

#include <stddef.h>

#include "tls/fd_quic_tls_enum.h"

#endif

