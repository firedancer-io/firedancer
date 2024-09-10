#ifndef HEADER_fd_src_waltz_quic_fd_quic_common_h
#define HEADER_fd_src_waltz_quic_fd_quic_common_h

#include "../../util/fd_util.h"

#define FD_QUIC_PARSE_FAIL (~(ulong)0)
#define FD_QUIC_ENCODE_FAIL ( ~(ulong)0)

/* the max supported versions we could receive in a version packet */
#define FD_QUIC_MAX_VERSIONS 8

#include <stddef.h>

#include "tls/fd_quic_tls_enum.h"

/* forward decls */
typedef struct fd_quic               fd_quic_t;
typedef struct fd_quic_config        fd_quic_config_t;
typedef struct fd_quic_tls_cfg       fd_quic_tls_cfg_t;
typedef struct fd_quic_tls           fd_quic_tls_t;
typedef struct fd_quic_tls_hs        fd_quic_tls_hs_t;
typedef struct fd_quic_tls_secret    fd_quic_tls_secret_t;
typedef struct fd_quic_tls_hs_data   fd_quic_tls_hs_data_t;
typedef struct fd_quic_pkt           fd_quic_pkt_t;
typedef struct fd_quic_state_private fd_quic_state_t;
typedef struct fd_quic_conn          fd_quic_conn_t;
typedef struct fd_quic_pkt_meta      fd_quic_pkt_meta_t;

struct __attribute__((aligned(16))) fd_quic_range {
  /* offset in [ offset_lo, offset_hi ) is considered inside the range */
  /* a zero-initialized range will be empty [0,0) */
  ulong offset_lo;
  ulong offset_hi;
};

typedef struct fd_quic_range fd_quic_range_t;

FD_PROTOTYPES_BEGIN

static inline int
fd_quic_range_can_insert( fd_quic_range_t const * range,
                          ulong                   idx ) {
  return idx+1UL >= range->offset_lo && idx <= range->offset_hi;
}

static inline int
fd_quic_range_insert( fd_quic_range_t * range,
                      ulong             idx ) {
  int hi_increased = idx >= range->offset_hi;
  range->offset_lo = fd_ulong_min( range->offset_lo, idx );
  range->offset_hi = fd_ulong_max( range->offset_hi, idx+1UL );
  return hi_increased;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_fd_quic_common_h */

