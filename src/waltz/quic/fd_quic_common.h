#ifndef HEADER_fd_src_waltz_quic_fd_quic_common_h
#define HEADER_fd_src_waltz_quic_fd_quic_common_h

#include "../../util/fd_util_base.h"

#define FD_QUIC_PARSE_FAIL (~(ulong)0)
#define FD_QUIC_ENCODE_FAIL ( ~(ulong)0)

/* the max supported versions we could receive in a version packet */
#define FD_QUIC_MAX_VERSIONS 8

#define FD_QUIC_HANDHOLDING 1
#if FD_QUIC_HANDHOLDING
#define FD_QUIC_INVARIANT(x, ...) do { \
    if( FD_UNLIKELY( !(x) ) ) { \
      FD_LOG_CRIT(( __VA_ARGS__ )); \
    } \
  } while(0)
#else
#define FD_QUIC_INVARIANT(x, ...) do { \
  if( FD_UNLIKELY( !(x) ) ) { \
    FD_LOG_WARNING(( __VA_ARGS__ )); \
  } \
} while(0)
#endif

/* forward decls */
typedef struct fd_quic               fd_quic_t;
typedef struct fd_quic_conn          fd_quic_conn_t;
typedef struct fd_quic_config        fd_quic_config_t;
typedef struct fd_quic_tls_cfg       fd_quic_tls_cfg_t;
typedef struct fd_quic_tls           fd_quic_tls_t;
typedef struct fd_quic_tls_hs        fd_quic_tls_hs_t;
typedef struct fd_quic_tls_secret    fd_quic_tls_secret_t;
typedef struct fd_quic_tls_hs_data   fd_quic_tls_hs_data_t;
typedef struct fd_quic_pkt           fd_quic_pkt_t;
typedef struct fd_quic_state_private fd_quic_state_t;
struct __attribute__((aligned(16))) fd_quic_range {
  /* offset in [ offset_lo, offset_hi ) is considered inside the range */
  /* a zero-initialized range will be empty [0,0) */
  ulong offset_lo;
  ulong offset_hi;
};

typedef struct fd_quic_range fd_quic_range_t;

#endif /* HEADER_fd_src_waltz_quic_fd_quic_common_h */
