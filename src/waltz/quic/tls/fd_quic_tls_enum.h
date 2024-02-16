#ifndef HEADER_src_waltz_quic_tls_fd_quic_tls_enum_h
#define HEADER_src_waltz_quic_tls_fd_quic_tls_enum_h

#define FD_QUIC_TLS_SUCCESS (0)
#define FD_QUIC_TLS_FAILED  (1)

#define FD_QUIC_TLS_HASH_SHA256 (100)
#define FD_QUIC_TLS_HASH_SHA384 (101)

#define FD_QUIC_TLS_AEAD_AES_128_GCM (200)

#define FD_QUIC_PKTTYPE_V1_INITIAL   (0)
#define FD_QUIC_PKTTYPE_V1_ZERO_RTT  (1)
#define FD_QUIC_PKTTYPE_V1_HANDSHAKE (2)
#define FD_QUIC_PKTTYPE_V1_RETRY     (3)

#endif /* HEADER_src_waltz_quic_tls_fd_quic_tls_enum_h */

