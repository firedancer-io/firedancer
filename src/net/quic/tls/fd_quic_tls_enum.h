#ifndef HEADER_fd_quic_tls_enum_h
#define HEADER_fd_quic_tls_enum_h


enum {
  FD_QUIC_TLS_SUCCESS = 0,
  FD_QUIC_TLS_FAILED,

  // supported hash algorithms
  FD_QUIC_TLS_HASH_SHA256 = 100,
  FD_QUIC_TLS_HASH_SHA384,

  // supported packet ciphers
  FD_QUIC_TLS_AEAD_AES_128_GCM,

  // supported header-protection ciphers

  // packet types
  FD_QUIC_PKTTYPE_V1_INITIAL = 0,
  FD_QUIC_PKTTYPE_V1_ZERO_RTT,
  FD_QUIC_PKTTYPE_V1_HANDSHAKE,
  FD_QUIC_PKTTYPE_V1_RETRY,
};

#endif

