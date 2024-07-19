#ifndef HEADER_fd_src_waltz_quic_fd_quic_retry_h
#define HEADER_fd_src_waltz_quic_fd_quic_retry_h

#include "crypto/fd_quic_crypto_suites.h"

/* fd_quic_retry.h contains APIs for
   - the QUIC-TLS v1 Retry Integrity Tag (RFC 9001) */

FD_PROTOTYPES_BEGIN

/* fd_quic_retry_integrity_tag_{encrypt,decrypt} implement the RFC 9001
   "Retry Integrity Tag" AEAD scheme.

   This is a standard and mandatory step in the QUIC retry proces, both
   on the server (encrypt) and client side.  Confusingly, all inputs to
   these functions are either public constants (e.g. the hardcoded
   encryption key) or sent in plain text over the wire.  Thus, the
   "retry_integrity_tag" is more like a hash function than a MAC and the
   retry_pseudo_pkt is just obfuscated, but not securely encrypted.

   Failure to generate a correct integrity tag as part of the retry
   handshake is considered a protocol error that typically results in
   connection termination.

   The fd_quic_retry_integrity_tag_encrypt function "encrypts" the byte
   range at retry_pseudo_pkt_sz and sets retry_integrity_tag.  It is
   infallible.

   The fd_quic_retry_integrity_tag_decrypt attempts to "decrypt" the
   byte range at retry_pseudo_pkt_sz.  It returns FD_QUIC_SUCCESS if the
   integrity tag seemed correct, and FD_QUIC_FAILURE otherwise.  On
   failure, the contents of retry_pseudo_pkt are undefined. */

void
fd_quic_retry_integrity_tag_encrypt(
    uchar * retry_pseudo_pkt,
    ulong   retry_pseudo_pkt_sz,
    uchar   retry_integrity_tag[static FD_QUIC_RETRY_INTEGRITY_TAG_SZ]
);

int
fd_quic_retry_integrity_tag_decrypt(
    uchar *     retry_pseudo_pkt,
    ulong       retry_pseudo_pkt_sz,
    uchar const retry_integrity_tag[static FD_QUIC_RETRY_INTEGRITY_TAG_SZ]
);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_fd_quic_retry_h */
