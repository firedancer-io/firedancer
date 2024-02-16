#ifndef HEADER_fd_src_waltz_tls_fd_tls_asn1_h
#define HEADER_fd_src_waltz_tls_fd_tls_asn1_h

#include "../fd_waltz_base.h"

/* fd_tls_asn1.h provides minimal APIs for handling ASN.1 DER encoded
   data.  Currently, limited to handling of Ed25519 keys as specified
   in RFC 8410. */

FD_PROTOTYPES_BEGIN

extern const uchar fd_asn1_ed25519_pubkey_prefix[12];

/* fd_ed25519_public_key_from_asn1 attempts to extract an Ed25519
   public key from an ASN.1 DER container at [buf,buf+sz).  On success,
   returns a pointer to the first byte of the 32 byte subregion holding
   the public key.  On failure, returns NULL.

   Does not verify the returned public key for validity -- assume
   untrusted.

   TODO Does not correctly handle all legal DER encodings.
   Only the trivial encoding is handled.  May not work with all TLS
   libraries.  (Protocol ossification ...) */

void const *
fd_ed25519_public_key_from_asn1( uchar const * buf,
                                 ulong         sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_tls_fd_tls_asn1_h */
