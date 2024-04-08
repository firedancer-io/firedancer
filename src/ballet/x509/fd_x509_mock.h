#ifndef HEADER_fd_src_ballet_x509_fd_x509_gen_h
#define HEADER_fd_src_ballet_x509_fd_x509_gen_h

/* fd_x509_gen.h generates mock X.509 certificates for QUIC peer-to-peer
   use.  These certificates are deliberately crafted to pass as valid
   when connecting to a rustls peer.  They are however semantically
   invalid (e.g. hardcoded to subject 'localhost').  The use of X.509 is
   a mistake in the first place, and should be fixed via RFC 7250 raw
   public keys.  As soon as raw public keys are implemented network
   wide, this code should be deleted. */

#include "../../util/fd_util_base.h"
#include "../sha512/fd_sha512.h"

/* FD_X509_MOCK_CERT_SZ is the byte size of the DER serialization of a
   mock X.509 certificate */

#define FD_X509_MOCK_CERT_SZ (0xf4)

/* fd_x509_mock_cert generates a dummy X.509 certificate given an
   Ed25519 public key.  Resulting cert will contain an invalid
   signature.  Certificate bytes (of size FD_X509_MOCK_CERT_SZ) are
   copied out to buf. */

void
fd_x509_mock_cert( uchar         buf[ static FD_X509_MOCK_CERT_SZ ],
                   uchar         public_key[ static 32 ] );

#endif /* HEADER_fd_src_ballet_x509_fd_x509_gen_h */
