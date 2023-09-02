#ifndef HEADER_fd_src_ballet_x509_fd_x509_gen_h
#define HEADER_fd_src_ballet_x509_fd_x509_gen_h

/* fd_x509_gen.h generates mock X.509 certificates for QUIC peer-to-peer
   use.  These certificates are deliberately crafted to pass as valid
   when connecting to a rustls peer.  They are however semantically
   invalid (e.g. hardcoded to subject 'localhost').  The use of X.509 is
   a mistake in the first place, and should be fixed via RFC 7250 raw
   public keys.  As soon as raw public keys are implemented network
   wide, this code should be deleted. */

#include "../fd_ballet_base.h"
#include "../sha512/fd_sha512.h"

/* FD_X509_MOCK_CERT_SZ is the byte size of the DER serialization of a
   mock X.509 certificate */

#define FD_X509_MOCK_CERT_SZ (0xf4)

/* fd_x509_mock_cert generates a self-signed X.509 certificate given
   an Ed25519 key.  Resulting cert will contain the given public key
   and an Ed25519 signature made with said key.  Certificate bytes
   (of size FD_X509_MOCK_CERT_SZ) are copied out to buf.  private_key
   is an arbitrary 32 byte vector used as an Ed25519 scalar/private key.
   serial is a random 64-bit integer.  Derives the corresponding Ed25519
   public key and performs a signature operation.  The caller should
   cache the resulting buffer as this is a slow operation. */

void
fd_x509_mock_cert( uchar         buf[ static FD_X509_MOCK_CERT_SZ ],
                   uchar         private_key[ static 32 ],
                   ulong         serial,
                   fd_sha512_t * sha );

#endif /* HEADER_fd_src_ballet_x509_fd_x509_gen_h */
