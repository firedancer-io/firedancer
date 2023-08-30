#ifndef HEADER_fd_src_ballet_x509_fd_x509_openssl_h
#define HEADER_fd_src_ballet_x509_fd_x509_openssl_h

/* fd_x509_openssl provides APIs for generating Solana peer-to-peer
   X.509 certs using OpenSSL. */

#include "../fd_ballet_base.h"

#if FD_HAS_OPENSSL

#include <openssl/x509.h>

FD_PROTOTYPES_BEGIN

/* fd_x509_gen_solana_cert generates a new Solana X.509 certificate,
   self-signed by the given Ed25519 key.  Ownership of ed25519_pkey is
   not transferred (caller should free). ip_address is the network order
   IP address to use as a subject alternative name. Returns X509 object
   on success. On failure, returns NULL. */

X509 *
fd_x509_gen_solana_cert( EVP_PKEY * ed25519_pkey );

FD_PROTOTYPES_END

#endif /* FD_HAS_OPENSSL */

#endif /* HEADER_fd_src_ballet_x509_fd_x509_openssl_h */
