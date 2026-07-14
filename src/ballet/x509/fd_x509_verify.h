#ifndef HEADER_fd_src_ballet_x509_fd_x509_verify_h
#define HEADER_fd_src_ballet_x509_fd_x509_verify_h

/* fd_x509_verify.h provides certificate chain verification.  Walks the
   chain from leaf cert through intermediates to a trusted root CA,
   verifying each signature.

   Ensures:
   - Each cert on the path is signed by the next cert or by a trust anchor
   - Where the next cert is the issuer, its subject matches and it has
     basicConstraints cA=TRUE
   - The path terminates at a trust anchor in the CA store
   - Hostname: the leaf cert's SAN must match the expected hostname

   We do NOT check:
   - Expiry dates (TODO?)
   - Certificate revocation (CRL / OCSP)
   - Path length constraints
   - Key usage */

#include "fd_x509.h"
#include "fd_x509_ca_store.h"

/* FD_X509_CHAIN_MAX is the maximum number of certs in a chain. */

#define FD_X509_CHAIN_MAX (8)

#define FD_X509_VERIFY_OK                  (0)
#define FD_X509_VERIFY_ERR_PARSE           (1)  /* certificate parse failed */
#define FD_X509_VERIFY_ERR_CHAIN_BREAK     (2)  /* issuer/subject mismatch in chain */
#define FD_X509_VERIFY_ERR_SIG             (3)  /* signature verification failed */
#define FD_X509_VERIFY_ERR_CA_FLAG         (4)  /* intermediate missing CA flag */
#define FD_X509_VERIFY_ERR_NO_TRUST_ANCHOR (5)  /* root not found in CA store */
#define FD_X509_VERIFY_ERR_HOSTNAME        (6)  /* SAN doesn't match hostname */
#define FD_X509_VERIFY_ERR_UNSUPPORTED     (7)  /* unsupported signature algorithm */
#define FD_X509_VERIFY_ERR_CHAIN_TOO_LONG  (8)  /* chain exceeds FD_X509_CHAIN_MAX */

FD_PROTOTYPES_BEGIN

/* fd_x509_verify_chain verifies a TLS certificate chain.

   chain_der is an array of DER-encoded certificates, chain_der_sz is
   the corresponding array of sizes.  chain_cnt is the number of
   certificates.  The first entry is the leaf cert.

   ca_store is the trusted CA store to anchor the chain against.

   hostname/hostname_len is the expected server hostname for SAN
   matching. hostname may be NULL or hostname_len may be 0 to skip
   hostname verification.

   Returns FD_X509_VERIFY_OK on success, or a non-zero error code on
   failure. */
int
fd_x509_verify_chain( uchar const * const *        chain_der,
                      ulong const *                chain_der_sz,
                      ulong                        chain_cnt,
                      fd_x509_ca_store_t const *   ca_store,
                      char const *                 hostname,
                      ulong                        hostname_len );

/* fd_x509_verify_tls_cert_msg verifies the certificate chain carried in
   the body of a TLS 1.3 Certificate handshake message (RFC 8446
   Section 4.4.2), i.e. a certificate_request_context followed by a
   CertificateList.  Parses the chain, then verifies it with
   fd_x509_verify_chain.  ca_store, hostname and hostname_len are as
   documented there.

   Returns FD_X509_VERIFY_OK on success, or a non-zero error code on
   failure. */

int
fd_x509_verify_tls_cert_msg( uchar const *              cert_msg,
                             ulong                      cert_msg_sz,
                             fd_x509_ca_store_t const * ca_store,
                             char const *               hostname,
                             ulong                      hostname_len );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_x509_fd_x509_verify_h */
