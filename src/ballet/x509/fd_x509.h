#ifndef HEADER_fd_src_ballet_x509_fd_x509_h
#define HEADER_fd_src_ballet_x509_fd_x509_h

/* fd_x509.h provides a minimal ASN.1 DER parser for X.509 certificates.

   Supported key / signature algorithms:
   - Ed25519 (OID 1.3.101.112)
   - ECDSA P-256 with SHA-256

   - TODO: ECDSA P-384 with SHA-384
   - TODO?: RSA */

#include "../../util/fd_util_base.h"

/* Key type identifiers */

#define FD_X509_KEY_ED25519    ((uchar)0)
#define FD_X509_KEY_ECDSA_P256 ((uchar)1)
#define FD_X509_KEY_ECDSA_P384 ((uchar)2)
#define FD_X509_KEY_UNKNOWN    ((uchar)0xFF)

/* Signature algorithm identifiers */

#define FD_X509_SIG_ED25519            ((uchar)0)
#define FD_X509_SIG_ECDSA_SHA256       ((uchar)1)
#define FD_X509_SIG_ECDSA_SHA384       ((uchar)2)
#define FD_X509_SIG_UNKNOWN            ((uchar)0xFF)

#define FD_X509_SAN_DNS_MAX (4)

struct fd_x509_san_dns {
  char const * name;      /* NOT NUL terminated */
  ushort       name_len;
};

typedef struct fd_x509_san_dns fd_x509_san_dns_t;

struct fd_x509_cert_info {
  /* Subject Public Key Info */
  uchar const * pubkey;
  ulong         pubkey_len;
  uchar         key_type;     /* FD_X509_KEY_{...} */

  /* TBS (to-be-signed) region */
  uchar const * tbs;
  ulong         tbs_len;

  /* Issuer and Subject  */
  uchar const * issuer;
  ulong         issuer_len;
  uchar const * subject;
  ulong         subject_len;

  /* Validity period */
  uchar const * not_before;
  ulong         not_before_len;
  uchar const * not_after;
  ulong         not_after_len;

  /* Certificate signature */
  uchar const * sig;
  ulong         sig_len;
  uchar         sig_alg;   /* FD_X509_SIG_{...} */

  /* Basic Constraints (RFC 5280 Section 4.2.1.9) */
  int           is_ca;     /* 1 if basicConstraints cA=TRUE */

  /* Subject Alternative Name DNS entries */
  fd_x509_san_dns_t san_dns[ FD_X509_SAN_DNS_MAX ];
  uint              san_dns_cnt;
};

typedef struct fd_x509_cert_info fd_x509_cert_info_t;

FD_PROTOTYPES_BEGIN

/* TODO(sinon): needed? */

int
fd_x509_extract_pubkey( uchar const *  cert,
                        ulong          cert_sz,
                        uchar const ** out_pubkey,
                        ulong *        out_pubkey_len,
                        uchar *        out_key_type );


/* fd_x509_decode_ecdsa_sig decodes a DER-encoded ECDSA signature
   SEQUENCE { INTEER r, INTEGER s } into raw_sig
   raw_sig must have room for 2*scalar_sz bytes, where scalar_sz is
   32 for P256 and 48 for P384.
   Returns 0 on success, -1 on failure. */

int
fd_x509_decode_ecdsa_sig( uchar const * der,
                          ulong         der_len,
                          uchar *       raw_sig,
                          ulong         scalar_sz );

/* fd_x509_ec_point_compress compresses an uncompressed EC point
   (04 || x || y) into a commpressed form (02/03 || x).
   coord_sz is the byte size of each coordinate. uncommpressed must be
   at least 1+2*coord_sz bytes.
   compressed must be at least 1+coord_sz bytes.
   Returns 0 on success, -1 on failure. */

int
fd_x509_ec_point_compress( uchar const * uncompressed,
                           ulong         coord_sz,
                           uchar *       compressed );

/* fd_x509_cert_parse fully parses a DER-encoded X.509 cert.

   Returns 0 on success, non-zero on failure.

   All pointers in *out refer into the [cert, cert+cert_sz) buffer. */

int
fd_x509_cert_parse( uchar const *         cert,
                    ulong                 cert_sz,
                    fd_x509_cert_info_t * out );

int
fd_x509_san_matches( fd_x509_cert_info_t const * info,
                     char const *                hostname,
                     ulong                       hostname_len );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_x509_fd_x509_h */
