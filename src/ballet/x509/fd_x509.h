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

struct fd_x509_cert_info {
  /* TBSCertificate version: 0=v1, 1=v2, 2=v3 */
  uchar         version;

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

  /* Subject Alternative Name GeneralNames content */
  uchar const * san_general_names;
  ulong         san_general_names_len;
  uchar         has_subject_alt_name;
};

typedef struct fd_x509_cert_info fd_x509_cert_info_t;

FD_PROTOTYPES_BEGIN

/* fd_x509_extract_pubkey parses cert and returns its subject public key and
   FD_X509_KEY_* type.  Supported key types are Ed25519, ECDSA P-256, and
   ECDSA P-384.  *out_pubkey aliases cert and remains valid only while cert
   remains valid.  cert and all output arguments must be non-NULL.

   Returns 0 on success and -1 on failure. */

int
fd_x509_extract_pubkey( uchar const *  cert,
                        ulong          cert_sz,
                        uchar const ** out_pubkey,
                        ulong *        out_pubkey_len,
                        uchar *        out_key_type );


/* fd_x509_decode_ecdsa_sig decodes a DER-encoded ECDSA signature
   SEQUENCE { INTEGER r, INTEGER s } into raw_sig
   raw_sig must have room for 2*scalar_sz bytes, where scalar_sz is
   32 for P256 and 48 for P384.
   Returns 0 on success, -1 on failure. */

int
fd_x509_decode_ecdsa_sig( uchar const * der,
                          ulong         der_len,
                          uchar *       raw_sig,
                          ulong         scalar_sz );

/* fd_x509_ec_point_compress compresses a supported
   uncompressed EC point (04 || x || y) into compressed form (02/03 || x).
   coord_sz must be 32 for P-256 or 48 for P-384.  uncompressed must be
   at least 1+2*coord_sz bytes.  Coordinates must be canonical and the
   exact supplied point must satisfy the curve equation.  compressed
   must be at least 1+coord_sz bytes. Both pointers must be non-NULL.
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

/* fd_x509_name_equal compares two DER-encoded X.509 Names according to
   the RFC 5280 distinguished-name matching rules supported by this
   verifier.  Returns 1 if equal and 0 otherwise. */

int
fd_x509_name_equal( uchar const * a,
                    ulong         a_len,
                    uchar const * b,
                    ulong         b_len );

/* fd_x509_san_matches tests hostname against every dNSName in info's
   subjectAltName extension.  Matching folds ASCII case and permits a
   wildcard only as the complete leftmost label.  IPv4 literals do not match
   dNSName values.  Returns 1 for a match and 0 for no match, an absent SAN,
   malformed input, or a NULL argument. */

int
fd_x509_san_matches( fd_x509_cert_info_t const * info,
                     char const *                hostname,
                     ulong                       hostname_len );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_x509_fd_x509_h */
