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

/* keyUsage bits (RFC 5280 Section 4.2.1.3), big endian */

#define FD_X509_KU_DIGITAL_SIGNATURE ((ushort)0x8000)  /* bit 0 */
#define FD_X509_KU_NON_REPUDIATION   ((ushort)0x4000)  /* bit 1 */
#define FD_X509_KU_KEY_ENCIPHERMENT  ((ushort)0x2000)  /* bit 2 */
#define FD_X509_KU_DATA_ENCIPHERMENT ((ushort)0x1000)  /* bit 3 */
#define FD_X509_KU_KEY_AGREEMENT     ((ushort)0x0800)  /* bit 4 */
#define FD_X509_KU_KEY_CERT_SIGN     ((ushort)0x0400)  /* bit 5 */
#define FD_X509_KU_CRL_SIGN          ((ushort)0x0200)  /* bit 6 */
#define FD_X509_KU_ENCIPHER_ONLY     ((ushort)0x0100)  /* bit 7 */
#define FD_X509_KU_DECIPHER_ONLY     ((ushort)0x0080)  /* bit 8 */

/* extKeyUsage purposes (RFC 5280 Section 4.2.1.12) */

#define FD_X509_EKU_SERVER_AUTH      ((ushort)0x0001)  /* 1.3.6.1.5.5.7.3.1 */
#define FD_X509_EKU_ANY              ((ushort)0x0002)  /* 2.5.29.37.0 */

#define FD_X509_SAN_DNS_MAX (4)

/* FD_X509_TIME_INVALID marks a validity timestamp that could not be
   parsed. */

#define FD_X509_TIME_INVALID (LONG_MIN)

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
  uchar         not_before_tag;  /* FD_DER_TAG_{UTC,GENERALIZED}_TIME */
  long          not_before_unix; /* seconds since the Unix epoch (or FD_X509_TIME_INVALID) */
  uchar const * not_after;
  ulong         not_after_len;
  uchar         not_after_tag;
  long          not_after_unix; /* seconds since the Unix epoch (or FD_X509_TIME_INVALID) */

  /* Certificate signature */
  uchar const * sig;
  ulong         sig_len;
  uchar         sig_alg;   /* FD_X509_SIG_{...} */

  /* Basic Constraints (RFC 5280 Section 4.2.1.9) */
  int           is_ca;     /* 1 if basicConstraints cA=TRUE */

  /* Key Usage (RFC 5280 Section 4.2.1.3) */
  ushort        key_usage;          /* FD_X509_KU_* bits, 0 if absent */
  uchar         has_key_usage;

  /* Extended Key Usage (RFC 5280 Section 4.2.1.12) */
  ushort        ext_key_usage;      /* FD_X509_EKU_* bits, 0 if absent */
  uchar         has_ext_key_usage;

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

/* fd_x509_time_parse converts an ASN.1 time value to seconds since the
   Unix epoch.  tag is FD_DER_TAG_UTC_TIME (YYMMDDHHMMSSZ, 13 bytes) or
   FD_DER_TAG_GENERALIZED_TIME (YYYYMMDDHHMMSSZ, 15 bytes).  [s,s+s_len)
   is the DER content, without tag and length.

   Returns seconds since the Unix epoch, or FD_X509_TIME_INVALID if the
   value is malformed or outside the accepted profile. */

long
fd_x509_time_parse( uchar         tag,
                    uchar const * s,
                    ulong         s_len );

int
fd_x509_san_matches( fd_x509_cert_info_t const * info,
                     char const *                hostname,
                     ulong                       hostname_len );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_x509_fd_x509_h */
