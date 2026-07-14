#include "fd_x509.h"
#include "fd_der.h"
#include <string.h>

/* OID for algorithm IDs. */

/* Ed25519: 1.3.101.112 */
static uchar const oid_ed25519[] = { 0x06, 0x03, 0x2b, 0x65, 0x70 };

/* ecPublicKey: 1.2.840.10045.2.1 */
static uchar const oid_ec_pubkey[] = { 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };

/* prime256v1 (P-256): 1.2.840.10045.3.1.7 */
static uchar const oid_prime256v1[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };

/* secp384r1 (P-384): 1.3.132.0.34 */
static uchar const oid_secp384r1[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };

/* ecdsa-with-SHA256: 1.2.840.10045.4.3.2 */
static uchar const oid_ecdsa_sha256[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };

/* ecdsa-with-SHA384: 1.2.840.10045.4.3.3 */
static uchar const oid_ecdsa_sha384[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03 };

/* subjectAltName: 2.5.29.17 */
static uchar const oid_san[] = { 0x06, 0x03, 0x55, 0x1d, 0x11 };

/* basicConstraints: 2.5.29.19 */
static uchar const oid_basic_constraints[] = { 0x06, 0x03, 0x55, 0x1d, 0x13 };


static uchar
fd_x509_parse_sig_alg( uchar const * alg, ulong alg_len ) {
  if( fd_der_oid_match( alg, alg_len, oid_ed25519, sizeof(oid_ed25519) ) )
    return FD_X509_SIG_ED25519;
  if( fd_der_oid_match( alg, alg_len, oid_ecdsa_sha256, sizeof(oid_ecdsa_sha256) ) )
    return FD_X509_SIG_ECDSA_SHA256;
  if( fd_der_oid_match( alg, alg_len, oid_ecdsa_sha384, sizeof(oid_ecdsa_sha384) ) )
    return FD_X509_SIG_ECDSA_SHA384;
  return FD_X509_SIG_UNKNOWN;
}

static int
fd_x509_parse_spki( fd_der_cursor_t * c,
                    uchar const **    out_pk,
                    ulong *           out_pk_len,
                    uchar *           out_type ) {

  /* algorithm AlgorithmIdentifier SEQUENCE */
  uchar const * alg_ptr; ulong alg_len;
  FD_DER_READ( *c, FD_DER_TAG_SEQUENCE, alg_ptr, alg_len );

  /* Ed25519? */
  if( alg_len >= sizeof(oid_ed25519) &&
      0 == memcmp( alg_ptr, oid_ed25519, sizeof(oid_ed25519) ) ) {
    uchar const * bits; ulong bits_len;
    FD_DER_READ_BITS( *c, bits, bits_len );
    if( FD_UNLIKELY( bits_len != 32 ) ) return -1;
    *out_pk     = bits;
    *out_pk_len = 32;
    *out_type   = FD_X509_KEY_ED25519;
    return 0;
  }

  /* ECDSA P-256? */
  if( alg_len >= sizeof(oid_ec_pubkey) + sizeof(oid_prime256v1) &&
      0 == memcmp( alg_ptr, oid_ec_pubkey, sizeof(oid_ec_pubkey) ) &&
      0 == memcmp( alg_ptr + sizeof(oid_ec_pubkey), oid_prime256v1, sizeof(oid_prime256v1) ) ) {
    uchar const * bits; ulong bits_len;
    FD_DER_READ_BITS( *c, bits, bits_len );
    if( FD_UNLIKELY( bits_len != 65 || bits[0] != 0x04 ) ) return -1;
    *out_pk     = bits;
    *out_pk_len = 65;
    *out_type   = FD_X509_KEY_ECDSA_P256;
    return 0;
  }

  /* ECDSA P-384? */
  if( alg_len >= sizeof(oid_ec_pubkey) + sizeof(oid_secp384r1) &&
      0 == memcmp( alg_ptr, oid_ec_pubkey, sizeof(oid_ec_pubkey) ) &&
      0 == memcmp( alg_ptr + sizeof(oid_ec_pubkey), oid_secp384r1, sizeof(oid_secp384r1) ) ) {
    uchar const * bits; ulong bits_len;
    FD_DER_READ_BITS( *c, bits, bits_len );
    if( FD_UNLIKELY( bits_len != 97 || bits[0] != 0x04 ) ) return -1;
    *out_pk     = bits;
    *out_pk_len = 97;
    *out_type   = FD_X509_KEY_ECDSA_P384;
    return 0;
  }

  /* TODO: RSA? */

  /* Unknown. */
  return -1;
}

static int
fd_x509_parse_extensions( fd_der_cursor_t *     c,
                          fd_x509_cert_info_t * out ) {

  while( FD_DER_HAS_MORE( *c ) ) {
    /* Each Extension is a SEQUENCE { OID, BOOLEAN?, OCTET STRING } */
    uchar const * ext_ptr; ulong ext_len;
    FD_DER_READ( *c, FD_DER_TAG_SEQUENCE, ext_ptr, ext_len );

    fd_der_cursor_t ext = { .p = ext_ptr, .end = ext_ptr + ext_len };

    uchar const * oid_raw; ulong oid_raw_len;
    FD_DER_READ_RAW( ext, FD_DER_TAG_OID, oid_raw, oid_raw_len );

    FD_DER_SKIP_IF( ext, FD_DER_TAG_BOOLEAN );

    /* OCTET STRING wrapping the extension value */
    uchar const * val_ptr; ulong val_len;
    FD_DER_READ( ext, FD_DER_TAG_OCTET_STRING, val_ptr, val_len );

    /* basicConstraints (2.5.29.19) */
    if( fd_der_oid_match( oid_raw, oid_raw_len,
                          oid_basic_constraints, sizeof(oid_basic_constraints) ) ) {
      /* SEQUENCE { BOOLEAN cA OPTIONAL, INTEGER pathLen OPTIONAL } */
      fd_der_cursor_t val = { .p = val_ptr, .end = val_ptr + val_len };
      uchar const * bc_ptr; ulong bc_len;
      FD_DER_READ( val, FD_DER_TAG_SEQUENCE, bc_ptr, bc_len );
      /* BOOLEAN TRUE = { 0x01, 0x01, 0xFF } */
      if( bc_len >= 3 && bc_ptr[0] == 0x01 && bc_ptr[1] == 0x01 && bc_ptr[2] == 0xFF )
        out->is_ca = 1;
      continue;
    }

    /* subjectAltName (2.5.29.17) */
    if( fd_der_oid_match( oid_raw, oid_raw_len,
                          oid_san, sizeof(oid_san) ) ) {
      fd_der_cursor_t val = { .p = val_ptr, .end = val_ptr + val_len };

      /* SEQUENCE OF GeneralName */
      uchar const * san_ptr; ulong san_len;
      FD_DER_READ( val, FD_DER_TAG_SEQUENCE, san_ptr, san_len );

      fd_der_cursor_t san = { .p = san_ptr, .end = san_ptr + san_len };
      while( FD_DER_HAS_MORE( san ) && out->san_dns_cnt < FD_X509_SAN_DNS_MAX ) {
        int gn_tag; ulong gn_len;
        if( FD_UNLIKELY( fd_der_read_tl( &san, &gn_tag, &gn_len ) ) ) break;

        /* Context tag [2] = dNSName (IA5String, implicit) */
        if( gn_tag == (int)FD_DER_TAG_CONTEXT_PRIM(2) ) {
          out->san_dns[ out->san_dns_cnt ].name     = (char const *)san.p;
          out->san_dns[ out->san_dns_cnt ].name_len = (ushort)gn_len;
          out->san_dns_cnt++;
        }
        san.p += gn_len;
      }
      continue;
    }

    /* Unknwon extension */
  }

  return 0;
}

int
fd_x509_cert_parse( uchar const *         cert,
                    ulong                 cert_sz,
                    fd_x509_cert_info_t * out ) {

  fd_memset( out, 0, sizeof(fd_x509_cert_info_t) );
  out->key_type = FD_X509_KEY_UNKNOWN;
  out->sig_alg  = FD_X509_SIG_UNKNOWN;

  FD_DER_CURSOR_FROM_BUF( c, cert, cert_sz );

  FD_DER_ENTER( c, FD_DER_TAG_SEQUENCE );

    /* tbsCertificate */
    uchar const * tbs_start = c.p;
    uchar const * tbs_ptr; ulong tbs_content_len;
    FD_DER_READ( c, FD_DER_TAG_SEQUENCE, tbs_ptr, tbs_content_len );
    out->tbs     = tbs_start;
    out->tbs_len = (ulong)( c.p - tbs_start );

    {
      fd_der_cursor_t tbs = { .p = tbs_ptr, .end = tbs_ptr + tbs_content_len };

      /* version [0] EXPLICIT */
      FD_DER_SKIP_IF( tbs, FD_DER_TAG_CONTEXT(0) );

      /* serialNumber INTEGER */
      FD_DER_SKIP( tbs );

      /* signature AlgorithmIdentifier SEQUENCE */
      uchar const * alg_ptr; ulong alg_len;
      FD_DER_READ( tbs, FD_DER_TAG_SEQUENCE, alg_ptr, alg_len );
      out->sig_alg = fd_x509_parse_sig_alg( alg_ptr, alg_len );

      /* issuer Name SEQEUENCE */
      FD_DER_READ_RAW( tbs, FD_DER_TAG_SEQUENCE, out->issuer, out->issuer_len );

      /* validity SEQUENCE { notBefore, notAfter } */
      FD_DER_ENTER( tbs, FD_DER_TAG_SEQUENCE );
        FD_DER_READ_TIME( tbs, out->not_before, out->not_before_len );
        FD_DER_READ_TIME( tbs, out->not_after,  out->not_after_len );
      FD_DER_LEAVE( tbs );

      /* subject Name SEQUENCE */
      FD_DER_READ_RAW( tbs, FD_DER_TAG_SEQUENCE, out->subject, out->subject_len );

      /* subjectPublicKeyInfo SEQUENCE */
      FD_DER_ENTER( tbs, FD_DER_TAG_SEQUENCE );
        if( FD_UNLIKELY( fd_x509_parse_spki( &tbs, &out->pubkey,
                                              &out->pubkey_len,
                                              &out->key_type ) ) )
          return -1;
      FD_DER_LEAVE( tbs );

      /* issuerUniqueID [1]
         subjectUniqueID [2]
         extensions [3] */
      while( FD_DER_HAS_MORE( tbs ) ) {
        int next_tag;
        FD_DER_PEEK_TAG( tbs, next_tag );

        if( next_tag == (int)FD_DER_TAG_CONTEXT(3) ) {
          FD_DER_ENTER( tbs, FD_DER_TAG_CONTEXT(3) );
            uchar const * ext_seq_ptr; ulong ext_seq_len;
            FD_DER_READ( tbs, FD_DER_TAG_SEQUENCE, ext_seq_ptr, ext_seq_len );
            fd_der_cursor_t ext = { .p = ext_seq_ptr, .end = ext_seq_ptr + ext_seq_len };
            fd_x509_parse_extensions( &ext, out );
          FD_DER_LEAVE( tbs );
        } else {
          FD_DER_SKIP( tbs );
        }
      }
    }

    /* signatureAlgorithm */
    FD_DER_SKIP( c );

    /* signatureValue BIT STRING */
    FD_DER_READ_BITS( c, out->sig, out->sig_len );

  FD_DER_LEAVE( c );

  return 0;
}

int
fd_x509_extract_pubkey( uchar const *  cert,
                        ulong          cert_sz,
                        uchar const ** out_pubkey,
                        ulong *        out_pubkey_len,
                        uchar *        out_key_type ) {
  fd_x509_cert_info_t info;
  int err = fd_x509_cert_parse( cert, cert_sz, &info );
  if( FD_UNLIKELY( err ) ) return err;
  *out_pubkey     = info.pubkey;
  *out_pubkey_len = info.pubkey_len;
  *out_key_type   = info.key_type;
  return 0;
}

/* Hostname matching (RFC 6125 Section 6.4.3) */

int
fd_x509_san_matches( fd_x509_cert_info_t const * info,
                     char const *                hostname,
                     ulong                       hostname_len ) {

  for( uint i = 0; i < info->san_dns_cnt; i++ ) {
    char const * pattern     = info->san_dns[i].name;
    ulong        pattern_len = info->san_dns[i].name_len;

    /* Exact match (case-insensitive) */
    if( pattern_len == hostname_len ) {
      int match = 1;
      for( ulong j = 0; j < pattern_len; j++ ) {
        char a = pattern[j]; if( a >= 'A' && a <= 'Z' ) a = (char)( a + ('a' - 'A') );
        char b = hostname[j]; if( b >= 'A' && b <= 'Z' ) b = (char)( b + ('a' - 'A') );
        if( a != b ) { match = 0; break; }
      }
      if( match ) return 1;
    }

    /* Wildcard: *.example.com matches foo.example.com */
    if( pattern_len >= 2 && pattern[0] == '*' && pattern[1] == '.' ) {
      char const * pattern_tail     = pattern + 2;
      ulong        pattern_tail_len = pattern_len - 2;

      ulong dot_pos = 0;
      for( ; dot_pos < hostname_len; dot_pos++ ) {
        if( hostname[dot_pos] == '.' ) break;
      }

      if( dot_pos < hostname_len ) {
        char const * host_tail     = hostname + dot_pos + 1;
        ulong        host_tail_len = hostname_len - dot_pos - 1;

        if( host_tail_len == pattern_tail_len ) {
          int match = 1;
          for( ulong j = 0; j < pattern_tail_len; j++ ) {
            char a = pattern_tail[j]; if( a >= 'A' && a <= 'Z' ) a = (char)( a + ('a' - 'A') );
            char b = host_tail[j];    if( b >= 'A' && b <= 'Z' ) b = (char)( b + ('a' - 'A') );
            if( a != b ) { match = 0; break; }
          }
          if( match ) return 1;
        }
      }
    }
  }

  return 0;
}

int
fd_x509_decode_ecdsa_sig( uchar const * der,
                          ulong         der_len,
                          uchar *       raw_sig,
                          ulong         scalar_sz ) {

  FD_DER_CURSOR_FROM_BUF( c, der, der_len );

  uchar const * r_ptr; ulong r_len;
  uchar const * s_ptr; ulong s_len;

  FD_DER_ENTER( c, FD_DER_TAG_SEQUENCE );
    FD_DER_READ( c, FD_DER_TAG_INTEGER, r_ptr, r_len );
    FD_DER_READ( c, FD_DER_TAG_INTEGER, s_ptr, s_len );
  FD_DER_LEAVE_RELAXED( c );

  if( FD_UNLIKELY( fd_der_int_to_fixed( r_ptr, r_len, raw_sig,             scalar_sz ) ) ) return -1;
  if( FD_UNLIKELY( fd_der_int_to_fixed( s_ptr, s_len, raw_sig + scalar_sz, scalar_sz ) ) ) return -1;

  return 0;
}

int
fd_x509_ec_point_compress( uchar const * uncompressed,
                           ulong         coord_sz,
                           uchar *       compressed ) {
  if( FD_UNLIKELY( uncompressed[0] != 0x04 ) ) return -1;

  compressed[0] = (uchar)( 0x02 | ( uncompressed[ 2*coord_sz ] & 0x01 ) );
  fd_memcpy( compressed + 1, uncompressed + 1, coord_sz );
  return 0;
}
