#include "fd_x509.h"
#include "fd_der.h"
#include "../../util/net/fd_ip4.h"
#include "../secp256r1/fd_secp256r1.h"
#include "../secp384r1/fd_secp384r1.h"
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

/* OID 2.5.29.15 (keyUsage) */
static uchar const oid_key_usage[] = { 0x06, 0x03, 0x55, 0x1d, 0x0f };

/* OID 2.5.29.37 (extKeyUsage) */
static uchar const oid_ext_key_usage[] = { 0x06, 0x03, 0x55, 0x1d, 0x25 };

/* OID 1.3.6.1.5.5.7.3.1 (id-kp-serverAuth) */
static uchar const oid_kp_server_auth[] = { 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };

/* OID 2.5.29.37.0 (anyExtendedKeyUsage) */
static uchar const oid_kp_any[] = { 0x06, 0x04, 0x55, 0x1d, 0x25, 0x00 };


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
  if( alg_len == sizeof(oid_ed25519) &&
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
  if( alg_len == sizeof(oid_ec_pubkey) + sizeof(oid_prime256v1) &&
      0 == memcmp( alg_ptr, oid_ec_pubkey, sizeof(oid_ec_pubkey) ) &&
      0 == memcmp( alg_ptr + sizeof(oid_ec_pubkey), oid_prime256v1, sizeof(oid_prime256v1) ) ) {
    uchar const * bits; ulong bits_len;
    FD_DER_READ_BITS( *c, bits, bits_len );
    if( FD_UNLIKELY( bits_len != 65 ) ) return -1;
    uchar compressed[ 33 ];
    if( FD_UNLIKELY( fd_secp256r1_public_key_compress( compressed, bits )
                     !=FD_SECP256R1_SUCCESS ) ) return -1;
    *out_pk     = bits;
    *out_pk_len = 65;
    *out_type   = FD_X509_KEY_ECDSA_P256;
    return 0;
  }

  /* ECDSA P-384? */
  if( alg_len == sizeof(oid_ec_pubkey) + sizeof(oid_secp384r1) &&
      0 == memcmp( alg_ptr, oid_ec_pubkey, sizeof(oid_ec_pubkey) ) &&
      0 == memcmp( alg_ptr + sizeof(oid_ec_pubkey), oid_secp384r1, sizeof(oid_secp384r1) ) ) {
    uchar const * bits; ulong bits_len;
    FD_DER_READ_BITS( *c, bits, bits_len );
    if( FD_UNLIKELY( bits_len != 97 ) ) return -1;
    uchar compressed[ 49 ];
    if( FD_UNLIKELY( fd_secp384r1_public_key_compress( compressed, bits )
                     !=FD_SECP384R1_SUCCESS ) ) return -1;
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
fd_x509_parse_path_len( uchar const * p,
                        ulong         len,
                        ulong *       out ) {
  /* INTEGER is signed.  pathLenConstraint is non-negative, and DER
     requires the shortest possible two's-complement encoding. */
  if( FD_UNLIKELY( !len || (p[0] & 0x80U) ) ) return -1;
  if( FD_UNLIKELY( len>1UL && p[0]==0x00 && !(p[1] & 0x80U) ) ) return -1;

  /* Values larger than ulong are valid ASN.1 (MAX is unbounded).  Such a
     value cannot constrain a path capped at FD_X509_CHAIN_MAX, so saturate
     it instead of rejecting an otherwise valid certificate. */
  ulong path_len = 0UL;
  for( ulong i=0UL; i<len; i++ ) {
    if( FD_UNLIKELY( path_len>(~0UL >> 8) ) ) {
      path_len = ~0UL;
      break;
    }
    path_len = (path_len << 8) | (ulong)p[i];
  }
  *out = path_len;
  return 0;
}

static int
fd_x509_serial_valid( uchar const * p,
                      ulong         len ) {
  /* RFC 5280 requires a positive serial number no longer than 20 octets.
     DER INTEGERs are signed and minimally encoded. */
  if( FD_UNLIKELY( !len || len>20UL || (p[0] & 0x80U) ) ) return 0;
  if( p[0]==0x00 ) {
    if( FD_UNLIKELY( len==1UL || !(p[1] & 0x80U) ) ) return 0;
  }
  return 1;
}

static int
fd_x509_unique_id_valid( uchar const * p,
                         ulong         len ) {
  /* UniqueIdentifier is an IMPLICIT BIT STRING. */
  if( FD_UNLIKELY( !len || p[0]>7U ) ) return 0;
  if( len==1UL ) return p[0]==0U;
  return !( p[len-1UL] & (uchar)( (1U<<p[0])-1U ) );
}

static int
fd_x509_general_name_valid( int           tag,
                            uchar const * p,
                            ulong         len ) {
  switch( tag ) {
  case FD_DER_TAG_CONTEXT(0): /* otherName */
  case FD_DER_TAG_CONTEXT(3): /* x400Address */
  case FD_DER_TAG_CONTEXT(4): /* directoryName */
  case FD_DER_TAG_CONTEXT(5): /* ediPartyName */
    /* not worth validating, we don't look at these */
    return !!len;
  case FD_DER_TAG_CONTEXT_PRIM(1): /* rfc822Name */
  case FD_DER_TAG_CONTEXT_PRIM(2): /* dNSName */
  case FD_DER_TAG_CONTEXT_PRIM(6): /* uniformResourceIdentifier */
    for( ulong i=0UL; i<len; i++ )
      if( FD_UNLIKELY( p[i] & 0x80U ) ) return 0;
    return 1;
  case FD_DER_TAG_CONTEXT_PRIM(7): /* iPAddress */
    return len==4UL || len==16UL;
  case FD_DER_TAG_CONTEXT_PRIM(8): /* registeredID */
    return fd_der_oid_valid( p, len );
  default:
    return 0;
  }
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

    int critical = 0;
    if( ext.p<ext.end && *ext.p==FD_DER_TAG_BOOLEAN ) {
      uchar const * critical_ptr; ulong critical_len;
      FD_DER_READ( ext, FD_DER_TAG_BOOLEAN, critical_ptr, critical_len );
      /* critical is DEFAULT FALSE, so DER permits only explicit TRUE. */
      if( FD_UNLIKELY( critical_len!=1UL || critical_ptr[0]!=0xFF ) ) return -1;
      critical = 1;
    }

    /* OCTET STRING wrapping the extension value */
    uchar const * val_ptr; ulong val_len;
    FD_DER_READ( ext, FD_DER_TAG_OCTET_STRING, val_ptr, val_len );
    if( FD_UNLIKELY( FD_DER_HAS_MORE( ext ) ) ) return -1;

    /* basicConstraints (2.5.29.19)
         BasicConstraints ::= SEQUENCE {
           cA                BOOLEAN DEFAULT FALSE,
           pathLenConstraint INTEGER (0..MAX) OPTIONAL } */
    if( fd_der_oid_match( oid_raw, oid_raw_len,
                          oid_basic_constraints, sizeof(oid_basic_constraints) ) ) {
      /* RFC 5280 Section 4.2 permits at most one instance of an extension. */
      if( FD_UNLIKELY( out->has_basic_constraints ) ) return -1;

      fd_der_cursor_t val = { .p = val_ptr, .end = val_ptr + val_len };
      FD_DER_ENTER( val, FD_DER_TAG_SEQUENCE );
        int bc_tag; FD_DER_PEEK_TAG_OR( val, bc_tag, 0 );
        if( bc_tag == (int)FD_DER_TAG_BOOLEAN ) {
          uchar const * ca_ptr; ulong ca_len;
          FD_DER_READ( val, FD_DER_TAG_BOOLEAN, ca_ptr, ca_len );
          /* cA is DEFAULT FALSE, so DER permits only explicit TRUE. */
          if( FD_UNLIKELY( ca_len!=1UL || ca_ptr[0]!=0xFF ) ) return -1;
          if( FD_UNLIKELY( !critical ) ) return -1;
          out->is_ca = 1;
        }
        int path_len_tag; FD_DER_PEEK_TAG_OR( val, path_len_tag, 0 );
        if( path_len_tag == (int)FD_DER_TAG_INTEGER ) {
          if( FD_UNLIKELY( !out->is_ca ) ) return -1;
          uchar const * path_len_ptr; ulong path_len_len;
          FD_DER_READ( val, FD_DER_TAG_INTEGER, path_len_ptr, path_len_len );
          if( FD_UNLIKELY( fd_x509_parse_path_len( path_len_ptr, path_len_len,
                                                   &out->path_len_constraint ) ) ) return -1;
          out->has_path_len_constraint = 1;
        }
      FD_DER_LEAVE( val );  /* rejects unconsumed SEQUENCE content */
      /* Reject trailing bytes in the extension's OCTET STRING */
      if( FD_UNLIKELY( FD_DER_HAS_MORE( val ) ) ) return -1;
      out->has_basic_constraints = 1;
      continue;
    }

    /* keyUsage (2.5.29.15)
         KeyUsage ::= BIT STRING { digitalSignature(0) ... decipherOnly(8) } */
    if( fd_der_oid_match( oid_raw, oid_raw_len,
                          oid_key_usage, sizeof(oid_key_usage) ) ) {
      /* RFC 5280 Section 4.2 permits at most one instance of an extension */
      if( FD_UNLIKELY( out->has_key_usage ) ) return -1;

      fd_der_cursor_t val = { .p = val_ptr, .end = val_ptr + val_len };
      uchar const * bs; ulong bs_len;
      FD_DER_READ( val, FD_DER_TAG_BIT_STRING, bs, bs_len );
      /* Reject trailing bytes in the extension's OCTET STRING */
      if( FD_UNLIKELY( FD_DER_HAS_MORE( val ) ) ) return -1;

      /* Content is unused_bits || bits.  A 9 bit NamedBitList needs at
         most two octets of bits. */
      if( FD_UNLIKELY( bs_len<2UL || bs_len>3UL ) ) return -1;
      uint unused = bs[0];
      if( FD_UNLIKELY( unused>7U ) ) return -1;

      /* DER zeroes the unused bits and trims trailing zero bits, so the
         final octet has no unused bits set and is itself nonzero */
      uchar last = bs[ bs_len-1UL ];
      if( FD_UNLIKELY( last & (uchar)( ( 1U<<unused ) - 1U ) ) ) return -1;
      if( FD_UNLIKELY( !last ) ) return -1;
      uint canonical_unused = 0U;
      while( !(last & (uchar)(1U<<canonical_unused)) ) canonical_unused++;
      if( FD_UNLIKELY( unused!=canonical_unused ) ) return -1;
      out->key_usage = (ushort)( ( (uint)bs[1] << 8 ) |
                                 ( bs_len>2UL ? (uint)bs[2] : 0U ) );
      out->has_key_usage = 1;
      continue;
    }

    /* extKeyUsage (2.5.29.37)
         ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId */
    if( fd_der_oid_match( oid_raw, oid_raw_len,
                          oid_ext_key_usage, sizeof(oid_ext_key_usage) ) ) {
      if( FD_UNLIKELY( out->has_ext_key_usage ) ) return -1;

      fd_der_cursor_t val = { .p = val_ptr, .end = val_ptr + val_len };
      ulong kp_cnt = 0UL;
      FD_DER_ENTER( val, FD_DER_TAG_SEQUENCE );
        while( FD_DER_HAS_MORE( val ) ) {
          uchar const * kp; ulong kp_len;
          FD_DER_READ_RAW( val, FD_DER_TAG_OID, kp, kp_len );
          kp_cnt++;
          if(      fd_der_oid_match( kp, kp_len, oid_kp_server_auth, sizeof(oid_kp_server_auth) ) )
            out->ext_key_usage = (ushort)( out->ext_key_usage | FD_X509_EKU_SERVER_AUTH );
          else if( fd_der_oid_match( kp, kp_len, oid_kp_any, sizeof(oid_kp_any) ) )
            out->ext_key_usage = (ushort)( out->ext_key_usage | FD_X509_EKU_ANY );
          /* Other key purposes are ignored */
        }
      FD_DER_LEAVE( val );
      if( FD_UNLIKELY( !kp_cnt ) ) return -1;  /* SIZE (1..MAX) */
      if( FD_UNLIKELY( FD_DER_HAS_MORE( val ) ) ) return -1;
      out->has_ext_key_usage = 1;
      continue;
    }

    /* subjectAltName (2.5.29.17) */
    if( fd_der_oid_match( oid_raw, oid_raw_len,
                          oid_san, sizeof(oid_san) ) ) {
      if( FD_UNLIKELY( out->has_subject_alt_name ) ) return -1;
      if( FD_UNLIKELY( out->subject_len==2UL && !critical ) ) return -1;

      fd_der_cursor_t val = { .p = val_ptr, .end = val_ptr + val_len };

      /* SEQUENCE OF GeneralName */
      uchar const * san_ptr; ulong san_len;
      FD_DER_READ( val, FD_DER_TAG_SEQUENCE, san_ptr, san_len );
      if( FD_UNLIKELY( !san_len ) ) return -1;  /* SIZE (1..MAX) */
      if( FD_UNLIKELY( FD_DER_HAS_MORE( val ) ) ) return -1;

      out->san_general_names     = san_ptr;
      out->san_general_names_len = san_len;
      out->has_subject_alt_name  = 1;

      fd_der_cursor_t san = { .p = san_ptr, .end = san_ptr + san_len };
      while( FD_DER_HAS_MORE( san ) ) {
        int gn_tag; ulong gn_len;
        if( FD_UNLIKELY( fd_der_read_tl( &san, &gn_tag, &gn_len ) ) ) return -1;
        if( FD_UNLIKELY( !fd_x509_general_name_valid( gn_tag, san.p, gn_len ) ) )
          return -1;
        san.p += gn_len;
      }
      continue;
    }

    /* Unknown extension */
    if( FD_UNLIKELY( critical ) ) return -1;
  }

  return 0;
}

/* dec2 reads a two digit decimal number, or -1 if either character is
   not an ASCII digit. */

static int
dec2( uchar const * s ) {
  if( FD_UNLIKELY( s[0]<'0' || s[0]>'9' || s[1]<'0' || s[1]>'9' ) ) return -1;
  return (s[0]-'0')*10 + (s[1]-'0');
}

/* days_from_civil returns the number of days between 1970-01-01 and
   y-m-d (proleptic Gregorian).  Howard Hinnant's algorithm, valid for
   any year representable in a long. */

static long
days_from_civil( long y,
                 long m,
                 long d ) {
  y -= m<=2;
  long era = (y>=0 ? y : y-399) / 400;
  long yoe = y - era*400;                                     /* [0, 399] */
  long doy = (153*(m + (m>2 ? -3 : 9)) + 2)/5 + d-1;          /* [0, 365] */
  long doe = yoe*365 + yoe/4 - yoe/100 + doy;                 /* [0, 146096] */
  return era*146097L + doe - 719468L;
}

long
fd_x509_time_parse( uchar         tag,
                    uchar const * s,
                    ulong         s_len ) {
  long year;

  if( tag==FD_DER_TAG_UTC_TIME ) {
    if( FD_UNLIKELY( s_len!=13UL ) ) return FD_X509_TIME_INVALID;
    int yy = dec2( s );
    if( FD_UNLIKELY( yy<0 ) ) return FD_X509_TIME_INVALID;
    /* RFC 5280 Section 4.1.2.5.1 */
    year = yy>=50 ? 1900L+yy : 2000L+yy;
    s += 2;
  } else if( tag==FD_DER_TAG_GENERALIZED_TIME ) {
    if( FD_UNLIKELY( s_len!=15UL ) ) return FD_X509_TIME_INVALID;
    int hi = dec2( s );
    int lo = dec2( s+2 );
    if( FD_UNLIKELY( hi<0 || lo<0 ) ) return FD_X509_TIME_INVALID;
    year = hi*100L + lo;
    s += 4;
  } else {
    return FD_X509_TIME_INVALID;
  }

  int mon = dec2( s   );
  int day = dec2( s+2 );
  int hh  = dec2( s+4 );
  int mm  = dec2( s+6 );
  int ss  = dec2( s+8 );
  if( FD_UNLIKELY( mon<0 || day<0 || hh<0 || mm<0 || ss<0 ) ) return FD_X509_TIME_INVALID;
  if( FD_UNLIKELY( s[10]!='Z' ) ) return FD_X509_TIME_INVALID;

  if( FD_UNLIKELY( mon<1 || mon>12 ) ) return FD_X509_TIME_INVALID;

  static uchar const mon_days[ 12 ] = { 31,28,31,30,31,30,31,31,30,31,30,31 };
  int leap = ( !(year%4) && (year%100) ) || !(year%400);
  int day_max = mon_days[ mon-1 ] + ( mon==2 && leap );
  if( FD_UNLIKELY( day<1 || day>day_max ) ) return FD_X509_TIME_INVALID;

  /* Leap seconds (ss==60) are rejected: RFC 5280 does not require them */
  if( FD_UNLIKELY( hh>23 || mm>59 || ss>59 ) ) return FD_X509_TIME_INVALID;

  return days_from_civil( year, mon, day )*86400L + hh*3600L + mm*60L + ss;
}

int
fd_x509_cert_parse( uchar const *         cert,
                    ulong                 cert_sz,
                    fd_x509_cert_info_t * out ) {

  if( FD_UNLIKELY( !cert || !out ) ) return -1;

  fd_memset( out, 0, sizeof(fd_x509_cert_info_t) );
  out->key_type = FD_X509_KEY_UNKNOWN;
  out->sig_alg  = FD_X509_SIG_UNKNOWN;

  uchar const * tbs_sig_alg     = NULL;
  ulong         tbs_sig_alg_len = 0UL;

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

      /* version [0] EXPLICIT Version DEFAULT v1 */
      if( FD_DER_HAS_MORE( tbs ) && *tbs.p==FD_DER_TAG_CONTEXT(0) ) {
        FD_DER_ENTER( tbs, FD_DER_TAG_CONTEXT(0) );
          uchar const * version; ulong version_len;
          FD_DER_READ( tbs, FD_DER_TAG_INTEGER, version, version_len );
          /* Explicit v1 violates DEFAULT encoding.  Only v1/v2/v3 exist. */
          if( FD_UNLIKELY( version_len!=1UL || version[0]<1U || version[0]>2U ) ) return -1;
          out->version = version[0];
        FD_DER_LEAVE( tbs );
      }

      /* serialNumber CertificateSerialNumber */
      uchar const * serial; ulong serial_len;
      FD_DER_READ( tbs, FD_DER_TAG_INTEGER, serial, serial_len );
      if( FD_UNLIKELY( !fd_x509_serial_valid( serial, serial_len ) ) ) return -1;

      /* signature AlgorithmIdentifier SEQUENCE */
      FD_DER_READ( tbs, FD_DER_TAG_SEQUENCE, tbs_sig_alg, tbs_sig_alg_len );
      out->sig_alg = fd_x509_parse_sig_alg( tbs_sig_alg, tbs_sig_alg_len );

      /* issuer Name SEQUENCE */
      FD_DER_READ_RAW( tbs, FD_DER_TAG_SEQUENCE, out->issuer, out->issuer_len );

      /* validity SEQUENCE { notBefore, notAfter } */
      FD_DER_ENTER( tbs, FD_DER_TAG_SEQUENCE );
        FD_DER_READ_TIME( tbs, out->not_before_tag, out->not_before, out->not_before_len );
        FD_DER_READ_TIME( tbs, out->not_after_tag,  out->not_after,  out->not_after_len  );
        out->not_before_unix = fd_x509_time_parse( out->not_before_tag, out->not_before, out->not_before_len );
        out->not_after_unix  = fd_x509_time_parse( out->not_after_tag,  out->not_after,  out->not_after_len  );
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
      int last_optional = 0;
      while( FD_DER_HAS_MORE( tbs ) ) {
        int next_tag;
        FD_DER_PEEK_TAG( tbs, next_tag );

        if( next_tag==(int)FD_DER_TAG_CONTEXT_PRIM(1) ||
            next_tag==(int)FD_DER_TAG_CONTEXT_PRIM(2) ) {
          int field = next_tag & 7;
          if( FD_UNLIKELY( out->version<1U || field<=last_optional ) ) return -1;
          int tag; ulong unique_id_len;
          if( FD_UNLIKELY( fd_der_read_tl( &tbs, &tag, &unique_id_len ) ) ) return -1;
          if( FD_UNLIKELY( !fd_x509_unique_id_valid( tbs.p, unique_id_len ) ) ) return -1;
          tbs.p += unique_id_len;
          last_optional = field;
        } else if( next_tag == (int)FD_DER_TAG_CONTEXT(3) ) {
          if( FD_UNLIKELY( out->version!=2U || last_optional>=3 ) ) return -1;
          last_optional = 3;
          FD_DER_ENTER( tbs, FD_DER_TAG_CONTEXT(3) );
            uchar const * ext_seq_ptr; ulong ext_seq_len;
            FD_DER_READ( tbs, FD_DER_TAG_SEQUENCE, ext_seq_ptr, ext_seq_len );
            if( FD_UNLIKELY( !ext_seq_len ) ) return -1;
            fd_der_cursor_t ext = { .p = ext_seq_ptr, .end = ext_seq_ptr + ext_seq_len };
            if( FD_UNLIKELY( fd_x509_parse_extensions( &ext, out ) ) ) return -1;
          FD_DER_LEAVE( tbs );
        } else {
          return -1;
        }
      }

      if( FD_UNLIKELY( out->subject_len==2UL && !out->has_subject_alt_name ) ) return -1;
    }

    /* signatureAlgorithm must match the TBSCertificate field exactly. */
    uchar const * outer_sig_alg; ulong outer_sig_alg_len;
    FD_DER_READ( c, FD_DER_TAG_SEQUENCE, outer_sig_alg, outer_sig_alg_len );
    if( FD_UNLIKELY( outer_sig_alg_len!=tbs_sig_alg_len ||
                     memcmp( outer_sig_alg, tbs_sig_alg, tbs_sig_alg_len ) ) ) return -1;

    /* signatureValue BIT STRING */
    FD_DER_READ_BITS( c, out->sig, out->sig_len );

  FD_DER_LEAVE( c );

  /* The supplied buffer is one DER Certificate, not a DER prefix. */
  if( FD_UNLIKELY( FD_DER_HAS_MORE( c ) ) ) return -1;

  return 0;
}

/* Distinguished-name matching **********************************************/

typedef struct {
  uchar const * p;
  ulong         len;
} fd_x509_der_slice_t;

static int
fd_x509_der_read( fd_der_cursor_t * c,
                  int               expected_tag,
                  uchar const **    content,
                  ulong *           content_len ) {
  int tag;
  if( FD_UNLIKELY( fd_der_read_tl( c, &tag, content_len ) || tag!=expected_tag ) ) return -1;
  *content = c->p;
  c->p += *content_len;
  return 0;
}

static int
fd_x509_dn_string_tag( int tag ) {
  return tag==(int)FD_DER_TAG_UTF8_STRING ||
         tag==(int)FD_DER_TAG_PRINTABLE_STR ||
         tag==(int)FD_DER_TAG_TELETEX_STRING ||
         tag==(int)FD_DER_TAG_UNIVERSAL_STRING ||
         tag==(int)FD_DER_TAG_BMP_STRING;
}

static int
fd_x509_dn_case_ignore_oid( uchar const * oid,
                            ulong         oid_len ) {
  if( oid_len==3UL && oid[0]==0x55U && oid[1]==0x04U ) { /* 2.5.4 */
    switch( oid[2] ) {
    case  3U: /* commonName */
    case  4U: /* surname */
    case  5U: /* serialNumber */
    case  6U: /* countryName */
    case  7U: /* localityName */
    case  8U: /* stateOrProvinceName */
    case  9U: /* streetAddress */
    case 10U: /* organizationName */
    case 11U: /* organizationalUnitName */
    case 12U: /* title */
    case 13U: /* description */
    case 15U: /* businessCategory */
    case 17U: /* postalCode */
    case 18U: /* postOfficeBox */
    case 19U: /* physicalDeliveryOfficeName */
    case 27U: /* destinationIndicator */
    case 41U: /* name */
    case 42U: /* givenName */
    case 43U: /* initials */
    case 44U: /* generationQualifier */
    case 46U: /* dnQualifier */
    case 51U: /* houseIdentifier */
    case 54U: /* dmdName */
    case 65U: /* pseudonym */
    case 72U: /* role */
    case 97U: /* organizationIdentifier */
      return 1;
    default:
      return 0;
    }
  }

  /* userId, 0.9.2342.19200300.100.1.1 */
  static uchar const oid_user_id[] = { 0x09,0x92,0x26,0x89,0x93,0xf2,0x2c,0x64,0x01,0x01 };
  return oid_len==sizeof(oid_user_id) && !memcmp( oid, oid_user_id, sizeof(oid_user_id) );
}

#define FD_X509_DN_VALUE_MAX (512UL)

/* Normalize the ASCII subset of DirectoryString values: fold case, trim
   leading/trailing spaces, and collapse internal runs of spaces. */

static int
fd_x509_dn_string_normalize( int           tag,
                             uchar const * p,
                             ulong         len,
                             uchar *       out,
                             ulong *       out_len ) {
  ulong width = tag==(int)FD_DER_TAG_BMP_STRING       ? 2UL :
                tag==(int)FD_DER_TAG_UNIVERSAL_STRING ? 4UL : 1UL;
  if( FD_UNLIKELY( len%width ) ) return -1;
  if( FD_UNLIKELY( len/width>FD_X509_DN_VALUE_MAX ) ) return -1;

  ulong j = 0UL;
  int pending_space = 0;
  for( ulong i=0UL; i<len; i+=width ) {
    uint c = 0U;
    for( ulong k=0UL; k<width; k++ ) c = (c<<8) | (uint)p[i+k];
    if( FD_UNLIKELY( c>0x7fU ) ) return -1;
    if( c==' ' ) {
      if( j ) pending_space = 1;
      continue;
    }
    if( FD_UNLIKELY( j+(ulong)pending_space>=FD_X509_DN_VALUE_MAX ) ) return -1;
    if( pending_space ) out[j++] = ' ';
    pending_space = 0;
    if( c>='A' && c<='Z' ) c += (uint)('a'-'A');
    out[j++] = (uchar)c;
  }
  *out_len = j;
  return 0;
}

static int
fd_x509_atv_equal( fd_x509_der_slice_t a,
                   fd_x509_der_slice_t b ) {
  fd_der_cursor_t ac = { .p=a.p, .end=a.p+a.len };
  fd_der_cursor_t bc = { .p=b.p, .end=b.p+b.len };

  uchar const * aoid; ulong aoid_len;
  uchar const * boid; ulong boid_len;
  if( FD_UNLIKELY( fd_x509_der_read( &ac, FD_DER_TAG_OID, &aoid, &aoid_len ) ||
                   fd_x509_der_read( &bc, FD_DER_TAG_OID, &boid, &boid_len ) ) ) return 0;
  if( aoid_len!=boid_len || memcmp( aoid, boid, aoid_len ) ) return 0;

  int atag; ulong aval_len;
  int btag; ulong bval_len;
  if( FD_UNLIKELY( fd_der_read_tl( &ac, &atag, &aval_len ) ||
                   fd_der_read_tl( &bc, &btag, &bval_len ) ) ) return 0;
  uchar const * aval = ac.p; ac.p += aval_len;
  uchar const * bval = bc.p; bc.p += bval_len;
  if( FD_UNLIKELY( ac.p!=ac.end || bc.p!=bc.end ) ) return 0;

  if( fd_x509_dn_case_ignore_oid( aoid, aoid_len ) &&
      fd_x509_dn_string_tag( atag ) && fd_x509_dn_string_tag( btag ) ) {
    uchar anorm[ FD_X509_DN_VALUE_MAX ]; ulong anorm_len;
    uchar bnorm[ FD_X509_DN_VALUE_MAX ]; ulong bnorm_len;
    if( !fd_x509_dn_string_normalize( atag, aval, aval_len, anorm, &anorm_len ) &&
        !fd_x509_dn_string_normalize( btag, bval, bval_len, bnorm, &bnorm_len ) )
      return anorm_len==bnorm_len && !memcmp( anorm, bnorm, anorm_len );
  }

  return atag==btag && aval_len==bval_len && !memcmp( aval, bval, aval_len );
}

#define FD_X509_RDN_ATV_MAX (16UL)

static int
fd_x509_rdn_equal( uchar const * a,
                   ulong         a_len,
                   uchar const * b,
                   ulong         b_len ) {
  fd_x509_der_slice_t aa[ FD_X509_RDN_ATV_MAX ]; ulong aa_cnt = 0UL;
  fd_x509_der_slice_t ba[ FD_X509_RDN_ATV_MAX ]; ulong ba_cnt = 0UL;
  fd_der_cursor_t ac = { .p=a, .end=a+a_len };
  fd_der_cursor_t bc = { .p=b, .end=b+b_len };

  while( FD_DER_HAS_MORE( ac ) ) {
    if( FD_UNLIKELY( aa_cnt==FD_X509_RDN_ATV_MAX ||
                     fd_x509_der_read( &ac, FD_DER_TAG_SEQUENCE,
                                       &aa[aa_cnt].p, &aa[aa_cnt].len ) ) ) return 0;
    aa_cnt++;
  }
  while( FD_DER_HAS_MORE( bc ) ) {
    if( FD_UNLIKELY( ba_cnt==FD_X509_RDN_ATV_MAX ||
                     fd_x509_der_read( &bc, FD_DER_TAG_SEQUENCE,
                                       &ba[ba_cnt].p, &ba[ba_cnt].len ) ) ) return 0;
    ba_cnt++;
  }
  if( aa_cnt!=ba_cnt ) return 0;

  uchar matched[ FD_X509_RDN_ATV_MAX ] = {0};
  for( ulong i=0UL; i<aa_cnt; i++ ) {
    ulong j=0UL;
    for( ; j<ba_cnt; j++ )
      if( !matched[j] && fd_x509_atv_equal( aa[i], ba[j] ) ) break;
    if( j==ba_cnt ) return 0;
    matched[j] = 1U;
  }
  return 1;
}

int
fd_x509_name_equal( uchar const * a,
                    ulong         a_len,
                    uchar const * b,
                    ulong         b_len ) {
  if( FD_UNLIKELY( (!a && a_len) || (!b && b_len) ) ) return 0;

  FD_DER_CURSOR_FROM_BUF( ac, a, a_len );
  FD_DER_CURSOR_FROM_BUF( bc, b, b_len );
  uchar const * ap; ulong alen;
  uchar const * bp; ulong blen;
  if( FD_UNLIKELY( fd_x509_der_read( &ac, FD_DER_TAG_SEQUENCE, &ap, &alen ) || ac.p!=ac.end ||
                   fd_x509_der_read( &bc, FD_DER_TAG_SEQUENCE, &bp, &blen ) || bc.p!=bc.end ) ) return 0;

  if( a_len==b_len && !memcmp( a, b, a_len ) ) return 1;

  ac.p=ap; ac.end=ap+alen;
  bc.p=bp; bc.end=bp+blen;
  while( FD_DER_HAS_MORE( ac ) && FD_DER_HAS_MORE( bc ) ) {
    uchar const * ardn; ulong ardn_len;
    uchar const * brdn; ulong brdn_len;
    if( FD_UNLIKELY( fd_x509_der_read( &ac, FD_DER_TAG_SET, &ardn, &ardn_len ) ||
                     fd_x509_der_read( &bc, FD_DER_TAG_SET, &brdn, &brdn_len ) ||
                     !fd_x509_rdn_equal( ardn, ardn_len, brdn, brdn_len ) ) ) return 0;
  }
  return ac.p==ac.end && bc.p==bc.end;
}

int
fd_x509_extract_pubkey( uchar const *  cert,
                        ulong          cert_sz,
                        uchar const ** out_pubkey,
                        ulong *        out_pubkey_len,
                        uchar *        out_key_type ) {
  if( FD_UNLIKELY( !cert || !out_pubkey || !out_pubkey_len || !out_key_type ) ) return -1;
  fd_x509_cert_info_t info;
  int err = fd_x509_cert_parse( cert, cert_sz, &info );
  if( FD_UNLIKELY( err ) ) return err;
  *out_pubkey     = info.pubkey;
  *out_pubkey_len = info.pubkey_len;
  *out_key_type   = info.key_type;
  return 0;
}

/* Hostname matching (RFC 6125 Section 6.4.3) */

/* dns_eq_ci compares two DNS names of equal length, folding ASCII case. */

static int
dns_eq_ci( char const * a,
           char const * b,
           ulong        len ) {
  for( ulong i=0UL; i<len; i++ ) {
    char x = a[i]; if( x>='A' && x<='Z' ) x = (char)( x + ('a'-'A') );
    char y = b[i]; if( y>='A' && y<='Z' ) y = (char)( y + ('a'-'A') );
    if( x!=y ) return 0;
  }
  return 1;
}

/* dns_name_valid returns 1 if [name,name+len) is a syntactically valid
   DNS hostname (RFC 1123 preferred syntax, plus '_').  Rejects empty
   labels, so a leading dot, a trailing dot, and ".." are all invalid. */

static int
dns_name_valid( char const * name,
                ulong        len ) {
  if( len<1UL || len>253UL ) return 0;

  ulong label_len = 0UL;
  for( ulong i=0UL; i<len; i++ ) {
    uchar c = (uchar)name[i];

    if( c=='.' ) {
      if( label_len<1UL || label_len>63UL ) return 0;
      if( name[i-1UL]=='-' ) return 0;
      label_len = 0UL;
      continue;
    }

    int alnum = ( c>='a' && c<='z' ) || ( c>='A' && c<='Z' ) || ( c>='0' && c<='9' );
    if( !( alnum || c=='-' || c=='_' ) ) return 0;
    if( c=='-' && label_len==0UL ) return 0;
    label_len++;
  }

  if( label_len<1UL || label_len>63UL ) return 0;
  if( name[len-1UL]=='-' ) return 0;

  return 1;
}

static int
dns_pattern_matches( char const * pattern,
                     ulong        pattern_len,
                     char const * hostname,
                     ulong        hostname_len ) {

  /* Wildcard: *.example.com matches foo.example.com.  The wildcard is
     only recognized as the whole leftmost label, and the remainder
     must span at least two labels, so *.com matches nothing. */

  if( pattern_len>=2UL && pattern[0]=='*' && pattern[1]=='.' ) {
    char const * pattern_tail     = pattern + 2;
    ulong        pattern_tail_len = pattern_len - 2UL;

    if( !dns_name_valid( pattern_tail, pattern_tail_len ) ) return 0;
    if( !memchr( pattern_tail, '.', pattern_tail_len ) ) return 0;

    ulong dot_pos = 0UL;
    for( ; dot_pos<hostname_len; dot_pos++ ) {
      if( hostname[dot_pos]=='.' ) break;
    }

    /* The wildcard must consume a non-empty label. */

    if( dot_pos==0UL || dot_pos>=hostname_len ) return 0;

    char const * host_tail     = hostname + dot_pos + 1UL;
    ulong        host_tail_len = hostname_len - dot_pos - 1UL;

    return host_tail_len==pattern_tail_len &&
           dns_eq_ci( pattern_tail, host_tail, pattern_tail_len );
  }

  /* Exact match (case-insensitive) */

  return pattern_len==hostname_len &&
         dns_name_valid( pattern, pattern_len ) &&
         dns_eq_ci( pattern, hostname, pattern_len );
}

int
fd_x509_san_matches( fd_x509_cert_info_t const * info,
                     char const *                hostname,
                     ulong                       hostname_len ) {

  if( FD_UNLIKELY( !info || !hostname ) ) return 0;

  /* Treat an absolute DNS reference name as equivalent to its relative
     spelling.  The root label is not part of the dNSName SAN value. */

  if( hostname_len && hostname[ hostname_len-1UL ]=='.' ) hostname_len--;

  if( FD_UNLIKELY( !dns_name_valid( hostname, hostname_len ) ) ) return 0;
  if( hostname_len<=15UL ) {
    char ip4[ 16 ];
    memcpy( ip4, hostname, hostname_len );
    ip4[ hostname_len ] = '\0';
    uint addr;
    if( FD_UNLIKELY( fd_cstr_to_ip4_addr( ip4, &addr ) ) ) return 0;
  }
  if( FD_UNLIKELY( !info->has_subject_alt_name ) ) return 0;

  fd_der_cursor_t san = { .p   = info->san_general_names,
                          .end = info->san_general_names + info->san_general_names_len };
  int matched = 0;
  while( FD_DER_HAS_MORE( san ) ) {
    int gn_tag; ulong gn_len;
    if( FD_UNLIKELY( fd_der_read_tl( &san, &gn_tag, &gn_len ) ) ) return 0;
    if( FD_UNLIKELY( !fd_x509_general_name_valid( gn_tag, san.p, gn_len ) ) )
      return 0;

    if( gn_tag==(int)FD_DER_TAG_CONTEXT_PRIM(2) &&
        dns_pattern_matches( (char const *)san.p, gn_len, hostname, hostname_len ) ) matched = 1;
    san.p += gn_len;
  }

  return matched;
}

int
fd_x509_decode_ecdsa_sig( uchar const * der,
                          ulong         der_len,
                          uchar *       raw_sig,
                          ulong         scalar_sz ) {

  if( FD_UNLIKELY( !der || !raw_sig ) ) return -1;

  FD_DER_CURSOR_FROM_BUF( c, der, der_len );

  uchar const * r_ptr; ulong r_len;
  uchar const * s_ptr; ulong s_len;

  FD_DER_ENTER( c, FD_DER_TAG_SEQUENCE );
    FD_DER_READ( c, FD_DER_TAG_INTEGER, r_ptr, r_len );
    FD_DER_READ( c, FD_DER_TAG_INTEGER, s_ptr, s_len );
  FD_DER_LEAVE( c );

  if( FD_UNLIKELY( FD_DER_HAS_MORE( c ) ) ) return -1;

  if( FD_UNLIKELY( fd_der_int_to_fixed( r_ptr, r_len, raw_sig,             scalar_sz ) ) ) return -1;
  if( FD_UNLIKELY( fd_der_int_to_fixed( s_ptr, s_len, raw_sig + scalar_sz, scalar_sz ) ) ) return -1;

  return 0;
}

int
fd_x509_ec_point_compress( uchar const * uncompressed,
                           ulong         coord_sz,
                           uchar *       compressed ) {
  if( FD_UNLIKELY( !uncompressed || !compressed ) ) return -1;
  if( FD_UNLIKELY( coord_sz!=32UL && coord_sz!=48UL ) ) return -1;
  if( coord_sz==32UL )
    return fd_secp256r1_public_key_compress( compressed, uncompressed )
           ==FD_SECP256R1_SUCCESS ? 0 : -1;
  else
    return fd_secp384r1_public_key_compress( compressed, uncompressed )
         ==FD_SECP384R1_SUCCESS ? 0 : -1;
}
