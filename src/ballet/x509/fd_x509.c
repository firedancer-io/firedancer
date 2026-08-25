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

    /* basicConstraints (2.5.29.19)
         BasicConstraints ::= SEQUENCE {
           cA                BOOLEAN DEFAULT FALSE,
           pathLenConstraint INTEGER (0..MAX) OPTIONAL } */
    if( fd_der_oid_match( oid_raw, oid_raw_len,
                          oid_basic_constraints, sizeof(oid_basic_constraints) ) ) {
      fd_der_cursor_t val = { .p = val_ptr, .end = val_ptr + val_len };
      FD_DER_ENTER( val, FD_DER_TAG_SEQUENCE );
        int bc_tag; FD_DER_PEEK_TAG_OR( val, bc_tag, 0 );
        if( bc_tag == (int)FD_DER_TAG_BOOLEAN ) {
          uchar const * ca_ptr; ulong ca_len;
          FD_DER_READ( val, FD_DER_TAG_BOOLEAN, ca_ptr, ca_len );
          /* DER encodes a BOOLEAN as a single 0x00 or 0xFF byte */
          if( FD_UNLIKELY( ca_len!=1UL ) ) return -1;
          if( FD_UNLIKELY( ca_ptr[0]!=0x00 && ca_ptr[0]!=0xFF ) ) return -1;
          out->is_ca = ca_ptr[0]==0xFF;
        }
        FD_DER_SKIP_IF( val, FD_DER_TAG_INTEGER );  /* pathLenConstraint */
      FD_DER_LEAVE( val );  /* rejects unconsumed SEQUENCE content */
      /* Reject trailing bytes in the extension's OCTET STRING */
      if( FD_UNLIKELY( FD_DER_HAS_MORE( val ) ) ) return -1;
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
      if( FD_UNLIKELY( bs_len<1UL || bs_len>3UL ) ) return -1;
      uint unused = bs[0];
      if( FD_UNLIKELY( unused>7U ) ) return -1;

      if( bs_len==1UL ) {
        /* Empty BIT STRING: every usage is denied.  bs[1] does not exist
           here, so key_usage stays 0. */
        if( FD_UNLIKELY( unused!=0U ) ) return -1;
      } else {
        /* DER zeroes the unused bits and trims trailing zero bits, so the
           final octet has no unused bits set and is itself nonzero */
        uchar last = bs[ bs_len-1UL ];
        if( FD_UNLIKELY( last & (uchar)( ( 1U<<unused ) - 1U ) ) ) return -1;
        if( FD_UNLIKELY( !last ) ) return -1;
        out->key_usage = (ushort)( ( (uint)bs[1] << 8 ) |
                                   ( bs_len>2UL ? (uint)bs[2] : 0U ) );
      }
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
      fd_der_cursor_t val = { .p = val_ptr, .end = val_ptr + val_len };

      /* SEQUENCE OF GeneralName */
      uchar const * san_ptr; ulong san_len;
      FD_DER_READ( val, FD_DER_TAG_SEQUENCE, san_ptr, san_len );

      fd_der_cursor_t san = { .p = san_ptr, .end = san_ptr + san_len };
      while( FD_DER_HAS_MORE( san ) ) {
        int gn_tag; ulong gn_len;
        if( FD_UNLIKELY( fd_der_read_tl( &san, &gn_tag, &gn_len ) ) ) return -1;

        /* Context tag [2] = dNSName (IA5String, implicit) */
        if( gn_tag == (int)FD_DER_TAG_CONTEXT_PRIM(2) &&
            out->san_dns_cnt < FD_X509_SAN_DNS_MAX ) {
          if( FD_UNLIKELY( gn_len > USHORT_MAX ) ) return -1;  /* name_len is a ushort */
          out->san_dns[ out->san_dns_cnt ].name     = (char const *)san.p;
          out->san_dns[ out->san_dns_cnt ].name_len = (ushort)gn_len;
          out->san_dns_cnt++;
        }
        san.p += gn_len;
      }
      continue;
    }

    /* Unknown extension */
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
      while( FD_DER_HAS_MORE( tbs ) ) {
        int next_tag;
        FD_DER_PEEK_TAG( tbs, next_tag );

        if( next_tag == (int)FD_DER_TAG_CONTEXT(3) ) {
          FD_DER_ENTER( tbs, FD_DER_TAG_CONTEXT(3) );
            uchar const * ext_seq_ptr; ulong ext_seq_len;
            FD_DER_READ( tbs, FD_DER_TAG_SEQUENCE, ext_seq_ptr, ext_seq_len );
            fd_der_cursor_t ext = { .p = ext_seq_ptr, .end = ext_seq_ptr + ext_seq_len };
            if( FD_UNLIKELY( fd_x509_parse_extensions( &ext, out ) ) ) return -1;
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

int
fd_x509_san_matches( fd_x509_cert_info_t const * info,
                     char const *                hostname,
                     ulong                       hostname_len ) {

  if( FD_UNLIKELY( !dns_name_valid( hostname, hostname_len ) ) ) return 0;

  for( uint i = 0; i < info->san_dns_cnt; i++ ) {
    char const * pattern     = info->san_dns[i].name;
    ulong        pattern_len = info->san_dns[i].name_len;

    /* Wildcard: *.example.com matches foo.example.com.  The wildcard is
       only recognized as the whole leftmost label, and the remainder
       must span at least two labels, so *.com matches nothing. */

    if( pattern_len>=2UL && pattern[0]=='*' && pattern[1]=='.' ) {
      char const * pattern_tail     = pattern + 2;
      ulong        pattern_tail_len = pattern_len - 2UL;

      if( !dns_name_valid( pattern_tail, pattern_tail_len ) ) continue;
      if( !memchr( pattern_tail, '.', pattern_tail_len ) ) continue;

      ulong dot_pos = 0UL;
      for( ; dot_pos<hostname_len; dot_pos++ ) {
        if( hostname[dot_pos]=='.' ) break;
      }

      /* The wildcard must consume a non-empty label. */

      if( dot_pos==0UL || dot_pos>=hostname_len ) continue;

      char const * host_tail     = hostname + dot_pos + 1UL;
      ulong        host_tail_len = hostname_len - dot_pos - 1UL;

      if( host_tail_len==pattern_tail_len &&
          dns_eq_ci( pattern_tail, host_tail, pattern_tail_len ) ) return 1;

      continue;
    }

    /* Exact match (case-insensitive) */

    if( pattern_len==hostname_len &&
        dns_name_valid( pattern, pattern_len ) &&
        dns_eq_ci( pattern, hostname, pattern_len ) ) return 1;
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
