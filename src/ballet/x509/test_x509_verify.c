#include "fd_x509.h"
#include "fd_der.h"
#include "fd_x509_verify.h"
#include "fd_x509_ca_store.h"
#include "../ed25519/fd_ed25519.h"
#include "../base64/fd_base64.h"
#include "../hex/fd_hex.h"
#include "../../util/fd_util.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* TEST_NOW is 2020-01-01T00:00:00Z.  Tests pin the clock so that the
   validity period checks never go stale. */

#define TEST_NOW (1577836800L)

/* Minimal DER writer, just enough to build test certificates.  Nested
   lengths are computed rather than hand-counted. */

static ulong
der_tlv( uchar *       out,
         uchar         tag,
         uchar const * content,
         ulong         content_len ) {
  ulong n = 0UL;
  out[ n++ ] = tag;
  if( content_len < 128UL ) {
    out[ n++ ] = (uchar)content_len;
  } else if( content_len < 256UL ) {
    out[ n++ ] = 0x81;
    out[ n++ ] = (uchar)content_len;
  } else {
    out[ n++ ] = 0x82;
    out[ n++ ] = (uchar)( content_len >> 8 );
    out[ n++ ] = (uchar)( content_len      );
  }
  if( content_len ) memcpy( out+n, content, content_len );
  return n + content_len;
}

static ulong
der_hdr_sz( uchar const * tlv ) {
  return (tlv[1] & 0x80U) ? 2UL+(ulong)(tlv[1] & 0x7fU) : 2UL;
}

static void
der_bump_len( uchar * tlv,
              ulong   delta ) {
  if( !(tlv[1] & 0x80U) ) {
    FD_TEST( (ulong)tlv[1]+delta<128UL );
    tlv[1] = (uchar)( (ulong)tlv[1]+delta );
    return;
  }
  uint n = (uint)(tlv[1] & 0x7fU);
  ulong len = 0UL;
  for( uint i=0U; i<n; i++ ) len = (len<<8) | tlv[2U+i];
  len += delta;
  for( uint i=n; i; i-- ) { tlv[1U+i] = (uchar)len; len >>= 8; }
  FD_TEST( !len );
}

/* set_san_info builds the GeneralNames content retained by cert_info. */

static void
set_san_info( fd_x509_cert_info_t * info,
              uchar *               general_names,
              char const *          name,
              ulong                 name_len ) {
  memset( info, 0, sizeof(fd_x509_cert_info_t) );
  info->san_general_names     = general_names;
  info->san_general_names_len = der_tlv( general_names, FD_DER_TAG_CONTEXT_PRIM(2),
                                         (uchar const *)name, name_len );
  info->has_subject_alt_name  = 1;
}

/* mk_cert builds a minimal Ed25519 certificate wrapping the caller
   supplied extensions blob (a concatenation of Extension TLVs).
   Returns the certificate length. */

static uchar const oid_ed25519_alg[] = { 0x06, 0x03, 0x2b, 0x65, 0x70 };

/* mk_tbs builds a TBSCertificate.  issuer and subject are encoded Name
   TLVs, empty RDNSequences when NULL -- the same encoding the CA store
   keys on.  pubkey is the 32 byte Ed25519 subjectPublicKey.  Returns the
   length of the encoded TBSCertificate, which is what gets signed. */

static ulong
mk_tbs( uchar *       out,
        uchar const * issuer,
        ulong         issuer_len,
        uchar const * subject,
        ulong         subject_len,
        uchar const * pubkey,
        char const *  not_before,
        uchar         not_before_tag,
        char const *  not_after,
        uchar         not_after_tag,
        uchar const * exts,
        ulong         exts_len ) {

  uchar buf[ 1024 ]; ulong n;

  uchar tbs[ 1024 ]; ulong t = 0UL;

  /* version [0] EXPLICIT INTEGER 2 */
  uchar const ver_int[] = { 0x02, 0x01, 0x02 };
  t += der_tlv( tbs+t, FD_DER_TAG_CONTEXT(0), ver_int, sizeof(ver_int) );

  /* serialNumber INTEGER 1 */
  uchar const serial[] = { 0x01 };
  t += der_tlv( tbs+t, FD_DER_TAG_INTEGER, serial, sizeof(serial) );

  /* signature AlgorithmIdentifier */
  t += der_tlv( tbs+t, FD_DER_TAG_SEQUENCE, oid_ed25519_alg, sizeof(oid_ed25519_alg) );

  /* issuer Name */
  if( issuer_len ) { memcpy( tbs+t, issuer, issuer_len ); t += issuer_len; }
  else             { t += der_tlv( tbs+t, FD_DER_TAG_SEQUENCE, NULL, 0UL ); }

  /* validity SEQUENCE { notBefore, notAfter } */
  n  = der_tlv( buf,   not_before_tag, (uchar const *)not_before, strlen( not_before ) );
  n += der_tlv( buf+n, not_after_tag,  (uchar const *)not_after,  strlen( not_after  ) );
  t += der_tlv( tbs+t, FD_DER_TAG_SEQUENCE, buf, n );

  /* subject Name */
  if( subject_len ) { memcpy( tbs+t, subject, subject_len ); t += subject_len; }
  else              { t += der_tlv( tbs+t, FD_DER_TAG_SEQUENCE, NULL, 0UL ); }

  /* subjectPublicKeyInfo SEQUENCE { AlgorithmIdentifier, BIT STRING } */
  uchar pk[ 33 ]; pk[0] = 0;  /* unused bits || 32 byte key */
  memcpy( pk+1, pubkey, 32UL );
  n  = der_tlv( buf,   FD_DER_TAG_SEQUENCE,   oid_ed25519_alg, sizeof(oid_ed25519_alg) );
  n += der_tlv( buf+n, FD_DER_TAG_BIT_STRING, pk, sizeof(pk) );
  t += der_tlv( tbs+t, FD_DER_TAG_SEQUENCE, buf, n );

  /* extensions [3] EXPLICIT SEQUENCE OF Extension */
  if( exts_len ) {
    n  = der_tlv( buf, FD_DER_TAG_SEQUENCE, exts, exts_len );
    t += der_tlv( tbs+t, FD_DER_TAG_CONTEXT(3), buf, n );
  }

  return der_tlv( out, FD_DER_TAG_SEQUENCE, tbs, t );
}

/* wrap_cert wraps an encoded TBSCertificate and its 64 byte signature
   into a Certificate SEQUENCE.  The signature is over the TBSCertificate
   TLV as passed, header included. */

static ulong
wrap_cert( uchar *       out,
           uchar const * tbs,
           ulong         tbs_len,
           uchar const * sig ) {
  uchar sig_bits[ 65 ]; sig_bits[0] = 0;  /* unused bits || 64 byte sig */
  memcpy( sig_bits+1, sig, 64UL );

  uchar buf[ 1024 ];
  memcpy( buf, tbs, tbs_len );
  ulong n = tbs_len;
  n += der_tlv( buf+n, FD_DER_TAG_SEQUENCE,   oid_ed25519_alg, sizeof(oid_ed25519_alg) );
  n += der_tlv( buf+n, FD_DER_TAG_BIT_STRING, sig_bits, sizeof(sig_bits) );
  return der_tlv( out, FD_DER_TAG_SEQUENCE, buf, n );
}

/* mk_cert_validity builds a certificate with fixed non-empty issuer and
   subject names, an all zero key and an all zero signature.  Good
   enough for every check that runs ahead of signature verification. */

static ulong
mk_cert_validity( uchar *       out,
                  char const *  not_before,
                  uchar         not_before_tag,
                  char const *  not_after,
                  uchar         not_after_tag,
                  uchar const * exts,
                  ulong         exts_len ) {
  static uchar const subject[] = {
    0x30,0x0c,0x31,0x0a,0x30,0x08,0x06,0x03,0x55,0x04,0x03,0x0c,0x01,'x'
  };
  uchar zero[ 64 ]; memset( zero, 0, sizeof(zero) );
  uchar tbs[ 1024 ];
  ulong tbs_len = mk_tbs( tbs, subject, sizeof(subject), subject, sizeof(subject), zero,
                          not_before, not_before_tag,
                          not_after,  not_after_tag,
                          exts, exts_len );
  return wrap_cert( out, tbs, tbs_len, zero );
}

/* mk_cert_signed builds a certificate valid at TEST_NOW, carrying the
   given issuer and subject names and public key, with a real Ed25519
   signature over the TBSCertificate by issuer_prvkey. */

static ulong
mk_cert_signed( uchar *       out,
                uchar const * issuer,
                ulong         issuer_len,
                uchar const * subject,
                ulong         subject_len,
                uchar const * pubkey,
                uchar const * issuer_prvkey,
                uchar const * exts,
                ulong         exts_len ) {
  uchar tbs[ 1024 ];
  ulong tbs_len = mk_tbs( tbs, issuer, issuer_len, subject, subject_len, pubkey,
                          "750101000000Z",   FD_DER_TAG_UTC_TIME,
                          "40960101000000Z", FD_DER_TAG_GENERALIZED_TIME,
                          exts, exts_len );

  fd_sha512_t sha[1];
  uchar issuer_pubkey[ 32 ];
  fd_ed25519_public_from_private( issuer_pubkey, issuer_prvkey, sha );

  uchar sig[ 64 ];
  fd_ed25519_sign( sig, tbs, tbs_len, issuer_pubkey, issuer_prvkey, sha );

  return wrap_cert( out, tbs, tbs_len, sig );
}

/* mk_cert builds a certificate that is valid at TEST_NOW. */

static ulong
mk_cert( uchar *       out,
         uchar const * exts,
         ulong         exts_len ) {
  return mk_cert_validity( out,
                           "750101000000Z",   FD_DER_TAG_UTC_TIME,
                           "40960101000000Z", FD_DER_TAG_GENERALIZED_TIME,
                           exts, exts_len );
}

/* mk_ext builds an Extension SEQUENCE { OID, OCTET STRING value }.
   oid is the full OID TLV. */

static ulong
mk_ext( uchar *       out,
        uchar const * oid,
        ulong         oid_len,
        uchar const * val,
        ulong         val_len ) {
  uchar buf[ 512 ];
  ulong n = 0UL;
  memcpy( buf, oid, oid_len ); n += oid_len;
  n += der_tlv( buf+n, FD_DER_TAG_OCTET_STRING, val, val_len );
  return der_tlv( out, FD_DER_TAG_SEQUENCE, buf, n );
}

/* mk_ext_critical builds an Extension with an explicit critical BOOLEAN. */

static ulong
mk_ext_critical( uchar *       out,
                 uchar const * oid,
                 ulong         oid_len,
                 uchar         critical,
                 uchar const * val,
                 ulong         val_len ) {
  uchar buf[ 512 ];
  ulong n = 0UL;
  memcpy( buf, oid, oid_len ); n += oid_len;
  n += der_tlv( buf+n, FD_DER_TAG_BOOLEAN, &critical, 1UL );
  n += der_tlv( buf+n, FD_DER_TAG_OCTET_STRING, val, val_len );
  return der_tlv( out, FD_DER_TAG_SEQUENCE, buf, n );
}

/* mk_name_tag builds a Name holding a single commonName RDN, and returns
   the length of the encoded Name. */

static uchar const oid_cn_tlv[] = { 0x06, 0x03, 0x55, 0x04, 0x03 };

static ulong
mk_name_oid_tag( uchar *       out,
                 uchar const * oid,
                 ulong         oid_len,
                 char const *  value,
                 uchar         tag ) {
  ulong value_len = strlen( value );
  FD_TEST( oid_len  <=16UL );
  FD_TEST( value_len<=64UL );

  uchar atv[ 128 ];
  memcpy( atv, oid, oid_len );
  ulong a = oid_len;
  a += der_tlv( atv+a, tag, (uchar const *)value, value_len );

  uchar rdn[ 160 ]; ulong r = der_tlv( rdn, FD_DER_TAG_SEQUENCE, atv, a );
  uchar set[ 192 ]; ulong n = der_tlv( set, FD_DER_TAG_SET,      rdn, r );
  return der_tlv( out, FD_DER_TAG_SEQUENCE, set, n );
}

static ulong
mk_name_tag( uchar *      out,
             char const * cn,
             uchar        tag ) {
  return mk_name_oid_tag( out, oid_cn_tlv, sizeof(oid_cn_tlv), cn, tag );
}

static ulong
mk_name( uchar *      out,
         char const * cn ) {
  return mk_name_tag( out, cn, FD_DER_TAG_UTF8_STRING );
}

/* mk_san builds a subjectAltName extension from a raw GeneralName blob. */

static uchar const oid_san_tlv[] = { 0x06, 0x03, 0x55, 0x1d, 0x11 };
static uchar const oid_bc_tlv [] = { 0x06, 0x03, 0x55, 0x1d, 0x13 };
static uchar const oid_ku_tlv [] = { 0x06, 0x03, 0x55, 0x1d, 0x0f };
static uchar const oid_eku_tlv[] = { 0x06, 0x03, 0x55, 0x1d, 0x25 };

static ulong
mk_san( uchar *       out,
        uchar const * gn,
        ulong         gn_len ) {
  uchar buf[ 512 ];
  ulong n = der_tlv( buf, FD_DER_TAG_SEQUENCE, gn, gn_len );
  return mk_ext( out, oid_san_tlv, sizeof(oid_san_tlv), buf, n );
}

static ulong
append_pem_cert( char *        out,
                 uchar const * der,
                 ulong         der_len ) {
  static char const begin[] = "-----BEGIN CERTIFICATE-----\n";
  static char const end[]   = "\n-----END CERTIFICATE-----\n";
  ulong n = 0UL;
  memcpy( out+n, begin, sizeof(begin)-1UL ); n += sizeof(begin)-1UL;
  n += fd_base64_encode( out+n, der, der_len );
  memcpy( out+n, end, sizeof(end)-1UL ); n += sizeof(end)-1UL;
  return n;
}

static void
rewrite_tmp_file( int          fd,
                  void const * data,
                  ulong        data_len ) {
  FD_TEST( !ftruncate( fd, 0 ) );
  FD_TEST( lseek( fd, 0L, SEEK_SET )==0L );
  uchar const * p = (uchar const *)data;
  while( data_len ) {
    long n = write( fd, p, data_len );
    FD_TEST( n>0L );
    p        += (ulong)n;
    data_len -= (ulong)n;
  }
}


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Test 1: Parse zero-length input */
  {
    uchar buf[ 1 ];
    fd_x509_cert_info_t info;
    FD_TEST( fd_x509_cert_parse( buf, 0UL, &info )!=0 );
    FD_TEST( fd_x509_cert_parse( NULL, 0UL, &info )!=0 );
    FD_TEST( fd_x509_cert_parse( buf, sizeof(buf), NULL )!=0 );
    FD_LOG_INFO(( "OK: parse zero-length returns non-zero" ));
  }

  /* Test 2: Parse 64 bytes of garbage (0xFF) */
  {
    uchar garbage[ 64 ];
    memset( garbage, 0xFF, 64 );
    fd_x509_cert_info_t info;
    FD_TEST( fd_x509_cert_parse( garbage, 64UL, &info )!=0 );
    FD_LOG_INFO(( "OK: parse garbage returns non-zero" ));
  }

  /* Test 3: Parse too-short valid-looking DER */
  {
    uchar short_der[ 5 ] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
    fd_x509_cert_info_t info;
    FD_TEST( fd_x509_cert_parse( short_der, 5UL, &info )!=0 );
    FD_LOG_INFO(( "OK: parse too-short DER returns non-zero" ));
  }

  /* Test 4: Exact match */
  {
    fd_x509_cert_info_t info; uchar gn[ 32 ];
    set_san_info( &info, gn, "example.com", 11UL );
    FD_TEST( fd_x509_san_matches( &info, "example.com", 11UL )==1 );
    FD_LOG_INFO(( "OK: exact SAN match" ));
  }

  /* Test 5: No match */
  {
    fd_x509_cert_info_t info; uchar gn[ 32 ];
    set_san_info( &info, gn, "example.com", 11UL );
    FD_TEST( fd_x509_san_matches( &info, "other.com", 9UL )==0 );
    FD_LOG_INFO(( "OK: SAN no match" ));
  }

  /* Test 6: Wildcard match */
  {
    fd_x509_cert_info_t info; uchar gn[ 32 ];
    set_san_info( &info, gn, "*.example.com", 13UL );
    FD_TEST( fd_x509_san_matches( &info, "foo.example.com", 15UL )==1 );
    FD_LOG_INFO(( "OK: wildcard SAN match" ));
  }

  /* Test 7: Wildcard no deep match */
  {
    fd_x509_cert_info_t info; uchar gn[ 32 ];
    set_san_info( &info, gn, "*.example.com", 13UL );
    FD_TEST( fd_x509_san_matches( &info, "a.b.example.com", 15UL )==0 );
    FD_LOG_INFO(( "OK: wildcard no deep match" ));
  }

  /* Test 8: Wildcard no bare match */
  {
    fd_x509_cert_info_t info; uchar gn[ 32 ];
    set_san_info( &info, gn, "*.example.com", 13UL );
    FD_TEST( fd_x509_san_matches( &info, "example.com", 11UL )==0 );
    FD_LOG_INFO(( "OK: wildcard no bare match" ));
  }

  /* Test 9: Multiple SANs, second matches */
  {
    fd_x509_cert_info_t info; uchar gn[ 64 ];
    set_san_info( &info, gn, "other.com", 9UL );
    info.san_general_names_len += der_tlv( gn+info.san_general_names_len,
                                           FD_DER_TAG_CONTEXT_PRIM(2),
                                           (uchar const *)"example.com", 11UL );
    FD_TEST( fd_x509_san_matches( &info, "example.com", 11UL )==1 );
    FD_LOG_INFO(( "OK: multiple SANs, second matches" ));
  }

  /* Test 10: Empty hostname */
  {
    fd_x509_cert_info_t info; uchar gn[ 32 ];
    set_san_info( &info, gn, "example.com", 11UL );
    FD_TEST( fd_x509_san_matches( &info, "", 0UL )==0 );
    FD_TEST( fd_x509_san_matches( NULL,  "example.com", 11UL )==0 );
    FD_TEST( fd_x509_san_matches( &info, NULL,          0UL  )==0 );
    FD_LOG_INFO(( "OK: empty hostname returns 0" ));
  }

  /* Version and serial number must follow the TBSCertificate schema. */
  {
    uchar cert[ 1024 ]; ulong cert_len = mk_cert( cert, NULL, 0UL );
    uchar * tbs = cert + der_hdr_sz( cert );
    uchar * version = tbs + der_hdr_sz( tbs );
    uchar * serial = version + der_hdr_sz( version ) + (ulong)version[1];
    fd_x509_cert_info_t info;

    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )==0 );
    FD_TEST( info.version==2U );

    version[2] = FD_DER_TAG_NULL;
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )!=0 );
    version[2] = FD_DER_TAG_INTEGER;
    version[4] = 3U;
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )!=0 );
    version[4] = 1U;
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )==0 );
    FD_TEST( info.version==1U );

    serial[0] = FD_DER_TAG_OCTET_STRING;
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )!=0 );
    serial[0] = FD_DER_TAG_INTEGER;
    serial[2] = 0U;
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )!=0 );

    FD_LOG_INFO(( "OK: TBSCertificate version and serial schema" ));
  }

  /* IPv4 reference identities require iPAddress SANs, not dNSName SANs. */
  {
    uchar general_names[ 64 ]; fd_x509_cert_info_t info;
    set_san_info( &info, general_names, "192.0.2.1", 9UL );
    FD_TEST( fd_x509_san_matches( &info, "192.0.2.1", 9UL )==0 );
    set_san_info( &info, general_names, "123.example", 11UL );
    FD_TEST( fd_x509_san_matches( &info, "123.example", 11UL )==1 );
    FD_LOG_INFO(( "OK: IPv4 literal rejected as dNSName" ));
  }

  /* Test 11: Empty store find returns NULL */
  {
    fd_x509_ca_store_t store;
    memset( &store, 0, sizeof(store) );
    uchar query[ 4 ] = { 0x30, 0x02, 0x01, 0x00 };
    ulong idx = 0UL;
    FD_TEST( fd_x509_ca_store_find_next( &store, query, 4UL, &idx )==NULL );
    FD_LOG_INFO(( "OK: empty store find returns NULL" ));
  }

  /* Test 12: Store with one entry, match */
  {
    fd_x509_ca_store_t store;
    memset( &store, 0, sizeof(store) );
    uchar subject_bytes[ 8 ] = { 0x30, 0x06, 0x31, 0x04, 0x0C, 0x02, 0x43, 0x41 };
    ulong subject_len = 8;
    store.cnt = 1;
    memcpy( store.entries[0].subject, subject_bytes, subject_len );
    store.entries[0].subject_len = subject_len;
    ulong idx = 0UL;
    FD_TEST( fd_x509_ca_store_find_next( &store, subject_bytes, subject_len, &idx )!=NULL );
    FD_LOG_INFO(( "OK: store find with matching subject" ));
  }

  /* Test 13: Store with one entry, no match */
  {
    fd_x509_ca_store_t store;
    memset( &store, 0, sizeof(store) );
    uchar subject_bytes[ 8 ] = { 0x30, 0x06, 0x31, 0x04, 0x0C, 0x02, 0x43, 0x41 };
    ulong subject_len = 8;
    store.cnt = 1;
    memcpy( store.entries[0].subject, subject_bytes, subject_len );
    store.entries[0].subject_len = subject_len;
    uchar other[ 4 ] = { 0x30, 0x02, 0x01, 0xFF };
    ulong idx = 0UL;
    FD_TEST( fd_x509_ca_store_find_next( &store, other, 4UL, &idx )==NULL );
    FD_LOG_INFO(( "OK: store find with non-matching subject returns NULL" ));
  }

  /* basicConstraints cA=TRUE, for CA certs built below */
  static uchar const bc_ca_true_val[] = { 0x30, 0x03, 0x01, 0x01, 0xFF };

  /* The PEM CA-store loader handles multiple entries, malformed inputs,
     filtering, capacity, and its bundle-size guard. */
  {
    uchar zero[ 64 ]; memset( zero, 0, sizeof(zero) );
    uchar root_name[ 64 ]; ulong root_name_len = mk_name( root_name, "Loader Root" );
    uchar ca_ext[ 64 ];
    ulong ca_ext_len = mk_ext_critical( ca_ext, oid_bc_tlv, sizeof(oid_bc_tlv),
                                        0xFF, bc_ca_true_val, sizeof(bc_ca_true_val) );

    uchar tbs[ 1024 ];
    ulong tbs_len = mk_tbs( tbs, root_name, root_name_len, root_name, root_name_len, zero,
                            "750101000000Z", FD_DER_TAG_UTC_TIME,
                            "40960101000000Z", FD_DER_TAG_GENERALIZED_TIME,
                            ca_ext, ca_ext_len );
    uchar ca_cert[ 1200 ]; ulong ca_cert_len = wrap_cert( ca_cert, tbs, tbs_len, zero );

    tbs_len = mk_tbs( tbs, root_name, root_name_len, root_name, root_name_len, zero,
                      "750101000000Z", FD_DER_TAG_UTC_TIME,
                      "40960101000000Z", FD_DER_TAG_GENERALIZED_TIME,
                      NULL, 0UL );
    uchar non_ca_cert[ 1200 ]; ulong non_ca_cert_len = wrap_cert( non_ca_cert, tbs, tbs_len, zero );

    char path[] = "/tmp/fd_x509_ca_store_test_XXXXXX";
    int tmp_fd = mkstemp( path ); FD_TEST( tmp_fd>=0 );
    fd_x509_ca_store_t store;
    char pem[ 8192 ]; ulong pem_len = 0UL;

    pem_len += append_pem_cert( pem+pem_len, ca_cert, ca_cert_len );
    pem_len += append_pem_cert( pem+pem_len, ca_cert, ca_cert_len );
    memcpy( pem+pem_len, "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n", 59UL );
    pem_len += 59UL;
    rewrite_tmp_file( tmp_fd, pem, pem_len );
    FD_TEST( fd_x509_ca_store_load( &store, path )==2L );
    FD_TEST( store.cnt==2UL );

    /* An unterminated block must not consume the following valid block's
       END marker and hide that trust anchor. */
    static char const unterminated[] = "-----BEGIN CERTIFICATE-----\n!!!!\n";
    memcpy( pem, unterminated, sizeof(unterminated)-1UL );
    pem_len = sizeof(unterminated)-1UL;
    pem_len += append_pem_cert( pem+pem_len, ca_cert, ca_cert_len );
    rewrite_tmp_file( tmp_fd, pem, pem_len );
    FD_TEST( fd_x509_ca_store_load( &store, path )==1L );
    FD_TEST( store.cnt==1UL );

    pem_len = append_pem_cert( pem, non_ca_cert, non_ca_cert_len );
    rewrite_tmp_file( tmp_fd, pem, pem_len );
    FD_TEST( fd_x509_ca_store_load( &store, path )==0L );
    FD_TEST( !store.cnt );

    uchar bad_der[] = { 0x30,0x03,0x02,0x01,0x00 };
    pem_len = append_pem_cert( pem, bad_der, sizeof(bad_der) );
    rewrite_tmp_file( tmp_fd, pem, pem_len );
    FD_TEST( fd_x509_ca_store_load( &store, path )==0L );

    /* P-384 SPKI is parseable, but P-384 issuer verification is not
       implemented.  Such a certificate must not be advertised as a
       usable trust anchor by the loader. */
    static char const p384_ca_hex[] =
      "308201d73082015ea0030201020214509ea19aab940dbdb2293c2ef5d5db6346153aed300a06082a8648ce3d040303301b"
      "3119301706035504030c1050333834204c6f6164657220526f6f74301e170d3236303832373032303634375a170d32363038"
      "32383032303634375a301b3119301706035504030c1050333834204c6f6164657220526f6f743076301006072a8648ce3d"
      "020106052b81040022036200048c16017e34456d0e4c20555d345ed5f1e208b4a3e938d2a0167b00fd182816f78e505850"
      "6c7bc9fa5fac4c27f56cec1c23938ecd89b3ceb87dd7a5d0dbd5a33aa7e2965493504d03a1f0025131281c339b82e73f1"
      "c1ff487de54f75fd3cb6598a3633061301d0603551d0e041604141f1c9ffabf79a16860732dd1bee3388ec8f6e52e301f"
      "0603551d230418301680141f1c9ffabf79a16860732dd1bee3388ec8f6e52e300f0603551d130101ff040530030101ff30"
      "0e0603551d0f0101ff040403020204300a06082a8648ce3d0403030367003064023058335f8c6993b5cb8051edca086f3e"
      "5568f827f8ce6bac28a4569c34ca90304e3bdca9221639a161ec035d1ec073501602301012fb483121416d72ce6ffcff478"
      "93d8c9cd05f1e05eaa5f6787fabf891e1863ca2cfe668156a544785e8cd761546dc";
    uchar p384_ca[ 475 ];
    fd_hex_decode( p384_ca, p384_ca_hex, sizeof(p384_ca) );
    fd_x509_cert_info_t p384_info;
    FD_TEST( !fd_x509_cert_parse( p384_ca, sizeof(p384_ca), &p384_info ) );
    FD_TEST( p384_info.key_type==FD_X509_KEY_ECDSA_P384 );
    FD_TEST( p384_info.is_ca );
    pem_len = append_pem_cert( pem, p384_ca, sizeof(p384_ca) );
    rewrite_tmp_file( tmp_fd, pem, pem_len );
    FD_TEST( fd_x509_ca_store_load( &store, path )==0L );
    FD_TEST( !store.cnt );

    /* An off-curve P-384 subject key must not parse, even though its y
       parity bit (the only part the compressed form retains) is intact. */
    ulong y_off = (ulong)( p384_info.pubkey - p384_ca ) + 49UL;
    p384_ca[ y_off ] ^= 1U;
    FD_TEST( fd_x509_cert_parse( p384_ca, sizeof(p384_ca), &p384_info ) );
    p384_ca[ y_off ] ^= 1U;

    /* Subjects larger than the bounded store representation are skipped. */
    uchar name_content[ FD_X509_CA_SUBJECT_MAX+1UL ]; memset( name_content, 0, sizeof(name_content) );
    uchar large_name[ 600 ]; ulong large_name_len = der_tlv( large_name, FD_DER_TAG_SEQUENCE,
                                                             name_content, sizeof(name_content) );
    tbs_len = mk_tbs( tbs, root_name, root_name_len, large_name, large_name_len, zero,
                      "750101000000Z", FD_DER_TAG_UTC_TIME,
                      "40960101000000Z", FD_DER_TAG_GENERALIZED_TIME,
                      ca_ext, ca_ext_len );
    uchar large_subject_cert[ 1400 ];
    ulong large_subject_cert_len = wrap_cert( large_subject_cert, tbs, tbs_len, zero );
    pem_len = append_pem_cert( pem, large_subject_cert, large_subject_cert_len );
    rewrite_tmp_file( tmp_fd, pem, pem_len );
    FD_TEST( fd_x509_ca_store_load( &store, path )==0L );

    ulong one_pem_len = append_pem_cert( pem, ca_cert, ca_cert_len );
    ulong cap_pem_len = one_pem_len*(FD_X509_CA_STORE_MAX+1UL);
    char * cap_pem = (char *)malloc( cap_pem_len ); FD_TEST( cap_pem );
    for( ulong i=0UL; i<FD_X509_CA_STORE_MAX+1UL; i++ )
      memcpy( cap_pem+i*one_pem_len, pem, one_pem_len );
    rewrite_tmp_file( tmp_fd, cap_pem, cap_pem_len );
    FD_TEST( fd_x509_ca_store_load( &store, path )==(long)FD_X509_CA_STORE_MAX );
    FD_TEST( store.cnt==FD_X509_CA_STORE_MAX );
    free( cap_pem );

    FD_TEST( !ftruncate( tmp_fd, (long)((64UL<<20)+1UL) ) );
    FD_TEST( fd_x509_ca_store_load( &store, path )==-1L );

    FD_TEST( !close( tmp_fd ) );
    FD_TEST( !unlink( path ) );
    FD_LOG_INFO(( "OK: PEM CA-store loader coverage" ));
  }

  /* Test 13b: find_next walks every entry sharing a subject */
  {
    fd_x509_ca_store_t store;
    memset( &store, 0, sizeof(store) );

    uchar dup  [ 64 ]; ulong dup_len   = mk_name( dup,   "Dup Root" );
    uchar other[ 64 ]; ulong other_len = mk_name( other, "Other Root" );

    store.cnt = 3;
    memcpy( store.entries[0].subject, dup,   dup_len   ); store.entries[0].subject_len = dup_len;
    memcpy( store.entries[1].subject, other, other_len ); store.entries[1].subject_len = other_len;
    memcpy( store.entries[2].subject, dup,   dup_len   ); store.entries[2].subject_len = dup_len;

    ulong idx = 0UL;
    FD_TEST( fd_x509_ca_store_find_next( &store, dup, dup_len, &idx )==&store.entries[0] );
    FD_TEST( fd_x509_ca_store_find_next( &store, dup, dup_len, &idx )==&store.entries[2] );
    FD_TEST( fd_x509_ca_store_find_next( &store, dup, dup_len, &idx )==NULL );

    FD_LOG_INFO(( "OK: find_next walks duplicate subjects" ));
  }

  /* Test 13c: a cert signed by the second of two anchors sharing a subject
     must verify.  Subjects repeat in real bundles after a key rollover, so
     stopping at the first match rejects a perfectly good chain. */
  {
    uchar root_name[ 64 ]; ulong root_name_len = mk_name( root_name, "Rollover Root" );
    uchar leaf_name[ 64 ]; ulong leaf_name_len = mk_name( leaf_name, "Leaf" );

    uchar prv_old[ 32 ]; memset( prv_old, 0xA1, sizeof(prv_old) );
    uchar prv_new[ 32 ]; memset( prv_new, 0xB2, sizeof(prv_new) );
    uchar leaf_pub[ 32 ]; memset( leaf_pub, 0x33, sizeof(leaf_pub) );

    fd_sha512_t sha[1];
    uchar pub_old[ 32 ]; fd_ed25519_public_from_private( pub_old, prv_old, sha );
    uchar pub_new[ 32 ]; fd_ed25519_public_from_private( pub_new, prv_new, sha );

    /* Leaf is signed by the new key, which is the second store entry. */
    uchar leaf[ 1024 ];
    ulong leaf_len = mk_cert_signed( leaf, root_name, root_name_len,
                                     leaf_name, leaf_name_len,
                                     leaf_pub, prv_new, NULL, 0UL );

    fd_x509_ca_store_t store;
    memset( &store, 0, sizeof(store) );
    store.cnt = 2;
    for( ulong k=0UL; k<2UL; k++ ) {
      memcpy( store.entries[k].subject, root_name, root_name_len );
      store.entries[k].subject_len = root_name_len;
      store.entries[k].pubkey_len  = 32UL;
      store.entries[k].key_type    = FD_X509_KEY_ED25519;
    }
    memcpy( store.entries[0].pubkey, pub_old, 32UL );
    memcpy( store.entries[1].pubkey, pub_new, 32UL );

    uchar const * chain_der   [ 1 ] = { leaf };
    ulong         chain_der_sz[ 1 ] = { leaf_len };
    FD_TEST( fd_x509_verify_chain( chain_der, chain_der_sz, 1UL, &store, NULL, 0UL, TEST_NOW )
             ==FD_X509_VERIFY_OK );

    /* Drop the matching anchor and the same chain must fail. */
    store.cnt = 1;
    FD_TEST( fd_x509_verify_chain( chain_der, chain_der_sz, 1UL, &store, NULL, 0UL, TEST_NOW )
             ==FD_X509_VERIFY_ERR_SIG );

    FD_LOG_INFO(( "OK: anchor sharing a subject with an earlier entry is tried" ));
  }

  /* Test 13d: the path ends at the first anchor that verifies, so a
     trailing cross-signature is ignored.  This is the shape real servers
     send: an intermediate we trust directly, followed by its cross-sign up
     to an older root we do not hold. */
  {
    uchar root_name [ 64 ]; ulong root_name_len  = mk_name( root_name,  "Trusted Root"  );
    uchar leaf_name [ 64 ]; ulong leaf_name_len  = mk_name( leaf_name,  "Leaf"          );
    uchar older_name[ 64 ]; ulong older_name_len = mk_name( older_name, "Untrusted Old Root" );

    uchar prv_root[ 32 ]; memset( prv_root, 0xC3, sizeof(prv_root) );
    uchar prv_old [ 32 ]; memset( prv_old,  0xD4, sizeof(prv_old)  );
    uchar leaf_pub[ 32 ]; memset( leaf_pub, 0x55, sizeof(leaf_pub) );

    fd_sha512_t sha[1];
    uchar pub_root[ 32 ]; fd_ed25519_public_from_private( pub_root, prv_root, sha );

    uchar exts[ 256 ];
    ulong exts_len = mk_ext_critical( exts, oid_bc_tlv, sizeof(oid_bc_tlv),
                                      0xFF, bc_ca_true_val, sizeof(bc_ca_true_val) );

    uchar leaf[ 1024 ];
    ulong leaf_len = mk_cert_signed( leaf, root_name, root_name_len,
                                     leaf_name, leaf_name_len,
                                     leaf_pub, prv_root, NULL, 0UL );

    /* The cross-sign: subject is the root we trust, issuer is one we do
       not have.  Its own signature is by that unknown root. */
    uchar cross[ 1024 ];
    ulong cross_len = mk_cert_signed( cross, older_name, older_name_len,
                                      root_name, root_name_len,
                                      pub_root, prv_old, exts, exts_len );

    fd_x509_ca_store_t store;
    memset( &store, 0, sizeof(store) );
    store.cnt = 1;
    memcpy( store.entries[0].subject, root_name, root_name_len );
    store.entries[0].subject_len = root_name_len;
    memcpy( store.entries[0].pubkey, pub_root, 32UL );
    store.entries[0].pubkey_len = 32UL;
    store.entries[0].key_type   = FD_X509_KEY_ED25519;

    uchar const * chain_der   [ 2 ] = { leaf, cross };
    ulong         chain_der_sz[ 2 ] = { leaf_len, cross_len };
    FD_TEST( fd_x509_verify_chain( chain_der, chain_der_sz, 2UL, &store, NULL, 0UL, TEST_NOW )
             ==FD_X509_VERIFY_OK );

    /* An unsupported SPKI in the unused cross-sign must also be ignored.
       The Ed25519 OID appears in the TBS signature algorithm first and in
       SPKI second; alter only that second occurrence. */
    uchar cross_unsupported[ 1024 ];
    memcpy( cross_unsupported, cross, cross_len );
    ulong oid_cnt = 0UL;
    for( ulong i=0UL; i+sizeof(oid_ed25519_alg)<=cross_len; i++ ) {
      if( !memcmp( cross_unsupported+i, oid_ed25519_alg, sizeof(oid_ed25519_alg) ) &&
          ++oid_cnt==2UL ) {
        cross_unsupported[ i+sizeof(oid_ed25519_alg)-1UL ] ^= 1U;
        break;
      }
    }
    FD_TEST( oid_cnt==2UL );
    fd_x509_cert_info_t unsupported_info;
    FD_TEST( fd_x509_cert_parse( cross_unsupported, cross_len, &unsupported_info )!=0 );
    chain_der[1] = cross_unsupported;
    FD_TEST( fd_x509_verify_chain( chain_der, chain_der_sz, 2UL, &store, NULL, 0UL, TEST_NOW )
             ==FD_X509_VERIFY_OK );
    chain_der[1] = cross;

    /* Without the anchor there is nothing to stop at, and the chain ends
       on an issuer we do not trust. */
    store.cnt = 0;
    FD_TEST( fd_x509_verify_chain( chain_der, chain_der_sz, 2UL, &store, NULL, 0UL, TEST_NOW )
             ==FD_X509_VERIFY_ERR_NO_TRUST_ANCHOR );
    store.cnt = 1;

    /* An expired cross-sign is off the path too, so it must not matter.
       Servers keep sending these long after they lapse. */
    uchar cross_exp[ 1024 ];
    {
      uchar tbs[ 1024 ];
      ulong tbs_len = mk_tbs( tbs, older_name, older_name_len,
                              root_name, root_name_len, pub_root,
                              "750101000000Z", FD_DER_TAG_UTC_TIME,
                              "191231235959Z", FD_DER_TAG_UTC_TIME,
                              exts, exts_len );
      uchar pub_old[ 32 ]; fd_ed25519_public_from_private( pub_old, prv_old, sha );
      uchar sig[ 64 ]; fd_ed25519_sign( sig, tbs, tbs_len, pub_old, prv_old, sha );
      chain_der   [ 1 ] = cross_exp;
      chain_der_sz[ 1 ] = wrap_cert( cross_exp, tbs, tbs_len, sig );
    }
    FD_TEST( fd_x509_verify_chain( chain_der, chain_der_sz, 2UL, &store, NULL, 0UL, TEST_NOW )
             ==FD_X509_VERIFY_OK );

    FD_LOG_INFO(( "OK: trailing cross-signature is ignored" ));
  }

  /* Test 14: Empty chain returns non-zero error */
  {
    fd_x509_ca_store_t store;
    memset( &store, 0, sizeof(store) );
    int err = fd_x509_verify_chain( NULL, NULL, 0UL, &store, "example.com", 11UL, TEST_NOW );
    FD_TEST( err!=FD_X509_VERIFY_OK );
    FD_LOG_INFO(( "OK: empty chain returns error" ));
  }

  /* Test 15: Chain with garbage cert returns FD_X509_VERIFY_ERR_PARSE */
  {
    uchar garbage[ 64 ];
    memset( garbage, 0xFF, 64 );
    uchar const * chain_der[ 1 ]    = { garbage };
    ulong         chain_der_sz[ 1 ] = { 64UL };
    fd_x509_ca_store_t store;
    memset( &store, 0, sizeof(store) );
    int err = fd_x509_verify_chain( chain_der, chain_der_sz, 1UL, &store, "example.com", 11UL, TEST_NOW );
    FD_TEST( err==FD_X509_VERIFY_ERR_PARSE );
    FD_LOG_INFO(( "OK: garbage cert returns ERR_PARSE" ));
  }

  /* Certificate size and path length are rejected before certificate
     parsing or signature verification. */
  {
    uchar one = 0U;
    uchar const * chain_der[ 1 ]    = { &one };
    ulong         chain_der_sz[ 1 ] = { FD_X509_CERT_SZ_MAX+1UL };
    fd_x509_ca_store_t store;
    memset( &store, 0, sizeof(store) );

    FD_TEST( fd_x509_verify_chain( chain_der, chain_der_sz, 1UL,
                                   &store, NULL, 0UL, TEST_NOW )
             ==FD_X509_VERIFY_ERR_CERT_TOO_LARGE );
    FD_TEST( fd_x509_verify_chain( NULL, NULL, FD_X509_CHAIN_MAX+1UL,
                                   &store, NULL, 0UL, TEST_NOW )
             ==FD_X509_VERIFY_ERR_CHAIN_TOO_LONG );
    FD_LOG_INFO(( "OK: certificate size and chain length bounds" ));
  }

  /* dNSName "example.com" GeneralName */
  static uchar const gn_example[] = {
    0x82, 0x0b, 'e','x','a','m','p','l','e','.','c','o','m'
  };

  /* Extension SEQUENCE holding only an OID -- no OCTET STRING value */
  static uchar const ext_truncated[] = {
    0x30, 0x05, 0x06, 0x03, 0x55, 0x1d, 0x0f
  };

  /* Test 16: SAN dNSName parsed out of a real DER certificate */
  {
    uchar exts[ 256 ]; ulong exts_len = mk_san( exts, gn_example, sizeof(gn_example) );
    uchar cert[ 1024 ]; ulong cert_len = mk_cert( cert, exts, exts_len );
    fd_x509_cert_info_t info;
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )==0 );
    FD_TEST( fd_x509_san_matches( &info, "example.com", 11UL )==1 );
    FD_LOG_INFO(( "OK: SAN dNSName parsed from DER" ));
  }

  /* Every entry must be a valid GeneralName, even after a matching dNSName. */
  {
    static struct {
      uchar value[ 4 ];
      ulong value_len;
    } const bad[] = {
      { { FD_DER_TAG_NULL,            0x00 },       2UL },
      { { FD_DER_TAG_CONTEXT(2),      0x00 },       2UL },
      { { FD_DER_TAG_CONTEXT_PRIM(7), 0x01, 0x7f }, 3UL },
      { { FD_DER_TAG_CONTEXT_PRIM(8), 0x01, 0x80 }, 3UL },
      { { FD_DER_TAG_CONTEXT_PRIM(2), 0x01, 0x80 }, 3UL },
      { { FD_DER_TAG_CONTEXT_PRIM(9), 0x00 },       2UL },
    };

    for( ulong i=0UL; i<sizeof(bad)/sizeof(bad[0]); i++ ) {
      uchar gn[ 64 ];
      memcpy( gn, gn_example, sizeof(gn_example) );
      memcpy( gn+sizeof(gn_example), bad[i].value, bad[i].value_len );
      ulong gn_len = sizeof(gn_example) + bad[i].value_len;
      uchar exts[ 256 ]; ulong exts_len = mk_san( exts, gn, gn_len );
      uchar cert[ 1024 ]; ulong cert_len = mk_cert( cert, exts, exts_len );
      fd_x509_cert_info_t info;
      FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )!=0 );

      set_san_info( &info, gn, "example.com", 11UL );
      memcpy( gn+info.san_general_names_len, bad[i].value, bad[i].value_len );
      info.san_general_names_len += bad[i].value_len;
      FD_TEST( !fd_x509_san_matches( &info, "example.com", 11UL ) );
    }
    FD_LOG_INFO(( "OK: malformed GeneralNames rejected" ));
  }

  /* GeneralNames is a non-empty SEQUENCE (SIZE (1..MAX)). */
  {
    uchar exts[ 256 ]; ulong exts_len = mk_san( exts, NULL, 0UL );
    uchar cert[ 1024 ]; ulong cert_len = mk_cert( cert, exts, exts_len );
    fd_x509_cert_info_t info;
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )!=0 );
    FD_LOG_INFO(( "OK: empty subjectAltName sequence rejected" ));
  }

  /* RFC 5280 requires a critical subjectAltName when subject is empty. */
  {
    uchar key[ 32 ] = {0};
    uchar san_val[ 64 ];
    ulong san_val_len = der_tlv( san_val, FD_DER_TAG_SEQUENCE,
                                 gn_example, sizeof(gn_example) );
    uchar exts[ 128 ];
    uchar cert[ 1024 ];
    fd_x509_cert_info_t info;

    ulong exts_len = mk_ext( exts, oid_san_tlv, sizeof(oid_san_tlv),
                             san_val, san_val_len );
    ulong cert_len = mk_cert_signed( cert, NULL, 0UL, NULL, 0UL,
                                     key, key, exts, exts_len );
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )!=0 );

    uchar const * chain_der[ 1 ] = { cert };
    ulong chain_der_sz[ 1 ] = { cert_len };
    fd_x509_ca_store_t store; memset( &store, 0, sizeof(store) );
    FD_TEST( fd_x509_verify_chain( chain_der, chain_der_sz, 1UL, &store,
                                   "example.com", 11UL, TEST_NOW )==FD_X509_VERIFY_ERR_PARSE );

    cert_len = mk_cert_signed( cert, NULL, 0UL, NULL, 0UL,
                               key, key, NULL, 0UL );
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )!=0 );

    exts_len = mk_ext_critical( exts, oid_san_tlv, sizeof(oid_san_tlv),
                                0xFF, san_val, san_val_len );
    cert_len = mk_cert_signed( cert, NULL, 0UL, NULL, 0UL,
                               key, key, exts, exts_len );
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )==0 );
    FD_LOG_INFO(( "OK: empty subject requires critical subjectAltName" ));
  }

  /* Matching walks all GeneralNames, including dNSNames beyond the
     four-entry inspection cache. */
  {
    static char const * const names[] = {
      "one.example", "two.example", "three.example",
      "four.example", "five.example", "target.example"
    };
    uchar gn[ 256 ]; ulong gn_len = 0UL;
    for( ulong i=0UL; i<sizeof(names)/sizeof(names[0]); i++ )
      gn_len += der_tlv( gn+gn_len, FD_DER_TAG_CONTEXT_PRIM(2),
                         (uchar const *)names[i], strlen( names[i] ) );

    uchar exts[ 512 ]; ulong exts_len = mk_san( exts, gn, gn_len );
    uchar cert[ 1024 ]; ulong cert_len = mk_cert( cert, exts, exts_len );
    fd_x509_cert_info_t info;
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )==0 );
    FD_TEST( fd_x509_san_matches( &info, "target.example", 14UL )==1 );
    FD_LOG_INFO(( "OK: SAN matching is not limited by cache size" ));
  }

  /* A Certificate SEQUENCE must consume the complete DER input. */
  {
    uchar cert[ 1024 ]; ulong cert_len = mk_cert( cert, NULL, 0UL );
    cert[ cert_len ] = 0x00;
    fd_x509_cert_info_t info;
    FD_TEST( fd_x509_cert_parse( cert, cert_len,     &info )==0 );
    FD_TEST( fd_x509_cert_parse( cert, cert_len+1UL, &info )!=0 );
    FD_LOG_INFO(( "OK: certificate DER suffix rejected" ));
  }

  /* The CertificateList vector must consume the complete TLS body. */
  {
    uchar cert[ 1024 ]; ulong cert_len = mk_cert( cert, NULL, 0UL );
    uchar msg[ 1200 ];
    ulong list_len = 3UL + cert_len + 2UL;
    ulong n = 0UL;
    msg[n++] = 0x00; /* empty certificate_request_context */
    msg[n++] = (uchar)( list_len >> 16 );
    msg[n++] = (uchar)( list_len >> 8  );
    msg[n++] = (uchar)( list_len       );
    msg[n++] = (uchar)( cert_len >> 16 );
    msg[n++] = (uchar)( cert_len >> 8  );
    msg[n++] = (uchar)( cert_len       );
    memcpy( msg+n, cert, cert_len ); n += cert_len;
    msg[n++] = 0x00; msg[n++] = 0x00; /* empty CertificateEntry extensions */

    fd_x509_ca_store_t store; memset( &store, 0, sizeof(store) );
    FD_TEST( fd_x509_verify_tls_cert_msg( msg, n, &store, NULL, 0UL, TEST_NOW )
             ==FD_X509_VERIFY_ERR_NO_TRUST_ANCHOR );
    msg[n] = 0x00;
    FD_TEST( fd_x509_verify_tls_cert_msg( msg, n+1UL, &store, NULL, 0UL, TEST_NOW )
             ==FD_X509_VERIFY_ERR_PARSE );

    /* A server Certificate has an empty request context, even when a
       non-empty context is otherwise correctly framed. */
    uchar bad_ctx[ 1200 ];
    bad_ctx[0] = 1U;
    bad_ctx[1] = 0x5aU;
    memcpy( bad_ctx+2UL, msg+1UL, n-1UL );
    FD_TEST( fd_x509_verify_tls_cert_msg( bad_ctx, n+1UL, &store, NULL, 0UL, TEST_NOW )
             ==FD_X509_VERIFY_ERR_PARSE );

    /* CertificateEntry extensions contain nested Extension records. */
    uchar ext_msg[ 1200 ]; memcpy( ext_msg, msg, n );
    ext_msg[1] = (uchar)( (list_len+4UL) >> 16 );
    ext_msg[2] = (uchar)( (list_len+4UL) >> 8  );
    ext_msg[3] = (uchar)(  list_len+4UL        );
    ext_msg[n-1UL] = 4U;
    ext_msg[n++] = 0xffU; ext_msg[n++] = 0U; /* unknown ExtensionType */
    ext_msg[n++] = 0U; ext_msg[n++] = 0U; /* empty extension_data */
    FD_TEST( fd_x509_verify_tls_cert_msg( ext_msg, n, &store, NULL, 0UL, TEST_NOW )
             ==FD_X509_VERIFY_ERR_NO_TRUST_ANCHOR );

    /* An extensions vector cannot contain a one-byte partial record. */
    memcpy( ext_msg, msg, n-4UL );
    ext_msg[1] = (uchar)( (list_len+1UL) >> 16 );
    ext_msg[2] = (uchar)( (list_len+1UL) >> 8  );
    ext_msg[3] = (uchar)(  list_len+1UL        );
    ext_msg[n-5UL] = 1U;
    ext_msg[n-4UL] = 0U;
    FD_TEST( fd_x509_verify_tls_cert_msg( ext_msg, n-3UL, &store, NULL, 0UL, TEST_NOW )
             ==FD_X509_VERIFY_ERR_PARSE );

    n -= 4UL;

    /* Truncated context/list prefixes and inconsistent nested lengths. */
    for( ulong sz=0UL; sz<4UL; sz++ )
      FD_TEST( fd_x509_verify_tls_cert_msg( msg, sz, &store, NULL, 0UL, TEST_NOW )
               ==FD_X509_VERIFY_ERR_PARSE );

    uchar bad[ 1200 ];
    memcpy( bad, msg, n );
    bad[0] = 1U; /* context claims one byte, leaving no full list prefix */
    FD_TEST( fd_x509_verify_tls_cert_msg( bad, 4UL, &store, NULL, 0UL, TEST_NOW )
             ==FD_X509_VERIFY_ERR_PARSE );

    memcpy( bad, msg, n );
    bad[6]++; /* cert_data length exceeds the list */
    FD_TEST( fd_x509_verify_tls_cert_msg( bad, n, &store, NULL, 0UL, TEST_NOW )
             ==FD_X509_VERIFY_ERR_PARSE );

    memcpy( bad, msg, n );
    bad[n-1UL] = 1U; /* CertificateEntry extensions claim one absent byte */
    FD_TEST( fd_x509_verify_tls_cert_msg( bad, n, &store, NULL, 0UL, TEST_NOW )
             ==FD_X509_VERIFY_ERR_PARSE );

    static uchar const empty_list[] = { 0x00, 0x00, 0x00, 0x00 };
    FD_TEST( fd_x509_verify_tls_cert_msg( empty_list, sizeof(empty_list),
                                         &store, NULL, 0UL, TEST_NOW )
             ==FD_X509_VERIFY_ERR_PARSE );

    /* An oversized cert_data length is rejected before touching its body. */
    uchar oversized[] = {
      0x00,
      0x00, 0x00, 0x03,
      0x01, 0x00, 0x01
    };
    FD_TEST( FD_X509_CERT_SZ_MAX==0x10000UL );
    FD_TEST( fd_x509_verify_tls_cert_msg( oversized, sizeof(oversized),
                                         &store, NULL, 0UL, TEST_NOW )
             ==FD_X509_VERIFY_ERR_CERT_TOO_LARGE );

    /* A ninth CertificateEntry exceeds the implementation path bound. */
    uchar long_msg[ 12000 ]; ulong long_n = 4UL;
    long_msg[0] = 0U;
    for( ulong i=0UL; i<FD_X509_CHAIN_MAX+1UL; i++ ) {
      long_msg[long_n++] = (uchar)( cert_len >> 16 );
      long_msg[long_n++] = (uchar)( cert_len >> 8  );
      long_msg[long_n++] = (uchar)( cert_len       );
      memcpy( long_msg+long_n, cert, cert_len ); long_n += cert_len;
      long_msg[long_n++] = 0U; long_msg[long_n++] = 0U;
    }
    ulong long_list_len = long_n-4UL;
    long_msg[1] = (uchar)( long_list_len >> 16 );
    long_msg[2] = (uchar)( long_list_len >> 8  );
    long_msg[3] = (uchar)( long_list_len       );
    FD_TEST( fd_x509_verify_tls_cert_msg( long_msg, long_n, &store, NULL, 0UL, TEST_NOW )
             ==FD_X509_VERIFY_ERR_CHAIN_TOO_LONG );
    FD_LOG_INFO(( "OK: TLS Certificate body suffix rejected" ));
  }

  /* ECDSA r and s INTEGERs must be positive and DER-minimal. */
  {
    uchar raw[ 64 ];
    static uchar const valid[] = {
      0x30,0x08, 0x02,0x02,0x00,0x80, 0x02,0x02,0x00,0x81
    };
    static uchar const negative[] = {
      0x30,0x06, 0x02,0x01,0x80, 0x02,0x01,0x01
    };
    static uchar const non_minimal[] = {
      0x30,0x07, 0x02,0x02,0x00,0x01, 0x02,0x01,0x01
    };
    static uchar const trailing_field[] = {
      0x30,0x08, 0x02,0x01,0x01, 0x02,0x01,0x01, 0x05,0x00
    };
    static uchar const trailing_suffix[] = {
      0x30,0x06, 0x02,0x01,0x01, 0x02,0x01,0x01, 0x00
    };
    static uchar const non_minimal_len[] = {
      0x30,0x81,0x06, 0x02,0x01,0x01, 0x02,0x01,0x01
    };
    FD_TEST( fd_x509_decode_ecdsa_sig( valid,       sizeof(valid),       raw, 32UL )==0 );
    FD_TEST( fd_x509_decode_ecdsa_sig( negative,    sizeof(negative),    raw, 32UL )!=0 );
    FD_TEST( fd_x509_decode_ecdsa_sig( non_minimal, sizeof(non_minimal), raw, 32UL )!=0 );
    FD_TEST( fd_x509_decode_ecdsa_sig( trailing_field,  sizeof(trailing_field),  raw, 32UL )!=0 );
    FD_TEST( fd_x509_decode_ecdsa_sig( trailing_suffix, sizeof(trailing_suffix), raw, 32UL )!=0 );
    FD_TEST( fd_x509_decode_ecdsa_sig( non_minimal_len, sizeof(non_minimal_len), raw, 32UL )!=0 );
    FD_TEST( fd_x509_decode_ecdsa_sig( NULL, 0UL, raw, 32UL )!=0 );
    FD_TEST( fd_x509_decode_ecdsa_sig( valid, sizeof(valid), NULL, 32UL )!=0 );
    FD_LOG_INFO(( "OK: malformed ECDSA INTEGERs rejected" ));
  }

  /* AlgorithmIdentifiers and Extension sequences require exact content. */
  {
    uchar cert[ 1200 ]; ulong cert_len = mk_cert( cert, NULL, 0UL );
    ulong oid_cnt = 0UL; ulong spki_oid_off = 0UL; ulong outer_oid_off = 0UL;
    for( ulong i=0UL; i+sizeof(oid_ed25519_alg)<=cert_len; i++ ) {
      if( !memcmp( cert+i, oid_ed25519_alg, sizeof(oid_ed25519_alg) ) ) {
        oid_cnt++;
        if( oid_cnt==2UL ) spki_oid_off = i;
        if( oid_cnt==3UL ) outer_oid_off = i;
      }
    }
    FD_TEST( oid_cnt==3UL );

    /* Ed25519 parameters must be absent.  Insert NULL after the SPKI OID
       and grow each enclosing length without otherwise changing the cert. */
    uchar bad[ 1200 ]; memcpy( bad, cert, cert_len );
    ulong insert_off = spki_oid_off + sizeof(oid_ed25519_alg);
    memmove( bad+insert_off+2UL, bad+insert_off, cert_len-insert_off );
    bad[insert_off] = FD_DER_TAG_NULL; bad[insert_off+1UL] = 0U;
    uchar * tbs  = bad + der_hdr_sz( bad );
    uchar * spki = bad + spki_oid_off - 4UL;
    FD_TEST( spki[0]==FD_DER_TAG_SEQUENCE && spki[2]==FD_DER_TAG_SEQUENCE );
    der_bump_len( spki+2UL, 2UL );
    der_bump_len( spki,     2UL );
    der_bump_len( tbs,      2UL );
    der_bump_len( bad,      2UL );
    fd_x509_cert_info_t info;
    FD_TEST( fd_x509_cert_parse( bad, cert_len+2UL, &info )!=0 );

    /* Outer and TBSCertificate signatureAlgorithm fields must match. */
    memcpy( bad, cert, cert_len );
    bad[ outer_oid_off+sizeof(oid_ed25519_alg)-1UL ] ^= 1U;
    FD_TEST( fd_x509_cert_parse( bad, cert_len, &info )!=0 );

    /* No fields may follow extnValue inside Extension. */
    uchar gn[ 32 ]; ulong gn_len = der_tlv( gn, FD_DER_TAG_CONTEXT_PRIM(2),
                                            (uchar const *)"example.com", 11UL );
    uchar san_val[ 64 ]; ulong san_val_len = der_tlv( san_val, FD_DER_TAG_SEQUENCE, gn, gn_len );
    uchar ext_body[ 128 ]; ulong ext_body_len = 0UL;
    memcpy( ext_body, oid_san_tlv, sizeof(oid_san_tlv) ); ext_body_len += sizeof(oid_san_tlv);
    ext_body_len += der_tlv( ext_body+ext_body_len, FD_DER_TAG_OCTET_STRING, san_val, san_val_len );
    ext_body_len += der_tlv( ext_body+ext_body_len, FD_DER_TAG_NULL, NULL, 0UL );
    uchar exts[ 160 ]; ulong exts_len = der_tlv( exts, FD_DER_TAG_SEQUENCE, ext_body, ext_body_len );
    cert_len = mk_cert( cert, exts, exts_len );
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )!=0 );

    FD_LOG_INFO(( "OK: AlgorithmIdentifier and Extension content is exact" ));
  }

  /* TBSCertificate has at most one optional [3] Extensions field. */
  {
    uchar gn[ 32 ]; ulong gn_len = der_tlv( gn, FD_DER_TAG_CONTEXT_PRIM(2),
                                            (uchar const *)"example.com", 11UL );
    uchar exts[ 128 ]; ulong exts_len = mk_san( exts, gn, gn_len );
    uchar zero[ 64 ]; memset( zero, 0, sizeof(zero) );
    uchar tbs[ 1200 ];
    ulong tbs_len = mk_tbs( tbs, NULL, 0UL, NULL, 0UL, zero,
                            "750101000000Z", FD_DER_TAG_UTC_TIME,
                            "40960101000000Z", FD_DER_TAG_GENERALIZED_TIME,
                            exts, exts_len );

    uchar ext_seq[ 160 ]; ulong ext_seq_len = der_tlv( ext_seq, FD_DER_TAG_SEQUENCE,
                                                       exts, exts_len );
    uchar duplicate[ 192 ]; ulong duplicate_len = der_tlv( duplicate, FD_DER_TAG_CONTEXT(3),
                                                           ext_seq, ext_seq_len );
    if( !(tbs[1] & 0x80U) && (ulong)tbs[1]+duplicate_len>=128UL ) {
      ulong old_content_len = tbs[1];
      memmove( tbs+3UL, tbs+2UL, old_content_len );
      tbs[1] = 0x81U;
      tbs[2] = (uchar)(old_content_len+duplicate_len);
      tbs_len++;
    } else {
      der_bump_len( tbs, duplicate_len );
    }
    memcpy( tbs+tbs_len, duplicate, duplicate_len );
    tbs_len += duplicate_len;

    uchar cert[ 1400 ]; ulong cert_len = wrap_cert( cert, tbs, tbs_len, zero );
    fd_x509_cert_info_t info;
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )!=0 );
    FD_LOG_INFO(( "OK: duplicate Extensions containers rejected" ));
  }

  /* Distinguished names reject invalid inputs before comparing bytes. */
  {
    uchar empty_name[]      = { FD_DER_TAG_SEQUENCE, 0x00 };
    uchar truncated_name[]  = { FD_DER_TAG_SEQUENCE };
    uchar nonminimal_name[] = { FD_DER_TAG_SEQUENCE, 0x81, 0x00 };

    FD_TEST( !fd_x509_name_equal( NULL, 0UL, NULL, 0UL ) );
    FD_TEST( !fd_x509_name_equal( NULL, 0UL, empty_name, sizeof(empty_name) ) );
    FD_TEST( !fd_x509_name_equal( empty_name, sizeof(empty_name), NULL, 0UL ) );
    FD_TEST( !fd_x509_name_equal( NULL, 1UL, empty_name, sizeof(empty_name) ) );
    FD_TEST( !fd_x509_name_equal( empty_name, sizeof(empty_name), NULL, 1UL ) );
    FD_TEST( !fd_x509_name_equal( empty_name, 0UL, empty_name, 0UL ) );
    FD_TEST( !fd_x509_name_equal( truncated_name, sizeof(truncated_name),
                                  truncated_name, sizeof(truncated_name) ) );
    FD_TEST( !fd_x509_name_equal( nonminimal_name, sizeof(nonminimal_name),
                                  nonminimal_name, sizeof(nonminimal_name) ) );
    FD_TEST( fd_x509_name_equal( empty_name, sizeof(empty_name),
                                 empty_name, sizeof(empty_name) ) );

    FD_LOG_INFO(( "OK: distinguished-name input validation" ));
  }

  /* Distinguished names compare using normalized string values and
     unordered AttributeTypeAndValue sets, not raw DER bytes. */
  {
    uchar utf8_name[ 96 ]; ulong utf8_name_len = mk_name( utf8_name, "  Example   Root  " );

    uchar atv[ 128 ];
    memcpy( atv, oid_cn_tlv, sizeof(oid_cn_tlv) );
    ulong atv_len = sizeof(oid_cn_tlv);
    atv_len += der_tlv( atv+atv_len, FD_DER_TAG_PRINTABLE_STR,
                        (uchar const *)"example root", 12UL );
    uchar rdn[ 160 ]; ulong rdn_len = der_tlv( rdn, FD_DER_TAG_SEQUENCE, atv, atv_len );
    uchar set[ 192 ]; ulong set_len = der_tlv( set, FD_DER_TAG_SET, rdn, rdn_len );
    uchar printable_name[ 224 ];
    ulong printable_name_len = der_tlv( printable_name, FD_DER_TAG_SEQUENCE, set, set_len );

    FD_TEST( memcmp( utf8_name, printable_name,
                     fd_ulong_min( utf8_name_len, printable_name_len ) ) );
    FD_TEST( fd_x509_name_equal( utf8_name, utf8_name_len,
                                printable_name, printable_name_len ) );

    fd_x509_ca_store_t store; memset( &store, 0, sizeof(store) );
    store.cnt = 1UL;
    memcpy( store.entries[0].subject, printable_name, printable_name_len );
    store.entries[0].subject_len = printable_name_len;
    ulong idx = 0UL;
    FD_TEST( fd_x509_ca_store_find_next( &store, utf8_name, utf8_name_len, &idx )==&store.entries[0] );

    FD_LOG_INFO(( "OK: distinguished-name normalization" ));
  }

  /* Test 17: Malformed extension AFTER the SAN must fail the whole parse
     (the recorded name must not survive a partial extension walk) */
  {
    uchar exts[ 256 ]; ulong exts_len = mk_san( exts, gn_example, sizeof(gn_example) );
    memcpy( exts+exts_len, ext_truncated, sizeof(ext_truncated) );
    exts_len += sizeof(ext_truncated);
    uchar cert[ 1024 ]; ulong cert_len = mk_cert( cert, exts, exts_len );
    fd_x509_cert_info_t info;
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )!=0 );
    FD_LOG_INFO(( "OK: malformed extension after SAN fails parse" ));
  }

  /* Test 18: Malformed extension BEFORE the SAN fails the same way */
  {
    uchar exts[ 256 ]; ulong exts_len = 0UL;
    memcpy( exts, ext_truncated, sizeof(ext_truncated) ); exts_len += sizeof(ext_truncated);
    exts_len += mk_san( exts+exts_len, gn_example, sizeof(gn_example) );
    uchar cert[ 1024 ]; ulong cert_len = mk_cert( cert, exts, exts_len );
    fd_x509_cert_info_t info;
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )!=0 );
    FD_LOG_INFO(( "OK: malformed extension before SAN fails parse" ));
  }

  /* Test 19: Truncated GeneralName after a good one must fail the parse */
  {
    uchar gn[ 64 ]; ulong gn_len = 0UL;
    memcpy( gn, gn_example, sizeof(gn_example) ); gn_len += sizeof(gn_example);
    gn[ gn_len++ ] = 0x82;  /* tag with no length byte */
    uchar exts[ 256 ]; ulong exts_len = mk_san( exts, gn, gn_len );
    uchar cert[ 1024 ]; ulong cert_len = mk_cert( cert, exts, exts_len );
    fd_x509_cert_info_t info;
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )!=0 );
    FD_LOG_INFO(( "OK: truncated GeneralName fails parse" ));
  }

  /* Test 20: A keyUsage extension after the SAN still parses, and the SAN
     is still reachable behind it */
  {
    uchar exts[ 256 ]; ulong exts_len = mk_san( exts, gn_example, sizeof(gn_example) );
    static uchar const oid_key_usage[] = { 0x06, 0x03, 0x55, 0x1d, 0x0f };
    static uchar const ku_val[] = { 0x03, 0x02, 0x05, 0xa0 };
    exts_len += mk_ext( exts+exts_len, oid_key_usage, sizeof(oid_key_usage),
                        ku_val, sizeof(ku_val) );
    uchar cert[ 1024 ]; ulong cert_len = mk_cert( cert, exts, exts_len );
    fd_x509_cert_info_t info;
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )==0 );
    FD_TEST( fd_x509_san_matches( &info, "example.com", 11UL )==1 );
    FD_TEST( info.has_key_usage==1 );
    FD_TEST( info.key_usage==(FD_X509_KU_DIGITAL_SIGNATURE|FD_X509_KU_KEY_ENCIPHERMENT) );
    FD_LOG_INFO(( "OK: keyUsage extension after SAN still parses" ));
  }

  /* Test 21: cA=TRUE followed by a malformed extension must not be
     smuggled through (fd_x509_ca_store_load gates on is_ca) */
  {
    static uchar const bc_ca_true[] = { 0x30, 0x03, 0x01, 0x01, 0xFF };
    uchar exts[ 256 ];
    ulong exts_len = mk_ext_critical( exts, oid_bc_tlv, sizeof(oid_bc_tlv),
                                      0xFF, bc_ca_true, sizeof(bc_ca_true) );
    memcpy( exts+exts_len, ext_truncated, sizeof(ext_truncated) );
    exts_len += sizeof(ext_truncated);
    uchar cert[ 1024 ]; ulong cert_len = mk_cert( cert, exts, exts_len );
    fd_x509_cert_info_t info;
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )!=0 );
    FD_LOG_INFO(( "OK: cA=TRUE with malformed extension tail fails parse" ));
  }

  /* Test 21a: Unknown critical extensions must fail certificate parsing.
     nameConstraints is intentionally unsupported by this parser. */
  {
    static uchar const oid_name_constraints[] = { 0x06, 0x03, 0x55, 0x1d, 0x1e };
    static uchar const empty_sequence[]       = { 0x30, 0x00 };

    uchar exts[ 256 ];
    uchar cert[ 1024 ];
    fd_x509_cert_info_t info;

    /* An unknown non-critical extension may be ignored. */
    ulong exts_len = mk_ext( exts, oid_name_constraints, sizeof(oid_name_constraints),
                             empty_sequence, sizeof(empty_sequence) );
    ulong cert_len = mk_cert( cert, exts, exts_len );
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )==0 );

    /* Explicit FALSE is forbidden because critical DEFAULTs to FALSE. */
    exts_len = mk_ext_critical( exts, oid_name_constraints, sizeof(oid_name_constraints),
                                0x00, empty_sequence, sizeof(empty_sequence) );
    cert_len = mk_cert( cert, exts, exts_len );
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )!=0 );

    /* A critical unsupported nameConstraints extension must be rejected. */
    exts_len = mk_ext_critical( exts, oid_name_constraints, sizeof(oid_name_constraints),
                                0xFF, empty_sequence, sizeof(empty_sequence) );
    cert_len = mk_cert( cert, exts, exts_len );
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )!=0 );

    /* Critical extensions implemented by this parser remain accepted. */
    uchar san_val[ 64 ];
    ulong san_val_len = der_tlv( san_val, FD_DER_TAG_SEQUENCE,
                                 gn_example, sizeof(gn_example) );
    exts_len = mk_ext_critical( exts, oid_san_tlv, sizeof(oid_san_tlv),
                                0xFF, san_val, san_val_len );
    cert_len = mk_cert( cert, exts, exts_len );
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )==0 );
    FD_TEST( fd_x509_san_matches( &info, "example.com", 11UL )==1 );

    FD_LOG_INFO(( "OK: unsupported critical extensions fail parse" ));
  }

  /* Test 21b: basicConstraints value must be a well-formed BasicConstraints */
  {
    /* Each case is the raw extnValue (a BasicConstraints SEQUENCE, possibly
       with trailing bytes inside the OCTET STRING). */
    static struct {
      uchar val[ 12 ]; ulong val_len;
      int ok; int is_ca; int has_path_len; ulong path_len;
    } const cases[] = {
      /* cA=TRUE followed by a truncated INTEGER tag */
      { { 0x30, 0x05, 0x01, 0x01, 0xFF, 0x02 },             6UL, 0, 0, 0, 0UL },
      /* cA=TRUE with a trailing byte after the SEQUENCE */
      { { 0x30, 0x03, 0x01, 0x01, 0xFF, 0x00 },             6UL, 0, 0, 0, 0UL },
      /* cA=TRUE, pathLenConstraint=0 */
      { { 0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00 }, 8UL, 1, 1, 1, 0UL },
      /* cA=TRUE, pathLenConstraint=128 (positive sign padding) */
      { { 0x30, 0x07, 0x01, 0x01, 0xFF, 0x02, 0x02, 0x00, 0x80 }, 9UL, 1, 1, 1, 128UL },
      /* cA=TRUE */
      { { 0x30, 0x03, 0x01, 0x01, 0xFF },                   5UL, 1, 1, 0, 0UL },
      /* cA=FALSE is forbidden because cA DEFAULTs to FALSE */
      { { 0x30, 0x03, 0x01, 0x01, 0x00 },                   5UL, 0, 0, 0, 0UL },
      /* cA absent (DEFAULT FALSE) */
      { { 0x30, 0x00 },                                     2UL, 1, 0, 0, 0UL },
      /* pathLenConstraint is forbidden when cA is absent */
      { { 0x30, 0x03, 0x02, 0x01, 0x00 },                   5UL, 0, 0, 0, 0UL },
      /* two byte BOOLEAN */
      { { 0x30, 0x04, 0x01, 0x02, 0xFF, 0xFF },             6UL, 0, 0, 0, 0UL },
      /* non-DER BOOLEAN TRUE */
      { { 0x30, 0x03, 0x01, 0x01, 0x01 },                   5UL, 0, 0, 0, 0UL },
      /* pathLenConstraint must not be negative */
      { { 0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0xFF }, 8UL, 0, 0, 0, 0UL },
      /* INTEGER content must not be empty */
      { { 0x30, 0x05, 0x01, 0x01, 0xFF, 0x02, 0x00 },       7UL, 0, 0, 0, 0UL },
      /* DER forbids redundant positive sign padding */
      { { 0x30, 0x07, 0x01, 0x01, 0xFF, 0x02, 0x02, 0x00, 0x00 }, 9UL, 0, 0, 0, 0UL },
    };
    for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
      uchar exts[ 256 ];
      ulong exts_len = mk_ext_critical( exts, oid_bc_tlv, sizeof(oid_bc_tlv),
                                        0xFF, cases[i].val, cases[i].val_len );
      exts_len += mk_san( exts+exts_len, gn_example, sizeof(gn_example) );
      uchar cert[ 1024 ]; ulong cert_len = mk_cert( cert, exts, exts_len );
      fd_x509_cert_info_t info;
      int err = fd_x509_cert_parse( cert, cert_len, &info );
      if( cases[i].ok ) {
        FD_TEST( err==0 );
        FD_TEST( info.is_ca==cases[i].is_ca );
        FD_TEST( info.has_basic_constraints==1 );
        FD_TEST( info.has_path_len_constraint==cases[i].has_path_len );
        FD_TEST( info.path_len_constraint==cases[i].path_len );
        FD_TEST( fd_x509_san_matches( &info, "example.com", 11UL )==1 );
      } else {
        FD_TEST( err!=0 );
      }
    }

    /* cA=TRUE requires critical basicConstraints. */
    uchar exts[ 256 ];
    ulong exts_len = mk_ext( exts, oid_bc_tlv, sizeof(oid_bc_tlv),
                             bc_ca_true_val, sizeof(bc_ca_true_val) );
    uchar cert[ 1024 ]; ulong cert_len = mk_cert( cert, exts, exts_len );
    fd_x509_cert_info_t info;
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )!=0 );

    /* A certificate must not contain basicConstraints twice. */
    exts_len  = mk_ext_critical( exts, oid_bc_tlv, sizeof(oid_bc_tlv),
                                 0xFF, bc_ca_true_val, sizeof(bc_ca_true_val) );
    exts_len += mk_ext_critical( exts+exts_len, oid_bc_tlv, sizeof(oid_bc_tlv),
                                 0xFF, bc_ca_true_val, sizeof(bc_ca_true_val) );
    cert_len = mk_cert( cert, exts, exts_len );
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )!=0 );

    FD_LOG_INFO(( "OK: basicConstraints parsed strictly" ));
  }

  /* Test 22: Wildcard must consume a non-empty label */
  {
    fd_x509_cert_info_t info; uchar gn[ 32 ];
    set_san_info( &info, gn, "*.example.com", 13UL );
    FD_TEST( fd_x509_san_matches( &info, ".example.com", 12UL )==0 );
    FD_TEST( fd_x509_san_matches( &info, "x.example.com", 13UL )==1 );
    FD_LOG_INFO(( "OK: wildcard rejects empty leftmost label" ));
  }

  /* Test 23: Wildcard tail must span at least two labels */
  {
    fd_x509_cert_info_t info; uchar gn[ 32 ];
    set_san_info( &info, gn, "*.com", 5UL );
    FD_TEST( fd_x509_san_matches( &info, "foo.com", 7UL )==0 );
    set_san_info( &info, gn, "*.", 2UL );
    FD_TEST( fd_x509_san_matches( &info, "a.", 2UL )==0 );
    FD_TEST( fd_x509_san_matches( &info, "a", 1UL )==0 );
    FD_LOG_INFO(( "OK: wildcard requires a two-label tail" ));
  }

  /* Test 24: Malformed SAN patterns never match */
  {
    fd_x509_cert_info_t info; uchar gn[ 32 ];
    set_san_info( &info, gn, ".example.com", 12UL );
    FD_TEST( fd_x509_san_matches( &info, ".example.com", 12UL )==0 );
    FD_LOG_INFO(( "OK: SAN pattern with empty leading label never matches" ));
  }

  /* Test 25: A terminal root dot is ignored on reference names */
  {
    fd_x509_cert_info_t info; uchar gn[ 32 ];
    set_san_info( &info, gn, "example.com", 11UL );
    FD_TEST( fd_x509_san_matches( &info, "example.com.", 12UL )==1 );
    set_san_info( &info, gn, "*.example.com", 13UL );
    FD_TEST( fd_x509_san_matches( &info, "www.example.com.", 16UL )==1 );
    FD_LOG_INFO(( "OK: terminal root dot normalized" ));
  }

  /* Test 26: Malformed hostnames never match */
  {
    fd_x509_cert_info_t info; uchar gn[ 32 ];
    set_san_info( &info, gn, "example.com", 11UL );
    FD_TEST( fd_x509_san_matches( &info, ".", 1UL )==0 );
    FD_TEST( fd_x509_san_matches( &info, "example.com..", 13UL )==0 );
    FD_TEST( fd_x509_san_matches( &info, "example..com", 12UL )==0 );
    FD_TEST( fd_x509_san_matches( &info, "example.com\0", 12UL )==0 );
    FD_TEST( fd_x509_san_matches( &info, "example.co\xffm", 12UL )==0 );
    FD_LOG_INFO(( "OK: malformed hostnames rejected" ));
  }

  /* Test 27: Exact match folds ASCII case */
  {
    fd_x509_cert_info_t info; uchar gn[ 32 ];
    set_san_info( &info, gn, "example.com", 11UL );
    FD_TEST( fd_x509_san_matches( &info, "EXAMPLE.COM", 11UL )==1 );
    FD_LOG_INFO(( "OK: exact match is case-insensitive" ));
  }

  /* Test 28: Oversized labels and names are rejected */
  {
    char host[ 320 ];
    memset( host, 'a', sizeof(host) );
    fd_x509_cert_info_t info; uchar gn[ 320 ];

    set_san_info( &info, gn, host, 64UL );
    FD_TEST( fd_x509_san_matches( &info, host, 64UL )==0 );  /* 64-char label */

    set_san_info( &info, gn, host, 254UL );
    FD_TEST( fd_x509_san_matches( &info, host, 254UL )==0 ); /* >253-byte name */

    FD_LOG_INFO(( "OK: oversized labels and names rejected" ));
  }

  /* Validity period checks.  The chain is anchored against an empty
     store, so a cert that clears the time gate fails later with
     NO_TRUST_ANCHOR; that is what proves the gate was cleared. */
  {
    fd_x509_ca_store_t store; store.cnt = 0;

    static struct {
      char const * not_before; uchar nb_tag;
      char const * not_after;  uchar na_tag;
      int          expected;
      char const * desc;
    } const cases[] = {
      { "750101000000Z",   FD_DER_TAG_UTC_TIME,
        "191231235959Z",   FD_DER_TAG_UTC_TIME,
        FD_X509_VERIFY_ERR_EXPIRED,          "expired one second ago" },
      { "200101000001Z",   FD_DER_TAG_UTC_TIME,
        "40960101000000Z", FD_DER_TAG_GENERALIZED_TIME,
        FD_X509_VERIFY_ERR_NOT_YET_VALID,    "valid in one second"    },
      { "200101000000Z",   FD_DER_TAG_UTC_TIME,
        "40960101000000Z", FD_DER_TAG_GENERALIZED_TIME,
        FD_X509_VERIFY_ERR_NO_TRUST_ANCHOR,  "notBefore == now"       },
      { "750101000000Z",   FD_DER_TAG_UTC_TIME,
        "200101000000Z",   FD_DER_TAG_UTC_TIME,
        FD_X509_VERIFY_ERR_NO_TRUST_ANCHOR,  "notAfter == now"        },
      { "75010100000XZ",   FD_DER_TAG_UTC_TIME,
        "40960101000000Z", FD_DER_TAG_GENERALIZED_TIME,
        FD_X509_VERIFY_ERR_TIME_PARSE,       "malformed notBefore"    },
      { "750101000000+0100", FD_DER_TAG_UTC_TIME,
        "40960101000000Z", FD_DER_TAG_GENERALIZED_TIME,
        FD_X509_VERIFY_ERR_TIME_PARSE,       "notBefore with offset"  },
    };

    for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
      uchar cert[ 1024 ];
      ulong cert_len = mk_cert_validity( cert,
                                         cases[i].not_before, cases[i].nb_tag,
                                         cases[i].not_after,  cases[i].na_tag,
                                         NULL, 0UL );
      uchar const * chain_der   [ 1 ] = { cert };
      ulong         chain_der_sz[ 1 ] = { cert_len };
      int err = fd_x509_verify_chain( chain_der, chain_der_sz, 1UL, &store, NULL, 0UL, TEST_NOW );
      if( FD_UNLIKELY( err!=cases[i].expected ) ) {
        FD_LOG_ERR(( "case %lu (%s): got %i, expected %i", i, cases[i].desc, err, cases[i].expected ));
      }
    }

    /* An expired intermediate must fail even behind a valid leaf */
    {
      uchar leaf[ 1024 ]; ulong leaf_len = mk_cert( leaf, NULL, 0UL );
      uchar ca  [ 1024 ];
      ulong ca_len = mk_cert_validity( ca,
                                       "750101000000Z", FD_DER_TAG_UTC_TIME,
                                       "191231235959Z", FD_DER_TAG_UTC_TIME,
                                       NULL, 0UL );
      uchar const * chain_der   [ 2 ] = { leaf, ca };
      ulong         chain_der_sz[ 2 ] = { leaf_len, ca_len };
      FD_TEST( fd_x509_verify_chain( chain_der, chain_der_sz, 2UL, &store, NULL, 0UL, TEST_NOW )
               ==FD_X509_VERIFY_ERR_EXPIRED );
    }

    /* Expiry is checked before the hostname, so it wins */
    {
      uchar gn[ 32 ]; ulong gn_len = der_tlv( gn, FD_DER_TAG_CONTEXT_PRIM(2), (uchar const *)"example.com", 11UL );
      uchar exts[ 128 ]; ulong exts_len = mk_san( exts, gn, gn_len );
      uchar cert[ 1024 ];
      ulong cert_len = mk_cert_validity( cert,
                                         "750101000000Z", FD_DER_TAG_UTC_TIME,
                                         "191231235959Z", FD_DER_TAG_UTC_TIME,
                                         exts, exts_len );
      uchar const * chain_der   [ 1 ] = { cert };
      ulong         chain_der_sz[ 1 ] = { cert_len };
      FD_TEST( fd_x509_verify_chain( chain_der, chain_der_sz, 1UL, &store, "other.com", 9UL, TEST_NOW )
               ==FD_X509_VERIFY_ERR_EXPIRED );
    }

    FD_LOG_INFO(( "OK: validity period checks" ));
  }


  /* Test 22: keyUsage BIT STRING parsing.  The extnValue is the whole
     BIT STRING TLV, so these vectors exercise the tag, the unused-bits
     octet and DER NamedBitList minimality. */
  {
    static struct {
      char const * desc;
      uchar        val[ 8 ];
      ulong        val_len;
      int          ok;
      ushort       ku;
    } const cases[] = {
      { "digitalSignature|keyEncipherment", { 0x03,0x02,0x05,0xA0           }, 4UL, 1, 0xA000 },
      { "keyCertSign|cRLSign",              { 0x03,0x02,0x01,0x06           }, 4UL, 1, 0x0600 },
      { "digitalSignature only",            { 0x03,0x02,0x07,0x80           }, 4UL, 1, 0x8000 },
      { "decipherOnly needs a 2nd octet",   { 0x03,0x03,0x07,0x80,0x80      }, 5UL, 1, 0x8080 },
      { "empty BIT STRING",                 { 0x03,0x01,0x00                }, 3UL, 0, 0      },
      { "empty BIT STRING, unused!=0",      { 0x03,0x01,0x05                }, 3UL, 0, 0      },
      { "unused bits > 7",                  { 0x03,0x02,0x08,0x80           }, 4UL, 0, 0      },
      { "unused bits not zeroed",           { 0x03,0x02,0x05,0xA1           }, 4UL, 0, 0      },
      { "unused count not minimal",         { 0x03,0x02,0x00,0x80           }, 4UL, 0, 0      },
      { "non-minimal NamedBitList",         { 0x03,0x03,0x00,0xA0,0x00      }, 5UL, 0, 0      },
      { "missing unused-bits octet",        { 0x03,0x00                     }, 2UL, 0, 0      },
      { "more than two octets of bits",     { 0x03,0x04,0x00,0x80,0x00,0x01 }, 6UL, 0, 0      },
      { "OCTET STRING, not BIT STRING",     { 0x04,0x02,0x05,0xA0           }, 4UL, 0, 0      },
      { "trailing bytes in extnValue",      { 0x03,0x02,0x05,0xA0,0x05,0x00 }, 6UL, 0, 0      },
    };

    for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
      uchar exts[ 256 ];
      ulong exts_len = mk_ext( exts, oid_ku_tlv, sizeof(oid_ku_tlv),
                               cases[i].val, cases[i].val_len );
      uchar cert[ 1024 ]; ulong cert_len = mk_cert( cert, exts, exts_len );
      fd_x509_cert_info_t info;
      int rc = fd_x509_cert_parse( cert, cert_len, &info );
      if( cases[i].ok ) {
        FD_TEST( rc==0 );
        FD_TEST( info.has_key_usage==1 );
        FD_TEST( info.key_usage==cases[i].ku );
      } else {
        FD_TEST( rc!=0 );
      }
    }

    /* Absent keyUsage is unconstrained */
    {
      uchar cert[ 1024 ]; ulong cert_len = mk_cert( cert, NULL, 0UL );
      fd_x509_cert_info_t info;
      FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )==0 );
      FD_TEST( info.has_key_usage==0 );
      FD_TEST( info.key_usage==0 );
    }

    /* RFC 5280 Section 4.2 permits at most one instance of an extension */
    {
      static uchar const ku_val[] = { 0x03, 0x02, 0x07, 0x80 };
      uchar exts[ 256 ];
      ulong exts_len  = mk_ext( exts, oid_ku_tlv, sizeof(oid_ku_tlv), ku_val, sizeof(ku_val) );
            exts_len += mk_ext( exts+exts_len, oid_ku_tlv, sizeof(oid_ku_tlv), ku_val, sizeof(ku_val) );
      uchar cert[ 1024 ]; ulong cert_len = mk_cert( cert, exts, exts_len );
      fd_x509_cert_info_t info;
      FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )!=0 );
    }

    FD_LOG_INFO(( "OK: keyUsage parsing" ));
  }

  /* Test 23: extKeyUsage parsing.  Unrecognized key purposes are ignored,
     but the extension must still be a well-formed SEQUENCE OF OID. */
  {
    static struct {
      char const * desc;
      uchar        val[ 24 ];
      ulong        val_len;
      int          ok;
      ushort       eku;
    } const cases[] = {
      { "serverAuth",
        { 0x30,0x0A, 0x06,0x08,0x2b,0x06,0x01,0x05,0x05,0x07,0x03,0x01 }, 12UL, 1,
        FD_X509_EKU_SERVER_AUTH },
      { "anyExtendedKeyUsage",
        { 0x30,0x06, 0x06,0x04,0x55,0x1d,0x25,0x00 }, 8UL, 1, FD_X509_EKU_ANY },
      { "clientAuth only",
        { 0x30,0x0A, 0x06,0x08,0x2b,0x06,0x01,0x05,0x05,0x07,0x03,0x02 }, 12UL, 1, 0 },
      { "serverAuth and clientAuth",
        { 0x30,0x14, 0x06,0x08,0x2b,0x06,0x01,0x05,0x05,0x07,0x03,0x01,
                     0x06,0x08,0x2b,0x06,0x01,0x05,0x05,0x07,0x03,0x02 }, 22UL, 1,
        FD_X509_EKU_SERVER_AUTH },
      { "OCSPSigning only",
        { 0x30,0x0A, 0x06,0x08,0x2b,0x06,0x01,0x05,0x05,0x07,0x03,0x09 }, 12UL, 1, 0 },
      { "empty SEQUENCE violates SIZE (1..MAX)",
        { 0x30,0x00 }, 2UL, 0, 0 },
      { "KeyPurposeId is not an OID",
        { 0x30,0x03, 0x02,0x01,0x01 }, 5UL, 0, 0 },
      { "truncated OID",
        { 0x30,0x03, 0x06,0x08,0x2b }, 5UL, 0, 0 },
      { "empty OID",
        { 0x30,0x02, 0x06,0x00 }, 4UL, 0, 0 },
      { "unterminated OID subidentifier",
        { 0x30,0x03, 0x06,0x01,0x80 }, 5UL, 0, 0 },
      { "non-minimal OID subidentifier",
        { 0x30,0x0B, 0x06,0x09,0x2b,0x06,0x01,0x05,0x05,0x07,0x03,0x80,0x02 }, 13UL, 0, 0 },
      { "trailing bytes after the SEQUENCE",
        { 0x30,0x06, 0x06,0x04,0x55,0x1d,0x25,0x00, 0x05,0x00 }, 10UL, 0, 0 },
    };

    for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
      uchar exts[ 256 ];
      ulong exts_len = mk_ext( exts, oid_eku_tlv, sizeof(oid_eku_tlv),
                               cases[i].val, cases[i].val_len );
      uchar cert[ 1024 ]; ulong cert_len = mk_cert( cert, exts, exts_len );
      fd_x509_cert_info_t info;
      int rc = fd_x509_cert_parse( cert, cert_len, &info );
      if( cases[i].ok ) {
        FD_TEST( rc==0 );
        FD_TEST( info.has_ext_key_usage==1 );
        FD_TEST( info.ext_key_usage==cases[i].eku );
      } else {
        FD_TEST( rc!=0 );
      }
    }

    /* A non-minimal extKeyUsage extnID must not become an ignored unknown
       non-critical extension. */
    {
      static uchar const nonminimal_eku_oid[] = { 0x06,0x04,0x55,0x1d,0x80,0x25 };
      static uchar const client_auth[] = {
        0x30,0x0A, 0x06,0x08,0x2b,0x06,0x01,0x05,0x05,0x07,0x03,0x02 };
      uchar exts[ 256 ];
      ulong exts_len = mk_ext( exts, nonminimal_eku_oid, sizeof(nonminimal_eku_oid),
                               client_auth, sizeof(client_auth) );
      uchar cert[ 1024 ]; ulong cert_len = mk_cert( cert, exts, exts_len );
      fd_x509_cert_info_t info;
      FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )!=0 );
    }

    {
      uchar cert[ 1024 ]; ulong cert_len = mk_cert( cert, NULL, 0UL );
      fd_x509_cert_info_t info;
      FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )==0 );
      FD_TEST( info.has_ext_key_usage==0 );
      FD_TEST( info.ext_key_usage==0 );
    }

    {
      static uchar const eku_val[] = { 0x30,0x06, 0x06,0x04,0x55,0x1d,0x25,0x00 };
      uchar exts[ 256 ];
      ulong exts_len  = mk_ext( exts, oid_eku_tlv, sizeof(oid_eku_tlv), eku_val, sizeof(eku_val) );
            exts_len += mk_ext( exts+exts_len, oid_eku_tlv, sizeof(oid_eku_tlv), eku_val, sizeof(eku_val) );
      uchar cert[ 1024 ]; ulong cert_len = mk_cert( cert, exts, exts_len );
      fd_x509_cert_info_t info;
      FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )!=0 );
    }

    FD_LOG_INFO(( "OK: extKeyUsage parsing" ));
  }

  /* Test 24: key usage policy over a real chain */
  {
    static uchar const ku_dsig    [] = { 0x03,0x02,0x07,0x80 };  /* digitalSignature */
    static uchar const ku_kenc    [] = { 0x03,0x02,0x05,0x20 };  /* keyEncipherment  */
    static uchar const ku_empty   [] = { 0x03,0x01,0x00      };  /* denies all       */
    static uchar const ku_certsign[] = { 0x03,0x02,0x01,0x06 };  /* keyCertSign|cRLSign */

    static uchar const eku_server[] = { 0x30,0x0A, 0x06,0x08,0x2b,0x06,0x01,0x05,0x05,0x07,0x03,0x01 };
    static uchar const eku_client[] = { 0x30,0x0A, 0x06,0x08,0x2b,0x06,0x01,0x05,0x05,0x07,0x03,0x02 };
    static uchar const eku_any   [] = { 0x30,0x06, 0x06,0x04,0x55,0x1d,0x25,0x00 };
    static uchar const eku_client_any[] = {
      0x30,0x10, 0x06,0x08,0x2b,0x06,0x01,0x05,0x05,0x07,0x03,0x02,
                 0x06,0x04,0x55,0x1d,0x25,0x00 };

    uchar root_name [ 64 ]; ulong root_name_len  = mk_name( root_name,  "KU Root"  );
    uchar inter_name[ 64 ]; ulong inter_name_len = mk_name( inter_name, "KU Inter" );
    uchar leaf_name [ 64 ]; ulong leaf_name_len  = mk_name( leaf_name,  "KU Leaf"  );

    uchar prv_root [ 32 ]; memset( prv_root,  0xE5, sizeof(prv_root)  );
    uchar prv_inter[ 32 ]; memset( prv_inter, 0xF7, sizeof(prv_inter) );
    uchar leaf_pub [ 32 ]; memset( leaf_pub,  0x66, sizeof(leaf_pub)  );

    fd_sha512_t sha[1];
    uchar pub_root [ 32 ]; fd_ed25519_public_from_private( pub_root,  prv_root,  sha );
    uchar pub_inter[ 32 ]; fd_ed25519_public_from_private( pub_inter, prv_inter, sha );

    fd_x509_ca_store_t store;
    memset( &store, 0, sizeof(store) );
    store.cnt = 1;
    memcpy( store.entries[0].subject, root_name, root_name_len );
    store.entries[0].subject_len = root_name_len;
    memcpy( store.entries[0].pubkey, pub_root, 32UL );
    store.entries[0].pubkey_len = 32UL;
    store.entries[0].key_type   = FD_X509_KEY_ED25519;

    /* Leaf policy: the leaf is signed straight by the root */
    static struct {
      char const *  desc;
      uchar const * ku;  ulong ku_len;
      uchar const * eku; ulong eku_len;
      int           expected;
    } const leaf_cases[] = {
      { "no keyUsage, no extKeyUsage",  NULL,0UL,                      NULL,0UL,                              FD_X509_VERIFY_OK                   },
      { "digitalSignature",             ku_dsig,sizeof(ku_dsig),       NULL,0UL,                              FD_X509_VERIFY_OK                   },
      { "keyEncipherment only",         ku_kenc,sizeof(ku_kenc),       NULL,0UL,                              FD_X509_VERIFY_ERR_KEY_USAGE        },
      { "empty keyUsage is malformed",  ku_empty,sizeof(ku_empty),     NULL,0UL,                              FD_X509_VERIFY_ERR_PARSE            },
      { "serverAuth",                   NULL,0UL,                      eku_server,sizeof(eku_server),         FD_X509_VERIFY_OK                   },
      { "clientAuth only",              NULL,0UL,                      eku_client,sizeof(eku_client),         FD_X509_VERIFY_ERR_EXT_KEY_USAGE    },
      { "anyExtendedKeyUsage",          NULL,0UL,                      eku_any,sizeof(eku_any),               FD_X509_VERIFY_OK                   },
      { "clientAuth plus anyEKU",       NULL,0UL,                      eku_client_any,sizeof(eku_client_any), FD_X509_VERIFY_OK                   },
      { "digitalSignature+serverAuth",  ku_dsig,sizeof(ku_dsig),       eku_server,sizeof(eku_server),         FD_X509_VERIFY_OK                   },
      /* keyUsage is checked first, so it is what the operator sees */
      { "both wrong reports keyUsage",  ku_kenc,sizeof(ku_kenc),       eku_client,sizeof(eku_client),         FD_X509_VERIFY_ERR_KEY_USAGE        },
    };

    for( ulong i=0UL; i<sizeof(leaf_cases)/sizeof(leaf_cases[0]); i++ ) {
      uchar exts[ 256 ]; ulong exts_len = 0UL;
      if( leaf_cases[i].ku )
        exts_len += mk_ext( exts+exts_len, oid_ku_tlv, sizeof(oid_ku_tlv),
                            leaf_cases[i].ku, leaf_cases[i].ku_len );
      if( leaf_cases[i].eku )
        exts_len += mk_ext( exts+exts_len, oid_eku_tlv, sizeof(oid_eku_tlv),
                            leaf_cases[i].eku, leaf_cases[i].eku_len );

      uchar leaf[ 1024 ];
      ulong leaf_len = mk_cert_signed( leaf, root_name, root_name_len,
                                       leaf_name, leaf_name_len,
                                       leaf_pub, prv_root,
                                       exts_len ? exts : NULL, exts_len );
      uchar const * chain_der   [ 1 ] = { leaf };
      ulong         chain_der_sz[ 1 ] = { leaf_len };
      FD_TEST( fd_x509_verify_chain( chain_der, chain_der_sz, 1UL, &store, NULL, 0UL, TEST_NOW )
               ==leaf_cases[i].expected );
    }

    /* Issuer policy: leaf <- intermediate <- root */
    static struct {
      char const *  desc;
      uchar const * ku;  ulong ku_len;
      uchar const * eku; ulong eku_len;
      int           ca;
      int           expected;
    } const inter_cases[] = {
      { "cA with keyCertSign",     ku_certsign,sizeof(ku_certsign), NULL,0UL,                      1, FD_X509_VERIFY_OK                },
      { "cA, keyUsage absent",     NULL,0UL,                        NULL,0UL,                      1, FD_X509_VERIFY_OK                },
      { "cA without keyCertSign",  ku_dsig,sizeof(ku_dsig),         NULL,0UL,                      1, FD_X509_VERIFY_ERR_KEY_USAGE     },
      { "cA with serverAuth",      ku_certsign,sizeof(ku_certsign), eku_server,sizeof(eku_server), 1, FD_X509_VERIFY_OK                },
      { "cA with clientAuth only", ku_certsign,sizeof(ku_certsign), eku_client,sizeof(eku_client), 1, FD_X509_VERIFY_ERR_EXT_KEY_USAGE },
      /* the cA flag is the more common misconfiguration, so it reports first */
      { "keyCertSign but no cA",   ku_certsign,sizeof(ku_certsign), NULL,0UL,                      0, FD_X509_VERIFY_ERR_CA_FLAG       },
    };

    for( ulong i=0UL; i<sizeof(inter_cases)/sizeof(inter_cases[0]); i++ ) {
      uchar exts[ 256 ]; ulong exts_len = 0UL;
      if( inter_cases[i].ca )
        exts_len += mk_ext_critical( exts+exts_len, oid_bc_tlv, sizeof(oid_bc_tlv),
                                     0xFF, bc_ca_true_val, sizeof(bc_ca_true_val) );
      if( inter_cases[i].ku )
        exts_len += mk_ext( exts+exts_len, oid_ku_tlv, sizeof(oid_ku_tlv),
                            inter_cases[i].ku, inter_cases[i].ku_len );
      if( inter_cases[i].eku )
        exts_len += mk_ext( exts+exts_len, oid_eku_tlv, sizeof(oid_eku_tlv),
                            inter_cases[i].eku, inter_cases[i].eku_len );

      uchar leaf[ 1024 ];
      ulong leaf_len = mk_cert_signed( leaf, inter_name, inter_name_len,
                                       leaf_name, leaf_name_len,
                                       leaf_pub, prv_inter, NULL, 0UL );
      uchar inter[ 1024 ];
      ulong inter_len = mk_cert_signed( inter, root_name, root_name_len,
                                        inter_name, inter_name_len,
                                        pub_inter, prv_root,
                                        exts_len ? exts : NULL, exts_len );

      uchar const * chain_der   [ 2 ] = { leaf, inter };
      ulong         chain_der_sz[ 2 ] = { leaf_len, inter_len };
      FD_TEST( fd_x509_verify_chain( chain_der, chain_der_sz, 2UL, &store, NULL, 0UL, TEST_NOW )
               ==inter_cases[i].expected );
    }

    /* Key usage is intrinsic to the cert, so it outranks the hostname */
    {
      uchar gn[ 32 ]; ulong gn_len = der_tlv( gn, FD_DER_TAG_CONTEXT_PRIM(2),
                                              (uchar const *)"example.com", 11UL );
      uchar exts[ 256 ];
      ulong exts_len  = mk_san( exts, gn, gn_len );
            exts_len += mk_ext( exts+exts_len, oid_ku_tlv, sizeof(oid_ku_tlv),
                                ku_kenc, sizeof(ku_kenc) );
      uchar leaf[ 1024 ];
      ulong leaf_len = mk_cert_signed( leaf, root_name, root_name_len,
                                       leaf_name, leaf_name_len,
                                       leaf_pub, prv_root, exts, exts_len );
      uchar const * chain_der   [ 1 ] = { leaf };
      ulong         chain_der_sz[ 1 ] = { leaf_len };
      FD_TEST( fd_x509_verify_chain( chain_der, chain_der_sz, 1UL, &store, "other.com", 9UL, TEST_NOW )
               ==FD_X509_VERIFY_ERR_KEY_USAGE );
    }

    /* Expiry is checked before key usage, so it wins */
    {
      uchar exts[ 256 ];
      ulong exts_len = mk_ext( exts, oid_ku_tlv, sizeof(oid_ku_tlv),
                               ku_kenc, sizeof(ku_kenc) );
      uchar leaf[ 1024 ];
      ulong leaf_len = mk_cert_validity( leaf,
                                         "750101000000Z", FD_DER_TAG_UTC_TIME,
                                         "191231235959Z", FD_DER_TAG_UTC_TIME,
                                         exts, exts_len );
      uchar const * chain_der   [ 1 ] = { leaf };
      ulong         chain_der_sz[ 1 ] = { leaf_len };
      FD_TEST( fd_x509_verify_chain( chain_der, chain_der_sz, 1UL, &store, NULL, 0UL, TEST_NOW )
               ==FD_X509_VERIFY_ERR_EXPIRED );
    }

    /* A trailing cross-sign the path never adopts must not be usage
       checked, however badly it is profiled */
    {
      uchar older_name[ 64 ]; ulong older_name_len = mk_name( older_name, "KU Old Root" );
      uchar prv_old[ 32 ]; memset( prv_old, 0xD4, sizeof(prv_old) );

      uchar leaf[ 1024 ];
      ulong leaf_len = mk_cert_signed( leaf, root_name, root_name_len,
                                       leaf_name, leaf_name_len,
                                       leaf_pub, prv_root, NULL, 0UL );

      uchar exts[ 256 ];
      ulong exts_len  = mk_ext_critical( exts, oid_bc_tlv, sizeof(oid_bc_tlv),
                                         0xFF, bc_ca_true_val, sizeof(bc_ca_true_val) );
            exts_len += mk_ext( exts+exts_len, oid_ku_tlv, sizeof(oid_ku_tlv),
                                ku_kenc, sizeof(ku_kenc) );
            exts_len += mk_ext( exts+exts_len, oid_eku_tlv, sizeof(oid_eku_tlv),
                                eku_client, sizeof(eku_client) );

      uchar cross[ 1024 ];
      ulong cross_len = mk_cert_signed( cross, older_name, older_name_len,
                                        root_name, root_name_len,
                                        pub_root, prv_old, exts, exts_len );

      uchar const * chain_der   [ 2 ] = { leaf, cross };
      ulong         chain_der_sz[ 2 ] = { leaf_len, cross_len };
      FD_TEST( fd_x509_verify_chain( chain_der, chain_der_sz, 2UL, &store, NULL, 0UL, TEST_NOW )
               ==FD_X509_VERIFY_OK );
    }

    FD_LOG_INFO(( "OK: key usage policy" ));
  }

  /* Test 25: basicConstraints pathLenConstraint limits the number of
     non-self-issued intermediate CAs below the constrained issuer. */
  {
    static uchar const bc_path_0[] = { 0x30,0x06, 0x01,0x01,0xFF, 0x02,0x01,0x00 };
    static uchar const bc_path_1[] = { 0x30,0x06, 0x01,0x01,0xFF, 0x02,0x01,0x01 };

    uchar root_name [ 64 ]; ulong root_name_len  = mk_name( root_name,  "Path Root"  );
    uchar upper_name[ 64 ]; ulong upper_name_len = mk_name( upper_name, "Path Upper" );
    uchar lower_name[ 64 ]; ulong lower_name_len = mk_name( lower_name, "Path Lower" );
    uchar leaf_name [ 64 ]; ulong leaf_name_len  = mk_name( leaf_name,  "Path Leaf"  );

    uchar prv_root [ 32 ]; memset( prv_root,  0x17, sizeof(prv_root)  );
    uchar prv_upper[ 32 ]; memset( prv_upper, 0x28, sizeof(prv_upper) );
    uchar prv_lower[ 32 ]; memset( prv_lower, 0x39, sizeof(prv_lower) );
    uchar leaf_pub [ 32 ]; memset( leaf_pub,  0x4A, sizeof(leaf_pub)  );

    fd_sha512_t sha[1];
    uchar pub_root [ 32 ]; fd_ed25519_public_from_private( pub_root,  prv_root,  sha );
    uchar pub_upper[ 32 ]; fd_ed25519_public_from_private( pub_upper, prv_upper, sha );
    uchar pub_lower[ 32 ]; fd_ed25519_public_from_private( pub_lower, prv_lower, sha );

    fd_x509_ca_store_t store;
    memset( &store, 0, sizeof(store) );
    store.cnt = 1;
    memcpy( store.entries[0].subject, root_name, root_name_len );
    store.entries[0].subject_len = root_name_len;
    memcpy( store.entries[0].pubkey, pub_root, 32UL );
    store.entries[0].pubkey_len = 32UL;
    store.entries[0].key_type   = FD_X509_KEY_ED25519;

    uchar ca_ext[ 64 ];
    ulong ca_ext_len = mk_ext_critical( ca_ext, oid_bc_tlv, sizeof(oid_bc_tlv),
                                        0xFF, bc_ca_true_val, sizeof(bc_ca_true_val) );

    uchar leaf[ 1024 ];
    ulong leaf_len = mk_cert_signed( leaf, lower_name, lower_name_len,
                                     leaf_name, leaf_name_len,
                                     leaf_pub, prv_lower, NULL, 0UL );
    uchar lower[ 1024 ];
    ulong lower_len = mk_cert_signed( lower, upper_name, upper_name_len,
                                      lower_name, lower_name_len,
                                      pub_lower, prv_upper, ca_ext, ca_ext_len );

    static struct {
      uchar const * constraint; ulong constraint_len; int expected;
    } const cases[] = {
      { bc_path_0, sizeof(bc_path_0), FD_X509_VERIFY_ERR_PATH_LEN },
      { bc_path_1, sizeof(bc_path_1), FD_X509_VERIFY_OK           },
    };

    for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
      uchar upper_ext[ 64 ];
      ulong upper_ext_len = mk_ext_critical( upper_ext, oid_bc_tlv, sizeof(oid_bc_tlv),
                                             0xFF, cases[i].constraint, cases[i].constraint_len );
      uchar upper[ 1024 ];
      ulong upper_len = mk_cert_signed( upper, root_name, root_name_len,
                                        upper_name, upper_name_len,
                                        pub_upper, prv_root, upper_ext, upper_ext_len );

      uchar const * chain_der   [ 3 ] = { leaf, lower, upper };
      ulong         chain_der_sz[ 3 ] = { leaf_len, lower_len, upper_len };
      FD_TEST( fd_x509_verify_chain( chain_der, chain_der_sz, 3UL,
                                     &store, NULL, 0UL, TEST_NOW )==cases[i].expected );
    }

    /* A self-issued rollover CA is explicitly excluded from the count.
       Use semantically equal but byte-distinct names throughout this
       path to cover adjacent linkage, self-issued classification, and
       trust-anchor lookup. */
    uchar upper_printable[ 64 ]; ulong upper_printable_len =
      mk_name_tag( upper_printable, "path upper", FD_DER_TAG_PRINTABLE_STR );
    uchar upper_spaced[ 64 ]; ulong upper_spaced_len =
      mk_name( upper_spaced, "  PATH   UPPER  " );
    uchar root_printable[ 64 ]; ulong root_printable_len =
      mk_name_tag( root_printable, "path root", FD_DER_TAG_PRINTABLE_STR );

    uchar rollover_leaf[ 1024 ];
    ulong rollover_leaf_len = mk_cert_signed( rollover_leaf, upper_printable, upper_printable_len,
                                              leaf_name, leaf_name_len,
                                              leaf_pub, prv_lower, NULL, 0UL );
    uchar rollover[ 1024 ];
    ulong rollover_len = mk_cert_signed( rollover, upper_spaced, upper_spaced_len,
                                         upper_printable, upper_printable_len,
                                         pub_lower, prv_upper, ca_ext, ca_ext_len );
    uchar upper_ext[ 64 ];
    ulong upper_ext_len = mk_ext_critical( upper_ext, oid_bc_tlv, sizeof(oid_bc_tlv),
                                           0xFF, bc_path_0, sizeof(bc_path_0) );
    uchar upper[ 1024 ];
    ulong upper_len = mk_cert_signed( upper, root_printable, root_printable_len,
                                      upper_name, upper_name_len,
                                      pub_upper, prv_root, upper_ext, upper_ext_len );

    uchar const * rollover_chain   [ 3 ] = { rollover_leaf, rollover, upper };
    ulong         rollover_chain_sz[ 3 ] = { rollover_leaf_len, rollover_len, upper_len };
    FD_TEST( fd_x509_verify_chain( rollover_chain, rollover_chain_sz, 3UL,
                                   &store, NULL, 0UL, TEST_NOW )==FD_X509_VERIFY_OK );

    /* A DirectoryString private attribute may be case-exact and must not make
       a subordinate CA look self-issued. */
    static uchar const oid_private_tlv[] = { 0x06,0x08, 0x2b,0x06,0x01,0x04,0x01,0x83,0xb2,0x03 };
    uchar private_lower[ 64 ]; ulong private_lower_len =
      mk_name_oid_tag( private_lower, oid_private_tlv, sizeof(oid_private_tlv),
                       "rolea", FD_DER_TAG_UTF8_STRING );
    uchar private_upper[ 64 ]; ulong private_upper_len =
      mk_name_oid_tag( private_upper, oid_private_tlv, sizeof(oid_private_tlv),
                       "RoleA", FD_DER_TAG_UTF8_STRING );
    FD_TEST( !fd_x509_name_equal( private_lower, private_lower_len,
                                  private_upper, private_upper_len ) );

    uchar private_leaf[ 1024 ];
    ulong private_leaf_len = mk_cert_signed( private_leaf, private_upper, private_upper_len,
                                             leaf_name, leaf_name_len,
                                             leaf_pub, prv_lower, NULL, 0UL );
    uchar private_ca[ 1024 ];
    ulong private_ca_len = mk_cert_signed( private_ca, private_lower, private_lower_len,
                                           private_upper, private_upper_len,
                                           pub_lower, prv_upper, ca_ext, ca_ext_len );
    uchar constrained_ca[ 1024 ];
    ulong constrained_ca_len = mk_cert_signed( constrained_ca, root_name, root_name_len,
                                               private_lower, private_lower_len,
                                               pub_upper, prv_root, upper_ext, upper_ext_len );

    uchar const * private_chain   [ 3 ] = { private_leaf, private_ca, constrained_ca };
    ulong         private_chain_sz[ 3 ] = { private_leaf_len, private_ca_len, constrained_ca_len };
    FD_TEST( fd_x509_verify_chain( private_chain, private_chain_sz, 3UL,
                                   &store, NULL, 0UL, TEST_NOW )==FD_X509_VERIFY_ERR_PATH_LEN );

    FD_LOG_INFO(( "OK: basicConstraints path length policy" ));
  }

  /* A real P-256 leaf exercises DER signature decoding, point
     compression, SHA-256, and acceptance of the high-S counterpart. */
  {
    static char const root_hex[] =
      "3082015c30820101a003020102020101300a06082a8648ce3d04030230143112301006035504030c09503235362d526f6f74"
      "3020170d3735303130313030303030305a180f34303936303130313030303030305a30143112301006035504030c09503235"
      "362d526f6f743059301306072a8648ce3d020106082a8648ce3d03010703420004671f7201dd7d2fc4b522cd92ec6786d63c"
      "393c359e9fb91ab1908fbae20dfba290814600793a00c80b9fa9d008e3d3572f027f149c2ef58e2f7b0bbfdfcf394aa34230"
      "40300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106301d0603551d0e04160414dd8d0e5786"
      "4b770f773d38c1751facba5a400b2a300a06082a8648ce3d0403020349003046022100c903451084b64556dd0d3d8e405f2f"
      "a219d944e6099e85a05e907757c54bf53a022100db79a58a678e48dd730e94dfc32ff8121fa3e96b7cf5bc45e24621aa1fc5"
      "81d0";
    static char const leaf_hex[] =
      "3082019b30820140a003020102020102300a06082a8648ce3d04030230143112301006035504030c09503235362d526f6f74"
      "3020170d3735303130313030303030305a180f34303936303130313030303030305a30143112301006035504030c09503235"
      "362d4c6561663059301306072a8648ce3d020106082a8648ce3d03010703420004340712b589308be9f5bf78ad40507be483"
      "977873305bdc1bc9352493fc9189b9908947a3b95a18deba9fa985114e3dbc898b6938112f4add4248c7b6b5e6f757a38180"
      "307e30170603551d110410300e820c703235362e6578616d706c65300e0603551d0f0101ff04040302078030130603551d25"
      "040c300a06082b06010505070301301d0603551d0e04160414b12f05f85a2a5f8b7681e1736908d916853f8284301f060355"
      "1d23041830168014dd8d0e57864b770f773d38c1751facba5a400b2a300a06082a8648ce3d0403020349003046022100b4f6"
      "cc152cda62cbd4a31670690092ee69de9fd62433f718e808bda7b1da535f022100c6e922e3ac4d10e0f6c347bcedbfc9b2"
      "0519f24f8e1fa6680961dc8b9ea87b42";

    uchar root[ 352 ]; uchar leaf[ 415 ];
    fd_hex_decode( root, root_hex, sizeof(root) );
    fd_hex_decode( leaf, leaf_hex, sizeof(leaf) );

    fd_x509_cert_info_t root_info; FD_TEST( !fd_x509_cert_parse( root, sizeof(root), &root_info ) );
    fd_x509_cert_info_t leaf_info; FD_TEST( !fd_x509_cert_parse( leaf, sizeof(leaf), &leaf_info ) );
    FD_TEST( root_info.key_type==FD_X509_KEY_ECDSA_P256 );
    FD_TEST( leaf_info.sig_alg==FD_X509_SIG_ECDSA_SHA256 );
    uchar raw_sig[ 64 ];
    FD_TEST( !fd_x509_decode_ecdsa_sig( leaf_info.sig, leaf_info.sig_len, raw_sig, 32UL ) );
    FD_TEST( raw_sig[32] & 0x80U ); /* s is in the high half of the scalar range */

    fd_x509_ca_store_t store; memset( &store, 0, sizeof(store) );
    store.cnt = 1UL;
    memcpy( store.entries[0].subject, root_info.subject, root_info.subject_len );
    store.entries[0].subject_len = root_info.subject_len;
    memcpy( store.entries[0].pubkey, root_info.pubkey, root_info.pubkey_len );
    store.entries[0].pubkey_len = root_info.pubkey_len;
    store.entries[0].key_type   = root_info.key_type;

    uchar const * chain_der[] = { leaf };
    ulong chain_der_sz[] = { sizeof(leaf) };
    FD_TEST( fd_x509_verify_chain( chain_der, chain_der_sz, 1UL, &store,
                                   "p256.example", 12UL, TEST_NOW )==FD_X509_VERIFY_OK );
    FD_LOG_INFO(( "OK: P-256 high-S certificate chain" ));
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
