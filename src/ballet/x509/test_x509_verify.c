#include "fd_x509.h"
#include "fd_der.h"
#include "fd_x509_verify.h"
#include "fd_x509_ca_store.h"
#include "../ed25519/fd_ed25519.h"
#include "../../util/fd_util.h"

#include <string.h>

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
  } else {
    out[ n++ ] = 0x82;
    out[ n++ ] = (uchar)( content_len >> 8 );
    out[ n++ ] = (uchar)( content_len      );
  }
  if( content_len ) memcpy( out+n, content, content_len );
  return n + content_len;
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

/* mk_cert_validity builds a certificate with empty issuer and subject
   names, an all zero key and an all zero signature.  Good enough for
   every check that runs ahead of signature verification. */

static ulong
mk_cert_validity( uchar *       out,
                  char const *  not_before,
                  uchar         not_before_tag,
                  char const *  not_after,
                  uchar         not_after_tag,
                  uchar const * exts,
                  ulong         exts_len ) {
  uchar zero[ 64 ]; memset( zero, 0, sizeof(zero) );
  uchar tbs[ 1024 ];
  ulong tbs_len = mk_tbs( tbs, NULL, 0UL, NULL, 0UL, zero,
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

/* mk_name builds a Name holding a single commonName RDN, and returns the
   length of the encoded Name.  That encoding is what both the chain and
   the CA store match on, byte for byte. */

static uchar const oid_cn_tlv[] = { 0x06, 0x03, 0x55, 0x04, 0x03 };

static ulong
mk_name( uchar *      out,
         char const * cn ) {
  uchar atv[ 128 ];
  memcpy( atv, oid_cn_tlv, sizeof(oid_cn_tlv) );
  ulong a = sizeof(oid_cn_tlv);
  a += der_tlv( atv+a, FD_DER_TAG_UTF8_STRING, (uchar const *)cn, strlen( cn ) );

  uchar rdn[ 160 ]; ulong r = der_tlv( rdn, FD_DER_TAG_SEQUENCE, atv, a );
  uchar set[ 192 ]; ulong n = der_tlv( set, FD_DER_TAG_SET,      rdn, r );
  return der_tlv( out, FD_DER_TAG_SEQUENCE, set, n );
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


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Test 1: Parse zero-length input */
  {
    uchar buf[ 1 ];
    fd_x509_cert_info_t info;
    FD_TEST( fd_x509_cert_parse( buf, 0UL, &info )!=0 );
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
    fd_x509_cert_info_t info;
    memset( &info, 0, sizeof(info) );
    info.san_dns_cnt = 1;
    info.san_dns[0].name     = "example.com";
    info.san_dns[0].name_len = 11;
    FD_TEST( fd_x509_san_matches( &info, "example.com", 11UL )==1 );
    FD_LOG_INFO(( "OK: exact SAN match" ));
  }

  /* Test 5: No match */
  {
    fd_x509_cert_info_t info;
    memset( &info, 0, sizeof(info) );
    info.san_dns_cnt = 1;
    info.san_dns[0].name     = "example.com";
    info.san_dns[0].name_len = 11;
    FD_TEST( fd_x509_san_matches( &info, "other.com", 9UL )==0 );
    FD_LOG_INFO(( "OK: SAN no match" ));
  }

  /* Test 6: Wildcard match */
  {
    fd_x509_cert_info_t info;
    memset( &info, 0, sizeof(info) );
    info.san_dns_cnt = 1;
    info.san_dns[0].name     = "*.example.com";
    info.san_dns[0].name_len = 13;
    FD_TEST( fd_x509_san_matches( &info, "foo.example.com", 15UL )==1 );
    FD_LOG_INFO(( "OK: wildcard SAN match" ));
  }

  /* Test 7: Wildcard no deep match */
  {
    fd_x509_cert_info_t info;
    memset( &info, 0, sizeof(info) );
    info.san_dns_cnt = 1;
    info.san_dns[0].name     = "*.example.com";
    info.san_dns[0].name_len = 13;
    FD_TEST( fd_x509_san_matches( &info, "a.b.example.com", 15UL )==0 );
    FD_LOG_INFO(( "OK: wildcard no deep match" ));
  }

  /* Test 8: Wildcard no bare match */
  {
    fd_x509_cert_info_t info;
    memset( &info, 0, sizeof(info) );
    info.san_dns_cnt = 1;
    info.san_dns[0].name     = "*.example.com";
    info.san_dns[0].name_len = 13;
    FD_TEST( fd_x509_san_matches( &info, "example.com", 11UL )==0 );
    FD_LOG_INFO(( "OK: wildcard no bare match" ));
  }

  /* Test 9: Multiple SANs, second matches */
  {
    fd_x509_cert_info_t info;
    memset( &info, 0, sizeof(info) );
    info.san_dns_cnt = 2;
    info.san_dns[0].name     = "other.com";
    info.san_dns[0].name_len = 9;
    info.san_dns[1].name     = "example.com";
    info.san_dns[1].name_len = 11;
    FD_TEST( fd_x509_san_matches( &info, "example.com", 11UL )==1 );
    FD_LOG_INFO(( "OK: multiple SANs, second matches" ));
  }

  /* Test 10: Empty hostname */
  {
    fd_x509_cert_info_t info;
    memset( &info, 0, sizeof(info) );
    info.san_dns_cnt = 1;
    info.san_dns[0].name     = "example.com";
    info.san_dns[0].name_len = 11;
    FD_TEST( fd_x509_san_matches( &info, "", 0UL )==0 );
    FD_LOG_INFO(( "OK: empty hostname returns 0" ));
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
    ulong exts_len = mk_ext( exts, oid_bc_tlv, sizeof(oid_bc_tlv),
                             bc_ca_true_val, sizeof(bc_ca_true_val) );

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
    FD_TEST( info.san_dns_cnt==1 );
    FD_TEST( fd_x509_san_matches( &info, "example.com", 11UL )==1 );
    FD_LOG_INFO(( "OK: SAN dNSName parsed from DER" ));
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
    ulong exts_len = mk_ext( exts, oid_bc_tlv, sizeof(oid_bc_tlv),
                             bc_ca_true, sizeof(bc_ca_true) );
    memcpy( exts+exts_len, ext_truncated, sizeof(ext_truncated) );
    exts_len += sizeof(ext_truncated);
    uchar cert[ 1024 ]; ulong cert_len = mk_cert( cert, exts, exts_len );
    fd_x509_cert_info_t info;
    FD_TEST( fd_x509_cert_parse( cert, cert_len, &info )!=0 );
    FD_LOG_INFO(( "OK: cA=TRUE with malformed extension tail fails parse" ));
  }

  /* Test 21b: basicConstraints value must be a well-formed BasicConstraints */
  {
    /* Each case is the raw extnValue (a BasicConstraints SEQUENCE, possibly
       with trailing bytes inside the OCTET STRING). */
    static struct { uchar val[ 8 ]; ulong val_len; int ok; int is_ca; } const cases[] = {
      /* cA=TRUE followed by a truncated INTEGER tag */
      { { 0x30, 0x05, 0x01, 0x01, 0xFF, 0x02 },             6UL, 0, 0 },
      /* cA=TRUE with a trailing byte after the SEQUENCE */
      { { 0x30, 0x03, 0x01, 0x01, 0xFF, 0x00 },             6UL, 0, 0 },
      /* cA=TRUE, pathLenConstraint=0 */
      { { 0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00 }, 8UL, 1, 1 },
      /* cA=TRUE */
      { { 0x30, 0x03, 0x01, 0x01, 0xFF },                   5UL, 1, 1 },
      /* cA=FALSE */
      { { 0x30, 0x03, 0x01, 0x01, 0x00 },                   5UL, 1, 0 },
      /* cA absent (DEFAULT FALSE) */
      { { 0x30, 0x00 },                                     2UL, 1, 0 },
      /* two byte BOOLEAN */
      { { 0x30, 0x04, 0x01, 0x02, 0xFF, 0xFF },             6UL, 0, 0 },
      /* non-DER BOOLEAN TRUE */
      { { 0x30, 0x03, 0x01, 0x01, 0x01 },                   5UL, 0, 0 },
    };
    for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
      uchar exts[ 256 ];
      ulong exts_len = mk_ext( exts, oid_bc_tlv, sizeof(oid_bc_tlv),
                               cases[i].val, cases[i].val_len );
      exts_len += mk_san( exts+exts_len, gn_example, sizeof(gn_example) );
      uchar cert[ 1024 ]; ulong cert_len = mk_cert( cert, exts, exts_len );
      fd_x509_cert_info_t info;
      int err = fd_x509_cert_parse( cert, cert_len, &info );
      if( cases[i].ok ) {
        FD_TEST( err==0 );
        FD_TEST( info.is_ca==cases[i].is_ca );
        FD_TEST( fd_x509_san_matches( &info, "example.com", 11UL )==1 );
      } else {
        FD_TEST( err!=0 );
      }
    }
    FD_LOG_INFO(( "OK: basicConstraints parsed strictly" ));
  }

  /* Test 22: Wildcard must consume a non-empty label */
  {
    fd_x509_cert_info_t info;
    memset( &info, 0, sizeof(info) );
    info.san_dns_cnt = 1;
    info.san_dns[0].name     = "*.example.com";
    info.san_dns[0].name_len = 13;
    FD_TEST( fd_x509_san_matches( &info, ".example.com", 12UL )==0 );
    FD_TEST( fd_x509_san_matches( &info, "x.example.com", 13UL )==1 );
    FD_LOG_INFO(( "OK: wildcard rejects empty leftmost label" ));
  }

  /* Test 23: Wildcard tail must span at least two labels */
  {
    fd_x509_cert_info_t info;
    memset( &info, 0, sizeof(info) );
    info.san_dns_cnt = 1;
    info.san_dns[0].name     = "*.com";
    info.san_dns[0].name_len = 5;
    FD_TEST( fd_x509_san_matches( &info, "foo.com", 7UL )==0 );
    info.san_dns[0].name     = "*.";
    info.san_dns[0].name_len = 2;
    FD_TEST( fd_x509_san_matches( &info, "a.", 2UL )==0 );
    FD_TEST( fd_x509_san_matches( &info, "a", 1UL )==0 );
    FD_LOG_INFO(( "OK: wildcard requires a two-label tail" ));
  }

  /* Test 24: Malformed SAN patterns never match */
  {
    fd_x509_cert_info_t info;
    memset( &info, 0, sizeof(info) );
    info.san_dns_cnt = 1;
    info.san_dns[0].name     = ".example.com";
    info.san_dns[0].name_len = 12;
    FD_TEST( fd_x509_san_matches( &info, ".example.com", 12UL )==0 );
    FD_LOG_INFO(( "OK: SAN pattern with empty leading label never matches" ));
  }

  /* Test 25: Malformed hostnames never match */
  {
    fd_x509_cert_info_t info;
    memset( &info, 0, sizeof(info) );
    info.san_dns_cnt = 1;
    info.san_dns[0].name     = "example.com";
    info.san_dns[0].name_len = 11;
    FD_TEST( fd_x509_san_matches( &info, "example.com.", 12UL )==0 );
    FD_TEST( fd_x509_san_matches( &info, "example..com", 12UL )==0 );
    FD_TEST( fd_x509_san_matches( &info, "example.com\0", 12UL )==0 );
    FD_TEST( fd_x509_san_matches( &info, "example.co\xffm", 12UL )==0 );
    FD_LOG_INFO(( "OK: malformed hostnames rejected" ));
  }

  /* Test 26: Exact match folds ASCII case */
  {
    fd_x509_cert_info_t info;
    memset( &info, 0, sizeof(info) );
    info.san_dns_cnt = 1;
    info.san_dns[0].name     = "example.com";
    info.san_dns[0].name_len = 11;
    FD_TEST( fd_x509_san_matches( &info, "EXAMPLE.COM", 11UL )==1 );
    FD_LOG_INFO(( "OK: exact match is case-insensitive" ));
  }

  /* Test 27: Oversized labels and names are rejected */
  {
    char host[ 320 ];
    memset( host, 'a', sizeof(host) );
    fd_x509_cert_info_t info;
    memset( &info, 0, sizeof(info) );
    info.san_dns_cnt = 1;

    info.san_dns[0].name     = host;
    info.san_dns[0].name_len = 64;
    FD_TEST( fd_x509_san_matches( &info, host, 64UL )==0 );  /* 64-char label */

    info.san_dns[0].name_len = 254;
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
      { "empty BIT STRING denies all",      { 0x03,0x01,0x00                }, 3UL, 1, 0x0000 },
      { "empty BIT STRING, unused!=0",      { 0x03,0x01,0x05                }, 3UL, 0, 0      },
      { "unused bits > 7",                  { 0x03,0x02,0x08,0x80           }, 4UL, 0, 0      },
      { "unused bits not zeroed",           { 0x03,0x02,0x05,0xA1           }, 4UL, 0, 0      },
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

    /* Absent keyUsage is unconstrained, and must be distinguishable from
       a present-but-empty one */
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
      { "keyUsage denies everything",   ku_empty,sizeof(ku_empty),     NULL,0UL,                              FD_X509_VERIFY_ERR_KEY_USAGE        },
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
        exts_len += mk_ext( exts+exts_len, oid_bc_tlv, sizeof(oid_bc_tlv),
                            bc_ca_true_val, sizeof(bc_ca_true_val) );
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
      ulong exts_len  = mk_ext( exts, oid_bc_tlv, sizeof(oid_bc_tlv),
                                bc_ca_true_val, sizeof(bc_ca_true_val) );
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

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
