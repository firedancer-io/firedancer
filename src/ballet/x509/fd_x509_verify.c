#include "fd_x509_verify.h"
#include "../ed25519/fd_ed25519.h"
#include "../secp256r1/fd_secp256r1.h"
#include <string.h>

/* fd_x509_verify_sig verifies a certificate's signature given the
   issuer's public key.  Returns 0 on success, non-zero on failure. */

static int
fd_x509_verify_sig( fd_x509_cert_info_t const * cert,
                    uchar const *               issuer_pubkey,
                    ulong                       issuer_pubkey_len,
                    uchar                       issuer_key_type ) {

  switch( cert->sig_alg ) {

  case FD_X509_SIG_ED25519: {
    if( FD_UNLIKELY( issuer_key_type != FD_X509_KEY_ED25519 ) ) return -1;
    if( FD_UNLIKELY( issuer_pubkey_len != 32 ) ) return -1;
    if( FD_UNLIKELY( cert->sig_len != 64 ) ) return -1;

    fd_sha512_t sha512[1];
    int err = fd_ed25519_verify( cert->tbs, cert->tbs_len, cert->sig, issuer_pubkey, sha512 );
    return ( err == FD_ED25519_SUCCESS ) ? 0 : -1;
  }

  case FD_X509_SIG_ECDSA_SHA256: {
    if( FD_UNLIKELY( issuer_key_type != FD_X509_KEY_ECDSA_P256 ) ) return -1;
    if( FD_UNLIKELY( issuer_pubkey_len != 65 ) ) return -1;

    uchar raw_sig[64];
    if( FD_UNLIKELY( fd_x509_decode_ecdsa_sig( cert->sig, cert->sig_len, raw_sig, 32 ) ) )
      return -1;

    uchar compressed_pk[33];
    if( FD_UNLIKELY( fd_x509_ec_point_compress( issuer_pubkey, 32, compressed_pk ) ) )
      return -1;

    fd_sha256_t sha256[1];
    int err = fd_secp256r1_verify_no_low_s( cert->tbs, cert->tbs_len, raw_sig, compressed_pk, sha256 );
    return ( err == FD_SECP256R1_SUCCESS ) ? 0 : -1;
  }

  default:
    return 1;  /* unsupported sig algorithm */
  }
}

/* fd_x509_check_validity returns FD_X509_VERIFY_OK if cert is within its
   validity period at unix_seconds, otherwise the error to report. */

static int
fd_x509_check_validity( fd_x509_cert_info_t const * cert,
                        long                        unix_seconds ) {
  if( FD_UNLIKELY( cert->not_before_unix==FD_X509_TIME_INVALID ||
                   cert->not_after_unix ==FD_X509_TIME_INVALID ) )
    return FD_X509_VERIFY_ERR_TIME_PARSE;
  if( FD_UNLIKELY( unix_seconds < cert->not_before_unix ) )
    return FD_X509_VERIFY_ERR_NOT_YET_VALID;
  if( FD_UNLIKELY( unix_seconds > cert->not_after_unix ) )
    return FD_X509_VERIFY_ERR_EXPIRED;
  return FD_X509_VERIFY_OK;
}

/* fd_x509_check_eku returns OK if cert may be used for TLS server
   authentication.  An absent extKeyUsage is unconstrained. */

static int
fd_x509_check_eku( fd_x509_cert_info_t const * cert ) {
  if( FD_UNLIKELY(
        cert->has_ext_key_usage &&
        !( cert->ext_key_usage & ( FD_X509_EKU_SERVER_AUTH|FD_X509_EKU_ANY ) ) ) ) {
    return FD_X509_VERIFY_ERR_EXT_KEY_USAGE;
  }
  return FD_X509_VERIFY_OK;
}

/* fd_x509_check_leaf_usage enforces the TLS 1.3 server authentication
   usage policy on the leaf.  */

static int
fd_x509_check_leaf_usage( fd_x509_cert_info_t const * leaf ) {
  if( FD_UNLIKELY(
      leaf->has_key_usage &&
      !( leaf->key_usage & FD_X509_KU_DIGITAL_SIGNATURE ) ) ) {
    return FD_X509_VERIFY_ERR_KEY_USAGE;
  }
  return fd_x509_check_eku( leaf );
}

/* Implemented as specified by RFC 5280 Section 6.1.3. */
int
fd_x509_verify_chain( uchar const * const *        chain_der,
                      ulong const *                chain_der_sz,
                      ulong                        chain_cnt,
                      fd_x509_ca_store_t const *   ca_store,
                      char const *                 hostname,
                      ulong                        hostname_len,
                      long                         unix_seconds ) {

  if( FD_UNLIKELY( chain_cnt == 0 ) ) return FD_X509_VERIFY_ERR_CHAIN_BREAK;
  if( FD_UNLIKELY( chain_cnt > FD_X509_CHAIN_MAX ) ) return FD_X509_VERIFY_ERR_CHAIN_TOO_LONG;

  for( ulong i=0UL; i<chain_cnt; i++ )
    if( FD_UNLIKELY( chain_der_sz[i] > FD_X509_CERT_SZ_MAX ) )
      return FD_X509_VERIFY_ERR_CERT_TOO_LARGE;

  fd_x509_cert_info_t certs[ FD_X509_CHAIN_MAX ] = {0};

  if( FD_UNLIKELY( fd_x509_cert_parse( chain_der[0], chain_der_sz[0], &certs[0] ) ) )
    return FD_X509_VERIFY_ERR_PARSE;

  int time_err = fd_x509_check_validity( &certs[0], unix_seconds );
  if( FD_UNLIKELY( time_err ) ) return time_err;

  int usage_err = fd_x509_check_leaf_usage( &certs[0] );
  if( FD_UNLIKELY( usage_err ) ) return usage_err;

  if( hostname && hostname_len ) {
    if( FD_UNLIKELY( !fd_x509_san_matches( &certs[0], hostname, hostname_len ) ) )
      return FD_X509_VERIFY_ERR_HOSTNAME;
  }

  ulong non_self_issued_ca_cnt = 0UL;
  for( ulong i = 0; i < chain_cnt; i++ ) {

    /* A trust anchor for this cert's issuer completes the path.  Peers
       routinely append cross-signatures leading up to some older root,
       so the certs beyond this point are not ours to walk: they chain to
       an anchor we do not need and may not even hold. */

    ulong idx      = 0UL;
    int   anchored = 0;
    for( fd_x509_ca_entry_t const * ca;
         !!( ca = fd_x509_ca_store_find_next( ca_store, certs[i].issuer, certs[i].issuer_len, &idx ) ); ) {
      anchored = 1;

      /* A name match is not a key match, so keep trying the remaining
         anchors sharing this subject.  An unsupported algorithm, on the
         other hand, is a property of the cert and not of the anchor. */

      int sig_rc = fd_x509_verify_sig( &certs[i], ca->pubkey, ca->pubkey_len, ca->key_type );
      if( FD_UNLIKELY( sig_rc > 0 ) ) return FD_X509_VERIFY_ERR_UNSUPPORTED;
      if( !sig_rc )                   return FD_X509_VERIFY_OK;
    }

    /* Not anchored here, so the next cert in the chain must be the
       issuer. */

    if( FD_UNLIKELY( i + 1 >= chain_cnt ) )
      return anchored ? FD_X509_VERIFY_ERR_SIG : FD_X509_VERIFY_ERR_NO_TRUST_ANCHOR;

    if( FD_UNLIKELY( fd_x509_cert_parse( chain_der[i+1], chain_der_sz[i+1], &certs[i+1] ) ) )
      return FD_X509_VERIFY_ERR_PARSE;

    if( FD_UNLIKELY( !fd_x509_name_equal( certs[i].issuer, certs[i].issuer_len,
                                          certs[i+1].subject, certs[i+1].subject_len ) ) )
      return FD_X509_VERIFY_ERR_CHAIN_BREAK;

    time_err = fd_x509_check_validity( &certs[i+1], unix_seconds );
    if( FD_UNLIKELY( time_err ) ) return time_err;

    if( FD_UNLIKELY( !certs[i+1].is_ca ) )
      return FD_X509_VERIFY_ERR_CA_FLAG;

    /* pathLenConstraint counts non-self-issued intermediate CA certs
       between this issuer and the leaf.  The leaf itself never counts. */
    if( FD_UNLIKELY( certs[i+1].has_path_len_constraint &&
                     non_self_issued_ca_cnt>certs[i+1].path_len_constraint ) )
      return FD_X509_VERIFY_ERR_PATH_LEN;

    if( FD_UNLIKELY( certs[i+1].has_key_usage &&
                     !( certs[i+1].key_usage & FD_X509_KU_KEY_CERT_SIGN ) ) )
      return FD_X509_VERIFY_ERR_KEY_USAGE;

    usage_err = fd_x509_check_eku( &certs[i+1] );
    if( FD_UNLIKELY( usage_err ) ) return usage_err;

    int sig_rc = fd_x509_verify_sig( &certs[i], certs[i+1].pubkey, certs[i+1].pubkey_len, certs[i+1].key_type );
    if( sig_rc < 0 )
      return FD_X509_VERIFY_ERR_SIG;
    if( sig_rc > 0 )
      return FD_X509_VERIFY_ERR_UNSUPPORTED;

    /* A self-issued rollover CA does not consume path length budget. */
    if( !fd_x509_name_equal( certs[i+1].issuer, certs[i+1].issuer_len,
                             certs[i+1].subject, certs[i+1].subject_len ) )
      non_self_issued_ca_cnt++;
  }

  return FD_X509_VERIFY_ERR_NO_TRUST_ANCHOR;  /* not reached */
}

int
fd_x509_verify_tls_cert_msg( uchar const *              cert_msg,
                             ulong                      cert_msg_sz,
                             fd_x509_ca_store_t const * ca_store,
                             char const *               hostname,
                             ulong                      hostname_len,
                             long                       unix_seconds ) {

  if( FD_UNLIKELY( !cert_msg ) ) return FD_X509_VERIFY_ERR_PARSE;

  uchar const * p   = cert_msg;
  uchar const * end = cert_msg + cert_msg_sz;

  /* A server Certificate sent for the main handshake must have an empty
     certificate_request_context (RFC 8446 Section 4.4.2). */
  if( FD_UNLIKELY( (ulong)(end-p)<1UL ) ) return FD_X509_VERIFY_ERR_PARSE;
  ulong ctx_len = *p++;
  if( FD_UNLIKELY( ctx_len ) ) return FD_X509_VERIFY_ERR_PARSE;

  /* certificate_list<0..2^24-1> */
  if( FD_UNLIKELY( (ulong)(end-p)<3UL ) ) return FD_X509_VERIFY_ERR_PARSE;
  ulong list_len = ( (ulong)p[0]<<16 ) | ( (ulong)p[1]<<8 ) | (ulong)p[2];
  p += 3;
  if( FD_UNLIKELY( list_len != (ulong)( end-p ) ) ) return FD_X509_VERIFY_ERR_PARSE;
  uchar const * list_end = p + list_len;

  uchar const * chain_der   [ FD_X509_CHAIN_MAX ];
  ulong         chain_der_sz[ FD_X509_CHAIN_MAX ];
  ulong         chain_cnt = 0UL;

  while( p < list_end ) {
    if( FD_UNLIKELY( chain_cnt >= FD_X509_CHAIN_MAX ) ) return FD_X509_VERIFY_ERR_CHAIN_TOO_LONG;

    /* cert_data<1..2^24-1> */
    if( FD_UNLIKELY( (ulong)(list_end-p)<3UL ) ) return FD_X509_VERIFY_ERR_PARSE;
    ulong cert_len = ( (ulong)p[0]<<16 ) | ( (ulong)p[1]<<8 ) | (ulong)p[2];
    p += 3;
    if( FD_UNLIKELY( !cert_len ) )
      return FD_X509_VERIFY_ERR_PARSE;
    if( FD_UNLIKELY( cert_len > FD_X509_CERT_SZ_MAX ) )
      return FD_X509_VERIFY_ERR_CERT_TOO_LARGE;
    if( FD_UNLIKELY( (ulong)(list_end-p)<cert_len ) )
      return FD_X509_VERIFY_ERR_PARSE;

    chain_der   [ chain_cnt ] = p;
    chain_der_sz[ chain_cnt ] = cert_len;
    chain_cnt++;
    p += cert_len;

    /* extensions<0..2^16-1> */
    if( FD_UNLIKELY( (ulong)(list_end-p)<2UL ) ) return FD_X509_VERIFY_ERR_PARSE;
    ulong ext_len = ( (ulong)p[0]<<8 ) | (ulong)p[1];
    p += 2;
    if( FD_UNLIKELY( (ulong)(list_end-p)<ext_len ) ) return FD_X509_VERIFY_ERR_PARSE;
    uchar const * ext_end = p + ext_len;

    while( p < ext_end ) {
      if( FD_UNLIKELY( (ulong)(ext_end-p)<4UL ) ) return FD_X509_VERIFY_ERR_PARSE;
      p += 2; /* ExtensionType */
      ulong ext_data_len = ( (ulong)p[0]<<8 ) | (ulong)p[1];
      p += 2;
      if( FD_UNLIKELY( (ulong)(ext_end-p)<ext_data_len ) ) return FD_X509_VERIFY_ERR_PARSE;
      p += ext_data_len;
    }
  }

  if( FD_UNLIKELY( !chain_cnt ) ) return FD_X509_VERIFY_ERR_PARSE;

  return fd_x509_verify_chain( chain_der, chain_der_sz, chain_cnt,
                              ca_store, hostname, hostname_len, unix_seconds );
}
