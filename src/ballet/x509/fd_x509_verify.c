#include "fd_x509_verify.h"
#include "../ed25519/fd_ed25519.h"
#include "../secp256r1/fd_secp256r1.h"
#include "../secp384r1/fd_secp384r1.h"
#include <string.h>

/* fd_x509_verify_sig verifies a certificate's signature given the
   issuer's public key.  Returns 0 on success, -1 on failure,
   or 1 if the signature algorithm is unsupported. */

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

  case FD_X509_SIG_ECDSA_SHA384: {
    if( FD_UNLIKELY( issuer_key_type != FD_X509_KEY_ECDSA_P384 ) ) return -1;
    if( FD_UNLIKELY( issuer_pubkey_len != 97 ) ) return -1;

    uchar raw_sig[96];
    if( FD_UNLIKELY( fd_x509_decode_ecdsa_sig( cert->sig, cert->sig_len, raw_sig, 48 ) ) )
      return -1;

    uchar compressed_pk[49];
    if( FD_UNLIKELY( fd_x509_ec_point_compress( issuer_pubkey, 48, compressed_pk ) ) )
      return -1;

    fd_sha512_t sha512[1];
    int err = fd_secp384r1_verify_no_low_s( cert->tbs, cert->tbs_len, raw_sig, compressed_pk, sha512 );
    return ( err == FD_SECP384R1_SUCCESS ) ? 0 : -1;
  }

  default:
    return 1;  /* unsupported sig algorithm */
  }
}

/* Implemented as specified by RFC 5280 Section 6.1.3. */
int
fd_x509_verify_chain( uchar const * const *        chain_der,
                      ulong const *                chain_der_sz,
                      ulong                        chain_cnt,
                      fd_x509_ca_store_t const *   ca_store,
                      char const *                 hostname,
                      ulong                        hostname_len ) {

  if( FD_UNLIKELY( chain_cnt == 0 ) ) return FD_X509_VERIFY_ERR_CHAIN_BREAK;
  if( FD_UNLIKELY( chain_cnt > FD_X509_CHAIN_MAX ) ) return FD_X509_VERIFY_ERR_CHAIN_TOO_LONG;

  fd_x509_cert_info_t certs[ FD_X509_CHAIN_MAX ];

  for( ulong i = 0; i < chain_cnt; i++ ) {
    if( FD_UNLIKELY( fd_x509_cert_parse( chain_der[i], chain_der_sz[i], &certs[i] ) ) )
      return FD_X509_VERIFY_ERR_PARSE;
  }

  if( hostname && hostname_len ) {
    if( FD_UNLIKELY( !fd_x509_san_matches( &certs[0], hostname, hostname_len ) ) )
      return FD_X509_VERIFY_ERR_HOSTNAME;
  }

  for( ulong i = 0; i < chain_cnt; i++ ) {
    uchar const * issuer_pubkey;
    ulong         issuer_pubkey_len;
    uchar         issuer_key_type;

    if( i + 1 < chain_cnt ) {
      /* Intermediate certificate. */
      if( FD_UNLIKELY( certs[i].issuer_len != certs[i+1].subject_len ||
                       0 != memcmp( certs[i].issuer, certs[i+1].subject, certs[i].issuer_len ) ) )
        return FD_X509_VERIFY_ERR_CHAIN_BREAK;

      if( FD_UNLIKELY( !certs[i+1].is_ca ) )
        return FD_X509_VERIFY_ERR_CA_FLAG;

      issuer_pubkey     = certs[i+1].pubkey;
      issuer_pubkey_len = certs[i+1].pubkey_len;
      issuer_key_type   = certs[i+1].key_type;
    } else {
      /* Root certificate. */
      fd_x509_ca_entry_t const * ca = fd_x509_ca_store_find( ca_store, certs[i].issuer, certs[i].issuer_len );
      if( !ca )
        ca = fd_x509_ca_store_find( ca_store, certs[i].subject, certs[i].subject_len );

      if( FD_UNLIKELY( !ca ) )
        return FD_X509_VERIFY_ERR_NO_TRUST_ANCHOR;

      issuer_pubkey     = ca->pubkey;
      issuer_pubkey_len = ca->pubkey_len;
      issuer_key_type   = ca->key_type;
    }

    int sig_rc = fd_x509_verify_sig( &certs[i], issuer_pubkey, issuer_pubkey_len, issuer_key_type );
    if( sig_rc < 0 )
      return FD_X509_VERIFY_ERR_SIG;
    if( sig_rc > 0 )
      return FD_X509_VERIFY_ERR_UNSUPPORTED;
  }

  return FD_X509_VERIFY_OK;
}
