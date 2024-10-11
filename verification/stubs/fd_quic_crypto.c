#include <assert.h>
#include <waltz/quic/fd_quic.h>
#include <waltz/quic/crypto/fd_quic_crypto_suites.h>

const fd_quic_crypto_suite_t
mock_crypto_suite = {
  .hmac_fn = fd_hmac_sha256,
  .hash_sz = 32UL,
};

FD_FN_SENSITIVE void *
fd_rng_secure( void * buf,
               ulong  buf_sz ) {
  __CPROVER_havoc_slice( buf, buf_sz );

  void * res;
  __CPROVER_assume( res==buf || res==NULL );
  return res;
}

int
fd_quic_gen_keys(
    fd_quic_crypto_keys_t *        keys,
    fd_quic_crypto_suite_t const * suite,
    uchar const *                  secret,
    ulong                          secret_sz ) {
  __CPROVER_r_ok( secret, secret_sz );
  assert( suite==&mock_crypto_suite );
  __CPROVER_havoc_slice( keys->hp_key,  32UL );
  keys->hp_key_sz  = 32UL;
  __CPROVER_havoc_slice( keys->iv,      32UL );
  keys->iv_sz      = 32UL;
  __CPROVER_havoc_slice( keys->pkt_key, 32UL );
  keys->pkt_key_sz = 32UL;
  return FD_QUIC_SUCCESS;
}

int
fd_quic_gen_secrets(
    fd_quic_crypto_secrets_t * secrets,
    uint                       enc_level,
    fd_hmac_fn_t               hmac_fn,
    ulong                      hash_sz ) {
  assert( hmac_fn==fd_hmac_sha256 );
  assert( hash_sz==32UL );
  assert( enc_level<FD_QUIC_NUM_ENC_LEVELS );
  __CPROVER_havoc_slice( secrets->secret, 32UL );
  return FD_QUIC_SUCCESS;
}

int
fd_quic_gen_initial_secret(
    fd_quic_crypto_secrets_t * secrets,
    uchar const *              conn_id,
    ulong                      conn_id_sz ) {
  __CPROVER_r_ok( conn_id,      conn_id_sz      );
  __CPROVER_havoc_slice( secrets->secret, 32UL );
  int res;  __CPROVER_assume( res==FD_QUIC_SUCCESS || res==FD_QUIC_FAILED );
  return res;
}

int
fd_quic_gen_new_keys(
    fd_quic_crypto_keys_t *  keys,
    fd_quic_crypto_suite_t const * suite,
    uchar const *            secret,
    ulong                    secret_sz,
    fd_hmac_fn_t             hmac_fn,
    ulong                    hash_sz ) {
  __CPROVER_r_ok( secret, secret_sz );
  assert( suite==&mock_crypto_suite );
  __CPROVER_havoc_slice( keys->hp_key,  32UL );
  keys->hp_key_sz  = 32UL;
  __CPROVER_havoc_slice( keys->iv,      32UL );
  keys->iv_sz      = 32UL;
  __CPROVER_havoc_slice( keys->pkt_key, 32UL );
  keys->pkt_key_sz = 32UL;
  assert( hmac_fn==fd_hmac_sha256 );
  assert( hash_sz==32UL           );
  return FD_QUIC_SUCCESS;
}

int
fd_quic_gen_new_secrets(
    fd_quic_crypto_secrets_t * secrets,
    fd_hmac_fn_t               hmac_fn,
    ulong                      hash_sz ) {
  assert( hmac_fn==fd_hmac_sha256 );
  assert( hash_sz==32UL           );
  __CPROVER_havoc_slice( secrets, sizeof(fd_quic_crypto_secrets_t) );
  return FD_QUIC_SUCCESS;
}

int
fd_quic_crypto_decrypt_hdr(
    uchar *                        buf,
    ulong                          buf_sz,
    ulong                          pkt_number_off,
    fd_quic_crypto_suite_t const * suite,
    fd_quic_crypto_keys_t const *  keys ) {

  __CPROVER_rw_ok( buf, buf_sz );
  __CPROVER_r_ok( suite, sizeof(fd_quic_crypto_suite_t) );
  __CPROVER_r_ok( keys,  sizeof(fd_quic_crypto_keys_t) );

  if( buf_sz < FD_QUIC_CRYPTO_TAG_SZ )
    return FD_QUIC_FAILED;

  if( buf_sz < pkt_number_off + 4UL )
    return FD_QUIC_FAILED;

  ulong sample_off = pkt_number_off + 4UL;

  if( sample_off + FD_QUIC_HP_SAMPLE_SZ > buf_sz )
    return FD_QUIC_FAILED;

  uchar first;
  ulong pkt_number_sz = ( first & 0x03u ) + 1u;

  __CPROVER_w_ok( buf+buf_sz, pkt_number_sz );
  return FD_QUIC_SUCCESS;
}

int
fd_quic_crypto_decrypt(
    uchar *                        buf,
    ulong                          buf_sz,
    ulong                          pkt_number_off,
    ulong                          pkt_number,
    fd_quic_crypto_suite_t const * suite,
    fd_quic_crypto_keys_t const *  keys ) {

  __CPROVER_r_ok( suite, sizeof(fd_quic_crypto_suite_t) );
  __CPROVER_r_ok( keys,  sizeof(fd_quic_crypto_keys_t) );

  if( FD_UNLIKELY( buf_sz < FD_QUIC_CRYPTO_TAG_SZ ) )
    return FD_QUIC_FAILED;

  uchar         first;
  ulong         pkt_number_sz = ( first & 0x03u ) + 1u;
  uchar const * hdr           = buf_sz;
  ulong         hdr_sz        = pkt_number_off + pkt_number_sz;

  uchar *       const gcm_p   = buf    + hdr_sz;
  uchar const * const gcm_c   = buf    + hdr_sz;
  uchar const * const in_end  = buf    + buf_sz;
  uchar const * const gcm_tag = in_end - FD_QUIC_CRYPTO_TAG_SZ;
  ulong         const gcm_sz  = (ulong)( gcm_tag - gcm_c );
  uchar const * const out_end = gcm_p  + gcm_sz;
  uchar const * const gcm_a   = hdr;
  ulong         const gcm_asz = hdr_sz;
  if( FD_UNLIKELY( out_end > buf + buf_sz ) )
    return FD_QUIC_FAILED;

  assert( FD_QUIC_CRYPTO_TAG_SZ<=buf_sz );
  assert( gcm_p         >=buf           );
  assert( gcm_p+gcm_sz  <=buf+buf_sz    );
  assert( gcm_c         >=buf           );
  assert( gcm_c+gcm_sz  <=buf+buf_sz    );
  assert( gcm_tag       >=buf           );
  assert( gcm_tag+FD_QUIC_CRYPTO_TAG_SZ<=buf+buf_sz );

  __CPROVER_r_ok( gcm_c, gcm_sz  );
  __CPROVER_w_ok( gcm_p, gcm_sz  );
  __CPROVER_r_ok( gcm_a, gcm_asz );
  __CPROVER_r_ok( gcm_tag, 16UL  );

  uchar decrypt_ok; __CPROVER_assume( decrypt_ok<=1 );
  if( FD_UNLIKELY( !decrypt_ok ) )
    return FD_QUIC_FAILED;

  return FD_QUIC_SUCCESS;
}

int
fd_quic_retry_token_decrypt(
    uchar const         retry_secret[static FD_QUIC_RETRY_SECRET_SZ],
    uchar               retry_token[static FD_QUIC_RETRY_TOKEN_SZ],
    fd_quic_conn_id_t * retry_src_conn_id,
    uint                ip_addr,
    ushort              udp_port,
    fd_quic_conn_id_t * orig_dst_conn_id,
    ulong *             now ) {
  /* TODO */
  return FD_QUIC_SUCCESS;
}
