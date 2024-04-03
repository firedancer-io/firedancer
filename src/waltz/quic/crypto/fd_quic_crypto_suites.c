#include "fd_quic_crypto_suites.h"
#include "../fd_quic.h"

#include <assert.h>
#include <limits.h>
#include <sys/random.h>

#include "../../../ballet/aes/fd_aes_gcm.h"

/* FD_QUIC_CRYPTO_V1_INITIAL_SALT is the salt to the initial secret
   HKDF in QUIC v1. */

uchar FD_QUIC_CRYPTO_V1_INITIAL_SALT[ 20UL ] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a };

/* Helpers */

#define FD_QUIC_HASH_SZ_sha256 (32UL)
#define FD_QUIC_HASH_SZ_sha384 (48UL)
#define FD_QUIC_HASH_SZ_sha512 (64UL)

void
fd_quic_crypto_ctx_init( fd_quic_crypto_ctx_t * ctx ) {

  /* initialize suites map */
#define EACH( ID, SUITE, MAJ, MIN, PKT, HP, HASHFN, KEY_SZ, IV_SZ, PKT_LIMIT, ... ) \
  ctx->suites[ ID ].id         = ID;                       \
  ctx->suites[ ID ].major      = MAJ;                      \
  ctx->suites[ ID ].minor      = MIN;                      \
  ctx->suites[ ID ].key_sz     = KEY_SZ;                   \
  ctx->suites[ ID ].iv_sz      = IV_SZ;                    \
  ctx->suites[ ID ].hmac_fn    = fd_hmac_##HASHFN;         \
  ctx->suites[ ID ].hash_sz    = FD_QUIC_HASH_SZ_##HASHFN; \
  ctx->suites[ ID ].pkt_limit  = PKT_LIMIT;
  FD_QUIC_CRYPTO_SUITE_LIST( EACH, )
#undef EACH
}

void
fd_quic_crypto_ctx_fini( fd_quic_crypto_ctx_t * ctx ) {
  /* for now, nothing to do */
  (void)ctx;
}

void *
fd_quic_hkdf_extract( void *       output,
                      void const * salt,    ulong salt_sz,
                      void const * conn_id, ulong conn_id_sz,
                      fd_hmac_fn_t hmac ) {
  return hmac( conn_id, conn_id_sz, salt, salt_sz, output );
}

void *
fd_quic_hkdf_expand_label( uchar *       output,  ulong output_sz,
                           uchar const * secret,  ulong secret_sz,
                           uchar const * label,   ulong label_sz,
                           fd_hmac_fn_t  hmac,
                           ulong         hash_sz ) {

  uchar temp[ FD_QUIC_CRYPTO_HASH_SZ_BOUND ] = {0};

  /* avoid overflow issues */
  if( FD_UNLIKELY( ( output_sz  > ( 1u<<16u )                ) |
                   ( secret_sz  > INT_MAX                    ) |
                   ( label_sz   > FD_QUIC_CRYPTO_LABEL_BOUND ) ) ) {
    FD_DEBUG(
        FD_LOG_WARNING( (
            "fd_quic_hkdf_expand_label: invalid params (output_sz=%lu secret_sz=%lu label_sz=%lu)",
            output_sz,
            secret_sz,
            label_sz
        ) );
    )
    return NULL;
  }

  if( FD_UNLIKELY( output_sz > hash_sz ) ) {
    FD_DEBUG( FD_LOG_WARNING(
        ( "fd_quic_hkdf_expand_label: output_sz (%lu) is larger than hash size (%lu)",
          output_sz,
          hash_sz )
    ) );
    return NULL;
  }

  if( FD_UNLIKELY( hash_sz > FD_QUIC_CRYPTO_HASH_SZ_BOUND ) ) {
    FD_DEBUG( FD_LOG_WARNING( ( "fd_quic_hkdf_expand_label: hash_sz is larger than output buffer" ) )
    );
    return NULL;
  }

  /* expand */
  uchar HKDF_PREFIX[6] = "tls13 ";
  ulong HKDF_PREFIX_SZ = sizeof( HKDF_PREFIX );

  /* format label */
  uchar label_data[ FD_QUIC_CRYPTO_LABEL_BOUND ];
  /* label data is:
       output size:          2 bytes
       size of prefix+label: 1 byte
       const 0x00:           1 byte
       const 0x01:           1 byte */
  ulong label_data_sz = 3 + HKDF_PREFIX_SZ + label_sz + 1 + 1;
  if( FD_UNLIKELY( label_data_sz > sizeof( label_data ) ) ) {
    FD_DEBUG( FD_LOG_WARNING( ( "fd_quic_hkdf_expand_label: label data size larger than allowed" ) ) );
    return NULL;
  }

  label_data[ 0 ] = (uchar)( output_sz >> 8u           );
  label_data[ 1 ] = (uchar)( output_sz & 0xffu         );
  label_data[ 2 ] = (uchar)( HKDF_PREFIX_SZ + label_sz );

  fd_memcpy( label_data+3,                HKDF_PREFIX, HKDF_PREFIX_SZ );
  fd_memcpy( label_data+3+HKDF_PREFIX_SZ, label,       label_sz       );

  label_data[ 3+HKDF_PREFIX_SZ+label_sz ] = 0x00u;

  // This is the first stage of HKDF-expand from https://www.rfc-editor.org/rfc/rfc5869
  // only one stage is required to achieve the desired length
  // so we just do it here
  label_data[4 + HKDF_PREFIX_SZ + label_sz] = 0x01u;

  // hash compute

  hmac( label_data, label_data_sz, secret, secret_sz, temp );
  fd_memcpy( output, temp, output_sz );
  return output;
}


int
fd_quic_gen_initial_secret(
    fd_quic_crypto_secrets_t * secrets,
    uchar const *              initial_salt,
    ulong                      initial_salt_sz,
    uchar const *              conn_id,
    ulong                      conn_id_sz ) {
  if( FD_UNLIKELY(
      !fd_quic_hkdf_extract( secrets->initial_secret,
                             initial_salt,            initial_salt_sz,
                             conn_id,                 conn_id_sz,
                             fd_hmac_sha256 ) ) ) {
    FD_DEBUG( FD_LOG_WARNING( ( "fd_quic_hkdf_extract failed" ) ) );
    return FD_QUIC_FAILED;
  }

  return FD_QUIC_SUCCESS;
}


int
fd_quic_gen_secrets(
    fd_quic_crypto_secrets_t * secrets,
    uint                       enc_level,
    fd_hmac_fn_t               hmac_fn,
    ulong                      hash_sz ) {
  uchar * client_secret = secrets->secret[enc_level][0];
  uchar * server_secret = secrets->secret[enc_level][1];

  if( enc_level == fd_quic_enc_level_initial_id ) {
    secrets->secret_sz[enc_level][0] = \
    secrets->secret_sz[enc_level][1] = FD_QUIC_INITIAL_SECRET_SZ;
  }

  uchar client_secret_sz = secrets->secret_sz[ enc_level ][0];
  uchar server_secret_sz = secrets->secret_sz[ enc_level ][1];

  char const client_in[] = FD_QUIC_CRYPTO_LABEL_CLIENT_IN;
  if( FD_UNLIKELY( !fd_quic_hkdf_expand_label(
      client_secret,           client_secret_sz,
      secrets->initial_secret, sizeof( secrets->initial_secret ),
      (uchar*)client_in,       strlen( client_in ),
      hmac_fn,                 hash_sz ) ) ) {
    FD_DEBUG( FD_LOG_WARNING( ( "fd_quic_hkdf_expand_label failed" ) ) );
    return FD_QUIC_FAILED;
  }

  char const server_in[] = FD_QUIC_CRYPTO_LABEL_SERVER_IN;
  if( FD_UNLIKELY( !fd_quic_hkdf_expand_label(
      server_secret,           server_secret_sz,
      secrets->initial_secret, sizeof( secrets->initial_secret ),
      (uchar*)server_in,       strlen( server_in ),
      hmac_fn,                 hash_sz ) ) ) {
    FD_LOG_WARNING(( "fd_quic_hkdf_expand_label failed" ));
    return FD_QUIC_FAILED;
  }

  return FD_QUIC_SUCCESS;
}


/* generate new secrets

   Used during key update to generate new secrets from the
   existing secrets

   see rfc9001 section 6, rfc8446 section 7.2 */
int
fd_quic_gen_new_secrets(
    fd_quic_crypto_secrets_t * secrets,
    fd_hmac_fn_t               hmac_fn,
    ulong                      hash_sz ) {
  /* Defined as:
     application_traffic_secret_N+1 =
           HKDF-Expand-Label(application_traffic_secret_N,
                             "traffic upd", "", Hash.length) */
  uint enc_level = fd_quic_enc_level_appdata_id;
  uchar * client_secret = secrets->new_secret[0];
  uchar * server_secret = secrets->new_secret[1];

  uchar * old_client_secret = secrets->secret[enc_level][0];
  uchar * old_server_secret = secrets->secret[enc_level][1];

  uchar client_secret_sz = secrets->secret_sz[enc_level][0];
  uchar server_secret_sz = secrets->secret_sz[enc_level][1];

  static char const key_update[] = FD_QUIC_CRYPTO_LABEL_KEY_UPDATE;
  if( FD_UNLIKELY( !fd_quic_hkdf_expand_label(
      client_secret,      client_secret_sz,
      old_client_secret,  client_secret_sz,
      (uchar*)key_update, sizeof(key_update)-1UL,
      hmac_fn,            hash_sz ) ) ) {
    FD_LOG_WARNING(( "fd_quic_hkdf_expand_label failed" ));
    return FD_QUIC_FAILED;
  }

  if( FD_UNLIKELY( !fd_quic_hkdf_expand_label(
      server_secret,      server_secret_sz,
      old_server_secret,  server_secret_sz,
      (uchar*)key_update, sizeof(key_update)-1UL,
      hmac_fn,            hash_sz ) ) ) {
    FD_LOG_WARNING(( "fd_quic_hkdf_expand_label failed" ));
    return FD_QUIC_FAILED;
  }

  return FD_QUIC_SUCCESS;
}


int
fd_quic_gen_keys(
    fd_quic_crypto_keys_t *  keys,
    fd_quic_crypto_suite_t const * suite,
    uchar const *            secret,
    ulong                    secret_sz ) {

  fd_hmac_fn_t hmac_fn = suite->hmac_fn;
  ulong        hash_sz = suite->hash_sz;
  ulong        key_sz  = suite->key_sz;
  ulong        iv_sz   = suite->iv_sz;

  if( key_sz > sizeof( keys->pkt_key ) ||
      key_sz > sizeof( keys->hp_key )  ||
      iv_sz  > sizeof( keys->iv ) ) {
    return FD_QUIC_FAILED;
  }

  /* quic key */

  /* output length passed with "quic hp" and "quic key" must be the key size from
     the current cipher */
  if( FD_UNLIKELY( !fd_quic_hkdf_expand_label(
      keys->pkt_key, key_sz,
      secret, secret_sz,
      (uchar*)FD_QUIC_CRYPTO_LABEL_QUIC_KEY,
      FD_QUIC_CRYPTO_LABEL_QUIC_KEY_SZ,
      hmac_fn, hash_sz ) ) ) {
    return FD_QUIC_FAILED;
  }
  keys->pkt_key_sz = key_sz;

  /* quic hp */

  /* output length passed with "quic hp" and "quic key" must be the key size from
     the current cipher */
  if( FD_UNLIKELY( !fd_quic_hkdf_expand_label(
      keys->hp_key, key_sz,
      secret, secret_sz,
      (uchar*)FD_QUIC_CRYPTO_LABEL_QUIC_HP,
      FD_QUIC_CRYPTO_LABEL_QUIC_HP_SZ,
      hmac_fn, hash_sz ) ) ) {
    return FD_QUIC_FAILED;
  }
  keys->hp_key_sz = key_sz;

  /* quic iv */
  if( FD_UNLIKELY( !fd_quic_hkdf_expand_label(
      keys->iv, iv_sz,
      secret, secret_sz,
      (uchar*)FD_QUIC_CRYPTO_LABEL_QUIC_IV,
      FD_QUIC_CRYPTO_LABEL_QUIC_IV_SZ,
      hmac_fn, hash_sz ) ) ) {
    return FD_QUIC_FAILED;
  }
  keys->iv_sz = iv_sz;

  return FD_QUIC_SUCCESS;
}


/* generates packet key and iv key
   used by key update

   TODO this overlaps with fd_quic_gen_keys, split into gen_hp_keys and gen_pkt_keys */
int
fd_quic_gen_new_keys(
    fd_quic_crypto_keys_t *  keys,
    fd_quic_crypto_suite_t const * suite,
    uchar const *            secret,
    ulong                    secret_sz,
    fd_hmac_fn_t             hmac_fn,
    ulong                    hash_sz ) {
  ulong key_sz = suite->key_sz;
  ulong iv_sz  = suite->iv_sz;

  if( key_sz > sizeof( keys->pkt_key ) ||
      iv_sz  > sizeof( keys->iv ) ) {
    return FD_QUIC_FAILED;
  }

  /* quic key */

  /* output length passed with "quic key" must be the key size from
     the current cipher */
  if( FD_UNLIKELY( !fd_quic_hkdf_expand_label( keys->pkt_key, key_sz,
      secret, secret_sz,
      (uchar*)FD_QUIC_CRYPTO_LABEL_QUIC_KEY,
      FD_QUIC_CRYPTO_LABEL_QUIC_KEY_SZ,
      hmac_fn, hash_sz ) ) ) {
    return FD_QUIC_FAILED;
  }
  keys->pkt_key_sz = key_sz;

  /* quic iv */
  if( FD_UNLIKELY( !fd_quic_hkdf_expand_label( keys->iv, iv_sz,
      secret, secret_sz,
      (uchar*)FD_QUIC_CRYPTO_LABEL_QUIC_IV,
      FD_QUIC_CRYPTO_LABEL_QUIC_IV_SZ,
      hmac_fn, hash_sz ) ) ) {
    return FD_QUIC_FAILED;
  }
  keys->iv_sz = iv_sz;

  return FD_QUIC_SUCCESS;
}


/* encrypt a packet

   uses the keys in keys to encrypt the packet "pkt" with header "hdr"
   (of length pkt_sz, and hdr_sz respectively) into out.

   out should have enough space to contain the full output with extra space
   for a full block which depends on the cipher

   *out_sz is used to determine the amount of buffer space left at *out
     if enough space is not available, the function fails and returns
     FD_QUIC_FAILED
   *out_sz is also set to the number of bytes written into *out at the end

   args
     out               the destination for the encrypted output
     out_sz            a pointer to the size of the buffer (on input) and the size of
                         the written bytes (on output)
     hdr               the input header bytes
     hdr_sz            the size of the header in bytes
     pkt               the input packet bytes
     pkt_sz            the size of the packet in bytes
     keys              a pointer to the keys to use
     pkt_number        needed to create the nonce used in encryption
                         likely points to the packet number within "hdr"
     pkt_number_sz     the size of the packet number in bytes
     */

int
fd_quic_crypto_encrypt(
    uchar *                  const out,
    ulong *                  const out_sz,
    uchar const *            const hdr,
    ulong                    const hdr_sz,
    uchar const *            const pkt,
    ulong                    const pkt_sz,
    fd_quic_crypto_suite_t const * const suite,
    fd_quic_crypto_keys_t *  const pkt_keys,
    fd_quic_crypto_keys_t *  const hp_keys ) {

  (void)suite;

  /* ensure we have enough space in the output buffer
     most space used by cipher:
       header bytes (just XORed)
       input bytes (encrypted)
       tag bytes */

  /* bound on the bytes needed for cipher output */
  ulong cipher_out_bound = hdr_sz + pkt_sz + FD_QUIC_CRYPTO_TAG_SZ;

  if( FD_UNLIKELY( *out_sz < cipher_out_bound ) ) {
    FD_DEBUG( FD_LOG_WARNING(( "fd_quic_crypto_encrypt: output buffer not big enough" )) );
    return FD_QUIC_FAILED;
  }

  if( FD_UNLIKELY( ( hdr_sz < 4 ) | ( hdr_sz > INT_MAX ) ) ) {
    FD_DEBUG( FD_LOG_WARNING(( "fd_quic_crypto_encrypt: packet header size out of bounds" )) );
    return FD_QUIC_FAILED;
  }

  /* bounds check */
  if( FD_UNLIKELY( pkt_sz > INT_MAX ) ) return FD_QUIC_FAILED;

  /* copy the header into the output */
  fd_memcpy( out, hdr, hdr_sz );

  /* first byte needed in a couple of places */
  uchar first = out[0];
  ulong pkt_number_sz = ( first & 0x03u ) + 1;
  uchar const * pkt_number = out + hdr_sz - pkt_number_sz;

  // nonce is quic-iv XORed with packet-number
  // packet number is 1-4 bytes, so only XOR last pkt_number_sz bytes
  uchar nonce[FD_QUIC_NONCE_SZ] = {0};
  ulong nonce_tmp = FD_QUIC_NONCE_SZ - pkt_number_sz;
  uchar const * quic_iv = pkt_keys->iv;
  fd_memcpy( nonce, quic_iv, nonce_tmp );
  for( ulong k = 0; k < pkt_number_sz; ++k ) {
    ulong j = nonce_tmp + k;
    nonce[j] = quic_iv[j] ^ pkt_number[k];
  }

  // Initial packets cipher uses AEAD_AES_128_GCM with keys derived from the Destination Connection ID field of the
  // first Initial packet sent by the client; see rfc9001 Section 5.2.

  fd_aes_gcm_t pkt_cipher[1];
  fd_aes_128_gcm_init( pkt_cipher, pkt_keys->pkt_key, nonce );

  /* cipher_text is start of encrypted packet bytes, which starts after the header */
  uchar * cipher_text = out + hdr_sz;
  uchar * tag         = cipher_text + pkt_sz;
  uchar * pkt_end     = tag + FD_QUIC_CRYPTO_TAG_SZ;

  fd_aes_gcm_aead_encrypt( pkt_cipher, cipher_text, pkt, pkt_sz, hdr, hdr_sz, tag );

  *out_sz = (ulong)( pkt_end - out );

  /* Header protection */

  /* sample start is defined as 4 bytes after the start of the packet number
     so shorter packet numbers means sample starts later in the cipher text */
  uchar const * sample = pkt_number + 4;

  fd_aes_key_t ecb[1];
  fd_aes_set_encrypt_key( hp_keys->hp_key, 128, ecb );
  uchar hp_cipher[16];
  fd_aes_encrypt( sample, hp_cipher, ecb );

  /* hp_cipher is mask */
  uchar const * mask = hp_cipher;

  uchar long_hdr = first & 0x80u; /* long header? */
  out[0] ^= (uchar)( mask[0] & ( long_hdr ? 0x0fu : 0x1fu ) );

  ulong pkt_number_off = hdr_sz - pkt_number_sz;

  for( ulong j = 0; j < pkt_number_sz; ++j ) {
    out[pkt_number_off + j] ^= mask[1+j];
  }

  return FD_QUIC_SUCCESS;
}

int
fd_quic_crypto_decrypt(
    uchar *                  const out,
    ulong *                  const p_out_sz,
    uchar const *            const in,
    ulong                    const in_sz,
    ulong                    const pkt_number_off,
    ulong                    const pkt_number,
    fd_quic_crypto_suite_t const * const suite,
    fd_quic_crypto_keys_t  const * const keys ) {

  (void)suite;

  ulong const out_bufsz = *p_out_sz;

  /* must have space for cipher_text_sz - FD_QUIC_CRYPTO_TAG_SZ */
  if( FD_UNLIKELY( out_bufsz + FD_QUIC_CRYPTO_TAG_SZ < in_sz ) ) {
    FD_DEBUG( FD_LOG_WARNING( ( "fd_quic_crypto_decrypt: plain text buffer too small" ) ) );
    return FD_QUIC_FAILED;
  }

  /* Derive header size */
  uint          first         = out[0];
  ulong         pkt_number_sz = ( first & 0x03u ) + 1u;
  uchar const * hdr           = out;
  ulong         hdr_sz        = pkt_number_off + pkt_number_sz;

  /* calculate nonce for decryption
     nonce is quic-iv XORed with *reconstructed* packet-number
     packet number is 1-4 bytes, so only XOR last pkt_number_sz bytes */
  uchar nonce[FD_QUIC_NONCE_SZ] = {0};
  uint nonce_tmp = FD_QUIC_NONCE_SZ - 4;
  uchar const * quic_iv = keys->iv;
  fd_memcpy( nonce, quic_iv, nonce_tmp );
  for( uint k = 0; k < 4; ++k ) {
    uint j = nonce_tmp + k;
    nonce[j] = (uchar)( quic_iv[j] ^ ( (uchar)( (pkt_number>>( (3u - k) * 8u ))&0xFF ) ) );
  }

  if( FD_UNLIKELY( in_sz < hdr_sz+FD_QUIC_CRYPTO_TAG_SZ ) )
    return FD_QUIC_FAILED;

  /* AES-GCM decrypt */
  uchar *       const gcm_p   = out    + hdr_sz;
  uchar const * const gcm_c   = in     + hdr_sz;
  uchar const * const in_end  = in     + in_sz;
  uchar const * const gcm_tag = in_end - FD_QUIC_CRYPTO_TAG_SZ;
  ulong         const gcm_sz  = (ulong)( gcm_tag - gcm_c );
  uchar const * const out_end = gcm_p  + gcm_sz;
  uchar const * const gcm_a   = hdr;
  ulong         const gcm_asz = hdr_sz;
  if( FD_UNLIKELY( out_end > out + out_bufsz ) ) {
    FD_DEBUG( FD_LOG_WARNING( ( "fd_quic_crypto_decrypt: plain text buffer too small" ) ) );
    return FD_QUIC_FAILED;
  }

  assert( FD_QUIC_CRYPTO_TAG_SZ<=in_sz  );
  assert( gcm_p         >=out           );
  assert( gcm_p+gcm_sz  <=out+out_bufsz );
  assert( gcm_c         >=in            );
  assert( gcm_c+gcm_sz  <=in+in_sz      );
  assert( gcm_tag       >=in            );
  assert( gcm_tag+FD_QUIC_CRYPTO_TAG_SZ<=in+in_sz );

  fd_aes_gcm_t pkt_cipher[1];
  fd_aes_128_gcm_init( pkt_cipher, keys->pkt_key, nonce );

  int decrypt_ok =
    fd_aes_gcm_aead_decrypt( pkt_cipher, gcm_c, gcm_p, gcm_sz, gcm_a, gcm_asz, gcm_tag );
  if( FD_UNLIKELY( !decrypt_ok ) ) {
    FD_DEBUG( FD_LOG_WARNING(( "fd_aes_gcm_aead_decrypt failed" )) );
    return FD_QUIC_FAILED;
  }

  *p_out_sz = (ulong)(out_end - out);
  return FD_QUIC_SUCCESS;
}


int
fd_quic_crypto_decrypt_hdr(
    uchar *                  plain_text,
    ulong                    plain_text_sz,
    uchar const *            cipher_text,
    ulong                    cipher_text_sz,
    ulong                    pkt_number_off,
    fd_quic_crypto_suite_t const * suite,
    fd_quic_crypto_keys_t const *  keys ) {

  (void)suite;

  /* must have at least a short header */
  if( FD_UNLIKELY( cipher_text_sz < FD_QUIC_CRYPTO_TAG_SZ ) ) {
    FD_LOG_WARNING(( "fd_quic_crypto_decrypt: cipher text too small" ));
    return FD_QUIC_FAILED;
  }

  /* must have capacity for header */
  if( FD_UNLIKELY( plain_text_sz < pkt_number_off + 4 ) ) {
    FD_DEBUG( FD_LOG_WARNING( ( "fd_quic_crypto_decrypt: plain text buffer too small" ) ) );
    return FD_QUIC_FAILED;
  }

  uint          first      = cipher_text[0]; /* first byte */
  uint          long_hdr   = first & 0x80u;  /* long header? (this bit is not encrypted) */
  ulong         sample_off = pkt_number_off + 4;

  if( FD_UNLIKELY( sample_off + FD_QUIC_HP_SAMPLE_SZ > cipher_text_sz ) ) {
    FD_DEBUG( FD_LOG_WARNING(( "fd_quic_crypto_decrypt failed. Not enough bytes for a sample" )) );
    return FD_QUIC_FAILED;
  }

  uchar const * sample = cipher_text + sample_off;

  /* TODO this is hardcoded to AES-128 */
  uchar hp_cipher[16];
  fd_aes_key_t ecb[1];
  fd_aes_set_encrypt_key( keys->hp_key, 128, ecb );
  fd_aes_encrypt( sample, hp_cipher, ecb );

  /* copy header, up to packet number, into output */
  fd_memcpy( plain_text, cipher_text, sample_off );

  /* hp_cipher is mask */
  uchar const * mask = hp_cipher;

  /* undo first byte mask */
  first        ^= (uint)mask[0] & ( long_hdr ? 0x0fu : 0x1fu );
  plain_text[0] = (uchar)first;

  /* now we can calculate the actual packet number size */
  ulong pkt_number_sz = ( first & 0x03u ) + 1u;

  /* undo packet number encryption */
  for( ulong j = 0u; j < pkt_number_sz; ++j ) {
    plain_text[pkt_number_off + j] ^= mask[1u+j];
  }

  return FD_QUIC_SUCCESS;
}

int
fd_quic_crypto_lookup_suite( uchar major,
                             uchar minor );

int
fd_quic_crypto_rand( uchar * buf,
                     ulong   buf_sz ) {
  /* TODO buffer */
  if( FD_UNLIKELY( (long)buf_sz!=getrandom( buf, buf_sz, 0 ) ) )
    return FD_QUIC_FAILED;
  return FD_QUIC_SUCCESS;
}

int fd_quic_retry_token_encrypt(
    fd_quic_conn_id_t const * orig_dst_conn_id,
    ulong               now,
    fd_quic_conn_id_t const * retry_src_conn_id,
    uint                ip_addr,
    ushort              udp_port,
    uchar               retry_token[static FD_QUIC_RETRY_TOKEN_SZ]
) {
  /* Generate pseudorandom bytes to use as the key for the AEAD HKDF. Note these bytes form the
     beginning of the retry token. */
  uchar * hkdf_key = retry_token;
  int     rc       = fd_quic_crypto_rand( retry_token, FD_QUIC_RETRY_TOKEN_HKDF_KEY_SZ );
  if ( FD_UNLIKELY( rc == FD_QUIC_FAILED ) ) {
    return FD_QUIC_FAILED;
  }

  /* The `extract` step of HKDF is unnecessary because what's being passed in to `expand` are
   pseudorandom bytes. */
  uchar aead_key[FD_QUIC_RETRY_TOKEN_AEAD_KEY_SZ];
  fd_quic_hkdf_expand_label(
      aead_key,
      FD_QUIC_RETRY_TOKEN_AEAD_KEY_SZ,
      hkdf_key,
      FD_QUIC_RETRY_TOKEN_HKDF_KEY_SZ,
      FD_QUIC_RETRY_TOKEN_AEAD_INFO,
      FD_QUIC_RETRY_TOKEN_AEAD_INFO_SZ,
      fd_hmac_sha256,
      FD_QUIC_RETRY_TOKEN_AEAD_KEY_SZ
  );

  /* Since the key is derived from random bytes and only used once, we use a zero IV (nonce).
     Note the IV length is by default 12 bytes (which is the recommended length for AES-GCM). */
  uchar iv[FD_QUIC_NONCE_SZ] = { 0 };

  /* The AAD is the client IPv4 address, UDP port, and retry source connection id. */
  ulong aad_sz = (ulong)FD_QUIC_RETRY_TOKEN_AAD_PREFIX_SZ + retry_src_conn_id->sz;
  uchar aad[aad_sz];
  memcpy( aad, &ip_addr, sizeof( uint ) );
  memcpy( aad + sizeof( uint ), &udp_port, sizeof( ushort ) );
  memcpy( aad + sizeof( uint ) + sizeof( ushort ), &retry_src_conn_id->sz, sizeof( uchar ) );
  memcpy(
      aad + sizeof( uint ) + sizeof( ushort ) + sizeof( uchar ),
      &retry_src_conn_id->conn_id,
      retry_src_conn_id->sz
  );

  uchar plaintext[FD_QUIC_RETRY_TOKEN_PLAINTEXT_SZ] = { 0 };
  if ( FD_UNLIKELY( orig_dst_conn_id->sz > FD_QUIC_MAX_CONN_ID_SZ ) ) return FD_QUIC_FAILED;
  memcpy( plaintext, &orig_dst_conn_id->sz, sizeof( uchar ) );
  memcpy( plaintext + 1, orig_dst_conn_id->conn_id, orig_dst_conn_id->sz );
  memcpy( plaintext + 1 + orig_dst_conn_id->sz, &now, sizeof( ulong ) );

  /* Append the ciphertext after random bytes in the retry_token. */
  uchar * ciphertext = hkdf_key + FD_QUIC_RETRY_TOKEN_HKDF_KEY_SZ;

  /* Append the authentication tag after ciphertext in the retry_token. */
  uchar * tag = ciphertext + FD_QUIC_RETRY_TOKEN_PLAINTEXT_SZ;

  fd_aes_gcm_t gcm[1];
  fd_aes_256_gcm_init( gcm, aead_key, iv );
  fd_aes_gcm_aead_encrypt( gcm, ciphertext, plaintext, FD_QUIC_RETRY_TOKEN_PLAINTEXT_SZ, aad, aad_sz, tag );

  return FD_QUIC_SUCCESS;
}

int fd_quic_retry_token_decrypt(
    uchar *             retry_token,
    fd_quic_conn_id_t * retry_src_conn_id,
    uint                ip_addr,
    ushort              udp_port,
    fd_quic_conn_id_t * orig_dst_conn_id,
    ulong *             now
) {
  /* Regenerate the AEAD key (the HKDF key is the first 32 bytes of the token). */
  uchar * hkdf_key = retry_token;
  uchar   aead_key[FD_QUIC_RETRY_TOKEN_AEAD_KEY_SZ] = { 0 };
  fd_quic_hkdf_expand_label(
      aead_key,
      FD_QUIC_RETRY_TOKEN_AEAD_KEY_SZ,
      hkdf_key,
      FD_QUIC_RETRY_TOKEN_HKDF_KEY_SZ,
      FD_QUIC_RETRY_TOKEN_AEAD_INFO,
      FD_QUIC_RETRY_TOKEN_AEAD_INFO_SZ,
      fd_hmac_sha256,
      FD_QUIC_RETRY_TOKEN_AEAD_KEY_SZ
  );

  uchar * ciphertext = hkdf_key + FD_QUIC_RETRY_TOKEN_HKDF_KEY_SZ;
  ulong   aad_sz     = (ulong)FD_QUIC_RETRY_TOKEN_AAD_PREFIX_SZ + retry_src_conn_id->sz;
  uchar   aad[aad_sz];
  memset( aad, 0, aad_sz );
  memcpy( aad, &ip_addr, sizeof( uint ) );
  memcpy( aad + sizeof( uint ), &udp_port, sizeof( ushort ) );
  memcpy( aad + sizeof( uint ) + sizeof( ushort ), &retry_src_conn_id->sz, sizeof( uchar ) );
  if ( FD_LIKELY( retry_src_conn_id->sz ) ) {
    fd_memcpy(
        aad + sizeof( uint ) + sizeof( ushort ) + sizeof( uchar ),
        &retry_src_conn_id->conn_id,
        retry_src_conn_id->sz
    );
  }
  uchar   iv[FD_QUIC_NONCE_SZ] = { 0 };
  uchar * tag                  = ciphertext + FD_QUIC_RETRY_TOKEN_CIPHERTEXT_SZ;
  uchar   plaintext[FD_QUIC_RETRY_TOKEN_PLAINTEXT_SZ] = { 0 };

  fd_aes_gcm_t gcm[1];
  fd_aes_256_gcm_init( gcm, aead_key, iv );
  int decrypt_ok =
    fd_aes_gcm_aead_decrypt( gcm, ciphertext, plaintext, FD_QUIC_RETRY_TOKEN_CIPHERTEXT_SZ, aad, aad_sz, tag );
  if( FD_UNLIKELY( !decrypt_ok ) )
    return FD_QUIC_FAILED;

  uchar orig_dst_conn_id_sz = *plaintext; /* untrusted input */
  if ( FD_UNLIKELY( orig_dst_conn_id_sz > FD_QUIC_MAX_CONN_ID_SZ ) ) return FD_QUIC_FAILED;
  orig_dst_conn_id->sz = orig_dst_conn_id_sz;
  memcpy( orig_dst_conn_id->conn_id, plaintext + sizeof( uchar ), orig_dst_conn_id->sz );
  *now = *( (ulong *)fd_type_pun( plaintext + sizeof( uchar ) + orig_dst_conn_id->sz ) );
  return FD_QUIC_SUCCESS;
}

int fd_quic_retry_integrity_tag_encrypt(
    uchar * retry_pseudo_pkt,
    int     retry_pseudo_pkt_len,
    uchar   retry_integrity_tag[static FD_QUIC_RETRY_INTEGRITY_TAG_SZ]
) {
  fd_aes_gcm_t gcm[1];
  fd_aes_128_gcm_init( gcm, FD_QUIC_RETRY_INTEGRITY_TAG_KEY, FD_QUIC_RETRY_INTEGRITY_TAG_NONCE );
  fd_aes_gcm_aead_encrypt( gcm, NULL, NULL, 0UL, retry_pseudo_pkt, (ulong)retry_pseudo_pkt_len, retry_integrity_tag );
  return FD_QUIC_SUCCESS;
}

int fd_quic_retry_integrity_tag_decrypt(
    uchar * retry_pseudo_pkt,
    int     retry_pseudo_pkt_len,
    uchar   retry_integrity_tag[static FD_QUIC_RETRY_INTEGRITY_TAG_SZ]
) {
  fd_aes_gcm_t gcm[1];
  fd_aes_128_gcm_init( gcm, FD_QUIC_RETRY_INTEGRITY_TAG_KEY, FD_QUIC_RETRY_INTEGRITY_TAG_NONCE );
  fd_aes_gcm_aead_decrypt( gcm, NULL, NULL, 0UL, retry_pseudo_pkt, (ulong)retry_pseudo_pkt_len, retry_integrity_tag );
  return FD_QUIC_SUCCESS;
}
