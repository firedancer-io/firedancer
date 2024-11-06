#include "fd_quic_crypto_suites.h"
#include "../fd_quic.h"

#include <assert.h>
#include <limits.h>

#include "../../../ballet/aes/fd_aes_base.h"
#include "../../../ballet/aes/fd_aes_gcm.h"
#include "../../../ballet/hmac/fd_hmac.h"
#include "../templ/fd_quic_parse_util.h"

/* FD_QUIC_CRYPTO_V1_INITIAL_SALT is the salt to the initial secret
   HKDF in QUIC v1. */

static uchar const FD_QUIC_CRYPTO_V1_INITIAL_SALT[ 20UL ] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a };

static inline void
fd_quic_hkdf_extract( void *       output,
                      void const * salt,    ulong salt_sz,
                      void const * conn_id, ulong conn_id_sz ) {
  fd_hmac_sha256( conn_id, conn_id_sz, salt, salt_sz, output );
}

static inline void
fd_quic_hkdf_expand_label( uchar *       out,
                           ulong         out_sz,
                           uchar const   secret[ 32 ],
                           char const *  label,
                           ulong         label_sz ) {
  fd_tls_hkdf_expand_label( out, out_sz, secret, label, label_sz, NULL, 0UL );
}

void
fd_quic_gen_initial_secret(
    fd_quic_crypto_secrets_t * secrets,
    uchar const *              conn_id,
    ulong                      conn_id_sz ) {
  /* Initial Packets
     from rfc:
     initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a */
  uchar const * initial_salt    = FD_QUIC_CRYPTO_V1_INITIAL_SALT;
  ulong         initial_salt_sz = sizeof(FD_QUIC_CRYPTO_V1_INITIAL_SALT);
  fd_quic_hkdf_extract( secrets->initial_secret,
                        initial_salt,            initial_salt_sz,
                        conn_id,                 conn_id_sz );
}


void
fd_quic_gen_secrets(
    fd_quic_crypto_secrets_t * secrets,
    uint                       enc_level ) {
  uchar * client_secret = secrets->secret[enc_level][0];
  uchar * server_secret = secrets->secret[enc_level][1];

  fd_quic_hkdf_expand_label(
      client_secret, FD_QUIC_SECRET_SZ,
      secrets->initial_secret,
      FD_QUIC_CRYPTO_LABEL_CLIENT_IN,
      FD_QUIC_CRYPTO_LABEL_CLIENT_IN_LEN );

  fd_quic_hkdf_expand_label(
      server_secret, FD_QUIC_SECRET_SZ,
      secrets->initial_secret,
      FD_QUIC_CRYPTO_LABEL_SERVER_IN,
      FD_QUIC_CRYPTO_LABEL_SERVER_IN_LEN );
}


/* generate new secrets

   Used during key update to generate new secrets from the
   existing secrets

   see rfc9001 section 6, rfc8446 section 7.2 */
void
fd_quic_gen_new_secrets( fd_quic_crypto_secrets_t * secrets ) {
  /* Defined as:
     application_traffic_secret_N+1 =
           HKDF-Expand-Label(application_traffic_secret_N,
                             "traffic upd", "", Hash.length) */
  uint enc_level = fd_quic_enc_level_appdata_id;
  uchar * client_secret = secrets->new_secret[0];
  uchar * server_secret = secrets->new_secret[1];

  uchar * old_client_secret = secrets->secret[enc_level][0];
  uchar * old_server_secret = secrets->secret[enc_level][1];

  fd_quic_hkdf_expand_label(
      client_secret, FD_QUIC_SECRET_SZ,
      old_client_secret,
      FD_QUIC_CRYPTO_LABEL_KEY_UPDATE, FD_QUIC_CRYPTO_LABEL_KEY_UPDATE_LEN );

  fd_quic_hkdf_expand_label(
      server_secret, FD_QUIC_SECRET_SZ,
      old_server_secret,
      FD_QUIC_CRYPTO_LABEL_KEY_UPDATE, FD_QUIC_CRYPTO_LABEL_KEY_UPDATE_LEN );
}


void
fd_quic_gen_keys(
    fd_quic_crypto_keys_t * keys,
    uchar const             secret[ 32 ] ) {

  /* quic key */

  /* output length passed with "quic hp" and "quic key" must be the key size from
     the current cipher */
  fd_quic_hkdf_expand_label(
      keys->pkt_key, FD_AES_128_KEY_SZ,
      secret,
      FD_QUIC_CRYPTO_LABEL_QUIC_KEY,
      FD_QUIC_CRYPTO_LABEL_QUIC_KEY_LEN );

  /* quic hp */

  /* output length passed with "quic hp" and "quic key" must be the key size from
     the current cipher */
  fd_quic_hkdf_expand_label(
      keys->hp_key, FD_AES_128_KEY_SZ,
      secret,
      FD_QUIC_CRYPTO_LABEL_QUIC_HP,
      FD_QUIC_CRYPTO_LABEL_QUIC_HP_LEN );

  /* quic iv */
  fd_quic_hkdf_expand_label(
      keys->iv, FD_AES_GCM_IV_SZ,
      secret,
      FD_QUIC_CRYPTO_LABEL_QUIC_IV,
      FD_QUIC_CRYPTO_LABEL_QUIC_IV_LEN );
}


/* generates packet key and iv key
   used by key update

   TODO this overlaps with fd_quic_gen_keys, split into gen_hp_keys and gen_pkt_keys */
void
fd_quic_gen_new_keys(
    fd_quic_crypto_keys_t * keys,
    uchar const             secret[ 32 ] ) {
  /* quic key */
  fd_quic_hkdf_expand_label(
      keys->pkt_key, FD_AES_128_KEY_SZ,
      secret,
      FD_QUIC_CRYPTO_LABEL_QUIC_KEY,
      FD_QUIC_CRYPTO_LABEL_QUIC_KEY_LEN );

  /* quic iv */
  fd_quic_hkdf_expand_label(
      keys->iv, FD_AES_GCM_IV_SZ,
      secret,
      FD_QUIC_CRYPTO_LABEL_QUIC_IV,
      FD_QUIC_CRYPTO_LABEL_QUIC_IV_LEN );
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
     pkt_sz            the size of the packet in bytes (frames after packet number not including MAC tag)
     keys              a pointer to the keys to use
     pkt_number        needed to create the nonce used in encryption
                         likely points to the packet number within "hdr"
     pkt_number_sz     the size of the packet number in bytes
     */

int
fd_quic_crypto_encrypt(
    uchar *                        const out,
    ulong *                        const out_sz,
    uchar const *                  const hdr,
    ulong                          const hdr_sz,
    uchar const *                  const pkt,
    ulong                          const pkt_sz,
    fd_quic_crypto_keys_t const *  const pkt_keys,
    fd_quic_crypto_keys_t const *  const hp_keys,
    ulong                          const pkt_number ) {


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
  ulong pkt_number_sz = fd_quic_h0_pkt_num_len( first ) + 1u;
  uchar const * pkt_number_ptr = out + hdr_sz - pkt_number_sz;

  // nonce is quic-iv XORed with packet-number
  // packet number is 1-4 bytes, so only XOR last pkt_number_sz bytes
  uchar nonce[FD_QUIC_NONCE_SZ] = {0};
  uint nonce_tmp = FD_QUIC_NONCE_SZ - 4;
  uchar const * quic_iv = pkt_keys->iv;
  memcpy( nonce, quic_iv, nonce_tmp );
  for( uint k = 0; k < 4; ++k ) {
    uint j = nonce_tmp + k;
    nonce[j] = (uchar)( quic_iv[j] ^ ( (uchar)( (pkt_number>>( (3u - k) * 8u ))&0xFF ) ) );
  }

  // Initial packets cipher uses AEAD_AES_128_GCM with keys derived from the Destination Connection ID field of the
  // first Initial packet sent by the client; see rfc9001 Section 5.2.

  fd_aes_gcm_t pkt_cipher[1];
  fd_aes_128_gcm_init( pkt_cipher, pkt_keys->pkt_key, nonce );

  /* cipher_text is start of encrypted packet bytes, which starts after the header */
  uchar * cipher_text = out + hdr_sz;
  uchar * tag         = cipher_text + pkt_sz;
  uchar * pkt_end     = tag + FD_QUIC_CRYPTO_TAG_SZ;

  fd_aes_gcm_encrypt( pkt_cipher, cipher_text, pkt, pkt_sz, hdr, hdr_sz, tag );

  *out_sz = (ulong)( pkt_end - out );

  /* Header protection */

  /* sample start is defined as 4 bytes after the start of the packet number
     so shorter packet numbers means sample starts later in the cipher text */
  uchar const * sample = pkt_number_ptr + 4;

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
    uchar *                        buf,
    ulong                          buf_sz,
    ulong                          pkt_number_off,
    ulong                          pkt_number,
    fd_quic_crypto_keys_t const *  keys ) {

  if( FD_UNLIKELY( ( pkt_number_off >= buf_sz      ) |
                   ( buf_sz < FD_QUIC_SHORTEST_PKT ) ) ) {
    FD_DEBUG( FD_LOG_WARNING( ( "fd_quic_crypto_decrypt: cipher text buffer too small" ) ) );
    return FD_QUIC_FAILED;
  }

  /* Derive header size */
  uint    first         = buf[0];
  ulong   pkt_number_sz = fd_quic_h0_pkt_num_len( first ) + 1u;
  uchar * hdr           = buf;
  ulong   hdr_sz        = pkt_number_off + pkt_number_sz;

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

  if( FD_UNLIKELY( ( buf_sz < hdr_sz ) |
                   ( buf_sz < hdr_sz+FD_QUIC_CRYPTO_TAG_SZ ) ) )
    return FD_QUIC_FAILED;

  /* Derive offsets

     +----------+ <-- buf
     | Header   |
     +----------+ <-- out
     | Payload  |
     +----------+ <-- gcm_tag
     | GCM Tag  |
     +----------+ <-- buf_end */

  uchar * const out     = buf     + hdr_sz;
  uchar * const buf_end = buf     + buf_sz;
  uchar * const gcm_tag = buf_end - FD_QUIC_CRYPTO_TAG_SZ;
  ulong   const gcm_sz  = (ulong)( gcm_tag - out );

  fd_aes_gcm_t pkt_cipher[1];
  fd_aes_128_gcm_init( pkt_cipher, keys->pkt_key, nonce );

  int decrypt_ok =
   fd_aes_gcm_decrypt( pkt_cipher,
                            out /* ciphertext */, out /* plaintext */,
                            gcm_sz,      /* size of plaintext */
                            hdr, hdr_sz, /* associated data */
                            gcm_tag      /* auth tag */ );
  if( FD_UNLIKELY( !decrypt_ok ) ) {
   FD_DEBUG( FD_LOG_WARNING(( "fd_aes_gcm_decrypt failed" )) );
   return FD_QUIC_FAILED;
  }

  return FD_QUIC_SUCCESS;
}


int
fd_quic_crypto_decrypt_hdr(
    uchar *                        buf,
    ulong                          buf_sz,
    ulong                          pkt_number_off,
    fd_quic_crypto_keys_t const *  keys ) {

  /* bounds checks */
  if( FD_UNLIKELY( ( buf_sz < FD_QUIC_CRYPTO_TAG_SZ ) |
                   ( pkt_number_off >= buf_sz       ) ) ) {
    FD_DEBUG( FD_LOG_WARNING(( "decrypt hdr: bounds checks failed" )) );
    return FD_QUIC_FAILED;
  }

  uint          first      = buf[0]; /* first byte */
  uint          long_hdr   = first & 0x80u;  /* long header? (this bit is not encrypted) */
  ulong         sample_off = pkt_number_off + 4;

  if( FD_UNLIKELY( sample_off + FD_QUIC_HP_SAMPLE_SZ > buf_sz ) ) {
    FD_DEBUG( FD_LOG_WARNING(( "decrypt hdr: not enough bytes for a sample" )) );
    return FD_QUIC_FAILED;
  }

  uchar * sample = buf + sample_off;

  /* TODO this is hardcoded to AES-128 */
  uchar hp_cipher[16];
  fd_aes_key_t ecb[1];
  fd_aes_set_encrypt_key( keys->hp_key, 128, ecb );
  fd_aes_encrypt( sample, hp_cipher, ecb );

  /* hp_cipher is mask */
  uchar const * mask = hp_cipher;

  /* undo first byte mask */
  first  ^= (uint)mask[0] & ( long_hdr ? 0x0fu : 0x1fu );
  buf[0]  = (uchar)first;

  /* now we can calculate the actual packet number size */
  ulong pkt_number_sz = fd_quic_h0_pkt_num_len( first ) + 1u;

  /* undo packet number encryption */
  for( ulong j = 0u; j < pkt_number_sz; ++j ) {
    buf[ pkt_number_off + j ] ^= mask[ 1u+j ];
  }

  return FD_QUIC_SUCCESS;
}
