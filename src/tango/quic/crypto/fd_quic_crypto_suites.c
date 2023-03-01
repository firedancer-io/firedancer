#include "fd_quic_crypto_suites.h"
#include "../fd_quic.h"
#include <openssl/rand.h>
#include <limits.h>


/* define initial salt */
uchar  FD_QUIC_CRYPTO_V1_INITIAL_SALT[]  = { 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
                                             0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
                                             0xcc, 0xbb, 0x7f, 0x0a };
ulong FD_QUIC_CRYPTO_V1_INITIAL_SALT_SZ = sizeof( FD_QUIC_CRYPTO_V1_INITIAL_SALT );


/* initialize crypto context */
void
fd_quic_crypto_ctx_init( fd_quic_crypto_ctx_t * ctx ) {
  ctx->CIPHER_AES_128_GCM       = EVP_aes_128_gcm();
  ctx->CIPHER_AES_256_GCM       = EVP_aes_256_gcm();
  ctx->CIPHER_AES_128_CCM       = EVP_aes_128_ccm();
  ctx->CIPHER_CHACHA20_POLY1305 = EVP_chacha20_poly1305();

  ctx->CIPHER_AES_128_ECB       = EVP_aes_128_ecb();
  ctx->CIPHER_AES_256_ECB       = EVP_aes_256_ecb();
  ctx->CIPHER_CHACHA20          = EVP_chacha20();

  ctx->HASH_SHA256              = EVP_sha256();
  ctx->HASH_SHA384              = EVP_sha384();

  /* initialize suites map */
#define _( ID, SUITE, MAJ, MIN, PKT, HP, HASHFN, KEY_SZ, IV_SZ, ... ) \
  ctx->suites[ID].id         = ID;                     \
  ctx->suites[ID].major      = MAJ;                    \
  ctx->suites[ID].minor      = MIN;                    \
  ctx->suites[ID].key_sz     = KEY_SZ;                 \
  ctx->suites[ID].iv_sz      = IV_SZ;                  \
  ctx->suites[ID].pkt_cipher = ctx->CIPHER_##PKT;      \
  ctx->suites[ID].hp_cipher  = ctx->CIPHER_##HP;       \
  ctx->suites[ID].hash       = ctx->HASH_##HASHFN;
  FD_QUIC_CRYPTO_SUITE_LIST( _, )
#undef _
}

void
fd_quic_crypto_ctx_reset( fd_quic_crypto_ctx_t * ctx ) {
  /* no need to free the EVP_MD hash functions */

  /* apparently nothing to do here */
  (void)ctx;
}

int
fd_quic_hkdf_extract( uchar *        output,  ulong output_sz,
                      EVP_MD const * md,
                      uchar const *  salt,    ulong salt_sz,
                      uchar const *  conn_id, ulong conn_id_sz ) {
  /* fetch hash size */
  int i_hash_sz = EVP_MD_size( md );

  /* avoid overflow issues */
  if( FD_UNLIKELY( ( salt_sz    > INT_MAX ) |
                   ( conn_id_sz > INT_MAX ) |
                   ( output_sz  > INT_MAX ) |
                   ( i_hash_sz  < 0 ) )     ) {
    return FD_QUIC_FAILED;
  }

  ulong hash_sz = (ulong)i_hash_sz;

  /* ensure buffer space for call to HMAC_Final */
  if( FD_UNLIKELY( output_sz < hash_sz ) ) {
    FD_LOG_ERR(( "fd_quic_hkdf_extract: output size to small for result" ));
    return FD_QUIC_FAILED;
  }

  HMAC_CTX * hash_ctx = HMAC_CTX_new();
  if( FD_UNLIKELY( !hash_ctx ) ) {
    FD_LOG_ERR(( "openssl error: HMAC_CTX_new returned NULL" ));
    return FD_QUIC_FAILED;
  }

  if( FD_UNLIKELY( HMAC_Init_ex( hash_ctx, salt, (int)salt_sz, md, NULL ) != 1 ) ) {
    FD_LOG_ERR(( "openssl error: HMAC_Init_ex failed" ));
    HMAC_CTX_free( hash_ctx );
    return FD_QUIC_FAILED;
  }

  /* this may be necessary for some hash functions */
  if( FD_UNLIKELY( !HMAC_Init_ex( hash_ctx, NULL, 0, NULL, NULL ) ) ) {
    FD_LOG_ERR(( "openssl error: HMAC_Init_ex failed" ));
    HMAC_CTX_free( hash_ctx );
    return FD_QUIC_FAILED;
  }

  if( FD_UNLIKELY( !HMAC_Update( hash_ctx, conn_id, conn_id_sz ) ) ) {
    FD_LOG_ERR(( "openssl error: HMAC_Update failed" ));
    HMAC_CTX_free( hash_ctx );
    return FD_QUIC_FAILED;
  }

  uint final_output_sz = (uint)output_sz;
  if( FD_UNLIKELY( !HMAC_Final( hash_ctx, output, &final_output_sz ) ) ) {
    FD_LOG_ERR(( "openssl error: HMAC_Final failed" ));
    HMAC_CTX_free( hash_ctx );
    return FD_QUIC_FAILED;
  }

  HMAC_CTX_free( hash_ctx );

  return FD_QUIC_SUCCESS;
}


int
fd_quic_hkdf_expand_label( uchar *        output,  ulong output_sz,
                           EVP_MD const * md,
                           uchar const *  secret,  ulong secret_sz,
                           uchar const *  label,   ulong label_sz ) {
  uchar temp[FD_QUIC_CRYPTO_HASH_SZ_BOUND] = {0};

  /* fetch hash size */
  int i_hash_sz = EVP_MD_size( md );

  /* avoid overflow issues */
  if( FD_UNLIKELY( ( output_sz  > ( 1u<<16u )                ) |
                   ( secret_sz  > INT_MAX                    ) |
                   ( label_sz   > FD_QUIC_CRYPTO_LABEL_BOUND ) |
                   ( i_hash_sz  < 0                          ) ) ) {
    return FD_QUIC_FAILED;
  }

  ulong hash_sz = (ulong)i_hash_sz;

  if( FD_UNLIKELY( output_sz > hash_sz ) ) {
    FD_LOG_ERR(( "fd_quic_hkdf_expand_label: output_sz is larger than hash size"  ));
    return FD_QUIC_FAILED;
  }

  if( FD_UNLIKELY( output_sz > sizeof( temp ) ) ) {
    FD_LOG_ERR(( "fd_quic_hkdf_expand_label: output_sz is larger than output buffer" ));
    return FD_QUIC_FAILED;
  }

  HMAC_CTX * hash_ctx = HMAC_CTX_new();
  if( FD_UNLIKELY( !hash_ctx ) ) {
    FD_LOG_ERR(( "HMAC_CTX_new returned NULL"  ));
    return FD_QUIC_FAILED;
  }

  if( FD_UNLIKELY( HMAC_Init_ex( hash_ctx, secret, (int)secret_sz, md, NULL ) != 1 ) ) {
    FD_LOG_ERR(( "HMAC_Init_ex returned error"  ));
    HMAC_CTX_free( hash_ctx );
    return FD_QUIC_FAILED;
  }

  /* expand */
  uchar   HKDF_PREFIX[6] = "tls13 ";
  ulong  HKDF_PREFIX_SZ = sizeof( HKDF_PREFIX );

  /* format label */
  uchar label_data[FD_QUIC_CRYPTO_LABEL_BOUND];
  /* label data is:
       output size:          2 bytes
       size of prefix+label: 1 byte
       const 0x00:           1 byte
       const 0x01:           1 byte */
  ulong label_data_sz = 3 + HKDF_PREFIX_SZ + label_sz + 1 + 1;
  if( FD_UNLIKELY( label_data_sz > sizeof( label_data ) ) ) {
    FD_LOG_ERR(( "fd_quic_hkdf_expand_label: label data size larger than allowed"  ));
    HMAC_CTX_free( hash_ctx );
    return FD_QUIC_FAILED;
  }

  label_data[0] = (uchar)( output_sz >> 8u );
  label_data[1] = (uchar)( output_sz & 0xffu );
  label_data[2] = (uchar)( HKDF_PREFIX_SZ + label_sz );
  fd_memcpy( label_data + 3, HKDF_PREFIX, HKDF_PREFIX_SZ );
  fd_memcpy( label_data + 3 + HKDF_PREFIX_SZ, label, label_sz );
  label_data[3 + HKDF_PREFIX_SZ + label_sz] = 0x00u;

  // This is the first stage of HKDF-expand from https://www.rfc-editor.org/rfc/rfc5869
  // only one stage is required to achive the desired length
  // so we just do it here
  label_data[4 + HKDF_PREFIX_SZ + label_sz] = 0x01u;

  // hash compute

  // this seems to do nothing for sha256, but  possibly it is necessary for some hash functions
  if( FD_UNLIKELY( !HMAC_Init_ex( hash_ctx, NULL, 0, NULL, NULL ) ) ) {
    FD_LOG_ERR(( "HMAC_Init_ex( hash_ctx, NULL, 0, NULL, NULL ) failed"  ));
    HMAC_CTX_free( hash_ctx );
    return FD_QUIC_FAILED;
  }

  if( FD_UNLIKELY( !HMAC_Update( hash_ctx, label_data, label_data_sz ) ) ) {
    FD_LOG_ERR(( "HMAC_Update failed"  ));
    HMAC_CTX_free( hash_ctx );
    return FD_QUIC_FAILED;
  }

  uint hmac_output_sz = 0;
  if( FD_UNLIKELY( !HMAC_Final( hash_ctx, temp, &hmac_output_sz ) ) ) {
    FD_LOG_ERR(( "HMAC_Final failed"  ));
    HMAC_CTX_free( hash_ctx );
    return FD_QUIC_FAILED;
  }

  fd_memcpy( output, temp, output_sz );

  HMAC_CTX_free( hash_ctx );

  return FD_QUIC_SUCCESS;
}


int
fd_quic_gen_initial_secret(
    fd_quic_crypto_secrets_t * secrets,
    uchar const *              initial_salt,
    ulong                      initial_salt_sz,
    uchar const *              conn_id,
    ulong                      conn_id_sz,
    EVP_MD const *             md ) {
  if( FD_UNLIKELY(
      fd_quic_hkdf_extract( secrets->initial_secret, sizeof( secrets->initial_secret ),
                            md,
                            initial_salt, initial_salt_sz,
                            conn_id, conn_id_sz )
      != FD_QUIC_SUCCESS ) ) {
    FD_LOG_ERR(( "fd_quic_hkdf_extract failed" ));
    return FD_QUIC_FAILED;
  }

  return FD_QUIC_SUCCESS;
}


int
fd_quic_gen_secrets(
    fd_quic_crypto_secrets_t * secrets,
    int                        enc_level,
    EVP_MD const *             md ) {
  uchar * client_secret = secrets->secret[enc_level][0];
  uchar * server_secret = secrets->secret[enc_level][1];

  if( enc_level == fd_quic_enc_level_initial_id ) {
    secrets->secret_sz[enc_level][0] = \
    secrets->secret_sz[enc_level][1] = FD_QUIC_INITIAL_SECRET_SZ;
  }

  uchar client_secret_sz = secrets->secret_sz[enc_level][0];
  uchar server_secret_sz = secrets->secret_sz[enc_level][1];

  char const client_in[] = FD_QUIC_CRYPTO_LABEL_CLIENT_IN;
  if( fd_quic_hkdf_expand_label( client_secret, client_secret_sz,
                                 md,
                                 secrets->initial_secret, sizeof( secrets->initial_secret ),
                                 (uchar*)client_in, strlen( client_in ) ) != FD_QUIC_SUCCESS ) {
    FD_LOG_ERR(( "fd_quic_hkdf_expand_label failed" ));
    return FD_QUIC_FAILED;
  }

  char const server_in[] = FD_QUIC_CRYPTO_LABEL_SERVER_IN;
  if( fd_quic_hkdf_expand_label( server_secret, server_secret_sz,
                                 md,
                                 secrets->initial_secret, sizeof( secrets->initial_secret ),
                                 (uchar*)server_in, strlen( server_in ) ) != FD_QUIC_SUCCESS ) {
    FD_LOG_ERR(( "fd_quic_hkdf_expand_label failed" ));
    return FD_QUIC_FAILED;
  }

  return FD_QUIC_SUCCESS;
}

int
fd_quic_gen_keys(
    fd_quic_crypto_keys_t * keys,
    ulong                   key_sz,
    ulong                   iv_sz,
    EVP_MD const *          md,
    uchar const *           secret,
    ulong                   secret_sz ) {

  if( key_sz > sizeof( keys->pkt_key ) ||
      key_sz > sizeof( keys->hp_key ) ||
      iv_sz > sizeof( keys->iv ) ) {
    return FD_QUIC_FAILED;
  }

  /* quic key */

  /* output length passed with "quic hp" and "quic key" must be the key size from
     the current cipher */
  if( fd_quic_hkdf_expand_label( keys->pkt_key, key_sz,
                                 md,
                                 secret, secret_sz,
                                 (uchar*)FD_QUIC_CRYPTO_LABEL_QUIC_KEY,
                                 FD_QUIC_CRYPTO_LABEL_QUIC_KEY_SZ ) != FD_QUIC_SUCCESS ) {
    return FD_QUIC_FAILED;
  }
  keys->pkt_key_sz = key_sz;

  /* quic hp */

  /* output length passed with "quic hp" and "quic key" must be the key size from
     the current cipher */
  if( fd_quic_hkdf_expand_label( keys->hp_key, key_sz,
                                 md,
                                 secret, secret_sz,
                                 (uchar*)FD_QUIC_CRYPTO_LABEL_QUIC_HP,
                                 FD_QUIC_CRYPTO_LABEL_QUIC_HP_SZ ) != FD_QUIC_SUCCESS ) {
    return FD_QUIC_FAILED;
  }
  keys->hp_key_sz = key_sz;

  /* quic iv */
  if( fd_quic_hkdf_expand_label( keys->iv, iv_sz,
                                 md,
                                 secret, secret_sz,
                                 (uchar*)FD_QUIC_CRYPTO_LABEL_QUIC_IV,
                                 FD_QUIC_CRYPTO_LABEL_QUIC_IV_SZ ) != FD_QUIC_SUCCESS ) {
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

   *out_sz is used to determine the amound of buffer space left at *out
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
    uchar *                  out,
    ulong *                 out_sz,
    uchar const *            hdr,
    ulong                   hdr_sz,
    uchar const *            pkt,
    ulong                   pkt_sz,
    fd_quic_crypto_suite_t * suite,
    fd_quic_crypto_keys_t *  keys ) {
  /* ensure we have enough space in the output buffer
     most space used by cipher:
       header bytes (just XORed)
       input bytes (encrypted)
       tag bytes
       1 cipher block extra */
  int i_block_sz = EVP_CIPHER_block_size( suite->pkt_cipher );
  if( i_block_sz < 0 ) return FD_QUIC_FAILED;

  ulong block_sz = (ulong)i_block_sz;

  /* bound on the bytes needed for cipher output */
  ulong cipher_out_bound = hdr_sz + pkt_sz + FD_QUIC_CRYPTO_TAG_SZ + block_sz;

  if( FD_UNLIKELY( *out_sz < cipher_out_bound ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: output buffer not big enough" ));
    return FD_QUIC_FAILED;
  }

  if( FD_UNLIKELY( ( hdr_sz < 4 ) | ( hdr_sz > INT_MAX ) ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: packet header size out of bounds" ));
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

  /* TODO possibly cipher_ctx may be stored and reused, but the documentation implies
     some resources (memory) will be freed during reset(), and reallocated in init() anyway */
  EVP_CIPHER_CTX * cipher_ctx = EVP_CIPHER_CTX_new();
  if( FD_UNLIKELY( !cipher_ctx ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: Error creating cipher ctx" ));
    return FD_QUIC_FAILED;
  }

  // nonce is quic-iv XORed with packet-number
  // packet number is 1-4 bytes, so only XOR last pkt_number_sz bytes
  uchar nonce[FD_QUIC_NONCE_SZ] = {0};
  ulong nonce_tmp = FD_QUIC_NONCE_SZ - pkt_number_sz;
  uchar const * quic_iv = keys->iv;
  fd_memcpy( nonce, quic_iv, nonce_tmp );
  for( ulong k = 0; k < pkt_number_sz; ++k ) {
    ulong j = nonce_tmp + k;
    nonce[j] = quic_iv[j] ^ pkt_number[k];
  }

  // Initial packets cipher uses AEAD_AES_128_GCM with keys derived from the Destination Connection ID field of the
  // first Initial packet sent by the client; see rfc9001 Section 5.2.

  if( FD_UNLIKELY( EVP_CipherInit_ex( cipher_ctx, suite->pkt_cipher, NULL, NULL, NULL, 1 /* encryption */ ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: EVP_CipherInit_ex failed" ));
    EVP_CIPHER_CTX_free( cipher_ctx );
    return FD_QUIC_FAILED;
  }

  if( FD_UNLIKELY( EVP_CIPHER_CTX_ctrl( cipher_ctx, EVP_CTRL_AEAD_SET_IVLEN, FD_QUIC_NONCE_SZ, NULL ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: EVP_CIPHER_CTX_ctrl failed" ));
    EVP_CIPHER_CTX_free( cipher_ctx );
    return FD_QUIC_FAILED;
  }

  if( FD_UNLIKELY( EVP_EncryptInit_ex( cipher_ctx, suite->pkt_cipher, NULL, keys->pkt_key, nonce ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: EVP_EncryptInit_ex failed" ));
    EVP_CIPHER_CTX_free( cipher_ctx );
    return FD_QUIC_FAILED;
  }

  /* auth data added with NULL output - still require out length */
  int tmp = 0;
  if( FD_UNLIKELY( EVP_EncryptUpdate( cipher_ctx, NULL, &tmp, hdr, (int)hdr_sz ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: EVP_EncryptUpdate failed auth_data" ));
    EVP_CIPHER_CTX_free( cipher_ctx );
    return FD_QUIC_FAILED;
  }

  /* EVP_EncryptUpdate requires "cipher_text" to point to a buffer large enough to contain
     the cipher text.
     The man page for EVP_EncryptUpdate says this about the size required:
         EVP_EncryptUpdate() encrypts inl bytes from the buffer in and
         writes the encrypted version to out. This function can be
         called multiple times to encrypt successive blocks of data.
         The amount of data written depends on the block alignment of
         the encrypted data.  For most ciphers and modes, the amount
         of data written can be anything from zero bytes to
         (inl + cipher_block_size - 1) bytes.  For wrap cipher modes,
         the amount of data written can be anything from zero bytes to
         (inl + cipher_block_size) bytes.  For stream ciphers, the
         amount of data written can be anything from zero bytes to inl
         bytes.  Thus, out should contain sufficient room for the
         operation being performed.  The actual number of bytes
         written is placed in out_sz. It also checks if in and out are
         partially overlapping, and if they are 0 is returned to
         indicate failure.

     I read this to mean the following should be enough for every cipher type:
         pkt_sz + EVP_CIPHER_block_size( cipher_ctx )

     */

  /* cipher_text is start of encrypted packet bytes, which starts after the header */
  uchar * cipher_text = out + hdr_sz;
  ulong offset = 0;
  int cipher_text_sz = 0;
  if( FD_UNLIKELY( EVP_EncryptUpdate( cipher_ctx, cipher_text, &cipher_text_sz, pkt, (int)pkt_sz ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: EVP_EncryptUpdate failed" ));
    EVP_CIPHER_CTX_free( cipher_ctx );
    return FD_QUIC_FAILED;
  }

  offset = (ulong)cipher_text_sz;
  if( FD_UNLIKELY( EVP_EncryptFinal( cipher_ctx, cipher_text + offset, &cipher_text_sz ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: EVP_EncryptFinal failed" ));
    EVP_CIPHER_CTX_free( cipher_ctx );
    return FD_QUIC_FAILED;
  }

  offset += (ulong)cipher_text_sz;

  if( FD_UNLIKELY( EVP_CIPHER_CTX_ctrl( cipher_ctx, EVP_CTRL_AEAD_GET_TAG, FD_QUIC_CRYPTO_TAG_SZ, cipher_text + offset ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: EVP_CTRL_AEAD_GET_TAG failed" ));
    EVP_CIPHER_CTX_free( cipher_ctx );
    return FD_QUIC_FAILED;
  }

  offset += FD_QUIC_CRYPTO_TAG_SZ;

  ulong enc_pkt_sz = offset; /* encrypted packet size, including tag */

  *out_sz = enc_pkt_sz + hdr_sz;

  /* Header protection */

  EVP_CIPHER_CTX * hp_cipher_ctx = EVP_CIPHER_CTX_new();
  if( FD_UNLIKELY( !hp_cipher_ctx ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: Error creating cipher ctx" ));
    EVP_CIPHER_CTX_free( cipher_ctx );
    return FD_QUIC_FAILED;
  }

  if( FD_UNLIKELY( EVP_CipherInit_ex( hp_cipher_ctx, suite->hp_cipher, NULL, NULL, NULL, 1 /* encryption */ ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: EVP_CipherInit_ex (hp) failed" ));
    EVP_CIPHER_CTX_free( cipher_ctx );
    EVP_CIPHER_CTX_free( hp_cipher_ctx );
    return FD_QUIC_FAILED;
  }

  if(FD_UNLIKELY(  EVP_EncryptInit_ex( hp_cipher_ctx, NULL, NULL, keys->hp_key, NULL ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: EVP_EncryptInit_ex failed" ));
    EVP_CIPHER_CTX_free( cipher_ctx );
    EVP_CIPHER_CTX_free( hp_cipher_ctx );
    return FD_QUIC_FAILED;
  }

  /* sample start is defined as 4 bytes after the start of the packet number
     so shorter packet numbers means sample starts later in the cipher text */
  uchar const * sample = pkt_number + 4;

  uchar hp_cipher[FD_QUIC_CRYPTO_BLOCK_BOUND] = {0};
  if( FD_UNLIKELY( EVP_CIPHER_block_size( suite->hp_cipher ) > FD_QUIC_CRYPTO_BLOCK_BOUND ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt failed. HP cipher block size too big" ));
    EVP_CIPHER_CTX_free( cipher_ctx );
    EVP_CIPHER_CTX_free( hp_cipher_ctx );
    return FD_QUIC_FAILED;
  }
  int hp_cipher_sz = 0;
  if( FD_UNLIKELY( EVP_EncryptUpdate( hp_cipher_ctx, hp_cipher, &hp_cipher_sz, sample, FD_QUIC_HP_SAMPLE_SZ ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: EVP_EncryptUpdate failed cipher (hp)" ));
    EVP_CIPHER_CTX_free( cipher_ctx );
    EVP_CIPHER_CTX_free( hp_cipher_ctx );
    return FD_QUIC_FAILED;
  }

  /* hp_cipher is mask */
  uchar const * mask = hp_cipher;

  uchar long_hdr = first & 0x80u; /* long header? */
  out[0] ^= (uchar)( mask[0] & ( long_hdr ? 0x0fu : 0x1fu ) );

  ulong pkt_number_off = hdr_sz - pkt_number_sz;

  for( ulong j = 0; j < pkt_number_sz; ++j ) {
    out[pkt_number_off + j] ^= mask[1+j];
  }

  EVP_CIPHER_CTX_free( cipher_ctx );
  EVP_CIPHER_CTX_free( hp_cipher_ctx );

  return FD_QUIC_SUCCESS;
}


int
fd_quic_crypto_decrypt(
    uchar *                  plain_text,
    ulong *                  plain_text_sz,
    uchar const *            cipher_text,
    ulong                    cipher_text_sz,
    ulong                    pkt_number_off,
    ulong                    pkt_number,
    fd_quic_crypto_suite_t * suite,
    fd_quic_crypto_keys_t *  keys ) {

  /* must have at least a short header and a TAG */
  if( FD_UNLIKELY( cipher_text_sz < FD_QUIC_CRYPTO_TAG_SZ ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: cipher text too small" ));
    return FD_QUIC_FAILED;
  }

  /* must have space for cipher_text_sz - FD_QUIC_CRYPTO_TAG_SZ */
  if( FD_UNLIKELY( *plain_text_sz + FD_QUIC_CRYPTO_TAG_SZ < cipher_text_sz ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: plain text buffer too small" ));
    return FD_QUIC_FAILED;
  }

  EVP_CIPHER_CTX * hp_cipher_ctx = EVP_CIPHER_CTX_new();
  if( FD_UNLIKELY( !hp_cipher_ctx ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: Error creating cipher ctx" ));
    return FD_QUIC_FAILED;
  }

  uint          first         = plain_text[0];
  ulong         pkt_number_sz = ( first & 0x03u ) + 1u;
  uchar const * hdr           = plain_text;
  ulong         hdr_sz        = pkt_number_off + pkt_number_sz;

  /* calculate nonce for decryption */

  /* nonce is quic-iv XORed with *reconstructed* packet-number
     packet number is 1-4 bytes, so only XOR last pkt_number_sz bytes */
  uchar nonce[FD_QUIC_NONCE_SZ] = {0};
  uint nonce_tmp = FD_QUIC_NONCE_SZ - 4;
  uchar const * quic_iv = keys->iv;
  fd_memcpy( nonce, quic_iv, nonce_tmp );
  for( uint k = 0; k < 4; ++k ) {
    uint j = nonce_tmp + k;
    nonce[j] = quic_iv[j] ^ (uchar)( pkt_number >> ( (3u - k) * 8u ) );
  }

  EVP_CIPHER_CTX * cipher_ctx = EVP_CIPHER_CTX_new();
  if( FD_UNLIKELY( !cipher_ctx ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: Error creating cipher ctx" ));
    EVP_CIPHER_CTX_free( hp_cipher_ctx );
    return FD_QUIC_FAILED;
  }

  if( FD_UNLIKELY( EVP_CipherInit_ex( cipher_ctx, suite->pkt_cipher, NULL, NULL, NULL, 0 /* decryption */ ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: EVP_CipherInit_ex failed" ));
    EVP_CIPHER_CTX_free( cipher_ctx );
    EVP_CIPHER_CTX_free( hp_cipher_ctx );
    return FD_QUIC_FAILED;
  }

  if( FD_UNLIKELY( EVP_CIPHER_CTX_ctrl( cipher_ctx, EVP_CTRL_AEAD_SET_IVLEN, FD_QUIC_NONCE_SZ, NULL ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: EVP_CIPHER_CTX_ctrl failed" ));
    EVP_CIPHER_CTX_free( cipher_ctx );
    EVP_CIPHER_CTX_free( hp_cipher_ctx );
    return FD_QUIC_FAILED;
  }

  if( FD_UNLIKELY( EVP_DecryptInit_ex( cipher_ctx, suite->pkt_cipher, NULL, keys->pkt_key, nonce ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: EVP_DecryptInit_ex failed" ));
    EVP_CIPHER_CTX_free( cipher_ctx );
    EVP_CIPHER_CTX_free( hp_cipher_ctx );
    return FD_QUIC_FAILED;
  }

  /* auth data added with NULL output - still require out length */
  int tmp = 0;
  if( FD_UNLIKELY( EVP_DecryptUpdate( cipher_ctx, NULL, &tmp, hdr, (int)hdr_sz ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: EVP_DecryptUpdate failed auth_data" ));
    EVP_CIPHER_CTX_free( cipher_ctx );
    EVP_CIPHER_CTX_free( hp_cipher_ctx );
    return FD_QUIC_FAILED;
  }

  int i_block_sz = EVP_CIPHER_block_size( suite->pkt_cipher );
  if( FD_UNLIKELY( FD_UNLIKELY( i_block_sz < 0 ) ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: EVP_CIPHER_block_size returned negative" ));
    EVP_CIPHER_CTX_free( cipher_ctx );
    EVP_CIPHER_CTX_free( hp_cipher_ctx );
    return FD_QUIC_FAILED;
  }

  ulong block_sz = (ulong)i_block_sz;
  ulong plain_out_bound = cipher_text_sz - hdr_sz - FD_QUIC_CRYPTO_TAG_SZ + block_sz;

  if( FD_UNLIKELY( FD_UNLIKELY( plain_out_bound > *plain_text_sz ) ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: not enough room for plain text" ));
    EVP_CIPHER_CTX_free( cipher_ctx );
    EVP_CIPHER_CTX_free( hp_cipher_ctx );
    return FD_QUIC_FAILED;
  }

  uchar *       payload    = plain_text + hdr_sz;
  ulong         payload_sz = cipher_text_sz - hdr_sz - FD_QUIC_CRYPTO_TAG_SZ;
  uchar const * tag        = cipher_text + cipher_text_sz - FD_QUIC_CRYPTO_TAG_SZ;
  int           out_sz     = 0;
  if( FD_UNLIKELY( EVP_DecryptUpdate( cipher_ctx, payload, &out_sz, cipher_text + hdr_sz, (int)payload_sz ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: EVP_DecryptUpdate failed" ));
    EVP_CIPHER_CTX_free( cipher_ctx );
    return FD_QUIC_FAILED;
  }

  /* set tag before final */
  if( FD_UNLIKELY( EVP_CIPHER_CTX_ctrl( cipher_ctx, EVP_CTRL_AEAD_SET_TAG, FD_QUIC_CRYPTO_TAG_SZ, (void*)tag ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: EVP_CTRL_AEAD_GET_TAG failed" ));
    EVP_CIPHER_CTX_free( cipher_ctx );
    return FD_QUIC_FAILED;
  }

  if( FD_UNLIKELY( out_sz < 0 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: EVP_CIPHER_CTX_ctrl returned negative value in out_sz" ));
    EVP_CIPHER_CTX_free( cipher_ctx );
    return FD_QUIC_FAILED;
  }

  ulong offset = (ulong)out_sz;
  if( EVP_DecryptFinal( cipher_ctx, payload + offset, &out_sz ) != 1 ) {
    /* TODO this can happen, probably shouldn't warn here */
    FD_LOG_WARNING(( "fd_quic_crypto_decrypt: EVP_DecryptFinal failed" ));

    EVP_CIPHER_CTX_free( cipher_ctx );
    return FD_QUIC_FAILED;
  }

  offset += (ulong)out_sz;

  *plain_text_sz = offset + hdr_sz;

  return FD_QUIC_SUCCESS;
}


int
fd_quic_crypto_decrypt_hdr(
    uchar *                  plain_text,
    ulong *                  plain_text_sz,
    uchar const *            cipher_text,
    ulong                    cipher_text_sz,
    ulong                    pkt_number_off,
    fd_quic_crypto_suite_t * suite,
    fd_quic_crypto_keys_t *  keys ) {

  /* must have at least a short header */
  if( FD_UNLIKELY( cipher_text_sz < FD_QUIC_CRYPTO_TAG_SZ ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: cipher text too small" ));
    return FD_QUIC_FAILED;
  }

  /* must have capacity for header */
  if( FD_UNLIKELY( *plain_text_sz < pkt_number_off + 4 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: plain text buffer too small" ));
    return FD_QUIC_FAILED;
  }

  uint          first      = cipher_text[0]; /* first byte */
  uint          long_hdr   = first & 0x80u;  /* long header? (this bit is not encrypted) */
  ulong         sample_off = pkt_number_off + 4;
  uchar const * sample     = cipher_text + sample_off;

  EVP_CIPHER_CTX * hp_cipher_ctx = EVP_CIPHER_CTX_new();
  if( FD_UNLIKELY( !hp_cipher_ctx ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: Error creating cipher ctx" ));
    return FD_QUIC_FAILED;
  }

  /* although this is a "decrypt" function, the mask must be calculated exactly the
     same as in the "encrypt" function */
  if( FD_UNLIKELY( EVP_CipherInit_ex( hp_cipher_ctx, suite->hp_cipher, NULL, NULL, NULL, 1 /* encryption */ ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: EVP_CipherInit_ex (hp) failed" ));
    EVP_CIPHER_CTX_free( hp_cipher_ctx );
    return FD_QUIC_FAILED;
  }

  if( FD_UNLIKELY( EVP_EncryptInit_ex( hp_cipher_ctx, NULL, NULL, keys->hp_key, NULL ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: EVP_EncryptInit_ex failed" ));
    EVP_CIPHER_CTX_free( hp_cipher_ctx );
    return FD_QUIC_FAILED;
  }

  uchar hp_cipher[FD_QUIC_CRYPTO_BLOCK_BOUND] = {0};
  if( FD_UNLIKELY( EVP_CIPHER_block_size( suite->hp_cipher ) > FD_QUIC_CRYPTO_BLOCK_BOUND ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt failed. HP cipher block size too big" ));
    EVP_CIPHER_CTX_free( hp_cipher_ctx );
    return FD_QUIC_FAILED;
  }

  if( FD_UNLIKELY( sample + FD_QUIC_HP_SAMPLE_SZ > cipher_text + cipher_text_sz ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt failed. Not enough bytes for a sample" ));
    EVP_CIPHER_CTX_free( hp_cipher_ctx );
    return FD_QUIC_FAILED;
  }

  int hp_cipher_sz = 0;
  if( FD_UNLIKELY( EVP_EncryptUpdate( hp_cipher_ctx, hp_cipher, &hp_cipher_sz, sample, FD_QUIC_HP_SAMPLE_SZ ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: EVP_EncryptUpdate failed cipher (hp)" ));
    EVP_CIPHER_CTX_free( hp_cipher_ctx );
    return FD_QUIC_FAILED;
  }

  /* copy header, up to packet number, into output */
  if( sample_off > *plain_text_sz ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: plain text buffer too short for header" ));
    EVP_CIPHER_CTX_free( hp_cipher_ctx );
    return FD_QUIC_FAILED;
  }
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

extern
int
fd_quic_crypto_lookup_suite( uchar major, uchar minor );

/* get random bytes

   just forward to openssl

   here to easily allow the source to change */
void
fd_quic_crypto_rand( uchar * buf, int buf_sz ) {
  int rc = RAND_bytes( buf, buf_sz );
  if( FD_LIKELY( rc == 1 ) ) return;

  /* openssl error getting random bytes - bail */
  ulong err = ERR_get_error();
  FD_LOG_ERR(( "openssl RAND_bytes failed. Error: %lu", err ));
}

