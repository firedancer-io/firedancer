#include "fd_quic_crypto_suites.h"
#include "../fd_quic.h"

#include <openssl/err.h>
#include <openssl/rand.h>
#include <limits.h>

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
  ctx->CIPHER_AES_128_GCM       = EVP_aes_128_gcm();
  ctx->CIPHER_AES_256_GCM       = EVP_aes_256_gcm();
  ctx->CIPHER_AES_128_CCM       = EVP_aes_128_ccm();
  ctx->CIPHER_CHACHA20_POLY1305 = EVP_chacha20_poly1305();

  ctx->CIPHER_AES_128_ECB       = EVP_aes_128_ecb();
  ctx->CIPHER_AES_256_ECB       = EVP_aes_256_ecb();
  ctx->CIPHER_CHACHA20          = EVP_chacha20();

  /* initialize suites map */
#define EACH( ID, SUITE, MAJ, MIN, PKT, HP, HASHFN, KEY_SZ, IV_SZ, ... ) \
  ctx->suites[ ID ].id         = ID;                       \
  ctx->suites[ ID ].major      = MAJ;                      \
  ctx->suites[ ID ].minor      = MIN;                      \
  ctx->suites[ ID ].key_sz     = KEY_SZ;                   \
  ctx->suites[ ID ].iv_sz      = IV_SZ;                    \
  ctx->suites[ ID ].pkt_cipher = ctx->CIPHER_##PKT;        \
  ctx->suites[ ID ].hp_cipher  = ctx->CIPHER_##HP;         \
  ctx->suites[ ID ].hmac_fn    = fd_hmac_##HASHFN;         \
  ctx->suites[ ID ].hash_sz    = FD_QUIC_HASH_SZ_##HASHFN;
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
    int                        enc_level,
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

  char const key_update[] = FD_QUIC_CRYPTO_LABEL_KEY_UPDATE;
  if( FD_UNLIKELY( !fd_quic_hkdf_expand_label(
      client_secret,      client_secret_sz,
      old_client_secret,  client_secret_sz,
      (uchar*)key_update, strlen( key_update ),
      hmac_fn,            hash_sz ) ) ) {
    FD_LOG_WARNING(( "fd_quic_hkdf_expand_label failed" ));
    return FD_QUIC_FAILED;
  }

  if( FD_UNLIKELY( !fd_quic_hkdf_expand_label(
      server_secret,      server_secret_sz,
      old_server_secret,  server_secret_sz,
      (uchar*)key_update, strlen( key_update ),
      hmac_fn,            hash_sz ) ) ) {
    FD_LOG_WARNING(( "fd_quic_hkdf_expand_label failed" ));
    return FD_QUIC_FAILED;
  }

  return FD_QUIC_SUCCESS;
}


void
fd_quic_free_keys( fd_quic_crypto_keys_t * keys ) {
  if( keys->pkt_cipher_ctx ) EVP_CIPHER_CTX_free( keys->pkt_cipher_ctx );
  if( keys->hp_cipher_ctx  ) EVP_CIPHER_CTX_free( keys->hp_cipher_ctx  );
  keys->pkt_cipher_ctx = NULL;
  keys->hp_cipher_ctx  = NULL;
}


void
fd_quic_free_pkt_keys( fd_quic_crypto_keys_t * keys ) {
  if( keys->pkt_cipher_ctx ) EVP_CIPHER_CTX_free( keys->pkt_cipher_ctx );
  keys->pkt_cipher_ctx = NULL;
}


/* TODO need to dispose of keys somewhere
   these allocate openssl resources now */
int
fd_quic_gen_keys(
    fd_quic_crypto_keys_t *  keys,
    fd_quic_crypto_suite_t * suite,
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

  /* initialize the cipher contexts */
  EVP_CIPHER_CTX * pkt_cipher_ctx = EVP_CIPHER_CTX_new();
  if( FD_UNLIKELY( !pkt_cipher_ctx ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: Error creating cipher (pkt) ctx" ));
  }

  EVP_CIPHER_CTX * hp_cipher_ctx = EVP_CIPHER_CTX_new();
  if( FD_UNLIKELY( !hp_cipher_ctx ) ) {
    FD_LOG_WARNING(( "fd_quic_crypto_encrypt: EVP_CIPHER_CTX_new (hp) failed" ));
    goto fd_quic_gen_keys_error;
  }

  if( FD_UNLIKELY( EVP_CipherInit_ex( pkt_cipher_ctx, suite->pkt_cipher, NULL, NULL, NULL, 1 /* encryption */ ) != 1 ) ) {
    FD_LOG_WARNING(( "fd_quic_crypto_encrypt: EVP_CipherInit_ex failed" ));
    goto fd_quic_gen_keys_error;
  }

  if( FD_UNLIKELY( EVP_CIPHER_CTX_ctrl( pkt_cipher_ctx, EVP_CTRL_AEAD_SET_IVLEN, FD_QUIC_NONCE_SZ, NULL ) != 1 ) ) {
    FD_LOG_WARNING(( "fd_quic_crypto_encrypt: EVP_CIPHER_CTX_ctrl failed" ));
    goto fd_quic_gen_keys_error;
  }

  if( FD_UNLIKELY( EVP_CipherInit_ex( hp_cipher_ctx, suite->hp_cipher, NULL, NULL, NULL, 1 /* encryption */ ) != 1 ) ) {
    FD_LOG_WARNING(( "fd_quic_crypto_encrypt: EVP_CipherInit_ex failed" ));
    goto fd_quic_gen_keys_error;
  }

  if(FD_UNLIKELY(  EVP_EncryptInit_ex( hp_cipher_ctx, NULL, NULL, keys->hp_key, NULL ) != 1 ) ) {
    FD_LOG_WARNING(( "fd_quic_crypto_encrypt: EVP_EncryptInit_ex failed" ));
    goto fd_quic_gen_keys_error;
  }

  keys->pkt_cipher_ctx = pkt_cipher_ctx;
  keys->hp_cipher_ctx  = hp_cipher_ctx;

  return FD_QUIC_SUCCESS;

fd_quic_gen_keys_error:
  if( pkt_cipher_ctx ) EVP_CIPHER_CTX_free( pkt_cipher_ctx );
  if( hp_cipher_ctx )  EVP_CIPHER_CTX_free( hp_cipher_ctx );

  return FD_QUIC_FAILED;
}


/* generates packet key and iv key
   used by key update

   TODO this overlaps with fd_quic_gen_keys, split into gen_hp_keys and gen_pkt_keys */
int
fd_quic_gen_new_keys(
    fd_quic_crypto_keys_t *  keys,
    fd_quic_crypto_suite_t * suite,
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

  /* initialize the cipher context */
  EVP_CIPHER_CTX * pkt_cipher_ctx = EVP_CIPHER_CTX_new();
  if( FD_UNLIKELY( !pkt_cipher_ctx ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: Error creating cipher ctx" ));
  }

  if( FD_UNLIKELY( EVP_CipherInit_ex( pkt_cipher_ctx, suite->pkt_cipher, NULL, NULL, NULL, 1 /* encryption */ ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: EVP_CipherInit_ex failed" ));
  }

  if( FD_UNLIKELY( EVP_CIPHER_CTX_ctrl( pkt_cipher_ctx, EVP_CTRL_AEAD_SET_IVLEN, FD_QUIC_NONCE_SZ, NULL ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: EVP_CIPHER_CTX_ctrl failed" ));
  }

  keys->pkt_cipher_ctx = pkt_cipher_ctx;
  keys->hp_cipher_ctx  = NULL;

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
    uchar *                  out,
    ulong *                  out_sz,
    uchar const *            hdr,
    ulong                    hdr_sz,
    uchar const *            pkt,
    ulong                    pkt_sz,
    fd_quic_crypto_suite_t * suite,
    fd_quic_crypto_keys_t *  pkt_keys,
    fd_quic_crypto_keys_t *  hp_keys ) {
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

  EVP_CIPHER_CTX * pkt_cipher_ctx = pkt_keys->pkt_cipher_ctx;
  if( FD_UNLIKELY( !pkt_cipher_ctx ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: no cipher ctx" ));
    return FD_QUIC_FAILED;
  }

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

  if( FD_UNLIKELY( EVP_EncryptInit_ex( pkt_cipher_ctx, suite->pkt_cipher, NULL, pkt_keys->pkt_key, nonce ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: EVP_EncryptInit_ex failed" ));
  }

  /* auth data added with NULL output - still require out length */
  int tmp = 0;
  if( FD_UNLIKELY( EVP_EncryptUpdate( pkt_cipher_ctx, NULL, &tmp, hdr, (int)hdr_sz ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: EVP_EncryptUpdate failed auth_data" ));
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
  if( FD_UNLIKELY( EVP_EncryptUpdate( pkt_cipher_ctx, cipher_text, &cipher_text_sz, pkt, (int)pkt_sz ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: EVP_EncryptUpdate failed" ));
  }

  offset = (ulong)cipher_text_sz;
  if( FD_UNLIKELY( EVP_EncryptFinal( pkt_cipher_ctx, cipher_text + offset, &cipher_text_sz ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: EVP_EncryptFinal failed" ));
  }

  offset += (ulong)cipher_text_sz;

  if( FD_UNLIKELY( EVP_CIPHER_CTX_ctrl( pkt_cipher_ctx, EVP_CTRL_AEAD_GET_TAG, FD_QUIC_CRYPTO_TAG_SZ, cipher_text + offset ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: EVP_CTRL_AEAD_GET_TAG failed" ));
    return FD_QUIC_FAILED;
  }

  offset += FD_QUIC_CRYPTO_TAG_SZ;

  ulong enc_pkt_sz = offset; /* encrypted packet size, including tag */

  *out_sz = enc_pkt_sz + hdr_sz;

  /* Header protection */

  EVP_CIPHER_CTX * hp_cipher_ctx = hp_keys->hp_cipher_ctx;
  if( FD_UNLIKELY( !hp_cipher_ctx ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: no hp cipher ctx" ));
    return FD_QUIC_FAILED;
  }

  /* sample start is defined as 4 bytes after the start of the packet number
     so shorter packet numbers means sample starts later in the cipher text */
  uchar const * sample = pkt_number + 4;

  uchar hp_cipher[FD_QUIC_CRYPTO_BLOCK_BOUND] = {0};
  if( FD_UNLIKELY( EVP_CIPHER_block_size( suite->hp_cipher ) > FD_QUIC_CRYPTO_BLOCK_BOUND ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt failed. HP cipher block size too big" ));
  }
  int hp_cipher_sz = 0;
  if( FD_UNLIKELY( EVP_EncryptUpdate( hp_cipher_ctx, hp_cipher, &hp_cipher_sz, sample, FD_QUIC_HP_SAMPLE_SZ ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_encrypt: EVP_EncryptUpdate failed cipher (hp)" ));
  }

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

static char const *
fd_quic_openssl_strerror( void ) {
  /* had a segfault in ERR_error_string_n
   * so disaabling this for now
   * TODO fix */
#if 1
  static char errbuf[ 256UL ];  /* openssl docs state buf <= 256 bytes */
  errbuf[ 0 ] = '\0';

  ulong err_id = ERR_get_error();
  ERR_error_string_n( err_id, errbuf, sizeof( errbuf ) );

  return errbuf;
#else
  return "";
#endif
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
    FD_LOG_WARNING(( "fd_quic_crypto_decrypt: cipher text too small" ));
    return FD_QUIC_FAILED;
  }

  /* must have space for cipher_text_sz - FD_QUIC_CRYPTO_TAG_SZ */
  if( FD_UNLIKELY( *plain_text_sz + FD_QUIC_CRYPTO_TAG_SZ < cipher_text_sz ) ) {
    /* should this stop the process? */
    FD_DEBUG( FD_LOG_WARNING( ( "fd_quic_crypto_decrypt: plain text buffer too small" ) ) );
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
    nonce[j] = (uchar)(quic_iv[j] ^ (uchar)( pkt_number >> ( (3u - k) * 8u ) ));
  }

  EVP_CIPHER_CTX * cipher_ctx = keys->pkt_cipher_ctx;
  if( FD_UNLIKELY( !cipher_ctx ) ) {
    return FD_QUIC_FAILED;
  }

  if( FD_UNLIKELY( EVP_DecryptInit_ex( cipher_ctx, suite->pkt_cipher, NULL, keys->pkt_key, nonce ) != 1 ) ) {
    return FD_QUIC_FAILED;
  }

  /* auth data added with NULL output - still require out length */
  int tmp = 0;
  if( FD_UNLIKELY( EVP_DecryptUpdate( cipher_ctx, NULL, &tmp, hdr, (int)hdr_sz ) != 1 ) ) {
    FD_DEBUG( FD_LOG_WARNING(( "fd_quic_crypto_decrypt: EVP_DecryptUpdate failed auth_data" )) );
    return FD_QUIC_FAILED;
  }

  int i_block_sz = EVP_CIPHER_block_size( suite->pkt_cipher );
  if( FD_UNLIKELY( FD_UNLIKELY( i_block_sz < 0 ) ) ) {
    /* logic error - crash */
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: EVP_CIPHER_block_size returned negative" ));
  }

  ulong block_sz = (ulong)i_block_sz;
  if( FD_UNLIKELY( cipher_text_sz + block_sz > *plain_text_sz + hdr_sz + FD_QUIC_CRYPTO_TAG_SZ ) ) {
    /* do not crash here as remotely triggerable */
    return FD_QUIC_FAILED;
  }

  uchar *       payload    = plain_text + hdr_sz;
  ulong         payload_sz = cipher_text_sz - hdr_sz - FD_QUIC_CRYPTO_TAG_SZ;
  uchar const * tag        = cipher_text + cipher_text_sz - FD_QUIC_CRYPTO_TAG_SZ;
  int           out_sz     = 0;
  if( FD_UNLIKELY( EVP_DecryptUpdate( cipher_ctx, payload, &out_sz, cipher_text + hdr_sz, (int)payload_sz ) != 1 ) ) {
    return FD_QUIC_FAILED;
  }

  /* set tag before final */
  if( FD_UNLIKELY( EVP_CIPHER_CTX_ctrl( cipher_ctx, EVP_CTRL_AEAD_SET_TAG, FD_QUIC_CRYPTO_TAG_SZ, (void*)tag ) != 1 ) ) {
    return FD_QUIC_FAILED;
  }

  if( FD_UNLIKELY( out_sz < 0 ) ) {
    FD_LOG_WARNING(( "fd_quic_crypto_decrypt: EVP_CIPHER_CTX_ctrl returned negative value in out_sz" ));
    return FD_QUIC_FAILED;
  }

  ulong offset = (ulong)out_sz;
  if( EVP_DecryptFinal( cipher_ctx, payload + offset, &out_sz ) != 1 ) {
    FD_DEBUG( FD_LOG_WARNING(
        ( "fd_quic_crypto_decrypt: EVP_DecryptFinal failed %s", fd_quic_openssl_strerror() )
    ) );
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
    FD_LOG_WARNING(( "fd_quic_crypto_decrypt: cipher text too small" ));
    return FD_QUIC_FAILED;
  }

  /* must have capacity for header */
  if( FD_UNLIKELY( *plain_text_sz < pkt_number_off + 4 ) ) {
    FD_DEBUG( FD_LOG_WARNING( ( "fd_quic_crypto_decrypt: plain text buffer too small" ) ) );
    return FD_QUIC_FAILED;
  }

  uint          first      = cipher_text[0]; /* first byte */
  uint          long_hdr   = first & 0x80u;  /* long header? (this bit is not encrypted) */
  ulong         sample_off = pkt_number_off + 4;
  uchar const * sample     = cipher_text + sample_off;

  EVP_CIPHER_CTX * hp_cipher_ctx = keys->hp_cipher_ctx;
  if( FD_UNLIKELY( !hp_cipher_ctx ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: Error creating cipher ctx" ));
  }

  uchar hp_cipher[ FD_QUIC_CRYPTO_BLOCK_BOUND ] = {0};
  if( FD_UNLIKELY( EVP_CIPHER_block_size( suite->hp_cipher ) > FD_QUIC_CRYPTO_BLOCK_BOUND ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt failed. HP cipher block size too big" ));
  }

  if( FD_UNLIKELY( sample + FD_QUIC_HP_SAMPLE_SZ > cipher_text + cipher_text_sz ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt failed. Not enough bytes for a sample" ));
  }

  int hp_cipher_sz = 0;
  if( FD_UNLIKELY( EVP_EncryptUpdate( hp_cipher_ctx, hp_cipher, &hp_cipher_sz, sample, FD_QUIC_HP_SAMPLE_SZ ) != 1 ) ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: EVP_EncryptUpdate failed cipher (hp)" ));
  }

  /* copy header, up to packet number, into output */
  if( sample_off > *plain_text_sz ) {
    FD_LOG_ERR(( "fd_quic_crypto_decrypt: plain text buffer too short for header" ));
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

int
fd_quic_crypto_lookup_suite( uchar major,
                             uchar minor );

int
fd_quic_crypto_rand( uchar * buf,
                     ulong   buf_sz ) {

  if( FD_UNLIKELY( buf_sz > INT_MAX ) ) {
    FD_DEBUG ( FD_LOG_WARNING(( "fd_quic_crypto_rand: buf_sz too big (%#lx)", buf_sz )) );
    return FD_QUIC_FAILED;
  }

  if( FD_LIKELY( 1==RAND_bytes( buf, (int)buf_sz ) ) )
    return FD_QUIC_SUCCESS;

  /* openssl error getting random bytes - bail */
  FD_LOG_ERR( ( "openssl RAND_bytes failed. Error: %s", fd_quic_openssl_strerror() ) );
}

int fd_quic_retry_token_encrypt(
    fd_quic_conn_id_t * orig_dst_conn_id,
    ulong               now,
    fd_quic_conn_id_t * retry_src_conn_id,
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

  int ciphertext_len = gcm_encrypt(
      EVP_aes_256_gcm(),
      plaintext,
      FD_QUIC_RETRY_TOKEN_PLAINTEXT_SZ,
      aad,
      (int)aad_sz,
      aead_key,
      iv,
      ciphertext,
      tag
  );
  if ( FD_QUIC_RETRY_TOKEN_CIPHERTEXT_SZ != ciphertext_len ) {
    return FD_QUIC_FAILED;
  }
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
  if ( FD_UNLIKELY(
           gcm_decrypt(
               EVP_aes_256_gcm(),
               ciphertext,
               FD_QUIC_RETRY_TOKEN_CIPHERTEXT_SZ,
               aad,
               (int)aad_sz,
               tag,
               aead_key,
               iv,
               plaintext
           ) == -1
       ) ) {
    return FD_QUIC_FAILED;
  };

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
  int ciphertext_len = gcm_encrypt(
      EVP_aes_128_gcm(),
      NULL,
      0,
      retry_pseudo_pkt,
      retry_pseudo_pkt_len,
      FD_QUIC_RETRY_INTEGRITY_TAG_KEY,
      FD_QUIC_RETRY_INTEGRITY_TAG_NONCE,
      NULL,
      retry_integrity_tag
  );
  if ( FD_UNLIKELY( ciphertext_len != 0 ) ) {
    return FD_QUIC_FAILED;
  }
  return FD_QUIC_SUCCESS;
}

int fd_quic_retry_integrity_tag_decrypt(
    uchar * retry_pseudo_pkt,
    int     retry_pseudo_pkt_len,
    uchar   retry_integrity_tag[static FD_QUIC_RETRY_INTEGRITY_TAG_SZ]
) {
  int plaintext_len = gcm_decrypt(
      EVP_aes_128_gcm(),
      NULL,
      0,
      retry_pseudo_pkt,
      retry_pseudo_pkt_len,
      retry_integrity_tag,
      FD_QUIC_RETRY_INTEGRITY_TAG_KEY,
      FD_QUIC_RETRY_INTEGRITY_TAG_NONCE,
      NULL
  );
  if ( FD_UNLIKELY( plaintext_len != 0 ) ) {
    return FD_QUIC_FAILED;
  }
  return FD_QUIC_SUCCESS;
}

int gcm_encrypt(
    const EVP_CIPHER * cipher,
    uchar *            plaintext,
    int                plaintext_len,
    uchar *            aad,
    int                aad_len,
    uchar *            key,
    uchar *            iv,
    uchar *            ciphertext,
    uchar *            tag
) {
  EVP_CIPHER_CTX * ctx;
  ctx = EVP_CIPHER_CTX_new();
  if( FD_UNLIKELY( !ctx ) ) {
    FD_DEBUG( FD_LOG_ERR( ( "EVP_CIPHER_CTX_new failed. Error: %s", fd_quic_openssl_strerror() ) ) );
    return -1;
  }

  if( FD_UNLIKELY( 1 != EVP_EncryptInit_ex( ctx, cipher, NULL, key, iv ) ) ) {
    FD_DEBUG( FD_LOG_ERR( ( "EVP_EncryptInit_ex failed. Error: %s", fd_quic_openssl_strerror() ) ); )
    return -1;
  }

  int len;
  /* The associated data ("AD" in AEAD). */
  if( FD_UNLIKELY( 1 != EVP_EncryptUpdate( ctx, NULL, &len, aad, aad_len ) ) ) {
    FD_DEBUG( FD_LOG_ERR( ( "EVP_EncryptUpdate (AAD) failed. Error: %s", fd_quic_openssl_strerror() ) ); )
    return -1;
  }

  /* The encryption of plaintext ("E" in AEAD). */
  int ciphertext_len;
  if ( plaintext_len > 0 &&
       FD_UNLIKELY( 1 != EVP_EncryptUpdate( ctx, ciphertext, &len, plaintext, plaintext_len ) ) ) {
    FD_DEBUG( FD_LOG_ERR( ( "EVP_EncryptUpdate (plaintext) failed. Error: %s", fd_quic_openssl_strerror() ) ); )
    return -1;
  }
  ciphertext_len = len;
  if ( FD_UNLIKELY( 1 != EVP_EncryptFinal_ex( ctx, ciphertext + len, &len ) ) ) {
    FD_DEBUG( FD_LOG_ERR( ( "EVP_EncryptFinal_ex failed. Error: %s", fd_quic_openssl_strerror() ) ); )
    return -1;
  }
  ciphertext_len += len;

  /* The authentication tag ("A" in AEAD). */
  if( FD_UNLIKELY( 1 != EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_GCM_GET_TAG, 16, tag ) ) ) {
    FD_DEBUG( FD_LOG_ERR(( "EVP_CIPHER_CTX_ctrl (get tag) failed. Error: %s", fd_quic_openssl_strerror() )) );
    return -1;
  }

  EVP_CIPHER_CTX_free( ctx );
  return ciphertext_len;
}

int gcm_decrypt(
    const EVP_CIPHER * cipher,
    uchar *            ciphertext,
    int                ciphertext_len,
    uchar *            aad,
    int                aad_len,
    uchar *            tag,
    uchar *            key,
    uchar *            iv,
    uchar *            plaintext
) {
  EVP_CIPHER_CTX * ctx;

  if( FD_UNLIKELY( !( ctx = EVP_CIPHER_CTX_new() ) ) ) {
    FD_DEBUG( FD_LOG_WARNING( ( "EVP_CIPHER_CTX_new failed. Error: %s", fd_quic_openssl_strerror() ) ) );
    return -1;
  }

  if( FD_UNLIKELY( !EVP_DecryptInit_ex( ctx, cipher, NULL, key, iv ) ) ) {
    FD_DEBUG( FD_LOG_WARNING( ( "EVP_DecryptInit_ex failed. Error: %s", fd_quic_openssl_strerror() ) ) );
    return -1;
  }

  int len;
  if( FD_UNLIKELY( !EVP_DecryptUpdate( ctx, NULL, &len, aad, aad_len ) ) ) {
    FD_DEBUG( FD_LOG_WARNING( ( "EVP_DecryptUpdate (AAD) failed. Error: %s", fd_quic_openssl_strerror() ) ) );
    return -1;
  }

  if( FD_UNLIKELY( !EVP_DecryptUpdate( ctx, plaintext, &len, ciphertext, ciphertext_len ) ) ) {
    FD_DEBUG( FD_LOG_WARNING( ( "EVP_DecryptUpdate (ciphertext) failed. Error: %s", fd_quic_openssl_strerror() ) ) );
    return -1;
  }

  int plaintext_len = len;
  if( FD_UNLIKELY( !EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_GCM_SET_TAG, FD_QUIC_CRYPTO_TAG_SZ, tag ) ) ) {
    FD_DEBUG( FD_LOG_WARNING( ( "EVP_CIPHER_CTX_ctrl (get tag) failed. Error: %s", fd_quic_openssl_strerror() ) ) );
    return -1;
  }

  int rc = EVP_DecryptFinal_ex( ctx, plaintext + len, &len );
  if( FD_UNLIKELY( rc <= 0 ) ) {
    FD_DEBUG( FD_LOG_WARNING( ( "EVP_DecryptFinal_ex failed. Error: %s", fd_quic_openssl_strerror() ) ) );
    return -1;
  }
  plaintext_len += len;

  EVP_CIPHER_CTX_free( ctx );
  return plaintext_len;
}
