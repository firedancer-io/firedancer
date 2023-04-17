#ifndef HEADER_fd_src_tango_quic_crypto_fd_quic_crypto_suites_h
#define HEADER_fd_src_tango_quic_crypto_fd_quic_crypto_suites_h

#include <openssl/ssl.h>
#include "../fd_quic_common.h"
#include "../../../ballet/hmac/fd_hmac.h"

/* Defines the crypto suites used by QUIC v1.

   QUIC v2 is defined here:
     https://www.rfc-editor.org/rfc/rfc9001.html#name-header-protection
     https://www.rfc-editor.org/rfc/rfc8446.html#page-133

   The suites are defined thusly:

       +------------------------------+-------------+
       | Description                  | Value       |
       +------------------------------+-------------+
       | TLS_AES_128_GCM_SHA256       | {0x13,0x01} |
       | TLS_AES_256_GCM_SHA384       | {0x13,0x02} |
       | TLS_CHACHA20_POLY1305_SHA256 | {0x13,0x03} |
       | TLS_AES_128_CCM_SHA256       | {0x13,0x04} |
       | TLS_AES_128_CCM_8_SHA256     | {0x13,0x05} |
       +------------------------------+-------------+

   Notes:
     TLS_AES_128_CCM_SHA256 does not seem to be mentioned in rfc9001, so is excluded
     TLS_AES_128_CCM_8_SHA256 has no packet-header encryption defined, and so must be excluded

     The remainder are defined below */

/* TLS suites

    id,  suite name,                   major, minor, pkt cipher,        hp cipher,   hash,   key sz, iv sz */
#define FD_QUIC_CRYPTO_SUITE_LIST( X, ... ) \
  X( 0, TLS_AES_128_GCM_SHA256,        0x13,  0x01,  AES_128_GCM,       AES_128_ECB, sha256, 16,     12, __VA_ARGS__ ) \
  X( 1, TLS_AES_256_GCM_SHA384,        0x13,  0x02,  AES_256_GCM,       AES_256_ECB, sha384, 32,     12, __VA_ARGS__ ) \
  X( 2, TLS_AES_128_CCM_SHA256,        0x13,  0x04,  AES_128_CCM,       AES_128_ECB, sha256, 16,     12, __VA_ARGS__ ) \
  X( 3, TLS_CHACHA20_POLY1305_SHA256,  0x13,  0x03,  CHACHA20_POLY1305, CHACHA20,    sha256, 32,     12, __VA_ARGS__ ) \


#define FD_QUIC_ENC_LEVEL_LIST( X, ... ) \
  X( 0, initial,    ssl_encryption_initial,     __VA_ARGS__ ) \
  X( 1, early_data, ssl_encryption_early_data,  __VA_ARGS__ ) \
  X( 2, handshake,  ssl_encryption_handshake,   __VA_ARGS__ ) \
  X( 3, appdata,    ssl_encryption_application, __VA_ARGS__ )

#define FD_QUIC_NUM_ENC_LEVELS 4


typedef struct fd_quic_crypto_keys    fd_quic_crypto_keys_t;
typedef struct fd_quic_crypto_ctx     fd_quic_crypto_ctx_t;
typedef struct fd_quic_crypto_suite   fd_quic_crypto_suite_t;
typedef struct fd_quic_crypto_secrets fd_quic_crypto_secrets_t;

/* TODO determine whether this is sufficient for all supported suites */
#define FD_QUIC_KEY_MAX_SZ 32

/* TODO determine whether this is correct for all supported cipher suites */
#define FD_QUIC_CRYPTO_TAG_SZ 16

/* determine whether this is correct for all supported cipher suites */
#define FD_QUIC_CRYPTO_SAMPLE_SZ 16

struct fd_quic_crypto_suite {
  int   id;
  int   major;
  int   minor;
  ulong key_sz;
  ulong iv_sz;

  EVP_CIPHER const * pkt_cipher;  /* not owned */
  EVP_CIPHER const * hp_cipher;   /* not owned */
  fd_hmac_fn_t       hmac_fn;     /* not owned */
  ulong              hash_sz;
};

struct fd_quic_crypto_keys {
  /* packet protection: */
  uchar pkt_key[FD_QUIC_KEY_MAX_SZ];
  ulong pkt_key_sz;

  uchar iv[FD_QUIC_KEY_MAX_SZ];
  ulong iv_sz;

  /* header protection */
  uchar hp_key[FD_QUIC_KEY_MAX_SZ];
  ulong hp_key_sz;

  EVP_CIPHER_CTX * pkt_cipher_ctx;
  EVP_CIPHER_CTX * hp_cipher_ctx;
};

/* crypto context */
struct fd_quic_crypto_ctx {
  /* for packet protection */
  EVP_CIPHER const * CIPHER_AES_128_GCM;
  EVP_CIPHER const * CIPHER_AES_256_GCM;
  EVP_CIPHER const * CIPHER_AES_128_CCM;
  EVP_CIPHER const * CIPHER_CHACHA20_POLY1305;

  /* for header protection */
  EVP_CIPHER const * CIPHER_AES_128_ECB;
  EVP_CIPHER const * CIPHER_AES_256_ECB;
  EVP_CIPHER const * CIPHER_CHACHA20;

  /* hash functions */
  fd_hmac_fn_t hmac_fn;
  ulong        hmac_out_sz;

  /* count +1 for each suite */
  fd_quic_crypto_suite_t suites[0
#define _( ... ) + 1
    FD_QUIC_CRYPTO_SUITE_LIST( _, )
#undef _
      ];
};

/* define enums for suites */
#define _( id, suite, maj, min, ... ) \
  suite = ( maj << 8 ) + min,
enum {
  FD_QUIC_CRYPTO_SUITE_LIST( _, )
};
#undef _

/* define enums for suite ids */
#define _( id, suite, maj, min, ... ) \
  suite##_ID = id,
enum {
  FD_QUIC_CRYPTO_SUITE_LIST( _, )
};
#undef _

/* define enums for encryption levels */
#define _( id, name, ... ) \
  fd_quic_enc_level_##name##_id = id,
enum {
  FD_QUIC_ENC_LEVEL_LIST( _, )
};
#undef _

#define FD_QUIC_INITIAL_SECRET_SZ 32
#define FD_QUIC_MAX_SECRET_SZ     64
#define FD_QUIC_HP_SAMPLE_SZ      16
#define FD_QUIC_NONCE_SZ          12

/* labels defined in rfc9001 */
#define FD_QUIC_CRYPTO_LABEL_CLIENT_IN "client in"
#define FD_QUIC_CRYPTO_LABEL_SERVER_IN "server in"

#define FD_QUIC_CRYPTO_LABEL_QUIC_KEY "quic key"
#define FD_QUIC_CRYPTO_LABEL_QUIC_IV  "quic iv"
#define FD_QUIC_CRYPTO_LABEL_QUIC_HP  "quic hp"

#define FD_QUIC_CRYPTO_LABEL_KEY_UPDATE "quic ku"

/* initial salt */
#define FD_QUIC_CRYPTO_V1_INITIAL_SALT_SZ   (20UL)
extern uchar FD_QUIC_CRYPTO_V1_INITIAL_SALT[ 20UL ];

/* each of these has "-1" to avoid counting the implied terminating NUL byte */
#define FD_QUIC_CRYPTO_LABEL_CLIENT_IN_SZ ( sizeof( FD_QUIC_CRYPTO_LABEL_CLIENT_IN ) - 1 )
#define FD_QUIC_CRYPTO_LABEL_SERVER_IN_SZ ( sizeof( FD_QUIC_CRYPTO_LABEL_SERVER_IN ) - 1 )

#define FD_QUIC_CRYPTO_LABEL_QUIC_KEY_SZ  ( sizeof( FD_QUIC_CRYPTO_LABEL_QUIC_KEY ) - 1 )
#define FD_QUIC_CRYPTO_LABEL_QUIC_IV_SZ   ( sizeof( FD_QUIC_CRYPTO_LABEL_QUIC_IV ) - 1 )
#define FD_QUIC_CRYPTO_LABEL_QUIC_HP_SZ   ( sizeof( FD_QUIC_CRYPTO_LABEL_QUIC_HP ) - 1 )

/* bound the max size of the above labels */
#define FD_QUIC_CRYPTO_LABEL_BOUND 64

/* bound the max size of a connection id */
#define FD_QUIC_CRYPTO_CONN_ID_BOUND 1024

/* bound on the storage needed for any of the hash functions in the suites */
#define FD_QUIC_CRYPTO_HASH_SZ_BOUND 64

/* bound on the storage needed for any of the suites' cipher block sizes */
#define FD_QUIC_CRYPTO_BLOCK_BOUND 64

struct fd_quic_crypto_secrets {
  uchar initial_secret[FD_QUIC_INITIAL_SECRET_SZ];

  /* a secret for each encryption level, and one for us (is_peer=0), and one for them */
  /* secret[enc_level][is_peer][0..FD_QUIC_MAX_SECRET_SZ] */
  uchar secret   [FD_QUIC_NUM_ENC_LEVELS][2][FD_QUIC_MAX_SECRET_SZ];
  uchar secret_sz[FD_QUIC_NUM_ENC_LEVELS][2];

  /* new secret for switching keys during key update */
  uchar new_secret   [2][FD_QUIC_MAX_SECRET_SZ];
  uchar new_secret_sz[2];
};

/* fd_quic_crypto_rand retrieves cryptographic quality random bytes
   into given memory region.  buf points to first byte of buffer in
   local address space.  buf_sz is the number of bytes to fill.  Current
   backend is OpenSSL RAND_bytes (>=256-bit security level on Linux).
   Return value in FD_QUIC_{SUCCESS,FAILURE}.  Reasons for failure
   include lack of entropy, in which case caller should wait and retry.
   buf_sz in [1,INT_MAX] but should be reasonably small (max KiB-ish) */

int
fd_quic_crypto_rand( uchar * buf,
                     ulong   buf_sz );

/* fd_quic_crypto_ctx_init initializes the given QUIC crypto context
   using the TLS provider library.  Should be considered an expensive
   operation and thus used sparingly.  On failure, logs error and
   terminates program.  Reasons for failure include fatal init error
   in TLS library. */

void
fd_quic_crypto_ctx_init( fd_quic_crypto_ctx_t * ctx );

/* fd_quic_crypto_ctx_fini finalizes the given QUIC crypto context
   object.  Releases resources back to the TLS provider library. */

void
fd_quic_crypto_ctx_fini( fd_quic_crypto_ctx_t * ctx );

/* HKDF extract and expand-label are defined here:
     https://www.rfc-editor.org/rfc/rfc9001.html#name-packet-protection
     https://www.rfc-editor.org/rfc/rfc5869.html

   they are used for used for generating secrets */

/* fd_quic_hkdf_extract

   TODO how to ensure no buffer overrun occurs here

   returns
     FD_QUIC_SUCCESS   if the operation succeeded
     FD_QUIC_FAILED    otherwise

   args
     output        a pointer to a buffer to receive the output data
                   must fit the size of the hash function used
     output_sz     the capacity of the output buffer in bytes
     salt          a pointer to the salt used - see rfc
     salt_sz       the size of the salt used.
     conn_id       a pointer to the raw connection id used
     conn_id_sz    the size of the connection id */
void *
fd_quic_hkdf_extract( void *       output,
                      void const * salt,    ulong salt_sz,
                      void const * conn_id, ulong conn_id_sz,
                      fd_hmac_fn_t hmac_fn );

/* fd_quic_hkdf_expand_label

   returns
     FD_QUIC_SUCCESS   if the operation succeeded
     FD_QUIC_FAILED    otherwise

   args
     output        a pointer to a buffer to receive the output data
     output_sz     the capacity of the output buffer in bytes
     md            a pointer to an EVP_MD initialized for the purpose
     label         a pointer to the label used - see rfc
     label_sz      the size of the label used */

void *
fd_quic_hkdf_expand_label( uchar *       output,  ulong output_sz,
                           uchar const * secret,  ulong secret_sz,
                           uchar const * label,   ulong label_sz,
                           fd_hmac_fn_t  hmac,
                           ulong         hash_sz );

/* fd_quic_gen_initial_secret generates the initial secret according to spec

   returns
     FD_QUIC_SUCCESS   if the operation succeeded
     FD_QUIC_FAILED    otherwise

   args
     secrets           a pointer to the structure to receive the secrets data
     initial_salt      the salt used to generate the secrets
     initial_salt_sz   the size of the salt used
     conn_id           the raw connection id required to generate the secrets
     conn_id_sz        the size of the raw connection id */
int
fd_quic_gen_initial_secret(
    fd_quic_crypto_secrets_t * secrets,
    uchar const *              initial_salt,
    ulong                      initial_salt_sz,
    uchar const *              conn_id,
    ulong                      conn_id_sz );

/* fd_quic_gen_secrets generate secrets according to the aforementioned RFCs

   returns
     FD_QUIC_SUCCESS   if the operation succeeded
     FD_QUIC_FAILED    otherwise

   args
     secrets           a pointer to the structure to receive the secrets data
     enc_level         the encryption level to update
     md                a pointer to the EVP_MD initialized for the purpose */
int
fd_quic_gen_secrets(
    fd_quic_crypto_secrets_t * secrets,
    int                        enc_level,
    fd_hmac_fn_t               hmac_fn,
    ulong                      hash_sz );


/* generate new secrets

   Used during key update to generate new secrets from the
   existing secrets

   see rfc9001 section 6, rfc8446 section 7.2 */
int
fd_quic_gen_new_secrets(
    fd_quic_crypto_secrets_t * secrets,
    fd_hmac_fn_t               hmac_fn,
    ulong                      hash_sz );


/* free the cipher ctx for the pkt keys and the hp keys */
void
fd_quic_free_keys( fd_quic_crypto_keys_t * keys );


/* free the cipher ctx for only the pkt keys */
void
fd_quic_free_pkt_keys( fd_quic_crypto_keys_t * keys );


/* fd_quic_gen_keys

   generate the keys used for encrypting and decrypting from the given secrets
   and associated data

   returns
     FD_QUIC_SUCCESS   if the operation succeeded
     FD_QUIC_FAILED    otherwise

   args
     keys               a pointer to the structure to receive the generated keys
     suite              the crypto suite in use for these keys
     md                 a pointer to the EVP_MD initialized for the purpose
     secret             a pointer to the secret used for generating the keys
     secret_sz          the size of the secret used */
int
fd_quic_gen_keys(
    fd_quic_crypto_keys_t *  keys,
    fd_quic_crypto_suite_t * suite,
    uchar const *            secret,
    ulong                    secret_sz );


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
    ulong                    hash_sz );

/* encrypt a packet according to rfc9001 packet protection and header protection

   may fail in the following scenarios:
     the receiving buffer is too small
     the decryption functions report failure (openssl)

   returns
     FD_QUIC_SUCCESS   if the operation succeeded
     FD_QUIC_FAILED    otherwise

   args
    out       destination for the full packet
    out_sz    size of the output buffer, and also returned size of the written bytes
    hdr       the input plain text header
    hdr_sz    the size of the input header
    pkt       the input plain text payload
    pkt_sz    the size of the input payload
    suite     the encryption suite to use
    keys      the keys to use
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
    fd_quic_crypto_keys_t *  hp_keys );


/* decrypt a quic protected packet

   may fail in the following scenarios:
     the receiving buffer is too small
     the decryption functions report failure (openssl)
     the decrypted data is corrupt

   returns
     FD_QUIC_SUCCESS   if the operation succeeded
     FD_QUIC_FAILED    otherwise

   args
     plain_text         the resulting decrypted data
     plain_text_sz      a pointer to the size of the decrypted data in bytes
                          this is used on input as the capacity of the buffer and
                            in output as the resulting output size
     cipher_text        the input cypher text
     cipher_text_sz     the input size in bytes of the cipher text
     pkt_number_off     the offset of the packet number within the cipher text
                        this must be determined from unprotected header data
     suite              which particular cipher suite the packet was protected with
     keys               the keys needed to decrypt */

int
fd_quic_crypto_decrypt(
    uchar *                  plain_text,
    ulong *                  plain_text_sz,
    uchar const *            cipher_text,
    ulong                    cipher_text_sz,
    ulong                    pkt_number_off,
    ulong                    pkt_number,
    fd_quic_crypto_suite_t * suite,
    fd_quic_crypto_keys_t *  keys );


/* decrypt a quic protected packet header

   this removes header protection (HP)

   may fail in the following scenarios:
     the receiving buffer is too small
     the decryption functions report failure (openssl)
     the decrypted data is corrupt

   returns
     FD_QUIC_SUCCESS   if the operation succeeded
     FD_QUIC_FAILED    otherwise

   args
     plain_text         the resulting decrypted data
     plain_text_sz      a pointer to the size of the decrypted data in bytes
                          this is used on input as the capacity of the buffer and
                            in output as the resulting output size
     cipher_text        the input cypher text
     cipher_text_sz     the input size in bytes of the cipher text
     pkt_number_off     the offset of the packet number within the cipher text
                        this must be determined from unprotected header data
     suite              which particular cipher suite the packet was protected with
     keys               the keys needed to decrypt */

int
fd_quic_crypto_decrypt_hdr(
    uchar *                  plain_text,
    ulong *                  plain_text_sz,
    uchar const *            cipher_text,
    ulong                    cipher_text_sz,
    ulong                    pkt_number_off,
    fd_quic_crypto_suite_t * suite,
    fd_quic_crypto_keys_t *  keys );


/* look up crypto suite by major/minor

   return
     index into ctx->suites
     -1 if not found

   args
     major   the suite major code
     minor   the suite minor code */
/*
  X( 0, TLS_AES_128_GCM_SHA256,        0x13,  0x01,  AES_128_GCM,       AES_128_ECB, SHA256, 16,     12, __VA_ARGS__ ) \
  */

inline int
fd_quic_crypto_lookup_suite( uchar major,
                             uchar minor ) {
  switch( ( (unsigned)major << 8 ) | (unsigned)minor ) {
#define _( ID, SUITE, MAJOR, MINOR, ... ) \
    case ( (unsigned)MAJOR << 8u ) + (unsigned)MINOR: return ID;
    FD_QUIC_CRYPTO_SUITE_LIST(_,)
    default:
      return -1;
#undef _
  }
}

#endif /* HEADER_fd_src_tango_quic_crypto_fd_quic_crypto_suites_h */

