#ifndef HEADER_fd_src_waltz_quic_crypto_fd_quic_crypto_suites_h
#define HEADER_fd_src_waltz_quic_crypto_fd_quic_crypto_suites_h

#include "../fd_quic_common.h"
#include "../fd_quic_enum.h"
#include "../fd_quic_conn_id.h"
#include "../../../ballet/aes/fd_aes_gcm.h"

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

typedef struct fd_quic_crypto_keys    fd_quic_crypto_keys_t;
typedef struct fd_quic_crypto_secrets fd_quic_crypto_secrets_t;

#define FD_QUIC_CRYPTO_TAG_SZ    16
#define FD_QUIC_CRYPTO_SAMPLE_SZ 16

struct fd_quic_crypto_keys {
  /* packet protection: */
  uchar pkt_key[FD_AES_128_KEY_SZ];
  uchar iv     [FD_AES_GCM_IV_SZ ];
  uchar hp_key [FD_AES_128_KEY_SZ];
};

/* define enums for encryption levels */
#define fd_quic_enc_level_initial_id    0
#define fd_quic_enc_level_early_data_id 1
#define fd_quic_enc_level_handshake_id  2
#define fd_quic_enc_level_appdata_id    3
#define FD_QUIC_NUM_ENC_LEVELS          4

/* labels defined in rfc9001 */
#define FD_QUIC_CRYPTO_LABEL_CLIENT_IN "client in"
#define FD_QUIC_CRYPTO_LABEL_SERVER_IN "server in"

#define FD_QUIC_CRYPTO_LABEL_QUIC_KEY "quic key"
#define FD_QUIC_CRYPTO_LABEL_QUIC_IV  "quic iv"
#define FD_QUIC_CRYPTO_LABEL_QUIC_HP  "quic hp"

#define FD_QUIC_CRYPTO_LABEL_KEY_UPDATE "quic ku"

/* each of these has "-1" to avoid counting the implied terminating NUL byte */
#define FD_QUIC_CRYPTO_LABEL_CLIENT_IN_LEN ( sizeof( FD_QUIC_CRYPTO_LABEL_CLIENT_IN ) - 1 )
#define FD_QUIC_CRYPTO_LABEL_SERVER_IN_LEN ( sizeof( FD_QUIC_CRYPTO_LABEL_SERVER_IN ) - 1 )

#define FD_QUIC_CRYPTO_LABEL_QUIC_KEY_LEN  ( sizeof( FD_QUIC_CRYPTO_LABEL_QUIC_KEY ) - 1 )
#define FD_QUIC_CRYPTO_LABEL_QUIC_IV_LEN   ( sizeof( FD_QUIC_CRYPTO_LABEL_QUIC_IV ) - 1 )
#define FD_QUIC_CRYPTO_LABEL_QUIC_HP_LEN   ( sizeof( FD_QUIC_CRYPTO_LABEL_QUIC_HP ) - 1 )

#define FD_QUIC_CRYPTO_LABEL_KEY_UPDATE_LEN ( sizeof( FD_QUIC_CRYPTO_LABEL_KEY_UPDATE ) - 1 )

struct fd_quic_crypto_secrets {
  uchar initial_secret[FD_QUIC_INITIAL_SECRET_SZ];

  /* a secret for each encryption level, and one for us (is_peer=0), and one for them */
  /* secret[enc_level][is_peer][0..FD_QUIC_MAX_SECRET_SZ] */
  uchar secret[FD_QUIC_NUM_ENC_LEVELS][2][FD_QUIC_SECRET_SZ];

  /* new secret for switching keys during key update */
  uchar new_secret[2][FD_QUIC_SECRET_SZ];
};

/* fd_quic_gen_initial_secret generates the initial secret according to spec

   args
     secrets           a pointer to the structure to receive the secrets data
     conn_id           the raw connection id required to generate the secrets
     conn_id_sz        the size of the raw connection id */
void
fd_quic_gen_initial_secret(
    fd_quic_crypto_secrets_t * secrets,
    uchar const *              conn_id,
    ulong                      conn_id_sz );

/* fd_quic_gen_secrets generate secrets according to the aforementioned RFCs

   args
     secrets           a pointer to the structure to receive the secrets data
     enc_level         the encryption level to update */
void
fd_quic_gen_secrets(
    fd_quic_crypto_secrets_t * secrets,
    uint                       enc_level );

void
fd_quic_key_update_derive( fd_quic_crypto_secrets_t * secrets,
                           fd_quic_crypto_keys_t      new_keys[2] );

/* fd_quic_gen_keys

   generate the keys used for encrypting and decrypting from the given secrets
   and associated data

   args
     keys               a pointer to the structure to receive the generated keys
     secret             a pointer to the secret used for generating the keys */
void
fd_quic_gen_keys(
    fd_quic_crypto_keys_t * keys,
    uchar const             secret[ 32 ] );


/* encrypt a packet according to rfc9001 packet protection and header protection

   may fail in the following scenarios:
     the receiving buffer is too small
     the decryption functions report failure (fd_tls)

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
    keys      the keys to use
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
    ulong                          const pkt_number );


/* decrypt a quic protected packet

   may fail in the following scenarios:
     the receiving buffer is too small
     the decryption functions report failure (fd_tls)
     the decrypted data is corrupt

   returns
     FD_QUIC_SUCCESS   if the operation succeeded
     FD_QUIC_FAILED    otherwise

   args
     buf                buffer containing a QUIC packet with a decrypted
                        header, and encrypted payload, and the auth tag
                        of size FD_QUIC_CRYPTO_TAG_SZ.  On return, the
                        payload will be decrypted.
     buf_sz             the size of the QUIC packet
     pkt_number_off     the offset of the packet number within the cipher text
                        this must be determined from unprotected header data
     keys               the keys needed to decrypt */

int
fd_quic_crypto_decrypt(
    uchar *                        buf,
    ulong                          buf_sz,
    ulong                          pkt_number_off,
    ulong                          pkt_number,
    fd_quic_crypto_keys_t const *  keys );


/* decrypt a quic protected packet header

   this removes header protection (HP)

   may fail in the following scenarios:
     the receiving buffer is too small
     the decryption functions report failure (fd_tls)
     the decrypted data is corrupt

   returns
     FD_QUIC_SUCCESS   if the operation succeeded
     FD_QUIC_FAILED    otherwise

   args
     buf                buffer containing an encrypted QUIC packet.
                        On return, the header is decrypted, the rest
                        still encrypted
     buf_sz             size of the QUIC packet
     pkt_number_off     the offset of the packet number within the cipher text
                        this must be determined from unprotected header data
     keys               the keys needed to decrypt */

int
fd_quic_crypto_decrypt_hdr(
    uchar *                        buf,
    ulong                          buf_sz,
    ulong                          pkt_number_off,
    fd_quic_crypto_keys_t const *  keys );

#endif /* HEADER_fd_src_waltz_quic_crypto_fd_quic_crypto_suites_h */
