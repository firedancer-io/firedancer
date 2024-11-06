#ifndef HEADER_fd_src_waltz_quic_fd_quic_retry_h
#define HEADER_fd_src_waltz_quic_fd_quic_retry_h

#include "fd_quic.h"
#include "fd_quic_conn_id.h"
#include "fd_quic_enum.h"
#include "fd_quic_proto_structs.h"
#include "crypto/fd_quic_crypto_suites.h"
#include "../../ballet/aes/fd_aes_gcm.h"

/* fd_quic_retry.h contains APIs for
   - the QUIC v1 Retry mechanism (RFC 9000)
   - the QUIC-TLS v1 Retry Integrity Tag (RFC 9001)
   - the fd_quic retry token scheme (loosely based on draft-ietf-quic-
     retry-offload-00 but incompatible) */

/* Retry Integrity Tag ************************************************/

/* The retry integrity tag is the 16-byte tag output of AES-128-GCM */
#define FD_QUIC_RETRY_INTEGRITY_TAG_SZ FD_QUIC_CRYPTO_TAG_SZ
#define FD_QUIC_RETRY_INTEGRITY_TAG_KEY ((uchar *)"\xbe\x0c\x69\x0b\x9f\x66\x57\x5a\x1d\x76\x6b\x54\xe3\x68\xc8\x4e")
#define FD_QUIC_RETRY_INTEGRITY_TAG_NONCE ((uchar *)"\x46\x15\x99\xd3\x5d\x63\x2b\xf2\x23\x98\x25\xbb")

FD_PROTOTYPES_BEGIN

/* fd_quic_retry_integrity_tag_{sign,verify} implement the RFC 9001
   "Retry Integrity Tag" AEAD scheme.

   This is a standard and mandatory step in the QUIC retry proces, both
   on the server (sign) and client (verify) side.  Confusingly, all
   inputs to these functions are either public constants (e.g. the
   hardcoded encryption key) or sent in plain text over the wire.  Thus,
   the "retry_integrity_tag" is more like a hash function than a MAC and
   the retry_pseudo_pkt is just obfuscated, but not securely encrypted.

   Failure to generate a correct integrity tag as part of the retry
   handshake is considered a protocol error that typically results in
   connection termination.

   fd_quic_retry_integrity_tag_sign creates a MAC over the byte range at
   retry_pseudo_pkt and writes it into retry_integrity_tag.  It is
   infallible.

   fd_quic_retry_integrity_tag_decrypt checks whether a Retry Integrity
   Tag matches the byte range at retry_pseudo_pkt.  It returns
   FD_QUIC_SUCCESS if the integrity tag is vaild, and FD_QUIC_FAILURE
   otherwise. */

static inline void
fd_quic_retry_integrity_tag_sign(
    fd_aes_gcm_t * aes_gcm,
    uchar const *  retry_pseudo_pkt,
    ulong          retry_pseudo_pkt_len,
    uchar          retry_integrity_tag[static FD_QUIC_RETRY_INTEGRITY_TAG_SZ]
) {
  fd_aes_128_gcm_init( aes_gcm, FD_QUIC_RETRY_INTEGRITY_TAG_KEY, FD_QUIC_RETRY_INTEGRITY_TAG_NONCE );
  fd_aes_gcm_encrypt( aes_gcm, NULL, NULL, 0UL, retry_pseudo_pkt, retry_pseudo_pkt_len, retry_integrity_tag );
}

FD_FN_PURE static inline int
fd_quic_retry_integrity_tag_verify(
    fd_aes_gcm_t * aes_gcm,
    uchar const *  retry_pseudo_pkt,
    ulong          retry_pseudo_pkt_len,
    uchar const    retry_integrity_tag[static FD_QUIC_RETRY_INTEGRITY_TAG_SZ]
) {
  fd_aes_128_gcm_init( aes_gcm, FD_QUIC_RETRY_INTEGRITY_TAG_KEY, FD_QUIC_RETRY_INTEGRITY_TAG_NONCE );
  int ok = fd_aes_gcm_decrypt( aes_gcm, NULL, NULL, 0UL, retry_pseudo_pkt, retry_pseudo_pkt_len, retry_integrity_tag );
  return ok ? FD_QUIC_SUCCESS : FD_QUIC_FAILED;
}

FD_PROTOTYPES_END

/* fd_quic retry token (non-standard) **********************************

   The QUIC Retry mechanism as specified in RFC 9000 does not
   authenticate retry packets.  To safely and statelessly handle retries
   in fd_quic, we need to authenticate the token itself.  A construction
   similar to a HMAC scheme is used, but using the OTM in AES-GCM.
   Although AES-GCM is not the ideal algorithm for the job, it was
   chosen because it's common throughout QUIC v1, and also quite fast.

   Security Note: This scheme relies on a 128-bit auth key and 96-bit
   unique nonces.  The encryption key is sourced from CSPRNG on startup
   and stays secret.  Nonces are generated using fd_rng_t (fine if an
   attacker can guess these nonces).  However, if fd_rng_t generates the
   same 96-bit nonce twice, the retry token authentication mechanism
   breaks down entirely (AES-GCM IV reuse). */

/* fd_quic_retry_data_t encodes data within the QUIC Retry token.
   It contains claims about the client. */

struct __attribute__((packed)) fd_quic_retry_data {
  /* 0x00 */ ushort magic;
# define FD_QUIC_RETRY_TOKEN_MAGIC 0xdaa5
  /* 0x02 */ uchar  odcid_sz;      /* in [1,20] */
  /* 0x03 */ uchar  rscid_sz;      /* in [1,20] */
  /* 0x04 */ uchar  token_id[12];  /* pseudorandom, guessable */
  /* 0x10 */ uchar  ip6_addr[16];  /* IPv6 or IPv4-mapped IPv6 address, net order */
  /* 0x20 */ ulong  expire_comp;   /* unix_nanos>>22 */
  /* 0x28 */ ushort udp_port;      /* host order */
  /* 0x2a */ uchar  odcid[20];     /* Original Destination Connection ID */
  /* 0x3e */ uchar  rscid[20];     /* Retry Source Connection ID */
  /* 0x52 */
};

typedef struct fd_quic_retry_data fd_quic_retry_data_t;

/* fd_quic_retry_token_t encodes the QUIC Retry token itself. */

struct fd_quic_retry_token {
  union {
    fd_quic_retry_data_t data;
    uchar                data_opaque[ sizeof(fd_quic_retry_data_t) ];
  };
  uchar mac_tag[ FD_AES_GCM_TAG_SZ ];
};

typedef struct fd_quic_retry_token fd_quic_retry_token_t;

FD_PROTOTYPES_BEGIN

/* fd_quic_retry_data_new initializes fd_quic_retry_data_t with a random
   nonce.  Uses fd_rng_t because only random (unique) bytes are required
   but it is not required that they are unguessable. */

static inline fd_quic_retry_data_t *
fd_quic_retry_data_new( fd_quic_retry_data_t * data,
                        fd_rng_t *             rng ) {
  memset( data, 0, sizeof(fd_quic_retry_data_t) );
  data->magic = FD_QUIC_RETRY_TOKEN_MAGIC;
  FD_STORE( uint, data->token_id + 0, fd_rng_uint( rng ) );
  FD_STORE( uint, data->token_id + 4, fd_rng_uint( rng ) );
  FD_STORE( uint, data->token_id + 8, fd_rng_uint( rng ) );
  return data;
}

/* fd_quic_retry_data_set_ip4 sets the IP address of the token payload
   to an IPv4-mapped IPv6 address. ip4_addr is in big endian order. */

static inline fd_quic_retry_data_t *
fd_quic_retry_data_set_ip4( fd_quic_retry_data_t * data,
                            uint                   ip4_addr ) {
  memset( data->ip6_addr,      0x00, 10 );
  memset( data->ip6_addr + 10, 0xFF,  2 );
  FD_STORE( uint, data->ip6_addr + 12, ip4_addr );
  return data;
}

/* fd_quic_retry_token_sign creates mac_tag using the AEAD instance in
   aes_gcm and the associated data in token->data.

   WARNING: The same token->data->token_id value may not be reused
            across two sign function calls. */

static inline void
fd_quic_retry_token_sign( fd_quic_retry_token_t * token,
                          fd_aes_gcm_t *          aes_gcm,
                          uchar const *           aes_key,
                          uchar const *           aes_iv ) {
  uchar iv[12];
  for( ulong j=0; j<12; j++ ) iv[j] = (uchar)( aes_iv[j] ^ token->data.token_id[j] );
  fd_aes_128_gcm_init( aes_gcm, aes_key, iv );

  void const * aad    = token->data_opaque;
  ulong        aad_sz = sizeof(fd_quic_retry_data_t);
  fd_aes_gcm_encrypt( aes_gcm, NULL, NULL, 0UL, aad, aad_sz, token->mac_tag );
}

/* fd_quic_retry_token_verify checks if token->mac_tag is valid given
   AEAD params and associated data in token->data.  Does not validate
   the content of token->data.
   Returns FD_QUIC_SUCCESS if valid, otherwise FD_QUIC_FAILED. */

static inline int
fd_quic_retry_token_verify( fd_quic_retry_token_t const * token,
                            fd_aes_gcm_t *                aes_gcm,
                            uchar const *                 aes_key,
                            uchar const *                 aes_iv ) {
  uchar iv[12];
  for( ulong j=0; j<12; j++ ) iv[j] = (uchar)( aes_iv[j] ^ token->data.token_id[j] );
  fd_aes_128_gcm_init( aes_gcm, aes_key, iv );

  void const * aad    = token->data_opaque;
  ulong        aad_sz = sizeof(fd_quic_retry_data_t);
  int ok = fd_aes_gcm_decrypt( aes_gcm, NULL, NULL, 0UL, aad, aad_sz, token->mac_tag );
  return ok ? FD_QUIC_SUCCESS : FD_QUIC_FAILED;
}

FD_PROTOTYPES_END

/* Retry Packets ******************************************************/

FD_PROTOTYPES_BEGIN

/* FD_QUIC_RETRY_LOCAL_SZ is the encoded size of Retry packets generated
   by fd_quic.  (Other QUIC implementations may produce differently
   sized retry packets) */

#define FD_QUIC_RETRY_LOCAL_SZ (161UL)

/* fd_quic_retry_{create,verify} do end-to-end issuance and verification
   of fd_quic retry tokens.  Used by the server-side. */

ulong
fd_quic_retry_create(
    uchar                     retry[FD_QUIC_RETRY_LOCAL_SZ], /* out */
    fd_quic_pkt_t const *     pkt,
    fd_rng_t *                rng,
    uchar const               retry_secret[ FD_QUIC_RETRY_SECRET_SZ ],
    uchar const               retry_iv[ FD_QUIC_RETRY_IV_SZ ],
    fd_quic_conn_id_t const * orig_dst_conn_id,
    fd_quic_conn_id_t const * new_conn_id,
    ulong                     wallclock /* ns since unix epoch */
);

int
fd_quic_retry_server_verify(
    fd_quic_pkt_t const *     pkt,
    fd_quic_initial_t const * initial,
    fd_quic_conn_id_t *       orig_dst_conn_id, /* out */
    fd_quic_conn_id_t *       retry_src_conn_id, /* out */
    uchar const               retry_secret[ FD_QUIC_RETRY_SECRET_SZ ],
    uchar const               retry_iv[ FD_QUIC_RETRY_IV_SZ ],
    ulong                     now /* ns since unix epoch */
);

int
fd_quic_retry_client_verify(
    uchar const * const       retry_ptr,
    ulong         const       retry_sz,
    fd_quic_conn_id_t const * orig_dst_conn_id,
    fd_quic_conn_id_t *       src_conn_id, /* out */
    uchar const **            token,
    ulong *                   token_sz
);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_fd_quic_retry_h */
