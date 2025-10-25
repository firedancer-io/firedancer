#ifndef HEADER_fd_src_waltz_snp_fd_snp_v1_h
#define HEADER_fd_src_waltz_snp_fd_snp_v1_h

#include "fd_snp_proto.h"
#include "../../ballet/ed25519/fd_x25519.h"

#define FD_SNP_HS_SERVER_CHALLENGE_TIMOUT_MS (60000L)

/* Size of payload and packet for each handshake message.
   All handshake packets are 1200 bytes long. */
#define FD_SNP_SIZEOF_CLIENT_INIT_PAYLOAD (52UL)
#define FD_SNP_SIZEOF_CLIENT_INIT         FD_SNP_MTU_MIN
#define FD_SNP_SIZEOF_SERVER_INIT_PAYLOAD (36UL)
#define FD_SNP_SIZEOF_SERVER_INIT         FD_SNP_MTU_MIN
#define FD_SNP_SIZEOF_CLIENT_CONT_PAYLOAD (68UL)
#define FD_SNP_SIZEOF_CLIENT_CONT         FD_SNP_MTU_MIN
#define FD_SNP_SIZEOF_SERVER_FINI_PAYLOAD (196UL)
#define FD_SNP_SIZEOF_SERVER_FINI         FD_SNP_MTU_MIN
#define FD_SNP_SIZEOF_CLIENT_FINI_PAYLOAD (148UL)
#define FD_SNP_SIZEOF_CLIENT_FINI         FD_SNP_MTU_MIN

/* Offsets of fields in the handshake packet. */
#define FD_SNP_PKT_SRC_SESSION_ID_OFF     (12UL)
#define FD_SNP_PKT_CLIENT_EPHEMERAL_OFF   (20UL)
#define FD_SNP_PKT_CLIENT_CHALLENGE_OFF   (52UL)
#define FD_SNP_PKT_CLIENT_ENC_PUBKEY_OFF  (20UL)
#define FD_SNP_PKT_CLIENT_ENC_SIG_OFF     (68UL)
#define FD_SNP_PKT_SERVER_CHALLENGE_OFF   (20UL)
#define FD_SNP_PKT_SERVER_EPHEMERAL_OFF   (36UL)
#define FD_SNP_PKT_SERVER_ENC_PUBKEY_OFF  (68UL)
#define FD_SNP_PKT_SERVER_ENC_SIG_OFF    (116UL)

/* Handshake packet header.
   It contains the version, session ID, and source session ID.
   Comparable to fd_snp_hdr_t, during the handhsake we have
   the extra src_session_id field. */
struct __attribute__((packed)) fd_snp_v1_pkt_hs {
  uint  version;
  ulong session_id;
  ulong src_session_id;
};
typedef struct fd_snp_v1_pkt_hs fd_snp_v1_pkt_hs_t;

/* Client handshake packet.
   It contains the hs header, and the client_init or client_fini data.
   For client_init, it contains the ephemeral private key and the challenge.
   For client_fini, it contains the ephemeral public key and the signature. */
struct __attribute__((packed)) fd_snp_v1_pkt_hs_client {
  fd_snp_v1_pkt_hs_t hs;
  union {
    struct {
      uchar          e[ 32 ];           /* client_init */
      uchar          r[ 16 ];           /* client_cont */
    };
    struct {
      uchar          enc_s1  [ 32+16 ]; /* client_fini */
      uchar          enc_sig1[ 64+16 ];
    };
  };
};
typedef struct fd_snp_v1_pkt_hs_client fd_snp_v1_pkt_hs_client_t;

/* Server handshake packet.
   It contains the hs header, and the server_init or server_fini data.
   For server_init, it contains the challenge and the ephemeral private key.
   For server_fini, it contains the ephemeral public key and the signature. */
struct __attribute__((packed)) fd_snp_v1_pkt_hs_server {
  fd_snp_v1_pkt_hs_t hs;
  uchar              r[ 16 ];           /* server_init */
  uchar              e[ 32 ];           /* server_fini */
  uchar              enc_s1  [ 32+16 ];
  uchar              enc_sig1[ 64+16 ];
};
typedef struct fd_snp_v1_pkt_hs_server fd_snp_v1_pkt_hs_server_t;

/* Server challenge.
   It contains the timestamp and the peer address.
   Used to validate the challenge in the server_init packet.
   This struct is exactly 16 bytes long, so we can encrypt it
   with a single AES block. */
struct __attribute__((packed)) fd_snp_v1_pkt_hs_server_r {
  long   timestamp_ms;
  ulong  peer_addr;
};
typedef struct fd_snp_v1_pkt_hs_server_r fd_snp_v1_pkt_hs_server_r_t;
FD_STATIC_ASSERT( sizeof(fd_snp_v1_pkt_hs_server_r_t)==16UL, fd_snp_v1_pkt_hs_server_r_t );

FD_PROTOTYPES_BEGIN

/* Send/recv functions used by fd_snp.c */

/* fd_snp_v1_finalize_packet finalizes the packet by adding the header,
   data, and MAC in SNPv1 format.
   conn is a valid, established connection (required, not checked).
   packet is a valid buffer of at least packet_sz bytes (required, not checked).
   packet_sz is the size of the packet buffer. */
void
fd_snp_v1_finalize_packet( fd_snp_conn_t * conn,
                           uchar *         packet,
                           ulong           packet_sz );

/* fd_snp_v1_validate_packet validates the packet by checking the MAC
   in SNPv1 format.
   conn is a valid, established connection (required, not checked).
   packet is a valid buffer of at least packet_sz bytes (required, not checked).
   packet_sz is the size of the packet buffer.
   Returns 0 on success, -1 on failure. */
int
fd_snp_v1_validate_packet( fd_snp_conn_t * conn,
                           uchar *         packet,
                           ulong           packet_sz );

/* Handshake functions used by fd_snp.c

   For consinstency, all handshake functions have the same signature.
   They accept in input a config (either client or server), a connection
   `conn` and an input packet `pkt_in` of size `pkt_in_sz`.
   They write the output packet in `pkt_out`, which is assumed to be at least
   1200 bytes long, and optionally they store a hash to be signed in the
   `extra` buffer.
   They return the size of the output packet on success, -1 on failure.

   Client and server are assumed to be initialized and not checked.
   Conn is assumed to be a valid pointer, the state and other properties are checked.
   In each function, unnecessary parameters are simply ignored.

   The handshake messages/functions are:

          Client                         Server
                   client_init
                  ------------------->
                   server_init
                  <-------------------
                   client_cont
                  ------------------->
                   server_fini
                  <-------------------
                   client_fini
                  ------------------->   --+
                                           | server_acpt
                                         <-+
*/

/* fd_snp_v1_client_init generates the client_init packet.
   (see also common docs above) */
int
fd_snp_v1_client_init( fd_snp_config_t const * client FD_PARAM_UNUSED,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       ulong                   pkt_in_sz,
                       uchar *                 pkt_out,
                       uchar *                 extra );

/* fd_snp_v1_server_init validates the client_init packet and
   generates the server_init packet.  (see also common docs above) */
int
fd_snp_v1_server_init( fd_snp_config_t const * server,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       ulong                   pkt_in_sz,
                       uchar *                 pkt_out,
                       uchar *                 extra );

/* fd_snp_v1_client_cont validates the server_init packet and
   generates the client_cont packet.  (see also common docs above) */
int
fd_snp_v1_client_cont( fd_snp_config_t const * client,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       ulong                   pkt_in_sz,
                       uchar *                 pkt_out,
                       uchar *                 extra );

/* fd_snp_v1_server_fini validates the client_cont packet and
   generates the server_fini packet and the metadata to be signed.
   (see also common docs above) */
int
fd_snp_v1_server_fini( fd_snp_config_t const * server,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       ulong                   pkt_in_sz,
                       uchar *                 pkt_out,
                       uchar *                 extra );

/* fd_snp_v1_client_fini validates the server_fini packet and
   generates the client_fini packet and the metadata to be signed.
   (see also common docs above) */
   int
fd_snp_v1_client_fini( fd_snp_config_t const * client,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       ulong                   pkt_in_sz,
                       uchar *                 pkt_out,
                       uchar *                 extra );

/* fd_snp_v1_server_acpt validates the client_fini.
   (see also common docs above) */
int
fd_snp_v1_server_acpt( fd_snp_config_t const * server,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       ulong                   pkt_in_sz,
                       uchar *                 pkt_out,
                       uchar *                 extra );

/* fd_snp_v1_server_fini_add_signature adds a signature to a pending
   server_fini packet. */
int
fd_snp_v1_server_fini_add_signature( fd_snp_conn_t * conn,
                                     uchar out[ FD_SNP_MTU-42 ],
                                     uchar const sig[ 64 ] );

/* fd_snp_v1_client_fini_add_signature adds a signature to a pending
   client_fini packet. */
int
fd_snp_v1_client_fini_add_signature( fd_snp_conn_t * conn,
                                     uchar out[ FD_SNP_MTU-42 ],
                                     uchar const sig[ 64 ] );

/* fd_snp_v1_server_fini_precheck validates the client_cont packet
   challenge. This is a convenient function to quickly exclude invalid
   packets, before performing more expensive operations (such as
   allocating connection state and generating cryptographic keys). */
int
fd_snp_v1_server_fini_precheck( fd_snp_config_t const * server,
                                fd_snp_conn_t *         conn,
                                uchar const *           pkt_in,
                                ulong                   pkt_in_sz,
                                uchar *                 pkt_out,
                                uchar *                 extra );

/* Private functions, defined here so we can use them in tests. */

static inline int
fd_snp_v1_crypto_key_share_generate( uchar private_key[32], uchar public_key[32] ) {
  int res = fd_snp_rng( private_key, 32 );
  if( FD_UNLIKELY( res < 0 ) ) {
    return -1;
  }
  fd_x25519_public( public_key, private_key );
  return 0;
}

static inline int
fd_snp_v1_crypto_enc_state_generate( fd_snp_config_t const * server,
                                     fd_snp_conn_t const *   conn,
                                     uchar                   out_challenge[ 16 ] ) {
  fd_snp_v1_pkt_hs_server_r_t challenge[1] = { 0 };
  challenge->timestamp_ms = fd_snp_timestamp_ms();
  challenge->peer_addr = conn->peer_addr;
  fd_aes_encrypt( (uchar const *)challenge, out_challenge, server->_state_enc_key );
  return 0;
}

static inline int
fd_snp_v1_crypto_enc_state_validate( fd_snp_config_t const * server,
                                     fd_snp_conn_t const *   conn,
                                     uchar const             in_challenge[ 16 ] ) {
  fd_snp_v1_pkt_hs_server_r_t decrypted[1] = { 0 };
  fd_aes_decrypt( in_challenge, (uchar *)decrypted, server->_state_dec_key );

  long now_ms = fd_snp_timestamp_ms();
  long min_ms = now_ms - FD_SNP_HS_SERVER_CHALLENGE_TIMOUT_MS;
  if( FD_LIKELY(
    ( min_ms <= decrypted->timestamp_ms && decrypted->timestamp_ms <= now_ms )
    && ( decrypted->peer_addr == conn->peer_addr )
  ) ) {
    return 0;
  }
  return -1;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_snp_fd_snp_v1_h */
