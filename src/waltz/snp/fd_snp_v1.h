#ifndef HEADER_snp_s0_client_h
#define HEADER_snp_s0_client_h

#include "fd_snp_proto.h"
#include "../../ballet/ed25519/fd_x25519.h"

#define FD_SNP_HS_SERVER_CHALLENGE_TIMOUT_MS (60000L)

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

#define FD_SNP_PKT_SRC_SESSION_ID_OFF     (12UL)
#define FD_SNP_PKT_CLIENT_EPHEMERAL_OFF   (20UL)
#define FD_SNP_PKT_CLIENT_CHALLENGE_OFF   (52UL)
#define FD_SNP_PKT_CLIENT_ENC_PUBKEY_OFF  (20UL)
#define FD_SNP_PKT_CLIENT_ENC_SIG_OFF     (68UL)
#define FD_SNP_PKT_SERVER_CHALLENGE_OFF   (20UL)
#define FD_SNP_PKT_SERVER_EPHEMERAL_OFF   (36UL)
#define FD_SNP_PKT_SERVER_ENC_PUBKEY_OFF  (68UL)
#define FD_SNP_PKT_SERVER_ENC_SIG_OFF    (116UL)

struct __attribute__((packed)) fd_snp_v1_pkt_hs {
  uint  version;
  ulong session_id;
  ulong src_session_id;
};
typedef struct fd_snp_v1_pkt_hs fd_snp_v1_pkt_hs_t;

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

struct __attribute__((packed)) fd_snp_v1_pkt_hs_server {
  fd_snp_v1_pkt_hs_t hs;
  uchar              r[ 16 ];           /* server_init */
  uchar              e[ 32 ];           /* server_fini */
  uchar              enc_s1  [ 32+16 ];
  uchar              enc_sig1[ 64+16 ];
};
typedef struct fd_snp_v1_pkt_hs_server fd_snp_v1_pkt_hs_server_t;

struct __attribute__((packed)) fd_snp_v1_pkt_hs_server_r {
  long   timestamp_ms;
  ulong  peer_addr;
};
typedef struct fd_snp_v1_pkt_hs_server_r fd_snp_v1_pkt_hs_server_r_t;
FD_STATIC_ASSERT( sizeof(fd_snp_v1_pkt_hs_server_r_t)==16UL, fd_snp_v1_pkt_hs_server_r_t );

FD_PROTOTYPES_BEGIN

int
fd_snp_v1_finalize_packet( fd_snp_conn_t * conn,
                           uchar *         packet,
                           ulong           packet_sz );

int
fd_snp_v1_validate_packet( fd_snp_conn_t * conn,
                           uchar *         packet,
                           ulong           packet_sz );

int
fd_snp_v1_client_init( fd_snp_config_t const * client,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       ulong                   pkt_in_sz,
                       uchar *                 pkt_out,
                       uchar *                 extra );

int
fd_snp_v1_server_init( fd_snp_config_t const * server,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       ulong                   pkt_in_sz,
                       uchar *                 pkt_out,
                       uchar *                 extra );

int
fd_snp_v1_client_cont( fd_snp_config_t const * client,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       ulong                   pkt_in_sz,
                       uchar *                 pkt_out,
                       uchar *                 extra );

int
fd_snp_v1_server_fini( fd_snp_config_t const * server,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       ulong                   pkt_in_sz,
                       uchar *                 pkt_out,
                       uchar *                 extra );

int
fd_snp_v1_client_fini( fd_snp_config_t const * client,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       ulong                   pkt_in_sz,
                       uchar *                 pkt_out,
                       uchar *                 extra );

int
fd_snp_v1_server_acpt( fd_snp_config_t const * server,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       ulong                   pkt_in_sz,
                       uchar *                 pkt_out,
                       uchar *                 extra );

int
fd_snp_v1_server_fini_add_signature( fd_snp_conn_t * conn,
                                     uchar out[ FD_SNP_MTU-42 ],
                                     uchar const sig[ 64 ] );

int
fd_snp_v1_client_fini_add_signature( fd_snp_conn_t * conn,
                                     uchar out[ FD_SNP_MTU-42 ],
                                     uchar const sig[ 64 ] );

int
fd_snp_v1_server_fini_precheck( fd_snp_config_t const * server,
                                fd_snp_conn_t *         conn,
                                uchar const *           pkt_in,
                                ulong                   pkt_in_sz,
                                uchar *                 pkt_out,
                                uchar *                 extra );
/* Private, for tests */

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

#endif /* HEADER_snp_s0_client_h */
