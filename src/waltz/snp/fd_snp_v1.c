#include "fd_snp_v1.h"
#include "fd_snp_common.h"

#include "../../util/bits/fd_bits.h"
#include "../../ballet/aes/fd_aes_gcm.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/hmac/fd_hmac.h"
#include "../../ballet/ed25519/fd_ed25519.h"

static inline uchar *
fd_snp_conn_tx_key( fd_snp_conn_t * conn ) {
  return conn->_sensitive_keys;
}

static inline uchar *
fd_snp_conn_rx_key( fd_snp_conn_t * conn ) {
  return conn->_sensitive_keys + 32;
}

static inline uchar *
fd_snp_conn_noise_hash( fd_snp_conn_t * conn ) {
  return conn->_peer_pubkey; /* SymmetricState.h */
}

static inline uchar *
fd_snp_conn_noise_chaining_key( fd_snp_conn_t * conn ) {
  return conn->_sensitive_keys; /* SymmetricState.ck */
}

static inline uchar *
fd_snp_conn_noise_cipher_key( fd_snp_conn_t * conn ) {
  return conn->_sensitive_keys + 32; /* CipherState.k */
}

static inline uchar *
fd_snp_conn_noise_shared_secret( fd_snp_conn_t * conn ) {
  return fd_snp_conn_noise_cipher_key( conn );
}

static inline uchar *
fd_snp_conn_ephemeral_private_key( fd_snp_conn_t * conn ) {
  return fd_snp_conn_noise_cipher_key( conn );
}

static inline uchar *
fd_snp_conn_ephemeral_public_key( fd_snp_conn_t * conn ) {
  return fd_snp_conn_noise_hash( conn );
}

static inline void
fd_snp_v1_noise_mix_hash( fd_snp_conn_t * conn,
                          uchar const *   data,
                          ulong           data_sz ) {
  fd_sha256_t sha[1];
  uchar * hash = fd_snp_conn_noise_hash( conn );
  fd_sha256_init( sha );
  fd_sha256_append( sha, hash, 32 );
  fd_sha256_append( sha, data, data_sz );
  fd_sha256_fini( sha, fd_snp_conn_noise_hash( conn ) );
}

static inline void
fd_snp_v1_noise_init( fd_snp_conn_t * conn ) {
  uchar init[32] = {
    0x5c, 0x25, 0xcd, 0x45, 0x0f, 0x2b, 0x6c, 0x94, 0xbe, 0x23, 0xd8, 0xb2, 0x8a, 0xca, 0x9d, 0x16,
    0x9b, 0xbd, 0xce, 0xb5, 0x5a, 0x4b, 0x3d, 0x47, 0x3f, 0x8e, 0x58, 0x00, 0xb7, 0xab, 0x3c, 0xcd,
  };
  uchar * hash = fd_snp_conn_noise_hash( conn );
  memcpy( hash, init, 32 );
  memcpy( fd_snp_conn_noise_chaining_key( conn ), hash, 32 );
}

void FD_FN_SENSITIVE
fd_snp_v1_noise_hkdf( fd_snp_conn_t * conn,
                      uchar const *   data,
                      ulong           data_sz,
                      uchar *         key0,
                      uchar *         key1 ) {
  uchar temp_key[32];
  uchar temp_data[33];

  fd_hmac_sha256( data, data_sz, fd_snp_conn_noise_chaining_key( conn ), 32, temp_key );

  temp_data[0] = 1;
  fd_hmac_sha256( temp_data, 1, temp_key, 32, key0 );

  memcpy( temp_data, key0, 32 );
  temp_data[32] = 2;
  fd_hmac_sha256( temp_data, 33, temp_key, 32, key1 );

  /* clean up sensitive variables */
  fd_memset_explicit( temp_key, 0, 32 );
  fd_memset_explicit( temp_data, 0, 33 );
}

static inline void
fd_snp_v1_noise_mix_key( fd_snp_conn_t * conn,
                         uchar const *   data,
                         ulong           data_sz ) {
  fd_snp_v1_noise_hkdf( conn, data, data_sz,
    fd_snp_conn_noise_chaining_key( conn ),
    fd_snp_conn_noise_cipher_key( conn )
  );
}

void FD_FN_SENSITIVE
fd_snp_v1_noise_enc_and_hash( fd_snp_conn_t * conn,
                              uchar           nonce,
                              uchar const *   data,
                              ulong           data_sz,
                              uchar *         out ) {
  fd_aes_gcm_t aes[1];
  uchar iv[16] = { 0 };
  uchar * hash = fd_snp_conn_noise_hash( conn );

  iv[0] = nonce;
  fd_aes_128_gcm_init( aes, fd_snp_conn_noise_cipher_key( conn ), iv );
  fd_aes_gcm_encrypt( aes, out, data, data_sz, hash, 32, out+data_sz );
  fd_snp_v1_noise_mix_key( conn, out, data_sz+16 );
}

int FD_FN_SENSITIVE
fd_snp_v1_noise_dec_and_hash( fd_snp_conn_t * conn,
                              uchar           nonce,
                              uchar const *   data,
                              ulong           data_sz,
                              uchar *         out ) {
  fd_aes_gcm_t aes[1];
  uchar iv[16] = { 0 };
  uchar * hash = fd_snp_conn_noise_hash( conn );

  iv[0] = nonce;
  fd_aes_128_gcm_init( aes, fd_snp_conn_noise_cipher_key( conn ), iv );
  if( FD_LIKELY( fd_aes_gcm_decrypt( aes, data, out, data_sz-16, hash, 32, data+data_sz-16 )==1 ) ) {
    fd_snp_v1_noise_mix_key( conn, data, data_sz );
    return 0;
  }
  return -1;
}

int
fd_snp_v1_noise_sig_verify( fd_snp_conn_t * conn,
                            uchar           pubkey[32],
                            uchar           sig[64] ) {
  fd_sha512_t sha[1];
  uchar const * msg = fd_snp_conn_noise_hash( conn );
  if( FD_LIKELY( fd_ed25519_verify( msg, 32, sig, pubkey, sha )==FD_ED25519_SUCCESS ) ) {
    return 0;
  }
  return -1;
}

void
fd_snp_v1_noise_fini( fd_snp_conn_t * conn ) {
  /* For server, key0 is rx key, key1 is tx key. For client it's vice versa. */
  if( conn->is_server ) {
    fd_snp_v1_noise_hkdf( conn, NULL, 0, fd_snp_conn_rx_key( conn ), fd_snp_conn_tx_key( conn ) );
  } else {
    fd_snp_v1_noise_hkdf( conn, NULL, 0, fd_snp_conn_tx_key( conn ), fd_snp_conn_rx_key( conn ) );
  }
}

int
fd_snp_v1_client_init( fd_snp_config_t const * client FD_PARAM_UNUSED,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in FD_PARAM_UNUSED, /* no incoming data */
                       ulong                   pkt_in_sz FD_PARAM_UNUSED, /* no incoming data */
                       uchar *                 pkt_out,
                       uchar *                 extra FD_PARAM_UNUSED ) {
  fd_snp_v1_pkt_hs_client_t out[1] = { 0 };

  /* Validate */
  if( FD_UNLIKELY( conn->state != 0 ) ) {
    return -1;
  }

  /* Prepare data */
  uchar * private_key = fd_snp_conn_ephemeral_private_key( conn );
  uchar * public_key  = fd_snp_conn_ephemeral_public_key ( conn );
  if( FD_UNLIKELY( fd_snp_v1_crypto_key_share_generate( private_key, public_key )<0 ) ) {
    return -1;
  }

  /* Prepare packet */
  out->hs.version = fd_snp_hdr_version_type( FD_SNP_V1, FD_SNP_TYPE_HS_CLIENT_INIT );
  out->hs.src_session_id = conn->session_id;
  memcpy( out->e, conn->_sensitive_keys+32, 32 );

  /* Finalize packet and copy to output buffer */
  memset( pkt_out+FD_SNP_SIZEOF_CLIENT_INIT_PAYLOAD, 0, FD_SNP_SIZEOF_CLIENT_INIT );
  memcpy( pkt_out, out, FD_SNP_SIZEOF_CLIENT_INIT_PAYLOAD );

  /* Update conn state */
  conn->state = FD_SNP_TYPE_HS_CLIENT_INIT;

  return (int)FD_SNP_SIZEOF_CLIENT_INIT;
}

int
fd_snp_v1_server_init( fd_snp_config_t const * server,
                       fd_snp_conn_t *         conn FD_PARAM_UNUSED, /* stateless */
                       uchar const *           pkt_in,
                       ulong                   pkt_in_sz,
                       uchar *                 pkt_out,
                       uchar *                 extra FD_PARAM_UNUSED ) {
  fd_snp_v1_pkt_hs_server_t out[1] = { 0 };

  /* Validate */
  if( FD_UNLIKELY( pkt_in_sz != FD_SNP_SIZEOF_CLIENT_INIT ) ) {
    return -1;
  }

  /* Prepare data */
  ulong session_id = fd_ulong_load_8_fast( pkt_in+FD_SNP_PKT_SRC_SESSION_ID_OFF );

  /* Prepare packet */
  out->hs.version = fd_snp_hdr_version_type( FD_SNP_V1, FD_SNP_TYPE_HS_SERVER_INIT );
  out->hs.session_id = session_id;
  fd_snp_v1_crypto_enc_state_generate( server, conn, out->r );

  /* Finalize packet and copy to output buffer */
  memset( pkt_out+FD_SNP_SIZEOF_SERVER_INIT_PAYLOAD, 0, FD_SNP_SIZEOF_SERVER_INIT );
  memcpy( pkt_out, out, FD_SNP_SIZEOF_SERVER_INIT_PAYLOAD );

  /* NO conn state update: stateless */

  return (int)FD_SNP_SIZEOF_SERVER_INIT;
}

int
fd_snp_v1_client_cont( fd_snp_config_t const * client FD_PARAM_UNUSED,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       ulong                   pkt_in_sz,
                       uchar *                 pkt_out,
                       uchar *                 extra FD_PARAM_UNUSED ) {
  fd_snp_v1_pkt_hs_client_t out[1] = { 0 };

  /* Validate */
  if( FD_UNLIKELY( conn->state != FD_SNP_TYPE_HS_CLIENT_INIT
                && conn->state != FD_SNP_TYPE_HS_CLIENT_CONT ) ) {
    return -1;
  }

  if( FD_UNLIKELY( pkt_in_sz != FD_SNP_SIZEOF_SERVER_INIT ) ) {
    return -1;
  }

  /* Prepare packet */
  out->hs.version = fd_snp_hdr_version_type( FD_SNP_V1, FD_SNP_TYPE_HS_CLIENT_CONT );
  out->hs.src_session_id = conn->session_id;
  memcpy( out->e, fd_snp_conn_ephemeral_public_key( conn ), 32 );
  memcpy( out->r, pkt_in+FD_SNP_PKT_SERVER_CHALLENGE_OFF, 16 );

  /* Finalize packet and copy to output buffer */
  memset( pkt_out+FD_SNP_SIZEOF_CLIENT_CONT_PAYLOAD, 0, FD_SNP_SIZEOF_CLIENT_CONT );
  memcpy( pkt_out, out, FD_SNP_SIZEOF_CLIENT_CONT_PAYLOAD );

  /* Update conn state */
  conn->state = FD_SNP_TYPE_HS_CLIENT_CONT;

  return (int)FD_SNP_SIZEOF_CLIENT_CONT;
}

int
fd_snp_v1_server_fini_precheck( fd_snp_config_t const * server,
                                fd_snp_conn_t *         conn,
                                uchar const *           pkt_in,
                                ulong                   pkt_in_sz,
                                uchar *                 pkt_out FD_PARAM_UNUSED,
                                uchar *                 extra FD_PARAM_UNUSED ) {
  /* Validate */
  if( FD_UNLIKELY( pkt_in_sz != FD_SNP_SIZEOF_CLIENT_CONT ) ) {
    return -1;
  }

  if( FD_UNLIKELY( fd_snp_v1_crypto_enc_state_validate( server, conn, pkt_in+FD_SNP_PKT_CLIENT_CHALLENGE_OFF )<0 ) ) {
    return -1;
  }

  return 0;
}

int
fd_snp_v1_server_fini( fd_snp_config_t const * server,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       ulong                   pkt_in_sz,
                       uchar *                 pkt_out,
                       uchar *                 extra ) {
  fd_snp_v1_pkt_hs_server_t out[1] = { 0 };

  /* Validate */
  if( FD_UNLIKELY( pkt_in_sz != FD_SNP_SIZEOF_CLIENT_CONT ) ) {
    return -1;
  }

  /* Expect server state to be just initialized
     (because it wasn't modified by server_init) */
  if( FD_UNLIKELY( conn->state != 0 ) ) {
    return -1;
  }

  if( FD_UNLIKELY( fd_snp_v1_crypto_enc_state_validate( server, conn, pkt_in+FD_SNP_PKT_CLIENT_CHALLENGE_OFF )<0 ) ) {
    return -1;
  }

  /* Prepare data */
  ulong session_id = fd_ulong_load_8_fast( pkt_in+FD_SNP_PKT_SRC_SESSION_ID_OFF );
  uchar const * client_ephemeral = pkt_in + FD_SNP_PKT_CLIENT_EPHEMERAL_OFF;
  uchar const * challenge = pkt_in + FD_SNP_PKT_CLIENT_CHALLENGE_OFF;

  uchar * server_ephemeral_private = fd_snp_conn_ephemeral_private_key( conn );
  uchar   server_ephemeral[ 32 ];
  if( FD_UNLIKELY( fd_snp_v1_crypto_key_share_generate( server_ephemeral_private, server_ephemeral )<0 ) ) {
    return -1;
  }

  uchar * shared_secret_ee = fd_snp_conn_noise_shared_secret( conn );
  fd_x25519_exchange( shared_secret_ee, server_ephemeral_private, client_ephemeral );

  fd_snp_v1_noise_init( conn );
  fd_snp_v1_noise_mix_hash( conn, (void *)&session_id, 8 ); /* client session_id */
  fd_snp_v1_noise_mix_hash( conn, client_ephemeral, 32 );
  fd_snp_v1_noise_mix_hash( conn, challenge, 16 );
  fd_snp_v1_noise_mix_hash( conn, (void *)&conn->session_id, 8 ); /* server session_id */
  fd_snp_v1_noise_mix_hash( conn, server_ephemeral, 32 );
  fd_snp_v1_noise_mix_key( conn, shared_secret_ee, 32 );
  fd_snp_v1_noise_enc_and_hash( conn, 0, conn->_pubkey, 32, out->enc_s1 );

  /* Prepare packet */
  out->hs.version = fd_snp_hdr_version_type( FD_SNP_V1, FD_SNP_TYPE_HS_SERVER_FINI );
  out->hs.session_id = session_id;
  out->hs.src_session_id = conn->session_id;
  memcpy( out->r, challenge, 16 );
  memcpy( out->e, server_ephemeral, 32 );

  /* Finalize packet and copy to output buffer */
  memset( pkt_out+FD_SNP_SIZEOF_SERVER_FINI_PAYLOAD, 0, FD_SNP_SIZEOF_SERVER_FINI );
  memcpy( pkt_out, out, FD_SNP_SIZEOF_SERVER_FINI_PAYLOAD );

  /* Update conn state */
  conn->peer_session_id = session_id;
  conn->state = FD_SNP_TYPE_HS_SERVER_FINI_SIG;

  /* Prepare payload to sign */
  memcpy( extra, fd_snp_conn_noise_hash( conn ), 32 );

  return (int)FD_SNP_SIZEOF_SERVER_FINI;
}

int
fd_snp_v1_client_fini( fd_snp_config_t const * client FD_PARAM_UNUSED,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       ulong                   pkt_in_sz,
                       uchar *                 pkt_out,
                       uchar *                 extra ) {
  fd_snp_v1_pkt_hs_client_t out[1] = { 0 };

  /* Validate */
  if( FD_UNLIKELY( conn->state != FD_SNP_TYPE_HS_CLIENT_CONT ) ) {
    return -1;
  }

  if( FD_UNLIKELY( pkt_in_sz != FD_SNP_SIZEOF_SERVER_FINI ) ) {
    return -1;
  }

  /* Prepare data */
  ulong session_id = fd_ulong_load_8_fast( pkt_in+FD_SNP_PKT_SRC_SESSION_ID_OFF );
  uchar const * challenge = pkt_in + FD_SNP_PKT_SERVER_CHALLENGE_OFF;
  uchar const * server_ephemeral = pkt_in + FD_SNP_PKT_SERVER_EPHEMERAL_OFF;
  uchar const * enc_server_pubkey = pkt_in + FD_SNP_PKT_SERVER_ENC_PUBKEY_OFF;
  uchar const * enc_server_sig = pkt_in + FD_SNP_PKT_SERVER_ENC_SIG_OFF;

  uchar * client_ephemeral_private = fd_snp_conn_ephemeral_private_key( conn );
  uchar   client_ephemeral[ 32 ];
  memcpy( client_ephemeral, fd_snp_conn_ephemeral_public_key( conn ), 32 );

  uchar * shared_secret_ee = fd_snp_conn_noise_shared_secret( conn );
  fd_x25519_exchange( shared_secret_ee, client_ephemeral_private, server_ephemeral );

  fd_snp_v1_noise_init( conn );
  fd_snp_v1_noise_mix_hash( conn, (void *)&conn->session_id, 8 ); /* client session_id */
  fd_snp_v1_noise_mix_hash( conn, client_ephemeral, 32 );
  fd_snp_v1_noise_mix_hash( conn, challenge, 16 );
  fd_snp_v1_noise_mix_hash( conn, (void *)&session_id, 8 ); /* server session_id */
  fd_snp_v1_noise_mix_hash( conn, server_ephemeral, 32 );
  fd_snp_v1_noise_mix_key( conn, shared_secret_ee, 32 );

  uchar server_pubkey[ 32 ];
  uchar server_sig   [ 64 ];
  if( FD_UNLIKELY( fd_snp_v1_noise_dec_and_hash( conn, 0, enc_server_pubkey, 32+16, server_pubkey )<0 ) ) {
    return -1;
  }
  if( FD_UNLIKELY( fd_snp_v1_noise_dec_and_hash( conn, 1, enc_server_sig, 64+16, server_sig )<0 ) ) {
    return -1;
  }
  if( FD_UNLIKELY( fd_snp_v1_noise_sig_verify( conn, server_pubkey, server_sig )<0 ) ) {
    return -1;
  }

  fd_snp_v1_noise_enc_and_hash( conn, 2, conn->_pubkey, 32, out->enc_s1 );

  /* Prepare packet */
  out->hs.version = fd_snp_hdr_version_type( FD_SNP_V1, FD_SNP_TYPE_HS_CLIENT_FINI );
  out->hs.session_id = session_id;
  out->hs.src_session_id = conn->session_id;

  /* Finalize packet and copy to output buffer */
  memset( pkt_out+FD_SNP_SIZEOF_CLIENT_FINI_PAYLOAD, 0, FD_SNP_SIZEOF_CLIENT_FINI );
  memcpy( pkt_out, out, FD_SNP_SIZEOF_CLIENT_FINI_PAYLOAD );

  /* Prepare payload to sign */
  memcpy( extra, fd_snp_conn_noise_hash( conn ), 32 );

  /* Update conn state */
  conn->peer_session_id = session_id;
  conn->state = FD_SNP_TYPE_HS_CLIENT_FINI_SIG;

  /* We need to temp store server_pubkey, so that we finalize it after
     the async signature. We store it at the end of the packet. */
  memcpy( pkt_out+FD_SNP_SIZEOF_CLIENT_FINI, server_pubkey, 32 );

  return (int)FD_SNP_SIZEOF_CLIENT_FINI;
}

int
fd_snp_v1_server_acpt( fd_snp_config_t const * server FD_PARAM_UNUSED,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       ulong                   pkt_in_sz,
                       uchar *                 pkt_out FD_PARAM_UNUSED,
                       uchar *                 extra FD_PARAM_UNUSED ) {
  /* Validate */
  if( FD_UNLIKELY( conn->state != FD_SNP_TYPE_HS_SERVER_FINI ) ) {
    return -1;
  }

  if( FD_UNLIKELY( pkt_in_sz != FD_SNP_SIZEOF_CLIENT_FINI ) ) {
    return -1;
  }

  /* Prepare data */
  uchar const * enc_client_pubkey = pkt_in + FD_SNP_PKT_CLIENT_ENC_PUBKEY_OFF;
  uchar const * enc_client_sig = pkt_in + FD_SNP_PKT_CLIENT_ENC_SIG_OFF;
  uchar client_pubkey[ 32 ];
  uchar client_sig   [ 64 ];
  if( FD_UNLIKELY( fd_snp_v1_noise_dec_and_hash( conn, 2, enc_client_pubkey, 32+16, client_pubkey )<0 ) ) {
    return -1;
  }
  if( FD_UNLIKELY( fd_snp_v1_noise_dec_and_hash( conn, 3, enc_client_sig, 64+16, client_sig )<0 ) ) {
    return -1;
  }
  if( FD_UNLIKELY( fd_snp_v1_noise_sig_verify( conn, client_pubkey, client_sig )<0 ) ) {
    return -1;
  }

  fd_snp_v1_noise_fini( conn );
  memcpy( conn->_peer_pubkey, client_pubkey, 32 );
  conn->state = FD_SNP_TYPE_HS_DONE;
  return 0;
}

int
fd_snp_v1_server_fini_add_signature( fd_snp_conn_t * conn,
                                     uchar           pkt_out[ FD_SNP_MTU-42 ],
                                     uchar const     sig[ 64 ] ) {
  fd_snp_v1_noise_enc_and_hash( conn, 1, sig, 64, pkt_out+FD_SNP_PKT_SERVER_ENC_SIG_OFF );
  conn->state = FD_SNP_TYPE_HS_SERVER_FINI;
  return 0;
}

int
fd_snp_v1_client_fini_add_signature( fd_snp_conn_t * conn,
                                     uchar           pkt_out[ FD_SNP_MTU-42 ],
                                     uchar const     sig[ 64 ] ) {
  fd_snp_v1_noise_enc_and_hash( conn, 3, sig, 64, pkt_out+FD_SNP_PKT_CLIENT_ENC_SIG_OFF );
  fd_snp_v1_noise_fini( conn );

  /* Set _peer_pubkey as server_pubkey, that was temp stored at the end of the packet */
  memcpy( conn->_peer_pubkey, pkt_out+FD_SNP_SIZEOF_CLIENT_FINI, 32 );

  conn->state = FD_SNP_TYPE_HS_DONE;
  return 0;
}

void
fd_snp_v1_finalize_packet( fd_snp_conn_t * conn,
                           uchar *         packet,
                           ulong           packet_sz ) {
  /* SNP header */
  snp_hdr_t * udp_payload = (snp_hdr_t *)packet;
  udp_payload->version_type = fd_snp_hdr_version_type( FD_SNP_V1, FD_SNP_TYPE_PAYLOAD );
  udp_payload->session_id = conn->peer_session_id;

  /* Data is already set by fd_snp_app_send */

  /* Compute MAC */
  packet[packet_sz-19] = FD_SNP_FRAME_AUTH;
  packet[packet_sz-18] = 16;
  packet[packet_sz-17] = 0;
  uchar * hmac_out = packet+packet_sz-16;
  /* this assumes that packet has extra 16 bytes (hmac_out is 32 bytes, truncated to 16) */
  fd_hmac_sha256( packet, packet_sz-16, fd_snp_conn_tx_key( conn ), 32, hmac_out );
}

int
fd_snp_v1_validate_packet( fd_snp_conn_t * conn,
                           uchar *         packet,
                           ulong           packet_sz ) {
  uchar hmac_out[ 32 ];
  if( FD_LIKELY(
       ( packet[packet_sz-19] == FD_SNP_FRAME_AUTH )
    && ( packet[packet_sz-18] == 16 )
    && ( packet[packet_sz-17] == 0 )
    && fd_hmac_sha256( packet, packet_sz-16, fd_snp_conn_rx_key( conn ), 32, hmac_out )==hmac_out
    && fd_memeq( hmac_out, packet+packet_sz-16, 16 )
  ) ) {
    return 0;
  }
  return -1;
}
