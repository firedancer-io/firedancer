
#include "fd_snp_base.h"
#include "fd_snp_s0_server.h"
#include "fd_snp_s0_client.h"
#include "fd_snp_proto.h"
#include "fd_snp_private.h"
#include "fd_snp.h"
#include "../../util/rng/fd_rng.h"
#include "../../ballet/aes/fd_aes_gcm.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/ed25519/fd_x25519.h"

#include <string.h>

#if 0
static char const sign_prefix_server[32] =
  "SNP v0 s0 server transcript     ";

static char const sign_prefix_client[32] =
  "SNP v0 s0 client transcript     ";
#endif

static inline void
fd_snp_rng( uchar * buf, ulong buf_sz ) {
  FD_TEST( fd_rng_secure( buf, buf_sz )!=NULL );
}

long
fd_snp_s0_client_initial( fd_snp_s0_client_params_t const * client,
                          fd_snp_s0_client_hs_t *           hs,
                          uchar                             pkt_out[ SNP_MTU ] ) {

  /* Expect client state to be just initialized */
  if( FD_UNLIKELY( hs->state != 0 ) ) {
    return -1;
  }

  snp_s0_hs_pkt_t * out = (snp_s0_hs_pkt_t *)pkt_out;
  fd_memset( out, 0, SNP_MTU_MIN );
  out->hs.base.version_type = snp_hdr_version_type( SNP_V0, SNP_TYPE_HS_CLIENT_INITIAL );

  /* client identity - useless? */
  fd_memcpy( out->identity, client->identity, SNP_ED25519_KEY_SZ );

  /* client token */
  fd_snp_rng( hs->client_token, SNP_TOKEN_SZ );
  fd_memcpy( out->client_token, hs->client_token, SNP_TOKEN_SZ );

  /* set next expected state */
  hs->state = SNP_TYPE_HS_SERVER_CONTINUE;

  return SNP_MTU_MIN;
}

void
fd_snp_s0_crypto_key_share_generate( uchar private_key[32], uchar public_key[32] ) {
  fd_snp_rng( private_key, 32 );
  fd_x25519_public( public_key, private_key );
}

void
fd_snp_s0_crypto_enc_state_generate( uchar private_key_enc[48], uchar public_key[32], uchar const key[16] ) {
  uchar private_key[32];
  fd_snp_rng( private_key, 32 );
  fd_x25519_public( public_key, private_key );

  fd_aes_gcm_t aes_gcm[1];
  fd_aes_128_gcm_init( aes_gcm, key, public_key );
  fd_aes_gcm_encrypt( aes_gcm, private_key_enc, private_key, 32, NULL, 0, private_key_enc+32 );
}

int
fd_snp_s0_crypto_enc_state_verify( uchar private_key[32], uchar const private_key_enc[48], uchar const public_key[32], uchar const key[16] ) {
  uchar public_key_check[32];

  fd_aes_gcm_t aes_gcm[1];
  fd_aes_128_gcm_init( aes_gcm, key, public_key );
  if( FD_UNLIKELY( 1!=fd_aes_gcm_decrypt( aes_gcm, private_key_enc, private_key, 32, NULL, 0, private_key_enc+32 ) ) ) {
    return -1;
  };

  fd_x25519_public( public_key_check, private_key );
  if( FD_UNLIKELY( 0!=memcmp( public_key, public_key_check, 32 ) ) ) {
    return -1;
  }

  return 0;
}

long
fd_snp_s0_server_handle_initial( fd_snp_s0_server_params_t const * server,
                                 snp_net_ctx_t const *             ctx,
                                 snp_s0_hs_pkt_t const *           pkt,
                                 uchar                             pkt_out[ SNP_MTU ],
                                 fd_snp_s0_server_hs_t * const     hs /* server_initial is stateless, we do NOT modify hs */
) {
  (void)ctx;

  /* Expect server state to be just initialized */
  if( FD_UNLIKELY( hs->state != 0 ) ) {
    return 0UL;
  }

  if( FD_UNLIKELY( snp_hdr_type( &pkt->hs.base ) != SNP_TYPE_HS_CLIENT_INITIAL ) ) {
    return -1;
  }

  /* Create key_share */
  uchar key_share[32];
  uchar key_share_private_enc[32+16];
  fd_snp_s0_crypto_enc_state_generate( key_share_private_enc, key_share, server->state_enc_key );

  /* Send back the cookie and our server identity */

  snp_s0_hs_pkt_server_continue_t * out = (snp_s0_hs_pkt_server_continue_t *)pkt_out;
  fd_memset( out, 0, SNP_MTU_MIN );

  out->hs.base.version_type = snp_hdr_version_type( SNP_V0, SNP_TYPE_HS_SERVER_CONTINUE );
  fd_memcpy( out->client_token, pkt->client_token, SNP_TOKEN_SZ  );
  fd_memcpy( out->key_share, key_share, 32 );
  fd_memcpy( out->key_share_enc, key_share_private_enc, 48 );

  /* Return info to user */

  return SNP_MTU_MIN;
}

long
fd_snp_s0_client_handle_continue( fd_snp_s0_client_params_t const * client,
                                  snp_s0_hs_pkt_t const *           pkt_in,
                                  uchar                             pkt_out[ SNP_MTU ],
                                  uchar                             to_sign[32],
                                  fd_snp_s0_client_hs_t *           hs ) {
  (void)client;

  /* Expect client state to be awaiting SNP_TYPE_HS_SERVER_CONTINUE */
  if( FD_UNLIKELY( hs->state != SNP_TYPE_HS_SERVER_CONTINUE ) ) {
    return -1;
  }

  if( FD_UNLIKELY( snp_hdr_type( &pkt_in->hs.base ) != SNP_TYPE_HS_SERVER_CONTINUE ) ) {
    return -1;
  }

  /* Check client token */
  snp_s0_hs_pkt_server_continue_t * in = (snp_s0_hs_pkt_server_continue_t *)pkt_in;
  if( FD_UNLIKELY( 0!=memcmp( in->client_token, hs->client_token, SNP_TOKEN_SZ ) ) ) {
    return -1;
  }

  /* Generate key_share */
  uchar key_share[32];
  uchar key_share_private[32];
  fd_snp_s0_crypto_key_share_generate( key_share_private, key_share );

  /* Compute shared_secret */
  uchar shared_secret_ee[32];
  fd_x25519_exchange( shared_secret_ee, key_share_private, in->key_share );
  
  /* FIXME: encrypt identity s */

  /* FIXME: prepare signature */

  /* assemble response */
  snp_s0_hs_pkt_client_accept_t * out = (snp_s0_hs_pkt_client_accept_t *)pkt_out;
  fd_memset( out, 0, SNP_MTU_MIN );

  out->hs.base.version_type = snp_hdr_version_type( SNP_V0, SNP_TYPE_HS_CLIENT_ACCEPT );
  fd_memcpy( out->server_key_share, in->key_share, 32 );
  fd_memcpy( out->server_key_share_enc, in->key_share_enc, 48 );
  fd_memcpy( out->key_share, key_share, 32 );
  fd_memcpy( out->identity, client->identity, 32 ); //FIXME

  //FIXME
  fd_memcpy( to_sign, shared_secret_ee, 32 );

  hs->state = SNP_TYPE_HS_SERVER_ACCEPT;
  return SNP_MTU_MIN;
}

void
fd_snp_s0_client_handle_continue_add_signature( uchar pkt_out[ SNP_MTU ],
                                                uchar sig[ 64 ] ) {
  snp_s0_hs_pkt_client_accept_t * out = (snp_s0_hs_pkt_client_accept_t *)pkt_out;
  fd_memcpy( out->signature, sig, 64 );
}

long
fd_snp_s0_server_handle_accept( fd_snp_s0_server_params_t const * server,
                                snp_net_ctx_t const *                ctx,
                                snp_s0_hs_pkt_t const *              pkt_in,
                                uchar                                pkt_out[ SNP_MTU ],
                                uchar                                to_sign[32],
                                fd_snp_s0_server_hs_t *              hs,
                                fd_snp_sesh_t *                      sesh ) {

  /* Expect server state to be just initialized
     (because it wasn't modified by server_initial) */
  if( FD_UNLIKELY( hs->state != 0 ) ) {
    return -1;
  }

  if( FD_UNLIKELY( snp_hdr_type( &pkt_in->hs.base ) != SNP_TYPE_HS_CLIENT_ACCEPT ) ) {
    return -1;
  }

  snp_s0_hs_pkt_client_accept_t * in = (snp_s0_hs_pkt_client_accept_t *)pkt_in;

  /* Decrypt and verify state */
  uchar key_share_private[32];
  if( FD_UNLIKELY( fd_snp_s0_crypto_enc_state_verify( key_share_private, in->server_key_share_enc, in->server_key_share, server->state_enc_key )<0 ) ) {
    return -1;
  }

  /* Compute shared_secret */
  uchar shared_secret_ee[32];
  fd_x25519_exchange( shared_secret_ee, key_share_private, in->key_share );

  /* FIXME: decrypt client identity s and signature sig */
  uchar client_identity[32];
  uchar signature[64];
  fd_memcpy( client_identity, in->identity, 32 );
  fd_memcpy( signature, in->signature, 64 );

  /* FIXME: verify signature */
  // if( FD_UNLIKELY( fd_ed25519_verify( ... )!=FD_ED25519_SUCCESS ) ) {
  //   return -1;
  // }

  /* FIXME: encrypt identity s */

  /* FIXME: prepare signature */

  /* Derive session ID */

  uchar session_id[ SNP_SESSION_ID_SZ ];
  snp_gen_session_id( session_id );

  /* assemble response */

  snp_s0_hs_pkt_server_accept_t * out = (snp_s0_hs_pkt_server_accept_t *)pkt_out;
  fd_memset( out, 0, SNP_MTU_MIN );

  out->hs.base.version_type = snp_hdr_version_type( SNP_V0, SNP_TYPE_HS_SERVER_ACCEPT );
  fd_memcpy( out->hs.base.session_id, session_id, SNP_SESSION_ID_SZ );
  fd_memcpy( out->identity, server->identity, 32 ); //FIXME

  //FIXME
  fd_memcpy( to_sign, shared_secret_ee, 32 );

  /* Return info to caller */

  fd_memcpy( hs->session_id, session_id, SNP_SESSION_ID_SZ );

  sesh->session_id = FD_LOAD( ulong, hs->session_id );
  sesh->socket_addr = ctx->b;
  sesh->server = 1;

  hs->state = SNP_TYPE_HS_DONE;
  return SNP_MTU_MIN;
}

void
fd_snp_s0_server_handle_accept_add_signature( uchar pkt_out[ SNP_MTU ],
                                              uchar sig[ 64 ] ) {
  snp_s0_hs_pkt_server_accept_t * out = (snp_s0_hs_pkt_server_accept_t *)pkt_out;
  fd_memcpy( out->signature, sig, 64 );
}

void
fd_snp_s0_server_rotate_secrets( fd_snp_s0_server_params_t * server ) {
  static fd_rng_t _rng[1];
  static int _done_init = 0;
  if( !_done_init ) {
    fd_rng_join( fd_rng_new( _rng, 3, 4 ) ); /* TODO - figure out correct args here */
    _done_init = 1;
  }

  *(ulong*)(server->cookie_secret)   = fd_rng_ulong( _rng );
  *(ulong*)(server->cookie_secret+8) = fd_rng_ulong( _rng );
}

fd_snp_s0_client_hs_t *
fd_snp_s0_client_hs_new( void * mem ) {
  fd_snp_s0_client_hs_t * hs = (fd_snp_s0_client_hs_t *)mem;
  fd_memset( hs, 0, sizeof(fd_snp_s0_client_hs_t) );
  return hs;
}

long
fd_snp_s0_client_handle_accept( fd_snp_t*                         snp,
                                fd_snp_s0_client_params_t const * client,
                                snp_s0_hs_pkt_t const *           pkt_in,
                                fd_snp_s0_client_hs_t *           hs ) {
  (void)client;

  /* Expect client state to be awaiting SNP_TYPE_HS_SERVER_ACCEPT */
  if( FD_UNLIKELY( hs->state != SNP_TYPE_HS_SERVER_ACCEPT ) ) {
    return -1;
  }

  if( FD_UNLIKELY( snp_hdr_type( &pkt_in->hs.base ) != SNP_TYPE_HS_SERVER_ACCEPT ) ) {
    return -1;
  }

  snp_s0_hs_pkt_client_accept_t * in = (snp_s0_hs_pkt_client_accept_t *)pkt_in;

  /* FIXME: decrypt server identity s and signature sig */
  uchar server_identity[32];
  uchar signature[64];
  fd_memcpy( server_identity, in->identity, 32 );
  fd_memcpy( signature, in->signature, 64 );


  fd_memcpy( hs->session_id, pkt_in->hs.base.session_id, SNP_SESSION_ID_SZ );
  /* create a new session object */
  fd_snp_state_private_t * priv = (fd_snp_state_private_t *)(snp+1);
  fd_snp_sesh_t * sesh = priv->sessions + priv->session_sz++;

  sesh->session_id = FD_LOAD( ulong, hs->session_id);
  sesh->socket_addr = hs->socket_addr;
  sesh->server = 0;

  /* FIXME: verify signature */
  // if( FD_UNLIKELY( fd_ed25519_verify( ... )!=FD_ED25519_SUCCESS ) ) {
  //   return -1;
  // }

  hs->state = SNP_TYPE_HS_DONE;
  return 0UL;
}

// long
// fd_snp_s0_client_handshake( fd_snp_s0_client_params_t const * client,
//                          fd_snp_s0_client_hs_t *           hs,
//                          uchar const *                pkt_in,
//                          ulong                       pkt_in_sz,
//                          uchar                        pkt_out[ static SNP_MTU ] ) {

//   if( FD_UNLIKELY( pkt_in_sz < sizeof(snp_s0_hs_pkt_t) ) )
//     return 0UL;

//   snp_s0_hs_pkt_t const * pkt = (snp_s0_hs_pkt_t const *)pkt_in;

//   if( FD_UNLIKELY(
//       /* Verify protocol version */
//       ( snp_hdr_version( &pkt->hs.base ) != SNP_V0       ) |
//       /* Verify client token */
//       ( 0!=memcmp( pkt->client_token, hs->client_token, SNP_TOKEN_SZ ) ) ) )
//     return 0UL;

//   switch( hs->state ) {
//   case SNP_TYPE_HS_CLIENT_INITIAL:
//     return snp_s0_client_handle_continue( client, pkt, pkt_out, hs );
//   case SNP_TYPE_HS_SERVER_CONTINUE:
//     return snp_s0_client_handle_accept  ( pkt, hs );
//   default:
//     return 0UL;
//   }

// }

long
fd_snp_s0_encode_appdata( fd_snp_sesh_t * sesh,
                     const uchar *      payload, /* TODO: create a 0cp mode */
                     ushort             payload_sz,
                     uchar              pkt_out[ SNP_MTU ] ) {
  snp_hdr_t* ptr = (snp_hdr_t*)pkt_out;
  ptr->version_type = snp_hdr_version_type( SNP_V0, SNP_TYPE_APP_SIMPLE );
  fd_memcpy( ptr->session_id, &(sesh->session_id), SNP_SESSION_ID_SZ );

  uchar* payload_ptr = (uchar*)(ptr+1);
  fd_memcpy( payload_ptr, payload, payload_sz );
  payload_ptr += payload_sz;

  /* append some fake MAC */
  fd_memset( payload_ptr, 0xff, SNP_MAC_SZ);
  payload_ptr += SNP_MAC_SZ;

  return payload_ptr-pkt_out;
}

long
fd_snp_s0_decode_appdata( fd_snp_sesh_t* sesh,
                          const uchar* encoded_buf,
                          ushort encoded_sz,
                          uchar pkt_out[SNP_BASIC_PAYLOAD_MTU]) {
  (void)sesh;
  /* Check minimum packet size (version + session_id + MAC) */
  const ushort min_size = 1 + SNP_SESSION_ID_SZ + SNP_MAC_SZ;
  if( encoded_sz < min_size ) {
      return -1;
  }

  snp_hdr_t* hdr = (snp_hdr_t*)encoded_buf;

  if( snp_hdr_version( hdr ) != SNP_V0 ) {
    return -2;
  }

  if( snp_hdr_type( hdr ) != SNP_TYPE_APP_SIMPLE ) {
    return -3;
  }

  /* Verify MAC (currently fake in encode, so just check for 0xff) */
  const uchar* mac_ptr = encoded_buf + encoded_sz - SNP_MAC_SZ;
  for( ulong i=0; i<SNP_MAC_SZ; i++ ) {
      if( mac_ptr[i]!= 0xff ) {
          return -5;
      }
  }

  /* Calculate payload size (everything after headers) */
  hdr++;
  long read_sz = (long)mac_ptr - (long)hdr;
  if( read_sz > 0)
    fd_memcpy( pkt_out, hdr, (size_t)read_sz );

  return read_sz;
}

