#define _POSIX_C_SOURCE 199309L

#include "fd_snp_private.h"
#include "fd_snp_s0_server.h"
#include "fd_snp_s0_client.h"
#include "fd_snp.h"
#include "../../ballet/sha512/fd_sha512.h"
#include "../../ballet/ed25519/fd_ed25519.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

void external_generate_keypair( uchar private_key[32], uchar public_key[32] ) {
  fd_sha512_t sha512[1];
  FD_TEST( fd_sha512_join( fd_sha512_new( sha512 ) ) );
  FD_TEST( fd_rng_secure( private_key, 32 )!=NULL );
  fd_ed25519_public_from_private( public_key, private_key, sha512 );
}

void external_sign( uchar signature[64], uchar to_sign[32], uchar private_key[32], uchar public_key[32] ) {
  fd_sha512_t sha512[1];
  fd_ed25519_sign( signature, to_sign, 32, public_key, private_key, sha512 );
}

static void
test_snp_app_send_recv( void ) {
  /* Init server, server_hs */
  fd_snp_s0_server_params_t server[1] = {0};
  fd_snp_s0_server_hs_t server_hs[1] = {0};

  uchar server_private_key[32];
  external_generate_keypair( server_private_key, server->identity );
  FD_TEST( fd_rng_secure( server->state_enc_key, 16 )!=NULL );

  /* Init client, client_hs */
  fd_snp_s0_client_params_t client[1] = {0};
  fd_snp_s0_client_hs_t client_hs[1]; fd_snp_s0_client_hs_new( client_hs );

  uchar client_private_key[32];
  external_generate_keypair( client_private_key, client->identity );

  /* Init ctx, sessions */

  snp_net_ctx_t ctx[1] = { 0 };
  fd_snp_sesh_t server_sesh[1] = { 0 };

  uchar client_pkt[ SNP_MTU ];
  uchar server_pkt[ SNP_MTU ];
  uchar to_sign[ 32 ];
  uchar signature[ 64 ];

  long client_pkt_sz;
  long server_pkt_sz;

  assert( client_hs->state == 0 );
  assert( server_hs->state == 0 );

  client_pkt_sz = fd_snp_s0_client_initial( client, client_hs, client_pkt );
  assert( client_pkt_sz>0L );
  assert( client_hs->state == SNP_TYPE_HS_SERVER_CONTINUE );

  server_pkt_sz = fd_snp_s0_server_handle_initial( server, ctx, (snp_s0_hs_pkt_t *)client_pkt, server_pkt, server_hs );
  assert( server_pkt_sz>0L );
  assert( server_hs->state == 0 );

  client_pkt_sz = fd_snp_s0_client_handle_continue( client, (snp_s0_hs_pkt_t *)server_pkt, client_pkt, to_sign, client_hs );
  external_sign( signature, to_sign, server_private_key, server->identity );
  fd_snp_s0_client_handle_continue_add_signature( client_pkt, signature );
  assert( client_pkt_sz>0L );
  assert( client_hs->state == SNP_TYPE_HS_SERVER_ACCEPT );

  server_pkt_sz = fd_snp_s0_server_handle_accept( server, ctx, (snp_s0_hs_pkt_t *)client_pkt, server_pkt, to_sign, server_hs, server_sesh );
  external_sign( signature, to_sign, server_private_key, server->identity );
  fd_snp_s0_server_handle_accept_add_signature( server_pkt, signature );
  assert( server_pkt_sz>0L );
  assert( server_hs->state == SNP_TYPE_HS_DONE );

  uchar scratch[sizeof(fd_snp_t)+sizeof(fd_snp_state_private_t)];
  fd_snp_t * snp = (fd_snp_t *)scratch;
  fd_snp_state_private_t * priv = (fd_snp_state_private_t *)(snp+1);
  assert( (uchar*)(snp+1) == (uchar*)priv );

  client_pkt_sz = fd_snp_s0_client_handle_accept( snp, client, (snp_s0_hs_pkt_t *)server_pkt, client_hs );
  assert( client_pkt_sz==0L );
  assert( client_hs->state == SNP_TYPE_HS_DONE );
  assert( priv->sessions[0].session_id == FD_LOAD( ulong, client_hs->session_id ) );

  puts( "APP handshake: OK" );
}

int
main( int     argc,
      char ** argv ) {
  (void)argc;
  (void)argv;

  test_snp_app_send_recv();

  return 0;
}
