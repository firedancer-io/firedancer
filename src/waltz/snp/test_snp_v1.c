#define _POSIX_C_SOURCE 199309L

#include "fd_snp_v1.h"
#include "../../ballet/sha512/fd_sha512.h"
#include "../../ballet/ed25519/fd_ed25519.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

static inline long
wallclock( void ) {
  struct timespec ts[1];
  clock_gettime( CLOCK_REALTIME, ts );
  return ((long)1e9)*((long)ts->tv_sec) + (long)ts->tv_nsec;
}

static inline void
bench_output( ulong iter, long dt ) {
  double ops  = ((double)iter) / ((double)dt) * 1e3;
  double ns   = ((double)dt) / ((double)iter);
  double gbps = ((float)(8UL*(70UL+1200UL)*iter)) / ((float)dt);
  fprintf( stderr, "\t%13.6f Gbps Ethernet equiv throughput / core\n", gbps );
  fprintf( stderr, "\t%13.6f Mpps / core\n", ops );
  fprintf( stderr, "\t%13.6f ns / op\n", ns );
}

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
test_v1_handshake( void ) {
  fd_snp_config_t client[1] = { 0 };
  fd_snp_conn_t   client_conn[1] = { 0 };
  uchar           client_private_key[ 32 ];

  fd_snp_config_t server[1] = { 0 };
  fd_snp_conn_t   server_conn[1] = { 0 };
  uchar           server_private_key[ 32 ];

  /* client init */
  external_generate_keypair( client_private_key, client->identity );
  client_conn->_pubkey = client->identity;

  /* server init */
  uchar aes_key[16];
  FD_TEST( fd_snp_rng( aes_key, 16 )==16 );
  fd_aes_set_encrypt_key( aes_key, 128, server->_state_enc_key );
  fd_aes_set_decrypt_key( aes_key, 128, server->_state_dec_key );

  external_generate_keypair( server_private_key, server->identity );
  server_conn->_pubkey = server->identity;

  int   res;
  int   pkt_sz;
  uchar _pkt[ 1500 ]; uchar * pkt = _pkt;
  uchar to_sign[ 32 ];
  uchar sig[ 64 ];

  pkt_sz = fd_snp_v1_client_init( client, client_conn, NULL, 0, pkt, NULL );
  FD_TEST_CUSTOM( pkt_sz>0, "fd_snp_v1_client_init failed" );
  pkt_sz = fd_snp_v1_server_init( server, server_conn, pkt, (ulong)pkt_sz, pkt, NULL );
  FD_TEST_CUSTOM( pkt_sz>0, "fd_snp_v1_server_init failed" );
  pkt_sz = fd_snp_v1_client_cont( client, client_conn, pkt, (ulong)pkt_sz, pkt, NULL );
  FD_TEST_CUSTOM( pkt_sz>0, "fd_snp_v1_client_cont failed" );
  pkt_sz = fd_snp_v1_server_fini( server, server_conn, pkt, (ulong)pkt_sz, pkt, to_sign );
  FD_TEST_CUSTOM( pkt_sz>0, "fd_snp_v1_server_fini failed" );
  external_sign( sig, to_sign, server_private_key, server->identity );
  res = fd_snp_v1_server_fini_add_signature( server_conn, pkt, sig );
  FD_TEST_CUSTOM( res==0, "fd_snp_v1_server_fini_add_signature failed" );
  pkt_sz = fd_snp_v1_client_fini( client, client_conn, pkt, (ulong)pkt_sz, pkt, to_sign );
  FD_TEST_CUSTOM( pkt_sz>0, "fd_snp_v1_client_fini failed" );
  external_sign( sig, to_sign, client_private_key, client->identity );
  res = fd_snp_v1_client_fini_add_signature( client_conn, pkt, sig );
  FD_TEST_CUSTOM( res==0, "fd_snp_v1_client_fini_add_signature failed" );
  pkt_sz = fd_snp_v1_server_acpt( server, server_conn, pkt, (ulong)pkt_sz, pkt, NULL );
  FD_TEST_CUSTOM( pkt_sz==0, "fd_snp_v1_server_acpt failed" );

  FD_TEST( client_conn->state==FD_SNP_TYPE_HS_DONE );
  FD_TEST( fd_memeq( client_conn->_peer_pubkey, server->identity, 32 ) );
  FD_TEST( server_conn->state==FD_SNP_TYPE_HS_DONE );
  FD_TEST( fd_memeq( server_conn->_peer_pubkey, client->identity, 32 ) );

  FD_LOG_NOTICE(( "Test v1 handshake: ok" ));

  /* Bench */
  unsigned long iter = 1001UL;
  long          dt   = -wallclock();
  for( unsigned long rem=iter; rem; rem-- ) {
    memset( client_conn, 0, sizeof( fd_snp_conn_t ) ); client_conn->_pubkey = client->identity;
    memset( server_conn, 0, sizeof( fd_snp_conn_t ) ); server_conn->_pubkey = server->identity;
    pkt_sz = fd_snp_v1_client_init( client, client_conn, NULL, 0, pkt, NULL );
    FD_TEST_CUSTOM( pkt_sz>0, "fd_snp_v1_client_init failed" );
    pkt_sz = fd_snp_v1_server_init( server, server_conn, pkt, (ulong)pkt_sz, pkt, NULL );
    FD_TEST_CUSTOM( pkt_sz>0, "fd_snp_v1_server_init failed" );
    pkt_sz = fd_snp_v1_client_cont( client, client_conn, pkt, (ulong)pkt_sz, pkt, NULL );
    FD_TEST_CUSTOM( pkt_sz>0, "fd_snp_v1_client_cont failed" );
    pkt_sz = fd_snp_v1_server_fini( server, server_conn, pkt, (ulong)pkt_sz, pkt, to_sign );
    FD_TEST_CUSTOM( pkt_sz>0, "fd_snp_v1_server_fini failed" );
    external_sign( sig, to_sign, server_private_key, server->identity );
    res = fd_snp_v1_server_fini_add_signature( server_conn, pkt, sig );
    FD_TEST_CUSTOM( res==0, "fd_snp_v1_server_fini_add_signature failed" );
    pkt_sz = fd_snp_v1_client_fini( client, client_conn, pkt, (ulong)pkt_sz, pkt, to_sign );
    FD_TEST_CUSTOM( pkt_sz>0, "fd_snp_v1_client_fini failed" );
    external_sign( sig, to_sign, client_private_key, client->identity );
    res = fd_snp_v1_client_fini_add_signature( client_conn, pkt, sig );
    FD_TEST_CUSTOM( res==0, "fd_snp_v1_client_fini_add_signature failed" );
    pkt_sz = fd_snp_v1_server_acpt( server, server_conn, pkt, (ulong)pkt_sz, pkt, NULL );
    FD_TEST_CUSTOM( pkt_sz==0, "fd_snp_v1_server_acpt failed" );
  }
  dt += wallclock();
  fprintf( stderr, "Benchmarking full handshake\n" );
  bench_output( iter, dt );
}

static void
bench_ephemeral_generate( void ) {

  uchar public_key[32];
  uchar private_key[32];

  /* warmup */
  for( unsigned long rem=1000UL; rem; rem-- ) {
    fd_snp_v1_crypto_key_share_generate( private_key, public_key );
    __asm__ __volatile__( "# Compiler Barrier" : "+r" (private_key[0]) );
  }

  /* for real */
  unsigned long iter = 2000UL;
  long          dt   = -wallclock();
  for( unsigned long rem=iter; rem; rem-- ) {
    fd_snp_v1_crypto_key_share_generate( private_key, public_key );
    __asm__ __volatile__( "# Compiler Barrier" : "+r" (private_key[0]) );
  }
  dt += wallclock();
  fprintf( stderr, "Benchmarking ephemeral/key share generate\n" );
  bench_output( iter, dt );
}

static void
bench_enc_state_generate( void ) {
  fd_snp_config_t config[1];
  fd_snp_conn_t   conn[1];
  uchar           out[16];

  uchar aes_key[16];
  FD_TEST( fd_snp_rng( aes_key, 16 )==16 );
  fd_aes_set_encrypt_key( aes_key, 128, config->_state_enc_key );
  fd_aes_set_decrypt_key( aes_key, 128, config->_state_dec_key );
  conn->peer_addr = 123UL;

  /* warmup */
  for( unsigned long rem=1000UL; rem; rem-- ) {
    fd_snp_v1_crypto_enc_state_generate( config, conn, out );
    __asm__ __volatile__( "# Compiler Barrier" : "+r" (out[0]) );
  }

  /* for real */
  unsigned long iter = 20000UL;
  long          dt   = -wallclock();
  for( unsigned long rem=iter; rem; rem-- ) {
    fd_snp_v1_crypto_enc_state_generate( config, conn, out );
    __asm__ __volatile__( "# Compiler Barrier" : "+r" (out[0]) );
  }
  dt += wallclock();
  fprintf( stderr, "Benchmarking encrypted state generate\n" );
  bench_output( iter, dt );
}

static void
bench_enc_state_verify( void ) {

  fd_snp_config_t config[1];
  fd_snp_conn_t   conn[1];
  uchar           out[16];

  uchar aes_key[16];
  FD_TEST( fd_snp_rng( aes_key, 16 )==16 );
  fd_aes_set_encrypt_key( aes_key, 128, config->_state_enc_key );
  fd_aes_set_decrypt_key( aes_key, 128, config->_state_dec_key );
  conn->peer_addr = 123UL;

  fd_snp_v1_crypto_enc_state_generate( config, conn, out );

  /* warmup */
  for( unsigned long rem=1000UL; rem; rem-- ) {
    fd_snp_v1_crypto_enc_state_validate( config, conn, out );
    __asm__ __volatile__( "# Compiler Barrier" : "+r" (out[0]) );
  }

  /* for real */
  unsigned long iter = 20000UL;
  long          dt   = -wallclock();
  for( unsigned long rem=iter; rem; rem-- ) {
    fd_snp_v1_crypto_enc_state_validate( config, conn, out );
    __asm__ __volatile__( "# Compiler Barrier" : "+r" (out[0]) );
  }
  dt += wallclock();
  fprintf( stderr, "Benchmarking encrypted state verify\n" );
  bench_output( iter, dt );
}

int
main( int     argc,
      char ** argv ) {
  (void)argc;
  (void)argv;

  test_v1_handshake();
  bench_ephemeral_generate();
  bench_enc_state_generate();
  bench_enc_state_verify();

  return 0;
}
