#include "fd_tlsrec.h"
#include "fd_tlsrec_sock.h"
#include "../tls/test_tls_helper.h"
#include "../../ballet/aes/fd_aes_gcm.h"
#include "../../ballet/ed25519/fd_x25519.h"
#include "../../ballet/x509/fd_x509_mock.h"

#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

/* Reimplement IV generation logic for testing.
   TLS 1.3 per-record nonce: base_iv XOR big-endian sequence number
   (RFC 8446 Section 5.3). */

static void
test_gen_iv( uchar iv[12], uchar const base[12], ulong seq ) {
  memcpy( iv, base, 12 );
  iv[11] ^= (uchar)(seq      & 0xFF);
  iv[10] ^= (uchar)((seq>>8) & 0xFF);
  iv[ 9] ^= (uchar)((seq>>16)& 0xFF);
  iv[ 8] ^= (uchar)((seq>>24)& 0xFF);
  iv[ 7] ^= (uchar)((seq>>32)& 0xFF);
  iv[ 6] ^= (uchar)((seq>>40)& 0xFF);
  iv[ 5] ^= (uchar)((seq>>48)& 0xFF);
  iv[ 4] ^= (uchar)((seq>>56)& 0xFF);
}

static ulong test_tlsrec_secret_levels;

static void
test_tlsrec_secrets( void const * hs,
                     void const * rx_secret,
                     void const * tx_secret,
                     uint         level ) {
  FD_TEST( hs );
  FD_TEST( rx_secret );
  FD_TEST( tx_secret );
  FD_TEST( level==FD_TLS_LEVEL_HANDSHAKE || level==FD_TLS_LEVEL_APPLICATION );
  test_tlsrec_secret_levels |= 1UL<<level;
}

static void
test_tlsrec_rx_fragments( fd_tlsrec_conn_t * conn,
                          uchar const *      data,
                          ulong              data_sz,
                          ulong              fragment_sz,
                          uchar *            tcp_tx,
                          ulong *            tcp_tx_sz,
                          uchar *            app_rx,
                          ulong *            app_rx_sz ) {
  ulong tcp_tx_cap = *tcp_tx_sz;
  ulong app_rx_cap = *app_rx_sz;
  ulong tcp_tx_off = 0UL;
  ulong app_rx_off = 0UL;

  while( data_sz ) {
    ulong sz = fd_ulong_min( data_sz, fragment_sz );
    fd_tlsrec_slice_t tcp_rx[1];
    fd_tlsrec_slice_init( tcp_rx, (uchar *)data, sz );

    ulong tcp_tx_rem = tcp_tx_cap - tcp_tx_off;
    ulong app_rx_rem = app_rx_cap - app_rx_off;
    FD_TEST( fd_tlsrec_conn_rx( conn, tcp_rx,
                                tcp_tx + tcp_tx_off, &tcp_tx_rem,
                                app_rx + app_rx_off, &app_rx_rem )==FD_TLSREC_SUCCESS );
    FD_TEST( fd_tlsrec_slice_is_empty( tcp_rx ) );

    tcp_tx_off += tcp_tx_rem;
    app_rx_off += app_rx_rem;
    data       += sz;
    data_sz    -= sz;
  }

  *tcp_tx_sz = tcp_tx_off;
  *app_rx_sz = app_rx_off;
}

static void
test_tlsrec_pair( fd_rng_t * rng ) {
  test_tlsrec_secret_levels = 0UL;

  fd_tls_test_sign_ctx_t client_sign_ctx[1];
  fd_tls_test_sign_ctx_t server_sign_ctx[1];
  fd_tls_test_sign_ctx( client_sign_ctx, rng );
  fd_tls_test_sign_ctx( server_sign_ctx, rng );

  fd_chacha_rng_t client_chacha[1], server_chacha[1];

  fd_tls_t client_tls = {
    .rng        = fd_tls_test_rand( client_chacha, rng ),
    .sign       = fd_tls_test_sign( client_sign_ctx ),
    .secrets_fn = test_tlsrec_secrets,
    .alpn       = { 2, 'h', '2' },
    .alpn_sz    = 3UL,
  };
  fd_tls_t server_tls = {
    .rng     = fd_tls_test_rand( server_chacha, rng ),
    .sign    = fd_tls_test_sign( server_sign_ctx ),
    .alpn    = { 2, 'h', '2' },
    .alpn_sz = 3UL,
  };

  for( ulong j=0UL; j<32UL; j++ ) {
    client_tls.kex_private_key[j] = fd_rng_uchar( rng );
    server_tls.kex_private_key[j] = fd_rng_uchar( rng );
  }
  fd_x25519_public( client_tls.kex_public_key, client_tls.kex_private_key );
  fd_x25519_public( server_tls.kex_public_key, server_tls.kex_private_key );

  fd_memcpy( client_tls.cert_public_key, client_sign_ctx->public_key, 32UL );
  fd_memcpy( server_tls.cert_public_key, server_sign_ctx->public_key, 32UL );
  fd_x509_mock_cert( client_tls.cert_x509, client_tls.cert_public_key );
  fd_x509_mock_cert( server_tls.cert_x509, server_tls.cert_public_key );
  client_tls.cert_x509_sz = FD_X509_MOCK_CERT_SZ;
  server_tls.cert_x509_sz = FD_X509_MOCK_CERT_SZ;

  fd_tlsrec_conn_t client[1];
  fd_tlsrec_conn_t server[1];
  FD_TEST( fd_tlsrec_conn_init( client, &client_tls, 0 )==client );
  FD_TEST( fd_tlsrec_conn_init( server, &server_tls, 1 )==server );
  fd_memcpy( client->hs.cli.server_pubkey, server_tls.cert_public_key, 32UL );

  uchar client_tx[ FD_TLSREC_CAP ];
  uchar server_tx[ FD_TLSREC_CAP ];
  uchar app_rx   [ FD_TLSREC_CAP ];

  /* Generate ClientHello. */
  ulong client_tx_sz = sizeof(client_tx);
  ulong app_rx_sz    = sizeof(app_rx);
  FD_TEST( fd_tlsrec_conn_rx( client, NULL, client_tx, &client_tx_sz,
                              app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
  FD_TEST( client_tx_sz>sizeof(fd_tlsrec_hdr_t) );
  FD_TEST( !app_rx_sz );

  /* Fragment ClientHello across record header and message body. */
  ulong server_tx_sz = sizeof(server_tx);
  app_rx_sz = sizeof(app_rx);
  test_tlsrec_rx_fragments( server, client_tx, client_tx_sz, 3UL,
                            server_tx, &server_tx_sz, app_rx, &app_rx_sz );
  FD_TEST( server_tx_sz>sizeof(fd_tlsrec_hdr_t) );
  FD_TEST( !app_rx_sz );

  /* Server flight contains multiple records and coalesced messages. */
  client_tx_sz = sizeof(client_tx);
  app_rx_sz    = sizeof(app_rx);
  test_tlsrec_rx_fragments( client, server_tx, server_tx_sz, 7UL,
                            client_tx, &client_tx_sz, app_rx, &app_rx_sz );
  FD_TEST( client_tx_sz>sizeof(fd_tlsrec_hdr_t) );
  FD_TEST( !app_rx_sz );
  FD_TEST( fd_tlsrec_conn_is_ready( client ) );
  FD_TEST( client->hs.cli.alpn_negotiated );

  server_tx_sz = sizeof(server_tx);
  app_rx_sz    = sizeof(app_rx);
  test_tlsrec_rx_fragments( server, client_tx, client_tx_sz, 2UL,
                            server_tx, &server_tx_sz, app_rx, &app_rx_sz );
  FD_TEST( !server_tx_sz );
  FD_TEST( !app_rx_sz );
  FD_TEST( fd_tlsrec_conn_is_ready( server ) );
  FD_TEST( test_tlsrec_secret_levels==( (1UL<<FD_TLS_LEVEL_HANDSHAKE) |
                                        (1UL<<FD_TLS_LEVEL_APPLICATION) ) );

  static uchar const client_msg[] = "fragmented client application data";
  fd_tlsrec_slice_t client_app[1];
  fd_tlsrec_slice_init( client_app, (uchar *)client_msg, sizeof(client_msg)-1UL );
  client_tx_sz = sizeof(client_tx);
  FD_TEST( fd_tlsrec_conn_tx( client, client_tx, &client_tx_sz, client_app )==FD_TLSREC_SUCCESS );
  FD_TEST( fd_tlsrec_slice_is_empty( client_app ) );

  server_tx_sz = sizeof(server_tx);
  app_rx_sz    = sizeof(app_rx);
  test_tlsrec_rx_fragments( server, client_tx, client_tx_sz, 1UL,
                            server_tx, &server_tx_sz, app_rx, &app_rx_sz );
  FD_TEST( !server_tx_sz );
  FD_TEST( app_rx_sz==sizeof(client_msg)-1UL );
  FD_TEST( !memcmp( app_rx, client_msg, app_rx_sz ) );

  static uchar const server_msg[] = "server application data";
  fd_tlsrec_slice_t server_app[1];
  fd_tlsrec_slice_init( server_app, (uchar *)server_msg, sizeof(server_msg)-1UL );
  server_tx_sz = sizeof(server_tx);
  FD_TEST( fd_tlsrec_conn_tx( server, server_tx, &server_tx_sz, server_app )==FD_TLSREC_SUCCESS );
  FD_TEST( fd_tlsrec_slice_is_empty( server_app ) );

  client_tx_sz = sizeof(client_tx);
  app_rx_sz    = sizeof(app_rx);
  test_tlsrec_rx_fragments( client, server_tx, server_tx_sz, 5UL,
                            client_tx, &client_tx_sz, app_rx, &app_rx_sz );
  FD_TEST( !client_tx_sz );
  FD_TEST( app_rx_sz==sizeof(server_msg)-1UL );
  FD_TEST( !memcmp( app_rx, server_msg, app_rx_sz ) );

  /* Client requests a key update.  Server responds and both directions
     switch to the next application traffic secret. */
  client_tx_sz = sizeof(client_tx);
  FD_TEST( fd_tlsrec_conn_key_update( client, client_tx, &client_tx_sz, 1 )==FD_TLSREC_SUCCESS );
  FD_TEST( client_tx_sz>sizeof(fd_tlsrec_hdr_t) );
  FD_TEST( !client->write_seq );

  server_tx_sz = sizeof(server_tx);
  app_rx_sz    = sizeof(app_rx);
  test_tlsrec_rx_fragments( server, client_tx, client_tx_sz, 3UL,
                            server_tx, &server_tx_sz, app_rx, &app_rx_sz );
  FD_TEST( server_tx_sz>sizeof(fd_tlsrec_hdr_t) );
  FD_TEST( !app_rx_sz );
  FD_TEST( !server->read_seq );
  FD_TEST( !server->write_seq );

  client_tx_sz = sizeof(client_tx);
  app_rx_sz    = sizeof(app_rx);
  test_tlsrec_rx_fragments( client, server_tx, server_tx_sz, 2UL,
                            client_tx, &client_tx_sz, app_rx, &app_rx_sz );
  FD_TEST( !client_tx_sz );
  FD_TEST( !app_rx_sz );
  FD_TEST( !client->read_seq );

  static uchar const updated_msg[] = "application data after KeyUpdate";
  fd_tlsrec_slice_init( client_app, (uchar *)updated_msg, sizeof(updated_msg)-1UL );
  client_tx_sz = sizeof(client_tx);
  FD_TEST( fd_tlsrec_conn_tx( client, client_tx, &client_tx_sz, client_app )==FD_TLSREC_SUCCESS );

  server_tx_sz = sizeof(server_tx);
  app_rx_sz    = sizeof(app_rx);
  test_tlsrec_rx_fragments( server, client_tx, client_tx_sz, 4UL,
                            server_tx, &server_tx_sz, app_rx, &app_rx_sz );
  FD_TEST( !server_tx_sz );
  FD_TEST( app_rx_sz==sizeof(updated_msg)-1UL );
  FD_TEST( !memcmp( app_rx, updated_msg, app_rx_sz ) );

  static uchar const updated_reply[] = "server data after KeyUpdate";
  fd_tlsrec_slice_init( server_app, (uchar *)updated_reply, sizeof(updated_reply)-1UL );
  server_tx_sz = sizeof(server_tx);
  FD_TEST( fd_tlsrec_conn_tx( server, server_tx, &server_tx_sz, server_app )==FD_TLSREC_SUCCESS );

  client_tx_sz = sizeof(client_tx);
  app_rx_sz    = sizeof(app_rx);
  test_tlsrec_rx_fragments( client, server_tx, server_tx_sz, 6UL,
                            client_tx, &client_tx_sz, app_rx, &app_rx_sz );
  FD_TEST( !client_tx_sz );
  FD_TEST( app_rx_sz==sizeof(updated_reply)-1UL );
  FD_TEST( !memcmp( app_rx, updated_reply, app_rx_sz ) );

  /* app_rx smaller than the ciphertext: decrypt in place, copy out */
  for( ulong frags=1UL; frags<=2UL; frags++ ) {
    fd_tlsrec_slice_init( server_app, (uchar *)server_msg, sizeof(server_msg)-1UL );
    server_tx_sz = sizeof(server_tx);
    FD_TEST( fd_tlsrec_conn_tx( server, server_tx, &server_tx_sz, server_app )==FD_TLSREC_SUCCESS );

    memset( app_rx, 0xff, sizeof(app_rx) );
    client_tx_sz = sizeof(client_tx);
    app_rx_sz    = sizeof(server_msg)-1UL;
    test_tlsrec_rx_fragments( client, server_tx, server_tx_sz, frags,
                              client_tx, &client_tx_sz, app_rx, &app_rx_sz );
    FD_TEST( !client_tx_sz );
    FD_TEST( app_rx_sz==sizeof(server_msg)-1UL );
    FD_TEST( !memcmp( app_rx, server_msg, app_rx_sz ) );
    FD_TEST( app_rx[ app_rx_sz ]==0xff );
  }

  /* KeyUpdate with zero app_rx capacity */
  server_tx_sz = sizeof(server_tx);
  FD_TEST( fd_tlsrec_conn_key_update( server, server_tx, &server_tx_sz, 0 )==FD_TLSREC_SUCCESS );
  client_tx_sz = sizeof(client_tx);
  app_rx_sz    = 0UL;
  test_tlsrec_rx_fragments( client, server_tx, server_tx_sz, 1UL,
                            client_tx, &client_tx_sz, app_rx, &app_rx_sz );
  FD_TEST( !client_tx_sz );
  FD_TEST( !app_rx_sz );
  FD_TEST( !client->read_seq );

  fd_tlsrec_slice_init( server_app, (uchar *)server_msg, sizeof(server_msg)-1UL );
  server_tx_sz = sizeof(server_tx);
  FD_TEST( fd_tlsrec_conn_tx( server, server_tx, &server_tx_sz, server_app )==FD_TLSREC_SUCCESS );
  client_tx_sz = sizeof(client_tx);
  app_rx_sz    = sizeof(app_rx);
  test_tlsrec_rx_fragments( client, server_tx, server_tx_sz, 1UL,
                            client_tx, &client_tx_sz, app_rx, &app_rx_sz );
  FD_TEST( app_rx_sz==sizeof(server_msg)-1UL );
  FD_TEST( !memcmp( app_rx, server_msg, app_rx_sz ) );

  /* Write key reaches the record limit: conn_tx rotates it with a
     KeyUpdate before the next app data record. */
  fd_tlsrec_slice_init( client_app, (uchar *)client_msg, sizeof(client_msg)-1UL );
  client_tx_sz = sizeof(client_tx);
  FD_TEST( fd_tlsrec_conn_tx( client, client_tx, &client_tx_sz, client_app )==FD_TLSREC_SUCCESS );
  ulong plain_rec_sz = client_tx_sz;
  server_tx_sz = sizeof(server_tx);
  app_rx_sz    = sizeof(app_rx);
  test_tlsrec_rx_fragments( server, client_tx, client_tx_sz, 1UL,
                            server_tx, &server_tx_sz, app_rx, &app_rx_sz );
  FD_TEST( app_rx_sz==sizeof(client_msg)-1UL );

  client->write_seq = FD_TLSREC_KEY_UPDATE_SEQ-1UL;
  server->read_seq  = FD_TLSREC_KEY_UPDATE_SEQ-1UL;
  fd_tlsrec_slice_init( client_app, (uchar *)client_msg, sizeof(client_msg)-1UL );
  client_tx_sz = sizeof(client_tx);
  FD_TEST( fd_tlsrec_conn_tx( client, client_tx, &client_tx_sz, client_app )==FD_TLSREC_SUCCESS );
  FD_TEST( client_tx_sz==plain_rec_sz );
  FD_TEST( client->write_seq==FD_TLSREC_KEY_UPDATE_SEQ );
  server_tx_sz = sizeof(server_tx);
  app_rx_sz    = sizeof(app_rx);
  test_tlsrec_rx_fragments( server, client_tx, client_tx_sz, 2UL,
                            server_tx, &server_tx_sz, app_rx, &app_rx_sz );
  FD_TEST( !server_tx_sz );
  FD_TEST( app_rx_sz==sizeof(client_msg)-1UL );
  FD_TEST( !memcmp( app_rx, client_msg, app_rx_sz ) );
  FD_TEST( server->read_seq==FD_TLSREC_KEY_UPDATE_SEQ );

  fd_tlsrec_slice_init( client_app, (uchar *)client_msg, sizeof(client_msg)-1UL );
  client_tx_sz = sizeof(client_tx);
  FD_TEST( fd_tlsrec_conn_tx( client, client_tx, &client_tx_sz, client_app )==FD_TLSREC_SUCCESS );
  FD_TEST( client_tx_sz==plain_rec_sz+27UL );
  FD_TEST( client->write_seq==1UL );
  server_tx_sz = sizeof(server_tx);
  app_rx_sz    = sizeof(app_rx);
  test_tlsrec_rx_fragments( server, client_tx, client_tx_sz, 3UL,
                            server_tx, &server_tx_sz, app_rx, &app_rx_sz );
  FD_TEST( !server_tx_sz );
  FD_TEST( app_rx_sz==sizeof(client_msg)-1UL );
  FD_TEST( !memcmp( app_rx, client_msg, app_rx_sz ) );
  FD_TEST( server->read_seq==1UL );

  /* Server side is unaffected by the client's rotation */
  fd_tlsrec_slice_init( server_app, (uchar *)server_msg, sizeof(server_msg)-1UL );
  server_tx_sz = sizeof(server_tx);
  FD_TEST( fd_tlsrec_conn_tx( server, server_tx, &server_tx_sz, server_app )==FD_TLSREC_SUCCESS );
  client_tx_sz = sizeof(client_tx);
  app_rx_sz    = sizeof(app_rx);
  test_tlsrec_rx_fragments( client, server_tx, server_tx_sz, 1UL,
                            client_tx, &client_tx_sz, app_rx, &app_rx_sz );
  FD_TEST( app_rx_sz==sizeof(server_msg)-1UL );
  FD_TEST( !memcmp( app_rx, server_msg, app_rx_sz ) );
}

/* Handshake messages larger than a record (e.g. a Certificate carrying
   a real WebPKI chain) must reassemble across records up to
   FD_TLSREC_HS_MSG_CAP.  Anything larger is a protocol error. */

static void
test_tlsrec_large_hs_msg( fd_rng_t * rng ) {
  fd_tls_test_sign_ctx_t sign_ctx[1];
  fd_tls_test_sign_ctx( sign_ctx, rng );
  fd_chacha_rng_t chacha[1];
  fd_tls_t tls = {
    .rng  = fd_tls_test_rand( chacha, rng ),
    .sign = fd_tls_test_sign( sign_ctx ),
  };
  for( ulong j=0UL; j<32UL; j++ ) tls.kex_private_key[j] = fd_rng_uchar( rng );
  fd_x25519_public( tls.kex_public_key, tls.kex_private_key );

  static uchar tcp_tx[ FD_TLSREC_CAP ];
  static uchar app_rx[ FD_TLSREC_CAP ];
  static uchar rec   [ FD_TLSREC_CAP ];

  for( ulong pass=0UL; pass<2UL; pass++ ) {
    ulong const msg_body_sz = pass ? FD_TLSREC_HS_MSG_CAP-sizeof(fd_tls_msg_hdr_t)+1UL  /* one over the cap */
                                   : 6000UL;                                          /* realistic cert chain */

    static fd_tlsrec_conn_t conn[1];
    FD_TEST( fd_tlsrec_conn_init( conn, &tls, 0 )==conn );
    ulong tcp_tx_sz = sizeof(tcp_tx), app_rx_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( conn, NULL, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
    FD_TEST( conn->hs.base.state==FD_TLS_HS_WAIT_SH );

    /* Plaintext handshake record holding the first 2000 bytes of a
       handshake message with a msg_body_sz byte body. */
    ulong const chunk_sz = 2000UL;
    ulong const rec_payload_sz = sizeof(fd_tls_msg_hdr_t)+chunk_sz;
    rec[0] = FD_TLS_REC_HANDSHAKE;
    rec[1] = 0x03; rec[2] = 0x03;
    rec[3] = (uchar)(rec_payload_sz>>8); rec[4] = (uchar)rec_payload_sz;
    rec[5] = FD_TLS_MSG_SERVER_HELLO;
    rec[6] = (uchar)(msg_body_sz>>16); rec[7] = (uchar)(msg_body_sz>>8); rec[8] = (uchar)msg_body_sz;
    ulong rec_sz = sizeof(fd_tlsrec_hdr_t)+rec_payload_sz;

    fd_tlsrec_slice_t tcp_rx[1];
    fd_tlsrec_slice_init( tcp_rx, rec, rec_sz );
    tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
    int rc = fd_tlsrec_conn_rx( conn, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz );
    if( pass ) {
      FD_TEST( rc==FD_TLSREC_ERR_PROTO );
    } else {
      FD_TEST( rc==FD_TLSREC_SUCCESS );
      FD_TEST( fd_tlsrec_slice_is_empty( tcp_rx ) );
      FD_TEST( conn->hs_rbuf.sz==rec_payload_sz );  /* reassembly in progress */
      FD_TEST( !fd_tlsrec_conn_is_failed( conn ) );
    }
  }
}

/* test_tlsrec_connect runs a full handshake between a fresh client and
   server that both use tls, leaving both sides in the CONNECTED state. */

static void
test_tlsrec_connect( fd_tls_t const *   tls,
                     fd_tlsrec_conn_t * cli,
                     fd_tlsrec_conn_t * srv ) {
  FD_TEST( fd_tlsrec_conn_init( cli, tls, 0 )==cli );
  FD_TEST( fd_tlsrec_conn_init( srv, tls, 1 )==srv );
  fd_memcpy( cli->hs.cli.server_pubkey, tls->cert_public_key, 32UL );

  static uchar cli_tx[ FD_TLSREC_CAP ], srv_tx[ FD_TLSREC_CAP ], app_rx[ FD_TLSREC_CAP ];
  ulong cli_tx_sz = sizeof(cli_tx), srv_tx_sz = sizeof(srv_tx), app_rx_sz = sizeof(app_rx);
  FD_TEST( fd_tlsrec_conn_rx( cli, NULL, cli_tx, &cli_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
  test_tlsrec_rx_fragments( srv, cli_tx, cli_tx_sz, 1UL, srv_tx, &srv_tx_sz, app_rx, &app_rx_sz );
  cli_tx_sz = sizeof(cli_tx);
  test_tlsrec_rx_fragments( cli, srv_tx, srv_tx_sz, 1UL, cli_tx, &cli_tx_sz, app_rx, &app_rx_sz );
  srv_tx_sz = sizeof(srv_tx);
  test_tlsrec_rx_fragments( srv, cli_tx, cli_tx_sz, 1UL, srv_tx, &srv_tx_sz, app_rx, &app_rx_sz );
  FD_TEST( fd_tlsrec_conn_is_ready( cli ) );
  FD_TEST( fd_tlsrec_conn_is_ready( srv ) );
}

/* test_tlsrec_send_raw writes one encrypted record carrying payload
   with the given inner content type, using conn's application write
   keys, and returns its size.  Mirrors fd_tlsrec_tx but lets a test
   pick the content type. */

static ulong
test_tlsrec_send_raw_ex( fd_tlsrec_conn_t * conn,
                         uchar *            out,
                         uchar const *      payload,
                         ulong              payload_sz,
                         uchar              content_type,
                         ulong              padding_sz,
                         ushort             version,
                         uint               key_idx ) {
  ulong pt_sz    = payload_sz + 1UL + padding_sz;
  ulong inner_sz = pt_sz + FD_AES_GCM_TAG_SZ;
  fd_tlsrec_hdr_t * hdr = fd_type_pun( out );
  *hdr = (fd_tlsrec_hdr_t){
    .content_type          = FD_TLS_REC_APPLICATION_DATA,
    .legacy_record_version = fd_ushort_bswap( version ),
    .length                = fd_ushort_bswap( (ushort)inner_sz ),
  };
  uchar * c = out + sizeof(fd_tlsrec_hdr_t);
  fd_memcpy( c, payload, payload_sz );
  c[ payload_sz ] = content_type;
  fd_memset( c+payload_sz+1UL, 0, padding_sz );

  uchar iv[12]; test_gen_iv( iv, conn->keys[key_idx].write_iv, conn->write_seq );
  fd_aes_gcm_t gcm[1];
  fd_aes_gcm_init( gcm, conn->keys[key_idx].write_key, 16UL, iv );
  fd_aes_gcm_encrypt( gcm, c, c, pt_sz, out, sizeof(fd_tlsrec_hdr_t), c+pt_sz );
  if( conn->write_seq!=ULONG_MAX ) conn->write_seq++;
  return sizeof(fd_tlsrec_hdr_t) + inner_sz;
}

static ulong
test_tlsrec_send_raw( fd_tlsrec_conn_t * conn,
                      uchar *            out,
                      uchar const *      payload,
                      ulong              payload_sz,
                      uchar              content_type ) {
  return test_tlsrec_send_raw_ex( conn, out, payload, payload_sz, content_type, 0UL, 0x0303, 1U );
}

static void
test_tlsrec_check_alert( fd_tlsrec_conn_t const * conn,
                         uchar const *           rec,
                         ulong                   rec_sz,
                         uchar                   desc ) {
  if( conn->tx_level==FD_TLS_LEVEL_INITIAL ) {
    uchar const expected[] = { 21, 3, 3, 0, 2, 2, desc };
    FD_TEST( rec_sz==sizeof(expected) && !memcmp( rec, expected, sizeof(expected) ) );
    return;
  }
  FD_TEST( rec_sz==24UL && rec[0]==FD_TLS_REC_APPLICATION_DATA );
  fd_tlsrec_keys_t const * keys = &conn->keys[ conn->tx_level==FD_TLS_LEVEL_APPLICATION ];
  uchar iv[12]; test_gen_iv( iv, keys->write_iv, conn->write_seq-1UL );
  fd_aes_gcm_t gcm[1];
  fd_aes_gcm_init( gcm, keys->write_key, 16UL, iv );
  uchar pt[3];
  FD_TEST( fd_aes_gcm_decrypt( gcm, rec+5UL, pt, 3UL, rec, 5UL, rec+8UL ) );
  FD_TEST( pt[0]==2U && pt[1]==desc && pt[2]==FD_TLS_REC_ALERT );
}

static void
test_tlsrec_ccs( fd_rng_t * rng ) {
  fd_tls_test_sign_ctx_t sign_ctx[1];
  fd_tls_test_sign_ctx( sign_ctx, rng );
  fd_chacha_rng_t chacha[1];
  fd_tls_t tls = {
    .rng  = fd_tls_test_rand( chacha, rng ),
    .sign = fd_tls_test_sign( sign_ctx ),
  };
  for( ulong j=0UL; j<32UL; j++ ) tls.kex_private_key[j] = fd_rng_uchar( rng );
  fd_x25519_public( tls.kex_public_key, tls.kex_private_key );
  fd_memcpy( tls.cert_public_key, sign_ctx->public_key, 32UL );
  fd_x509_mock_cert( tls.cert_x509, tls.cert_public_key );
  tls.cert_x509_sz = FD_X509_MOCK_CERT_SZ;

  static uchar client_hello[ FD_TLSREC_CAP ];
  static uchar tcp_tx[ FD_TLSREC_CAP ];
  static uchar app_rx[ FD_TLSREC_CAP ];

  /* Any client will do to move a server into WAIT_FINISHED */
  static fd_tlsrec_conn_t client[1];
  FD_TEST( fd_tlsrec_conn_init( client, &tls, 0 )==client );
  ulong client_hello_sz = sizeof(client_hello), app_rx_sz = sizeof(app_rx);
  FD_TEST( fd_tlsrec_conn_rx( client, NULL, client_hello, &client_hello_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );

  static uchar const ccs_ok  [] = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
  static uchar const ccs_val [] = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x02 };
  static uchar const ccs_long[] = { 0x14, 0x03, 0x03, 0x00, 0x02, 0x01, 0x01 };
  static uchar const ccs_zero[] = { 0x14, 0x03, 0x03, 0x00, 0x00 };
  struct { uchar const * rec; ulong sz; int ok; } const cases[] = {
    { ccs_ok,   sizeof(ccs_ok),   1 },
    { ccs_val,  sizeof(ccs_val),  0 },
    { ccs_long, sizeof(ccs_long), 0 },
    { ccs_zero, sizeof(ccs_zero), 0 },
  };

  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    static fd_tlsrec_conn_t server[1];
    static fd_tlsrec_conn_t waiting_client[1];
    *waiting_client = *client;
    FD_TEST( fd_tlsrec_conn_init( server, &tls, 1 )==server );

    fd_tlsrec_slice_t tcp_rx[1];
    ulong tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);

    /* A client has already sent ClientHello while waiting for SH. */
    fd_tlsrec_slice_init( tcp_rx, (uchar *)cases[i].rec, cases[i].sz );
    int client_rc = fd_tlsrec_conn_rx( waiting_client, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz );
    FD_TEST( client_rc==(cases[i].ok ? FD_TLSREC_SUCCESS : FD_TLSREC_ERR_PROTO) );
    if( cases[i].ok ) {
      FD_TEST( !tcp_tx_sz && waiting_client->tx_level==FD_TLS_LEVEL_INITIAL );
    } else {
      test_tlsrec_check_alert( waiting_client, tcp_tx, tcp_tx_sz, FD_TLS_ALERT_UNEXPECTED_MESSAGE );
    }

    /* CCS before ClientHello is always an error */
    fd_tlsrec_slice_init( tcp_rx, (uchar *)cases[i].rec, cases[i].sz );
    tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( server, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_ERR_PROTO );
    test_tlsrec_check_alert( server, tcp_tx, tcp_tx_sz, FD_TLS_ALERT_UNEXPECTED_MESSAGE );

    FD_TEST( fd_tlsrec_conn_init( server, &tls, 1 )==server );
    fd_tlsrec_slice_init( tcp_rx, client_hello, client_hello_sz );
    tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( server, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
    FD_TEST( server->hs.base.state!=FD_TLS_HS_START && !fd_tlsrec_conn_is_failed( server ) );

    fd_tlsrec_slice_init( tcp_rx, (uchar *)cases[i].rec, cases[i].sz );
    tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
    int rc = fd_tlsrec_conn_rx( server, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz );
    if( !cases[i].ok ) {
      FD_TEST( rc==FD_TLSREC_ERR_PROTO );
      FD_TEST( fd_tlsrec_conn_is_failed( server ) );
      FD_TEST( server->hs.base.reason==FD_TLS_REASON_CCS );
      test_tlsrec_check_alert( server, tcp_tx, tcp_tx_sz, FD_TLS_ALERT_UNEXPECTED_MESSAGE );
      continue;
    }
    FD_TEST( rc==FD_TLSREC_SUCCESS );
    FD_TEST( fd_tlsrec_slice_is_empty( tcp_rx ) );
    FD_TEST( !fd_tlsrec_conn_is_failed( server ) );
    FD_TEST( !tcp_tx_sz && !app_rx_sz && !server->read_seq );

    /* Repeated compatibility CCS records are discarded. */
    fd_tlsrec_slice_init( tcp_rx, (uchar *)ccs_ok, sizeof(ccs_ok) );
    tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( server, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
    FD_TEST( !tcp_tx_sz && !app_rx_sz && !server->read_seq );
  }

  /* A server awaiting a retry ClientHello remains inside the window. */
  do {
    static fd_tlsrec_conn_t server[1];
    FD_TEST( fd_tlsrec_conn_init( server, &tls, 1 )==server );
    server->hs.srv.hello_retry = 1;
    fd_tlsrec_slice_t tcp_rx[1];
    for( ulong i=0UL; i<2UL; i++ ) {
      fd_tlsrec_slice_init( tcp_rx, (uchar *)ccs_ok, sizeof(ccs_ok) );
      ulong tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
      FD_TEST( fd_tlsrec_conn_rx( server, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
      FD_TEST( !tcp_tx_sz && !app_rx_sz && !server->read_seq );
    }
  } while(0);

  /* CCS after the handshake completed is fatal */
  do {
    static fd_tlsrec_conn_t cli[1], srv[1];
    static uchar cli_tx[ FD_TLSREC_CAP ], srv_tx[ FD_TLSREC_CAP ];
    test_tlsrec_connect( &tls, cli, srv );
    ulong cli_tx_sz, srv_tx_sz;

    fd_tlsrec_slice_t tcp_rx[1];
    fd_tlsrec_slice_init( tcp_rx, (uchar *)ccs_ok, sizeof(ccs_ok) );
    srv_tx_sz = sizeof(srv_tx); app_rx_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( srv, tcp_rx, srv_tx, &srv_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_ERR_PROTO );
    FD_TEST( srv->hs.base.reason==FD_TLS_REASON_CCS );
    test_tlsrec_check_alert( srv, srv_tx, srv_tx_sz, FD_TLS_ALERT_UNEXPECTED_MESSAGE );
    fd_tlsrec_slice_init( tcp_rx, (uchar *)ccs_ok, sizeof(ccs_ok) );
    cli_tx_sz = sizeof(cli_tx); app_rx_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( cli, tcp_rx, cli_tx, &cli_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_ERR_PROTO );
    FD_TEST( cli->hs.base.reason==FD_TLS_REASON_CCS );
    test_tlsrec_check_alert( cli, cli_tx, cli_tx_sz, FD_TLS_ALERT_UNEXPECTED_MESSAGE );
  } while(0);
}

/* Split each flight record inside its first handshake header, with
   repeated compatibility CCS before and between the fragments. */

static void
test_tlsrec_ccs_flight( fd_tlsrec_conn_t const * sender,
                        fd_tlsrec_conn_t *       receiver,
                        uchar const *            flight,
                        ulong                    flight_sz,
                        uchar *                  reply,
                        ulong *                  reply_sz ) {
  static fd_tlsrec_conn_t emitter[1];
  *emitter = *sender;
  emitter->write_seq = 0UL;
  ulong seq = 0UL;
  ulong reply_cap = *reply_sz;
  *reply_sz = 0UL;
  static uchar pt[ FD_TLSREC_CAP ], rec[ FD_TLSREC_CAP ], app[ FD_TLSREC_CAP ];
  static uchar const ccs[] = { 20, 0, 0, 0, 1, 1 };
  while( flight_sz ) {
    fd_tlsrec_hdr_t const * hdr = fd_type_pun_const( flight );
    ulong payload_sz = fd_ushort_bswap( hdr->length );
    ulong rec_sz = 5UL+payload_sz;
    FD_TEST( rec_sz<=flight_sz );
    int encrypted = hdr->content_type==FD_TLS_REC_APPLICATION_DATA;
    if( encrypted ) {
      FD_TEST( payload_sz>FD_AES_GCM_TAG_SZ+1UL );
      payload_sz -= FD_AES_GCM_TAG_SZ;
      uchar iv[12]; test_gen_iv( iv, sender->keys[0].write_iv, seq++ );
      fd_aes_gcm_t gcm[1];
      fd_aes_gcm_init( gcm, sender->keys[0].write_key, 16UL, iv );
      FD_TEST( fd_aes_gcm_decrypt( gcm, flight+5UL, pt, payload_sz, flight, 5UL, flight+5UL+payload_sz ) );
      FD_TEST( pt[--payload_sz]==FD_TLS_REC_HANDSHAKE );
    } else {
      FD_TEST( hdr->content_type==FD_TLS_REC_HANDSHAKE );
      fd_memcpy( pt, flight+5UL, payload_sz );
    }
    FD_TEST( payload_sz>1UL );
    for( ulong part=0UL; part<2UL; part++ ) {
      for( ulong repeat=0UL; repeat<2UL; repeat++ ) {
        ulong out_sz = reply_cap-*reply_sz, app_sz = sizeof(app);
        ulong read_seq = receiver->read_seq, hs_sz = receiver->hs_rbuf.sz;
        uchar tx_level = receiver->tx_level;
        test_tlsrec_rx_fragments( receiver, ccs, sizeof(ccs), 1UL, reply+*reply_sz, &out_sz, app, &app_sz );
        FD_TEST( !out_sz && !app_sz && receiver->read_seq==read_seq && receiver->hs_rbuf.sz==hs_sz );
        FD_TEST( receiver->tx_level==tx_level );
      }
      ulong off = part ? 1UL : 0UL;
      ulong len = part ? payload_sz-1UL : 1UL;
      ulong sz;
      if( encrypted ) {
        sz = test_tlsrec_send_raw_ex( emitter, rec, pt+off, len, FD_TLS_REC_HANDSHAKE, 0UL, 0x0303, 0U );
      } else {
        fd_memcpy( rec, flight, 5UL );
        ((fd_tlsrec_hdr_t *)rec)->length = fd_ushort_bswap( (ushort)len );
        fd_memcpy( rec+5UL, pt+off, len );
        sz = 5UL+len;
      }
      ulong out_sz = reply_cap-*reply_sz, app_sz = sizeof(app);
      test_tlsrec_rx_fragments( receiver, rec, sz, 3UL, reply+*reply_sz, &out_sz, app, &app_sz );
      *reply_sz += out_sz;
      FD_TEST( !app_sz );
    }
    flight += rec_sz;
    flight_sz -= rec_sz;
  }
}

static void
test_tlsrec_handshake_epochs( fd_rng_t * rng ) {
  fd_tls_test_sign_ctx_t sign_ctx[1];
  fd_tls_test_sign_ctx( sign_ctx, rng );
  fd_chacha_rng_t chacha[1];
  fd_tls_t tls = {
    .rng  = fd_tls_test_rand( chacha, rng ),
    .sign = fd_tls_test_sign( sign_ctx ),
  };
  for( ulong j=0UL; j<32UL; j++ ) tls.kex_private_key[j] = fd_rng_uchar( rng );
  fd_x25519_public( tls.kex_public_key, tls.kex_private_key );
  fd_memcpy( tls.cert_public_key, sign_ctx->public_key, 32UL );
  fd_x509_mock_cert( tls.cert_x509, tls.cert_public_key );
  tls.cert_x509_sz = FD_X509_MOCK_CERT_SZ;

  static fd_tlsrec_conn_t cli[1], srv[1];
  static uchar client_flight[ FD_TLSREC_CAP ], server_flight[ FD_TLSREC_CAP ];
  static uchar rec[ FD_TLSREC_CAP ], tcp_tx[ FD_TLSREC_CAP ], app_rx[ FD_TLSREC_CAP ];
  fd_tlsrec_slice_t tcp_rx[1];
  for( int fail=0; fail<3; fail++ ) {
    FD_TEST( fd_tlsrec_conn_init( cli, &tls, 0 )==cli );
    FD_TEST( fd_tlsrec_conn_init( srv, &tls, 1 )==srv );
    fd_memcpy( cli->hs.cli.server_pubkey, tls.cert_public_key, 32UL );
    ulong cli_sz = sizeof(client_flight), srv_sz = sizeof(server_flight), app_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( cli, NULL, client_flight, &cli_sz, app_rx, &app_sz )==FD_TLSREC_SUCCESS );
    fd_tlsrec_slice_init( tcp_rx, client_flight, cli_sz );
    app_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( srv, tcp_rx, server_flight, &srv_sz, app_rx, &app_sz )==FD_TLSREC_SUCCESS );
    FD_TEST( srv->hs.base.state==FD_TLS_HS_WAIT_CERT );
    FD_TEST( srv->tx_level==FD_TLS_LEVEL_APPLICATION && !srv->write_seq && !srv->read_seq );
    cli_sz = sizeof(client_flight);
    test_tlsrec_ccs_flight( srv, cli, server_flight, srv_sz, client_flight, &cli_sz );
    FD_TEST( fd_tlsrec_conn_is_ready( cli ) && cli_sz );

    if( fail ) {
      /* The server has sent Finished, but the client authentication
         flight is invalid.  Its fatal alert must use application keys. */
      if( fail==1 ) {
        client_flight[cli_sz-1UL] ^= 1U;
      } else {
        /* Encrypted CCS is forbidden even inside the legal window. */
        uchar ccs[] = { 1 };
        cli_sz = test_tlsrec_send_raw_ex( cli, client_flight, ccs, sizeof(ccs),
                                          FD_TLS_REC_CHANGE_CIPHER_SPEC, 0UL, 0x0303, 0U );
      }
      fd_tlsrec_slice_init( tcp_rx, client_flight, cli_sz );
      ulong tx_sz = sizeof(tcp_tx); app_sz = sizeof(app_rx);
      FD_TEST( fd_tlsrec_conn_rx( srv, tcp_rx, tcp_tx, &tx_sz, app_rx, &app_sz )==
               (fail==1 ? FD_TLSREC_ERR_CRYPTO : FD_TLSREC_ERR_PROTO) );
      test_tlsrec_check_alert( srv, tcp_tx, tx_sz, fail==1 ? FD_TLS_ALERT_BAD_RECORD_MAC : FD_TLS_ALERT_UNEXPECTED_MESSAGE );
      fd_tlsrec_slice_init( tcp_rx, tcp_tx, tx_sz );
      ulong rec_sz = sizeof(rec); app_sz = sizeof(app_rx);
      FD_TEST( fd_tlsrec_conn_rx( cli, tcp_rx, rec, &rec_sz, app_rx, &app_sz )==FD_TLSREC_ERR_PROTO );
      FD_TEST( cli->hs.base.reason==FD_TLS_REASON_PEER_ALERT && !rec_sz );
      continue;
    }

    /* An application-epoch alert before the client Finished consumes
       sequence zero.  Receiving Finished must not reset that counter. */
    uchar cancel[] = { 1, FD_TLS_ALERT_USER_CANCELED };
    ulong rec_sz = test_tlsrec_send_raw( srv, rec, cancel, sizeof(cancel), FD_TLS_REC_ALERT );
    fd_tlsrec_slice_init( tcp_rx, rec, rec_sz );
    ulong tx_sz = sizeof(tcp_tx); app_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( cli, tcp_rx, tcp_tx, &tx_sz, app_rx, &app_sz )==FD_TLSREC_SUCCESS );
    FD_TEST( cli->read_seq==1UL );
    srv_sz = sizeof(server_flight);
    test_tlsrec_ccs_flight( cli, srv, client_flight, cli_sz, server_flight, &srv_sz );
    FD_TEST( fd_tlsrec_conn_is_ready( srv ) && !srv_sz && srv->write_seq==1UL );
    uchar data[] = { 'x' };
    fd_tlsrec_slice_t app_tx[1];
    fd_tlsrec_slice_init( app_tx, data, sizeof(data) );
    rec_sz = sizeof(rec);
    FD_TEST( fd_tlsrec_conn_tx( srv, rec, &rec_sz, app_tx )==FD_TLSREC_SUCCESS );
    fd_tlsrec_slice_init( tcp_rx, rec, rec_sz );
    tx_sz = sizeof(tcp_tx); app_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( cli, tcp_rx, tcp_tx, &tx_sz, app_rx, &app_sz )==FD_TLSREC_SUCCESS );
    FD_TEST( !tx_sz && app_sz==1UL && app_rx[0]=='x' && cli->read_seq==2UL );
  }
}

/* RFC 8446 Section 5.1: handshake messages must not be interleaved
   with other record types.  A handshake message split across records
   must be completed before application_data or alert records arrive.
   CCS is independently rejected outside its compatibility window. */

static void
test_tlsrec_hs_interleave( fd_rng_t * rng ) {
  fd_tls_test_sign_ctx_t sign_ctx[1];
  fd_tls_test_sign_ctx( sign_ctx, rng );
  fd_chacha_rng_t chacha[1];
  fd_tls_t tls = {
    .rng  = fd_tls_test_rand( chacha, rng ),
    .sign = fd_tls_test_sign( sign_ctx ),
  };
  for( ulong j=0UL; j<32UL; j++ ) tls.kex_private_key[j] = fd_rng_uchar( rng );
  fd_x25519_public( tls.kex_public_key, tls.kex_private_key );
  fd_memcpy( tls.cert_public_key, sign_ctx->public_key, 32UL );
  fd_x509_mock_cert( tls.cert_x509, tls.cert_public_key );
  tls.cert_x509_sz = FD_X509_MOCK_CERT_SZ;

  /* KeyUpdate { type=0x18, length=1, update_not_requested } split so the
     first record ends inside the message header */
  static uchar const ku_head[] = { 0x18, 0x00, 0x00 };
  static uchar const ku_tail[] = { 0x01, 0x00 };
  static uchar const app    [] = { 'x' };
  static uchar const alert  [] = { 0x01, 0x00 };  /* warning close_notify */
  static uchar const ccs    [] = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };

  struct { uchar const * p; ulong sz; uchar ct; int plaintext; int ok; } const cases[] = {
    { ku_tail, sizeof(ku_tail), FD_TLS_REC_HANDSHAKE,        0, 1 },
    { app,     sizeof(app),     FD_TLS_REC_APPLICATION_DATA, 0, 0 },
    { alert,   sizeof(alert),   FD_TLS_REC_ALERT,            0, 0 },
    { ccs,     sizeof(ccs),     0,                           1, 0 },
  };

  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    static fd_tlsrec_conn_t cli[1], srv[1];
    static uchar rec[ FD_TLSREC_CAP ], tcp_tx[ FD_TLSREC_CAP ], app_rx[ FD_TLSREC_CAP ];
    test_tlsrec_connect( &tls, cli, srv );

    fd_tlsrec_slice_t tcp_rx[1];
    ulong rec_sz = test_tlsrec_send_raw( srv, rec, ku_head, sizeof(ku_head), FD_TLS_REC_HANDSHAKE );
    fd_tlsrec_slice_init( tcp_rx, rec, rec_sz );
    ulong tcp_tx_sz = sizeof(tcp_tx), app_rx_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( cli, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
    FD_TEST( !tcp_tx_sz && !app_rx_sz );
    FD_TEST( cli->hs_rbuf.sz==sizeof(ku_head) );

    if( cases[i].plaintext ) {
      fd_tlsrec_slice_init( tcp_rx, (uchar *)cases[i].p, cases[i].sz );
    } else {
      rec_sz = test_tlsrec_send_raw( srv, rec, cases[i].p, cases[i].sz, cases[i].ct );
      fd_tlsrec_slice_init( tcp_rx, rec, rec_sz );
    }
    tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
    int rc = fd_tlsrec_conn_rx( cli, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz );
    if( cases[i].ok ) {
      /* The completed KeyUpdate rotates the read keys */
      FD_TEST( rc==FD_TLSREC_SUCCESS );
      FD_TEST( !cli->hs_rbuf.sz );
      FD_TEST( !cli->read_seq );
      FD_TEST( !fd_tlsrec_conn_is_failed( cli ) );
    } else {
      FD_TEST( rc==FD_TLSREC_ERR_PROTO );
      FD_TEST( fd_tlsrec_conn_is_failed( cli ) );
      FD_TEST( cli->hs.base.reason==(cases[i].plaintext ? FD_TLS_REASON_CCS : FD_TLS_REASON_HS_INTERLEAVED) );
      FD_TEST( !app_rx_sz );
    }
  }
}

/* A message that changes the read keys must end its record (RFC 8446
   Section 5.1): nothing authenticated under the old keys may follow it.
   Decrypted content is bounded at 2^14 bytes (Section 5.4) even though
   the ciphertext may be 256 bytes larger. */

static void
test_tlsrec_key_change_boundary( fd_rng_t * rng ) {
  fd_tls_test_sign_ctx_t sign_ctx[1];
  fd_tls_test_sign_ctx( sign_ctx, rng );
  fd_chacha_rng_t chacha[1];
  fd_tls_t tls = {
    .rng  = fd_tls_test_rand( chacha, rng ),
    .sign = fd_tls_test_sign( sign_ctx ),
  };
  for( ulong j=0UL; j<32UL; j++ ) tls.kex_private_key[j] = fd_rng_uchar( rng );
  fd_x25519_public( tls.kex_public_key, tls.kex_private_key );
  fd_memcpy( tls.cert_public_key, sign_ctx->public_key, 32UL );
  fd_x509_mock_cert( tls.cert_x509, tls.cert_public_key );
  tls.cert_x509_sz = FD_X509_MOCK_CERT_SZ;

  static uchar const ku[]      = { 0x18, 0x00, 0x00, 0x01, 0x00 };
  static uchar const ku_ku[]   = { 0x18, 0x00, 0x00, 0x01, 0x00, 0x18, 0x00, 0x00, 0x01, 0x00 };
  static uchar const ku_frag[] = { 0x18, 0x00, 0x00, 0x01, 0x00, 0x18 };
  static uchar big[ FD_TLSREC_PLAINTEXT_MAX+1UL ];
  memset( big, 'b', sizeof(big) );

  struct { uchar const * p; ulong sz; uchar ct; int rc; ushort reason; ulong app_sz; } const cases[] = {
    { ku,      sizeof(ku),      FD_TLS_REC_HANDSHAKE,        FD_TLSREC_SUCCESS,   0,                            0UL                     },
    { ku_ku,   sizeof(ku_ku),   FD_TLS_REC_HANDSHAKE,        FD_TLSREC_ERR_PROTO, FD_TLS_REASON_HS_KEY_CHANGE,  0UL                     },
    { ku_frag, sizeof(ku_frag), FD_TLS_REC_HANDSHAKE,        FD_TLSREC_ERR_PROTO, FD_TLS_REASON_HS_KEY_CHANGE,  0UL                     },
    { big,     sizeof(big)-1UL, FD_TLS_REC_APPLICATION_DATA, FD_TLSREC_SUCCESS,   0,                            FD_TLSREC_PLAINTEXT_MAX },
    { big,     sizeof(big),     FD_TLS_REC_APPLICATION_DATA, FD_TLSREC_ERR_PROTO, FD_TLS_REASON_REC_OVERFLOW,   0UL                     },
    { big,     sizeof(big),     FD_TLS_REC_HANDSHAKE,        FD_TLSREC_ERR_PROTO, FD_TLS_REASON_REC_OVERFLOW,   0UL                     },
  };

  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    static fd_tlsrec_conn_t cli[1], srv[1];
    static uchar rec[ FD_TLSREC_CAP ], tcp_tx[ FD_TLSREC_CAP ], app_rx[ FD_TLSREC_CAP ];
    test_tlsrec_connect( &tls, cli, srv );

    ulong rec_sz = test_tlsrec_send_raw( srv, rec, cases[i].p, cases[i].sz, cases[i].ct );
    fd_tlsrec_slice_t tcp_rx[1];
    fd_tlsrec_slice_init( tcp_rx, rec, rec_sz );
    ulong tcp_tx_sz = sizeof(tcp_tx), app_rx_sz = sizeof(app_rx);
    int rc = fd_tlsrec_conn_rx( cli, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz );
    FD_TEST( rc==cases[i].rc );
    FD_TEST( app_rx_sz==cases[i].app_sz );
    if( rc ) {
      FD_TEST( fd_tlsrec_conn_is_failed( cli ) );
      FD_TEST( cli->hs.base.reason==cases[i].reason );
    } else {
      FD_TEST( !fd_tlsrec_conn_is_failed( cli ) );
      FD_TEST( cli->read_seq==( cases[i].ct==FD_TLS_REC_HANDSHAKE ? 0UL : 1UL ) );
    }
  }
}

/* However many KeyUpdates the peer requests in one call, a single reply
   answers them all (RFC 8446 Section 4.6.3), so a small tx buffer is
   never a fatal condition.  Without room for even that, the reply waits
   for the next call. */

static void
test_tlsrec_key_update_flood( fd_rng_t * rng ) {
  fd_tls_test_sign_ctx_t sign_ctx[1];
  fd_tls_test_sign_ctx( sign_ctx, rng );
  fd_chacha_rng_t chacha[1];
  fd_tls_t tls = {
    .rng  = fd_tls_test_rand( chacha, rng ),
    .sign = fd_tls_test_sign( sign_ctx ),
  };
  for( ulong j=0UL; j<32UL; j++ ) tls.kex_private_key[j] = fd_rng_uchar( rng );
  fd_x25519_public( tls.kex_public_key, tls.kex_private_key );
  fd_memcpy( tls.cert_public_key, sign_ctx->public_key, 32UL );
  fd_x509_mock_cert( tls.cert_x509, tls.cert_public_key );
  tls.cert_x509_sz = FD_X509_MOCK_CERT_SZ;

  static fd_tlsrec_conn_t cli[1], srv[1];
  static uchar wire[ 2*FD_TLSREC_CAP ], app_rx[ FD_TLSREC_CAP ];
  test_tlsrec_connect( &tls, cli, srv );

  ulong const n_updates = 40UL;
  ulong wire_sz = 0UL;
  for( ulong i=0UL; i<n_updates; i++ ) {
    ulong sz = sizeof(wire)-wire_sz;
    FD_TEST( fd_tlsrec_conn_key_update( srv, wire+wire_sz, &sz, 1 )==FD_TLSREC_SUCCESS );
    FD_TEST( sz==27UL );
    wire_sz += sz;
  }

  /* 40 requests need 1080 bytes of replies if answered one by one; the
     socket adapter guarantees only 512 */
  uchar tcp_tx[ 512 ];
  fd_tlsrec_slice_t tcp_rx[1];
  fd_tlsrec_slice_init( tcp_rx, wire, wire_sz );
  ulong tcp_tx_sz = sizeof(tcp_tx), app_rx_sz = sizeof(app_rx);
  FD_TEST( fd_tlsrec_conn_rx( cli, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
  FD_TEST( fd_tlsrec_slice_is_empty( tcp_rx ) );
  FD_TEST( tcp_tx_sz==27UL );
  FD_TEST( !app_rx_sz );
  FD_TEST( !cli->key_update_pending );
  FD_TEST( !cli->read_seq && !cli->write_seq );

  /* The server processes the reply and both directions still work */
  fd_tlsrec_slice_init( tcp_rx, tcp_tx, tcp_tx_sz );
  ulong srv_tx_sz = sizeof(wire); app_rx_sz = sizeof(app_rx);
  FD_TEST( fd_tlsrec_conn_rx( srv, tcp_rx, wire, &srv_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
  FD_TEST( !srv_tx_sz && !app_rx_sz );
  FD_TEST( !srv->read_seq );

  static uchar const ping[] = "ping";
  fd_tlsrec_slice_t app_tx[1];
  for( uint dir=0U; dir<2U; dir++ ) {
    fd_tlsrec_conn_t * a = dir ? srv : cli;
    fd_tlsrec_conn_t * b = dir ? cli : srv;
    fd_tlsrec_slice_init( app_tx, (uchar *)ping, sizeof(ping) );
    wire_sz = sizeof(wire);
    FD_TEST( fd_tlsrec_conn_tx( a, wire, &wire_sz, app_tx )==FD_TLSREC_SUCCESS );
    fd_tlsrec_slice_init( tcp_rx, wire, wire_sz );
    tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( b, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
    FD_TEST( app_rx_sz==sizeof(ping) && !memcmp( app_rx, ping, sizeof(ping) ) );
    FD_TEST( !tcp_tx_sz );
  }

  /* No room at all: the reply is deferred to the next tx */
  wire_sz = sizeof(wire);
  FD_TEST( fd_tlsrec_conn_key_update( srv, wire, &wire_sz, 1 )==FD_TLSREC_SUCCESS );
  fd_tlsrec_slice_init( tcp_rx, wire, wire_sz );
  tcp_tx_sz = 0UL; app_rx_sz = sizeof(app_rx);
  FD_TEST( fd_tlsrec_conn_rx( cli, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
  FD_TEST( !tcp_tx_sz );
  FD_TEST( cli->key_update_pending );
  fd_tlsrec_slice_init( app_tx, (uchar *)ping, sizeof(ping) );
  wire_sz = sizeof(wire);
  FD_TEST( fd_tlsrec_conn_tx( cli, wire, &wire_sz, app_tx )==FD_TLSREC_SUCCESS );
  FD_TEST( !cli->key_update_pending );
  FD_TEST( wire_sz==27UL+sizeof(fd_tlsrec_hdr_t)+sizeof(ping)+1UL+FD_AES_GCM_TAG_SZ );
  fd_tlsrec_slice_init( tcp_rx, wire, wire_sz );
  tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
  FD_TEST( fd_tlsrec_conn_rx( srv, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
  FD_TEST( app_rx_sz==sizeof(ping) && !memcmp( app_rx, ping, sizeof(ping) ) );
}

/* A failing endpoint tells the peer why with a fatal alert under the
   keys in force, and a local close_notify closes the write side only. */

static void
test_tlsrec_alert_tx( fd_rng_t * rng ) {
  fd_tls_test_sign_ctx_t sign_ctx[1];
  fd_tls_test_sign_ctx( sign_ctx, rng );
  fd_chacha_rng_t chacha[1];
  fd_tls_t tls = {
    .rng  = fd_tls_test_rand( chacha, rng ),
    .sign = fd_tls_test_sign( sign_ctx ),
  };
  for( ulong j=0UL; j<32UL; j++ ) tls.kex_private_key[j] = fd_rng_uchar( rng );
  fd_x25519_public( tls.kex_public_key, tls.kex_private_key );
  fd_memcpy( tls.cert_public_key, sign_ctx->public_key, 32UL );
  fd_x509_mock_cert( tls.cert_x509, tls.cert_public_key );
  tls.cert_x509_sz = FD_X509_MOCK_CERT_SZ;

  static fd_tlsrec_conn_t cli[1], srv[1];
  static uchar wire[ FD_TLSREC_CAP ], tcp_tx[ FD_TLSREC_CAP ], app_rx[ FD_TLSREC_CAP ];
  ulong const alert_rec_sz = sizeof(fd_tlsrec_hdr_t)+2UL+1UL+FD_AES_GCM_TAG_SZ;
  fd_tlsrec_slice_t tcp_rx[1];
  ulong tcp_tx_sz, app_rx_sz;

  /* Established: a record with a bad tag draws an encrypted
     bad_record_mac that the peer decodes as a fatal alert */
  test_tlsrec_connect( &tls, cli, srv );
  static uchar const app[] = { 'x' };
  ulong sz = test_tlsrec_send_raw( srv, wire, app, sizeof(app), FD_TLS_REC_APPLICATION_DATA );
  wire[ sz-1UL ] ^= 1U;
  fd_tlsrec_slice_init( tcp_rx, wire, sz );
  tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
  FD_TEST( fd_tlsrec_conn_rx( cli, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_ERR_CRYPTO );
  FD_TEST( fd_tlsrec_conn_is_failed( cli ) );
  FD_TEST( cli->hs.base.reason==FD_TLS_REASON_REC_MAC );
  FD_TEST( cli->tx_closed );
  FD_TEST( tcp_tx_sz==alert_rec_sz && !app_rx_sz );
  FD_TEST( tcp_tx[0]==FD_TLS_REC_APPLICATION_DATA );  /* encrypted */

  fd_tlsrec_slice_init( tcp_rx, tcp_tx, tcp_tx_sz );
  ulong srv_tx_sz = sizeof(wire); app_rx_sz = sizeof(app_rx);
  FD_TEST( fd_tlsrec_conn_rx( srv, tcp_rx, wire, &srv_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_ERR_PROTO );
  FD_TEST( srv->hs.base.reason==FD_TLS_REASON_PEER_ALERT );
  FD_TEST( !srv_tx_sz );  /* no alert in reply to an alert */

  /* Mid-handshake: a client holding handshake keys alerts under them */
  FD_TEST( fd_tlsrec_conn_init( cli, &tls, 0 )==cli );
  FD_TEST( fd_tlsrec_conn_init( srv, &tls, 1 )==srv );
  fd_memcpy( cli->hs.cli.server_pubkey, tls.cert_public_key, 32UL );
  tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
  FD_TEST( fd_tlsrec_conn_rx( cli, NULL, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
  fd_tlsrec_slice_init( tcp_rx, tcp_tx, tcp_tx_sz );
  srv_tx_sz = sizeof(wire); app_rx_sz = sizeof(app_rx);
  FD_TEST( fd_tlsrec_conn_rx( srv, tcp_rx, wire, &srv_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
  FD_TEST( srv->tx_level==FD_TLS_LEVEL_APPLICATION );  /* its Finished is out */
  /* corrupt the last byte of the server flight (inside Finished) */
  wire[ srv_tx_sz-1UL ] ^= 1U;
  fd_tlsrec_slice_init( tcp_rx, wire, srv_tx_sz );
  tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
  FD_TEST( fd_tlsrec_conn_rx( cli, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_ERR_CRYPTO );
  FD_TEST( cli->tx_level==FD_TLS_LEVEL_HANDSHAKE );
  FD_TEST( tcp_tx_sz==alert_rec_sz );
  FD_TEST( tcp_tx[0]==FD_TLS_REC_APPLICATION_DATA );
  /* the server, waiting for the client Finished, decodes it under
     handshake keys */
  fd_tlsrec_slice_init( tcp_rx, tcp_tx, tcp_tx_sz );
  srv_tx_sz = sizeof(wire); app_rx_sz = sizeof(app_rx);
  FD_TEST( fd_tlsrec_conn_rx( srv, tcp_rx, wire, &srv_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_ERR_PROTO );
  FD_TEST( srv->hs.base.reason==FD_TLS_REASON_PEER_ALERT );

  /* Local close: close_notify goes out, tx is refused, rx still works */
  test_tlsrec_connect( &tls, cli, srv );
  tcp_tx_sz = sizeof(tcp_tx);
  FD_TEST( fd_tlsrec_conn_close( cli, tcp_tx, &tcp_tx_sz )==FD_TLSREC_SUCCESS );
  FD_TEST( tcp_tx_sz==alert_rec_sz );
  FD_TEST( cli->tx_closed && !fd_tlsrec_conn_is_failed( cli ) );
  tcp_tx_sz = sizeof(tcp_tx);
  FD_TEST( fd_tlsrec_conn_close( cli, tcp_tx, &tcp_tx_sz )==FD_TLSREC_ERR_STATE );
  FD_TEST( !tcp_tx_sz );

  fd_tlsrec_slice_t app_tx[1];
  fd_tlsrec_slice_init( app_tx, (uchar *)app, sizeof(app) );
  tcp_tx_sz = sizeof(tcp_tx);
  FD_TEST( fd_tlsrec_conn_tx( cli, tcp_tx, &tcp_tx_sz, app_tx )==FD_TLSREC_ERR_STATE );
  tcp_tx_sz = sizeof(tcp_tx);
  FD_TEST( fd_tlsrec_conn_key_update( cli, tcp_tx, &tcp_tx_sz, 0 )==FD_TLSREC_ERR_STATE );

  tcp_tx_sz = sizeof(tcp_tx);
  FD_TEST( fd_tlsrec_conn_close( cli, tcp_tx, &tcp_tx_sz )==FD_TLSREC_ERR_STATE );
  FD_TEST( fd_tlsrec_conn_init( cli, &tls, 0 )==cli );
  test_tlsrec_connect( &tls, cli, srv );
  tcp_tx_sz = sizeof(tcp_tx);
  FD_TEST( fd_tlsrec_conn_close( cli, tcp_tx, &tcp_tx_sz )==FD_TLSREC_SUCCESS );
  fd_tlsrec_slice_init( tcp_rx, tcp_tx, tcp_tx_sz );
  srv_tx_sz = sizeof(wire); app_rx_sz = sizeof(app_rx);
  FD_TEST( fd_tlsrec_conn_rx( srv, tcp_rx, wire, &srv_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
  FD_TEST( srv->rx_closed && !srv->tx_closed && !srv_tx_sz );

  fd_tlsrec_slice_init( app_tx, (uchar *)app, sizeof(app) );
  srv_tx_sz = sizeof(wire);
  FD_TEST( fd_tlsrec_conn_tx( srv, wire, &srv_tx_sz, app_tx )==FD_TLSREC_SUCCESS );
  fd_tlsrec_slice_init( tcp_rx, wire, srv_tx_sz );
  tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
  FD_TEST( fd_tlsrec_conn_rx( cli, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
  FD_TEST( app_rx_sz==sizeof(app) && app_rx[0]=='x' && !tcp_tx_sz );

  /* Too small a buffer leaves the write side open */
  test_tlsrec_connect( &tls, cli, srv );
  tcp_tx_sz = alert_rec_sz-1UL;
  FD_TEST( fd_tlsrec_conn_close( cli, tcp_tx, &tcp_tx_sz )==FD_TLSREC_ERR_OOM );
  FD_TEST( !tcp_tx_sz && !cli->tx_closed );
}

/* A server that rejects the ClientHello has no keys yet and answers
   with a plaintext alert.  The client must surface that as a fatal
   handshake error instead of treating the record as garbage. */

static void
test_tlsrec_plaintext_alert( fd_rng_t * rng ) {
  fd_chacha_rng_t chacha[1];
  fd_tls_t tls = { .rng = fd_tls_test_rand( chacha, rng ) };
  for( ulong j=0UL; j<32UL; j++ ) tls.kex_private_key[j] = fd_rng_uchar( rng );
  fd_x25519_public( tls.kex_public_key, tls.kex_private_key );

  static uchar tcp_tx[ FD_TLSREC_CAP ];
  static uchar app_rx[ FD_TLSREC_CAP ];

  static uchar const alert_hs_fail [] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 40 };
  static uchar const alert_version [] = { 0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 70 };
  static uchar const alert_warn    [] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 40 };
  static uchar const alert_close   [] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x01,  0 };
  static uchar const alert_cancel  [] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 90 };
  static uchar const alert_cancel2 [] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 90 };
  static uchar const alert_short   [] = { 0x15, 0x03, 0x03, 0x00, 0x01, 0x02 };
  static uchar const alert_long    [] = { 0x15, 0x03, 0x03, 0x00, 0x04, 0x02, 40, 0x02, 40 };
  static uchar const alert_empty   [] = { 0x15, 0x03, 0x03, 0x00, 0x00 };
  struct { uchar const * rec; ulong sz; int rc; ushort reason; } const cases[] = {
    { alert_hs_fail, sizeof(alert_hs_fail), FD_TLSREC_ERR_PROTO, FD_TLS_REASON_PEER_ALERT  },
    { alert_version, sizeof(alert_version), FD_TLSREC_ERR_PROTO, FD_TLS_REASON_PEER_ALERT  },
    { alert_warn,    sizeof(alert_warn),    FD_TLSREC_ERR_PROTO, FD_TLS_REASON_PEER_ALERT  },
    { alert_close,   sizeof(alert_close),   FD_TLSREC_SUCCESS,   0                         },
    { alert_cancel,  sizeof(alert_cancel),  FD_TLSREC_SUCCESS,   0                         },
    { alert_cancel2, sizeof(alert_cancel2), FD_TLSREC_SUCCESS,   0                         },
    { alert_short,   sizeof(alert_short),   FD_TLSREC_ERR_PROTO, FD_TLS_REASON_ALERT_PARSE },
    { alert_long,    sizeof(alert_long),    FD_TLSREC_ERR_PROTO, FD_TLS_REASON_ALERT_PARSE },
    { alert_empty,   sizeof(alert_empty),   FD_TLSREC_ERR_PROTO, FD_TLS_REASON_ALERT_PARSE },
  };

  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    static fd_tlsrec_conn_t client[1];
    FD_TEST( fd_tlsrec_conn_init( client, &tls, 0 )==client );
    ulong tcp_tx_sz = sizeof(tcp_tx), app_rx_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( client, NULL, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
    FD_TEST( client->hs.base.state==FD_TLS_HS_WAIT_SH );

    /* Deliver byte-by-byte to exercise record reassembly */
    for( ulong frag=1UL; frag<=cases[i].sz; frag++ ) {
      FD_TEST( fd_tlsrec_conn_init( client, &tls, 0 )==client );
      tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
      FD_TEST( fd_tlsrec_conn_rx( client, NULL, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );

      int rc = FD_TLSREC_SUCCESS;
      for( ulong off=0UL; off<cases[i].sz && rc==FD_TLSREC_SUCCESS; off+=frag ) {
        fd_tlsrec_slice_t tcp_rx[1];
        fd_tlsrec_slice_init( tcp_rx, (uchar *)cases[i].rec+off, fd_ulong_min( frag, cases[i].sz-off ) );
        tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
        rc = fd_tlsrec_conn_rx( client, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz );
        FD_TEST( rc!=FD_TLSREC_SUCCESS || fd_tlsrec_slice_is_empty( tcp_rx ) );
      }
      FD_TEST( rc==cases[i].rc );
      FD_TEST( app_rx_sz==0UL );
      if( cases[i].rc==FD_TLSREC_SUCCESS ) {
        FD_TEST( !fd_tlsrec_conn_is_failed( client ) );
        FD_TEST( client->rx_closed==(cases[i].rec[6]==FD_TLS_ALERT_CLOSE_NOTIFY) );
        FD_TEST( client->hs.base.state==FD_TLS_HS_WAIT_SH );
      } else {
        FD_TEST( fd_tlsrec_conn_is_failed( client ) );
        FD_TEST( client->hs.base.reason==cases[i].reason );
      }
    }
  }

  /* Non-handshake, non-alert plaintext is still rejected */
  do {
    static fd_tlsrec_conn_t client[1];
    FD_TEST( fd_tlsrec_conn_init( client, &tls, 0 )==client );
    ulong tcp_tx_sz = sizeof(tcp_tx), app_rx_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( client, NULL, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
    static uchar const appdata[] = { 0x17, 0x03, 0x03, 0x00, 0x02, 0x02, 40 };
    fd_tlsrec_slice_t tcp_rx[1];
    fd_tlsrec_slice_init( tcp_rx, (uchar *)appdata, sizeof(appdata) );
    tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( client, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_ERR_PROTO );
  } while(0);

  /* Once the server has sent ServerHello it holds write keys, so a
     client past WAIT_SH treats a plaintext alert as an unauthenticated
     stray record rather than a peer alert. */
  do {
    static fd_tlsrec_conn_t client[1];
    FD_TEST( fd_tlsrec_conn_init( client, &tls, 0 )==client );
    ulong tcp_tx_sz = sizeof(tcp_tx), app_rx_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( client, NULL, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
    client->hs.base.state = FD_TLS_HS_WAIT_EE;
    fd_tlsrec_slice_t tcp_rx[1];
    fd_tlsrec_slice_init( tcp_rx, (uchar *)alert_hs_fail, sizeof(alert_hs_fail) );
    tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( client, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_ERR_PROTO );
    FD_TEST( fd_tlsrec_conn_is_failed( client ) );
    FD_TEST( client->hs.base.reason==FD_TLS_REASON_REC_TYPE );
  } while(0);

  /* A client only installs write keys right before its Finished, so a
     server accepts a plaintext alert until then (OpenSSL clients reject
     the server certificate this way). */
  do {
    static fd_tlsrec_conn_t server[1];
    FD_TEST( fd_tlsrec_conn_init( server, &tls, 1 )==server );
    server->hs.base.state = FD_TLS_HS_WAIT_FINISHED;
    fd_tlsrec_slice_t tcp_rx[1];
    fd_tlsrec_slice_init( tcp_rx, (uchar *)alert_hs_fail, sizeof(alert_hs_fail) );
    ulong tcp_tx_sz = sizeof(tcp_tx), app_rx_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( server, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_ERR_PROTO );
    FD_TEST( fd_tlsrec_conn_is_failed( server ) );
    FD_TEST( server->hs.base.reason==FD_TLS_REASON_PEER_ALERT );
  } while(0);
}

/* A close_notify alert closes the receive side.  Plaintext delivered
   before it in the same call survives; records after it are discarded
   without being decrypted, and later calls consume input without
   producing anything.  The write side stays usable (half-close). */

static void
test_tlsrec_close_notify( fd_rng_t * rng ) {
  fd_tls_test_sign_ctx_t sign_ctx[1];
  fd_tls_test_sign_ctx( sign_ctx, rng );
  fd_chacha_rng_t chacha[1];
  fd_tls_t tls = {
    .rng  = fd_tls_test_rand( chacha, rng ),
    .sign = fd_tls_test_sign( sign_ctx ),
  };
  for( ulong j=0UL; j<32UL; j++ ) tls.kex_private_key[j] = fd_rng_uchar( rng );
  fd_x25519_public( tls.kex_public_key, tls.kex_private_key );
  fd_memcpy( tls.cert_public_key, sign_ctx->public_key, 32UL );
  fd_x509_mock_cert( tls.cert_x509, tls.cert_public_key );
  tls.cert_x509_sz = FD_X509_MOCK_CERT_SZ;

  static fd_tlsrec_conn_t cli[1], srv[1];
  static uchar wire[ 3*FD_TLSREC_CAP ], tcp_tx[ FD_TLSREC_CAP ], app_rx[ FD_TLSREC_CAP ];
  test_tlsrec_connect( &tls, cli, srv );
  FD_TEST( !cli->rx_closed );

  static uchar const before[] = "before";
  static uchar const after [] = "after";
  static uchar const close [] = { 0x01, 0x00 };  /* warning close_notify */
  ulong sz  = test_tlsrec_send_raw( srv, wire,    before, sizeof(before), FD_TLS_REC_APPLICATION_DATA );
        sz += test_tlsrec_send_raw( srv, wire+sz, close,  sizeof(close),  FD_TLS_REC_ALERT            );
        sz += test_tlsrec_send_raw( srv, wire+sz, after,  sizeof(after),  FD_TLS_REC_APPLICATION_DATA );

  fd_tlsrec_slice_t tcp_rx[1];
  fd_tlsrec_slice_init( tcp_rx, wire, sz );
  ulong tcp_tx_sz = sizeof(tcp_tx), app_rx_sz = sizeof(app_rx);
  FD_TEST( fd_tlsrec_conn_rx( cli, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
  FD_TEST( fd_tlsrec_slice_is_empty( tcp_rx ) );
  FD_TEST( !tcp_tx_sz );
  FD_TEST( app_rx_sz==sizeof(before) && 0==memcmp( app_rx, before, sizeof(before) ) );
  FD_TEST( cli->rx_closed );
  FD_TEST( !fd_tlsrec_conn_is_failed( cli ) );
  FD_TEST( cli->read_seq==2UL );  /* the record after close_notify was not decrypted */

  /* Anything else, even garbage, is swallowed */
  static uchar const junk[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  fd_tlsrec_slice_init( tcp_rx, (uchar *)junk, sizeof(junk) );
  tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
  FD_TEST( fd_tlsrec_conn_rx( cli, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
  FD_TEST( fd_tlsrec_slice_is_empty( tcp_rx ) );
  FD_TEST( !tcp_tx_sz && !app_rx_sz );
  FD_TEST( !fd_tlsrec_conn_is_failed( cli ) );

  /* Write side still open: the server decrypts what the client sends */
  fd_tlsrec_slice_t app_tx[1];
  fd_tlsrec_slice_init( app_tx, (uchar *)after, sizeof(after) );
  tcp_tx_sz = sizeof(tcp_tx);
  FD_TEST( fd_tlsrec_conn_tx( cli, tcp_tx, &tcp_tx_sz, app_tx )==FD_TLSREC_SUCCESS );
  FD_TEST( fd_tlsrec_slice_is_empty( app_tx ) && tcp_tx_sz );
  fd_tlsrec_slice_init( tcp_rx, tcp_tx, tcp_tx_sz );
  ulong srv_tx_sz = sizeof(wire); app_rx_sz = sizeof(app_rx);
  FD_TEST( fd_tlsrec_conn_rx( srv, tcp_rx, wire, &srv_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
  FD_TEST( app_rx_sz==sizeof(after) && 0==memcmp( app_rx, after, sizeof(after) ) );
  FD_TEST( !srv->rx_closed );
}

/* fd_tlsrec_sock_rx reports a close_notify as EOF once the plaintext
   before it was consumed, even if the TCP connection stays open. */

static void
test_tlsrec_sock_close_notify( fd_rng_t * rng ) {
  fd_tls_test_sign_ctx_t sign_ctx[1];
  fd_tls_test_sign_ctx( sign_ctx, rng );
  fd_chacha_rng_t chacha[1];
  fd_tls_t tls = {
    .rng  = fd_tls_test_rand( chacha, rng ),
    .sign = fd_tls_test_sign( sign_ctx ),
  };
  for( ulong j=0UL; j<32UL; j++ ) tls.kex_private_key[j] = fd_rng_uchar( rng );
  fd_x25519_public( tls.kex_public_key, tls.kex_private_key );
  fd_memcpy( tls.cert_public_key, sign_ctx->public_key, 32UL );
  fd_x509_mock_cert( tls.cert_x509, tls.cert_public_key );
  tls.cert_x509_sz = FD_X509_MOCK_CERT_SZ;

  static fd_tlsrec_conn_t cli[1], srv[1];
  static fd_tlsrec_sock_t sock[1];
  static uchar wire[ 2*FD_TLSREC_CAP ];
  test_tlsrec_connect( &tls, cli, srv );
  fd_tlsrec_sock_init( sock );

  int fds[2];
  FD_TEST( !socketpair( AF_UNIX, SOCK_STREAM, 0, fds ) );

  static uchar const before[] = "before";
  static uchar const close_ [] = { 0x01, 0x00 };
  ulong sz  = test_tlsrec_send_raw( srv, wire,    before, sizeof(before), FD_TLS_REC_APPLICATION_DATA );
        sz += test_tlsrec_send_raw( srv, wire+sz, close_, sizeof(close_), FD_TLS_REC_ALERT            );
  FD_TEST( write( fds[1], wire, sz )==(long)sz );

  ulong tcp_rx_sz;
  FD_TEST( fd_tlsrec_sock_rx( sock, cli, fds[0], &tcp_rx_sz )==0 );
  FD_TEST( tcp_rx_sz==sz );
  FD_TEST( cli->rx_closed );
  FD_TEST( fd_tlsrec_sock_rx_avail( sock )==sizeof(before) );
  FD_TEST( 0==memcmp( fd_tlsrec_sock_rx_data( sock ), before, sizeof(before) ) );

  /* Plaintext still held: no EOF yet */
  FD_TEST( fd_tlsrec_sock_rx( sock, cli, fds[0], &tcp_rx_sz )==0 );
  FD_TEST( fd_tlsrec_sock_rx_avail( sock )==sizeof(before) );

  fd_tlsrec_sock_rx_consume( sock, sizeof(before) );
  FD_TEST( fd_tlsrec_sock_rx( sock, cli, fds[0], &tcp_rx_sz )==FD_TLSREC_SOCK_ERR_EOF );

  /* close_notify arriving in its own call with no plaintext is EOF immediately */
  static fd_tlsrec_conn_t cli2[1], srv2[1];
  test_tlsrec_connect( &tls, cli2, srv2 );
  fd_tlsrec_sock_init( sock );
  sz = test_tlsrec_send_raw( srv2, wire, close_, sizeof(close_), FD_TLS_REC_ALERT );
  FD_TEST( write( fds[1], wire, sz )==(long)sz );
  FD_TEST( fd_tlsrec_sock_rx( sock, cli2, fds[0], &tcp_rx_sz )==FD_TLSREC_SOCK_ERR_EOF );
  FD_TEST( cli2->rx_closed );

  /* fd_tlsrec_sock_close sends close_notify, which the peer sees as EOF */
  static fd_tlsrec_sock_t srv_sock[1];
  fd_tlsrec_sock_init( srv_sock );
  FD_TEST( fd_tlsrec_sock_close( sock, cli2, fds[0] )==0 );
  FD_TEST( cli2->tx_closed );
  FD_TEST( fd_tlsrec_sock_close( sock, cli2, fds[0] )==FD_TLSREC_ERR_STATE );
  FD_TEST( fd_tlsrec_sock_rx( srv_sock, srv2, fds[1], &tcp_rx_sz )==FD_TLSREC_SOCK_ERR_EOF );
  FD_TEST( srv2->rx_closed );

  FD_TEST( !close( fds[0] ) );
  FD_TEST( !close( fds[1] ) );
}

/* RFC 8446 Sections 5.1-5.2: ignore the legacy version, but authenticate
   it as AAD.  Encrypted records must have outer type application_data. */

static void
test_tlsrec_rec_hdr( fd_rng_t * rng ) {
  fd_tls_test_sign_ctx_t sign_ctx[1];
  fd_tls_test_sign_ctx( sign_ctx, rng );
  fd_chacha_rng_t chacha[1];
  fd_tls_t tls = {
    .rng  = fd_tls_test_rand( chacha, rng ),
    .sign = fd_tls_test_sign( sign_ctx ),
  };
  for( ulong j=0UL; j<32UL; j++ ) tls.kex_private_key[j] = fd_rng_uchar( rng );
  fd_x25519_public( tls.kex_public_key, tls.kex_private_key );
  fd_memcpy( tls.cert_public_key, sign_ctx->public_key, 32UL );
  fd_x509_mock_cert( tls.cert_x509, tls.cert_public_key );
  tls.cert_x509_sz = FD_X509_MOCK_CERT_SZ;

  static fd_tlsrec_conn_t cli[1], srv[1];
  static uchar rec[ FD_TLSREC_CAP ], tcp_tx[ FD_TLSREC_CAP ], app_rx[ FD_TLSREC_CAP ];
  fd_tlsrec_slice_t tcp_rx[1];
  ulong tcp_tx_sz, app_rx_sz;

  /* Encrypted records with a tampered header */
  static uchar const app[] = { 'x' };
  struct { uchar type; ushort ver; ushort reason; } const enc_cases[] = {
    { FD_TLS_REC_HANDSHAKE,          0x0303, FD_TLS_REASON_REC_TYPE    },
    { FD_TLS_REC_ALERT,              0x0303, FD_TLS_REASON_REC_TYPE    },
    { FD_TLS_REC_CHANGE_CIPHER_SPEC, 0x0303, FD_TLS_REASON_CCS         },
    { FD_TLS_REC_APPLICATION_DATA,   0x0301, FD_TLS_REASON_REC_MAC     },
    { FD_TLS_REC_APPLICATION_DATA,   0x0304, FD_TLS_REASON_REC_MAC     },
    { FD_TLS_REC_ALERT,              0x0301, FD_TLS_REASON_REC_TYPE    },
  };
  for( ulong i=0UL; i<sizeof(enc_cases)/sizeof(enc_cases[0]); i++ ) {
    test_tlsrec_connect( &tls, cli, srv );
    ulong rec_sz = test_tlsrec_send_raw( srv, rec, app, sizeof(app), FD_TLS_REC_APPLICATION_DATA );
    fd_tlsrec_hdr_t * hdr = fd_type_pun( rec );
    hdr->content_type          = enc_cases[i].type;
    hdr->legacy_record_version = fd_ushort_bswap( enc_cases[i].ver );
    fd_tlsrec_slice_init( tcp_rx, rec, rec_sz );
    tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
    int mac = enc_cases[i].reason==FD_TLS_REASON_REC_MAC;
    FD_TEST( fd_tlsrec_conn_rx( cli, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==
             (mac ? FD_TLSREC_ERR_CRYPTO : FD_TLSREC_ERR_PROTO) );
    test_tlsrec_check_alert( cli, tcp_tx, tcp_tx_sz, mac ? FD_TLS_ALERT_BAD_RECORD_MAC : FD_TLS_ALERT_UNEXPECTED_MESSAGE );
    FD_TEST( fd_tlsrec_conn_is_failed( cli ) );
    FD_TEST( cli->hs.base.reason==enc_cases[i].reason );
    FD_TEST( !app_rx_sz );
    FD_TEST( cli->read_seq==0UL );
  }

  /* Both plaintext and authenticated ciphertext ignore every version. */
  ushort const versions[] = {
    0x0301, 0x0303, 0x0300, 0x0302, 0x0304, 0x0000, 0xffff
  };
  for( ulong i=0UL; i<sizeof(versions)/sizeof(versions[0]); i++ ) {
    test_tlsrec_connect( &tls, cli, srv );
    ulong enc_sz = test_tlsrec_send_raw_ex( srv, rec, app, sizeof(app), FD_TLS_REC_APPLICATION_DATA,
                                           0UL, versions[i], 1U );
    tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
    test_tlsrec_rx_fragments( cli, rec, enc_sz, 3UL, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz );
    FD_TEST( !tcp_tx_sz && app_rx_sz==sizeof(app) && !memcmp( app_rx, app, sizeof(app) ) );

    FD_TEST( fd_tlsrec_conn_init( cli, &tls, 0 )==cli );
    FD_TEST( fd_tlsrec_conn_init( srv, &tls, 1 )==srv );
    ulong rec_sz = sizeof(rec); app_rx_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( cli, NULL, rec, &rec_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
    fd_tlsrec_hdr_t * hdr = fd_type_pun( rec );
    hdr->legacy_record_version = fd_ushort_bswap( versions[i] );
    fd_tlsrec_slice_init( tcp_rx, rec, rec_sz );
    tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
    int rc = fd_tlsrec_conn_rx( srv, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz );
    FD_TEST( rc==FD_TLSREC_SUCCESS );
    FD_TEST( tcp_tx_sz );  /* ServerHello flight */
  }

  /* Plaintext ServerHello ignores the legacy version too. */
  do {
    FD_TEST( fd_tlsrec_conn_init( cli, &tls, 0 )==cli );
    FD_TEST( fd_tlsrec_conn_init( srv, &tls, 1 )==srv );
    fd_memcpy( cli->hs.cli.server_pubkey, tls.cert_public_key, 32UL );
    ulong rec_sz = sizeof(rec); app_rx_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( cli, NULL, rec, &rec_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
    fd_tlsrec_slice_init( tcp_rx, rec, rec_sz );
    static uchar srv_tx[ FD_TLSREC_CAP ];
    ulong srv_tx_sz = sizeof(srv_tx); app_rx_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( srv, tcp_rx, srv_tx, &srv_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
    fd_tlsrec_hdr_t * hdr = fd_type_pun( srv_tx );
    FD_TEST( hdr->content_type==FD_TLS_REC_HANDSHAKE );
    hdr->legacy_record_version = fd_ushort_bswap( 0x0301 );
    fd_tlsrec_slice_init( tcp_rx, srv_tx, srv_tx_sz );
    tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( cli, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
    FD_TEST( fd_tlsrec_conn_is_ready( cli ) );
  } while(0);
}

static void
test_tlsrec_inner_plaintext( fd_rng_t * rng ) {
  fd_tls_test_sign_ctx_t sign_ctx[1];
  fd_tls_test_sign_ctx( sign_ctx, rng );
  fd_chacha_rng_t chacha[1];
  fd_tls_t tls = {
    .rng  = fd_tls_test_rand( chacha, rng ),
    .sign = fd_tls_test_sign( sign_ctx ),
  };
  for( ulong j=0UL; j<32UL; j++ ) tls.kex_private_key[j] = fd_rng_uchar( rng );
  fd_x25519_public( tls.kex_public_key, tls.kex_private_key );
  fd_memcpy( tls.cert_public_key, sign_ctx->public_key, 32UL );
  fd_x509_mock_cert( tls.cert_x509, tls.cert_public_key );
  tls.cert_x509_sz = FD_X509_MOCK_CERT_SZ;

  static uchar const ku_bad_value[] = { 24, 0, 0, 1, 2 };
  static uchar const ku_bad_size [] = { 24, 0, 0, 2, 0, 0 };
  static uchar const ku_empty    [] = { 24, 0, 0, 0 };
  static uchar const ccs         [] = { 1 };
  static uchar big[ FD_TLSREC_PLAINTEXT_MAX ];
  memset( big, 'b', sizeof(big) );
  struct {
    uchar const * payload;
    ulong         sz;
    ulong         padding;
    uchar         ct;
    uchar         alert;
  } const cases[] = {
    { big,          sizeof(big),  0UL,     FD_TLS_REC_APPLICATION_DATA,   0                               },
    { big,          sizeof(big),  1UL,     FD_TLS_REC_APPLICATION_DATA,   FD_TLS_ALERT_RECORD_OVERFLOW    },
    { big,          1UL,          16383UL, FD_TLS_REC_APPLICATION_DATA,   0                               },
    { big,          1UL,          16384UL, FD_TLS_REC_APPLICATION_DATA,   FD_TLS_ALERT_RECORD_OVERFLOW    },
    { big,          0UL,          16384UL, FD_TLS_REC_APPLICATION_DATA,   0                               },
    { big,          0UL,          16385UL, FD_TLS_REC_APPLICATION_DATA,   FD_TLS_ALERT_RECORD_OVERFLOW    },
    { big,          0UL,          0UL,     FD_TLS_REC_APPLICATION_DATA,   0                               },
    { big,          0UL,          0UL,     FD_TLS_REC_HANDSHAKE,          FD_TLS_ALERT_UNEXPECTED_MESSAGE },
    { big,          0UL,          8UL,     FD_TLS_REC_HANDSHAKE,          FD_TLS_ALERT_UNEXPECTED_MESSAGE },
    { big,          0UL,          8UL,     0,                             FD_TLS_ALERT_UNEXPECTED_MESSAGE },
    { ccs,          sizeof(ccs),  0UL,     FD_TLS_REC_CHANGE_CIPHER_SPEC, FD_TLS_ALERT_UNEXPECTED_MESSAGE },
    { ku_bad_value, sizeof(ku_bad_value), 0UL, FD_TLS_REC_HANDSHAKE,       FD_TLS_ALERT_ILLEGAL_PARAMETER  },
    { ku_bad_size,  sizeof(ku_bad_size),  0UL, FD_TLS_REC_HANDSHAKE,       FD_TLS_ALERT_DECODE_ERROR       },
    { ku_empty,     sizeof(ku_empty),     0UL, FD_TLS_REC_HANDSHAKE,       FD_TLS_ALERT_DECODE_ERROR       },
  };
  static fd_tlsrec_conn_t cli[1], srv[1];
  static uchar rec[ FD_TLSREC_CAP ], tcp_tx[ FD_TLSREC_CAP ], app_rx[ FD_TLSREC_CAP ];
  fd_tlsrec_slice_t tcp_rx[1];
  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    test_tlsrec_connect( &tls, cli, srv );
    ulong sz = test_tlsrec_send_raw_ex( srv, rec, cases[i].payload, cases[i].sz,
                                       cases[i].ct, cases[i].padding, 0x0303, 1U );
    fd_tlsrec_slice_init( tcp_rx, rec, sz );
    ulong tcp_tx_sz = sizeof(tcp_tx), app_rx_sz = sizeof(app_rx);
    int rc = fd_tlsrec_conn_rx( cli, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz );
    FD_TEST( rc==(cases[i].alert ? FD_TLSREC_ERR_PROTO : FD_TLSREC_SUCCESS) );
    if( cases[i].alert ) {
      FD_TEST( !app_rx_sz && fd_tlsrec_conn_is_failed( cli ) );
      test_tlsrec_check_alert( cli, tcp_tx, tcp_tx_sz, cases[i].alert );
    } else {
      FD_TEST( !tcp_tx_sz && app_rx_sz==cases[i].sz );
      FD_TEST( !memcmp( app_rx, cases[i].payload, app_rx_sz ) );
    }
  }

  /* Empty handshake records are forbidden before keys exist too. */
  FD_TEST( fd_tlsrec_conn_init( srv, &tls, 1 )==srv );
  uchar empty[] = { 22, 3, 3, 0, 0 };
  fd_tlsrec_slice_init( tcp_rx, empty, sizeof(empty) );
  ulong tcp_tx_sz = sizeof(tcp_tx), app_rx_sz = sizeof(app_rx);
  FD_TEST( fd_tlsrec_conn_rx( srv, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_ERR_PROTO );
  test_tlsrec_check_alert( srv, tcp_tx, tcp_tx_sz, FD_TLS_ALERT_UNEXPECTED_MESSAGE );

  /* user_canceled does not close either direction, irrespective of the
     legacy level byte.  A warning-level error alert is still fatal. */
  for( uchar level=1U; level<=2U; level++ ) {
    test_tlsrec_connect( &tls, cli, srv );
    uchar cancel[] = { level, FD_TLS_ALERT_USER_CANCELED };
    ulong sz = test_tlsrec_send_raw( srv, rec, cancel, sizeof(cancel), FD_TLS_REC_ALERT );
    sz += test_tlsrec_send_raw( srv, rec+sz, big, 1UL, FD_TLS_REC_APPLICATION_DATA );
    fd_tlsrec_slice_init( tcp_rx, rec, sz );
    tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( cli, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
    FD_TEST( !tcp_tx_sz && app_rx_sz==1UL && app_rx[0]=='b' );
    FD_TEST( !cli->rx_closed && !cli->tx_closed && fd_tlsrec_conn_is_ready( cli ) );
    cancel[1] = FD_TLS_ALERT_HANDSHAKE_FAILURE;
    sz = test_tlsrec_send_raw( srv, rec, cancel, sizeof(cancel), FD_TLS_REC_ALERT );
    fd_tlsrec_slice_init( tcp_rx, rec, sz );
    tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( cli, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_ERR_PROTO );
    FD_TEST( !tcp_tx_sz && cli->hs.base.reason==FD_TLS_REASON_PEER_ALERT );
  }
}

static void
test_tlsrec_seq_and_closed_update( fd_rng_t * rng ) {
  fd_tls_test_sign_ctx_t sign_ctx[1];
  fd_tls_test_sign_ctx( sign_ctx, rng );
  fd_chacha_rng_t chacha[1];
  fd_tls_t tls = {
    .rng  = fd_tls_test_rand( chacha, rng ),
    .sign = fd_tls_test_sign( sign_ctx ),
  };
  for( ulong j=0UL; j<32UL; j++ ) tls.kex_private_key[j] = fd_rng_uchar( rng );
  fd_x25519_public( tls.kex_public_key, tls.kex_private_key );
  fd_memcpy( tls.cert_public_key, sign_ctx->public_key, 32UL );
  fd_x509_mock_cert( tls.cert_x509, tls.cert_public_key );
  tls.cert_x509_sz = FD_X509_MOCK_CERT_SZ;

  static fd_tlsrec_conn_t cli[1], srv[1];
  static uchar rec[ FD_TLSREC_CAP ], tcp_tx[ FD_TLSREC_CAP ], app_rx[ FD_TLSREC_CAP ];
  uchar const data[] = { 'x' };
  fd_tlsrec_slice_t tcp_rx[1], app_tx[1];
  ulong sz, tcp_tx_sz, app_rx_sz;

  /* A pending or newly requested update cannot reopen the write side. */
  for( int pending=0; pending<2; pending++ ) {
    test_tlsrec_connect( &tls, cli, srv );
    sz = sizeof(rec);
    FD_TEST( fd_tlsrec_conn_key_update( srv, rec, &sz, 1 )==FD_TLSREC_SUCCESS );
    if( pending ) {
      fd_tlsrec_slice_init( tcp_rx, rec, sz );
      tcp_tx_sz = 0UL; app_rx_sz = sizeof(app_rx);
      FD_TEST( fd_tlsrec_conn_rx( cli, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
      FD_TEST( cli->key_update_pending );
    }
    tcp_tx_sz = sizeof(tcp_tx);
    FD_TEST( fd_tlsrec_conn_close( cli, tcp_tx, &tcp_tx_sz )==FD_TLSREC_SUCCESS );
    ulong write_seq = cli->write_seq;
    fd_tlsrec_slice_init( tcp_rx, rec, pending ? 0UL : sz );
    tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( cli, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
    FD_TEST( !tcp_tx_sz && !cli->key_update_pending && cli->write_seq==write_seq );
    sz = test_tlsrec_send_raw( srv, rec, data, sizeof(data), FD_TLS_REC_APPLICATION_DATA );
    fd_tlsrec_slice_init( tcp_rx, rec, sz );
    tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( cli, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
    FD_TEST( !tcp_tx_sz && app_rx_sz==sizeof(data) );
  }

  /* The final usable sequence can carry a KeyUpdate and reset both
     sides without wrapping.  Automatic rotation takes the same path. */
  for( int automatic=0; automatic<2; automatic++ ) {
    test_tlsrec_connect( &tls, cli, srv );
    cli->write_seq = srv->read_seq = ULONG_MAX-1UL;
    sz = sizeof(rec);
    if( automatic ) {
      fd_tlsrec_slice_init( app_tx, (uchar *)data, sizeof(data) );
      FD_TEST( fd_tlsrec_conn_tx( cli, rec, &sz, app_tx )==FD_TLSREC_SUCCESS );
    } else {
      FD_TEST( fd_tlsrec_conn_key_update( cli, rec, &sz, 0 )==FD_TLSREC_SUCCESS );
    }
    FD_TEST( cli->write_seq==(ulong)automatic );
    fd_tlsrec_slice_init( tcp_rx, rec, sz );
    tcp_tx_sz = sizeof(tcp_tx); app_rx_sz = sizeof(app_rx);
    FD_TEST( fd_tlsrec_conn_rx( srv, tcp_rx, tcp_tx, &tcp_tx_sz, app_rx, &app_rx_sz )==FD_TLSREC_SUCCESS );
    FD_TEST( srv->read_seq==(ulong)automatic && app_rx_sz==(ulong)automatic );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* Test 1: AES-128-GCM encrypt/decrypt roundtrip ***********************/
  do {
    FD_LOG_INFO(( "Testing AES-128-GCM encrypt/decrypt roundtrip" ));

    uchar key[16] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                      0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
    uchar iv [12] = { 0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                      0x18,0x19,0x1a,0x1b };
    uchar aad[ 5] = { 0x17, 0x03, 0x03, 0x00, 0x30 }; /* TLS record header */

    uchar const plaintext[] = "Hello, TLS record layer!";
    ulong pt_sz = sizeof(plaintext)-1;  /* exclude NUL */

    uchar ciphertext[256];
    uchar tag[FD_AES_GCM_TAG_SZ];
    uchar recovered [256];

    fd_aes_gcm_t aes_gcm[1];

    /* Encrypt */
    fd_aes_gcm_init( aes_gcm, key, 16UL, iv );
    fd_aes_gcm_encrypt( aes_gcm, ciphertext, plaintext, pt_sz,
                        aad, sizeof(aad), tag );

    /* Ciphertext must differ from plaintext */
    FD_TEST( 0!=memcmp( ciphertext, plaintext, pt_sz ) );

    /* Decrypt */
    fd_aes_gcm_init( aes_gcm, key, 16UL, iv );
    int ok = fd_aes_gcm_decrypt( aes_gcm, ciphertext, recovered, pt_sz,
                                 aad, sizeof(aad), tag );
    FD_TEST( ok==FD_AES_GCM_DECRYPT_OK );
    FD_TEST( 0==memcmp( recovered, plaintext, pt_sz ) );

    FD_LOG_INFO(( "OK: AES-128-GCM roundtrip" ));
  } while(0);

  /* Test 2: IV generation with sequence XOR *****************************/
  do {
    FD_LOG_INFO(( "Testing IV generation with sequence XOR" ));

    uchar base_iv[12] = { 0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                          0x18,0x19,0x1a,0x1b };
    uchar iv[12];

    /* seq=0 -> iv == base_iv */
    test_gen_iv( iv, base_iv, 0UL );
    FD_TEST( 0==memcmp( iv, base_iv, 12 ) );

    /* seq=1 -> iv differs from base_iv only in last byte */
    test_gen_iv( iv, base_iv, 1UL );
    FD_TEST( 0==memcmp( iv, base_iv, 11 ) );  /* first 11 bytes unchanged */
    FD_TEST( iv[11]==(uchar)(base_iv[11] ^ 0x01) );

    /* seq=0x0102030405060708 -> verify each byte XORed correctly */
    test_gen_iv( iv, base_iv, 0x0102030405060708UL );
    FD_TEST( iv[ 0]==base_iv[ 0] );  /* untouched (only 8 bytes of seq) */
    FD_TEST( iv[ 1]==base_iv[ 1] );  /* untouched */
    FD_TEST( iv[ 2]==base_iv[ 2] );  /* untouched */
    FD_TEST( iv[ 3]==base_iv[ 3] );  /* untouched */
    FD_TEST( iv[ 4]==(uchar)(base_iv[ 4] ^ 0x01) );
    FD_TEST( iv[ 5]==(uchar)(base_iv[ 5] ^ 0x02) );
    FD_TEST( iv[ 6]==(uchar)(base_iv[ 6] ^ 0x03) );
    FD_TEST( iv[ 7]==(uchar)(base_iv[ 7] ^ 0x04) );
    FD_TEST( iv[ 8]==(uchar)(base_iv[ 8] ^ 0x05) );
    FD_TEST( iv[ 9]==(uchar)(base_iv[ 9] ^ 0x06) );
    FD_TEST( iv[10]==(uchar)(base_iv[10] ^ 0x07) );
    FD_TEST( iv[11]==(uchar)(base_iv[11] ^ 0x08) );

    FD_LOG_INFO(( "OK: IV generation with sequence XOR" ));
  } while(0);

  /* Test 3: AAD is the 5-byte record header *****************************/
  do {
    FD_LOG_INFO(( "Testing AAD as 5-byte TLS record header" ));

    uchar key[16] = { 0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe,
                      0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08 };
    uchar iv [12] = { 0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
                      0xf8,0xf9,0xfa,0xfb };

    uchar const plaintext[] = "authenticated additional data test";
    ulong pt_sz = sizeof(plaintext)-1;

    /* Construct proper TLS record header as AAD:
       content_type=23 (app data), version=0x0303 (TLS 1.2 compat),
       length = payload_sz + tag_sz (16) */
    ushort rec_length = (ushort)( pt_sz + FD_AES_GCM_TAG_SZ );
    uchar aad[5];
    aad[0] = FD_TLS_REC_APPLICATION_DATA;       /* content_type = 23 */
    aad[1] = 0x03;                       /* version hi */
    aad[2] = 0x03;                       /* version lo */
    aad[3] = (uchar)( rec_length >> 8 ); /* length hi */
    aad[4] = (uchar)( rec_length      ); /* length lo */

    uchar ciphertext[256];
    uchar tag[FD_AES_GCM_TAG_SZ];
    uchar recovered [256];

    fd_aes_gcm_t aes_gcm[1];

    /* Encrypt with correct AAD */
    fd_aes_gcm_init( aes_gcm, key, 16UL, iv );
    fd_aes_gcm_encrypt( aes_gcm, ciphertext, plaintext, pt_sz,
                        aad, sizeof(aad), tag );

    /* Decrypt with same AAD succeeds */
    fd_aes_gcm_init( aes_gcm, key, 16UL, iv );
    int ok = fd_aes_gcm_decrypt( aes_gcm, ciphertext, recovered, pt_sz,
                                 aad, sizeof(aad), tag );
    FD_TEST( ok==FD_AES_GCM_DECRYPT_OK );
    FD_TEST( 0==memcmp( recovered, plaintext, pt_sz ) );

    /* Decrypt with different AAD fails */
    uchar bad_aad[5];
    memcpy( bad_aad, aad, 5 );
    bad_aad[0] = FD_TLS_REC_HANDSHAKE;  /* wrong content type */

    fd_aes_gcm_init( aes_gcm, key, 16UL, iv );
    ok = fd_aes_gcm_decrypt( aes_gcm, ciphertext, recovered, pt_sz,
                             bad_aad, sizeof(bad_aad), tag );
    FD_TEST( ok==FD_AES_GCM_DECRYPT_FAIL );

    /* Also try corrupting the length field in AAD */
    uchar bad_aad2[5];
    memcpy( bad_aad2, aad, 5 );
    bad_aad2[4] ^= 0x01;  /* flip one bit in length */

    fd_aes_gcm_init( aes_gcm, key, 16UL, iv );
    ok = fd_aes_gcm_decrypt( aes_gcm, ciphertext, recovered, pt_sz,
                             bad_aad2, sizeof(bad_aad2), tag );
    FD_TEST( ok==FD_AES_GCM_DECRYPT_FAIL );

    FD_LOG_INFO(( "OK: AAD as 5-byte TLS record header" ));
  } while(0);

  /* Test 4: Tag corruption -> decrypt fails *****************************/
  do {
    FD_LOG_INFO(( "Testing tag corruption detection" ));

    uchar key[16] = { 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
                      0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00 };
    uchar iv [12] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                      0x09,0x0a,0x0b,0x0c };
    uchar aad[ 5] = { 0x17, 0x03, 0x03, 0x00, 0x20 };

    uchar const plaintext[] = "tag tamper test";
    ulong pt_sz = sizeof(plaintext)-1;

    uchar ciphertext[256];
    uchar tag[FD_AES_GCM_TAG_SZ];
    uchar recovered [256];

    fd_aes_gcm_t aes_gcm[1];

    /* Encrypt */
    fd_aes_gcm_init( aes_gcm, key, 16UL, iv );
    fd_aes_gcm_encrypt( aes_gcm, ciphertext, plaintext, pt_sz,
                        aad, sizeof(aad), tag );

    /* Flip one bit in the tag */
    uchar bad_tag[FD_AES_GCM_TAG_SZ];
    memcpy( bad_tag, tag, FD_AES_GCM_TAG_SZ );
    bad_tag[0] ^= 0x01;

    fd_aes_gcm_init( aes_gcm, key, 16UL, iv );
    int ok = fd_aes_gcm_decrypt( aes_gcm, ciphertext, recovered, pt_sz,
                                 aad, sizeof(aad), bad_tag );
    FD_TEST( ok==FD_AES_GCM_DECRYPT_FAIL );

    FD_LOG_INFO(( "OK: tag corruption detected" ));
  } while(0);

  /* Test 5: Wrong key -> decrypt fails **********************************/
  do {
    FD_LOG_INFO(( "Testing wrong key detection" ));

    uchar key_a[16] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
    uchar key_b[16] = { 0xff,0xfe,0xfd,0xfc,0xfb,0xfa,0xf9,0xf8,
                        0xf7,0xf6,0xf5,0xf4,0xf3,0xf2,0xf1,0xf0 };
    uchar iv   [12] = { 0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
                        0x28,0x29,0x2a,0x2b };
    uchar aad  [ 5] = { 0x17, 0x03, 0x03, 0x00, 0x30 };

    uchar const plaintext[] = "wrong key test data";
    ulong pt_sz = sizeof(plaintext)-1;

    uchar ciphertext[256];
    uchar tag[FD_AES_GCM_TAG_SZ];
    uchar recovered [256];

    fd_aes_gcm_t aes_gcm[1];

    /* Encrypt with key A */
    fd_aes_gcm_init( aes_gcm, key_a, 16UL, iv );
    fd_aes_gcm_encrypt( aes_gcm, ciphertext, plaintext, pt_sz,
                        aad, sizeof(aad), tag );

    /* Decrypt with key B -> must fail */
    fd_aes_gcm_init( aes_gcm, key_b, 16UL, iv );
    int ok = fd_aes_gcm_decrypt( aes_gcm, ciphertext, recovered, pt_sz,
                                 aad, sizeof(aad), tag );
    FD_TEST( ok==FD_AES_GCM_DECRYPT_FAIL );

    FD_LOG_INFO(( "OK: wrong key detected" ));
  } while(0);

  /* Test 6: Record size parsing *****************************************/
  do {
    FD_LOG_INFO(( "Testing record size parsing from header" ));

    /* Verify sizeof(fd_tlsrec_hdr_t) == 5 */
    FD_TEST( sizeof(fd_tlsrec_hdr_t)==5UL );

    /* Valid header: content_type=23, version=0x0303, length=100
       rec_sz = sizeof(hdr) + length = 5 + 100 = 105 */
    fd_tlsrec_hdr_t hdr;
    hdr.content_type          = FD_TLS_REC_APPLICATION_DATA;
    hdr.legacy_record_version = fd_ushort_bswap( (ushort)0x0303 );
    hdr.length                = fd_ushort_bswap( (ushort)100 );

    fd_tlsrec_hdr_bswap( &hdr );
    FD_TEST( hdr.content_type          ==(uchar)23 );
    FD_TEST( hdr.legacy_record_version ==(ushort)0x0303 );
    FD_TEST( hdr.length                ==(ushort)100 );

    ulong rec_sz = sizeof(fd_tlsrec_hdr_t) + (ulong)hdr.length;
    FD_TEST( rec_sz==105UL );

    /* Length=0 -> rec_sz = 5 */
    fd_tlsrec_hdr_t hdr0;
    hdr0.content_type          = FD_TLS_REC_APPLICATION_DATA;
    hdr0.legacy_record_version = fd_ushort_bswap( (ushort)0x0303 );
    hdr0.length                = fd_ushort_bswap( (ushort)0 );

    fd_tlsrec_hdr_bswap( &hdr0 );
    FD_TEST( hdr0.length==0 );

    ulong rec_sz0 = sizeof(fd_tlsrec_hdr_t) + (ulong)hdr0.length;
    FD_TEST( rec_sz0==5UL );

    FD_LOG_INFO(( "OK: record size parsing" ));
  } while(0);

  /* Test 7: Record-layer client/server integration *********************/
  test_tlsrec_pair( rng );
  test_tlsrec_large_hs_msg( rng );
  test_tlsrec_ccs( rng );
  test_tlsrec_handshake_epochs( rng );
  test_tlsrec_hs_interleave( rng );
  test_tlsrec_key_change_boundary( rng );
  test_tlsrec_key_update_flood( rng );
  test_tlsrec_alert_tx( rng );
  test_tlsrec_plaintext_alert( rng );
  test_tlsrec_close_notify( rng );
  test_tlsrec_sock_close_notify( rng );
  test_tlsrec_rec_hdr( rng );
  test_tlsrec_inner_plaintext( rng );
  test_tlsrec_seq_and_closed_update( rng );

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
