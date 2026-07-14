#include "fd_tlsrec.h"
#include "../tls/test_tls_helper.h"
#include "../../ballet/aes/fd_aes_gcm.h"
#include "../../ballet/ed25519/fd_x25519.h"
#include "../../ballet/x509/fd_x509_mock.h"

#include <string.h>

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

  fd_tls_t client_tls = {
    .rand       = fd_tls_test_rand( rng ),
    .sign       = fd_tls_test_sign( client_sign_ctx ),
    .secrets_fn = test_tlsrec_secrets,
  };
  fd_tls_t server_tls = {
    .rand = fd_tls_test_rand( rng ),
    .sign = fd_tls_test_sign( server_sign_ctx ),
  };

  for( ulong j=0UL; j<32UL; j++ ) {
    client_tls.key_share_private[j] = fd_rng_uchar( rng );
    server_tls.key_share_private[j] = fd_rng_uchar( rng );
  }
  fd_x25519_public( client_tls.key_share_public, client_tls.key_share_private );
  fd_x25519_public( server_tls.key_share_public, server_tls.key_share_private );

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

  /* Test 2: AES-256-GCM encrypt/decrypt roundtrip ***********************/
  do {
    FD_LOG_INFO(( "Testing AES-256-GCM encrypt/decrypt roundtrip" ));

    uchar key[32] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                      0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                      0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                      0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f };
    uchar iv [12] = { 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
                      0xa8,0xa9,0xaa,0xab };
    uchar aad[ 5] = { 0x17, 0x03, 0x03, 0x00, 0x40 };

    uchar const plaintext[] = "AES-256-GCM TLS record test payload!!";
    ulong pt_sz = sizeof(plaintext)-1;

    uchar ciphertext[256];
    uchar tag[FD_AES_GCM_TAG_SZ];
    uchar recovered [256];

    fd_aes_gcm_t aes_gcm[1];

    /* Encrypt */
    fd_aes_gcm_init( aes_gcm, key, 32UL, iv );
    fd_aes_gcm_encrypt( aes_gcm, ciphertext, plaintext, pt_sz,
                        aad, sizeof(aad), tag );

    FD_TEST( 0!=memcmp( ciphertext, plaintext, pt_sz ) );

    /* Decrypt */
    fd_aes_gcm_init( aes_gcm, key, 32UL, iv );
    int ok = fd_aes_gcm_decrypt( aes_gcm, ciphertext, recovered, pt_sz,
                                 aad, sizeof(aad), tag );
    FD_TEST( ok==FD_AES_GCM_DECRYPT_OK );
    FD_TEST( 0==memcmp( recovered, plaintext, pt_sz ) );

    FD_LOG_INFO(( "OK: AES-256-GCM roundtrip" ));
  } while(0);

  /* Test 3: IV generation with sequence XOR *****************************/
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

  /* Test 4: AAD is the 5-byte record header *****************************/
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

  /* Test 5: Tag corruption -> decrypt fails *****************************/
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

  /* Test 6: Wrong key -> decrypt fails **********************************/
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

  /* Test 7: Record size parsing *****************************************/
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

  /* Test 8: Record-layer client/server integration *********************/
  test_tlsrec_pair( rng );

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
