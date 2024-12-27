#include "../crypto/fd_quic_crypto_suites.h"

FD_IMPORT_BINARY( test_client_initial,   "src/waltz/quic/fixtures/rfc9001-client-initial-payload.bin"   );
FD_IMPORT_BINARY( test_client_encrypted, "src/waltz/quic/fixtures/rfc9001-client-initial-encrypted.bin" );

/* the destination connection id from the example */
/* 0x8394c8f03e515708 */
static uchar const test_dst_conn_id[8] = "\x83\x94\xc8\xf0\x3e\x51\x57\x08";

/* expected value from rfc9001:
   7db5df06e7a69e432496adedb0085192 3595221596ae2ae9fb8115c1e9ed0a44 */
static uchar const expected_initial_secret[32] =
  { 0x7d, 0xb5, 0xdf, 0x06, 0xe7, 0xa6, 0x9e, 0x43,
    0x24, 0x96, 0xad, 0xed, 0xb0, 0x08, 0x51, 0x92,
    0x35, 0x95, 0x22, 0x15, 0x96, 0xae, 0x2a, 0xe9,
    0xfb, 0x81, 0x15, 0xc1, 0xe9, 0xed, 0x0a, 0x44 };

/* rfc9001 a.1. The secrets for protecting client packets are:

   client_initial_secret
       = HKDF-Expand-Label(initial_secret, "client in", "", 32)
       = c00cf151ca5be075ed0ebfb5c80323c4
         2d6b7db67881289af4008f1f6c357aea

   key = HKDF-Expand-Label(client_initial_secret, "quic key", "", 16)
       = 1f369613dd76d5467730efcbe3b1a22d

   iv  = HKDF-Expand-Label(client_initial_secret, "quic iv", "", 12)
       = fa044b2f42a3fd3b46fb255c

   hp  = HKDF-Expand-Label(client_initial_secret, "quic hp", "", 16)
       = 9f50449e04a0e810283a1e9933adedd2 */
static uchar const expected_client_initial_secret[32] =
  { 0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4,
    0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea };
static uchar const expected_client_key[16] =
  { 0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d };
static uchar const expected_client_quic_iv[12] =
  { 0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c };
static uchar const expected_client_quic_hp_key[16] =
  { 0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2 };

/* rfc9001 a.1. The secrets for protecting server packets are:

   server_initial_secret
       = HKDF-Expand-Label(initial_secret, "server in", "", 32)
       = 3c199828fd139efd216c155ad844cc81
         fb82fa8d7446fa7d78be803acdda951b

   key = HKDF-Expand-Label(server_initial_secret, "quic key", "", 16)
       = cf3a5331653c364c88f0f379b6067e37

   iv  = HKDF-Expand-Label(server_initial_secret, "quic iv", "", 12)
       = 0ac1493ca1905853b0bba03e

   hp  = HKDF-Expand-Label(server_initial_secret, "quic hp", "", 16)
       = c206b8d9b9f0f37644430b490eeaa314 */
static uchar const expected_server_initial_secret[32] =
  { 0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81,
    0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b };
static uchar const expected_server_key[16] =
  { 0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c, 0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37 };
static uchar const expected_server_quic_iv[12] =
  { 0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53, 0xb0, 0xbb, 0xa0, 0x3e };
static uchar const expected_server_quic_hp_key[16] =
  { 0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76, 0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14 };

/* The unprotected header indicates a length of 1182 bytes: the 4-byte packet number, 1162 bytes of frames,
   and the 16-byte authentication tag. The header includes the connection ID and a packet number of 2:
       c300000001088394c8f03e5157080000449e00000002 */
static uchar const packet_header[] =
  { 0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00, 0x00,
    0x44, 0x9e, 0x00, 0x00, 0x00, 0x02 };


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /*   initial_secret = HKDF-Extract(initial_salt, */
  /*                                 client_dst_connection_id) */

  /*   client_initial_secret = HKDF-Expand-Label(initial_secret, */
  /*                                             "client in", "", */
  /*                                             Hash.length) */
  /*   server_initial_secret = HKDF-Expand-Label(initial_secret, */
  /*                                             "server in", "", */
  /*                                             Hash.length) */

  /* from https://www.rfc-editor.org/rfc/rfc9001.html#initial-secrets

     Initial packets apply the packet protection process, but use a secret derived
     from the Destination Connection ID field from the client's first Initial packet.

     This secret is determined by using HKDF-Extract (see Section 2.2 of [HKDF]) with
     a salt of 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a and the input keying
     material (IKM) of the Destination Connection ID field. This produces an
     intermediate pseudorandom key (PRK) that is used to derive two separate secrets
     for sending and receiving.

     The secret used by clients to construct Initial packets uses the PRK and the
     label "client in" as input to the HKDF-Expand-Label function from TLS [TLS13] to
     produce a 32-byte secret. Packets constructed by the server use the same process
     with the label "server in". The hash function for HKDF when deriving initial
     secrets and keys is SHA-256 [SHA].

     Initial packets use AEAD_AES_128_GCM with keys derived from the Destination
     Connection ID field of the first Initial packet sent by the client; */

  /* Derive key TEST from rfc9001 */

  /* create secrets via fd_quic/crypto */
  fd_quic_crypto_secrets_t secrets;

  /* initial salt is based on quic version */
  fd_quic_gen_initial_secrets(
      &secrets,
      test_dst_conn_id, sizeof( test_dst_conn_id ),
      /* is_server */ 1 );
  FD_TEST( 0==memcmp( secrets.initial_secret, expected_initial_secret, sizeof( expected_initial_secret ) ) );
  FD_LOG_INFO(( "fd_quic_gen_initial_secret: PASSED" ));

  /* initial secrets are derived from the initial client destination connection id
     both client and server initial secrets are derived here */
  FD_LOG_DEBUG(( "client initial secret: "
                 FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT,
                 FD_LOG_HEX16_FMT_ARGS( secrets.secret[0][0]    ),
                 FD_LOG_HEX16_FMT_ARGS( secrets.secret[0][0]+16 ) ));
  FD_TEST( 0==memcmp( secrets.secret[0][0], expected_client_initial_secret, sizeof( expected_client_initial_secret ) ) );
  FD_LOG_INFO(( "fd_quic_gen_secrets: client_initial_secret PASSED" ));

  FD_LOG_DEBUG(( "server initial secret: "
                 FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT,
                 FD_LOG_HEX16_FMT_ARGS( secrets.secret[0][1]    ),
                 FD_LOG_HEX16_FMT_ARGS( secrets.secret[0][1]+16 ) ));
  FD_TEST( 0==memcmp( secrets.secret[0][1], expected_server_initial_secret, sizeof( expected_server_initial_secret ) ) );
  FD_LOG_INFO(( "fd_quic_gen_secrets: server_initial_secret PASSED" ));

  fd_quic_crypto_keys_t client_keys;
  fd_quic_gen_keys( &client_keys, secrets.secret[0][0] );

  FD_TEST( 0==memcmp( client_keys.pkt_key, expected_client_key,         sizeof( expected_client_key )         ) );
  FD_TEST( 0==memcmp( client_keys.iv,      expected_client_quic_iv,     sizeof( expected_client_quic_iv )     ) );
  FD_TEST( 0==memcmp( client_keys.hp_key,  expected_client_quic_hp_key, sizeof( expected_client_quic_hp_key ) ) );

  fd_quic_crypto_keys_t server_keys;
  fd_quic_gen_keys( &server_keys, secrets.secret[0][1] );

  FD_TEST( 0==memcmp( server_keys.pkt_key, expected_server_key,         sizeof( expected_server_key )         ) );
  FD_TEST( 0==memcmp( server_keys.iv,      expected_server_quic_iv,     sizeof( expected_server_quic_iv )     ) );
  FD_TEST( 0==memcmp( server_keys.hp_key,  expected_server_quic_hp_key, sizeof( expected_server_quic_hp_key ) ) );

  uchar cipher_text_[4096] = {0};
  ulong cipher_text_sz = sizeof(cipher_text_);

  uchar const * pkt    = test_client_initial;
  ulong         pkt_sz = test_client_initial_sz;

  uchar const * hdr    = packet_header;
  ulong         hdr_sz = sizeof( packet_header );

  ulong pkt_number = 2UL;

  FD_TEST( fd_quic_crypto_encrypt(
      cipher_text_, &cipher_text_sz,
      hdr,          hdr_sz,
      pkt,          pkt_sz,
      &client_keys,
      &client_keys,
      pkt_number )==FD_QUIC_SUCCESS );

  uchar const * cipher_text = cipher_text_;

  FD_TEST( cipher_text_sz==test_client_encrypted_sz );
  FD_LOG_HEXDUMP_DEBUG(( "plain_text",  test_client_initial, test_client_initial_sz ));
  FD_LOG_HEXDUMP_DEBUG(( "cipher_text", cipher_text,         cipher_text_sz         ));

  ulong j; for( j=0UL; j<test_client_encrypted_sz && cipher_text[j]==test_client_encrypted[j]; j++ );
  if( FD_UNLIKELY( !fd_memeq( cipher_text, test_client_encrypted, test_client_encrypted_sz ) ) ) {
    FD_LOG_ERR(( "test_client_encrypted mismatch at %#lx", j ));
  }

  uchar revert[4096];
  ulong const pn_offset = 18; /* from example in rfc */

  fd_memcpy( revert, cipher_text, cipher_text_sz );
  FD_TEST( fd_quic_crypto_decrypt_hdr(
        revert, cipher_text_sz,
        pn_offset,
        &client_keys ) == FD_QUIC_SUCCESS );

  uchar revert_partial[4096];  /* only header decrypted */
  fd_memcpy( revert_partial, revert, cipher_text_sz );

  FD_TEST( fd_quic_crypto_decrypt(
        revert, cipher_text_sz,
        pn_offset, pkt_number,
        &client_keys ) == FD_QUIC_SUCCESS );

  ulong revert_sz = cipher_text_sz - FD_QUIC_CRYPTO_TAG_SZ;
  FD_LOG_HEXDUMP_DEBUG(( "reverted", revert, revert_sz ));

  if( revert_sz != hdr_sz + test_client_initial_sz ) {
    FD_LOG_ERR(( "decrypted plain text size doesn't match original plain text size: %lu != %lu",
        revert_sz, test_client_initial_sz ));
  }
  FD_TEST( 0==memcmp( revert, hdr, hdr_sz ) );
  FD_TEST( 0==memcmp( revert + hdr_sz, test_client_initial, test_client_initial_sz ) );

  FD_LOG_INFO(( "decrypted packet matches original packet" ));

  /* Undersz header */
  fd_memcpy( revert, cipher_text, cipher_text_sz );
  FD_TEST( fd_quic_crypto_decrypt_hdr(
        revert, FD_QUIC_CRYPTO_TAG_SZ-1UL,
        pn_offset,
        &client_keys ) == FD_QUIC_FAILED );

  /* Overflowing packet number offset */
  fd_memcpy( revert, cipher_text, cipher_text_sz );
  FD_TEST( fd_quic_crypto_decrypt_hdr(
        revert, cipher_text_sz,
        ULONG_MAX,
        &client_keys ) == FD_QUIC_FAILED );

  /* Packet number cut off */
  fd_memcpy( revert, cipher_text, cipher_text_sz );
  FD_TEST( fd_quic_crypto_decrypt_hdr(
        revert, pn_offset + 3,
        pn_offset,
        &client_keys ) == FD_QUIC_FAILED );

  /* Sample out of bounds */
  fd_memcpy( revert, cipher_text, cipher_text_sz );
  FD_TEST( fd_quic_crypto_decrypt_hdr(
        revert, pn_offset + 19,
        pn_offset,
        &client_keys ) == FD_QUIC_FAILED );

  /* Corrupt the ciphertext */
  fd_memcpy( revert, revert_partial, cipher_text_sz );
  revert[80]++;
  FD_TEST( fd_quic_crypto_decrypt(
        revert, cipher_text_sz,
        pn_offset, pkt_number,
        &client_keys ) == FD_QUIC_FAILED );

  /* Output buffer size exactly as large as output */
  fd_memcpy( revert, revert_partial, cipher_text_sz );
  FD_TEST( cipher_text_sz == 1200UL );
  FD_TEST( fd_quic_crypto_decrypt(
        revert, cipher_text_sz,
        pn_offset, pkt_number,
        &client_keys ) == FD_QUIC_SUCCESS );

  /* Overflowing packet number offset */
  fd_memcpy( revert, revert_partial, cipher_text_sz );
  FD_TEST( cipher_text_sz == 1200UL );
  FD_TEST( fd_quic_crypto_decrypt(
        revert, cipher_text_sz,
        ULONG_MAX, pkt_number,
        &client_keys ) == FD_QUIC_FAILED );

  /* do a quick benchmark of QUIC header + payload protection on small
     and large packets from UDP/IP4/VLAN/Ethernet */

  static ulong const bench_sz[2] = { 64UL, 1472UL };

  uchar buf1[ 1472 ] __attribute__((aligned(128)));
  uchar buf2[ 1472 ] __attribute__((aligned(128)));
  for( ulong b=0UL; b<1472UL; b++ ) buf1[b] = fd_rng_uchar( rng );
  for( ulong b=0UL; b<1472UL; b++ ) buf2[b] = fd_rng_uchar( rng );

  FD_LOG_NOTICE(( "Benchmarking header+payload decrypt" ));
  for( ulong idx=0U; idx<2UL; idx++ ) {
    ulong sz = bench_sz[ idx ];

    /* warmup */
    for( ulong rem=10UL; rem; rem-- ) {
      fd_quic_crypto_decrypt_hdr( buf2, sz, 0,       &client_keys );
      fd_quic_crypto_decrypt    ( buf2, sz, 0, 1234, &client_keys );
    }

    /* for real */
    ulong iter = 1000000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      fd_quic_crypto_decrypt_hdr( buf2, sz, 0,       &client_keys );
      fd_quic_crypto_decrypt    ( buf2, sz, 0, 1234, &client_keys );
    }
    dt += fd_log_wallclock();
    float gbps = ((float)(8UL*(70UL+sz)*iter)) / ((float)dt);
    FD_LOG_NOTICE(( "~%6.3f Gbps Ethernet equiv throughput / core (sz %4lu)", (double)gbps, sz ));
  } while(0);

  FD_LOG_NOTICE(( "Benchmarking header+payload encrypt" ));
  for( ulong idx=0U; idx<2UL; idx++ ) {
    ulong const out_sz = bench_sz[ idx ];
    ulong const hdr_sz = 22UL;
    ulong const sz     = out_sz - FD_QUIC_CRYPTO_TAG_SZ - hdr_sz;

    /* warmup */
    for( ulong rem=10UL; rem; rem-- ) {
      ulong out_sz_ = out_sz;
      fd_quic_crypto_encrypt( buf2, &out_sz_, hdr, hdr_sz, buf1, sz, &client_keys, &client_keys, 1234 );
    }

    /* for real */
    ulong iter = 1000000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      ulong out_sz_ = out_sz;
      fd_quic_crypto_encrypt( buf2, &out_sz_, hdr, hdr_sz, buf1, sz, &client_keys, &client_keys, 1234 );
    }
    dt += fd_log_wallclock();
    float gbps = ((float)(8UL*(70UL+out_sz)*iter)) / ((float)dt);
    FD_LOG_NOTICE(( "~%6.3f Gbps Ethernet equiv throughput / core (sz %4lu)", (double)gbps, out_sz ));
  } while(0);

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
