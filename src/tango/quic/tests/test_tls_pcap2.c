#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
//#include <openssl/opensslv.h>
//#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../crypto/fd_quic_crypto_suites.h"
#include "../../../ballet/hmac/fd_hmac.h"
#include "../../../util/fd_util.h"

// example from rfc9001:
uchar test_client_initial[4+377+855] =
    "\x06\x00\x41\x79\x01\x00\x01\x75\x03\x03\x6f\x2d\xa1\x28\xdd\x7e"
    "\xff\xa9\x8c\x1c\xe4\x84\x55\x04\xa2\xcc\xc6\x35\x46\xfa\xfa\xfa"
    "\x47\xa3\xf7\xff\x2a\xaa\x7f\xa4\x28\x0b\x00\x00\x06\x13\x02\x13"
    "\x01\x13\x03\x01\x00\x01\x46\x00\x33\x00\xa7\x00\xa5\x00\x17\x00"
    "\x41\x04\x6d\x7d\xad\xed\xf2\x09\x94\x79\x7a\xe9\x3c\xce\x69\x55"
    "\xc0\xca\x94\xd7\x0c\xbe\x06\xd3\x35\x2c\xfa\x09\xda\x7e\xd7\x8e"
    "\xda\x0b\x99\xb4\x31\xba\x1e\x52\x9c\x9c\xaf\xc5\x16\xcb\x7d\xb5"
    "\xf5\x14\x3f\xaf\x26\x3e\x0a\x0d\x85\x54\x9f\x64\x38\x75\x12\xe7"
    "\x23\xad\x00\x1d\x00\x20\x0f\x3d\x20\xaa\x73\x05\xad\x27\x77\x35"
    "\xa3\xd8\xe2\x34\xf4\xab\x55\x06\xb9\x1e\x3e\xaf\x5b\x6d\x48\x6b"
    "\x6b\x16\xde\x4b\x50\x7a\x00\x1e\x00\x38\x16\xe8\xe2\x5d\x14\x8d"
    "\x2c\x81\xc4\x42\xf7\x3e\x6e\x55\x6b\x94\xf3\x5e\x91\x5b\xcf\xe8"
    "\x31\x21\x2b\xb5\xef\x50\x51\xca\xf0\xa8\x36\xe3\xd0\xf3\xfe\x3a"
    "\xda\xab\x58\xc0\xca\x33\xb2\xd8\x99\x6f\xfc\x87\x92\x1c\xc6\xce"
    "\x86\x2a\x00\x2b\x00\x03\x02\x03\x04\x00\x0d\x00\x0e\x00\x0c\x08"
    "\x04\x04\x03\x04\x01\x02\x01\x08\x07\x08\x08\x00\x0a\x00\x08\x00"
    "\x06\x00\x17\x00\x1d\x00\x1e\x00\x2d\x00\x02\x01\x01\x00\x00\x00"
    "\x0e\x00\x0c\x00\x00\x09\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x00"
    "\x10\x00\x1d\x00\x1b\x02\x68\x33\x05\x68\x33\x2d\x33\x32\x05\x68"
    "\x33\x2d\x33\x31\x05\x68\x33\x2d\x33\x30\x05\x68\x33\x2d\x32\x39"
    "\x00\x39\x00\x39\x01\x04\x80\x00\xea\x60\x04\x04\x80\x10\x00\x00"
    "\x05\x04\x80\x10\x00\x00\x06\x04\x80\x10\x00\x00\x07\x04\x80\x10"
    "\x00\x00\x08\x02\x40\x80\x09\x02\x40\x80\x0a\x01\x03\x0b\x01\x19"
    "\x0e\x01\x08\x0f\x08\xec\x73\x1b\x41\xa0\xd5\xc6\xfe";

// 0x8394c8f03e515708
uchar test_dst_conn_id[8] = "\x2a\x68\x59\x18\x78\xc8\x91\x4c";
//uchar test_dst_conn_id[8] = "\xec\x73\x1b\x41\xa0\xd5\xc6\xfe";

// Initial Packets
//   initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
uchar initial_salt[] = { 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
                         0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
                         0xcc, 0xbb, 0x7f, 0x0a };
ulong initial_salt_sz = sizeof( initial_salt );

void
test_secret_gen( uchar const * expected_output,
                 uchar const * secret,
                 ulong         secret_sz,
                 char const *  label,
                 ulong         output_sz ) {
  uchar new_secret[64] = {0};
  ulong label_sz = strlen( label );

  fd_quic_hkdf_expand_label( new_secret, output_sz,
                             secret, secret_sz,
                             (uchar*)label, label_sz,
                             fd_hmac_sha256, 32UL );

  char hexdump_label_buf[ 128 ];
  snprintf( hexdump_label_buf, 128UL, "secret for %s", label );
  FD_LOG_HEXDUMP_NOTICE(( hexdump_label_buf, new_secret, output_sz ));

  FD_TEST( 0==memcmp( new_secret, expected_output, output_sz ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  //   initial_secret = HKDF-Extract(initial_salt,
  //                                 client_dst_connection_id)
  //
  //   client_initial_secret = HKDF-Expand-Label(initial_secret,
  //                                             "client in", "",
  //                                             Hash.length)
  //   server_initial_secret = HKDF-Expand-Label(initial_secret,
  //                                             "server in", "",
  //                                             Hash.length)

  // from https://www.rfc-editor.org/rfc/rfc9001.html#initial-secrets

  // Initial packets apply the packet protection process, but use a secret derived
  // from the Destination Connection ID field from the client's first Initial packet.
  //
  // This secret is determined by using HKDF-Extract (see Section 2.2 of [HKDF]) with
  // a salt of 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a and the input keying
  // material (IKM) of the Destination Connection ID field. This produces an
  // intermediate pseudorandom key (PRK) that is used to derive two separate secrets
  // for sending and receiving.
  //
  // The secret used by clients to construct Initial packets uses the PRK and the
  // label "client in" as input to the HKDF-Expand-Label function from TLS [TLS13] to
  // produce a 32-byte secret. Packets constructed by the server use the same process
  // with the label "server in". The hash function for HKDF when deriving initial
  // secrets and keys is SHA-256 [SHA].

  // Initial packets use AEAD_AES_128_GCM with keys derived from the Destination
  // Connection ID field of the first Initial packet sent by the client;

  // sha256 size in octets is 32
  uchar initial_secret[32] = {0};
  ulong initial_secret_sz  = 32;

  fd_quic_hkdf_extract( initial_secret,
                        initial_salt, initial_salt_sz,
                        test_dst_conn_id, 8UL,
                        fd_hmac_sha256 );

  FD_LOG_HEXDUMP_NOTICE(( "initial_secret", initial_secret, initial_secret_sz ));

  // Derive key TEST from rfc9001

  // hash create
  // create secrets

  // client_initial_secret
  //      = HKDF-Expand-Label(initial_secret, "client in", "", 32)
  //      = c00cf151ca5be075ed0ebfb5c80323c4 2d6b7db67881289af4008f1f6c357aea
  uchar client_initial_secret[32] = {0};
  ulong client_initial_secret_sz = 32;

  test_secret_gen( client_initial_secret, initial_secret, initial_secret_sz, "client in", 32 );

  // uchar server_initial_secret[32] = {0};
  // ulong server_initial_secret_sz = 32;

  // test_secret_gen( server_initial_secret, initial_secret, initial_secret_sz, "server in", 32 );

  // expected from rfc9001 section A1
  uchar quic_iv_secret[12] = {0};
  test_secret_gen( quic_iv_secret, client_initial_secret, client_initial_secret_sz, "quic iv", 12 );

  // key = HKDF-Expand-Label(client_initial_secret, "quic key", "", 16)
  //       = 1f369613dd76d5467730efcbe3b1a22d

  uchar client_key[16] = {0};
  test_secret_gen( client_key, client_initial_secret, client_initial_secret_sz, "quic key", 16 );

  // hp  = HKDF-Expand-Label(client_initial_secret, "quic hp", "", 16)
  //       = 9f50449e04a0e810283a1e9933adedd2
  uchar client_hp_key[16] = {0};
  test_secret_gen( client_hp_key, client_initial_secret, client_initial_secret_sz, "quic hp", 16 );

  // encryption/header protection

  // The unprotected header indicates a length of 1182 bytes: the 4-byte packet number, 1162 bytes of frames,
  // and the 16-byte authentication tag. The header includes the connection ID and a packet number of 2:
  //     c300000001088394c8f03e5157080000449e00000002
  // uchar packet_header[] = { 0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94,
  //                           0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00, 0x00,
  //                           0x44, 0x9e, 0x00, 0x00, 0x00, 0x02 };
  uchar packet_header[] = { 0xc1, 0x00, 0x00, 0x00, 0x01, 0x08, 0x2a, 0x68,
                            0x59, 0x18, 0x78, 0xc8, 0x91, 0x4c, 0x08, 0xec,
                            0x73, 0x1b, 0x41, 0xa0, 0xd5, 0xc6, 0xfe, 0x00,
                            0x44, 0xe6, 0x00, 0x00 };

  // load cipher suite
  EVP_CIPHER *FD_AES_128_GCM_ALG_HANDLE;
  // EVP_CIPHER *FD_AES_256_GCM_ALG_HANDLE;
  // EVP_CIPHER *FD_AES_256_CBC_ALG_HANDLE;
  EVP_CIPHER *FD_AES_128_ECB_ALG_HANDLE;
  // EVP_CIPHER *FD_AES_256_ECB_ALG_HANDLE;

  FD_AES_128_GCM_ALG_HANDLE = (EVP_CIPHER *)EVP_aes_128_gcm();
  FD_AES_128_ECB_ALG_HANDLE = (EVP_CIPHER *)EVP_aes_128_ecb();

  EVP_CIPHER_CTX* cipher_ctx = EVP_CIPHER_CTX_new();
  FD_TEST( cipher_ctx );

  // packet number is 0
  uchar packet_number[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

  uchar nonce[12] = {0};
  for( ulong j = 0; j < 12; ++j ) {
    nonce[j] = quic_iv_secret[j] ^ packet_number[j] ;
  }

  const EVP_CIPHER *aead;

  // Initial packets use AEAD_AES_128_GCM with keys derived from the Destination Connection ID field of the
  // first Initial packet sent by the client; see Section 5.2.
  aead = FD_AES_128_GCM_ALG_HANDLE;

  FD_TEST( 1==EVP_CipherInit_ex( cipher_ctx, aead, NULL, NULL, NULL, 1 /* encryption */ ) );

  FD_TEST( 1==EVP_CIPHER_CTX_ctrl( cipher_ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL ) );

  FD_TEST( 1==EVP_EncryptInit_ex( cipher_ctx, aead, NULL, client_key, nonce ) );

  // auth data???

  // uchar auth_data[64] = {0};

  int outl = 0;
  FD_TEST( 1==EVP_EncryptUpdate( cipher_ctx, NULL, &outl, packet_header, sizeof( packet_header ) ) );

  uchar cipher_text[4096];
  ulong offset = 0;
  int cipher_text_sz = 2048;
  int plain_text_sz = sizeof( test_client_initial );
  FD_LOG_NOTICE(( "plain_text_sz: %d", plain_text_sz ));

  FD_TEST( 1==EVP_EncryptUpdate( cipher_ctx, cipher_text, &cipher_text_sz, test_client_initial, plain_text_sz ) );
  FD_TEST( cipher_text_sz>=0 );
  offset = (ulong)cipher_text_sz;

  FD_LOG_NOTICE(( "Encrypted %d bytes", cipher_text_sz ));

  FD_TEST( 1==EVP_EncryptFinal( cipher_ctx, cipher_text + offset, &cipher_text_sz ) );
  FD_TEST( cipher_text_sz>=0 );
  offset += (ulong)cipher_text_sz;

  // TODO put TAG on end
  //   see if (EVP_CIPHER_CTX_ctrl(CipherCtx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {

  FD_TEST( 1==EVP_CIPHER_CTX_ctrl( cipher_ctx, EVP_CTRL_AEAD_GET_TAG, 16, cipher_text + offset  ) );

  offset += 16;

  FD_LOG_NOTICE(( "Encrypted %d bytes", cipher_text_sz ));

  printf( "plain_text: " );
  for( ulong j=0; j < (ulong)plain_text_sz; ++j ) {
    printf( "%2.2x ", test_client_initial[j] );
  }
  printf( "\n" );
  printf( "\n" );

  printf( "cipher_text: " );
  for( ulong j=0; j < offset+(ulong)cipher_text_sz; ++j ) {
    printf( "%2.2x ", cipher_text[j] );
  }
  printf( "\n" );


  // Header protection

  EVP_CIPHER_CTX* hp_cipher_ctx = EVP_CIPHER_CTX_new();
  FD_TEST( hp_cipher_ctx );

  FD_TEST( 1==EVP_CipherInit_ex( hp_cipher_ctx, FD_AES_128_ECB_ALG_HANDLE, NULL, NULL, NULL, 1 /* encryption */ ) );

  FD_TEST( 1==EVP_EncryptInit_ex( hp_cipher_ctx, NULL, NULL, client_hp_key, NULL ) );

  uchar const * sample = cipher_text + 2; // not necessarily true - the sample begins 4 bytes after the start of the packet number
  uchar hp_cipher[64];
  int hp_cipher_sz = 0;
  FD_TEST( 1==EVP_EncryptUpdate( hp_cipher_ctx, hp_cipher, &hp_cipher_sz, sample, 16 ) );

  printf( "hp: " );
  for( ulong j=0; j<16; ++j ) {
    printf( "%2.2x ", hp_cipher[j] );
  }
  printf( "\n" );

  // hp_cipher is mask
  uchar const * mask = hp_cipher;
  uchar enc_header[64];

  fd_memcpy( enc_header, packet_header, sizeof( packet_header ) );

  // long header
  ulong pn_length = ( packet_header[0] & 0x03u ) + 1;
  enc_header[0] = (uchar)(enc_header[0] ^ (mask[0] & 0x0fu)); // short would be "& 0x1fu"

  ulong pn_offset = 26;

  for( ulong j = 0; j < pn_length; ++j ) {
    enc_header[pn_offset + j] ^= mask[1+j];
  }

  FD_LOG_HEXDUMP_INFO(( "header",  packet_header, sizeof(packet_header) ));
  FD_LOG_HEXDUMP_INFO(( "encoded", enc_header,    sizeof(packet_header) ));

  // FD_TEST( 1==EVP_DecryptInit_ex( cipher_ctx, NULL, NULL, NULL, Iv ) );


  // to decrypt...
  //   calculate the secrets
  //   calculate the keys
  //   find the sample
  //   calculate the header mask
  //   apply the header mask
  //   use the header to determine the nonce for the decryption
  //   decrypt the packet
  //   determine the tag
  //   compare the tag

  // then we can start handling the frames

  EVP_CIPHER_CTX_free( cipher_ctx    );
  EVP_CIPHER_CTX_free( hp_cipher_ctx );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
