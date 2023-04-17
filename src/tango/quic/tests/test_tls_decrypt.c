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
uchar test_client_initial[1162] = {
    0x06, 0x00, 0x40, 0xf1, 0x01, 0x00, 0x00, 0xed, 0x03, 0x03, 0xeb, 0xf8, 0xfa, 0x56, 0xf1, 0x29,
    0x39, 0xb9, 0x58, 0x4a, 0x38, 0x96, 0x47, 0x2e, 0xc4, 0x0b, 0xb8, 0x63, 0xcf, 0xd3, 0xe8, 0x68,
    0x04, 0xfe, 0x3a, 0x47, 0xf0, 0x6a, 0x2b, 0x69, 0x48, 0x4c, 0x00, 0x00, 0x04, 0x13, 0x01, 0x13,
    0x02, 0x01, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b, 0x65, 0x78,
    0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a,
    0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x10, 0x00, 0x07, 0x00, 0x05,
    0x04, 0x61, 0x6c, 0x70, 0x6e, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33,
    0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x93, 0x70, 0xb2, 0xc9, 0xca, 0xa4, 0x7f, 0xba,
    0xba, 0xf4, 0x55, 0x9f, 0xed, 0xba, 0x75, 0x3d, 0xe1, 0x71, 0xfa, 0x71, 0xf5, 0x0f, 0x1c, 0xe1,
    0x5d, 0x43, 0xe9, 0x94, 0xec, 0x74, 0xd7, 0x48, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00,
    0x0d, 0x00, 0x10, 0x00, 0x0e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03, 0x08, 0x04, 0x08,
    0x05, 0x08, 0x06, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01, 0x00,
    0x39, 0x00, 0x32, 0x04, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x05, 0x04, 0x80,
    0x00, 0xff, 0xff, 0x07, 0x04, 0x80, 0x00, 0xff, 0xff, 0x08, 0x01, 0x10, 0x01, 0x04, 0x80, 0x00,
    0x75, 0x30, 0x09, 0x01, 0x10, 0x0f, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x06,
    0x04, 0x80, 0x00, 0xff, 0xff };

// 0x8394c8f03e515708
uchar test_dst_conn_id[8] = "\x83\x94\xc8\xf0\x3e\x51\x57\x08";

// keys from rfc9001:
//  client in:
//  00200f746c73313320636c69656e7420696e00
uchar client_in[] = { 0x00, 0x20, 0x0f, 0x74, 0x6c, 0x73, 0x31, 0x33,
                      0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20,
                      0x69, 0x6e, 0x00 };
//  server in:
//  00200f746c7331332073657276657220696e00
uchar server_in[] = { 0x00, 0x20, 0x0f, 0x74, 0x6c, 0x73, 0x31, 0x33,
                      0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20,
                      0x69, 0x6e, 0x00 };
//  quic key:
//  00100e746c7331332071756963206b657900
uchar quic_key[] =  { 0x00, 0x10, 0x0e, 0x74, 0x6c, 0x73, 0x31, 0x33,
                      0x20, 0x71, 0x75, 0x69, 0x63, 0x20, 0x6b, 0x65,
                      0x79, 0x00 };
//  quic iv:
//  000c0d746c733133207175696320697600
uchar quic_iv[] =   { 0x00, 0x0c, 0x0d, 0x74, 0x6c, 0x73, 0x31, 0x33,
                      0x20, 0x71, 0x75, 0x69, 0x63, 0x20, 0x69, 0x76,
                      0x00 };
//  quic hp:
//  00100d746c733133207175696320687000
uchar quic_hp[] =   { 0x00, 0x10, 0x0d, 0x74, 0x6c, 0x73, 0x31, 0x33,
                      0x20, 0x71, 0x75, 0x69, 0x63, 0x20, 0x68, 0x70,
                      0x00 };

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
  ulong initial_secret_sz  = sizeof( initial_secret );

  // expected value from rfc9001:
  // 7db5df06e7a69e432496adedb0085192 3595221596ae2ae9fb8115c1e9ed0a44
  uchar initial_secret_expect[32] = {
    0x7d, 0xb5, 0xdf, 0x06, 0xe7, 0xa6, 0x9e, 0x43,
    0x24, 0x96, 0xad, 0xed, 0xb0, 0x08, 0x51, 0x92,
    0x35, 0x95, 0x22, 0x15, 0x96, 0xae, 0x2a, 0xe9,
    0xfb, 0x81, 0x15, 0xc1, 0xe9, 0xed, 0x0a, 0x44 };

  fd_quic_hkdf_extract( initial_secret,
                        initial_salt,     initial_salt_sz,
                        test_dst_conn_id, sizeof( test_dst_conn_id ),
                        fd_hmac_sha256 );

  FD_LOG_HEXDUMP_NOTICE(( "initial secret", initial_secret, initial_secret_sz ));

  FD_TEST( 0==memcmp( initial_secret, initial_secret_expect, initial_secret_sz ) );
  FD_LOG_NOTICE(( "initial_secret PASSED" ));

  // Derive key TEST from rfc9001

  // hash create
  // create secrets

  // client_initial_secret
  //      = HKDF-Expand-Label(initial_secret, "client in", "", 32)
  //      = c00cf151ca5be075ed0ebfb5c80323c4 2d6b7db67881289af4008f1f6c357aea
  uchar const expected_client_initial_secret[] = {
    0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4,
    0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea };
  ulong expected_client_initial_secret_sz = sizeof( expected_client_initial_secret );
  test_secret_gen( expected_client_initial_secret, initial_secret, initial_secret_sz, "client in", 32 );

  // expected from rfc9001 section A1
  uchar const expected_quic_iv_secret[] = { 0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c };
  test_secret_gen( expected_quic_iv_secret, expected_client_initial_secret, expected_client_initial_secret_sz, "quic iv", 12 );

  // key = HKDF-Expand-Label(client_initial_secret, "quic key", "", 16)
  //       = 1f369613dd76d5467730efcbe3b1a22d

  uchar const expected_client_key[] = { 0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
                                        0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d };
  test_secret_gen( expected_client_key, expected_client_initial_secret, expected_client_initial_secret_sz, "quic key", 16 );

  // hp  = HKDF-Expand-Label(client_initial_secret, "quic hp", "", 16)
  //       = 9f50449e04a0e810283a1e9933adedd2
  uchar const expected_client_hp_key[] = { 0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
                                           0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2 };
  test_secret_gen( expected_client_hp_key, expected_client_initial_secret, expected_client_initial_secret_sz, "quic hp", 16 );

  // encryption/header protection

  // The unprotected header indicates a length of 1182 bytes: the 4-byte packet number, 1162 bytes of frames,
  // and the 16-byte authentication tag. The header includes the connection ID and a packet number of 2:
  //     c300000001088394c8f03e5157080000449e00000002
  uchar packet_header[] = { 0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94,
                            0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00, 0x00,
                            0x44, 0x9e, 0x00, 0x00, 0x00, 0x02 };

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

  // packet number is 2
  uchar packet_number[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

  uchar nonce[12] = {0};
  for( ulong j=0; j<12; ++j ) {
    nonce[j] = expected_quic_iv_secret[j] ^ packet_number[j] ;
  }

  const EVP_CIPHER *aead;

  // Initial packets use AEAD_AES_128_GCM with keys derived from the Destination Connection ID field of the
  // first Initial packet sent by the client; see Section 5.2.
  aead = FD_AES_128_GCM_ALG_HANDLE;

  FD_TEST( 1==EVP_CipherInit_ex( cipher_ctx, aead, NULL, NULL, NULL, 1 /* encryption */ ) );

  FD_TEST( 1==EVP_CIPHER_CTX_ctrl( cipher_ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL ) );

  FD_TEST( 1==EVP_EncryptInit_ex( cipher_ctx, aead, NULL, expected_client_key, nonce ) );

  // auth data???

  // uchar auth_data[64] = {};

  int outl = 0;
  FD_TEST( 1==EVP_EncryptUpdate( cipher_ctx, NULL, &outl, packet_header, sizeof( packet_header ) ) );

  uchar cipher_text[4096];
  ulong offset = 0;
  int cipher_text_sz = 2048;
  int plain_text_sz = sizeof( test_client_initial );
  FD_TEST( 1==EVP_EncryptUpdate( cipher_ctx, cipher_text, &cipher_text_sz, test_client_initial, plain_text_sz ) );
  FD_TEST( cipher_text_sz>0 );
  offset = (ulong)cipher_text_sz;

  FD_LOG_NOTICE(( "Encrypted %d bytes", cipher_text_sz ));

  FD_TEST( 1==EVP_EncryptFinal( cipher_ctx, cipher_text + offset, &cipher_text_sz ) );
  FD_TEST( cipher_text_sz==0 );
  offset += (ulong)cipher_text_sz;

  // TODO put TAG on end
  //   see if (EVP_CIPHER_CTX_ctrl(CipherCtx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {

  FD_TEST( 1==EVP_CIPHER_CTX_ctrl( cipher_ctx, EVP_CTRL_AEAD_GET_TAG, 16, cipher_text + offset ) );

  offset += 16;

  FD_LOG_NOTICE(( "Encrypted %d bytes", cipher_text_sz ));

  FD_LOG_HEXDUMP_NOTICE(( "plain_text",  test_client_initial, sizeof(test_client_initial) ));
  FD_LOG_HEXDUMP_NOTICE(( "cipher_text", cipher_text,         offset                      ));

  // Header protection

  EVP_CIPHER_CTX* hp_cipher_ctx = EVP_CIPHER_CTX_new();
  FD_TEST( hp_cipher_ctx );

  FD_TEST( 1==EVP_CipherInit_ex( hp_cipher_ctx, FD_AES_128_ECB_ALG_HANDLE, NULL, NULL, NULL, 1 /* encryption */ ) );

  FD_TEST( 1==EVP_EncryptInit_ex( hp_cipher_ctx, NULL, NULL, expected_client_hp_key, NULL ) );

  uchar const * sample = cipher_text; // not necessarily true - the sample begins 4 bytes after the start of the packet number
  uchar hp_cipher[64];
  int hp_cipher_sz = 0;
  FD_TEST( 1==EVP_EncryptUpdate( hp_cipher_ctx, hp_cipher, &hp_cipher_sz, sample, 16 ) );

  FD_LOG_HEXDUMP_INFO(( "hp", hp_cipher, 16UL ));

  // FD_TEST( 1==EVP_DecryptInit_ex( cipher_ctx, NULL, NULL, NULL, Iv ) );

  EVP_CIPHER_CTX_free( cipher_ctx    );
  EVP_CIPHER_CTX_free( hp_cipher_ctx );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
