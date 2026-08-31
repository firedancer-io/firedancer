#include "../fd_ballet.h"
#include "fd_secp384r1.h"
#include "../hex/fd_hex.h"

#if FD_USING_GCC && __GNUC__ >= 15
#pragma GCC diagnostic ignored "-Wunterminated-string-initialization"
#endif

/* msg = "test message for P-384 ECDSA verification" (41 bytes) */
static uchar const test_msg[] = {
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
  0x20, 0x66, 0x6f, 0x72, 0x20, 0x50, 0x2d, 0x33, 0x38, 0x34, 0x20, 0x45,
  0x43, 0x44, 0x53, 0x41, 0x20, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63,
  0x61, 0x74, 0x69, 0x6f, 0x6e
};
#define TEST_MSG_SZ 41

/* raw signature r||s (96 bytes) */
static uchar const test_sig[] = {
  0x48, 0x4a, 0x83, 0x19, 0x33, 0x28, 0x78, 0xfc, 0x91, 0xc0, 0x8a, 0xfe,
  0x3e, 0xde, 0x19, 0xc9, 0x7a, 0x92, 0xbd, 0xf5, 0x1f, 0x50, 0x11, 0xae,
  0xe4, 0x26, 0x78, 0xbf, 0xa9, 0x33, 0xdb, 0x38, 0xdd, 0x2f, 0x27, 0x34,
  0xcc, 0xc3, 0x56, 0x0d, 0xef, 0x4f, 0x84, 0xa6, 0x7a, 0xb5, 0xbc, 0xe0,
  0x5c, 0x7f, 0xf2, 0x6f, 0xd9, 0xa6, 0x05, 0x4f, 0xfe, 0x92, 0x48, 0x1f,
  0xb5, 0xea, 0xca, 0x24, 0x64, 0x9b, 0x00, 0xc4, 0xaa, 0xd4, 0x30, 0x56,
  0x7f, 0x94, 0x4a, 0x57, 0x29, 0xad, 0x0b, 0x27, 0x53, 0x3d, 0x97, 0x99,
  0xd0, 0x3e, 0x1e, 0xf3, 0xe2, 0x31, 0x2c, 0xa5, 0xf4, 0xd9, 0xcd, 0xa5
};

/* compressed public key (49 bytes: 02/03 || x) */
static uchar const test_pubkey[] = {
  0x02, 0x8f, 0xf5, 0x67, 0xc6, 0x55, 0x19, 0xcf, 0x12, 0x5e, 0x48, 0x34,
  0xfa, 0x2b, 0x6d, 0x7d, 0x7f, 0xe4, 0x48, 0x92, 0xb3, 0xec, 0xf1, 0x7d,
  0x59, 0xac, 0x19, 0x43, 0x42, 0x86, 0x1d, 0xb8, 0xc8, 0x4a, 0x08, 0xf5,
  0x24, 0xb1, 0xcb, 0xaa, 0xcb, 0x70, 0x82, 0xbc, 0x59, 0x61, 0xe6, 0xfc,
  0x14
};

/* This valid signature makes the verifier compute u1*G == u2*A.  Here
   u1=1, r=x(2G), s=SHA-384(msg), and A=(s/r)G. */
static uchar const equal_points_msg[] = "p384 equal-points regression";

static uchar const equal_points_sig[] = {
  0x08, 0xd9, 0x99, 0x05, 0x7b, 0xa3, 0xd2, 0xd9, 0x69, 0x26, 0x00, 0x45,
  0xc5, 0x5b, 0x97, 0xf0, 0x89, 0x02, 0x59, 0x59, 0xa6, 0xf4, 0x34, 0xd6,
  0x51, 0xd2, 0x07, 0xd1, 0x9f, 0xb9, 0x6e, 0x9e, 0x4f, 0xe0, 0xe8, 0x6e,
  0xbe, 0x0e, 0x64, 0xf8, 0x5b, 0x96, 0xa9, 0xc7, 0x52, 0x95, 0xdf, 0x61,
  0x3b, 0xea, 0x15, 0x34, 0x7b, 0x36, 0x36, 0xdb, 0x37, 0xcc, 0xfe, 0x25,
  0x05, 0x4c, 0x19, 0xc1, 0x96, 0x17, 0x6c, 0xa2, 0x39, 0xd8, 0xb6, 0x39,
  0x95, 0x1e, 0x4f, 0xd0, 0xb7, 0x36, 0xb7, 0xed, 0xfe, 0xcf, 0xb4, 0xa4,
  0x4d, 0xb4, 0x72, 0xad, 0x62, 0xe8, 0x25, 0xcc, 0x9e, 0x5f, 0xd7, 0xee,
};

static uchar const equal_points_pubkey[] = {
  0x03, 0x6a, 0x7f, 0xe3, 0x41, 0x34, 0xff, 0xac, 0xac, 0x83, 0xba, 0x8f,
  0x70, 0xb4, 0x23, 0x7a, 0xbc, 0x24, 0x9b, 0xd2, 0xa2, 0xdc, 0x3d, 0x5f,
  0x7f, 0xb2, 0x8b, 0x30, 0x54, 0xca, 0xe5, 0x5f, 0x70, 0xe0, 0xb4, 0x32,
  0x44, 0x92, 0x59, 0x3a, 0x2c, 0xb3, 0x61, 0x1a, 0x2d, 0x74, 0x17, 0x42,
  0x10,
};

static void
test_public_key_compress( void ) {
  uchar uncompressed[ 97 ];
  uchar compressed  [ 49 ];
  uchar expected    [ 49 ];

  fd_hex_decode( uncompressed,
                 "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385"
                 "502f25dbf55296c3a545e3872760ab7"
                 "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
                 "0a60b1ce1d7e819d7a431d7c90ea0e5f",
                 97UL );
  fd_hex_decode( expected,
                 "03aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385"
                 "502f25dbf55296c3a545e3872760ab7",
                 49UL );

  FD_TEST( fd_secp384r1_public_key_compress( compressed, uncompressed )==FD_SECP384R1_SUCCESS );
  FD_TEST( fd_memeq( compressed, expected, sizeof(expected) ) );

  /* Preserve y parity while corrupting the rest of the coordinate. */
  uchar bad[ 97 ];
  fd_memcpy( bad, uncompressed, sizeof(bad) );
  bad[ 49 ] ^= 1U;
  FD_TEST( fd_secp384r1_public_key_compress( compressed, bad )==FD_SECP384R1_FAILURE );

  fd_memcpy( bad, uncompressed, sizeof(bad) );
  bad[ 0 ] = 0x02U;
  FD_TEST( fd_secp384r1_public_key_compress( compressed, bad )==FD_SECP384R1_FAILURE );

  fd_memcpy( bad, uncompressed, sizeof(bad) );
  fd_hex_decode( bad+1,
                 "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
                 "ffffffff0000000000000000ffffffff",
                 48UL );
  FD_TEST( fd_secp384r1_public_key_compress( compressed, bad )==FD_SECP384R1_FAILURE );

  fd_memcpy( bad, uncompressed, sizeof(bad) );
  fd_hex_decode( bad+49,
                 "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
                 "ffffffff0000000000000000ffffffff",
                 48UL );
  FD_TEST( fd_secp384r1_public_key_compress( compressed, bad )==FD_SECP384R1_FAILURE );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_sha512_t sha[1];
  FD_TEST( fd_sha512_join( fd_sha512_new( sha ) ) );

  test_public_key_compress();

  /* Test 1: invalid signature (all zeros) must be rejected */
  {
    uchar zero_sig[96] = {0};
    uchar zero_pub[49] = {0}; zero_pub[0] = 0x02;
    FD_TEST( fd_secp384r1_verify( (uchar const *)"x", 1, zero_sig, zero_pub, sha ) == FD_SECP384R1_FAILURE );
    FD_TEST( fd_secp384r1_verify_no_low_s( (uchar const *)"x", 1, zero_sig, zero_pub, sha ) == FD_SECP384R1_FAILURE );
    FD_LOG_INFO(( "OK: invalid signatures rejected" ));
  }

  /* Test 2: valid signature must verify (no low-S check) */
  {
    int result = fd_secp384r1_verify_no_low_s( test_msg, TEST_MSG_SZ, test_sig, test_pubkey, sha );
    FD_TEST( result == FD_SECP384R1_SUCCESS );
    FD_TEST( fd_secp384r1_verify( test_msg, TEST_MSG_SZ, test_sig, test_pubkey, sha ) == FD_SECP384R1_SUCCESS );
    FD_LOG_INFO(( "OK: valid ECDSA-P384 signature verified (no_low_s)" ));
  }

  /* Test 3: corrupted signature must fail */
  {
    uchar bad_sig[96];
    fd_memcpy( bad_sig, test_sig, 96 );
    bad_sig[0] ^= 0x01;
    FD_TEST( fd_secp384r1_verify_no_low_s( test_msg, TEST_MSG_SZ, bad_sig, test_pubkey, sha ) == FD_SECP384R1_FAILURE );
    FD_LOG_INFO(( "OK: corrupted signature rejected" ));
  }

  /* Test 4: wrong message must fail */
  {
    uchar wrong_msg[] = "wrong message for P-384 ECDSA verification";
    FD_TEST( fd_secp384r1_verify_no_low_s( wrong_msg, sizeof(wrong_msg)-1, test_sig, test_pubkey, sha ) == FD_SECP384R1_FAILURE );
    FD_LOG_INFO(( "OK: wrong message rejected" ));
  }

  /* Test 5: wrong pubkey must fail */
  {
    uchar bad_pub[49];
    fd_memcpy( bad_pub, test_pubkey, 49 );
    bad_pub[1] ^= 0x01;
    FD_TEST( fd_secp384r1_verify_no_low_s( test_msg, TEST_MSG_SZ, test_sig, bad_pub, sha ) == FD_SECP384R1_FAILURE );
    FD_LOG_INFO(( "OK: wrong pubkey rejected" ));
  }

  /* Test 6: equal Jacobian summands must be doubled, not mapped to infinity */
  {
    FD_TEST( fd_secp384r1_verify( equal_points_msg, sizeof(equal_points_msg)-1UL,
                                 equal_points_sig, equal_points_pubkey, sha ) == FD_SECP384R1_SUCCESS );
    FD_LOG_INFO(( "OK: equal-point addition signature verified" ));
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
