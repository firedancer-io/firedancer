#include "../fd_ballet.h"
#include "fd_secp256k1.h"
#include "../hex/fd_hex.h"

static void
log_bench( char const * descr,
           ulong        iter,
           long         dt ) {
  float khz = 1e6f *(float)iter/(float)dt;
  float tau = (float)dt /(float)iter;
  FD_LOG_NOTICE(( "%-31s %11.3fK/s/core %10.3f ns/call", descr, (double)khz, (double)tau ));
}

/**********************************************************************/
/* Helper: decode hex and recover, checking expected result            */
/**********************************************************************/

static void
test_recover_ok( char const * sig_hex,
                 char const * msg_hex,
                 int          rec_id,
                 char const * pub_hex ) {
  uchar sig[64], msg[32], pub[64], pub_expected[64];
  fd_hex_decode( sig, sig_hex, 64 );
  fd_hex_decode( msg, msg_hex, 32 );
  fd_hex_decode( pub_expected, pub_hex, 64 );
  FD_TEST( fd_secp256k1_recover( pub, msg, sig, rec_id ) == pub );
  if( memcmp( pub, pub_expected, 64UL ) ) {
    FD_LOG_HEXDUMP_WARNING(( "expected", pub_expected, 64UL ));
    FD_LOG_HEXDUMP_WARNING(( "got     ", pub,          64UL ));
    FD_LOG_ERR(( "FAIL: recovery mismatch for rec_id=%d", rec_id ));
  }
}

static void
test_recover_fail( char const * sig_hex,
                   char const * msg_hex,
                   int          rec_id ) {
  uchar sig[64], msg[32], pub[64];
  fd_hex_decode( sig, sig_hex, 64 );
  fd_hex_decode( msg, msg_hex, 32 );
  FD_TEST( fd_secp256k1_recover( pub, msg, sig, rec_id ) == NULL );
}

/**********************************************************************/
/* Test: recovery – original tests (Solana, Ethereum)                 */
/**********************************************************************/

static void
test_recover( FD_FN_UNUSED fd_rng_t * rng ) {
  FD_LOG_NOTICE(( "Testing recovery (Solana/Ethereum vectors)" ));

  /* Solana test #1
     https://github.com/solana-labs/solana/blob/v1.17.4/programs/sbf/rust/secp256k1_recover/src/lib.rs */
  {
    uchar _pub_expected[ 65 ] = {
        0x42, 0xcd, 0x27, 0xe4, 0x0f, 0xdf, 0x7c, 0x97, 0x0a, 0xa2, 0xca, 0x0b, 0x88, 0x5b, 0x96,
        0x0f, 0x8b, 0x62, 0x8a, 0x41, 0xa1, 0x81, 0xe7, 0xe6, 0x8e, 0x03, 0xea, 0x0b, 0x84, 0x20,
        0x58, 0x9b, 0x32, 0x06, 0xbd, 0x66, 0x2f, 0x75, 0x65, 0xd6, 0x9d, 0xbd, 0x1d, 0x34, 0x29,
        0x6a, 0xd9, 0x35, 0x38, 0xed, 0x86, 0x9e, 0x99, 0x20, 0x43, 0xc3, 0xeb, 0xad, 0x65, 0x50,
        0xa0, 0x11, 0x6e, 0x5d,
    }; uchar * pub_expected = _pub_expected;
    uchar _msg[ 32 ] = {
        0xde, 0xa5, 0x66, 0xb6, 0x94, 0x3b, 0xe0, 0xe9, 0x62, 0x53, 0xc2, 0x21, 0x5b, 0x1b, 0xac,
        0x69, 0xe7, 0xa8, 0x1e, 0xdb, 0x41, 0xc5, 0x02, 0x8b, 0x4f, 0x5c, 0x45, 0xc5, 0x3b, 0x49,
        0x54, 0xd0,
    }; uchar * msg = _msg;
    int rec_id = 1;
    uchar _sig[ 64 ] = {
        0x97, 0xa4, 0xee, 0x31, 0xfe, 0x82, 0x65, 0x72, 0x9f, 0x4a, 0xa6, 0x7d, 0x24, 0xd4, 0xa7,
        0x27, 0xf8, 0xc3, 0x15, 0xa4, 0xc8, 0xf9, 0x80, 0xeb, 0x4c, 0x4d, 0x4a, 0xfa, 0x6e, 0xc9,
        0x42, 0x41, 0x5d, 0x10, 0xd9, 0xc2, 0x8a, 0x90, 0xe9, 0x92, 0x9c, 0x52, 0x4b, 0x2c, 0xfb,
        0x65, 0xdf, 0xbc, 0xf6, 0x8c, 0xfd, 0x68, 0xdb, 0x17, 0xf9, 0x5d, 0x23, 0x5f, 0x96, 0xd8,
        0xf0, 0x72, 0x01, 0x2d,
    }; uchar * sig = _sig;
    uchar _pub[ 65 ]; uchar * pub = _pub;
    FD_TEST( fd_secp256k1_recover(pub, msg, sig, rec_id)==pub );
    FD_TEST( !memcmp( pub, pub_expected, 64UL ) );
  }

  /* Solana test #2 (keccak256("hello world")) */
  {
    uchar _pub_expected[ 65 ] = {
        0x9B, 0xEE, 0x7C, 0x18, 0x34, 0xE0, 0x18, 0x21, 0x7B, 0x40, 0x14, 0x9B, 0x84, 0x2E, 0xFA,
        0x80, 0x96, 0x00, 0x1A, 0x9B, 0x17, 0x88, 0x01, 0x80, 0xA8, 0x46, 0x99, 0x09, 0xE9, 0xC4,
        0x73, 0x6E, 0x39, 0x0B, 0x94, 0x00, 0x97, 0x68, 0xC2, 0x28, 0xB5, 0x55, 0xD3, 0x0C, 0x0C,
        0x42, 0x43, 0xC1, 0xEE, 0xA5, 0x0D, 0xC0, 0x48, 0x62, 0xD3, 0xAE, 0xB0, 0x3D, 0xA2, 0x20,
        0xAC, 0x11, 0x85, 0xEE,
    }; uchar * pub_expected = _pub_expected;
    uchar _msg[ 32 ]; uchar * msg = _msg;
    fd_hex_decode(msg, "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad", 32);
    int rec_id = 0;
    uchar _sig[ 64 ] = {
        0x93, 0x92, 0xC4, 0x6C, 0x42, 0xF6, 0x31, 0x73, 0x81, 0xD4, 0xB2, 0x44, 0xE9, 0x2F, 0xFC,
        0xE3, 0xF4, 0x57, 0xDD, 0x50, 0xB3, 0xA5, 0x20, 0x26, 0x3B, 0xE7, 0xEF, 0x8A, 0xB0, 0x69,
        0xBB, 0xDE, 0x2F, 0x90, 0x12, 0x93, 0xD7, 0x3F, 0xA0, 0x29, 0x0C, 0x46, 0x4B, 0x97, 0xC5,
        0x00, 0xAD, 0xEA, 0x6A, 0x64, 0x4D, 0xC3, 0x8D, 0x25, 0x24, 0xEF, 0x97, 0x6D, 0xC6, 0xD7,
        0x1D, 0x9F, 0x5A, 0x26,
    }; uchar * sig = _sig;
    uchar _pub[ 65 ]; uchar * pub = _pub;
    FD_TEST( fd_secp256k1_recover(pub, msg, sig, rec_id)==pub );
    FD_TEST( !memcmp( pub, pub_expected, 64UL ) );
  }

  /* Ethereum test
     https://github.com/ethereum/go-ethereum/blob/v1.13.4/crypto/secp256k1/secp256_test.go#L206 */
  uchar _pub_expected[ 65 ]; uchar * pub_expected = _pub_expected;
  uchar _pub[ 65 ]; uchar * pub = _pub;
  uchar _msg[ 32 ]; uchar * msg = _msg;
  uchar _sig[ 64 ]; uchar * sig = _sig;
  int rec_id = 0;

  fd_hex_decode(msg, "ce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008", 32);
  fd_hex_decode(sig, "90f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e549984a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc93", 64);
  rec_id = 1;
  fd_hex_decode(pub_expected, "e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f15878109880a0a2b2667f7e725ceea70c673093bf67663e0312623c8e091b13cf2c0f11ef652", 64);
  FD_TEST( fd_secp256k1_recover(pub, msg, sig, rec_id)==pub );
  FD_TEST( !memcmp( pub, pub_expected, 64UL ) );

  /* Test sig recovery succeeds but returns incorrect public key */
  uchar saved = msg[0];
  msg[0] = 0;
  FD_TEST( fd_secp256k1_recover(pub, msg, sig, rec_id)==pub );
  FD_TEST( !!memcmp( pub, pub_expected, 64UL ) );
  msg[0] = saved;

  /* Test sig recovery fails (zeroing first byte of r makes r start
     with 0x00, putting it out of range depending on remaining bytes) */
  saved = sig[0];
  sig[0] = 0;
  FD_TEST( fd_secp256k1_recover(pub, msg, sig, rec_id)==NULL );
  sig[0] = saved;

  /* Test recovery id fails (but doesn't panic) */
  FD_TEST( fd_secp256k1_recover(pub, msg, sig, -1)==NULL );  /* invalid */
  FD_TEST( fd_secp256k1_recover(pub, msg, sig, 3)==NULL );   /* incorrect */
  FD_TEST( fd_secp256k1_recover(pub, msg, sig, 4)==NULL );   /* invalid */
  FD_TEST( fd_secp256k1_recover(pub, msg, sig, 123)==NULL ); /* invalid */

  FD_LOG_NOTICE(( "Recovery original tests passed" ));
}

/**********************************************************************/
/* Test: recovery – extended vectors                                  */
/* (Generated algebraically: privkey=1, pubkey=G)                     */
/**********************************************************************/

static void
test_recover_extended( void ) {
  FD_LOG_NOTICE(( "Testing recovery (extended vectors)" ));

  /* privkey=1 (pubkey=G), k=7, msg=0xdeadbeef..., recovery_id=0 */
  test_recover_ok(
    "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc"
    "bf5886c2e39f7daa6083907c4746116f25861d6eef54dfe5fca30c9701a8db40",
    "deadbeefcafebabe0000000000000000deadbeefcafebabe0000000000000000",
    0,
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
  );

  /* Same sig, recovery_id=1 gives a different (valid) public key */
  test_recover_ok(
    "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc"
    "bf5886c2e39f7daa6083907c4746116f25861d6eef54dfe5fca30c9701a8db40",
    "deadbeefcafebabe0000000000000000deadbeefcafebabe0000000000000000",
    1,
    "83048846fd31e56526c3324d667b2f049672389e7567cf0b77b02055bda37e82"
    "1b5f94fbfb1f0795b3328dcce3ead76d5b9aea150f1e420845b192f84202f19a"
  );

  /* privkey=1, k=1 (nonce=1, so R=G), msg=0x01, recovery_id=0
     This exercises the case where r is the generator's x-coordinate,
     exercising large r values close to n. */
  test_recover_ok(
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81799",
    "0000000000000000000000000000000000000000000000000000000000000001",
    0,
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
  );

  /* privkey=1, k=42, all-zero message hash, recovery_id=0
     This exercises the msg_hash=0 edge case, which exercises
     scalar_tomont and scalar_negate with zero-like values. */
  test_recover_ok(
    "fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af"
    "3ceafaa2b5413874d60a6abe79aa5626e8afe5952b3bd33995550d1bfa881f8c",
    "0000000000000000000000000000000000000000000000000000000000000000",
    0,
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
  );

  /* privkey=1, k=7, msg=0xFF...FF (max 256-bit hash, larger than n)
     This exercises the case where msg_hash > n; the implementation
     must correctly reduce via Montgomery multiplication. */
  test_recover_ok(
    "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc"
    "566446e9c69fac218515d9a0d98f3601da46eca0abc83768182451c85f487624",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    0,
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
  );

  /* privkey=1, k=7, msg_hash = n+1 (one more than the group order).
     Since msg is reduced mod n via Montgomery multiplication,
     n+1 mod n = 1, so this tests that values above n are correctly
     handled (not truncated or rejected). */
  test_recover_ok(
    "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc"
    "31d1fdc53456878f3bf14757b4fcecdd47fdc80e62a3a51ef39208a3ccff5192",
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142",
    0,
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
  );

  /* recovery_id=2 (high-r path): r=2, x_actual=n+2, constructed algebraically.
     This exercises the recovery_id & 2 branch where r < p-n and the
     actual x-coordinate is r + n. */
  test_recover_ok(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    2,
    "529ef7eaff94e859890474307089d299f1b1ceaf4a9baa0c6d05fde6e90d26d5"
    "aacf7ebe39707e7a185286820e5491de0a66c32f1f1e9c49fc760148414f25b2"
  );

  /* recovery_id=3 (high-r + odd y) with the same (r,s) */
  test_recover_ok(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    3,
    "76b13533ba24b7143984c77d9ac70bd4b3ac9b0f4c1ddd917515ebf796402f2b"
    "352f80e70c0e04152b0b75ebe23c271faea07675726154777477e9ab4e38e82f"
  );

  /* Both rec_id=0 and rec_id=1 valid for r=1: two different public keys.
     This exercises recovery with the smallest valid r, and confirms that
     both y-parities give valid but distinct points. */
  test_recover_ok(
    "0000000000000000000000000000000000000000000000000000000000000001"
    "1111111122222222333333334444444455555555666666667777777788888888",
    "aaaaaaaabbbbbbbbccccccccddddddddaaaaaaaabbbbbbbbccccccccdddddddd",
    0,
    "f5cfabdb1477191f03c43805acd2f0ad616d238ea53da37769bc6d4c7fc32a37"
    "bae492a9030afd0e1825174df0d7864d3449ff17f7206a75c747772368b506dc"
  );

  test_recover_ok(
    "0000000000000000000000000000000000000000000000000000000000000001"
    "1111111122222222333333334444444455555555666666667777777788888888",
    "aaaaaaaabbbbbbbbccccccccddddddddaaaaaaaabbbbbbbbccccccccdddddddd",
    1,
    "7bc6f20380e59fa85af638dbf741a82a2763b0e8b2c27b28eb63b0a231466d1a"
    "3732b6935a8884484d254f52d1d86bd89fbdb59f430f93a2e53ef87aebdb19c5"
  );

  FD_LOG_NOTICE(( "Recovery extended tests passed" ));
}

/**********************************************************************/
/* Test: recovery – edge cases and failure paths                      */
/**********************************************************************/

static void
test_recover_edge_cases( void ) {
  FD_LOG_NOTICE(( "Testing recovery edge cases" ));

  /* Any valid message will do for rejection tests */
  char const * msg = "deadbeefcafebabe0000000000000000deadbeefcafebabe0000000000000000";

  /* r=0 should fail (scalar_frombytes rejects zero) */
  test_recover_fail(
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000001",
    msg, 0
  );

  /* s=0 should fail (scalar_frombytes rejects zero) */
  test_recover_fail(
    "0000000000000000000000000000000000000000000000000000000000000001"
    "0000000000000000000000000000000000000000000000000000000000000000",
    msg, 0
  );

  /* r=n should fail (scalar_frombytes rejects r >= n) */
  test_recover_fail(
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
    "0000000000000000000000000000000000000000000000000000000000000001",
    msg, 0
  );

  /* s=n should fail (scalar_frombytes rejects s >= n) */
  test_recover_fail(
    "0000000000000000000000000000000000000000000000000000000000000001"
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    msg, 0
  );

  /* r=n+1 should fail */
  test_recover_fail(
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"
    "0000000000000000000000000000000000000000000000000000000000000001",
    msg, 0
  );

  /* s=n+1 should fail */
  test_recover_fail(
    "0000000000000000000000000000000000000000000000000000000000000001"
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142",
    msg, 0
  );

  /* r=0xFFFF...FFFF should fail (much larger than n) */
  test_recover_fail(
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "0000000000000000000000000000000000000000000000000000000000000001",
    msg, 0
  );

  /* s=0xFFFF...FFFF should fail */
  test_recover_fail(
    "0000000000000000000000000000000000000000000000000000000000000001"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    msg, 0
  );

  /* Both r and s zero should fail */
  test_recover_fail(
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000",
    msg, 0
  );

  /* r=5 where x^3+7 is not a quadratic residue mod p:
     sqrt fails, so recovery_y returns NULL. */
  test_recover_fail(
    "0000000000000000000000000000000000000000000000000000000000000005"
    "0000000000000000000000000000000000000000000000000000000000000001",
    msg, 0
  );

  /* Same r=5 with recovery_id=1: still fails (sqrt still fails) */
  test_recover_fail(
    "0000000000000000000000000000000000000000000000000000000000000005"
    "0000000000000000000000000000000000000000000000000000000000000001",
    msg, 1
  );

  /* r=7 where x^3+7 is not a QR: sqrt fails */
  test_recover_fail(
    "0000000000000000000000000000000000000000000000000000000000000007"
    "0000000000000000000000000000000000000000000000000000000000000001",
    msg, 0
  );

  /* r=9 where x^3+7 is not a QR: sqrt fails */
  test_recover_fail(
    "0000000000000000000000000000000000000000000000000000000000000009"
    "0000000000000000000000000000000000000000000000000000000000000001",
    msg, 0
  );

  /* recovery_id=2 with r >= p-n: should fail at the p-n boundary check.
     p-n = 0x14551231950b75fc4402da1722fc9baee */
  test_recover_fail(
    "000000000000000000000000000000014551231950b75fc4402da1722fc9baee"
    "0000000000000000000000000000000000000000000000000000000000000001",
    msg, 2
  );

  /* recovery_id=2 with r = p-n+1: also fail */
  test_recover_fail(
    "000000000000000000000000000000014551231950b75fc4402da1722fc9baef"
    "0000000000000000000000000000000000000000000000000000000000000001",
    msg, 2
  );

  /* recovery_id=2 with r = p-n-1: x = r+n = p-1, and (p-1)^3+7 = 6 mod p
     which is not a QR, so sqrt fails. */
  test_recover_fail(
    "000000000000000000000000000000014551231950b75fc4402da1722fc9baed"
    "0000000000000000000000000000000000000000000000000000000000000001",
    msg, 2
  );

  /* recovery_id=2 with r=0: fails because scalar_frombytes rejects 0 */
  test_recover_fail(
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000001",
    msg, 2
  );

  /* recovery_id=2 with r=1: x=n+1, (n+1)^3+7 is NOT a QR, sqrt fails */
  test_recover_fail(
    "0000000000000000000000000000000000000000000000000000000000000001"
    "0000000000000000000000000000000000000000000000000000000000000001",
    msg, 2
  );

  /* recovery_id=3 with r=0: fails */
  test_recover_fail(
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000001",
    msg, 3
  );

  /* Negative and out-of-range recovery IDs */
  {
    uchar sig[64], msg_bytes[32], pub[64];
    fd_hex_decode( sig,
      "0000000000000000000000000000000000000000000000000000000000000001"
      "0000000000000000000000000000000000000000000000000000000000000001", 64 );
    fd_hex_decode( msg_bytes, msg, 32 );
    FD_TEST( fd_secp256k1_recover( pub, msg_bytes, sig, -1 ) == NULL );
    FD_TEST( fd_secp256k1_recover( pub, msg_bytes, sig, -100 ) == NULL );
    FD_TEST( fd_secp256k1_recover( pub, msg_bytes, sig, 4 ) == NULL );
    FD_TEST( fd_secp256k1_recover( pub, msg_bytes, sig, 255 ) == NULL );
    FD_TEST( fd_secp256k1_recover( pub, msg_bytes, sig, INT_MAX ) == NULL );
    FD_TEST( fd_secp256k1_recover( pub, msg_bytes, sig, INT_MIN ) == NULL );
  }

  /* r=n-1 (maximum valid r): (n-1)^3+7 is NOT a QR for secp256k1,
     so recovery_y will return NULL. */
  test_recover_fail(
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
    "0000000000000000000000000000000000000000000000000000000000000001",
    msg, 0
  );

  /* s=n-1 (maximum valid s) with r=1 (QR): should succeed */
  test_recover_ok(
    "0000000000000000000000000000000000000000000000000000000000000001"
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
    msg,
    0,
    /* Expected pubkey computed algebraically:
       r_inv = inv(1, n) = 1
       u1 = -e * 1 mod n, u2 = (n-1) * 1 mod n = n-1
       pubkey = u1*G + u2*R where R = point with x=1, even y */
    "c61d2d9784a23ed1fc690536466ee379912bece5f13bb7019d741a19aee25cf2"
    "cd7467baa513eeb616d7e3ba1853dd6674d8ccd91486864a8fa5fc0027a6f795"
  );

  FD_LOG_NOTICE(( "Recovery edge case tests passed" ));
}

/**********************************************************************/
/* Test: recovery consistency                                         */
/**********************************************************************/

static void
test_recover_consistency( void ) {
  FD_LOG_NOTICE(( "Testing recovery consistency" ));

  /* For the same sig+msg, recovering with rec_id=0 and rec_id=1 should
     give different but deterministic public keys. */
  {
    uchar sig[64], msg[32], pub0[64], pub1[64];
    fd_hex_decode( sig,
      "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc"
      "bf5886c2e39f7daa6083907c4746116f25861d6eef54dfe5fca30c9701a8db40", 64 );
    fd_hex_decode( msg,
      "deadbeefcafebabe0000000000000000deadbeefcafebabe0000000000000000", 32 );

    /* Both rec_id=0 and rec_id=1 should succeed */
    FD_TEST( fd_secp256k1_recover( pub0, msg, sig, 0 ) != NULL );
    FD_TEST( fd_secp256k1_recover( pub1, msg, sig, 1 ) != NULL );

    /* They should produce DIFFERENT public keys */
    FD_TEST( memcmp( pub0, pub1, 64 ) != 0 );

    /* Recovering twice with the same rec_id gives the same result */
    uchar pub0_again[64];
    FD_TEST( fd_secp256k1_recover( pub0_again, msg, sig, 0 ) != NULL );
    FD_TEST( !memcmp( pub0, pub0_again, 64 ) );
  }

  /* Different message hashes with same signature give different keys */
  {
    uchar sig[64], msg1[32], msg2[32], pub1[64], pub2[64];
    fd_hex_decode( sig,
      "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc"
      "bf5886c2e39f7daa6083907c4746116f25861d6eef54dfe5fca30c9701a8db40", 64 );
    fd_hex_decode( msg1,
      "deadbeefcafebabe0000000000000000deadbeefcafebabe0000000000000000", 32 );
    fd_hex_decode( msg2,
      "0000000000000000000000000000000000000000000000000000000000000001", 32 );

    FD_TEST( fd_secp256k1_recover( pub1, msg1, sig, 0 ) != NULL );
    FD_TEST( fd_secp256k1_recover( pub2, msg2, sig, 0 ) != NULL );
    FD_TEST( memcmp( pub1, pub2, 64 ) != 0 );
  }

  FD_LOG_NOTICE(( "Recovery consistency tests passed" ));
}

/**********************************************************************/
/* Benches                                                            */
/**********************************************************************/

static void
bench_recover( void ) {
  uchar _pub[64]; uchar * pub = _pub;
  uchar _msg[32]; uchar * msg = _msg;
  uchar _sig[64]; uchar * sig = _sig;
  int rec_id = 1;
  fd_hex_decode(msg, "ce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008", 32);
  fd_hex_decode(sig, "90f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e549984a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc93", 64);

  ulong iter = 10000UL;

  {
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( pub ); FD_COMPILER_FORGET( sig ); FD_COMPILER_FORGET( msg );
      fd_secp256k1_recover(pub, msg, sig, rec_id);
    }
    dt = fd_log_wallclock() - dt;
    char cstr[128];
    log_bench( fd_cstr_printf( cstr, 128UL, NULL, "fd_secp256k1_recover(good)" ), iter, dt );
  }

  {
    sig[0] = 0;
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( pub ); FD_COMPILER_FORGET( sig ); FD_COMPILER_FORGET( msg );
      fd_secp256k1_recover(pub, msg, sig, rec_id);
    }
    dt = fd_log_wallclock() - dt;
    char cstr[128];
    log_bench( fd_cstr_printf( cstr, 128UL, NULL, "fd_secp256k1_recover(bad)" ), iter, dt );
  }
}

/**********************************************************************/

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  test_recover          ( rng );
  test_recover_extended ();
  test_recover_edge_cases();
  test_recover_consistency();
  bench_recover();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
