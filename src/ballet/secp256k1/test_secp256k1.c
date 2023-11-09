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

static void
test_recover( FD_FN_UNUSED fd_rng_t * rng ) {
  // test correctness
  //
  // solana tests
  // https://github.com/solana-labs/solana/blob/v1.17.4/programs/sbf/rust/secp256k1_recover/src/lib.rs
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

  {
    uchar _pub_expected[ 65 ] = {
        0x9B, 0xEE, 0x7C, 0x18, 0x34, 0xE0, 0x18, 0x21, 0x7B, 0x40, 0x14, 0x9B, 0x84, 0x2E, 0xFA,
        0x80, 0x96, 0x00, 0x1A, 0x9B, 0x17, 0x88, 0x01, 0x80, 0xA8, 0x46, 0x99, 0x09, 0xE9, 0xC4,
        0x73, 0x6E, 0x39, 0x0B, 0x94, 0x00, 0x97, 0x68, 0xC2, 0x28, 0xB5, 0x55, 0xD3, 0x0C, 0x0C,
        0x42, 0x43, 0xC1, 0xEE, 0xA5, 0x0D, 0xC0, 0x48, 0x62, 0xD3, 0xAE, 0xB0, 0x3D, 0xA2, 0x20,
        0xAC, 0x11, 0x85, 0xEE,
    }; uchar * pub_expected = _pub_expected;
    uchar _msg[ 32 ]; uchar * msg = _msg;
    // keccak256("hello world")
    fd_hex_decode(msg, "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad", 64);
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


  uchar _pub_expected[ 65 ]; uchar * pub_expected = _pub_expected;
  uchar _pub[ 65 ]; uchar * pub = _pub;
  uchar _msg[ 32 ]; uchar * msg = _msg;
  uchar _sig[ 64 ]; uchar * sig = _sig;
  int rec_id = 0;

  // ethereum tests
  // https://github.com/ethereum/go-ethereum/blob/v1.13.4/crypto/secp256k1/secp256_test.go#L206
  fd_hex_decode(msg, "ce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008", 64);
  fd_hex_decode(sig, "90f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e549984a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc93", 128);
  // in the go code, this is the last byte of sig
  rec_id = 1;
  // in the go code, the public key is serialized with an extra prefix byte
  fd_hex_decode(pub_expected, "e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f15878109880a0a2b2667f7e725ceea70c673093bf67663e0312623c8e091b13cf2c0f11ef652", 128);
  FD_TEST( fd_secp256k1_recover(pub, msg, sig, rec_id)==pub );
  FD_TEST( !memcmp( pub, pub_expected, 64UL ) );

  // test sig recovery succeeds but returns incorrect public key
  uchar saved = msg[0];
  msg[0] = 0;
  FD_TEST( fd_secp256k1_recover(pub, msg, sig, rec_id)==pub );
  FD_TEST( !!memcmp( pub, pub_expected, 64UL ) );
  msg[0] = saved;

  // test sig recovery fails
  saved = sig[0];
  sig[0] = 0;
  FD_TEST( fd_secp256k1_recover(pub, msg, sig, rec_id)==NULL );
  sig[0] = saved;

  // test recovery id fails (but doesn't panic)
  FD_TEST( fd_secp256k1_recover(pub, msg, sig, -1)==NULL );  // invalid
  FD_TEST( fd_secp256k1_recover(pub, msg, sig, 3)==NULL );   // incorrect
  FD_TEST( fd_secp256k1_recover(pub, msg, sig, 4)==NULL );   // invalid
  FD_TEST( fd_secp256k1_recover(pub, msg, sig, 123)==NULL ); // invalid

  // benches
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

  test_recover ( rng );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
