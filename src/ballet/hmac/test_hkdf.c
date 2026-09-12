#include "../../ballet/hmac/fd_hmac.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/sha512/fd_sha512.h"

static ulong test_hkdf_extract_salt_sz;

static void *
test_hkdf_extract_hmac( void const * data,
                        ulong        data_sz,
                        void const * key,
                        ulong        key_sz,
                        void *       hash ) {
  (void)data;
  (void)data_sz;
  FD_TEST( key );
  test_hkdf_extract_salt_sz = key_sz;
  return hash;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  {
    uchar prk[ 64 ];
    test_hkdf_extract_salt_sz = 0UL;
    FD_TEST( fd_hkdf_extract( prk, 48UL, NULL, 0UL, NULL, 0UL,
                              test_hkdf_extract_hmac )==prk );
    FD_TEST( test_hkdf_extract_salt_sz==48UL );

    test_hkdf_extract_salt_sz = 0UL;
    FD_TEST( !fd_hkdf_extract( prk, 65UL, NULL, 0UL, NULL, 0UL,
                               test_hkdf_extract_hmac ) );
    FD_TEST( !test_hkdf_extract_salt_sz );
    FD_LOG_INFO(( "OK: HKDF-Extract default salt uses HashLen" ));
  }

  {
    uchar secret[ 32 ];
    memset( secret, 0xAB, 32UL );

    uchar ctx[ 32 ];
    fd_sha256_hash( NULL, 0UL, ctx );

    uchar out1[ 32 ];
    uchar out2[ 32 ];
    fd_hkdf_expand_label( out1, 32UL,
                          secret, 32UL,
                          "key", 3UL,
                          ctx, 32UL,
                          fd_hmac_sha256 );
    fd_hkdf_expand_label( out2, 32UL,
                          secret, 32UL,
                          "key", 3UL,
                          ctx, 32UL,
                          fd_hmac_sha256 );
    FD_TEST( 0==memcmp( out1, out2, 32UL ) );
    FD_LOG_INFO(( "OK: determinism" ));
  }

  {
    uchar secret[ 32 ];
    memset( secret, 0xAB, 32UL );

    uchar ctx[ 32 ];
    fd_sha256_hash( NULL, 0UL, ctx );

    uchar out_key[ 32 ];
    uchar out_iv [ 32 ];
    fd_hkdf_expand_label( out_key, 32UL,
                          secret, 32UL,
                          "key", 3UL,
                          ctx, 32UL,
                          fd_hmac_sha256 );
    fd_hkdf_expand_label( out_iv, 32UL,
                          secret, 32UL,
                          "iv", 2UL,
                          ctx, 32UL,
                          fd_hmac_sha256 );
    FD_TEST( 0!=memcmp( out_key, out_iv, 32UL ) );
    FD_LOG_INFO(( "OK: different labels produce different output" ));
  }

  {
    static uchar const expected[ 32 ] =
      { 0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5,
        0x67, 0x8f, 0x54, 0xfc, 0x9d, 0xba, 0xb6, 0x97,
        0x16, 0xc0, 0x76, 0x18, 0x9c, 0x48, 0x25, 0x0c,
        0xeb, 0xea, 0xc3, 0x57, 0x6c, 0x36, 0x11, 0xba };

    uchar psk[ 32 ];
    memset( psk, 0, 32UL );

    /* early_secret = HKDF-Extract( salt=NULL, IKM=psk ) */
    uchar early_secret[ 32 ];
    fd_hmac_sha256( psk, 32UL, NULL, 0UL, early_secret );

    uchar empty_hash[ 32 ];
    fd_sha256_hash( NULL, 0UL, empty_hash );

    uchar out[ 32 ];
    fd_hkdf_expand_label( out, 32UL,
                          early_secret, 32UL,
                          "derived", 7UL,
                          empty_hash, 32UL,
                          fd_hmac_sha256 );
    FD_TEST( 0==memcmp( out, expected, 32UL ) );
    FD_LOG_INFO(( "OK: SHA-256 derived label known vector" ));
  }

  {
    static uchar const expected[ 48 ] =
      { 0x15, 0x91, 0xda, 0xc5, 0xcb, 0xbf, 0x03, 0x30,
        0xa4, 0xa8, 0x4d, 0xe9, 0xc7, 0x53, 0x33, 0x0e,
        0x92, 0xd0, 0x1f, 0x0a, 0x88, 0x21, 0x4b, 0x44,
        0x64, 0x97, 0x2f, 0xd6, 0x68, 0x04, 0x9e, 0x93,
        0xe5, 0x2f, 0x2b, 0x16, 0xfa, 0xd9, 0x22, 0xfd,
        0xc0, 0x58, 0x44, 0x78, 0x42, 0x8f, 0x28, 0x2b };

    uchar psk[ 48 ];
    memset( psk, 0, 48UL );

    /* early_secret = HKDF-Extract( salt=NULL, IKM=psk ) */
    uchar early_secret[ 48 ];
    fd_hmac_sha384( psk, 48UL, NULL, 0UL, early_secret );

    uchar empty_hash[ 48 ];
    fd_sha384_hash( NULL, 0UL, empty_hash );

    uchar out[ 48 ];
    fd_hkdf_expand_label( out, 48UL,
                          early_secret, 48UL,
                          "derived", 7UL,
                          empty_hash, 48UL,
                          fd_hmac_sha384 );
    FD_TEST( 0==memcmp( out, expected, 48UL ) );
    FD_LOG_INFO(( "OK: SHA-384 derived label known vector" ));
  }

  {
    static uchar const expected[ 64 ] =
      { 0x03, 0x87, 0x12, 0xef, 0x75, 0xe2, 0x94, 0x1a,
        0x52, 0xa8, 0x5c, 0xa3, 0x11, 0x0c, 0x87, 0xf6,
        0xde, 0xa3, 0xef, 0xd7, 0x61, 0x6b, 0x00, 0x79,
        0xf7, 0xf1, 0xaf, 0x54, 0x91, 0x0b, 0x5c, 0x11,
        0xc2, 0x18, 0x54, 0x3c, 0xca, 0x92, 0x64, 0xcb,
        0xf3, 0x9f, 0x4b, 0x9b, 0xff, 0x6e, 0xf8, 0xb9,
        0xd1, 0x98, 0xce, 0xaf, 0xd2, 0xb1, 0x08, 0x96,
        0xf9, 0x17, 0x60, 0x56, 0x4d, 0x4d, 0x71, 0x8e };

    uchar secret[ 64 ];
    memset( secret, 0xAB, sizeof(secret) );

    uchar ctx[ 64 ];
    fd_sha512_hash( NULL, 0UL, ctx );

    struct {
      ulong canary_lo;
      uchar out[ 64 ];
      ulong canary_hi;
    } result = { .canary_lo = 0x0123456789abcdefUL,
                 .canary_hi = 0xfedcba9876543210UL };

    FD_TEST( fd_hkdf_expand_label( result.out, sizeof(result.out),
                                   secret, sizeof(secret),
                                   "key", 3UL,
                                   ctx, sizeof(ctx),
                                   fd_hmac_sha512 )==result.out );
    FD_TEST( !memcmp( result.out, expected, sizeof(expected) ) );
    FD_TEST( result.canary_lo==0x0123456789abcdefUL );
    FD_TEST( result.canary_hi==0xfedcba9876543210UL );
    FD_LOG_INFO(( "OK: SHA-512 full-size output" ));
  }

  {
    uchar secret[ 64 ] = {0};
    uchar out[ 65 ];
    uchar label[ 65 ] = {0};
    uchar ctx[ 65 ] = {0};
    memset( out, 0x5A, sizeof(out) );

    FD_TEST( !fd_hkdf_expand_label( out, 0UL, secret, 64UL,
                                    "", 0UL, NULL, 0UL, fd_hmac_sha512 ) );
    FD_TEST( !fd_hkdf_expand_label( out, 65UL, secret, 64UL,
                                    "", 0UL, NULL, 0UL, fd_hmac_sha512 ) );
    FD_TEST( !fd_hkdf_expand_label( out, 49UL, secret, 48UL,
                                    "", 0UL, NULL, 0UL, fd_hmac_sha384 ) );
    FD_TEST( !fd_hkdf_expand_label( out, 1UL, secret, 65UL,
                                    "", 0UL, NULL, 0UL, fd_hmac_sha512 ) );
    FD_TEST( !fd_hkdf_expand_label( out, 1UL, secret, 64UL,
                                    (char const *)label, 65UL, NULL, 0UL, fd_hmac_sha512 ) );
    FD_TEST( !fd_hkdf_expand_label( out, 1UL, secret, 64UL,
                                    "", 0UL, ctx, 65UL, fd_hmac_sha512 ) );
    for( ulong i=0UL; i<sizeof(out); i++ ) FD_TEST( out[i]==0x5A );
    FD_LOG_INFO(( "OK: invalid sizes rejected without writing output" ));
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
