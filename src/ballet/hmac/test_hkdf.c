#include "../../ballet/hmac/fd_hmac.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/sha512/fd_sha512.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

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

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
