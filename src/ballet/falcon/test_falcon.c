#include "../../util/fd_util.h"
#include "fd_falcon.h"

#define Q 12289
#define N 512
#define LOGN 9

#include "fd_falcon_fq.h"

static uchar const tv_pubkey[ FD_FALCON_PUBKEY_SIZE ] = {
  9, 2, 206, 33, 107, 228, 44, 208, 79, 200, 76, 36, 199, 29, 19, 7,
  142, 202, 7, 151, 110, 228, 173, 186, 44, 152, 35, 70, 216, 120, 192,
  148, 118, 127, 226, 156, 52, 92, 226, 250, 135, 75, 238, 35, 158, 166,
  11, 223, 167, 39, 165, 22, 130, 195, 223, 6, 162, 104, 73, 195, 247,
  38, 70, 42, 89, 233, 196, 22, 99, 135, 186, 137, 86, 223, 201, 250,
  98, 32, 149, 32, 237, 101, 57, 202, 221, 168, 249, 232, 17, 166, 142,
  216, 105, 112, 19, 90, 213, 2, 109, 189, 22, 241, 89, 151, 164, 187,
  190, 53, 104, 56, 215, 92, 122, 145, 52, 237, 184, 191, 37, 188, 186,
  10, 3, 19, 119, 235, 240, 17, 13, 84, 115, 200, 70, 130, 123, 37,
  107, 154, 180, 208, 38, 30, 65, 200, 219, 241, 164, 36, 182, 218, 31,
  33, 208, 226, 26, 137, 189, 41, 148, 7, 79, 165, 54, 94, 167, 112,
  14, 235, 210, 38, 148, 124, 250, 123, 225, 167, 101, 244, 215, 249,
  39, 80, 2, 61, 242, 104, 148, 81, 46, 121, 72, 197, 100, 105, 232,
  129, 209, 153, 218, 129, 53, 175, 193, 110, 82, 58, 248, 162, 63, 213,
  128, 34, 174, 34, 154, 201, 92, 255, 9, 93, 111, 243, 44, 137, 13,
  178, 41, 65, 25, 33, 144, 91, 59, 165, 45, 84, 181, 13, 236, 180,
  77, 195, 215, 200, 153, 102, 121, 232, 40, 164, 59, 141, 6, 135, 232,
  189, 224, 96, 197, 16, 21, 170, 158, 0, 12, 146, 89, 143, 5, 184,
  112, 169, 75, 41, 1, 169, 225, 42, 233, 171, 242, 10, 81, 113, 74,
  3, 106, 133, 28, 206, 137, 21, 66, 209, 235, 82, 126, 115, 16, 118,
  212, 255, 47, 9, 186, 104, 148, 162, 9, 3, 202, 111, 167, 110, 19,
  209, 45, 192, 171, 166, 185, 38, 237, 110, 137, 84, 132, 29, 192, 82,
  74, 85, 227, 101, 108, 156, 25, 136, 94, 171, 101, 77, 134, 148, 147,
  81, 251, 139, 2, 234, 50, 174, 113, 95, 9, 139, 226, 78, 131, 210,
  226, 113, 204, 140, 36, 20, 142, 123, 213, 146, 89, 40, 56, 250, 85,
  184, 138, 219, 137, 123, 229, 217, 150, 151, 227, 252, 172, 250, 192,
  37, 180, 81, 246, 43, 108, 53, 98, 201, 239, 144, 113, 68, 87, 162,
  246, 73, 34, 95, 112, 32, 233, 175, 219, 185, 42, 226, 190, 219, 166,
  25, 51, 185, 5, 207, 212, 26, 3, 8, 43, 214, 223, 139, 36, 39, 236,
  123, 252, 171, 42, 222, 22, 120, 156, 9, 103, 69, 103, 222, 17, 41,
  193, 178, 246, 158, 156, 15, 143, 178, 55, 197, 93, 5, 207, 143, 105,
  173, 139, 183, 39, 162, 8, 154, 67, 113, 30, 198, 202, 84, 182, 18,
  193, 215, 47, 160, 43, 102, 64, 152, 120, 109, 8, 83, 209, 188, 152,
  225, 74, 87, 144, 178, 202, 198, 199, 210, 72, 87, 208, 251, 68, 245,
  217, 95, 52, 33, 51, 150, 134, 232, 175, 165, 186, 146, 75, 186, 148,
  240, 115, 201, 9, 233, 251, 138, 208, 164, 98, 36, 214, 248, 27, 34,
  162, 1, 174, 219, 168, 148, 194, 170, 68, 186, 214, 135, 77, 110, 36,
  206, 27, 184, 63, 81, 230, 159, 52, 161, 64, 173, 136, 85, 79, 108,
  71, 72, 255, 159, 100, 111, 13, 219, 211, 164, 133, 208, 186, 216, 5,
  250, 41, 235, 153, 104, 24, 81, 113, 69, 5, 227, 113, 166, 74, 123,
  207, 104, 151, 149, 129, 68, 145, 220, 157, 197, 39, 82, 233, 162,
  127, 150, 244, 108, 232, 248, 164, 39, 149, 199, 16, 126, 193, 134,
  120, 146, 73, 108, 145, 161, 119, 251, 128, 149, 13, 105, 59, 212,
  173, 222, 48, 46, 144, 60, 65, 50, 236, 149, 56, 134, 141, 232, 207,
  128, 95, 90, 33, 146, 150, 127, 166, 195, 80, 106, 26, 171, 60, 17,
  161, 95, 30, 71, 179, 180, 110, 100, 151, 177, 90, 136, 46, 44, 200,
  73, 161, 180, 66, 73, 233, 127, 97, 241, 107, 208, 236, 234, 213, 71,
  221, 113, 197, 221, 165, 170, 138, 86, 254, 54, 49, 34, 21, 133, 46,
  120, 218, 152, 93, 85, 164, 164, 216, 247, 20, 142, 69, 103, 209, 228,
  103, 135, 194, 35, 135, 202, 74, 133, 240, 17, 227, 117, 196, 92, 202,
  12, 224, 161, 91, 205, 19, 55, 189, 201, 39, 27, 250, 132, 115, 225,
  136, 47, 51, 133, 88, 105, 125, 154, 175, 7, 90, 144, 120, 51, 90,
  31, 184, 161, 179, 182, 233, 217, 207, 67, 98, 132, 6, 124, 88, 197,
  164, 142, 4, 122, 64, 8, 208, 43, 124, 133, 7, 194, 238, 111, 136,
  218, 76, 151, 246, 15, 117, 68, 76, 120, 132, 150, 103, 132, 50, 201,
  95, 58, 146, 8, 180, 168, 193, 203, 198, 226, 212, 218, 97, 37, 61,
  160, 129, 39, 94, 143, 52, 219, 228, 161, 236, 194, 34, 36, 195, 8,
  0, 167, 117, 53, 116, 200, 149, 134, 149, 102, 108, 40, 149, 179, 92,
  206, 7, 137, 68, 163, 16, 65, 165, 35, 131, 124, 237, 114, 23, 105,
  15, 161, 124, 54, 203, 69, 146, 99, 53, 230, 123, 24, 4, 149, 157
};

static uchar const tv_signature[] = {
  57, 22, 193, 37, 21, 37, 128, 147, 121, 153, 86, 54, 140, 223, 193,
  130, 193, 202, 74, 52, 240, 119, 233, 36, 68, 22, 168, 196, 193, 63,
  176, 202, 36, 30, 139, 122, 193, 113, 45, 40, 235, 11, 164, 166, 12,
  198, 53, 151, 111, 248, 100, 105, 235, 37, 13, 107, 59, 184, 99, 146,
  49, 176, 180, 89, 254, 175, 177, 124, 110, 228, 20, 223, 106, 108,
  196, 205, 91, 109, 124, 211, 13, 81, 137, 174, 58, 72, 230, 113, 133,
  50, 166, 188, 75, 219, 101, 207, 34, 72, 121, 152, 227, 249, 153, 222,
  233, 148, 28, 76, 138, 105, 232, 184, 58, 55, 137, 188, 38, 34, 99,
  112, 60, 20, 232, 106, 247, 93, 111, 38, 59, 193, 117, 126, 33, 80,
  45, 69, 84, 132, 92, 48, 133, 147, 49, 150, 218, 185, 239, 222, 26,
  217, 143, 40, 72, 27, 121, 87, 225, 75, 82, 200, 43, 28, 109, 147,
  4, 238, 66, 70, 108, 90, 248, 203, 2, 72, 25, 90, 76, 235, 9, 167,
  167, 255, 35, 247, 125, 123, 251, 222, 105, 40, 240, 60, 203, 203, 20,
  181, 45, 105, 19, 38, 201, 70, 216, 190, 214, 117, 146, 204, 12, 150,
  215, 33, 41, 90, 48, 233, 121, 219, 79, 2, 219, 235, 119, 133, 202,
  133, 145, 157, 49, 187, 152, 254, 17, 73, 131, 36, 122, 86, 92, 141,
  250, 12, 28, 179, 81, 134, 39, 150, 73, 29, 59, 205, 153, 55, 174,
  21, 235, 131, 201, 207, 158, 198, 13, 249, 204, 82, 40, 153, 199, 22,
  109, 255, 220, 163, 73, 228, 65, 227, 232, 194, 213, 11, 23, 118, 198,
  149, 58, 70, 62, 68, 138, 190, 238, 204, 136, 146, 121, 220, 219, 205,
  53, 173, 134, 32, 210, 220, 50, 240, 254, 39, 85, 37, 49, 16, 41,
  168, 209, 19, 199, 209, 202, 53, 155, 73, 93, 161, 234, 190, 107, 85,
  162, 95, 205, 49, 106, 26, 99, 150, 197, 36, 201, 161, 15, 78, 118,
  38, 107, 96, 215, 124, 216, 36, 25, 176, 96, 217, 82, 224, 242, 54,
  40, 115, 103, 84, 150, 78, 213, 84, 98, 167, 134, 114, 145, 226, 97,
  58, 227, 160, 249, 41, 106, 227, 52, 223, 32, 63, 93, 138, 245, 229,
  84, 251, 82, 235, 156, 255, 67, 132, 139, 236, 226, 139, 12, 165, 183,
  96, 18, 90, 132, 246, 205, 156, 165, 195, 146, 67, 179, 132, 53, 243,
  234, 180, 225, 15, 193, 27, 13, 126, 118, 166, 242, 150, 70, 21, 144,
  68, 207, 119, 255, 167, 202, 236, 197, 80, 157, 103, 65, 174, 188,
  231, 81, 53, 97, 5, 120, 33, 151, 116, 245, 100, 238, 193, 216, 235,
  76, 189, 202, 73, 102, 72, 106, 28, 198, 53, 205, 230, 54, 191, 208,
  117, 54, 153, 7, 247, 5, 63, 218, 12, 137, 47, 181, 94, 187, 173,
  162, 209, 132, 209, 191, 53, 120, 168, 181, 249, 80, 50, 237, 136, 110,
  77, 31, 82, 160, 128, 48, 144, 217, 129, 168, 165, 201, 83, 119, 17,
  7, 216, 101, 127, 73, 3, 48, 92, 138, 221, 25, 228, 113, 163, 219,
  108, 57, 138, 254, 228, 188, 236, 28, 124, 194, 12, 85, 65, 230, 61,
  113, 70, 105, 31, 195, 125, 249, 205, 46, 239, 61, 157, 49, 180, 93,
  204, 101, 241, 246, 89, 39, 93, 191, 123, 137, 181, 84, 101, 113, 47,
  118, 239, 37, 97, 240, 70, 230, 173, 246, 113, 147, 230, 42, 229, 11,
  221, 180, 142, 111, 26, 57, 142, 238, 77, 171, 160, 108, 82, 180, 17,
  166, 252, 85, 154, 171, 119, 16, 209, 71, 158, 108, 38, 247, 235, 134,
  109, 143, 29, 63, 104, 108, 142, 59, 253, 190, 70, 245, 119, 138, 245,
  80, 217, 143, 28, 157, 82, 113, 186, 148, 116, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0
};

static uchar const tv_msg[] = "data1";
#define TV_MSG_LEN (sizeof(tv_msg)-1)

static void
test_fq_add( void ) {
  FD_TEST( fd_falcon_fq_add( 0, 0 )==0 );
  FD_TEST( fd_falcon_fq_add( 1, 0 )==1 );
  FD_TEST( fd_falcon_fq_add( 0, 1 )==1 );
  FD_TEST( fd_falcon_fq_add( 1, 2 )==3 );
  FD_TEST( fd_falcon_fq_add( 2, 1 )==3 );

  FD_TEST( fd_falcon_fq_add( Q-1, 1 )==0 );
  FD_TEST( fd_falcon_fq_add( 1, Q-1 )==0 );
  FD_TEST( fd_falcon_fq_add( Q-1, Q-1 )==Q-2 );
  FD_TEST( fd_falcon_fq_add( Q/2, Q/2 )==Q-1 );

  for( uint a=0; a<Q; a+=997 ) {
    FD_TEST( fd_falcon_fq_add( a, 0 )==a );
    for( uint b=0; b<Q; b+=991 ) {
      uint expected = (a + b) % Q;
      FD_TEST( fd_falcon_fq_add( a, b )==expected );
      FD_TEST( fd_falcon_fq_add( b, a )==expected );
    }
  }
  FD_LOG_NOTICE(( "OK: fq_add" ));
}

static void
test_fq_neg( void ) {
  FD_TEST( fd_falcon_fq_neg( 0 )==0 );
  FD_TEST( fd_falcon_fq_neg( 1 )==Q-1 );
  FD_TEST( fd_falcon_fq_neg( Q-1 )==1 );
  FD_TEST( fd_falcon_fq_neg( Q/2 )==Q - Q/2 );

  for( uint a=0; a<Q; a+=997 ) {
    uint neg_a = fd_falcon_fq_neg( a );
    FD_TEST( fd_falcon_fq_add( a, neg_a )==0 );
    if( a==0 ) FD_TEST( neg_a==0 );
    else        FD_TEST( neg_a==Q-a );
  }
  FD_LOG_NOTICE(( "OK: fq_neg" ));
}

static void
test_fq_sub( void ) {
  FD_TEST( fd_falcon_fq_sub( 0, 0 )==0 );
  FD_TEST( fd_falcon_fq_sub( 5, 3 )==2 );
  FD_TEST( fd_falcon_fq_sub( 3, 5 )==Q-2 );
  FD_TEST( fd_falcon_fq_sub( 0, 1 )==Q-1 );
  FD_TEST( fd_falcon_fq_sub( 1, 0 )==1 );

  for( uint a=0; a<Q; a+=997 ) {
    FD_TEST( fd_falcon_fq_sub( a, 0 )==a );
    FD_TEST( fd_falcon_fq_sub( a, a )==0 );
    for( uint b=0; b<Q; b+=991 ) {
      uint expected = (a + Q - b) % Q;
      FD_TEST( fd_falcon_fq_sub( a, b )==expected );
    }
  }
  FD_LOG_NOTICE(( "OK: fq_sub" ));
}

static void
test_fq_mul( void ) {
  FD_TEST( fd_falcon_fq_mul( 0, 0 )==0 );
  FD_TEST( fd_falcon_fq_mul( 1, 0 )==0 );
  FD_TEST( fd_falcon_fq_mul( 0, 1 )==0 );
  FD_TEST( fd_falcon_fq_mul( 1, 1 )==1 );
  FD_TEST( fd_falcon_fq_mul( 2, 3 )==6 );
  FD_TEST( fd_falcon_fq_mul( Q-1, 1 )==Q-1 );
  FD_TEST( fd_falcon_fq_mul( Q-1, 2 )==Q-2 );
  FD_TEST( fd_falcon_fq_mul( Q-1, Q-1 )==1 );

  for( uint a=0; a<Q; a+=997 ) {
    FD_TEST( fd_falcon_fq_mul( a, 1 )==a );
    FD_TEST( fd_falcon_fq_mul( a, 0 )==0 );
    for( uint b=0; b<Q; b+=991 ) {
      uint expected = (uint)(((ulong)a * b) % Q);
      FD_TEST( fd_falcon_fq_mul( a, b )==expected );
      FD_TEST( fd_falcon_fq_mul( b, a )==expected );
    }
  }
  FD_LOG_NOTICE(( "OK: fq_mul" ));
}

static void
test_fft_roundtrip( fd_rng_t * rng ) {
  fd_falcon_fq_t poly[ N ];
  fd_falcon_fq_t fft_out[ N ];
  fd_falcon_fq_t ifft_out[ N ];

  /* All-zeros polynomial */
  memset( poly, 0, sizeof(poly) );
  fd_falcon_fq_fft( fft_out, poly );
  fd_falcon_fq_ifft( ifft_out, fft_out );
  for( int i=0; i<N; i++ ) FD_TEST( ifft_out[i]==0 );

  /* All-ones polynomial */
  for( int i=0; i<N; i++ ) poly[i] = 1;
  fd_falcon_fq_fft( fft_out, poly );
  fd_falcon_fq_ifft( ifft_out, fft_out );
  for( int i=0; i<N; i++ ) FD_TEST( ifft_out[i]==1 );

  /* Single coefficient set (X^0 = 1, rest zero) */
  memset( poly, 0, sizeof(poly) );
  poly[0] = 42;
  fd_falcon_fq_fft( fft_out, poly );
  fd_falcon_fq_ifft( ifft_out, fft_out );
  FD_TEST( ifft_out[0]==42 );
  for( int i=1; i<N; i++ ) FD_TEST( ifft_out[i]==0 );

  /* Random polynomials */
  for( int trial=0; trial<20; trial++ ) {
    for( int i=0; i<N; i++ ) poly[i] = fd_rng_uint( rng ) % Q;
    fd_falcon_fq_fft( fft_out, poly );
    fd_falcon_fq_ifft( ifft_out, fft_out );
    for( int i=0; i<N; i++ ) FD_TEST( ifft_out[i]==poly[i] );
  }

  /* Verify FFT output differs from input (non-trivial transform) */
  for( int i=0; i<N; i++ ) poly[i] = (uint)(i + 1) % Q;
  fd_falcon_fq_fft( fft_out, poly );
  int differs = 0;
  for( int i=0; i<N; i++ ) differs |= (fft_out[i] != poly[i]);
  FD_TEST( differs );

  FD_LOG_NOTICE(( "OK: fft/ifft roundtrip" ));
}

static void
test_fft_linearity( fd_rng_t * rng ) {
  fd_falcon_fq_t a[ N ], b[ N ], sum[ N ];
  fd_falcon_fq_t fft_a[ N ], fft_b[ N ], fft_sum[ N ];

  for( int trial=0; trial<5; trial++ ) {
    for( int i=0; i<N; i++ ) {
      a[i] = fd_rng_uint( rng ) % Q;
      b[i] = fd_rng_uint( rng ) % Q;
      sum[i] = fd_falcon_fq_add( a[i], b[i] );
    }
    fd_falcon_fq_fft( fft_a, a );
    fd_falcon_fq_fft( fft_b, b );
    fd_falcon_fq_fft( fft_sum, sum );

    for( int i=0; i<N; i++ ) {
      FD_TEST( fft_sum[i]==fd_falcon_fq_add( fft_a[i], fft_b[i] ) );
    }
  }
  FD_LOG_NOTICE(( "OK: fft linearity" ));
}

static void
test_pubkey_parse_valid( void ) {
  fd_falcon_pubkey_t pk[1];
  FD_TEST( 0==fd_falcon_pubkey_parse( pk, tv_pubkey ) );

  /* All coefficients must be in [0, Q) */
  for( int i=0; i<N; i++ ) FD_TEST( pk->h[i]<Q );

  FD_LOG_NOTICE(( "OK: pubkey parse valid" ));
}

static void
test_pubkey_parse_invalid_header( void ) {
  fd_falcon_pubkey_t pk[1];
  uchar bad[ FD_FALCON_PUBKEY_SIZE ];
  memcpy( bad, tv_pubkey, FD_FALCON_PUBKEY_SIZE );

  /* Wrong header values */
  uchar bad_headers[] = { 0, 1, 8, 10, 0xFF };
  for( ulong i=0; i<sizeof(bad_headers); i++ ) {
    bad[0] = bad_headers[i];
    FD_TEST( -1==fd_falcon_pubkey_parse( pk, bad ) );
  }

  FD_LOG_NOTICE(( "OK: pubkey parse invalid header" ));
}

static void
test_pubkey_parse_coeff_out_of_range( void ) {
  fd_falcon_pubkey_t pk[1];
  uchar bad[ FD_FALCON_PUBKEY_SIZE ];

  memset( bad, 0, FD_FALCON_PUBKEY_SIZE );
  bad[0] = LOGN;
  bad[1] = 0xC0;
  bad[2] = 0x04;
  FD_TEST( -1==fd_falcon_pubkey_parse( pk, bad ) );

  memset( bad, 0, FD_FALCON_PUBKEY_SIZE );
  bad[0] = LOGN;
  bad[1] = 0xFF;
  bad[2] = 0xFC;
  FD_TEST( -1==fd_falcon_pubkey_parse( pk, bad ) );

  FD_LOG_NOTICE(( "OK: pubkey parse coeff out of range" ));
}

static void
test_pubkey_parse_all_zero_coeffs( void ) {
  fd_falcon_pubkey_t pk[1];
  uchar zero_pk[ FD_FALCON_PUBKEY_SIZE ];
  memset( zero_pk, 0, FD_FALCON_PUBKEY_SIZE );
  zero_pk[0] = LOGN;
  FD_TEST( 0==fd_falcon_pubkey_parse( pk, zero_pk ) );
  for( int i=0; i<N; i++ ) FD_TEST( pk->h[i]==0 );

  FD_LOG_NOTICE(( "OK: pubkey parse all-zero coefficients" ));
}

static void
test_pubkey_parse_deterministic( void ) {
  fd_falcon_pubkey_t pk1[1], pk2[1];
  FD_TEST( 0==fd_falcon_pubkey_parse( pk1, tv_pubkey ) );
  FD_TEST( 0==fd_falcon_pubkey_parse( pk2, tv_pubkey ) );
  FD_TEST( 0==memcmp( pk1, pk2, sizeof(fd_falcon_pubkey_t) ) );

  FD_LOG_NOTICE(( "OK: pubkey parse deterministic" ));
}

static void
test_sig_parse_valid( void ) {
  fd_falcon_signature_t sig[1];
  FD_TEST( 0==fd_falcon_signature_parse( sig, tv_signature, sizeof(tv_signature) ) );
  FD_LOG_NOTICE(( "OK: sig parse valid" ));
}

static void
test_sig_parse_empty( void ) {
  fd_falcon_signature_t sig[1];
  uchar empty = 0;
  FD_TEST( -1==fd_falcon_signature_parse( sig, &empty, 0 ) );
  FD_LOG_NOTICE(( "OK: sig parse empty" ));
}

static void
test_sig_parse_too_short( void ) {
  fd_falcon_signature_t sig[1];
  uchar short_buf[40];
  memset( short_buf, 0, sizeof(short_buf) );
  short_buf[0] = 0x39;

  for( ulong len=1; len<=40; len++ ) {
    FD_TEST( -1==fd_falcon_signature_parse( sig, short_buf, len ) );
  }
  FD_LOG_NOTICE(( "OK: sig parse too short" ));
}

static void
test_sig_parse_invalid_header( void ) {
  fd_falcon_signature_t sig[1];
  uchar bad[ 666 ];
  memset( bad, 0, sizeof(bad) );

  uchar bad_headers[] = { 0x00, 0x38, 0x3A, 0xFF, 0x09 };
  for( ulong i=0; i<sizeof(bad_headers); i++ ) {
    bad[0] = bad_headers[i];
    FD_TEST( -1==fd_falcon_signature_parse( sig, bad, sizeof(bad) ) );
  }
  FD_LOG_NOTICE(( "OK: sig parse invalid header" ));
}

static void
test_sig_parse_truncated( void ) {
  fd_falcon_signature_t sig[1];

  uchar trunc[50];
  memset( trunc, 0, sizeof(trunc) );
  trunc[0] = 0x39;
  FD_TEST( -1==fd_falcon_signature_parse( sig, trunc, sizeof(trunc) ) );

  FD_LOG_NOTICE(( "OK: sig parse truncated" ));
}

static void
test_sig_parse_deterministic( void ) {
  fd_falcon_signature_t sig1[1], sig2[1];
  FD_TEST( 0==fd_falcon_signature_parse( sig1, tv_signature, sizeof(tv_signature) ) );
  FD_TEST( 0==fd_falcon_signature_parse( sig2, tv_signature, sizeof(tv_signature) ) );
  FD_TEST( 0==memcmp( sig1->nonce, sig2->nonce, 40 ) );
  FD_TEST( 0==memcmp( sig1->s2, sig2->s2, sizeof(fd_falcon_fq_t)*N ) );
  FD_LOG_NOTICE(( "OK: sig parse deterministic" ));
}

static void
test_verify_valid( void ) {
  fd_falcon_pubkey_t pk[1];
  fd_falcon_signature_t sig[1];
  FD_TEST( 0==fd_falcon_pubkey_parse( pk, tv_pubkey ) );
  FD_TEST( 0==fd_falcon_signature_parse( sig, tv_signature, sizeof(tv_signature) ) );
  FD_TEST( 0==fd_falcon_verify( tv_msg, TV_MSG_LEN, sig, pk ) );
  FD_LOG_NOTICE(( "OK: verify valid" ));
}

static void
test_verify_wrong_message( void ) {
  fd_falcon_pubkey_t pk[1];
  fd_falcon_signature_t sig[1];
  FD_TEST( 0==fd_falcon_pubkey_parse( pk, tv_pubkey ) );
  FD_TEST( 0==fd_falcon_signature_parse( sig, tv_signature, sizeof(tv_signature) ) );

  /* Different message content */
  uchar wrong_msg[] = "data2";
  FD_TEST( -1==fd_falcon_verify( wrong_msg, sizeof(wrong_msg)-1, sig, pk ) );

  /* Same prefix but different length */
  FD_TEST( -1==fd_falcon_verify( tv_msg, TV_MSG_LEN-1, sig, pk ) );

  /* Longer message */
  uchar long_msg[] = "data1_extra";
  FD_TEST( -1==fd_falcon_verify( long_msg, sizeof(long_msg)-1, sig, pk ) );

  /* Single bit flip in message */
  uchar flipped[5];
  memcpy( flipped, tv_msg, TV_MSG_LEN );
  flipped[0] ^= 1;
  FD_TEST( -1==fd_falcon_verify( flipped, TV_MSG_LEN, sig, pk ) );

  FD_LOG_NOTICE(( "OK: verify wrong message" ));
}

static void
test_verify_wrong_pubkey( void ) {
  fd_falcon_pubkey_t pk[1];
  fd_falcon_signature_t sig[1];
  FD_TEST( 0==fd_falcon_pubkey_parse( pk, tv_pubkey ) );
  FD_TEST( 0==fd_falcon_signature_parse( sig, tv_signature, sizeof(tv_signature) ) );

  /* Flip one coefficient in the pubkey */
  fd_falcon_pubkey_t bad_pk[1];
  memcpy( bad_pk, pk, sizeof(fd_falcon_pubkey_t) );
  bad_pk->h[0] = (bad_pk->h[0] + 1) % Q;
  FD_TEST( -1==fd_falcon_verify( tv_msg, TV_MSG_LEN, sig, bad_pk ) );

  /* Flip a coefficient in the middle */
  memcpy( bad_pk, pk, sizeof(fd_falcon_pubkey_t) );
  bad_pk->h[N/2] = (bad_pk->h[N/2] + 1) % Q;
  FD_TEST( -1==fd_falcon_verify( tv_msg, TV_MSG_LEN, sig, bad_pk ) );

  /* Flip the last coefficient */
  memcpy( bad_pk, pk, sizeof(fd_falcon_pubkey_t) );
  bad_pk->h[N-1] = (bad_pk->h[N-1] + 1) % Q;
  FD_TEST( -1==fd_falcon_verify( tv_msg, TV_MSG_LEN, sig, bad_pk ) );

  /* Zero out the entire pubkey polynomial */
  memset( bad_pk->h, 0, sizeof(bad_pk->h) );
  FD_TEST( -1==fd_falcon_verify( tv_msg, TV_MSG_LEN, sig, bad_pk ) );

  FD_LOG_NOTICE(( "OK: verify wrong pubkey" ));
}

static void
test_verify_wrong_signature( void ) {
  fd_falcon_pubkey_t pk[1];
  fd_falcon_signature_t sig[1];
  FD_TEST( 0==fd_falcon_pubkey_parse( pk, tv_pubkey ) );

  /* Flip nonce byte */
  FD_TEST( 0==fd_falcon_signature_parse( sig, tv_signature, sizeof(tv_signature) ) );
  sig->nonce[0] ^= 1;
  FD_TEST( -1==fd_falcon_verify( tv_msg, TV_MSG_LEN, sig, pk ) );

  /* Flip nonce byte at the end */
  FD_TEST( 0==fd_falcon_signature_parse( sig, tv_signature, sizeof(tv_signature) ) );
  sig->nonce[39] ^= 0xFF;
  FD_TEST( -1==fd_falcon_verify( tv_msg, TV_MSG_LEN, sig, pk ) );

  /* Flip s2 coefficient */
  FD_TEST( 0==fd_falcon_signature_parse( sig, tv_signature, sizeof(tv_signature) ) );
  sig->s2[0] = (sig->s2[0] + 1) % Q;
  FD_TEST( -1==fd_falcon_verify( tv_msg, TV_MSG_LEN, sig, pk ) );

  /* Flip s2 in the middle */
  FD_TEST( 0==fd_falcon_signature_parse( sig, tv_signature, sizeof(tv_signature) ) );
  sig->s2[N/2] = (sig->s2[N/2] + 100) % Q;
  FD_TEST( -1==fd_falcon_verify( tv_msg, TV_MSG_LEN, sig, pk ) );

  FD_LOG_NOTICE(( "OK: verify wrong signature" ));
}

static void
test_verify_empty_message( void ) {
  fd_falcon_pubkey_t pk[1];
  fd_falcon_signature_t sig[1];
  FD_TEST( 0==fd_falcon_pubkey_parse( pk, tv_pubkey ) );
  FD_TEST( 0==fd_falcon_signature_parse( sig, tv_signature, sizeof(tv_signature) ) );

  /* The signature was created for "data1", not empty, so must fail */
  FD_TEST( -1==fd_falcon_verify( (uchar const *)"", 0, sig, pk ) );

  FD_LOG_NOTICE(( "OK: verify empty message" ));
}

static void
test_verify_idempotent( void ) {
  fd_falcon_pubkey_t pk[1];
  fd_falcon_signature_t sig[1];
  FD_TEST( 0==fd_falcon_pubkey_parse( pk, tv_pubkey ) );
  FD_TEST( 0==fd_falcon_signature_parse( sig, tv_signature, sizeof(tv_signature) ) );

  for( int i=0; i<100; i++ ) {
    FD_TEST( 0==fd_falcon_verify( tv_msg, TV_MSG_LEN, sig, pk ) );
  }
  FD_LOG_NOTICE(( "OK: verify idempotent" ));
}

static void
bench_verify( void ) {
  fd_falcon_pubkey_t pk[1];
  fd_falcon_signature_t sig[1];

  ulong iter = 100000UL;
  long  dt   = -fd_log_wallclock();
  for( ulong i=0UL; i<iter; i++ ) {
    fd_falcon_signature_t const * _sig = sig;
    fd_falcon_pubkey_t    const * _pk  = pk;
    FD_COMPILER_FORGET( _sig );
    FD_COMPILER_FORGET( _pk );
    FD_TEST( 0==fd_falcon_pubkey_parse( pk, tv_pubkey ) );
    FD_TEST( 0==fd_falcon_signature_parse( sig, tv_signature, sizeof(tv_signature) ) );
    FD_TEST( 0==fd_falcon_verify( tv_msg, TV_MSG_LEN, _sig, _pk ) );
  }
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "falcon512 verify: %li ns/verify (%lu iterations)", dt/(long)iter, iter ));
}

static void
bench_pubkey_parse( void ) {
  fd_falcon_pubkey_t pk[1];

  ulong iter = 100000UL;
  long  dt   = -fd_log_wallclock();
  for( ulong i=0UL; i<iter; i++ ) {
    fd_falcon_pubkey_t    const * _pk  = pk;
    FD_COMPILER_FORGET( _pk );
    FD_TEST( 0==fd_falcon_pubkey_parse( pk, tv_pubkey ) );
  }
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "falcon512 pubkey parse: %li ns/parse (%lu iterations)", dt/(long)iter, iter ));
}

static void
bench_sig_parse( void ) {
  fd_falcon_signature_t sig[1];

  ulong iter = 100000UL;
  long  dt   = -fd_log_wallclock();
  for( ulong i=0UL; i<iter; i++ ) {
    fd_falcon_signature_t const * _sig = sig;
    FD_COMPILER_FORGET( _sig );
    FD_TEST( 0==fd_falcon_signature_parse( sig, tv_signature, sizeof(tv_signature) ) );
  }
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "falcon512 signature parse: %li ns/parse (%lu iterations)", dt/(long)iter, iter ));
}

int main( int     argc,
          char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  test_fq_add();
  test_fq_neg();
  test_fq_sub();
  test_fq_mul();

  test_fft_roundtrip( rng );
  test_fft_linearity( rng );

  test_pubkey_parse_valid();
  test_pubkey_parse_invalid_header();
  test_pubkey_parse_coeff_out_of_range();
  test_pubkey_parse_all_zero_coeffs();
  test_pubkey_parse_deterministic();

  test_sig_parse_valid();
  test_sig_parse_empty();
  test_sig_parse_too_short();
  test_sig_parse_invalid_header();
  test_sig_parse_truncated();
  test_sig_parse_deterministic();

  test_verify_valid();
  test_verify_wrong_message();
  test_verify_wrong_pubkey();
  test_verify_wrong_signature();
  test_verify_empty_message();
  test_verify_idempotent();

  bench_verify();
  bench_pubkey_parse();
  bench_sig_parse();

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
