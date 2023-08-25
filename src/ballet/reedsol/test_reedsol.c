#include "fd_reedsol_ppt.h"
#include <stdio.h>

FD_IMPORT_BINARY( fd_reedsol_generic_constants, "src/ballet/reedsol/constants/generic_constants.bin" );
static short const * log_tbl     = (short const *)fd_reedsol_generic_constants; /* Indexed [0, 256) */
static uchar const * invlog_tbl  = fd_reedsol_generic_constants + 256UL*sizeof(short) + 512UL*sizeof(uchar); /* Indexed [-512, 512) */
static uchar const * matrix_32_32= fd_reedsol_generic_constants + 256UL*sizeof(short) + 1024UL*sizeof(uchar); /* Row major order, 32x32 */

#define SHRED_SZ (1024UL)
uchar data_shreds[ SHRED_SZ * FD_REEDSOL_DATA_SHREDS_MAX ];
uchar parity_shreds[ SHRED_SZ * FD_REEDSOL_PARITY_SHREDS_MAX ];
uchar recovered_shreds[ SHRED_SZ * FD_REEDSOL_PARITY_SHREDS_MAX ];

FD_STATIC_ASSERT( FD_REEDSOL_SUCCESS    == 0, unit_test );
FD_STATIC_ASSERT( FD_REEDSOL_ERR_CORRUPT==-1, unit_test );
FD_STATIC_ASSERT( FD_REEDSOL_ERR_PARTIAL==-2, unit_test );

FD_STATIC_ASSERT( sizeof(fd_reedsol_t) == FD_REEDSOL_FOOTPRINT, reedsol_footprint );

uchar mem[ FD_REEDSOL_FOOTPRINT ] __attribute__((aligned(FD_REEDSOL_ALIGN)));

static uchar gfmul( uchar a, uchar b ){ return invlog_tbl[ log_tbl[ a ] + log_tbl[ b ] ]; }
static uchar gfinv( uchar a ){ return invlog_tbl[ 255 - log_tbl[ a ] ]; }

/* Reference implementation using the matrix-based version similar to
   the Rust crate. */
void fd_reedsol_encode_ref( ulong                 shred_sz,
                            uchar const * const * data_shred,
                            ulong                 data_shred_cnt,
                            uchar       * const * parity_shred,
                            ulong                 parity_shred_cnt ) {

  uchar top_matrix[ FD_REEDSOL_DATA_SHREDS_MAX ][ 2UL*FD_REEDSOL_DATA_SHREDS_MAX ];
  uchar main_matrix[ FD_REEDSOL_PARITY_SHREDS_MAX ][ FD_REEDSOL_DATA_SHREDS_MAX ];
  /* Set first row */
  top_matrix[ 0 ][ 0 ] = (uchar)1;
  for( ulong j=1UL; j<data_shred_cnt; j++ )     top_matrix[  0 ][ j ] = (uchar)0;

  for( ulong i=1UL; i<data_shred_cnt; i++ ) {
    /* Populate ith row */
    ulong log_i = (ulong)log_tbl[ i ]; /* i != 0, so log_tbl[ i ] >= 0 */
    top_matrix[ i ][ 0 ] = (uchar)1;
    for( ulong j=1UL; j<data_shred_cnt; j++ )   top_matrix[  i ][ j ] = invlog_tbl[ (log_i*j)%255UL ];
  }
  /* Populate main_matrix as well */
  for( ulong i=0UL; i<parity_shred_cnt; i++ ) {
    ulong log_i = (ulong)log_tbl[ i+data_shred_cnt ];
    main_matrix[ i ][ 0 ] = (uchar)1;
    for( ulong j=1UL; j<data_shred_cnt; j++ )   main_matrix[  i ][ j ] = invlog_tbl[ (log_i*j)%255UL ];
  }

  /* Augment top_matrix with an identity matrix */
  for( ulong i=0UL; i<data_shred_cnt; i++ ) for( ulong j=0UL; j<data_shred_cnt; j++ ) top_matrix[ i ][ j+data_shred_cnt ] = (uchar)(i==j);

  /* Gaussian elimination to invert top_matrix */
  for( ulong row=0UL; row<data_shred_cnt; row++ ) {
    for( ulong swap_with = row; swap_with<data_shred_cnt; swap_with++ ) {
      if( FD_LIKELY( top_matrix[ swap_with ][ row ] ) ) {
        /* swap row with swap_with if necessary */
        if( row != swap_with ) {
          for( ulong j=row; j<2UL*data_shred_cnt; j++ ) {
            uchar temp = top_matrix[ row ][ j ];
            top_matrix[ row ][ j ] = top_matrix[ swap_with ][ j ];
            top_matrix[ swap_with ][ j ] = temp;
          }
        }
        break;
      }
    }

    /* Scale row to set pivot to 1 */
    long l_p = 255L - log_tbl[ top_matrix[ row ][ row ] ]; /* We've chosen row so that top_matrix[row][row] != 0, so 0<l_p<=255 */
    for( ulong j=row; j<2UL*data_shred_cnt; j++ ) top_matrix[ row ][ j ] = invlog_tbl[ l_p + log_tbl[ top_matrix[ row ][ j ] ] ];

    /* Clear out next rows */
    for( ulong i=row+1UL; i<data_shred_cnt; i++ ) {
      long ls = log_tbl[ top_matrix[ i ][ row ] ];
      /* top_matrix[ i ] += scalar * top_matrix[ row ] */
      for( ulong j=row; j<2UL*data_shred_cnt; j++ ) top_matrix[ i ][ j ] ^= invlog_tbl[ ls + log_tbl[ top_matrix[ row ][ j ] ] ];
    }
  }

  /* Now the back substitute step */
  for( ulong row=0UL; row<data_shred_cnt; row++ ) for( ulong col=row+1UL; col<data_shred_cnt; col++ ) {
    if( top_matrix[ row ][ col ] ) {
      long ls = log_tbl[ top_matrix[ row ][ col ] ];
      /* top_matrix[ row ] -= scale*top_matrix[ col ] */
      for( ulong j=col; j<2UL*data_shred_cnt; j++ ) top_matrix[ row ][ j ] ^= invlog_tbl[ ls + log_tbl[ top_matrix[ col ][ j ] ] ];
    }
  }

  /* main_matrix = main_matrix * (right half of top_matrix).
   * In-place multipication, so we need some extra temporary space. */
  for( ulong i=0UL; i<parity_shred_cnt; i++ ) {
    ulong temp[ FD_REEDSOL_DATA_SHREDS_MAX ];
    fd_memset( temp, 0, data_shred_cnt*sizeof(ulong) );
    for( ulong j=0UL; j<data_shred_cnt; j++) for( ulong k=0UL; k<data_shred_cnt; k++ )
      temp[ j ] ^= (ulong)invlog_tbl[ log_tbl[ main_matrix[ i ][ k ] ] + log_tbl[ top_matrix[ k ][ data_shred_cnt+j ] ] ];
    /* Done with row i, so copy it back to main_matrix */
    for( ulong j=0UL; j<data_shred_cnt; j++) main_matrix[ i ][ j ] = (uchar)temp[ j ];
  }

  /* Done computing the matrix.  Now actually use it. */

  for( ulong shred_pos=0UL; shred_pos<shred_sz; shred_pos++ ) {
    for( ulong row=0UL; row<parity_shred_cnt; row++ ) {
      ulong sum = 0UL;
      /* In GF(2^8), sum += matrix[row][col] * data[col][shred_pos].
         We compute a*b as invlog[log[a]+log[b]], where the + is normal
         integer addition mod 256.  The log and invlog tables handle the
         0 cases naturally. */
      for( ulong col=0UL; col<data_shred_cnt; col++ )
        sum ^= (ulong)invlog_tbl[ log_tbl[ main_matrix[ row ][ col ] ] + log_tbl[ data_shred[ col ][ shred_pos ] ] ];
      parity_shred[ row ][ shred_pos ] = (uchar)sum;
    }
  }
}

static void
basic_tests( void ) {

  FD_TEST( !strcmp( fd_reedsol_strerror( FD_REEDSOL_SUCCESS     ), "success" ) );
  FD_TEST( !strcmp( fd_reedsol_strerror( FD_REEDSOL_ERR_CORRUPT ), "corrupt" ) );
  FD_TEST( !strcmp( fd_reedsol_strerror( FD_REEDSOL_ERR_PARTIAL ), "partial" ) );
  FD_TEST( !strcmp( fd_reedsol_strerror( 1                      ), "unknown" ) );

  uchar * d[ 32UL ];
  uchar * p[ 32UL ];

  fd_memset( data_shreds, 0, SHRED_SZ*32UL );

  for( ulong i=0UL; i<32UL; i++ ) { d[ i ] = data_shreds + SHRED_SZ*i; p[ i ] = parity_shreds + SHRED_SZ*i; }

  fd_reedsol_t * rs = fd_reedsol_encode_init( mem, SHRED_SZ );
  /* Identity matrix */
  for( ulong i=0UL; i<32UL; i++ ) d[ i ][ i ] = (uchar)1;

  for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_encode_add_parity_shred( fd_reedsol_encode_add_data_shred( rs, d[ i ] ), p[ i ] );
  fd_reedsol_encode_fini( rs );

  for( ulong i=0UL; i<32UL; i++ ) for( ulong j=0UL; j<32UL; j++ )  FD_TEST( p[ i ][ j ] == matrix_32_32[ i*32UL+j ] );

  /* Increasing diagonal */
  rs = fd_reedsol_encode_init( mem, SHRED_SZ );
  for( ulong i=0UL; i<32UL; i++ ) d[ i ][ i ] = (uchar)i;

  for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_encode_add_parity_shred( fd_reedsol_encode_add_data_shred( rs, d[ i ] ), p[ i ] );
  fd_reedsol_encode_fini( rs );

  ulong sum = 0UL;
  for( ulong i=0UL; i<32UL; i++ ) for( ulong j=0UL; j<32UL; j+=sizeof(ulong) ) sum += *(ulong*)(p[ i ] + j);

  FD_TEST( sum == 0x121a5c5754f0c0deUL );

  /* All 1s */
  /* The unique polynomial of degree < 32 that is 1 at all integers x in
     [0, 32) is the constant 1, so it also has value 1 at all other
     points. */
  rs = fd_reedsol_encode_init( mem, SHRED_SZ );
  fd_memset( data_shreds, 1, SHRED_SZ * 32UL );

  for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_encode_add_parity_shred( fd_reedsol_encode_add_data_shred( rs, d[ i ] ), p[ i ] );
  fd_reedsol_encode_fini( rs );

  for( ulong i=0UL; i<32UL; i++ ) for( ulong j=0UL; j<32UL; j++ ) FD_TEST( p[ i ][ j ] == (uchar)1 );

}

typedef uchar linear_chunk_t[ 32UL ];

#define LINEAR_MAX_DIM (128UL)

/* FFT, PPT, and even Reed-Solomon encoding are all linear functions on
   each byte of the chunk. */
typedef void linear_func_t( linear_chunk_t *, linear_chunk_t * );
static void
test_linearity( linear_func_t to_test,
                ulong         input_cnt,
                ulong         output_cnt,
                fd_rng_t *    rng,
                ulong         test_cnt,
                ulong         chunk_sz ) {
  /* If these fail, the test is wrong */
  FD_TEST( input_cnt <= LINEAR_MAX_DIM && output_cnt <= LINEAR_MAX_DIM );
  FD_TEST( chunk_sz <= 32UL );

  linear_chunk_t  inputs[ LINEAR_MAX_DIM ];
  linear_chunk_t outputs[ LINEAR_MAX_DIM ];

  /* For a linear function, f(0) = 0 */
  for( ulong i=0UL; i<input_cnt; i++ ) fd_memset( inputs[ i ], 0, chunk_sz );
  to_test( inputs, outputs );
  for( ulong j=0UL; j<output_cnt; j++ ) for( ulong col=0UL; col<chunk_sz; col++ ) FD_TEST( outputs[ j ][ col ] == (uchar)0 );

  /* First show f is a vectorized function, i.e. the c^th column of the
     output is a function of the c^th column of the input alone, and
     these functions are all the same. */
  for( ulong k=0UL; k<test_cnt; k++ ) {
    linear_chunk_t  inputs2[ LINEAR_MAX_DIM ];
    linear_chunk_t outputs2[ LINEAR_MAX_DIM ];
    /* Initialize randomly */
    for( ulong i=0UL; i<input_cnt; i++ ) for( ulong col=0UL; col<chunk_sz; col++ ) inputs[ i ][ col ] = fd_rng_uchar( rng );
    to_test( inputs, outputs );

    for( ulong shift=1UL; shift<chunk_sz; shift++ ) {
      for( ulong i=0UL; i<input_cnt; i++ )
        for( ulong col=0UL; col<chunk_sz; col++ ) inputs2[ i ][ (col+shift)%chunk_sz ] = inputs[ i ][ col ];

      to_test( inputs2, outputs2 );

      for( ulong j=0UL; j<output_cnt; j++ )
        for( ulong col=0UL; col<chunk_sz; col++ ) FD_TEST( outputs[ j ][ col ] == outputs2[ j ][ (col+shift)%32UL ] );
    }
  }

  /* f(a + b) = f(a) + f(b) */
  for( ulong k=0UL; k<test_cnt; k++ ) {
    linear_chunk_t  inputsA[ LINEAR_MAX_DIM ];
    linear_chunk_t outputsA[ LINEAR_MAX_DIM ];
    linear_chunk_t  inputsB[ LINEAR_MAX_DIM ];
    linear_chunk_t outputsB[ LINEAR_MAX_DIM ];

    for( ulong i=0UL; i<input_cnt; i++ ) for( ulong col=0UL; col<chunk_sz; col++ ) {
      inputsA[ i ][ col ] = fd_rng_uchar( rng );
      inputsB[ i ][ col ] = fd_rng_uchar( rng );
      inputs[ i ][ col ] = inputsA[ i ][ col ] ^ inputsB[ i ][ col ];
    }

    to_test( inputsA, outputsA );
    to_test( inputsB, outputsB );
    to_test( inputs,  outputs  );

    for( ulong j=0UL; j<output_cnt; j++ ) for( ulong col=0UL; col<chunk_sz; col++ )
      FD_TEST( outputs[ j ][ col ] == (outputsA[ j ][ col ] ^ outputsB[ j ][ col ] ) );
  }

  /* f( lambda * x ) = lambda * f(x) */
  for( ulong k=0UL; k<test_cnt; k++ ) {
    linear_chunk_t  inputs2[ LINEAR_MAX_DIM ];
    linear_chunk_t outputs2[ LINEAR_MAX_DIM ];
    uchar col_scalars[ 32UL ];

    for( ulong i=0UL; i<chunk_sz; i++ ) col_scalars[ i ] = fd_rng_uchar( rng );

    for( ulong i=0UL; i<input_cnt; i++ ) for( ulong col=0UL; col<chunk_sz; col++ )
      inputs2[ i ][ col ] = gfmul( inputs[ i ][ col ], col_scalars[ col ] );

    to_test( inputs2, outputs2 );

    for( ulong j=0UL; j<output_cnt; j++ )  for( ulong col=0UL; col<chunk_sz; col++ )
      FD_TEST( outputs2[ j ][ col ] == gfmul( outputs[ j ][ col ], col_scalars[ col ] ) );
  }
}

#define REPEAT_128(m, SEP, offset, binary) REPEAT_64(m, SEP, offset, binary##0) SEP() REPEAT_64(m, SEP, (offset)+64UL, binary##1)
#define REPEAT_64( m, SEP, offset, binary) REPEAT_32(m, SEP, offset, binary##0) SEP() REPEAT_32(m, SEP, (offset)+32UL, binary##1)
#define REPEAT_32( m, SEP, offset, binary) REPEAT_16(m, SEP, offset, binary##0) SEP() REPEAT_16(m, SEP, (offset)+16UL, binary##1)
#define REPEAT_16( m, SEP, offset, binary) REPEAT_8( m, SEP, offset, binary##0) SEP() REPEAT_8( m, SEP, (offset)+ 8UL, binary##1)
#define REPEAT_8(  m, SEP, offset, binary) REPEAT_4( m, SEP, offset, binary##0) SEP() REPEAT_4( m, SEP, (offset)+ 4UL, binary##1)
#define REPEAT_4(  m, SEP, offset, binary) REPEAT_2( m, SEP, offset, binary##0) SEP() REPEAT_2( m, SEP, (offset)+ 2UL, binary##1)
#define REPEAT_2(  m, SEP, offset, binary) m(offset, binary##0) SEP() m((offset)+1UL, binary##1)

#define LOAD_VAR(offset, binary) gf_t v##binary = gf_ldu( inputs[offset] );
#define STORE_VAR(offset, binary) gf_stu( outputs[offset], v##binary );
#define VAR(   offset, binary)  v##binary
#define REFVAR(offset, binary) &v##binary
#define COMMA() ,
#define NO_SEP()

#define WRAP_FFT(N) \
static void \
wrapped_fft_##N( linear_chunk_t * inputs, linear_chunk_t * outputs ) { \
    REPEAT_##N(LOAD_VAR, NO_SEP , 0, ) \
    FD_REEDSOL_GENERATE_FFT( N, 0, REPEAT_##N(VAR, COMMA, 0, ) ); \
    REPEAT_##N(STORE_VAR, NO_SEP , 0, ) \
} \
static void \
wrapped_fft_##N##_shift( linear_chunk_t * inputs, linear_chunk_t * outputs ) { \
    REPEAT_##N(LOAD_VAR, NO_SEP , 0, ) \
    FD_REEDSOL_GENERATE_FFT( N, N, REPEAT_##N(VAR, COMMA, 0, ) ); \
    REPEAT_##N(STORE_VAR, NO_SEP , 0, ) \
} \
static void \
wrapped_ifft_##N( linear_chunk_t * inputs, linear_chunk_t * outputs ) { \
    REPEAT_##N(LOAD_VAR, NO_SEP , 0, ) \
    FD_REEDSOL_GENERATE_IFFT( N, 0, REPEAT_##N(VAR, COMMA, 0, ) ); \
    REPEAT_##N(STORE_VAR, NO_SEP , 0, ) \
} \
static void \
wrapped_ifft_##N##_shift( linear_chunk_t * inputs, linear_chunk_t * outputs ) { \
    REPEAT_##N(LOAD_VAR, NO_SEP , 0, ) \
    FD_REEDSOL_GENERATE_IFFT( N, N, REPEAT_##N(VAR, COMMA, 0, ) ); \
    REPEAT_##N(STORE_VAR, NO_SEP , 0, ) \
}

#define WRAP_FFT2(N) \
static void \
wrapped_fft_##N( linear_chunk_t * inputs, linear_chunk_t * outputs ) { \
    REPEAT_##N(LOAD_VAR, NO_SEP , 0, ) \
    fd_reedsol_fft_##N##_0( REPEAT_##N(REFVAR, COMMA, 0, ) ); \
    REPEAT_##N(STORE_VAR, NO_SEP , 0, ) \
} \
static void \
wrapped_fft_##N##_shift( linear_chunk_t * inputs, linear_chunk_t * outputs ) { \
    REPEAT_##N(LOAD_VAR, NO_SEP , 0, ) \
    fd_reedsol_fft_##N##_##N( REPEAT_##N(REFVAR, COMMA, 0, ) ); \
    REPEAT_##N(STORE_VAR, NO_SEP , 0, ) \
} \
static void \
wrapped_ifft_##N( linear_chunk_t * inputs, linear_chunk_t * outputs ) { \
    REPEAT_##N(LOAD_VAR, NO_SEP , 0, ) \
    fd_reedsol_ifft_##N##_0( REPEAT_##N(REFVAR, COMMA, 0, ) ); \
    REPEAT_##N(STORE_VAR, NO_SEP , 0, ) \
} \
static void \
wrapped_ifft_##N##_shift( linear_chunk_t * inputs, linear_chunk_t * outputs ) { \
    REPEAT_##N(LOAD_VAR, NO_SEP , 0, ) \
    fd_reedsol_ifft_##N##_##N( REPEAT_##N(REFVAR, COMMA, 0, ) ); \
    REPEAT_##N(STORE_VAR, NO_SEP , 0, ) \
}

#define INVOKE(M, ...) M( __VA_ARGS__)

#define WRAP_PPT(N, K) \
static void \
wrapped_ppt_##N##_## K ( linear_chunk_t * inputs, linear_chunk_t * outputs ) { \
    INVOKE(REPEAT_##N, LOAD_VAR, NO_SEP , 0, ) \
    FD_REEDSOL_GENERATE_PPT( N, K, REPEAT_##N(VAR, COMMA, 0, ) ); \
    REPEAT_##N(STORE_VAR, NO_SEP , 0, ) \
}
#define WRAP_PPT2(N, K) \
static void \
wrapped_ppt_##N##_## K ( linear_chunk_t * inputs, linear_chunk_t * outputs ) { \
    INVOKE(REPEAT_##N, LOAD_VAR, NO_SEP , 0, ) \
    fd_reedsol_ppt_##N##_##K( REPEAT_##N(REFVAR, COMMA, 0, ) ); \
    REPEAT_##N(STORE_VAR, NO_SEP , 0, ) \
}

static ulong wrapped_data_shred_cnt, wrapped_parity_shred_cnt;
static void
wrapped_encode_generic( linear_chunk_t * inputs, linear_chunk_t * outputs ) {
  fd_reedsol_t * rs = fd_reedsol_encode_init( mem, 32UL );

  for( ulong i=0UL; i<wrapped_data_shred_cnt;  i++ )  fd_reedsol_encode_add_data_shred(   rs, inputs[ i ]  );
  for( ulong j=0UL; j<wrapped_parity_shred_cnt; j++ ) fd_reedsol_encode_add_parity_shred( rs, outputs[ j ] );

  fd_reedsol_encode_fini( rs );
}

WRAP_FFT(4) WRAP_FFT(8) WRAP_FFT(16) WRAP_FFT(32) WRAP_FFT2(64) WRAP_FFT2(128)

WRAP_PPT(16,  1) WRAP_PPT(16,  2) WRAP_PPT(16,  3) WRAP_PPT(16,  4)
WRAP_PPT(16,  5) WRAP_PPT(16,  6) WRAP_PPT(16,  7) WRAP_PPT(16,  8)
WRAP_PPT(16,  9) WRAP_PPT(16, 10) WRAP_PPT(16, 11) WRAP_PPT(16, 12)
WRAP_PPT(16, 13) WRAP_PPT(16, 14) WRAP_PPT(16, 15)

WRAP_PPT2(32, 17) WRAP_PPT2(32, 18) WRAP_PPT2(32, 19) WRAP_PPT2(32, 20)
WRAP_PPT2(32, 21) WRAP_PPT2(32, 22) WRAP_PPT2(32, 23) WRAP_PPT2(32, 24)
WRAP_PPT2(32, 25) WRAP_PPT2(32, 26) WRAP_PPT2(32, 27) WRAP_PPT2(32, 28)
WRAP_PPT2(32, 29) WRAP_PPT2(32, 30) WRAP_PPT2(32, 31)

WRAP_PPT2(64, 33) WRAP_PPT2(64, 34) WRAP_PPT2(64, 35) WRAP_PPT2(64, 36)
WRAP_PPT2(64, 37) WRAP_PPT2(64, 38) WRAP_PPT2(64, 39) WRAP_PPT2(64, 40)
WRAP_PPT2(64, 41) WRAP_PPT2(64, 42) WRAP_PPT2(64, 43) WRAP_PPT2(64, 44)
WRAP_PPT2(64, 45) WRAP_PPT2(64, 46) WRAP_PPT2(64, 47) WRAP_PPT2(64, 48)
WRAP_PPT2(64, 49) WRAP_PPT2(64, 50) WRAP_PPT2(64, 51) WRAP_PPT2(64, 52)
WRAP_PPT2(64, 53) WRAP_PPT2(64, 54) WRAP_PPT2(64, 55) WRAP_PPT2(64, 56)
WRAP_PPT2(64, 57) WRAP_PPT2(64, 58) WRAP_PPT2(64, 59) WRAP_PPT2(64, 60)
WRAP_PPT2(64, 61) WRAP_PPT2(64, 62) WRAP_PPT2(64, 63)

WRAP_PPT2(128, 65) WRAP_PPT2(128, 66) WRAP_PPT2(128, 67)

static void
test_linearity_all( fd_rng_t * rng ) {
  ulong TC = 10000UL; /* Test count */
  const ulong CW = GF_WIDTH;

  FD_LOG_NOTICE(( "Testing linearity of FFT and IFFT" ));
  test_linearity( wrapped_fft_4,    4UL,  4UL, rng, TC, CW ); test_linearity( wrapped_fft_4_shift,    4UL,  4UL, rng, TC, CW );
  test_linearity( wrapped_ifft_4,   4UL,  4UL, rng, TC, CW ); test_linearity( wrapped_ifft_4_shift,   4UL,  4UL, rng, TC, CW );
  test_linearity( wrapped_fft_8,    8UL,  8UL, rng, TC, CW ); test_linearity( wrapped_fft_8_shift,    8UL,  8UL, rng, TC, CW );
  test_linearity( wrapped_ifft_8,   8UL,  8UL, rng, TC, CW ); test_linearity( wrapped_ifft_8_shift,   8UL,  8UL, rng, TC, CW );
  test_linearity( wrapped_fft_16,  16UL, 16UL, rng, TC, CW ); test_linearity( wrapped_fft_16_shift,  16UL, 16UL, rng, TC, CW );
  test_linearity( wrapped_ifft_16, 16UL, 16UL, rng, TC, CW ); test_linearity( wrapped_ifft_16_shift, 16UL, 16UL, rng, TC, CW );
  test_linearity( wrapped_fft_32,  32UL, 32UL, rng, TC, CW ); test_linearity( wrapped_fft_32_shift,  32UL, 32UL, rng, TC, CW );
  test_linearity( wrapped_ifft_32, 32UL, 32UL, rng, TC, CW ); test_linearity( wrapped_ifft_32_shift, 32UL, 32UL, rng, TC, CW );
  test_linearity( wrapped_fft_64,  64UL, 64UL, rng, TC, CW ); test_linearity( wrapped_fft_64_shift,  64UL, 64UL, rng, TC, CW );
  test_linearity( wrapped_ifft_64, 64UL, 64UL, rng, TC, CW ); test_linearity( wrapped_ifft_64_shift, 64UL, 64UL, rng, TC, CW );
  test_linearity( wrapped_fft_128,        128UL, 128UL, rng, TC, CW );
  test_linearity( wrapped_fft_128_shift,  128UL, 128UL, rng, TC, CW );
  test_linearity( wrapped_ifft_128,       128UL, 128UL, rng, TC, CW );
  test_linearity( wrapped_ifft_128_shift, 128UL, 128UL, rng, TC, CW );

  FD_LOG_NOTICE(( "Testing linearity of PPT 16" ));
  test_linearity( wrapped_ppt_16_1,  16UL, 16UL, rng, TC, CW ); test_linearity( wrapped_ppt_16_2,  16UL, 16UL, rng, TC, CW );
  test_linearity( wrapped_ppt_16_3,  16UL, 16UL, rng, TC, CW ); test_linearity( wrapped_ppt_16_4,  16UL, 16UL, rng, TC, CW );
  test_linearity( wrapped_ppt_16_5,  16UL, 16UL, rng, TC, CW ); test_linearity( wrapped_ppt_16_6,  16UL, 16UL, rng, TC, CW );
  test_linearity( wrapped_ppt_16_7,  16UL, 16UL, rng, TC, CW ); test_linearity( wrapped_ppt_16_8,  16UL, 16UL, rng, TC, CW );
  test_linearity( wrapped_ppt_16_9,  16UL, 16UL, rng, TC, CW ); test_linearity( wrapped_ppt_16_10, 16UL, 16UL, rng, TC, CW );
  test_linearity( wrapped_ppt_16_11, 16UL, 16UL, rng, TC, CW ); test_linearity( wrapped_ppt_16_12, 16UL, 16UL, rng, TC, CW );
  test_linearity( wrapped_ppt_16_13, 16UL, 16UL, rng, TC, CW ); test_linearity( wrapped_ppt_16_14, 16UL, 16UL, rng, TC, CW );
  test_linearity( wrapped_ppt_16_15, 16UL, 16UL, rng, TC, CW );

  TC /= 2UL;
  FD_LOG_NOTICE(( "Testing linearity of PPT 32" ));
  test_linearity( wrapped_ppt_32_17, 32UL, 32UL, rng, TC, CW ); test_linearity( wrapped_ppt_32_18, 32UL, 32UL, rng, TC, CW );
  test_linearity( wrapped_ppt_32_19, 32UL, 32UL, rng, TC, CW ); test_linearity( wrapped_ppt_32_20, 32UL, 32UL, rng, TC, CW );
  test_linearity( wrapped_ppt_32_21, 32UL, 32UL, rng, TC, CW ); test_linearity( wrapped_ppt_32_22, 32UL, 32UL, rng, TC, CW );
  test_linearity( wrapped_ppt_32_23, 32UL, 32UL, rng, TC, CW ); test_linearity( wrapped_ppt_32_24, 32UL, 32UL, rng, TC, CW );
  test_linearity( wrapped_ppt_32_25, 32UL, 32UL, rng, TC, CW ); test_linearity( wrapped_ppt_32_26, 32UL, 32UL, rng, TC, CW );
  test_linearity( wrapped_ppt_32_27, 32UL, 32UL, rng, TC, CW ); test_linearity( wrapped_ppt_32_28, 32UL, 32UL, rng, TC, CW );
  test_linearity( wrapped_ppt_32_29, 32UL, 32UL, rng, TC, CW ); test_linearity( wrapped_ppt_32_30, 32UL, 32UL, rng, TC, CW );
  test_linearity( wrapped_ppt_32_31, 32UL, 32UL, rng, TC, CW );

  TC /= 2UL;
  FD_LOG_NOTICE(( "Testing linearity of PPT 64" ));
  test_linearity( wrapped_ppt_64_33, 64UL, 64UL, rng, TC, CW ); test_linearity( wrapped_ppt_64_34, 64UL, 64UL, rng, TC, CW );
  test_linearity( wrapped_ppt_64_35, 64UL, 64UL, rng, TC, CW ); test_linearity( wrapped_ppt_64_36, 64UL, 64UL, rng, TC, CW );
  test_linearity( wrapped_ppt_64_37, 64UL, 64UL, rng, TC, CW ); test_linearity( wrapped_ppt_64_38, 64UL, 64UL, rng, TC, CW );
  test_linearity( wrapped_ppt_64_39, 64UL, 64UL, rng, TC, CW ); test_linearity( wrapped_ppt_64_40, 64UL, 64UL, rng, TC, CW );
  test_linearity( wrapped_ppt_64_41, 64UL, 64UL, rng, TC, CW ); test_linearity( wrapped_ppt_64_42, 64UL, 64UL, rng, TC, CW );
  test_linearity( wrapped_ppt_64_43, 64UL, 64UL, rng, TC, CW ); test_linearity( wrapped_ppt_64_44, 64UL, 64UL, rng, TC, CW );
  test_linearity( wrapped_ppt_64_45, 64UL, 64UL, rng, TC, CW ); test_linearity( wrapped_ppt_64_46, 64UL, 64UL, rng, TC, CW );
  test_linearity( wrapped_ppt_64_47, 64UL, 64UL, rng, TC, CW ); test_linearity( wrapped_ppt_64_48, 64UL, 64UL, rng, TC, CW );
  test_linearity( wrapped_ppt_64_49, 64UL, 64UL, rng, TC, CW ); test_linearity( wrapped_ppt_64_50, 64UL, 64UL, rng, TC, CW );
  test_linearity( wrapped_ppt_64_51, 64UL, 64UL, rng, TC, CW ); test_linearity( wrapped_ppt_64_52, 64UL, 64UL, rng, TC, CW );
  test_linearity( wrapped_ppt_64_53, 64UL, 64UL, rng, TC, CW ); test_linearity( wrapped_ppt_64_54, 64UL, 64UL, rng, TC, CW );
  test_linearity( wrapped_ppt_64_55, 64UL, 64UL, rng, TC, CW ); test_linearity( wrapped_ppt_64_56, 64UL, 64UL, rng, TC, CW );
  test_linearity( wrapped_ppt_64_57, 64UL, 64UL, rng, TC, CW ); test_linearity( wrapped_ppt_64_58, 64UL, 64UL, rng, TC, CW );
  test_linearity( wrapped_ppt_64_59, 64UL, 64UL, rng, TC, CW ); test_linearity( wrapped_ppt_64_60, 64UL, 64UL, rng, TC, CW );
  test_linearity( wrapped_ppt_64_61, 64UL, 64UL, rng, TC, CW ); test_linearity( wrapped_ppt_64_62, 64UL, 64UL, rng, TC, CW );
  test_linearity( wrapped_ppt_64_63, 64UL, 64UL, rng, TC, CW );

  test_linearity( wrapped_ppt_128_65, 128UL, 128UL, rng, TC, CW );
  test_linearity( wrapped_ppt_128_66, 128UL, 128UL, rng, TC, CW );
  test_linearity( wrapped_ppt_128_67, 128UL, 128UL, rng, TC, CW );

  FD_LOG_NOTICE(( "Testing linearity of reedsol_encode" ));
  for( wrapped_data_shred_cnt=1UL; wrapped_data_shred_cnt<=FD_REEDSOL_DATA_SHREDS_MAX; wrapped_data_shred_cnt++ )
    for( wrapped_parity_shred_cnt=1UL; wrapped_parity_shred_cnt<=FD_REEDSOL_PARITY_SHREDS_MAX; wrapped_parity_shred_cnt++ )
      test_linearity( wrapped_encode_generic, wrapped_data_shred_cnt, wrapped_parity_shred_cnt, rng, 500UL, 32UL );
}

/* Since now we know these are linear operators, we only need to test
   their behavior on a basis.  We'll use the identity matrix as the
   basis. */

/* Reference implementations for s, S, and X as defined in
   fd_reedsol_fft.h */
static uchar
s_ref( int j, uchar x ) { /* j in [0, 6) */
  ulong mask = fd_ulong_mask_lsb( j );
  ulong min_x = x & (~mask);
  ulong max_x = min_x + mask + 1UL;

  uchar prod = (uchar)1;
  for( ulong y=min_x; y<max_x; y++ ) prod = gfmul( prod, (uchar)y );
  return prod;
}

static uchar S_ref( int j, uchar x ) { return gfmul( s_ref( j, x ), gfinv( s_ref( j, (uchar)(1<<j) ) ) ); }

static uchar
X_ref( ulong i, uchar x ) { /* i in [0, 64) */
  uchar prod = (uchar)1;
  for( int j=0UL; j<6; j++ ) if( i & (1UL<<j) ) prod = gfmul( prod, S_ref( j, x ) );
  return prod;
}

static void
test_fft_single( linear_func_t to_test, ulong N, ulong expected_shift ) {
  linear_chunk_t inputs[  FD_REEDSOL_DATA_SHREDS_MAX   ];
  linear_chunk_t outputs[ FD_REEDSOL_PARITY_SHREDS_MAX ];

  /* Only use first uchar in the chunk to simplify the code */
  for( ulong outer=0UL; outer<N; outer++ ) {
    for( ulong i=0UL; i<N; i++ ) inputs[ i ][ 0 ] = (uchar)(i==outer);

    to_test( inputs, outputs );

    for( ulong r=0UL; r<N; r++ ) FD_TEST( outputs[ r ][ 0 ] == X_ref( outer, (uchar)(r+expected_shift) ) );
  }
}

static void
test_ifft_single( linear_func_t to_test, ulong N, ulong expected_shift ) {
  linear_chunk_t inputs[  FD_REEDSOL_DATA_SHREDS_MAX   ];
  linear_chunk_t outputs[ FD_REEDSOL_PARITY_SHREDS_MAX ];

  for( ulong outer=0UL; outer<N; outer++ ) {
    for( ulong i=0UL; i<N; i++ ) inputs[ i ][ 0 ] = (uchar)(i==outer);

    to_test( inputs, outputs );

    for( ulong p=0UL; p<N; p++ ) {
      /* Evaluate the polynomial at p */
      uchar sum = (uchar)0;

      for( ulong r=0UL; r<N; r++ )
        sum ^= gfmul( outputs[ r ][ 0 ], X_ref( r, (uchar)(p+expected_shift) ) );
      FD_TEST( (int)sum == (outer==p) );
    }
  }
}

/* Test that f1 and f2 are inverses of each other */
static void
test_inv( linear_func_t f1, linear_func_t f2, ulong N ) {
  linear_chunk_t A[  FD_REEDSOL_DATA_SHREDS_MAX   ];
  linear_chunk_t B[ FD_REEDSOL_PARITY_SHREDS_MAX ];

  for( ulong i=0UL; i<N; i++ ) for( ulong j=0UL; j<N; j++ ) A[ i ][ j ] = (uchar)(i==j);

  f1( A, B );
  f2( B, A );

  for( ulong i=0UL; i<N; i++ ) for( ulong j=0UL; j<N; j++ ) FD_TEST( A[ i ][ j ] == (uchar)(i==j) );

  for( ulong i=0UL; i<N; i++ ) for( ulong j=0UL; j<N; j++ ) B[ i ][ j ] = (uchar)(i==j);

  f2( B, A );
  f1( A, B );

  for( ulong i=0UL; i<N; i++ ) for( ulong j=0UL; j<N; j++ ) FD_TEST( B[ i ][ j ] == (uchar)(i==j) );
}

static void
test_fft_all( void ) {
  test_fft_single( wrapped_fft_4,          4UL,  0UL );  test_ifft_single( wrapped_ifft_4,          4UL,  0UL );
  test_fft_single( wrapped_fft_4_shift,    4UL,  4UL );  test_ifft_single( wrapped_ifft_4_shift,    4UL,  4UL );
  test_fft_single( wrapped_fft_8,          8UL,  0UL );  test_ifft_single( wrapped_ifft_8,          8UL,  0UL );
  test_fft_single( wrapped_fft_8_shift,    8UL,  8UL );  test_ifft_single( wrapped_ifft_8_shift,    8UL,  8UL );
  test_fft_single( wrapped_fft_16,        16UL,  0UL );  test_ifft_single( wrapped_ifft_16,        16UL,  0UL );
  test_fft_single( wrapped_fft_16_shift,  16UL, 16UL );  test_ifft_single( wrapped_ifft_16_shift,  16UL, 16UL );
  test_fft_single( wrapped_fft_32,        32UL,  0UL );  test_ifft_single( wrapped_ifft_32,        32UL,  0UL );
  test_fft_single( wrapped_fft_32_shift,  32UL, 32UL );  test_ifft_single( wrapped_ifft_32_shift,  32UL, 32UL );
  test_fft_single( wrapped_fft_64,        64UL,  0UL );  test_ifft_single( wrapped_ifft_64,        64UL,  0UL );
  test_fft_single( wrapped_fft_64_shift,  64UL, 64UL );  test_ifft_single( wrapped_ifft_64_shift,  64UL, 64UL );

  test_inv( wrapped_fft_4,        wrapped_ifft_4,         4UL ); test_inv( wrapped_ifft_4,        wrapped_fft_4,         4UL );
  test_inv( wrapped_fft_8,        wrapped_ifft_8,         8UL ); test_inv( wrapped_ifft_8,        wrapped_fft_8,         8UL );
  test_inv( wrapped_fft_16,       wrapped_ifft_16,       16UL ); test_inv( wrapped_ifft_16,       wrapped_fft_16,       16UL );
  test_inv( wrapped_fft_32,       wrapped_ifft_32,       32UL ); test_inv( wrapped_ifft_32,       wrapped_fft_32,       32UL );
  test_inv( wrapped_fft_4_shift,  wrapped_ifft_4_shift,   4UL ); test_inv( wrapped_ifft_4_shift,  wrapped_fft_4_shift,   4UL );
  test_inv( wrapped_fft_8_shift,  wrapped_ifft_8_shift,   8UL ); test_inv( wrapped_ifft_8_shift,  wrapped_fft_8_shift,   8UL );
  test_inv( wrapped_fft_16_shift, wrapped_ifft_16_shift, 16UL ); test_inv( wrapped_ifft_16_shift, wrapped_fft_16_shift, 16UL );
  test_inv( wrapped_fft_32_shift, wrapped_ifft_32_shift, 32UL ); test_inv( wrapped_ifft_32_shift, wrapped_fft_32_shift, 32UL );
  /* test_inv only supports up to 32 at the moment */
  /* test_inv( wrapped_fft_64_shift, wrapped_ifft_64_shift, 64UL ); test_inv( wrapped_ifft_64_shift, wrapped_fft_64_shift, 64UL );
     test_inv( wrapped_fft_64,       wrapped_ifft_64,       64UL ); test_inv( wrapped_ifft_64,       wrapped_fft_64,       64UL ); */
}

static void
test_encode_vs_ref( fd_rng_t * rng ) {
  /* Setup */
  uchar * d[ FD_REEDSOL_DATA_SHREDS_MAX   ];
  uchar * p[ FD_REEDSOL_PARITY_SHREDS_MAX ];
  uchar * r[ FD_REEDSOL_PARITY_SHREDS_MAX ];

  ulong const stride = 71UL; /* Prime >= 64 */
  for( ulong i=0UL; i<FD_REEDSOL_DATA_SHREDS_MAX; i++ )    d[ i ] = data_shreds   + stride*i;
  for( ulong i=0UL; i<FD_REEDSOL_PARITY_SHREDS_MAX; i++ )  p[ i ] = parity_shreds + stride*i;
  for( ulong i=0UL; i<FD_REEDSOL_PARITY_SHREDS_MAX; i++ )  r[ i ] = parity_shreds + stride*(i+FD_REEDSOL_PARITY_SHREDS_MAX);

  for( ulong d_cnt=1UL; d_cnt<=FD_REEDSOL_DATA_SHREDS_MAX; d_cnt++ ) {
    for( ulong p_cnt=1UL; p_cnt<=FD_REEDSOL_PARITY_SHREDS_MAX; p_cnt++ ) {
      for( ulong shred_sz=32UL; shred_sz<=64UL; shred_sz++ ) {

        fd_memset( data_shreds,      0,     FD_REEDSOL_DATA_SHREDS_MAX   * stride );
        fd_memset( parity_shreds, 0xCC, 2UL*FD_REEDSOL_PARITY_SHREDS_MAX * stride );

        /* populate data shreds with an identity followed by random data */
        for( ulong i=0UL; i<d_cnt; i++ )
          for( ulong k=0UL; k<shred_sz; k++ ) d[ i ][ k ] = (k<d_cnt) ? (uchar)(k==i) : fd_rng_uchar( rng );

        fd_reedsol_t * rs = fd_reedsol_encode_init( mem, shred_sz );
        for( ulong i=0UL; i<d_cnt; i++ ) fd_reedsol_encode_add_data_shred(   rs, d[ i ] );
        for( ulong j=0UL; j<p_cnt; j++ ) fd_reedsol_encode_add_parity_shred( rs, p[ j ] );

        fd_reedsol_encode_fini( rs );

        fd_reedsol_encode_ref( shred_sz, (uchar const * const *)d, d_cnt, r, p_cnt );
        for( ulong j=0UL; j<p_cnt; j++ ) for( ulong k=0UL; k<shred_sz; k++ ) FD_TEST( p[ j ][ k ] == r[ j ][ k ] );
      }
    }
  }
}

static void
battery_performance_base( fd_rng_t *    rng ) {
  ulong const test_count = 90000UL;

  uchar * d[ FD_REEDSOL_DATA_SHREDS_MAX   ];
  uchar * p[ FD_REEDSOL_PARITY_SHREDS_MAX ];
  for( ulong i=0UL; i<32UL; i++ ) { d[ i ] = data_shreds + SHRED_SZ*i; p[ i ] = parity_shreds + SHRED_SZ*i; }

  for( ulong j=0UL; j<SHRED_SZ*32UL; j++ ) FD_VOLATILE( data_shreds[ j ] ) = fd_rng_uchar( rng );

  /* Warm up instruction cache */
  fd_reedsol_t * rs = fd_reedsol_encode_init( mem, SHRED_SZ );
  for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_encode_add_parity_shred( fd_reedsol_encode_add_data_shred( rs, d[ i ] ), p[ i ] );
  fd_reedsol_encode_fini( rs );

  rs = fd_reedsol_encode_init( mem, SHRED_SZ );
  for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_encode_add_parity_shred( fd_reedsol_encode_add_data_shred( rs, d[ i ] ), p[ i ] );
  fd_reedsol_encode_fini( rs );

  /* Measure encode */
  long encode = -fd_log_wallclock();

  for( ulong i=0UL; i<test_count; i++ ) {
    rs = fd_reedsol_encode_init( mem, SHRED_SZ );
    for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_encode_add_parity_shred( fd_reedsol_encode_add_data_shred( rs, d[ i ] ), p[ i ] );
    fd_reedsol_encode_fini( rs );
  }

  encode += fd_log_wallclock();

  FD_LOG_NOTICE(( "average time per encode call %f ns ( %f GiB/s, %f Gbps )",
                  (double)(encode        )/(double)test_count,
                  (double)(test_count * 32UL * SHRED_SZ) / ((double)(encode)*1.0737),
                  (double)(test_count * 32UL * SHRED_SZ * 8UL) / ((double)(encode))
        ));
}

char output[ FD_REEDSOL_DATA_SHREDS_MAX * FD_REEDSOL_PARITY_SHREDS_MAX * 8UL ];
long loop_times[ FD_REEDSOL_DATA_SHREDS_MAX+1UL ][ FD_REEDSOL_PARITY_SHREDS_MAX+1UL ];

static void
battery_performance_generic( fd_rng_t *    rng,
                             ulong         max_data_shreds,
                             ulong         max_parity_shreds,
                             ulong         test_count ) {

  uchar * d[ FD_REEDSOL_DATA_SHREDS_MAX   ];
  uchar * p[ FD_REEDSOL_PARITY_SHREDS_MAX ];
  for( ulong i=0UL; i<max_data_shreds; i++ )    d[ i ] = data_shreds + SHRED_SZ*i;
  for( ulong i=0UL; i<max_parity_shreds; i++ )  p[ i ] = parity_shreds + SHRED_SZ*i;

  for( ulong j=0UL; j<SHRED_SZ*max_data_shreds; j++ )
    FD_VOLATILE( data_shreds[ j ] ) = fd_rng_uchar( rng );

  for( ulong d_cnt=1UL; d_cnt<=max_data_shreds; d_cnt++ ) {
    for( ulong p_cnt=1UL; p_cnt<=max_parity_shreds; p_cnt++ ) {
      /* Warm up instruction cache */
      fd_reedsol_t * rs = fd_reedsol_encode_init( mem, SHRED_SZ );
      for( ulong i=0UL; i<d_cnt; i++ ) fd_reedsol_encode_add_data_shred(   rs, d[ i ] );
      for( ulong i=0UL; i<p_cnt; i++ ) fd_reedsol_encode_add_parity_shred( rs, p[ i ] );
      fd_reedsol_encode_fini( rs );

      rs = fd_reedsol_encode_init( mem, SHRED_SZ );
      for( ulong i=0UL; i<d_cnt; i++ ) fd_reedsol_encode_add_data_shred(   rs, d[ i ] );
      for( ulong i=0UL; i<p_cnt; i++ ) fd_reedsol_encode_add_parity_shred( rs, p[ i ] );
      fd_reedsol_encode_fini( rs );

      /* Measure encode */
      long encode = -fd_log_wallclock();

      for( ulong i=0UL; i<test_count; i++ ) {
        rs = fd_reedsol_encode_init( mem, SHRED_SZ );
        for( ulong i=0UL; i<d_cnt; i++ ) fd_reedsol_encode_add_data_shred(   rs, d[ i ] );
        for( ulong i=0UL; i<p_cnt; i++ ) fd_reedsol_encode_add_parity_shred( rs, p[ i ] );
        fd_reedsol_encode_fini( rs );
      }

      encode += fd_log_wallclock();

      loop_times[ d_cnt ][ p_cnt ] = encode;
    }
  }

  char * str = fd_cstr_init( output );
  str = fd_cstr_append_cstr( str, "Performance in Gbps of parity data produced\nD\\P " );
  for( ulong p_cnt=1UL; p_cnt<=max_parity_shreds; p_cnt++ ) str = fd_cstr_append_printf( str, "%5lu ", p_cnt );
  str = fd_cstr_append_char( str, '\n' );

  for( ulong d_cnt=1UL; d_cnt<=max_data_shreds; d_cnt++ ) {
    str = fd_cstr_append_printf( str, "%3lu ", d_cnt );
    for( ulong p_cnt=1UL; p_cnt<=max_parity_shreds; p_cnt++ ) {
      str = fd_cstr_append_printf( str, "%5.1f ", (double)(test_count*p_cnt*SHRED_SZ*8UL) / (double)loop_times[ d_cnt ][ p_cnt ]);
    }
    str = fd_cstr_append_char( str, '\n' );
  }
  fd_cstr_fini( str );

  printf( "%s", output );
}

static inline uchar
pi_ref( uchar x, uchar * erasures, ulong erasures_cnt ) {
  uchar prod = 1;
  for( ulong i=0UL; i<erasures_cnt; i++ ) prod = gfmul( prod, x ^ erasures[ i ] );
  return prod;
}

static uchar
pi_prime_inv_ref( uchar x, uchar * erasures, ulong erasures_cnt ) {
  uchar prod = 1;
  for( ulong i=0UL; i<erasures_cnt; i++ ) if( erasures[i] != x ) prod = gfmul( prod, x ^ erasures[ i ] );
  return gfinv( prod );
}

typedef void gen_pi_fn_t( uchar const *, uchar * );

static void
test_pi( gen_pi_fn_t fn,
         ulong       N,
         fd_rng_t *  rng ) {
  FD_LOG_NOTICE(( "Testing Pi %lu", N ));
#define MAX_N 256UL
  FD_TEST( N<=MAX_N ); /* Update the test if this fails */
  uchar in[  MAX_N ] W_ATTR;
  uchar out[ MAX_N ] W_ATTR;

  uchar erasures[ MAX_N ];
  /* erasures = [ i ] */
  for( ulong i=0; i<N; i++ ) {
    fd_memset( in, 0, N );
    erasures[ 0 ] = (uchar)i;
    in[ i ] = (uchar)1;

    fn( in, out );

    for( ulong j=0UL; j<N; j++ ) {
      if( j==i ) FD_TEST( out[ j ] == pi_prime_inv_ref( (uchar)j, erasures, 1UL ) );
      else       FD_TEST( out[ j ] == pi_ref(           (uchar)j, erasures, 1UL ) );
    }
  }

  /* erausres = [ i, j ] */
  for( ulong i=0UL; i<N; i++ ) for( ulong j=i+1UL; j<N; j++ ) {
    fd_memset( in, 0, N );
    in [ i ] = in[ j ] = (uchar)1;
    erasures[ 0 ] = (uchar)i;
    erasures[ 1 ] = (uchar)j;

    fn( in, out );

    for( ulong k=0UL; k<N; k++ ) {
      if( k==i || k==j ) FD_TEST( out[ k ] == pi_prime_inv_ref( (uchar)k, erasures, 2UL ) );
      else               FD_TEST( out[ k ] == pi_ref(           (uchar)k, erasures, 2UL ) );
    }
  }

  for( ulong rep=0UL; rep<1000UL; rep++ ) {
    fd_memset( in, 0, N );
    ulong erasure_cnt = 0UL;
    for( ulong i=0UL; i<N; i++ ) {
      /* Vary probability with rep */
      if( (fd_rng_uint( rng ) & 0xFF) < (rep & 0xFF ) ) {
        erasures[ erasure_cnt++ ] = (uchar)i;
        in[ i ] = (uchar)1;
      }
    }

    fn( in, out );

    ulong j=0UL;
    for( ulong i=0UL; i<N; i++ ) {
      if( j<erasure_cnt && i==erasures[ j ] ) { FD_TEST( out[ i ] == pi_prime_inv_ref( (uchar)i, erasures, erasure_cnt ) ); j++; }
      else                                      FD_TEST( out[ i ] == pi_ref(           (uchar)i, erasures, erasure_cnt ) );
    }
  }
#undef MAX_N

}
static void
test_pi_all( fd_rng_t * rng ) {
  test_pi( fd_reedsol_private_gen_pi_16,   16UL, rng );
  test_pi( fd_reedsol_private_gen_pi_32,   32UL, rng );
  test_pi( fd_reedsol_private_gen_pi_64,   64UL, rng );
  test_pi( fd_reedsol_private_gen_pi_128, 128UL, rng );
  test_pi( fd_reedsol_private_gen_pi_256, 256UL, rng );
}

static void
test_recover( fd_rng_t * rng ) {
  uchar * d[ FD_REEDSOL_DATA_SHREDS_MAX   ];
  uchar * p[ FD_REEDSOL_PARITY_SHREDS_MAX ];
  uchar * r[ FD_REEDSOL_PARITY_SHREDS_MAX+1UL ];
  for( ulong i=0UL; i<FD_REEDSOL_DATA_SHREDS_MAX;   i++ )  d[ i ] = data_shreds + SHRED_SZ*i;
  for( ulong i=0UL; i<FD_REEDSOL_PARITY_SHREDS_MAX; i++ )  p[ i ] = parity_shreds + SHRED_SZ*i;
  for( ulong i=0UL; i<FD_REEDSOL_PARITY_SHREDS_MAX; i++ )  r[ i ] = recovered_shreds + SHRED_SZ*i;

  /* Fill with random data */
  for( ulong i=0UL; i<FD_REEDSOL_DATA_SHREDS_MAX; i++ ) for( ulong j=0UL; j<SHRED_SZ; j++ ) d[ i ][ j ] = fd_rng_uchar( rng );

  for( ulong d_cnt=1UL; d_cnt<=FD_REEDSOL_DATA_SHREDS_MAX; d_cnt++ ) {
    for( ulong p_cnt=1UL; p_cnt<=FD_REEDSOL_PARITY_SHREDS_MAX; p_cnt++ ) {

      fd_reedsol_t * rs = fd_reedsol_encode_init( mem, SHRED_SZ );
      for( ulong i=0UL; i<d_cnt; i++ ) fd_reedsol_encode_add_data_shred(   rs, d[ i ] );
      for( ulong i=0UL; i<p_cnt; i++ ) fd_reedsol_encode_add_parity_shred( rs, p[ i ] );
      fd_reedsol_encode_fini( rs );

      for( ulong e_cnt=0UL; e_cnt<=p_cnt+1UL; e_cnt++ ) {
        /* Use reservoir sampling to select exactly e_cnt of the shreds
           to erased */
        uchar * erased_truth[ FD_REEDSOL_PARITY_SHREDS_MAX+1UL ];
        ulong erased_cnt = 0UL;
        rs = fd_reedsol_recover_init( mem, SHRED_SZ );
        for( ulong i=0UL; i<d_cnt; i++ ) {
          /* Erase with probability:
             (e_cnt - erased_cnt)/(d_cnt + p_cnt - i) */
          if( fd_rng_ulong_roll( rng, d_cnt+p_cnt-i ) < (e_cnt-erased_cnt) ) {
            erased_truth[ erased_cnt ] = d[ i ];
            fd_reedsol_recover_add_erased_shred(    rs, 1, r[ erased_cnt++ ] );
          } else fd_reedsol_recover_add_rcvd_shred( rs, 1, d[ i ] );
        }
        for( ulong i=0UL; i<p_cnt; i++ ) {
          if( fd_rng_ulong_roll( rng, p_cnt-i ) < (e_cnt-erased_cnt) ) {
            erased_truth[ erased_cnt ] = p[ i ];
            fd_reedsol_recover_add_erased_shred(    rs, 0, r[ erased_cnt++ ] );
          } else fd_reedsol_recover_add_rcvd_shred( rs, 0, p[ i ] );
        }

        FD_TEST( erased_cnt==e_cnt ); /* If this fails, the test is wrong. */
        int retval = fd_reedsol_recover_fini( rs );

        if( FD_UNLIKELY( e_cnt>p_cnt ) ) { FD_TEST( retval==FD_REEDSOL_ERR_PARTIAL ); continue; }

        FD_TEST( FD_REEDSOL_SUCCESS==retval );

        for( ulong i=0UL; i<e_cnt; i++ ) FD_TEST( 0==memcmp( erased_truth[ i ], r[ i ], SHRED_SZ ) );
      }

      /* Corrupt one shred and make sure it gets caught */
      for( ulong corrupt_idx=0UL; corrupt_idx<d_cnt+p_cnt; corrupt_idx++ ) {
        ulong byte_idx = fd_rng_ulong_roll( rng, SHRED_SZ );
        if( corrupt_idx<d_cnt )  d[ corrupt_idx       ][ byte_idx ] ^= (uchar)1;
        else                     p[ corrupt_idx-d_cnt ][ byte_idx ] ^= (uchar)1;

        rs = fd_reedsol_recover_init( mem, SHRED_SZ );
        for( ulong i=0UL; i<d_cnt; i++ ) fd_reedsol_recover_add_rcvd_shred( rs, 1, d[ i ] );
        for( ulong i=0UL; i<p_cnt; i++ ) fd_reedsol_recover_add_rcvd_shred( rs, 0, p[ i ] );

        FD_TEST( FD_REEDSOL_ERR_CORRUPT==fd_reedsol_recover_fini( rs ) );

        if( corrupt_idx<d_cnt )  d[ corrupt_idx       ][ byte_idx ] ^= (uchar)1;
        else                     p[ corrupt_idx-d_cnt ][ byte_idx ] ^= (uchar)1;
      }
    }
  }
}

static void
test_recover_performance( fd_rng_t *    rng ) {
  ulong const test_count = 90000UL;

  uchar * d[ FD_REEDSOL_DATA_SHREDS_MAX   ];
  uchar * p[ FD_REEDSOL_PARITY_SHREDS_MAX ];
  uchar * r[ FD_REEDSOL_PARITY_SHREDS_MAX ];
  for( ulong i=0UL; i<32UL; i++ ) {
    d[ i ] = data_shreds + SHRED_SZ*i;
    p[ i ] = parity_shreds + SHRED_SZ*i;
    r[ i ] = recovered_shreds + SHRED_SZ*i;
  }

  for( ulong j=0UL; j<SHRED_SZ*32UL; j++ ) data_shreds[ j ] = fd_rng_uchar( rng );

  /* Produce parity data */
  fd_reedsol_t * rs = fd_reedsol_encode_init( mem, SHRED_SZ );
  for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_encode_add_parity_shred( fd_reedsol_encode_add_data_shred( rs, d[ i ] ), p[ i ] );
  fd_reedsol_encode_fini( rs );

  /* Warm up instruction cache */
  rs = fd_reedsol_recover_init( mem, SHRED_SZ );
  for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_recover_add_rcvd_shred( rs, 1, d[ i ] );
  for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_recover_add_rcvd_shred( rs, 0, p[ i ] );
  FD_TEST( FD_REEDSOL_SUCCESS==fd_reedsol_recover_fini( rs ) );

  rs = fd_reedsol_recover_init( mem, SHRED_SZ );
  for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_recover_add_rcvd_shred( rs, 1, d[ i ] );
  for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_recover_add_rcvd_shred( rs, 0, p[ i ] );
  fd_reedsol_recover_fini( rs );

  /* Measure recover */
  long recover = -fd_log_wallclock();

  for( ulong i=0UL; i<test_count; i++ ) {
    rs = fd_reedsol_recover_init( mem, SHRED_SZ );
    for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_recover_add_rcvd_shred( rs, 1, d[ i ] );
    for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_recover_add_rcvd_shred( rs, 0, p[ i ] );
    fd_reedsol_recover_fini( rs );
  }

  recover += fd_log_wallclock();

  FD_LOG_NOTICE(( "average time per recover (no erasures) call %f ns ( %f GiB/s, %f Gbps )",
                  (double)(recover        )/(double)test_count,
                  (double)(test_count * 64UL * SHRED_SZ) / ((double)(recover)*1.0737),
                  (double)(test_count * 64UL * SHRED_SZ * 8UL) / ((double)(recover))
        ));

  /* Test when just parity has been erased */

  /* Warm up instruction cache */
  rs = fd_reedsol_recover_init( mem, SHRED_SZ );
  for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_recover_add_rcvd_shred( rs, 1, d[ i ] );
  for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_recover_add_erased_shred( rs, 0, r[ i ] );
  FD_TEST( FD_REEDSOL_SUCCESS==fd_reedsol_recover_fini( rs ) );

  rs = fd_reedsol_recover_init( mem, SHRED_SZ );
  for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_recover_add_rcvd_shred( rs, 1, d[ i ] );
  for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_recover_add_erased_shred( rs, 0, r[ i ] );
  fd_reedsol_recover_fini( rs );

  /* Measure recover */
  recover = -fd_log_wallclock();

  for( ulong i=0UL; i<test_count; i++ ) {
    rs = fd_reedsol_recover_init( mem, SHRED_SZ );
    for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_recover_add_rcvd_shred( rs, 1, d[ i ] );
    for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_recover_add_erased_shred( rs, 0, r[ i ] );
    fd_reedsol_recover_fini( rs );
  }

  recover += fd_log_wallclock();

  FD_LOG_NOTICE(( "average time per recover (parity erased) call %f ns ( %f GiB/s, %f Gbps )",
                  (double)(recover        )/(double)test_count,
                  (double)(test_count * 64UL * SHRED_SZ) / ((double)(recover)*1.0737),
                  (double)(test_count * 64UL * SHRED_SZ * 8UL) / ((double)(recover))
        ));

  /* Test when just data has been erased */

  /* Warm up instruction cache */
  rs = fd_reedsol_recover_init( mem, SHRED_SZ );
  for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_recover_add_erased_shred( rs, 1, r[ i ] );
  for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_recover_add_rcvd_shred( rs, 0, p[ i ] );
  FD_TEST( FD_REEDSOL_SUCCESS==fd_reedsol_recover_fini( rs ) );

  rs = fd_reedsol_recover_init( mem, SHRED_SZ );
  for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_recover_add_erased_shred( rs, 1, r[ i ] );
  for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_recover_add_rcvd_shred( rs, 0, p[ i ] );
  fd_reedsol_recover_fini( rs );

  /* Measure recover */
  recover = -fd_log_wallclock();

  for( ulong i=0UL; i<test_count; i++ ) {
    rs = fd_reedsol_recover_init( mem, SHRED_SZ );
    for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_recover_add_erased_shred( rs, 1, r[ i ] );
    for( ulong i=0UL; i<32UL; i++ ) fd_reedsol_recover_add_rcvd_shred( rs, 0, p[ i ] );
    fd_reedsol_recover_fini( rs );
  }

  recover += fd_log_wallclock();

  FD_LOG_NOTICE(( "average time per recover (data erased) call %f ns ( %f GiB/s, %f Gbps )",
                  (double)(recover        )/(double)test_count,
                  (double)(test_count * 64UL * SHRED_SZ) / ((double)(recover)*1.0737),
                  (double)(test_count * 64UL * SHRED_SZ * 8UL) / ((double)(recover))
        ));

  /* Test when even shreds have been erased */
  /* Warm up instruction cache */
  rs = fd_reedsol_recover_init( mem, SHRED_SZ );
  for( ulong i=0UL; i<32UL; i+=2UL ) { fd_reedsol_recover_add_erased_shred( rs, 1, r[ i/2UL ] );      fd_reedsol_recover_add_rcvd_shred( rs, 1, d[ i+1UL ] ); }
  for( ulong i=0UL; i<32UL; i+=2UL ) { fd_reedsol_recover_add_erased_shred( rs, 0, r[ 16UL+i/2UL ] ); fd_reedsol_recover_add_rcvd_shred( rs, 0, p[ i+1UL ] ); }
  FD_TEST( FD_REEDSOL_SUCCESS==fd_reedsol_recover_fini( rs ) );

  rs = fd_reedsol_recover_init( mem, SHRED_SZ );
  for( ulong i=0UL; i<32UL; i+=2UL ) { fd_reedsol_recover_add_erased_shred( rs, 1, r[ i/2UL ] );      fd_reedsol_recover_add_rcvd_shred( rs, 1, d[ i+1UL ] ); }
  for( ulong i=0UL; i<32UL; i+=2UL ) { fd_reedsol_recover_add_erased_shred( rs, 0, r[ 16UL+i/2UL ] ); fd_reedsol_recover_add_rcvd_shred( rs, 0, p[ i+1UL ] ); }
  fd_reedsol_recover_fini( rs );

  /* Measure recover */
  recover = -fd_log_wallclock();

  for( ulong i=0UL; i<test_count; i++ ) {
    rs = fd_reedsol_recover_init( mem, SHRED_SZ );
    for( ulong i=0UL; i<32UL; i+=2UL ) { fd_reedsol_recover_add_erased_shred( rs, 1, r[ i/2UL ] );      fd_reedsol_recover_add_rcvd_shred( rs, 1, d[ i+1UL ] ); }
    for( ulong i=0UL; i<32UL; i+=2UL ) { fd_reedsol_recover_add_erased_shred( rs, 0, r[ 16UL+i/2UL ] ); fd_reedsol_recover_add_rcvd_shred( rs, 0, p[ i+1UL ] ); }
    fd_reedsol_recover_fini( rs );
  }

  recover += fd_log_wallclock();

  FD_LOG_NOTICE(( "average time per recover (even erased) call %f ns ( %f GiB/s, %f Gbps )",
                  (double)(recover        )/(double)test_count,
                  (double)(test_count * 64UL * SHRED_SZ) / ((double)(recover)*1.0737),
                  (double)(test_count * 64UL * SHRED_SZ * 8UL) / ((double)(recover))
        ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

// ulong cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--cnt", NULL, 100000UL );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  basic_tests();
  battery_performance_base( rng );
  battery_performance_generic( rng, 32UL, 32UL, 5000UL );
  test_encode_vs_ref( rng );
  test_recover( rng );
  test_recover_performance( rng );
  test_pi_all( rng );
  test_linearity_all( rng );
  test_fft_all();

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
