#include "fd_base58.h"

extern uchar const base58_inverse[];

static char const base58_chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/* fd_base58_encode_ref interprets byte_cnt bytes from bytes as a large
   big-endian integer, and converts it to a nul-terminated base58
   string, storing the output in out.

   Requires byte_cnt <= 64 and out_cnt <= 128.

   This writes at most out_cnt characters to out, including the nul
   terminator.  Returns NULL if the supplied output buffer is not big
   enough, and returns out otherwise.  The length of a base58 string is
   data-dependent, but passing 1+1.5*byte_cnt is sufficient (the actual
   coefficient is log_58(256)).

   This method is slow and the optimized fixed-size conversion methods
   should be used where possible.

   fd_base58_decode_ref converts the base58-encoded number stored in the
   `encoded_len` length cstr `encoded` to a large integer which is
   written big-endian to out.

   Requires encoded_len <= 88 and out_cnt <= 64.

   This writes exactly out_cnt bytes to out.  Returns out on success.
   Returns NULL if encoded was not a valid base58 integer or if it
   decoded to a byte string with length not exactly out_cnt.

   This method is slow and the optimized fixed-size conversion methods
   should be used where possible. */

static char *
fd_base58_encode_ref( uchar const * bytes,
                      ulong         byte_cnt,
                      char *        out,
                      ulong         out_cnt ) {

  if( FD_UNLIKELY( (byte_cnt>64UL) | (out_cnt>128UL) ) ) return NULL;
  if( FD_UNLIKELY( out_cnt<byte_cnt+1UL              ) ) return NULL;

  /* Copy bytes to something we can clobber */
  ulong quotient[ 64UL ];
  for( ulong j=0UL; j<byte_cnt; j++ ) quotient[j] = bytes[j];
  out_cnt--; /* Save room for nul */
  ulong raw_base58[ 128UL ];

  ulong zero_cnt = 0UL;
  while( zero_cnt<byte_cnt && !bytes[ zero_cnt ] ) zero_cnt++;

  ulong last_nonzero = 0UL;
  /* Grade-school long division */
  ulong start_j = 0UL;
  for( ulong i=0UL; i<out_cnt; i++ ) {
    ulong remainder = 0UL;
    if( start_j<byte_cnt && !quotient[ start_j ] ) start_j++;
    for( ulong j=start_j; j<byte_cnt; j++ ) {
      remainder = remainder*256UL + quotient[j];
      quotient[j] = remainder / 58UL;
      remainder %= 58UL;
    }
    raw_base58[ i ] = remainder;
    if( remainder ) last_nonzero = 1UL+i;
  }

  if( FD_UNLIKELY( last_nonzero + zero_cnt > out_cnt ) ) return NULL;
  for( ulong j=0UL; j<byte_cnt; j++ ) if( FD_UNLIKELY( quotient[ j ] ) ) return NULL; /* Output too small */

  /* Convert to base58 characters */
  ulong out_i = 0UL;
  ulong raw_j = 0UL;
  for( ; out_i<zero_cnt;     out_i++ ) out[ out_i   ] = '1';
  for( ; raw_j<last_nonzero; raw_j++ ) out[ out_i++ ] = base58_chars[ raw_base58[ last_nonzero-1UL-raw_j ] ];
  out[ out_i ] = '\0';

  return out;
}

static uchar *
fd_base58_decode_ref( char const * encoded,
                      ulong        encoded_len, /* excluding nul-terminator */
                      uchar *      out,
                      ulong        out_cnt ) {

  ulong zero_cnt = 0UL;
  for( ; zero_cnt<fd_ulong_min( encoded_len, out_cnt ); zero_cnt++ )
    if( encoded[ zero_cnt ] == '1' ) out[ zero_cnt ] = (uchar)0;
    else break;

  out += zero_cnt;
  encoded += zero_cnt;
  encoded_len -= zero_cnt;
  out_cnt -= zero_cnt;

  if( FD_UNLIKELY( (out_cnt==0) & (encoded_len>0) ) ) return NULL; /* N '1's followed by trailing characters */

  if( FD_UNLIKELY( encoded_len>128UL ) ) return NULL;
  ulong raw_base58[ 128UL ];

  for( ulong i=0UL; i<encoded_len; i++ ) {
    char c = encoded[ i ];
    if( FD_UNLIKELY( (c<'1') | (c>'z') ) ) return NULL;
    uchar raw = base58_inverse[ (ulong)(c-'1') ];
    if( FD_UNLIKELY( (ulong)raw==255UL ) ) return NULL;
    raw_base58[ i ] = raw;
  }

  /* Grade-school long division */
  ulong start_j = 0UL;
  for( ulong i=0UL; i<out_cnt; i++ ) {
    ulong remainder = 0UL;
    while( FD_LIKELY( start_j<encoded_len ) && !raw_base58[ start_j ] ) start_j++;
    for( ulong j=start_j; j<encoded_len; j++ ) {
      remainder = remainder*58UL + raw_base58[j];
      raw_base58[ j ] = remainder >> 8;
      remainder &= 0xFF;
    }
    out[ out_cnt-1UL-i ] = (uchar)remainder;
  }
  if( FD_UNLIKELY( out_cnt && !out[ 0UL ] ) ) return NULL; /* Wrong number of leading 1s */

  for( ulong j=start_j; j<encoded_len; j++ ) if( FD_UNLIKELY( raw_base58[ j ] ) ) return NULL; /* Output too small */

  return out-zero_cnt;
}

/* Drop-in replacements for the non-suffixed versions, but using the ref
   algorithm. */

static char *
fd_base58_encode_32_ref( uchar const * bytes,
                         ulong *       opt_len,
                         char *        out ) {
  fd_base58_encode_ref( bytes, 32UL, out, FD_BASE58_ENCODED_32_SZ );
  fd_ulong_store_if( !!opt_len, opt_len, strlen( out ) );
  return out;
}

static char *
fd_base58_encode_64_ref( uchar const * bytes,
                         ulong *       opt_len,
                         char *        out ) {
  fd_base58_encode_ref( bytes, 64UL, out, FD_BASE58_ENCODED_64_SZ );
  fd_ulong_store_if( !!opt_len, opt_len, strlen( out ) );
  return out;
}

static uchar *
fd_base58_decode_32_ref( char const * encoded,
                         uchar *      out ) {
  return fd_base58_decode_ref( encoded, strlen( encoded ), out, 32UL );
}

static uchar *
fd_base58_decode_64_ref( char const * encoded,
                         uchar *      out ) {
  return fd_base58_decode_ref( encoded, strlen( encoded ), out, 64UL );
}

typedef char  *(*encode_func_t)( uchar const *, ulong *, char * );
typedef uchar *(*decode_func_t)( char  const *, uchar * );

static void
battery_encode_basic32( encode_func_t encode_func ) {
  char  buf  [ FD_BASE58_ENCODED_32_SZ ];
  uchar bytes[ 32UL ];
  ulong len  [ 1UL ];

  fd_memset( bytes, '\0', 32UL );
  FD_TEST( !strcmp( "11111111111111111111111111111111", encode_func( bytes, len, buf ) ) );
  FD_TEST( *len==32UL );

  bytes[ 31UL ]++;
  FD_TEST( !strcmp( "11111111111111111111111111111112", encode_func( bytes, len, buf ) ) );
  FD_TEST( *len==32UL );

  bytes[ 30UL ]++;
  /* 257 in base58 is 5S */
  FD_TEST( !strcmp( "1111111111111111111111111111115S", encode_func( bytes, len, buf ) ) );
  FD_TEST( *len==32UL );

  fd_memset( bytes, '\xFF', 32UL );
  FD_TEST( !strcmp( "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG", encode_func( bytes, len, buf ) ) );
  FD_TEST( *len==44UL );

  bytes[ 31UL ]--;
  FD_TEST( !strcmp( "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFF", encode_func( bytes, len, buf ) ) );
  FD_TEST( *len==44UL );
}

static void
battery_encode_basic64( encode_func_t encode_func ) {
  char  buf  [ FD_BASE58_ENCODED_64_SZ ];
  uchar bytes[ 64UL ];
  ulong len  [ 1UL ];

  fd_memset( bytes, '\0', 64UL );
  FD_TEST( !strcmp( "1111111111111111111111111111111111111111111111111111111111111111",
                    encode_func( bytes, len, buf ) ) );
  FD_TEST( *len==64UL );

  bytes[ 63UL ]++;
  FD_TEST( !strcmp( "1111111111111111111111111111111111111111111111111111111111111112",
                    encode_func( bytes, len, buf ) ) );
  FD_TEST( *len==64UL );

  bytes[ 62UL ]++;
  /* 257 in base58 is 5S */
  FD_TEST( !strcmp( "111111111111111111111111111111111111111111111111111111111111115S",
                    encode_func( bytes, len, buf ) ) );
  FD_TEST( *len==64UL );

  fd_memset( bytes, '\xFF', 64UL );
  FD_TEST( !strcmp( "67rpwLCuS5DGA8KGZXKsVQ7dnPb9goRLoKfgGbLfQg9WoLUgNY77E2jT11fem3coV9nAkguBACzrU1iyZM4B8roQ",
                    encode_func( bytes, len, buf ) ) );
  FD_TEST( *len==88UL );

  bytes[ 63UL ]--;
  FD_TEST( !strcmp( "67rpwLCuS5DGA8KGZXKsVQ7dnPb9goRLoKfgGbLfQg9WoLUgNY77E2jT11fem3coV9nAkguBACzrU1iyZM4B8roP",
                    encode_func( bytes, len, buf ) ) );
  FD_TEST( *len==88UL );
}

static void
battery_encode_bounds( encode_func_t encode_func,
                       ulong         n,
                       ulong         encode_sz,
                       char *        buf,          /* indexed [0,encode_sz) */
                       uchar *       bytes ) {     /* indexed [0,n) */
  fd_memset( bytes, 0, n );
  for( ulong i=0UL; i<n; i++ ) {
    bytes[ n-1UL-i ] = (uchar)1;
    fd_memset( buf, '\xCC', encode_sz );
    ulong len[ 1 ];
    FD_TEST( encode_func( bytes, len, buf )==buf );
    FD_TEST( (n<=len[0]) & (len[0]<encode_sz) );
    FD_TEST( strlen( buf )==len[0] );
    for( ulong j=len[0]+1UL; j<encode_sz; j++ ) FD_TEST( buf[ j ]=='\xCC' );
  }
}

static void
battery_decode_fail32( decode_func_t decode_func ) {
# define N_TESTS (15UL)
  char const * encoded[ N_TESTS ] = {
    "1",
    "1111111111111111111111111111111",
    "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJz",         /* clearly too short */
    "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofL",     /* largest 31 byte value */
    "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofLRda4", /* clearly too long */
    "111111111111111111111111111111111",               /* Smallest 33 byte value */
    "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFJ",    /* 2nd-smallest 33 byte value that doesn't start with 0x0 */
    "11aEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWx",    /* Starts with too many '1's */
    "11111111111111111111111111111110",                /* Invalid characters */
    "1111111111111111111111111111111!",
    "1111111111111111111111111111111;",
    "1111111111111111111111111111111I",
    "1111111111111111111111111111111O",
    "1111111111111111111111111111111_",
    "1111111111111111111111111111111l",
  };

  uchar buf[ 32UL ];
  for( ulong i=0UL; i<N_TESTS; i++ ) FD_TEST( !decode_func( encoded[ i ], buf ) );
# undef N_TESTS
}

static void
battery_decode_fail64( decode_func_t decode_func ) {
# define N_TESTS (15UL)
  char const * encoded[ N_TESTS ] = {
    "1",
    "111111111111111111111111111111111111111111111111111111111111111",
    "2AFv15MNPuA84RmU66xw2uMzGipcVxNpzAffoacGVvjFue3CBmf633fAWuiP9cwL9C3z3CJiGgRSFjJfeEcA",        /* clearly too short */
    "2AFv15MNPuA84RmU66xw2uMzGipcVxNpzAffoacGVvjFue3CBmf633fAWuiP9cwL9C3z3CJiGgRSFjJfeEcA6QW",     /* largest 63 byte value */
    "2AFv15MNPuA84RmU66xw2uMzGipcVxNpzAffoacGVvjFue3CBmf633fAWuiP9cwL9C3z3CJiGgRSFjJfeEcA6QWabc",  /* clearly too long */
    "11111111111111111111111111111111111111111111111111111111111111111",                           /* Smallest 65 byte value */
    "67rpwLCuS5DGA8KGZXKsVQ7dnPb9goRLoKfgGbLfQg9WoLUgNY77E2jT11fem3coV9nAkguBACzrU1iyZM4B8roS",    /* 2nd-smallest 65 byte value
                                                                                                      that doesn't start with 0x0 */
    "1114tjGcyzrfXw2deDmDAFFaFyss32WRgkYdDJuprrNEL8kc799TrHSQHfE9fv6ZDBUg2dsMJdfYr71hjE4EfjEN",    /* Start with too many '1's */
    "1111111111111111111111111111111111111111111111111111111111111110",                            /* Invalid characters */
    "111111111111111111111111111111111111111111111111111111111111111!",
    "111111111111111111111111111111111111111111111111111111111111111;",
    "111111111111111111111111111111111111111111111111111111111111111I",
    "111111111111111111111111111111111111111111111111111111111111111O",
    "111111111111111111111111111111111111111111111111111111111111111_",
    "111111111111111111111111111111111111111111111111111111111111111l",
  };

  uchar buf[ 64UL ];
  for( ulong i=0UL; i<N_TESTS; i++ ) FD_TEST( !decode_func( encoded[ i ], buf ) );
# undef N_TESTS
}

static void
battery_sample32( encode_func_t encode_func,
                     decode_func_t decode_func ) {

# define N_TESTS (7UL)
  static char const * encoded[ N_TESTS ] = {
    "XkCriyrNwS3G4rzAXtG5B1nnvb5Ka1JtCku93VqeKAr",
    "Awes4Tr6TX8JDzEhCZY2QVNimT6iD1zWHzf1vNyGvpLM",
    "DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy",
    "EgxVyTgh2Msg781wt9EsqYx4fW8wSvfFAHGLaJQjghiL",
    "EvnRmnMrd69kFdbLMxWkTn1icZ7DCceRhvmb2SJXqDo4",
    "Certusm1sa411sMpV9FPqU5dXAYhmmhygvxJ23S6hJ24",
    "11111111111111111111111111111111"
  };

  static uchar const binary[ N_TESTS ][ 32UL ] = {
    { 0x07,0xe0,0x46,0x93,0x3c,0x70,0x90,0xfa,0x2e,0x3e,0x85,0x39,0xfc,0x95,0xdc,0x8f,
      0xed,0x4d,0x15,0xd0,0xbf,0x3d,0x3a,0xce,0x98,0x88,0x81,0x67,0x81,0x30,0x8d,0x8b },
    { 0x93,0xb9,0x5b,0xa3,0xdb,0x98,0x5d,0x8c,0xca,0xe4,0x90,0x69,0x42,0x8f,0xec,0xf2,
      0xff,0x3b,0x7d,0xa6,0x62,0xa9,0x58,0xba,0x9e,0x0e,0x46,0xeb,0x0d,0xbd,0x16,0xf6 },
    { 0xb8,0xa7,0xfd,0xff,0xf8,0x8b,0x18,0xcc,0x25,0x98,0x52,0x9d,0x0d,0xad,0x9b,0xf9,
      0x69,0x7a,0x8a,0x20,0x8e,0xe9,0x68,0xd4,0x4e,0x61,0x8b,0x03,0x2e,0x04,0x65,0x10 },
    { 0xcb,0x64,0x55,0xcb,0x03,0x29,0xc7,0x8f,0xea,0x65,0x57,0xa6,0x1b,0x97,0x9a,0x96,
      0x5e,0xe7,0xe7,0x9a,0xc7,0x8c,0x8f,0xd9,0x89,0x37,0x92,0xf2,0x78,0x6d,0x0e,0xd5 },
    { 0xce,0xef,0x13,0xd8,0x09,0x8b,0xf5,0xda,0x4b,0x19,0x59,0x6a,0xc9,0xad,0x36,0x7c,
      0x9c,0x5e,0x1a,0xad,0xe0,0xae,0xc9,0xd7,0xc0,0x41,0x3a,0xeb,0xcc,0x62,0x3b,0xdf },
    { 0xad,0x23,0x76,0x6d,0xde,0xe6,0xe9,0x9c,0xa3,0x34,0x0e,0xe5,0xbe,0xac,0x08,0x84,
      0xc8,0x9d,0xdb,0xc7,0x4d,0xfe,0x24,0x8f,0xea,0x56,0x13,0x56,0x98,0xba,0xfd,0xd1 },
    { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 }
  };

  for( ulong i=0UL; i<N_TESTS; i++ ) {
    char  buf [ FD_BASE58_ENCODED_32_SZ ];
    uchar buf2[ 32 ];
    FD_TEST( !strcmp( encoded[i], encode_func( binary [i], NULL, buf  )       ) );
    FD_TEST( !memcmp( binary [i], decode_func( encoded[i],       buf2 ), 32UL ) );
  }
# undef N_TESTS
}

static void
battery_sample64( encode_func_t encode_func,
                     decode_func_t decode_func ) {
# define N_TESTS (6UL)
  static char const * encoded[ N_TESTS ] = {
    "1111111111111111111111111111111111111111111111111111111111111111",
    "5eQS44iKV8B4b4gTt4tPZLPSHtD7F78fFDhbHDknsrAE1vUipnDf3pK6h5eZ8CqWqFgZPoYY6XHKUuvyt7BLWHpb",
    "4EZ6eZt7svb2gYEFFnf14KSpHMD9k6F57qjDwD7dDZhegkrn4e3EzoHNNV83Fjc9cN8BQgG2uRFGwDSivw9yk7Nx",
    "so5VqLRtAF6RxQJ4BSv31SPQfcFhUU1rqCroUJSLCWSEPhZqAEEwiTrH1kdndyztYbTCdmE7qKavgApDqVjmrKQ",
    "RSAtWLUiyEhWUrcBtqmFUgtBHQ2ghJz4poJdXyruFQJpbyfY9AQBfr3dZUP6xdBy7PRqzeXYGUsNai8gcEivZQL",
    "11cgTH4D5e8S3snD444WbbGrkepjTvWMj2jkmCGJtgn3H7qrPb1BnwapxpbGdRtHQh9t9Wbn9t6ZDGHzWpL4df"
  };

  static uchar const binary[ N_TESTS ][ 64UL ] = {
    { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    { 0xe8,0x52,0xe3,0x69,0x0d,0xa0,0xeb,0xf5,0xb4,0x66,0xed,0x0c,0x89,0x6b,0x2c,0x8f,
      0xea,0xe6,0x0e,0x3b,0x23,0xc0,0x37,0xfc,0xdd,0x68,0xbf,0xc2,0xe4,0x60,0x7b,0x47,
      0xb9,0x79,0x02,0x2e,0x4c,0xf6,0x2a,0x04,0x26,0x4e,0xef,0x55,0x94,0x0e,0xc8,0x57,
      0xb3,0x46,0xf1,0xa4,0x11,0x5b,0xaa,0x1a,0xc8,0x3d,0x3b,0x05,0xca,0xa8,0x23,0x00 },
    { 0xa1,0xbd,0x2a,0xdf,0x4f,0x4f,0x9f,0xe0,0x6e,0xc2,0x88,0x0b,0x1b,0x53,0x0e,0x7c,
      0xb7,0xbe,0x4c,0x22,0xda,0x1a,0x45,0x93,0x4f,0x5e,0x09,0x25,0x02,0x6d,0x9f,0xec,
      0xed,0xa1,0xda,0xb7,0xdf,0x93,0xf1,0x20,0xf0,0x57,0xfc,0x57,0x00,0xf2,0x49,0x0c,
      0xd2,0xd9,0x15,0x15,0xc4,0x12,0xaa,0x1e,0xec,0x57,0x2b,0x86,0x53,0x90,0xc2,0x09 },
    { 0x2b,0xcd,0x9e,0x54,0xf5,0xde,0x5c,0xf0,0xbc,0xbe,0xa0,0x12,0xf8,0x13,0x7e,0x54,
      0x7a,0x7d,0x41,0xc9,0xa0,0x7b,0xa1,0xbc,0x08,0x34,0xf2,0x8a,0x20,0xcf,0xff,0xdd,
      0x4a,0x6c,0xcb,0xbf,0xe5,0x63,0x2f,0x4b,0x84,0x0f,0xda,0xbc,0xa3,0xf0,0x85,0x75,
      0x7d,0xe8,0xa9,0xaf,0x10,0x0e,0xd7,0x1f,0xaf,0xb3,0x30,0xc2,0x0f,0xd2,0x60,0x0f },
    { 0x15,0x12,0x28,0x92,0x1f,0xfb,0x04,0x22,0xa2,0x0e,0x3e,0xef,0x11,0x93,0x6f,0x52,
      0x46,0x79,0x5a,0x91,0x2a,0xf2,0x66,0x76,0x88,0x1a,0x15,0x2d,0x64,0x1c,0xaf,0x69,
      0x8f,0x69,0xda,0x82,0x89,0xcc,0x56,0x69,0x6c,0xa1,0xbe,0x23,0xbc,0xfb,0xb1,0xb4,
      0xfc,0x90,0x2b,0xf0,0xfe,0x78,0x9f,0x7e,0xae,0xe9,0x4e,0x94,0x53,0xe6,0xb6,0x01 },
    { 0x00,0x00,0x0a,0x55,0xc6,0xbf,0x47,0x12,0x05,0x36,0x06,0xff,0xb5,0x20,0xe3,0x96,
      0xd0,0x03,0x9d,0x87,0xde,0x43,0x32,0x17,0xed,0x33,0xf0,0x7b,0x22,0x94,0x6f,0x54,
      0x62,0xa2,0xec,0x85,0x1f,0x5d,0xb9,0x8e,0x6c,0x29,0xbf,0x01,0x8a,0x06,0xc0,0x00,
      0x2e,0x5d,0x19,0x41,0xf3,0xdf,0xe1,0xe1,0x55,0x37,0x52,0xfb,0x6d,0x84,0xa5,0x02 }
  };

  for( ulong i=0UL; i<N_TESTS; i++ ) {
    char  buf [ FD_BASE58_ENCODED_64_SZ ];
    uchar buf2[ 64 ];
    FD_TEST( !strcmp( encoded[i], encode_func( binary [i], NULL, buf  )       ) );
    FD_TEST( !memcmp( binary [i], decode_func( encoded[i],       buf2 ), 64UL ) );
  }
# undef N_TESTS
}

static void
battery_match( encode_func_t encode_func_ref,
               encode_func_t encode_func,
               decode_func_t decode_func,
               ulong         n,            /* assumed power of 2 */
               ulong         encode_sz,
               fd_rng_t *    rng,
               ulong         cnt,
               char  *       buf_ref,      /* indexed [0,encode_sz) */
               uchar *       bytes_ref,    /* indexed [0,n) */
               char  *       buf,          /* indexed [0,encode_sz) */
               uchar *       bytes ) {     /* indexed [0,n) */
  ulong mask = n-1UL;

  for( ulong i=0UL; i<cnt; i++ ) {

    /* Create the reference bytes.  To stress out various edge cases, we
       have a random bytes with a random length cyclic wrap around
       streak of zeros. */
    for( ulong j=0UL; j<n; j++ ) bytes_ref[ j ] = fd_rng_uchar( rng );
    ulong off = fd_rng_ulong( rng ) & mask;
    for( ulong rem = fd_rng_ulong( rng ) & mask; rem; rem-- ) {
      bytes_ref[ off ] = (uchar)0;
      off = (off+1UL) & mask;
    }

    /* Compute the reference encoding and validate that it looks sane */
    ulong len_ref[1];
    FD_TEST( encode_func_ref( bytes_ref, len_ref, buf_ref )==buf_ref );
    FD_TEST( (n<=len_ref[0]) & (len_ref[0]<encode_sz) );
    FD_TEST( strlen( buf_ref )==len_ref[0] );

    /* Test encoding with NULL len */
    FD_TEST( encode_func( bytes_ref, NULL, buf )==buf );
    FD_TEST( !strcmp( buf, buf_ref ) );

    /* Test encoding with non-NULL len */
    ulong len[1];
    fd_memset( buf, 0, encode_sz );
    FD_TEST( encode_func( bytes_ref, len, buf )==buf );
    FD_TEST( !strcmp( buf, buf_ref ) );
    FD_TEST( len[0]==len_ref[0] );

    /* Test decoding */
    FD_TEST( decode_func( buf, bytes )==bytes );
    FD_TEST( !memcmp( bytes, bytes_ref, n ) );
  }
}

static void
battery_performance( encode_func_t encode_func,
                     decode_func_t decode_func,
                     ulong         n,
                     ulong         encode_sz,
                     fd_rng_t *    rng,
                     char  *       buf,          /* indexed [0,encode_sz) */
                     uchar *       bytes ) {     /* indexed [0,n) */
  ulong const test_count = 3000UL;

  /* Count non-conversion work */
  long overhead = -fd_log_wallclock();
  for( ulong i=0UL; i<test_count; i++ ) {
    for( ulong j=0UL; j<n;         j++ ) FD_VOLATILE( bytes[ j ] ) = fd_rng_uchar( rng );
    for( ulong j=0UL; j<encode_sz; j++ ) FD_VOLATILE_CONST( buf[ j ] );
  }
  overhead += fd_log_wallclock();

  /* Warm up instruction cache */
  encode_func( bytes, NULL, buf );
  encode_func( bytes, NULL, buf );
  encode_func( bytes, NULL, buf );

  /* Measure encode */
  long encode = -fd_log_wallclock();
  for( ulong i=0UL; i<test_count; i++ ) {
    for( ulong j=0UL; j<n;         j++ ) FD_VOLATILE( bytes[ j ] ) = fd_rng_uchar( rng );
    encode_func( bytes, NULL, buf );
    for( ulong j=0UL; j<encode_sz; j++ ) FD_VOLATILE_CONST( buf[ j ] );
  }
  encode += fd_log_wallclock();

  /* Warm up instruction cache */
  decode_func( buf, bytes );
  decode_func( buf, bytes );
  decode_func( buf, bytes );

  /* Measure encode-decode pair */
  long encode_decode = -fd_log_wallclock();
  for( ulong i=0UL; i<test_count; i++ ) {
    for( ulong j=0UL; j<n; j++ ) FD_VOLATILE( bytes[ j ] ) = fd_rng_uchar( rng );
    decode_func( encode_func( bytes, NULL, buf ), bytes );
    for( ulong j=0UL; j<n; j++ ) FD_VOLATILE_CONST( bytes[ j ] );
  }
  encode_decode += fd_log_wallclock();

  /* Note: the overhead subtraction for the decode is very slightly
     inaccurate. */
  FD_LOG_NOTICE(( "average time per encode call (excluding overhead) %f ns, average time per decode call %f ns",
                  (double)(encode        - overhead)/(double)test_count,
                  (double)(encode_decode - encode  )/(double)test_count  ));
}

#define MAKE_TESTS(n,name)                                                                     \
static inline void                                                                             \
test_encode_basic##name( void ) {                                                              \
  battery_encode_basic##n( fd_base58_encode_##name );                                          \
}                                                                                              \
                                                                                               \
static inline void                                                                             \
test_encode_bounds##name( void ) {                                                             \
  char  buf  [ FD_BASE58_ENCODED_##n##_SZ ];                                                   \
  uchar bytes[ n ]; /* force unaligned */                                                      \
  battery_encode_bounds( fd_base58_encode_##name, n, FD_BASE58_ENCODED_##n##_SZ, buf, bytes ); \
}                                                                                              \
                                                                                               \
static inline void                                                                             \
test_decode_fail##name( void ) {                                                               \
  battery_decode_fail##n( fd_base58_decode_##name );                                           \
}                                                                                              \
                                                                                               \
static inline void                                                                             \
test_sample##name( void ) {                                                                    \
  battery_sample##n( fd_base58_encode_##name, fd_base58_decode_##name );                       \
}                                                                                              \
                                                                                               \
static inline void                                                                             \
test_match##name( fd_rng_t * rng,                                                              \
                  ulong      cnt ) {                                                           \
  char  buf_ref  [ FD_BASE58_ENCODED_##n##_SZ ];                                               \
  char  buf      [ FD_BASE58_ENCODED_##n##_SZ ];                                               \
  uchar bytes_ref[ n ];                                                                        \
  uchar bytes    [ n ];                                                                        \
  battery_match( fd_base58_encode_##n##_ref, fd_base58_encode_##name, fd_base58_decode_##name, \
                 n, FD_BASE58_ENCODED_##n##_SZ, rng, cnt, buf_ref, bytes_ref, buf, bytes );    \
}                                                                                              \
                                                                                               \
static inline void                                                                             \
test_performance##name( fd_rng_t * rng ) {                                                     \
  char  buf  [ FD_BASE58_ENCODED_##n##_SZ ];                                                   \
  uchar bytes[ n ];                                                                            \
  battery_performance( fd_base58_encode_##name, fd_base58_decode_##name,                       \
                       n, FD_BASE58_ENCODED_##n##_SZ, rng, buf, bytes );                       \
}

MAKE_TESTS(32,32_ref)
MAKE_TESTS(64,64_ref)
MAKE_TESTS(32,32    )
MAKE_TESTS(64,64    )

#undef MAKE_TESTS

#if FD_HAS_AVX

#include "fd_base58_avx.h"

static void
test_count_leading_zeros( void ) {
  uchar buffer[ 64UL ] __attribute__((aligned(32)));

  fd_memset( buffer, 0, 64UL );
  FD_TEST( count_leading_zeros_32( wuc_ld( buffer ) )                        == 32UL );
  FD_TEST( count_leading_zeros_45( wuc_ld( buffer ), wuc_ld( buffer+32UL ) ) == 45UL );

  buffer[ 0UL ] = (uchar)2;
  FD_TEST( count_leading_zeros_32( wuc_ld( buffer ) )                        == 0UL );
  FD_TEST( count_leading_zeros_45( wuc_ld( buffer ), wuc_ld( buffer+32UL ) ) == 0UL );

  buffer[ 0UL ] = (uchar)0;
  buffer[ 1UL ] = (uchar)7;
  FD_TEST( count_leading_zeros_32( wuc_ld( buffer ) )                        == 1UL );
  FD_TEST( count_leading_zeros_45( wuc_ld( buffer ), wuc_ld( buffer+32UL ) ) == 1UL );

  buffer[ 1UL ] = (uchar)255;
  FD_TEST( count_leading_zeros_32( wuc_ld( buffer ) )                        == 1UL );
  FD_TEST( count_leading_zeros_45( wuc_ld( buffer ), wuc_ld( buffer+32UL ) ) == 1UL );

  fd_memset( buffer, 123, 64UL );
  for( ulong i=0UL; i<32UL; i++ ) {
    buffer[ i ] = (uchar)0;
    FD_TEST( count_leading_zeros_32( wuc_ld( buffer ) )                        == i+1UL );
    FD_TEST( count_leading_zeros_45( wuc_ld( buffer ), wuc_ld( buffer+32UL ) ) == i+1UL );
  }

  for( ulong i=32UL; i<45UL; i++ ) {
    buffer[ i ] = (uchar)0;
    FD_TEST( count_leading_zeros_32( wuc_ld( buffer ) )                        == 32UL  );
    FD_TEST( count_leading_zeros_45( wuc_ld( buffer ), wuc_ld( buffer+32UL ) ) == i+1UL );
  }

  for( ulong i=45UL; i<64UL; i++ ) {
    buffer[ i ] = (uchar)0;
    FD_TEST( count_leading_zeros_32( wuc_ld( buffer ) )                        == 32UL );
    FD_TEST( count_leading_zeros_45( wuc_ld( buffer ), wuc_ld( buffer+32UL ) ) == 45UL );
  }
}

static void
test_raw_to_base58( void ) {
  uchar in [ 32UL ] __attribute__((aligned(32)));
  uchar out[ 32UL ] __attribute__((aligned(32)));

  for( ulong i=0UL; i<58UL; i++ ) {
    for( ulong j=0UL; j<32UL; j++ ) in[ j ] = (uchar)((i+j)%58UL);
    wuc_st( out, raw_to_base58( wuc_ld( in ) ) );
    for( ulong j=0UL; j<32UL; j++ ) FD_TEST( out[ j ] == base58_chars[ in[ j ] ] );
  }
}

static void
test_intermediate_to_raw( void ) {
  ulong c1 = 0UL; /* +     j */
  ulong c2 = 1UL; /* +   3*j */
  ulong c3 = 2UL; /* + 101*j */
  ulong c4 = 3UL; /* + 503*j */
  uchar out[ 32UL ] __attribute__((aligned(32)));

  for( ulong j=0UL; j<1000000UL; j++ ) {
    wl_t  intermediate = wl( (long)c1, (long)c2, (long)c3, (long)c4 );
    wuc_t raw          = intermediate_to_raw( intermediate );
    wuc_st( out, raw );

    FD_TEST( out[  0UL ] == (uchar)( c1/11316496UL)       );
    FD_TEST( out[  1UL ] == (uchar)((c1/195112UL  )%58UL) );
    FD_TEST( out[  2UL ] == (uchar)((c1/3364UL    )%58UL) );
    FD_TEST( out[  3UL ] == (uchar)((c1/58UL      )%58UL) );
    FD_TEST( out[  4UL ] == (uchar)((c1/1UL       )%58UL) );
    FD_TEST( out[  5UL ] == (uchar)( c2/11316496UL)       );
    FD_TEST( out[  6UL ] == (uchar)((c2/195112UL  )%58UL) );
    FD_TEST( out[  7UL ] == (uchar)((c2/3364UL    )%58UL) );
    FD_TEST( out[  8UL ] == (uchar)((c2/58UL      )%58UL) );
    FD_TEST( out[  9UL ] == (uchar)((c2/1UL       )%58UL) );
    FD_TEST( out[ 10UL ] == (uchar)0                      );
    FD_TEST( out[ 11UL ] == (uchar)0                      );
    FD_TEST( out[ 12UL ] == (uchar)0                      );
    FD_TEST( out[ 13UL ] == (uchar)0                      );
    FD_TEST( out[ 14UL ] == (uchar)0                      );
    FD_TEST( out[ 15UL ] == (uchar)0                      );
    FD_TEST( out[ 16UL ] == (uchar)( c3/11316496UL)       );
    FD_TEST( out[ 17UL ] == (uchar)((c3/195112UL  )%58UL) );
    FD_TEST( out[ 18UL ] == (uchar)((c3/3364UL    )%58UL) );
    FD_TEST( out[ 19UL ] == (uchar)((c3/58UL      )%58UL) );
    FD_TEST( out[ 20UL ] == (uchar)((c3/1UL       )%58UL) );
    FD_TEST( out[ 21UL ] == (uchar)( c4/11316496UL)       );
    FD_TEST( out[ 22UL ] == (uchar)((c4/195112UL  )%58UL) );
    FD_TEST( out[ 23UL ] == (uchar)((c4/3364UL    )%58UL) );
    FD_TEST( out[ 24UL ] == (uchar)((c4/58UL      )%58UL) );
    FD_TEST( out[ 25UL ] == (uchar)((c4/1UL       )%58UL) );
    FD_TEST( out[ 26UL ] == (uchar)0                      );
    FD_TEST( out[ 27UL ] == (uchar)0                      );
    FD_TEST( out[ 28UL ] == (uchar)0                      );
    FD_TEST( out[ 29UL ] == (uchar)0                      );
    FD_TEST( out[ 30UL ] == (uchar)0                      );
    FD_TEST( out[ 31UL ] == (uchar)0                      );

    c1 +=   1UL;
    c2 +=   3UL;
    c3 += 101UL;
    c4 += 503UL;
  }
}

static void
test_ten_per_slot_down( void ) {

  /* Test 32B version */
  {
    uchar in [ 32UL*3UL ] __attribute__((aligned(32)));
    uchar out[ 32UL*2UL ] __attribute__((aligned(32)));
    fd_memset( in,  0, 32UL*3UL );
    fd_memset( out, 0, 32UL*2UL );
    for( ulong i=0UL; i<45UL; i++ ) in[ 16UL*(i/10UL) + (i%10UL) ] = (uchar)(i+1UL);

    wuc_t a = wuc_ld( in+0UL  );
    wuc_t b = wuc_ld( in+32UL );
    wuc_t c = wuc_ld( in+64UL );
    wuc_t out0;
    wuc_t out1;
    ten_per_slot_down_32( a, b, c, out0, out1 );
    wuc_st( out+ 0UL, out0 );
    wuc_st( out+32UL, out1 );

    for( ulong i=0UL; i<45UL; i++ ) FD_TEST( out[ i ] == (uchar)(i+1UL) );
  }

  /* Test 64B version */
  {
    uchar in [ 32UL*5UL ] __attribute__((aligned(32)));
    uchar out[ 32UL*3UL ] __attribute__((aligned(32)));
    fd_memset( in,  0, 32UL*5UL );
    fd_memset( out, 0, 32UL*3UL );
    for( ulong i=0UL; i<90UL; i++ ) in[ 16UL*(i/10UL) + (i%10UL) ] = (uchar)(i+1UL);

    wuc_t a = wuc_ld( in+  0UL );
    wuc_t b = wuc_ld( in+ 32UL );
    wuc_t c = wuc_ld( in+ 64UL );
    wuc_t d = wuc_ld( in+ 96UL );
    wuc_t e = wuc_ld( in+128UL );
    wuc_t out0;
    wuc_t out1;
    wuc_t out2;
    ten_per_slot_down_64( a, b, c, d, e, out0, out1, out2 );
    wuc_st( out+ 0UL, out0 );
    wuc_st( out+32UL, out1 );
    wuc_st( out+64UL, out2 );

    for( ulong i=0UL; i<90UL; i++ ) FD_TEST( out[ i ] == (uchar)(i+1UL) );
  }
}

#endif /* FD_HAS_AVX */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--cnt", NULL, 100000UL );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

# if FD_HAS_AVX
  FD_LOG_NOTICE(( "Testing AVX internals" ));
  test_intermediate_to_raw();
  test_raw_to_base58();
  test_count_leading_zeros();
  test_ten_per_slot_down();
# endif

  FD_LOG_NOTICE(( "Testing reference 256-bit conversion" ));
  test_encode_basic32_ref();
  test_encode_bounds32_ref();
  test_decode_fail32_ref();
  test_sample32_ref();
  test_match32_ref( rng, cnt );
  test_performance32_ref( rng );

  FD_LOG_NOTICE(( "Testing reference 512-bit conversion" ));
  test_encode_basic64_ref();
  test_encode_bounds64_ref();
  test_decode_fail64_ref();
  test_sample64_ref();
  test_match64_ref( rng, cnt );
  test_performance64_ref( rng );

  FD_LOG_NOTICE(( "Testing 256-bit conversion" ));
  test_encode_basic32();
  test_encode_bounds32();
  test_decode_fail32();
  test_sample32();
  test_match32( rng, cnt );
  test_performance32( rng );

  FD_LOG_NOTICE(( "Testing 512-bit conversion" ));
  test_encode_basic64();
  test_encode_bounds64();
  test_decode_fail64();
  test_sample64();
  test_match64( rng, cnt );
  test_performance64( rng );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
