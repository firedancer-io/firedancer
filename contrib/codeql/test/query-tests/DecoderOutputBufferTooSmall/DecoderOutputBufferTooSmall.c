typedef unsigned char uchar;
typedef unsigned long ulong;

#define FD_BASE64_DEC_SZ(sz) ((((sz)+3UL)/4UL)*3UL)

long    fd_base64_decode  ( uchar * out, char const * in, ulong in_sz );
uchar * fd_base58_decode_32( char const * encoded, uchar * out );
uchar * fd_base58_decode_64( char const * encoded, uchar * out );

struct holder {
  uchar out[ 16 ];
};

void
test_base64( char const * in,
             ulong        dynamic_sz ) {
  uchar too_small[ 16 ];
  fd_base64_decode( too_small, in, 24UL ); /* $ Alert */

  uchar exact[ FD_BASE64_DEC_SZ( 24UL ) ];
  fd_base64_decode( exact, in, 24UL );

  uchar larger[ 32 ];
  fd_base64_decode( larger, in, 40UL );

  uchar unknown_needed[ 16 ];
  fd_base64_decode( unknown_needed, in, dynamic_sz );

  struct holder h;
  fd_base64_decode( h.out, in, 24UL ); /* $ Alert */
}

void
test_base58( char const * in ) {
  uchar too_small_32[ 31 ];
  fd_base58_decode_32( in, too_small_32 ); /* $ Alert */

  uchar exact_32[ 32 ];
  fd_base58_decode_32( in, exact_32 );

  uchar too_small_64[ 63 ];
  fd_base58_decode_64( in, too_small_64 ); /* $ Alert */

  uchar exact_64[ 64 ];
  fd_base58_decode_64( in, exact_64 );
}
