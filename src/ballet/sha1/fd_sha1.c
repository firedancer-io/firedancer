/* This is a modified copy of the teeny sha1 library, see NOTICES for
   license information. */

#include "fd_sha1.h"

uchar *
fd_sha1_hash( uchar const * data,
              ulong         data_len,
              uchar *       hash ) {
  uint W[ 80 ];
  uint H[] = { 0x67452301,
               0xEFCDAB89,
               0x98BADCFE,
               0x10325476,
               0xC3D2E1F0 };

  ulong data_bits = data_len*8UL;
  ulong loop_cnt = (data_len+8UL)/64UL + 1;
  ulong tailbytes = 64UL*loop_cnt-data_len;
  uchar datatail[ 128 ] = {0};

  /* Pre-processing of data tail (includes padding to fill out 512-bit
     chunk):
        Add bit '1' to end of message (big-endian)
        Add 64-bit message length in bits at very end (big-endian) */

  datatail[ 0 ] = 0x80;
  datatail[ tailbytes-8UL ] = (uchar)( data_bits>>56 & 0xFF);
  datatail[ tailbytes-7UL ] = (uchar)( data_bits>>48 & 0xFF);
  datatail[ tailbytes-6UL ] = (uchar)( data_bits>>40 & 0xFF);
  datatail[ tailbytes-5UL ] = (uchar)( data_bits>>32 & 0xFF);
  datatail[ tailbytes-4UL ] = (uchar)( data_bits>>24 & 0xFF);
  datatail[ tailbytes-3UL ] = (uchar)( data_bits>>16 & 0xFF);
  datatail[ tailbytes-2UL ] = (uchar)( data_bits>>8  & 0xFF);
  datatail[ tailbytes-1UL ] = (uchar)( data_bits>>0  & 0xFF);

  uint didx = 0;
  for( ulong lidx=0UL; lidx<loop_cnt; lidx++ ) {
    /* Compute all elements in W */
    fd_memset( W, 0U, sizeof(W) );

    /* Break 512-bit chunk into sixteen 32-bit, big endian words */
    for( ulong widx=0UL; widx<=15UL; widx++ ) {
      int wcount = 24;

      /* Copy byte-per byte from specified buffer */
      while( didx<data_len && wcount>=0 ) {
        W[ widx ] += (((uint)data[ didx ]) << wcount);
        didx++;
        wcount -= 8;
      }

      /* Fill out W with padding as needed */
      while( wcount>=0 ) {
        W[ widx ] += (((uint)datatail[ didx-data_len ]) << wcount);
        didx++;
        wcount -= 8;
      }
    }

    /* Extend the sixteen 32-bit words into eighty 32-bit words, with potential optimization from:
       "Improving the Performance of the Secure Hash Algorithm (SHA-1)" by Max Locktyukhin */
#define SHA1ROTATELEFT(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))
    for( ulong widx=16UL; widx<=31UL; widx++)  W[ widx ] = SHA1ROTATELEFT( W[ widx-3UL ] ^ W[ widx-8UL ]  ^ W[ widx-14UL ] ^ W[ widx-16UL ], 1 );
    for( ulong widx=32UL; widx<=79UL; widx++ ) W[ widx ] = SHA1ROTATELEFT( W[ widx-6UL ] ^ W[ widx-16UL ] ^ W[ widx-28UL ] ^ W[ widx-32UL ], 2 );

    /* Main loop */
    uint a = H[ 0 ];
    uint b = H[ 1 ];
    uint c = H[ 2 ];
    uint d = H[ 3 ];
    uint e = H[ 4 ];

    uint f = 0, k = 0;
    for( ulong idx=0UL; idx<=79UL; idx++ ) {
      if( idx<=19UL ) {
        f = (b & c) | ((~b) & d);
        k = 0x5A827999;
      } else if( idx>=20UL && idx<=39UL ) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1;
      } else if( idx>=40UL && idx<=59UL ) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDC;
      } else if( idx>=60UL && idx<=79UL ) {
        f = b ^ c ^ d;
        k = 0xCA62C1D6;
      }

      uint temp = SHA1ROTATELEFT( a, 5 )+f+e+k+W[ idx ];
      e = d;
      d = c;
      c = SHA1ROTATELEFT( b, 30 );
      b = a;
      a = temp;
    }
#undef SHA1ROTATELEFT

    H[ 0 ] += a;
    H[ 1 ] += b;
    H[ 2 ] += c;
    H[ 3 ] += d;
    H[ 4 ] += e;

    for( ulong idx=0UL; idx<5UL; idx++ ) {
      hash[ idx*4UL+0UL ] = (uchar)( H[ idx ] >> 24 );
      hash[ idx*4UL+1UL ] = (uchar)( H[ idx ] >> 16 );
      hash[ idx*4UL+2UL ] = (uchar)( H[ idx ] >> 8  );
      hash[ idx*4UL+3UL ] = (uchar)( H[ idx ]       );
    }
  }

  return hash;
}
