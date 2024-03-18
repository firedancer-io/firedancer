#include "fd_utf8.h"

/* Basic UTF-8 validator imported from Rust's core/src/str/validations.rs */

/* FIXME: Add high-performance AVX version */

static uchar const fd_utf8_char_width[ 256 ] = {
  // 1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 1
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 2
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 3
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 4
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 5
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 6
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 7
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 8
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 9
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // A
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // B
  0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // C
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // D
  3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // E
  4, 4, 4, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // F
};

FD_FN_PURE int
fd_utf8_verify( char const * str,
                ulong        sz ) {

  char const *       cur = str;
  char const * const end = cur+sz;

  while( cur<end ) {
    uint c0 = (uchar)*cur;
    if( c0>=0x80U ) {
      cur++;
      ulong width = fd_utf8_char_width[ c0 ];
      switch( width ) {
      case 2: {
        schar c1 = (schar)( *cur++ );
        if( FD_UNLIKELY( (c1>=-64) ) )
          return 0;
        break;
      }
      case 3: {
        uchar c1 = (uchar)( *cur++ );
        schar c2 = (schar)( *cur++ );
        if( FD_UNLIKELY(
            !(   ( (c0==0xe0)&           (c1>=0xa0)&(c1<=0xbf) )
               | ( (c0>=0xe1)&(c0<=0xec)&(c1>=0x80)&(c1<=0xbf) )
               | ( (c0==0xed)&           (c1>=0x80)&(c1<=0x9f) )
               | ( (c0>=0xee)&(c0<=0xef)&(c1>=0x80)&(c1<=0xbf) ) )
            | (c2>=-64) ) )
          return 0;
        break;
      }
      case 4: {
        uchar c1 = (uchar)( *cur++ );
        schar c2 = (schar)( *cur++ );
        schar c3 = (schar)( *cur++ );
        if( FD_UNLIKELY(
            !(   ( (c0==0xf0)&           (c1>=0x90)&(c1<=0xbf) )
               | ( (c0>=0xf1)&(c0<=0xf3)&(c1>=0x80)&(c1<=0xbf) )
               | ( (c0==0xf4)&           (c1>=0x80)&(c1<=0x8f) ) )
            | (c2>=-64)
            | (c3>=-64) ) )
          return 0;
        break;
      }
      default:
        return 0;
      }
    } else {
      cur++;
    }
  }

  return 1;
}
