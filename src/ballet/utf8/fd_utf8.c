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

FD_FN_PURE long
fd_utf8_check_cstr( char const * cstr,
                    ulong        sz ) {

  char const *       cur     = cstr;
  char const * const end     = cur+sz;
  char const * const end_par = end-15UL;

  while( cur<end ) {
    uint c0 = (uchar)*cur;
    if( c0==0x00U ) return cur-cstr;
    if( c0>=0x80U ) {
      cur++;
      ulong width  = fd_utf8_char_width[ c0 ];
      ulong extras = width-1UL;  /* number of continuation bytes */
      if( FD_UNLIKELY( cur+extras >= end ) ) return -1L;

      switch( width ) {
      case 2: {
        schar c1 = (schar)( *cur++ );
        if( FD_UNLIKELY( (c1>=-64) ) )
          return -1;
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
          return -1;
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
          return -1;
        break;
      }
      default:
        return -1L;
      }
    } else if( fd_ulong_is_aligned( (ulong)cur, 8UL ) ) {
      /* Fast-forward until first non-ascii byte */
      while( cur<end_par ) {
        ulong u0 = *(ulong const *)( __builtin_assume_aligned( cur,     8UL ) );
        ulong u1 = *(ulong const *)( __builtin_assume_aligned( cur+8UL, 8UL ) );
        if(  (u0&0x8080808080808080UL)
          |  (u1&0x8080808080808080UL)
          | ((u0-0x0101010101010101UL) & ~u0 & 0x8080808080808080UL)
          | ((u1-0x0101010101010101UL) & ~u1 & 0x8080808080808080UL) )
          break;
        cur += 16UL;
      }
      while( cur<end ) {
        if( !*cur ) return cur-cstr;
        if( (uchar)*cur >= 0x80U ) return -1L;
        cur++;
      }
    } else {
      cur++;
    }
  }

  /* Missing null terminator */
  return -1L;
}
