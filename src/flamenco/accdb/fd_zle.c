#include "fd_zle.h"

/* Wire format: a stream of frames, each producing L literal bytes then
   Z zero bytes.

     token     1 byte = (min(L,15)<<4) | min(Z,15)
     lit_ext   varint( L-15 )  only if L>=15
     literals  L bytes verbatim
     zero_ext  varint( Z-15 )  only if Z>=15

   The token 0x00 is invalid.  The greedy encoder breaks the open
   literal frame iff a zero run is >=FD_ZLE_MIN_Z long, and falls back
   to a single all-literal frame if that did not win, bounding overhead
   at 1+varint(data_sz-15) <= FD_ZLE_OVERHEAD bytes. */

#define FD_ZLE_MIN_Z (2UL)

static inline ulong
fd_zle_vput( uchar * p,
             ulong   v ) {
  ulong k = 0UL;
  do {
    p[k] = (uchar)( v & 0x7fUL );
    v >>= 7;
    if( v ) p[k] = (uchar)( p[k] | 0x80 );
    k++;
  } while( v );
  return k;
}

static inline int
fd_zle_vget( uchar const * s,
             ulong         slen,
             ulong *       pi,
             ulong *       out ) {
  ulong v  = 0UL;
  ulong i  = *pi;
  int   sh = 0;
  for(;;) {
    if( FD_UNLIKELY( (i>=slen) | (sh>42) ) ) return 0;
    uchar b = s[i++];
    v |= (ulong)( b & 0x7f )<<sh;
    if( !(b & 0x80) ) break;
    sh += 7;
  }
  *pi  = i;
  *out = v;
  return 1;
}

static inline ulong
fd_zle_vlen( ulong v ) {
  ulong k = 1UL;
  while( v>=128UL ) { v >>= 7; k++; }
  return k;
}

static inline ulong
fd_zle_ext( ulong v ) {
  return v>=15UL ? fd_zle_vlen( v-15UL ) : 0UL;
}

static inline ulong
fd_zle_frame_sz( ulong L,
                 ulong Z ) {
  return 1UL + fd_zle_ext( L ) + L + fd_zle_ext( Z );
}

static uchar *
fd_zle_emit( uchar *                   o,
             uchar const * FD_RESTRICT lit,
             ulong                     L,
             ulong                     Z ) {
  ulong ln = L<15UL ? L : 15UL;
  ulong zn = Z<15UL ? Z : 15UL;
  *o++ = (uchar)( (ln<<4) | zn );
  if( L>=15UL ) o += fd_zle_vput( o, L-15UL );
  if( L       ) fd_memcpy( o, lit, L );
  o += L;
  if( Z>=15UL ) o += fd_zle_vput( o, Z-15UL );
  return o;
}

ulong
fd_zle_compress( void *       FD_RESTRICT comp,
                 void const * FD_RESTRICT data,
                 ulong                    data_sz ) {
  uchar *       dst = (uchar *)comp;
  uchar const * src = (uchar const *)data;
  ulong         n   = data_sz;

  if( FD_UNLIKELY( !n ) ) return 0UL;

  /* escape as soon as a frame would reach the escape size, keeps writes
     within FD_ZLE_COMPRESS_BOUND( data_sz ). */

  ulong esc_sz = 1UL + fd_zle_ext( n ) + n;

  uchar * o   = dst;
  ulong   pos = 0UL;
  ulong   fs  = 0UL;
  while( pos<n ) {
    ulong zs = pos;
    while( (zs<n) &&  src[zs] ) zs++;
    if( zs==n ) break;
    ulong ze = zs;
    while( (ze<n) && !src[ze] ) ze++;
    if( ze-zs>=FD_ZLE_MIN_Z ) {
      ulong L = zs-fs;
      ulong Z = ze-zs;
      if( FD_UNLIKELY( (ulong)( o-dst )+fd_zle_frame_sz( L, Z )>=esc_sz ) ) goto escape;
      o  = fd_zle_emit( o, src+fs, L, Z );
      fs = ze;
    }
    pos = ze;
  }
  if( fs<n ) {
    ulong L = n-fs;
    if( FD_UNLIKELY( (ulong)( o-dst )+fd_zle_frame_sz( L, 0UL )>=esc_sz ) ) goto escape;
    o = fd_zle_emit( o, src+fs, L, 0UL );
  }
  return (ulong)( o-dst );

escape:
  return (ulong)( fd_zle_emit( dst, src, n, 0UL )-dst );
}

long
fd_zle_decompress( void *       FD_RESTRICT data,
                   ulong                    data_sz,
                   void const * FD_RESTRICT comp,
                   ulong                    comp_sz ) {
  uchar *       d = (uchar *)data;
  uchar const * s = (uchar const *)comp;
  ulong i = 0UL;
  ulong o = 0UL;
  while( i<comp_sz ) {
    uchar t = s[i++];
    if( FD_UNLIKELY( !t ) ) return FD_ZLE_ERR_CORRUPT;
    ulong L = (ulong)( t>>4 );
    ulong Z = (ulong)( t&15 );
    ulong e;
    if( L==15UL ) {
      if( FD_UNLIKELY( !fd_zle_vget( s, comp_sz, &i, &e ) ) ) return FD_ZLE_ERR_CORRUPT;
      L += e;
    }
    if( FD_UNLIKELY( L>comp_sz-i ) ) return FD_ZLE_ERR_CORRUPT;
    if( FD_UNLIKELY( L>data_sz-o ) ) return FD_ZLE_ERR_SPACE;
    fd_memcpy( d+o, s+i, L );
    i += L;
    o += L;
    if( Z==15UL ) {
      if( FD_UNLIKELY( !fd_zle_vget( s, comp_sz, &i, &e ) ) ) return FD_ZLE_ERR_CORRUPT;
      Z += e;
    }
    if( FD_UNLIKELY( Z>data_sz-o ) ) return FD_ZLE_ERR_SPACE;
    fd_memset( d+o, 0, Z );
    o += Z;
  }
  return (long)o;
}

char const *
fd_zle_strerror( long res ) {
  switch( res ) {
  case FD_ZLE_ERR_SPACE:   return "out of buffer space";
  case FD_ZLE_ERR_CORRUPT: return "malformed compressed data";
  case 0L:                 return "empty";
  default:
    if( FD_UNLIKELY( res>0L ) ) return "ok";
    return "unknown";
  }
}
