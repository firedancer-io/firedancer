#include "fd_zle.h"

#if FD_HAS_AVX512
#include "../../util/simd/fd_avx512.h"
#endif

/* Wire format: a stream of frames, each producing L literal bytes then
   Z zero bytes.

     token     1 byte = (min(L,15)<<4) | min(Z,15)
     lit_ext   varint( L-15 )  only if L>=15
     literals  L bytes verbatim
     zero_ext  varint( Z-15 )  only if Z>=15

   The token 0x00 is invalid.  The greedy encoder breaks the open
   literal frame iff a zero run is >=FD_ZLE_MIN_Z long, and falls back
   to a single all-literal frame if that did not win, bounding overhead
   at 1+varint(data_sz-15) <= FD_ZLE_OVERHEAD bytes.

   Note that fd_zle makes assumptions on memory protection setup
   surrounding the input buffer for performance (fd_zle deliberately
   reads slightly out of bounds to omit expensive tail access
   specialization, see API docs in fd_zle.h). */

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

#if FD_HAS_AVX512

/* fd_zle_zmask returns the zero-byte mask of the 64 byte word at
   s+(w<<6), for w<(n+63)/64.  Bits at positions >=n read as non-zero so
   runs terminate at n. */

static inline ulong
fd_zle_zmask( uchar const * s,
              ulong         w,
              ulong         n ) {
  ulong off = w<<6;
  ulong m   = wwb_eq( wwb_ldu( s+off ), wwb_zero() );
  if( FD_LIKELY( off+64UL<=n ) ) return m;
  return m & ( ~0UL>>( 64UL-( n-off ) ) );
}

/* fd_zle_cand marks where a zero run of FD_ZLE_MIN_Z bytes starts.
   Output bit i survives only when src[i]==src[i+1]==0.  nz==1 implies
   first byte in next 64 byte block is zero (if unknown set it to 1). */

FD_STATIC_ASSERT( FD_ZLE_MIN_Z==2UL, unit );

static inline ulong
fd_zle_cand( ulong m,
             ulong nz ) {
  return m & ( ( m>>1 ) | ( nz<<63 ) );
}

/* inline-friendly memcpy/memset */

static inline void
fd_zle_copy( uchar *       FD_RESTRICT d,
             uchar const * FD_RESTRICT s,
             ulong                     sz ) {
  ulong k = 0UL;
  for( ; k+64UL<=sz; k+=64UL ) {
    wwb_stu( d+k, wwb_ldu( s+k ) );
  }
  if( k<sz ) {
    __mmask64 m = _cvtu64_mask64( ~0UL>>( 64UL-( sz-k ) ) );
    _mm512_mask_storeu_epi8( (void *)( d+k ), m, _mm512_maskz_loadu_epi8( m, s+k ) );
  }
}

#define FD_ZLE_ZERO_THRESH (512UL)

static inline void
fd_zle_zero( uchar * d,
             ulong   sz ) {
  wwb_t z = wwb_zero();
  if( FD_LIKELY( sz<=64UL ) ) {
    /* _bzhi_u64 saturates at 64, so sz==64 yields the full mask */
    _mm512_mask_storeu_epi8( (void *)d, _cvtu64_mask64( _bzhi_u64( ~0UL, sz ) ), z );
    return;
  }
  if( FD_LIKELY( sz<FD_ZLE_ZERO_THRESH ) ) {
    ulong k = 0UL;
    do { wwb_stu( d+k, z ); k += 64UL; } while( k+64UL<=sz );
    wwb_stu( d+sz-64UL, z );  /* overlaps, stays in range */
    return;
  }
  fd_memset( d, 0, sz );
}

#else

static inline void
fd_zle_copy( uchar * FD_RESTRICT       d,
             uchar const * FD_RESTRICT s,
             ulong                     sz ) {
  if( sz ) fd_memcpy( d, s, sz );
}

static inline void
fd_zle_zero( uchar * d,
             ulong   sz ) {
  fd_memset( d, 0, sz );
}

#endif

static uchar *
fd_zle_emit( uchar *                   o,
             uchar const * FD_RESTRICT lit,
             ulong                     L,
             ulong                     Z ) {
  ulong ln = L<15UL ? L : 15UL;
  ulong zn = Z<15UL ? Z : 15UL;
  *o++ = (uchar)( (ln<<4) | zn );
  if( L>=15UL ) o += fd_zle_vput( o, L-15UL );
  fd_zle_copy( o, lit, L );
  o += L;
  if( Z>=15UL ) o += fd_zle_vput( o, Z-15UL );
  return o;
}

#if FD_HAS_AVX512

/* fd_zle_spill extends a zero run past the end of word *pw, returning
   the run length and leaving *pw / *pm at the word where it ended. */

static inline ulong
fd_zle_spill( uchar const * s,
              ulong         n,
              ulong         words,
              ulong *       pw,
              ulong *       pm,
              ulong         len ) {
  ulong w = *pw+1UL;
  for(;;) {
    if( w>=words ) { *pw = w; *pm = 0UL; return len; }
    ulong t = fd_zle_zmask( s, w, n );
    if( FD_UNLIKELY( t!=~0UL ) ) {
      ulong ext = (ulong)__builtin_ctzll( ~t );
      *pw = w;
      *pm = t & ~( ( 1UL<<ext )-1UL );
      return len+ext;
    }
    w++; len += 64UL;
    while( ( w<<6 )+256UL<=n ) {
      uchar const * p = s+( w<<6 );
      wwb_t v = wwb_or( wwb_or( wwb_ldu( p       ), wwb_ldu( p+ 64UL ) ),
                        wwb_or( wwb_ldu( p+128UL ), wwb_ldu( p+192UL ) ) );
      if( FD_UNLIKELY( _mm512_test_epi8_mask( v, v ) ) ) break;
      w += 4UL; len += 256UL;
    }
  }
}

/* L and Z fit in 256 bytes here. */

static inline uchar *
fd_zle_vput_small( uchar * o,
                   ulong   v ) {
  ulong big = (ulong)( v>=128UL );
  o[0] = (uchar)( ( v & 0x7fUL ) | ( big<<7 ) );
  o[1] = (uchar)( v>>7 );
  return o+1UL+big;
}

static inline uchar *
fd_zle_emit_small( uchar *                   o,
                   uchar const * FD_RESTRICT lit,
                   ulong                     L,
                   ulong                     Z ) {
  ulong ln = L<15UL ? L : 15UL;
  ulong zn = Z<15UL ? Z : 15UL;
  *o++ = (uchar)( (ln<<4) | zn );
  if( L>=15UL ) o = fd_zle_vput_small( o, L-15UL );
  if( FD_LIKELY( L<=64UL ) ) {   /* the common case is a single vector */
    /* masked load partially OOB */
    __mmask64 m = _cvtu64_mask64( _bzhi_u64( ~0UL, (uint)L ) );
    _mm512_mask_storeu_epi8( (void *)o, m, _mm512_maskz_loadu_epi8( m, lit ) );
  } else fd_zle_copy( o, lit, L );
  o += L;
  if( Z>=15UL ) o = fd_zle_vput_small( o, Z-15UL );
  return o;
}

/* FD_ZLE_EXT extends a zero run that reached the end of the previous
   64-byte word.  Count consecutive zero bytes from the start of m, add
   them to len, and remove their bits from m.  Set full if all 64 bytes
   were zero, meaning the run may continue into the following word. */

#define FD_ZLE_EXT( m ) do {                                           \
    ulong _e = ~(m) ? (ulong)__builtin_ctzll( ~(m) ) : 64UL;           \
    len  += _e;                                                        \
    (m)   = _e<64UL ? ( (m) & ~( ( 1UL<<_e )-1UL ) ) : 0UL;            \
    full  = _e==64UL;                                                  \
  } while(0)

/* FD_ZLE_WALK scans zero-byte mask m and emits a frame for each zero
   run of at least FD_ZLE_MIN_Z bytes.  wb is the input offset
   represented by bit 0.  EXT continues a run past bit 63 into
   subsequent mask words. */

#define FD_ZLE_WALK( m, wb, EXT ) do {                                 \
    while( m ) {                                                       \
      ulong b   = (ulong)__builtin_ctzll( m );                         \
      ulong zs  = (wb)+b;                                              \
      ulong hi  = (m)>>b;                                              \
      ulong len;                                                       \
      ulong full FD_FN_UNUSED = 0UL;                                   \
      if( ~hi ) {                                                      \
        len = (ulong)__builtin_ctzll( ~hi );                           \
        (m) &= ~( ( ( 1UL<<len )-1UL )<<b );                           \
      } else {                          /* run fills rest of word */   \
        len = 64UL-b;                                                  \
        (m) = 0UL;                                                     \
      }                                                                \
      if( b+len==64UL ) { EXT; }                                       \
      if( len>=FD_ZLE_MIN_Z ) {                                        \
        o  = fd_zle_emit_small( o, src+fs, zs-fs, len );               \
        fs = zs+len;                                                   \
      }                                                                \
    }                                                                  \
  } while(0)

/* fd_zle_fini closes the open literal frame and applies the deferred
   escape test. */

static inline ulong
fd_zle_fini( uchar *       FD_RESTRICT dst,
             uchar *                   o,
             uchar const * FD_RESTRICT src,
             ulong                     n,
             ulong                     fs ) {
  if( fs<n ) o = fd_zle_emit_small( o, src+fs, n-fs, 0UL );
  ulong sz = (ulong)( o-dst );
  if( FD_UNLIKELY( sz>=1UL+fd_zle_ext( n )+n ) ) return (ulong)( fd_zle_emit( dst, src, n, 0UL )-dst );
  return sz;
}

/* fd_zle_w1..fd_zle_w4 encode inputs of exactly 1..4 mask words, i.e.
   64*(k-1)<n<=64*k.  A compile time word count keeps each body
   straight-line with its mask words in registers, which is what these
   lengths are bound by. */

static ulong
fd_zle_w1( uchar *       FD_RESTRICT dst,
           uchar const * FD_RESTRICT src,
           ulong                     n ) {
  ulong   m0 = fd_zle_zmask( src, 0UL, n );
  uchar * o  = dst;
  ulong   fs = 0UL;                    /* start of the open literal frame */
  FD_ZLE_WALK( m0, 0UL, (void)0 );
  return fd_zle_fini( dst, o, src, n, fs );
}

static ulong
fd_zle_w2( uchar *       FD_RESTRICT dst,
           uchar const * FD_RESTRICT src,
           ulong                     n ) {
  ulong   m0 = fd_zle_zmask( src, 0UL, n );
  ulong   m1 = fd_zle_zmask( src, 1UL, n );
  uchar * o  = dst;
  ulong   fs = 0UL;
  FD_ZLE_WALK( m0,  0UL, FD_ZLE_EXT( m1 ) );
  FD_ZLE_WALK( m1, 64UL, (void)0 );
  return fd_zle_fini( dst, o, src, n, fs );
}

static ulong
fd_zle_w3( uchar *       FD_RESTRICT dst,
           uchar const * FD_RESTRICT src,
           ulong                     n ) {
  ulong   m0 = fd_zle_zmask( src, 0UL, n );
  ulong   m1 = fd_zle_zmask( src, 1UL, n );
  ulong   m2 = fd_zle_zmask( src, 2UL, n );
  uchar * o  = dst;
  ulong   fs = 0UL;
  FD_ZLE_WALK( m0,   0UL, { FD_ZLE_EXT( m1 ); if( full ) FD_ZLE_EXT( m2 ); } );
  FD_ZLE_WALK( m1,  64UL, FD_ZLE_EXT( m2 ) );
  FD_ZLE_WALK( m2, 128UL, (void)0 );
  return fd_zle_fini( dst, o, src, n, fs );
}

static ulong
fd_zle_w4( uchar *       FD_RESTRICT dst,
           uchar const * FD_RESTRICT src,
           ulong                     n ) {
  ulong   m0 = fd_zle_zmask( src, 0UL, n );
  ulong   m1 = fd_zle_zmask( src, 1UL, n );
  ulong   m2 = fd_zle_zmask( src, 2UL, n );
  ulong   m3 = fd_zle_zmask( src, 3UL, n );
  uchar * o  = dst;
  ulong   fs = 0UL;
  FD_ZLE_WALK( m0,   0UL, { FD_ZLE_EXT( m1 ); if( full ) { FD_ZLE_EXT( m2 ); if( full ) FD_ZLE_EXT( m3 ); } } );
  FD_ZLE_WALK( m1,  64UL, { FD_ZLE_EXT( m2 ); if( full ) FD_ZLE_EXT( m3 ); } );
  FD_ZLE_WALK( m2, 128UL, FD_ZLE_EXT( m3 ) );
  FD_ZLE_WALK( m3, 192UL, (void)0 );
  return fd_zle_fini( dst, o, src, n, fs );
}

#undef FD_ZLE_WALK
#undef FD_ZLE_EXT

/* fd_zle_big is the general encoder */

static ulong __attribute__((noinline))
fd_zle_big( uchar *       FD_RESTRICT dst,
            uchar const * FD_RESTRICT src,
            ulong                     n ) {

  /* if a frame reaches esc_sz bytes, use a plaintext frame */

  ulong esc_sz = 1UL + fd_zle_ext( n ) + n;
  ulong lim    = (ulong)dst + esc_sz;
  ulong words  = ( n+63UL )>>6;

  uchar * o  = dst;
  ulong   fs = 0UL;
  ulong   w  = 0UL;
  ulong   m  = fd_zle_zmask( src, 0UL, n );
  ulong   d  = fd_zle_cand( m, 1UL );

  for(;;) {

    if( !d ) {

      w++;
      for(;;) {
        if( FD_UNLIKELY( w>=words ) ) goto trailing;
        m = fd_zle_zmask( src, w, n );
        d = fd_zle_cand( m, 1UL );
        if( d ) break;
        w++;
        while( ( w<<6 )+257UL<=n ) {
          uchar const * p  = src+( w<<6 );
          wwb_t a0 = wwb_or( wwb_ldu( p       ), wwb_ldu( p+  1UL ) );
          wwb_t a1 = wwb_or( wwb_ldu( p+ 64UL ), wwb_ldu( p+ 65UL ) );
          wwb_t a2 = wwb_or( wwb_ldu( p+128UL ), wwb_ldu( p+129UL ) );
          wwb_t a3 = wwb_or( wwb_ldu( p+192UL ), wwb_ldu( p+193UL ) );
          wwb_t t  = _mm512_min_epu8( _mm512_min_epu8( a0, a1 ), _mm512_min_epu8( a2, a3 ) );
          if( FD_UNLIKELY( _mm512_testn_epi8_mask( t, t ) ) ) break;
          w += 4UL;
        }
      }
    }

    /* ctz(d+lo) gives the index of the zero run's final byte */

    ulong lo = d & ( ~d+1UL ); /* lowest candidate */
    ulong b  = (ulong)__builtin_ctzll( d );
    ulong zs = ( w<<6 )+b;
    ulong x  = d + lo;
    ulong len;
    if( FD_LIKELY( x ) ) {
      len = (ulong)__builtin_ctzll( x )-b+1UL;
      d   = x & ( x-1UL );
    } else { /* x==0: run hit the word end */
      len = fd_zle_spill( src, n, words, &w, &m, 64UL-b );
      d   = fd_zle_cand( m, 1UL );
    }
    if( FD_LIKELY( len>=FD_ZLE_MIN_Z ) ) {
      ulong L = zs-fs;
      if( FD_UNLIKELY( (ulong)o+L+15UL>=lim ) &&
          (ulong)o+fd_zle_frame_sz( L, len )>=lim ) goto escape;
      o  = fd_zle_emit( o, src+fs, L, len );
      fs = zs+len;
    }
  }

trailing:
  if( fs<n ) {
    ulong L = n-fs;
    if( FD_UNLIKELY( (ulong)o+L+15UL>=lim ) &&
        (ulong)o+fd_zle_frame_sz( L, 0UL )>=lim ) goto escape;
    o = fd_zle_emit( o, src+fs, L, 0UL );
  }
  return (ulong)( o-dst );

escape:
  return (ulong)( fd_zle_emit( dst, src, n, 0UL )-dst );
}

ulong
fd_zle_compress( void *       FD_RESTRICT comp,
                 void const * FD_RESTRICT data,
                 ulong                    data_sz ) {
  uchar *       dst = (uchar *)comp;
  uchar const * src = (uchar const *)data;
  if( FD_UNLIKELY( !data_sz        ) ) return 0UL;
  if( FD_LIKELY  ( data_sz<= 64UL  ) ) return fd_zle_w1 ( dst, src, data_sz );
  if( FD_LIKELY  ( data_sz<=128UL  ) ) return fd_zle_w2 ( dst, src, data_sz );
  if( FD_LIKELY  ( data_sz<=192UL  ) ) return fd_zle_w3 ( dst, src, data_sz );
  if( FD_LIKELY  ( data_sz<=256UL  ) ) return fd_zle_w4 ( dst, src, data_sz );
  return                                      fd_zle_big( dst, src, data_sz );
}

#else

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

#endif /* FD_HAS_AVX512 */

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
    fd_zle_copy( d+o, s+i, L );
    i += L;
    o += L;
    if( Z==15UL ) {
      if( FD_UNLIKELY( !fd_zle_vget( s, comp_sz, &i, &e ) ) ) return FD_ZLE_ERR_CORRUPT;
      Z += e;
    }
    if( FD_UNLIKELY( Z>data_sz-o ) ) return FD_ZLE_ERR_SPACE;
    fd_zle_zero( d+o, Z );
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
