#include "../fd_util.h"

/* FIXME: TEST LAYOUT MACROS */
/* FIXME: TEST BASE10_DIG_CNT! */

FD_STATIC_ASSERT( FD_ULONG_SVW_ENC_MAX==9UL, unit_test );

/* Treat a binary bit pattern as a floating point number and vice versa. */

static inline uint   float_as_uint( float f ) { union { float f; uint u; } t; t.f = f; return t.u; }
static inline float  uint_as_float( uint  u ) { union { float f; uint u; } t; t.u = u; return t.f; }

#if FD_HAS_DOUBLE
static inline ulong  double_as_ulong( double f ) { union { double f; ulong u; } t; t.f = f; return t.u; }
static inline double ulong_as_double( ulong  u ) { union { double f; ulong u; } t; t.u = u; return t.f; }
#endif

int
main( int     argc,
      char ** argv ) {

  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing uchar" ));
    int   w     = 8;
    uchar zeros = (uchar) 0UL;
    uchar ones  = (uchar)~0UL;
    for( int n=0; n< w; n++ ) {
      uchar x = (uchar)(1UL<<n);
      FD_TEST( fd_uchar_is_pow2( x ) );
      FD_TEST( !fd_uchar_is_pow2( (uchar)~x ) );
    }
    for( int n=0; n<=w; n++ ) { uchar x = (uchar)((n<w) ? (1UL<<n) : 0UL); FD_TEST( fd_uchar_pow2( n )==x ); }
    for( int b=0; b< w; b++ ) {
      uchar mask  = (uchar)(1UL<<b);
      uchar maskc = (uchar)~mask;
      FD_TEST( fd_uchar_mask_bit   ( b           )==mask  );
      FD_TEST( fd_uchar_clear_bit  ( zeros, b    )==zeros ); FD_TEST( fd_uchar_set_bit    ( zeros, b    )==mask  );
      FD_TEST( fd_uchar_clear_bit  ( mask,  b    )==zeros ); FD_TEST( fd_uchar_set_bit    ( mask,  b    )==mask  );
      FD_TEST( fd_uchar_clear_bit  ( maskc, b    )==maskc ); FD_TEST( fd_uchar_set_bit    ( maskc, b    )==ones  );
      FD_TEST( fd_uchar_clear_bit  ( ones,  b    )==maskc ); FD_TEST( fd_uchar_set_bit    ( ones,  b    )==ones  );
      FD_TEST( fd_uchar_flip_bit   ( zeros, b    )==mask  ); FD_TEST( fd_uchar_extract_bit( zeros, b    )==0     );
      FD_TEST( fd_uchar_flip_bit   ( mask,  b    )==zeros ); FD_TEST( fd_uchar_extract_bit( mask,  b    )==1     );
      FD_TEST( fd_uchar_flip_bit   ( maskc, b    )==ones  ); FD_TEST( fd_uchar_extract_bit( maskc, b    )==0     );
      FD_TEST( fd_uchar_flip_bit   ( ones,  b    )==maskc ); FD_TEST( fd_uchar_extract_bit( ones,  b    )==1     );
      FD_TEST( fd_uchar_insert_bit ( zeros, b, 0 )==zeros ); FD_TEST( fd_uchar_insert_bit ( zeros, b, 1 )==mask  );
      FD_TEST( fd_uchar_insert_bit ( mask,  b, 0 )==zeros ); FD_TEST( fd_uchar_insert_bit ( mask,  b, 1 )==mask  );
      FD_TEST( fd_uchar_insert_bit ( maskc, b, 0 )==maskc ); FD_TEST( fd_uchar_insert_bit ( maskc, b, 1 )==ones  );
      FD_TEST( fd_uchar_insert_bit ( ones,  b, 0 )==maskc ); FD_TEST( fd_uchar_insert_bit ( ones,  b, 1 )==ones  );
    }
    for( int n=0; n<=w; n++ ) {
      uchar mask  = (uchar)(((n<w) ? (1UL<<n) : 0UL)-1UL);
      uchar maskc = (uchar)~mask;
      FD_TEST( fd_uchar_mask_lsb   ( n               )==mask  );
      FD_TEST( fd_uchar_clear_lsb  ( zeros, n        )==zeros ); FD_TEST( fd_uchar_set_lsb    ( zeros, n       )==mask  );
      FD_TEST( fd_uchar_clear_lsb  ( mask,  n        )==zeros ); FD_TEST( fd_uchar_set_lsb    ( mask,  n       )==mask  );
      FD_TEST( fd_uchar_clear_lsb  ( maskc, n        )==maskc ); FD_TEST( fd_uchar_set_lsb    ( maskc, n       )==ones  );
      FD_TEST( fd_uchar_clear_lsb  ( ones,  n        )==maskc ); FD_TEST( fd_uchar_set_lsb    ( ones,  n       )==ones  );
      FD_TEST( fd_uchar_flip_lsb   ( zeros, n        )==mask  ); FD_TEST( fd_uchar_extract_lsb( zeros, n       )==zeros );
      FD_TEST( fd_uchar_flip_lsb   ( mask,  n        )==zeros ); FD_TEST( fd_uchar_extract_lsb( mask,  n       )==mask  );
      FD_TEST( fd_uchar_flip_lsb   ( maskc, n        )==ones  ); FD_TEST( fd_uchar_extract_lsb( maskc, n       )==zeros );
      FD_TEST( fd_uchar_flip_lsb   ( ones,  n        )==maskc ); FD_TEST( fd_uchar_extract_lsb( ones,  n       )==mask  );
      FD_TEST( fd_uchar_insert_lsb ( zeros, n, zeros )==zeros ); FD_TEST( fd_uchar_insert_lsb ( zeros, n, mask )==mask  );
      FD_TEST( fd_uchar_insert_lsb ( mask,  n, zeros )==zeros ); FD_TEST( fd_uchar_insert_lsb ( mask,  n, mask )==mask  );
      FD_TEST( fd_uchar_insert_lsb ( maskc, n, zeros )==maskc ); FD_TEST( fd_uchar_insert_lsb ( maskc, n, mask )==ones  );
      FD_TEST( fd_uchar_insert_lsb ( ones,  n, zeros )==maskc ); FD_TEST( fd_uchar_insert_lsb ( ones,  n, mask )==ones  );
    }
    for( int h=0; h< w; h++ ) {
      for( int l=0; l<=h; l++ ) {
        uchar x     = fd_uchar_mask_lsb( h-l+1 );
        uchar mask  = (uchar)(x << l);
        uchar maskc = (uchar)~mask;
        FD_TEST( fd_uchar_mask   ( l,h               )==mask  );
        FD_TEST( fd_uchar_clear  ( zeros, l,h        )==zeros ); FD_TEST( fd_uchar_set    ( zeros, l,h    )==mask  );
        FD_TEST( fd_uchar_clear  ( mask,  l,h        )==zeros ); FD_TEST( fd_uchar_set    ( mask,  l,h    )==mask  );
        FD_TEST( fd_uchar_clear  ( maskc, l,h        )==maskc ); FD_TEST( fd_uchar_set    ( maskc, l,h    )==ones  );
        FD_TEST( fd_uchar_clear  ( ones,  l,h        )==maskc ); FD_TEST( fd_uchar_set    ( ones,  l,h    )==ones  );
        FD_TEST( fd_uchar_flip   ( zeros, l,h        )==mask  ); FD_TEST( fd_uchar_extract( zeros, l,h    )==zeros );
        FD_TEST( fd_uchar_flip   ( mask,  l,h        )==zeros ); FD_TEST( fd_uchar_extract( mask,  l,h    )==x     );
        FD_TEST( fd_uchar_flip   ( maskc, l,h        )==ones  ); FD_TEST( fd_uchar_extract( maskc, l,h    )==zeros );
        FD_TEST( fd_uchar_flip   ( ones,  l,h        )==maskc ); FD_TEST( fd_uchar_extract( ones,  l,h    )==x     );
        FD_TEST( fd_uchar_insert ( zeros, l,h, zeros )==zeros ); FD_TEST( fd_uchar_insert ( zeros, l,h, x )==mask  );
        FD_TEST( fd_uchar_insert ( mask,  l,h, zeros )==zeros ); FD_TEST( fd_uchar_insert ( mask,  l,h, x )==mask  );
        FD_TEST( fd_uchar_insert ( maskc, l,h, zeros )==maskc ); FD_TEST( fd_uchar_insert ( maskc, l,h, x )==ones  );
        FD_TEST( fd_uchar_insert ( ones,  l,h, zeros )==maskc ); FD_TEST( fd_uchar_insert ( ones,  l,h, x )==ones  );
      }
    }
    FD_TEST( fd_uchar_popcnt  ( zeros )==0        ); FD_TEST( fd_uchar_popcnt  ( ones  )==w        );
    FD_TEST( fd_uchar_find_lsb          ( ones      )==0    );
    FD_TEST( fd_uchar_find_lsb_w_default( ones , -1 )==0    );
    FD_TEST( fd_uchar_find_lsb_w_default( zeros, -1 )==-1   );
    FD_TEST( fd_uchar_find_msb          ( ones      )==(w-1));
    FD_TEST( fd_uchar_find_msb_w_default( ones , -1 )==(w-1));
    FD_TEST( fd_uchar_find_msb_w_default( zeros, -1 )==-1   );
    FD_TEST( fd_uchar_pow2_up ( zeros )==(uchar)0 ); FD_TEST( fd_uchar_pow2_up ( ones  )==(uchar)0          );
    FD_TEST( fd_uchar_pow2_dn ( zeros )==(uchar)1 ); FD_TEST( fd_uchar_pow2_dn ( ones  )==(uchar)(1<<(w-1)) );
    for( int i=1; i<w; i++ ) {
      uchar x = (uchar)(1UL<<i);
      FD_TEST( fd_uchar_pop_lsb ( x )==zeros );
      FD_TEST( fd_uchar_popcnt  ( x )==1     ); FD_TEST( fd_uchar_popcnt  ( (uchar)~x )==w-1 );
      FD_TEST( fd_uchar_find_lsb( x )==i     ); FD_TEST( fd_uchar_find_msb( x )==i );
      FD_TEST( fd_uchar_find_lsb_w_default( x , -1 )==i );
      FD_TEST( fd_uchar_find_msb_w_default( x , -1 )==i );
      FD_TEST( fd_uchar_pow2_up ( x )==x     );
      FD_TEST( fd_uchar_pow2_dn ( x )==x     );
      for( int j=0; j<i; j++ ) {
        uchar y = (uchar)(1UL<<j);
        uchar z = (uchar)(x|y);
        FD_TEST( fd_uchar_pop_lsb ( z )==x             );
        FD_TEST( fd_uchar_popcnt  ( z )==2             ); FD_TEST( fd_uchar_popcnt  ( (uchar)~z )==w-2 );
        FD_TEST( fd_uchar_find_lsb( z )==j             ); FD_TEST( fd_uchar_find_msb( z )==i );
        FD_TEST( fd_uchar_find_lsb_w_default( z , -1 )==j );
        FD_TEST( fd_uchar_find_msb_w_default( z , -1 )==i );
        FD_TEST( fd_uchar_pow2_up ( z )==(uchar)(x<<1) );
        FD_TEST( fd_uchar_pow2_dn ( z )==(uchar) x     );
      }
    }
    for( int n=0; n<=w; n++ ) {
      uchar x = (uchar)((n==w)? 0U : (1U<<n )); int sl = n+(w-8)-((n>>3)<<4);
      uchar y = (uchar)((n==w)? 0U : (1U<<sl)); FD_TEST( fd_uchar_bswap( x )==y );
    }
    for( int i=0; i<w; i++ ) {
      uchar align = (uchar) (1UL<<i);
      uchar lo    = (uchar)((1UL<<i)-1UL);
      uchar hi    = (uchar)~lo;
      FD_TEST( fd_uchar_is_aligned( zeros, align )        );
      FD_TEST( fd_uchar_alignment ( zeros, align )==zeros );
      FD_TEST( fd_uchar_align_dn  ( zeros, align )==zeros );
      FD_TEST( fd_uchar_align_up  ( zeros, align )==zeros );
      FD_TEST( fd_uchar_is_aligned( ones,  align )==(!i)  );
      FD_TEST( fd_uchar_alignment ( ones,  align )==lo    );
      FD_TEST( fd_uchar_align_dn  ( ones,  align )==hi    );
      FD_TEST( fd_uchar_align_up  ( ones,  align )==((!i) ? ones : zeros) );
      for( int j=0; j<w; j++ ) {
        uchar x = (uchar)(1UL<<j);
        FD_TEST( fd_uchar_is_aligned( x, align )==(j>=i)        );
        FD_TEST( fd_uchar_alignment ( x, align )==( x     & lo) );
        FD_TEST( fd_uchar_align_dn  ( x, align )==( x     & hi) );
        FD_TEST( fd_uchar_align_up  ( x, align )==((x+lo) & hi) );
      }
    }
    for( int iter=0; iter<16777216; iter++ ) {
      uchar m = (uchar)fd_rng_ulong( rng );
      uchar x = (uchar)fd_rng_ulong( rng );
      uchar y = (uchar)fd_rng_ulong( rng );
      int   c = fd_uchar_extract_bit( m, 0 );
      FD_TEST( fd_uchar_blend( m, x, y )==(uchar)( (x & m) | (y & ~m) ) );
      FD_TEST( fd_uchar_if   ( c, x, y )==(c ? x : y)                   );
      FD_TEST( fd_uchar_abs  ( x       )==x                             );
      FD_TEST( fd_uchar_min  ( x, y    )==((x<y) ? x : y)               );
      FD_TEST( fd_uchar_max  ( x, y    )==((x>y) ? x : y)               );

      uchar z = x; fd_uchar_store_if( c, &z, y ); FD_TEST( z==(c ? y : x) );

      uchar xx; uchar yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );

      int n = (int)fd_rng_uint( rng );
      int s = n & 15;
      FD_TEST( fd_uchar_shift_left  ( x, s )==((s>7) ? ((uchar)0) : (uchar)(x<<s)) );
      FD_TEST( fd_uchar_shift_right ( x, s )==((s>7) ? ((uchar)0) : (uchar)(x>>s)) );
      FD_TEST( fd_uchar_rotate_left ( x, n )==(uchar)((x<<(n&7))|(x>>((-n)&7))) );
      FD_TEST( fd_uchar_rotate_right( x, n )==(uchar)((x>>(n&7))|(x<<((-n)&7))) );
    }
  }

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing ushort" ));
    int    w     = 16;
    ushort zeros = (ushort) 0UL;
    ushort ones  = (ushort)~0UL;
    for( int n=0; n< w; n++ ) {
      ushort x = (ushort)(1UL<<n);
      FD_TEST( fd_ushort_is_pow2( x ) );
      FD_TEST( !fd_ushort_is_pow2( (ushort)~x ) );
    }
    for( int n=0; n<=w; n++ ) { ushort x = (ushort)((n<w) ? (1UL<<n) : 0UL); FD_TEST( fd_ushort_pow2( n )==x ); }
    for( int b=0; b< w; b++ ) {
      ushort mask  = (ushort)(1UL<<b);
      ushort maskc = (ushort)~mask;
      FD_TEST( fd_ushort_mask_bit   ( b           )==mask  );
      FD_TEST( fd_ushort_clear_bit  ( zeros, b    )==zeros ); FD_TEST( fd_ushort_set_bit    ( zeros, b    )==mask  );
      FD_TEST( fd_ushort_clear_bit  ( mask,  b    )==zeros ); FD_TEST( fd_ushort_set_bit    ( mask,  b    )==mask  );
      FD_TEST( fd_ushort_clear_bit  ( maskc, b    )==maskc ); FD_TEST( fd_ushort_set_bit    ( maskc, b    )==ones  );
      FD_TEST( fd_ushort_clear_bit  ( ones,  b    )==maskc ); FD_TEST( fd_ushort_set_bit    ( ones,  b    )==ones  );
      FD_TEST( fd_ushort_flip_bit   ( zeros, b    )==mask  ); FD_TEST( fd_ushort_extract_bit( zeros, b    )==0     );
      FD_TEST( fd_ushort_flip_bit   ( mask,  b    )==zeros ); FD_TEST( fd_ushort_extract_bit( mask,  b    )==1     );
      FD_TEST( fd_ushort_flip_bit   ( maskc, b    )==ones  ); FD_TEST( fd_ushort_extract_bit( maskc, b    )==0     );
      FD_TEST( fd_ushort_flip_bit   ( ones,  b    )==maskc ); FD_TEST( fd_ushort_extract_bit( ones,  b    )==1     );
      FD_TEST( fd_ushort_insert_bit ( zeros, b, 0 )==zeros ); FD_TEST( fd_ushort_insert_bit ( zeros, b, 1 )==mask  );
      FD_TEST( fd_ushort_insert_bit ( mask,  b, 0 )==zeros ); FD_TEST( fd_ushort_insert_bit ( mask,  b, 1 )==mask  );
      FD_TEST( fd_ushort_insert_bit ( maskc, b, 0 )==maskc ); FD_TEST( fd_ushort_insert_bit ( maskc, b, 1 )==ones  );
      FD_TEST( fd_ushort_insert_bit ( ones,  b, 0 )==maskc ); FD_TEST( fd_ushort_insert_bit ( ones,  b, 1 )==ones  );
    }
    for( int n=0; n<=w; n++ ) {
      ushort mask  = (ushort)(((n<w) ? (1UL<<n) : 0UL)-1UL);
      ushort maskc = (ushort)~mask;
      FD_TEST( fd_ushort_mask_lsb   ( n               )==mask  );
      FD_TEST( fd_ushort_clear_lsb  ( zeros, n        )==zeros ); FD_TEST( fd_ushort_set_lsb    ( zeros, n       )==mask  );
      FD_TEST( fd_ushort_clear_lsb  ( mask,  n        )==zeros ); FD_TEST( fd_ushort_set_lsb    ( mask,  n       )==mask  );
      FD_TEST( fd_ushort_clear_lsb  ( maskc, n        )==maskc ); FD_TEST( fd_ushort_set_lsb    ( maskc, n       )==ones  );
      FD_TEST( fd_ushort_clear_lsb  ( ones,  n        )==maskc ); FD_TEST( fd_ushort_set_lsb    ( ones,  n       )==ones  );
      FD_TEST( fd_ushort_flip_lsb   ( zeros, n        )==mask  ); FD_TEST( fd_ushort_extract_lsb( zeros, n       )==zeros );
      FD_TEST( fd_ushort_flip_lsb   ( mask,  n        )==zeros ); FD_TEST( fd_ushort_extract_lsb( mask,  n       )==mask  );
      FD_TEST( fd_ushort_flip_lsb   ( maskc, n        )==ones  ); FD_TEST( fd_ushort_extract_lsb( maskc, n       )==zeros );
      FD_TEST( fd_ushort_flip_lsb   ( ones,  n        )==maskc ); FD_TEST( fd_ushort_extract_lsb( ones,  n       )==mask  );
      FD_TEST( fd_ushort_insert_lsb ( zeros, n, zeros )==zeros ); FD_TEST( fd_ushort_insert_lsb ( zeros, n, mask )==mask  );
      FD_TEST( fd_ushort_insert_lsb ( mask,  n, zeros )==zeros ); FD_TEST( fd_ushort_insert_lsb ( mask,  n, mask )==mask  );
      FD_TEST( fd_ushort_insert_lsb ( maskc, n, zeros )==maskc ); FD_TEST( fd_ushort_insert_lsb ( maskc, n, mask )==ones  );
      FD_TEST( fd_ushort_insert_lsb ( ones,  n, zeros )==maskc ); FD_TEST( fd_ushort_insert_lsb ( ones,  n, mask )==ones  );
    }
    for( int h=0; h< w; h++ ) {
      for( int l=0; l<=h; l++ ) {
        ushort x     = fd_ushort_mask_lsb( h-l+1 );
        ushort mask  = (ushort)(x << l);
        ushort maskc = (ushort)~mask;
        FD_TEST( fd_ushort_mask   ( l,h               )==mask  );
        FD_TEST( fd_ushort_clear  ( zeros, l,h        )==zeros ); FD_TEST( fd_ushort_set    ( zeros, l,h    )==mask  );
        FD_TEST( fd_ushort_clear  ( mask,  l,h        )==zeros ); FD_TEST( fd_ushort_set    ( mask,  l,h    )==mask  );
        FD_TEST( fd_ushort_clear  ( maskc, l,h        )==maskc ); FD_TEST( fd_ushort_set    ( maskc, l,h    )==ones  );
        FD_TEST( fd_ushort_clear  ( ones,  l,h        )==maskc ); FD_TEST( fd_ushort_set    ( ones,  l,h    )==ones  );
        FD_TEST( fd_ushort_flip   ( zeros, l,h        )==mask  ); FD_TEST( fd_ushort_extract( zeros, l,h    )==zeros );
        FD_TEST( fd_ushort_flip   ( mask,  l,h        )==zeros ); FD_TEST( fd_ushort_extract( mask,  l,h    )==x     );
        FD_TEST( fd_ushort_flip   ( maskc, l,h        )==ones  ); FD_TEST( fd_ushort_extract( maskc, l,h    )==zeros );
        FD_TEST( fd_ushort_flip   ( ones,  l,h        )==maskc ); FD_TEST( fd_ushort_extract( ones,  l,h    )==x     );
        FD_TEST( fd_ushort_insert ( zeros, l,h, zeros )==zeros ); FD_TEST( fd_ushort_insert ( zeros, l,h, x )==mask  );
        FD_TEST( fd_ushort_insert ( mask,  l,h, zeros )==zeros ); FD_TEST( fd_ushort_insert ( mask,  l,h, x )==mask  );
        FD_TEST( fd_ushort_insert ( maskc, l,h, zeros )==maskc ); FD_TEST( fd_ushort_insert ( maskc, l,h, x )==ones  );
        FD_TEST( fd_ushort_insert ( ones,  l,h, zeros )==maskc ); FD_TEST( fd_ushort_insert ( ones,  l,h, x )==ones  );
      }
    }
    FD_TEST( fd_ushort_popcnt  ( zeros )==0         ); FD_TEST( fd_ushort_popcnt  ( ones )==w         );
    FD_TEST( fd_ushort_find_lsb          ( ones      )==0    );
    FD_TEST( fd_ushort_find_lsb_w_default( ones , -1 )==0    );
    FD_TEST( fd_ushort_find_lsb_w_default( zeros, -1 )==-1   );
    FD_TEST( fd_ushort_find_msb          ( ones      )==(w-1));
    FD_TEST( fd_ushort_find_msb_w_default( ones , -1 )==(w-1));
    FD_TEST( fd_ushort_find_msb_w_default( zeros, -1 )==-1   );
    FD_TEST( fd_ushort_pow2_up ( zeros )==(ushort)0 ); FD_TEST( fd_ushort_pow2_up ( ones )==(ushort)0          );
    FD_TEST( fd_ushort_pow2_dn ( zeros )==(ushort)1 ); FD_TEST( fd_ushort_pow2_dn ( ones )==(ushort)(1<<(w-1)) );
    for( int i=1; i<w; i++ ) {
      ushort x = (ushort)(1UL<<i);
      FD_TEST( fd_ushort_pop_lsb ( x )==zeros );
      FD_TEST( fd_ushort_popcnt  ( x )==1     ); FD_TEST( fd_ushort_popcnt  ( (ushort)~x )==w-1 );
      FD_TEST( fd_ushort_find_lsb( x )==i     ); FD_TEST( fd_ushort_find_msb( x )==i );
      FD_TEST( fd_ushort_find_lsb_w_default( x , -1 )==i );
      FD_TEST( fd_ushort_find_msb_w_default( x , -1 )==i );
      FD_TEST( fd_ushort_pow2_up ( x )==x     );
      FD_TEST( fd_ushort_pow2_dn ( x )==x     );
      for( int j=0; j<i; j++ ) {
        ushort y = (ushort)(1UL<<j);
        ushort z = (ushort)(x|y);
        FD_TEST( fd_ushort_pop_lsb ( z )==x              );
        FD_TEST( fd_ushort_popcnt  ( z )==2              ); FD_TEST( fd_ushort_popcnt  ( (ushort)~z )==w-2 );
        FD_TEST( fd_ushort_find_lsb( z )==j              ); FD_TEST( fd_ushort_find_msb( z )==i );
        FD_TEST( fd_ushort_find_lsb_w_default( z , -1 )==j );
        FD_TEST( fd_ushort_find_msb_w_default( z , -1 )==i );
        FD_TEST( fd_ushort_pow2_up ( z )==(ushort)(x<<1) );
        FD_TEST( fd_ushort_pow2_dn ( z )==(ushort) x     );
      }
    }
    for( int n=0; n<=w; n++ ) { 
      ushort x = (ushort)((n==w)? 0U : (1U<<n )); int sl = n+(w-8)-((n>>3)<<4); 
      ushort y = (ushort)((n==w)? 0U : (1U<<sl)); FD_TEST( fd_ushort_bswap( x )==y );
    } 
    for( int i=0; i<w; i++ ) {
      ushort align = (ushort) (1UL<<i);
      ushort lo    = (ushort)((1UL<<i)-1UL);
      ushort hi    = (ushort)~lo;
      FD_TEST( fd_ushort_is_aligned( zeros, align )        );
      FD_TEST( fd_ushort_alignment ( zeros, align )==zeros );
      FD_TEST( fd_ushort_align_dn  ( zeros, align )==zeros );
      FD_TEST( fd_ushort_align_up  ( zeros, align )==zeros );
      FD_TEST( fd_ushort_is_aligned( ones,  align )==(!i)  );
      FD_TEST( fd_ushort_alignment ( ones,  align )==lo    );
      FD_TEST( fd_ushort_align_dn  ( ones,  align )==hi    );
      FD_TEST( fd_ushort_align_up  ( ones,  align )==((!i) ? ones : zeros) );
      for( int j=0; j<w; j++ ) {
        ushort x = (ushort)(1UL<<j);
        FD_TEST( fd_ushort_is_aligned( x, align )==(j>=i)        );
        FD_TEST( fd_ushort_alignment ( x, align )==( x     & lo) );
        FD_TEST( fd_ushort_align_dn  ( x, align )==( x     & hi) );
        FD_TEST( fd_ushort_align_up  ( x, align )==((x+lo) & hi) );
      }
    }
    for( int iter=0; iter<16777216; iter++ ) {
      ushort m = (ushort)fd_rng_ulong( rng );
      ushort x = (ushort)fd_rng_ulong( rng );
      ushort y = (ushort)fd_rng_ulong( rng );
      int    c = fd_ushort_extract_bit( m, 0 );
      FD_TEST( fd_ushort_blend( m, x, y )==(ushort)( (x & m) | (y & ~m) ) );
      FD_TEST( fd_ushort_if   ( c, x, y )==(c ? x : y)                   );
      FD_TEST( fd_ushort_abs  ( x       )==x                             );
      FD_TEST( fd_ushort_min  ( x, y    )==((x<y) ? x : y)               );
      FD_TEST( fd_ushort_max  ( x, y    )==((x>y) ? x : y)               );

      ushort z = x; fd_ushort_store_if( c, &z, y ); FD_TEST( z==(c ? y : x) );

      ushort xx; ushort yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );

      int n = (int)fd_rng_uint( rng );
      int s = n & 31;
      FD_TEST( fd_ushort_shift_left  ( x, s )==((s>15) ? ((ushort)0) : (ushort)(x<<s)) );
      FD_TEST( fd_ushort_shift_right ( x, s )==((s>15) ? ((ushort)0) : (ushort)(x>>s)) );
      FD_TEST( fd_ushort_rotate_left ( x, n )==(ushort)((x<<(n&15))|(x>>((-n)&15))) );
      FD_TEST( fd_ushort_rotate_right( x, n )==(ushort)((x>>(n&15))|(x<<((-n)&15))) );
    }
  }

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing uint" ));
    int  w     = 32;
    uint zeros = (uint) 0UL;
    uint ones  = (uint)~0UL;
    for( int n=0; n< w; n++ ) {
      uint x = (uint)(1UL<<n);
      FD_TEST( fd_uint_is_pow2( x ) );
      FD_TEST( !fd_uint_is_pow2( (uint)~x ) );
    }
    for( int n=0; n<=w; n++ ) { uint x = (uint)((n<w) ? (1UL<<n) : 0UL); FD_TEST( fd_uint_pow2( n )==x ); }
    for( int b=0; b< w; b++ ) {
      uint mask  = (uint)(1UL<<b);
      uint maskc = (uint)~mask;
      FD_TEST( fd_uint_mask_bit   ( b           )==mask  );
      FD_TEST( fd_uint_clear_bit  ( zeros, b    )==zeros ); FD_TEST( fd_uint_set_bit    ( zeros, b    )==mask  );
      FD_TEST( fd_uint_clear_bit  ( mask,  b    )==zeros ); FD_TEST( fd_uint_set_bit    ( mask,  b    )==mask  );
      FD_TEST( fd_uint_clear_bit  ( maskc, b    )==maskc ); FD_TEST( fd_uint_set_bit    ( maskc, b    )==ones  );
      FD_TEST( fd_uint_clear_bit  ( ones,  b    )==maskc ); FD_TEST( fd_uint_set_bit    ( ones,  b    )==ones  );
      FD_TEST( fd_uint_flip_bit   ( zeros, b    )==mask  ); FD_TEST( fd_uint_extract_bit( zeros, b    )==0     );
      FD_TEST( fd_uint_flip_bit   ( mask,  b    )==zeros ); FD_TEST( fd_uint_extract_bit( mask,  b    )==1     );
      FD_TEST( fd_uint_flip_bit   ( maskc, b    )==ones  ); FD_TEST( fd_uint_extract_bit( maskc, b    )==0     );
      FD_TEST( fd_uint_flip_bit   ( ones,  b    )==maskc ); FD_TEST( fd_uint_extract_bit( ones,  b    )==1     );
      FD_TEST( fd_uint_insert_bit ( zeros, b, 0 )==zeros ); FD_TEST( fd_uint_insert_bit ( zeros, b, 1 )==mask  );
      FD_TEST( fd_uint_insert_bit ( mask,  b, 0 )==zeros ); FD_TEST( fd_uint_insert_bit ( mask,  b, 1 )==mask  );
      FD_TEST( fd_uint_insert_bit ( maskc, b, 0 )==maskc ); FD_TEST( fd_uint_insert_bit ( maskc, b, 1 )==ones  );
      FD_TEST( fd_uint_insert_bit ( ones,  b, 0 )==maskc ); FD_TEST( fd_uint_insert_bit ( ones,  b, 1 )==ones  );
    }
    for( int n=0; n<=w; n++ ) {
      uint mask  = (uint)(((n<w) ? (1UL<<n) : 0UL)-1UL);
      uint maskc = (uint)~mask;
      FD_TEST( fd_uint_mask_lsb   ( n               )==mask  );
      FD_TEST( fd_uint_clear_lsb  ( zeros, n        )==zeros ); FD_TEST( fd_uint_set_lsb    ( zeros, n       )==mask  );
      FD_TEST( fd_uint_clear_lsb  ( mask,  n        )==zeros ); FD_TEST( fd_uint_set_lsb    ( mask,  n       )==mask  );
      FD_TEST( fd_uint_clear_lsb  ( maskc, n        )==maskc ); FD_TEST( fd_uint_set_lsb    ( maskc, n       )==ones  );
      FD_TEST( fd_uint_clear_lsb  ( ones,  n        )==maskc ); FD_TEST( fd_uint_set_lsb    ( ones,  n       )==ones  );
      FD_TEST( fd_uint_flip_lsb   ( zeros, n        )==mask  ); FD_TEST( fd_uint_extract_lsb( zeros, n       )==zeros );
      FD_TEST( fd_uint_flip_lsb   ( mask,  n        )==zeros ); FD_TEST( fd_uint_extract_lsb( mask,  n       )==mask  );
      FD_TEST( fd_uint_flip_lsb   ( maskc, n        )==ones  ); FD_TEST( fd_uint_extract_lsb( maskc, n       )==zeros );
      FD_TEST( fd_uint_flip_lsb   ( ones,  n        )==maskc ); FD_TEST( fd_uint_extract_lsb( ones,  n       )==mask  );
      FD_TEST( fd_uint_insert_lsb ( zeros, n, zeros )==zeros ); FD_TEST( fd_uint_insert_lsb ( zeros, n, mask )==mask  );
      FD_TEST( fd_uint_insert_lsb ( mask,  n, zeros )==zeros ); FD_TEST( fd_uint_insert_lsb ( mask,  n, mask )==mask  );
      FD_TEST( fd_uint_insert_lsb ( maskc, n, zeros )==maskc ); FD_TEST( fd_uint_insert_lsb ( maskc, n, mask )==ones  );
      FD_TEST( fd_uint_insert_lsb ( ones,  n, zeros )==maskc ); FD_TEST( fd_uint_insert_lsb ( ones,  n, mask )==ones  );
    }
    for( int h=0; h< w; h++ ) {
      for( int l=0; l<=h; l++ ) {
        uint x     = fd_uint_mask_lsb( h-l+1 );
        uint mask  = (uint)(x << l);
        uint maskc = (uint)~mask;
        FD_TEST( fd_uint_mask   ( l,h               )==mask  );
        FD_TEST( fd_uint_clear  ( zeros, l,h        )==zeros ); FD_TEST( fd_uint_set    ( zeros, l,h    )==mask  );
        FD_TEST( fd_uint_clear  ( mask,  l,h        )==zeros ); FD_TEST( fd_uint_set    ( mask,  l,h    )==mask  );
        FD_TEST( fd_uint_clear  ( maskc, l,h        )==maskc ); FD_TEST( fd_uint_set    ( maskc, l,h    )==ones  );
        FD_TEST( fd_uint_clear  ( ones,  l,h        )==maskc ); FD_TEST( fd_uint_set    ( ones,  l,h    )==ones  );
        FD_TEST( fd_uint_flip   ( zeros, l,h        )==mask  ); FD_TEST( fd_uint_extract( zeros, l,h    )==zeros );
        FD_TEST( fd_uint_flip   ( mask,  l,h        )==zeros ); FD_TEST( fd_uint_extract( mask,  l,h    )==x     );
        FD_TEST( fd_uint_flip   ( maskc, l,h        )==ones  ); FD_TEST( fd_uint_extract( maskc, l,h    )==zeros );
        FD_TEST( fd_uint_flip   ( ones,  l,h        )==maskc ); FD_TEST( fd_uint_extract( ones,  l,h    )==x     );
        FD_TEST( fd_uint_insert ( zeros, l,h, zeros )==zeros ); FD_TEST( fd_uint_insert ( zeros, l,h, x )==mask  );
        FD_TEST( fd_uint_insert ( mask,  l,h, zeros )==zeros ); FD_TEST( fd_uint_insert ( mask,  l,h, x )==mask  );
        FD_TEST( fd_uint_insert ( maskc, l,h, zeros )==maskc ); FD_TEST( fd_uint_insert ( maskc, l,h, x )==ones  );
        FD_TEST( fd_uint_insert ( ones,  l,h, zeros )==maskc ); FD_TEST( fd_uint_insert ( ones,  l,h, x )==ones  );
      }
    }
    FD_TEST( fd_uint_popcnt  ( zeros )==0       ); FD_TEST( fd_uint_popcnt  ( ones  )==w       );
    FD_TEST( fd_uint_find_lsb          ( ones      )==0    );
    FD_TEST( fd_uint_find_lsb_w_default( ones , -1 )==0    );
    FD_TEST( fd_uint_find_lsb_w_default( zeros, -1 )==-1   );
    FD_TEST( fd_uint_find_msb          ( ones      )==(w-1));
    FD_TEST( fd_uint_find_msb_w_default( ones , -1 )==(w-1));
    FD_TEST( fd_uint_find_msb_w_default( zeros, -1 )==-1   );
    FD_TEST( fd_uint_pow2_up ( zeros )==0U ); FD_TEST( fd_uint_pow2_up ( ones  )==0U          );
    FD_TEST( fd_uint_pow2_dn ( zeros )==1U ); FD_TEST( fd_uint_pow2_dn ( ones  )==(1U<<(w-1)) );
    for( int i=1; i<w; i++ ) {
      uint x = (uint)(1UL<<i);
      FD_TEST( fd_uint_pop_lsb ( x )==zeros );
      FD_TEST( fd_uint_popcnt  ( x )==1     ); FD_TEST( fd_uint_popcnt  ( (uint)~x )==w-1 );
      FD_TEST( fd_uint_find_lsb( x )==i     ); FD_TEST( fd_uint_find_msb( x )==i );
      FD_TEST( fd_uint_find_lsb_w_default( x , -1 )==i );
      FD_TEST( fd_uint_find_msb_w_default( x , -1 )==i );
      FD_TEST( fd_uint_pow2_up ( x )==x     );
      FD_TEST( fd_uint_pow2_dn ( x )==x     );
      for( int j=0; j<i; j++ ) {
        uint y = (uint)(1UL<<j);
        uint z = (uint)(x|y);
        FD_TEST( fd_uint_pop_lsb ( z )==x      );
        FD_TEST( fd_uint_popcnt  ( z )==2      ); FD_TEST( fd_uint_popcnt  ( (uint)~z )==w-2 );
        FD_TEST( fd_uint_find_lsb( z )==j      ); FD_TEST( fd_uint_find_msb( z )==i );
        FD_TEST( fd_uint_find_lsb_w_default( z , -1 )==j );
        FD_TEST( fd_uint_find_msb_w_default( z , -1 )==i );
        FD_TEST( fd_uint_pow2_up ( z )==(x<<1) );
        FD_TEST( fd_uint_pow2_dn ( z )== x     );
      }
    }
    for( int n=0; n<=w; n++ ) {  
      uint x = (uint)((n==w)? 0U : (1U<<n )); int sl = n+(w-8)-((n>>3)<<4);
      uint y = (uint)((n==w)? 0U : (1U<<sl)); FD_TEST( fd_uint_bswap( x )==y );
    } 
    for( int i=0; i<w; i++ ) {
      uint align = (uint) (1UL<<i);
      uint lo    = (uint)((1UL<<i)-1UL);
      uint hi    = (uint)~lo;
      FD_TEST( fd_uint_is_aligned( zeros, align )        );
      FD_TEST( fd_uint_alignment ( zeros, align )==zeros );
      FD_TEST( fd_uint_align_dn  ( zeros, align )==zeros );
      FD_TEST( fd_uint_align_up  ( zeros, align )==zeros );
      FD_TEST( fd_uint_is_aligned( ones,  align )==(!i)  );
      FD_TEST( fd_uint_alignment ( ones,  align )==lo    );
      FD_TEST( fd_uint_align_dn  ( ones,  align )==hi    );
      FD_TEST( fd_uint_align_up  ( ones,  align )==((!i) ? ones : zeros) );
      for( int j=0; j<w; j++ ) {
        uint x = (uint)(1UL<<j);
        FD_TEST( fd_uint_is_aligned( x, align )==(j>=i)        );
        FD_TEST( fd_uint_alignment ( x, align )==( x     & lo) );
        FD_TEST( fd_uint_align_dn  ( x, align )==( x     & hi) );
        FD_TEST( fd_uint_align_up  ( x, align )==((x+lo) & hi) );
      }
    }
    for( int iter=0; iter<16777216; iter++ ) {
      uint m = (uint)fd_rng_ulong( rng );
      uint x = (uint)fd_rng_ulong( rng );
      uint y = (uint)fd_rng_ulong( rng );
      int  c = fd_uint_extract_bit( m, 0 );
      FD_TEST( fd_uint_blend( m, x, y )==(uint)( (x & m) | (y & ~m) )  );
      FD_TEST( fd_uint_if   ( c, x, y )==(c ? x : y)                   );
      FD_TEST( fd_uint_abs  ( x       )==x                             );
      FD_TEST( fd_uint_min  ( x, y    )==((x<y) ? x : y)               );
      FD_TEST( fd_uint_max  ( x, y    )==((x>y) ? x : y)               );

      uint z = x; fd_uint_store_if( c, &z, y ); FD_TEST( z==(c ? y : x) );

      uint xx; uint yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );

      int n = (int)y;
      int s = n & 63;
      FD_TEST( fd_uint_shift_left  ( x, s )==((s>31) ? 0U : (uint)(x<<s)) );
      FD_TEST( fd_uint_shift_right ( x, s )==((s>31) ? 0U : (uint)(x>>s)) );
      FD_TEST( fd_uint_rotate_left ( x, n )==((x<<(n&31))|(x>>((-n)&31))) );
      FD_TEST( fd_uint_rotate_right( x, n )==((x>>(n&31))|(x<<((-n)&31))) );
    }
  }

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing ulong" ));
    int   w     = 64;
    ulong zeros = (ulong) 0UL;
    ulong ones  = (ulong)~0UL;
    for( int n=0; n< w; n++ ) {
      ulong x = (ulong)(1UL<<n);
      FD_TEST( fd_ulong_is_pow2( x ) );
      FD_TEST( !fd_ulong_is_pow2( (ulong)~x ) );
    }
    for( int n=0; n<=w; n++ ) { ulong x = (ulong)((n<w) ? (1UL<<n) : 0UL); FD_TEST( fd_ulong_pow2( n )==x ); }
    for( int b=0; b< w; b++ ) {
      ulong mask  = (ulong)(1UL<<b);
      ulong maskc = (ulong)~mask;
      FD_TEST( fd_ulong_mask_bit   ( b           )==mask  );
      FD_TEST( fd_ulong_clear_bit  ( zeros, b    )==zeros ); FD_TEST( fd_ulong_set_bit    ( zeros, b    )==mask  );
      FD_TEST( fd_ulong_clear_bit  ( mask,  b    )==zeros ); FD_TEST( fd_ulong_set_bit    ( mask,  b    )==mask  );
      FD_TEST( fd_ulong_clear_bit  ( maskc, b    )==maskc ); FD_TEST( fd_ulong_set_bit    ( maskc, b    )==ones  );
      FD_TEST( fd_ulong_clear_bit  ( ones,  b    )==maskc ); FD_TEST( fd_ulong_set_bit    ( ones,  b    )==ones  );
      FD_TEST( fd_ulong_flip_bit   ( zeros, b    )==mask  ); FD_TEST( fd_ulong_extract_bit( zeros, b    )==0     );
      FD_TEST( fd_ulong_flip_bit   ( mask,  b    )==zeros ); FD_TEST( fd_ulong_extract_bit( mask,  b    )==1     );
      FD_TEST( fd_ulong_flip_bit   ( maskc, b    )==ones  ); FD_TEST( fd_ulong_extract_bit( maskc, b    )==0     );
      FD_TEST( fd_ulong_flip_bit   ( ones,  b    )==maskc ); FD_TEST( fd_ulong_extract_bit( ones,  b    )==1     );
      FD_TEST( fd_ulong_insert_bit ( zeros, b, 0 )==zeros ); FD_TEST( fd_ulong_insert_bit ( zeros, b, 1 )==mask  );
      FD_TEST( fd_ulong_insert_bit ( mask,  b, 0 )==zeros ); FD_TEST( fd_ulong_insert_bit ( mask,  b, 1 )==mask  );
      FD_TEST( fd_ulong_insert_bit ( maskc, b, 0 )==maskc ); FD_TEST( fd_ulong_insert_bit ( maskc, b, 1 )==ones  );
      FD_TEST( fd_ulong_insert_bit ( ones,  b, 0 )==maskc ); FD_TEST( fd_ulong_insert_bit ( ones,  b, 1 )==ones  );
    }
    for( int n=0; n<=w; n++ ) {
      ulong mask  = (ulong)(((n<w) ? (1UL<<n) : 0UL)-1UL);
      ulong maskc = (ulong)~mask;
      FD_TEST( fd_ulong_mask_lsb   ( n               )==mask  );
      FD_TEST( fd_ulong_clear_lsb  ( zeros, n        )==zeros ); FD_TEST( fd_ulong_set_lsb    ( zeros, n       )==mask  );
      FD_TEST( fd_ulong_clear_lsb  ( mask,  n        )==zeros ); FD_TEST( fd_ulong_set_lsb    ( mask,  n       )==mask  );
      FD_TEST( fd_ulong_clear_lsb  ( maskc, n        )==maskc ); FD_TEST( fd_ulong_set_lsb    ( maskc, n       )==ones  );
      FD_TEST( fd_ulong_clear_lsb  ( ones,  n        )==maskc ); FD_TEST( fd_ulong_set_lsb    ( ones,  n       )==ones  );
      FD_TEST( fd_ulong_flip_lsb   ( zeros, n        )==mask  ); FD_TEST( fd_ulong_extract_lsb( zeros, n       )==zeros );
      FD_TEST( fd_ulong_flip_lsb   ( mask,  n        )==zeros ); FD_TEST( fd_ulong_extract_lsb( mask,  n       )==mask  );
      FD_TEST( fd_ulong_flip_lsb   ( maskc, n        )==ones  ); FD_TEST( fd_ulong_extract_lsb( maskc, n       )==zeros );
      FD_TEST( fd_ulong_flip_lsb   ( ones,  n        )==maskc ); FD_TEST( fd_ulong_extract_lsb( ones,  n       )==mask  );
      FD_TEST( fd_ulong_insert_lsb ( zeros, n, zeros )==zeros ); FD_TEST( fd_ulong_insert_lsb ( zeros, n, mask )==mask  );
      FD_TEST( fd_ulong_insert_lsb ( mask,  n, zeros )==zeros ); FD_TEST( fd_ulong_insert_lsb ( mask,  n, mask )==mask  );
      FD_TEST( fd_ulong_insert_lsb ( maskc, n, zeros )==maskc ); FD_TEST( fd_ulong_insert_lsb ( maskc, n, mask )==ones  );
      FD_TEST( fd_ulong_insert_lsb ( ones,  n, zeros )==maskc ); FD_TEST( fd_ulong_insert_lsb ( ones,  n, mask )==ones  );
    }
    for( int h=0; h< w; h++ ) {
      for( int l=0; l<=h; l++ ) {
        ulong x     = fd_ulong_mask_lsb( h-l+1 );
        ulong mask  = (ulong)(x << l);
        ulong maskc = (ulong)~mask;
        FD_TEST( fd_ulong_mask   ( l,h               )==mask  );
        FD_TEST( fd_ulong_clear  ( zeros, l,h        )==zeros ); FD_TEST( fd_ulong_set    ( zeros, l,h    )==mask  );
        FD_TEST( fd_ulong_clear  ( mask,  l,h        )==zeros ); FD_TEST( fd_ulong_set    ( mask,  l,h    )==mask  );
        FD_TEST( fd_ulong_clear  ( maskc, l,h        )==maskc ); FD_TEST( fd_ulong_set    ( maskc, l,h    )==ones  );
        FD_TEST( fd_ulong_clear  ( ones,  l,h        )==maskc ); FD_TEST( fd_ulong_set    ( ones,  l,h    )==ones  );
        FD_TEST( fd_ulong_flip   ( zeros, l,h        )==mask  ); FD_TEST( fd_ulong_extract( zeros, l,h    )==zeros );
        FD_TEST( fd_ulong_flip   ( mask,  l,h        )==zeros ); FD_TEST( fd_ulong_extract( mask,  l,h    )==x     );
        FD_TEST( fd_ulong_flip   ( maskc, l,h        )==ones  ); FD_TEST( fd_ulong_extract( maskc, l,h    )==zeros );
        FD_TEST( fd_ulong_flip   ( ones,  l,h        )==maskc ); FD_TEST( fd_ulong_extract( ones,  l,h    )==x     );
        FD_TEST( fd_ulong_insert ( zeros, l,h, zeros )==zeros ); FD_TEST( fd_ulong_insert ( zeros, l,h, x )==mask  );
        FD_TEST( fd_ulong_insert ( mask,  l,h, zeros )==zeros ); FD_TEST( fd_ulong_insert ( mask,  l,h, x )==mask  );
        FD_TEST( fd_ulong_insert ( maskc, l,h, zeros )==maskc ); FD_TEST( fd_ulong_insert ( maskc, l,h, x )==ones  );
        FD_TEST( fd_ulong_insert ( ones,  l,h, zeros )==maskc ); FD_TEST( fd_ulong_insert ( ones,  l,h, x )==ones  );
      }
    }
    FD_TEST( fd_ulong_popcnt  ( zeros )==0        ); FD_TEST( fd_ulong_popcnt  ( ones  )==w        );
    FD_TEST( fd_ulong_find_lsb          ( ones      )==0    );
    FD_TEST( fd_ulong_find_lsb_w_default( ones , -1 )==0    );
    FD_TEST( fd_ulong_find_lsb_w_default( zeros, -1 )==-1   );
    FD_TEST( fd_ulong_find_msb          ( ones      )==(w-1));
    FD_TEST( fd_ulong_find_msb_w_default( ones , -1 )==(w-1));
    FD_TEST( fd_ulong_find_msb_w_default( zeros, -1 )==-1   );
    FD_TEST( fd_ulong_pow2_up ( zeros )==0UL ); FD_TEST( fd_ulong_pow2_up ( ones  )==0UL          );
    FD_TEST( fd_ulong_pow2_dn ( zeros )==1UL ); FD_TEST( fd_ulong_pow2_dn ( ones  )==(1UL<<(w-1)) );
    for( int i=1; i<w; i++ ) {
      ulong x = (ulong)(1UL<<i);
      FD_TEST( fd_ulong_pop_lsb ( x )==zeros );
      FD_TEST( fd_ulong_popcnt  ( x )==1     ); FD_TEST( fd_ulong_popcnt  ( (ulong)~x )==w-1 );
      FD_TEST( fd_ulong_find_lsb( x )==i     ); FD_TEST( fd_ulong_find_msb( x )==i );
      FD_TEST( fd_ulong_find_lsb_w_default( x , -1 )==i );
      FD_TEST( fd_ulong_find_msb_w_default( x , -1 )==i );
      FD_TEST( fd_ulong_pow2_up ( x )==x     );
      FD_TEST( fd_ulong_pow2_dn ( x )==x     );
      for( int j=0; j<i; j++ ) {
        ulong y = (ulong)(1UL<<j);
        ulong z = (ulong)(x|y);
        FD_TEST( fd_ulong_pop_lsb ( z )==x      );
        FD_TEST( fd_ulong_popcnt  ( z )==2      ); FD_TEST( fd_ulong_popcnt  ( (ulong)~z )==w-2 );
        FD_TEST( fd_ulong_find_lsb( z )==j      ); FD_TEST( fd_ulong_find_msb( z )==i );
        FD_TEST( fd_ulong_find_lsb_w_default( z , -1 )==j );
        FD_TEST( fd_ulong_find_msb_w_default( z , -1 )==i );
        FD_TEST( fd_ulong_pow2_up ( z )==(x<<1) );
        FD_TEST( fd_ulong_pow2_dn ( z )== x     );
      }
    }
    for( int n=0; n<=w; n++ ) { int sl = n+(w-8)-((n>>3)<<4); 
      ulong x = (ulong)((n==w)? 0UL : (1UL<<n ));
      ulong y = (ulong)((n==w)? 0UL : (1UL<<sl)); FD_TEST( fd_ulong_bswap( x )==y );
    }  
    for( int i=0; i<w; i++ ) {
      ulong align = (ulong) (1UL<<i);
      ulong lo    = (ulong)((1UL<<i)-1UL);
      ulong hi    = (ulong)~lo;
      FD_TEST( fd_ulong_is_aligned( zeros, align )        );
      FD_TEST( fd_ulong_alignment ( zeros, align )==zeros );
      FD_TEST( fd_ulong_align_dn  ( zeros, align )==zeros );
      FD_TEST( fd_ulong_align_up  ( zeros, align )==zeros );
      FD_TEST( FD_ULONG_ALIGN_UP  ( zeros, align )==zeros );
      FD_TEST( fd_ulong_is_aligned( ones,  align )==(!i)  );
      FD_TEST( fd_ulong_alignment ( ones,  align )==lo    );
      FD_TEST( fd_ulong_align_dn  ( ones,  align )==hi    );
      FD_TEST( fd_ulong_align_up  ( ones,  align )==((!i) ? ones : zeros) );
      FD_TEST( FD_ULONG_ALIGN_UP  ( ones,  align )==((!i) ? ones : zeros) );
      for( int j=0; j<w; j++ ) {
        ulong x = (ulong)(1UL<<j);
        FD_TEST( fd_ulong_is_aligned( x, align )==(j>=i)        );
        FD_TEST( fd_ulong_alignment ( x, align )==( x     & lo) );
        FD_TEST( fd_ulong_align_dn  ( x, align )==( x     & hi) );
        FD_TEST( fd_ulong_align_up  ( x, align )==((x+lo) & hi) );
        FD_TEST( FD_ULONG_ALIGN_UP  ( x, align )==((x+lo) & hi) );
      }
    }

    for( int iter=0; iter<16777216; iter++ ) {
      ulong m = (ulong)fd_rng_ulong( rng );
      ulong x = (ulong)fd_rng_ulong( rng );
      ulong y = (ulong)fd_rng_ulong( rng );
      int   c = fd_ulong_extract_bit( m, 0 );
      FD_TEST( fd_ulong_blend( m, x, y )==(ulong)( (x & m) | (y & ~m) ) );
      FD_TEST( fd_ulong_if   ( c, x, y )==(c ? x : y)                   );
      FD_TEST( fd_ulong_abs  ( x       )==x                             );
      FD_TEST( fd_ulong_min  ( x, y    )==((x<y) ? x : y)               );
      FD_TEST( fd_ulong_max  ( x, y    )==((x>y) ? x : y)               );

      ulong z = x; fd_ulong_store_if( c, &z, y ); FD_TEST( z==(c ? y : x) );

      ulong xx; ulong yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );

      FD_TEST( fd_ptr_if( c, (uchar *)x, (uchar *)y )==(uchar *)(c ? x : y) );

      int n = (int)(uint)y;
      int s = n & 127;
      FD_TEST( fd_ulong_shift_left  ( x, s )==((s>63) ? 0UL : (ulong)(x<<s)) );
      FD_TEST( fd_ulong_shift_right ( x, s )==((s>63) ? 0UL : (ulong)(x>>s)) );
      FD_TEST( fd_ulong_rotate_left ( x, n )==((x<<(n&63))|(x>>((-n)&63))) );
      FD_TEST( fd_ulong_rotate_right( x, n )==((x>>(n&63))|(x<<((-n)&63))) );

      int s0 = (int)(m & 63UL); m >>= 6;
      int s1 = (int)(m & 63UL);

      uchar svw[ FD_ULONG_SVW_ENC_MAX ]; x >>= s0;
      ulong         enc_sz = fd_ulong_svw_enc_sz( x );   FD_TEST( enc_sz<=FD_ULONG_SVW_ENC_MAX );
      uchar const * nxt    = fd_ulong_svw_enc( svw, x ); FD_TEST( (ulong)(nxt-svw)==enc_sz     );

      FD_TEST( fd_ulong_svw_dec_sz     ( svw         )==enc_sz );
      FD_TEST( fd_ulong_svw_dec_tail_sz( nxt         )==enc_sz );
      FD_TEST( fd_ulong_svw_dec_fixed  ( svw, enc_sz )==x      );
      FD_TEST( fd_ulong_svw_dec        ( svw, &y     )==nxt    ); FD_TEST( x==y );
      FD_TEST( fd_ulong_svw_dec_tail   ( nxt, &y     )==svw    ); FD_TEST( x==y );

      x >>= s1;
      FD_TEST( fd_ulong_svw_enc_fixed( svw, enc_sz, x )==nxt );

      FD_TEST( fd_ulong_svw_dec_sz     ( svw         )==enc_sz );
      FD_TEST( fd_ulong_svw_dec_tail_sz( nxt         )==enc_sz );
      FD_TEST( fd_ulong_svw_dec_fixed  ( svw, enc_sz )==x      );
      FD_TEST( fd_ulong_svw_dec        ( svw, &y     )==nxt    ); FD_TEST( x==y );
      FD_TEST( fd_ulong_svw_dec_tail   ( nxt, &y     )==svw    ); FD_TEST( x==y );
    }
  }

# if FD_HAS_INT128
  if( 1 ) {
    FD_LOG_NOTICE(( "Testing uint128" ));
    int   w       = 128;
    uint128 zeros =  (uint128)0;
    uint128 ones  = ~(uint128)0;
    for( int n=0; n< w; n++ ) {
      uint128 x = ((uint128)1)<<n;
      FD_TEST( fd_uint128_is_pow2( x ) );
      FD_TEST( !fd_uint128_is_pow2( ~x ) );
    }
    for( int n=0; n<=w; n++ ) { uint128 x = ((n<w) ? (((uint128)1)<<n) : ((uint128)0)); FD_TEST( fd_uint128_pow2( n )==x ); }
    for( int b=0; b< w; b++ ) {
      uint128 mask  = ((uint128)1)<<b;
      uint128 maskc = ~mask;
      FD_TEST( fd_uint128_mask_bit   ( b           )==mask  );
      FD_TEST( fd_uint128_clear_bit  ( zeros, b    )==zeros ); FD_TEST( fd_uint128_set_bit    ( zeros, b    )==mask  );
      FD_TEST( fd_uint128_clear_bit  ( mask,  b    )==zeros ); FD_TEST( fd_uint128_set_bit    ( mask,  b    )==mask  );
      FD_TEST( fd_uint128_clear_bit  ( maskc, b    )==maskc ); FD_TEST( fd_uint128_set_bit    ( maskc, b    )==ones  );
      FD_TEST( fd_uint128_clear_bit  ( ones,  b    )==maskc ); FD_TEST( fd_uint128_set_bit    ( ones,  b    )==ones  );
      FD_TEST( fd_uint128_flip_bit   ( zeros, b    )==mask  ); FD_TEST( fd_uint128_extract_bit( zeros, b    )==0     );
      FD_TEST( fd_uint128_flip_bit   ( mask,  b    )==zeros ); FD_TEST( fd_uint128_extract_bit( mask,  b    )==1     );
      FD_TEST( fd_uint128_flip_bit   ( maskc, b    )==ones  ); FD_TEST( fd_uint128_extract_bit( maskc, b    )==0     );
      FD_TEST( fd_uint128_flip_bit   ( ones,  b    )==maskc ); FD_TEST( fd_uint128_extract_bit( ones,  b    )==1     );
      FD_TEST( fd_uint128_insert_bit ( zeros, b, 0 )==zeros ); FD_TEST( fd_uint128_insert_bit ( zeros, b, 1 )==mask  );
      FD_TEST( fd_uint128_insert_bit ( mask,  b, 0 )==zeros ); FD_TEST( fd_uint128_insert_bit ( mask,  b, 1 )==mask  );
      FD_TEST( fd_uint128_insert_bit ( maskc, b, 0 )==maskc ); FD_TEST( fd_uint128_insert_bit ( maskc, b, 1 )==ones  );
      FD_TEST( fd_uint128_insert_bit ( ones,  b, 0 )==maskc ); FD_TEST( fd_uint128_insert_bit ( ones,  b, 1 )==ones  );
    }
    for( int n=0; n<=w; n++ ) {
      uint128 mask  = ((n<w) ? (((uint128)1)<<n) : ((uint128)0))-((uint128)1);
      uint128 maskc = ~mask;
      FD_TEST( fd_uint128_mask_lsb   ( n               )==mask  );
      FD_TEST( fd_uint128_clear_lsb  ( zeros, n        )==zeros ); FD_TEST( fd_uint128_set_lsb    ( zeros, n       )==mask  );
      FD_TEST( fd_uint128_clear_lsb  ( mask,  n        )==zeros ); FD_TEST( fd_uint128_set_lsb    ( mask,  n       )==mask  );
      FD_TEST( fd_uint128_clear_lsb  ( maskc, n        )==maskc ); FD_TEST( fd_uint128_set_lsb    ( maskc, n       )==ones  );
      FD_TEST( fd_uint128_clear_lsb  ( ones,  n        )==maskc ); FD_TEST( fd_uint128_set_lsb    ( ones,  n       )==ones  );
      FD_TEST( fd_uint128_flip_lsb   ( zeros, n        )==mask  ); FD_TEST( fd_uint128_extract_lsb( zeros, n       )==zeros );
      FD_TEST( fd_uint128_flip_lsb   ( mask,  n        )==zeros ); FD_TEST( fd_uint128_extract_lsb( mask,  n       )==mask  );
      FD_TEST( fd_uint128_flip_lsb   ( maskc, n        )==ones  ); FD_TEST( fd_uint128_extract_lsb( maskc, n       )==zeros );
      FD_TEST( fd_uint128_flip_lsb   ( ones,  n        )==maskc ); FD_TEST( fd_uint128_extract_lsb( ones,  n       )==mask  );
      FD_TEST( fd_uint128_insert_lsb ( zeros, n, zeros )==zeros ); FD_TEST( fd_uint128_insert_lsb ( zeros, n, mask )==mask  );
      FD_TEST( fd_uint128_insert_lsb ( mask,  n, zeros )==zeros ); FD_TEST( fd_uint128_insert_lsb ( mask,  n, mask )==mask  );
      FD_TEST( fd_uint128_insert_lsb ( maskc, n, zeros )==maskc ); FD_TEST( fd_uint128_insert_lsb ( maskc, n, mask )==ones  );
      FD_TEST( fd_uint128_insert_lsb ( ones,  n, zeros )==maskc ); FD_TEST( fd_uint128_insert_lsb ( ones,  n, mask )==ones  );
    }
    for( int h=0; h< w; h++ ) {
      for( int l=0; l<=h; l++ ) {
        uint128 x     = fd_uint128_mask_lsb( h-l+1 );
        uint128 mask  = x << l;
        uint128 maskc = ~mask;
        FD_TEST( fd_uint128_mask   ( l,h               )==mask  );
        FD_TEST( fd_uint128_clear  ( zeros, l,h        )==zeros ); FD_TEST( fd_uint128_set    ( zeros, l,h    )==mask  );
        FD_TEST( fd_uint128_clear  ( mask,  l,h        )==zeros ); FD_TEST( fd_uint128_set    ( mask,  l,h    )==mask  );
        FD_TEST( fd_uint128_clear  ( maskc, l,h        )==maskc ); FD_TEST( fd_uint128_set    ( maskc, l,h    )==ones  );
        FD_TEST( fd_uint128_clear  ( ones,  l,h        )==maskc ); FD_TEST( fd_uint128_set    ( ones,  l,h    )==ones  );
        FD_TEST( fd_uint128_flip   ( zeros, l,h        )==mask  ); FD_TEST( fd_uint128_extract( zeros, l,h    )==zeros );
        FD_TEST( fd_uint128_flip   ( mask,  l,h        )==zeros ); FD_TEST( fd_uint128_extract( mask,  l,h    )==x     );
        FD_TEST( fd_uint128_flip   ( maskc, l,h        )==ones  ); FD_TEST( fd_uint128_extract( maskc, l,h    )==zeros );
        FD_TEST( fd_uint128_flip   ( ones,  l,h        )==maskc ); FD_TEST( fd_uint128_extract( ones,  l,h    )==x     );
        FD_TEST( fd_uint128_insert ( zeros, l,h, zeros )==zeros ); FD_TEST( fd_uint128_insert ( zeros, l,h, x )==mask  );
        FD_TEST( fd_uint128_insert ( mask,  l,h, zeros )==zeros ); FD_TEST( fd_uint128_insert ( mask,  l,h, x )==mask  );
        FD_TEST( fd_uint128_insert ( maskc, l,h, zeros )==maskc ); FD_TEST( fd_uint128_insert ( maskc, l,h, x )==ones  );
        FD_TEST( fd_uint128_insert ( ones,  l,h, zeros )==maskc ); FD_TEST( fd_uint128_insert ( ones,  l,h, x )==ones  );
      }
    }
    FD_TEST( fd_uint128_popcnt  ( zeros )==0          ); FD_TEST( fd_uint128_popcnt  ( ones  )==w          );
    FD_TEST( fd_uint128_find_lsb          ( ones      )==0    );
    FD_TEST( fd_uint128_find_lsb_w_default( ones , -1 )==0    );
    FD_TEST( fd_uint128_find_lsb_w_default( zeros, -1 )==-1   );
    FD_TEST( fd_uint128_find_msb          ( ones      )==(w-1));
    FD_TEST( fd_uint128_find_msb_w_default( ones , -1 )==(w-1));
    FD_TEST( fd_uint128_find_msb_w_default( zeros, -1 )==-1   );
    FD_TEST( fd_uint128_pow2_up ( zeros )==(uint128)0 ); FD_TEST( fd_uint128_pow2_up ( ones  )==(uint128)0            );
    FD_TEST( fd_uint128_pow2_dn ( zeros )==(uint128)1 ); FD_TEST( fd_uint128_pow2_dn ( ones  )==(((uint128)1)<<(w-1)) );
    for( int i=1; i<w; i++ ) {
      uint128 x = ((uint128)1)<<i;
      FD_TEST( fd_uint128_pop_lsb ( x )==zeros );
      FD_TEST( fd_uint128_popcnt  ( x )==1     ); FD_TEST( fd_uint128_popcnt  ( ~x )==w-1 );
      FD_TEST( fd_uint128_find_lsb( x )==i     ); FD_TEST( fd_uint128_find_msb(  x )==i );
      FD_TEST( fd_uint128_find_lsb_w_default( x , -1 )==i );
      FD_TEST( fd_uint128_find_msb_w_default( x , -1 )==i );
      FD_TEST( fd_uint128_pow2_up ( x )==x     );
      FD_TEST( fd_uint128_pow2_dn ( x )==x     );
      for( int j=0; j<i; j++ ) {
        uint128 y = ((uint128)1)<<j;
        uint128 z = x|y;
        FD_TEST( fd_uint128_pop_lsb ( z )==x      );
        FD_TEST( fd_uint128_popcnt  ( z )==2      ); FD_TEST( fd_uint128_popcnt  ( ~z )==w-2 );
        FD_TEST( fd_uint128_find_lsb( z )==j      ); FD_TEST( fd_uint128_find_msb(  z )==i );
        FD_TEST( fd_uint128_find_lsb_w_default( z , -1 )==j );
        FD_TEST( fd_uint128_find_msb_w_default( z , -1 )==i );
        FD_TEST( fd_uint128_pow2_up ( z )==(x<<1) );
        FD_TEST( fd_uint128_pow2_dn ( z )== x     );
      }
    }
    for( int n=0; n<=w; n++ ) { int sl = n+(w-8)-((n>>3)<<4); 
      uint128 x = (uint128)((n==w)? (uint128)0 : ((uint128)(1U)<<n ));
      uint128 y = (uint128)((n==w)? (uint128)0 : ((uint128)(1U)<<sl)); FD_TEST( fd_uint128_bswap( x )==y );
    }      
    for( int i=0; i<w; i++ ) {
      uint128 align =  ((uint128)1)<<i;
      uint128 lo    = (((uint128)1)<<i)-((uint128)1);
      uint128 hi    = ~lo;
      FD_TEST( fd_uint128_is_aligned( zeros, align )        );
      FD_TEST( fd_uint128_alignment ( zeros, align )==zeros );
      FD_TEST( fd_uint128_align_dn  ( zeros, align )==zeros );
      FD_TEST( fd_uint128_align_up  ( zeros, align )==zeros );
      FD_TEST( fd_uint128_is_aligned( ones,  align )==(!i)  );
      FD_TEST( fd_uint128_alignment ( ones,  align )==lo    );
      FD_TEST( fd_uint128_align_dn  ( ones,  align )==hi    );
      FD_TEST( fd_uint128_align_up  ( ones,  align )==((!i) ? ones : zeros) );
      for( int j=0; j<w; j++ ) {
        uint128 x = ((uint128)1)<<j;
        FD_TEST( fd_uint128_is_aligned( x, align )==(j>=i)        );
        FD_TEST( fd_uint128_alignment ( x, align )==( x     & lo) );
        FD_TEST( fd_uint128_align_dn  ( x, align )==( x     & hi) );
        FD_TEST( fd_uint128_align_up  ( x, align )==((x+lo) & hi) );
      }
    }
    for( int iter=0; iter<16777216; iter++ ) {
      uint128 m = fd_rng_uint128( rng );
      uint128 x = fd_rng_uint128( rng );
      uint128 y = fd_rng_uint128( rng );
      int     c = fd_uint128_extract_bit( m, 0 );
      FD_TEST( fd_uint128_blend( m, x, y )==((x & m) | (y & ~m))            );
      FD_TEST( fd_uint128_if   ( c, x, y )==(c ? x : y)                     );
      FD_TEST( fd_uint128_abs  ( x       )==x                               );
      FD_TEST( fd_uint128_min  ( x, y    )==((x<y) ? x : y)                 );
      FD_TEST( fd_uint128_max  ( x, y    )==((x>y) ? x : y)                 );

      uint128 z = x; fd_uint128_store_if( c, &z, y ); FD_TEST( z==(c ? y : x) );

      uint128 xx; uint128 yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );

      int n = (int)(uint)y;
      int s = n & 255;
      FD_TEST( fd_uint128_shift_left  ( x, s )==((s>127) ? (uint128)0 : (uint128)(x<<s)) );
      FD_TEST( fd_uint128_shift_right ( x, s )==((s>127) ? (uint128)0 : (uint128)(x>>s)) );
      FD_TEST( fd_uint128_rotate_left ( x, n )==((x<<(n&127))|(x>>((-n)&127))) );
      FD_TEST( fd_uint128_rotate_right( x, n )==((x>>(n&127))|(x<<((-n)&127))) );
    }
  }
# endif

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing char" ));
    for( int iter=0; iter<16777216; iter++ ) {
      int  c = (int)(fd_rng_ulong( rng ) & 1UL);
      char x = (char)fd_rng_ulong( rng );
      char y = (char)fd_rng_ulong( rng );
      FD_TEST( fd_char_if( c, x, y )==(c ? x : y) );

      char z = x; fd_char_store_if( c, &z, y ); FD_TEST( z==(c ? y : x) );

      char xx; char yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );
    }
  }

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing schar" ));
    FD_TEST( fd_schar_abs(  (schar)SCHAR_MIN )==(uchar)1+(uchar)SCHAR_MAX );
    FD_TEST( fd_schar_abs( -(schar)SCHAR_MAX )==         (uchar)SCHAR_MAX );
    FD_TEST( fd_schar_abs(         -(schar)1 )==                 (uchar)1 );
    FD_TEST( fd_schar_abs(          (schar)0 )==                 (uchar)0 );
    FD_TEST( fd_schar_abs(          (schar)1 )==                 (uchar)1 );
    FD_TEST( fd_schar_abs(  (schar)SCHAR_MAX )==         (uchar)SCHAR_MAX );
    for( int iter=0; iter<16777216; iter++ ) {
      int c = (int)(fd_rng_ulong( rng ) & 1UL);
      schar x = (schar)fd_rng_ulong( rng );
      schar y = (schar)fd_rng_ulong( rng );
      FD_TEST( fd_schar_if ( c, x, y )==(c ? x : y)                             );
      FD_TEST( fd_schar_abs( x       )==(uchar)((x<(schar)0) ? ((schar)-x) : x) );
      FD_TEST( fd_schar_min( x, y    )==((x<y) ? x : y)                         );
      FD_TEST( fd_schar_max( x, y    )==((x>y) ? x : y)                         );

      schar z = x; fd_schar_store_if( c, &z, y ); FD_TEST( z==(c ? y : x) );

      schar xx; schar yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );

      int   n = (int)fd_rng_uint( rng );
      int   s = n & 15;
      uchar m = (uchar)-(((uchar)x) >> 7);
      FD_TEST( fd_schar_shift_left  ( x, s )==(schar)fd_uchar_shift_left  ( (uchar)x, s ) );
      FD_TEST( fd_schar_shift_right ( x, s )==(schar)(uchar)(fd_uchar_shift_right( (uchar)(((uchar)x) ^ m), s ) ^ m) );
      FD_TEST( fd_schar_rotate_left ( x, n )==(schar)fd_uchar_rotate_left ( (uchar)x, n ) );
      FD_TEST( fd_schar_rotate_right( x, n )==(schar)fd_uchar_rotate_right( (uchar)x, n ) );
    }

    FD_TEST( fd_schar_zz_enc( (schar)        0 )==(uchar)            0 );
    FD_TEST( fd_schar_zz_enc( (schar)       -1 )==(uchar)            1 );
    FD_TEST( fd_schar_zz_enc( (schar)        1 )==(uchar)            2 );
    FD_TEST( fd_schar_zz_enc( (schar)SCHAR_MIN )==(uchar) UCHAR_MAX    );
    FD_TEST( fd_schar_zz_enc( (schar)SCHAR_MAX )==(uchar)(UCHAR_MAX-1) );

    FD_TEST( fd_schar_zz_dec( (uchar)            0 )==(schar)        0 );
    FD_TEST( fd_schar_zz_dec( (uchar)            1 )==(schar)       -1 );
    FD_TEST( fd_schar_zz_dec( (uchar)            2 )==(schar)        1 );
    FD_TEST( fd_schar_zz_dec( (uchar) UCHAR_MAX    )==(schar)SCHAR_MIN );
    FD_TEST( fd_schar_zz_dec( (uchar)(UCHAR_MAX-1) )==(schar)SCHAR_MAX );
  }

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing short" ));
    FD_TEST( fd_short_abs(  (short)SHORT_MIN )==(ushort)1+(ushort)SHORT_MAX );
    FD_TEST( fd_short_abs( -(short)SHORT_MAX )==          (ushort)SHORT_MAX );
    FD_TEST( fd_short_abs(         -(short)1 )==                  (ushort)1 );
    FD_TEST( fd_short_abs(          (short)0 )==                  (ushort)0 );
    FD_TEST( fd_short_abs(          (short)1 )==                  (ushort)1 );
    FD_TEST( fd_short_abs(  (short)SHORT_MAX )==          (ushort)SHORT_MAX );
    for( int iter=0; iter<16777216; iter++ ) {
      int c = (int)(fd_rng_ulong( rng ) & 1UL);
      short x = (short)fd_rng_ulong( rng );
      short y = (short)fd_rng_ulong( rng );
      FD_TEST( fd_short_if ( c, x, y )==(c ? x : y)                              );
      FD_TEST( fd_short_abs( x       )==(ushort)((x<(short)0) ? ((short)-x) : x) );
      FD_TEST( fd_short_min( x, y    )==((x<y) ? x : y)                          );
      FD_TEST( fd_short_max( x, y    )==((x>y) ? x : y)                          );

      short z = x; fd_short_store_if( c, &z, y ); FD_TEST( z==(c ? y : x) );

      short xx; short yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );

      int    n = (int)fd_rng_uint( rng );
      int    s = n & 31;
      ushort m = (ushort)-(((ushort)x) >> 15);
      FD_TEST( fd_short_shift_left  ( x, s )==(short)fd_ushort_shift_left  ( (ushort)x, s ) );
      FD_TEST( fd_short_shift_right ( x, s )==(short)(ushort)(fd_ushort_shift_right( (ushort)(((ushort)x) ^ m), s ) ^ m) );
      FD_TEST( fd_short_rotate_left ( x, n )==(short)fd_ushort_rotate_left ( (ushort)x, n ) );
      FD_TEST( fd_short_rotate_right( x, n )==(short)fd_ushort_rotate_right( (ushort)x, n ) );
    }

    FD_TEST( fd_short_zz_enc( (short)        0 )==(ushort)             0 );
    FD_TEST( fd_short_zz_enc( (short)       -1 )==(ushort)             1 );
    FD_TEST( fd_short_zz_enc( (short)        1 )==(ushort)             2 );
    FD_TEST( fd_short_zz_enc( (short)SHORT_MIN )==(ushort) USHORT_MAX    );
    FD_TEST( fd_short_zz_enc( (short)SHORT_MAX )==(ushort)(USHORT_MAX-1) );

    FD_TEST( fd_short_zz_dec( (ushort)             0 )==(short)        0 );
    FD_TEST( fd_short_zz_dec( (ushort)             1 )==(short)       -1 );
    FD_TEST( fd_short_zz_dec( (ushort)             2 )==(short)        1 );
    FD_TEST( fd_short_zz_dec( (ushort) USHORT_MAX    )==(short)SHORT_MIN );
    FD_TEST( fd_short_zz_dec( (ushort)(USHORT_MAX-1) )==(short)SHORT_MAX );
  }

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing int" ));
    FD_TEST( fd_int_abs(  INT_MIN )==1U+(uint)INT_MAX );
    FD_TEST( fd_int_abs( -INT_MAX )==   (uint)INT_MAX );
    FD_TEST( fd_int_abs(       -1 )==              1U );
    FD_TEST( fd_int_abs(        0 )==              0U );
    FD_TEST( fd_int_abs(        1 )==              1U );
    FD_TEST( fd_int_abs(  INT_MAX )==   (uint)INT_MAX );
    for( int iter=0; iter<16777216; iter++ ) {
      int c = (int)(fd_rng_ulong( rng ) & 1UL);
      int x = (int)fd_rng_ulong( rng );
      int y = (int)fd_rng_ulong( rng );
      FD_TEST( fd_int_if ( c, x, y )==(c ? x : y)                        );
      FD_TEST( fd_int_abs( x       )==(uint)((x<(int)0) ? ((int)-x) : x) );
      FD_TEST( fd_int_min( x, y    )==((x<y) ? x : y)                    );
      FD_TEST( fd_int_max( x, y    )==((x>y) ? x : y)                    );

      int z = x; fd_int_store_if( c, &z, y ); FD_TEST( z==(c ? y : x) );

      int xx; int yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );

      int  n = (int)fd_rng_uint( rng );
      int  s = n & 63;
      uint m = (uint)-(((uint)x) >> 31);
      FD_TEST( fd_int_shift_left  ( x, s )==(int)fd_uint_shift_left  ( (uint)x, s ) );
      FD_TEST( fd_int_shift_right ( x, s )==(int)(fd_uint_shift_right( ((uint)x)^m, s )^m) );
      FD_TEST( fd_int_rotate_left ( x, n )==(int)fd_uint_rotate_left ( (uint)x, n ) );
      FD_TEST( fd_int_rotate_right( x, n )==(int)fd_uint_rotate_right( (uint)x, n ) );
    }

    FD_TEST( fd_int_zz_enc(       0 )==           0U );
    FD_TEST( fd_int_zz_enc(      -1 )==           1U );
    FD_TEST( fd_int_zz_enc(       1 )==           2U );
    FD_TEST( fd_int_zz_enc( INT_MIN )== UINT_MAX     );
    FD_TEST( fd_int_zz_enc( INT_MAX )==(UINT_MAX-1U) );

    FD_TEST( fd_int_zz_dec(            0U )==      0 );
    FD_TEST( fd_int_zz_dec(            1U )==     -1 );
    FD_TEST( fd_int_zz_dec(            2U )==      1 );
    FD_TEST( fd_int_zz_dec(  UINT_MAX     )==INT_MIN );
    FD_TEST( fd_int_zz_dec( (UINT_MAX-1U) )==INT_MAX );
  }

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing long" ));
    FD_TEST( fd_long_abs(  LONG_MIN )==1UL+(ulong)LONG_MAX );
    FD_TEST( fd_long_abs( -LONG_MAX )==    (ulong)LONG_MAX );
    FD_TEST( fd_long_abs(       -1L )==                1UL );
    FD_TEST( fd_long_abs(        0L )==                0UL );
    FD_TEST( fd_long_abs(        1L )==                1UL );
    FD_TEST( fd_long_abs(  LONG_MAX )==    (ulong)LONG_MAX );
    for( int iter=0; iter<16777216; iter++ ) {
      int  c = (int)(fd_rng_ulong( rng ) & 1UL);
      long x = (long)fd_rng_ulong( rng );
      long y = (long)fd_rng_ulong( rng );
      FD_TEST( fd_long_if ( c, x, y )==(c ? x : y)                           );
      FD_TEST( fd_long_abs( x       )==(ulong)((x<(long)0) ? ((long)-x) : x) );
      FD_TEST( fd_long_min( x, y    )==((x<y) ? x : y)                       );
      FD_TEST( fd_long_max( x, y    )==((x>y) ? x : y)                       );

      long z = x; fd_long_store_if( c, &z, y ); FD_TEST( z==(c ? y : x) );

      long xx; long yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );

      int   n = (int)fd_rng_uint( rng );
      int   s = n & 127;
      ulong m = (ulong)-(((ulong)x) >> 63);
      FD_TEST( fd_long_shift_left  ( x, s )==(long)fd_ulong_shift_left  ( (ulong)x, s ) );
      FD_TEST( fd_long_shift_right ( x, s )==(long)(fd_ulong_shift_right( ((ulong)x)^m, s )^m) );
      FD_TEST( fd_long_rotate_left ( x, n )==(long)fd_ulong_rotate_left ( (ulong)x, n ) );
      FD_TEST( fd_long_rotate_right( x, n )==(long)fd_ulong_rotate_right( (ulong)x, n ) );
    }

    FD_TEST( fd_long_zz_enc(       0L )==            0UL );
    FD_TEST( fd_long_zz_enc(      -1L )==            1UL );
    FD_TEST( fd_long_zz_enc(       1L )==            2UL );
    FD_TEST( fd_long_zz_enc( LONG_MIN )== ULONG_MAX      );
    FD_TEST( fd_long_zz_enc( LONG_MAX )==(ULONG_MAX-1UL) );

    FD_TEST( fd_long_zz_dec(             0UL )==      0L );
    FD_TEST( fd_long_zz_dec(             1UL )==     -1L );
    FD_TEST( fd_long_zz_dec(             2UL )==      1L );
    FD_TEST( fd_long_zz_dec(  ULONG_MAX      )==LONG_MIN );
    FD_TEST( fd_long_zz_dec( (ULONG_MAX-1UL) )==LONG_MAX );
  }

# if FD_HAS_INT128
  if( 1 ) {
    FD_LOG_NOTICE(( "Testing int128" ));
    FD_TEST( fd_int128_abs(  INT128_MIN )==(uint128)1+(uint128)INT128_MAX );
    FD_TEST( fd_int128_abs( -INT128_MAX )==           (uint128)INT128_MAX );
    FD_TEST( fd_int128_abs(  -(int128)1 )==                    (uint128)1 );
    FD_TEST( fd_int128_abs(   (int128)0 )==                    (uint128)0 );
    FD_TEST( fd_int128_abs(   (int128)1 )==                    (uint128)1 );
    FD_TEST( fd_int128_abs(  INT128_MAX )==           (uint128)INT128_MAX );
    for( int iter=0; iter<16777216; iter++ ) {
      int    c = (int)(fd_rng_ulong( rng ) & 1UL);
      int128 x = (int128)fd_rng_uint128( rng );
      int128 y = (int128)fd_rng_uint128( rng );
      FD_TEST( fd_int128_if ( c, x, y )==(c ? x : y)                       );
      FD_TEST( fd_int128_abs( x       )==(uint128)((x<(int128)0) ? -x : x) );
      FD_TEST( fd_int128_min( x, y    )==((x<y) ? x : y)                   );
      FD_TEST( fd_int128_max( x, y    )==((x>y) ? x : y)                   );

      int128 z = x; fd_int128_store_if( c, &z, y ); FD_TEST( z==(c ? y : x) );

      int128 xx; int128 yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );

      int     n = (int)fd_rng_uint( rng );
      int     s = n & 255;
      uint128 m = (uint128)-(((uint128)x) >> 127);
      FD_TEST( fd_int128_shift_left  ( x, s )==(int128)fd_uint128_shift_left  ( (uint128)x, s ) );
      FD_TEST( fd_int128_shift_right ( x, s )==(int128)(fd_uint128_shift_right( ((uint128)x)^m, s )^m) );
      FD_TEST( fd_int128_rotate_left ( x, n )==(int128)fd_uint128_rotate_left ( (uint128)x, n ) );
      FD_TEST( fd_int128_rotate_right( x, n )==(int128)fd_uint128_rotate_right( (uint128)x, n ) );
    }

    FD_TEST( fd_int128_zz_enc(  (int128)0 )==              (uint128)0 );
    FD_TEST( fd_int128_zz_enc( -(int128)1 )==              (uint128)1 );
    FD_TEST( fd_int128_zz_enc(  (int128)1 )==              (uint128)2 );
    FD_TEST( fd_int128_zz_enc( INT128_MIN )== UINT128_MAX             );
    FD_TEST( fd_int128_zz_enc( INT128_MAX )==(UINT128_MAX-(uint128)1) );

    FD_TEST( fd_int128_zz_dec(               (uint128)0 )== (int128)0 );
    FD_TEST( fd_int128_zz_dec(               (uint128)1 )==-(int128)1 );
    FD_TEST( fd_int128_zz_dec(               (uint128)2 )== (int128)1 );
    FD_TEST( fd_int128_zz_dec(  UINT128_MAX             )==INT128_MIN );
    FD_TEST( fd_int128_zz_dec( (UINT128_MAX-(uint128)1) )==INT128_MAX );
  }
# endif

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing float" ));

    float psnan = uint_as_float(            (255U<<23) | (1U<<22) );
    float pqnan = uint_as_float(            (255U<<23) |  1U      );
    float pinf  = uint_as_float(            (255U<<23)            );
    float pzero = uint_as_float(                               0U );
    float nzero = uint_as_float( (1U<<31)                         );
    float ninf  = uint_as_float( (1U<<31) | (255U<<23)            );
    float nqnan = uint_as_float( (1U<<31) | (255U<<23) |  1U      );
    float nsnan = uint_as_float( (1U<<31) | (255U<<23) | (1U<<22) );

#   if 0 /* Detailed tester only works if fast math is disabled (most like -ffinite-math) */
#   define _(x,y,z,w) FD_TEST( fd_float_eq( x, y )==z && (x==y)==w )
    _( psnan, psnan, 1, 0 ); _( pqnan, psnan, 0, 0 ); _( pinf , psnan, 0, 0 ); _( pzero, psnan, 0, 0 ); _( nzero, psnan, 0, 0 ); _( ninf , psnan, 0, 0 ); _( nqnan, psnan, 0, 0 ); _( nsnan, psnan, 0, 0 );
    _( psnan, pqnan, 0, 0 ); _( pqnan, pqnan, 1, 0 ); _( pinf , pqnan, 0, 0 ); _( pzero, pqnan, 0, 0 ); _( nzero, pqnan, 0, 0 ); _( ninf , pqnan, 0, 0 ); _( nqnan, pqnan, 0, 0 ); _( nsnan, pqnan, 0, 0 );
    _( psnan, pinf , 0, 0 ); _( pqnan, pinf , 0, 0 ); _( pinf , pinf , 1, 1 ); _( pzero, pinf , 0, 0 ); _( nzero, pinf , 0, 0 ); _( ninf , pinf , 0, 0 ); _( nqnan, pinf , 0, 0 ); _( nsnan, pinf , 0, 0 );
    _( psnan, pzero, 0, 0 ); _( pqnan, pzero, 0, 0 ); _( pinf , pzero, 0, 0 ); _( pzero, pzero, 1, 1 ); _( nzero, pzero, 0, 1 ); _( ninf , pzero, 0, 0 ); _( nqnan, pzero, 0, 0 ); _( nsnan, pzero, 0, 0 );
    _( psnan, nzero, 0, 0 ); _( pqnan, nzero, 0, 0 ); _( pinf , nzero, 0, 0 ); _( pzero, nzero, 0, 1 ); _( nzero, nzero, 1, 1 ); _( ninf , nzero, 0, 0 ); _( nqnan, nzero, 0, 0 ); _( nsnan, nzero, 0, 0 );
    _( psnan, ninf , 0, 0 ); _( pqnan, ninf , 0, 0 ); _( pinf , ninf , 0, 0 ); _( pzero, ninf , 0, 0 ); _( nzero, ninf , 0, 0 ); _( ninf , ninf , 1, 1 ); _( nqnan, ninf , 0, 0 ); _( nsnan, ninf , 0, 0 );
    _( psnan, nqnan, 0, 0 ); _( pqnan, nqnan, 0, 0 ); _( pinf , nqnan, 0, 0 ); _( pzero, nqnan, 0, 0 ); _( nzero, nqnan, 0, 0 ); _( ninf , nqnan, 0, 0 ); _( nqnan, nqnan, 1, 0 ); _( nsnan, nqnan, 0, 0 );
    _( psnan, nsnan, 0, 0 ); _( pqnan, nsnan, 0, 0 ); _( pinf , nsnan, 0, 0 ); _( pzero, nsnan, 0, 0 ); _( nzero, nsnan, 0, 0 ); _( ninf , nsnan, 0, 0 ); _( nqnan, nsnan, 0, 0 ); _( nsnan, nsnan, 1, 0 );
#   undef _
#   endif

    FD_TEST( float_as_uint( fd_float_abs( psnan ) )==float_as_uint( psnan ) );
    FD_TEST( float_as_uint( fd_float_abs( pqnan ) )==float_as_uint( pqnan ) );
    FD_TEST( float_as_uint( fd_float_abs( pinf  ) )==float_as_uint( pinf  ) );
    FD_TEST( float_as_uint( fd_float_abs( pzero ) )==float_as_uint( pzero ) );
    FD_TEST( float_as_uint( fd_float_abs( nzero ) )==float_as_uint( pzero ) );
    FD_TEST( float_as_uint( fd_float_abs( ninf  ) )==float_as_uint( pinf  ) );
    FD_TEST( float_as_uint( fd_float_abs( nqnan ) )==float_as_uint( pqnan ) );
    FD_TEST( float_as_uint( fd_float_abs( nsnan ) )==float_as_uint( psnan ) );

    for( int iter=0; iter<16777216; iter++ ) {
      int   c = (int)(fd_rng_uint( rng ) & 1U);
      float x = uint_as_float( fd_rng_uint( rng ) );
      float y = uint_as_float( fd_rng_uint( rng ) );
      FD_TEST( fd_float_eq( fd_float_if( c, x, y ), (c ? x : y) ) );
      FD_TEST( float_as_uint( fd_float_abs( x ) )==(((float_as_uint( x ))<<1)>>1) );

      float z = x; fd_float_store_if( c, &z, y ); FD_TEST( fd_float_eq( z, (c ? y : x) ) );

      float xx; float yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );
    }
  }

# if FD_HAS_DOUBLE
  if( 1 ) {
    FD_LOG_NOTICE(( "Testing double" ));

    double psnan = ulong_as_double(             (2047UL<<52) | (1UL<<51) );
    double pqnan = ulong_as_double(             (2047UL<<52) |  1UL      );
    double pinf  = ulong_as_double(             (2047UL<<52)             );
    double pzero = ulong_as_double(                                  0UL );
    double nzero = ulong_as_double( (1UL<<63)                            );
    double ninf  = ulong_as_double( (1UL<<63) | (2047UL<<52)             );
    double nqnan = ulong_as_double( (1UL<<63) | (2047UL<<52) |  1UL      );
    double nsnan = ulong_as_double( (1UL<<63) | (2047UL<<52) | (1UL<<51) );

#   if 0 /* Detailed tester only works if fast math is disabled (most like -ffinite-math) */
#   define _(x,y,z,w) FD_TEST( fd_double_eq( x, y )==z && (x==y)==w )
    _( psnan, psnan, 1, 0 ); _( pqnan, psnan, 0, 0 ); _( pinf , psnan, 0, 0 ); _( pzero, psnan, 0, 0 ); _( nzero, psnan, 0, 0 ); _( ninf , psnan, 0, 0 ); _( nqnan, psnan, 0, 0 ); _( nsnan, psnan, 0, 0 );
    _( psnan, pqnan, 0, 0 ); _( pqnan, pqnan, 1, 0 ); _( pinf , pqnan, 0, 0 ); _( pzero, pqnan, 0, 0 ); _( nzero, pqnan, 0, 0 ); _( ninf , pqnan, 0, 0 ); _( nqnan, pqnan, 0, 0 ); _( nsnan, pqnan, 0, 0 );
    _( psnan, pinf , 0, 0 ); _( pqnan, pinf , 0, 0 ); _( pinf , pinf , 1, 1 ); _( pzero, pinf , 0, 0 ); _( nzero, pinf , 0, 0 ); _( ninf , pinf , 0, 0 ); _( nqnan, pinf , 0, 0 ); _( nsnan, pinf , 0, 0 );
    _( psnan, pzero, 0, 0 ); _( pqnan, pzero, 0, 0 ); _( pinf , pzero, 0, 0 ); _( pzero, pzero, 1, 1 ); _( nzero, pzero, 0, 1 ); _( ninf , pzero, 0, 0 ); _( nqnan, pzero, 0, 0 ); _( nsnan, pzero, 0, 0 );
    _( psnan, nzero, 0, 0 ); _( pqnan, nzero, 0, 0 ); _( pinf , nzero, 0, 0 ); _( pzero, nzero, 0, 1 ); _( nzero, nzero, 1, 1 ); _( ninf , nzero, 0, 0 ); _( nqnan, nzero, 0, 0 ); _( nsnan, nzero, 0, 0 );
    _( psnan, ninf , 0, 0 ); _( pqnan, ninf , 0, 0 ); _( pinf , ninf , 0, 0 ); _( pzero, ninf , 0, 0 ); _( nzero, ninf , 0, 0 ); _( ninf , ninf , 1, 1 ); _( nqnan, ninf , 0, 0 ); _( nsnan, ninf , 0, 0 );
    _( psnan, nqnan, 0, 0 ); _( pqnan, nqnan, 0, 0 ); _( pinf , nqnan, 0, 0 ); _( pzero, nqnan, 0, 0 ); _( nzero, nqnan, 0, 0 ); _( ninf , nqnan, 0, 0 ); _( nqnan, nqnan, 1, 0 ); _( nsnan, nqnan, 0, 0 );
    _( psnan, nsnan, 0, 0 ); _( pqnan, nsnan, 0, 0 ); _( pinf , nsnan, 0, 0 ); _( pzero, nsnan, 0, 0 ); _( nzero, nsnan, 0, 0 ); _( ninf , nsnan, 0, 0 ); _( nqnan, nsnan, 0, 0 ); _( nsnan, nsnan, 1, 0 );
#   undef _
#   endif

    FD_TEST( double_as_ulong( fd_double_abs( psnan ) )==double_as_ulong( psnan ) );
    FD_TEST( double_as_ulong( fd_double_abs( pqnan ) )==double_as_ulong( pqnan ) );
    FD_TEST( double_as_ulong( fd_double_abs( pinf  ) )==double_as_ulong( pinf  ) );
    FD_TEST( double_as_ulong( fd_double_abs( pzero ) )==double_as_ulong( pzero ) );
    FD_TEST( double_as_ulong( fd_double_abs( nzero ) )==double_as_ulong( pzero ) );
    FD_TEST( double_as_ulong( fd_double_abs( ninf  ) )==double_as_ulong( pinf  ) );
    FD_TEST( double_as_ulong( fd_double_abs( nqnan ) )==double_as_ulong( pqnan ) );
    FD_TEST( double_as_ulong( fd_double_abs( nsnan ) )==double_as_ulong( psnan ) );

    for( int iter=0; iter<16777216; iter++ ) {
      int    c = (int)(fd_rng_uint( rng ) & 1U);
      double x = ulong_as_double( fd_rng_ulong( rng ) );
      double y = ulong_as_double( fd_rng_ulong( rng ) );
      FD_TEST( fd_double_eq( fd_double_if( c, x, y ), (c ? x : y) ) );
      FD_TEST( double_as_ulong( fd_double_abs( x ) )==(((double_as_ulong( x ))<<1)>>1) );

      double z = x; fd_double_store_if( c, &z, y ); FD_TEST( fd_double_eq( z, (c ? y : x) ) );

      double xx; double yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );
    }
  }
# endif

  if(1) {
    FD_LOG_NOTICE(( "Testing unaligned" ));

    uchar buf[2048];
    for( ulong i=0UL; i<2048UL; i++ ) buf[i] = fd_rng_uchar( rng );
    for( ulong i=0UL; i<2048UL; i++ ) {
      if( 1 ) {
        uchar * d = buf + i; uchar const * s = d;
        uchar ref; memcpy( &ref, s, 1UL ); uchar refb = (uchar)~ref;
        FD_TEST( FD_STORE( uchar, d, refb )==(uchar *)d ); FD_TEST( FD_LOAD( uchar, s )==refb );
        FD_TEST( FD_STORE( uchar, d, ref  )==(uchar *)d ); FD_TEST( FD_LOAD( uchar, s )==ref  );
        FD_TEST( fd_uchar_load_1( s )==ref ); FD_TEST( fd_uchar_load_1_fast( s )==ref );
      }
      if( (i+2UL)<=2048UL ) {
        uchar * d = buf + i; uchar const * s = d;
        ushort ref; memcpy( &ref, s, 2UL ); ushort refb = (ushort)~ref;
        FD_TEST( FD_STORE( ushort, d, refb )==(ushort *)d ); FD_TEST( FD_LOAD( ushort, s )==refb );
        FD_TEST( FD_STORE( ushort, d, ref  )==(ushort *)d ); FD_TEST( FD_LOAD( ushort, s )==ref  );
        ushort mask = (ushort)~(ushort)0;
        FD_TEST( fd_ushort_load_2( s )==ref ); FD_TEST( fd_ushort_load_2_fast( s )==ref ); mask >>= 8; ref &= mask;
        FD_TEST( fd_ushort_load_1( s )==ref ); FD_TEST( fd_ushort_load_1_fast( s )==ref );
      }
      if( (i+4UL)<=2048UL ) {
        uchar * d = buf + i; uchar const * s = d;
        uint ref; memcpy( &ref, s, 4UL ); uint refb = ~ref;
        FD_TEST( FD_STORE( uint, d, refb )==(uint *)d ); FD_TEST( FD_LOAD( uint, s )==refb );
        FD_TEST( FD_STORE( uint, d, ref  )==(uint *)d ); FD_TEST( FD_LOAD( uint, s )==ref  );
        uint mask = ~0U;
        FD_TEST( fd_uint_load_4( s )==ref ); FD_TEST( fd_uint_load_4_fast( s )==ref ); mask >>= 8; ref &= mask;
        FD_TEST( fd_uint_load_3( s )==ref ); FD_TEST( fd_uint_load_3_fast( s )==ref ); mask >>= 8; ref &= mask;
        FD_TEST( fd_uint_load_2( s )==ref ); FD_TEST( fd_uint_load_2_fast( s )==ref ); mask >>= 8; ref &= mask;
        FD_TEST( fd_uint_load_1( s )==ref ); FD_TEST( fd_uint_load_1_fast( s )==ref );
      }
      if( (i+8UL)<=2048UL ) {
        uchar * d = buf + i; uchar const * s = d;
        ulong ref; memcpy( &ref, s, 8UL ); ulong refb = ~ref;
        FD_TEST( FD_STORE( ulong, d, refb )==(ulong *)d ); FD_TEST( FD_LOAD( ulong, s )==refb );
        FD_TEST( FD_STORE( ulong, d, ref  )==(ulong *)d ); FD_TEST( FD_LOAD( ulong, s )==ref  );
        ulong mask = ~0UL;
        FD_TEST( fd_ulong_load_8( s )==ref ); FD_TEST( fd_ulong_load_8_fast( s )==ref ); mask >>= 8; ref &= mask;
        FD_TEST( fd_ulong_load_7( s )==ref ); FD_TEST( fd_ulong_load_7_fast( s )==ref ); mask >>= 8; ref &= mask;
        FD_TEST( fd_ulong_load_6( s )==ref ); FD_TEST( fd_ulong_load_6_fast( s )==ref ); mask >>= 8; ref &= mask;
        FD_TEST( fd_ulong_load_5( s )==ref ); FD_TEST( fd_ulong_load_5_fast( s )==ref ); mask >>= 8; ref &= mask;
        FD_TEST( fd_ulong_load_4( s )==ref ); FD_TEST( fd_ulong_load_4_fast( s )==ref ); mask >>= 8; ref &= mask;
        FD_TEST( fd_ulong_load_3( s )==ref ); FD_TEST( fd_ulong_load_3_fast( s )==ref ); mask >>= 8; ref &= mask;
        FD_TEST( fd_ulong_load_2( s )==ref ); FD_TEST( fd_ulong_load_2_fast( s )==ref ); mask >>= 8; ref &= mask;
        FD_TEST( fd_ulong_load_1( s )==ref ); FD_TEST( fd_ulong_load_1_fast( s )==ref );
      }
#     if FD_HAS_INT128 && FD_UNALIGNED_ACCESS_STYLE==0
      /* Note: for uint128 datatypes, some compiler might emit
         instructions that do not allow unaligned direct load / store so
         we only test uint128 FD_LOAD / FD_STORE under STYLE==0. */
      if( (i+16UL)<=2048UL ) {
        uchar * d = buf + i; uchar const * s = d;
        uint128 ref; memcpy( &ref, s, 8UL ); uint128 refb = ~ref;
        FD_TEST( FD_STORE( uint128, d, refb )==(uint128 *)d ); FD_TEST( FD_LOAD( uint128, s )==refb );
        FD_TEST( FD_STORE( uint128, d, ref  )==(uint128 *)d ); FD_TEST( FD_LOAD( uint128, s )==ref  );
        /* FIXME: Consider adding APIs for unaligned 128-bit access? */
      }
#     endif
    }
  }

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
