#include "../fd_util.h"

/* Note: with a handful of exceptions, this is just test_bits batteries
   for each type but with the explicit typing for the macros scrubbed. */

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
      FD_TEST( fd_is_pow2( x ) );
      FD_TEST( !fd_is_pow2( (uchar)~x ) );
    }
    for( int n=0; n<=w; n++ ) { uchar x = (uchar)((n<w) ? (1UL<<n) : 0UL); FD_TEST( fd_pow2( uchar, n )==x ); }
    for( int b=0; b< w; b++ ) {
      uchar mask  = (uchar)(1UL<<b);
      uchar maskc = (uchar)~mask;
      FD_TEST( fd_mask_bit   ( uchar, b    )==mask  );
      FD_TEST( fd_clear_bit  ( zeros, b    )==zeros ); FD_TEST( fd_set_bit    ( zeros, b    )==mask  );
      FD_TEST( fd_clear_bit  ( mask,  b    )==zeros ); FD_TEST( fd_set_bit    ( mask,  b    )==mask  );
      FD_TEST( fd_clear_bit  ( maskc, b    )==maskc ); FD_TEST( fd_set_bit    ( maskc, b    )==ones  );
      FD_TEST( fd_clear_bit  ( ones,  b    )==maskc ); FD_TEST( fd_set_bit    ( ones,  b    )==ones  );
      FD_TEST( fd_flip_bit   ( zeros, b    )==mask  ); FD_TEST( fd_extract_bit( zeros, b    )==0     );
      FD_TEST( fd_flip_bit   ( mask,  b    )==zeros ); FD_TEST( fd_extract_bit( mask,  b    )==1     );
      FD_TEST( fd_flip_bit   ( maskc, b    )==ones  ); FD_TEST( fd_extract_bit( maskc, b    )==0     );
      FD_TEST( fd_flip_bit   ( ones,  b    )==maskc ); FD_TEST( fd_extract_bit( ones,  b    )==1     );
      FD_TEST( fd_insert_bit ( zeros, b, 0 )==zeros ); FD_TEST( fd_insert_bit ( zeros, b, 1 )==mask  );
      FD_TEST( fd_insert_bit ( mask,  b, 0 )==zeros ); FD_TEST( fd_insert_bit ( mask,  b, 1 )==mask  );
      FD_TEST( fd_insert_bit ( maskc, b, 0 )==maskc ); FD_TEST( fd_insert_bit ( maskc, b, 1 )==ones  );
      FD_TEST( fd_insert_bit ( ones,  b, 0 )==maskc ); FD_TEST( fd_insert_bit ( ones,  b, 1 )==ones  );
    }
    for( int n=0; n<=w; n++ ) {
      uchar mask  = (uchar)(((n<w) ? (1UL<<n) : 0UL)-1UL);
      uchar maskc = (uchar)~mask;
      FD_TEST( fd_mask_lsb   ( uchar, n        )==mask  );
      FD_TEST( fd_clear_lsb  ( zeros, n        )==zeros ); FD_TEST( fd_set_lsb    ( zeros, n       )==mask  );
      FD_TEST( fd_clear_lsb  ( mask,  n        )==zeros ); FD_TEST( fd_set_lsb    ( mask,  n       )==mask  );
      FD_TEST( fd_clear_lsb  ( maskc, n        )==maskc ); FD_TEST( fd_set_lsb    ( maskc, n       )==ones  );
      FD_TEST( fd_clear_lsb  ( ones,  n        )==maskc ); FD_TEST( fd_set_lsb    ( ones,  n       )==ones  );
      FD_TEST( fd_flip_lsb   ( zeros, n        )==mask  ); FD_TEST( fd_extract_lsb( zeros, n       )==zeros );
      FD_TEST( fd_flip_lsb   ( mask,  n        )==zeros ); FD_TEST( fd_extract_lsb( mask,  n       )==mask  );
      FD_TEST( fd_flip_lsb   ( maskc, n        )==ones  ); FD_TEST( fd_extract_lsb( maskc, n       )==zeros );
      FD_TEST( fd_flip_lsb   ( ones,  n        )==maskc ); FD_TEST( fd_extract_lsb( ones,  n       )==mask  );
      FD_TEST( fd_insert_lsb ( zeros, n, zeros )==zeros ); FD_TEST( fd_insert_lsb ( zeros, n, mask )==mask  );
      FD_TEST( fd_insert_lsb ( mask,  n, zeros )==zeros ); FD_TEST( fd_insert_lsb ( mask,  n, mask )==mask  );
      FD_TEST( fd_insert_lsb ( maskc, n, zeros )==maskc ); FD_TEST( fd_insert_lsb ( maskc, n, mask )==ones  );
      FD_TEST( fd_insert_lsb ( ones,  n, zeros )==maskc ); FD_TEST( fd_insert_lsb ( ones,  n, mask )==ones  );
    }
    for( int h=0; h< w; h++ ) {
      for( int l=0; l<=h; l++ ) {
        uchar x     = fd_mask_lsb( uchar, h-l+1 );
        uchar mask  = (uchar)(x << l);
        uchar maskc = (uchar)~mask;
        FD_TEST( fd_mask   ( uchar, l,h        )==mask  );
        FD_TEST( fd_clear  ( zeros, l,h        )==zeros ); FD_TEST( fd_set    ( zeros, l,h    )==mask  );
        FD_TEST( fd_clear  ( mask,  l,h        )==zeros ); FD_TEST( fd_set    ( mask,  l,h    )==mask  );
        FD_TEST( fd_clear  ( maskc, l,h        )==maskc ); FD_TEST( fd_set    ( maskc, l,h    )==ones  );
        FD_TEST( fd_clear  ( ones,  l,h        )==maskc ); FD_TEST( fd_set    ( ones,  l,h    )==ones  );
        FD_TEST( fd_flip   ( zeros, l,h        )==mask  ); FD_TEST( fd_extract( zeros, l,h    )==zeros );
        FD_TEST( fd_flip   ( mask,  l,h        )==zeros ); FD_TEST( fd_extract( mask,  l,h    )==x     );
        FD_TEST( fd_flip   ( maskc, l,h        )==ones  ); FD_TEST( fd_extract( maskc, l,h    )==zeros );
        FD_TEST( fd_flip   ( ones,  l,h        )==maskc ); FD_TEST( fd_extract( ones,  l,h    )==x     );
        FD_TEST( fd_insert ( zeros, l,h, zeros )==zeros ); FD_TEST( fd_insert ( zeros, l,h, x )==mask  );
        FD_TEST( fd_insert ( mask,  l,h, zeros )==zeros ); FD_TEST( fd_insert ( mask,  l,h, x )==mask  );
        FD_TEST( fd_insert ( maskc, l,h, zeros )==maskc ); FD_TEST( fd_insert ( maskc, l,h, x )==ones  );
        FD_TEST( fd_insert ( ones,  l,h, zeros )==maskc ); FD_TEST( fd_insert ( ones,  l,h, x )==ones  );
      }
    }
    FD_TEST( fd_popcnt  ( zeros )==0                ); FD_TEST( fd_popcnt  ( ones  )==w                  );
    FD_TEST( fd_find_lsb( ones  )==0                ); FD_TEST( fd_find_msb( ones  )==(w-1)              );
    FD_TEST( fd_find_lsb_w_default( zeros, -1 )==-1 ); FD_TEST( fd_find_lsb_w_default( ones, -1 )==0     );
    FD_TEST( fd_find_msb_w_default( zeros, -1 )==-1 ); FD_TEST( fd_find_msb_w_default( ones, -1 )==(w-1) );
    FD_TEST( fd_pow2_up ( zeros )==(uchar)0         ); FD_TEST( fd_pow2_up ( ones  )==(uchar)0           );
    FD_TEST( fd_pow2_dn ( zeros )==(uchar)1         ); FD_TEST( fd_pow2_dn ( ones  )==(uchar)(1<<(w-1))  );
    for( int i=1; i<w; i++ ) {
      uchar x = (uchar)(1UL<<i);
      FD_TEST( fd_lsb     ( x )==x               ); FD_TEST( fd_pop_lsb ( x )==zeros           );
      FD_TEST( fd_popcnt  ( x )==1               ); FD_TEST( fd_popcnt  ( (uchar)~x )==(w-1)   );
      FD_TEST( fd_find_lsb( x )==i               ); FD_TEST( fd_find_msb( x )==i               );
      FD_TEST( fd_find_lsb_w_default( x, -1 )==i ); FD_TEST( fd_find_msb_w_default( x, -1 )==i );
      FD_TEST( fd_pow2_up ( x )==x               ); FD_TEST( fd_pow2_dn ( x )==x               );
      for( int j=0; j<i; j++ ) {
        uchar y = (uchar)(1UL<<j);
        uchar z = (uchar)(x|y);
        FD_TEST( fd_lsb     ( z )==y               ); FD_TEST( fd_pop_lsb ( z )==x               );
        FD_TEST( fd_popcnt  ( z )==2               ); FD_TEST( fd_popcnt  ( (uchar)~z )==(w-2)   );
        FD_TEST( fd_find_lsb( z )==j               ); FD_TEST( fd_find_msb( z )==i               );
        FD_TEST( fd_find_lsb_w_default( z, -1 )==j ); FD_TEST( fd_find_msb_w_default( z, -1 )==i );
        FD_TEST( fd_pow2_up ( z )==(uchar)(x<<1)   ); FD_TEST( fd_pow2_dn ( z )==(uchar) x       );
      }
    }
    for( int n=0; n<=w; n++ ) {
      uchar x = (uchar)((n==w)? 0U : (1U<<n )); int sl = n+(w-8)-((n>>3)<<4);
      uchar y = (uchar)((n==w)? 0U : (1U<<sl)); FD_TEST( fd_bswap( x )==y );
    }
    for( int i=0; i<w; i++ ) {
      uchar align = (uchar) (1UL<<i);
      uchar lo    = (uchar)((1UL<<i)-1UL);
      uchar hi    = (uchar)~lo;
      FD_TEST( fd_is_aligned( zeros, align )        );
      FD_TEST( fd_alignment ( zeros, align )==zeros );
      FD_TEST( fd_align_dn  ( zeros, align )==zeros );
      FD_TEST( fd_align_up  ( zeros, align )==zeros );
      FD_TEST( fd_is_aligned( ones,  align )==(!i)  );
      FD_TEST( fd_alignment ( ones,  align )==lo    );
      FD_TEST( fd_align_dn  ( ones,  align )==hi    );
      FD_TEST( fd_align_up  ( ones,  align )==((!i) ? ones : zeros) );
      for( int j=0; j<w; j++ ) {
        uchar x = (uchar)(1UL<<j);
        FD_TEST( fd_is_aligned( x, align )==(j>=i)        );
        FD_TEST( fd_alignment ( x, align )==( x     & lo) );
        FD_TEST( fd_align_dn  ( x, align )==( x     & hi) );
        FD_TEST( fd_align_up  ( x, align )==((x+lo) & hi) );
      }
    }
    for( int iter=0; iter<16777216; iter++ ) {
      uchar m = (uchar)fd_rng_ulong( rng );
      uchar x = (uchar)fd_rng_ulong( rng );
      uchar y = (uchar)fd_rng_ulong( rng );
      int   c = fd_extract_bit( m, 0 );
      FD_TEST( fd_blend( m, x, y )==(uchar)( (x & m) | (y & ~m) ) );
      FD_TEST( fd_if   ( c, x, y )==(c ? x : y)                   );
      FD_TEST( fd_abs  ( x       )==x                             );
      FD_TEST( fd_min  ( x, y    )==((x<y) ? x : y)               );
      FD_TEST( fd_max  ( x, y    )==((x>y) ? x : y)               );

      uchar z = x; fd_store_if( c, &z, y ); FD_TEST( z==(c ? y : x) );

      uchar xx; uchar yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );

      int n = (int)fd_rng_uint( rng );
      int s = n & 15;
      FD_TEST( fd_shift_left  ( x, s )==((s>7) ? ((uchar)0) : (uchar)(x<<s)) );
      FD_TEST( fd_shift_right ( x, s )==((s>7) ? ((uchar)0) : (uchar)(x>>s)) );
      FD_TEST( fd_rotate_left ( x, n )==(uchar)((x<<(n&7))|(x>>((-n)&7))) );
      FD_TEST( fd_rotate_right( x, n )==(uchar)((x>>(n&7))|(x<<((-n)&7))) );
    }
  }

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing ushort" ));
    int    w     = 16;
    ushort zeros = (ushort) 0UL;
    ushort ones  = (ushort)~0UL;
    for( int n=0; n< w; n++ ) {
      ushort x = (ushort)(1UL<<n);
      FD_TEST( fd_is_pow2( x ) );
      FD_TEST( !fd_is_pow2( (ushort)~x ) );
    }
    for( int n=0; n<=w; n++ ) { ushort x = (ushort)((n<w) ? (1UL<<n) : 0UL); FD_TEST( fd_pow2( ushort, n )==x ); }
    for( int b=0; b< w; b++ ) {
      ushort mask  = (ushort)(1UL<<b);
      ushort maskc = (ushort)~mask;
      FD_TEST( fd_mask_bit   ( ushort, b   )==mask  );
      FD_TEST( fd_clear_bit  ( zeros, b    )==zeros ); FD_TEST( fd_set_bit    ( zeros, b    )==mask  );
      FD_TEST( fd_clear_bit  ( mask,  b    )==zeros ); FD_TEST( fd_set_bit    ( mask,  b    )==mask  );
      FD_TEST( fd_clear_bit  ( maskc, b    )==maskc ); FD_TEST( fd_set_bit    ( maskc, b    )==ones  );
      FD_TEST( fd_clear_bit  ( ones,  b    )==maskc ); FD_TEST( fd_set_bit    ( ones,  b    )==ones  );
      FD_TEST( fd_flip_bit   ( zeros, b    )==mask  ); FD_TEST( fd_extract_bit( zeros, b    )==0     );
      FD_TEST( fd_flip_bit   ( mask,  b    )==zeros ); FD_TEST( fd_extract_bit( mask,  b    )==1     );
      FD_TEST( fd_flip_bit   ( maskc, b    )==ones  ); FD_TEST( fd_extract_bit( maskc, b    )==0     );
      FD_TEST( fd_flip_bit   ( ones,  b    )==maskc ); FD_TEST( fd_extract_bit( ones,  b    )==1     );
      FD_TEST( fd_insert_bit ( zeros, b, 0 )==zeros ); FD_TEST( fd_insert_bit ( zeros, b, 1 )==mask  );
      FD_TEST( fd_insert_bit ( mask,  b, 0 )==zeros ); FD_TEST( fd_insert_bit ( mask,  b, 1 )==mask  );
      FD_TEST( fd_insert_bit ( maskc, b, 0 )==maskc ); FD_TEST( fd_insert_bit ( maskc, b, 1 )==ones  );
      FD_TEST( fd_insert_bit ( ones,  b, 0 )==maskc ); FD_TEST( fd_insert_bit ( ones,  b, 1 )==ones  );
    }
    for( int n=0; n<=w; n++ ) {
      ushort mask  = (ushort)(((n<w) ? (1UL<<n) : 0UL)-1UL);
      ushort maskc = (ushort)~mask;
      FD_TEST( fd_mask_lsb   ( ushort, n       )==mask  );
      FD_TEST( fd_clear_lsb  ( zeros, n        )==zeros ); FD_TEST( fd_set_lsb    ( zeros, n       )==mask  );
      FD_TEST( fd_clear_lsb  ( mask,  n        )==zeros ); FD_TEST( fd_set_lsb    ( mask,  n       )==mask  );
      FD_TEST( fd_clear_lsb  ( maskc, n        )==maskc ); FD_TEST( fd_set_lsb    ( maskc, n       )==ones  );
      FD_TEST( fd_clear_lsb  ( ones,  n        )==maskc ); FD_TEST( fd_set_lsb    ( ones,  n       )==ones  );
      FD_TEST( fd_flip_lsb   ( zeros, n        )==mask  ); FD_TEST( fd_extract_lsb( zeros, n       )==zeros );
      FD_TEST( fd_flip_lsb   ( mask,  n        )==zeros ); FD_TEST( fd_extract_lsb( mask,  n       )==mask  );
      FD_TEST( fd_flip_lsb   ( maskc, n        )==ones  ); FD_TEST( fd_extract_lsb( maskc, n       )==zeros );
      FD_TEST( fd_flip_lsb   ( ones,  n        )==maskc ); FD_TEST( fd_extract_lsb( ones,  n       )==mask  );
      FD_TEST( fd_insert_lsb ( zeros, n, zeros )==zeros ); FD_TEST( fd_insert_lsb ( zeros, n, mask )==mask  );
      FD_TEST( fd_insert_lsb ( mask,  n, zeros )==zeros ); FD_TEST( fd_insert_lsb ( mask,  n, mask )==mask  );
      FD_TEST( fd_insert_lsb ( maskc, n, zeros )==maskc ); FD_TEST( fd_insert_lsb ( maskc, n, mask )==ones  );
      FD_TEST( fd_insert_lsb ( ones,  n, zeros )==maskc ); FD_TEST( fd_insert_lsb ( ones,  n, mask )==ones  );
    }
    for( int h=0; h< w; h++ ) {
      for( int l=0; l<=h; l++ ) {
        ushort x     = fd_mask_lsb( ushort, h-l+1 );
        ushort mask  = (ushort)(x << l);
        ushort maskc = (ushort)~mask;
        FD_TEST( fd_mask   ( ushort, l,h       )==mask  );
        FD_TEST( fd_clear  ( zeros, l,h        )==zeros ); FD_TEST( fd_set    ( zeros, l,h    )==mask  );
        FD_TEST( fd_clear  ( mask,  l,h        )==zeros ); FD_TEST( fd_set    ( mask,  l,h    )==mask  );
        FD_TEST( fd_clear  ( maskc, l,h        )==maskc ); FD_TEST( fd_set    ( maskc, l,h    )==ones  );
        FD_TEST( fd_clear  ( ones,  l,h        )==maskc ); FD_TEST( fd_set    ( ones,  l,h    )==ones  );
        FD_TEST( fd_flip   ( zeros, l,h        )==mask  ); FD_TEST( fd_extract( zeros, l,h    )==zeros );
        FD_TEST( fd_flip   ( mask,  l,h        )==zeros ); FD_TEST( fd_extract( mask,  l,h    )==x     );
        FD_TEST( fd_flip   ( maskc, l,h        )==ones  ); FD_TEST( fd_extract( maskc, l,h    )==zeros );
        FD_TEST( fd_flip   ( ones,  l,h        )==maskc ); FD_TEST( fd_extract( ones,  l,h    )==x     );
        FD_TEST( fd_insert ( zeros, l,h, zeros )==zeros ); FD_TEST( fd_insert ( zeros, l,h, x )==mask  );
        FD_TEST( fd_insert ( mask,  l,h, zeros )==zeros ); FD_TEST( fd_insert ( mask,  l,h, x )==mask  );
        FD_TEST( fd_insert ( maskc, l,h, zeros )==maskc ); FD_TEST( fd_insert ( maskc, l,h, x )==ones  );
        FD_TEST( fd_insert ( ones,  l,h, zeros )==maskc ); FD_TEST( fd_insert ( ones,  l,h, x )==ones  );
      }
    }
    FD_TEST( fd_popcnt  ( zeros )==0                ); FD_TEST( fd_popcnt  ( ones )==w                   );
    FD_TEST( fd_find_lsb( ones  )==0                ); FD_TEST( fd_find_msb( ones )==(w-1)               );
    FD_TEST( fd_find_lsb_w_default( zeros, -1 )==-1 ); FD_TEST( fd_find_lsb_w_default( ones, -1 )==0     );
    FD_TEST( fd_find_msb_w_default( zeros, -1 )==-1 ); FD_TEST( fd_find_msb_w_default( ones, -1 )==(w-1) );
    FD_TEST( fd_pow2_up ( zeros )==(ushort)0        ); FD_TEST( fd_pow2_up ( ones )==(ushort)0           );
    FD_TEST( fd_pow2_dn ( zeros )==(ushort)1        ); FD_TEST( fd_pow2_dn ( ones )==(ushort)(1<<(w-1))  );
    for( int i=1; i<w; i++ ) {
      ushort x = (ushort)(1UL<<i);
      FD_TEST( fd_lsb     ( x )==x               ); FD_TEST( fd_pop_lsb ( x )==zeros           );
      FD_TEST( fd_popcnt  ( x )==1               ); FD_TEST( fd_popcnt  ( (ushort)~x )==(w-1)  );
      FD_TEST( fd_find_lsb( x )==i               ); FD_TEST( fd_find_msb( x )==i               );
      FD_TEST( fd_find_lsb_w_default( x, -1 )==i ); FD_TEST( fd_find_msb_w_default( x, -1 )==i );
      FD_TEST( fd_pow2_up ( x )==x               ); FD_TEST( fd_pow2_dn ( x )==x               );
      for( int j=0; j<i; j++ ) {
        ushort y = (ushort)(1UL<<j);
        ushort z = (ushort)(x|y);
        FD_TEST( fd_lsb     ( z )==y               ); FD_TEST( fd_pop_lsb ( z )==x               );
        FD_TEST( fd_popcnt  ( z )==2               ); FD_TEST( fd_popcnt  ( (ushort)~z )==(w-2)  );
        FD_TEST( fd_find_lsb( z )==j               ); FD_TEST( fd_find_msb( z )==i               );
        FD_TEST( fd_find_lsb_w_default( z, -1 )==j ); FD_TEST( fd_find_msb_w_default( z, -1 )==i );
        FD_TEST( fd_pow2_up ( z )==(ushort)(x<<1)  ); FD_TEST( fd_pow2_dn ( z )==(ushort) x      );
      }
    }
    for( int n=0; n<=w; n++ ) {
      ushort x = (ushort)((n==w)? 0U : (1U<<n )); int sl = n+(w-8)-((n>>3)<<4);
      ushort y = (ushort)((n==w)? 0U : (1U<<sl)); FD_TEST( fd_bswap( x )==y );
    }
    for( int i=0; i<w; i++ ) {
      ushort align = (ushort) (1UL<<i);
      ushort lo    = (ushort)((1UL<<i)-1UL);
      ushort hi    = (ushort)~lo;
      FD_TEST( fd_is_aligned( zeros, align )        );
      FD_TEST( fd_alignment ( zeros, align )==zeros );
      FD_TEST( fd_align_dn  ( zeros, align )==zeros );
      FD_TEST( fd_align_up  ( zeros, align )==zeros );
      FD_TEST( fd_is_aligned( ones,  align )==(!i)  );
      FD_TEST( fd_alignment ( ones,  align )==lo    );
      FD_TEST( fd_align_dn  ( ones,  align )==hi    );
      FD_TEST( fd_align_up  ( ones,  align )==((!i) ? ones : zeros) );
      for( int j=0; j<w; j++ ) {
        ushort x = (ushort)(1UL<<j);
        FD_TEST( fd_is_aligned( x, align )==(j>=i)        );
        FD_TEST( fd_alignment ( x, align )==( x     & lo) );
        FD_TEST( fd_align_dn  ( x, align )==( x     & hi) );
        FD_TEST( fd_align_up  ( x, align )==((x+lo) & hi) );
      }
    }
    for( int iter=0; iter<16777216; iter++ ) {
      ushort m = (ushort)fd_rng_ulong( rng );
      ushort x = (ushort)fd_rng_ulong( rng );
      ushort y = (ushort)fd_rng_ulong( rng );
      int    c = fd_extract_bit( m, 0 );
      FD_TEST( fd_blend( m, x, y )==(ushort)( (x & m) | (y & ~m) ) );
      FD_TEST( fd_if   ( c, x, y )==(c ? x : y)                   );
      FD_TEST( fd_abs  ( x       )==x                             );
      FD_TEST( fd_min  ( x, y    )==((x<y) ? x : y)               );
      FD_TEST( fd_max  ( x, y    )==((x>y) ? x : y)               );

      ushort z = x; fd_store_if( c, &z, y ); FD_TEST( z==(c ? y : x) );

      ushort xx; ushort yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );

      int n = (int)fd_rng_uint( rng );
      int s = n & 31;
      FD_TEST( fd_shift_left  ( x, s )==((s>15) ? ((ushort)0) : (ushort)(x<<s)) );
      FD_TEST( fd_shift_right ( x, s )==((s>15) ? ((ushort)0) : (ushort)(x>>s)) );
      FD_TEST( fd_rotate_left ( x, n )==(ushort)((x<<(n&15))|(x>>((-n)&15))) );
      FD_TEST( fd_rotate_right( x, n )==(ushort)((x>>(n&15))|(x<<((-n)&15))) );
    }
  }

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing uint" ));
    int  w     = 32;
    uint zeros = (uint) 0UL;
    uint ones  = (uint)~0UL;
    for( int n=0; n< w; n++ ) {
      uint x = (uint)(1UL<<n);
      FD_TEST( fd_is_pow2( x ) );
      FD_TEST( !fd_is_pow2( (uint)~x ) );
    }
    for( int n=0; n<=w; n++ ) { uint x = (uint)((n<w) ? (1UL<<n) : 0UL); FD_TEST( fd_pow2( uint, n )==x ); }
    for( int b=0; b< w; b++ ) {
      uint mask  = (uint)(1UL<<b);
      uint maskc = (uint)~mask;
      FD_TEST( fd_mask_bit   ( uint,  b    )==mask  );
      FD_TEST( fd_clear_bit  ( zeros, b    )==zeros ); FD_TEST( fd_set_bit    ( zeros, b    )==mask  );
      FD_TEST( fd_clear_bit  ( mask,  b    )==zeros ); FD_TEST( fd_set_bit    ( mask,  b    )==mask  );
      FD_TEST( fd_clear_bit  ( maskc, b    )==maskc ); FD_TEST( fd_set_bit    ( maskc, b    )==ones  );
      FD_TEST( fd_clear_bit  ( ones,  b    )==maskc ); FD_TEST( fd_set_bit    ( ones,  b    )==ones  );
      FD_TEST( fd_flip_bit   ( zeros, b    )==mask  ); FD_TEST( fd_extract_bit( zeros, b    )==0     );
      FD_TEST( fd_flip_bit   ( mask,  b    )==zeros ); FD_TEST( fd_extract_bit( mask,  b    )==1     );
      FD_TEST( fd_flip_bit   ( maskc, b    )==ones  ); FD_TEST( fd_extract_bit( maskc, b    )==0     );
      FD_TEST( fd_flip_bit   ( ones,  b    )==maskc ); FD_TEST( fd_extract_bit( ones,  b    )==1     );
      FD_TEST( fd_insert_bit ( zeros, b, 0 )==zeros ); FD_TEST( fd_insert_bit ( zeros, b, 1 )==mask  );
      FD_TEST( fd_insert_bit ( mask,  b, 0 )==zeros ); FD_TEST( fd_insert_bit ( mask,  b, 1 )==mask  );
      FD_TEST( fd_insert_bit ( maskc, b, 0 )==maskc ); FD_TEST( fd_insert_bit ( maskc, b, 1 )==ones  );
      FD_TEST( fd_insert_bit ( ones,  b, 0 )==maskc ); FD_TEST( fd_insert_bit ( ones,  b, 1 )==ones  );
    }
    for( int n=0; n<=w; n++ ) {
      uint mask  = (uint)(((n<w) ? (1UL<<n) : 0UL)-1UL);
      uint maskc = (uint)~mask;
      FD_TEST( fd_mask_lsb   ( uint,  n        )==mask  );
      FD_TEST( fd_clear_lsb  ( zeros, n        )==zeros ); FD_TEST( fd_set_lsb    ( zeros, n       )==mask  );
      FD_TEST( fd_clear_lsb  ( mask,  n        )==zeros ); FD_TEST( fd_set_lsb    ( mask,  n       )==mask  );
      FD_TEST( fd_clear_lsb  ( maskc, n        )==maskc ); FD_TEST( fd_set_lsb    ( maskc, n       )==ones  );
      FD_TEST( fd_clear_lsb  ( ones,  n        )==maskc ); FD_TEST( fd_set_lsb    ( ones,  n       )==ones  );
      FD_TEST( fd_flip_lsb   ( zeros, n        )==mask  ); FD_TEST( fd_extract_lsb( zeros, n       )==zeros );
      FD_TEST( fd_flip_lsb   ( mask,  n        )==zeros ); FD_TEST( fd_extract_lsb( mask,  n       )==mask  );
      FD_TEST( fd_flip_lsb   ( maskc, n        )==ones  ); FD_TEST( fd_extract_lsb( maskc, n       )==zeros );
      FD_TEST( fd_flip_lsb   ( ones,  n        )==maskc ); FD_TEST( fd_extract_lsb( ones,  n       )==mask  );
      FD_TEST( fd_insert_lsb ( zeros, n, zeros )==zeros ); FD_TEST( fd_insert_lsb ( zeros, n, mask )==mask  );
      FD_TEST( fd_insert_lsb ( mask,  n, zeros )==zeros ); FD_TEST( fd_insert_lsb ( mask,  n, mask )==mask  );
      FD_TEST( fd_insert_lsb ( maskc, n, zeros )==maskc ); FD_TEST( fd_insert_lsb ( maskc, n, mask )==ones  );
      FD_TEST( fd_insert_lsb ( ones,  n, zeros )==maskc ); FD_TEST( fd_insert_lsb ( ones,  n, mask )==ones  );
    }
    for( int h=0; h< w; h++ ) {
      for( int l=0; l<=h; l++ ) {
        uint x     = fd_mask_lsb( uint, h-l+1 );
        uint mask  = (uint)(x << l);
        uint maskc = (uint)~mask;
        FD_TEST( fd_mask   ( uint,  l,h        )==mask  );
        FD_TEST( fd_clear  ( zeros, l,h        )==zeros ); FD_TEST( fd_set    ( zeros, l,h    )==mask  );
        FD_TEST( fd_clear  ( mask,  l,h        )==zeros ); FD_TEST( fd_set    ( mask,  l,h    )==mask  );
        FD_TEST( fd_clear  ( maskc, l,h        )==maskc ); FD_TEST( fd_set    ( maskc, l,h    )==ones  );
        FD_TEST( fd_clear  ( ones,  l,h        )==maskc ); FD_TEST( fd_set    ( ones,  l,h    )==ones  );
        FD_TEST( fd_flip   ( zeros, l,h        )==mask  ); FD_TEST( fd_extract( zeros, l,h    )==zeros );
        FD_TEST( fd_flip   ( mask,  l,h        )==zeros ); FD_TEST( fd_extract( mask,  l,h    )==x     );
        FD_TEST( fd_flip   ( maskc, l,h        )==ones  ); FD_TEST( fd_extract( maskc, l,h    )==zeros );
        FD_TEST( fd_flip   ( ones,  l,h        )==maskc ); FD_TEST( fd_extract( ones,  l,h    )==x     );
        FD_TEST( fd_insert ( zeros, l,h, zeros )==zeros ); FD_TEST( fd_insert ( zeros, l,h, x )==mask  );
        FD_TEST( fd_insert ( mask,  l,h, zeros )==zeros ); FD_TEST( fd_insert ( mask,  l,h, x )==mask  );
        FD_TEST( fd_insert ( maskc, l,h, zeros )==maskc ); FD_TEST( fd_insert ( maskc, l,h, x )==ones  );
        FD_TEST( fd_insert ( ones,  l,h, zeros )==maskc ); FD_TEST( fd_insert ( ones,  l,h, x )==ones  );
      }
    }
    FD_TEST( fd_popcnt  ( zeros )==0                ); FD_TEST( fd_popcnt  ( ones  )==w                  );
    FD_TEST( fd_find_lsb( ones  )==0                ); FD_TEST( fd_find_msb( ones  )==(w-1)              );
    FD_TEST( fd_find_lsb_w_default( zeros, -1 )==-1 ); FD_TEST( fd_find_lsb_w_default( ones, -1 )==0     );
    FD_TEST( fd_find_msb_w_default( zeros, -1 )==-1 ); FD_TEST( fd_find_msb_w_default( ones, -1 )==(w-1) );
    FD_TEST( fd_pow2_up ( zeros )==0U               ); FD_TEST( fd_pow2_up ( ones  )==0U                 );
    FD_TEST( fd_pow2_dn ( zeros )==1U               ); FD_TEST( fd_pow2_dn ( ones  )==(1U<<(w-1))        );
    for( int i=1; i<w; i++ ) {
      uint x = (uint)(1UL<<i);
      FD_TEST( fd_lsb     ( x )==x               ); FD_TEST( fd_pop_lsb (  x )==zeros          );
      FD_TEST( fd_popcnt  ( x )==1               ); FD_TEST( fd_popcnt  ( ~x )==(w-1)          );
      FD_TEST( fd_find_lsb( x )==i               ); FD_TEST( fd_find_msb(  x )==i              );
      FD_TEST( fd_find_lsb_w_default( x, -1 )==i ); FD_TEST( fd_find_msb_w_default( x, -1 )==i );
      FD_TEST( fd_pow2_up ( x )==x               ); FD_TEST( fd_pow2_dn (  x )==x              );
      for( int j=0; j<i; j++ ) {
        uint y = (uint)(1UL<<j);
        uint z = (uint)(x|y);
        FD_TEST( fd_lsb     ( z )==y               ); FD_TEST( fd_pop_lsb (  z )==x              );
        FD_TEST( fd_popcnt  ( z )==2               ); FD_TEST( fd_popcnt  ( ~z )==(w-2)          );
        FD_TEST( fd_find_lsb( z )==j               ); FD_TEST( fd_find_msb(  z )==i              );
        FD_TEST( fd_find_lsb_w_default( z, -1 )==j ); FD_TEST( fd_find_msb_w_default( z, -1 )==i );
        FD_TEST( fd_pow2_up ( z )==(x<<1)          ); FD_TEST( fd_pow2_dn (  z )==x              );
      }
    }
    for( int n=0; n<=w; n++ ) {
      uint x = (uint)((n==w)? 0U : (1U<<n )); int sl = n+(w-8)-((n>>3)<<4);
      uint y = (uint)((n==w)? 0U : (1U<<sl)); FD_TEST( fd_bswap( x )==y );
    }
    for( int i=0; i<w; i++ ) {
      uint align = (uint) (1UL<<i);
      uint lo    = (uint)((1UL<<i)-1UL);
      uint hi    = (uint)~lo;
      FD_TEST( fd_is_aligned( zeros, align )        );
      FD_TEST( fd_alignment ( zeros, align )==zeros );
      FD_TEST( fd_align_dn  ( zeros, align )==zeros );
      FD_TEST( fd_align_up  ( zeros, align )==zeros );
      FD_TEST( fd_is_aligned( ones,  align )==(!i)  );
      FD_TEST( fd_alignment ( ones,  align )==lo    );
      FD_TEST( fd_align_dn  ( ones,  align )==hi    );
      FD_TEST( fd_align_up  ( ones,  align )==((!i) ? ones : zeros) );
      for( int j=0; j<w; j++ ) {
        uint x = (uint)(1UL<<j);
        FD_TEST( fd_is_aligned( x, align )==(j>=i)        );
        FD_TEST( fd_alignment ( x, align )==( x     & lo) );
        FD_TEST( fd_align_dn  ( x, align )==( x     & hi) );
        FD_TEST( fd_align_up  ( x, align )==((x+lo) & hi) );
      }
    }
    for( int iter=0; iter<16777216; iter++ ) {
      uint m = (uint)fd_rng_ulong( rng );
      uint x = (uint)fd_rng_ulong( rng );
      uint y = (uint)fd_rng_ulong( rng );
      int  c = fd_extract_bit( m, 0 );
      FD_TEST( fd_blend( m, x, y )==(uint)( (x & m) | (y & ~m) )  );
      FD_TEST( fd_if   ( c, x, y )==(c ? x : y)                   );
      FD_TEST( fd_abs  ( x       )==x                             );
      FD_TEST( fd_min  ( x, y    )==((x<y) ? x : y)               );
      FD_TEST( fd_max  ( x, y    )==((x>y) ? x : y)               );

      uint z = x; fd_store_if( c, &z, y ); FD_TEST( z==(c ? y : x) );

      uint xx; uint yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );

      int n = (int)y;
      int s = n & 63;
      FD_TEST( fd_shift_left  ( x, s )==((s>31) ? 0U : (uint)(x<<s)) );
      FD_TEST( fd_shift_right ( x, s )==((s>31) ? 0U : (uint)(x>>s)) );
      FD_TEST( fd_rotate_left ( x, n )==((x<<(n&31))|(x>>((-n)&31))) );
      FD_TEST( fd_rotate_right( x, n )==((x>>(n&31))|(x<<((-n)&31))) );
    }
  }

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing ulong" ));
    int   w     = 64;
    ulong zeros = (ulong) 0UL;
    ulong ones  = (ulong)~0UL;
    for( int n=0; n< w; n++ ) {
      ulong x = (ulong)(1UL<<n);
      FD_TEST( fd_is_pow2( x ) );
      FD_TEST( !fd_is_pow2( (ulong)~x ) );
    }
    for( int n=0; n<=w; n++ ) { ulong x = (ulong)((n<w) ? (1UL<<n) : 0UL); FD_TEST( fd_pow2( ulong, n )==x ); }
    for( int b=0; b< w; b++ ) {
      ulong mask  = (ulong)(1UL<<b);
      ulong maskc = (ulong)~mask;
      FD_TEST( fd_mask_bit   ( ulong, b    )==mask  );
      FD_TEST( fd_clear_bit  ( zeros, b    )==zeros ); FD_TEST( fd_set_bit    ( zeros, b    )==mask  );
      FD_TEST( fd_clear_bit  ( mask,  b    )==zeros ); FD_TEST( fd_set_bit    ( mask,  b    )==mask  );
      FD_TEST( fd_clear_bit  ( maskc, b    )==maskc ); FD_TEST( fd_set_bit    ( maskc, b    )==ones  );
      FD_TEST( fd_clear_bit  ( ones,  b    )==maskc ); FD_TEST( fd_set_bit    ( ones,  b    )==ones  );
      FD_TEST( fd_flip_bit   ( zeros, b    )==mask  ); FD_TEST( fd_extract_bit( zeros, b    )==0     );
      FD_TEST( fd_flip_bit   ( mask,  b    )==zeros ); FD_TEST( fd_extract_bit( mask,  b    )==1     );
      FD_TEST( fd_flip_bit   ( maskc, b    )==ones  ); FD_TEST( fd_extract_bit( maskc, b    )==0     );
      FD_TEST( fd_flip_bit   ( ones,  b    )==maskc ); FD_TEST( fd_extract_bit( ones,  b    )==1     );
      FD_TEST( fd_insert_bit ( zeros, b, 0 )==zeros ); FD_TEST( fd_insert_bit ( zeros, b, 1 )==mask  );
      FD_TEST( fd_insert_bit ( mask,  b, 0 )==zeros ); FD_TEST( fd_insert_bit ( mask,  b, 1 )==mask  );
      FD_TEST( fd_insert_bit ( maskc, b, 0 )==maskc ); FD_TEST( fd_insert_bit ( maskc, b, 1 )==ones  );
      FD_TEST( fd_insert_bit ( ones,  b, 0 )==maskc ); FD_TEST( fd_insert_bit ( ones,  b, 1 )==ones  );
    }
    for( int n=0; n<=w; n++ ) {
      ulong mask  = (ulong)(((n<w) ? (1UL<<n) : 0UL)-1UL);
      ulong maskc = (ulong)~mask;
      FD_TEST( fd_mask_lsb   ( ulong, n        )==mask  );
      FD_TEST( fd_clear_lsb  ( zeros, n        )==zeros ); FD_TEST( fd_set_lsb    ( zeros, n       )==mask  );
      FD_TEST( fd_clear_lsb  ( mask,  n        )==zeros ); FD_TEST( fd_set_lsb    ( mask,  n       )==mask  );
      FD_TEST( fd_clear_lsb  ( maskc, n        )==maskc ); FD_TEST( fd_set_lsb    ( maskc, n       )==ones  );
      FD_TEST( fd_clear_lsb  ( ones,  n        )==maskc ); FD_TEST( fd_set_lsb    ( ones,  n       )==ones  );
      FD_TEST( fd_flip_lsb   ( zeros, n        )==mask  ); FD_TEST( fd_extract_lsb( zeros, n       )==zeros );
      FD_TEST( fd_flip_lsb   ( mask,  n        )==zeros ); FD_TEST( fd_extract_lsb( mask,  n       )==mask  );
      FD_TEST( fd_flip_lsb   ( maskc, n        )==ones  ); FD_TEST( fd_extract_lsb( maskc, n       )==zeros );
      FD_TEST( fd_flip_lsb   ( ones,  n        )==maskc ); FD_TEST( fd_extract_lsb( ones,  n       )==mask  );
      FD_TEST( fd_insert_lsb ( zeros, n, zeros )==zeros ); FD_TEST( fd_insert_lsb ( zeros, n, mask )==mask  );
      FD_TEST( fd_insert_lsb ( mask,  n, zeros )==zeros ); FD_TEST( fd_insert_lsb ( mask,  n, mask )==mask  );
      FD_TEST( fd_insert_lsb ( maskc, n, zeros )==maskc ); FD_TEST( fd_insert_lsb ( maskc, n, mask )==ones  );
      FD_TEST( fd_insert_lsb ( ones,  n, zeros )==maskc ); FD_TEST( fd_insert_lsb ( ones,  n, mask )==ones  );
    }
    for( int h=0; h< w; h++ ) {
      for( int l=0; l<=h; l++ ) {
        ulong x     = fd_mask_lsb( ulong, h-l+1 );
        ulong mask  = (ulong)(x << l);
        ulong maskc = (ulong)~mask;
        FD_TEST( fd_mask   ( ulong, l,h        )==mask  );
        FD_TEST( fd_clear  ( zeros, l,h        )==zeros ); FD_TEST( fd_set    ( zeros, l,h    )==mask  );
        FD_TEST( fd_clear  ( mask,  l,h        )==zeros ); FD_TEST( fd_set    ( mask,  l,h    )==mask  );
        FD_TEST( fd_clear  ( maskc, l,h        )==maskc ); FD_TEST( fd_set    ( maskc, l,h    )==ones  );
        FD_TEST( fd_clear  ( ones,  l,h        )==maskc ); FD_TEST( fd_set    ( ones,  l,h    )==ones  );
        FD_TEST( fd_flip   ( zeros, l,h        )==mask  ); FD_TEST( fd_extract( zeros, l,h    )==zeros );
        FD_TEST( fd_flip   ( mask,  l,h        )==zeros ); FD_TEST( fd_extract( mask,  l,h    )==x     );
        FD_TEST( fd_flip   ( maskc, l,h        )==ones  ); FD_TEST( fd_extract( maskc, l,h    )==zeros );
        FD_TEST( fd_flip   ( ones,  l,h        )==maskc ); FD_TEST( fd_extract( ones,  l,h    )==x     );
        FD_TEST( fd_insert ( zeros, l,h, zeros )==zeros ); FD_TEST( fd_insert ( zeros, l,h, x )==mask  );
        FD_TEST( fd_insert ( mask,  l,h, zeros )==zeros ); FD_TEST( fd_insert ( mask,  l,h, x )==mask  );
        FD_TEST( fd_insert ( maskc, l,h, zeros )==maskc ); FD_TEST( fd_insert ( maskc, l,h, x )==ones  );
        FD_TEST( fd_insert ( ones,  l,h, zeros )==maskc ); FD_TEST( fd_insert ( ones,  l,h, x )==ones  );
      }
    }
    FD_TEST( fd_popcnt  ( zeros )==0                ); FD_TEST( fd_popcnt  ( ones  )==w                  );
    FD_TEST( fd_find_lsb( ones  )==0                ); FD_TEST( fd_find_msb( ones  )==(w-1)              );
    FD_TEST( fd_find_lsb_w_default( zeros, -1 )==-1 ); FD_TEST( fd_find_lsb_w_default( ones, -1 )==0     );
    FD_TEST( fd_find_msb_w_default( zeros, -1 )==-1 ); FD_TEST( fd_find_msb_w_default( ones, -1 )==(w-1) );
    FD_TEST( fd_pow2_up ( zeros )==0UL              ); FD_TEST( fd_pow2_up ( ones  )==0UL                );
    FD_TEST( fd_pow2_dn ( zeros )==1UL              ); FD_TEST( fd_pow2_dn ( ones  )==(1UL<<(w-1))       );
    for( int i=1; i<w; i++ ) {
      ulong x = (ulong)(1UL<<i);
      FD_TEST( fd_lsb     ( x )==x               ); FD_TEST( fd_pop_lsb (  x )==zeros          );
      FD_TEST( fd_popcnt  ( x )==1               ); FD_TEST( fd_popcnt  ( ~x )==(w-1)          );
      FD_TEST( fd_find_lsb( x )==i               ); FD_TEST( fd_find_msb(  x )==i              );
      FD_TEST( fd_find_lsb_w_default( x, -1 )==i ); FD_TEST( fd_find_msb_w_default( x, -1 )==i );
      FD_TEST( fd_pow2_up ( x )==x               ); FD_TEST( fd_pow2_dn (  x )==x              );
      for( int j=0; j<i; j++ ) {
        ulong y = (ulong)(1UL<<j);
        ulong z = (ulong)(x|y);
        FD_TEST( fd_lsb     ( z )==y               ); FD_TEST( fd_pop_lsb (  z )==x              );
        FD_TEST( fd_popcnt  ( z )==2               ); FD_TEST( fd_popcnt  ( ~z )==(w-2)          );
        FD_TEST( fd_find_lsb( z )==j               ); FD_TEST( fd_find_msb(  z )==i              );
        FD_TEST( fd_find_lsb_w_default( z, -1 )==j ); FD_TEST( fd_find_msb_w_default( z, -1 )==i );
        FD_TEST( fd_pow2_up ( z )==(x<<1)          ); FD_TEST( fd_pow2_dn (  z )==x              );
      }
    }
    for( int n=0; n<=w; n++ ) {
      int sl = n+(w-8)-((n>>3)<<4);
      ulong x = (ulong)((n==w)? 0UL : (1UL<<n ));
      ulong y = (ulong)((n==w)? 0UL : (1UL<<sl));
      FD_TEST( fd_bswap( x )==y );
    }
    for( int i=0; i<w; i++ ) {
      ulong align = (ulong) (1UL<<i);
      ulong lo    = (ulong)((1UL<<i)-1UL);
      ulong hi    = (ulong)~lo;
      FD_TEST( fd_is_aligned( zeros, align )        );
      FD_TEST( fd_alignment ( zeros, align )==zeros );
      FD_TEST( fd_align_dn  ( zeros, align )==zeros );
      FD_TEST( fd_align_up  ( zeros, align )==zeros );
      FD_TEST( fd_is_aligned( ones,  align )==(!i)  );
      FD_TEST( fd_alignment ( ones,  align )==lo    );
      FD_TEST( fd_align_dn  ( ones,  align )==hi    );
      FD_TEST( fd_align_up  ( ones,  align )==((!i) ? ones : zeros) );
      for( int j=0; j<w; j++ ) {
        ulong x = (ulong)(1UL<<j);
        FD_TEST( fd_is_aligned( x, align )==(j>=i)        );
        FD_TEST( fd_alignment ( x, align )==( x     & lo) );
        FD_TEST( fd_align_dn  ( x, align )==( x     & hi) );
        FD_TEST( fd_align_up  ( x, align )==((x+lo) & hi) );
      }
    }

    for( int iter=0; iter<16777216; iter++ ) {
      ulong m = (ulong)fd_rng_ulong( rng );
      ulong x = (ulong)fd_rng_ulong( rng );
      ulong y = (ulong)fd_rng_ulong( rng );
      int   c = fd_extract_bit( m, 0 );
      FD_TEST( fd_blend( m, x, y )==(ulong)( (x & m) | (y & ~m) ) );
      FD_TEST( fd_if   ( c, x, y )==(c ? x : y)                   );
      FD_TEST( fd_abs  ( x       )==x                             );
      FD_TEST( fd_min  ( x, y    )==((x<y) ? x : y)               );
      FD_TEST( fd_max  ( x, y    )==((x>y) ? x : y)               );

      ulong z = x; fd_store_if( c, &z, y ); FD_TEST( z==(c ? y : x) );

      ulong xx; ulong yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );

      FD_TEST( fd_ptr_if( c, (uchar *)x, (uchar *)y )==(uchar *)(c ? x : y) );

      int n = (int)(uint)y;
      int s = n & 127;
      FD_TEST( fd_shift_left  ( x, s )==((s>63) ? 0UL : (ulong)(x<<s)) );
      FD_TEST( fd_shift_right ( x, s )==((s>63) ? 0UL : (ulong)(x>>s)) );
      FD_TEST( fd_rotate_left ( x, n )==((x<<(n&63))|(x>>((-n)&63))) );
      FD_TEST( fd_rotate_right( x, n )==((x>>(n&63))|(x<<((-n)&63))) );
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
      FD_TEST( fd_is_pow2( x ) );
      FD_TEST( !fd_is_pow2( ~x ) );
    }
    for( int n=0; n<=w; n++ ) { uint128 x = ((n<w) ? (((uint128)1)<<n) : ((uint128)0)); FD_TEST( fd_pow2( uint128, n )==x ); }
    for( int b=0; b< w; b++ ) {
      uint128 mask  = ((uint128)1)<<b;
      uint128 maskc = ~mask;
      FD_TEST( fd_mask_bit   ( uint128, b  )==mask  );
      FD_TEST( fd_clear_bit  ( zeros, b    )==zeros ); FD_TEST( fd_set_bit    ( zeros, b    )==mask  );
      FD_TEST( fd_clear_bit  ( mask,  b    )==zeros ); FD_TEST( fd_set_bit    ( mask,  b    )==mask  );
      FD_TEST( fd_clear_bit  ( maskc, b    )==maskc ); FD_TEST( fd_set_bit    ( maskc, b    )==ones  );
      FD_TEST( fd_clear_bit  ( ones,  b    )==maskc ); FD_TEST( fd_set_bit    ( ones,  b    )==ones  );
      FD_TEST( fd_flip_bit   ( zeros, b    )==mask  ); FD_TEST( fd_extract_bit( zeros, b    )==0     );
      FD_TEST( fd_flip_bit   ( mask,  b    )==zeros ); FD_TEST( fd_extract_bit( mask,  b    )==1     );
      FD_TEST( fd_flip_bit   ( maskc, b    )==ones  ); FD_TEST( fd_extract_bit( maskc, b    )==0     );
      FD_TEST( fd_flip_bit   ( ones,  b    )==maskc ); FD_TEST( fd_extract_bit( ones,  b    )==1     );
      FD_TEST( fd_insert_bit ( zeros, b, 0 )==zeros ); FD_TEST( fd_insert_bit ( zeros, b, 1 )==mask  );
      FD_TEST( fd_insert_bit ( mask,  b, 0 )==zeros ); FD_TEST( fd_insert_bit ( mask,  b, 1 )==mask  );
      FD_TEST( fd_insert_bit ( maskc, b, 0 )==maskc ); FD_TEST( fd_insert_bit ( maskc, b, 1 )==ones  );
      FD_TEST( fd_insert_bit ( ones,  b, 0 )==maskc ); FD_TEST( fd_insert_bit ( ones,  b, 1 )==ones  );
    }
    for( int n=0; n<=w; n++ ) {
      uint128 mask  = ((n<w) ? (((uint128)1)<<n) : ((uint128)0))-((uint128)1);
      uint128 maskc = ~mask;
      FD_TEST( fd_mask_lsb   ( uint128, n      )==mask  );
      FD_TEST( fd_clear_lsb  ( zeros, n        )==zeros ); FD_TEST( fd_set_lsb    ( zeros, n       )==mask  );
      FD_TEST( fd_clear_lsb  ( mask,  n        )==zeros ); FD_TEST( fd_set_lsb    ( mask,  n       )==mask  );
      FD_TEST( fd_clear_lsb  ( maskc, n        )==maskc ); FD_TEST( fd_set_lsb    ( maskc, n       )==ones  );
      FD_TEST( fd_clear_lsb  ( ones,  n        )==maskc ); FD_TEST( fd_set_lsb    ( ones,  n       )==ones  );
      FD_TEST( fd_flip_lsb   ( zeros, n        )==mask  ); FD_TEST( fd_extract_lsb( zeros, n       )==zeros );
      FD_TEST( fd_flip_lsb   ( mask,  n        )==zeros ); FD_TEST( fd_extract_lsb( mask,  n       )==mask  );
      FD_TEST( fd_flip_lsb   ( maskc, n        )==ones  ); FD_TEST( fd_extract_lsb( maskc, n       )==zeros );
      FD_TEST( fd_flip_lsb   ( ones,  n        )==maskc ); FD_TEST( fd_extract_lsb( ones,  n       )==mask  );
      FD_TEST( fd_insert_lsb ( zeros, n, zeros )==zeros ); FD_TEST( fd_insert_lsb ( zeros, n, mask )==mask  );
      FD_TEST( fd_insert_lsb ( mask,  n, zeros )==zeros ); FD_TEST( fd_insert_lsb ( mask,  n, mask )==mask  );
      FD_TEST( fd_insert_lsb ( maskc, n, zeros )==maskc ); FD_TEST( fd_insert_lsb ( maskc, n, mask )==ones  );
      FD_TEST( fd_insert_lsb ( ones,  n, zeros )==maskc ); FD_TEST( fd_insert_lsb ( ones,  n, mask )==ones  );
    }
    for( int h=0; h< w; h++ ) {
      for( int l=0; l<=h; l++ ) {
        uint128 x     = fd_mask_lsb( uint128, h-l+1 );
        uint128 mask  = x << l;
        uint128 maskc = ~mask;
        FD_TEST( fd_mask   ( uint128, l,h      )==mask  );
        FD_TEST( fd_clear  ( zeros, l,h        )==zeros ); FD_TEST( fd_set    ( zeros, l,h    )==mask  );
        FD_TEST( fd_clear  ( mask,  l,h        )==zeros ); FD_TEST( fd_set    ( mask,  l,h    )==mask  );
        FD_TEST( fd_clear  ( maskc, l,h        )==maskc ); FD_TEST( fd_set    ( maskc, l,h    )==ones  );
        FD_TEST( fd_clear  ( ones,  l,h        )==maskc ); FD_TEST( fd_set    ( ones,  l,h    )==ones  );
        FD_TEST( fd_flip   ( zeros, l,h        )==mask  ); FD_TEST( fd_extract( zeros, l,h    )==zeros );
        FD_TEST( fd_flip   ( mask,  l,h        )==zeros ); FD_TEST( fd_extract( mask,  l,h    )==x     );
        FD_TEST( fd_flip   ( maskc, l,h        )==ones  ); FD_TEST( fd_extract( maskc, l,h    )==zeros );
        FD_TEST( fd_flip   ( ones,  l,h        )==maskc ); FD_TEST( fd_extract( ones,  l,h    )==x     );
        FD_TEST( fd_insert ( zeros, l,h, zeros )==zeros ); FD_TEST( fd_insert ( zeros, l,h, x )==mask  );
        FD_TEST( fd_insert ( mask,  l,h, zeros )==zeros ); FD_TEST( fd_insert ( mask,  l,h, x )==mask  );
        FD_TEST( fd_insert ( maskc, l,h, zeros )==maskc ); FD_TEST( fd_insert ( maskc, l,h, x )==ones  );
        FD_TEST( fd_insert ( ones,  l,h, zeros )==maskc ); FD_TEST( fd_insert ( ones,  l,h, x )==ones  );
      }
    }
    FD_TEST( fd_popcnt  ( zeros )==0                ); FD_TEST( fd_popcnt  ( ones  )==w                     );
    FD_TEST( fd_find_lsb( ones  )==0                ); FD_TEST( fd_find_msb( ones  )==(w-1)                 );
    FD_TEST( fd_find_lsb_w_default( zeros, -1 )==-1 ); FD_TEST( fd_find_lsb_w_default( ones, -1 )==0        );
    FD_TEST( fd_find_msb_w_default( zeros, -1 )==-1 ); FD_TEST( fd_find_msb_w_default( ones, -1 )==(w-1)    );
    FD_TEST( fd_pow2_up ( zeros )==(uint128)0       ); FD_TEST( fd_pow2_up ( ones  )==(uint128)0            );
    FD_TEST( fd_pow2_dn ( zeros )==(uint128)1       ); FD_TEST( fd_pow2_dn ( ones  )==(((uint128)1)<<(w-1)) );
    for( int i=1; i<w; i++ ) {
      uint128 x = ((uint128)1)<<i;
      FD_TEST( fd_lsb     ( x )==x               ); FD_TEST( fd_pop_lsb (  x )==zeros          );
      FD_TEST( fd_popcnt  ( x )==1               ); FD_TEST( fd_popcnt  ( ~x )==(w-1)          );
      FD_TEST( fd_find_lsb( x )==i               ); FD_TEST( fd_find_msb(  x )==i              );
      FD_TEST( fd_find_lsb_w_default( x, -1 )==i ); FD_TEST( fd_find_msb_w_default( x, -1 )==i );
      FD_TEST( fd_pow2_up ( x )==x               ); FD_TEST( fd_pow2_dn ( x )==x               );
      for( int j=0; j<i; j++ ) {
        uint128 y = ((uint128)1)<<j;
        uint128 z = x|y;
        FD_TEST( fd_lsb     ( z )==y               ); FD_TEST( fd_pop_lsb (  z )==x              );
        FD_TEST( fd_popcnt  ( z )==2               ); FD_TEST( fd_popcnt  ( ~z )==(w-2)          );
        FD_TEST( fd_find_lsb( z )==j               ); FD_TEST( fd_find_msb(  z )==i              );
        FD_TEST( fd_find_lsb_w_default( z, -1 )==j ); FD_TEST( fd_find_msb_w_default( z, -1 )==i );
        FD_TEST( fd_pow2_up ( z )==(x<<1)          ); FD_TEST( fd_pow2_dn (  z )== x             );
      }
    }
    for( int n=0; n<=w; n++ ) { int sl = n+(w-8)-((n>>3)<<4);
      uint128 x = (uint128)((n==w)? (uint128)0 : ((uint128)(1U)<<n ));
      uint128 y = (uint128)((n==w)? (uint128)0 : ((uint128)(1U)<<sl)); FD_TEST( fd_bswap( x )==y );
    }
    for( int i=0; i<w; i++ ) {
      uint128 align =  ((uint128)1)<<i;
      uint128 lo    = (((uint128)1)<<i)-((uint128)1);
      uint128 hi    = ~lo;
      FD_TEST( fd_is_aligned( zeros, align )        );
      FD_TEST( fd_alignment ( zeros, align )==zeros );
      FD_TEST( fd_align_dn  ( zeros, align )==zeros );
      FD_TEST( fd_align_up  ( zeros, align )==zeros );
      FD_TEST( fd_is_aligned( ones,  align )==(!i)  );
      FD_TEST( fd_alignment ( ones,  align )==lo    );
      FD_TEST( fd_align_dn  ( ones,  align )==hi    );
      FD_TEST( fd_align_up  ( ones,  align )==((!i) ? ones : zeros) );
      for( int j=0; j<w; j++ ) {
        uint128 x = ((uint128)1)<<j;
        FD_TEST( fd_is_aligned( x, align )==(j>=i)        );
        FD_TEST( fd_alignment ( x, align )==( x     & lo) );
        FD_TEST( fd_align_dn  ( x, align )==( x     & hi) );
        FD_TEST( fd_align_up  ( x, align )==((x+lo) & hi) );
      }
    }
    for( int iter=0; iter<16777216; iter++ ) {
      uint128 m = fd_rng_uint128( rng );
      uint128 x = fd_rng_uint128( rng );
      uint128 y = fd_rng_uint128( rng );
      int     c = fd_extract_bit( m, 0 );
      FD_TEST( fd_blend( m, x, y )==((x & m) | (y & ~m))            );
      FD_TEST( fd_if   ( c, x, y )==(c ? x : y)                     );
      FD_TEST( fd_abs  ( x       )==x                               );
      FD_TEST( fd_min  ( x, y    )==((x<y) ? x : y)                 );
      FD_TEST( fd_max  ( x, y    )==((x>y) ? x : y)                 );

      uint128 z = x; fd_store_if( c, &z, y ); FD_TEST( z==(c ? y : x) );

      uint128 xx; uint128 yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );

      int n = (int)(uint)y;
      int s = n & 255;
      FD_TEST( fd_shift_left  ( x, s )==((s>127) ? (uint128)0 : (uint128)(x<<s)) );
      FD_TEST( fd_shift_right ( x, s )==((s>127) ? (uint128)0 : (uint128)(x>>s)) );
      FD_TEST( fd_rotate_left ( x, n )==((x<<(n&127))|(x>>((-n)&127))) );
      FD_TEST( fd_rotate_right( x, n )==((x>>(n&127))|(x<<((-n)&127))) );
    }
  }
# endif

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing char" ));
    for( int iter=0; iter<16777216; iter++ ) {
      int  c = (int)(fd_rng_ulong( rng ) & 1UL);
      char x = (char)fd_rng_ulong( rng );
      char y = (char)fd_rng_ulong( rng );
      FD_TEST( fd_if( c, x, y )==(c ? x : y) );

      char z = x; fd_store_if( c, &z, y ); FD_TEST( z==(c ? y : x) );

      char xx; char yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );
    }
  }

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing schar" ));
    FD_TEST( (uchar)fd_abs(  (schar)SCHAR_MIN )==(uchar)1+(uchar)SCHAR_MAX );
    FD_TEST( (uchar)fd_abs( -(schar)SCHAR_MAX )==         (uchar)SCHAR_MAX );
    FD_TEST( (uchar)fd_abs(         -(schar)1 )==                 (uchar)1 );
    FD_TEST( (uchar)fd_abs(          (schar)0 )==                 (uchar)0 );
    FD_TEST( (uchar)fd_abs(          (schar)1 )==                 (uchar)1 );
    FD_TEST( (uchar)fd_abs(  (schar)SCHAR_MAX )==         (uchar)SCHAR_MAX );
    for( int iter=0; iter<16777216; iter++ ) {
      int c = (int)(fd_rng_ulong( rng ) & 1UL);
      schar x = (schar)fd_rng_ulong( rng );
      schar y = (schar)fd_rng_ulong( rng );
      FD_TEST( fd_if ( c, x, y )==(c ? x : y)                             );
      FD_TEST( (uchar)fd_abs( x       )==(uchar)((x<(schar)0) ? ((schar)-x) : x) );
      FD_TEST( fd_min( x, y    )==((x<y) ? x : y)                         );
      FD_TEST( fd_max( x, y    )==((x>y) ? x : y)                         );

      schar z = x; fd_store_if( c, &z, y ); FD_TEST( z==(c ? y : x) );

      schar xx; schar yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );

      int   n = (int)fd_rng_uint( rng );
      int   s = n & 15;
      uchar m = (uchar)-(((uchar)x) >> 7);
      FD_TEST( fd_shift_left  ( x, s )==(schar)fd_shift_left  ( (uchar)x, s ) );
      FD_TEST( fd_shift_right ( x, s )==(schar)(uchar)(fd_shift_right( (uchar)(((uchar)x) ^ m), s ) ^ m) );
      FD_TEST( fd_rotate_left ( x, n )==(schar)fd_rotate_left ( (uchar)x, n ) );
      FD_TEST( fd_rotate_right( x, n )==(schar)fd_rotate_right( (uchar)x, n ) );
    }
  }

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing short" ));
    FD_TEST( (ushort)fd_abs(  (short)SHORT_MIN )==(ushort)1+(ushort)SHORT_MAX );
    FD_TEST( (ushort)fd_abs( -(short)SHORT_MAX )==          (ushort)SHORT_MAX );
    FD_TEST( (ushort)fd_abs(         -(short)1 )==                  (ushort)1 );
    FD_TEST( (ushort)fd_abs(          (short)0 )==                  (ushort)0 );
    FD_TEST( (ushort)fd_abs(          (short)1 )==                  (ushort)1 );
    FD_TEST( (ushort)fd_abs(  (short)SHORT_MAX )==          (ushort)SHORT_MAX );
    for( int iter=0; iter<16777216; iter++ ) {
      int c = (int)(fd_rng_ulong( rng ) & 1UL);
      short x = (short)fd_rng_ulong( rng );
      short y = (short)fd_rng_ulong( rng );
      FD_TEST( fd_if ( c, x, y )==(c ? x : y)                              );
      FD_TEST( (ushort)fd_abs( x       )==(ushort)((x<(short)0) ? ((short)-x) : x) );
      FD_TEST( fd_min( x, y    )==((x<y) ? x : y)                          );
      FD_TEST( fd_max( x, y    )==((x>y) ? x : y)                          );

      short z = x; fd_store_if( c, &z, y ); FD_TEST( z==(c ? y : x) );

      short xx; short yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );

      int    n = (int)fd_rng_uint( rng );
      int    s = n & 31;
      ushort m = (ushort)-(((ushort)x) >> 15);
      FD_TEST( fd_shift_left  ( x, s )==(short)fd_shift_left  ( (ushort)x, s ) );
      FD_TEST( fd_shift_right ( x, s )==(short)(ushort)(fd_shift_right( (ushort)(((ushort)x) ^ m), s ) ^ m) );
      FD_TEST( fd_rotate_left ( x, n )==(short)fd_rotate_left ( (ushort)x, n ) );
      FD_TEST( fd_rotate_right( x, n )==(short)fd_rotate_right( (ushort)x, n ) );
    }
  }

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing int" ));
    FD_TEST( (uint)fd_abs(  INT_MIN )==1U+(uint)INT_MAX );
    FD_TEST( (uint)fd_abs( -INT_MAX )==   (uint)INT_MAX );
    FD_TEST( (uint)fd_abs(       -1 )==              1U );
    FD_TEST( (uint)fd_abs(        0 )==              0U );
    FD_TEST( (uint)fd_abs(        1 )==              1U );
    FD_TEST( (uint)fd_abs(  INT_MAX )==   (uint)INT_MAX );
    for( int iter=0; iter<16777216; iter++ ) {
      int c = (int)(fd_rng_ulong( rng ) & 1UL);
      int x = (int)fd_rng_ulong( rng );
      int y = (int)fd_rng_ulong( rng );
      FD_TEST( fd_if ( c, x, y )==(c ? x : y)                        );
      FD_TEST( (uint)fd_abs( x       )==(uint)((x<(int)0) ? ((int)-x) : x) );
      FD_TEST( fd_min( x, y    )==((x<y) ? x : y)                    );
      FD_TEST( fd_max( x, y    )==((x>y) ? x : y)                    );

      int z = x; fd_store_if( c, &z, y ); FD_TEST( z==(c ? y : x) );

      int xx; int yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );

      int  n = (int)fd_rng_uint( rng );
      int  s = n & 63;
      uint m = (uint)-(((uint)x) >> 31);
      FD_TEST( fd_shift_left  ( x, s )==(int)fd_uint_shift_left  ( (uint)x, s ) );
      FD_TEST( fd_shift_right ( x, s )==(int)(fd_uint_shift_right( ((uint)x)^m, s )^m) );
      FD_TEST( fd_rotate_left ( x, n )==(int)fd_uint_rotate_left ( (uint)x, n ) );
      FD_TEST( fd_rotate_right( x, n )==(int)fd_uint_rotate_right( (uint)x, n ) );
    }
  }

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing long" ));
    FD_TEST( (ulong)fd_abs(  LONG_MIN )==1UL+(ulong)LONG_MAX );
    FD_TEST( (ulong)fd_abs( -LONG_MAX )==    (ulong)LONG_MAX );
    FD_TEST( (ulong)fd_abs(       -1L )==                1UL );
    FD_TEST( (ulong)fd_abs(        0L )==                0UL );
    FD_TEST( (ulong)fd_abs(        1L )==                1UL );
    FD_TEST( (ulong)fd_abs(  LONG_MAX )==    (ulong)LONG_MAX );
    for( int iter=0; iter<16777216; iter++ ) {
      int  c = (int)(fd_rng_ulong( rng ) & 1UL);
      long x = (long)fd_rng_ulong( rng );
      long y = (long)fd_rng_ulong( rng );
      FD_TEST( fd_if ( c, x, y )==(c ? x : y)                           );
      FD_TEST( (ulong)fd_abs( x       )==(ulong)((x<(long)0) ? ((long)-x) : x) );
      FD_TEST( fd_min( x, y    )==((x<y) ? x : y)                       );
      FD_TEST( fd_max( x, y    )==((x>y) ? x : y)                       );

      long z = x; fd_store_if( c, &z, y ); FD_TEST( z==(c ? y : x) );

      long xx; long yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );

      int   n = (int)fd_rng_uint( rng );
      int   s = n & 127;
      ulong m = (ulong)-(((ulong)x) >> 63);
      FD_TEST( fd_shift_left  ( x, s )==(long)fd_shift_left  ( (ulong)x, s ) );
      FD_TEST( fd_shift_right ( x, s )==(long)(fd_shift_right( ((ulong)x)^m, s )^m) );
      FD_TEST( fd_rotate_left ( x, n )==(long)fd_rotate_left ( (ulong)x, n ) );
      FD_TEST( fd_rotate_right( x, n )==(long)fd_rotate_right( (ulong)x, n ) );
    }
  }

# if FD_HAS_INT128
  if( 1 ) {
    FD_LOG_NOTICE(( "Testing int128" ));
    FD_TEST( (uint128)fd_abs(  INT128_MIN )==(uint128)1+(uint128)INT128_MAX );
    FD_TEST( (uint128)fd_abs( -INT128_MAX )==           (uint128)INT128_MAX );
    FD_TEST( (uint128)fd_abs(  -(int128)1 )==                    (uint128)1 );
    FD_TEST( (uint128)fd_abs(   (int128)0 )==                    (uint128)0 );
    FD_TEST( (uint128)fd_abs(   (int128)1 )==                    (uint128)1 );
    FD_TEST( (uint128)fd_abs(  INT128_MAX )==           (uint128)INT128_MAX );
    for( int iter=0; iter<16777216; iter++ ) {
      int    c = (int)(fd_rng_ulong( rng ) & 1UL);
      int128 x = (int128)fd_rng_uint128( rng );
      int128 y = (int128)fd_rng_uint128( rng );
      FD_TEST( fd_if ( c, x, y )==(c ? x : y)                       );
      FD_TEST( (uint128)fd_abs( x       )==(uint128)((x<(int128)0) ? -x : x) );
      FD_TEST( fd_min( x, y    )==((x<y) ? x : y)                   );
      FD_TEST( fd_max( x, y    )==((x>y) ? x : y)                   );

      int128 z = x; fd_store_if( c, &z, y ); FD_TEST( z==(c ? y : x) );

      int128 xx; int128 yy;
      xx = x; yy = y; fd_swap( xx, yy );       FD_TEST( (xx==y)           & (yy==x)           );
      xx = x; yy = y; fd_swap_if( c, xx, yy ); FD_TEST( (xx==(c ? y : x)) & (yy==(c ? x : y)) );

      int     n = (int)fd_rng_uint( rng );
      int     s = n & 255;
      uint128 m = (uint128)-(((uint128)x) >> 127);
      FD_TEST( fd_shift_left  ( x, s )==(int128)fd_shift_left  ( (uint128)x, s ) );
      FD_TEST( fd_shift_right ( x, s )==(int128)(fd_shift_right( ((uint128)x)^m, s )^m) );
      FD_TEST( fd_rotate_left ( x, n )==(int128)fd_rotate_left ( (uint128)x, n ) );
      FD_TEST( fd_rotate_right( x, n )==(int128)fd_rotate_right( (uint128)x, n ) );
    }
  }
# endif

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
