#include "../fd_util.h"

/* FIXME: TEST BASE10_DIG_CNT! */
/* FIXME: TEST FLOAT_IF, DOUBLE_IF */

int
main( int     argc,
      char ** argv ) {

  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

# define TEST(c) do if( !(c) ) { FD_LOG_WARNING(( "FAIL: " #c )); return 1; } while(0)

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing uchar" ));
    int   w     = 8;
    uchar zeros = (uchar) 0UL;
    uchar ones  = (uchar)~0UL;
    for( int n=0; n< w; n++ ) {
      uchar x = (uchar)(1UL<<n);
      TEST( fd_uchar_is_pow2( x ) );
      TEST( !fd_uchar_is_pow2( (uchar)~x ) );
    }
    for( int n=0; n<=w; n++ ) { uchar x = (uchar)((n<w) ? (1UL<<n) : 0UL); TEST( fd_uchar_pow2( n )==x ); }
    for( int b=0; b< w; b++ ) {
      uchar mask  = (uchar)(1UL<<b);
      uchar maskc = (uchar)~mask;
      TEST( fd_uchar_mask_bit   ( b           )==mask  );
      TEST( fd_uchar_clear_bit  ( zeros, b    )==zeros ); TEST( fd_uchar_set_bit    ( zeros, b    )==mask  );
      TEST( fd_uchar_clear_bit  ( mask,  b    )==zeros ); TEST( fd_uchar_set_bit    ( mask,  b    )==mask  );
      TEST( fd_uchar_clear_bit  ( maskc, b    )==maskc ); TEST( fd_uchar_set_bit    ( maskc, b    )==ones  );
      TEST( fd_uchar_clear_bit  ( ones,  b    )==maskc ); TEST( fd_uchar_set_bit    ( ones,  b    )==ones  );
      TEST( fd_uchar_flip_bit   ( zeros, b    )==mask  ); TEST( fd_uchar_extract_bit( zeros, b    )==0     );
      TEST( fd_uchar_flip_bit   ( mask,  b    )==zeros ); TEST( fd_uchar_extract_bit( mask,  b    )==1     );
      TEST( fd_uchar_flip_bit   ( maskc, b    )==ones  ); TEST( fd_uchar_extract_bit( maskc, b    )==0     );
      TEST( fd_uchar_flip_bit   ( ones,  b    )==maskc ); TEST( fd_uchar_extract_bit( ones,  b    )==1     );
      TEST( fd_uchar_insert_bit ( zeros, b, 0 )==zeros ); TEST( fd_uchar_insert_bit ( zeros, b, 1 )==mask  );
      TEST( fd_uchar_insert_bit ( mask,  b, 0 )==zeros ); TEST( fd_uchar_insert_bit ( mask,  b, 1 )==mask  );
      TEST( fd_uchar_insert_bit ( maskc, b, 0 )==maskc ); TEST( fd_uchar_insert_bit ( maskc, b, 1 )==ones  );
      TEST( fd_uchar_insert_bit ( ones,  b, 0 )==maskc ); TEST( fd_uchar_insert_bit ( ones,  b, 1 )==ones  );
    }
    for( int n=0; n<=w; n++ ) {
      uchar mask  = (uchar)(((n<w) ? (1UL<<n) : 0UL)-1UL);
      uchar maskc = (uchar)~mask;
      TEST( fd_uchar_mask_lsb   ( n               )==mask  );
      TEST( fd_uchar_clear_lsb  ( zeros, n        )==zeros ); TEST( fd_uchar_set_lsb    ( zeros, n       )==mask  );
      TEST( fd_uchar_clear_lsb  ( mask,  n        )==zeros ); TEST( fd_uchar_set_lsb    ( mask,  n       )==mask  );
      TEST( fd_uchar_clear_lsb  ( maskc, n        )==maskc ); TEST( fd_uchar_set_lsb    ( maskc, n       )==ones  );
      TEST( fd_uchar_clear_lsb  ( ones,  n        )==maskc ); TEST( fd_uchar_set_lsb    ( ones,  n       )==ones  );
      TEST( fd_uchar_flip_lsb   ( zeros, n        )==mask  ); TEST( fd_uchar_extract_lsb( zeros, n       )==zeros );
      TEST( fd_uchar_flip_lsb   ( mask,  n        )==zeros ); TEST( fd_uchar_extract_lsb( mask,  n       )==mask  );
      TEST( fd_uchar_flip_lsb   ( maskc, n        )==ones  ); TEST( fd_uchar_extract_lsb( maskc, n       )==zeros );
      TEST( fd_uchar_flip_lsb   ( ones,  n        )==maskc ); TEST( fd_uchar_extract_lsb( ones,  n       )==mask  );
      TEST( fd_uchar_insert_lsb ( zeros, n, zeros )==zeros ); TEST( fd_uchar_insert_lsb ( zeros, n, mask )==mask  );
      TEST( fd_uchar_insert_lsb ( mask,  n, zeros )==zeros ); TEST( fd_uchar_insert_lsb ( mask,  n, mask )==mask  );
      TEST( fd_uchar_insert_lsb ( maskc, n, zeros )==maskc ); TEST( fd_uchar_insert_lsb ( maskc, n, mask )==ones  );
      TEST( fd_uchar_insert_lsb ( ones,  n, zeros )==maskc ); TEST( fd_uchar_insert_lsb ( ones,  n, mask )==ones  );
    }
    for( int h=0; h< w; h++ ) {
      for( int l=0; l<=h; l++ ) {
        uchar x     = fd_uchar_mask_lsb( h-l+1 );
        uchar mask  = (uchar)(x << l);
        uchar maskc = (uchar)~mask;
        TEST( fd_uchar_mask   ( l,h               )==mask  );
        TEST( fd_uchar_clear  ( zeros, l,h        )==zeros ); TEST( fd_uchar_set    ( zeros, l,h    )==mask  );
        TEST( fd_uchar_clear  ( mask,  l,h        )==zeros ); TEST( fd_uchar_set    ( mask,  l,h    )==mask  );
        TEST( fd_uchar_clear  ( maskc, l,h        )==maskc ); TEST( fd_uchar_set    ( maskc, l,h    )==ones  );
        TEST( fd_uchar_clear  ( ones,  l,h        )==maskc ); TEST( fd_uchar_set    ( ones,  l,h    )==ones  );
        TEST( fd_uchar_flip   ( zeros, l,h        )==mask  ); TEST( fd_uchar_extract( zeros, l,h    )==zeros );
        TEST( fd_uchar_flip   ( mask,  l,h        )==zeros ); TEST( fd_uchar_extract( mask,  l,h    )==x     );
        TEST( fd_uchar_flip   ( maskc, l,h        )==ones  ); TEST( fd_uchar_extract( maskc, l,h    )==zeros );
        TEST( fd_uchar_flip   ( ones,  l,h        )==maskc ); TEST( fd_uchar_extract( ones,  l,h    )==x     );
        TEST( fd_uchar_insert ( zeros, l,h, zeros )==zeros ); TEST( fd_uchar_insert ( zeros, l,h, x )==mask  );
        TEST( fd_uchar_insert ( mask,  l,h, zeros )==zeros ); TEST( fd_uchar_insert ( mask,  l,h, x )==mask  );
        TEST( fd_uchar_insert ( maskc, l,h, zeros )==maskc ); TEST( fd_uchar_insert ( maskc, l,h, x )==ones  );
        TEST( fd_uchar_insert ( ones,  l,h, zeros )==maskc ); TEST( fd_uchar_insert ( ones,  l,h, x )==ones  );
      }
    }
    TEST( fd_uchar_popcnt  ( zeros )==0        ); TEST( fd_uchar_popcnt  ( ones  )==w        );
    TEST( fd_uchar_find_lsb          ( ones      )==0    );
    TEST( fd_uchar_find_lsb_w_default( ones , -1 )==0    );
    TEST( fd_uchar_find_lsb_w_default( zeros, -1 )==-1   );
    TEST( fd_uchar_find_msb          ( ones      )==(w-1));
    TEST( fd_uchar_find_msb_w_default( ones , -1 )==(w-1));
    TEST( fd_uchar_find_msb_w_default( zeros, -1 )==-1   );
    TEST( fd_uchar_pow2_up ( zeros )==(uchar)0 ); TEST( fd_uchar_pow2_up ( ones  )==(uchar)0 );
    for( int i=1; i<w; i++ ) {
      uchar x = (uchar)(1UL<<i);
      TEST( fd_uchar_pop_lsb ( x )==zeros );
      TEST( fd_uchar_popcnt  ( x )==1     ); TEST( fd_uchar_popcnt  ( (uchar)~x )==w-1 );
      TEST( fd_uchar_find_lsb( x )==i     ); TEST( fd_uchar_find_msb( x )==i );
      TEST( fd_uchar_find_lsb_w_default( x , -1 )==i ); 
      TEST( fd_uchar_find_msb_w_default( x , -1 )==i );
      TEST( fd_uchar_pow2_up ( x )==x     );
      for( int j=0; j<i; j++ ) {
        uchar y = (uchar)(1UL<<j);
        uchar z = (uchar)(x|y);
        TEST( fd_uchar_pop_lsb ( z )==x             );
        TEST( fd_uchar_popcnt  ( z )==2             ); TEST( fd_uchar_popcnt  ( (uchar)~z )==w-2 );
        TEST( fd_uchar_find_lsb( z )==j             ); TEST( fd_uchar_find_msb( z )==i );
        TEST( fd_uchar_find_lsb_w_default( z , -1 )==j ); 
        TEST( fd_uchar_find_msb_w_default( z , -1 )==i );
        TEST( fd_uchar_pow2_up ( z )==(uchar)(x<<1) );
      }
    }
    for( int n=0; n<=w; n++ ) { 
      uchar x = (uchar)((n==w)? 0U : (1U<<n )); int sl = n+(w-8)-((n>>3)<<4); 
      uchar y = (uchar)((n==w)? 0U : (1U<<sl)); TEST( fd_uchar_bswap( x )==y ); 
    } 
    for( int i=0; i<w; i++ ) {
      uchar align = (uchar) (1UL<<i);
      uchar lo    = (uchar)((1UL<<i)-1UL);
      uchar hi    = (uchar)~lo;
      TEST( fd_uchar_is_aligned( zeros, align )        );
      TEST( fd_uchar_alignment ( zeros, align )==zeros );
      TEST( fd_uchar_align_dn  ( zeros, align )==zeros );
      TEST( fd_uchar_align_up  ( zeros, align )==zeros );
      TEST( fd_uchar_is_aligned( ones,  align )==(!i)  );
      TEST( fd_uchar_alignment ( ones,  align )==lo    );
      TEST( fd_uchar_align_dn  ( ones,  align )==hi    );
      TEST( fd_uchar_align_up  ( ones,  align )==((!i) ? ones : zeros) );
      for( int j=0; j<w; j++ ) {
        uchar x = (uchar)(1UL<<j);
        TEST( fd_uchar_is_aligned( x, align )==(j>=i)        );
        TEST( fd_uchar_alignment ( x, align )==( x     & lo) );
        TEST( fd_uchar_align_dn  ( x, align )==( x     & hi) );
        TEST( fd_uchar_align_up  ( x, align )==((x+lo) & hi) );
      }
    }
    for( int iter=0; iter<16777216; iter++ ) {
      uchar m = (uchar)fd_rng_ulong( rng );
      uchar x = (uchar)fd_rng_ulong( rng );
      uchar y = (uchar)fd_rng_ulong( rng );
      int   c = fd_uchar_extract_bit( m, 0 );
      TEST( fd_uchar_blend( m, x, y )==(uchar)( (x & m) | (y & ~m) ) );
      TEST( fd_uchar_if   ( c, x, y )==(c ? x : y)                   );
      TEST( fd_uchar_abs  ( x       )==x                             );
      TEST( fd_uchar_min  ( x, y    )==((x<y) ? x : y)               );
      TEST( fd_uchar_max  ( x, y    )==((x>y) ? x : y)               );
    }
  }

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing ushort" ));
    int    w     = 16;
    ushort zeros = (ushort) 0UL;
    ushort ones  = (ushort)~0UL;
    for( int n=0; n< w; n++ ) {
      ushort x = (ushort)(1UL<<n);
      TEST( fd_ushort_is_pow2( x ) );
      TEST( !fd_ushort_is_pow2( (ushort)~x ) );
    }
    for( int n=0; n<=w; n++ ) { ushort x = (ushort)((n<w) ? (1UL<<n) : 0UL); TEST( fd_ushort_pow2( n )==x ); }
    for( int b=0; b< w; b++ ) {
      ushort mask  = (ushort)(1UL<<b);
      ushort maskc = (ushort)~mask;
      TEST( fd_ushort_mask_bit   ( b           )==mask  );
      TEST( fd_ushort_clear_bit  ( zeros, b    )==zeros ); TEST( fd_ushort_set_bit    ( zeros, b    )==mask  );
      TEST( fd_ushort_clear_bit  ( mask,  b    )==zeros ); TEST( fd_ushort_set_bit    ( mask,  b    )==mask  );
      TEST( fd_ushort_clear_bit  ( maskc, b    )==maskc ); TEST( fd_ushort_set_bit    ( maskc, b    )==ones  );
      TEST( fd_ushort_clear_bit  ( ones,  b    )==maskc ); TEST( fd_ushort_set_bit    ( ones,  b    )==ones  );
      TEST( fd_ushort_flip_bit   ( zeros, b    )==mask  ); TEST( fd_ushort_extract_bit( zeros, b    )==0     );
      TEST( fd_ushort_flip_bit   ( mask,  b    )==zeros ); TEST( fd_ushort_extract_bit( mask,  b    )==1     );
      TEST( fd_ushort_flip_bit   ( maskc, b    )==ones  ); TEST( fd_ushort_extract_bit( maskc, b    )==0     );
      TEST( fd_ushort_flip_bit   ( ones,  b    )==maskc ); TEST( fd_ushort_extract_bit( ones,  b    )==1     );
      TEST( fd_ushort_insert_bit ( zeros, b, 0 )==zeros ); TEST( fd_ushort_insert_bit ( zeros, b, 1 )==mask  );
      TEST( fd_ushort_insert_bit ( mask,  b, 0 )==zeros ); TEST( fd_ushort_insert_bit ( mask,  b, 1 )==mask  );
      TEST( fd_ushort_insert_bit ( maskc, b, 0 )==maskc ); TEST( fd_ushort_insert_bit ( maskc, b, 1 )==ones  );
      TEST( fd_ushort_insert_bit ( ones,  b, 0 )==maskc ); TEST( fd_ushort_insert_bit ( ones,  b, 1 )==ones  );
    }
    for( int n=0; n<=w; n++ ) {
      ushort mask  = (ushort)(((n<w) ? (1UL<<n) : 0UL)-1UL);
      ushort maskc = (ushort)~mask;
      TEST( fd_ushort_mask_lsb   ( n               )==mask  );
      TEST( fd_ushort_clear_lsb  ( zeros, n        )==zeros ); TEST( fd_ushort_set_lsb    ( zeros, n       )==mask  );
      TEST( fd_ushort_clear_lsb  ( mask,  n        )==zeros ); TEST( fd_ushort_set_lsb    ( mask,  n       )==mask  );
      TEST( fd_ushort_clear_lsb  ( maskc, n        )==maskc ); TEST( fd_ushort_set_lsb    ( maskc, n       )==ones  );
      TEST( fd_ushort_clear_lsb  ( ones,  n        )==maskc ); TEST( fd_ushort_set_lsb    ( ones,  n       )==ones  );
      TEST( fd_ushort_flip_lsb   ( zeros, n        )==mask  ); TEST( fd_ushort_extract_lsb( zeros, n       )==zeros );
      TEST( fd_ushort_flip_lsb   ( mask,  n        )==zeros ); TEST( fd_ushort_extract_lsb( mask,  n       )==mask  );
      TEST( fd_ushort_flip_lsb   ( maskc, n        )==ones  ); TEST( fd_ushort_extract_lsb( maskc, n       )==zeros );
      TEST( fd_ushort_flip_lsb   ( ones,  n        )==maskc ); TEST( fd_ushort_extract_lsb( ones,  n       )==mask  );
      TEST( fd_ushort_insert_lsb ( zeros, n, zeros )==zeros ); TEST( fd_ushort_insert_lsb ( zeros, n, mask )==mask  );
      TEST( fd_ushort_insert_lsb ( mask,  n, zeros )==zeros ); TEST( fd_ushort_insert_lsb ( mask,  n, mask )==mask  );
      TEST( fd_ushort_insert_lsb ( maskc, n, zeros )==maskc ); TEST( fd_ushort_insert_lsb ( maskc, n, mask )==ones  );
      TEST( fd_ushort_insert_lsb ( ones,  n, zeros )==maskc ); TEST( fd_ushort_insert_lsb ( ones,  n, mask )==ones  );
    }
    for( int h=0; h< w; h++ ) {
      for( int l=0; l<=h; l++ ) {
        ushort x     = fd_ushort_mask_lsb( h-l+1 );
        ushort mask  = (ushort)(x << l);
        ushort maskc = (ushort)~mask;
        TEST( fd_ushort_mask   ( l,h               )==mask  );
        TEST( fd_ushort_clear  ( zeros, l,h        )==zeros ); TEST( fd_ushort_set    ( zeros, l,h    )==mask  );
        TEST( fd_ushort_clear  ( mask,  l,h        )==zeros ); TEST( fd_ushort_set    ( mask,  l,h    )==mask  );
        TEST( fd_ushort_clear  ( maskc, l,h        )==maskc ); TEST( fd_ushort_set    ( maskc, l,h    )==ones  );
        TEST( fd_ushort_clear  ( ones,  l,h        )==maskc ); TEST( fd_ushort_set    ( ones,  l,h    )==ones  );
        TEST( fd_ushort_flip   ( zeros, l,h        )==mask  ); TEST( fd_ushort_extract( zeros, l,h    )==zeros );
        TEST( fd_ushort_flip   ( mask,  l,h        )==zeros ); TEST( fd_ushort_extract( mask,  l,h    )==x     );
        TEST( fd_ushort_flip   ( maskc, l,h        )==ones  ); TEST( fd_ushort_extract( maskc, l,h    )==zeros );
        TEST( fd_ushort_flip   ( ones,  l,h        )==maskc ); TEST( fd_ushort_extract( ones,  l,h    )==x     );
        TEST( fd_ushort_insert ( zeros, l,h, zeros )==zeros ); TEST( fd_ushort_insert ( zeros, l,h, x )==mask  );
        TEST( fd_ushort_insert ( mask,  l,h, zeros )==zeros ); TEST( fd_ushort_insert ( mask,  l,h, x )==mask  );
        TEST( fd_ushort_insert ( maskc, l,h, zeros )==maskc ); TEST( fd_ushort_insert ( maskc, l,h, x )==ones  );
        TEST( fd_ushort_insert ( ones,  l,h, zeros )==maskc ); TEST( fd_ushort_insert ( ones,  l,h, x )==ones  );
      }
    }
    TEST( fd_ushort_popcnt  ( zeros )==0         ); TEST( fd_ushort_popcnt  ( ones )==w         );
    TEST( fd_ushort_find_lsb          ( ones      )==0    );
    TEST( fd_ushort_find_lsb_w_default( ones , -1 )==0    );
    TEST( fd_ushort_find_lsb_w_default( zeros, -1 )==-1   );
    TEST( fd_ushort_find_msb          ( ones      )==(w-1));
    TEST( fd_ushort_find_msb_w_default( ones , -1 )==(w-1));
    TEST( fd_ushort_find_msb_w_default( zeros, -1 )==-1   );
    TEST( fd_ushort_pow2_up ( zeros )==(ushort)0 ); TEST( fd_ushort_pow2_up ( ones )==(ushort)0 );
    for( int i=1; i<w; i++ ) {
      ushort x = (ushort)(1UL<<i);
      TEST( fd_ushort_pop_lsb ( x )==zeros );
      TEST( fd_ushort_popcnt  ( x )==1     ); TEST( fd_ushort_popcnt  ( (ushort)~x )==w-1 );
      TEST( fd_ushort_find_lsb( x )==i     ); TEST( fd_ushort_find_msb( x )==i );
      TEST( fd_ushort_find_lsb_w_default( x , -1 )==i ); 
      TEST( fd_ushort_find_msb_w_default( x , -1 )==i );
      TEST( fd_ushort_pow2_up ( x )==x     );
      for( int j=0; j<i; j++ ) {
        ushort y = (ushort)(1UL<<j);
        ushort z = (ushort)(x|y);
        TEST( fd_ushort_pop_lsb ( z )==x              );
        TEST( fd_ushort_popcnt  ( z )==2              ); TEST( fd_ushort_popcnt  ( (ushort)~z )==w-2 );
        TEST( fd_ushort_find_lsb( z )==j              ); TEST( fd_ushort_find_msb( z )==i );
        TEST( fd_ushort_find_lsb_w_default( z , -1 )==j ); 
        TEST( fd_ushort_find_msb_w_default( z , -1 )==i );
        TEST( fd_ushort_pow2_up ( z )==(ushort)(x<<1) );
      }
    }
    for( int n=0; n<=w; n++ ) { 
      ushort x = (ushort)((n==w)? 0U : (1U<<n )); int sl = n+(w-8)-((n>>3)<<4); 
      ushort y = (ushort)((n==w)? 0U : (1U<<sl)); TEST( fd_ushort_bswap( x )==y ); 
    } 
    for( int i=0; i<w; i++ ) {
      ushort align = (ushort) (1UL<<i);
      ushort lo    = (ushort)((1UL<<i)-1UL);
      ushort hi    = (ushort)~lo;
      TEST( fd_ushort_is_aligned( zeros, align )        );
      TEST( fd_ushort_alignment ( zeros, align )==zeros );
      TEST( fd_ushort_align_dn  ( zeros, align )==zeros );
      TEST( fd_ushort_align_up  ( zeros, align )==zeros );
      TEST( fd_ushort_is_aligned( ones,  align )==(!i)  );
      TEST( fd_ushort_alignment ( ones,  align )==lo    );
      TEST( fd_ushort_align_dn  ( ones,  align )==hi    );
      TEST( fd_ushort_align_up  ( ones,  align )==((!i) ? ones : zeros) );
      for( int j=0; j<w; j++ ) {
        ushort x = (ushort)(1UL<<j);
        TEST( fd_ushort_is_aligned( x, align )==(j>=i)        );
        TEST( fd_ushort_alignment ( x, align )==( x     & lo) );
        TEST( fd_ushort_align_dn  ( x, align )==( x     & hi) );
        TEST( fd_ushort_align_up  ( x, align )==((x+lo) & hi) );
      }
    }
    for( int iter=0; iter<16777216; iter++ ) {
      ushort m = (ushort)fd_rng_ulong( rng );
      ushort x = (ushort)fd_rng_ulong( rng );
      ushort y = (ushort)fd_rng_ulong( rng );
      int    c = fd_ushort_extract_bit( m, 0 );
      TEST( fd_ushort_blend( m, x, y )==(ushort)( (x & m) | (y & ~m) ) );
      TEST( fd_ushort_if   ( c, x, y )==(c ? x : y)                   );
      TEST( fd_ushort_abs  ( x       )==x                             );
      TEST( fd_ushort_min  ( x, y    )==((x<y) ? x : y)               );
      TEST( fd_ushort_max  ( x, y    )==((x>y) ? x : y)               );
    }
  }

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing uint" ));
    int  w     = 32;
    uint zeros = (uint) 0UL;
    uint ones  = (uint)~0UL;
    for( int n=0; n< w; n++ ) {
      uint x = (uint)(1UL<<n);
      TEST( fd_uint_is_pow2( x ) );
      TEST( !fd_uint_is_pow2( (uint)~x ) );
    }
    for( int n=0; n<=w; n++ ) { uint x = (uint)((n<w) ? (1UL<<n) : 0UL); TEST( fd_uint_pow2( n )==x ); }
    for( int b=0; b< w; b++ ) {
      uint mask  = (uint)(1UL<<b);
      uint maskc = (uint)~mask;
      TEST( fd_uint_mask_bit   ( b           )==mask  );
      TEST( fd_uint_clear_bit  ( zeros, b    )==zeros ); TEST( fd_uint_set_bit    ( zeros, b    )==mask  );
      TEST( fd_uint_clear_bit  ( mask,  b    )==zeros ); TEST( fd_uint_set_bit    ( mask,  b    )==mask  );
      TEST( fd_uint_clear_bit  ( maskc, b    )==maskc ); TEST( fd_uint_set_bit    ( maskc, b    )==ones  );
      TEST( fd_uint_clear_bit  ( ones,  b    )==maskc ); TEST( fd_uint_set_bit    ( ones,  b    )==ones  );
      TEST( fd_uint_flip_bit   ( zeros, b    )==mask  ); TEST( fd_uint_extract_bit( zeros, b    )==0     );
      TEST( fd_uint_flip_bit   ( mask,  b    )==zeros ); TEST( fd_uint_extract_bit( mask,  b    )==1     );
      TEST( fd_uint_flip_bit   ( maskc, b    )==ones  ); TEST( fd_uint_extract_bit( maskc, b    )==0     );
      TEST( fd_uint_flip_bit   ( ones,  b    )==maskc ); TEST( fd_uint_extract_bit( ones,  b    )==1     );
      TEST( fd_uint_insert_bit ( zeros, b, 0 )==zeros ); TEST( fd_uint_insert_bit ( zeros, b, 1 )==mask  );
      TEST( fd_uint_insert_bit ( mask,  b, 0 )==zeros ); TEST( fd_uint_insert_bit ( mask,  b, 1 )==mask  );
      TEST( fd_uint_insert_bit ( maskc, b, 0 )==maskc ); TEST( fd_uint_insert_bit ( maskc, b, 1 )==ones  );
      TEST( fd_uint_insert_bit ( ones,  b, 0 )==maskc ); TEST( fd_uint_insert_bit ( ones,  b, 1 )==ones  );
    }
    for( int n=0; n<=w; n++ ) {
      uint mask  = (uint)(((n<w) ? (1UL<<n) : 0UL)-1UL);
      uint maskc = (uint)~mask;
      TEST( fd_uint_mask_lsb   ( n               )==mask  );
      TEST( fd_uint_clear_lsb  ( zeros, n        )==zeros ); TEST( fd_uint_set_lsb    ( zeros, n       )==mask  );
      TEST( fd_uint_clear_lsb  ( mask,  n        )==zeros ); TEST( fd_uint_set_lsb    ( mask,  n       )==mask  );
      TEST( fd_uint_clear_lsb  ( maskc, n        )==maskc ); TEST( fd_uint_set_lsb    ( maskc, n       )==ones  );
      TEST( fd_uint_clear_lsb  ( ones,  n        )==maskc ); TEST( fd_uint_set_lsb    ( ones,  n       )==ones  );
      TEST( fd_uint_flip_lsb   ( zeros, n        )==mask  ); TEST( fd_uint_extract_lsb( zeros, n       )==zeros );
      TEST( fd_uint_flip_lsb   ( mask,  n        )==zeros ); TEST( fd_uint_extract_lsb( mask,  n       )==mask  );
      TEST( fd_uint_flip_lsb   ( maskc, n        )==ones  ); TEST( fd_uint_extract_lsb( maskc, n       )==zeros );
      TEST( fd_uint_flip_lsb   ( ones,  n        )==maskc ); TEST( fd_uint_extract_lsb( ones,  n       )==mask  );
      TEST( fd_uint_insert_lsb ( zeros, n, zeros )==zeros ); TEST( fd_uint_insert_lsb ( zeros, n, mask )==mask  );
      TEST( fd_uint_insert_lsb ( mask,  n, zeros )==zeros ); TEST( fd_uint_insert_lsb ( mask,  n, mask )==mask  );
      TEST( fd_uint_insert_lsb ( maskc, n, zeros )==maskc ); TEST( fd_uint_insert_lsb ( maskc, n, mask )==ones  );
      TEST( fd_uint_insert_lsb ( ones,  n, zeros )==maskc ); TEST( fd_uint_insert_lsb ( ones,  n, mask )==ones  );
    }
    for( int h=0; h< w; h++ ) {
      for( int l=0; l<=h; l++ ) {
        uint x     = fd_uint_mask_lsb( h-l+1 );
        uint mask  = (uint)(x << l);
        uint maskc = (uint)~mask;
        TEST( fd_uint_mask   ( l,h               )==mask  );
        TEST( fd_uint_clear  ( zeros, l,h        )==zeros ); TEST( fd_uint_set    ( zeros, l,h    )==mask  );
        TEST( fd_uint_clear  ( mask,  l,h        )==zeros ); TEST( fd_uint_set    ( mask,  l,h    )==mask  );
        TEST( fd_uint_clear  ( maskc, l,h        )==maskc ); TEST( fd_uint_set    ( maskc, l,h    )==ones  );
        TEST( fd_uint_clear  ( ones,  l,h        )==maskc ); TEST( fd_uint_set    ( ones,  l,h    )==ones  );
        TEST( fd_uint_flip   ( zeros, l,h        )==mask  ); TEST( fd_uint_extract( zeros, l,h    )==zeros );
        TEST( fd_uint_flip   ( mask,  l,h        )==zeros ); TEST( fd_uint_extract( mask,  l,h    )==x     );
        TEST( fd_uint_flip   ( maskc, l,h        )==ones  ); TEST( fd_uint_extract( maskc, l,h    )==zeros );
        TEST( fd_uint_flip   ( ones,  l,h        )==maskc ); TEST( fd_uint_extract( ones,  l,h    )==x     );
        TEST( fd_uint_insert ( zeros, l,h, zeros )==zeros ); TEST( fd_uint_insert ( zeros, l,h, x )==mask  );
        TEST( fd_uint_insert ( mask,  l,h, zeros )==zeros ); TEST( fd_uint_insert ( mask,  l,h, x )==mask  );
        TEST( fd_uint_insert ( maskc, l,h, zeros )==maskc ); TEST( fd_uint_insert ( maskc, l,h, x )==ones  );
        TEST( fd_uint_insert ( ones,  l,h, zeros )==maskc ); TEST( fd_uint_insert ( ones,  l,h, x )==ones  );
      }
    }
    TEST( fd_uint_popcnt  ( zeros )==0       ); TEST( fd_uint_popcnt  ( ones  )==w       );
    TEST( fd_uint_find_lsb          ( ones      )==0    );
    TEST( fd_uint_find_lsb_w_default( ones , -1 )==0    );
    TEST( fd_uint_find_lsb_w_default( zeros, -1 )==-1   );
    TEST( fd_uint_find_msb          ( ones      )==(w-1));
    TEST( fd_uint_find_msb_w_default( ones , -1 )==(w-1));
    TEST( fd_uint_find_msb_w_default( zeros, -1 )==-1   );
    TEST( fd_uint_pow2_up ( zeros )==(uint)0 ); TEST( fd_uint_pow2_up ( ones  )==(uint)0 );
    for( int i=1; i<w; i++ ) {
      uint x = (uint)(1UL<<i);
      TEST( fd_uint_pop_lsb ( x )==zeros );
      TEST( fd_uint_popcnt  ( x )==1     ); TEST( fd_uint_popcnt  ( (uint)~x )==w-1 );
      TEST( fd_uint_find_lsb( x )==i     ); TEST( fd_uint_find_msb( x )==i );
      TEST( fd_uint_find_lsb_w_default( x , -1 )==i ); 
      TEST( fd_uint_find_msb_w_default( x , -1 )==i );
      TEST( fd_uint_pow2_up ( x )==x     );
      for( int j=0; j<i; j++ ) {
        uint y = (uint)(1UL<<j);
        uint z = (uint)(x|y);
        TEST( fd_uint_pop_lsb ( z )==x      );
        TEST( fd_uint_popcnt  ( z )==2      ); TEST( fd_uint_popcnt  ( (uint)~z )==w-2 );
        TEST( fd_uint_find_lsb( z )==j      ); TEST( fd_uint_find_msb( z )==i );
        TEST( fd_uint_find_lsb_w_default( z , -1 )==j ); 
        TEST( fd_uint_find_msb_w_default( z , -1 )==i );
        TEST( fd_uint_pow2_up ( z )==(x<<1) );
      }
    }
    for( int n=0; n<=w; n++ ) {  
      uint x = (uint)((n==w)? 0U : (1U<<n )); int sl = n+(w-8)-((n>>3)<<4);
      uint y = (uint)((n==w)? 0U : (1U<<sl)); TEST( fd_uint_bswap( x )==y ); 
    } 
    for( int i=0; i<w; i++ ) {
      uint align = (uint) (1UL<<i);
      uint lo    = (uint)((1UL<<i)-1UL);
      uint hi    = (uint)~lo;
      TEST( fd_uint_is_aligned( zeros, align )        );
      TEST( fd_uint_alignment ( zeros, align )==zeros );
      TEST( fd_uint_align_dn  ( zeros, align )==zeros );
      TEST( fd_uint_align_up  ( zeros, align )==zeros );
      TEST( fd_uint_is_aligned( ones,  align )==(!i)  );
      TEST( fd_uint_alignment ( ones,  align )==lo    );
      TEST( fd_uint_align_dn  ( ones,  align )==hi    );
      TEST( fd_uint_align_up  ( ones,  align )==((!i) ? ones : zeros) );
      for( int j=0; j<w; j++ ) {
        uint x = (uint)(1UL<<j);
        TEST( fd_uint_is_aligned( x, align )==(j>=i)        );
        TEST( fd_uint_alignment ( x, align )==( x     & lo) );
        TEST( fd_uint_align_dn  ( x, align )==( x     & hi) );
        TEST( fd_uint_align_up  ( x, align )==((x+lo) & hi) );
      }
    }
    for( int iter=0; iter<16777216; iter++ ) {
      uint m = (uint)fd_rng_ulong( rng );
      uint x = (uint)fd_rng_ulong( rng );
      uint y = (uint)fd_rng_ulong( rng );
      int  c = fd_uint_extract_bit( m, 0 );
      TEST( fd_uint_blend( m, x, y )==(uint)( (x & m) | (y & ~m) ) );
      TEST( fd_uint_if   ( c, x, y )==(c ? x : y)                   );
      TEST( fd_uint_abs  ( x       )==x                             );
      TEST( fd_uint_min  ( x, y    )==((x<y) ? x : y)               );
      TEST( fd_uint_max  ( x, y    )==((x>y) ? x : y)               );
    }
  }

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing ulong" ));
    int   w     = 64;
    ulong zeros = (ulong) 0UL;
    ulong ones  = (ulong)~0UL;
    for( int n=0; n< w; n++ ) {
      ulong x = (ulong)(1UL<<n);
      TEST( fd_ulong_is_pow2( x ) );
      TEST( !fd_ulong_is_pow2( (ulong)~x ) );
    }
    for( int n=0; n<=w; n++ ) { ulong x = (ulong)((n<w) ? (1UL<<n) : 0UL); TEST( fd_ulong_pow2( n )==x ); }
    for( int b=0; b< w; b++ ) {
      ulong mask  = (ulong)(1UL<<b);
      ulong maskc = (ulong)~mask;
      TEST( fd_ulong_mask_bit   ( b           )==mask  );
      TEST( fd_ulong_clear_bit  ( zeros, b    )==zeros ); TEST( fd_ulong_set_bit    ( zeros, b    )==mask  );
      TEST( fd_ulong_clear_bit  ( mask,  b    )==zeros ); TEST( fd_ulong_set_bit    ( mask,  b    )==mask  );
      TEST( fd_ulong_clear_bit  ( maskc, b    )==maskc ); TEST( fd_ulong_set_bit    ( maskc, b    )==ones  );
      TEST( fd_ulong_clear_bit  ( ones,  b    )==maskc ); TEST( fd_ulong_set_bit    ( ones,  b    )==ones  );
      TEST( fd_ulong_flip_bit   ( zeros, b    )==mask  ); TEST( fd_ulong_extract_bit( zeros, b    )==0     );
      TEST( fd_ulong_flip_bit   ( mask,  b    )==zeros ); TEST( fd_ulong_extract_bit( mask,  b    )==1     );
      TEST( fd_ulong_flip_bit   ( maskc, b    )==ones  ); TEST( fd_ulong_extract_bit( maskc, b    )==0     );
      TEST( fd_ulong_flip_bit   ( ones,  b    )==maskc ); TEST( fd_ulong_extract_bit( ones,  b    )==1     );
      TEST( fd_ulong_insert_bit ( zeros, b, 0 )==zeros ); TEST( fd_ulong_insert_bit ( zeros, b, 1 )==mask  );
      TEST( fd_ulong_insert_bit ( mask,  b, 0 )==zeros ); TEST( fd_ulong_insert_bit ( mask,  b, 1 )==mask  );
      TEST( fd_ulong_insert_bit ( maskc, b, 0 )==maskc ); TEST( fd_ulong_insert_bit ( maskc, b, 1 )==ones  );
      TEST( fd_ulong_insert_bit ( ones,  b, 0 )==maskc ); TEST( fd_ulong_insert_bit ( ones,  b, 1 )==ones  );
    }
    for( int n=0; n<=w; n++ ) {
      ulong mask  = (ulong)(((n<w) ? (1UL<<n) : 0UL)-1UL);
      ulong maskc = (ulong)~mask;
      TEST( fd_ulong_mask_lsb   ( n               )==mask  );
      TEST( fd_ulong_clear_lsb  ( zeros, n        )==zeros ); TEST( fd_ulong_set_lsb    ( zeros, n       )==mask  );
      TEST( fd_ulong_clear_lsb  ( mask,  n        )==zeros ); TEST( fd_ulong_set_lsb    ( mask,  n       )==mask  );
      TEST( fd_ulong_clear_lsb  ( maskc, n        )==maskc ); TEST( fd_ulong_set_lsb    ( maskc, n       )==ones  );
      TEST( fd_ulong_clear_lsb  ( ones,  n        )==maskc ); TEST( fd_ulong_set_lsb    ( ones,  n       )==ones  );
      TEST( fd_ulong_flip_lsb   ( zeros, n        )==mask  ); TEST( fd_ulong_extract_lsb( zeros, n       )==zeros );
      TEST( fd_ulong_flip_lsb   ( mask,  n        )==zeros ); TEST( fd_ulong_extract_lsb( mask,  n       )==mask  );
      TEST( fd_ulong_flip_lsb   ( maskc, n        )==ones  ); TEST( fd_ulong_extract_lsb( maskc, n       )==zeros );
      TEST( fd_ulong_flip_lsb   ( ones,  n        )==maskc ); TEST( fd_ulong_extract_lsb( ones,  n       )==mask  );
      TEST( fd_ulong_insert_lsb ( zeros, n, zeros )==zeros ); TEST( fd_ulong_insert_lsb ( zeros, n, mask )==mask  );
      TEST( fd_ulong_insert_lsb ( mask,  n, zeros )==zeros ); TEST( fd_ulong_insert_lsb ( mask,  n, mask )==mask  );
      TEST( fd_ulong_insert_lsb ( maskc, n, zeros )==maskc ); TEST( fd_ulong_insert_lsb ( maskc, n, mask )==ones  );
      TEST( fd_ulong_insert_lsb ( ones,  n, zeros )==maskc ); TEST( fd_ulong_insert_lsb ( ones,  n, mask )==ones  );
    }
    for( int h=0; h< w; h++ ) {
      for( int l=0; l<=h; l++ ) {
        ulong x     = fd_ulong_mask_lsb( h-l+1 );
        ulong mask  = (ulong)(x << l);
        ulong maskc = (ulong)~mask;
        TEST( fd_ulong_mask   ( l,h               )==mask  );
        TEST( fd_ulong_clear  ( zeros, l,h        )==zeros ); TEST( fd_ulong_set    ( zeros, l,h    )==mask  );
        TEST( fd_ulong_clear  ( mask,  l,h        )==zeros ); TEST( fd_ulong_set    ( mask,  l,h    )==mask  );
        TEST( fd_ulong_clear  ( maskc, l,h        )==maskc ); TEST( fd_ulong_set    ( maskc, l,h    )==ones  );
        TEST( fd_ulong_clear  ( ones,  l,h        )==maskc ); TEST( fd_ulong_set    ( ones,  l,h    )==ones  );
        TEST( fd_ulong_flip   ( zeros, l,h        )==mask  ); TEST( fd_ulong_extract( zeros, l,h    )==zeros );
        TEST( fd_ulong_flip   ( mask,  l,h        )==zeros ); TEST( fd_ulong_extract( mask,  l,h    )==x     );
        TEST( fd_ulong_flip   ( maskc, l,h        )==ones  ); TEST( fd_ulong_extract( maskc, l,h    )==zeros );
        TEST( fd_ulong_flip   ( ones,  l,h        )==maskc ); TEST( fd_ulong_extract( ones,  l,h    )==x     );
        TEST( fd_ulong_insert ( zeros, l,h, zeros )==zeros ); TEST( fd_ulong_insert ( zeros, l,h, x )==mask  );
        TEST( fd_ulong_insert ( mask,  l,h, zeros )==zeros ); TEST( fd_ulong_insert ( mask,  l,h, x )==mask  );
        TEST( fd_ulong_insert ( maskc, l,h, zeros )==maskc ); TEST( fd_ulong_insert ( maskc, l,h, x )==ones  );
        TEST( fd_ulong_insert ( ones,  l,h, zeros )==maskc ); TEST( fd_ulong_insert ( ones,  l,h, x )==ones  );
      }
    }
    TEST( fd_ulong_popcnt  ( zeros )==0        ); TEST( fd_ulong_popcnt  ( ones  )==w        );
    TEST( fd_ulong_find_lsb          ( ones      )==0    );
    TEST( fd_ulong_find_lsb_w_default( ones , -1 )==0    );
    TEST( fd_ulong_find_lsb_w_default( zeros, -1 )==-1   );
    TEST( fd_ulong_find_msb          ( ones      )==(w-1));
    TEST( fd_ulong_find_msb_w_default( ones , -1 )==(w-1));
    TEST( fd_ulong_find_msb_w_default( zeros, -1 )==-1   );
    TEST( fd_ulong_pow2_up ( zeros )==(ulong)0 ); TEST( fd_ulong_pow2_up ( ones  )==(ulong)0 );
    for( int i=1; i<w; i++ ) {
      ulong x = (ulong)(1UL<<i);
      TEST( fd_ulong_pop_lsb ( x )==zeros );
      TEST( fd_ulong_popcnt  ( x )==1     ); TEST( fd_ulong_popcnt  ( (ulong)~x )==w-1 );
      TEST( fd_ulong_find_lsb( x )==i     ); TEST( fd_ulong_find_msb( x )==i );
      TEST( fd_ulong_find_lsb_w_default( x , -1 )==i ); 
      TEST( fd_ulong_find_msb_w_default( x , -1 )==i );
      TEST( fd_ulong_pow2_up ( x )==x     );
      for( int j=0; j<i; j++ ) {
        ulong y = (ulong)(1UL<<j);
        ulong z = (ulong)(x|y);
        TEST( fd_ulong_pop_lsb ( z )==x      );
        TEST( fd_ulong_popcnt  ( z )==2      ); TEST( fd_ulong_popcnt  ( (ulong)~z )==w-2 );
        TEST( fd_ulong_find_lsb( z )==j      ); TEST( fd_ulong_find_msb( z )==i );
        TEST( fd_ulong_find_lsb_w_default( z , -1 )==j ); 
        TEST( fd_ulong_find_msb_w_default( z , -1 )==i );
        TEST( fd_ulong_pow2_up ( z )==(x<<1) );
      }
    }
    for( int n=0; n<=w; n++ ) { int sl = n+(w-8)-((n>>3)<<4); 
      ulong x = (ulong)((n==w)? 0UL : (1UL<<n ));
      ulong y = (ulong)((n==w)? 0UL : (1UL<<sl)); TEST( fd_ulong_bswap( x )==y ); 
    }  
    for( int i=0; i<w; i++ ) {
      ulong align = (ulong) (1UL<<i);
      ulong lo    = (ulong)((1UL<<i)-1UL);
      ulong hi    = (ulong)~lo;
      TEST( fd_ulong_is_aligned( zeros, align )        );
      TEST( fd_ulong_alignment ( zeros, align )==zeros );
      TEST( fd_ulong_align_dn  ( zeros, align )==zeros );
      TEST( fd_ulong_align_up  ( zeros, align )==zeros );
      TEST( fd_ulong_is_aligned( ones,  align )==(!i)  );
      TEST( fd_ulong_alignment ( ones,  align )==lo    );
      TEST( fd_ulong_align_dn  ( ones,  align )==hi    );
      TEST( fd_ulong_align_up  ( ones,  align )==((!i) ? ones : zeros) );
      for( int j=0; j<w; j++ ) {
        ulong x = (ulong)(1UL<<j);
        TEST( fd_ulong_is_aligned( x, align )==(j>=i)        );
        TEST( fd_ulong_alignment ( x, align )==( x     & lo) );
        TEST( fd_ulong_align_dn  ( x, align )==( x     & hi) );
        TEST( fd_ulong_align_up  ( x, align )==((x+lo) & hi) );
      }
    }

    for( int iter=0; iter<16777216; iter++ ) {
      ulong m = (ulong)fd_rng_ulong( rng );
      ulong x = (ulong)fd_rng_ulong( rng );
      ulong y = (ulong)fd_rng_ulong( rng );
      int   c = fd_ulong_extract_bit( m, 0 );
      TEST( fd_ulong_blend( m, x, y )==(ulong)( (x & m) | (y & ~m) ) );
      TEST( fd_ulong_if   ( c, x, y )==(c ? x : y)                   );
      TEST( fd_ulong_abs  ( x       )==x                             );
      TEST( fd_ulong_min  ( x, y    )==((x<y) ? x : y)               );
      TEST( fd_ulong_max  ( x, y    )==((x>y) ? x : y)               );

      int s0 = (int)(m & 63UL); m >>= 6;
      int s1 = (int)(m & 63UL);

      uchar svw[ FD_ULONG_SVW_ENC_MAX ]; x >>= s0;
      ulong         enc_sz = fd_ulong_svw_enc_sz( x );   TEST( enc_sz<=FD_ULONG_SVW_ENC_MAX );
      uchar const * nxt    = fd_ulong_svw_enc( svw, x ); TEST( (ulong)(nxt-svw)==enc_sz     );

      TEST( fd_ulong_svw_dec_sz     ( svw         )==enc_sz );
      TEST( fd_ulong_svw_dec_tail_sz( nxt         )==enc_sz );
      TEST( fd_ulong_svw_dec_fixed  ( svw, enc_sz )==x      );
      TEST( fd_ulong_svw_dec        ( svw, &y     )==nxt    ); TEST( x==y );
      TEST( fd_ulong_svw_dec_tail   ( nxt, &y     )==svw    ); TEST( x==y );

      x >>= s1;
      TEST( fd_ulong_svw_enc_fixed( svw, enc_sz, x )==nxt );

      TEST( fd_ulong_svw_dec_sz     ( svw         )==enc_sz );
      TEST( fd_ulong_svw_dec_tail_sz( nxt         )==enc_sz );
      TEST( fd_ulong_svw_dec_fixed  ( svw, enc_sz )==x      );
      TEST( fd_ulong_svw_dec        ( svw, &y     )==nxt    ); TEST( x==y );
      TEST( fd_ulong_svw_dec_tail   ( nxt, &y     )==svw    ); TEST( x==y );
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
      TEST( fd_uint128_is_pow2( x ) );
      TEST( !fd_uint128_is_pow2( ~x ) );
    }
    for( int n=0; n<=w; n++ ) { uint128 x = ((n<w) ? (((uint128)1)<<n) : ((uint128)0)); TEST( fd_uint128_pow2( n )==x ); }
    for( int b=0; b< w; b++ ) {
      uint128 mask  = ((uint128)1)<<b;
      uint128 maskc = ~mask;
      TEST( fd_uint128_mask_bit   ( b           )==mask  );
      TEST( fd_uint128_clear_bit  ( zeros, b    )==zeros ); TEST( fd_uint128_set_bit    ( zeros, b    )==mask  );
      TEST( fd_uint128_clear_bit  ( mask,  b    )==zeros ); TEST( fd_uint128_set_bit    ( mask,  b    )==mask  );
      TEST( fd_uint128_clear_bit  ( maskc, b    )==maskc ); TEST( fd_uint128_set_bit    ( maskc, b    )==ones  );
      TEST( fd_uint128_clear_bit  ( ones,  b    )==maskc ); TEST( fd_uint128_set_bit    ( ones,  b    )==ones  );
      TEST( fd_uint128_flip_bit   ( zeros, b    )==mask  ); TEST( fd_uint128_extract_bit( zeros, b    )==0     );
      TEST( fd_uint128_flip_bit   ( mask,  b    )==zeros ); TEST( fd_uint128_extract_bit( mask,  b    )==1     );
      TEST( fd_uint128_flip_bit   ( maskc, b    )==ones  ); TEST( fd_uint128_extract_bit( maskc, b    )==0     );
      TEST( fd_uint128_flip_bit   ( ones,  b    )==maskc ); TEST( fd_uint128_extract_bit( ones,  b    )==1     );
      TEST( fd_uint128_insert_bit ( zeros, b, 0 )==zeros ); TEST( fd_uint128_insert_bit ( zeros, b, 1 )==mask  );
      TEST( fd_uint128_insert_bit ( mask,  b, 0 )==zeros ); TEST( fd_uint128_insert_bit ( mask,  b, 1 )==mask  );
      TEST( fd_uint128_insert_bit ( maskc, b, 0 )==maskc ); TEST( fd_uint128_insert_bit ( maskc, b, 1 )==ones  );
      TEST( fd_uint128_insert_bit ( ones,  b, 0 )==maskc ); TEST( fd_uint128_insert_bit ( ones,  b, 1 )==ones  );
    }
    for( int n=0; n<=w; n++ ) {
      uint128 mask  = ((n<w) ? (((uint128)1)<<n) : ((uint128)0))-((uint128)1);
      uint128 maskc = ~mask;
      TEST( fd_uint128_mask_lsb   ( n               )==mask  );
      TEST( fd_uint128_clear_lsb  ( zeros, n        )==zeros ); TEST( fd_uint128_set_lsb    ( zeros, n       )==mask  );
      TEST( fd_uint128_clear_lsb  ( mask,  n        )==zeros ); TEST( fd_uint128_set_lsb    ( mask,  n       )==mask  );
      TEST( fd_uint128_clear_lsb  ( maskc, n        )==maskc ); TEST( fd_uint128_set_lsb    ( maskc, n       )==ones  );
      TEST( fd_uint128_clear_lsb  ( ones,  n        )==maskc ); TEST( fd_uint128_set_lsb    ( ones,  n       )==ones  );
      TEST( fd_uint128_flip_lsb   ( zeros, n        )==mask  ); TEST( fd_uint128_extract_lsb( zeros, n       )==zeros );
      TEST( fd_uint128_flip_lsb   ( mask,  n        )==zeros ); TEST( fd_uint128_extract_lsb( mask,  n       )==mask  );
      TEST( fd_uint128_flip_lsb   ( maskc, n        )==ones  ); TEST( fd_uint128_extract_lsb( maskc, n       )==zeros );
      TEST( fd_uint128_flip_lsb   ( ones,  n        )==maskc ); TEST( fd_uint128_extract_lsb( ones,  n       )==mask  );
      TEST( fd_uint128_insert_lsb ( zeros, n, zeros )==zeros ); TEST( fd_uint128_insert_lsb ( zeros, n, mask )==mask  );
      TEST( fd_uint128_insert_lsb ( mask,  n, zeros )==zeros ); TEST( fd_uint128_insert_lsb ( mask,  n, mask )==mask  );
      TEST( fd_uint128_insert_lsb ( maskc, n, zeros )==maskc ); TEST( fd_uint128_insert_lsb ( maskc, n, mask )==ones  );
      TEST( fd_uint128_insert_lsb ( ones,  n, zeros )==maskc ); TEST( fd_uint128_insert_lsb ( ones,  n, mask )==ones  );
    }
    for( int h=0; h< w; h++ ) {
      for( int l=0; l<=h; l++ ) {
        uint128 x     = fd_uint128_mask_lsb( h-l+1 );
        uint128 mask  = x << l;
        uint128 maskc = ~mask;
        TEST( fd_uint128_mask   ( l,h               )==mask  );
        TEST( fd_uint128_clear  ( zeros, l,h        )==zeros ); TEST( fd_uint128_set    ( zeros, l,h    )==mask  );
        TEST( fd_uint128_clear  ( mask,  l,h        )==zeros ); TEST( fd_uint128_set    ( mask,  l,h    )==mask  );
        TEST( fd_uint128_clear  ( maskc, l,h        )==maskc ); TEST( fd_uint128_set    ( maskc, l,h    )==ones  );
        TEST( fd_uint128_clear  ( ones,  l,h        )==maskc ); TEST( fd_uint128_set    ( ones,  l,h    )==ones  );
        TEST( fd_uint128_flip   ( zeros, l,h        )==mask  ); TEST( fd_uint128_extract( zeros, l,h    )==zeros );
        TEST( fd_uint128_flip   ( mask,  l,h        )==zeros ); TEST( fd_uint128_extract( mask,  l,h    )==x     );
        TEST( fd_uint128_flip   ( maskc, l,h        )==ones  ); TEST( fd_uint128_extract( maskc, l,h    )==zeros );
        TEST( fd_uint128_flip   ( ones,  l,h        )==maskc ); TEST( fd_uint128_extract( ones,  l,h    )==x     );
        TEST( fd_uint128_insert ( zeros, l,h, zeros )==zeros ); TEST( fd_uint128_insert ( zeros, l,h, x )==mask  );
        TEST( fd_uint128_insert ( mask,  l,h, zeros )==zeros ); TEST( fd_uint128_insert ( mask,  l,h, x )==mask  );
        TEST( fd_uint128_insert ( maskc, l,h, zeros )==maskc ); TEST( fd_uint128_insert ( maskc, l,h, x )==ones  );
        TEST( fd_uint128_insert ( ones,  l,h, zeros )==maskc ); TEST( fd_uint128_insert ( ones,  l,h, x )==ones  );
      }
    }
    TEST( fd_uint128_popcnt  ( zeros )==0          ); TEST( fd_uint128_popcnt  ( ones  )==w          );
    TEST( fd_uint128_find_lsb          ( ones      )==0    );
    TEST( fd_uint128_find_lsb_w_default( ones , -1 )==0    );
    TEST( fd_uint128_find_lsb_w_default( zeros, -1 )==-1   );
    TEST( fd_uint128_find_msb          ( ones      )==(w-1));
    TEST( fd_uint128_find_msb_w_default( ones , -1 )==(w-1));
    TEST( fd_uint128_find_msb_w_default( zeros, -1 )==-1   );
    TEST( fd_uint128_pow2_up ( zeros )==(uint128)0 ); TEST( fd_uint128_pow2_up ( ones  )==(uint128)0 );
    for( int i=1; i<w; i++ ) {
      uint128 x = ((uint128)1)<<i;
      TEST( fd_uint128_pop_lsb ( x )==zeros );
      TEST( fd_uint128_popcnt  ( x )==1     ); TEST( fd_uint128_popcnt  ( ~x )==w-1 );
      TEST( fd_uint128_find_lsb( x )==i     ); TEST( fd_uint128_find_msb(  x )==i );
      TEST( fd_uint128_find_lsb_w_default( x , -1 )==i ); 
      TEST( fd_uint128_find_msb_w_default( x , -1 )==i );
      TEST( fd_uint128_pow2_up ( x )==x     );
      for( int j=0; j<i; j++ ) {
        uint128 y = ((uint128)1)<<j;
        uint128 z = x|y;
        TEST( fd_uint128_pop_lsb ( z )==x      );
        TEST( fd_uint128_popcnt  ( z )==2      ); TEST( fd_uint128_popcnt  ( ~z )==w-2 );
        TEST( fd_uint128_find_lsb( z )==j      ); TEST( fd_uint128_find_msb(  z )==i );
        TEST( fd_uint128_find_lsb_w_default( z , -1 )==j ); 
        TEST( fd_uint128_find_msb_w_default( z , -1 )==i );
        TEST( fd_uint128_pow2_up ( z )==(x<<1) );
      }
    }
    for( int n=0; n<=w; n++ ) { int sl = n+(w-8)-((n>>3)<<4); 
      uint128 x = (uint128)((n==w)? (uint128)0 : ((uint128)(1U)<<n ));
      uint128 y = (uint128)((n==w)? (uint128)0 : ((uint128)(1U)<<sl)); TEST( fd_uint128_bswap( x )==y ); 
    }      
    for( int i=0; i<w; i++ ) {
      uint128 align =  ((uint128)1)<<i;
      uint128 lo    = (((uint128)1)<<i)-((uint128)1);
      uint128 hi    = ~lo;
      TEST( fd_uint128_is_aligned( zeros, align )        );
      TEST( fd_uint128_alignment ( zeros, align )==zeros );
      TEST( fd_uint128_align_dn  ( zeros, align )==zeros );
      TEST( fd_uint128_align_up  ( zeros, align )==zeros );
      TEST( fd_uint128_is_aligned( ones,  align )==(!i)  );
      TEST( fd_uint128_alignment ( ones,  align )==lo    );
      TEST( fd_uint128_align_dn  ( ones,  align )==hi    );
      TEST( fd_uint128_align_up  ( ones,  align )==((!i) ? ones : zeros) );
      for( int j=0; j<w; j++ ) {
        uint128 x = ((uint128)1)<<j;
        TEST( fd_uint128_is_aligned( x, align )==(j>=i)        );
        TEST( fd_uint128_alignment ( x, align )==( x     & lo) );
        TEST( fd_uint128_align_dn  ( x, align )==( x     & hi) );
        TEST( fd_uint128_align_up  ( x, align )==((x+lo) & hi) );
      }
    }
    for( int iter=0; iter<16777216; iter++ ) {
      uint128 m = fd_rng_uint128( rng );
      uint128 x = fd_rng_uint128( rng );
      uint128 y = fd_rng_uint128( rng );
      int   c = fd_uint128_extract_bit( m, 0 );
      TEST( fd_uint128_blend( m, x, y )==((x & m) | (y & ~m)) );
      TEST( fd_uint128_if   ( c, x, y )==(c ? x : y)          );
      TEST( fd_uint128_abs  ( x       )==x                    );
      TEST( fd_uint128_min  ( x, y    )==((x<y) ? x : y)      );
      TEST( fd_uint128_max  ( x, y    )==((x>y) ? x : y)      );
    }
  }
# endif

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing char" ));
    for( int iter=0; iter<16777216; iter++ ) {
      int c = (int)(fd_rng_ulong( rng ) & 1UL);
      schar x = (schar)fd_rng_ulong( rng );
      schar y = (schar)fd_rng_ulong( rng );
      TEST( fd_schar_if( c, x, y )==(c ? x : y) );
    }
  }

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing schar" ));
    for( int iter=0; iter<16777216; iter++ ) {
      int c = (int)(fd_rng_ulong( rng ) & 1UL);
      schar x = (schar)fd_rng_ulong( rng );
      schar y = (schar)fd_rng_ulong( rng );
      TEST( fd_schar_if ( c, x, y )==(c ? x : y)                             );
      TEST( fd_schar_abs( x       )==(uchar)((x<(schar)0) ? ((schar)-x) : x) );
      TEST( fd_schar_min( x, y    )==((x<y) ? x : y)                         );
      TEST( fd_schar_max( x, y    )==((x>y) ? x : y)                         );
    }

    TEST( fd_schar_zz_enc( (schar)        0 )==(uchar)            0 );
    TEST( fd_schar_zz_enc( (schar)       -1 )==(uchar)            1 );
    TEST( fd_schar_zz_enc( (schar)        1 )==(uchar)            2 );
    TEST( fd_schar_zz_enc( (schar)SCHAR_MIN )==(uchar) UCHAR_MAX    );
    TEST( fd_schar_zz_enc( (schar)SCHAR_MAX )==(uchar)(UCHAR_MAX-1) );

    TEST( fd_schar_zz_dec( (uchar)            0 )==(schar)        0 );
    TEST( fd_schar_zz_dec( (uchar)            1 )==(schar)       -1 );
    TEST( fd_schar_zz_dec( (uchar)            2 )==(schar)        1 );
    TEST( fd_schar_zz_dec( (uchar) UCHAR_MAX    )==(schar)SCHAR_MIN );
    TEST( fd_schar_zz_dec( (uchar)(UCHAR_MAX-1) )==(schar)SCHAR_MAX );
  }

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing short" ));
    for( int iter=0; iter<16777216; iter++ ) {
      int c = (int)(fd_rng_ulong( rng ) & 1UL);
      short x = (short)fd_rng_ulong( rng );
      short y = (short)fd_rng_ulong( rng );
      TEST( fd_short_if ( c, x, y )==(c ? x : y)                              );
      TEST( fd_short_abs( x       )==(ushort)((x<(short)0) ? ((short)-x) : x) );
      TEST( fd_short_min( x, y    )==((x<y) ? x : y)                          );
      TEST( fd_short_max( x, y    )==((x>y) ? x : y)                          );
    }

    TEST( fd_short_zz_enc( (short)        0 )==(ushort)             0 );
    TEST( fd_short_zz_enc( (short)       -1 )==(ushort)             1 );
    TEST( fd_short_zz_enc( (short)        1 )==(ushort)             2 );
    TEST( fd_short_zz_enc( (short)SHORT_MIN )==(ushort) USHORT_MAX    );
    TEST( fd_short_zz_enc( (short)SHORT_MAX )==(ushort)(USHORT_MAX-1) );

    TEST( fd_short_zz_dec( (ushort)             0 )==(short)        0 );
    TEST( fd_short_zz_dec( (ushort)             1 )==(short)       -1 );
    TEST( fd_short_zz_dec( (ushort)             2 )==(short)        1 );
    TEST( fd_short_zz_dec( (ushort) USHORT_MAX    )==(short)SHORT_MIN );
    TEST( fd_short_zz_dec( (ushort)(USHORT_MAX-1) )==(short)SHORT_MAX );
  }

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing int" ));
    for( int iter=0; iter<16777216; iter++ ) {
      int c = (int)(fd_rng_ulong( rng ) & 1UL);
      int x = (int)fd_rng_ulong( rng );
      int y = (int)fd_rng_ulong( rng );
      TEST( fd_int_if ( c, x, y )==(c ? x : y)                        );
      TEST( fd_int_abs( x       )==(uint)((x<(int)0) ? ((int)-x) : x) );
      TEST( fd_int_min( x, y    )==((x<y) ? x : y)                    );
      TEST( fd_int_max( x, y    )==((x>y) ? x : y)                    );
    }

    TEST( fd_int_zz_enc(       0 )==           0U );
    TEST( fd_int_zz_enc(      -1 )==           1U );
    TEST( fd_int_zz_enc(       1 )==           2U );
    TEST( fd_int_zz_enc( INT_MIN )== UINT_MAX     );
    TEST( fd_int_zz_enc( INT_MAX )==(UINT_MAX-1U) );

    TEST( fd_int_zz_dec(            0U )==      0 );
    TEST( fd_int_zz_dec(            1U )==     -1 );
    TEST( fd_int_zz_dec(            2U )==      1 );
    TEST( fd_int_zz_dec(  UINT_MAX     )==INT_MIN );
    TEST( fd_int_zz_dec( (UINT_MAX-1U) )==INT_MAX );
  }

  if( 1 ) {
    FD_LOG_NOTICE(( "Testing long" ));
    for( int iter=0; iter<16777216; iter++ ) {
      int  c = (int)(fd_rng_ulong( rng ) & 1UL);
      long x = (long)fd_rng_ulong( rng );
      long y = (long)fd_rng_ulong( rng );
      TEST( fd_long_if ( c, x, y )==(c ? x : y)                           );
      TEST( fd_long_abs( x       )==(ulong)((x<(long)0) ? ((long)-x) : x) );
      TEST( fd_long_min( x, y    )==((x<y) ? x : y)                       );
      TEST( fd_long_max( x, y    )==((x>y) ? x : y)                       );
    }

    TEST( fd_long_zz_enc(       0L )==            0UL );
    TEST( fd_long_zz_enc(      -1L )==            1UL );
    TEST( fd_long_zz_enc(       1L )==            2UL );
    TEST( fd_long_zz_enc( LONG_MIN )== ULONG_MAX      );
    TEST( fd_long_zz_enc( LONG_MAX )==(ULONG_MAX-1UL) );

    TEST( fd_long_zz_dec(             0UL )==      0L );
    TEST( fd_long_zz_dec(             1UL )==     -1L );
    TEST( fd_long_zz_dec(             2UL )==      1L );
    TEST( fd_long_zz_dec(  ULONG_MAX      )==LONG_MIN );
    TEST( fd_long_zz_dec( (ULONG_MAX-1UL) )==LONG_MAX );
  }

# if FD_HAS_INT128
  if( 1 ) {
    FD_LOG_NOTICE(( "Testing int128" ));
    for( int iter=0; iter<16777216; iter++ ) {
      int    c = (int)(fd_rng_ulong( rng ) & 1UL);
      int128 x = (int128)fd_rng_uint128( rng );
      int128 y = (int128)fd_rng_uint128( rng );
      TEST( fd_int128_if ( c, x, y )==(c ? x : y)                       );
      TEST( fd_int128_abs( x       )==(uint128)((x<(int128)0) ? -x : x) );
      TEST( fd_int128_min( x, y    )==((x<y) ? x : y)                   );
      TEST( fd_int128_max( x, y    )==((x>y) ? x : y)                   );
    }

    TEST( fd_int128_zz_enc(  (int128)0 )==              (uint128)0 );
    TEST( fd_int128_zz_enc( -(int128)1 )==              (uint128)1 );
    TEST( fd_int128_zz_enc(  (int128)1 )==              (uint128)2 );
    TEST( fd_int128_zz_enc( INT128_MIN )== UINT128_MAX             );
    TEST( fd_int128_zz_enc( INT128_MAX )==(UINT128_MAX-(uint128)1) );

    TEST( fd_int128_zz_dec(               (uint128)0 )== (int128)0 );
    TEST( fd_int128_zz_dec(               (uint128)1 )==-(int128)1 );
    TEST( fd_int128_zz_dec(               (uint128)2 )== (int128)1 );
    TEST( fd_int128_zz_dec(  UINT128_MAX             )==INT128_MIN );
    TEST( fd_int128_zz_dec( (UINT128_MAX-(uint128)1) )==INT128_MAX );
  }
# endif

# undef TEST

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
