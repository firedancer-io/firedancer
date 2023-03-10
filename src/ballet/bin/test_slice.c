#include "fd_slice.h"

FD_STATIC_ASSERT( alignof(fd_slice_t)==FD_SLICE_ALIGN,     alignment );
FD_STATIC_ASSERT( sizeof (fd_slice_t)==FD_SLICE_FOOTPRINT, alignment );


void
test_empty( fd_slice_t * slice ) {
  /* On empty, all memory accesses should gracefully fail */

  FD_TEST( fd_slice_sz( slice )==0UL );

  FD_TEST( fd_slice_peek( slice, 0UL, 0UL )==NULL ); FD_TEST( !fd_slice_isoob( slice ) );
  FD_TEST( fd_slice_peek( slice, 0UL, 1UL )==NULL ); FD_TEST( !fd_slice_isoob( slice ) );

  FD_TEST(  fd_slice_subslice( fd_slice_clearerr( slice ), 0UL, 0UL ) ); FD_TEST( !fd_slice_isoob( slice ) );
  FD_TEST( !fd_slice_subslice( fd_slice_clearerr( slice ), 0UL, 1UL ) ); FD_TEST(  fd_slice_isoob( slice ) );

            fd_slice_advance( fd_slice_clearerr( slice ), 0UL );         FD_TEST( !fd_slice_isoob( slice ) );
  FD_TEST( !fd_slice_advance( fd_slice_clearerr( slice ), 1UL ) );       FD_TEST(  fd_slice_isoob( slice ) );

  FD_TEST( fd_slice_read_uchar    ( fd_slice_clearerr( slice ) )==0UL ); FD_TEST(  fd_slice_isoob( slice ) );
  FD_TEST( fd_slice_read_ushort   ( fd_slice_clearerr( slice ) )==0UL ); FD_TEST(  fd_slice_isoob( slice ) );
  FD_TEST( fd_slice_read_uint     ( fd_slice_clearerr( slice ) )==0UL ); FD_TEST(  fd_slice_isoob( slice ) );
  FD_TEST( fd_slice_read_ulong    ( fd_slice_clearerr( slice ) )==0UL ); FD_TEST(  fd_slice_isoob( slice ) );
  FD_TEST( fd_slice_read_ushort_be( fd_slice_clearerr( slice ) )==0UL ); FD_TEST(  fd_slice_isoob( slice ) );
  FD_TEST( fd_slice_read_uint_be  ( fd_slice_clearerr( slice ) )==0UL ); FD_TEST(  fd_slice_isoob( slice ) );
  FD_TEST( fd_slice_read_ulong_be ( fd_slice_clearerr( slice ) )==0UL ); FD_TEST(  fd_slice_isoob( slice ) );
}


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( fd_slice_align()    ==FD_SLICE_ALIGN );
  FD_TEST( fd_slice_footprint()==FD_SLICE_FOOTPRINT );

  /* Test fd_slice_new */

  fd_slice_t _slice[2];

  FD_TEST( fd_slice_new( NULL )==NULL ); /* NULL slice    */
  FD_TEST( fd_slice_new( (void *)((ulong)_slice+1UL) )==NULL ); /* unalign slice */

  fd_slice_t * slice = fd_slice_new( _slice );
  FD_TEST( slice );

  test_empty( slice );

  /* Test fd_slice_peek */

  uchar mem[ 8UL ] = {'a','b','c','d','e','f','g','h'};

  FD_TEST( fd_slice_join( slice, mem, 8UL )==slice );
  FD_TEST( fd_slice_isoob( slice )==0U  );
  FD_TEST( fd_slice_sz   ( slice )==8UL );

  for( ulong i=0UL; i<=8UL; i++ )
    FD_TEST( fd_slice_peek( slice, 0UL, i )==mem );

  for( ulong i=9UL; i<16UL; i++ )
    FD_TEST( fd_slice_peek( slice, 0UL, i )==NULL ); /* OOB sz */

  for( ulong i=0UL; i<8UL; i++ )
    FD_TEST( fd_slice_peek( slice, i, 8UL-i )==mem+i );

  for( ulong i=8UL; i<16UL; i++ )
    FD_TEST( fd_slice_peek( slice, i, 1UL )==NULL ); /* OOB off */

  FD_TEST( fd_slice_peek( slice, ULONG_MAX, 0UL       )==NULL ); /* overflow off */
  FD_TEST( fd_slice_peek( slice, ULONG_MAX, 1UL       )==NULL ); /* overflow off */
  FD_TEST( fd_slice_peek( slice, ULONG_MAX, 2UL       )==NULL ); /* overflow off, but in-bounds end */
  FD_TEST( fd_slice_peek( slice, 0UL,       ULONG_MAX )==NULL ); /* overflow sz */
  FD_TEST( fd_slice_peek( slice, 1UL,       ULONG_MAX )==NULL ); /* overflow sz */
  FD_TEST( fd_slice_peek( slice, 2UL,       ULONG_MAX )==NULL ); /* overflow sz */
  FD_TEST( fd_slice_peek( slice, ULONG_MAX, ULONG_MAX )==NULL ); /* overflow off, sz */

  FD_TEST( !fd_slice_isoob( slice ) ); /* fd_slice_peek does not set OOB */

  /* FIXME: test fd_slice_subslice */
  /* FIXME: test fd_slice_advance  */

  /* Test fd_slice_clone */

  fd_slice_t * slice2 = fd_slice_new( _slice+1UL );
  FD_TEST( slice );

  FD_TEST( fd_slice_join ( slice,  mem, 8UL  )==slice  );
  FD_TEST( fd_slice_clone( slice2, slice     )==slice2 );
  FD_TEST( 0==memcmp( slice, slice2, FD_SLICE_FOOTPRINT ) );

  FD_TEST( fd_uchar_load_1 ( fd_slice_peek( slice,  0UL, 1UL ) )==0x61 );
  FD_TEST( fd_slice_advance( slice, 2UL  )      );
  FD_TEST( fd_uchar_load_1 ( fd_slice_peek( slice,  0UL, 1UL ) )==0x63 );
  FD_TEST( fd_uchar_load_1 ( fd_slice_peek( slice2, 0UL, 1UL ) )==0x61 );
  FD_TEST( fd_slice_sz     ( slice       )==6UL );
  FD_TEST( fd_slice_sz     ( slice2      )==8UL );

  FD_TEST( fd_slice_advance( slice2, 1UL )      );
  FD_TEST( fd_uchar_load_1 ( fd_slice_peek( slice,  0UL, 1UL ) )==0x63 );
  FD_TEST( fd_uchar_load_1 ( fd_slice_peek( slice2, 0UL, 1UL ) )==0x62 );
  FD_TEST( fd_slice_sz     ( slice       )==6UL );
  FD_TEST( fd_slice_sz     ( slice2      )==7UL );

  /* Test fd_slice_read primitives */

  FD_TEST( fd_slice_read_uchar    ( fd_slice_join( slice, mem, 8UL ) )==              0x61UL ); FD_TEST( !fd_slice_isoob( slice ) );
  FD_TEST( fd_slice_read_ushort   ( fd_slice_join( slice, mem, 8UL ) )==            0x6261UL ); FD_TEST( !fd_slice_isoob( slice ) );
  FD_TEST( fd_slice_read_uint     ( fd_slice_join( slice, mem, 8UL ) )==        0x64636261UL ); FD_TEST( !fd_slice_isoob( slice ) );
  FD_TEST( fd_slice_read_ulong    ( fd_slice_join( slice, mem, 8UL ) )==0x6867666564636261UL ); FD_TEST( !fd_slice_isoob( slice ) );
  FD_TEST( fd_slice_read_ushort_be( fd_slice_join( slice, mem, 8UL ) )==0x6162UL             ); FD_TEST( !fd_slice_isoob( slice ) );
  FD_TEST( fd_slice_read_uint_be  ( fd_slice_join( slice, mem, 8UL ) )==0x61626364UL         ); FD_TEST( !fd_slice_isoob( slice ) );
  FD_TEST( fd_slice_read_ulong_be ( fd_slice_join( slice, mem, 8UL ) )==0x6162636465666768UL ); FD_TEST( !fd_slice_isoob( slice ) );

  FD_TEST( fd_slice_read_ushort   ( fd_slice_join( slice, mem, 1UL ) )==0UL ); FD_TEST( fd_slice_isoob( slice ) );
  FD_TEST( fd_slice_read_uint     ( fd_slice_join( slice, mem, 3UL ) )==0UL ); FD_TEST( fd_slice_isoob( slice ) );
  FD_TEST( fd_slice_read_ulong    ( fd_slice_join( slice, mem, 7UL ) )==0UL ); FD_TEST( fd_slice_isoob( slice ) );
  FD_TEST( fd_slice_read_ushort_be( fd_slice_join( slice, mem, 1UL ) )==0UL ); FD_TEST( fd_slice_isoob( slice ) );
  FD_TEST( fd_slice_read_uint_be  ( fd_slice_join( slice, mem, 3UL ) )==0UL ); FD_TEST( fd_slice_isoob( slice ) );
  FD_TEST( fd_slice_read_ulong_be ( fd_slice_join( slice, mem, 7UL ) )==0UL ); FD_TEST( fd_slice_isoob( slice ) );

  /* Test fd_slice_leave */

  FD_TEST( fd_slice_join ( slice, mem, 8UL )==slice );
  FD_TEST( fd_slice_sz   ( slice )          ==8UL   );
  FD_TEST( fd_slice_leave( slice )          ==slice );
  FD_TEST( fd_slice_sz   ( slice )          ==0UL   );

  test_empty( slice );

  /* Test fd_slice_delete */

  FD_TEST( fd_slice_delete( slice2 )==_slice+1UL );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
