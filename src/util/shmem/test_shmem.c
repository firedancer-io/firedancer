#include "../fd_util.h"

#if FD_HAS_HOSTED && FD_HAS_X86

#include <ctype.h> /* For isalnum */

FD_STATIC_ASSERT( FD_SHMEM_NAME_MAX==FD_LOG_NAME_MAX, unit_test );

FD_STATIC_ASSERT( FD_SHMEM_UNKNOWN_LG_PAGE_SZ ==-1, unit_test );
FD_STATIC_ASSERT( FD_SHMEM_NORMAL_LG_PAGE_SZ  ==12, unit_test );
FD_STATIC_ASSERT( FD_SHMEM_HUGE_LG_PAGE_SZ    ==21, unit_test );
FD_STATIC_ASSERT( FD_SHMEM_GIGANTIC_LG_PAGE_SZ==30, unit_test );

FD_STATIC_ASSERT( FD_SHMEM_UNKNOWN_PAGE_SZ == 0UL,                                unit_test );
FD_STATIC_ASSERT( FD_SHMEM_NORMAL_PAGE_SZ  ==(1UL<<FD_SHMEM_NORMAL_LG_PAGE_SZ  ), unit_test );
FD_STATIC_ASSERT( FD_SHMEM_HUGE_PAGE_SZ    ==(1UL<<FD_SHMEM_HUGE_LG_PAGE_SZ    ), unit_test );
FD_STATIC_ASSERT( FD_SHMEM_GIGANTIC_PAGE_SZ==(1UL<<FD_SHMEM_GIGANTIC_LG_PAGE_SZ), unit_test );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

# define TEST(c) do if( !(c) ) { FD_LOG_WARNING(( "FAIL: " #c )); return 1; } while(0)

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  
  TEST( !fd_shmem_name_len( NULL ) ); /* NULL name */

  for( int i=0; i<1000000; i++ ) {
    ulong len = (ulong)fd_rng_uint_roll( rng, FD_SHMEM_NAME_MAX+1UL ); /* In [0,FD_SHMEM_NAME_MAX] */
    char name[ FD_SHMEM_NAME_MAX+1UL ];
    for( ulong b=0UL; b<len; b++ ) {
      uint r = fd_rng_uint_roll( rng, 66U ); /* In [0,65] */
      char c;
      if     ( r< 26U ) c = (char)( ((uint)'A') +  r      ); /* Allowed anywhere, A-Z */
      else if( r< 52U ) c = (char)( ((uint)'a') + (r-26U) ); /* Allowed anywhere, a-z */
      else if( r< 62U ) c = (char)( ((uint)'0') + (r-52U) ); /* Allowed anywhere, 0-9 */
      else if( r==62U ) c = '.'; /* Forbidden at start */
      else if( r==63U ) c = '-'; /* " */
      else if( r==64U ) c = '_'; /* " */
      else              c = '@'; /* Completely forbidden */
      name[b] = c;
    }
    name[len] = '\0';

    ulong expected = len;
    if     ( len< 1UL               ) expected = 0UL; /* too short */
    else if( len>=FD_SHMEM_NAME_MAX ) expected = 0UL; /* too long */
    else if( !isalnum( name[0] )    ) expected = 0UL; /* invalid first character */
    else
      for( ulong b=1UL; b<len; b++ ) {
        char c = name[b];
        if( !( isalnum( c ) || (c=='_') || (c=='-') || (c=='.') ) ) { expected = 0UL; break; } /* invalid suffix character */
      }

    TEST( fd_shmem_name_len( name )==expected );
  }

  TEST( fd_shmem_name_len( ""                                         )==0UL                     ); /* too short */
  TEST( fd_shmem_name_len( "1"                                        )==1UL                     );
  TEST( fd_shmem_name_len( "-"                                        )==0UL                     ); /* bad first char */
  TEST( fd_shmem_name_len( "123456789012345678901234567890123456789"  )==(FD_SHMEM_NAME_MAX-1UL) );
  TEST( fd_shmem_name_len( "1234567890123456789012345678901234567890" )==0UL                     ); /* too long */

  TEST( fd_cstr_to_shmem_lg_page_sz( NULL       )==FD_SHMEM_UNKNOWN_LG_PAGE_SZ  );
  TEST( fd_cstr_to_shmem_lg_page_sz( ""         )==FD_SHMEM_UNKNOWN_LG_PAGE_SZ  );
  TEST( fd_cstr_to_shmem_lg_page_sz( "1"        )==FD_SHMEM_UNKNOWN_LG_PAGE_SZ  );
  TEST( fd_cstr_to_shmem_lg_page_sz( "foo"      )==FD_SHMEM_UNKNOWN_LG_PAGE_SZ  );
  TEST( fd_cstr_to_shmem_lg_page_sz( "normal"   )==FD_SHMEM_NORMAL_LG_PAGE_SZ   );
  TEST( fd_cstr_to_shmem_lg_page_sz( "NORMAL"   )==FD_SHMEM_NORMAL_LG_PAGE_SZ   );
  TEST( fd_cstr_to_shmem_lg_page_sz( "12"       )==FD_SHMEM_NORMAL_LG_PAGE_SZ   );
  TEST( fd_cstr_to_shmem_lg_page_sz( "huge"     )==FD_SHMEM_HUGE_LG_PAGE_SZ     );
  TEST( fd_cstr_to_shmem_lg_page_sz( "HUGE"     )==FD_SHMEM_HUGE_LG_PAGE_SZ     );
  TEST( fd_cstr_to_shmem_lg_page_sz( "21"       )==FD_SHMEM_HUGE_LG_PAGE_SZ     );
  TEST( fd_cstr_to_shmem_lg_page_sz( "gigantic" )==FD_SHMEM_GIGANTIC_LG_PAGE_SZ );
  TEST( fd_cstr_to_shmem_lg_page_sz( "GIGANTIC" )==FD_SHMEM_GIGANTIC_LG_PAGE_SZ );
  TEST( fd_cstr_to_shmem_lg_page_sz( "30"       )==FD_SHMEM_GIGANTIC_LG_PAGE_SZ );

  TEST( !strcmp( fd_shmem_lg_page_sz_to_cstr(  0 ), "unknown"  ) );
  TEST( !strcmp( fd_shmem_lg_page_sz_to_cstr( 12 ), "normal"   ) );
  TEST( !strcmp( fd_shmem_lg_page_sz_to_cstr( 21 ), "huge"     ) );
  TEST( !strcmp( fd_shmem_lg_page_sz_to_cstr( 30 ), "gigantic" ) );

  TEST( fd_cstr_to_shmem_page_sz( NULL         )==FD_SHMEM_UNKNOWN_PAGE_SZ  );
  TEST( fd_cstr_to_shmem_page_sz( ""           )==FD_SHMEM_UNKNOWN_PAGE_SZ  );
  TEST( fd_cstr_to_shmem_page_sz( "1"          )==FD_SHMEM_UNKNOWN_PAGE_SZ  );
  TEST( fd_cstr_to_shmem_page_sz( "foo"        )==FD_SHMEM_UNKNOWN_PAGE_SZ  );
  TEST( fd_cstr_to_shmem_page_sz( "normal"     )==FD_SHMEM_NORMAL_PAGE_SZ   );
  TEST( fd_cstr_to_shmem_page_sz( "NORMAL"     )==FD_SHMEM_NORMAL_PAGE_SZ   );
  TEST( fd_cstr_to_shmem_page_sz( "4096"       )==FD_SHMEM_NORMAL_PAGE_SZ   );
  TEST( fd_cstr_to_shmem_page_sz( "huge"       )==FD_SHMEM_HUGE_PAGE_SZ     );
  TEST( fd_cstr_to_shmem_page_sz( "HUGE"       )==FD_SHMEM_HUGE_PAGE_SZ     );
  TEST( fd_cstr_to_shmem_page_sz( "2097152"    )==FD_SHMEM_HUGE_PAGE_SZ     );
  TEST( fd_cstr_to_shmem_page_sz( "gigantic"   )==FD_SHMEM_GIGANTIC_PAGE_SZ );
  TEST( fd_cstr_to_shmem_page_sz( "GIGANTIC"   )==FD_SHMEM_GIGANTIC_PAGE_SZ );
  TEST( fd_cstr_to_shmem_page_sz( "1073741824" )==FD_SHMEM_GIGANTIC_PAGE_SZ );

  TEST( !strcmp( fd_shmem_page_sz_to_cstr(          0UL ), "unknown"  ) );
  TEST( !strcmp( fd_shmem_page_sz_to_cstr(       4096UL ), "normal"   ) );
  TEST( !strcmp( fd_shmem_page_sz_to_cstr(    2097152UL ), "huge"     ) );
  TEST( !strcmp( fd_shmem_page_sz_to_cstr( 1073741824UL ), "gigantic" ) );

  fd_rng_leave( fd_rng_delete( rng ) );

# undef TEST

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_HOSTED and FD_HAS_X86 capabilities" ));
  fd_halt();
  return 0;
}

#endif

