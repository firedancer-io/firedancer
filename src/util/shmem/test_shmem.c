#include "../fd_util.h"

#if FD_HAS_HOSTED

#include <ctype.h> /* For isalnum */
#include <errno.h>

FD_STATIC_ASSERT( FD_SHMEM_JOIN_MAX>0UL, unit_test );

FD_STATIC_ASSERT( FD_SHMEM_JOIN_MODE_READ_ONLY ==0, unit_test );
FD_STATIC_ASSERT( FD_SHMEM_JOIN_MODE_READ_WRITE==1, unit_test );

FD_STATIC_ASSERT( FD_SHMEM_NUMA_MAX> 0L,                unit_test );
FD_STATIC_ASSERT( FD_SHMEM_CPU_MAX >=FD_SHMEM_NUMA_MAX, unit_test );

FD_STATIC_ASSERT( FD_SHMEM_UNKNOWN_LG_PAGE_SZ ==-1, unit_test );
FD_STATIC_ASSERT( FD_SHMEM_NORMAL_LG_PAGE_SZ  ==12, unit_test );
FD_STATIC_ASSERT( FD_SHMEM_HUGE_LG_PAGE_SZ    ==21, unit_test );
FD_STATIC_ASSERT( FD_SHMEM_GIGANTIC_LG_PAGE_SZ==30, unit_test );

FD_STATIC_ASSERT( FD_SHMEM_UNKNOWN_PAGE_SZ == 0UL,                                unit_test );
FD_STATIC_ASSERT( FD_SHMEM_NORMAL_PAGE_SZ  ==(1UL<<FD_SHMEM_NORMAL_LG_PAGE_SZ  ), unit_test );
FD_STATIC_ASSERT( FD_SHMEM_HUGE_PAGE_SZ    ==(1UL<<FD_SHMEM_HUGE_LG_PAGE_SZ    ), unit_test );
FD_STATIC_ASSERT( FD_SHMEM_GIGANTIC_PAGE_SZ==(1UL<<FD_SHMEM_GIGANTIC_LG_PAGE_SZ), unit_test );

FD_STATIC_ASSERT( FD_SHMEM_NAME_MAX==FD_LOG_NAME_MAX, unit_test );

FD_STATIC_ASSERT( FD_SHMEM_PAGE_SZ_CSTR_MAX==9UL, unit_test );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  
  ulong numa_cnt = fd_shmem_numa_cnt(); FD_TEST( (1UL<=numa_cnt) & (numa_cnt<=FD_SHMEM_NUMA_MAX) );
  ulong cpu_cnt  = fd_shmem_cpu_cnt (); FD_TEST( (1UL<=cpu_cnt ) & (cpu_cnt <=FD_SHMEM_CPU_MAX ) );
  FD_TEST( numa_cnt<=cpu_cnt );

  FD_TEST( fd_shmem_numa_idx( cpu_cnt )==ULONG_MAX );
  FD_TEST( fd_shmem_cpu_idx( numa_cnt )==ULONG_MAX );
  for( ulong cpu_idx=0UL; cpu_idx<cpu_cnt; cpu_idx++ ) {
    ulong numa_idx = fd_shmem_numa_idx( cpu_idx );
    FD_TEST( numa_idx<numa_cnt );
    FD_TEST( fd_shmem_cpu_idx( numa_idx )<=cpu_idx );
    FD_LOG_NOTICE(( "cpu %lu -> numa %lu", cpu_idx, numa_idx ));
  }

  for( ulong numa_idx=0UL; numa_idx<numa_cnt; numa_idx++ ) {
    ulong cpu_idx = fd_shmem_cpu_idx( numa_idx );
    FD_TEST( cpu_idx<cpu_cnt );
    FD_TEST( fd_shmem_numa_idx( cpu_idx )==numa_idx );
    FD_LOG_NOTICE(( "numa %lu -> cpu %lu", numa_idx, cpu_idx ));
  }

  FD_TEST( !fd_shmem_name_len( NULL ) ); /* NULL name */

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

    FD_TEST( fd_shmem_name_len( name )==expected );
  }

  FD_TEST( fd_shmem_name_len( ""                                         )==0UL                     ); /* too short */
  FD_TEST( fd_shmem_name_len( "1"                                        )==1UL                     );
  FD_TEST( fd_shmem_name_len( "-"                                        )==0UL                     ); /* bad first char */
  FD_TEST( fd_shmem_name_len( "123456789012345678901234567890123456789"  )==(FD_SHMEM_NAME_MAX-1UL) );
  FD_TEST( fd_shmem_name_len( "1234567890123456789012345678901234567890" )==0UL                     ); /* too long */

  FD_TEST( fd_cstr_to_shmem_lg_page_sz( NULL       )==FD_SHMEM_UNKNOWN_LG_PAGE_SZ  );
  FD_TEST( fd_cstr_to_shmem_lg_page_sz( ""         )==FD_SHMEM_UNKNOWN_LG_PAGE_SZ  );
  FD_TEST( fd_cstr_to_shmem_lg_page_sz( "1"        )==FD_SHMEM_UNKNOWN_LG_PAGE_SZ  );
  FD_TEST( fd_cstr_to_shmem_lg_page_sz( "foo"      )==FD_SHMEM_UNKNOWN_LG_PAGE_SZ  );
  FD_TEST( fd_cstr_to_shmem_lg_page_sz( "normal"   )==FD_SHMEM_NORMAL_LG_PAGE_SZ   );
  FD_TEST( fd_cstr_to_shmem_lg_page_sz( "NORMAL"   )==FD_SHMEM_NORMAL_LG_PAGE_SZ   );
  FD_TEST( fd_cstr_to_shmem_lg_page_sz( "12"       )==FD_SHMEM_NORMAL_LG_PAGE_SZ   );
  FD_TEST( fd_cstr_to_shmem_lg_page_sz( "huge"     )==FD_SHMEM_HUGE_LG_PAGE_SZ     );
  FD_TEST( fd_cstr_to_shmem_lg_page_sz( "HUGE"     )==FD_SHMEM_HUGE_LG_PAGE_SZ     );
  FD_TEST( fd_cstr_to_shmem_lg_page_sz( "21"       )==FD_SHMEM_HUGE_LG_PAGE_SZ     );
  FD_TEST( fd_cstr_to_shmem_lg_page_sz( "gigantic" )==FD_SHMEM_GIGANTIC_LG_PAGE_SZ );
  FD_TEST( fd_cstr_to_shmem_lg_page_sz( "GIGANTIC" )==FD_SHMEM_GIGANTIC_LG_PAGE_SZ );
  FD_TEST( fd_cstr_to_shmem_lg_page_sz( "30"       )==FD_SHMEM_GIGANTIC_LG_PAGE_SZ );

  FD_TEST( !strcmp( fd_shmem_lg_page_sz_to_cstr(  0 ), "unknown"  ) );
  FD_TEST( !strcmp( fd_shmem_lg_page_sz_to_cstr( 12 ), "normal"   ) );
  FD_TEST( !strcmp( fd_shmem_lg_page_sz_to_cstr( 21 ), "huge"     ) );
  FD_TEST( !strcmp( fd_shmem_lg_page_sz_to_cstr( 30 ), "gigantic" ) );

  FD_TEST( fd_cstr_to_shmem_page_sz( NULL         )==FD_SHMEM_UNKNOWN_PAGE_SZ  );
  FD_TEST( fd_cstr_to_shmem_page_sz( ""           )==FD_SHMEM_UNKNOWN_PAGE_SZ  );
  FD_TEST( fd_cstr_to_shmem_page_sz( "1"          )==FD_SHMEM_UNKNOWN_PAGE_SZ  );
  FD_TEST( fd_cstr_to_shmem_page_sz( "foo"        )==FD_SHMEM_UNKNOWN_PAGE_SZ  );
  FD_TEST( fd_cstr_to_shmem_page_sz( "normal"     )==FD_SHMEM_NORMAL_PAGE_SZ   );
  FD_TEST( fd_cstr_to_shmem_page_sz( "NORMAL"     )==FD_SHMEM_NORMAL_PAGE_SZ   );
  FD_TEST( fd_cstr_to_shmem_page_sz( "4096"       )==FD_SHMEM_NORMAL_PAGE_SZ   );
  FD_TEST( fd_cstr_to_shmem_page_sz( "huge"       )==FD_SHMEM_HUGE_PAGE_SZ     );
  FD_TEST( fd_cstr_to_shmem_page_sz( "HUGE"       )==FD_SHMEM_HUGE_PAGE_SZ     );
  FD_TEST( fd_cstr_to_shmem_page_sz( "2097152"    )==FD_SHMEM_HUGE_PAGE_SZ     );
  FD_TEST( fd_cstr_to_shmem_page_sz( "gigantic"   )==FD_SHMEM_GIGANTIC_PAGE_SZ );
  FD_TEST( fd_cstr_to_shmem_page_sz( "GIGANTIC"   )==FD_SHMEM_GIGANTIC_PAGE_SZ );
  FD_TEST( fd_cstr_to_shmem_page_sz( "1073741824" )==FD_SHMEM_GIGANTIC_PAGE_SZ );

  FD_TEST( !strcmp( fd_shmem_page_sz_to_cstr(          0UL ), "unknown"  ) );
  FD_TEST( !strcmp( fd_shmem_page_sz_to_cstr(       4096UL ), "normal"   ) );
  FD_TEST( !strcmp( fd_shmem_page_sz_to_cstr(    2097152UL ), "huge"     ) );
  FD_TEST( !strcmp( fd_shmem_page_sz_to_cstr( 1073741824UL ), "gigantic" ) );

  fd_shmem_join_info_t info[ 1 ];

  /* These should all fail */
  /* FIXME: COVERAGE OF LEAVE WITH NO JOIN BEHAVIOR */
  /* FIXME: COVERAGE OF JOIN/LEAVE FUNCS AND JOIN OPT_INFO */

  FD_TEST( fd_shmem_join_query_by_name( NULL,      NULL )==EINVAL ); FD_TEST( fd_shmem_join_query_by_name( NULL,      info )==EINVAL );
  FD_TEST( fd_shmem_join_query_by_name( "",        NULL )==EINVAL ); FD_TEST( fd_shmem_join_query_by_name( "",        info )==EINVAL );
  FD_TEST( fd_shmem_join_query_by_join( NULL,      NULL )==EINVAL ); FD_TEST( fd_shmem_join_query_by_join( NULL,      info )==EINVAL );

  FD_TEST( fd_shmem_join_query_by_addr( NULL, 0UL, NULL )==ENOENT );
  FD_TEST( fd_shmem_join_query_by_addr( NULL, 0UL, info )==ENOENT );

  FD_TEST( fd_shmem_join_query_by_addr( NULL, 1UL, NULL )==ENOENT );
  FD_TEST( fd_shmem_join_query_by_addr( NULL, 1UL, info )==ENOENT );

  FD_TEST( fd_shmem_join_query_by_addr( (void *)ULONG_MAX, 2UL, NULL )==EINVAL );
  FD_TEST( fd_shmem_join_query_by_addr( (void *)ULONG_MAX, 2UL, info )==EINVAL );

  if( argc>1 ) {
    ulong name_cnt = fd_ulong_min( (ulong)(argc-1), FD_SHMEM_JOIN_MAX );
    char ** _name = &argv[1]; /* Assumed valid and distinct */

    fd_shmem_join_info_t ref_info[ FD_SHMEM_JOIN_MAX ];
    fd_memset( ref_info, 0, name_cnt*sizeof(fd_shmem_join_info_t) );

    for( int i=0; i<65536; i++ ) {
      ulong idx = fd_rng_ulong_roll( rng, name_cnt );
      char const * name = _name[ idx ];

      uint r  = fd_rng_uint( rng );
      int  op = (int)(r & 1U); r >>= 1;
      int  rw = (int)(r & 1U); r >>= 1;

      if( op ) { /* join */

        int mode = rw ? FD_SHMEM_JOIN_MODE_READ_WRITE : FD_SHMEM_JOIN_MODE_READ_ONLY;
        if( !ref_info[ idx ].ref_cnt ) { /* this join needs to map it */

          FD_TEST( fd_shmem_join_query_by_name( name, NULL )==ENOENT );
          FD_TEST( fd_shmem_join_query_by_name( name, info )==ENOENT );

          void * join = fd_shmem_join( name, mode, NULL, NULL, NULL );
          FD_TEST( join );

          FD_TEST( !fd_shmem_join_query_by_name( name, NULL ) );
          FD_TEST( !fd_shmem_join_query_by_name( name, info ) );

          void * shmem    = info->shmem;
          ulong  page_sz  = info->page_sz;
          ulong  page_cnt = info->page_cnt;
          ulong  sz       = page_sz*page_cnt;
          ulong  off      = fd_rng_ulong_roll( rng, sz );

          FD_TEST( info->ref_cnt==1L                                                  );
          FD_TEST( info->join   ==join                                                );
          FD_TEST( shmem        ==join                                                );
          FD_TEST( fd_ulong_is_aligned( (ulong)shmem, page_sz )                       );
          FD_TEST( fd_shmem_is_page_sz( page_sz )                                     );
          FD_TEST( page_cnt     > 0UL                                                 );
          FD_TEST( page_cnt     <=((ulong)LONG_MAX/page_sz)                           );
          FD_TEST( info->mode   ==mode                                                );
          FD_TEST( info->hash   ==(uint)fd_hash( 0UL, info->name, FD_SHMEM_NAME_MAX ) );
          FD_TEST( !strcmp( info->name, name )                                        );

          fd_shmem_join_info_t * ref = &ref_info[idx];

          fd_memset( ref, 0, sizeof(fd_shmem_join_info_t) );
          FD_TEST( !fd_shmem_join_query_by_join( join, NULL ) );
          FD_TEST( !fd_shmem_join_query_by_join( join, ref ) );
          FD_TEST( !memcmp( ref, info, sizeof(fd_shmem_join_info_t) ) );

          fd_memset( ref, 0, sizeof(fd_shmem_join_info_t) );
          FD_TEST( !fd_shmem_join_query_by_addr( ((uchar *)shmem) + off, 1UL, NULL ) );
          FD_TEST( !fd_shmem_join_query_by_addr( ((uchar *)shmem) + off, 1UL, ref  ) );
          FD_TEST( !memcmp( ref, info, sizeof(fd_shmem_join_info_t) ) );

        } else { /* this join just increments the ref cnt */

          fd_shmem_join_info_t * ref = &ref_info[idx];
          void * join     = ref->join;
          void * shmem    = ref->shmem;
          ulong  page_sz  = ref->page_sz;
          ulong  page_cnt = ref->page_cnt;
          ulong  sz       = page_sz*page_cnt;
          ulong  off      = fd_rng_ulong_roll( rng, sz );

          fd_memset( info, 0, sizeof(fd_shmem_join_info_t) );
          FD_TEST( !fd_shmem_join_query_by_name( name, NULL ) );
          FD_TEST( !fd_shmem_join_query_by_name( name, info ) );
          FD_TEST( !memcmp( info, ref, sizeof(fd_shmem_join_info_t) ) );

          fd_memset( info, 0, sizeof(fd_shmem_join_info_t) );
          FD_TEST( !fd_shmem_join_query_by_join( join, NULL ) );
          FD_TEST( !fd_shmem_join_query_by_join( join, info ) );
          FD_TEST( !memcmp( info, ref, sizeof(fd_shmem_join_info_t) ) );

          fd_memset( info, 0, sizeof(fd_shmem_join_info_t) );
          FD_TEST( !fd_shmem_join_query_by_addr( ((uchar *)shmem) + off, 1UL, NULL ) );
          FD_TEST( !fd_shmem_join_query_by_addr( ((uchar *)shmem) + off, 1UL, info ) );
          FD_TEST( !memcmp( info, ref, sizeof(fd_shmem_join_info_t) ) );

          FD_TEST( fd_shmem_join( name, mode, NULL, NULL, NULL )==join );
          ref_info[idx].ref_cnt++;

          fd_memset( info, 0, sizeof(fd_shmem_join_info_t) );
          FD_TEST( !fd_shmem_join_query_by_name( name, NULL ) );
          FD_TEST( !fd_shmem_join_query_by_name( name, info ) );
          FD_TEST( !memcmp( info, ref, sizeof(fd_shmem_join_info_t) ) );

          fd_memset( info, 0, sizeof(fd_shmem_join_info_t) );
          FD_TEST( !fd_shmem_join_query_by_join( join, NULL ) );
          FD_TEST( !fd_shmem_join_query_by_join( join, info ) );
          FD_TEST( !memcmp( info, ref, sizeof(fd_shmem_join_info_t) ) );

          fd_memset( info, 0, sizeof(fd_shmem_join_info_t) );
          FD_TEST( !fd_shmem_join_query_by_addr( ((uchar *)shmem) + off, 1UL, NULL ) );
          FD_TEST( !fd_shmem_join_query_by_addr( ((uchar *)shmem) + off, 1UL, info ) );
          FD_TEST( !memcmp( info, ref, sizeof(fd_shmem_join_info_t) ) );
        }

      } else { /* leave */

        if( ref_info[idx].ref_cnt<1L ) continue; /* Not currently joined */

        fd_shmem_join_info_t * ref = &ref_info[idx];
        void * join     = ref->join;
        void * shmem    = ref->shmem;
        ulong  page_sz  = ref->page_sz;
        ulong  page_cnt = ref->page_cnt;
        ulong  sz       = page_sz*page_cnt;
        ulong  off      = fd_rng_ulong_roll( rng, sz );

        fd_memset( info, 0, sizeof(fd_shmem_join_info_t) );
        FD_TEST( !fd_shmem_join_query_by_name( name, NULL ) );
        FD_TEST( !fd_shmem_join_query_by_name( name, info ) );
        FD_TEST( !memcmp( info, ref, sizeof(fd_shmem_join_info_t) ) );

        fd_memset( info, 0, sizeof(fd_shmem_join_info_t) );
        FD_TEST( !fd_shmem_join_query_by_join( join, NULL ) );
        FD_TEST( !fd_shmem_join_query_by_join( join, info ) );
        FD_TEST( !memcmp( info, ref, sizeof(fd_shmem_join_info_t) ) );

        fd_memset( info, 0, sizeof(fd_shmem_join_info_t) );
        FD_TEST( !fd_shmem_join_query_by_addr( ((uchar *)shmem) + off, 1UL, NULL ) );
        FD_TEST( !fd_shmem_join_query_by_addr( ((uchar *)shmem) + off, 1UL, info ) );
        FD_TEST( !memcmp( info, ref, sizeof(fd_shmem_join_info_t) ) );

        fd_shmem_leave( join, NULL, NULL );
        ref_info[idx].ref_cnt--;

        if( !ref_info[idx].ref_cnt ) { /* this leave should have unmapped it */

          FD_TEST( fd_shmem_join_query_by_name( name, NULL )==ENOENT );
          FD_TEST( fd_shmem_join_query_by_name( name, info )==ENOENT );

          FD_TEST( fd_shmem_join_query_by_join( join, NULL )==ENOENT );
          FD_TEST( fd_shmem_join_query_by_join( join, info )==ENOENT );

          FD_TEST( fd_shmem_join_query_by_addr( ((uchar *)shmem) + off, 1UL, NULL )==ENOENT );
          FD_TEST( fd_shmem_join_query_by_addr( ((uchar *)shmem) + off, 1UL, info )==ENOENT );

        } else if( ref_info[idx].ref_cnt>1L ) { /* this leave just decrements the ref cnt */

          fd_memset( info, 0, sizeof(fd_shmem_join_info_t) );
          FD_TEST( !fd_shmem_join_query_by_name( name, NULL ) );
          FD_TEST( !fd_shmem_join_query_by_name( name, info ) );
          FD_TEST( !memcmp( info, ref, sizeof(fd_shmem_join_info_t) ) );

          fd_memset( info, 0, sizeof(fd_shmem_join_info_t) );
          FD_TEST( !fd_shmem_join_query_by_join( join, NULL ) );
          FD_TEST( !fd_shmem_join_query_by_join( join, info ) );
          FD_TEST( !memcmp( info, ref, sizeof(fd_shmem_join_info_t) ) );

          fd_memset( info, 0, sizeof(fd_shmem_join_info_t) );
          FD_TEST( !fd_shmem_join_query_by_addr( ((uchar *)shmem) + off, 1UL, NULL ) );
          FD_TEST( !fd_shmem_join_query_by_addr( ((uchar *)shmem) + off, 1UL, info ) );
          FD_TEST( !memcmp( info, ref, sizeof(fd_shmem_join_info_t) ) );

        }
      }
    }
  }

  /* FIXME: DO MORE EXTENSIVE TESTS OF ACQUIRE / RELEASE */

  ulong test_cnt = 3UL;
  static ulong const test_psz [3] = { FD_SHMEM_NORMAL_PAGE_SZ, FD_SHMEM_HUGE_PAGE_SZ, FD_SHMEM_GIGANTIC_PAGE_SZ };
  static ulong const test_pcnt[3] = { 3UL,                     2UL,                   1UL                       };
  static ulong const test_cpu [3] = { 0UL,                     0UL,                   0UL                       };
  for( ulong test_idx=0UL; test_idx<test_cnt; test_idx++ ) {
    ulong psz  = test_psz [ test_idx ];
    ulong pcnt = test_pcnt[ test_idx ];
    ulong cpu  = test_cpu [ test_idx ];

    void * page = fd_shmem_acquire( psz, pcnt, cpu );
    FD_TEST( page );
    FD_TEST( fd_ulong_is_aligned( (ulong)page, psz ) );
    FD_TEST( !fd_shmem_numa_validate( page, psz, pcnt, cpu ) );

    void * join = (void *)((ulong)page + (fd_rng_ulong( rng ) & (psz-1UL)));
    char * name = "test";
    int    mode = fd_rng_int( rng ) & 1;

    fd_shmem_join_info_t ref[1];
    memset( ref, 0, sizeof(fd_shmem_join_info_t) );
    ref->ref_cnt  = 1L;
    ref->join     = join;
    ref->shmem    = page;
    ref->page_sz  = psz;
    ref->page_cnt = pcnt;
    ref->mode     = mode;
    strcpy( ref->name, name );
    ref->hash     = (uint)fd_hash( 0UL, ref->name, FD_SHMEM_NAME_MAX );

    fd_shmem_join_info_t nop[1];
    fd_shmem_join_info_t info[1];

    memset( nop, fd_rng_int( rng ), sizeof(fd_shmem_join_info_t) ); *info = *nop;
    FD_TEST(  fd_shmem_join_query_by_name( name,      NULL ) ); FD_TEST( !memcmp( info, nop, sizeof(fd_shmem_join_info_t) ) );
    FD_TEST(  fd_shmem_join_query_by_name( name,      info ) ); FD_TEST( !memcmp( info, nop, sizeof(fd_shmem_join_info_t) ) );
    memset( nop, fd_rng_int( rng ), sizeof(fd_shmem_join_info_t) ); *info = *nop;
    FD_TEST(  fd_shmem_join_query_by_join( join,      NULL ) ); FD_TEST( !memcmp( info, nop, sizeof(fd_shmem_join_info_t) ) );
    FD_TEST(  fd_shmem_join_query_by_join( join,      info ) ); FD_TEST( !memcmp( info, nop, sizeof(fd_shmem_join_info_t) ) );
    memset( nop, fd_rng_int( rng ), sizeof(fd_shmem_join_info_t) ); *info = *nop;
    FD_TEST(  fd_shmem_join_query_by_addr( page, 1UL, NULL ) ); FD_TEST( !memcmp( info, nop, sizeof(fd_shmem_join_info_t) ) );
    FD_TEST(  fd_shmem_join_query_by_addr( page, 1UL, info ) ); FD_TEST( !memcmp( info, nop, sizeof(fd_shmem_join_info_t) ) );

    FD_TEST( !fd_shmem_join_anonymous( name, mode, join, page, psz, pcnt ) );

    memset( nop, fd_rng_int( rng ), sizeof(fd_shmem_join_info_t) ); *info = *nop;
    FD_TEST( !fd_shmem_join_query_by_name( name,      NULL ) ); FD_TEST( !memcmp( info, nop, sizeof(fd_shmem_join_info_t) ) );
    FD_TEST( !fd_shmem_join_query_by_name( name,      info ) ); FD_TEST( !memcmp( info, ref, sizeof(fd_shmem_join_info_t) ) );
    memset( nop, fd_rng_int( rng ), sizeof(fd_shmem_join_info_t) ); *info = *nop;
    FD_TEST( !fd_shmem_join_query_by_join( join,      NULL ) ); FD_TEST( !memcmp( info, nop, sizeof(fd_shmem_join_info_t) ) );
    FD_TEST( !fd_shmem_join_query_by_join( join,      info ) ); FD_TEST( !memcmp( info, ref, sizeof(fd_shmem_join_info_t) ) );
    memset( nop, fd_rng_int( rng ), sizeof(fd_shmem_join_info_t) ); *info = *nop;
    FD_TEST( !fd_shmem_join_query_by_addr( page, 1UL, NULL ) ); FD_TEST( !memcmp( info, nop, sizeof(fd_shmem_join_info_t) ) );
    FD_TEST( !fd_shmem_join_query_by_addr( page, 1UL, info ) ); FD_TEST( !memcmp( info, ref, sizeof(fd_shmem_join_info_t) ) );

    memset( nop, fd_rng_int( rng ), sizeof(fd_shmem_join_info_t) ); *info = *nop;
    FD_TEST( fd_shmem_join( name, fd_rng_int( rng ) & 1, NULL, NULL, info )==join ); ref->ref_cnt++;
    FD_TEST( !memcmp( info, ref, sizeof(fd_shmem_join_info_t) ) );

    memset( nop, fd_rng_int( rng ), sizeof(fd_shmem_join_info_t) ); *info = *nop;
    FD_TEST( fd_shmem_join( name, fd_rng_int( rng ) & 1, NULL, NULL, info )==join ); ref->ref_cnt++;
    FD_TEST( !memcmp( info, ref, sizeof(fd_shmem_join_info_t) ) );

    memset( nop, fd_rng_int( rng ), sizeof(fd_shmem_join_info_t) ); *info = *nop;
    FD_TEST( !fd_shmem_join_query_by_name( name,      NULL ) ); FD_TEST( !memcmp( info, nop, sizeof(fd_shmem_join_info_t) ) );
    FD_TEST( !fd_shmem_join_query_by_name( name,      info ) ); FD_TEST( !memcmp( info, ref, sizeof(fd_shmem_join_info_t) ) );
    memset( nop, fd_rng_int( rng ), sizeof(fd_shmem_join_info_t) ); *info = *nop;
    FD_TEST( !fd_shmem_join_query_by_join( join,      NULL ) ); FD_TEST( !memcmp( info, nop, sizeof(fd_shmem_join_info_t) ) );
    FD_TEST( !fd_shmem_join_query_by_join( join,      info ) ); FD_TEST( !memcmp( info, ref, sizeof(fd_shmem_join_info_t) ) );
    memset( nop, fd_rng_int( rng ), sizeof(fd_shmem_join_info_t) ); *info = *nop;
    FD_TEST( !fd_shmem_join_query_by_addr( page, 1UL, NULL ) ); FD_TEST( !memcmp( info, nop, sizeof(fd_shmem_join_info_t) ) );
    FD_TEST( !fd_shmem_join_query_by_addr( page, 1UL, info ) ); FD_TEST( !memcmp( info, ref, sizeof(fd_shmem_join_info_t) ) );

    fd_shmem_leave( join, NULL, NULL ); ref->ref_cnt--;
    fd_shmem_leave( join, NULL, NULL ); ref->ref_cnt--;

    memset( nop, fd_rng_int( rng ), sizeof(fd_shmem_join_info_t) ); *info = *nop;
    FD_TEST( !fd_shmem_join_query_by_name( name,      NULL ) ); FD_TEST( !memcmp( info, nop, sizeof(fd_shmem_join_info_t) ) );
    FD_TEST( !fd_shmem_join_query_by_name( name,      info ) ); FD_TEST( !memcmp( info, ref, sizeof(fd_shmem_join_info_t) ) );
    memset( nop, fd_rng_int( rng ), sizeof(fd_shmem_join_info_t) ); *info = *nop;
    FD_TEST( !fd_shmem_join_query_by_join( join,      NULL ) ); FD_TEST( !memcmp( info, nop, sizeof(fd_shmem_join_info_t) ) );
    FD_TEST( !fd_shmem_join_query_by_join( join,      info ) ); FD_TEST( !memcmp( info, ref, sizeof(fd_shmem_join_info_t) ) );
    memset( nop, fd_rng_int( rng ), sizeof(fd_shmem_join_info_t) ); *info = *nop;
    FD_TEST( !fd_shmem_join_query_by_addr( page, 1UL, NULL ) ); FD_TEST( !memcmp( info, nop, sizeof(fd_shmem_join_info_t) ) );
    FD_TEST( !fd_shmem_join_query_by_addr( page, 1UL, info ) ); FD_TEST( !memcmp( info, ref, sizeof(fd_shmem_join_info_t) ) );

    FD_TEST( !fd_shmem_leave_anonymous( join, NULL ) ); ref->ref_cnt--;

    memset( nop, fd_rng_int( rng ), sizeof(fd_shmem_join_info_t) ); *info = *nop;
    FD_TEST(  fd_shmem_join_query_by_name( name,      NULL ) ); FD_TEST( !memcmp( info, nop, sizeof(fd_shmem_join_info_t) ) );
    FD_TEST(  fd_shmem_join_query_by_name( name,      info ) ); FD_TEST( !memcmp( info, nop, sizeof(fd_shmem_join_info_t) ) );
    memset( nop, fd_rng_int( rng ), sizeof(fd_shmem_join_info_t) ); *info = *nop;
    FD_TEST(  fd_shmem_join_query_by_join( join,      NULL ) ); FD_TEST( !memcmp( info, nop, sizeof(fd_shmem_join_info_t) ) );
    FD_TEST(  fd_shmem_join_query_by_join( join,      info ) ); FD_TEST( !memcmp( info, nop, sizeof(fd_shmem_join_info_t) ) );
    memset( nop, fd_rng_int( rng ), sizeof(fd_shmem_join_info_t) ); *info = *nop;
    FD_TEST(  fd_shmem_join_query_by_addr( page, 1UL, NULL ) ); FD_TEST( !memcmp( info, nop, sizeof(fd_shmem_join_info_t) ) );
    FD_TEST(  fd_shmem_join_query_by_addr( page, 1UL, info ) ); FD_TEST( !memcmp( info, nop, sizeof(fd_shmem_join_info_t) ) );

    fd_shmem_release( page, psz, pcnt );
  }

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_HOSTED capabilities" ));
  fd_halt();
  return 0;
}

#endif

