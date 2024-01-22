#include "../fd_util.h"

FD_STATIC_ASSERT( FD_WKSP_CSTR_MAX==61UL, unit_test );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * name     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--name",      NULL,   "helper_test" );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL,      "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL,             1UL );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );
  char const * _mode    = fd_env_strip_cmdline_cstr ( &argc, &argv, "--mode",      NULL,          "0600" );
  uint         seed     = fd_env_strip_cmdline_uint ( &argc, &argv, "--near-cpu",  NULL,           1234U );
  ulong        part_max = fd_env_strip_cmdline_uint ( &argc, &argv, "--near-cpu",  NULL,             0UL );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  ulong mode    = fd_cstr_to_ulong_octal  ( _mode    );

  ulong zero = 0UL;
  ulong big  = ULONG_MAX;

  for( ulong iter=0UL; iter<2UL; iter++ ) {

    fd_wksp_t * wksp;

    if( iter==0UL ) { /* Do named test */

      FD_LOG_NOTICE(( "Testing named --name %s --page-sz %s (%lu) --page-cnt %lu --near-cpu %lu --mode %s (0%lo) --seed %u --part-max %lu",
                      name, _page_sz, page_sz, page_cnt, near_cpu, _mode, mode, seed, part_max ));

      /* Test fd_wksp_new_named */

      FD_TEST( fd_wksp_new_named( NULL, page_sz, 1UL, &page_cnt, &near_cpu, mode,      seed, part_max  )==FD_WKSP_ERR_INVAL );
      FD_TEST( fd_wksp_new_named( name,     0UL, 1UL, &page_cnt, &near_cpu, mode,      seed, part_max  )==FD_WKSP_ERR_INVAL );
      FD_TEST( fd_wksp_new_named( name, page_sz, 0UL, &page_cnt, &near_cpu, mode,      seed, part_max  )==FD_WKSP_ERR_INVAL );
      FD_TEST( fd_wksp_new_named( name, page_sz, 1UL, NULL,      &near_cpu, mode,      seed, part_max  )==FD_WKSP_ERR_INVAL );
      FD_TEST( fd_wksp_new_named( name, page_sz, 1UL, &zero,     &near_cpu, mode,      seed, part_max  )==FD_WKSP_ERR_INVAL );
      FD_TEST( fd_wksp_new_named( name, page_sz, 1UL, &big,      &near_cpu, mode,      seed, part_max  )==FD_WKSP_ERR_INVAL );
      FD_TEST( fd_wksp_new_named( name, page_sz, 1UL, &page_cnt, NULL,      mode,      seed, part_max  )==FD_WKSP_ERR_INVAL );
      FD_TEST( fd_wksp_new_named( name, page_sz, 1UL, &page_cnt, &big,      mode,      seed, part_max  )==FD_WKSP_ERR_FAIL  );
      FD_TEST( fd_wksp_new_named( name, page_sz, 1UL, &page_cnt, &near_cpu, ULONG_MAX, seed, part_max  )==FD_WKSP_ERR_FAIL  );
      /* seed arb */
      FD_TEST( fd_wksp_new_named( name, page_sz, 1UL, &page_cnt, &near_cpu, mode,      seed, ULONG_MAX )==FD_WKSP_ERR_INVAL );

      FD_TEST( !fd_wksp_new_named( name, page_sz, 1UL, &page_cnt, &near_cpu, mode, seed, part_max ) );

      /* Test fd_wksp_attach */

      FD_TEST( !fd_wksp_attach( NULL ) );
      wksp = fd_wksp_attach( name ); FD_TEST( wksp );

    } else {

      FD_LOG_NOTICE(( "Testing anon --name %s --page-sz %s (%lu) --page-cnt %lu --near-cpu %lu --seed %u --part-max %lu",
                      name, _page_sz, page_sz, page_cnt, near_cpu, seed, part_max ));

      /* Test fd_wksp_new_anon */

      FD_TEST( !fd_wksp_new_anon( NULL, page_sz, 1UL, &page_cnt, &near_cpu, seed, part_max  ) );
      FD_TEST( !fd_wksp_new_anon( name,     0UL, 1UL, &page_cnt, &near_cpu, seed, part_max  ) );
      FD_TEST( !fd_wksp_new_anon( name, page_sz, 0UL, &page_cnt, &near_cpu, seed, part_max  ) );
      FD_TEST( !fd_wksp_new_anon( name, page_sz, 1UL, NULL,      &near_cpu, seed, part_max  ) );
      FD_TEST( !fd_wksp_new_anon( name, page_sz, 1UL, &zero,     &near_cpu, seed, part_max  ) );
      FD_TEST( !fd_wksp_new_anon( name, page_sz, 1UL, &big,      &near_cpu, seed, part_max  ) );
      FD_TEST( !fd_wksp_new_anon( name, page_sz, 1UL, &page_cnt, NULL,      seed, part_max  ) );
      FD_TEST( !fd_wksp_new_anon( name, page_sz, 1UL, &page_cnt, &big,      seed, part_max  ) );
      /* seed arb */
      FD_TEST( !fd_wksp_new_anon( name, page_sz, 1UL, &page_cnt, &near_cpu, seed, ULONG_MAX ) );

      wksp = fd_wksp_new_anon( name, page_sz, 1UL, &page_cnt, &near_cpu, seed, part_max ); FD_TEST( wksp );

      /* Test fd_wksp_attach */

      FD_TEST( fd_wksp_attach( name )==wksp );
      fd_wksp_detach( wksp );

    }

    /* Test fd_wksp_alloc_laddr */

    FD_TEST( !fd_wksp_alloc_laddr( NULL, 1UL, 1UL, 12UL ) );
    FD_TEST( !fd_wksp_alloc_laddr( wksp, 3UL, 1UL, 12UL ) );
    FD_TEST( !fd_wksp_alloc_laddr( wksp, 1UL, 0UL, 12UL ) );
    FD_TEST( !fd_wksp_alloc_laddr( wksp, 1UL, 1UL,  0UL ) );

    void * laddr = fd_wksp_alloc_laddr( wksp, 1UL, 1UL, 12UL ); FD_TEST( laddr );
    ulong  gaddr = fd_wksp_gaddr_fast( wksp, laddr );
    FD_TEST( fd_wksp_tag( wksp, gaddr )==12UL );

    /* Test fd_wksp_containing */

    FD_TEST( !fd_wksp_containing( NULL        )       );
    FD_TEST( !fd_wksp_containing( (void *)1UL )       );
    FD_TEST(  fd_wksp_containing( laddr       )==wksp );

    char cstr1[ FD_WKSP_CSTR_MAX ];
    char cstr2[ FD_WKSP_CSTR_MAX ];

    /* Test fd_wksp_cstr_alloc */

    FD_TEST( !fd_wksp_cstr_alloc( NULL, 1UL, 1UL,       23UL, cstr1 )        );
    FD_TEST( !fd_wksp_cstr_alloc( name, 3UL, 1UL,       23UL, cstr1 )        );
    FD_TEST(  fd_wksp_cstr_alloc( name, 1UL, 0UL,       23UL, cstr1 )==cstr1 ); /* name:0 */
    FD_TEST( !fd_wksp_cstr_alloc( name, 1UL, ULONG_MAX, 23UL, cstr1 )        );
    FD_TEST( !fd_wksp_cstr_alloc( name, 1UL, 1UL,        0UL, cstr1 )        );
    FD_TEST(  fd_wksp_cstr_alloc( name, 1UL, 1UL,       23UL, cstr1 )==cstr1 );

    /* Test fd_wksp_cstr_tag */

    FD_TEST( fd_wksp_cstr_tag( NULL  )== 0UL );
    FD_TEST( fd_wksp_cstr_tag( cstr1 )==23UL );

    /* Test fd_wksp_cstr_memset */

    fd_wksp_cstr_memset( NULL,  123 );
    fd_wksp_cstr_memset( cstr1, 123 );

    /* Test fd_wksp_map */

    FD_TEST( !fd_wksp_map( NULL ) );
    uchar * laddr1 = fd_wksp_map( cstr1 ); FD_TEST( laddr1 );
    ulong   gaddr1 = fd_wksp_gaddr_fast( wksp, laddr1 );
    FD_TEST( laddr1!=laddr );
    FD_TEST( *laddr1==(uchar)123 );
    FD_TEST( fd_wksp_tag( wksp, gaddr1 )==23UL );

    /* Test fd_wksp_cstr */

    cstr2[0] = '\0'; FD_TEST( !fd_wksp_cstr( NULL, gaddr1, cstr2 )        );
    cstr2[0] = '\0'; FD_TEST(  fd_wksp_cstr( wksp, 0UL,    cstr2 )==cstr2 ); /* name:0 */
    cstr2[0] = '\0'; FD_TEST( !fd_wksp_cstr( wksp, 1UL,    cstr2 )        );
    cstr2[0] = '\0'; FD_TEST( !fd_wksp_cstr( wksp, gaddr1, NULL  )        );
    cstr2[0] = '\0'; FD_TEST(  fd_wksp_cstr( wksp, gaddr1, cstr2 )==cstr2 );
    FD_TEST( !strcmp( cstr1, cstr2 ) );

    /* Test fd_wksp_cstr_laddr */

    cstr2[0] = '\0'; FD_TEST( !fd_wksp_cstr_laddr( NULL,        cstr2 )        );
    cstr2[0] = '\0'; FD_TEST( !fd_wksp_cstr_laddr( (void *)1UL, cstr2 )        );
    cstr2[0] = '\0'; FD_TEST( !fd_wksp_cstr_laddr( laddr1,      NULL  )        );
    cstr2[0] = '\0'; FD_TEST(  fd_wksp_cstr_laddr( laddr1,      cstr2 )==cstr2 );
    FD_TEST( !strcmp( cstr1, cstr2 ) );
 
    /* Test fd_wksp_unmap */

    fd_wksp_unmap( NULL   );
    fd_wksp_unmap( laddr1 );

    /* Test fd_wksp_free */

    fd_wksp_cstr_free( NULL  );
    fd_wksp_cstr_free( cstr1 );
    fd_wksp_cstr_free( cstr1 );
  
    FD_TEST( fd_wksp_cstr_tag( cstr1 )==0UL );
    fd_wksp_cstr_memset( NULL, 255 );

    /* Test fd_wksp_free_laddr */

    fd_wksp_free_laddr( NULL        );
    fd_wksp_free_laddr( (void *)1UL );
    fd_wksp_free_laddr( laddr       );
    fd_wksp_free_laddr( laddr       );

    if( iter==0 ) { /* Test fd_wksp_delete_named */

      /* Test fd_wksp_detach */

      fd_wksp_detach( NULL );
      fd_wksp_detach( wksp );
      fd_wksp_detach( wksp );

      FD_TEST(  fd_wksp_delete_named( NULL )==FD_WKSP_ERR_FAIL );
      FD_TEST( !fd_wksp_delete_named( name )                   );
      FD_TEST(  fd_wksp_delete_named( name )==FD_WKSP_ERR_FAIL );

    } else { /* Test fd_wksp_delete_anon */

      fd_wksp_delete_anon( NULL );
      fd_wksp_delete_anon( wksp );
      fd_wksp_delete_anon( wksp );

    }

    /* Misc edge cases */

    FD_TEST( !fd_wksp_attach    ( name  ) );
    FD_TEST( !fd_wksp_containing( laddr ) );
    fd_wksp_free_laddr( laddr );
  }

  /* TODO: Test pod helpers */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

