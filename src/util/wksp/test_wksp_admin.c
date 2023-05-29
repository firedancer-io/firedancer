#include "../fd_util.h"

/* TODO: additional fd_wksp_footprint, part_max_est, data_max_est tests */

FD_STATIC_ASSERT( FD_WKSP_SUCCESS    == 0, unit_test );
FD_STATIC_ASSERT( FD_WKSP_ERR_INVAL  ==-1, unit_test );
FD_STATIC_ASSERT( FD_WKSP_ERR_FAIL   ==-2, unit_test );
FD_STATIC_ASSERT( FD_WKSP_ERR_CORRUPT==-3, unit_test );

FD_STATIC_ASSERT( FD_WKSP_ALIGN==128UL, unit_test );

#define SCRATCH_MAX (16384UL)
uchar scratch[ SCRATCH_MAX ] __attribute__((aligned((FD_WKSP_ALIGN))));

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong        scratch_sz = fd_env_strip_cmdline_ulong( &argc, &argv, "--scratch-sz", "", SCRATCH_MAX );
  char const * name       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--name",       "", "test"      );
  uint         seed       = fd_env_strip_cmdline_uint ( &argc, &argv, "--seed",       "", 1234U       );
  ulong        part_max   = fd_env_strip_cmdline_ulong( &argc, &argv, "--part-max",   "", 64UL        );
  ulong        data_max   = fd_env_strip_cmdline_ulong( &argc, &argv, "--data-max",   "", 8192UL      );

  if( FD_UNLIKELY( scratch_sz>SCRATCH_MAX ) ) FD_LOG_ERR(( "Increase SCRATCH_MAX for this --scratch-sz" ));

  FD_LOG_NOTICE(( "Testing with --scratch-sz %lu --name %s --seed %u --part-max %lu --data-max %lu",
                  scratch_sz, name, seed, part_max, data_max ));

  /* Test part_max_est */

  FD_TEST( !fd_wksp_part_max_est( 0UL,        64UL      )                ); /* Too small footprint */
  FD_TEST( !fd_wksp_part_max_est( scratch_sz, 0L        )                ); /* Too small size typical */
  FD_TEST( !fd_wksp_part_max_est( scratch_sz, ULONG_MAX )                ); /* Too large size typical */
  FD_TEST(  fd_wksp_part_max_est( ULONG_MAX,  64UL      )==(1UL<<32)-1UL ); /* Index comp limited */

  /* Test data_max_est */

  FD_TEST( !fd_wksp_data_max_est( 0UL,        part_max      ) ); /* Too small footprint for meta */
  FD_TEST( !fd_wksp_data_max_est( scratch_sz, 0L            ) ); /* Too small part_max */
  FD_TEST( !fd_wksp_data_max_est( scratch_sz, (1UL<<32)-1UL ) ); /* Too small footprint for part_max */
  FD_TEST( !fd_wksp_data_max_est( ULONG_MAX,  (1UL<<32)     ) ); /* Too large part_max */
  FD_TEST(  fd_wksp_data_max_est( ULONG_MAX,  (1UL<<32)-1UL ) ); /* Largest possible footprint with largest part_max */

  /* Test align */

  ulong align = fd_wksp_align();
  FD_TEST( fd_ulong_is_pow2( align ) );
  FD_TEST( FD_WKSP_ALIGN==align );

  /* Test footprint */

  FD_TEST( !fd_wksp_footprint( 0UL,      data_max  ) ); /* Too small part_max */
  FD_TEST( !fd_wksp_footprint( 1UL<<32,  data_max  ) ); /* Too large part_max */
  FD_TEST( !fd_wksp_footprint( part_max, 0UL       ) ); /* Too small data_max */
  FD_TEST( !fd_wksp_footprint( part_max, ULONG_MAX ) ); /* Too large data_max */

  ulong footprint = fd_wksp_footprint( part_max, data_max );
  FD_TEST( footprint );
  FD_TEST( fd_ulong_is_aligned( footprint, FD_WKSP_ALIGN ) );
  FD_TEST( FD_WKSP_FOOTPRINT( part_max, data_max )==footprint );

  /* Test new */

  FD_TEST( !fd_wksp_new( NULL,        name, seed, part_max, data_max  ) ); /* NULL wksp */
  FD_TEST( !fd_wksp_new( scratch+1UL, name, seed, part_max, data_max  ) ); /* bad align */
  FD_TEST( !fd_wksp_new( scratch,     NULL, seed, part_max, data_max  ) ); /* Bad name (usual shmem name rules apply) */
  /* seed is arbitrary */
  FD_TEST( !fd_wksp_new( scratch,     name, seed, 0UL,      data_max  ) ); /* Too small part_max */
  FD_TEST( !fd_wksp_new( scratch,     name, seed, 1UL<<32,  data_max  ) ); /* Too large part_max */
  FD_TEST( !fd_wksp_new( scratch,     name, seed, part_max, 0UL       ) ); /* Too small data_max */
  FD_TEST( !fd_wksp_new( scratch,     name, seed, part_max, ULONG_MAX ) ); /* Too large data_max */

  void * shwksp = fd_wksp_new( scratch, name, seed, part_max, data_max ); FD_TEST( shwksp );

  /* Test join */

  FD_TEST( !fd_wksp_join( NULL        ) );
  FD_TEST( !fd_wksp_join( scratch+1UL ) );

  fd_wksp_t * wksp = fd_wksp_join( shwksp ); FD_TEST( wksp );

  /* Test accessors */

  FD_TEST( !strcmp( fd_wksp_name( wksp ), name ) );

  FD_TEST( fd_wksp_seed    ( wksp )==seed        );
  FD_TEST( fd_wksp_part_max( wksp )==part_max    );
  FD_TEST( fd_wksp_data_max( wksp )==data_max    );

  /* Note that rebuild and verify are tested in user aggressively */

  /* Test leave */

  FD_TEST( !fd_wksp_leave( NULL )         );
  FD_TEST(  fd_wksp_leave( wksp )==shwksp );

  /* Test delete */
  
  FD_TEST( !fd_wksp_delete( NULL        )     );
  FD_TEST( !fd_wksp_delete( scratch+1UL )     );
  FD_TEST(  fd_wksp_delete( shwksp )==scratch );

  /* Test post-delete join / double-delete */

  FD_TEST( !fd_wksp_join  ( shwksp ) );
  FD_TEST( !fd_wksp_delete( shwksp ) );

  /* Test strerror */

  FD_TEST( !strcmp( fd_wksp_strerror( FD_WKSP_SUCCESS     ), "success" ) );
  FD_TEST( !strcmp( fd_wksp_strerror( FD_WKSP_ERR_INVAL   ), "inval"   ) );
  FD_TEST( !strcmp( fd_wksp_strerror( FD_WKSP_ERR_FAIL    ), "fail"    ) );
  FD_TEST( !strcmp( fd_wksp_strerror( FD_WKSP_ERR_CORRUPT ), "corrupt" ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

