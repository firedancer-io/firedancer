#include "fd_funkier.h"

#if FD_HAS_HOSTED

FD_STATIC_ASSERT( FD_FUNKIER_ALIGN    ==4096UL,                unit-test );

FD_STATIC_ASSERT( FD_FUNKIER_ALIGN    >=alignof(fd_funkier_t), unit-test );

FD_STATIC_ASSERT( FD_FUNKIER_MAGIC    ==0xf17eda2ce7fc2c02UL,  unit-test );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * name     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL,            NULL );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL,      "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL,             1UL );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );
  ulong        wksp_tag = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-tag",  NULL,          1234UL );
  ulong        seed     = fd_env_strip_cmdline_ulong( &argc, &argv, "--seed",      NULL,          5678UL );
  ulong        txn_max  = fd_env_strip_cmdline_ulong( &argc, &argv, "--txn-max",   NULL,        262144UL );
  ulong        rec_max  = fd_env_strip_cmdline_ulong( &argc, &argv, "--rec-max",   NULL,        262144UL );

  fd_wksp_t * wksp;
  if( name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", name ));
    wksp = fd_wksp_attach( name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }

  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "Unable to attach to wksp" ));

  FD_LOG_NOTICE(( "Testing with --wksp-tag %lu --seed %lu --txn-max %lu --rec-max %lu", wksp_tag, seed, txn_max, rec_max ));

  ulong align     = fd_funkier_align();     FD_TEST( align    ==FD_FUNKIER_ALIGN     );
  ulong footprint = fd_funkier_footprint(txn_max, rec_max);
  FD_TEST( fd_ulong_is_pow2( align ) && footprint && fd_ulong_is_aligned( footprint, align ) );

  void * shmem = fd_wksp_alloc_laddr( wksp, align, footprint, wksp_tag );
  if( FD_UNLIKELY( !shmem ) ) FD_LOG_ERR(( "Unable to allocate shmem" ));

#ifdef FD_FUNKIER_HANDHOLDING
  FD_TEST( !fd_funkier_new( NULL,          wksp_tag, seed, txn_max, rec_max ) ); /* NULL shmem */
  FD_TEST( !fd_funkier_new( (void *)1UL,   wksp_tag, seed, txn_max, rec_max ) ); /* misaligned shmem */
  FD_TEST( !fd_funkier_new( (void *)align, wksp_tag, seed, txn_max, rec_max ) ); /* not a wksp addr */
  FD_TEST( !fd_funkier_new( shmem,         0UL,      seed, txn_max, rec_max ) ); /* bad tag */
  /* seed is arbitrary */
  FD_TEST( !fd_funkier_new( shmem,         wksp_tag, seed, FD_FUNKIER_TXN_IDX_NULL+1UL,             rec_max ) ); /* idx compr limited */
#endif
  void * shfunk = fd_funkier_new( shmem, wksp_tag, seed, txn_max, rec_max ); FD_TEST( shfunk==shmem );

#ifdef FD_FUNKIER_HANDHOLDING
  FD_TEST( !fd_funkier_join( NULL          ) ); /* NULL shmem */
  FD_TEST( !fd_funkier_join( (void *)1UL   ) ); /* misaligned shmem */
  FD_TEST( !fd_funkier_join( (void *)align ) ); /* not a wksp addr */
#endif
  fd_funkier_t * funk = fd_funkier_join( shfunk ); FD_TEST( funk );

  FD_TEST( fd_funkier_wksp    ( funk )==wksp     );
  FD_TEST( fd_funkier_wksp_tag( funk )==wksp_tag );
  FD_TEST( fd_funkier_seed    ( funk )==seed     );

  FD_TEST( fd_funkier_txn_max( funk )==txn_max );

  fd_funkier_txn_xid_t const * root = fd_funkier_root( funk );
  FD_TEST( root );
  FD_TEST( fd_funkier_txn_xid_eq_root( root ) );

  fd_funkier_txn_xid_t const * last_publish = fd_funkier_last_publish( funk );
  FD_TEST( last_publish );
  FD_TEST( fd_funkier_txn_xid_eq_root( last_publish ) );

  FD_TEST( !fd_funkier_last_publish_is_frozen ( funk          ) );

#ifdef FD_FUNKIER_HANDHOLDING
  FD_TEST( !fd_funkier_verify( funk ) );
#endif

#ifdef FD_FUNKIER_HANDHOLDING
  FD_TEST( !fd_funkier_leave( NULL )         ); /* Not a join */
#endif
  FD_TEST(  fd_funkier_leave( funk )==shfunk );

#ifdef FD_FUNKIER_HANDHOLDING
  FD_TEST( !fd_funkier_delete( NULL          )        ); /* NULL shmem */
  FD_TEST( !fd_funkier_delete( (void *)1UL   )        ); /* misaligned shmem */
  FD_TEST( !fd_funkier_delete( (void *)align )        ); /* not wksp addr */
#endif
  FD_TEST(  fd_funkier_delete( shfunk        )==shmem ); /* NULL shmem */

#ifdef FD_FUNKIER_HANDHOLDING
  FD_TEST( !fd_funkier_join  ( shfunk        )        ); /* Can't join deleted */
  FD_TEST( !fd_funkier_delete( shfunk        )        ); /* Can't delete twice */
#endif

  /* Test combinations of txn_max==0 and rec_max==0 */

  funk = fd_funkier_join( fd_funkier_new( shmem, wksp_tag, seed, 0UL, rec_max ) ); FD_TEST( funk );
#ifdef FD_FUNKIER_HANDHOLDING
  FD_TEST( !fd_funkier_verify( funk ) );
#endif
  FD_TEST( fd_funkier_delete( fd_funkier_leave( funk ) ) );

  funk = fd_funkier_join( fd_funkier_new( shmem, wksp_tag, seed, txn_max, 0UL ) ); FD_TEST( funk );
#ifdef FD_FUNKIER_HANDHOLDING
  FD_TEST( !fd_funkier_verify( funk ) );
#endif
  FD_TEST( fd_funkier_delete( fd_funkier_leave( funk ) ) );

  funk = fd_funkier_join( fd_funkier_new( shmem, wksp_tag, seed, 0UL, 0UL ) ); FD_TEST( funk );
#ifdef FD_FUNKIER_HANDHOLDING
  FD_TEST( !fd_funkier_verify( funk ) );
#endif
  FD_TEST( fd_funkier_delete( fd_funkier_leave( funk ) ) );

  fd_wksp_free_laddr( shmem );
  if( name ) fd_wksp_detach( wksp );
  else       fd_wksp_delete_anonymous( wksp );

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
