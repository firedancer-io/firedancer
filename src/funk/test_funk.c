#include "fd_funk.h"

#if FD_HAS_HOSTED

FD_STATIC_ASSERT( FD_FUNK_ALIGN    ==4096UL,                unit-test );

FD_STATIC_ASSERT( FD_FUNK_ALIGN    >=alignof(fd_funk_t), unit-test );

FD_STATIC_ASSERT( FD_FUNK_MAGIC    ==0xf17eda2ce7fc2c02UL,  unit-test );

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
  uint         rec_max  = fd_env_strip_cmdline_uint(  &argc, &argv, "--rec-max",   NULL,          262144 );

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

  FD_LOG_NOTICE(( "Testing with --wksp-tag %lu --seed %lu --txn-max %lu --rec-max %u", wksp_tag, seed, txn_max, rec_max ));

  ulong align     = fd_funk_align();     FD_TEST( align    ==FD_FUNK_ALIGN     );
  ulong footprint = fd_funk_footprint(txn_max, rec_max);
  FD_TEST( fd_ulong_is_pow2( align ) && footprint && fd_ulong_is_aligned( footprint, align ) );

  void * shmem = fd_wksp_alloc_laddr( wksp, align, footprint, wksp_tag );
  if( FD_UNLIKELY( !shmem ) ) FD_LOG_ERR(( "Unable to allocate shmem" ));

  FD_TEST( !fd_funk_new( NULL,          wksp_tag, seed, txn_max, rec_max ) ); /* NULL shmem */
  FD_TEST( !fd_funk_new( (void *)1UL,   wksp_tag, seed, txn_max, rec_max ) ); /* misaligned shmem */
  FD_TEST( !fd_funk_new( (void *)align, wksp_tag, seed, txn_max, rec_max ) ); /* not a wksp addr */
  FD_TEST( !fd_funk_new( shmem,         0UL,      seed, txn_max, rec_max ) ); /* bad tag */
  /* seed is arbitrary */
  FD_TEST( !fd_funk_new( shmem,         wksp_tag, seed, FD_FUNK_TXN_IDX_NULL+1UL,             rec_max ) ); /* idx compr limited */
  void * shfunk = fd_funk_new( shmem, wksp_tag, seed, txn_max, rec_max ); FD_TEST( shfunk==shmem );

  fd_funk_t funk_[1];
  FD_TEST( !fd_funk_join( funk_, NULL          ) ); /* NULL shmem */
  FD_TEST( !fd_funk_join( funk_, (void *)1UL   ) ); /* misaligned shmem */
  FD_TEST( !fd_funk_join( funk_, (void *)align ) ); /* not a wksp addr */
  fd_funk_t * funk = fd_funk_join( funk_, shfunk ); FD_TEST( funk );

  FD_TEST( fd_funk_wksp    ( funk )==wksp     );
  FD_TEST( fd_funk_wksp_tag( funk )==wksp_tag );
  FD_TEST( fd_funk_seed    ( funk )==seed     );

  FD_TEST( fd_funk_txn_max( funk )==txn_max );

  fd_funk_txn_xid_t const * root = fd_funk_root( funk );
  FD_TEST( root );
  FD_TEST( fd_funk_txn_xid_eq_root( root ) );

  fd_funk_txn_xid_t const * last_publish = fd_funk_last_publish( funk );
  FD_TEST( last_publish );
  FD_TEST( fd_funk_txn_xid_eq_root( last_publish ) );

  FD_TEST( !fd_funk_last_publish_is_frozen ( funk          ) );

  FD_TEST( !fd_funk_verify( funk ) );

  FD_TEST( !fd_funk_leave( NULL, NULL )        ); /* Not a join */
  FD_TEST(  fd_funk_leave( funk, NULL )==funk_ );

  FD_TEST( !fd_funk_delete( NULL          )        ); /* NULL shmem */
  FD_TEST( !fd_funk_delete( (void *)1UL   )        ); /* misaligned shmem */
  FD_TEST( !fd_funk_delete( (uchar*)shfunk + align ) ); /* wrong pointer */
  FD_TEST( !fd_funk_delete( (void *)align )        ); /* not wksp addr */
  FD_TEST(  fd_funk_delete( shfunk        )==shmem ); /* NULL shmem */

  FD_TEST( !fd_funk_join  ( funk_, shfunk )        ); /* Can't join deleted */
  FD_TEST( !fd_funk_delete( shfunk        )        ); /* Can't delete twice */

  /* Test combinations of txn_max==0 and rec_max==0 */

  funk = fd_funk_join( funk_, fd_funk_new( shmem, wksp_tag, seed, 0UL, rec_max ) ); FD_TEST( funk );
  FD_TEST( !fd_funk_verify( funk ) );
  FD_TEST( fd_funk_leave( funk, NULL ) );
  FD_TEST( fd_funk_delete( shmem ) );

  funk = fd_funk_join( funk_, fd_funk_new( shmem, wksp_tag, seed, txn_max, 0UL ) ); FD_TEST( funk );
  FD_TEST( !fd_funk_verify( funk ) );
  FD_TEST( fd_funk_leave( funk, NULL ) );
  FD_TEST( fd_funk_delete( shmem ) );

  funk = fd_funk_join( funk_, fd_funk_new( shmem, wksp_tag, seed, 0UL, 0UL ) ); FD_TEST( funk );
  FD_TEST( !fd_funk_verify( funk ) );
  FD_TEST( fd_funk_leave( funk, NULL ) );
  FD_TEST( fd_funk_delete( shmem ) );

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
