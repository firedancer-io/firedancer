#include "fd_accdb_impl_v0.h"
#include "fd_accdb_ref.h"
#include "fd_accdb_sync.h"
#include <stdlib.h> /* aligned_alloc */

FD_FN_CONST static fd_pubkey_t
key( ulong i ) {
  fd_pubkey_t k = { .ul={
      i, fd_ulong_hash( i ), fd_ulong_hash( i+1 ), fd_ulong_hash( i+2 )
  } };
  return k;
}

static void
test_accdb_v0_logic( void ) {

  /* Construct db_v0 object */

  ulong const rec_max = 16UL;
  ulong db_fp = fd_accdb_v0_footprint( rec_max );
  FD_TEST( db_fp );
  void * db_mem;
  FD_TEST( (db_mem = aligned_alloc( fd_accdb_v0_align(), db_fp )) );
  fd_accdb_v0_t * db = fd_accdb_v0_join( fd_accdb_v0_new( db_mem, rec_max ) );
  FD_TEST( db );

  /* Create database handle */

  fd_accdb_user_t user_[1];
  fd_accdb_user_t * user = fd_accdb_user_v0_init( user_, db );
  fd_accdb_user_v0_t * user_v0 = fd_type_pun( user );

  /* Start test */

  fd_accdb_ro_t ro0[1];
  fd_accdb_rw_t rw0[1];

  /* Non-existent accounts */

  fd_pubkey_t const k0 = {0};
  FD_TEST( !fd_accdb_open_ro( user, ro0, NULL, &k0 ) );
  FD_TEST( !fd_accdb_open_rw( user, rw0, NULL, &k0, 0UL, 0 ) );
  fd_pubkey_t const k1 = key( 1UL );
  FD_TEST( !fd_accdb_open_ro( user, ro0, NULL, &k1 ) );
  FD_TEST( !fd_accdb_open_rw( user, rw0, NULL, &k1, 0UL, 0 ) );
  FD_TEST( user_v0->base.rw_active==0 );
  FD_TEST( user_v0->base.ro_active==0 );

  /* Create account */

  FD_TEST( fd_accdb_open_rw( user, rw0, NULL, &k0, 0UL, FD_ACCDB_FLAG_CREATE )==rw0 );
  FD_TEST( rw0->ref->accdb_type==FD_ACCDB_TYPE_V0 );
  FD_TEST( rw0->ref->user_data==0UL );
  FD_TEST( user_v0->base.rw_active==1 );
  fd_accdb_ref_lamports_set( rw0, 1UL );
  fd_accdb_close_rw( user, rw0 );
  FD_TEST( user_v0->base.rw_active==0 );

  FD_TEST( fd_accdb_open_ro( user, ro0, NULL, &k0 )==ro0 );
  FD_TEST( ro0->ref->accdb_type==FD_ACCDB_TYPE_V0 );
  FD_TEST( ro0->ref->user_data==0UL );
  FD_TEST( user_v0->base.ro_active==1 );
  FD_TEST( fd_pubkey_eq( fd_accdb_ref_address( ro0 ), &k0 ) );
  FD_TEST( fd_accdb_ref_data_sz ( ro0 )==0UL );
  FD_TEST( fd_accdb_ref_lamports( ro0 )==1UL );
  FD_TEST( fd_pubkey_eq( fd_accdb_ref_owner( ro0 ), &k0 ) );
  FD_TEST( fd_accdb_ref_exec_bit( ro0 )==0 );
  FD_TEST( fd_accdb_ref_slot( ro0 )==0UL );
  fd_accdb_close_ro( user, ro0 );
  FD_TEST( user_v0->base.ro_active==0 );

  FD_TEST( fd_accdb_open_rw( user, rw0, NULL, &k0, 0UL, 0 )==rw0 );
  fd_accdb_close_rw( user, rw0 );

  FD_TEST( !fd_accdb_open_ro( user, ro0, NULL, &k1 ) );
  FD_TEST( !fd_accdb_open_rw( user, rw0, NULL, &k1, 0UL, 0 ) );

  /* Account creation fail (no lamports added) */

  FD_TEST( fd_accdb_open_rw( user, rw0, NULL, &k1, 0UL, FD_ACCDB_FLAG_CREATE )==rw0 );
  FD_TEST( user_v0->base.rw_active==1 );
  fd_accdb_close_rw( user, rw0 );
  FD_TEST( user_v0->base.rw_active==0 );
  FD_TEST( !fd_accdb_open_rw( user, rw0, NULL, &k1, 0UL, 0 ) );
  FD_TEST( !fd_accdb_open_ro( user, ro0, NULL, &k1 ) );

  /* Delete account */

  FD_TEST( fd_accdb_open_rw( user, rw0, NULL, &k0, 0UL, 0 )==rw0 );
  FD_TEST( user_v0->base.rw_active==1 );
  fd_accdb_ref_lamports_set( rw0, 0UL );
  fd_accdb_close_rw( user, rw0 );
  FD_TEST( user_v0->base.rw_active==0 );
  FD_TEST( !fd_accdb_open_ro( user, ro0, NULL, &k0 ) );

  /* Clean up */

  fd_accdb_user_v0_fini( user );
  FD_TEST( fd_accdb_v0_delete( fd_accdb_v0_leave( db ) )==db_mem );
  free( db_mem );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_accdb_v0_logic();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
