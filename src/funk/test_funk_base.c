#include "fd_funk.h"

FD_STATIC_ASSERT( FD_FUNK_SUCCESS          == 0,                         unit_test );
FD_STATIC_ASSERT( FD_FUNK_ERR_INVAL        ==-1,                         unit_test );
FD_STATIC_ASSERT( FD_FUNK_ERR_KEY          ==-2,                         unit_test );
FD_STATIC_ASSERT( FD_FUNK_ERR_TXN          ==-3,                         unit_test );
FD_STATIC_ASSERT( FD_FUNK_ERR_MEM          ==-4,                         unit_test );
FD_STATIC_ASSERT( FD_FUNK_ERR_IO           ==-5,                         unit_test );

FD_STATIC_ASSERT( FD_FUNK_REC_KEY_ALIGN    ==32UL,                       unit_test );
FD_STATIC_ASSERT( FD_FUNK_REC_KEY_FOOTPRINT==64UL,                       unit_test );

FD_STATIC_ASSERT( FD_FUNK_REC_KEY_ALIGN    ==alignof(fd_funk_rec_key_t), unit_test );
FD_STATIC_ASSERT( FD_FUNK_REC_KEY_FOOTPRINT==sizeof (fd_funk_rec_key_t), unit_test );

FD_STATIC_ASSERT( FD_FUNK_REC_VAL_MAX      ==(10UL<<20),                 unit_test );

FD_STATIC_ASSERT( FD_FUNK_TXN_ID_ALIGN     ==32UL,                       unit_test );
FD_STATIC_ASSERT( FD_FUNK_TXN_ID_FOOTPRINT ==32UL,                       unit_test );

FD_STATIC_ASSERT( FD_FUNK_TXN_ID_ALIGN     ==alignof(fd_funk_txn_id_t),  unit_test );
FD_STATIC_ASSERT( FD_FUNK_TXN_ID_FOOTPRINT ==sizeof (fd_funk_txn_id_t),  unit_test );

static fd_funk_rec_key_t *
fd_funk_rec_key_set_unique( fd_funk_rec_key_t * key ) {
  static FD_TLS ulong tag = 0UL;
  key->ul[0] = fd_log_app_id();
  key->ul[1] = fd_log_thread_id();
  key->ul[2] = ++tag;
# if FD_HAS_X86
  key->ul[3] = (ulong)fd_tickcount();
# else
  key->ul[3] = 0UL;
# endif
  key->ul[4] = key->ul[0]; key->ul[5] = key->ul[1]; key->ul[6] = key->ul[2]; key->ul[7] = key->ul[3];
  return key;
}

static fd_funk_txn_id_t *
fd_funk_txn_id_set_unique( fd_funk_txn_id_t * xid ) {
  static FD_TLS ulong tag = 0UL;
  xid->ul[0] = fd_log_app_id();
  xid->ul[1] = fd_log_thread_id();
  xid->ul[2] = ++tag;
# if FD_HAS_X86
  xid->ul[3] = (ulong)fd_tickcount();
# else
  xid->ul[3] = 0UL;
# endif
  return xid;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( !strcmp( fd_funk_strerror( FD_FUNK_SUCCESS   ), "success" ) );
  FD_TEST( !strcmp( fd_funk_strerror( FD_FUNK_ERR_INVAL ), "inval"   ) );
  FD_TEST( !strcmp( fd_funk_strerror( FD_FUNK_ERR_KEY   ), "key"     ) );
  FD_TEST( !strcmp( fd_funk_strerror( FD_FUNK_ERR_TXN   ), "txn"     ) );
  FD_TEST( !strcmp( fd_funk_strerror( FD_FUNK_ERR_MEM   ), "mem"     ) );
  FD_TEST( !strcmp( fd_funk_strerror( FD_FUNK_ERR_IO    ), "io"      ) );
  FD_TEST( !strcmp( fd_funk_strerror( 1                 ), "unknown" ) );

  for( ulong rem=1000000UL; rem; rem-- ) {
    fd_funk_rec_key_t a[1]; fd_funk_rec_key_set_unique( a );
    fd_funk_rec_key_t b[1]; fd_funk_rec_key_set_unique( b );

    ulong hash = fd_funk_rec_key_hash( a, 1234UL ); FD_COMPILER_FORGET( hash );
    /**/  hash = fd_funk_rec_key_hash( b, 1234UL ); FD_COMPILER_FORGET( hash );

    FD_TEST( fd_funk_rec_key_eq( a, a )==1 ); FD_TEST( fd_funk_rec_key_eq( a, b )==0 );
    FD_TEST( fd_funk_rec_key_eq( b, a )==0 ); FD_TEST( fd_funk_rec_key_eq( b, b )==1 );

    FD_TEST( fd_funk_rec_key_copy( b, a )==b );

    FD_TEST( fd_funk_rec_key_eq( a, a )==1 ); FD_TEST( fd_funk_rec_key_eq( a, b )==1 );
    FD_TEST( fd_funk_rec_key_eq( b, a )==1 ); FD_TEST( fd_funk_rec_key_eq( b, b )==1 );
  }

  fd_funk_txn_id_t z[1];
  FD_TEST( fd_funk_txn_id_set_root( z )==z );
  FD_TEST( fd_funk_txn_id_eq_root ( z )==1 );
  FD_TEST( !(z->ul[0] | z->ul[1] | z->ul[2] | z->ul[3]) );

  for( ulong rem=1000000UL; rem; rem-- ) {
    fd_funk_txn_id_t a[1]; fd_funk_txn_id_set_unique( a );
    fd_funk_txn_id_t b[1]; fd_funk_txn_id_set_unique( b );

    ulong hash = fd_funk_txn_id_hash( a, 1234UL ); FD_COMPILER_FORGET( hash );
    /**/  hash = fd_funk_txn_id_hash( b, 1234UL ); FD_COMPILER_FORGET( hash );

    FD_TEST( fd_funk_txn_id_eq_root( a )==0 );
    FD_TEST( fd_funk_txn_id_eq_root( b )==0 );
    FD_TEST( fd_funk_txn_id_eq_root( z )==1 );
    FD_TEST( fd_funk_txn_id_eq( a, a )==1 ); FD_TEST( fd_funk_txn_id_eq( a, b )==0 ); FD_TEST( fd_funk_txn_id_eq( a, z )==0 );
    FD_TEST( fd_funk_txn_id_eq( b, a )==0 ); FD_TEST( fd_funk_txn_id_eq( b, b )==1 ); FD_TEST( fd_funk_txn_id_eq( b, z )==0 );
    FD_TEST( fd_funk_txn_id_eq( z, a )==0 ); FD_TEST( fd_funk_txn_id_eq( z, b )==0 ); FD_TEST( fd_funk_txn_id_eq( z, z )==1 );
    FD_TEST( !(z->ul[0] | z->ul[1] | z->ul[2] | z->ul[3]) );

    FD_TEST( fd_funk_txn_id_copy( b, a )==b );

    FD_TEST( fd_funk_txn_id_eq_root( a )==0 );
    FD_TEST( fd_funk_txn_id_eq_root( b )==0 );
    FD_TEST( fd_funk_txn_id_eq_root( z )==1 );
    FD_TEST( fd_funk_txn_id_eq( a, a )==1 ); FD_TEST( fd_funk_txn_id_eq( a, b )==1 ); FD_TEST( fd_funk_txn_id_eq( a, z )==0 );
    FD_TEST( fd_funk_txn_id_eq( b, a )==1 ); FD_TEST( fd_funk_txn_id_eq( b, b )==1 ); FD_TEST( fd_funk_txn_id_eq( b, z )==0 );
    FD_TEST( fd_funk_txn_id_eq( z, a )==0 ); FD_TEST( fd_funk_txn_id_eq( z, b )==0 ); FD_TEST( fd_funk_txn_id_eq( z, z )==1 );
    FD_TEST( !(z->ul[0] | z->ul[1] | z->ul[2] | z->ul[3]) );

    FD_TEST( fd_funk_txn_id_copy( a, z )==a );

    FD_TEST( fd_funk_txn_id_eq_root( a )==1 );
    FD_TEST( fd_funk_txn_id_eq_root( b )==0 );
    FD_TEST( fd_funk_txn_id_eq_root( z )==1 );
    FD_TEST( fd_funk_txn_id_eq( a, a )==1 ); FD_TEST( fd_funk_txn_id_eq( a, b )==0 ); FD_TEST( fd_funk_txn_id_eq( a, z )==1 );
    FD_TEST( fd_funk_txn_id_eq( b, a )==0 ); FD_TEST( fd_funk_txn_id_eq( b, b )==1 ); FD_TEST( fd_funk_txn_id_eq( b, z )==0 );
    FD_TEST( fd_funk_txn_id_eq( z, a )==1 ); FD_TEST( fd_funk_txn_id_eq( z, b )==0 ); FD_TEST( fd_funk_txn_id_eq( z, z )==1 );
    FD_TEST( !(z->ul[0] | z->ul[1] | z->ul[2] | z->ul[3]) );
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

