#include "fd_uint256.h"

static void
test_ulong_sub_borrow( void ) {
  ulong r;
  int   b;

  fd_ulong_sub_borrow( &r, &b, 0UL,       0UL, 0 );  FD_TEST( r==0UL       && b==0 );
  fd_ulong_sub_borrow( &r, &b, ULONG_MAX, 0UL, 0 );  FD_TEST( r==ULONG_MAX && b==0 );
  fd_ulong_sub_borrow( &r, &b, 0UL,       1UL, 0 );  FD_TEST( r==ULONG_MAX && b==1 );
  fd_ulong_sub_borrow( &r, &b, 4UL,       2UL, 1 );  FD_TEST( r==1UL       && b==0 );
  fd_ulong_sub_borrow( &r, &b, 2UL,       2UL, 1 );  FD_TEST( r==ULONG_MAX && b==1 );
}

static void
test_ulong_add_carry( void ) {
  ulong r;
  int   c;

  fd_ulong_add_carry( &r, &c, 0UL,       0UL, 0 );  FD_TEST( r==0UL       && c==0 );
  fd_ulong_add_carry( &r, &c, ULONG_MAX, 0UL, 0 );  FD_TEST( r==ULONG_MAX && c==0 );
  fd_ulong_add_carry( &r, &c, ULONG_MAX, 1UL, 0 );  FD_TEST( r==0UL       && c==1 );
  fd_ulong_add_carry( &r, &c, 4UL,       2UL, 1 );  FD_TEST( r==7UL       && c==0 );
  fd_ulong_add_carry( &r, &c, ULONG_MAX, 0UL, 1 );  FD_TEST( r==0UL       && c==1 );
  fd_ulong_add_carry( &r, &c, ULONG_MAX, ULONG_MAX, 1 );  FD_TEST( r==ULONG_MAX && c==1 );
}

int
main( int    argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_ulong_sub_borrow();
  test_ulong_add_carry();
  /* TODO more checks here */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
