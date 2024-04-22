#include "fd_acc_mgr.h"

static void
test_acc_exists( void ) {
  FD_TEST( fd_acc_exists( NULL )==0 );

  fd_account_meta_t const zero = {0};
  FD_TEST( fd_acc_exists( &zero )==0 );

  fd_account_meta_t const has_rent_epoch =
    { .info = { .rent_epoch = 32 } };
  FD_TEST( fd_acc_exists( &has_rent_epoch )==0 );

  fd_account_meta_t const has_lamports =
    { .info = { .lamports = 1 } };
  FD_TEST( fd_acc_exists( &has_lamports )==1 );

  fd_account_meta_t const has_data =
    { .dlen = 1 };
  FD_TEST( fd_acc_exists( &has_data )==1 );

  for( ulong i=0UL; i<32UL; i++ ) {
    fd_account_meta_t has_owner = {0};
    has_owner.info.owner[i] = 1;
    FD_TEST( fd_acc_exists( &has_owner )==1 );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_acc_exists();

  fd_halt();
  return 0;
}
