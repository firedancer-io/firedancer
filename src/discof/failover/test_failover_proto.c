#include "fd_failover_proto.h"
#include "../../util/fd_util.h"

static void
fill_hello( fd_failover_hello_t * h,
            uchar                 junk,
            uchar                 staked,
            uchar                 vote,
            uchar                 role ) {
  fd_memset( h, 0, sizeof(fd_failover_hello_t) );
  h->version = (ushort)FD_FAILOVER_VERSION;
  fd_memset( h->junk_pubkey,   junk,   32UL );
  fd_memset( h->staked_pubkey, staked, 32UL );
  fd_memset( h->vote_account,  vote,   32UL );
  h->role    = role;
  h->mode    = (uchar)FD_FAILOVER_MODE_TOWER;
  h->boot_id = 0x1000UL+junk;
}

static void
test_hello( void ) {
  fd_failover_hello_t active, standby;
  fill_hello( &active,  1U, 0xAA, 0xBB, FD_FAILOVER_ROLE_ACTIVE );
  fill_hello( &standby, 2U, 0xAA, 0xBB, FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( fd_failover_hello_check( &active, &standby )==FD_FAILOVER_HELLO_OK );
  FD_TEST( fd_failover_hello_check( &standby, &active )==FD_FAILOVER_HELLO_OK );
}

static void
test_wrong_staked_key( void ) {
  fd_failover_hello_t active, standby;
  fill_hello( &active,  1U, 0xAA, 0xBB, FD_FAILOVER_ROLE_ACTIVE );
  fill_hello( &standby, 2U, 0xAC, 0xBB, FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( fd_failover_hello_check( &active, &standby )==FD_FAILOVER_HELLO_ERR_STAKED );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  test_hello();
  test_wrong_staked_key();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
