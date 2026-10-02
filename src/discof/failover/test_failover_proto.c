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

/* test_handoff_decode: requests and results need their exact size and
   nonzero ids. */
static void
test_handoff_decode( void ) {
  fd_failover_handoff_request_t request = { .handoff_id=5UL, .target_boot_id=6UL }, request_out;
  FD_TEST( fd_failover_handoff_request_decode( &request_out, (uchar const *)&request, sizeof(request) ) && request_out.handoff_id==5UL );
  FD_TEST( !fd_failover_handoff_request_decode( &request_out, (uchar const *)&request, sizeof(request)-1UL ) );
  request.target_boot_id = 0UL;
  FD_TEST( !fd_failover_handoff_request_decode( &request_out, (uchar const *)&request, sizeof(request) ) );

  fd_failover_handoff_result_t result = { .handoff_id=5UL }, result_out;
  FD_TEST( fd_failover_handoff_result_decode( &result_out, (uchar const *)&result, sizeof(result) ) && result_out.handoff_id==5UL );
  FD_TEST( !fd_failover_handoff_result_decode( &result_out, (uchar const *)&result, sizeof(result)+1UL ) );
  result.handoff_id = 0UL;
  FD_TEST( !fd_failover_handoff_result_decode( &result_out, (uchar const *)&result, sizeof(result) ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  test_hello();
  test_wrong_staked_key();
  test_handoff_decode();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
