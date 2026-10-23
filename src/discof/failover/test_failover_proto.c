#include "fd_failover_proto.h"
#include "../../choreo/votor/ag_hist.h"
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
  h->mode    = (uchar)FD_FAILOVER_MODE_ALPENGLOW;
  h->boot_id = 0x1000UL+junk;
}

static void
test_hello( void ) {
  fd_failover_hello_t active, standby;
  fill_hello( &active,  1U, 0xAA, 0xBB, FD_FAILOVER_ROLE_ACTIVE );
  fill_hello( &standby, 2U, 0xAA, 0xBB, FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( fd_failover_hello_check( &active, &standby )==FD_FAILOVER_HELLO_OK );
  FD_TEST( fd_failover_hello_check( &standby, &active )==FD_FAILOVER_HELLO_OK );
  uchar unsupported[] = { 0U, 2U, 255U };
  for( ulong i=0UL; i<sizeof(unsupported); i++ ) {
    standby.mode = unsupported[ i ];
    FD_TEST( fd_failover_hello_check( &active, &standby )==FD_FAILOVER_HELLO_ERR_MODE );
    active.mode = standby.mode;
    FD_TEST( fd_failover_hello_check( &active, &standby )==FD_FAILOVER_HELLO_ERR_MODE );
    active.mode = FD_FAILOVER_MODE_ALPENGLOW;
  }
}

static void
test_demoted_decode( void ) {
  ag_hist_t hist = { .anchor=100UL, .last_leader_slot=ULONG_MAX, .vote_bound=ULONG_MAX, .rec_cnt=1UL };
  hist.rec[ 0 ].slot  = 101UL;
  hist.rec[ 0 ].flags = AG_HIST_FLAG_VOTED;
  uchar state[ FD_FAILOVER_STATE_MAX ];
  ulong state_sz;
  FD_TEST( !ag_hist_ser( &hist, state, sizeof(state), &state_sz ) );
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  ulong sz = fd_failover_demoted_encode( payload, 1UL, 2UL, 101UL, state, state_sz );
  fd_failover_demoted_t decoded;
  FD_TEST( sz && fd_failover_demoted_decode( &decoded, payload, sz ) );
  FD_TEST( decoded.mode==FD_FAILOVER_MODE_ALPENGLOW && decoded.last_vote_slot==101UL );
  FD_TEST( !fd_failover_demoted_decode( &decoded, payload, sz-1UL ) );
  FD_TEST( !fd_failover_demoted_decode( &decoded, payload, sz+1UL ) );
  fd_failover_demoted_t * header = (fd_failover_demoted_t *)payload;
  header->mode = 0U;
  FD_TEST( !fd_failover_demoted_decode( &decoded, payload, sz ) );
  header->mode           = FD_FAILOVER_MODE_ALPENGLOW;
  header->last_vote_slot = 102UL;
  FD_TEST( !fd_failover_demoted_decode( &decoded, payload, sz ) );
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
  fd_failover_handoff_request_t request = { .handoff_id=5UL, .target_boot_id=6UL, .replay_slot=FD_FAILOVER_SLOT_NULL }, request_out;
  FD_TEST( fd_failover_handoff_request_decode( &request_out, (uchar const *)&request, sizeof(request) ) && request_out.handoff_id==5UL );
  FD_TEST( request_out.replay_slot==FD_FAILOVER_SLOT_NULL );
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
  test_demoted_decode();
  test_wrong_staked_key();
  test_handoff_decode();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
