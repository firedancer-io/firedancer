#include "failover.c"
#include "../../../disco/topo/fd_topo.h"

/* Every result has one exit code, and a takeover that failed after its
   handoff failed exits with the handoff's code. */

/* Referenced by fdctl_shared's help/action machinery, unused here. */

char const *         FD_APP_NAME    = "Firedancer";
char const *         FD_BINARY_NAME = "firedancer";
action_t *           ACTIONS[]      = { NULL };
fd_topo_run_tile_t * TILES[]        = { NULL };

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cnt = sizeof(failover_results)/sizeof(failover_results[0]);
  for( ulong i=0UL; i<cnt; i++ ) {
    failover_result_t const * row = &failover_results[ i ];
    FD_TEST( failover_result_find( row->result )==row );
    FD_TEST( row->exit_code==FAILOVER_EXIT_REFUSED || row->exit_code==FAILOVER_EXIT_UNKNOWN || row->exit_code==FAILOVER_EXIT_NOBODY );
    /* A plain failure exits with its own code. */
    FD_TEST( failover_exit_code( row->result, FD_ADMINCTL_RESULT_SUCCESS )==row->exit_code );
    /* So does a takeover after the handoff left the identity with the remote. */
    FD_TEST( failover_exit_code( row->result, FD_FAILOVER_CONTROL_RESULT_HANDED_OFF )==row->exit_code );
  }
  FD_TEST( !failover_result_find( FD_ADMINCTL_RESULT_SUCCESS ) );
  FD_TEST( !failover_result_find( FD_FAILOVER_CONTROL_RESULT_ALREADY_HOLDS ) );

  /* Only a failure the remote caused or could not answer falls back to a takeover. */
  FD_TEST(  failover_result_find( FD_FAILOVER_CONTROL_RESULT_TIMEOUT          )->takeover );
  FD_TEST(  failover_result_find( FD_FAILOVER_CONTROL_RESULT_NO_PEER          )->takeover );
  FD_TEST(  failover_result_find( FD_FAILOVER_CONTROL_RESULT_HANDED_OFF       )->takeover );
  FD_TEST( !failover_result_find( FD_FAILOVER_CONTROL_RESULT_BUSY             )->takeover );
  FD_TEST( !failover_result_find( FD_FAILOVER_CONTROL_RESULT_HOLDS_OTHER      )->takeover );
  FD_TEST( !failover_result_find( FD_FAILOVER_CONTROL_RESULT_HOLDER_LIVE      )->takeover );
  FD_TEST( !failover_result_find( FD_SET_IDENTITY_RESULT_KEYPAIR_MISMATCH     )->takeover );
  FD_TEST( !failover_result_find( FD_SET_IDENTITY_RESULT_AUTHORIZED_VOTER     )->takeover );

  /* The takeover failed after the handoff did: the handoff's code wins. */
  FD_TEST( failover_exit_code( FD_FAILOVER_CONTROL_RESULT_HOLDER_LIVE,     FD_FAILOVER_CONTROL_RESULT_TIMEOUT       )==FAILOVER_EXIT_UNKNOWN );
  FD_TEST( failover_exit_code( FD_FAILOVER_CONTROL_RESULT_ADOPTION_FAILED, FD_FAILOVER_CONTROL_RESULT_TIMEOUT       )==FAILOVER_EXIT_UNKNOWN );
  FD_TEST( failover_exit_code( FD_FAILOVER_CONTROL_RESULT_ADOPTION_FAILED, FD_FAILOVER_CONTROL_RESULT_NO_PEER       )==FAILOVER_EXIT_REFUSED );
  FD_TEST( failover_exit_code( FD_FAILOVER_CONTROL_RESULT_REPLAY_BEHIND,   FD_FAILOVER_CONTROL_RESULT_PEER_RESTARTED )==FAILOVER_EXIT_UNKNOWN );
  /* Unless the identity was handed off, the takeover then speaks for itself. */
  FD_TEST( failover_exit_code( FD_FAILOVER_CONTROL_RESULT_ADOPTION_FAILED, FD_FAILOVER_CONTROL_RESULT_HANDED_OFF    )==FAILOVER_EXIT_NOBODY );
  FD_TEST( failover_exit_code( FD_FAILOVER_CONTROL_RESULT_HOLDER_LIVE,     FD_FAILOVER_CONTROL_RESULT_HANDED_OFF    )==FAILOVER_EXIT_REFUSED );
  /* Or set-identity changed the identity during it. */
  FD_TEST( failover_exit_code( FD_FAILOVER_CONTROL_RESULT_IDENTITY_CHANGED, FD_FAILOVER_CONTROL_RESULT_NO_PEER      )==FAILOVER_EXIT_UNKNOWN );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
