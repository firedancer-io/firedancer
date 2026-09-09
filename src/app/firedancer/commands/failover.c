#define _GNU_SOURCE
#include "adminctl_client.h"
#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"
#include "../../../discof/failover/fd_failover_proto.h"

#include <unistd.h>

static char const * const SESSION_NAMES[] = {
  "listening", "dialing", "hello", "paired", "rejected", "backoff"
};
static char const * const READINESS_NAMES[] = {
  "ready", "link down", "peer status stale", "role or term conflict",
  "active is unhealthy", "standby is unhealthy", "standby is not caught up"
};

#define SESSION_NAME_CNT   ( sizeof(SESSION_NAMES  )/sizeof(SESSION_NAMES  [ 0 ]) )
#define READINESS_NAME_CNT ( sizeof(READINESS_NAMES)/sizeof(READINESS_NAMES[ 0 ]) )

FD_STATIC_ASSERT( SESSION_NAME_CNT  ==FD_FAILOVER_SESSION_CNT,   session_names   );
FD_STATIC_ASSERT( READINESS_NAME_CNT==FD_FAILOVER_READINESS_CNT, readiness_names );

static void
failover_cmd_args( int *    pargc,
                   char *** pargv,
                   args_t * args ) {
  char const * name = fd_env_strip_cmdline_cstr( pargc, pargv, "--name", NULL, NULL );
  if( FD_UNLIKELY( name ) ) fd_cstr_ncpy( args->failover.name, name, sizeof(args->failover.name) );

  if( FD_UNLIKELY( !( *pargc ) ) ) FD_LOG_ERR(( "missing subcommand, supported: status" ));
  if( FD_UNLIKELY( strcmp( **pargv, "status" ) ) ) FD_LOG_ERR(( "unknown subcommand `%s`, supported: status", **pargv ));
  ( *pargc )--;
  ( *pargv )++;
}

static void
print_slot( char const * label,
            ulong        slot ) {
  if( FD_UNLIKELY( slot==FD_FAILOVER_SLOT_NULL ) ) FD_LOG_STDOUT(( "%-22s unknown\n", label ));
  else FD_LOG_STDOUT(( "%-22s %lu\n", label, slot ));
}

static char const *
role_name( uchar role ) {
  if( FD_LIKELY( role==FD_FAILOVER_ROLE_STANDBY ) ) return "standby";
  if( FD_LIKELY( role==FD_FAILOVER_ROLE_ACTIVE  ) ) return "active";
  return "unknown";
}

static void
failover_cmd_fn( args_t *   args,
                 config_t * config ) {
  fd_adminctl_t * adminctl = adminctl_client_attach( config, args->failover.name );

  void * payload     = NULL;
  ulong  payload_max = 0UL;
  ulong  slot_idx    = fd_adminctl_reserve( adminctl, &payload, &payload_max );
  if( FD_UNLIKELY( slot_idx==ULONG_MAX ) ) FD_LOG_ERR(( "all admin command slots are busy" ));
  if( FD_UNLIKELY( sizeof(fd_adminctl_failover_status_req_t)>payload_max ) ) FD_LOG_ERR(( "adminctl failover-status payload too large" ));

  fd_adminctl_failover_status_req_t * req = (fd_adminctl_failover_status_req_t *)payload;
  req->version = FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION;

  fd_adminctl_publish( adminctl, slot_idx, FD_ADMINCTL_CMD_FAILOVER_STATUS, sizeof(fd_adminctl_failover_status_req_t) );

  fd_adminctl_failover_status_resp_t resp = { 0 };
  ulong resp_sz = 0UL;
  ulong result  = fd_adminctl_wait_response( adminctl, slot_idx, &resp, sizeof(resp), &resp_sz );
  switch( result ) {
    case FD_ADMINCTL_RESULT_SUCCESS: {
      if( FD_UNLIKELY( resp_sz!=sizeof(resp) || resp.version!=FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION ) ) {
        FD_LOG_ERR(( "running validator returned an incompatible failover-status response" ));
      }

      if( FD_UNLIKELY( !resp.enabled ) ) {
        FD_LOG_STDOUT(( "%-22s %s\n", "failover:", "disabled" ));
        break;
      }

      FD_LOG_STDOUT(( "%-22s %s\n", "failover:", "enabled" ));
      FD_LOG_STDOUT(( "%-22s %s at term %lu\n", "role:", role_name( resp.role ), resp.term ));
      FD_LOG_STDOUT(( "%-22s %s\n", "link:", resp.link_state<SESSION_NAME_CNT ? SESSION_NAMES[ resp.link_state ] : "unknown" ));
      if( FD_LIKELY( resp.peer_status_valid ) ) {
        FD_LOG_STDOUT(( "%-22s %s at term %lu\n", "peer:", role_name( resp.peer_role ), resp.peer_term ));
        if( FD_UNLIKELY( resp.peer_status_age_nanos==ULONG_MAX ) ) FD_LOG_STDOUT(( "%-22s unknown\n", "peer status age:" ));
        else                                                       FD_LOG_STDOUT(( "%-22s %.3f ms\n", "peer status age:", (double)resp.peer_status_age_nanos/1e6 ));
        print_slot( "peer replay slot:",    resp.peer_replay_slot    );
        print_slot( "peer last vote slot:", resp.peer_last_vote_slot );
      }
      FD_LOG_STDOUT(( "%-22s %s\n", "handoff ready:", resp.ready ? "yes" : "no" ));
      if( FD_UNLIKELY( !resp.ready ) ) {
        char const * reason = resp.readiness_reason<READINESS_NAME_CNT
          ? READINESS_NAMES[ resp.readiness_reason ]
          : "unknown";
        FD_LOG_STDOUT(( "%-22s %s\n", "reason:", reason ));
      }
      FD_LOG_STDOUT(( "%-22s 0x%08x (flags 0x%02x)\n", "status:", resp.status, (uint)resp.flags ));
      if( FD_LIKELY( resp.peer_status_valid ) ) {
        FD_LOG_STDOUT(( "%-22s 0x%08x (flags 0x%02x)\n", "peer status:", resp.peer_status, (uint)resp.peer_flags ));
      }
      print_slot( "replay slot:",    resp.replay_slot    );
      print_slot( "root slot:",      resp.root_slot      );
      print_slot( "last vote slot:", resp.last_vote_slot );
      if( FD_UNLIKELY( resp.replication_lag_slots==FD_FAILOVER_SLOT_NULL ) ) FD_LOG_STDOUT(( "%-22s unknown\n", "replication lag:" ));
      else FD_LOG_STDOUT(( "%-22s %lu slots\n", "replication lag:", resp.replication_lag_slots ));
      if( FD_UNLIKELY( !resp.rtt_nanos ) ) FD_LOG_STDOUT(( "%-22s unmeasured\n", "round trip:" ));
      else                                 FD_LOG_STDOUT(( "%-22s %.3f ms\n", "round trip:", (double)resp.rtt_nanos/1e6 ));
      FD_LOG_STDOUT(( "%-22s %lu sent, %lu received, %lu authentication failures\n",
                      "frames:", resp.frames_sent, resp.frames_received, resp.mac_failures ));
      FD_LOG_STDOUT(( "%-22s %lu protocol failures, %lu HELLO rejections, %lu connections\n",
                      "channel:", resp.wire_failures, resp.hello_rejections, resp.connections ));
      break;
    }
    case FD_ADMINCTL_RESULT_UNKNOWN_COMMAND:
    case FD_ADMINCTL_RESULT_ABI_VERSION_MISMATCH:
    case FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH:
      FD_LOG_ERR(( "failover status is incompatible with the running validator" ));
    default:
      FD_LOG_ERR(( "unexpected failover-status result %lu", result ));
  }
}

static void
failover_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "--name", "<name>", "Name of the validator instance to attach to, if more than one is\n"
                                                "running on this host" );
}

action_t fd_action_failover = {
  .name           = "failover",
  .args           = failover_cmd_args,
  .fn             = failover_cmd_fn,
  .require_config = 0,
  .perm           = NULL,
  .is_diagnostic  = 1,
  .description    = "Inspect the failover pair channel of the running validator",
  .detail         = "`failover status` prints the pair channel's role, link state, peer view,\n"
                    "replication lag, measured round trip time, and frame counters.\n"
                    "\n"
                    "This command does not start a validator; it attaches to one that is already\n"
                    "running.  With no arguments it discovers the running validator automatically.\n"
                    "If multiple validators are running, pass --name to select one.\n",
  .usage          = "failover status [--name <name>]",
  .args_help      = failover_args_help,
};
