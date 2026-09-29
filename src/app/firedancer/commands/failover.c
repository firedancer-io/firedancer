#define _GNU_SOURCE
#include "adminctl_client.h"
#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"
#include "../../../discof/failover/fd_failover_proto.h"
#include "../../../util/net/fd_ip4.h"

#include <stdio.h>
#include <unistd.h>

static char const * const ACTION_NAMES[] = {
  "idle", "demote, switching to the junk key", "demote, waiting for the peer's answer",
  "promote, waiting for replay", "promote, waiting for vote history adoption", "promote, switching to the staked key",
  "handoff, requesting the active's final vote state", "handoff, waiting for completion"
};
static char const * const SESSION_NAMES[] = {
  "listening", "dialing", "hello", "paired", "backoff"
};
static char const * const SOURCE_NAMES[] = {
  "the stored peer tower", "the vote account (automatic fallback)"
};
static char const * const HANDOFF_NAMES[] = {
  "not sent", "pending", "taken", "declined", "restarted", "cancelled by promote --force"
};

#define ACTION_NAME_CNT  ( sizeof(ACTION_NAMES )/sizeof(ACTION_NAMES [ 0 ]) )
#define SESSION_NAME_CNT ( sizeof(SESSION_NAMES)/sizeof(SESSION_NAMES[ 0 ]) )
#define SOURCE_NAME_CNT  ( sizeof(SOURCE_NAMES )/sizeof(SOURCE_NAMES [ 0 ]) )
#define HANDOFF_NAME_CNT ( sizeof(HANDOFF_NAMES)/sizeof(HANDOFF_NAMES[ 0 ]) )

FD_STATIC_ASSERT( ACTION_NAME_CNT ==FD_FAILOVER_ACTION_CNT,       action_names  );
FD_STATIC_ASSERT( SESSION_NAME_CNT==FD_FAILOVER_SESSION_CNT,      session_names );
FD_STATIC_ASSERT( SOURCE_NAME_CNT ==FD_FAILOVER_SOURCE_CNT,       source_names  );
FD_STATIC_ASSERT( HANDOFF_NAME_CNT==FD_FAILOVER_HANDOFF_CNT,      handoff_names );

static void
failover_cmd_args( int *    pargc,
                   char *** pargv,
                   args_t * args ) {
  char const * name = fd_env_strip_cmdline_cstr( pargc, pargv, "--name", NULL, NULL );
  if( FD_UNLIKELY( name ) ) fd_cstr_ncpy( args->failover.name, name, sizeof(args->failover.name) );
  args->failover.yes   = fd_env_strip_cmdline_contains( pargc, pargv, "--yes"   );
  args->failover.force = fd_env_strip_cmdline_contains( pargc, pargv, "--force" );

  if( FD_UNLIKELY( !( *pargc ) ) ) {
    FD_LOG_ERR(( "missing subcommand, supported: status, handoff, demote, promote" ));
  }
  char const * cmd = **pargv;
  ulong        i;
  for( i=0UL; i<FD_ADMINCTL_FAILOVER_CMD_CNT; i++ ) if( !strcmp( cmd, fd_adminctl_failover_cmd_name( i ) ) ) break;
  if( FD_UNLIKELY( i==FD_ADMINCTL_FAILOVER_CMD_CNT ) ) {
    FD_LOG_ERR(( "unknown subcommand `%s`, supported: status, handoff, demote, promote", cmd ));
  }
  args->failover.cmd = (int)i;
  ( *pargc )--;
  ( *pargv )++;

  if( FD_UNLIKELY( args->failover.yes && args->failover.cmd==(int)FD_ADMINCTL_FAILOVER_CMD_STATUS ) ) {
    FD_LOG_ERR(( "--yes is only meaningful for `failover handoff`, `failover demote` and `failover promote`" ));
  }
  if( FD_UNLIKELY( args->failover.force && args->failover.cmd!=(int)FD_ADMINCTL_FAILOVER_CMD_PROMOTE ) ) {
    FD_LOG_ERR(( "--force is only meaningful for `failover promote`" ));
  }
}

static char const *
role_name( uchar role ) {
  if( FD_LIKELY( role==FD_FAILOVER_ROLE_STANDBY ) ) return "standby";
  if( FD_LIKELY( role==FD_FAILOVER_ROLE_ACTIVE  ) ) return "active";
  return "unknown";
}

static char const *
action_name( uchar action ) {
  return action<ACTION_NAME_CNT ? ACTION_NAMES[ action ] : "unknown";
}

/* Map a refusal code to a human readable reason, NULL for anything
   that is not a refusal. */
static char const *
control_result_name( ulong result ) {
  switch( result ) {
    case FD_FAILOVER_CONTROL_RESULT_BAD_ROLE:          return "this machine is not in the role that command needs, `handoff` and `promote` run on a standby, `demote` on the active";
    case FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS:       return "a transition or key switch is running, check `failover status`";
    case FD_FAILOVER_CONTROL_RESULT_NO_ACTIVE_ADDRESS: return "gossip has no address for the active, wait or set [failover.peer_address]";
    case FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY:      return "the peer could not finish this request, check its failover status and log";
    case FD_FAILOVER_CONTROL_RESULT_PEER_UNVERIFIED:   return "the peer cannot be verified, --force is required, including first use and restart. Vote history is unknown: it has not been checked. Use `failover handoff` here to request a transfer from an active failover peer, or `failover promote --force` only after ensuring every other machine with this identity cannot sign";
    case FD_FAILOVER_CONTROL_RESULT_PEER_ACTIVE:       return "the authenticated peer holds the identity";
    case FD_FAILOVER_CONTROL_RESULT_HANDOFF_PENDING:   return "the peer has not answered our last handoff";
    case FD_FAILOVER_CONTROL_RESULT_TAKEN:             return "the peer took our last handoff and may still be voting";
    case FD_FAILOVER_CONTROL_RESULT_STAKED_SEEN:       return "gossip showed the staked identity at another host within the last 15 seconds, an active is publishing";
    case FD_FAILOVER_CONTROL_RESULT_NO_FINAL_TOWER:    return "the active has no eligible final vote state to hand over and keeps the identity, check its voting progress and vote-history logs before retrying";
    default:                                           return NULL;
  }
}

static void
failover_confirm( args_t const * args ) {
  /* Each of these moves or drops the staked identity, so the operator
     confirms first.  What promote rests on is printed even with --yes. */
  if( args->failover.cmd==(int)FD_ADMINCTL_FAILOVER_CMD_PROMOTE ) {
    FD_LOG_STDOUT(( "This takes the staked identity on your word.  No other machine may hold it or be\n"
                    "in a promotion.  Run `failover status` on the other machine: its local role\n"
                    "must be standby with no promotion in progress, or that machine must be stopped\n"
                    "or otherwise unable to vote.  Never promote both machines at once.\n"
                    "Votes the other machine cast and never reported are not covered.\n"
                    "Unilateral promotion requires --force, including first use and restart.\n"
                    "The peer check comes before selecting or adopting vote history.\n" ));
    if( FD_UNLIKELY( args->failover.force ) ) {
      FD_LOG_STDOUT(( "WARNING: --force skips every check on the other machine.  Use it only when that\n"
                      "machine cannot sign, or both machines may vote with the staked identity.\n"
                      "It also permits incomplete or empty vote history, which may lose earlier lockouts.\n" ));
    }
    FD_LOG_STDOUT(( "Promotion tries eligible saved vote state, then account history where supported.\n"
                    "Without --force, unusable or incomplete history refuses promotion.\n" ));
  }
  if( FD_UNLIKELY( !args->failover.yes ) ) {
    if( args->failover.cmd==(int)FD_ADMINCTL_FAILOVER_CMD_HANDOFF ) {
      FD_LOG_STDOUT(( "This asks the active to hand the staked identity to this standby.  Type yes to continue: " ));
    } else if( args->failover.cmd==(int)FD_ADMINCTL_FAILOVER_CMD_DEMOTE ) {
      FD_LOG_STDOUT(( "This gives up the staked identity and tells the other machine nothing. Recover\n"
                      "on one member after fencing its peer with `failover promote --force`. Type yes to continue: " ));
    } else {
      FD_LOG_STDOUT(( "Type yes to continue: " ));
    }
    char line[ 16 ] = {0};
    if( FD_UNLIKELY( !fgets( line, sizeof(line), stdin ) ) ) FD_LOG_ERR(( "no confirmation given" ));
    if( FD_UNLIKELY( strcmp( line, "yes\n" ) ) ) FD_LOG_ERR(( "not confirmed, nothing was done" ));
  }
}

/* Prints failover status.  Slots, identities and the rest are left to
   RPC, gossip, metrics and the logs. */
static void
failover_status_print( fd_adminctl_failover_status_resp_t const * resp ) {
  if( FD_UNLIKELY( !resp->enabled ) ) {
    FD_LOG_STDOUT(( "%-22s %s\n", "failover:", "disabled" ));
    return;
  }

  FD_LOG_STDOUT(( "%-22s %s\n", "failover:", "enabled" ));
  FD_LOG_STDOUT(( "%-22s %s\n", "role:",   role_name  ( resp->role   ) ));
  FD_LOG_STDOUT(( "%-22s %s\n", "action:", action_name( resp->action ) ));
  FD_LOG_STDOUT(( "%-22s %s\n", "stuck:",  resp->stuck ? "yes, see the log" : "no" ));
  FD_LOG_STDOUT(( "%-22s %s\n", "link:",   resp->link_state<SESSION_NAME_CNT ? SESSION_NAMES[ resp->link_state ] : "unknown" ));
  FD_LOG_STDOUT(( "%-22s %s\n", "peer role:", resp->peer_role_valid ? role_name( resp->peer_role ) : "unknown, no authenticated failover session" ));
  if( FD_UNLIKELY( !resp->peer_boot_id ) ) FD_LOG_STDOUT(( "%-22s none paired since boot\n", "peer boot id:" ));
  else                                     FD_LOG_STDOUT(( "%-22s %016lx\n", "peer boot id:", resp->peer_boot_id ));
  if( FD_UNLIKELY( !resp->peer_addr ) ) {
    FD_LOG_STDOUT(( "%-22s unknown, gossip has no contact info for the staked identity from another host\n", "peer address:" ));
  } else {
    FD_LOG_STDOUT(( "%-22s " FD_IP4_ADDR_FMT ":%u, from %s\n", "peer address:", FD_IP4_ADDR_FMT_ARGS( resp->peer_addr ), (uint)resp->peer_port,
                    resp->peer_addr_cfg ? "[failover.peer_address]" : "gossip" ));
  }

  if( FD_UNLIKELY( !resp->handoff_id ) ) {
    FD_LOG_STDOUT(( "%-22s none since boot\n", "last handoff:" ));
  } else {
    FD_LOG_STDOUT(( "%-22s %lu, %s\n", "last handoff:", resp->handoff_id,
                    resp->handoff_result<HANDOFF_NAME_CNT ? HANDOFF_NAMES[ resp->handoff_result ] : "unknown" ));
  }

  /* What `failover promote` would do right now. */
  if( FD_LIKELY( resp->promote_result==FD_ADMINCTL_RESULT_SUCCESS ) ) {
    FD_LOG_STDOUT(( "%-22s %s\n", "promote:", "would go ahead" ));
  } else {
    char const * refusal = control_result_name( resp->promote_result );
    FD_LOG_STDOUT(( "%-22s refused, %s\n", "promote:", refusal ? refusal : "unknown reason" ));
  }
  FD_LOG_STDOUT(( "%-22s %s\n", "promote adopts:",
                  resp->promote_source<SOURCE_NAME_CNT ? SOURCE_NAMES[ resp->promote_source ] : "unknown" ));
  if( FD_UNLIKELY( resp->promote_floor==FD_FAILOVER_SLOT_NULL ) ) FD_LOG_STDOUT(( "%-22s none\n", "coverage floor:" ));
  else                                                             FD_LOG_STDOUT(( "%-22s slot %lu\n", "coverage floor:", resp->promote_floor ));
}

/* Send the command to the failover tile and print the result. */
static void
failover_cmd_fn( args_t *   args,
                 config_t * config ) {
  fd_adminctl_t * adminctl = adminctl_client_attach( config, args->failover.name );
  int             status   = args->failover.cmd==(int)FD_ADMINCTL_FAILOVER_CMD_STATUS;
  if( !status ) failover_confirm( args );

  void * payload     = NULL;
  ulong  payload_max = 0UL;
  ulong  slot_idx    = fd_adminctl_reserve( adminctl, &payload, &payload_max );
  if( FD_UNLIKELY( slot_idx==ULONG_MAX ) ) FD_LOG_ERR(( "all admin command slots are busy" ));
  if( FD_UNLIKELY( sizeof(fd_adminctl_failover_req_t)>payload_max ) ) FD_LOG_ERR(( "adminctl failover payload too large" ));

  /* Confirmation changes no permissions. FORCE is explicit in both
     interactive and noninteractive use. */
  fd_adminctl_failover_req_t * req = (fd_adminctl_failover_req_t *)payload;
  fd_memset( req, 0, sizeof(*req) );
  req->version = FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION;
  req->cmd     = (ulong)args->failover.cmd;
  if( FD_UNLIKELY( args->failover.yes ) ) req->flags |= FD_ADMINCTL_FAILOVER_FLAG_YES;
  if( FD_UNLIKELY( args->failover.force ) ) req->flags |= FD_ADMINCTL_FAILOVER_FLAG_FORCE;

  fd_adminctl_publish( adminctl, slot_idx, FD_ADMINCTL_CMD_FAILOVER, sizeof(*req) );

  union {
    fd_adminctl_failover_control_resp_t control;
    fd_adminctl_failover_status_resp_t  status;
  } resp = { 0 };
  ulong        resp_sz  = 0UL;
  ulong        result   = fd_adminctl_wait_response( adminctl, slot_idx, &resp, sizeof(resp), &resp_sz );
  char const * cmd_name = fd_adminctl_failover_cmd_name( (ulong)args->failover.cmd );
  char const * refusal  = control_result_name( result );
  if( FD_UNLIKELY( refusal ) ) FD_LOG_ERR(( "`failover %s` refused, %s", cmd_name, refusal ));
  switch( result ) {
    case FD_ADMINCTL_RESULT_SUCCESS:
      if( FD_UNLIKELY( resp_sz!=(status ? sizeof(resp.status) : sizeof(resp.control)) ||
                       (status ? resp.status.version : resp.control.version)!=FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION ) ) {
        FD_LOG_ERR(( "running validator returned an incompatible failover response" ));
      }
      if( status ) {
        failover_status_print( &resp.status );
      } else {
        FD_LOG_STDOUT(( "%-22s accepted\n", cmd_name ));
        FD_LOG_STDOUT(( "%-22s %s\n", "role:",   role_name  ( resp.control.role   ) ));
        FD_LOG_STDOUT(( "%-22s %s\n", "action:", action_name( resp.control.action ) ));
        FD_LOG_STDOUT(( "%-22s %s\n", "confirm with:", "failover status" ));
      }
      break;
    case FD_FAILOVER_CONTROL_RESULT_BUSY:
      FD_LOG_ERR(( "another failover command is in flight, try again" ));
    case FD_FAILOVER_CONTROL_RESULT_UNRESPONSIVE:
      if( status ) FD_LOG_ERR(( "the validator's failover tile did not answer in time" ));
      FD_LOG_ERR(( "the validator's failover tile did not answer in time, the outcome is indeterminate, run `failover status`" ));
    case FD_ADMINCTL_RESULT_UNSUPPORTED:
      if( status ) FD_LOG_ERR(( "this validator has no failover command bus, so it cannot report failover status" ));
      FD_LOG_ERR(( "failover is not enabled on the running validator, it is on when [failover.junk_identity_key] is set" ));
    case FD_ADMINCTL_RESULT_UNKNOWN_COMMAND:
    case FD_ADMINCTL_RESULT_ABI_VERSION_MISMATCH:
    case FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH:
      FD_LOG_ERR(( "failover is incompatible with the running validator" ));
    default:
      FD_LOG_ERR(( "unexpected failover result %lu", result ));
  }
}

static void
failover_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "--name", "<name>", "Name of the validator instance to attach to, if more than one is\n"
                                                "running on this host" );
  fd_action_help_arg( help, "--yes", NULL,      "Skip the confirmation prompt. It does not authorize peer or\n"
                                                "vote-history overrides" );
  fd_action_help_arg( help, "--force", NULL,    "Only with `promote`.  Skip every check on the other machine and\n"
                                                "stop waiting for its answer to our handoff.  Use it only when the\n"
                                                "other machine cannot sign. Also accept incomplete or empty vote\n"
                                                "history, earlier lockouts may be lost" );
}

action_t fd_action_failover = {
  .name           = "failover",
  .args           = failover_cmd_args,
  .fn             = failover_cmd_fn,
  .require_config = 0,
  .perm           = NULL,
  .is_diagnostic  = 1,
  .description    = "Inspect and drive failover of the running validator",
  .detail         = "`failover status` prints what only the failover tile knows: this machine's\n"
                    "role and current action, whether it is stuck, the link to the peer, the\n"
                    "peer's role and boot id, the peer address we dial and where it came from,\n"
                    "how our last handoff ended, and what `promote` would do right now.\n"
                    "An unknown peer role means there is no authenticated failover session.\n"
                    "Gossip may still show the staked identity elsewhere and refuse promotion.\n"
                    "\n"
                    "The remaining commands drive the controller.  Run `handoff` on the standby.\n"
                    "It dials the active from gossip, takes its final vote state and disconnects.\n"
                    "`demote` gives the\n"
                    "identity up without promoting anyone and runs on the active, the other\n"
                    "machine then needs `failover promote --force`.  `promote` takes the identity\n"
                    "without dialing. Every unilateral promotion requires --force, including\n"
                    "first use and restart, because it cannot verify the peer. It tries saved\n"
                    "Tower state, then the vote account, --force also permits incomplete or\n"
                    "empty history if needed. No other machine may\n"
                    "hold the identity or be in a promotion, and\n"
                    "both machines are never promoted at once.  `promote --force` skips the\n"
                    "checks on the other machine when it cannot sign.  Each asks for\n"
                    "confirmation unless --yes is given.\n"
                    "\n"
                    "While the validator switches its identity, `failover status` and every\n"
                    "command wait for the switch to finish, and they hang behind a switch that\n"
                    "never finishes.  Then read the log, and stop a validator that stays stuck.\n"
                    "\n"
                    "This command does not start a validator, it attaches to one that is already\n"
                    "running.  With no arguments it discovers the running validator automatically.\n"
                    "If multiple validators are running, pass --name to select one.\n",
  .usage          = "failover status|handoff|demote|promote [--name <name>] [--yes] [--force]",
  .args_help      = failover_args_help,
};
