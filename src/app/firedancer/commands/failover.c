#define _GNU_SOURCE
#include "adminctl_client.h"
#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"
#include "../../../discof/failover/fd_failover_proto.h"
#include "../../../disco/topo/fd_dns_resolve.h"
#include "../../../util/net/fd_ip4.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static char const * const ACTION_NAMES[] = {
  "idle", "demote, switching to the junk key", "demote, waiting for the peer's answer",
  "promote, waiting for replay", "promote, waiting for vote history adoption", "promote, switching to the staked key",
  "handoff, requesting the active's final vote state", "handoff, waiting for completion",
  "demote, waiting for the tower to drain"
};
static char const * const SESSION_NAMES[] = {
  "listening", "dialing", "hello", "paired", "backoff"
};
static char const * const SOURCE_NAMES[] = {
  "the stored peer tower", "the vote account (automatic fallback)"
};
static char const * const HANDOFF_NAMES[] = {
  "nothing handed over", "pending", "taken", "declined", "restarted", "cancelled by `failover promote --force`",
  "the dialed machine was a standby"
};

#define ACTION_NAME_CNT  ( sizeof(ACTION_NAMES )/sizeof(ACTION_NAMES [ 0 ]) )
#define SESSION_NAME_CNT ( sizeof(SESSION_NAMES)/sizeof(SESSION_NAMES[ 0 ]) )
#define SOURCE_NAME_CNT  ( sizeof(SOURCE_NAMES )/sizeof(SOURCE_NAMES [ 0 ]) )
#define HANDOFF_NAME_CNT ( sizeof(HANDOFF_NAMES)/sizeof(HANDOFF_NAMES[ 0 ]) )

FD_STATIC_ASSERT( ACTION_NAME_CNT ==FD_FAILOVER_ACTION_CNT,       action_names  );
FD_STATIC_ASSERT( SESSION_NAME_CNT==FD_FAILOVER_SESSION_CNT,      session_names );
FD_STATIC_ASSERT( SOURCE_NAME_CNT ==FD_FAILOVER_SOURCE_CNT,       source_names  );
FD_STATIC_ASSERT( HANDOFF_NAME_CNT==FD_FAILOVER_HANDOFF_CNT,      handoff_names );

/* Strips key and its value.  The cmdline strip drops a key given last
   with no value without a word and takes the flag after the key as its
   value, so we refuse both, each right before its own strip. */
static char const *
strip_value( int *        pargc,
             char ***     pargv,
             char const * key ) {
  for( int i=0; i<*pargc; i++ ) {
    if( FD_UNLIKELY( !strcmp( (*pargv)[ i ], key ) && ( i+1==*pargc || !strncmp( (*pargv)[ i+1 ], "--", 2UL ) ) ) ) {
      FD_LOG_ERR(( "`%s` needs a value", key ));
    }
  }
  return fd_env_strip_cmdline_cstr( pargc, pargv, key, NULL, NULL );
}

static void
failover_cmd_args( int *    pargc,
                   char *** pargv,
                   args_t * args ) {
  char const * name    = strip_value( pargc, pargv, "--name"    );
  char const * address = strip_value( pargc, pargv, "--address" );
  char const * port    = strip_value( pargc, pargv, "--port"    );
  if( FD_UNLIKELY( name ) ) fd_cstr_ncpy( args->failover.name, name, sizeof(args->failover.name) );
  args->failover.yes   = fd_env_strip_cmdline_contains( pargc, pargv, "--yes"   );
  args->failover.force = fd_env_strip_cmdline_contains( pargc, pargv, "--force" );

  if( FD_UNLIKELY( !( *pargc ) ) ) {
    FD_LOG_ERR(( "missing subcommand, supported: status, promote, demote" ));
  }
  /* `promote` asks the active to hand over, `promote --force` takes the
     identity without it. */
  char const * cmd = **pargv;
  if(      !strcmp( cmd, "status"  ) ) args->failover.cmd = (int)FD_ADMINCTL_FAILOVER_CMD_STATUS;
  else if( !strcmp( cmd, "demote"  ) ) args->failover.cmd = (int)FD_ADMINCTL_FAILOVER_CMD_DEMOTE;
  else if( !strcmp( cmd, "promote" ) ) args->failover.cmd = (int)( args->failover.force ? FD_ADMINCTL_FAILOVER_CMD_PROMOTE : FD_ADMINCTL_FAILOVER_CMD_HANDOFF );
  else FD_LOG_ERR(( "unknown subcommand `%s`, supported: status, promote, demote", cmd ));
  ( *pargc )--;
  ( *pargv )++;

  if( FD_UNLIKELY( args->failover.yes && args->failover.cmd==(int)FD_ADMINCTL_FAILOVER_CMD_STATUS ) ) {
    FD_LOG_ERR(( "--yes is only meaningful for `failover promote` and `failover demote`" ));
  }
  if( FD_UNLIKELY( args->failover.force && args->failover.cmd!=(int)FD_ADMINCTL_FAILOVER_CMD_PROMOTE ) ) {
    FD_LOG_ERR(( "--force is only meaningful for `failover promote`" ));
  }
  if( FD_UNLIKELY( ( address || port ) && args->failover.cmd!=(int)FD_ADMINCTL_FAILOVER_CMD_HANDOFF ) ) {
    FD_LOG_ERR(( "--address and --port are only meaningful for `failover promote` without --force" ));
  }
  if( FD_UNLIKELY( address && !fd_dns_resolve_address( address, &args->failover.addr ) ) ) {
    FD_LOG_ERR(( "could not resolve --address `%s` to an IPv4 address", address ));
  }
  if( FD_UNLIKELY( address && !args->failover.addr ) ) {
    FD_LOG_ERR(( "--address `%s` is 0.0.0.0, give the active's own address", address ));
  }
  if( port ) {
    uint value = 0U;
    for( char const * c=port; *c; c++ ) {
      uint digit = (uint)( *c-'0' );
      if( FD_UNLIKELY( digit>9U || value*10U+digit>65535U ) ) {
        FD_LOG_ERR(( "--port `%s` must be a port number from 1 to 65535", port ));
      }
      value = value*10U+digit;
    }
    if( FD_UNLIKELY( !value ) ) {
      FD_LOG_ERR(( "--port `%s` must be a port number from 1 to 65535", port ));
    }
    args->failover.port = (ushort)value;
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
    case FD_FAILOVER_CONTROL_RESULT_BAD_ROLE:          return "this machine is not in the role that command needs, `promote` runs on a standby, `demote` on the active";
    case FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS:       return "a transition or key switch is running, check `failover status`";
    case FD_FAILOVER_CONTROL_RESULT_NO_ACTIVE_ADDRESS: return "gossip has no address for the active, wait or give it with --address, and if both machines show "
                                                              "`role: standby` no machine holds the identity and `failover promote --force` on one of them takes it";
    case FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY:      return "the peer could not finish this request, check `failover status` and the log on the peer";
    case FD_FAILOVER_CONTROL_RESULT_PEER_UNVERIFIED:   return "the peer cannot be verified, --force is required, including first use and restart. Vote history is unknown: it has not been checked. Use `failover promote` here to request a handoff from an active failover peer, or `failover promote --force` only after ensuring every other machine with this identity cannot sign";
    case FD_FAILOVER_CONTROL_RESULT_PEER_ACTIVE:       return "the authenticated peer holds the identity";
    case FD_FAILOVER_CONTROL_RESULT_HANDOFF_PENDING:   return "the peer has not answered our last handoff, if it shows `role: active` run `failover promote` there to "
                                                              "finish it, if it shows `role: standby` nothing votes and `failover promote --force` on one machine takes the identity";
    case FD_FAILOVER_CONTROL_RESULT_TAKEN:             return "the peer took our last handoff and may still be voting";
    case FD_FAILOVER_CONTROL_RESULT_STAKED_SEEN:       return "gossip showed the staked identity at another host within the last 15 seconds, an active is publishing";
    case FD_FAILOVER_CONTROL_RESULT_NO_FINAL_TOWER:    return "the active has no eligible final vote state to hand over and keeps the identity, check its voting progress and vote-history logs before retrying";
    default:                                           return NULL;
  }
}

static void
failover_confirm( args_t const * args ) {
  /* Each of these moves or drops the staked identity, so the operator
     confirms first.  What `failover promote --force` rests on is printed
     even with --yes. */
  if( args->failover.cmd==(int)FD_ADMINCTL_FAILOVER_CMD_PROMOTE ) {
    FD_LOG_STDOUT(( "This takes the staked identity on your word.  No other machine may hold it or be\n"
                    "in a promotion, including any validator running this identity without failover.\n"
                    "Run `failover status` on the other machine: its local role must be standby with\n"
                    "no promotion in progress, or that machine must be stopped or otherwise unable to\n"
                    "vote.  Never promote both machines at once.  Votes the other machine cast that\n"
                    "this machine never learned of are not covered.\n"
                    "WARNING: --force skips every check on the other machine.  Use it only when that\n"
                    "machine cannot sign, or both machines may vote with the staked identity.\n"
                    "It also permits incomplete or empty vote history, which may lose earlier lockouts.\n"
                    "Promotion tries eligible saved vote state, then the vote account, and if the vote\n"
                    "account cannot be adopted it starts from an EMPTY vote history.\n" ));
  }
  if( FD_UNLIKELY( !args->failover.yes ) ) {
    if( args->failover.cmd==(int)FD_ADMINCTL_FAILOVER_CMD_HANDOFF ) {
      FD_LOG_STDOUT(( "This asks the active to hand the staked identity to this standby.  The active\n"
                      "gives up the identity first, so if this standby has not caught up the handoff\n"
                      "fails and neither machine votes until `failover promote --force`.  Check that\n"
                      "this machine is caught up.  Type yes to continue: " ));
    } else if( args->failover.cmd==(int)FD_ADMINCTL_FAILOVER_CMD_DEMOTE ) {
      FD_LOG_STDOUT(( "This gives up the staked identity and tells the other machine nothing.  Nothing\n"
                      "votes until `failover promote --force` runs on one machine.  To move the\n"
                      "identity to the other machine, run `failover promote` there instead.  Type yes\n"
                      "to continue: " ));
    } else {
      FD_LOG_STDOUT(( "Type yes to continue: " ));
    }
    char line[ 16 ] = {0};
    if( FD_UNLIKELY( !fgets( line, sizeof(line), stdin ) ) ) FD_LOG_ERR(( "no confirmation given" ));
    if( FD_UNLIKELY( strcmp( line, "yes\n" ) ) ) FD_LOG_ERR(( "not confirmed, nothing was done" ));
  }
}

/* What this machine knows of another holder of the staked identity,
   from the refusal a promote without --force would get now.  It is what
   `failover promote --force` skips, never a go ahead. */
static char const *
other_holder( ulong result ) {
  switch( result ) {
    case FD_FAILOVER_CONTROL_RESULT_BAD_ROLE:        return "n/a, this machine holds the identity";
    case FD_FAILOVER_CONTROL_RESULT_PEER_ACTIVE:     return "the authenticated peer says it holds the identity";
    case FD_FAILOVER_CONTROL_RESULT_TAKEN:           return "the peer took our last handoff and may be voting";
    case FD_FAILOVER_CONTROL_RESULT_HANDOFF_PENDING: return "the peer has not answered our last handoff and may hold the identity";
    case FD_FAILOVER_CONTROL_RESULT_STAKED_SEEN:     return "gossip showed the staked identity at another host within 15 seconds, an active is probably voting, "
                                                            "for 15 seconds after a restart this can be an old entry";
    case FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS:     return "unknown while a transition or key switch runs here";
    case FD_ADMINCTL_RESULT_SUCCESS:
    case FD_FAILOVER_CONTROL_RESULT_PEER_UNVERIFIED: return "none seen by this machine, which does not prove the other machine is stopped, check it before "
                                                            "`failover promote --force`";
    default:                                         return "unknown";
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
  if( FD_UNLIKELY( resp->request_paused ) ) {
    FD_LOG_STDOUT(( "%-22s %s, paused at its 64-second deadline and not dialing, `failover promote` resumes it\n", "action:", action_name( resp->action ) ));
  } else {
    FD_LOG_STDOUT(( "%-22s %s\n", "action:", action_name( resp->action ) ));
  }
  FD_LOG_STDOUT(( "%-22s %s\n", "stuck:",  !resp->stuck ? "no" : resp->request_paused ? "yes, the handoff request is paused, see the log" : "yes, see the log" ));
  FD_LOG_STDOUT(( "%-22s %s\n", "link:",   resp->link_state<SESSION_NAME_CNT ? SESSION_NAMES[ resp->link_state ] : "unknown" ));
  FD_LOG_STDOUT(( "%-22s %s\n", "peer role:", resp->peer_role_valid ? role_name( resp->peer_role ) : "unknown, no authenticated failover session" ));
  if( FD_UNLIKELY( !resp->peer_boot_id ) ) FD_LOG_STDOUT(( "%-22s none paired since boot\n", "peer boot id:" ));
  else                                     FD_LOG_STDOUT(( "%-22s %016lx\n", "peer boot id:", resp->peer_boot_id ));
  if( FD_UNLIKELY( !resp->peer_addr && resp->role==FD_FAILOVER_ROLE_ACTIVE ) ) {
    FD_LOG_STDOUT(( "%-22s n/a, this machine is the active\n", "peer address:" ));
  } else if( FD_UNLIKELY( !resp->peer_addr ) ) {
    FD_LOG_STDOUT(( "%-22s unknown, gossip has no contact info for the staked identity from another host\n", "peer address:" ));
  } else {
    FD_LOG_STDOUT(( "%-22s " FD_IP4_ADDR_FMT ":%u, from %s\n", "peer address:", FD_IP4_ADDR_FMT_ARGS( resp->peer_addr ), (uint)resp->peer_port,
                    resp->peer_addr_cmd ? "--address" : "gossip" ));
  }

  if( FD_UNLIKELY( !resp->handoff_id ) ) {
    FD_LOG_STDOUT(( "%-22s none since boot\n", "last handoff:" ));
  } else {
    FD_LOG_STDOUT(( "%-22s %lu, %s\n", "last handoff:", resp->handoff_id,
                    resp->handoff_result<HANDOFF_NAME_CNT ? HANDOFF_NAMES[ resp->handoff_result ] : "unknown" ));
  }

  /* What a takeover without the active would find right now, what
     `failover promote --force` skips and the history it adopts. */
  FD_LOG_STDOUT(( "%-22s %s\n", "other holder:", other_holder( resp->promote_result ) ));
  FD_LOG_STDOUT(( "%-22s %s\n", "takeover adopts:",
                  resp->promote_source<SOURCE_NAME_CNT ? SOURCE_NAMES[ resp->promote_source ] : "unknown" ));
  if( FD_UNLIKELY( resp->promote_floor==FD_FAILOVER_SLOT_NULL ) ) FD_LOG_STDOUT(( "%-22s none known\n", "coverage floor:" ));
  else                                                             FD_LOG_STDOUT(( "%-22s slot %lu\n", "coverage floor:", resp->promote_floor ));
}

/* A command waits while the validator switches its identity, and we say
   so once it has waited a few seconds.  Only write is safe here. */
static void
wait_note( int sig ) {
  (void)sig;
  static char const note[] = "the validator has not answered for 3 seconds, it may be switching its identity, "
                             "see `failover: switching the identity` in its log, still waiting\n";
  ssize_t written = write( STDERR_FILENO, note, sizeof(note)-1UL );
  (void)written;
}

/* Sends req to the failover tile and waits for the answer, which lands
   in resp.  Returns the adminctl result. */
static ulong
failover_request( fd_adminctl_t *                    adminctl,
                  fd_adminctl_failover_req_t const * req,
                  void *                             resp,
                  ulong                              resp_max,
                  ulong *                            resp_sz ) {
  void * payload     = NULL;
  ulong  payload_max = 0UL;
  ulong  slot_idx    = fd_adminctl_reserve( adminctl, &payload, &payload_max );
  if( FD_UNLIKELY( slot_idx==ULONG_MAX ) ) FD_LOG_ERR(( "all admin command slots are busy" ));
  if( FD_UNLIKELY( sizeof(*req)>payload_max ) ) FD_LOG_ERR(( "adminctl failover payload too large" ));
  fd_memcpy( payload, req, sizeof(*req) );
  fd_adminctl_publish( adminctl, slot_idx, FD_ADMINCTL_CMD_FAILOVER, sizeof(*req) );

  struct sigaction sa = { .sa_handler = wait_note };
  if( FD_UNLIKELY( sigaction( SIGALRM, &sa, NULL ) ) ) FD_LOG_ERR(( "sigaction(SIGALRM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  alarm( 3U );
  ulong result = fd_adminctl_wait_response( adminctl, slot_idx, resp, resp_max, resp_sz );
  alarm( 0U );
  return result;
}

static void __attribute__((noreturn))
fail_disabled( int status ) {
  if( status ) FD_LOG_ERR(( "this validator has no failover command bus, so it cannot report failover status" ));
  FD_LOG_ERR(( "failover is not enabled on the running validator, set [failover.enabled] to true and restart it" ));
}

static void __attribute__((noreturn))
fail_incompatible( void ) {
  FD_LOG_ERR(( "running validator returned an incompatible failover response, use the firedancer binary the validator runs" ));
}

/* Before we prompt we check that failover is on and that this machine is
   in the role the command needs, so nobody confirms a command that is
   then refused.  The failover tile still decides.  Anything else is left
   to the command itself. */
static void
failover_precheck( fd_adminctl_t * adminctl,
                   args_t const *  args ) {
  fd_adminctl_failover_req_t req = { .version=FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION, .cmd=FD_ADMINCTL_FAILOVER_CMD_STATUS };
  fd_adminctl_failover_status_resp_t status;
  ulong status_sz = 0UL;
  ulong result    = failover_request( adminctl, &req, &status, sizeof(status), &status_sz );
  if( FD_UNLIKELY( result!=FD_ADMINCTL_RESULT_SUCCESS || status_sz!=sizeof(status) ||
                   status.version!=FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION ) ) return;
  if( FD_UNLIKELY( status.enabled!=1 ) ) fail_disabled( 0 );
  int want_active = args->failover.cmd==(int)FD_ADMINCTL_FAILOVER_CMD_DEMOTE;
  if( FD_UNLIKELY( (status.role==FD_FAILOVER_ROLE_ACTIVE)!=want_active ) ) {
    FD_LOG_ERR(( "`failover %s` refused, %s", fd_adminctl_failover_cmd_typed( (ulong)args->failover.cmd ),
                 control_result_name( FD_FAILOVER_CONTROL_RESULT_BAD_ROLE ) ));
  }
}

/* Send the command to the failover tile and print the result. */
static void
failover_cmd_fn( args_t *   args,
                 config_t * config ) {
  fd_adminctl_t * adminctl = adminctl_client_attach( config, args->failover.name );
  int             status   = args->failover.cmd==(int)FD_ADMINCTL_FAILOVER_CMD_STATUS;
  if( !status && !args->failover.yes ) failover_precheck( adminctl, args );
  if( !status ) failover_confirm( args );

  /* Confirmation changes no permissions. FORCE is explicit in both
     interactive and noninteractive use. */
  fd_adminctl_failover_req_t req;
  fd_memset( &req, 0, sizeof(req) );
  req.version = FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION;
  req.cmd     = (ulong)args->failover.cmd;
  if( FD_UNLIKELY( args->failover.yes   ) ) req.flags |= FD_ADMINCTL_FAILOVER_FLAG_YES;
  if( FD_UNLIKELY( args->failover.force ) ) req.flags |= FD_ADMINCTL_FAILOVER_FLAG_FORCE;
  req.addr    = args->failover.addr;
  req.port    = args->failover.port;

  union {
    fd_adminctl_failover_control_resp_t control;
    fd_adminctl_failover_status_resp_t  status;
  } resp = { 0 };
  ulong        resp_sz  = 0UL;
  ulong        result   = failover_request( adminctl, &req, &resp, sizeof(resp), &resp_sz );
  char const * cmd_name = fd_adminctl_failover_cmd_typed( (ulong)args->failover.cmd );
  char const * refusal  = control_result_name( result );
  if( FD_UNLIKELY( refusal ) ) FD_LOG_ERR(( "`failover %s` refused, %s", cmd_name, refusal ));
  switch( result ) {
    case FD_ADMINCTL_RESULT_SUCCESS:
      if( FD_UNLIKELY( resp_sz!=(status ? sizeof(resp.status) : sizeof(resp.control)) ||
                       (status ? resp.status.version : resp.control.version)!=FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION ||
                       (status && resp.status.mode>=FD_FAILOVER_MODE_CNT) ) ) {
        fail_incompatible();
      }
      if( status ) {
        failover_status_print( &resp.status );
      } else {
        ulong id = resp.control.handoff_id;
        FD_LOG_STDOUT(( "%-22s accepted\n", cmd_name ));
        FD_LOG_STDOUT(( "%-22s %s\n", "role:",   role_name  ( resp.control.role   ) ));
        FD_LOG_STDOUT(( "%-22s %s\n", "action:", action_name( resp.control.action ) ));
        if( args->failover.cmd==(int)FD_ADMINCTL_FAILOVER_CMD_HANDOFF ) {
          FD_LOG_STDOUT(( "%-22s %lu, done when `failover status` here shows role: active and last handoff: %lu, taken\n", "handoff:", id, id ));
        } else if( args->failover.cmd==(int)FD_ADMINCTL_FAILOVER_CMD_DEMOTE ) {
          FD_LOG_STDOUT(( "%-22s %lu, done when `failover status` here shows role: standby and action: idle\n", "demotion:", id ));
        } else {
          FD_LOG_STDOUT(( "%-22s done when `failover status` here shows role: active and action: idle\n", "promotion:" ));
        }
      }
      break;
    case FD_FAILOVER_CONTROL_RESULT_BUSY:
      FD_LOG_ERR(( "another failover command is in flight, try again" ));
    case FD_FAILOVER_CONTROL_RESULT_UNRESPONSIVE:
      if( status ) FD_LOG_ERR(( "the validator's failover tile did not answer in time" ));
      FD_LOG_ERR(( "the validator's failover tile did not answer in time, the outcome is indeterminate, run `failover status`" ));
    case FD_ADMINCTL_RESULT_UNSUPPORTED:
      fail_disabled( status );
    case FD_ADMINCTL_RESULT_UNKNOWN_COMMAND:
    case FD_ADMINCTL_RESULT_ABI_VERSION_MISMATCH:
    case FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH:
      FD_LOG_ERR(( "failover is incompatible with the running validator, use the firedancer binary the validator runs" ));
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
  fd_action_help_arg( help, "--force", NULL,    "Only with `promote`.  Take the identity without the active, skip\n"
                                                "every check on the other machine and stop waiting for its answer\n"
                                                "to our handoff.  Use it only when the other machine cannot sign.\n"
                                                "Also accept incomplete or empty vote history, earlier lockouts may\n"
                                                "be lost" );
  fd_action_help_arg( help, "--address", "<address>", "Only with `promote` without --force.  The active to ask, an IPv4\n"
                                                      "address or host name, instead of the address gossip shows for it,\n"
                                                      "for example when the active listens on a private network" );
  fd_action_help_arg( help, "--port", "<port>", "Only with `promote` without --force.  The active's failover port.\n"
                                                "Without it we dial our own [failover.listen_port], so both machines\n"
                                                "normally use the same port" );
}

action_t fd_action_failover = {
  .name           = "failover",
  .args           = failover_cmd_args,
  .fn             = failover_cmd_fn,
  .require_config = 0,
  .perm           = NULL,
  .description    = "Inspect and drive failover of the running validator",
  .detail         = "Moves the staked identity between two validators.  A validator with\n"
                    "[failover] enabled boots as a standby under its junk identity and does\n"
                    "not vote until promoted.\n"
                    "\n"
                    "`status` prints this machine's failover state.  `promote` on the standby\n"
                    "asks the active to hand over its identity.  `promote --force` takes the\n"
                    "identity without the active, for when it cannot sign.  Each asks for\n"
                    "confirmation unless --yes is given.\n"
                    "\n"
                    "This command does not start a validator; it attaches to one that is already\n"
                    "running.  With no arguments it discovers the running validator automatically.\n"
                    "If multiple validators are running, pass --name to select one.\n",
  .usage          = "failover status|promote|demote [--name <name>] [--yes] [--force] [--address <address>] [--port <port>]",
  .args_help      = failover_args_help,
};
