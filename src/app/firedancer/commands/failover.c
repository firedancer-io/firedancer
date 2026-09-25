#define _GNU_SOURCE
#include "adminctl_client.h"
#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"
#include "../../../discof/failover/fd_failover_proto.h"

#include <stdio.h>
#include <unistd.h>

static char const * const CMD_NAMES[] = {
  "handoff", "drill", "demote", "promote", "pause", "resume", "clear", "reclaim"
};
static char const * const STATE_NAMES[] = {
  "standby", "active", "demoting", "promoting", "reclaiming"
};

#define CMD_NAME_CNT   ( sizeof(CMD_NAMES  )/sizeof(CMD_NAMES  [ 0 ]) )
#define STATE_NAME_CNT ( sizeof(STATE_NAMES)/sizeof(STATE_NAMES[ 0 ]) )

FD_STATIC_ASSERT( CMD_NAME_CNT ==FD_ADMINCTL_FAILOVER_CMD_CNT, cmd_names   );
FD_STATIC_ASSERT( STATE_NAME_CNT==FD_FAILOVER_STATE_CNT,         state_names );

static char const * const SESSION_NAMES[] = {
  "listening", "dialing", "hello", "paired", "backoff"
};
static char const * const READINESS_NAMES[] = {
  "healthy", "link down", "peer status stale", "role or term conflict",
  "active is unhealthy", "spare is unhealthy", "spare is behind on replication",
  "failover is disabled"
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
  args->failover.peer_idx = fd_env_strip_cmdline_ulong( pargc, pargv, "--peer", NULL, 0UL );
  args->failover.force    = fd_env_strip_cmdline_contains( pargc, pargv, "--force" );
  args->failover.yes      = fd_env_strip_cmdline_contains( pargc, pargv, "--yes" );
  char const * staked = fd_env_strip_cmdline_cstr( pargc, pargv, "--staked-pubkey", NULL, NULL );
  if( FD_UNLIKELY( staked ) ) fd_cstr_ncpy( args->failover.staked_pubkey, staked, sizeof(args->failover.staked_pubkey) );

  if( FD_UNLIKELY( !( *pargc ) ) ) {
    FD_LOG_ERR(( "missing subcommand, supported: status, handoff, drill, demote, promote, pause, resume, clear, reclaim" ));
  }
  char const * cmd = **pargv;
  args->failover.cmd = -1;
  if( FD_LIKELY( strcmp( cmd, "status" ) ) ) {
    ulong i;
    for( i=0UL; i<CMD_NAME_CNT; i++ ) if( !strcmp( cmd, CMD_NAMES[ i ] ) ) break;
    if( FD_UNLIKELY( i==CMD_NAME_CNT ) ) {
      FD_LOG_ERR(( "unknown subcommand `%s`, supported: status, handoff, drill, demote, promote, pause, resume, clear, reclaim", cmd ));
    }
    args->failover.cmd = (int)i;
  }
  ( *pargc )--;
  ( *pargv )++;

  if( FD_UNLIKELY( args->failover.force && args->failover.cmd!=(int)FD_ADMINCTL_FAILOVER_CMD_PROMOTE ) ) {
    FD_LOG_ERR(( "--force is only meaningful for `failover promote`" ));
  }
  if( FD_UNLIKELY( args->failover.yes && args->failover.cmd!=(int)FD_ADMINCTL_FAILOVER_CMD_HANDOFF && !args->failover.force ) ) {
    FD_LOG_ERR(( "--yes is only meaningful for `failover handoff` and `failover promote --force`" ));
  }
  if( FD_UNLIKELY( args->failover.force && !args->failover.staked_pubkey[ 0 ] ) ) {
    FD_LOG_ERR(( "--force requires --staked-pubkey <base58> naming the identity being taken over" ));
  }
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

/* Map a refusal code to a human readable reason. */
static char const *
control_result_name( ulong result ) {
  switch( result ) {
    case FD_FAILOVER_CONTROL_RESULT_DISABLED:     return "failover is not enabled on this validator";
    case FD_FAILOVER_CONTROL_RESULT_BAD_ROLE:     return "this machine is not in the role that command needs";
    case FD_FAILOVER_CONTROL_RESULT_NOT_PAIRED:   return "the pool is not paired, so the peer cannot be asked";
    case FD_FAILOVER_CONTROL_RESULT_BUSY:         return "a transition is already in flight";
    case FD_FAILOVER_CONTROL_RESULT_PAUSED:       return "failover is paused, resume it first";
    case FD_FAILOVER_CONTROL_RESULT_NO_EVIDENCE:  return "no durable demotion confirmation, so promotion is refused";
    case FD_FAILOVER_CONTROL_RESULT_BAD_IDENTITY: return "--staked-pubkey does not name this pool's identity";
    case FD_FAILOVER_CONTROL_RESULT_UNSUPPORTED:  return "that command cannot be applied here";
    case FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY: return "the spare's last status says it cannot take the identity, check its status";
    case FD_FAILOVER_CONTROL_RESULT_IDENTITY_MISMATCH:
      return "the installed identity does not match the recorded role, stuck stays set: do not promote anything, investigate";
    case FD_FAILOVER_CONTROL_RESULT_TOWER_ROLLBACK: return "the confirmation's final tower is older than the tower the peer streamed, so promotion is refused";
    case FD_FAILOVER_CONTROL_RESULT_PEER_REACHABLE: return "the peer is reachable, or was until a moment ago, so it is not fenced: use `handoff` or `reclaim` instead";
    case FD_FAILOVER_CONTROL_RESULT_PRECONDITION: return "a handoff pre-check failed, `failover status` names the reason";
    default:                                      return NULL;
  }
}

/* Send the command to the failover tile and print the result. */
static void
failover_control_fn( args_t *        args,
                     fd_adminctl_t * adminctl ) {
  /* handoff actually moves the identity, so confirm with the operator first. */
  if( FD_UNLIKELY( args->failover.cmd==(int)FD_ADMINCTL_FAILOVER_CMD_HANDOFF && !args->failover.yes ) ) {
    FD_LOG_STDOUT(( "This moves the staked identity between the two machines.  Type yes to continue: " ));
    char line[ 16 ] = {0};
    if( FD_UNLIKELY( !fgets( line, sizeof(line), stdin ) ) ) FD_LOG_ERR(( "no confirmation given" ));
    if( FD_UNLIKELY( strcmp( line, "yes\n" ) ) ) FD_LOG_ERR(( "not confirmed, nothing was done" ));
  }
  /* A forced promotion is an attestation about a machine this validator
     cannot see, so it asks for the word rather than a yes. */
  if( FD_UNLIKELY( args->failover.cmd==(int)FD_ADMINCTL_FAILOVER_CMD_PROMOTE && args->failover.force && !args->failover.yes ) ) {
    FD_LOG_STDOUT(( "This installs the staked identity here on your word that the peer cannot sign.  A peer that is\n"
                    "merely unreachable over the network is not fenced and will keep voting.  Only continue if the\n"
                    "peer has been powered off or otherwise proved unable to sign.  Type fenced to continue: " ));
    char line[ 16 ] = {0};
    if( FD_UNLIKELY( !fgets( line, sizeof(line), stdin ) ) ) FD_LOG_ERR(( "no confirmation given" ));
    if( FD_UNLIKELY( strcmp( line, "fenced\n" ) ) ) FD_LOG_ERR(( "not confirmed, nothing was done" ));
  }

  void * payload     = NULL;
  ulong  payload_max = 0UL;
  ulong  slot_idx    = fd_adminctl_reserve( adminctl, &payload, &payload_max );
  if( FD_UNLIKELY( slot_idx==ULONG_MAX ) ) FD_LOG_ERR(( "all admin command slots are busy" ));
  if( FD_UNLIKELY( sizeof(fd_adminctl_failover_control_t)>payload_max ) ) FD_LOG_ERR(( "adminctl failover-control payload too large" ));

  fd_adminctl_failover_control_t * req = (fd_adminctl_failover_control_t *)payload;
  fd_memset( req, 0, sizeof(*req) );
  req->version = FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION;
  req->cmd     = (ulong)args->failover.cmd;
  req->force   = (uchar)!!args->failover.force;
  if( FD_UNLIKELY( args->failover.staked_pubkey[ 0 ] &&
                   !fd_base58_decode_32( args->failover.staked_pubkey, req->staked_pubkey ) ) ) {
    FD_LOG_ERR(( "--staked-pubkey is not a base58 public key" ));
  }

  fd_adminctl_publish( adminctl, slot_idx, FD_ADMINCTL_CMD_FAILOVER_CONTROL, sizeof(*req) );

  fd_adminctl_failover_control_resp_t resp = { 0 };
  ulong resp_sz = 0UL;
  ulong result  = fd_adminctl_wait_response( adminctl, slot_idx, &resp, sizeof(resp), &resp_sz );
  char const * refusal = control_result_name( result );
  if( FD_UNLIKELY( refusal ) ) FD_LOG_ERR(( "%s: %s", CMD_NAMES[ args->failover.cmd ], refusal ));
  switch( result ) {
    case FD_ADMINCTL_RESULT_SUCCESS:
      if( FD_UNLIKELY( resp_sz!=sizeof(resp) || resp.version!=FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION ) ) {
        FD_LOG_ERR(( "running validator returned an incompatible failover-control response" ));
      }
      FD_LOG_STDOUT(( "%-22s accepted\n", CMD_NAMES[ args->failover.cmd ] ));
      FD_LOG_STDOUT(( "%-22s %s at term %lu%s\n", "state:",
                      resp.state<STATE_NAME_CNT ? STATE_NAMES[ resp.state ] : "unknown",
                      resp.term, resp.paused ? ", paused" : "" ));
      FD_LOG_STDOUT(( "%-22s %s\n", "role:", role_name( resp.role ) ));
      FD_LOG_STDOUT(( "%-22s %s\n", "confirm with:", "failover status" ));
      break;
    case FD_FAILOVER_STATUS_RESULT_BUSY:
      FD_LOG_ERR(( "another failover command is in flight, try again" ));
    case FD_FAILOVER_STATUS_RESULT_UNRESPONSIVE:
      FD_LOG_ERR(( "the validator's failover tile did not answer in time, the outcome is indeterminate, run `failover status`" ));
    case FD_ADMINCTL_RESULT_UNSUPPORTED:
      FD_LOG_ERR(( "this validator has no failover command bus" ));
    case FD_ADMINCTL_RESULT_UNKNOWN_COMMAND:
    case FD_ADMINCTL_RESULT_ABI_VERSION_MISMATCH:
    case FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH:
      FD_LOG_ERR(( "failover control is incompatible with the running validator" ));
    default:
      FD_LOG_ERR(( "unexpected failover-control result %lu", result ));
  }
}

static void
failover_cmd_fn( args_t *   args,
                 config_t * config ) {
  fd_adminctl_t * adminctl = adminctl_client_attach( config, args->failover.name );

  if( FD_UNLIKELY( args->failover.cmd>=0 ) ) {
    failover_control_fn( args, adminctl );
    return;
  }

  void * payload     = NULL;
  ulong  payload_max = 0UL;
  ulong  slot_idx    = fd_adminctl_reserve( adminctl, &payload, &payload_max );
  if( FD_UNLIKELY( slot_idx==ULONG_MAX ) ) FD_LOG_ERR(( "all admin command slots are busy" ));
  if( FD_UNLIKELY( sizeof(fd_adminctl_failover_status_req_t)>payload_max ) ) FD_LOG_ERR(( "adminctl failover-status payload too large" ));

  fd_adminctl_failover_status_req_t * req = (fd_adminctl_failover_status_req_t *)payload;
  req->version  = FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION;
  req->peer_idx = args->failover.peer_idx;

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
      FD_LOG_STDOUT(( "%-22s %u machines, %u paired\n", "pool:", (uint)resp.member_cnt, (uint)resp.peers_paired ));
      FD_LOG_STDOUT(( "%-22s member %u of the list\n", "this machine:", (uint)resp.self_idx ));
      FD_LOG_STDOUT(( "%-22s %s at term %lu\n", "role:", role_name( resp.role ), resp.term ));
      FD_LOG_STDOUT(( "%-22s peer %u\n", "reporting:", (uint)resp.peer_idx ));
      FD_LOG_STDOUT(( "%-22s %s\n", "link:", resp.link_state<SESSION_NAME_CNT ? SESSION_NAMES[ resp.link_state ] : "unknown" ));
      if( FD_LIKELY( resp.peer_status_valid ) ) {
        FD_LOG_STDOUT(( "%-22s %s at term %lu\n", "peer:", role_name( resp.peer_role ), resp.peer_term ));
        if( FD_UNLIKELY( resp.peer_status_age_nanos==ULONG_MAX ) ) FD_LOG_STDOUT(( "%-22s unknown\n", "peer status age:" ));
        else                                                       FD_LOG_STDOUT(( "%-22s %.3f ms\n", "peer status age:", (double)resp.peer_status_age_nanos/1e6 ));
        print_slot( "peer replay slot:",    resp.peer_replay_slot    );
        print_slot( "peer last vote slot:", resp.peer_last_vote_slot );
      }
      char const * health = resp.readiness_reason<READINESS_NAME_CNT
        ? READINESS_NAMES[ resp.readiness_reason ]
        : "unknown";
      FD_LOG_STDOUT(( "%-22s %s\n", "pool health:", health ));
      FD_LOG_STDOUT(( "%-22s %s\n", "handoff ready:", "not reported" ));
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
      FD_LOG_STDOUT(( "%-22s %lu sent, %lu received\n",
                      "frames:", resp.frames_sent, resp.frames_received ));
      FD_LOG_STDOUT(( "%-22s %lu protocol failures, %lu HELLO rejections\n",
                      "channel:", resp.wire_failures, resp.hello_rejections ));
      FD_LOG_STDOUT(( "%-22s %lu attempts, %lu sessions paired\n",
                      "connections:", resp.connection_attempts, resp.sessions_paired ));
      FD_LOG_STDOUT(( "%-22s %lu pending, %lu TLS failures, %lu timeouts\n",
                      "handshakes:", resp.pending_handshakes, resp.tls_failures, resp.handshake_timeouts ));
      FD_LOG_STDOUT(( "%-22s %lu\n", "admission drops:", resp.admission_drops ));
      break;
    }
    case FD_FAILOVER_STATUS_RESULT_BUSY:
      FD_LOG_ERR(( "another failover status request is in flight, try again" ));
    case FD_FAILOVER_STATUS_RESULT_UNRESPONSIVE:
      FD_LOG_ERR(( "the validator's failover tile did not answer in time" ));
    case FD_FAILOVER_STATUS_RESULT_NO_SUCH_PEER:
      FD_LOG_ERR(( "this validator has no failover peer %lu", args->failover.peer_idx ));
    case FD_ADMINCTL_RESULT_UNSUPPORTED:
      FD_LOG_ERR(( "this validator has no failover command bus, so it cannot report failover status" ));
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
  fd_action_help_arg( help, "--peer", "<idx>",  "Which pool peer to report, in member list order without this\n"
                                                "machine.  Defaults to 0" );
  fd_action_help_arg( help, "--yes", NULL,      "Skip the confirmation prompt for `handoff` and `promote --force`" );
  fd_action_help_arg( help, "--force", NULL,    "For `promote` with no demotion confirmation, attest that the peer has\n"
                                                "been fenced out of band and name the identity with --staked-pubkey.\n"
                                                "This machine adopts its own signed tower file and takes the key.  It\n"
                                                "is refused while the peer is reachable, or was until a moment ago,\n"
                                                "but a peer that is merely partitioned passes that check and keeps\n"
                                                "voting, so use it only for a machine that has been powered off or\n"
                                                "otherwise proved unable to sign.  It never overrides tower\n"
                                                "recovery or freshness checks" );
  fd_action_help_arg( help, "--staked-pubkey", "<base58>",
                                                "The identity being taken over, required with --force" );
}

action_t fd_action_failover = {
  .name           = "failover",
  .args           = failover_cmd_args,
  .fn             = failover_cmd_fn,
  .require_config = 0,
  .perm           = NULL,
  .is_diagnostic  = 1,
  .description    = "Inspect and drive the failover pool of the running validator",
  .detail         = "`failover status` prints the pool's membership, this machine's role, the\n"
                    "selected peer's link state and view, replication lag, measured round trip\n"
                    "time, frame counters, and TLS admission and handshake counters.\n"
                    "\n"
                    "The remaining commands drive the controller.  `handoff` moves the identity and\n"
                    "`drill` rehearses the same checks without moving it, and both run from\n"
                    "either machine.  `demote` gives the identity up without promoting anyone\n"
                    "and runs on the active.  `promote` takes it and runs on a spare.  `pause`\n"
                    "and `resume` hold and release every transition, on either machine.\n"
                    "`clear` lowers the stuck flag, and only once the admin tile has confirmed\n"
                    "the installed identity matches the recorded role.\n"
                    "`reclaim` asks the peer to stand down so a holder that restarted may take\n"
                    "the identity back, and runs on a spare whose peer also stands by.\n"
                    "\n"
                    "This command does not start a validator; it attaches to one that is already\n"
                    "running.  With no arguments it discovers the running validator automatically.\n"
                    "If multiple validators are running, pass --name to select one.\n",
  .usage          = "failover status|handoff|drill|demote|promote|pause|resume|clear|reclaim [--name <name>] [--peer <idx>] [--yes] [--force --staked-pubkey <base58>]",
  .args_help      = failover_args_help,
};
