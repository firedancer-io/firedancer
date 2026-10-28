#define _GNU_SOURCE
#include "adminctl_client.h"
#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"
#include "../../../discof/failover/fd_failover_proto.h"
#include "../../../disco/topo/fd_dns_resolve.h"
#include "../../../util/net/fd_ip4.h"
#include "../../../disco/keyguard/fd_keyload.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../../../ballet/ed25519/fd_ed25519.h"
#include "../../platform/fd_cap_chk.h"

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>

/* human-readable output string lookup tables */
static char const * const ACTION_NAMES[] = {
  "idle",
  "giving up the identity, switching to the junk key",
  "giving up the identity, waiting for the peer's answer",
  "taking the identity, waiting for replay",
  "taking the identity, waiting for vote history adoption",
  "taking the identity, switching to it",
  "taking the identity, requesting the final vote state",
  "taking the identity, waiting for the peer to record the handoff",
  "giving up the identity, waiting for the vote history stream to drain"
};
static char const * const SESSION_NAMES[] = {
  "listening", "dialing", "hello", "paired", "backoff"
};
static char const * const SOURCE_NAMES[] = {
  "the stored peer vote history", "an empty history (requires --force)"
};
static char const * const HANDOFF_NAMES[] = {
  "nothing handed over", "pending", "taken", "declined", "restarted", "cancelled by `failover promote --force`",
  "the dialed machine does not run the identity"
};

#define ACTION_NAME_CNT  ( sizeof(ACTION_NAMES )/sizeof(ACTION_NAMES [ 0 ]) )
#define SESSION_NAME_CNT ( sizeof(SESSION_NAMES)/sizeof(SESSION_NAMES[ 0 ]) )
#define SOURCE_NAME_CNT  ( sizeof(SOURCE_NAMES )/sizeof(SOURCE_NAMES [ 0 ]) )
#define HANDOFF_NAME_CNT ( sizeof(HANDOFF_NAMES)/sizeof(HANDOFF_NAMES[ 0 ]) )

FD_STATIC_ASSERT( ACTION_NAME_CNT ==FD_FAILOVER_ACTION_CNT,  action_names  );
FD_STATIC_ASSERT( SESSION_NAME_CNT==FD_FAILOVER_SESSION_CNT, session_names );
FD_STATIC_ASSERT( SOURCE_NAME_CNT ==FD_FAILOVER_SOURCE_CNT,  source_names  );
FD_STATIC_ASSERT( HANDOFF_NAME_CNT==FD_FAILOVER_HANDOFF_CNT, handoff_names );

static char const *
action_name( uchar action ) {
  return action<ACTION_NAME_CNT ? ACTION_NAMES[ action ] : "unknown";
}

/* other_holder is what this machine knows about the other machine running the identity */
static char const *
other_holder( ulong result ) {
  switch( result ) {
    case FD_FAILOVER_CONTROL_RESULT_INPUT_LOST:      return "unknown after input loss, failover requires a restart";
    case FD_FAILOVER_CONTROL_RESULT_WRONG_HOLDER:    return "N/A, this machine runs the identity";
    case FD_FAILOVER_CONTROL_RESULT_PEER_HOLDS:      return "the authenticated peer says it runs the identity";
    case FD_FAILOVER_CONTROL_RESULT_TAKEN:           return "the peer took our last handoff and may be voting";
    case FD_FAILOVER_CONTROL_RESULT_HANDOFF_PENDING: return "the peer has not answered our last handoff and may now be running the identity";
    case FD_FAILOVER_CONTROL_RESULT_STAKED_SEEN:     return "gossip showed the identity at another host within 15 seconds, it is probably voting there";
    case FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS:     return "unknown, a transition or key switch is currently in progress";
    case FD_ADMINCTL_RESULT_SUCCESS:                 return "none seen by this machine, the other machine may be stopped";
    default:                                         return "unknown";
  }
}

/* Strips key and its value. */
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

/* Fetch and parse CLI args (Helper). */
static void
failover_cmd_args( int *    pargc,
                   char *** pargv,
                   args_t * args,
                   int      status ) {
  char const * name    = strip_value( pargc, pargv, "--name"    );
  char const * address = strip_value( pargc, pargv, "--address" );
  char const * port    = strip_value( pargc, pargv, "--port"    );
  if( FD_UNLIKELY( name ) ) fd_cstr_ncpy( args->failover.name, name, sizeof(args->failover.name) );
  args->failover.yes   = fd_env_strip_cmdline_contains( pargc, pargv, "--yes"   );
  args->failover.force = fd_env_strip_cmdline_contains( pargc, pargv, "--force" );

  args->failover.cmd = (int)( status ? FD_ADMINCTL_FAILOVER_CMD_STATUS :
                              args->failover.force ? FD_ADMINCTL_FAILOVER_CMD_PROMOTE : FD_ADMINCTL_FAILOVER_CMD_HANDOFF );

  if( FD_UNLIKELY( args->failover.yes && args->failover.cmd==(int)FD_ADMINCTL_FAILOVER_CMD_STATUS ) ) {
    FD_LOG_ERR(( "--yes is only meaningful for `failover promote`" ));
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
    FD_LOG_ERR(( "--address `%s` is 0.0.0.0, provide the address of the machine running the identity", address ));
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
  if( !status && *pargc && ( (*pargv)[ 0 ][ 0 ]!='-' || !strcmp( (*pargv)[ 0 ], "-" ) ) ) {
    fd_cstr_ncpy( args->failover.keypair_path, (*pargv)[ 0 ], sizeof(args->failover.keypair_path) );
    (*pargc)--;
    (*pargv)++;
  }
}

static void
failover_args( int *    pargc,
               char *** pargv,
               args_t * args ) {
  if( FD_UNLIKELY( !*pargc || ( strcmp( (*pargv)[ 0 ], "promote" ) && strcmp( (*pargv)[ 0 ], "status" ) ) ) ) {
    FD_LOG_ERR(( "usage: firedancer failover <promote|status> [OPTIONS]" ));
  }
  int status = !strcmp( (*pargv)[ 0 ], "status" );
  (*pargc)--;
  (*pargv)++;
  failover_cmd_args( pargc, pargv, args, status );
}

/* The error string when a keypair other than the identity this machine runs is given */
static char const *
holds_target_name( char const * target_b58 ) {
  static char buf[ 192 ];
  FD_TEST( fd_cstr_printf_check( buf, sizeof(buf), NULL, "this machine runs `%s`, hand it off first, or pass --force to stop managing it here",
                                 target_b58 ? target_b58 : "the target identity" ) );
  return buf;
}


/* The installed identity relative to the target and the junk key. */
static char const *
installed_name( fd_adminctl_failover_status_resp_t const * resp ) {
  if( !memcmp( resp->installed, resp->target, 32UL ) ) return "the target";
  if( !memcmp( resp->installed, resp->junk,   32UL ) ) return "this machine's junk key";
  return "another key";
}

/* Prints the identity lines of a status */
static void
failover_identities_print( fd_adminctl_failover_status_resp_t const * resp ) {
  FD_BASE58_ENCODE_32_BYTES( resp->target,    target_b58    );
  FD_BASE58_ENCODE_32_BYTES( resp->installed, installed_b58 );
  FD_LOG_STDOUT(( "%-26s %s\n",      "target identity:",      target_b58 ));
  FD_LOG_STDOUT(( "%-26s %s (%s)\n", "installed identity:",   installed_b58, installed_name( resp ) ));
  FD_LOG_STDOUT(( "%-26s %s\n",      "runs target identity:", resp->holds ? "yes" : "no" ));
}

static void
failover_floor_print( fd_adminctl_failover_status_resp_t const * resp ) {
  if( FD_UNLIKELY( resp->promote_floor==FD_FAILOVER_SLOT_NULL ) ) FD_LOG_STDOUT(( "%-26s none known\n", "coverage floor:" ));
  else                                                            FD_LOG_STDOUT(( "%-26s slot %lu\n", "coverage floor:", resp->promote_floor ));
}

static void
failover_confirm( args_t const *                             args,
                  fd_adminctl_failover_status_resp_t const * status ) {
  if( args->failover.cmd==(int)FD_ADMINCTL_FAILOVER_CMD_PROMOTE ) {
    if( FD_LIKELY( status ) ) {
      failover_identities_print( status );
      FD_LOG_STDOUT(( "%-26s %s\n", "other holder:", other_holder( status->promote_result ) ));
      failover_floor_print( status );
      FD_LOG_STDOUT(( "force only at most one machine at a time.\n" ));
    }
    FD_LOG_STDOUT(( "This takes the identity upon your command.  No other machine may run it or be in a\n"
                    "promotion, including any validator running this identity without failover.\n"
                    "Run `failover status` on the other machine. It must show `runs target identity: no`\n"
                    "with no promotion in progress, or that machine must be stopped or otherwise\n"
                    "unable to vote.  Never promote both machines at once.\n"
                    "WARNING: --force skips every check on the other machine.  Use it only when the\n"
                    "other machine is not signing votes, or both machines may double-vote.\n"
                    "Promotion tries eligible saved vote history first, then starts from an EMPTY\n"
                    "history with a bound covering replay and known votes.  Missing votes and leader\n"
                    "windows above that bound remain unprotected.\n" ));
  }
  if( FD_UNLIKELY( !args->failover.yes && isatty( STDIN_FILENO ) ) ) {
    if( args->failover.cmd==(int)FD_ADMINCTL_FAILOVER_CMD_HANDOFF ) {
      FD_LOG_STDOUT(( "This asks the remote validator running this identity to hand it to this machine.  It keeps\n"
                      "the identity if this machine is more than 64 slots behind its finality anchor.\n"
                      "Otherwise, it gives up the identity before this validator adopts its history.\n"
                      "If replay stalls, the handoff can fail with neither machine voting.\n"
                      "Check that this machine is caught up.  Type yes to continue: " ));
    } else {
      FD_LOG_STDOUT(( "Type yes to continue: " ));
    }
    char line[ 16 ] = {0};
    if( FD_UNLIKELY( !fgets( line, sizeof(line), stdin ) ) ) FD_LOG_ERR(( "no confirmation given" ));
    if( FD_UNLIKELY( strcmp( line, "yes\n" ) ) ) FD_LOG_ERR(( "not confirmed, nothing was done" ));
  }
}

/* Prints the response to `failover status`. */
static void
failover_status_print( fd_adminctl_failover_status_resp_t const * resp ) {
  if( FD_UNLIKELY( !resp->enabled ) ) {
    FD_LOG_STDOUT(( "%-26s %s\n", "failover:", "disabled" ));
    return;
  }

  FD_LOG_STDOUT(( "%-26s %s\n", "failover:", "enabled" ));
  failover_identities_print( resp );
  FD_BASE58_ENCODE_32_BYTES( resp->junk, junk_b58 );
  FD_LOG_STDOUT(( "%-26s %s\n", "junk key:", junk_b58 ));
  if( FD_UNLIKELY( resp->request_paused ) ) {
    FD_LOG_STDOUT(( "%-26s %s, paused at its deadline, `failover promote` resumes it\n", "action:", action_name( resp->action ) ));
  } else {
    FD_LOG_STDOUT(( "%-26s %s\n", "action:", action_name( resp->action ) ));
  }
  FD_LOG_STDOUT(( "%-26s %s\n", "stuck:",  !resp->stuck ? "no" : resp->request_paused ? "yes, the handoff request is paused, see the log" : "yes, see the log" ));
  FD_LOG_STDOUT(( "%-26s %s\n", "link:",   resp->link_state<SESSION_NAME_CNT ? SESSION_NAMES[ resp->link_state ] : "unknown" ));
  FD_LOG_STDOUT(( "%-26s %s\n", "peer runs target identity:", !resp->peer_holds_valid ? "unknown, no authenticated failover session" : resp->peer_holds ? "yes" : "no" ));
  if( FD_UNLIKELY( !resp->peer_boot_id ) ) FD_LOG_STDOUT(( "%-26s none paired since boot\n", "peer boot id:" ));
  else                                     FD_LOG_STDOUT(( "%-26s %016lx\n", "peer boot id:", resp->peer_boot_id ));
  if( FD_UNLIKELY( !resp->peer_addr && resp->holds ) ) {
    FD_LOG_STDOUT(( "%-26s n/a, this machine runs the identity\n", "peer address:" ));
  } else if( FD_UNLIKELY( !resp->peer_addr ) ) {
    FD_LOG_STDOUT(( "%-26s unknown, gossip has no contact info for the identity from another host\n", "peer address:" ));
  } else {
    FD_LOG_STDOUT(( "%-26s " FD_IP4_ADDR_FMT ":%u, from %s\n", "peer address:", FD_IP4_ADDR_FMT_ARGS( resp->peer_addr ), (uint)resp->peer_port,
                    resp->peer_addr_cmd ? "--address" : "gossip" ));
  }

  if( FD_UNLIKELY( !resp->handoff_id ) ) {
    FD_LOG_STDOUT(( "%-26s none since boot\n", "last handoff:" ));
  } else {
    FD_LOG_STDOUT(( "%-26s %lu, %s\n", "last handoff:", resp->handoff_id,
                    resp->handoff_result<HANDOFF_NAME_CNT ? HANDOFF_NAMES[ resp->handoff_result ] : "unknown" ));
  }

  FD_LOG_STDOUT(( "%-26s %s\n", "other holder:", other_holder( resp->promote_result ) ));
  FD_LOG_STDOUT(( "%-26s %s\n", "takeover adopts:",
                  resp->promote_source<SOURCE_NAME_CNT ? SOURCE_NAMES[ resp->promote_source ] : "unknown" ));
  failover_floor_print( resp );
}

static uchar const * FD_FN_SENSITIVE
failover_keypair_load( char const * path ) {
  if( FD_LIKELY( strcmp( path, "-" ) ) ) return fd_keyload_load( path, 0 );
  int fd = dup( STDIN_FILENO );
  if( FD_UNLIKELY( -1==fd ) ) FD_LOG_ERR(( "dup(stdin) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  uchar * keypair = fd_keyload_alloc_protected_pages( 1UL, 2UL );
  FD_LOG_STDOUT(( "Reading identity keypair from stdin.  Press Ctrl-D when done.\n" ));
  fd_keyload_read( fd, "stdin", keypair );
  return fd_keyload_mprotect_ro( keypair, 0 );
}

/* Sends req to the failover tile via adminctl and waits for the response.  Returns the adminctl result. */
static ulong FD_FN_SENSITIVE
failover_request( fd_adminctl_t *                    adminctl,
                  fd_adminctl_failover_req_t const * req,
                  uchar const *                      keypair,
                  void *                             resp,
                  ulong                              resp_max,
                  ulong *                            resp_sz ) {
  void * payload     = NULL;
  ulong  payload_max = 0UL;
  ulong  slot_idx    = fd_adminctl_reserve( adminctl, &payload, &payload_max );
  if( FD_UNLIKELY( slot_idx==ULONG_MAX ) ) FD_LOG_ERR(( "all admin command slots are busy" ));
  ulong payload_sz = keypair ? sizeof(fd_adminctl_failover_prepare_t) : sizeof(*req);
  if( FD_UNLIKELY( payload_sz>payload_max ) ) FD_LOG_ERR(( "adminctl failover payload too large" ));
  fd_memcpy( payload, req, sizeof(*req) );
  if( keypair ) fd_memcpy( ((fd_adminctl_failover_prepare_t *)payload)->keypair, keypair, 64UL );
  ulong cmd = req->cmd==FD_ADMINCTL_FAILOVER_CMD_STATUS ? FD_ADMINCTL_CMD_FAILOVER_STATUS : FD_ADMINCTL_CMD_FAILOVER_PROMOTE;
  fd_adminctl_publish( adminctl, slot_idx, cmd, payload_sz );
  return fd_adminctl_wait_response( adminctl, slot_idx, resp, resp_max, resp_sz );
}

static void __attribute__((noreturn))
fail_disabled( int status ) {
  if( status ) FD_LOG_ERR(( "`failover status` is unavailable because this validator has no failover command bus" ));
  FD_LOG_ERR(( "failover is not running on this validator, set [failover.enabled] to true and restart it" ));
}

static void __attribute__((noreturn))
fail_incompatible( void ) {
  FD_LOG_ERR(( "running validator returned an incompatible failover response, use the firedancer binary the validator runs" ));
}

/* failover_status_fetch reads the live `failover status` into status.
   Returns 1 when it is valid, 0 when the validator gave no usable
   answer. */
static int
failover_status_fetch( fd_adminctl_t *                      adminctl,
                       fd_adminctl_failover_status_resp_t * status ) {
  fd_adminctl_failover_req_t req       = { .version=FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION, .cmd=FD_ADMINCTL_FAILOVER_CMD_STATUS };
  ulong                      status_sz = 0UL;
  ulong                      result    = failover_request( adminctl, &req, NULL, status, sizeof(*status), &status_sz );
  if( FD_UNLIKELY( result==FD_ADMINCTL_RESULT_UNKNOWN_COMMAND ) ) fail_disabled( 0 );
  if( FD_UNLIKELY( result!=FD_ADMINCTL_RESULT_SUCCESS || status_sz!=sizeof(*status) ||
                   status->version!=FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION ) ) return 0;
  if( FD_UNLIKELY( !status->enabled ) ) fail_disabled( 0 );
  return 1;
}

/* Run sanity checks before invoking failover. */
static void FD_FN_SENSITIVE
failover_precheck( fd_adminctl_failover_status_resp_t const * status,
                   args_t const *                             args,
                   uchar const *                              keypair ) {
  char const * cmd_name = fd_adminctl_failover_cmd_typed( (ulong)args->failover.cmd );
  if( keypair ) {
    uchar       pubkey[ 32 ];
    fd_sha512_t sha512[ 1 ];
    FD_TEST( fd_sha512_join( fd_sha512_new( sha512 ) ) );
    fd_ed25519_public_from_private( pubkey, keypair, sha512 );
    int same = !memcmp( pubkey, status->target, 32UL );
    if( FD_UNLIKELY( same && status->holds ) ) {
      FD_LOG_ERR(( "`%s` refused, %s", cmd_name, fd_adminctl_failover_result_cstr( FD_FAILOVER_CONTROL_RESULT_WRONG_HOLDER ) ));
    }
    if( FD_UNLIKELY( !same && status->holds && status->promote_floor!=FD_FAILOVER_SLOT_NULL && !args->failover.force ) ) {
      FD_BASE58_ENCODE_32_BYTES( status->target, target_b58 );
      FD_LOG_ERR(( "`%s` refused, %s", cmd_name, holds_target_name( target_b58 ) ));
    }
    if( FD_UNLIKELY( !same && status->action!=FD_FAILOVER_ACTION_IDLE && !args->failover.force ) ) {
      FD_LOG_ERR(( "`%s` refused, a transition is running, wait for `failover status` to show idle or pass --force", cmd_name ));
    }
    return;
  }
  if( FD_UNLIKELY( status->holds &&
                   !( args->failover.cmd==(int)FD_ADMINCTL_FAILOVER_CMD_HANDOFF &&
                      status->request_paused && status->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT ) ) ) {
    FD_LOG_ERR(( "`%s` refused, %s", cmd_name, fd_adminctl_failover_result_cstr( FD_FAILOVER_CONTROL_RESULT_WRONG_HOLDER ) ));
  }
}

/* Send the command to the failover tile and print the result. */
static void
failover_cmd_fn( args_t *   args,
                 config_t * config ) {
  fd_adminctl_t * adminctl = adminctl_client_attach( config, args->failover.name );
  uchar const *   keypair  = args->failover.keypair_path[ 0 ] ? failover_keypair_load( args->failover.keypair_path ) : NULL;
  /* run prechecks on the current status */
  int             status   = args->failover.cmd==(int)FD_ADMINCTL_FAILOVER_CMD_STATUS;
  if( !status ) {
    fd_adminctl_failover_status_resp_t live;
    int                                live_ok = failover_status_fetch( adminctl, &live );
    if( live_ok && !args->failover.yes && isatty( STDIN_FILENO ) ) failover_precheck( &live, args, keypair );
    failover_confirm( args, live_ok ? &live : NULL );
  }

  /* fetch args */
  fd_adminctl_failover_req_t req;
  fd_memset( &req, 0, sizeof(req) );
  req.version = FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION;
  req.cmd     = (ulong)args->failover.cmd;
  if( FD_UNLIKELY( args->failover.yes   ) ) req.flags |= FD_ADMINCTL_FAILOVER_FLAG_YES;
  if( FD_UNLIKELY( args->failover.force ) ) req.flags |= FD_ADMINCTL_FAILOVER_FLAG_FORCE;
  req.addr = args->failover.addr;
  req.port = args->failover.port;

  union {
    fd_adminctl_failover_control_resp_t control;
    fd_adminctl_failover_status_resp_t  status;
  } resp = { 0 };
  ulong        resp_sz  = 0UL;

  /* run the command */
  ulong        result   = failover_request( adminctl, &req, keypair, &resp, sizeof(resp), &resp_sz );
  char const * cmd_name = fd_adminctl_failover_cmd_typed( (ulong)args->failover.cmd );
  if( keypair ) fd_keyload_unload( keypair, 0 );
  int refused = result>=FD_FAILOVER_CONTROL_RESULT_WRONG_HOLDER || result==FD_SET_IDENTITY_RESULT_KEYPAIR_MISMATCH || result==FD_SET_IDENTITY_RESULT_AUTHORIZED_VOTER;

  if( FD_UNLIKELY( refused ) ) FD_LOG_ERR(( "`%s` refused, %s", cmd_name, fd_adminctl_failover_result_cstr( result ) ));

  /* show the result */
  switch( result ) {
    case FD_ADMINCTL_RESULT_SUCCESS:
      if( FD_UNLIKELY( resp_sz!=(status ? sizeof(resp.status) : sizeof(resp.control)) ||
                       (status ? resp.status.version : resp.control.version)!=FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION ||
                       (status && resp.status.mode!=FD_FAILOVER_MODE_ALPENGLOW) ) ) {
        fail_incompatible();
      }
      if( status ) {
        failover_status_print( &resp.status );
      } else {
        ulong id = resp.control.handoff_id;
        FD_LOG_STDOUT(( "%-26s accepted\n", cmd_name ));
        FD_LOG_STDOUT(( "%-26s %s\n", "runs target identity:", resp.control.holds ? "yes" : "no" ));
        FD_LOG_STDOUT(( "%-26s %s\n", "action:", action_name( resp.control.action ) ));
        if( args->failover.cmd==(int)FD_ADMINCTL_FAILOVER_CMD_HANDOFF ) {
          FD_LOG_STDOUT(( "%-26s %lu, done when `failover status` here shows runs target identity: yes and last handoff: %lu, taken\n", "handoff:", id, id ));
        } else {
          FD_LOG_STDOUT(( "%-26s done when `failover status` here shows runs target identity: yes and action: idle\n", "promotion:" ));
        }
      }
      break;
    case FD_FAILOVER_CONTROL_RESULT_BUSY:
      FD_LOG_ERR(( "another failover command is in flight, try again" ));
    case FD_FAILOVER_CONTROL_RESULT_UNRESPONSIVE:
      if( status ) FD_LOG_ERR(( "the validator's failover tile did not answer in time" ));
      FD_LOG_ERR(( "the validator's failover tile did not answer in time, the outcome is unknown, check `failover status`" ));
    case FD_ADMINCTL_RESULT_UNKNOWN_COMMAND:
      if( status ) {
        FD_LOG_STDOUT(( "%-26s %s\n", "failover:", "disabled" ));
        break;
      }
      fail_disabled( 0 );
    case FD_ADMINCTL_RESULT_UNSUPPORTED:
      fail_disabled( status );
    case FD_ADMINCTL_RESULT_ABI_VERSION_MISMATCH:
    case FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH:
      FD_LOG_ERR(( "failover is incompatible with the running validator, use the same firedancer version this validator runs" ));
    default:
      FD_LOG_ERR(( "unexpected failover result %lu", result ));
  }
}

static void
failover_status_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "--name",           "<name>",    "Name of the validator instance to attach to, if more than one is\n"
                                                             "running on this host" );
}

static void
failover_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "<promote|status>", NULL,        "Request failover takeover on this validator (promote), or read its failover state (status)." );
  fd_action_help_arg( help, "[<keypair>]",      NULL,        "Path to the keypair of the identity to take, in the standard Solana keypair\n"
                                                             "file format (the 64-byte JSON array), or `-` to read it from stdin.  Defaults\n"
                                                             "to [paths.identity_key] or the last keypair given to `failover promote` or\n"
                                                             "`set-identity`." );
  failover_status_args_help( help );
  fd_action_help_arg( help, "--yes",            NULL,        "Bypass the interactive confirmation prompt." );
  fd_action_help_arg( help, "--force",          NULL,        "Forcibly take the identity without asking the machine running it, skipping every\n"
                                                             "check.  Only use when the other machine cannot vote.\n" );
  fd_action_help_arg( help, "--address",        "<address>", "Only without --force.  The target machine's IPv4 address or host name" );
  fd_action_help_arg( help, "--port",           "<port>",    "Only without --force.  The target machine's failover port, 8010 by default" );
}

static void
failover_promote_perm( args_t *         args,
                       fd_cap_chk_t *   chk,
                       config_t const * config FD_PARAM_UNUSED ) {
  if( args->failover.keypair_path[ 0 ] ) {
    fd_cap_chk_raise_rlimit( chk, "failover promote", RLIMIT_MEMLOCK, 5UL*FD_SHMEM_NORMAL_PAGE_SZ,
                             "lock the target keypair in memory" );
  }
}

action_t fd_action_failover = {
  .name           = "failover",
  .args           = failover_args,
  .fn             = failover_cmd_fn,
  .require_config = 0,
  .perm           = failover_promote_perm,
  .description    = "Take the identity that another validator runs or read the failover status",
  .detail         = "Hands off an identity between validators.  Each boots under its own\n"
                    "[paths.identity_key], and all validators must use the same [paths.vote_account].\n"
                    "On the machine that should take over, pass the keypair of the target identity.\n"
                    "A validator with [failover.boot_to_standby] boots as a standby under a junk key\n"
                    "generated in memory and loads the keypair in its [paths.identity_key] as the\n"
                    "identity to take over, so `failover promote` there reads the keypair from the\n"
                    "configuration instead of the command line.\n"
                    "\n"
                    "Asks the machine running the identity to hand it over.  With --force,\n"
                    "takes the identity without handover.\n"
                    "This command asks for confirmation unless --yes is given.\n"
                    "Use `failover status` to check handover progress.\n"
                    "\n"
                    "This command does not start a validator. It attaches to one that is already\n"
                    "running.  If multiple validators are running, pass --name to select one.\n",
  .usage          = "failover promote [<keypair>] [--name <name>] [--yes] [--force] [--address <address>] [--port <port>]\n"
                    "       firedancer failover status [--name <name>]",
  .args_help      = failover_args_help,
};
