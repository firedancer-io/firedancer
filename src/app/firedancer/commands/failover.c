#define _GNU_SOURCE
#include "adminctl_client.h"
#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"
#include "../../../discof/admin/fd_adminctl.h"
#include "../../../disco/topo/fd_dns_resolve.h"
#include "../../../disco/keyguard/fd_keyload.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../../../ballet/ed25519/fd_ed25519.h"
#include "../../../util/net/fd_ip4.h"
#include "../../platform/fd_cap_chk.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>

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
failover_args( int *    pargc,
               char *** pargv,
               args_t * args ) {
  if( FD_UNLIKELY( !*pargc || ( strcmp( (*pargv)[ 0 ], "promote" ) && strcmp( (*pargv)[ 0 ], "takeover" ) ) ) ) {
    FD_LOG_ERR(( "usage: firedancer failover <promote|takeover> [<keypair>] [OPTIONS]" ));
  }
  args->failover.takeover = !strcmp( (*pargv)[ 0 ], "takeover" );
  (*pargc)--;
  (*pargv)++;
  char const * name    = strip_value( pargc, pargv, "--name"    );
  char const * address = strip_value( pargc, pargv, "--address" );
  char const * port    = strip_value( pargc, pargv, "--port"    );
  if( FD_UNLIKELY( name ) ) fd_cstr_ncpy( args->failover.name, name, sizeof(args->failover.name) );
  args->failover.yes   = fd_env_strip_cmdline_contains( pargc, pargv, "--yes"   );
  args->failover.force = fd_env_strip_cmdline_contains( pargc, pargv, "--force" );

  if( FD_UNLIKELY( args->failover.force && !args->failover.takeover ) ) {
    FD_LOG_ERR(( "--force goes with `failover takeover`, `failover promote` hands the identity over cleanly" ));
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
  if( *pargc && ( (*pargv)[ 0 ][ 0 ]!='-' || !strcmp( (*pargv)[ 0 ], "-" ) ) ) {
    fd_cstr_ncpy( args->failover.keypair_path, (*pargv)[ 0 ], sizeof(args->failover.keypair_path) );
    (*pargc)--;
    (*pargv)++;
  }
}

static void
failover_confirm( args_t const * args ) {
  if( args->failover.force ) {
    FD_LOG_STDOUT(( "This asks the machine running the identity to hand it over.  If that fails for any\n"
                    "reason, this machine takes the identity anyway.\n"
                    "WARNING: --force skips every check on the other machine, which may still run the\n"
                    "identity.  Use it only when that machine is not signing votes, or both machines\n"
                    "may double-vote.  Never take over on both machines at once.\n" ));
  } else if( args->failover.takeover ) {
    FD_LOG_STDOUT(( "This asks the machine running the identity to hand it over.  If that fails and\n"
                    "the other machine shows no signs of life, neither in gossip for 15 seconds nor on\n"
                    "the failover channel, this machine takes the identity anyway.\n"
                    "WARNING: a takeover skips the checks on the other machine.  A machine that is only\n"
                    "cut off from this one may still sign votes, and both machines may double-vote.\n" ));
  }
  if( FD_UNLIKELY( !args->failover.yes && isatty( STDIN_FILENO ) ) ) {
    if( !args->failover.takeover ) {
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

/* Prints a step of the command as the failover tile takes it. */
static void
failover_print_step( char const * step ) {
  FD_LOG_NOTICE(( "%s", step ));
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

/* Sends req to the failover tile via adminctl and waits for the answer.
   Returns the adminctl result, along with the identity this machine will
   use afterwards in resp. */
static ulong FD_FN_SENSITIVE
failover_request( fd_adminctl_t *                    adminctl,
                  fd_adminctl_failover_req_t const * req,
                  uchar const *                      keypair,
                  fd_adminctl_failover_resp_t *      resp ) {
  void * payload     = NULL;
  ulong  payload_max = 0UL;
  ulong  slot_idx    = fd_adminctl_reserve( adminctl, &payload, &payload_max );
  if( FD_UNLIKELY( slot_idx==ULONG_MAX ) ) FD_LOG_ERR(( "all admin command slots are busy" ));
  ulong payload_sz = keypair ? sizeof(fd_adminctl_failover_prepare_t) : sizeof(*req);
  if( FD_UNLIKELY( payload_sz>payload_max ) ) FD_LOG_ERR(( "adminctl failover payload too large" ));
  fd_memcpy( payload, req, sizeof(*req) );
  if( keypair ) fd_memcpy( ((fd_adminctl_failover_prepare_t *)payload)->keypair, keypair, 64UL );

  fd_adminctl_publish( adminctl, slot_idx, FD_ADMINCTL_CMD_FAILOVER_PROMOTE, payload_sz );
  ulong resp_sz = 0UL;
  ulong result  = fd_adminctl_wait_steps( adminctl, slot_idx, resp, sizeof(*resp), &resp_sz, failover_print_step );
  if( FD_UNLIKELY( resp_sz!=sizeof(*resp) || resp->version!=FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION ) ) fd_memset( resp, 0, sizeof(*resp) );
  return result;
}

/* Exit codes. */

#define FAILOVER_EXIT_OTHER   (1) /* any other failure, as FD_LOG_ERR exits */
#define FAILOVER_EXIT_REFUSED (2) /* refused, no validator changed identity */
#define FAILOVER_EXIT_UNKNOWN (3) /* the outcome is unknown */
#define FAILOVER_EXIT_NOBODY  (4) /* nobody runs the identity */

struct failover_result {
  ulong        result;
  char const * name;
  char const * meaning;
  int          exit_code;
  int          takeover;
};
typedef struct failover_result failover_result_t;

static failover_result_t const failover_results[] = {
  { FD_FAILOVER_CONTROL_RESULT_BUSY,              "busy",              "another failover command is running on the local validator",                                      FAILOVER_EXIT_REFUSED, 0 },
  { FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS,       "in_progress",       "a handoff or identity switch is running on the local or the remote validator",                    FAILOVER_EXIT_REFUSED, 0 },
  { FD_FAILOVER_CONTROL_RESULT_NO_HOLDER_ADDRESS, "no_holder_address", "gossip did not show a validator running the identity",                                            FAILOVER_EXIT_REFUSED, 1 },
  { FD_FAILOVER_CONTROL_RESULT_NOT_HOLDER,        "not_holder",        "the validator at the address does not run the identity",                                          FAILOVER_EXIT_REFUSED, 1 },
  { FD_FAILOVER_CONTROL_RESULT_NO_PEER,           "no_peer",           "no validator running the identity answered at the address before the deadline",                   FAILOVER_EXIT_REFUSED, 1 },
  { FD_FAILOVER_CONTROL_RESULT_HANDED_OFF,        "handed_off",        "the local validator handed the identity off and waits for the remote validator's answer",         FAILOVER_EXIT_REFUSED, 1 },
  { FD_FAILOVER_CONTROL_RESULT_NO_FINAL_HISTORY,  "no_final_history",  "the remote validator has no vote history for its last vote yet",                                  FAILOVER_EXIT_REFUSED, 1 },
  { FD_FAILOVER_CONTROL_RESULT_REPLAY_BEHIND,     "replay_behind",     "the local validator's replay is too far behind the finality anchor of the vote history to adopt", FAILOVER_EXIT_REFUSED, 1 },
  { FD_FAILOVER_CONTROL_RESULT_HOLDS_OTHER,       "holds_other",       "the local validator runs a staked identity other than the one in the keypair",                    FAILOVER_EXIT_REFUSED, 0 },
  { FD_FAILOVER_CONTROL_RESULT_HOLDER_LIVE,       "holder_live",       "the remote validator may still be live",                                                          FAILOVER_EXIT_REFUSED, 0 },
  { FD_SET_IDENTITY_RESULT_KEYPAIR_MISMATCH,      "keypair_mismatch",  "the public key in the keypair file does not match its private key",                               FAILOVER_EXIT_REFUSED, 0 },
  { FD_SET_IDENTITY_RESULT_AUTHORIZED_VOTER,      "authorized_voter",  "the identity is an authorized voter on the local validator",                                      FAILOVER_EXIT_REFUSED, 0 },
  { FD_FAILOVER_CONTROL_RESULT_TIMEOUT,           "timeout",           "the remote validator did not answer before the deadline",                                         FAILOVER_EXIT_UNKNOWN, 1 },
  { FD_FAILOVER_CONTROL_RESULT_PEER_RESTARTED,    "peer_restarted",    "the remote validator restarted before it answered",                                               FAILOVER_EXIT_UNKNOWN, 1 },
  { FD_FAILOVER_CONTROL_RESULT_HANDOFF_ABORTED,   "handoff_aborted",   "the remote validator aborted the handoff and may have given up the identity",                     FAILOVER_EXIT_UNKNOWN, 1 },
  { FD_FAILOVER_CONTROL_RESULT_PEER_HOLDS,        "peer_holds",        "another validator runs the identity",                                                             FAILOVER_EXIT_UNKNOWN, 1 },
  { FD_FAILOVER_CONTROL_RESULT_IDENTITY_CHANGED,  "identity_changed",  "set-identity changed the local validator's identity while the command ran",                       FAILOVER_EXIT_UNKNOWN, 0 },
  { FD_FAILOVER_CONTROL_RESULT_ADOPTION_FAILED,   "adoption_failed",   "the local validator did not adopt the vote history",                                              FAILOVER_EXIT_NOBODY,  1 },
  { FD_FAILOVER_CONTROL_RESULT_SWITCH_FAILED,     "switch_failed",     "the local validator's identity switch failed",                                                    FAILOVER_EXIT_NOBODY,  1 },
};

static failover_result_t const *
failover_result_find( ulong result ) {
  for( ulong i=0UL; i<sizeof(failover_results)/sizeof(failover_results[0]); i++ ) {
    if( failover_results[ i ].result==result ) return &failover_results[ i ];
  }
  return NULL;
}

#define FD_LOG_ERR_NOEXIT(a) do {                                       \
    long _fd_log_msg_now = fd_log_wallclock();                          \
    fd_log_private_1( 4, _fd_log_msg_now, __FILE__, __LINE__, __func__, \
                      fd_log_private_0 a );                             \
  } while(0)

/* The command as the operator typed it. */
static char const *
failover_cmd_name( args_t const * args ) {
  return !args->failover.takeover ? "failover promote" : args->failover.force ? "failover takeover --force" : "failover takeover";
}

/* The exit code for a failed command. */
static int
failover_exit_code( ulong result,
                    ulong handoff ) {
  int code = failover_result_find( result )->exit_code;
  if( handoff!=FD_ADMINCTL_RESULT_SUCCESS && handoff!=FD_FAILOVER_CONTROL_RESULT_HANDED_OFF && result!=FD_FAILOVER_CONTROL_RESULT_IDENTITY_CHANGED ) {
    code = failover_result_find( handoff )->exit_code;
  }
  return code;
}

static void __attribute__((noreturn))
fail_result( char const * cmd,
             ulong        result,
             ulong        handoff ) {
  switch( result ) {
    case FD_ADMINCTL_RESULT_UNKNOWN_COMMAND:
    case FD_ADMINCTL_RESULT_UNSUPPORTED:
    case FD_ADMINCTL_RESULT_ABI_VERSION_MISMATCH:
    case FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH:
      FD_LOG_ERR(( "this command is incompatible with the running validator" ));
    default:
      break;
  }
  failover_result_t const * row = failover_result_find( result );
  if( FD_UNLIKELY( !row ) ) {
    FD_LOG_ERR_NOEXIT(( "`%s` failed with result %#lx, check both validators with `firedancer get-identity`", cmd, result ));
    exit( FAILOVER_EXIT_OTHER );
  }
  int code = failover_exit_code( result, handoff );
  char const * state = code==FAILOVER_EXIT_REFUSED ? "no validator changed identity" :
                       code==FAILOVER_EXIT_NOBODY  ? "nobody runs the identity" :
                                                     "the outcome is unknown, check both validators with `firedancer get-identity`";
  FD_LOG_ERR_NOEXIT(( "`%s` failed (%s), %s, %s", cmd, row->name, row->meaning, state ));
  exit( code );
}

/* Run sanity checks before invoking failover. */
static void FD_FN_SENSITIVE
failover_preflight( fd_adminctl_t * adminctl,
                    args_t const *  args,
                    uchar const *   keypair ) {
  fd_adminctl_failover_req_t req = { .version=FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION, .cmd=FD_ADMINCTL_FAILOVER_CMD_PREFLIGHT };
  if( FD_UNLIKELY( args->failover.takeover ) ) req.flags |= FD_ADMINCTL_FAILOVER_FLAG_TAKEOVER;
  if( FD_UNLIKELY( args->failover.force    ) ) req.flags |= FD_ADMINCTL_FAILOVER_FLAG_FORCE;
  fd_sha512_t sha512[ 1 ];
  FD_TEST( fd_sha512_join( fd_sha512_new( sha512 ) ) );
  fd_ed25519_public_from_private( req.target, keypair, sha512 );
  fd_adminctl_failover_resp_t resp;
  ulong result = failover_request( adminctl, &req, NULL, &resp );
  if( FD_UNLIKELY( result!=FD_ADMINCTL_RESULT_SUCCESS ) ) fail_result( failover_cmd_name( args ), result, FD_ADMINCTL_RESULT_SUCCESS );
}

/* Asks the failover tile for the handoff and waits for its outcome. */
static void
failover_cmd_fn( args_t *   args,
                 config_t * config ) {
  fd_adminctl_t * adminctl = adminctl_client_attach( config, args->failover.name );
  char const *    cmd      = failover_cmd_name( args );
  uchar const *   keypair  = args->failover.keypair_path[ 0 ] ? failover_keypair_load( args->failover.keypair_path ) : NULL;
  if( keypair ) failover_preflight( adminctl, args, keypair );
  failover_confirm( args );

  fd_adminctl_failover_req_t req;
  fd_memset( &req, 0, sizeof(req) );
  req.version = FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION;
  req.cmd     = FD_ADMINCTL_FAILOVER_CMD_HANDOFF;
  if( FD_UNLIKELY( args->failover.yes      ) ) req.flags |= FD_ADMINCTL_FAILOVER_FLAG_YES;
  if( FD_UNLIKELY( args->failover.takeover ) ) req.flags |= FD_ADMINCTL_FAILOVER_FLAG_TAKEOVER;
  if( FD_UNLIKELY( args->failover.force    ) ) req.flags |= FD_ADMINCTL_FAILOVER_FLAG_FORCE;
  req.addr = args->failover.addr;
  req.port = args->failover.port;

  char const * bold   = fd_log_style_bold();
  char const * normal = fd_log_style_normal();
  if( args->failover.addr ) {
    FD_LOG_NOTICE(( "requesting handoff of the identity from peer `" FD_IP4_ADDR_FMT ":%hu`", FD_IP4_ADDR_FMT_ARGS( args->failover.addr ),
                    (ushort)( args->failover.port ? args->failover.port : 8010 ) ));
  } else {
    FD_LOG_NOTICE(( "requesting handoff of the identity from the peer running it in gossip" ));
  }

  fd_adminctl_failover_resp_t resp;
  ulong result  = failover_request( adminctl, &req, keypair, &resp );
  ulong handoff = FD_ADMINCTL_RESULT_SUCCESS;

  failover_result_t const * failed = failover_result_find( result );
  if( FD_UNLIKELY( failed && failed->takeover && args->failover.takeover ) ) {
    FD_LOG_WARNING(( "the handoff failed (%s), %s", failed->name, failed->meaning ));
    handoff = result;
    if( args->failover.force ) FD_LOG_NOTICE(( "taking the identity without the other machine, --force skips all checks" ));
    else                       FD_LOG_NOTICE(( "taking the identity if the other machine shows no signs of life" ));

    req.cmd   = FD_ADMINCTL_FAILOVER_CMD_PROMOTE;
    req.flags = req.flags & (FD_ADMINCTL_FAILOVER_FLAG_YES|FD_ADMINCTL_FAILOVER_FLAG_TAKEOVER|FD_ADMINCTL_FAILOVER_FLAG_FORCE);
    req.addr  = 0U;
    req.port  = (ushort)0;
    if( keypair ) fd_memcpy( req.target, keypair+32UL, 32UL );
    result    = failover_request( adminctl, &req, NULL, &resp );
  }
  if( keypair ) fd_keyload_unload( keypair, 0 );

  int already = result==FD_FAILOVER_CONTROL_RESULT_ALREADY_HOLDS;
  if( FD_UNLIKELY( result!=FD_ADMINCTL_RESULT_SUCCESS && !already ) ) fail_result( cmd, result, handoff );
  if( FD_UNLIKELY( !resp.version ) ) {
    FD_LOG_ERR_NOEXIT(( "`%s` returned an incompatible response", cmd ));
    exit( FAILOVER_EXIT_OTHER );
  }
  FD_BASE58_ENCODE_32_BYTES( resp.identity, identity_b58 );
  if( FD_UNLIKELY( already ) ) {
    FD_LOG_NOTICE(( "the local validator already runs the identity %s%s%s", bold, identity_b58, normal ));
    return;
  }
  if( resp.slot==ULONG_MAX ) FD_LOG_NOTICE(( "promotion success (identity now %s%s%s, no earlier vote)", bold, identity_b58, normal ));
  else                       FD_LOG_NOTICE(( "promotion success (identity now %s%s%s at slot %lu)", bold, identity_b58, normal, resp.slot ));
}

static void
failover_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "promote",     NULL,        "Ask the machine running the identity to hand it over to this validator and\n"
                                                        "wait for the result.  For planned switches, the other machine must be up." );
  fd_action_help_arg( help, "takeover",    NULL,        "Like promote, but if the handoff fails and the machine running the identity\n"
                                                        "shows no signs of life, take the identity without it, from an empty vote\n"
                                                        "history.  Use when that machine is down or unreachable." );
  fd_action_help_arg( help, "[<keypair>]", NULL,        "Path to the keypair of the identity to take, in the standard Solana keypair\n"
                                                        "file format (the 64-byte JSON array), or `-` to read it from stdin.  Defaults\n"
                                                        "to [paths.identity_key] or the last keypair given to `failover` or\n"
                                                        "`set-identity`." );
  fd_action_help_arg( help, "--name",      "<name>",    "Name of the validator instance to attach to, if more than one is\n"
                                                        "running on this host" );
  fd_action_help_arg( help, "--yes",       NULL,        "Bypass the interactive confirmation prompt." );
  fd_action_help_arg( help, "--force",     NULL,        "takeover only.  Take the identity even if the machine running it still shows\n"
                                                        "signs of life, skipping every check.  Only use when that machine cannot sign,\n"
                                                        "or both machines may double-vote." );
  fd_action_help_arg( help, "--address",   "<address>", "The target machine's IPv4 address or host name" );
  fd_action_help_arg( help, "--port",      "<port>",    "The target machine's failover port, 8010 by default" );
}

static void
failover_promote_perm( args_t *         args,
                       fd_cap_chk_t *   chk,
                       config_t const * config FD_PARAM_UNUSED ) {
  if( args->failover.keypair_path[ 0 ] ) {
    fd_cap_chk_raise_rlimit( chk, failover_cmd_name( args ), RLIMIT_MEMLOCK, 5UL*FD_SHMEM_NORMAL_PAGE_SZ,
                             "lock the target keypair in memory" );
  }
}

action_t fd_action_failover = {
  .name           = "failover",
  .args           = failover_args,
  .fn             = failover_cmd_fn,
  .require_config = 0,
  .no_topo        = 1,
  .perm           = failover_promote_perm,
  .description    = "Take the identity that another validator runs",
  .detail         = "Hands off an identity between validators.  Each boots under its own\n"
                    "[paths.identity_key].  On the machine that should take over, pass the keypair\n"
                    "of the target identity.\n"
                    "A validator with [failover.boot_to_standby] boots as a standby under a junk key\n"
                    "generated in memory and loads the keypair in its [paths.identity_key] as the\n"
                    "identity to take over, so `failover` there reads the keypair from the\n"
                    "configuration instead of the command line.\n"
                    "\n"
                    "`failover promote` asks the machine running the identity to hand it over.\n"
                    "`failover takeover` does the same, and if that fails and the other machine shows\n"
                    "no signs of life, takes the identity without handover.  With --force, it takes\n"
                    "the identity even from a machine that may be live.\n"
                    "This command asks for confirmation unless --yes is given.\n"
                    "It waits for the outcome and exits 0 once this machine runs the identity,\n"
                    "and non-zero with the reason when it does not.  For checking status,\n"
                    "`get-identity` prints the key a machine runs.\n"
                    "\n"
                    "This command does not start a validator. It attaches to one that is already\n"
                    "running.  If multiple validators are running, pass --name to select one.\n",
  .usage          = "failover <promote|takeover> [<keypair>] [--name <name>] [--yes] [--force] [--address <address>] [--port <port>]",
  .args_help      = failover_args_help,
};
