#define _GNU_SOURCE
#include "adminctl_client.h"
#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"

#include <unistd.h>
#include "../../platform/fd_cap_chk.h"
#include "../../../disco/keyguard/fd_keyload.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../../../ballet/ed25519/fd_ed25519.h"

#include <strings.h>
#include <unistd.h>
#include <sys/resource.h>

void
set_identity_cmd_perm( args_t *         args   FD_PARAM_UNUSED,
                       fd_cap_chk_t *   chk,
                       config_t const * config FD_PARAM_UNUSED ) {
  /* 5 huge pages for the key storage area */
  ulong mlock_limit = 5UL * FD_SHMEM_NORMAL_PAGE_SZ;
  fd_cap_chk_raise_rlimit( chk, "set-identity", RLIMIT_MEMLOCK, mlock_limit, "call `rlimit(2)` to increase `RLIMIT_MEMLOCK` so all memory can be locked with `mlock(2)`" );
}

void
set_identity_cmd_args( int *    pargc,
                       char *** pargv,
                       args_t * args) {

  char const * name = fd_env_strip_cmdline_cstr( pargc, pargv, "--name", NULL, NULL );
  if( FD_UNLIKELY( name ) ) fd_cstr_ncpy( args->set_identity.name, name, sizeof(args->set_identity.name) );

  if( FD_UNLIKELY( *pargc<1 ) ) goto err;

  char const * path = *pargv[0];
  (*pargc)--;
  (*pargv)++;

  if( FD_UNLIKELY( !strcmp( path, "-" ) ) ) {
    uchar * keypair_wr = fd_keyload_alloc_protected_pages( 1UL, 2UL );
    FD_LOG_STDOUT(( "Reading identity keypair from stdin.  Press Ctrl-D when done.\n" ));
    fd_keyload_read( STDIN_FILENO, "stdin", keypair_wr );
    args->set_identity.keypair = fd_keyload_mprotect_ro( keypair_wr, 0 );
  } else {
    args->set_identity.keypair = fd_keyload_load( path, 0 );
  }

  return;

err:
  FD_LOG_ERR(( "Usage: %s set-identity <keypair>", FD_BINARY_NAME ));
}

static void FD_FN_SENSITIVE
set_identity( args_t *   args,
              config_t * config ) {
  uchar       check_public_key[ 32 ];
  fd_sha512_t sha512[ 1 ];
  FD_TEST( fd_sha512_join( fd_sha512_new( sha512 ) ) );
  fd_ed25519_public_from_private( check_public_key, args->set_identity.keypair, sha512 );
  if( FD_UNLIKELY( memcmp( check_public_key, args->set_identity.keypair+32UL, 32UL ) ) )
    FD_LOG_ERR(( "The public key in the identity key file does not match the public key derived from the private key. "
                 "Firedancer will not use the key pair to sign as it might leak the private key." ));

  char identity_key_base58[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( args->set_identity.keypair+32UL, NULL, identity_key_base58 );
  identity_key_base58[ FD_BASE58_ENCODED_32_SZ-1UL ] = '\0';

  fd_adminctl_t * adminctl = adminctl_client_attach( config, args->set_identity.name );

  void * payload     = NULL;
  ulong  payload_max = 0UL;
  ulong  slot_idx    = fd_adminctl_reserve( adminctl, &payload, &payload_max );
  if( FD_UNLIKELY( slot_idx==ULONG_MAX ) ) {
    FD_LOG_ERR(( "Failed to process `set-identity` command as there are other pending "
                 "commands that are being processed.  Please wait for other commands to complete "
                 "or forcefully terminate the other processes and retry the command." ));
  }
  if( FD_UNLIKELY( sizeof(fd_adminctl_set_identity_t)>payload_max ) ) FD_LOG_ERR(( "adminctl set-identity payload too large" ));

  fd_adminctl_set_identity_t * req = (fd_adminctl_set_identity_t *)payload;
  req->version = FD_ADMINCTL_SET_IDENTITY_PAYLOAD_VERSION;
  memcpy( req->keypair, args->set_identity.keypair, 64UL );

  uchar * keypair_wr = fd_keyload_mprotect_wr( args->set_identity.keypair, 0 );
  fd_memzero_explicit( keypair_wr, 64UL );
  fd_keyload_mprotect_ro( keypair_wr, 0 );

  fd_adminctl_publish( adminctl, slot_idx, FD_ADMINCTL_CMD_SET_IDENTITY, sizeof(fd_adminctl_set_identity_t) );

  ulong result = fd_adminctl_wait( adminctl, slot_idx );
  switch( result ) {
    case FD_ADMINCTL_RESULT_SUCCESS:
      FD_LOG_NOTICE(( "Validator identity key switched to `%s`", identity_key_base58 ));
      break;
    case FD_ADMINCTL_RESULT_UNKNOWN_COMMAND:
    case FD_SET_IDENTITY_RESULT_PAYLOAD_TOO_SMALL:
    case FD_SET_IDENTITY_RESULT_UNSUPPORTED_PAYLOAD_VERSION:
    case FD_SET_IDENTITY_RESULT_UNEXPECTED_PAYLOAD_SIZE:
    case FD_SET_IDENTITY_RESULT_KEYPAIR_MISMATCH:
      FD_LOG_ERR(( "Failed to set identity: the command was not able to successfully communicate "
                   "with the running Firedancer process. It is possible that you are running the "
                   "command from an older or newer version of Firedancer that is no longer compatible." ));
    default:
      FD_LOG_ERR(( "Unexpected set-identity result %lu.  This can be a result of a version mismatch "
                   "between the command and the running Firedancer process. Please report this to the "
                   "Firedancer team for investigation.", result ));
  }
}

void
set_identity_cmd_fn( args_t *   args,
                     config_t * config ) {
  set_identity( args, config );
}

static void
set_identity_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "<keypair>", NULL,   "Path to the new identity keypair, in the standard Solana keypair file\n"
                                                 "format (the 64-byte JSON array).  Pass `-` to read the same JSON\n"
                                                 "array from stdin instead of from a file" );
  fd_action_help_arg( help, "--name", "<name>",  "Name of the validator instance to attach to, if more than one is\n"
                                                 "running on this host" );
}

action_t fd_action_set_identity = {
  .name           = "set-identity",
  .args           = set_identity_cmd_args,
  .fn             = set_identity_cmd_fn,
  .require_config = 0,
  .perm           = set_identity_cmd_perm,
  .description    = "Change the identity of a running validator",
  .detail         = "Switches the gossip/voting/block-production identity key of an already\n"
                    "running validator to the keypair you provide, without restarting it.  The\n"
                    "switch is atomic: the validator briefly pauses block production so it never\n"
                    "signs with a mix of the old and new keys, then resumes under the new\n"
                    "identity.  On success it prints `Validator identity key switched to <pubkey>`\n"
                    "and exits 0; on any error it exits non-zero and the identity is unchanged.\n"
                    "\n"
                    "This command does not start a validator; it attaches to one that is already\n"
                    "running.  With no arguments it discovers the running validator automatically.\n"
                    "If multiple validators are running, pass --name to select one.  If --config is\n"
                    "given, the validator is instead located from the configuration file; only the\n"
                    "name and [hugetlbfs.mount_path] values are used, and they must match the\n"
                    "running validator.\n"
                    "\n"
                    "The change is live only: it is not written back to the config file, so the\n"
                    "validator reverts to the configured [paths.identity_key] on its next restart.\n"
                    "To make the new identity permanent, also update that path in the config.\n",
  .usage          = "set-identity <keypair> [--name <name>]",
  .args_help      = set_identity_args_help,
};
