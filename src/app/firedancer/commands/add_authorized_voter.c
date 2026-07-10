#include "adminctl_client.h"
#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"

#include "../../../disco/keyguard/fd_keyload.h"
#include "../../../ballet/ed25519/fd_ed25519.h"

#include <unistd.h>

void
add_authorized_voter_cmd_args( int *    pargc,
                               char *** pargv,
                               args_t * args ) {

  char const * name = fd_env_strip_cmdline_cstr( pargc, pargv, "--name", NULL, NULL );
  if( FD_UNLIKELY( name ) ) fd_cstr_ncpy( args->add_authorized_voter.name, name, sizeof(args->add_authorized_voter.name) );

  if( FD_UNLIKELY( *pargc<1 ) ) {
    FD_LOG_ERR(( "Usage: %s add-authorized-voter <keypair>", FD_BINARY_NAME ));
  }

  char const * path = *pargv[0];
  (*pargc)--;
  (*pargv)++;

  if( FD_UNLIKELY( !strcmp( path, "-" ) ) ) {
    uchar * keypair_wr = fd_keyload_alloc_protected_pages( 1UL, 2UL );
    FD_LOG_STDOUT(( "Reading authorized voter keypair from stdin.  Press Ctrl-D when done.\n" ));
    fd_keyload_read( STDIN_FILENO, "stdin", keypair_wr );
    args->add_authorized_voter.keypair = fd_keyload_mprotect_ro( keypair_wr, 0 );
  } else {
    args->add_authorized_voter.keypair = fd_keyload_load( path, 0 );
  }
}

static void FD_FN_SENSITIVE
add_authorized_voter( args_t *   args,
                      config_t * config ) {

  uchar       public_key[ 32 ];
  fd_sha512_t sha512[ 1 ];
  FD_TEST( fd_sha512_join( fd_sha512_new( sha512 ) ) );

  fd_ed25519_public_from_private( public_key, args->add_authorized_voter.keypair, sha512 );
  if( FD_UNLIKELY( memcmp( public_key, args->add_authorized_voter.keypair+32UL, 32UL ) ) ) {
    FD_LOG_ERR(( "The public key in the key file does not match the public key derived from the private key."
                 "Firedancer will not use the key pair to sign as it might leak the private key." ));
  }

  fd_adminctl_t * adminctl = adminctl_client_attach( config, args->add_authorized_voter.name );

  void * payload     = NULL;
  ulong  payload_max = 0UL;
  ulong  slot_idx    = fd_adminctl_reserve( adminctl, &payload, &payload_max );
  if( FD_UNLIKELY( slot_idx==ULONG_MAX ) ) {
    FD_LOG_ERR(( "Failed to process `add-authorized-voter` command as there are other pending "
                 "commands that are being processed.  Please wait for other commands to complete "
                 "or forcefully terminate the other processes and retry the command." ));
  }

  fd_adminctl_add_auth_voter_t * req = (fd_adminctl_add_auth_voter_t *)payload;
  req->version = FD_ADMINCTL_ADD_AUTH_VOTER_PAYLOAD_VERSION;
  memcpy( req->keypair, args->add_authorized_voter.keypair, 64UL );

  uchar * keypair_wr = fd_keyload_mprotect_wr( args->add_authorized_voter.keypair, 0 );
  fd_memzero_explicit( keypair_wr, 64UL );
  fd_keyload_mprotect_ro( keypair_wr, 0 );

  fd_adminctl_publish( adminctl, slot_idx, FD_ADMINCTL_CMD_ADD_AUTH_VOTER, sizeof(fd_adminctl_add_auth_voter_t) );

  ulong result = fd_adminctl_wait( adminctl, slot_idx );
  switch( result ) {
    case FD_ADMINCTL_RESULT_SUCCESS:
      FD_LOG_NOTICE(( "Authorized voter key added successfully" ));
      break;
    case FD_ADD_AUTHORIZED_VOTER_RESULT_PAYLOAD_TOO_SMALL:
    case FD_ADD_AUTHORIZED_VOTER_RESULT_UNSUPPORTED_PAYLOAD_VERSION:
    case FD_ADD_AUTHORIZED_VOTER_RESULT_UNEXPECTED_PAYLOAD_SIZE:
    case FD_ADD_AUTHORIZED_VOTER_RESULT_KEYPAIR_MISMATCH:
      FD_LOG_ERR(( "Failed to add authorized voter key: the command was not able to "
                   "successfully communicate with the running Firedancer process. It "
                   "is possible that you are running the command from an older or "
                   "newer version of Firedancer that is no longer compatible." ));
    case FD_ADD_AUTHORIZED_VOTER_RESULT_MAX_AUTH_VOTERS:
      FD_LOG_ERR(( "Failed to add authorized voter key: maximum number of authorized voters "
                   "supported by the validator has been reached" ));
    case FD_ADD_AUTHORIZED_VOTER_RESULT_DUPLICATE_AUTH_VOTER:
      FD_LOG_ERR(( "Failed to add authorized voter key: the authorized voter key exists in "
                   "the validator's authorized voter list" ));
    default:
      FD_LOG_ERR(( "Unexpected add-authorized-voter result %lu.  This can be a result "
                   "of a version mismatch between the command and the running Firedancer "
                   "process. Please report this to the Firedancer team for investigation.", result ));
  }
}

void
add_authorized_voter_cmd_fn( args_t *   args,
                             config_t * config ) {
  add_authorized_voter( args, config );
}

static void
add_authorized_voter_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "<keypair>", NULL,  "Path to the authorized voter keypair to add, in the standard Solana\n"
                                                "keypair file format (the 64-byte JSON array).  The full keypair is\n"
                                                "required, not just the public key, because the validator must sign\n"
                                                "votes with it.  Pass `-` to read the same JSON array from stdin\n"
                                                "instead of from a file" );
  fd_action_help_arg( help, "--name", "<name>", "Name of the validator instance to attach to, if more than one is\n"
                                                "running on this host" );
}

action_t fd_action_add_authorized_voter = {
  .name           = "add-authorized-voter",
  .args           = add_authorized_voter_cmd_args,
  .fn             = add_authorized_voter_cmd_fn,
  .require_config = 0,
  .perm           = NULL,
  .description    = "Add an authorized voter to the validator",
  .detail         = "Registers an additional authorized voter key with an already running\n"
                    "validator so it can sign votes with that key, in addition to the identity\n"
                    "key and any voters already configured.  On success it prints `Authorized\n"
                    "voter key added successfully` and exits 0.  It fails (non-zero, with no change)\n"
                    "if the key is already an authorized voter, or if the validator already has\n"
                    "the maximum of 16 authorized voters.\n"
                    "\n"
                    "This command does not start a validator; it attaches to one that is already\n"
                    "running.  With no arguments it discovers the running validator automatically.\n"
                    "If multiple validators are running, pass --name to select one.  If --config is\n"
                    "given, the validator is instead located from the configuration file; only the\n"
                    "name and [hugetlbfs.mount_path] values are used, and they must match the\n"
                    "running validator.\n"
                    "\n"
                    "The change is live only: it is not written back to the config file, so the\n"
                    "voter is dropped on the validator's next restart.  To keep it across restarts,\n"
                    "also add the keypair path to [paths.authorized_voter_paths] in the config.",
  .usage          = "add-authorized-voter <keypair> [--name <name>]",
  .args_help      = add_authorized_voter_args_help,
};
