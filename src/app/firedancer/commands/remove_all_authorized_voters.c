#include "adminctl_client.h"
#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"

void
remove_all_authorized_voters_cmd_args( int *    pargc,
                                       char *** pargv,
                                       args_t * args ) {
  char const * name = fd_env_strip_cmdline_cstr( pargc, pargv, "--name", NULL, NULL );
  if( FD_UNLIKELY( name ) ) fd_cstr_ncpy( args->remove_all_authorized_voters.name, name, sizeof(args->remove_all_authorized_voters.name) );
}

void
remove_all_authorized_voters_cmd_fn( args_t *   args,
                                     config_t * config ) {

  fd_adminctl_t * adminctl = adminctl_client_attach( config, args->remove_all_authorized_voters.name );

  void * payload     = NULL;
  ulong  payload_max = 0UL;
  ulong  slot_idx    = fd_adminctl_reserve( adminctl, &payload, &payload_max );
  if( FD_UNLIKELY( slot_idx==ULONG_MAX ) ) {
    FD_LOG_ERR(( "Failed to process `remove-all-authorized-voters` command as there are other pending "
                 "commands that are being processed.  Please wait for other commands to complete "
                 "or forcefully terminate the other processes and retry the command." ));
  }
  if( FD_UNLIKELY( sizeof(fd_adminctl_remove_all_auth_voters_t)>payload_max ) ) FD_LOG_ERR(( "adminctl remove-all-authorized-voters payload too large" ));

  fd_adminctl_remove_all_auth_voters_t * req = (fd_adminctl_remove_all_auth_voters_t *)payload;
  req->version = FD_ADMINCTL_REMOVE_ALL_AUTH_VOTERS_PAYLOAD_VERSION;

  fd_adminctl_publish( adminctl, slot_idx, FD_ADMINCTL_CMD_REMOVE_ALL_AUTH_VOTERS, sizeof(fd_adminctl_remove_all_auth_voters_t) );

  ulong result = fd_adminctl_wait( adminctl, slot_idx );
  switch( result ) {
    case FD_ADMINCTL_RESULT_SUCCESS:
      FD_LOG_NOTICE(( "All authorized voters removed" ));
      break;
    case FD_ADMINCTL_RESULT_UNKNOWN_COMMAND:
    case FD_REMOVE_ALL_AUTH_VOTERS_RESULT_PAYLOAD_TOO_SMALL:
    case FD_REMOVE_ALL_AUTH_VOTERS_RESULT_UNSUPPORTED_PAYLOAD_VERSION:
    case FD_REMOVE_ALL_AUTH_VOTERS_RESULT_UNEXPECTED_PAYLOAD_SIZE:
      FD_LOG_ERR(( "Failed to remove authorized voter keys: the command was not able to "
                   "successfully communicate with the running Firedancer process. It "
                   "is possible that you are running the command from an older or "
                   "newer version of Firedancer that is no longer compatible." ));
    default:
      FD_LOG_ERR(( "Unexpected remove-all-authorized-voters result %lu.  This can be a result "
                   "of a version mismatch between the command and the running Firedancer "
                   "process. Please report this to the Firedancer team for investigation.", result ));
  }
}

static void
remove_all_authorized_voters_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "--name", "<name>", "Name of the validator instance to attach to, if more than one is\n"
                                                "running on this host" );
}

action_t fd_action_remove_all_authorized_voters = {
  .name           = "remove-all-authorized-voters",
  .args           = remove_all_authorized_voters_cmd_args,
  .fn             = remove_all_authorized_voters_cmd_fn,
  .require_config = 0,
  .perm           = NULL,
  .description    = "Remove all authorized voters from the validator",
  .detail         = "Removes every authorized voter key from an already running validator,\n"
                    "including any seeded from [paths.authorized_voter_paths] at startup as\n"
                    "well as any added at runtime with add-authorized-voter.  After this the\n"
                    "validator can only sign votes for vote accounts whose authorized voter is\n"
                    "the identity key.  On success it prints `All authorized voters removed` and\n"
                    "exits 0.  It is idempotent: removing when there are no authorized voters\n"
                    "also succeeds.\n"
                    "\n"
                    "This command does not start a validator; it attaches to one that is already\n"
                    "running.  With no arguments it discovers the running validator automatically.\n"
                    "If multiple validators are running, pass --name to select one.  If --config is\n"
                    "given, the validator is instead located from the configuration file; only the\n"
                    "name and [hugetlbfs.mount_path] values are used, and they must match the\n"
                    "running validator.\n"
                    "\n"
                    "The change is live only: it is not written back to the config file, so any\n"
                    "voters in [paths.authorized_voter_paths] return on the validator's next\n"
                    "restart.  To drop them across restarts, also remove them from the config.",
  .usage          = "remove-all-authorized-voters [--name <name>]",
  .args_help      = remove_all_authorized_voters_args_help,
};
