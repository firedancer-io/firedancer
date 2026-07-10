#define _GNU_SOURCE
#include "adminctl_client.h"
#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"

#include "../../../ballet/base58/fd_base58.h"

#include <unistd.h>

void
get_identity_cmd_args( int *    pargc,
                       char *** pargv,
                       args_t * args ) {
  char const * name = fd_env_strip_cmdline_cstr( pargc, pargv, "--name", NULL, NULL );
  if( FD_UNLIKELY( name ) ) fd_cstr_ncpy( args->get_identity.name, name, sizeof(args->get_identity.name) );
}

void
get_identity_cmd_fn( args_t *   args,
                     config_t * config ) {
  fd_adminctl_t * adminctl = adminctl_client_attach( config, args->get_identity.name );

  void * payload     = NULL;
  ulong  payload_max = 0UL;
  ulong  slot_idx    = fd_adminctl_reserve( adminctl, &payload, &payload_max );
  if( FD_UNLIKELY( slot_idx==ULONG_MAX ) ) {
    FD_LOG_ERR(( "Failed to process `get-identity` command as there are other pending "
                 "commands that are being processed.  Please wait for other commands to complete "
                 "or forcefully terminate the other processes and retry the command." ));
  }
  if( FD_UNLIKELY( sizeof(fd_adminctl_get_identity_req_t)>payload_max ) ) FD_LOG_ERR(( "adminctl get-identity payload too large" ));

  fd_adminctl_get_identity_req_t * req = (fd_adminctl_get_identity_req_t *)payload;
  req->version = FD_ADMINCTL_GET_IDENTITY_PAYLOAD_VERSION;

  fd_adminctl_publish( adminctl, slot_idx, FD_ADMINCTL_CMD_GET_IDENTITY, sizeof(fd_adminctl_get_identity_req_t) );

  fd_adminctl_get_identity_resp_t resp = {0};
  ulong resp_sz = 0UL;
  ulong result  = fd_adminctl_wait_response( adminctl, slot_idx, &resp, sizeof(resp), &resp_sz );
  switch( result ) {
    case FD_ADMINCTL_RESULT_SUCCESS: {
      if( FD_UNLIKELY( resp_sz!=sizeof(resp) || resp.version!=FD_ADMINCTL_GET_IDENTITY_PAYLOAD_VERSION ) )
        FD_LOG_ERR(( "Failed to get identity: the running Firedancer process returned an unexpected "
                     "response.  It is possible that you are running the command from an older or "
                     "newer version of Firedancer that is no longer compatible." ));
      char identity_key_str[ FD_BASE58_ENCODED_32_SZ ];
      fd_base58_encode_32( resp.identity_pubkey, NULL, identity_key_str );
      FD_LOG_STDOUT(( "%s\n", identity_key_str ));
      break;
    }
    case FD_ADMINCTL_RESULT_UNKNOWN_COMMAND:
    case FD_GET_IDENTITY_RESULT_PAYLOAD_TOO_SMALL:
    case FD_GET_IDENTITY_RESULT_UNSUPPORTED_PAYLOAD_VERSION:
    case FD_GET_IDENTITY_RESULT_UNEXPECTED_PAYLOAD_SIZE:
      FD_LOG_ERR(( "Failed to get identity: the command was not able to successfully communicate "
                   "with the running Firedancer process. It is possible that you are running the "
                   "command from an older or newer version of Firedancer that is no longer compatible." ));
    default:
      FD_LOG_ERR(( "Unexpected get-identity result %lu.  This can be a result of a version mismatch "
                   "between the command and the running Firedancer process. Please report this to the "
                   "Firedancer team for investigation.", result ));
  }
}

static void
get_identity_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "--name", "<name>", "Name of the validator instance to attach to, if more than one is\n"
                                                "running on this host" );
}

action_t fd_action_get_identity = {
  .name           = "get-identity",
  .args           = get_identity_cmd_args,
  .fn             = get_identity_cmd_fn,
  .require_config = 0,
  .perm           = NULL,
  .description    = "Get the current active identity of the running validator",
  .detail         = "Prints the base58 encoded identity public key the running validator is\n"
                    "currently using for gossip, voting, and block production.  This may differ\n"
                    "from [paths.identity_key] in the configuration file if the identity was\n"
                    "changed at runtime with `set-identity`.\n"
                    "\n"
                    "This command does not start a validator; it attaches to one that is already\n"
                    "running.  With no arguments it discovers the running validator automatically.\n"
                    "If multiple validators are running, pass --name to select one.  If --config is\n"
                    "given, the validator is instead located from the configuration file; only the\n"
                    "name and [hugetlbfs.mount_path] values are used, and they must match the\n"
                    "running validator.\n",
  .usage          = "get-identity [--name <name>]",
  .args_help      = get_identity_args_help,
};
