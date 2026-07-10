#define _GNU_SOURCE
#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"

#include "../../../disco/topo/fd_topo.h"
#include "../../../discof/admin/fd_adminctl.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../../../util/pod/fd_pod.h"

#include <unistd.h>

void
get_identity_cmd_fn( args_t *   args   FD_PARAM_UNUSED,
                     config_t * config ) {
  ulong admin_ctl_obj_id = fd_pod_query_ulong( config->topo.props, "adminctl", ULONG_MAX );
  if( FD_UNLIKELY( admin_ctl_obj_id==ULONG_MAX ) ) FD_LOG_ERR(( "Failed to get identity as the command could not communicate with the "
                                                                "running Firedancer process.  It is possible you are running the command from an "
                                                                "older or newer version of Firedancer that is no longer compatible." ));

  fd_topo_obj_t const * admin_ctl_obj = &config->topo.objs[ admin_ctl_obj_id ];

  fd_topo_join_workspace( &config->topo, &config->topo.workspaces[ admin_ctl_obj->wksp_id ], FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );

  fd_adminctl_t * adminctl = fd_adminctl_join( fd_topo_obj_laddr( &config->topo, admin_ctl_obj->id ) );
  if( FD_UNLIKELY( !adminctl ) ) FD_LOG_ERR(( "Failed to get identity as the command could not communicate with the "
                                              "running Firedancer process.  It is possible you are running the command from an "
                                              "older or newer version of Firedancer that is no longer compatible." ));

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

action_t fd_action_get_identity = {
  .name           = "get-identity",
  .args           = NULL,
  .fn             = get_identity_cmd_fn,
  .require_config = 1,
  .perm           = NULL,
  .description    = "Get the current active identity of the running validator",
  .detail         = "Prints the base58 encoded identity public key the running validator is\n"
                    "currently using for gossip, voting, and block production.  This may differ\n"
                    "from [paths.identity_key] in the configuration file if the identity was\n"
                    "changed at runtime with `set-identity`.\n"
                    "\n"
                    "This command does not start a validator; it attaches to one that is already\n"
                    "running.  It finds the running validator from the shared memory described by\n"
                    "the configuration file, so you must point --config at the same config file the\n"
                    "validator was started with, and run it from a binary built from the same git\n"
                    "commit (compare this binary's `--version` against the running validator's).\n",
};
