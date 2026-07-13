#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"

#include "../../../disco/topo/fd_topo.h"
#include "../../../discof/admin/fd_adminctl.h"
#include "../../../util/pod/fd_pod.h"

void
remove_all_authorized_voters_cmd_fn( args_t *   args FD_PARAM_UNUSED,
                                     config_t * config ) {

  /* Join the adminctl object.  Once joined, we can publish a request to
     the admin tile. */
  ulong admin_ctl_obj_id = fd_pod_query_ulong( config->topo.props, "adminctl", ULONG_MAX );
  if( FD_UNLIKELY( admin_ctl_obj_id==ULONG_MAX ) ) FD_LOG_ERR(( "Failed to remove authorized voters as the command could not communicate with the "
                                                                "running Firedancer process.  It is possible you are running the command from an "
                                                                "older or newer version of Firedancer that is no longer compatible." ));
  fd_topo_obj_t const * admin_ctl_obj = &config->topo.objs[ admin_ctl_obj_id ];

  fd_topo_join_workspace( &config->topo, &config->topo.workspaces[ admin_ctl_obj->wksp_id ], FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );

  fd_adminctl_t * adminctl = fd_adminctl_join( fd_topo_obj_laddr( &config->topo, admin_ctl_obj->id ) );
  if( FD_UNLIKELY( !adminctl ) ) FD_LOG_ERR(( "Failed to remove authorized voters as the command could not communicate with the "
                                              "running Firedancer process.  It is possible you are running the command from an "
                                              "older or newer version of Firedancer that is no longer compatible." ));

  void * payload     = NULL;
  ulong  payload_max = 0UL;
  ulong  slot_idx    = fd_adminctl_reserve( adminctl, &payload, &payload_max );
  if( FD_UNLIKELY( slot_idx==ULONG_MAX ) ) {
    FD_LOG_ERR(( "Failed to process `remove-all-authorized-voters` command as there are other pending "
                 "commands that are being processed.  Please wait for other commands to complete "
                 "or forcefully terminate the other processes and retry the command." ));
  }

  fd_adminctl_remove_all_auth_voters_t * req = (fd_adminctl_remove_all_auth_voters_t *)payload;
  req->version = FD_ADMINCTL_REMOVE_ALL_AUTH_VOTERS_PAYLOAD_VERSION;

  fd_adminctl_publish( adminctl, slot_idx, FD_ADMINCTL_CMD_REMOVE_ALL_AUTH_VOTERS, sizeof(fd_adminctl_remove_all_auth_voters_t) );

  ulong result = fd_adminctl_wait( adminctl, slot_idx );
  switch( result ) {
    case FD_ADMINCTL_RESULT_SUCCESS:
      FD_LOG_NOTICE(( "All authorized voters removed" ));
      break;
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

action_t fd_action_remove_all_authorized_voters = {
  .name           = "remove-all-authorized-voters",
  .args           = NULL,
  .fn             = remove_all_authorized_voters_cmd_fn,
  .require_config = 1,
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
                    "running.  It finds the running validator from the shared memory described by\n"
                    "the configuration file, so you must point --config at the SAME config file the\n"
                    "validator was started with, and run it from a binary built from the SAME git\n"
                    "commit (compare this binary's `--version` against the running validator's).  If\n"
                    "the config or binary differ, the layout will not match and the command fails\n"
                    "without changing anything.\n"
                    "\n"
                    "The change is live only: it is not written back to the config file, so any\n"
                    "voters in [paths.authorized_voter_paths] return on the validator's next\n"
                    "restart.  To drop them across restarts, also remove them from the config.",
  .usage          = "remove-all-authorized-voters",
};
