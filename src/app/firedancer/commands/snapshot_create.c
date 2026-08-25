#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"
#include "../../shared/fd_bootinfo.h"
#include "../../../discof/admin/fd_adminctl.h"

static ulong
send_snapshot_create_cmd( fd_topo_t * topo,
                          ulong       target_slot ) {
  fd_topo_obj_t const * admin_ctl_obj = fd_topo_find_obj( topo, "adminctl", "admin", ULONG_MAX );
  if( FD_UNLIKELY( !admin_ctl_obj ) ) FD_LOG_ERR(( "admin tile command endpoint not found" ));

  fd_topo_wksp_t * admin_ctl_wksp = &topo->workspaces[ admin_ctl_obj->wksp_id ];
  fd_topo_join_workspace( topo, admin_ctl_wksp, FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  fd_topo_workspace_fill( topo, admin_ctl_wksp );

  fd_adminctl_t * adminctl = fd_adminctl_join( fd_topo_obj_laddr( topo, admin_ctl_obj->id ) );
  if( FD_UNLIKELY( !adminctl ) ) {
    FD_LOG_ERR(( "Failed to request snapshot creation as the command could not communicate with the "
                 "running Firedancer process. It is possible you are running the command from an "
                 "older or newer version of Firedancer that is no longer compatible." ));
  }

  void * payload     = NULL;
  ulong  payload_max = 0UL;
  ulong  slot_idx    = fd_adminctl_reserve( adminctl, &payload, &payload_max );
  if( FD_UNLIKELY( slot_idx==ULONG_MAX ) ) {
    FD_LOG_ERR(( "Failed to process `snapshot-create` command as there are other pending "
                 "commands that are being processed. Please wait for other commands to complete "
                 "or forcefully terminate the other processes and retry the command." ));
  }
  FD_TEST( payload_max>=sizeof(fd_adminctl_snap_create_t) );

  fd_adminctl_snap_create_t * req = payload;
  req->version = FD_ADMINCTL_SNAP_CREATE_PAYLOAD_VERSION;
  req->slot    = target_slot;

  fd_adminctl_publish( adminctl, slot_idx, FD_ADMINCTL_CMD_SNAP_CREATE, sizeof(fd_adminctl_snap_create_t) );
  return fd_adminctl_wait( adminctl, slot_idx );
}

static void
snapshot_create_cmd_args( int *    pargc,
                          char *** pargv,
                          args_t * args ) {
  args->snapshot_create.slot = fd_env_strip_cmdline_ulong( pargc, pargv, "--slot", NULL, 0UL );
}

static void
snapshot_create_cmd_fn( args_t *   args,
                        config_t * config ) {
  fd_bootinfo_adopt( config );
  fd_bootinfo_check_layout( config );
  fd_topo_t * topo = &config->topo;

  /* Send snapshot create command */
  ulong result = send_snapshot_create_cmd( topo, args->snapshot_create.slot );
  if( FD_UNLIKELY( result ) ) {
    if( FD_UNLIKELY( result==FD_ADMINCTL_RESULT_UNSUPPORTED ) ) {
      FD_LOG_ERR(( "snapshot creation is not supported by the running Firedancer configuration" ));
    } else if( FD_LIKELY( result==FD_SNAPSHOT_CREATE_RESULT_BUSY && !args->snapshot_create.slot ) ) {
      FD_LOG_NOTICE(( "snapshot creation already in progress, attaching ..." ));
    } else {
      FD_LOG_ERR(( "failed to request snapshot creation (%lu)", result ));
    }
  } else if( FD_UNLIKELY( args->snapshot_create.slot ) ) {
    FD_LOG_NOTICE(( "snapshot creation scheduled at slot %lu, waiting ...", args->snapshot_create.slot ));
  }
}

static void
snapshot_create_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "--slot", "<slot>",
      "Schedule snapshot creation at a slot in the future rather than\n"
      "creating one immediately.  Rooting stops at the first rooted slot at\n"
      "or after <slot> and a snapshot of it is created (default 0, which\n"
      "snapshots the current root immediately)" );
}

action_t fd_action_snapshot_create = {
  .name           = "snapshot-create",
  .args           = snapshot_create_cmd_args,
  .fn             = snapshot_create_cmd_fn,
  .description    = "Create a snapshot",
  .usage          = "snapshot-create [OPTIONS]",
  .args_help      = snapshot_create_args_help,
};
