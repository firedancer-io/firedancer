#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"
#include "../../../discof/replay/fd_replay_tile.h"

#if !FD_HAS_ATOMIC
#error "This compile unit requires FD_HAS_ATOMIC"
#endif

static ulong
send_admin_cmd( fd_frag_meta_t *       admin_cmd,
                fd_frag_meta_t const * admin_rsp,
                ulong                  orig ) {
  /* Send request */
  ulong   cmd_depth = fd_mcache_depth( admin_cmd );
  ulong * seq_next  = &fd_mcache_seq_laddr( admin_cmd )[1];
  ulong   seq       = FD_ATOMIC_FETCH_AND_ADD( seq_next, 1UL );
  ulong   ctl       = fd_frag_meta_ctl( orig, 0, 0, 0 );
  ulong   tspub     = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_mcache_publish( admin_cmd, cmd_depth, seq, 0UL, 0UL, 0UL, ctl, 0UL, tspub );

  /* Spin-wait for reply */
  ulong rsp_depth = fd_mcache_depth( admin_rsp );
  fd_frag_meta_t meta;
  for(;;) {
    fd_frag_meta_t const * mline;
    ulong                  seq_found;
    long                   seq_diff;
    ulong                  poll_max = 0UL;
    FD_MCACHE_WAIT( &meta, mline, seq_found, seq_diff, poll_max, admin_rsp, rsp_depth, seq );
    (void)mline; (void)seq_diff;
    if( FD_UNLIKELY( fd_seq_gt( seq_found, seq ) ) ) {
      FD_LOG_ERR(( "corrupt admin queue (seq=%lu seq_found=%lu)", seq, seq_found ));
    }
    if( FD_UNLIKELY( fd_seq_eq( seq_found, seq ) ) ) break;
    fd_log_sleep( (long)1e6 ); /* sleep 1ms */
    /* FIXME also check the replay tile's heartbeat to bail if it's down */
  }

  return meta.sig;
}

static void
snapshot_create_cmd_fn( args_t *   args,
                        config_t * config ) {
  (void)args;

  /* Topology boilerplate: Find admin command/response queues */
  fd_topo_t * topo = &config->topo;
  ulong admin_cmd_wksp_id = fd_topo_find_wksp( topo, "admin_replay" ); FD_TEST( admin_cmd_wksp_id!=ULONG_MAX );
  fd_topo_wksp_t * admin_topo_wksp = &topo->workspaces[ admin_cmd_wksp_id ];
  fd_topo_join_workspace( topo, admin_topo_wksp, FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_REGULAR );
  fd_topo_workspace_fill( topo, admin_topo_wksp );
  ulong admin_cmd_link_id = fd_topo_find_link( topo, "admin_replay", 0UL ); FD_TEST( admin_cmd_link_id!=ULONG_MAX );
  ulong admin_rsp_link_id = fd_topo_find_link( topo, "replay_admin", 0UL ); FD_TEST( admin_rsp_link_id!=ULONG_MAX );
  fd_topo_link_t const * admin_cmd_link   = &topo->links[ admin_cmd_link_id ];
  fd_topo_link_t const * admin_rsp_link   = &topo->links[ admin_rsp_link_id ];
  fd_frag_meta_t *       admin_cmd_mcache = admin_cmd_link->mcache;
  fd_frag_meta_t const * admin_rsp_mcache = admin_rsp_link->mcache;

  /* Send snapshot create command */
  ulong err = send_admin_cmd( admin_cmd_mcache, admin_rsp_mcache, REPLAY_ADMIN_CMD_SNAP_CREATE );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "failed to request snapshot creation %lu-%s", err, fd_replay_admin_strerror( err ) ));
  }
  FD_LOG_NOTICE(( "requested snapshot creation" ));
}

action_t fd_action_snapshot_create = {
  .name           = "snapshot-create",
  .fn             = snapshot_create_cmd_fn,
  .description    = "Create a snapshot",
  .require_config = 1
};
