#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"
#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h"
#include "../../firedancer/topology.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../discof/backup/fd_snapmk.h"
#include "../../../discof/replay/fd_replay_tile.h"
#include "../../../flamenco/runtime/fd_bank.h"
#include "../../../util/pod/fd_pod_format.h"

#include <unistd.h>

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

static void
snapshot_create_offline_topo( config_t * config ) {
  fd_topo_t * topo = &config->topo;
  fd_topob_new( topo, config->name );
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );

  /* Inject link controlled by this compile unit */

  fd_topob_wksp( topo, "replay_out" );
  fd_topob_link( topo, "replay_out", "replay_out", 8192UL, sizeof( fd_replay_message_t ), 1UL )->permit_no_producers = 1;

  /* snapshot-create topology */

  uint snapzp_tile_cnt = config->firedancer.layout.snapzp_tile_count;
# define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )

  fd_topob_wksp( topo, "funk" );
  fd_topob_wksp( topo, "funk_locks" );
  setup_topo_funk( topo,
      config->firedancer.accounts.max_accounts,
      config->firedancer.runtime.max_live_slots + config->firedancer.accounts.write_delay_slots,
      config->firedancer.accounts.in_memory_only
          ? config->firedancer.accounts.file_size_gib
          : config->firedancer.accounts.max_unrooted_account_size_gib );
  ulong funk_obj_id; FD_TEST( (funk_obj_id = fd_pod_query_ulong( topo->props, "funk", ULONG_MAX ))!=ULONG_MAX );
  ulong funk_locks_obj_id; FD_TEST( (funk_locks_obj_id = fd_pod_query_ulong( topo->props, "funk_locks", ULONG_MAX ))!=ULONG_MAX );
  fd_topo_obj_t * funk_obj = &topo->objs[ funk_obj_id ];
  fd_topo_obj_t * funk_locks_obj = &topo->objs[ funk_locks_obj_id ];

  fd_topob_wksp( topo, "metric_in"     );
  fd_topob_wksp( topo, "snapmk"        );
  fd_topob_wksp( topo, "snapzp"        );
  fd_topob_wksp( topo, "snapmk_zp"     );
  fd_topob_wksp( topo, "snapmk_replay" );

  FOR(snapzp_tile_cnt) fd_topob_link( topo, "snapmk_zp",     "snapmk_zp",     32UL,  sizeof(fd_snapmk_batch_t), 1UL );
  /**/                 fd_topob_link( topo, "snapmk_replay", "snapmk_replay", 128UL, 0UL,                       1UL )->permit_no_consumers = 1;
  fd_topo_obj_t * zp_fseq = fd_topob_obj( topo, "fseq", "snapmk" );
  fd_pod_insert_ulong( topo->props, "snapzp.fseq", zp_fseq->id );

  fd_topo_tile_t * snapmk_tile = fd_topob_tile( topo, "snapmk", "snapmk", "metric_in", ULONG_MAX, 0, 0, 0 );
  FOR(snapzp_tile_cnt) fd_topob_tile( topo, "snapzp", "snapzp", "metric_in", ULONG_MAX, 0, 0, 0 );

  /**/                 fd_topob_tile_in ( topo, "snapmk", 0UL, "metric_in", "replay_out",    0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  FOR(snapzp_tile_cnt) fd_topob_tile_out( topo, "snapmk", 0UL,              "snapmk_zp",     i                                       );
  FOR(snapzp_tile_cnt) fd_topob_tile_in ( topo, "snapzp", i,   "metric_in", "snapmk_zp",     i,   FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out( topo, "snapmk", 0UL,              "snapmk_replay", 0UL                                     );

  /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "snapmk", 0UL ) ], funk_obj,       FD_SHMEM_JOIN_MODE_READ_ONLY  );
  /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "snapmk", 0UL ) ], funk_locks_obj, FD_SHMEM_JOIN_MODE_READ_ONLY  );
  /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "snapmk", 0UL ) ], zp_fseq,        FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topob_wksp( topo, "banks" );
  fd_topo_obj_t * banks_obj = setup_topo_banks( topo, "banks", config->firedancer.runtime.max_live_slots, config->firedancer.runtime.max_fork_width, 0 );
  fd_topob_tile_uses( topo, snapmk_tile, banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, banks_obj->id, "banks" ) );

# undef FOR

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    fd_topo_configure_tile( tile, config );
  }

  fd_topob_auto_layout( topo, 0 );
  fd_topob_finish( topo, CALLBACKS );
}

static args_t
configure_args( void ) {
  args_t args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };
  ulong stage_idx = 0UL;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_hugetlbfs;
  args.configure.stages[ stage_idx++ ] = NULL;
  return args;
}

static char *
fmt_bytes( char * buf,
           ulong  buf_sz,
           double bytes ) {
  char * tmp = fd_alloca_check( 1UL, buf_sz );
  if( FD_LIKELY( bytes<1000L ) ) FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%.0f bytes/s", bytes ) );
  else if( FD_LIKELY( bytes<1000000L ) ) FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%.1f KB/s", bytes/1000.0 ) );
  else if( FD_LIKELY( bytes<1000000000L ) ) FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%.1f MB/s", bytes/1000000.0 ) );
  else FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%.1f GB/s", bytes/1000000000.0 ) );
  FD_TEST( fd_cstr_printf_check( buf, buf_sz, NULL, "%10s", tmp ) );
  return buf;
}

static void
snapshot_create_offline_cmd_fn( args_t *   args,
                                config_t * config ) {
  (void)args;
  fd_topo_t * topo = &config->topo;
  args_t c_args = configure_args();
  configure_cmd_fn( &c_args, config );

  /* Create workspaces (except stateful ones) */
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    fd_topo_wksp_t * wksp = &topo->workspaces[ i ];
    if( !strcmp( wksp->name, "funk"       ) ) continue;
    if( !strcmp( wksp->name, "funk_locks" ) ) continue;
    if( !strcmp( wksp->name, "banks"      ) ) continue;
    if( FD_UNLIKELY( fd_topo_create_workspace( topo, wksp, 1 ) )==-1 ) {
      FD_TEST( 0==fd_topo_create_workspace( topo, wksp, 0 ) );
    }
    fd_topo_join_workspace( topo, wksp, FD_SHMEM_JOIN_MODE_READ_WRITE, 0 );
    fd_topo_wksp_new( topo, wksp, CALLBACKS );
    fd_topo_leave_workspace( topo, wksp );
  }
  initialize_stacks( config );

  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  fd_topo_fill( topo );

  /* Topology boilerplate: Find replay_out link and clear it */
  ulong replay_out_link_id = fd_topo_find_link( topo, "replay_out", 0UL ); FD_TEST( replay_out_link_id!=ULONG_MAX );
  fd_topo_link_t const * replay_out_link = &topo->links[ replay_out_link_id ];
  fd_frag_meta_t *       replay_mcache   = replay_out_link->mcache; FD_TEST( replay_mcache );
  void *                 replay_dcache   = replay_out_link->dcache; FD_TEST( replay_dcache );
  fd_wksp_t *            replay_wksp     = fd_wksp_containing( replay_dcache ); FD_TEST( replay_wksp );
  ulong                  replay_depth    = fd_mcache_depth( replay_mcache );
  for( ulong i=0UL; i<replay_depth; i++ ) {
    replay_mcache[ i ].seq = i-1UL;
  }
  fd_mcache_seq_update( fd_mcache_seq_laddr( replay_mcache ), ULONG_MAX );

  fd_topo_run_single_process( topo, 2, config->uid, config->gid, fdctl_tile_run );

  /* Topology boilerplate: Find published bank */
  ulong banks_obj_id = fd_pod_query_ulong( topo->props, "banks", ULONG_MAX ); FD_TEST( banks_obj_id!=ULONG_MAX );
  fd_banks_t * banks = fd_banks_join( fd_topo_obj_laddr( topo, banks_obj_id ) ); FD_TEST( banks );
  ulong bank_idx = banks->root_idx;
  FD_TEST( bank_idx < banks->max_total_banks );

  ulong                  snapmk_tile_id     = fd_topo_find_tile( topo, "snapmk", 0UL ); FD_TEST( snapmk_tile_id!=ULONG_MAX );
  fd_topo_tile_t const * snapmk_tile        = &topo->tiles[ snapmk_tile_id ];
  ulong *                snapmk_metrics_obj = snapmk_tile->metrics;
  ulong volatile *       mk_tile_metrics    = fd_metrics_tile( snapmk_metrics_obj );

  ulong snapzp_cnt = fd_topo_tile_name_cnt( topo, "snapzp" );
  ulong volatile * zp_in_metrics[ FD_TOPO_MAX_TILE_IN_LINKS ];
  for( ulong i=0UL; i<snapzp_cnt; i++ ) {
    ulong snapzp_tile_id = fd_topo_find_tile( topo, "snapzp", i ); FD_TEST( snapzp_tile_id!=ULONG_MAX );
    fd_topo_tile_t const * snapzp_tile = &topo->tiles[ snapzp_tile_id ];
    ulong *         snapzp_metrics_obj = snapzp_tile->metrics;
    zp_in_metrics[ i ] = fd_metrics_tile( snapzp_metrics_obj );
  }

# define SUM_ZP_METRIC( id ) __extension__ ({ ulong x = 0UL; for( ulong i=0UL; i<snapzp_cnt; i++ ) x += zp_in_metrics[ i ][ MIDX( COUNTER, SNAPZP, id ) ]; x; })
  ulong accounts_before = SUM_ZP_METRIC( ACCOUNTS_COMPRESSED );
  long dt = -fd_log_wallclock();

  /* Send snapshot create command */
  ulong start_signal = mk_tile_metrics[ MIDX( COUNTER, SNAPMK, SNAPSHOTS_CREATED ) ];

  ulong chunk0 = fd_dcache_compact_chunk0( replay_wksp, replay_dcache );
  fd_replay_snap_create_t * msg = fd_chunk_to_laddr( replay_wksp, chunk0 );
  msg->bank_idx = bank_idx;
  ulong seq    = 0UL;
  ulong chunk  = fd_laddr_to_chunk( replay_wksp, msg );
  ulong sz     = sizeof(fd_replay_snap_create_t);
  ulong ctl    = fd_frag_meta_ctl( 0, 1, 1, 0 );
  ulong tspub  = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_mcache_publish( replay_mcache, replay_depth, seq, REPLAY_SIG_SNAP_CREATE, chunk, sz, ctl, 0UL, tspub );

  /* Wait for snapshot creation to start */
  while( mk_tile_metrics[ MIDX( COUNTER, SNAPMK, SNAPSHOTS_CREATED ) ]==start_signal ) {
    fd_log_sleep( (long)1e6 );
  }
  ulong accounts_processed_prev = SUM_ZP_METRIC( ACCOUNTS_COMPRESSED );
  ulong tot_sz_prev             = SUM_ZP_METRIC( BYTES_COMPRESSED    );
  ulong tot_sz_before = tot_sz_prev;
  long period = (long)2e7;
  while( mk_tile_metrics[ MIDX( GAUGE, SNAPMK, ACTIVE ) ] ) {
    fd_log_sleep( period );
    ulong accounts_processed = SUM_ZP_METRIC( ACCOUNTS_COMPRESSED );
    ulong tot_sz             = SUM_ZP_METRIC( BYTES_COMPRESSED  );
    ulong accounts_delta     = accounts_processed - accounts_processed_prev;
    ulong sz_delta           = tot_sz - tot_sz_prev;
    char buf[ 64 ];
    FD_LOG_NOTICE(( "  accounts=%3.2e/s  data=%s",
      (double)accounts_delta * (1e9/(double)period),
      fmt_bytes( buf, sizeof(buf), (double)sz_delta * (1e9/(double)period) ) ));
    accounts_processed_prev = accounts_processed;
    tot_sz_prev = tot_sz;
  }

  dt += fd_log_wallclock();
  ulong accounts_after = SUM_ZP_METRIC( ACCOUNTS_COMPRESSED );
  ulong tot_sz_after = 0UL; for( ulong i=0UL; i<snapzp_cnt; i++ ) tot_sz_after += zp_in_metrics[ i ][ MIDX( COUNTER, SNAPZP, BYTES_COMPRESSED ) ];
  ulong account_cnt = accounts_after - accounts_before;
  char buf[ 64 ];
  FD_LOG_NOTICE(( "Done: %lu accounts in %.1f seconds (%g accounts/s, %s compress input)",
                  account_cnt,
                  (double)dt/1e9,
                  (double)account_cnt / ((double)dt/1e9),
                  fmt_bytes( buf, sizeof(buf), (double)(tot_sz_after - tot_sz_before) / ((double)dt/1e9) ) ) );
# undef SUM_ZP_METRIC
}

action_t fd_action_snapshot_create_offline = {
  .name           = "snapshot-create-offline",
  .topo           = snapshot_create_offline_topo,
  .fn             = snapshot_create_offline_cmd_fn,
  .description    = "Create a snapshot (offline)",
  .require_config = 1
};
