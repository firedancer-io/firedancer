/* The repair command spawns a smaller topology for profiling the repair
   tile.  This is a standalone application, and it can be run in mainnet,
   testnet and/or a private cluster. */

#include "../../../disco/net/fd_net_tile.h"
#include "../../../disco/tiles.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../../disco/topo/fd_cpu_topo.h"
#include "../../../util/pod/fd_pod_format.h"

#include "../../firedancer/topology.h"
#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h" /* initialize_workspaces */
#include "../../shared/fd_config.h" /* config_t */
#include "../../shared_dev/commands/dev.h"
#include "../../../disco/tiles.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../../util/pod/fd_pod_format.h"
#include "../../../waltz/resolv/fd_io_readline.h"
#include "../../platform/fd_sys_util.h"
#include "../../shared/commands/monitor/helper.h"
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../discof/restore/utils/fd_ssmanifest_parser.h"
#include "../../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../../flamenco/stakes/fd_stake_weight.h"
#include "../../../flamenco/leaders/fd_leaders_base.h"
#include "../../../discof/repair/fd_repair_tile.c"

#include "gossip.h"
#include "core_subtopo.h"

#include <unistd.h> /* pause */
#include <fcntl.h>
#include <stdio.h>
#include <termios.h>
#include <errno.h>

extern action_t fd_action_repair;

struct fd_location_info {
  ulong ip4_addr;         /* for map key convenience */
  char location[ 128 ];
};
typedef struct fd_location_info fd_location_info_t;

#define MAP_NAME    fd_location_table
#define MAP_T       fd_location_info_t
#define MAP_KEY     ip4_addr
#define MAP_LG_SLOT_CNT 16
#define MAP_MEMOIZE 0
#include "../../../util/tmpl/fd_map.c"

uchar __attribute__((aligned(alignof(fd_location_info_t)))) location_table_mem[ sizeof(fd_location_info_t) * (1 << 16 ) ];

static struct termios termios_backup;

static void
restore_terminal( void ) {
  (void)tcsetattr( STDIN_FILENO, TCSANOW, &termios_backup );
}

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

void
resolve_gossip_entrypoints( config_t * config );

#define MANIFEST_LOAD_MAX_SZ (2UL * FD_SHMEM_GIGANTIC_PAGE_SZ)

/* https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L632 */
static int
repair_verify_epoch_stakes( fd_snapshot_manifest_t const * manifest ) {
  fd_epoch_schedule_t epoch_schedule = (fd_epoch_schedule_t){
    .slots_per_epoch             = manifest->epoch_schedule_params.slots_per_epoch,
    .leader_schedule_slot_offset = manifest->epoch_schedule_params.leader_schedule_slot_offset,
    .warmup                      = manifest->epoch_schedule_params.warmup,
    .first_normal_epoch          = manifest->epoch_schedule_params.first_normal_epoch,
    .first_normal_slot           = manifest->epoch_schedule_params.first_normal_slot,
  };

  ulong min_required_epoch = fd_slot_to_epoch( &epoch_schedule, manifest->slot, NULL );
  ulong max_required_epoch = fd_slot_to_leader_schedule_epoch( &epoch_schedule, manifest->slot );

  for( ulong i=min_required_epoch; i<=max_required_epoch; i++ ) {
    int found = 0;
    for( ulong j=0UL; j<FD_EPOCH_STAKES_LEN; j++ ) {
      if( manifest->epoch_stakes[j].epoch==i ) {
        found = 1;
        break;
      }
    }
    if( FD_UNLIKELY( !found ) ) {
      FD_LOG_WARNING(( "stakes not found for epoch %lu in manifest", i ));
      return -1;
    }
  }
  return 0;
}

static inline ulong
repair_generate_epoch_info_msg( ulong                                       epoch,
                                fd_epoch_schedule_t const *                 epoch_schedule,
                                fd_snapshot_manifest_epoch_stakes_t const * epoch_stakes,
                                ulong *                                     epoch_info_msg_out ) {
  fd_epoch_info_msg_t *    epoch_info_msg = (fd_epoch_info_msg_t *)fd_type_pun( epoch_info_msg_out );
  fd_vote_stake_weight_t * stake_weights  = fd_epoch_info_msg_stake_weights( epoch_info_msg );

  epoch_info_msg->epoch             = epoch;
  epoch_info_msg->start_slot        = fd_epoch_slot0( epoch_schedule, epoch );
  epoch_info_msg->slot_cnt          = fd_epoch_slot_cnt( epoch_schedule, epoch );
  epoch_info_msg->excluded_id_stake = 0UL;
  epoch_info_msg->ns_per_slot       = FD_SLOT_PARAMS_400MS.ns_per_slot;

  fd_memset( &epoch_info_msg->features, 0xFF, sizeof(fd_features_t) );

  ulong idx = 0UL;
  for( ulong i=0UL; i<epoch_stakes->vote_stakes_len; i++ ) {
    ulong stake = epoch_stakes->vote_stakes[ i ].stake;
    if( FD_UNLIKELY( !stake ) ) continue;
    stake_weights[ idx ].stake = stake;
    memcpy( stake_weights[ idx ].id_key.uc, epoch_stakes->vote_stakes[ i ].identity, sizeof(fd_pubkey_t) );
    memcpy( stake_weights[ idx ].vote_key.uc, epoch_stakes->vote_stakes[ i ].vote, sizeof(fd_pubkey_t) );
    idx++;
  }
  epoch_info_msg->staked_vote_cnt = idx;
  sort_vote_weights_by_stake_vote_inplace( stake_weights, idx );

  fd_stake_weight_t * id_weights = fd_epoch_info_msg_id_weights( epoch_info_msg );
  epoch_info_msg->staked_id_cnt = compute_id_weights_from_vote_weights( id_weights, stake_weights, epoch_info_msg->staked_vote_cnt );
  FD_TEST( idx<=MAX_SHRED_DESTS );

  epoch_info_msg->epoch_schedule = *epoch_schedule;
  return fd_epoch_info_msg_sz( epoch_info_msg->staked_vote_cnt, epoch_info_msg->staked_id_cnt );
}

/* repair_load_manifest loads the snapshot manifest from disk and
   pre-populates the snapin_manif and replay_epoch dcache links so
   that consumer tiles see the data on their first poll cycle. */
static void
repair_load_manifest( fd_topo_t *  topo,
                      char const * manifest_path ) {
  if( FD_UNLIKELY( !manifest_path || !manifest_path[0] ) ) return;

  /* Parse manifest */

  int fd = open( manifest_path, O_RDONLY );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "open(%s) failed (%d-%s)", manifest_path, errno, fd_io_strerror( errno ) ));

  fd_snapshot_manifest_t * manifest = aligned_alloc( alignof(fd_snapshot_manifest_t), sizeof(fd_snapshot_manifest_t) );
  FD_TEST( manifest );
  for( ulong i=0UL; i<FD_EPOCH_STAKES_LEN; i++ ) manifest->epoch_stakes[i].epoch = ULONG_MAX;

  uchar * buf = aligned_alloc( 128UL, MANIFEST_LOAD_MAX_SZ );
  FD_TEST( buf );
  ulong buf_sz = 0;
  FD_TEST( !fd_io_read( fd, buf, 0UL, MANIFEST_LOAD_MAX_SZ-1UL, &buf_sz ) );
  close( fd );

  fd_ssmanifest_parser_t * parser = fd_ssmanifest_parser_join( fd_ssmanifest_parser_new(
      aligned_alloc( fd_ssmanifest_parser_align(), fd_ssmanifest_parser_footprint() ) ) );
  FD_TEST( parser );
  fd_ssmanifest_parser_init( parser, manifest );
  int parser_err = fd_ssmanifest_parser_consume( parser, buf, buf_sz );
  FD_TEST( parser_err!=FD_SSMANIFEST_PARSER_ADVANCE_ERROR );
  FD_TEST( fd_ssmanifest_parser_fini( parser )==FD_SSMANIFEST_PARSER_ADVANCE_DONE );
  free( parser );
  free( buf );

  FD_LOG_NOTICE(( "manifest bank slot %lu", manifest->slot ));
  FD_TEST( !repair_verify_epoch_stakes( manifest ) );

  /* Update root_slot fseq */

  ulong root_slot_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "root_slot" );
  if( FD_LIKELY( root_slot_obj_id!=ULONG_MAX ) ) {
    ulong * root_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, root_slot_obj_id ) );
    FD_TEST( root_fseq );
    fd_fseq_update( root_fseq, manifest->slot );
  }

  /* Publish manifest to snapin_manif dcache */

  ulong snap_link_idx = fd_topo_find_link( topo, "snapin_manif", 0UL );
  FD_TEST( snap_link_idx!=ULONG_MAX );
  fd_topo_link_t * snap_link = &topo->links[ snap_link_idx ];
  fd_wksp_t *      snap_mem  = topo->workspaces[ topo->objs[ snap_link->dcache_obj_id ].wksp_id ].wksp;
  ulong snap_chunk0 = fd_dcache_compact_chunk0( snap_mem, snap_link->dcache );
  ulong snap_wmark  = fd_dcache_compact_wmark ( snap_mem, snap_link->dcache, snap_link->mtu );
  ulong snap_chunk  = snap_chunk0;

  uchar * snap_dst = fd_chunk_to_laddr( snap_mem, snap_chunk );
  memcpy( snap_dst, manifest, sizeof(fd_snapshot_manifest_t) );
  fd_mcache_publish( snap_link->mcache, snap_link->depth, 0UL,
                     fd_ssmsg_sig( FD_SSMSG_MANIFEST_INCREMENTAL ),
                     snap_chunk, sizeof(fd_snapshot_manifest_t), 0UL, 0UL, 0UL );
  snap_chunk = fd_dcache_compact_next( snap_chunk, sizeof(fd_snapshot_manifest_t), snap_chunk0, snap_wmark );

  fd_mcache_publish( snap_link->mcache, snap_link->depth, 1UL,
                     fd_ssmsg_sig( FD_SSMSG_DONE ), 0UL, 0UL, 0UL, 0UL, 0UL );

  /* Publish epoch stake weights to replay_epoch dcache */

  ulong epoch_link_idx = fd_topo_find_link( topo, "replay_epoch", 0UL );
  FD_TEST( epoch_link_idx!=ULONG_MAX );
  fd_topo_link_t * epoch_link = &topo->links[ epoch_link_idx ];
  fd_wksp_t *      epoch_mem  = topo->workspaces[ topo->objs[ epoch_link->dcache_obj_id ].wksp_id ].wksp;
  ulong epoch_chunk0 = fd_dcache_compact_chunk0( epoch_mem, epoch_link->dcache );
  ulong epoch_wmark  = fd_dcache_compact_wmark ( epoch_mem, epoch_link->dcache, epoch_link->mtu );
  ulong epoch_chunk  = epoch_chunk0;
  ulong epoch_seq    = 0UL;

  /* Construct fd_epoch_schedule_t field-by-field rather than type-punning
     from the unpacked manifest struct (fd_epoch_schedule_t is packed). */
  fd_epoch_schedule_t schedule_local;
  schedule_local.slots_per_epoch             = manifest->epoch_schedule_params.slots_per_epoch;
  schedule_local.leader_schedule_slot_offset = manifest->epoch_schedule_params.leader_schedule_slot_offset;
  schedule_local.warmup                      = manifest->epoch_schedule_params.warmup;
  schedule_local.first_normal_epoch          = manifest->epoch_schedule_params.first_normal_epoch;
  schedule_local.first_normal_slot           = manifest->epoch_schedule_params.first_normal_slot;
  fd_epoch_schedule_t const * schedule = &schedule_local;
  ulong epoch = fd_slot_to_epoch( schedule, manifest->slot, NULL );

  ulong epoch_stakes_base      = epoch > 0UL ? epoch - 1UL : 0UL;
  ulong leader_schedule_epoch  = fd_slot_to_leader_schedule_epoch( schedule, manifest->slot );
  ulong cur_idx = epoch - epoch_stakes_base;
  FD_TEST( cur_idx < FD_EPOCH_STAKES_LEN );

  ulong * epoch_dst = fd_chunk_to_laddr( epoch_mem, epoch_chunk );
  ulong epoch_sz = repair_generate_epoch_info_msg( epoch, schedule, &manifest->epoch_stakes[cur_idx], epoch_dst );
  fd_mcache_publish( epoch_link->mcache, epoch_link->depth, epoch_seq,
                     4UL, epoch_chunk, epoch_sz, 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  epoch_chunk = fd_dcache_compact_next( epoch_chunk, epoch_sz, epoch_chunk0, epoch_wmark );
  epoch_seq++;
  FD_LOG_NOTICE(( "sending current epoch stake weights - epoch: %lu", epoch ));

  if( leader_schedule_epoch >= epoch + 1UL ) {
    ulong next_idx = epoch + 1UL - epoch_stakes_base;
    FD_TEST( next_idx < FD_EPOCH_STAKES_LEN );

    epoch_dst = fd_chunk_to_laddr( epoch_mem, epoch_chunk );
    epoch_sz = repair_generate_epoch_info_msg( epoch + 1UL, schedule, &manifest->epoch_stakes[next_idx], epoch_dst );
    fd_mcache_publish( epoch_link->mcache, epoch_link->depth, epoch_seq,
                       4UL, epoch_chunk, epoch_sz, 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
    epoch_chunk = fd_dcache_compact_next( epoch_chunk, epoch_sz, epoch_chunk0, epoch_wmark );
    epoch_seq++;
    FD_LOG_NOTICE(( "sending next epoch stake weights - epoch: %lu", epoch + 1UL ));
  }
  (void)epoch_chunk;

  free( manifest );
}

/* repair_topo is a subset of "src/app/firedancer/topology.c" at commit
   0d8386f4f305bb15329813cfe4a40c3594249e96, slightly modified to work
   as a repair catchup.  TODO ideally, one should invoke the firedancer
   topology first, and exclude the parts that are not needed, instead of
   manually generating new topologies for every command.  This would
   also guarantee that the catchup is replicating (as close as possible)
   the full topology. */
static void
repair_topo( config_t * config ) {
  resolve_gossip_entrypoints( config );

  ulong net_tile_cnt    = config->layout.net_tile_count;
  ulong shred_tile_cnt  = config->layout.shred_tile_count;
  ulong quic_tile_cnt   = config->layout.quic_tile_count;
  ulong sign_tile_cnt   = config->firedancer.layout.sign_tile_count;
  ulong gossvf_tile_cnt = config->firedancer.layout.gossvf_tile_count;

  fd_topo_t * topo = { fd_topob_new( &config->topo, config->name ) };
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  topo->gigantic_page_threshold = config->hugetlbfs.gigantic_page_threshold_mib << 20;

  ulong tile_to_cpu[ FD_TILE_MAX ] = {0};
  ushort parsed_tile_to_cpu[ FD_TILE_MAX ];
  /* Unassigned tiles will be floating, unless auto topology is enabled. */
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) parsed_tile_to_cpu[ i ] = USHORT_MAX;

  int is_auto_affinity = !strcmp( config->layout.affinity, "auto" );
  int is_bench_auto_affinity = !strcmp( config->development.bench.affinity, "auto" );

  if( FD_UNLIKELY( is_auto_affinity != is_bench_auto_affinity ) ) {
    FD_LOG_ERR(( "The CPU affinity string in the configuration file under [layout.affinity] and [development.bench.affinity] must all be set to 'auto' or all be set to a specific CPU affinity string." ));
  }

  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );

  ulong affinity_tile_cnt = 0UL;
  if( FD_LIKELY( !is_auto_affinity ) ) affinity_tile_cnt = fd_topob_parse_affinity_cstr( config->layout.affinity, parsed_tile_to_cpu, 0 );

  for( ulong i=0UL; i<affinity_tile_cnt; i++ ) {
    if( FD_UNLIKELY( parsed_tile_to_cpu[ i ]!=USHORT_MAX && parsed_tile_to_cpu[ i ]>=cpus->cpu_cnt ) )
      FD_LOG_ERR(( "The CPU affinity string in the configuration file under [layout.affinity] specifies a CPU index of %hu, but the system "
                  "only has %lu CPUs. You should either change the CPU allocations in the affinity string, or increase the number of CPUs "
                  "in the system.",
                  parsed_tile_to_cpu[ i ], cpus->cpu_cnt ));
    tile_to_cpu[ i ] = fd_ulong_if( parsed_tile_to_cpu[ i ]==USHORT_MAX, ULONG_MAX, (ulong)parsed_tile_to_cpu[ i ] );
  }

  fd_core_subtopo(   config, tile_to_cpu );
  fd_gossip_subtopo( config, tile_to_cpu );

  /*             topo, name */
  fd_topob_wksp( topo, "net_shred"    );
  fd_topob_wksp( topo, "net_repair"   );
  fd_topob_wksp( topo, "net_quic"     );

  fd_topob_wksp( topo, "shred_out"    );
  fd_topob_wksp( topo, "replay_epoch" );

  fd_topob_wksp( topo, "poh_shred"    );

  fd_topob_wksp( topo, "shred_sign"   );
  fd_topob_wksp( topo, "sign_shred"   );

  fd_topob_wksp( topo, "repair_sign"  );
  fd_topob_wksp( topo, "sign_repair"  );
  fd_topob_wksp( topo, "rnonce"       );
  fd_topob_wksp( topo, "repair_out"  );

  fd_topob_wksp( topo, "txsend_out"   );

  fd_topob_wksp( topo, "shred"        );
  fd_topob_wksp( topo, "repair"       );
  fd_topob_wksp( topo, "fec_sets"     );
  fd_topob_wksp( topo, "snapin_manif" );

  fd_topob_wksp( topo, "genesi_out"   ); /* mock genesi_out for ipecho */

  fd_topob_wksp( topo, "tower_out"    ); /* mock tower_out for confirmation msgs. Not needed for any topo except eqvoc. */

  #define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )

  ulong pending_fec_shreds_depth = fd_ulong_min( fd_ulong_pow2_up( config->tiles.shred.max_pending_shred_sets * FD_REEDSOL_DATA_SHREDS_MAX ), USHORT_MAX + 1 /* dcache max */ );

  /*                                  topo, link_name,      wksp_name,      depth,                                    mtu,                           burst */
  FOR(quic_tile_cnt)   fd_topob_link( topo, "quic_net",     "net_quic",     config->net.ingress_buffer_size,          FD_NET_MTU,                    1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_net",    "net_shred",    config->net.ingress_buffer_size,          FD_NET_MTU,                    1UL );

  /**/                 fd_topob_link( topo, "replay_epoch", "replay_epoch", 128UL,                                    FD_EPOCH_OUT_MTU,              1UL );

  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_sign",   "shred_sign",   128UL,                                    32UL,                          1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "sign_shred",   "sign_shred",   128UL,                                    64UL,                          1UL );

  /**/                 fd_topob_link( topo, "repair_net",   "net_repair",   config->net.ingress_buffer_size,          FD_NET_MTU,                    1UL );

  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_out",    "shred_out",    pending_fec_shreds_depth,                 sizeof(fd_shred_message_t),    2UL /* at most 2 msgs per after_frag */ );
  FOR(sign_tile_cnt-1) fd_topob_link( topo, "repair_sign",  "repair_sign",  256UL,                                    FD_REPAIR_MAX_PREIMAGE_SZ,     1UL );
  FOR(sign_tile_cnt-1) fd_topob_link( topo, "sign_repair",  "sign_repair",  128UL,                                    sizeof(fd_ed25519_sig_t),      1UL );

  /**/                 fd_topob_link( topo, "repair_out",   "repair_out",   128UL,                                    sizeof(fd_fec_complete_t),   1UL );

  /**/                 fd_topob_link( topo, "poh_shred",    "poh_shred",    16384UL,                                  USHORT_MAX,                    1UL );

  /**/                 fd_topob_link( topo, "txsend_out",   "txsend_out",   128UL,                                    FD_TXN_MTU,                    1UL );

  /**/                 fd_topob_link( topo, "snapin_manif", "snapin_manif", 2UL,                                      sizeof(fd_snapshot_manifest_t),1UL );

  /**/                 fd_topob_link( topo, "genesi_out",   "genesi_out",   1UL,                                      FD_GENESIS_TILE_MTU,            1UL );
  /**/                 fd_topob_link( topo, "tower_out",    "tower_out",    1024UL,                                   sizeof(fd_tower_msg_t),         1UL );

  FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_repair", i, config->net.ingress_buffer_size );
  FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_quic",   i, config->net.ingress_buffer_size );
  FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_shred",  i, config->net.ingress_buffer_size );

  /*                                              topo, tile_name, tile_wksp, metrics_wksp, cpu_idx,                       is_agave, uses_id_keyswitch, uses_av_keyswitch */
  FOR(shred_tile_cnt)              fd_topob_tile( topo, "shred",   "shred",   "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1,                 0 );
  fd_topo_tile_t * repair_tile =   fd_topob_tile( topo, "repair",  "repair",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1,                 0 );

  /* Setup a shared wksp object for fec sets. */

  ulong shred_depth = 65536UL; /* from fdctl/topology.c shred_store link. MAKE SURE TO KEEP IN SYNC. */
  ulong fec_set_cnt = 2UL*shred_depth + config->tiles.shred.max_pending_shred_sets + 6UL;
  ulong fec_sets_sz = fec_set_cnt*sizeof(fd_fec_set_t); /* mirrors # of dcache entires in frankendancer */
  fd_topo_obj_t * fec_sets_obj = setup_topo_fec_sets( topo, "fec_sets", shred_tile_cnt*fec_sets_sz );
  for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
    fd_topo_tile_t * shred_tile = &topo->tiles[ fd_topo_find_tile( topo, "shred", i ) ];
    fd_topob_tile_uses( topo, shred_tile,  fec_sets_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  }
  fd_topob_tile_uses( topo, repair_tile, fec_sets_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  FD_TEST( fd_pod_insertf_ulong( topo->props, fec_sets_obj->id, "fec_sets" ) );

  /* There's another special fseq that's used to communicate the shred
    version from the Agave boot path to the shred tile. */
  fd_topo_obj_t * poh_shred_obj = fd_topob_obj( topo, "fseq", "poh_shred" );
  fd_topo_tile_t * poh_tile = &topo->tiles[ fd_topo_find_tile( topo, "gossip", 0UL ) ];
  fd_topob_tile_uses( topo, poh_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
    fd_topo_tile_t * shred_tile = &topo->tiles[ fd_topo_find_tile( topo, "shred", i ) ];
    fd_topob_tile_uses( topo, shred_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  }
  FD_TEST( fd_pod_insertf_ulong( topo->props, poh_shred_obj->id, "poh_shred" ) );

  if( FD_LIKELY( !is_auto_affinity ) ) {
    if( FD_UNLIKELY( affinity_tile_cnt<topo->tile_cnt ) )
      FD_LOG_ERR(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [layout.affinity] only provides for %lu cores. "
                  "You should either increase the number of cores dedicated to Firedancer in the affinity string, or decrease the number of cores needed by reducing "
                  "the total tile count. You can reduce the tile count by decreasing individual tile counts in the [layout] section of the configuration file.",
                  topo->tile_cnt, affinity_tile_cnt ));
    if( FD_UNLIKELY( affinity_tile_cnt>topo->tile_cnt ) )
      FD_LOG_WARNING(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [layout.affinity] provides for %lu cores. "
                      "Not all cores in the affinity will be used by Firedancer. You may wish to increase the number of tiles in the system by increasing "
                      "individual tile counts in the [layout] section of the configuration file.",
                      topo->tile_cnt, affinity_tile_cnt ));
  }

  /*                                      topo, tile_name, tile_kind_id, fseq_wksp,   link_name,      link_kind_id,  reliable,            polled */
  for( ulong j=0UL; j<shred_tile_cnt; j++ )
                  fd_topos_tile_in_net(  topo,                           "metric_in", "shred_net",     j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  for( ulong j=0UL; j<quic_tile_cnt; j++ )
                  {fd_topos_tile_in_net(  topo,                          "metric_in", "quic_net",      j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );} /* No reliable consumers of networking fragments, may be dropped or overrun */

  /**/            fd_topob_tile_in(      topo, "gossip",  0UL,           "metric_in", "txsend_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );

  /**/            fd_topos_tile_in_net(  topo,                           "metric_in", "repair_net",    0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */

  FOR(shred_tile_cnt) for( ulong j=0UL; j<net_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "net_shred",     j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "poh_shred",     0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "replay_epoch",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "gossip_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_out( topo, "shred",  i,                          "shred_out",     i                                                    );
  FOR(shred_tile_cnt)  fd_topob_tile_out( topo, "shred",  i,                          "shred_net",     i                                                    );
  FOR(shred_tile_cnt)  fd_topob_tile_in ( topo, "shred",  i,             "metric_in", "ipecho_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );

  /**/                 fd_topob_tile_out( topo, "repair",  0UL,                       "repair_net",    0UL                                                  );

  /* Sign links don't need to be reliable because they are synchronous,
    so there's at most one fragment in flight at a time anyway.  The
    sign links are also not polled by the mux, instead the tiles will
    read the sign responses out of band in a dedicated spin loop. */
  for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
    /**/               fd_topob_tile_in(  topo, "sign",   0UL,           "metric_in", "shred_sign",    i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
    /**/               fd_topob_tile_out( topo, "shred",  i,                          "shred_sign",    i                                                    );
    /**/               fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "sign_shred",    i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
    /**/               fd_topob_tile_out( topo, "sign",   0UL,                        "sign_shred",    i                                                    );
  }
  FOR(gossvf_tile_cnt) fd_topob_tile_in ( topo, "gossvf",   i,           "metric_in", "replay_epoch",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );

  /**/                 fd_topob_tile_in ( topo, "gossip",   0UL,         "metric_in", "replay_epoch",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );

  FOR(net_tile_cnt)    fd_topob_tile_in(  topo, "repair",  0UL,          "metric_in", "net_repair",    i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                 fd_topob_tile_in(  topo, "repair",  0UL,          "metric_in", "gossip_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
                       fd_topob_tile_in(  topo, "repair",  0UL,          "metric_in", "snapin_manif",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "repair",  0UL,          "metric_in", "shred_out",     i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  FOR(sign_tile_cnt-1) fd_topob_tile_out( topo, "repair", 0UL,                        "repair_sign",   i                                                    );
  FOR(sign_tile_cnt-1) fd_topob_tile_in ( topo, "sign",   i+1,           "metric_in", "repair_sign",   i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  FOR(sign_tile_cnt-1) fd_topob_tile_out( topo, "sign",   i+1,                        "sign_repair",   i                                                    );
  FOR(sign_tile_cnt-1) fd_topob_tile_in ( topo, "repair", 0UL,           "metric_in", "sign_repair",   i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );

  /**/                 fd_topob_tile_out( topo, "repair", 0UL,                        "repair_out",   0UL                                                   );
  /**/                 fd_topob_tile_in ( topo, "gossip", 0UL,           "metric_in", "sign_gossip",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  /**/                 fd_topob_tile_in ( topo, "ipecho", 0UL,           "metric_in", "genesi_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_in ( topo, "repair", 0UL,           "metric_in", "tower_out",     0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );

  /* Repair and shred share a secret they use to generate the nonces.
    It's not super security sensitive, but for good hygiene, we make it
    an object. */
  if( 1 /* just restrict the scope for these variables in this big function */ ) {
    fd_topo_obj_t * rnonce_ss_obj = fd_topob_obj( topo, "rnonce_ss", "rnonce" );
    fd_topo_tile_t * repair_tile = &topo->tiles[ fd_topo_find_tile( topo, "repair", 0UL ) ];
    fd_topob_tile_uses( topo, repair_tile, rnonce_ss_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
    for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
      fd_topo_tile_t * shred_tile = &topo->tiles[ fd_topo_find_tile( topo, "shred", i ) ];
      fd_topob_tile_uses( topo, shred_tile, rnonce_ss_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
    }
    FD_TEST( fd_pod_insertf_ulong( topo->props, rnonce_ss_obj->id, "rnonce_ss" ) );
  }

  FD_TEST( fd_link_permit_no_producers( topo, "quic_net"      ) == quic_tile_cnt );
  FD_TEST( fd_link_permit_no_producers( topo, "poh_shred"     ) == 1UL           );
  FD_TEST( fd_link_permit_no_producers( topo, "txsend_out"    ) == 1UL           );
  FD_TEST( fd_link_permit_no_producers( topo, "genesi_out"    ) == 1UL           );
  FD_TEST( fd_link_permit_no_producers( topo, "tower_out"     ) == 1UL           );
  FD_TEST( fd_link_permit_no_producers( topo, "replay_epoch"  ) == 1UL           );
  FD_TEST( fd_link_permit_no_producers( topo, "snapin_manif"  ) == 1UL           );
  FD_TEST( fd_link_permit_no_consumers( topo, "net_quic"     ) == net_tile_cnt  );
  FD_TEST( fd_link_permit_no_consumers( topo, "repair_out"   ) == 1UL           );

  config->tiles.txsend.txsend_src_port = 0; /* disable txsend */

  FOR(net_tile_cnt) fd_topos_net_tile_finish( topo, i );

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    fd_topo_configure_tile( tile, config );
  }

  if( FD_UNLIKELY( is_auto_affinity ) ) fd_topob_auto_layout( topo, 0 );

  fd_topob_finish( topo, CALLBACKS );

  config->topo = *topo;
}

static char *
fmt_count( char buf[ static 64 ], ulong count ) {
  char tmp[ 64 ];
  if( FD_LIKELY( count<1000UL ) ) FD_TEST( fd_cstr_printf_check( tmp, 64UL, NULL, "%lu", count ) );
  else if( FD_LIKELY( count<1000000UL ) ) FD_TEST( fd_cstr_printf_check( tmp, 64UL, NULL, "%.1f K", (double)count/1000.0 ) );
  else if( FD_LIKELY( count<1000000000UL ) ) FD_TEST( fd_cstr_printf_check( tmp, 64UL, NULL, "%.1f M", (double)count/1000000.0 ) );

  FD_TEST( fd_cstr_printf_check( buf, 64UL, NULL, "%12s", tmp ) );
  return buf;
}

static void
print_histogram_buckets( volatile ulong * metrics,
                         ulong offset,
                         int converter,
                         double histmin,
                         double histmax,
                         char * title ) {
  fd_histf_t hist[1];

  /* Create histogram structure only to get bucket edges for display */
  if( FD_LIKELY( converter == FD_METRICS_CONVERTER_SECONDS ) ) {
    /* For SLOT_COMPLETE_TIME: min=0.2, max=2.0 seconds */
    FD_TEST( fd_histf_new( hist, fd_metrics_convert_seconds_to_ticks( histmin ), fd_metrics_convert_seconds_to_ticks( histmax ) ) );
  } else if( FD_LIKELY( converter == FD_METRICS_CONVERTER_NONE ) ) {
    /* For non-time histograms, we'd need the actual min/max values */
    FD_TEST( fd_histf_new( hist, (ulong)histmin, (ulong)histmax ) );
  } else {
    FD_LOG_ERR(( "unknown converter %i", converter ));
  }

  printf( " +---------------------+--------------------+--------------+\n" );
  printf( " | %-19s |                    | Count        |\n", title );
  printf( " +---------------------+--------------------+--------------+\n" );

  ulong total_count = 0;
  for( ulong k = 0; k < FD_HISTF_BUCKET_CNT; k++ ) {
    ulong bucket_count = metrics[ offset + k ];
    total_count += bucket_count;
  }

  for( ulong k = 0; k < FD_HISTF_BUCKET_CNT; k++ ) {
    /* Get individual bucket count directly from metrics array */
    ulong bucket_count = metrics[ offset + k ];

    char * le_str;
    char le_buf[ 64 ];
    if( FD_UNLIKELY( k == FD_HISTF_BUCKET_CNT - 1UL ) ) {
      le_str = "+Inf";
    } else {
      ulong edge = fd_histf_right( hist, k );
      if( FD_LIKELY( converter == FD_METRICS_CONVERTER_SECONDS ) ) {
        double edgef = fd_metrics_convert_ticks_to_seconds( edge - 1 );
        FD_TEST( fd_cstr_printf_check( le_buf, sizeof( le_buf ), NULL, "%.3f", edgef ) );
      } else {
        FD_TEST( fd_cstr_printf_check( le_buf, sizeof( le_buf ), NULL, "%.3f", (double)(edge - 1) / 1000000.0 ) );
      }
      le_str = le_buf;
    }

    char count_buf[ 64 ];
    fmt_count( count_buf, bucket_count );

    /* Match visual bar length to the %-18s display column width. */
    char  bar_buf[ 19 ];
    ulong bar_max = sizeof( bar_buf ) - 1UL;
    if( bucket_count > 0 && total_count > 0 ) {
      ulong bar_length = (bucket_count * bar_max) / total_count;
      if( bar_length == 0 ) bar_length = 1;
      if( bar_length > bar_max ) bar_length = bar_max;
      for( ulong i = 0; i < bar_length; i++ ) { bar_buf[ i ] = '|'; }
      bar_buf[ bar_length ] = '\0';
    } else {
      bar_buf[ 0 ] = '\0';
    }

    printf( " | %-19s | %-18s | %s |\n", le_str, bar_buf, count_buf );
  }

  /* Print sum and total count */
  char sum_buf[ 64 ];
  char avg_buf[ 64 ];
  if( FD_LIKELY( converter == FD_METRICS_CONVERTER_SECONDS ) ) {
    double sumf = fd_metrics_convert_ticks_to_seconds( metrics[ offset + FD_HISTF_BUCKET_CNT ] );
    FD_TEST( fd_cstr_printf_check( sum_buf, sizeof( sum_buf ), NULL, "%.6f", sumf ) );
    double avg = sumf / (double)total_count;
    FD_TEST( fd_cstr_printf_check( avg_buf, sizeof( avg_buf ), NULL, "%.6f", avg ) );
  } else {
    FD_TEST( fd_cstr_printf_check( sum_buf, sizeof( sum_buf ), NULL, "%lu", metrics[ offset + FD_HISTF_BUCKET_CNT ] ));
  }

  printf( " +---------------------+--------------------+---------------+\n" );
  printf( " | Sum: %-14s | Count: %-11lu | Avg: %-8s |\n", sum_buf, total_count, avg_buf );
  printf( " +---------------------+--------------------+---------------+\n" );
}

static fd_slot_metrics_t temp_slots[ FD_CATCHUP_METRICS_MAX ];

static void
print_catchup_slots( fd_wksp_t * repair_tile_wksp, ctx_t * repair_ctx, int verbose, int sort_by_slot ) {
  fd_repair_metrics_t * catchup = repair_ctx->slot_metrics;
  ulong catchup_gaddr = fd_wksp_gaddr_fast( repair_ctx->wksp, catchup );
  fd_repair_metrics_t * catchup_table = (fd_repair_metrics_t *)fd_wksp_laddr( repair_tile_wksp, catchup_gaddr );
  if( FD_LIKELY( sort_by_slot ) ) {
    fd_repair_metrics_print_sorted( catchup_table, verbose, temp_slots );
  } else {
    fd_repair_metrics_print( catchup_table, verbose );
  }
}

static fd_location_info_t * location_table;
static fd_pubkey_t peers_copy[ FD_REPAIR_PEER_MAX];

static ulong
sort_peers_by_latency( fd_policy_peer_map_t * active_table, fd_policy_peer_dlist_t * peers_dlist, fd_policy_peer_dlist_t * peers_wlist, fd_policy_peer_t * peers_arr ) {
  ulong i = 0;
  fd_policy_peer_dlist_iter_t iter = fd_policy_peer_dlist_iter_fwd_init( peers_dlist, peers_arr );
  while( !fd_policy_peer_dlist_iter_done( iter, peers_dlist, peers_arr ) ) {
    fd_policy_peer_t * peer = fd_policy_peer_dlist_iter_ele( iter, peers_dlist, peers_arr );
    if( FD_UNLIKELY( !peer ) ) break;
    peers_copy[ i++ ] = peer->key;
    if( FD_UNLIKELY( i >= FD_REPAIR_PEER_MAX ) ) break;
    iter = fd_policy_peer_dlist_iter_fwd_next( iter, peers_dlist, peers_arr );
  }
  ulong fast_cnt = i;
  iter = fd_policy_peer_dlist_iter_fwd_init( peers_wlist, peers_arr );
  while( !fd_policy_peer_dlist_iter_done( iter, peers_wlist, peers_arr ) ) {
    fd_policy_peer_t * peer = fd_policy_peer_dlist_iter_ele( iter, peers_wlist, peers_arr );
    if( FD_UNLIKELY( !peer ) ) break;
    peers_copy[ i++ ] = peer->key;
    if( FD_UNLIKELY( i >= FD_REPAIR_PEER_MAX ) ) break;
    iter = fd_policy_peer_dlist_iter_fwd_next( iter, peers_wlist, peers_arr );
  }
  FD_LOG_NOTICE(( "Fast peers cnt: %lu. Slow peers cnt: %lu.", fast_cnt, i - fast_cnt ));

  ulong peer_cnt = i;
  for( uint i = 0; i < peer_cnt - 1; i++ ) {
    int swapped = 0;
    for( uint j = 0; j < peer_cnt - 1 - i; j++ ) {
      fd_policy_peer_t const * active_j  = fd_policy_peer_map_ele_query( active_table, &peers_copy[ j ], NULL, peers_arr );
      fd_policy_peer_t const * active_j1 = fd_policy_peer_map_ele_query( active_table, &peers_copy[ j + 1 ], NULL, peers_arr );

      /* Skip peers with no responses */
      double latency_j  = 10e9;
      double latency_j1 = 10e9;
      if( FD_LIKELY( active_j  && active_j->res_cnt > 0  ) ) latency_j  = ((double)active_j->total_lat / (double)active_j->res_cnt);
      if( FD_LIKELY( active_j1 && active_j1->res_cnt > 0 ) ) latency_j1 = ((double)active_j1->total_lat / (double)active_j1->res_cnt);

      /* Swap if j has higher latency than j+1 */
      if( latency_j > latency_j1 ) {
        fd_pubkey_t temp    = peers_copy[ j ];
        peers_copy[ j ]     = peers_copy[ j + 1 ];
        peers_copy[ j + 1 ] = temp;
        swapped             = 1;
      }
    }
    if( !swapped ) break;
  }
  return peer_cnt;
}

static void
print_peer_location_latency( fd_wksp_t * repair_tile_wksp, ctx_t * tile_ctx ) {
  ulong              policy_gaddr  = fd_wksp_gaddr_fast( tile_ctx->wksp, tile_ctx->policy );
  fd_policy_t *      policy        = fd_wksp_laddr     ( repair_tile_wksp, policy_gaddr );
  ulong              peermap_gaddr = fd_wksp_gaddr_fast( tile_ctx->wksp, policy->peers.map  );
  ulong              peerarr_gaddr = fd_wksp_gaddr_fast( tile_ctx->wksp, policy->peers.pool );
  ulong              peerlst_gaddr = fd_wksp_gaddr_fast( tile_ctx->wksp, policy->peers.fast );
  ulong              peerwst_gaddr = fd_wksp_gaddr_fast( tile_ctx->wksp, policy->peers.slow );
  fd_policy_peer_map_t *   peers_map   = (fd_policy_peer_map_t *)  fd_wksp_laddr( repair_tile_wksp, peermap_gaddr );
  fd_policy_peer_dlist_t * peers_dlist = (fd_policy_peer_dlist_t *)fd_wksp_laddr( repair_tile_wksp, peerlst_gaddr );
  fd_policy_peer_dlist_t * peers_wlist = (fd_policy_peer_dlist_t *)fd_wksp_laddr( repair_tile_wksp, peerwst_gaddr );
  fd_policy_peer_t *       peers_arr   = (fd_policy_peer_t *)      fd_wksp_laddr( repair_tile_wksp, peerarr_gaddr );

  ulong peer_cnt = sort_peers_by_latency( peers_map, peers_dlist, peers_wlist, peers_arr );
  printf("\nPeer Location/Latency Information\n");
  printf( "     | %-46s | %-7s | %-8s | %-8s | %-7s | %-7s | %-12s | %s\n", "Pubkey", "Req Cnt", "Req B/s", "Rx B/s", "Rx Rate", "Avg Latency", "Ewma Latency", "Location Info" );
  for( uint i = 0; i < peer_cnt; i++ ) {
    fd_policy_peer_t const * active = fd_policy_peer_map_ele_query( peers_map, &peers_copy[ i ], NULL, peers_arr );
    if( FD_LIKELY( active && active->res_cnt > 0 ) ) {
      fd_location_info_t * info = fd_location_table_query( location_table, active->ip4, NULL );
      char * geolocation = info ? info->location : "";
      double peer_bps    = (double)(active->res_cnt * FD_SHRED_MIN_SZ) / ((double)(active->last_resp_ts - active->first_resp_ts) / 1e9);
      double req_bps     = (double)active->req_cnt * 202 / ((double)(active->last_req_ts - active->first_req_ts) / 1e9);
      FD_BASE58_ENCODE_32_BYTES( active->key.key, key_b58 );
      printf( "%-5u | %-46s | %-7lu | %-8.2f | %-8.2f | %-7.2f | %10.3fms | %10.3fms | %s\n", i, key_b58, active->req_cnt, req_bps, peer_bps, (double)active->res_cnt / (double)active->req_cnt, ((double)active->total_lat / (double)active->res_cnt) / 1e6, (double)active->ewma_lat / 1e6, geolocation );
    }
  }
  printf("\n");
  fflush( stdout );
}

static void
read_iptable( char * iptable_path, fd_location_info_t * location_table ) {
  int iptable_fd = open( iptable_path, O_RDONLY );
  if( FD_UNLIKELY( iptable_fd<0 ) ) return;

  /* read iptable line by line */
  if( FD_LIKELY( iptable_fd>=0 ) ) {
    char line[ 256 ];
    uchar istream_buf[256];
    fd_io_buffered_istream_t istream[1];
    fd_io_buffered_istream_init( istream, iptable_fd, istream_buf, sizeof(istream_buf) );
    for(;;) {
      int err;
      if( !fd_io_fgets( line, sizeof(line), istream, &err ) ) break;
      fd_location_info_t location_info;
      sscanf( line, "%lu %[^\n]", &location_info.ip4_addr, location_info.location );
      fd_location_info_t * info = fd_location_table_insert( location_table, location_info.ip4_addr );
      if( FD_UNLIKELY( info==NULL ) ) break;
      memcpy( info->location, location_info.location, sizeof(info->location) );
    }
  }
}

static void
print_tile_metrics( volatile ulong * shred_metrics,
                    volatile ulong * repair_metrics,
                    volatile ulong * repair_metrics_prev, /* for diffing metrics */
                    volatile ulong ** repair_net_links,
                    volatile ulong ** net_shred_links,
                    ulong   net_tile_cnt,
                    ulong * last_sent_cnt,
                    long    last_print_ts,
                    long    now ) {
  char buf2[ 64 ];
  ulong rcvd = shred_metrics [ MIDX( COUNTER, SHRED,  SHRED_REPAIR_RX ) ];
  ulong sent = repair_metrics[ MIDX( COUNTER, REPAIR, REQUEST_TX_NEEDED_WINDOW ) ] +
                repair_metrics[ MIDX( COUNTER, REPAIR, REQUEST_TX_NEEDED_HIGHEST_WINDOW ) ] +
                repair_metrics[ MIDX( COUNTER, REPAIR, REQUEST_TX_NEEDED_ORPHAN ) ];
  printf(" Requests received: (%lu/%lu) %.1f%% \n", rcvd, sent, (double)rcvd / (double)sent * 100.0 );
  printf( " +---------------+--------------+\n" );
  printf( " | Request Type  | Count        |\n" );
  printf( " +---------------+--------------+\n" );
  printf( " | Orphan        | %s |\n", fmt_count( buf2, repair_metrics[ MIDX( COUNTER, REPAIR, REQUEST_TX_NEEDED_ORPHAN         ) ] ) );
  printf( " | HighestWindow | %s |\n", fmt_count( buf2, repair_metrics[ MIDX( COUNTER, REPAIR, REQUEST_TX_NEEDED_HIGHEST_WINDOW ) ] ) );
  printf( " | Index         | %s |\n", fmt_count( buf2, repair_metrics[ MIDX( COUNTER, REPAIR, REQUEST_TX_NEEDED_WINDOW         ) ] ) );
  printf( " +---------------+--------------+\n" );
  printf( " Send Pkt Rate: %s pps\n",  fmt_count( buf2, (ulong)((sent - *last_sent_cnt)*1e9L / (now - last_print_ts) ) ) );
  *last_sent_cnt = sent;

  /* Sum overrun across all net tiles connected to repair_net */
  ulong total_overrun = repair_net_links[0][ MIDX( COUNTER, LINK, FRAG_POLLING_OVERRUN ) ]; /* coarse double counting prevention */
  ulong total_consumed = 0UL;
  for( ulong i = 0UL; i < net_tile_cnt; i++ ) {
    volatile ulong * ovar_net_metrics = repair_net_links[i];
    total_overrun  += ovar_net_metrics[ MIDX( COUNTER, LINK, FRAG_READING_OVERRUN ) ];
    total_consumed += ovar_net_metrics[ MIDX( COUNTER, LINK, FRAG_CONSUMED ) ]; /* consumed is incremented after after_frag is called */
  }
  printf( " Outgoing requests overrun:  %s\n", fmt_count( buf2, total_overrun  ) );
  printf( " Outgoing requests consumed: %s\n", fmt_count( buf2, total_consumed ) );

  total_overrun  = net_shred_links[0][ MIDX( COUNTER, LINK, FRAG_READING_OVERRUN ) ];
  total_consumed = 0UL;
  for( ulong i = 0UL; i < net_tile_cnt; i++ ) {
    volatile ulong * ovar_net_metrics = net_shred_links[i];
    total_overrun  += ovar_net_metrics[ MIDX( COUNTER, LINK, FRAG_READING_OVERRUN ) ];
    total_consumed += ovar_net_metrics[ MIDX( COUNTER, LINK, FRAG_CONSUMED ) ]; /* shred frag filtering happens manually in after_frag, so no need to index every shred_tile. */
  }

  printf( " Incoming shreds overrun:    %s\n", fmt_count( buf2, total_overrun ) );
  printf( " Incoming shreds consumed:   %s\n", fmt_count( buf2, total_consumed ) );

  print_histogram_buckets( repair_metrics,
                            MIDX( HISTOGRAM, REPAIR, RESPONSE_LATENCY_NANOS ),
                            FD_METRICS_CONVERTER_NONE,
                            FD_METRICS_HISTOGRAM_REPAIR_RESPONSE_LATENCY_NANOS_MIN,
                            FD_METRICS_HISTOGRAM_REPAIR_RESPONSE_LATENCY_NANOS_MAX,
                            "Response Latency" );

  printf(" Repair Peers: %lu\n", repair_metrics[ MIDX( COUNTER, REPAIR, PEER_REQUESTED ) ] );
  printf(" Shreds rejected (no stakes): %lu\n", shred_metrics[ MIDX( COUNTER, SHRED, SHRED_PROCESSED ) ] );
  /* Print histogram buckets similar to Prometheus format */
  print_histogram_buckets( repair_metrics,
                          MIDX( HISTOGRAM, REPAIR, SLOT_COMPLETE_DURATION_SECONDS ),
                          FD_METRICS_CONVERTER_SECONDS,
                          FD_METRICS_HISTOGRAM_REPAIR_SLOT_COMPLETE_DURATION_SECONDS_MIN,
                          FD_METRICS_HISTOGRAM_REPAIR_SLOT_COMPLETE_DURATION_SECONDS_MAX,
                          "Slot Complete Time" );

#define DIFFX(METRIC) repair_metrics[ MIDX( COUNTER, TILE, METRIC ) ] - repair_metrics_prev[ MIDX( COUNTER, TILE, METRIC ) ]
  ulong hkeep_ticks        = DIFFX(REGIME_DURATION_NANOS_CAUGHT_UP_HOUSEKEEPING) + DIFFX(REGIME_DURATION_NANOS_PROCESSING_HOUSEKEEPING) + DIFFX(REGIME_DURATION_NANOS_BACKPRESSURE_HOUSEKEEPING);
  ulong busy_ticks         = DIFFX(REGIME_DURATION_NANOS_PROCESSING_PREFRAG) + DIFFX(REGIME_DURATION_NANOS_PROCESSING_POSTFRAG ) + DIFFX(REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG);
  ulong caught_up_ticks    = DIFFX(REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG);
  ulong backpressure_ticks = DIFFX(REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG);
  ulong total_ticks = hkeep_ticks + busy_ticks + caught_up_ticks + backpressure_ticks;

  printf( " Repair Hkeep: %.1f %%  Busy: %.1f %%  Idle: %.1f %%  Backp: %0.1f %%\n",
            (double)hkeep_ticks/(double)total_ticks*100.0,
            (double)busy_ticks/(double)total_ticks*100.0,
            (double)caught_up_ticks/(double)total_ticks*100.0,
            (double)backpressure_ticks/(double)total_ticks*100.0 );
#undef DIFFX
  fflush( stdout );

  printf( " Block failed insert: %lu\n", repair_metrics[ MIDX( COUNTER, REPAIR, BLOCK_INSERT_FAILED ) ] );
  printf( " Block evicted: %lu\n", repair_metrics[ MIDX( COUNTER, REPAIR, BLOCK_EVICTED ) ] );
  printf( " slot evicted: %lu\n", repair_metrics[ MIDX( GAUGE, REPAIR, SLOT_LAST_EVICTED ) ] );
  printf( " slot evicted by: %lu\n", repair_metrics[ MIDX( GAUGE, REPAIR, SLOT_LAST_EVICTION_CAUSE ) ] );
  printf( " slot failed insert: %lu\n", repair_metrics[ MIDX( GAUGE, REPAIR, SLOT_LAST_INSERT_FAILED ) ] );
  for( ulong i=0UL; i<FD_METRICS_TOTAL_SZ/sizeof(ulong); i++ ) repair_metrics_prev[ i ] = repair_metrics[ i ];
}

static void
repair_ctx_wksp( args_t *          args,
                 config_t *        config,
                 ctx_t **          repair_ctx,
                 fd_topo_wksp_t ** repair_wksp ) {
  (void)args;

  fd_topo_t * topo = &config->topo;
  ulong wksp_id = fd_topo_find_wksp( topo, "repair" );
  if( FD_UNLIKELY( wksp_id==ULONG_MAX ) ) FD_LOG_ERR(( "repair workspace not found" ));

  fd_topo_wksp_t * _repair_wksp = &topo->workspaces[ wksp_id ];

  ulong tile_id = fd_topo_find_tile( topo, "repair", 0UL );
  if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "repair tile not found" ));

  fd_topo_join_workspace( topo, _repair_wksp, FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );

  /* Access the repair tile scratch memory where repair_tile_ctx is stored */
  fd_topo_tile_t * tile = &topo->tiles[ tile_id ];
  void * scratch = fd_topo_obj_laddr( &config->topo, tile->tile_obj_id );
  if( FD_UNLIKELY( !scratch ) ) FD_LOG_ERR(( "Failed to access repair tile scratch memory" ));

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * _repair_ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );

  *repair_ctx  = _repair_ctx;
  *repair_wksp = _repair_wksp;
}

static void
repair_cmd_fn_catchup( args_t *   args,
                       config_t * config ) {

  memset( &config->topo, 0, sizeof(config->topo) );
  repair_topo( config );

  fd_topo_print_log( 1, &config->topo );

  args_t configure_args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };
  for( ulong i=0UL; STAGES[ i ]; i++ ) {
    configure_args.configure.stages[ i ] = STAGES[ i ];
  }
  configure_cmd_fn( &configure_args, config );
  if( 0==strcmp( config->net.provider, "xdp" ) ) {
    fd_topo_install_xdp_simple( &config->topo, config->net.bind_address_parsed );
  }
  run_firedancer_init( config, 1, 0 );

  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );

  fd_topo_fill( &config->topo );

  repair_load_manifest( &config->topo, args->repair.manifest_path );

  /* Access repair workspace memory and metrics */

  ulong repair_tile_idx = fd_topo_find_tile( &config->topo, "repair", 0UL );
  ulong shred_tile_idx  = fd_topo_find_tile( &config->topo, "shred", 0UL );
  FD_TEST( repair_tile_idx!=ULONG_MAX );
  FD_TEST( shred_tile_idx !=ULONG_MAX );
  fd_topo_tile_t * repair_tile = &config->topo.tiles[ repair_tile_idx ];
  fd_topo_tile_t * shred_tile  = &config->topo.tiles[ shred_tile_idx ];

  fd_topo_wksp_t * repair_wksp;
  ctx_t          * repair_ctx;
  repair_ctx_wksp( args, config, &repair_ctx, &repair_wksp );

  volatile ulong * shred_metrics  = fd_metrics_tile( shred_tile->metrics );
  volatile ulong * repair_metrics = fd_metrics_tile( repair_tile->metrics );
  FD_TEST( repair_metrics );
  ulong * repair_metrics_prev = aligned_alloc( 8UL, sizeof(ulong) * FD_METRICS_TOTAL_SZ );
  FD_TEST( repair_metrics_prev );
  memset( repair_metrics_prev, 0, sizeof(ulong) * FD_METRICS_TOTAL_SZ );

  /* Collect link metrics */

  /* Collect all net tiles and their repair_net link metrics */
  ulong net_cnt  = config->layout.net_tile_count;
  volatile ulong ** repair_net_links = aligned_alloc( 8UL, net_cnt * sizeof(volatile ulong*) );
  volatile ulong ** net_shred_links  = aligned_alloc( 8UL, net_cnt * sizeof(volatile ulong*) );
  FD_TEST( repair_net_links );
  FD_TEST( net_shred_links  );

  for( ulong i = 0UL; i < net_cnt; i++ ) {
    ulong tile_idx = fd_topo_find_tile( &config->topo, "net", i );
    if( FD_UNLIKELY( tile_idx == ULONG_MAX ) ) FD_LOG_ERR(( "net tile %lu not found", i ));
    fd_topo_tile_t * tile = &config->topo.tiles[ tile_idx ];

    ulong repair_net_in_idx = fd_topo_find_tile_in_link( &config->topo, tile, "repair_net", 0UL );
    if( FD_UNLIKELY( repair_net_in_idx == ULONG_MAX ) ) FD_LOG_ERR(( "repair_net link not found for net tile %lu", i ));
    FD_TEST( tile->metrics );
    repair_net_links[i] = fd_metrics_link_in( tile->metrics, repair_net_in_idx );
    FD_TEST( repair_net_links[i] );

    /* process all net_shred links */
    ulong shred_tile_idx = fd_topo_find_tile( &config->topo, "shred", 0 );
    if( FD_UNLIKELY( shred_tile_idx == ULONG_MAX ) ) FD_LOG_ERR(( "shred tile 0 not found" ));
    fd_topo_tile_t * shred_tile = &config->topo.tiles[ shred_tile_idx ];

    ulong shred_out_in_idx = fd_topo_find_tile_in_link( &config->topo, shred_tile, "net_shred", i );
    if( FD_UNLIKELY( shred_out_in_idx == ULONG_MAX ) ) FD_LOG_ERR(( "net_shred link not found for shred tile 0" ));
    FD_TEST( shred_tile->metrics );
    net_shred_links[i] = fd_metrics_link_in( shred_tile->metrics, shred_out_in_idx );
    FD_TEST( net_shred_links[i] );
  }

  FD_LOG_NOTICE(( "Repair catchup run" ));

  ulong    shred_out_link_idx = fd_topo_find_link( &config->topo, "shred_out", 0UL );
  FD_TEST( shred_out_link_idx!=ULONG_MAX );
  fd_topo_link_t * shred_out_link   = &config->topo.links[ shred_out_link_idx  ];
  fd_frag_meta_t * shred_out_mcache = shred_out_link->mcache;
  void * shred_out_dcache = config->topo.workspaces[ config->topo.objs[ shred_out_link->dcache_obj_id ].wksp_id ].wksp;

  ulong turbine_slot0 = 0;
  long  last_print    = fd_log_wallclock();
  ulong last_sent     = 0UL;

  fd_topo_run_single_process( &config->topo, 0, config->uid, config->gid, fdctl_tile_run );
  for(;;) {

    if( FD_UNLIKELY( !turbine_slot0 ) ) {
      fd_frag_meta_t * frag = &shred_out_mcache[0]; /* hack to get first frag */
      if ( frag->sz > 0 ) {
        uchar      * shred_out_chunk = fd_chunk_to_laddr( shred_out_dcache, frag->chunk );
        fd_shred_base_t * shred_out_shred = (fd_shred_base_t *)fd_type_pun( shred_out_chunk );
        turbine_slot0 = shred_out_shred->shred.slot;
        FD_LOG_NOTICE(("turbine_slot0: %lu", turbine_slot0));
      }
    }

    /* print metrics */

    long now = fd_log_wallclock();
    int catchup_finished = 0;
    if( FD_UNLIKELY( now - last_print > 1e9L ) ) {
      print_tile_metrics( shred_metrics, repair_metrics, repair_metrics_prev, repair_net_links, net_shred_links, net_cnt, &last_sent, last_print, now );
      ulong slots_behind = turbine_slot0 > repair_metrics[ MIDX( GAUGE, REPAIR, SLOT_HIGHEST_REPAIRED ) ] ? turbine_slot0 - repair_metrics[ MIDX( GAUGE, REPAIR, SLOT_HIGHEST_REPAIRED ) ] : 0;
      printf(" Repaired slots: %lu/%lu  (slots behind: %lu)\n", repair_metrics[ MIDX( GAUGE, REPAIR, SLOT_HIGHEST_REPAIRED ) ], turbine_slot0, slots_behind );
      if( turbine_slot0 && !slots_behind ) {
        catchup_finished = 1;
      }
      printf("\n");
      fflush( stdout );
      last_print = now;
    }

    if( FD_UNLIKELY( catchup_finished ) ) {
      /* repair cmd owned memory */
      location_table = fd_location_table_join( fd_location_table_new( location_table_mem ) );
      read_iptable( args->repair.iptable_path, location_table );
      print_peer_location_latency( repair_wksp->wksp, repair_ctx );
      print_catchup_slots( repair_wksp->wksp, repair_ctx, 0, 1 );
      FD_LOG_NOTICE(("Catchup to slot %lu completed successfully", turbine_slot0));
      fd_sys_util_exit_group( 0 );
    }
  }
}

/* Tests equivocation detection & repair path. */
static void
repair_cmd_fn_eqvoc( args_t *   args,
                     config_t * config ) {
  (void)args;
  memset( &config->topo, 0, sizeof(config->topo) );
  repair_topo( config );

  FD_LOG_NOTICE(( "Repair eqvoc testing init" ));
  fd_topo_print_log( 1, &config->topo );

  args_t configure_args = { .configure.command = CONFIGURE_CMD_INIT, };
  for( ulong i=0UL; STAGES[ i ]; i++ ) configure_args.configure.stages[ i ] = STAGES[ i ];
  configure_cmd_fn( &configure_args, config );
  if( 0==strcmp( config->net.provider, "xdp" ) ) fd_topo_install_xdp_simple( &config->topo, config->net.bind_address_parsed );

  run_firedancer_init( config, 1, 0 );
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  fd_topo_fill( &config->topo );

  repair_load_manifest( &config->topo, args->repair.manifest_path );

  ulong repair_tile_idx = fd_topo_find_tile( &config->topo, "repair", 0UL );
  fd_topo_tile_t * repair_tile = &config->topo.tiles[ repair_tile_idx ];
  volatile ulong * repair_metrics = fd_metrics_tile( repair_tile->metrics );

  void * scratch = fd_topo_obj_laddr( &config->topo, repair_tile->tile_obj_id );
  if( FD_UNLIKELY( !scratch ) ) FD_LOG_ERR(( "Failed to access repair tile scratch memory" ));
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * repair_ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );
  (void)repair_ctx;

  /* read tower_out mcache dcache */
  ulong tower_out_link_idx = fd_topo_find_link( &config->topo, "tower_out", 0UL );
  FD_TEST( tower_out_link_idx!=ULONG_MAX );
  fd_topo_link_t * tower_out_link = &config->topo.links[ tower_out_link_idx ];
  fd_frag_meta_t * tower_out_mcache = tower_out_link->mcache;
  fd_wksp_t * tower_out_mem = config->topo.workspaces[ config->topo.objs[ tower_out_link->dcache_obj_id ].wksp_id ].wksp;
  ulong tower_out_chunk0 = fd_dcache_compact_chunk0( tower_out_mem, tower_out_link->dcache );
  ulong tower_out_wmark = fd_dcache_compact_wmark( tower_out_mem, tower_out_link->dcache, tower_out_link->mtu );
  ulong tower_out_chunk = tower_out_chunk0;

  fd_topo_run_single_process( &config->topo, 0, config->uid, config->gid, fdctl_tile_run );
  int confirmed = 0;
  for(;;) {
    /* publish a confirmation on tower_out */
    if( FD_UNLIKELY( !confirmed && repair_metrics[ MIDX( GAUGE, REPAIR, SLOT_HIGHEST_REPAIRED ) ] != 0 ) ) {
      fd_tower_slot_confirmed_t * msg = fd_chunk_to_laddr( tower_out_mem, tower_out_chunk );
      FD_LOG_NOTICE(( "publishing confirmation for slot %lu", msg->slot ));
      fd_mcache_publish( tower_out_mcache, tower_out_link->depth, 0, FD_TOWER_SIG_SLOT_CONFIRMED, tower_out_chunk, sizeof(fd_tower_slot_confirmed_t), 0, 0, 0 );
      tower_out_chunk = fd_dcache_compact_next( tower_out_chunk, sizeof(fd_tower_slot_confirmed_t), tower_out_chunk0, tower_out_wmark );
      confirmed = 1;
    }
    sleep( 1 );
  }
}

static void
repair_cmd_fn_metrics( args_t *   args,
                       config_t * config ) {
  //memset( &config->topo, 0, sizeof(config->topo) );

  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  fd_topo_fill( &config->topo );

  ctx_t *          repair_ctx;
  fd_topo_wksp_t * repair_wksp;
  repair_ctx_wksp( args, config, &repair_ctx, &repair_wksp );

  ulong    shred_tile_idx  = fd_topo_find_tile( &config->topo, "shred", 0UL );
  ulong    repair_tile_idx = fd_topo_find_tile( &config->topo, "repair", 0UL );
  FD_TEST( shred_tile_idx != ULONG_MAX );
  FD_TEST( repair_tile_idx!= ULONG_MAX );
  fd_topo_tile_t * shred_tile  = &config->topo.tiles[ shred_tile_idx ];
  fd_topo_tile_t * repair_tile = &config->topo.tiles[ repair_tile_idx ];

  volatile ulong * shred_metrics = fd_metrics_tile( shred_tile->metrics );
  FD_TEST( shred_metrics );

  volatile ulong * repair_metrics = fd_metrics_tile( repair_tile->metrics );
  FD_TEST( repair_metrics );
  ulong * repair_metrics_prev = aligned_alloc( 8UL, sizeof(ulong) * FD_METRICS_TOTAL_SZ );
  FD_TEST( repair_metrics_prev );
  memset( repair_metrics_prev, 0, sizeof(ulong) * FD_METRICS_TOTAL_SZ );


  ulong net_tile_cnt = config->layout.net_tile_count;
  volatile ulong ** repair_net_links = aligned_alloc( 8UL, net_tile_cnt * sizeof(volatile ulong*) );
  volatile ulong ** net_shred_links  = aligned_alloc( 8UL, net_tile_cnt * sizeof(volatile ulong*) );
  FD_TEST( repair_net_links );
  FD_TEST( net_shred_links );

  for( ulong i = 0UL; i < net_tile_cnt; i++ ) {
    /* process all repair_net links */
    ulong tile_idx = fd_topo_find_tile( &config->topo, "net", i );
    if( FD_UNLIKELY( tile_idx == ULONG_MAX ) ) FD_LOG_ERR(( "net tile %lu not found", i ));
    fd_topo_tile_t * tile = &config->topo.tiles[ tile_idx ];

    ulong repair_net_in_idx = fd_topo_find_tile_in_link( &config->topo, tile, "repair_net", 0UL );
    if( FD_UNLIKELY( repair_net_in_idx == ULONG_MAX ) ) FD_LOG_ERR(( "repair_net link not found for net tile %lu", i ));
    repair_net_links[i] = fd_metrics_link_in( tile->metrics, repair_net_in_idx );
    FD_TEST( repair_net_links[i] );

    /* process all net_shred links */
    tile_idx = fd_topo_find_tile( &config->topo, "shred", 0 );
    if( FD_UNLIKELY( tile_idx == ULONG_MAX ) ) FD_LOG_ERR(( "shred tile 0 not found" ));
    fd_topo_tile_t * shred_tile = &config->topo.tiles[ tile_idx ];

    ulong shred_out_in_idx = fd_topo_find_tile_in_link( &config->topo, shred_tile, "net_shred", i );
    if( FD_UNLIKELY( shred_out_in_idx == ULONG_MAX ) ) FD_LOG_ERR(( "net_shred link not found for shred tile 0" ));
    net_shred_links[i] = fd_metrics_link_in( shred_tile->metrics, shred_out_in_idx );
    FD_TEST( net_shred_links[i] );
  }

  long  last_print_ts = fd_log_wallclock();
  ulong last_sent     = 0UL;
  for(;;) {
    long now = fd_log_wallclock();
    if( FD_UNLIKELY( now - last_print_ts > 1e9L ) ) {
      print_tile_metrics( shred_metrics, repair_metrics, repair_metrics_prev, repair_net_links, net_shred_links, net_tile_cnt, &last_sent, last_print_ts, now );
      last_print_ts = now;
    }
  }
}

static void
repair_cmd_fn_forest( args_t *   args,
                      config_t * config ) {
  ctx_t *          repair_ctx;
  fd_topo_wksp_t * repair_wksp;
  repair_ctx_wksp( args, config, &repair_ctx, &repair_wksp );

  ulong forest_gaddr = fd_wksp_gaddr_fast( repair_ctx->wksp, repair_ctx->forest );
  fd_forest_t * forest = (fd_forest_t *)fd_wksp_laddr( repair_wksp->wksp, forest_gaddr );

  for( ;; ) {
    fd_forest_print( forest );
    sleep( 1 );
  }
}

static void
repair_cmd_fn_inflight( args_t *   args,
                        config_t * config ) {
  ctx_t *          repair_ctx;
  fd_topo_wksp_t * repair_wksp;
  repair_ctx_wksp( args, config, &repair_ctx, &repair_wksp );

  ulong            inflights_gaddr = fd_wksp_gaddr_fast( repair_ctx->wksp, repair_ctx->inflights );
  fd_inflights_t * inflights       = (fd_inflights_t *)fd_wksp_laddr( repair_wksp->wksp, inflights_gaddr );

  ulong inflight_pool_off = (ulong)inflights->pool - (ulong)repair_ctx->inflights;
  fd_inflight_t * inflight_pool = (fd_inflight_t *)fd_wksp_laddr( repair_wksp->wksp, inflights_gaddr + inflight_pool_off );

  for( ;; ) {
    fd_inflights_print( inflights->outstanding_dl, inflight_pool );
    printf("popped count: %lu\n", inflights->popped_cnt);
    fd_inflights_print( inflights->popped_dl, inflight_pool );
    sleep( 1 );
  }
}

static void
repair_cmd_fn_requests( args_t *   args,
                        config_t * config ) {
  ctx_t *          repair_ctx;
  fd_topo_wksp_t * repair_wksp;
  repair_ctx_wksp( args, config, &repair_ctx, &repair_wksp );

  fd_forest_t *          forest = fd_forest_join( fd_wksp_laddr( repair_wksp->wksp, fd_wksp_gaddr_fast( repair_ctx->wksp, repair_ctx->forest ) ) );
  fd_forest_reqslist_t * dlist  = fd_forest_reqslist( forest );
  fd_forest_ref_t *      pool   = fd_forest_reqspool( forest );

  fd_forest_reqslist_t * orphlist = fd_forest_orphlist( forest );

  for( ;; ) {
    printf("%-15s %-12s %-12s %-12s %-20s %-12s\n",
            "Slot", "Buffered Idx", "Complete Idx", "First Shred ts", "Turbine Cnt", "Repair Cnt");
    printf("%-15s %-12s %-12s %-12s %-20s %-12s\n",
            "---------------", "------------", "------------", "------------",
            "--------------------", "------------");
    for( fd_forest_reqslist_iter_t iter = fd_forest_reqslist_iter_fwd_init( dlist, pool );
        !fd_forest_reqslist_iter_done( iter, dlist, pool );
        iter = fd_forest_reqslist_iter_fwd_next( iter, dlist, pool ) ) {
      fd_forest_ref_t * req = fd_forest_reqslist_iter_ele( iter, dlist, pool );
      fd_forest_blk_t * blk = fd_forest_pool_ele( fd_forest_pool( forest ), req->idx );

      printf("%-15lu %-12u %-12u %-20ld %-12u %-10u\n",
              blk->slot,
              blk->buffered_idx,
              blk->complete_idx,
              blk->first_shred_ts,
              blk->turbine_cnt,
              blk->repair_cnt);
    }
    printf("\n");

    /* now lets print the orphreqs */

    printf("Orphan Requests:\n");
    printf("%-15s %-12s %-12s %-12s %-20s %-12s %-10s\n",
      "Slot", "Consumed Idx", "Buffered Idx", "Complete Idx",
      "First Shred Timestamp", "Turbine Cnt", "Repair Cnt");
printf("%-15s %-12s %-12s %-12s %-20s %-12s %-10s\n",
      "---------------", "------------", "------------", "------------",
      "--------------------", "------------", "----------");

    for( fd_forest_reqslist_iter_t iter = fd_forest_reqslist_iter_fwd_init( orphlist, pool );
                                         !fd_forest_reqslist_iter_done( iter, orphlist, pool );
                                   iter = fd_forest_reqslist_iter_fwd_next( iter, orphlist, pool ) ) {
      fd_forest_ref_t * req = fd_forest_reqslist_iter_ele( iter, orphlist, pool );
      fd_forest_blk_t * blk = fd_forest_pool_ele( fd_forest_pool( forest ), req->idx );
      printf("%-15lu %-12u %-12u %-20ld %-12u %-10u\n",
              blk->slot,
              blk->buffered_idx,
              blk->complete_idx,
              blk->first_shred_ts,
              blk->turbine_cnt,
              blk->repair_cnt);
    }
    sleep( 1 );
  }
}

static void
repair_cmd_fn_waterfall( args_t *   args,
                         config_t * config ) {

  fd_topo_t * topo    = &config->topo;
  ulong       wksp_id = fd_topo_find_wksp( topo, "repair" );
  if( FD_UNLIKELY( wksp_id==ULONG_MAX ) ) FD_LOG_ERR(( "repair workspace not found" ));
  fd_topo_wksp_t * repair_wksp = &topo->workspaces[ wksp_id ];
  fd_topo_join_workspace( topo, repair_wksp, FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );

  /* Access the repair tile scratch memory where repair_tile_ctx is stored */
  ulong tile_id = fd_topo_find_tile( topo, "repair", 0UL );
  if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "repair tile not found" ));
  fd_topo_tile_t * tile = &topo->tiles[ tile_id ];
  void * scratch = fd_topo_obj_laddr( &config->topo, tile->tile_obj_id );
  if( FD_UNLIKELY( !scratch ) ) FD_LOG_ERR(( "Failed to access repair tile scratch memory" ));

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * repair_ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );

  /* catchup cmd owned memory */
  location_table = fd_location_table_join( fd_location_table_new( location_table_mem ) );
  read_iptable( args->repair.iptable_path, location_table );

  // Add terminal setup here - same as monitor.c
  atexit( restore_terminal );
  if( FD_UNLIKELY( 0!=tcgetattr( STDIN_FILENO, &termios_backup ) ) ) {
    FD_LOG_ERR(( "tcgetattr(STDIN_FILENO) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  /* Disable character echo and line buffering */
  struct termios term = termios_backup;
  term.c_lflag &= (tcflag_t)~(ICANON | ECHO);
  if( FD_UNLIKELY( 0!=tcsetattr( STDIN_FILENO, TCSANOW, &term ) ) ) {
    FD_LOG_WARNING(( "tcsetattr(STDIN_FILENO) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  int  catchup_verbose = 0;
  long last_print = 0;
  for( ;; ) {
    int c = fd_getchar();
    if( FD_UNLIKELY( c=='i'    ) ) catchup_verbose = !catchup_verbose;
    if( FD_UNLIKELY( c=='\x04' ) ) break; /* Ctrl-D */

    long now = fd_log_wallclock();
    if( FD_UNLIKELY( now - last_print > 1e9L ) ) {
      last_print = now;
      print_catchup_slots( repair_wksp->wksp, repair_ctx, catchup_verbose, args->repair.sort_by_slot );
      printf( "catchup slots | Use 'i' to toggle extra slot information" TEXT_NEWLINE );
      fflush( stdout );

      /* Peer location latency is not that useful post catchup, and also
         requires some concurrent dlist iteration, so only print it when
         in catchup mode. */
    }
  }
}

#define PEERS_DISPLAY_MAX 20

static void
print_peer_dlist( fd_policy_peer_dlist_t *     dlist,
                  fd_policy_peer_t *           pool,
                  fd_policy_peer_dlist_iter_t  cursor,
                  char const *                 label ) {
  ulong cnt = 0;
  for( fd_policy_peer_dlist_iter_t it = fd_policy_peer_dlist_iter_fwd_init( dlist, pool );
       !fd_policy_peer_dlist_iter_done( it, dlist, pool );
       it = fd_policy_peer_dlist_iter_fwd_next( it, dlist, pool ) ) cnt++;

  printf( "%s (%lu peers)\n", label, cnt );
  if( !cnt || fd_policy_peer_dlist_iter_done( cursor, dlist, pool ) ) {
    printf( "  (empty or iterator not initialized)\n\n" );
    return;
  }

  printf( "     | %-8s | %-12s | %-12s | %-8s | %-8s\n",
          "Idx", "Pubkey", "Ewma Lat", "Avg Lat", "Req/Res" );
  printf( "-----+----------+--------------+--------------+----------+---------\n" );

  fd_policy_peer_dlist_iter_t it = cursor;
  for( ulong i = 0; i < PEERS_DISPLAY_MAX && i < cnt; i++ ) {
    fd_policy_peer_t * peer = fd_policy_peer_dlist_iter_ele( it, dlist, pool );

    FD_BASE58_ENCODE_32_BYTES( peer->key.key, b58 );
    char pubkey_short[13];
    fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( pubkey_short ), b58, 12 ) );

    double avg_lat_ms  = peer->res_cnt ? ((double)peer->total_lat / (double)peer->res_cnt) / 1e6 : 0.0;
    double ewma_lat_ms = (double)peer->ewma_lat / 1e6;

    printf( " %s%c%s | %-8lu | %-12s | %9.3fms | %9.3fms | %lu/%lu\n",
            i == 0 ? "\033[1;33m" : "",
            i == 0 ? '>' : ' ',
            i == 0 ? "\033[0m"    : "",
            fd_policy_peer_pool_idx( pool, peer ),
            pubkey_short,
            ewma_lat_ms,
            avg_lat_ms,
            peer->req_cnt,
            peer->res_cnt );

    it = fd_policy_peer_dlist_iter_fwd_next( it, dlist, pool );
    if( fd_policy_peer_dlist_iter_done( it, dlist, pool ) ) {
      it = fd_policy_peer_dlist_iter_fwd_init( dlist, pool );
    }
  }
  if( cnt > PEERS_DISPLAY_MAX ) printf( "  ... (%lu more)\n", cnt - PEERS_DISPLAY_MAX );
  printf( "\n" );
}

static void
repair_cmd_fn_peers( args_t *   args,
                     config_t * config ) {
  ctx_t *          repair_ctx;
  fd_topo_wksp_t * repair_wksp;
  repair_ctx_wksp( args, config, &repair_ctx, &repair_wksp );

  fd_policy_t * policy = fd_wksp_laddr( repair_wksp->wksp, fd_wksp_gaddr_fast( repair_ctx->wksp, repair_ctx->policy ) );

  fd_policy_peer_dlist_t * fast_dlist = fd_wksp_laddr( repair_wksp->wksp, fd_wksp_gaddr_fast( repair_ctx->wksp, policy->peers.fast ) );
  fd_policy_peer_dlist_t * slow_dlist = fd_wksp_laddr( repair_wksp->wksp, fd_wksp_gaddr_fast( repair_ctx->wksp, policy->peers.slow ) );
  fd_policy_peer_t *       pool       = fd_wksp_laddr( repair_wksp->wksp, fd_wksp_gaddr_fast( repair_ctx->wksp, policy->peers.pool ) );

  long last_print = 0;
  for( ;; ) {
    long now = fd_log_wallclock();
    if( FD_UNLIKELY( now - last_print > 1e9L ) ) {
      last_print = now;
      printf( "\033[2J\033[H" );

      char fast_label[64];
      char slow_label[64];
      snprintf( fast_label, sizeof(fast_label), "FAST PEERS (ewma < %ldms)", (long)(FD_POLICY_LATENCY_THRESH / 1e6L) );
      snprintf( slow_label, sizeof(slow_label), "SLOW PEERS (ewma >= %ldms or no responses)", (long)(FD_POLICY_LATENCY_THRESH / 1e6L) );
      print_peer_dlist( fast_dlist, pool, policy->peers.select.fast_iter, fast_label );
      print_peer_dlist( slow_dlist, pool, policy->peers.select.slow_iter, slow_label );

      printf( "select cnt: %u / %u (fast per slow)\n", policy->peers.select.cnt, FD_POLICY_FAST_PER_SLOW );
      printf( "pool used: %lu / %lu\n", fd_policy_peer_pool_used( pool ), fd_policy_peer_pool_max( pool ) );

      fflush( stdout );
    }

  }
}




void
repair_cmd_args( int *    pargc,
                 char *** pargv,
                 args_t * args ) {

  /* positional arg */

  args->repair.pos_arg = (*pargv)[0];
  if( FD_UNLIKELY( !args->repair.pos_arg ) ) {
    args->repair.help = 1;
    return;
  }
  (*pargc)--;
  (*pargv)++;

  /* required args */

  char const * manifest_path = fd_env_strip_cmdline_cstr    ( pargc, pargv, "--manifest-path", NULL, NULL      );

  /* optional args */

  char const * iptable_path  = fd_env_strip_cmdline_cstr    ( pargc, pargv, "--iptable",       NULL, NULL      );
  ulong        slot          = fd_env_strip_cmdline_ulong   ( pargc, pargv, "--slot",          NULL, ULONG_MAX );
  int          sort_by_slot  = fd_env_strip_cmdline_contains( pargc, pargv, "--sort-by-slot"                   );

  if( FD_UNLIKELY( !strcmp( args->repair.pos_arg, "catchup" ) && !manifest_path ) ) {
    args->repair.help = 1;
    return;
  }

  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( args->repair.manifest_path ), manifest_path, sizeof(args->repair.manifest_path)-1UL ) );
  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( args->repair.iptable_path ),  iptable_path,  sizeof(args->repair.iptable_path )-1UL ) );
  args->repair.slot         = slot;
  args->repair.sort_by_slot = sort_by_slot;
}

static void
repair_cmd_fn( args_t *   args,
              config_t * config ) {

  if( args->repair.help ) {
    fd_action_help_print( &fd_action_repair );
    return;
  }

  if     ( !strcmp( args->repair.pos_arg, "catchup"   ) ) repair_cmd_fn_catchup  ( args, config );
  else if( !strcmp( args->repair.pos_arg, "eqvoc"     ) ) repair_cmd_fn_eqvoc    ( args, config );
  else if( !strcmp( args->repair.pos_arg, "forest"    ) ) repair_cmd_fn_forest   ( args, config );
  else if( !strcmp( args->repair.pos_arg, "inflight"  ) ) repair_cmd_fn_inflight ( args, config );
  else if( !strcmp( args->repair.pos_arg, "requests"  ) ) repair_cmd_fn_requests ( args, config );
  else if( !strcmp( args->repair.pos_arg, "waterfall" ) ) repair_cmd_fn_waterfall( args, config );
  else if( !strcmp( args->repair.pos_arg, "peers"     ) ) repair_cmd_fn_peers    ( args, config );
  else if( !strcmp( args->repair.pos_arg, "metrics"   ) ) repair_cmd_fn_metrics  ( args, config );
  else                                                    fd_action_help_print( &fd_action_repair );
}

static void
repair_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "catchup",         NULL,     "Run a reduced topology that only repairs slots until catchup.\n"
                                                         "Requires --manifest-path; accepts --iptable and --sort-by-slot" );
  fd_action_help_arg( help, "eqvoc",           NULL,     "Test equivocation detection and the repair path" );
  fd_action_help_arg( help, "forest",          NULL,     "Print the repair forest.  Accepts --slot to drill into a slot" );
  fd_action_help_arg( help, "inflight",        NULL,     "Print the inflight repairs" );
  fd_action_help_arg( help, "requests",        NULL,     "Print the queued repair requests" );
  fd_action_help_arg( help, "waterfall",       NULL,     "Print a waterfall diagram of recent slot completion times and\n"
                                                         "response latencies.  Accepts --iptable and --sort-by-slot" );
  fd_action_help_arg( help, "peers",           NULL,     "Print the list of slow and fast repair peers" );
  fd_action_help_arg( help, "metrics",         NULL,     "Print repair tile metrics in a digestible format" );
  fd_action_help_arg( help, "--manifest-path", "<path>", "Path to manifest file (required by catchup)" );
  fd_action_help_arg( help, "--iptable",       "<path>", "Path to iptable file (catchup, waterfall)" );
  fd_action_help_arg( help, "--slot",          "<slot>", "Specific forest slot to drill into (forest)" );
  fd_action_help_arg( help, "--sort-by-slot",  NULL,     "Sort results by slot (catchup, waterfall)" );
}

action_t fd_action_repair = {
  .name        = "repair",
  .args        = repair_cmd_args,
  .fn          = repair_cmd_fn,
  .perm        = dev_cmd_perm,
  .description = "Spawn a reduced topology for inspecting and profiling the repair tile",
  .detail      = "Boots a smaller Firedancer topology focused on the repair tile and runs the\n"
                 "requested subcommand to drive or inspect repair behavior.  Pick one of the\n"
                 "subcommands below.",
  .usage       = "repair <catchup|eqvoc|forest|inflight|requests|waterfall|peers|metrics> [OPTIONS]",
  .args_help   = repair_args_help,
};
