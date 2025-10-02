#include "fd_gui_peers.h"
#include "fd_gui_printf.h"

#include "../../ballet/json/cJSON.h"
#include "../../flamenco/gossip/fd_gossip_private.h"
#include "../../flamenco/gossip/fd_gossip_types.h"

#define LOGGING 0

FD_FN_CONST ulong
fd_gui_peers_align( void ) {
  ulong a = 128UL;
  a = fd_ulong_max( a, alignof(fd_gui_peers_ctx_t)              );
  a = fd_ulong_max( a, fd_gui_peers_live_table_align()          );
  a = fd_ulong_max( a, fd_gui_peers_bandwidth_tracking_align()  );
  a = fd_ulong_max( a, fd_gui_peers_node_pubkey_map_align()     );
  a = fd_ulong_max( a, fd_gui_peers_node_sock_map_align()       );
  a = fd_ulong_max( a, alignof(fd_gui_peers_ws_conn_t)          );
  FD_TEST( fd_ulong_pow2_up( a )==a );
  return a;
}

FD_FN_CONST ulong
fd_gui_peers_footprint( ulong max_ws_conn_cnt ) {
  ulong pubkey_chain_cnt = fd_gui_peers_node_pubkey_map_chain_cnt_est( FD_CONTACT_INFO_TABLE_SIZE );
  ulong sock_chain_cnt   = fd_gui_peers_node_sock_map_chain_cnt_est  ( FD_CONTACT_INFO_TABLE_SIZE );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_gui_peers_ctx_t),             sizeof(fd_gui_peers_ctx_t)                                              );
  l = FD_LAYOUT_APPEND( l, fd_gui_peers_live_table_align(),         fd_gui_peers_live_table_footprint        ( FD_CONTACT_INFO_TABLE_SIZE ) );
  l = FD_LAYOUT_APPEND( l, fd_gui_peers_bandwidth_tracking_align(), fd_gui_peers_bandwidth_tracking_footprint( FD_CONTACT_INFO_TABLE_SIZE ) );
  l = FD_LAYOUT_APPEND( l, fd_gui_peers_node_pubkey_map_align(),    fd_gui_peers_node_pubkey_map_footprint   ( pubkey_chain_cnt )           );
  l = FD_LAYOUT_APPEND( l, fd_gui_peers_node_sock_map_align(),      fd_gui_peers_node_sock_map_footprint     ( sock_chain_cnt )             );
  l = FD_LAYOUT_APPEND( l, alignof(fd_gui_peers_ws_conn_t),         max_ws_conn_cnt*sizeof(fd_gui_peers_ws_conn_t)                          );

  return FD_LAYOUT_FINI( l, fd_gui_peers_align() );
}

void *
fd_gui_peers_new( void *             shmem,
                  fd_http_server_t * http,
                  fd_topo_t *        topo,
                  ulong              max_ws_conn_cnt,
                  long               now ) {
    if( FD_UNLIKELY( !shmem ) ) {
      FD_LOG_WARNING(( "NULL shmem" ));
      return NULL;
    }

    if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_gui_peers_align() ) ) ) {
      FD_LOG_WARNING(( "misaligned shmem" ));
      return NULL;
    }

    ulong pubkey_chain_cnt = fd_gui_peers_node_pubkey_map_chain_cnt_est( FD_CONTACT_INFO_TABLE_SIZE );
    ulong sock_chain_cnt   = fd_gui_peers_node_sock_map_chain_cnt_est  ( FD_CONTACT_INFO_TABLE_SIZE );

    FD_SCRATCH_ALLOC_INIT( l, shmem );
    fd_gui_peers_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gui_peers_ctx_t),             sizeof(fd_gui_peers_ctx_t)                                              );
    void * _live_table       = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_peers_live_table_align(),         fd_gui_peers_live_table_footprint        ( FD_CONTACT_INFO_TABLE_SIZE ) );
    void * _bw_tracking      = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_peers_bandwidth_tracking_align(), fd_gui_peers_bandwidth_tracking_footprint( FD_CONTACT_INFO_TABLE_SIZE ) );
    void * _pubkey_map       = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_peers_node_pubkey_map_align(),    fd_gui_peers_node_pubkey_map_footprint   ( pubkey_chain_cnt )           );
    void * _sock_map         = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_peers_node_sock_map_align(),      fd_gui_peers_node_sock_map_footprint     ( sock_chain_cnt )             );
    ctx->client_viewports    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gui_peers_ws_conn_t),         max_ws_conn_cnt*sizeof(fd_gui_peers_ws_conn_t)                          );

    for( ulong i = 0UL; i<max_ws_conn_cnt; i++ ) ctx->client_viewports[ i ].connected = 0;

    ctx->http = http;
    ctx->topo = topo;

    ctx->max_ws_conn_cnt   = max_ws_conn_cnt;
    ctx->open_ws_conn_cnt  = 0UL;
    ctx->active_ws_conn_id = ULONG_MAX;

    ctx->next_client_nanos              = now;
    ctx->next_metric_rate_update_nanos  = now;
    ctx->next_gossip_stats_update_nanos = now;
    memset( &ctx->gossip_stats, 0, sizeof(ctx->gossip_stats) );

    for( ulong i = 0; i<FD_CONTACT_INFO_TABLE_SIZE; i++) ctx->contact_info_table[ i ].valid = 0;

    ctx->live_table      = fd_gui_peers_live_table_join( fd_gui_peers_live_table_new( _live_table, FD_CONTACT_INFO_TABLE_SIZE ) );
    fd_gui_peers_live_table_seed( ctx->contact_info_table, FD_CONTACT_INFO_TABLE_SIZE, 42UL );

    ctx->bw_tracking     = fd_gui_peers_bandwidth_tracking_join( fd_gui_peers_bandwidth_tracking_new( _bw_tracking, FD_CONTACT_INFO_TABLE_SIZE ) );
    fd_gui_peers_bandwidth_tracking_seed( ctx->contact_info_table, FD_CONTACT_INFO_TABLE_SIZE, 42UL );

    ctx->node_pubkey_map = fd_gui_peers_node_pubkey_map_join( fd_gui_peers_node_pubkey_map_new( _pubkey_map, fd_gui_peers_node_pubkey_map_chain_cnt_est( FD_CONTACT_INFO_TABLE_SIZE ), 42UL ) );
    ctx->node_sock_map   = fd_gui_peers_node_sock_map_join  ( fd_gui_peers_node_sock_map_new  ( _sock_map,   fd_gui_peers_node_sock_map_chain_cnt_est  ( FD_CONTACT_INFO_TABLE_SIZE ), 42UL ) );

    return shmem;
}

fd_gui_peers_ctx_t *
fd_gui_peers_join( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_gui_peers_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  fd_gui_peers_ctx_t * ctx = (fd_gui_peers_ctx_t *)shmem;

  return ctx;
}

static ulong
fd_gui_sum_tiles_counter( fd_gui_peers_ctx_t * peers,
                          char const *         name,
                          ulong                tile_cnt,
                          ulong                metric_idx ) {
  ulong total = 0UL;
  for( ulong i = 0UL; i < peers->topo->tile_cnt; i++ ) {
    if( FD_UNLIKELY( !strcmp( peers->topo->tiles[ i ].name, name ) ) ) {
      FD_TEST( peers->topo->tiles[ i ].kind_id < tile_cnt );
      fd_topo_tile_t const * tile = &peers->topo->tiles[ i ];
      volatile ulong const * tile_metrics = fd_metrics_tile( tile->metrics );
      total += tile_metrics[ metric_idx ];
    }
  }
  return total;
}

static void
fd_gui_peers_gossip_stats_snap( fd_gui_peers_ctx_t *          peers,
                                fd_gui_peers_gossip_stats_t * gossip_stats,
                                long                          now ) {
  gossip_stats->sample_time = now;
  ulong gossvf_tile_cnt = fd_topo_tile_name_cnt( peers->topo, "gossvf"  );
  ulong gossip_tile_cnt = 1UL;

  gossip_stats->network_health_pull_response_msg_rx_success =
      fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PULL_RESPONSE ) );
  gossip_stats->network_health_pull_response_msg_rx_failure =
      fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_RESPONSE_NO_VALID_CRDS ) );
  gossip_stats->network_health_push_msg_rx_success =
      fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PUSH ) );
  gossip_stats->network_health_push_msg_rx_failure =
      fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PUSH_NO_VALID_CRDS ) );
  gossip_stats->network_health_push_crds_rx_success =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_UPSERTED_PUSH ) );
  gossip_stats->network_health_push_crds_rx_failure =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PUSH_STALE ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PUSH_DUPLICATE ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PUSH_SIGNATURE ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PUSH_RELAYER_NO_CONTACT_INFO ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PUSH_RELAYER_SHRED_VERSION ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PUSH_ORIGIN_NO_CONTACT_INFO ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PUSH_ORIGIN_SHRED_VERSION ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PUSH_INACTIVE ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PUSH_WALLCLOCK ) );
  gossip_stats->network_health_pull_response_crds_rx_success =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_UPSERTED_PULL_RESPONSE ) );
  gossip_stats->network_health_pull_response_crds_rx_failure =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_STALE ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_WALLCLOCK ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_DUPLICATE ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_DUPLICATE ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_SIGNATURE ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_RELAYER_SHRED_VERSION ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_ORIGIN_NO_CONTACT_INFO ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_ORIGIN_SHRED_VERSION ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_INACTIVE ) );
  gossip_stats->network_health_push_crds_rx_duplicate =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PUSH_DUPLICATE ) );
  gossip_stats->network_health_pull_response_crds_rx_duplicate =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_DUPLICATE ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_DUPLICATE ) );

  gossip_stats->network_health_total_stake = 0UL; /* todo ... fetch from RPC */
  gossip_stats->network_health_total_peers = 0UL; /* todo ... fetch from RPC */

  gossip_stats->network_health_connected_stake          = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_PEER_TOTAL_STAKE ) );
  gossip_stats->network_health_connected_staked_peers   = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_PEER_STAKED_COUNT ) );
  gossip_stats->network_health_connected_unstaked_peers = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_PEER_UNSTAKED_COUNT ) );

  gossip_stats->network_ingress_peer_sz = fd_ulong_min( fd_gui_peers_bandwidth_tracking_ele_cnt( peers->bw_tracking ), FD_GUI_PEERS_GOSSIP_TOP_PEERS_CNT );
  gossip_stats->network_ingress_total_bytes_per_sec = 0UL;

  for( fd_gui_peers_bandwidth_tracking_fwd_iter_t iter = fd_gui_peers_bandwidth_tracking_fwd_iter_init( peers->bw_tracking, &FD_GUI_PEERS_BW_TRACKING_INGRESS_SORT_KEY, peers->contact_info_table ), j = 0UL;
       !fd_gui_peers_bandwidth_tracking_fwd_iter_done( iter );
       iter = fd_gui_peers_bandwidth_tracking_fwd_iter_next( iter, peers->contact_info_table ), j++ ) {
    fd_gui_peers_node_t * cur = fd_gui_peers_bandwidth_tracking_fwd_iter_ele( iter, peers->contact_info_table );

    if( FD_UNLIKELY( j<gossip_stats->network_ingress_peer_sz ) ) {
      if( FD_LIKELY( cur->has_node_info ) ) FD_TEST( fd_cstr_printf_check( gossip_stats->network_ingress_peer_names[ j ], sizeof(gossip_stats->network_ingress_peer_names[ j ]), NULL, "%s", cur->name ) );
      else                                  gossip_stats->network_ingress_peer_names[ j ][ 0 ] = '\0';
      gossip_stats->network_ingress_peer_bytes_per_sec[ j ] = cur->gossvf_rx_sum.rate;
      fd_memcpy( &gossip_stats->network_ingress_peer_identities[ j ], cur->contact_info.pubkey.uc, 32UL );
    }

    gossip_stats->network_ingress_total_bytes_per_sec += cur->gossvf_rx_sum.rate;
  }

  gossip_stats->network_ingress_total_bytes =
      fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PULL_REQUEST) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PULL_RESPONSE) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PUSH) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PRUNE) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PING) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PONG) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_UNPARSEABLE) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_NOT_CONTACT_INFO) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_LOOPBACK) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_INACTIVE) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_WALLCLOCK) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_SIGNATURE) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_SHRED_VERSION) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PRUNE_DESTINATION) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PRUNE_WALLCLOCK) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PRUNE_SIGNATURE) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PUSH_NO_VALID_CRDS) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_RESPONSE_NO_VALID_CRDS) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PING_SIGNATURE) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PONG_SIGNATURE) );

  gossip_stats->network_egress_peer_sz = fd_ulong_min( fd_gui_peers_bandwidth_tracking_ele_cnt( peers->bw_tracking ), FD_GUI_PEERS_GOSSIP_TOP_PEERS_CNT );

  FD_TEST( gossip_stats->network_egress_peer_sz==gossip_stats->network_ingress_peer_sz );

  gossip_stats->network_egress_peer_sz = fd_ulong_min( fd_gui_peers_bandwidth_tracking_ele_cnt( peers->bw_tracking ), FD_GUI_PEERS_GOSSIP_TOP_PEERS_CNT );
  gossip_stats->network_egress_total_bytes_per_sec = 0UL;

  for( fd_gui_peers_bandwidth_tracking_fwd_iter_t iter = fd_gui_peers_bandwidth_tracking_fwd_iter_init( peers->bw_tracking, &FD_GUI_PEERS_BW_TRACKING_EGRESS_SORT_KEY, peers->contact_info_table ), j = 0UL;
       !fd_gui_peers_bandwidth_tracking_fwd_iter_done( iter );
       iter = fd_gui_peers_bandwidth_tracking_fwd_iter_next( iter, peers->contact_info_table ), j++ ) {
    fd_gui_peers_node_t * cur = fd_gui_peers_bandwidth_tracking_fwd_iter_ele( iter, peers->contact_info_table );

    if( FD_UNLIKELY( j<gossip_stats->network_egress_peer_sz ) ) {
      if( FD_LIKELY( cur->has_node_info ) ) FD_TEST( fd_cstr_printf_check( gossip_stats->network_egress_peer_names[ j ], sizeof(gossip_stats->network_egress_peer_names[ j ]), NULL, "%s", cur->name ) );
      else                                  gossip_stats->network_egress_peer_names[ j ][ 0 ] = '\0';
      gossip_stats->network_egress_peer_bytes_per_sec[ j ] = cur->gossip_tx_sum.rate;
      fd_memcpy( &gossip_stats->network_egress_peer_identities[ j ], cur->contact_info.pubkey.uc, 32UL );
    }

    gossip_stats->network_egress_total_bytes_per_sec += cur->gossip_tx_sum.rate;
  }

  gossip_stats->network_egress_total_bytes =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PING ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PONG ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PRUNE ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PULL_REQUEST ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PULL_RESPONSE ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PUSH ) );

  gossip_stats->storage_capacity = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_CAPACITY ) );
  gossip_stats->storage_expired_cnt = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_EXPIRED_COUNT ) );
  gossip_stats->storage_evicted_cnt = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_EVICTED_COUNT ) );

  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_V_CONTACT_INFO_V1_IDX               ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_COUNT_CONTACT_INFO_V1 )               );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_V_VOTE_IDX                          ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_COUNT_VOTE )                          );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_V_LOWEST_SLOT_IDX                   ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_COUNT_LOWEST_SLOT )                   );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_V_SNAPSHOT_HASHES_IDX               ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_COUNT_SNAPSHOT_HASHES )               );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_V_ACCOUNTS_HASHES_IDX               ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_COUNT_ACCOUNTS_HASHES )               );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_V_EPOCH_SLOTS_IDX                   ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_COUNT_EPOCH_SLOTS )                   );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_V_VERSION_V1_IDX                    ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_COUNT_VERSION_V1 )                    );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_V_VERSION_V2_IDX                    ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_COUNT_VERSION_V2 )                    );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_V_NODE_INSTANCE_IDX                 ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_COUNT_NODE_INSTANCE )                 );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_V_DUPLICATE_SHRED_IDX               ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_COUNT_DUPLICATE_SHRED )               );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_V_INCREMENTAL_SNAPSHOT_HASHES_IDX   ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_COUNT_INCREMENTAL_SNAPSHOT_HASHES )   );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_V_CONTACT_INFO_V2_IDX               ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_COUNT_CONTACT_INFO_V2 )               );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_V_RESTART_LAST_VOTED_FORK_SLOTS_IDX ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_COUNT_RESTART_LAST_VOTED_FORK_SLOTS ) );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_V_RESTART_HEAVIEST_FORK_IDX         ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_COUNT_RESTART_HEAVIEST_FORK )         );

  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_CONTACT_INFO_V1_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_COUNT_CONTACT_INFO_V1 ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_COUNT_CONTACT_INFO_V1 ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_VOTE_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_COUNT_VOTE ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_COUNT_VOTE ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_LOWEST_SLOT_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_COUNT_LOWEST_SLOT ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_COUNT_LOWEST_SLOT ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_SNAPSHOT_HASHES_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_COUNT_SNAPSHOT_HASHES ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_COUNT_SNAPSHOT_HASHES ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_ACCOUNTS_HASHES_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_COUNT_ACCOUNTS_HASHES ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_COUNT_ACCOUNTS_HASHES ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_EPOCH_SLOTS_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_COUNT_EPOCH_SLOTS ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_COUNT_EPOCH_SLOTS ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_VERSION_V1_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_COUNT_VERSION_V1 ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_COUNT_VERSION_V1 ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_VERSION_V2_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_COUNT_VERSION_V2 ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_COUNT_VERSION_V2 ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_NODE_INSTANCE_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_COUNT_NODE_INSTANCE ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_COUNT_NODE_INSTANCE ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_DUPLICATE_SHRED_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_COUNT_DUPLICATE_SHRED ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_COUNT_DUPLICATE_SHRED ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_INCREMENTAL_SNAPSHOT_HASHES_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_COUNT_INCREMENTAL_SNAPSHOT_HASHES ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_COUNT_INCREMENTAL_SNAPSHOT_HASHES ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_CONTACT_INFO_V2_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_COUNT_CONTACT_INFO_V2 ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_COUNT_CONTACT_INFO_V2 ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_RESTART_LAST_VOTED_FORK_SLOTS_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_COUNT_RESTART_LAST_VOTED_FORK_SLOTS ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_COUNT_RESTART_LAST_VOTED_FORK_SLOTS ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_RESTART_HEAVIEST_FORK_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_COUNT_RESTART_HEAVIEST_FORK ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_COUNT_RESTART_HEAVIEST_FORK ) );

  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_CONTACT_INFO_V1_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_BYTES_CONTACT_INFO_V1 ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_BYTES_CONTACT_INFO_V1 ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_VOTE_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_BYTES_VOTE ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_BYTES_VOTE ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_LOWEST_SLOT_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_BYTES_LOWEST_SLOT ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_BYTES_LOWEST_SLOT ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_SNAPSHOT_HASHES_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_BYTES_SNAPSHOT_HASHES ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_BYTES_SNAPSHOT_HASHES ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_ACCOUNTS_HASHES_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_BYTES_ACCOUNTS_HASHES ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_BYTES_ACCOUNTS_HASHES ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_EPOCH_SLOTS_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_BYTES_EPOCH_SLOTS ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_BYTES_EPOCH_SLOTS ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_VERSION_V1_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_BYTES_VERSION_V1 ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_BYTES_VERSION_V1 ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_VERSION_V2_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_BYTES_VERSION_V2 ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_BYTES_VERSION_V2 ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_NODE_INSTANCE_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_BYTES_NODE_INSTANCE ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_BYTES_NODE_INSTANCE ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_DUPLICATE_SHRED_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_BYTES_DUPLICATE_SHRED ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_BYTES_DUPLICATE_SHRED ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_INCREMENTAL_SNAPSHOT_HASHES_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_BYTES_INCREMENTAL_SNAPSHOT_HASHES ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_BYTES_INCREMENTAL_SNAPSHOT_HASHES ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_CONTACT_INFO_V2_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_BYTES_CONTACT_INFO_V2 ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_BYTES_CONTACT_INFO_V2 ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_RESTART_LAST_VOTED_FORK_SLOTS_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_BYTES_RESTART_LAST_VOTED_FORK_SLOTS ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_BYTES_RESTART_LAST_VOTED_FORK_SLOTS ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_V_RESTART_HEAVIEST_FORK_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PUSH_BYTES_RESTART_HEAVIEST_FORK ) )
    + fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_TX_PULL_RESPONSE_BYTES_RESTART_HEAVIEST_FORK ) );

  gossip_stats->messages_bytes_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PULL_REQUEST_IDX  ] = fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PULL_REQUEST ) );
  gossip_stats->messages_bytes_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PULL_RESPONSE_IDX ] = fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PULL_RESPONSE ) );
  gossip_stats->messages_bytes_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PUSH_IDX          ] = fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PUSH ) );
  gossip_stats->messages_bytes_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PING_IDX          ] = fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PING ) );
  gossip_stats->messages_bytes_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PONG_IDX          ] = fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PONG ) );
  gossip_stats->messages_bytes_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PRUNE_IDX         ] = fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PRUNE ) );

  gossip_stats->messages_count_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PULL_REQUEST_IDX  ] =
      fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PULL_REQUEST ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_NOT_CONTACT_INFO ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_LOOPBACK ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_INACTIVE ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_WALLCLOCK ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_SIGNATURE ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_SHRED_VERSION ) );
  gossip_stats->messages_count_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PULL_RESPONSE_IDX ] =
      fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PULL_RESPONSE ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_RESPONSE_NO_VALID_CRDS ) );
  gossip_stats->messages_count_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PUSH_IDX          ] =
      fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PUSH ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PUSH_NO_VALID_CRDS ) );
  gossip_stats->messages_count_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PING_IDX          ] =
      fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PING ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PING_SIGNATURE ) );
  gossip_stats->messages_count_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PONG_IDX          ] =
      fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PONG ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PONG_SIGNATURE ) );
  gossip_stats->messages_count_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PRUNE_IDX         ] =
      fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PRUNE ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_DESTINATION ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_WALLCLOCK ) )
    + fd_gui_sum_tiles_counter( peers, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_SIGNATURE ) );

  gossip_stats->messages_bytes_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PULL_REQUEST_IDX  ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PULL_REQUEST ) );
  gossip_stats->messages_bytes_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PULL_RESPONSE_IDX ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PULL_RESPONSE ) );
  gossip_stats->messages_bytes_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PUSH_IDX          ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PUSH ) );
  gossip_stats->messages_bytes_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PING_IDX          ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PING ) );
  gossip_stats->messages_bytes_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PONG_IDX          ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PONG ) );
  gossip_stats->messages_bytes_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PRUNE_IDX         ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PRUNE ) );

  gossip_stats->messages_count_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PULL_REQUEST_IDX  ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PULL_REQUEST ) );
  gossip_stats->messages_count_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PULL_RESPONSE_IDX ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PULL_RESPONSE ) );
  gossip_stats->messages_count_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PUSH_IDX          ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PUSH ) );
  gossip_stats->messages_count_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PING_IDX          ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PING ) );
  gossip_stats->messages_count_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PONG_IDX          ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PONG ) );
  gossip_stats->messages_count_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PRUNE_IDX         ] = fd_gui_sum_tiles_counter( peers, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PRUNE ) );
}

static int
fd_gui_peers_contact_info_eq( fd_contact_info_t const * ci1,
                              fd_contact_info_t const * ci2 ) {
  int ci_eq =
       ci1->shred_version                    == ci2->shred_version
    && ci1->instance_creation_wallclock_nanos== ci2->instance_creation_wallclock_nanos
 // && ci1->wallclock_nanos                  == ci2->wallclock_nanos
    && ci1->version.client                   == ci2->version.client
    && ci1->version.major                    == ci2->version.major
    && ci1->version.minor                    == ci2->version.minor
    && ci1->version.patch                    == ci2->version.patch
    && ci1->version.commit                   == ci2->version.commit
    && ci1->version.feature_set              == ci2->version.feature_set;

    if( FD_LIKELY( !ci_eq ) ) return 0;
    for( ulong j=0UL; j<(FD_CONTACT_INFO_SOCKET_CNT); j++ ) {
      if( FD_LIKELY( !(ci1->sockets[ j ].addr==ci2->sockets[ j ].addr && ci1->sockets[ j ].port==ci2->sockets[ j ].port) ) ) return 0;
    }
    return 1;
}

void
fd_gui_peers_handle_gossip_message( fd_gui_peers_ctx_t *  peers,
                                    uchar const *         payload,
                                    ulong                 payload_sz,
                                    fd_ip4_port_t const * peer_sock,
                                    int                   is_rx ) {
  fd_gui_peers_node_t * peer = fd_gui_peers_node_sock_map_ele_query( peers->node_sock_map, peer_sock, NULL, peers->contact_info_table );

  /* We set MAP_MULTI=1 since there are not guarantees that duplicates
     sockets wont exist. In cases where we see multiple sockets the
     update timestamp in fd_gui_peers_node_t is the tiebreaker */
  for( fd_gui_peers_node_t * p = peer; p!=NULL; p=(fd_gui_peers_node_t *)fd_gui_peers_node_sock_map_ele_next_const( p, NULL, peers->contact_info_table ) ) {
    if( peer->update_time_nanos>p->update_time_nanos ) peer = p;
  }

  if( FD_UNLIKELY( !peer ) ) return; /* NOP, peer not known yet */

  fd_gossip_view_t view[ 1 ];
  ulong decode_sz = fd_gossip_msg_parse( view, payload, payload_sz );
  if( FD_UNLIKELY( !decode_sz ) ) return; /* NOP, msg unparsable */

  FD_TEST( view->tag < FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT );
  fd_ptr_if( is_rx, &peer->gossvf_rx[ view->tag ], &peer->gossip_tx[ view->tag ] )->cur += payload_sz;
  fd_ptr_if( is_rx, (fd_gui_peers_metric_rate_t *)&peer->gossvf_rx_sum, (fd_gui_peers_metric_rate_t *)&peer->gossip_tx_sum )->cur += payload_sz;
#if LOGGING
  if( is_rx ) FD_LOG_WARNING(("payload rx=%lu", payload_sz ));
  else FD_LOG_WARNING(("payload tx=%lu", payload_sz ));
#endif
}

int
fd_gui_peers_handle_gossip_update( fd_gui_peers_ctx_t *               peers,
                                   fd_gossip_update_message_t const * update,
                                   long                               now ) {
    switch( update->tag ) {
      case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO: {
        /* origin_pubkey should be the same as the contact info pubkey */
        if( FD_UNLIKELY( memcmp( update->contact_info.contact_info->pubkey.uc, update->origin_pubkey, 32UL ) ) ) {
          char ci_pk[ FD_BASE58_ENCODED_32_SZ ];
          char og_pk[ FD_BASE58_ENCODED_32_SZ ];
          fd_base58_encode_32( update->contact_info.contact_info->pubkey.uc, NULL, ci_pk );
          fd_base58_encode_32( update->origin_pubkey, NULL, og_pk );

          FD_LOG_ERR(( "invariant violation: update->contact_info.contact_info->pubkey.uc=%s != update->origin_pubkey=%s ", ci_pk, og_pk ));
        }
        if( FD_UNLIKELY( update->contact_info.idx>=FD_CONTACT_INFO_TABLE_SIZE ) ) FD_LOG_ERR(( "unexpected contact_info_idx %lu >= %lu", update->contact_info.idx, FD_CONTACT_INFO_TABLE_SIZE ));
        fd_gui_peers_node_t * peer = &peers->contact_info_table[ update->contact_info.idx ];

        if( FD_LIKELY( peer->valid ) ) {
#if LOGGING
          char _pk[ FD_BASE58_ENCODED_32_SZ ];
          fd_base58_encode_32( update->origin_pubkey, NULL, _pk );
          FD_LOG_WARNING(("UPDATE %lu pk=%s", update->contact_info.idx, _pk ));
#endif
          /* invariant checks */
          if( FD_UNLIKELY( memcmp( peer->contact_info.pubkey.uc, update->origin_pubkey, 32UL ) ) ) {
            char ci_pk[ FD_BASE58_ENCODED_32_SZ ];
            char og_pk[ FD_BASE58_ENCODED_32_SZ ];
            fd_base58_encode_32( peer->contact_info.pubkey.uc, NULL, ci_pk );
            fd_base58_encode_32( update->origin_pubkey, NULL, og_pk );

            /* A new pubkey is not allowed to overwrite an existing valid index */
            FD_LOG_ERR(( "invariant violation: peer->contact_info.pubkey.uc=%s != update->origin_pubkey=%s ", ci_pk, og_pk ));
          }
          FD_TEST( peer==fd_gui_peers_node_pubkey_map_ele_query_const( peers->node_pubkey_map, (fd_pubkey_t * )update->origin_pubkey, NULL, peers->contact_info_table ) );
          fd_gui_peers_node_t * peer_sock = fd_gui_peers_node_sock_map_ele_query( peers->node_sock_map, &peer->contact_info.sockets[ FD_CONTACT_INFO_SOCKET_GOSSIP ], NULL, peers->contact_info_table );
          int found = 0;
          for( fd_gui_peers_node_t * p = peer_sock; !!p; p=(fd_gui_peers_node_t *)fd_gui_peers_node_sock_map_ele_next_const( p, NULL, peers->contact_info_table ) ) {
            if( peer==p ) {
              found = 1;
              break;
            }
          }
          FD_TEST( found );

          /* update does nothing */
          if( FD_UNLIKELY( fd_gui_peers_contact_info_eq( &peer->contact_info, update->contact_info.contact_info ) ) ) {
            peer->contact_info.wallclock_nanos = update->contact_info.contact_info->wallclock_nanos;
            return FD_GUI_PEERS_NODE_NOP;
          }

          fd_gui_peers_node_sock_map_idx_remove_fast( peers->node_sock_map, update->contact_info.idx, peers->contact_info_table );
          fd_gui_peers_live_table_idx_remove        ( peers->live_table,    update->contact_info.idx, peers->contact_info_table );
          fd_gui_peers_bandwidth_tracking_idx_remove( peers->bw_tracking,   update->contact_info.idx, peers->contact_info_table );

          fd_memcpy( &peer->contact_info, update->contact_info.contact_info, sizeof(peer->contact_info) );
          peer->update_time_nanos = now;

          fd_gui_peers_bandwidth_tracking_idx_insert( peers->bw_tracking,   update->contact_info.idx, peers->contact_info_table );
          fd_gui_peers_live_table_idx_insert        ( peers->live_table,    update->contact_info.idx, peers->contact_info_table );
          fd_gui_peers_node_sock_map_idx_insert     ( peers->node_sock_map, update->contact_info.idx, peers->contact_info_table );

          return FD_GUI_PEERS_NODE_UPDATE;
        } else {
          FD_TEST( !fd_gui_peers_node_pubkey_map_ele_query_const( peers->node_pubkey_map, &update->contact_info.contact_info->pubkey, NULL, peers->contact_info_table ) );
#if LOGGING
          char _pk[ FD_BASE58_ENCODED_32_SZ ];
          fd_base58_encode_32( update->origin_pubkey, NULL, _pk );
          FD_LOG_WARNING(( "ADD %lu pk=%s", update->contact_info.idx, _pk ));
#endif
          memset( &peer->gossvf_rx,     0, sizeof(peer->gossvf_rx) );
          memset( &peer->gossip_tx,     0, sizeof(peer->gossip_tx) );
          memset( &peer->gossvf_rx_sum, 0, sizeof(peer->gossvf_rx_sum) );
          memset( &peer->gossip_tx_sum, 0, sizeof(peer->gossip_tx_sum) );
          peer->has_node_info = 0;
          peer->valid = 1;
          peer->update_time_nanos = now;
          fd_memcpy( &peer->contact_info, update->contact_info.contact_info, sizeof(peer->contact_info) );

          /* update pubkey_map, sock_map */
          fd_gui_peers_node_sock_map_idx_insert  ( peers->node_sock_map,   update->contact_info.idx, peers->contact_info_table );
          fd_gui_peers_node_pubkey_map_idx_insert( peers->node_pubkey_map, update->contact_info.idx, peers->contact_info_table );

          /* update live tables */
          fd_gui_peers_live_table_idx_insert        ( peers->live_table,  update->contact_info.idx, peers->contact_info_table );
          fd_gui_peers_bandwidth_tracking_idx_insert( peers->bw_tracking, update->contact_info.idx, peers->contact_info_table );

          fd_gui_printf_peers_view_resize( peers, fd_gui_peers_live_table_ele_cnt( peers->live_table ) );
          FD_TEST( !fd_http_server_ws_broadcast( peers->http ) );

          return FD_GUI_PEERS_NODE_ADD;
        }

        break;
      }
      case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE: {
        if( FD_UNLIKELY( update->contact_info_remove.idx>=FD_CONTACT_INFO_TABLE_SIZE ) ) FD_LOG_ERR(( "unexpected remove_contact_info_idx %lu >= %lu", update->contact_info_remove.idx, FD_CONTACT_INFO_TABLE_SIZE ));
#if LOGGING
        char _pk[ FD_BASE58_ENCODED_32_SZ ];
        fd_base58_encode_32( update->origin_pubkey, NULL, _pk );
        FD_LOG_WARNING(( "REMOVE %lu pk=%s",update->contact_info.idx, _pk ));
#endif

        fd_gui_peers_node_t * peer = &peers->contact_info_table[ update->contact_info_remove.idx ];

        /* invariant checks */
        FD_TEST( peer->valid ); /* Should have already been in the table */
        FD_TEST( peer==fd_gui_peers_node_pubkey_map_ele_query_const( peers->node_pubkey_map, (fd_pubkey_t * )update->origin_pubkey, NULL, peers->contact_info_table ) );
        fd_gui_peers_node_t * peer_sock = fd_gui_peers_node_sock_map_ele_query( peers->node_sock_map, &peer->contact_info.sockets[ FD_CONTACT_INFO_SOCKET_GOSSIP ], NULL, peers->contact_info_table );
        int found = 0;
        for( fd_gui_peers_node_t const * p = peer_sock; !!p; p=(fd_gui_peers_node_t const *)fd_gui_peers_node_sock_map_ele_next_const( p, NULL, peers->contact_info_table ) ) {
          if( peer==p ) {
            found = 1;
            break;
          }
        }
        FD_TEST( found );

        fd_gui_peers_live_table_idx_remove          ( peers->live_table,      update->contact_info_remove.idx, peers->contact_info_table );
        fd_gui_peers_bandwidth_tracking_idx_remove  ( peers->bw_tracking,     update->contact_info_remove.idx, peers->contact_info_table );
        fd_gui_peers_node_sock_map_idx_remove_fast  ( peers->node_sock_map,   update->contact_info_remove.idx, peers->contact_info_table );
        fd_gui_peers_node_pubkey_map_idx_remove_fast( peers->node_pubkey_map, update->contact_info_remove.idx, peers->contact_info_table );
        peer->valid = 0;

        fd_gui_printf_peers_view_resize( peers, fd_gui_peers_live_table_ele_cnt( peers->live_table ) );
        FD_TEST( !fd_http_server_ws_broadcast( peers->http ) );
        break;
      }
      default: break;
    }

    return FD_GUI_PEERS_NODE_NOP;
}

static void
fd_gui_peers_viewport_snap( fd_gui_peers_ctx_t * peers, ulong ws_conn_id ) {
  FD_TEST( peers->client_viewports[ ws_conn_id ].connected );
  if( !(peers->client_viewports[ ws_conn_id ].row_cnt && peers->client_viewports[ ws_conn_id ].row_cnt<FD_GUI_PEERS_WS_VIEWPORT_MAX_SZ) ) FD_LOG_ERR(("row_cnt=%lu", peers->client_viewports[ ws_conn_id ].row_cnt ));

  if( FD_UNLIKELY( fd_gui_peers_live_table_active_sort_key_cnt( peers->live_table )==FD_GUI_PEERS_CI_TABLE_SORT_KEY_CNT ) ) {
    /* we're out of cached sort keys. disconnect the oldest client */
    ulong oldest_ws_conn_id    = ULONG_MAX;
    long oldest_connected_time = LONG_MAX;
    for( ulong i=0UL; i<peers->max_ws_conn_cnt; i++ ) {
      if( FD_UNLIKELY( peers->client_viewports[ i ].connected && peers->client_viewports[ i ].connected_time < oldest_connected_time ) ) {
        oldest_ws_conn_id = i;
        oldest_connected_time = peers->client_viewports[ i ].connected_time;
      }
    }
    FD_TEST( oldest_ws_conn_id!=ULONG_MAX );
    fd_gui_peers_live_table_sort_key_remove( peers->live_table, peers->client_viewports[ oldest_ws_conn_id ].sort_key );
    FD_TEST( fd_gui_peers_live_table_active_sort_key_cnt( peers->live_table )==FD_GUI_PEERS_CI_TABLE_SORT_KEY_CNT-1UL );
  }

  for( fd_gui_peers_live_table_fwd_iter_t iter = fd_gui_peers_live_table_fwd_iter_init( peers->live_table, peers->client_viewports[ ws_conn_id ].sort_key, peers->contact_info_table ), j = 0;
       !fd_gui_peers_live_table_fwd_iter_done( iter ) && j<peers->client_viewports[ ws_conn_id ].start_row+peers->client_viewports[ ws_conn_id ].row_cnt;
       iter = fd_gui_peers_live_table_fwd_iter_next( iter, peers->contact_info_table ), j++ ) {
    if( FD_LIKELY( j<peers->client_viewports[ ws_conn_id ].start_row ) ) continue;
    fd_gui_peers_node_t const * cur = fd_gui_peers_live_table_fwd_iter_ele_const( iter, peers->contact_info_table );
    fd_gui_peers_node_t * ref = &peers->client_viewports[ ws_conn_id ].viewport[ j ];

    fd_memcpy( ref, cur, sizeof(fd_gui_peers_node_t) );
  }
}

static int
fd_gui_peers_request_scroll( fd_gui_peers_ctx_t * peers,
                             ulong                ws_conn_id,
                             ulong                request_id,
                             cJSON const *        params ) {
  if( FD_UNLIKELY( !peers->client_viewports[ ws_conn_id ].connected ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  const cJSON * start_row_param = cJSON_GetObjectItemCaseSensitive( params, "start_row" );
  if( FD_UNLIKELY( !cJSON_IsNumber( start_row_param ) ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  ulong _start_row = start_row_param->valueulong;

  const cJSON * row_cnt_param = cJSON_GetObjectItemCaseSensitive( params, "row_cnt" );
  if( FD_UNLIKELY( !cJSON_IsNumber( row_cnt_param ) ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  ulong _row_cnt = row_cnt_param->valueulong;

  if( FD_UNLIKELY( _row_cnt==0 || _row_cnt > FD_GUI_PEERS_WS_VIEWPORT_MAX_SZ ) ) {
    fd_gui_printf_null_query_response( peers->http, "gossip", "query_scroll", request_id );
    FD_TEST( !fd_http_server_ws_send( peers->http, ws_conn_id ) );
    return 0;
  }

  if( FD_UNLIKELY( peers->client_viewports[ ws_conn_id ].start_row==_start_row && peers->client_viewports[ ws_conn_id ].row_cnt==_row_cnt ) ) {
    return 0; /* NOP, scroll window hasn't changed */
  }

  /* update the client's viewport */
  peers->client_viewports[ ws_conn_id ].start_row = _start_row;
  peers->client_viewports[ ws_conn_id ].row_cnt   = _row_cnt;

  fd_gui_printf_peers_viewport_request( peers, "query_scroll", ws_conn_id, request_id );
  FD_TEST( !fd_http_server_ws_send( peers->http, ws_conn_id ) );
  return 0;
}

static int
fd_gui_peers_request_sort( fd_gui_peers_ctx_t * peers,
                           ulong                ws_conn_id,
                           ulong                request_id,
                           cJSON const *        params ) {
  if( FD_UNLIKELY( !peers->client_viewports[ ws_conn_id ].connected ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  const cJSON * col_id_param = cJSON_GetObjectItemCaseSensitive( params, "col_id" );
  if( FD_UNLIKELY( !cJSON_IsString( col_id_param ) ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  char * _col_name = col_id_param->valuestring;

  ulong _col_idx = fd_gui_peers_live_table_col_name_to_idx( peers->live_table, _col_name );
  if( FD_UNLIKELY( _col_idx==ULONG_MAX) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  ulong sort_idx = ULONG_MAX;
  for( ulong i=0UL; i<FD_GUI_PEERS_CI_TABLE_SORT_KEY_CNT; i++ ) {
    if( FD_UNLIKELY( _col_idx==peers->client_viewports[ ws_conn_id ].sort_key->col[ i ] ) ) {
      sort_idx = i;
      break;
    }
  }
  FD_TEST( sort_idx!=ULONG_MAX );

  const cJSON * dir_param = cJSON_GetObjectItemCaseSensitive( params, "dir" );
  if( FD_UNLIKELY( !cJSON_IsNumber( dir_param ) ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  int _dir = dir_param->valueint;

  if( FD_UNLIKELY( _dir > 1 || _dir < -1 ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  if( FD_UNLIKELY( peers->client_viewports[ ws_conn_id ].sort_key->dir[ sort_idx ]==_dir ) ) return 0; /* NOP, sort_key hasn't changed */

  /* shift the column to the front of the sort key */
  for( ulong i=sort_idx; i>0; i-- ) {
    peers->client_viewports[ ws_conn_id ].sort_key->col[ i ] = peers->client_viewports[ ws_conn_id ].sort_key->col[ i-1UL ];
    peers->client_viewports[ ws_conn_id ].sort_key->dir[ i ] = peers->client_viewports[ ws_conn_id ].sort_key->dir[ i-1UL ];
  }
  peers->client_viewports[ ws_conn_id ].sort_key->col[ 0 ] = _col_idx;
  peers->client_viewports[ ws_conn_id ].sort_key->dir[ 0 ] = _dir;

  if( FD_UNLIKELY( peers->client_viewports[ ws_conn_id ].row_cnt==0 )) return 0; /* NOP */

  fd_gui_printf_peers_viewport_request( peers, "query_sort_col", ws_conn_id, request_id );
  FD_TEST( !fd_http_server_ws_send( peers->http, ws_conn_id ) );
  return 0;
}

int
fd_gui_peers_ws_message( fd_gui_peers_ctx_t * peers,
                         ulong                ws_conn_id,
                         uchar const *        data,
                         ulong                data_len ) {
  /* TODO: cJSON allocates, might fail SIGSYS due to brk(2)...
     switch off this (or use wksp allocator) */
  const char * parse_end;
  cJSON * json = cJSON_ParseWithLengthOpts( (char *)data, data_len, &parse_end, 0 );
  if( FD_UNLIKELY( !json ) ) {
    return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  }

  const cJSON * node = cJSON_GetObjectItemCaseSensitive( json, "id" );
  if( FD_UNLIKELY( !cJSON_IsNumber( node ) ) ) {
    cJSON_Delete( json );
    return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  }
  ulong id = node->valueulong;

  const cJSON * topic = cJSON_GetObjectItemCaseSensitive( json, "topic" );
  if( FD_UNLIKELY( !cJSON_IsString( topic ) || topic->valuestring==NULL ) ) {
    cJSON_Delete( json );
    return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  }

  const cJSON * key = cJSON_GetObjectItemCaseSensitive( json, "key" );
  if( FD_UNLIKELY( !cJSON_IsString( key ) || key->valuestring==NULL ) ) {
    cJSON_Delete( json );
    return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  }

  if( FD_LIKELY( !strcmp( topic->valuestring, "gossip" ) && !strcmp( key->valuestring, "query_sort_col" ) ) ) {
    const cJSON * params = cJSON_GetObjectItemCaseSensitive( json, "params" );
    if( FD_UNLIKELY( !cJSON_IsObject( params ) ) ) {
      cJSON_Delete( json );
      return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
    }

    int result = fd_gui_peers_request_sort( peers, ws_conn_id, id, params );
    cJSON_Delete( json );
    return result;
  } else if( FD_LIKELY( !strcmp( topic->valuestring, "gossip" ) && !strcmp( key->valuestring, "query_scroll" ) ) ) {
    const cJSON * params = cJSON_GetObjectItemCaseSensitive( json, "params" );
    if( FD_UNLIKELY( !cJSON_IsObject( params ) ) ) {
      cJSON_Delete( json );
      return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
    }

    int result = fd_gui_peers_request_scroll( peers, ws_conn_id, id, params );
    cJSON_Delete( json );
    return result;
  }

  cJSON_Delete( json );
  return FD_HTTP_SERVER_CONNECTION_CLOSE_UNKNOWN_METHOD;
}

static void
fd_gui_peers_viewport_log( fd_gui_peers_ctx_t *  peers,
                           ulong                 ws_conn_id) {

  FD_TEST( peers->client_viewports[ ws_conn_id ].row_cnt && peers->client_viewports[ ws_conn_id ].row_cnt < FD_GUI_PEERS_WS_VIEWPORT_MAX_SZ );

  char out[ 1<<14 ];
  char * p = fd_cstr_init( out );

  p = fd_cstr_append_printf( p,
    "\n[Viewport] table_size=%lu max_viewport_size=%lu\n"
    "+-------+----------------+----------------+----------------+----------------+----------------------------------------------------+-----------------+\n"
    "| Row # | RX Push (bps)  | RX Pull (bps)  | TX Push (bps)  | TX Pull (bps)  | Pubkey                                             | IP Address      |\n"
    "+-------+----------------+----------------+----------------+----------------+----------------------------------------------------+-----------------+\n",
    fd_gui_peers_live_table_ele_cnt( peers->live_table ), peers->client_viewports[ ws_conn_id ].row_cnt );

  FD_TEST( peers->client_viewports[ ws_conn_id ].connected );
  for( fd_gui_peers_live_table_fwd_iter_t iter = fd_gui_peers_live_table_fwd_iter_init( peers->live_table, peers->client_viewports[ ws_conn_id ].sort_key, peers->contact_info_table ), j = 0UL;
       !fd_gui_peers_live_table_fwd_iter_done(iter) && j < peers->client_viewports[ ws_conn_id ].start_row + peers->client_viewports[ ws_conn_id ].row_cnt;
       iter = fd_gui_peers_live_table_fwd_iter_next(iter, peers->contact_info_table), j++ ) {
    if( FD_LIKELY( j < peers->client_viewports[ ws_conn_id ].start_row ) ) continue;

    fd_gui_peers_node_t const * cur = fd_gui_peers_live_table_fwd_iter_ele_const( iter, peers->contact_info_table );

    char pubkey_base58[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( cur->contact_info.pubkey.uc, NULL, pubkey_base58 );

    char peer_addr[ 16 ]; /* 255.255.255.255 + '\0' */
    FD_TEST(fd_cstr_printf_check( peer_addr, sizeof(peer_addr), NULL, FD_IP4_ADDR_FMT,
                                  FD_IP4_ADDR_FMT_ARGS( cur->contact_info.sockets[FD_CONTACT_INFO_SOCKET_GOSSIP].addr ) ) );

    long cur_egress_push_bps           = cur->gossip_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PUSH_IDX ].rate;
    long cur_ingress_push_bps          = cur->gossvf_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PUSH_IDX ].rate;
    long cur_egress_pull_response_bps  = cur->gossip_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PULL_RESPONSE_IDX ].rate;
    long cur_ingress_pull_response_bps = cur->gossvf_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PULL_RESPONSE_IDX ].rate;

    p = fd_cstr_append_printf( p,
                               "| %5lu | %14ld | %14ld | %14ld | %14ld | %-50s | %-15s |\n",
                               peers->client_viewports[ ws_conn_id ].start_row + j,
                               cur_ingress_push_bps,
                               cur_ingress_pull_response_bps,
                               cur_egress_push_bps,
                               cur_egress_pull_response_bps,
                               pubkey_base58,
                               peer_addr );
  }
  p = fd_cstr_append_printf(p, "+-------+----------------+----------------+----------------+----------------+----------------------------------------------------+-----------------+" );
  fd_cstr_fini( p );
  FD_LOG_NOTICE(( "%s", out ));
}

static void
fd_gui_peers_ws_conn_rr_grow( fd_gui_peers_ctx_t * peers, ulong ws_conn_id ) {
  if( FD_UNLIKELY( !peers->open_ws_conn_cnt ) ) peers->active_ws_conn_id = ws_conn_id;
  peers->open_ws_conn_cnt++;
}

static void
fd_gui_peers_ws_conn_rr_shrink( fd_gui_peers_ctx_t * peers, ulong ws_conn_id ) {
  peers->open_ws_conn_cnt--;

  if( FD_UNLIKELY( peers->open_ws_conn_cnt && peers->active_ws_conn_id==ws_conn_id ) ) {
    for( ulong i=0UL; i<peers->max_ws_conn_cnt; i++ ) {
      ulong next_ws_conn_id = (ws_conn_id + i) % peers->max_ws_conn_cnt;
      if( FD_UNLIKELY( peers->client_viewports[ next_ws_conn_id ].connected ) ) {
        peers->active_ws_conn_id = next_ws_conn_id;
        break;
      }
    }
  }
}

static int
fd_gui_peers_ws_conn_rr_advance( fd_gui_peers_ctx_t * peers, long now ) {
  if( FD_LIKELY( !peers->open_ws_conn_cnt || now <= peers->next_client_nanos ) ) return 0;

  for( ulong i=1UL; i<peers->max_ws_conn_cnt; i++ ) {
    ulong next_ws_conn_id = (peers->active_ws_conn_id + i) % peers->max_ws_conn_cnt;
    if( FD_UNLIKELY( peers->client_viewports[ next_ws_conn_id ].connected ) ) {
      peers->active_ws_conn_id = next_ws_conn_id;
      break;
    }
  }
  return 1;
}

int
fd_gui_peers_poll( fd_gui_peers_ctx_t * peers, long now ) {
  int did_work = 0;

  /* update client viewports in a round-robin */
  if( FD_UNLIKELY( fd_gui_peers_ws_conn_rr_advance( peers, now ) ) ) {
    FD_TEST( peers->client_viewports[ peers->active_ws_conn_id ].connected );
    if( FD_LIKELY( peers->client_viewports[ peers->active_ws_conn_id ].row_cnt ) ) {
      /* broadcast the diff as cell updates */
      fd_gui_printf_peers_viewport_update( peers, peers->active_ws_conn_id );
      FD_TEST( !fd_http_server_ws_send( peers->http, peers->active_ws_conn_id ) );

      /* log the diff */
      fd_gui_peers_viewport_log( peers, peers->active_ws_conn_id );
      (void)fd_gui_peers_viewport_log;

      /* update client state to the latest viewport */
      fd_gui_peers_viewport_snap( peers, peers->active_ws_conn_id );
    }

    peers->next_client_nanos = now + ((FD_GUI_PEERS_WS_VIEWPORT_UPDATE_INTERVAL_MILLIS * 1000000L) / (long)peers->open_ws_conn_cnt);
    did_work = 1;
  }

  if( FD_UNLIKELY( now >= peers->next_metric_rate_update_nanos ) ) {
    for( fd_gui_peers_node_pubkey_map_iter_t iter = fd_gui_peers_node_pubkey_map_iter_init( peers->node_pubkey_map, peers->contact_info_table );
         !fd_gui_peers_node_pubkey_map_iter_done( iter, peers->node_pubkey_map, peers->contact_info_table );
         iter = fd_gui_peers_node_pubkey_map_iter_next( iter, peers->node_pubkey_map, peers->contact_info_table ) ) {
      fd_gui_peers_node_t * peer = fd_gui_peers_node_pubkey_map_iter_ele( iter, peers->node_pubkey_map, peers->contact_info_table );

      double window = (double)(now - (peers->next_metric_rate_update_nanos - (FD_GUI_PEERS_METRIC_RATE_UPDATE_INTERVAL_MILLIS * 1000000L)));

      /* optimization: no need to remove / re-insert if the rates haven't changed */
      int change = 0;
      for( ulong i=0UL; i<FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT; i++ ) {
        fd_gui_peers_metric_rate_t * metric = &peer->gossvf_rx[ i ];
        long new_rate = (long)(((double)((long)metric->cur - (long)metric->ref) * 1e9 / window));
        if( FD_LIKELY( metric->rate == new_rate ) ) continue;
        change = 1;
        break;
      }

      if( !change) {
        for( ulong i=0UL; i<FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT; i++ ) {
          fd_gui_peers_metric_rate_t * metric = &peer->gossip_tx[ i ];
          long new_rate = (long)(((double)((long)metric->cur - (long)metric->ref) * 1e9 / window));
          if( FD_LIKELY( metric->rate == new_rate ) ) continue;
          change = 1;
          break;
        }
      }

      if( !change ) continue;

      /* live_table */
      fd_gui_peers_live_table_ele_remove( peers->live_table, peer, peers->contact_info_table );
      for( ulong i=0UL; i<FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT; i++ ) {
        fd_gui_peers_metric_rate_t * metric = &peer->gossvf_rx[ i ];
        metric->rate = (long)(((double)((long)metric->cur - (long)metric->ref) * 1e9 / window));
        metric->ref  = metric->cur;
      }

      for( ulong i=0UL; i<FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT; i++ ) {
        fd_gui_peers_metric_rate_t * metric = &peer->gossip_tx[ i ];
        metric->rate = (long)(((double)((long)metric->cur - (long)metric->ref) * 1e9 / window));
        metric->ref  = metric->cur;
      }
      fd_gui_peers_live_table_ele_insert( peers->live_table, peer, peers->contact_info_table );

      /* bandwidth_tracking */
      fd_gui_peers_bandwidth_tracking_ele_remove( peers->bw_tracking, peer, peers->contact_info_table );
      peer->gossvf_rx_sum.rate = (long)(((double)((long)peer->gossvf_rx_sum.cur - (long)peer->gossvf_rx_sum.ref) * 1e9 / window));
      peer->gossvf_rx_sum.ref  = peer->gossvf_rx_sum.cur;

      peer->gossip_tx_sum.rate = (long)(((double)((long)peer->gossip_tx_sum.cur - (long)peer->gossip_tx_sum.ref) * 1e9 / window));
      peer->gossip_tx_sum.ref  = peer->gossip_tx_sum.cur;
      fd_gui_peers_bandwidth_tracking_ele_insert( peers->bw_tracking, peer, peers->contact_info_table );
    }

    peers->next_metric_rate_update_nanos = now + (FD_GUI_PEERS_METRIC_RATE_UPDATE_INTERVAL_MILLIS * 1000000L);
    did_work = 1;
    fd_gui_peers_live_table_verify( peers->live_table, peers->contact_info_table ); /* todo ... remove */
  }

  if( FD_LIKELY( now >= peers->next_gossip_stats_update_nanos ) ) {
    fd_gui_peers_gossip_stats_snap( peers, peers->gossip_stats, now );
    fd_gui_peers_printf_gossip_stats( peers );
    fd_http_server_ws_broadcast( peers->http );

    peers->next_gossip_stats_update_nanos = now + (FD_GUI_PEERS_GOSSIP_STATS_UPDATE_INTERVAL_MILLIS * 1000000L);
    did_work = 1;
  }

  return did_work;
}

void
fd_gui_peers_ws_open( fd_gui_peers_ctx_t * peers, ulong ws_conn_id, long now ) {
  fd_gui_peers_ws_conn_rr_grow( peers, ws_conn_id );
  peers->client_viewports[ ws_conn_id ].connected = 1;
  peers->client_viewports[ ws_conn_id ].connected_time = now;
  peers->client_viewports[ ws_conn_id ].start_row = 0;
  peers->client_viewports[ ws_conn_id ].row_cnt = 0;
  fd_memcpy( peers->client_viewports[ ws_conn_id ].sort_key, &FD_GUI_PEERS_LIVE_TABLE_DEFAULT_SORT_KEY, sizeof(fd_gui_peers_live_table_sort_key_t) );
}

void
fd_gui_peers_ws_close( fd_gui_peers_ctx_t * peers, ulong ws_conn_id ) {
  fd_gui_peers_live_table_sort_key_remove( peers->live_table, peers->client_viewports[ ws_conn_id ].sort_key );
  peers->client_viewports[ ws_conn_id ].connected = 0;
  fd_gui_peers_ws_conn_rr_shrink( peers, ws_conn_id );
}

#undef LOGGING
