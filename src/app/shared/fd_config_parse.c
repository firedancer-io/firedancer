#include "../platform/fd_config_extract.h"
#include "fd_config_private.h"

static int
fdctl_cfg_get_str( fd_config_t *          cfg,
                   fd_topo_str_t *        out,
                   fd_toml_doc_t const *  doc,
                   fd_toml_node_t const * node,
                   char const *           path ) {
  if( FD_UNLIKELY( node->type!=FD_TOML_NODE_STRING ) ) {
    FD_LOG_WARNING(( "invalid value for `%s`", path ));
    return 0;
  }
  if( FD_UNLIKELY( !fd_config_str_set( cfg, out, fd_toml_node_str( doc, node ), node->str.len ) ) ) {
    FD_LOG_WARNING(( "`%s`: config string storage exhausted", path ));
    return 0;
  }
  return 1;
}

#include "../platform/fd_config_macros.c"

static void
fd_config_check_configf( fd_config_t *  config,
                         fd_configf_t * config_f ) {
  (void)config_f;
  char const * snapshots = FD_TOPO_STR( config->paths.snapshots );
  if( FD_UNLIKELY( strlen( snapshots )>PATH_MAX-1UL ) ) {
    FD_LOG_ERR(( "[config->paths.snapshots] is too long (max %lu)", PATH_MAX-1UL ));
  }
  if( FD_UNLIKELY( snapshots[ 0 ]!='\0' && snapshots[ 0 ]!='/' ) ) {
    FD_LOG_ERR(( "[config->paths.snapshots] must be an absolute path and hence start with a '/'"));
  }
}

static fd_configh_t *
fd_config_extract_tomlh( fd_toml_doc_t * doc,
                         fd_config_t *   cfg,
                         fd_configh_t *  config ) {
  CFG_POP_STR       ( dynamic_port_range );

  CFG_POP_STR       ( reporting.solana_metrics_config );

  CFG_POP_STR       ( layout.agave_affinity );
  CFG_POP           ( uint, layout.agave_unified_scheduler_handler_threads );
  CFG_POP           ( uint, layout.resolh_tile_count );
  CFG_POP           ( uint, layout.bank_tile_count );

  CFG_POP1_STR      ( ledger.accounts_path, paths.accounts_path );
  CFG_POP1_STR_ARRAY( consensus.authorized_voter_paths, paths.authorized_voter_paths );

  CFG_POP           ( uint, ledger.limit_size );
  CFG_POP_STR_ARRAY ( ledger.account_indexes );
  CFG_POP_STR_ARRAY ( ledger.account_index_include_keys );
  CFG_POP_STR_ARRAY ( ledger.account_index_exclude_keys );
  CFG_POP           ( bool, ledger.enable_accounts_disk_index );
  CFG_POP_STR       ( ledger.accounts_index_path );
  CFG_POP_STR       ( ledger.accounts_hash_cache_path );
  CFG_POP           ( bool, ledger.require_tower );
  CFG_POP_STR       ( ledger.snapshot_archive_format );

  CFG_POP           ( bool, gossip.port_check );

  CFG_POP           ( bool, consensus.snapshot_fetch );
  CFG_POP           ( bool, consensus.genesis_fetch );
  CFG_POP           ( bool, consensus.poh_speed_test );
  CFG_POP           ( uint, consensus.wait_for_supermajority_at_slot );
  CFG_POP_STR       ( consensus.expected_bank_hash );
  CFG_POP           ( bool, consensus.wait_for_vote_to_start_leader );
  CFG_POP_ARRAY     ( uint, consensus.hard_fork_at_slots );
  CFG_POP_STR_ARRAY ( consensus.known_validators );
  CFG_POP           ( bool, consensus.os_network_limits_test );

  CFG_POP           ( ushort, rpc.port );
  CFG_POP           ( bool, rpc.extended_tx_metadata_storage );
  CFG_POP           ( bool, rpc.full_api );
  CFG_POP           ( bool, rpc.private );
  CFG_POP_STR       ( rpc.bind_address );
  CFG_POP_STR       ( rpc.public_address );
  CFG_POP           ( bool, rpc.transaction_history );
  CFG_POP           ( bool, rpc.only_known );
  CFG_POP           ( bool, rpc.pubsub_enable_block_subscription );
  CFG_POP           ( bool, rpc.pubsub_enable_vote_subscription );
  CFG_POP           ( bool, rpc.bigtable_ledger_storage );

  CFG_POP           ( bool, snapshots.enabled );
  CFG_POP           ( bool, snapshots.incremental_snapshots );
  CFG_POP           ( uint, snapshots.full_snapshot_interval_slots );
  CFG_POP           ( uint, snapshots.incremental_snapshot_interval_slots );
  CFG_POP           ( uint, snapshots.minimum_snapshot_download_speed );
  CFG_POP           ( uint, snapshots.maximum_snapshot_download_abort );
  CFG_POP           ( uint, snapshots.maximum_full_snapshots_to_retain );
  CFG_POP           ( uint, snapshots.maximum_incremental_snapshots_to_retain );
  CFG_POP_STR       ( snapshots.path );
  CFG_POP_STR       ( snapshots.incremental_path );

  return config;
}

static fd_configf_t *
fd_config_extract_tomlf( fd_toml_doc_t * doc,
                         fd_config_t *   cfg,
                         fd_configf_t *  config ) {
  CFG_POP_STR_ARRAY ( paths.authorized_voter_paths );

  CFG_POP_STR       ( gossip.host );

  CFG_POP           ( bool, layout.enable_block_production );
  CFG_POP           ( bool, layout.enable_snapshot_production );
  CFG_POP           ( uint, layout.execrp_tile_count );
  CFG_POP           ( uint, layout.sign_tile_count );
  CFG_POP           ( uint, layout.resolv_tile_count );
  CFG_POP           ( uint, layout.execle_tile_count );
  CFG_POP           ( uint, layout.gossvf_tile_count );
  CFG_POP           ( uint, layout.snapdc_tile_count );
  CFG_POP           ( uint, layout.snapzp_tile_count );
  CFG_POP           ( uint, layout.snapsv_tile_count );
  CFG_POP           ( uint, layout.snapsv_io_worker_count );

  CFG_POP           ( ulong, accounts.max_accounts );
  CFG_POP           ( ulong, accounts.cache_size_gib );

  CFG_POP           ( ulong, runtime.max_live_slots );
  CFG_POP           ( ulong, runtime.max_fork_width );

  CFG_POP           ( ulong, runtime.program_cache.heap_size_mib );
  CFG_POP           ( ulong, runtime.program_cache.mean_cache_entry_size );

  CFG_POP_STR       ( consensus.wait_for_supermajority_with_bank_hash );

  CFG_POP           ( uint, snapshots.sources.max_local_full_effective_age );
  CFG_POP           ( uint, snapshots.sources.max_local_incremental_age );
  CFG_POP           ( bool, snapshots.sources.gossip.allow_any );
  CFG_POP_STR_ARRAY ( snapshots.sources.gossip.allow_list );
  CFG_POP_STR_ARRAY ( snapshots.sources.gossip.block_list );
  CFG_POP_STR_ARRAY ( snapshots.sources.servers );
  CFG_POP           ( bool, snapshots.incremental_snapshots );
  CFG_POP           ( bool, snapshots.genesis_download );
  CFG_POP           ( uint, snapshots.max_full_snapshots_to_keep );
  CFG_POP           ( uint, snapshots.max_incremental_snapshots_to_keep );
  CFG_POP           ( uint, snapshots.max_retry_abort );
  CFG_POP           ( uint, snapshots.min_download_speed_mibs );
  CFG_POP           ( ulong, snapshots.wait_for_peers_timeout_seconds );
  CFG_POP           ( ulong, snapshots.full_snapshot_interval_blocks );
  CFG_POP           ( ulong, snapshots.incremental_snapshot_interval_blocks );
  CFG_POP           ( ulong, snapshots.max_incremental_snapshot_accounts );

  CFG_POP           ( bool, snapshots.server.enabled );
  CFG_POP_STR       ( snapshots.server.http_listen_address );
  CFG_POP           ( uint, snapshots.server.http_listen_port );
  CFG_POP           ( ulong, snapshots.server.max_http_connections );
  CFG_POP           ( ulong, snapshots.server.idle_timeout_millis );
  CFG_POP           ( ulong, snapshots.server.send_timeout_millis );
  CFG_POP           ( ulong, snapshots.server.send_buffer_size_kib );

  CFG_POP           ( bool, development.hard_fork_fatal );
  CFG_POP           ( bool, development.fixed_fec_sets );
  CFG_POP           ( bool, development.alpenglow );

  CFG_POP           ( ushort, development.votor.quic_client_listen_port );
  CFG_POP           ( ushort, development.votor.quic_server_listen_port );

  CFG_POP           ( bool, development.genesis.validate_genesis_hash );
  CFG_POP           ( ulong, development.genesis.max_file_size_mib );

  CFG_POP_STR       ( development.ledger_input.format );
  CFG_POP_STR       ( development.ledger_input.path );
  CFG_POP           ( ulong, development.ledger_input.end_slot );

  CFG_POP_STR       ( development.backtest.affinity );
  CFG_POP           ( ulong, development.backtest.root_distance );

  CFG_POP_STR       ( development.forktest.affinity );

  return config;
}

fd_config_t *
fd_config_extract_toml( fd_toml_doc_t * doc,
                        fd_config_t *   config ) {
  fd_config_t * cfg = config;
  CFG_POP_STR       ( name );
  CFG_POP_STR       ( user );

  CFG_POP           ( bool, telemetry );

  CFG_POP_STR       ( log.path );
  CFG_POP_STR       ( log.colorize );
  CFG_POP_STR       ( log.level_logfile );
  CFG_POP_STR       ( log.level_stderr );
  CFG_POP_STR       ( log.level_flush );

  if( FD_UNLIKELY( config->is_firedancer ) ) {
    CFG_POP_STR       ( paths.base );
    CFG_POP_STR       ( paths.identity_key );
    CFG_POP_STR       ( paths.vote_account );
    CFG_POP_STR       ( paths.snapshots );
    CFG_POP_STR       ( paths.genesis );
    CFG_POP_STR       ( paths.accounts );
    CFG_POP_STR       ( paths.shredb );
    CFG_POP_STR       ( paths.guidb );
  } else {
    CFG_POP1_STR      ( scratch_directory, paths.base );
    CFG_POP1_STR      ( ledger.path, frankendancer.paths.ledger );
    CFG_POP1_STR      ( consensus.identity_path, paths.identity_key );
    CFG_POP1_STR      ( consensus.vote_account_path, paths.vote_account );
  }

  CFG_POP_STR_ARRAY ( gossip.entrypoints );
  CFG_POP           ( ushort, gossip.port );

  CFG_POP           ( ushort, consensus.expected_shred_version );
  CFG_POP_STR       ( consensus.expected_genesis_hash );
  CFG_POP           ( bool, consensus.wait_for_vote_to_start_leader );

  CFG_POP_STR       ( layout.affinity );
  CFG_POP_STR       ( layout.blocklist_cores );
  CFG_POP           ( uint, layout.net_tile_count );
  CFG_POP           ( uint, layout.quic_tile_count );
  CFG_POP           ( uint, layout.verify_tile_count );
  CFG_POP           ( uint, layout.shred_tile_count );

  CFG_POP_STR       ( hugetlbfs.mount_path );
  CFG_POP_STR       ( hugetlbfs.max_page_size );
  CFG_POP           ( ulong, hugetlbfs.gigantic_page_threshold_mib );

  CFG_POP_STR       ( net.interface );
  CFG_POP_STR       ( net.bind_address );
  CFG_POP_STR       ( net.provider );
  CFG_POP           ( uint, net.ingress_buffer_size );
  CFG_POP_STR       ( net.xdp.xdp_mode );
  CFG_POP           ( boolau, net.xdp.xdp_zero_copy );
  CFG_POP_STR       ( net.xdp.poll_mode );
  CFG_POP           ( uint, net.xdp.xdp_rx_queue_size );
  CFG_POP           ( uint, net.xdp.xdp_tx_queue_size );
  CFG_POP           ( uint, net.xdp.flush_timeout_micros );
  CFG_POP_STR       ( net.xdp.rss_queue_mode );
  CFG_POP           ( boolau, net.xdp.listen_gre );
  CFG_POP           ( boolau, net.xdp.native_bond );
  CFG_POP           ( uint, net.mlx5.rx_queue_size );
  CFG_POP           ( uint, net.mlx5.tx_queue_size );
  CFG_POP           ( uint, net.socket.receive_buffer_size );
  CFG_POP           ( uint, net.socket.send_buffer_size );

  CFG_POP           ( ulong, tiles.netlink.max_routes );
  CFG_POP           ( ulong, tiles.netlink.max_peer_routes );
  CFG_POP           ( ulong, tiles.netlink.max_neighbors );

  CFG_POP           ( ulong, tiles.gossip.max_entries );

  CFG_POP           ( ushort, tiles.quic.regular_transaction_listen_port );
  CFG_POP           ( ushort, tiles.quic.quic_transaction_listen_port );
  CFG_POP           ( uint, tiles.quic.txn_reassembly_count );
  CFG_POP           ( uint, tiles.quic.max_concurrent_connections );
  CFG_POP           ( uint, tiles.quic.max_concurrent_handshakes );
  CFG_POP           ( uint, tiles.quic.idle_timeout_millis );
  CFG_POP           ( uint, tiles.quic.ack_delay_millis );
  CFG_POP           ( bool, tiles.quic.retry );
  CFG_POP_STR       ( tiles.quic.ssl_key_log_file );

  CFG_POP           ( uint, tiles.verify.signature_cache_size );
  CFG_POP           ( uint, tiles.verify.receive_buffer_size );
  CFG_POP           ( uint, tiles.verify.mtu );

  CFG_POP           ( uint, tiles.dedup.signature_cache_size );

  CFG_POP           ( bool, tiles.bundle.enabled );
  CFG_POP_STR       ( tiles.bundle.url );
  CFG_POP_STR       ( tiles.bundle.tls_domain_name );
  CFG_POP_STR       ( tiles.bundle.tip_distribution_program_addr );
  CFG_POP_STR       ( tiles.bundle.tip_payment_program_addr );
  CFG_POP_STR       ( tiles.bundle.tip_distribution_authority );
  CFG_POP           ( uint, tiles.bundle.commission_bps );
  CFG_POP           ( ulong, tiles.bundle.keepalive_interval_millis );
  CFG_POP           ( bool, tiles.bundle.tls_cert_verify );

  CFG_POP           ( uint, tiles.pack.max_pending_transactions );
  CFG_POP           ( bool, tiles.pack.use_consumed_cus );
  CFG_POP_STR       ( tiles.pack.schedule_strategy );
  CFG_POP_STR_ARRAY ( tiles.pack.account_blocklist );

  CFG_POP           ( ulong, tiles.replay.max_transaction_lookahead_buffer_size );
  CFG_POP_STR_ARRAY ( tiles.replay.enable_features );

  CFG_POP           ( bool, tiles.pohh.lagged_consecutive_leader_start );

  CFG_POP           ( uint, tiles.shred.max_pending_shred_sets );
  CFG_POP           ( ushort, tiles.shred.shred_listen_port );
  CFG_POP_STR_ARRAY ( tiles.shred.additional_shred_destinations_retransmit );
  CFG_POP_STR_ARRAY ( tiles.shred.additional_shred_destinations_leader );
  CFG_POP           ( ulong, tiles.shred.shred_cache_size_mib );

  CFG_POP_STR       ( tiles.metric.prometheus_listen_address );
  CFG_POP           ( ushort, tiles.metric.prometheus_listen_port );

  CFG_POP_STR       ( tiles.event.url );

  CFG_POP           ( bool, tiles.gui.enabled );
  CFG_POP_STR       ( tiles.gui.gui_listen_address );
  CFG_POP           ( ushort, tiles.gui.gui_listen_port );
  CFG_POP           ( ulong, tiles.gui.max_http_connections );
  CFG_POP           ( ulong, tiles.gui.max_websocket_connections );
  CFG_POP           ( ulong, tiles.gui.max_http_request_length );
  CFG_POP           ( ulong, tiles.gui.send_buffer_size_mb );
  CFG_POP           ( ulong, tiles.gui.db_size_gib );

  CFG_POP           ( bool, tiles.rpc.enabled );
  CFG_POP_STR       ( tiles.rpc.rpc_listen_address );
  CFG_POP           ( ushort, tiles.rpc.rpc_listen_port );
  CFG_POP           ( ulong, tiles.rpc.max_http_connections );
  CFG_POP           ( ulong, tiles.rpc.max_websocket_connections );
  CFG_POP           ( ulong, tiles.rpc.max_http_request_length );
  CFG_POP           ( ulong, tiles.rpc.send_buffer_size_mb );
  CFG_POP           ( bool, tiles.rpc.delay_startup );

  CFG_POP           ( ushort, tiles.repair.repair_client_listen_port );
  CFG_POP           ( ulong, tiles.repair.slot_max );

  CFG_POP           ( ulong, tiles.rotor.slot_max );

  CFG_POP           ( bool, tiles.rserve.enabled );
  CFG_POP           ( ushort, tiles.rserve.repair_serve_listen_port );
  CFG_POP           ( ulong, tiles.rserve.shred_storage_limit_gib );

  CFG_POP           ( ulong, capture.capture_start_slot );
  CFG_POP_STR       ( capture.solcap_capture );
  CFG_POP           ( bool, capture.recent_only );
  CFG_POP           ( ulong, capture.recent_slots_per_file );
  CFG_POP_STR       ( capture.dump_proto_dir );
  CFG_POP_STR       ( capture.dump_syscall_name_filter );
  CFG_POP_STR       ( capture.dump_instr_program_id_filter );
  CFG_POP           ( bool, capture.dump_syscall_to_pb );
  CFG_POP           ( bool, capture.dump_instr_to_pb );
  CFG_POP           ( bool, capture.dump_txn_to_pb );
  CFG_POP           ( bool, capture.dump_txn_as_fixture );
  CFG_POP           ( bool, capture.dump_block_to_pb );

  CFG_POP           ( ushort, tiles.txsend.txsend_src_port );

  CFG_POP           ( bool, development.sandbox );
  CFG_POP           ( bool, development.no_clone );
  CFG_POP_STR       ( development.core_dump );
  CFG_POP           ( bool, development.no_agave );
  CFG_POP           ( bool, development.bootstrap );

  CFG_POP           ( bool, development.gossip.allow_private_address );

  CFG_POP           ( ulong, development.genesis.hashes_per_tick );
  CFG_POP           ( ulong, development.genesis.target_tick_duration_micros );
  CFG_POP           ( ulong, development.genesis.ticks_per_slot );
  CFG_POP           ( ulong, development.genesis.fund_initial_accounts );
  CFG_POP           ( ulong, development.genesis.fund_initial_amount_lamports );
  CFG_POP           ( ulong, development.genesis.vote_account_stake_lamports );
  CFG_POP           ( bool, development.genesis.warmup_epochs );

  CFG_POP           ( uint, development.bench.benchg_tile_count );
  CFG_POP           ( uint, development.bench.benchs_tile_count );
  CFG_POP_STR       ( development.bench.affinity );
  CFG_POP_STR       ( development.bench.transaction_mode );
  CFG_POP           ( ulong, development.bench.max_cost_per_block );
  CFG_POP           ( ulong, development.bench.max_shreds_per_block );
  CFG_POP           ( ulong, development.bench.disable_blockstore_from_slot );
  CFG_POP           ( bool, development.bench.disable_status_cache );

  CFG_POP_STR       ( development.bundle.ssl_key_log_file );
  CFG_POP           ( uint, development.bundle.buffer_size_kib );

  CFG_POP           ( bool, development.event.report_shreds );
  CFG_POP           ( bool, development.event.report_transactions );
  CFG_POP           ( bool, development.event.report_runtime_diffs );

  CFG_POP_STR       ( development.pktgen.affinity );
  CFG_POP_STR       ( development.pktgen.fake_dst_ip );

  CFG_POP_STR       ( development.udpecho.affinity );

  if( FD_UNLIKELY( !config->is_firedancer ) ) {
    CFG_POP           ( bool, development.gui.websocket_compression );
  }

  CFG_POP           ( ulong, development.accdb.partition_size_gib );

  CFG_POP           ( bool, development.hugetlbfs.min_size );

  if( FD_UNLIKELY( config->is_firedancer ) ) {
    if( FD_UNLIKELY( !fd_config_extract_tomlf( doc, cfg, &config->firedancer ) ) ) return NULL;
    fd_config_check_configf( config, &config->firedancer );
  } else {
    if( FD_UNLIKELY( !fd_config_extract_tomlh( doc, cfg, &config->frankendancer ) ) ) return NULL;
  }

  /* Renamed config options */

# define CFG_RENAMED( old_path, new_path )                             \
  do {                                                                 \
    if( FD_UNLIKELY( fd_toml_get( doc, NULL, #old_path ) ) ) {         \
      FD_LOG_WARNING(( "Config option `%s` was renamed to `%s`. "      \
                       "Please update your config file.",              \
                       #old_path, #new_path ));                        \
      return NULL;                                                     \
    }                                                                  \
    (void)config->new_path; /* assert new path exists */               \
  } while(0)

  CFG_RENAMED( tiles.net.interface,            net.interface                );
  CFG_RENAMED( tiles.net.bind_address,         net.bind_address             );
  CFG_RENAMED( tiles.net.provider,             net.provider                 );
  CFG_RENAMED( tiles.net.xdp_mode,             net.xdp.xdp_mode             );
  CFG_RENAMED( tiles.net.xdp_zero_copy,        net.xdp.xdp_zero_copy        );
  CFG_RENAMED( tiles.net.xdp_rx_queue_size,    net.xdp.xdp_rx_queue_size    );
  CFG_RENAMED( tiles.net.xdp_tx_queue_size,    net.xdp.xdp_tx_queue_size    );
  CFG_RENAMED( tiles.net.flush_timeout_micros, net.xdp.flush_timeout_micros );
  CFG_RENAMED( tiles.net.send_buffer_size,     net.ingress_buffer_size      );

  CFG_RENAMED( development.net.provider,                 net.provider                   );
  CFG_RENAMED( development.net.sock_receive_buffer_size, net.socket.receive_buffer_size );
  CFG_RENAMED( development.net.sock_send_buffer_size,    net.socket.send_buffer_size    );

  CFG_RENAMED( tiles.repair.repair_intake_listen_port,   tiles.repair.repair_client_listen_port );

# undef CFG_RENAMED

# define CFG_DEPRECATED( path )                                        \
  do {                                                                 \
    char const * key = #path;                                          \
    fd_toml_node_t * node = fd_toml_get( doc, NULL, key );             \
    if( FD_UNLIKELY( node ) ) {                                        \
      FD_LOG_WARNING(( "ignoring deprecated config option `%s`", key ));\
      fd_toml_node_consume( node );                                    \
    }                                                                  \
  } while(0)

  CFG_DEPRECATED( development.bundle.ssl_heap_size_mib );

# undef CFG_DEPRECATED

  fd_toml_node_t * left = fd_toml_find_leftover( doc, fd_toml_root( doc ) );
  if( FD_UNLIKELY( left ) ) {
    char path[ 256 ];
    fd_toml_node_path( doc, left, path, sizeof(path) );
    FD_LOG_WARNING(( "Config file contains unrecognized key `%s` (line %u)", path, left->line ));
    return NULL;
  }
  return config;
}

#undef CFG_POP
#undef CFG_ARRAY
