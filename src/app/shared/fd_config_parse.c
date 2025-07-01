#include "../platform/fd_config_extract.h"
#include "../platform/fd_config_macros.c"
#include "fd_config_private.h"

static void
fd_config_check_configf( fd_config_t *  config,
                         fd_configf_t * config_f ) {
  (void)config_f;
  if( FD_UNLIKELY( strlen( config->tiles.replay.snapshot_dir )>PATH_MAX-1UL ) ) {
    FD_LOG_ERR(( "[tiles.replay.snapshot_dir] is too long (max %lu)", PATH_MAX-1UL ));
  }
  if( FD_UNLIKELY( config->tiles.replay.snapshot_dir[ 0 ]!='\0' && config->tiles.replay.snapshot_dir[ 0 ]!='/' ) ) {
    FD_LOG_ERR(( "[tiles.replay.snapshot_dir] must be an absolute path and hence start with a '/'"));
  }
}

fd_configh_t *
fd_config_extract_podh( uchar *        pod,
                        fd_configh_t * config ) {
  CFG_POP      ( cstr,   dynamic_port_range                               );

  CFG_POP      ( cstr,   reporting.solana_metrics_config                  );

  CFG_POP      ( cstr,   layout.agave_affinity                            );
  CFG_POP      ( uint,   layout.agave_unified_scheduler_handler_threads   );

  CFG_POP1      ( cstr,  ledger.accounts_path,             paths.accounts_path          );
  CFG_POP1_ARRAY( cstr,  consensus.authorized_voter_paths, paths.authorized_voter_paths );

  CFG_POP      ( uint,   ledger.limit_size                                );
  CFG_POP_ARRAY( cstr,   ledger.account_indexes                           );
  CFG_POP_ARRAY( cstr,   ledger.account_index_include_keys                );
  CFG_POP_ARRAY( cstr,   ledger.account_index_exclude_keys                );
  CFG_POP      ( cstr,   ledger.accounts_index_path                       );
  CFG_POP      ( cstr,   ledger.accounts_hash_cache_path                  );
  CFG_POP      ( bool,   ledger.enable_accounts_disk_index                );
  CFG_POP      ( bool,   ledger.require_tower                             );
  CFG_POP      ( cstr,   ledger.snapshot_archive_format                   );

  CFG_POP      ( bool,   gossip.port_check                                );
  CFG_POP      ( cstr,   gossip.host                                      );

  CFG_POP      ( bool,   consensus.snapshot_fetch                         );
  CFG_POP      ( bool,   consensus.genesis_fetch                          );
  CFG_POP      ( bool,   consensus.poh_speed_test                         );
  CFG_POP      ( cstr,   consensus.expected_genesis_hash                  );
  CFG_POP      ( uint,   consensus.wait_for_supermajority_at_slot         );
  CFG_POP      ( cstr,   consensus.expected_bank_hash                     );
  CFG_POP      ( bool,   consensus.wait_for_vote_to_start_leader          );
  CFG_POP_ARRAY( uint,   consensus.hard_fork_at_slots                     );
  CFG_POP_ARRAY( cstr,   consensus.known_validators                       );
  CFG_POP      ( bool,   consensus.os_network_limits_test                 );

  CFG_POP      ( bool,   rpc.full_api                                     );
  CFG_POP      ( bool,   rpc.private                                      );
  CFG_POP      ( cstr,   rpc.bind_address                                 );
  CFG_POP      ( bool,   rpc.transaction_history                          );
  CFG_POP      ( bool,   rpc.only_known                                   );
  CFG_POP      ( bool,   rpc.pubsub_enable_block_subscription             );
  CFG_POP      ( bool,   rpc.pubsub_enable_vote_subscription              );
  CFG_POP      ( bool,   rpc.bigtable_ledger_storage                      );

  CFG_POP      ( bool,   snapshots.enabled                                );
  CFG_POP      ( bool,   snapshots.incremental_snapshots                  );
  CFG_POP      ( uint,   snapshots.full_snapshot_interval_slots           );
  CFG_POP      ( uint,   snapshots.incremental_snapshot_interval_slots    );
  CFG_POP      ( uint,   snapshots.minimum_snapshot_download_speed        );
  CFG_POP      ( uint,   snapshots.maximum_snapshot_download_abort        );
  CFG_POP      ( uint,   snapshots.maximum_full_snapshots_to_retain       );
  CFG_POP      ( uint,   snapshots.maximum_incremental_snapshots_to_retain);
  CFG_POP      ( cstr,   snapshots.path                                   );
  CFG_POP      ( cstr,   snapshots.incremental_path                       );

  return config;
}

fd_configf_t *
fd_config_extract_podf( uchar *        pod,
                        fd_configf_t * config ) {
  CFG_POP      ( uint,   layout.exec_tile_count                           );
  CFG_POP      ( uint,   layout.writer_tile_count                         );

  CFG_POP      ( ulong,  blockstore.shred_max                             );
  CFG_POP      ( ulong,  blockstore.block_max                             );
  CFG_POP      ( ulong,  blockstore.idx_max                               );
  CFG_POP      ( ulong,  blockstore.alloc_max                             );
  CFG_POP      ( cstr,   blockstore.file                                  );
  CFG_POP      ( cstr,   blockstore.checkpt                               );
  CFG_POP      ( cstr,   blockstore.restore                               );

  CFG_POP      ( ulong,  runtime.heap_size_gib                            );

  CFG_POP      ( ulong,  runtime.limits.max_rooted_slots                  );
  CFG_POP      ( ulong,  runtime.limits.max_live_slots                    );
  CFG_POP      ( ulong,  runtime.limits.max_transactions_per_slot         );
  CFG_POP      ( ulong,  runtime.limits.snapshot_grace_period_seconds     );
  CFG_POP      ( ulong,  runtime.limits.max_vote_accounts                 );
  CFG_POP      ( ulong,  runtime.limits.max_banks                         );

  CFG_POP      ( ulong,  funk.max_account_records                         );
  CFG_POP      ( ulong,  funk.heap_size_gib                               );
  CFG_POP      ( ulong,  funk.max_database_transactions                   );

  return config;
}

fd_config_t *
fd_config_extract_pod( uchar *       pod,
                       fd_config_t * config ) {
  CFG_POP      ( cstr,   name                                             );
  CFG_POP      ( cstr,   user                                             );

  CFG_POP      ( cstr,   log.path                                         );
  CFG_POP      ( cstr,   log.colorize                                     );
  CFG_POP      ( cstr,   log.level_logfile                                );
  CFG_POP      ( cstr,   log.level_stderr                                 );
  CFG_POP      ( cstr,   log.level_flush                                  );

  if( FD_UNLIKELY( config->is_firedancer ) ) {
    CFG_POP      ( cstr,   paths.base                                       );
    CFG_POP      ( cstr,   paths.ledger                                     );
    CFG_POP      ( cstr,   paths.identity_key                               );
    CFG_POP      ( cstr,   paths.vote_account                               );
  } else {
    CFG_POP1     ( cstr,   scratch_directory,           paths.base          );
    CFG_POP1     ( cstr,   ledger.path,                 paths.ledger        );
    CFG_POP1     ( cstr,   consensus.identity_path,     paths.identity_key  );
    CFG_POP1     ( cstr,   consensus.vote_account_path, paths.vote_account  );
  }

  CFG_POP_ARRAY( cstr,   gossip.entrypoints                               );
  CFG_POP      ( ushort, gossip.port                                      );

  CFG_POP      ( ushort, consensus.expected_shred_version                 );

  CFG_POP      ( ushort, rpc.port                                         );
  CFG_POP      ( bool,   rpc.extended_tx_metadata_storage                 );
  if( FD_UNLIKELY( config->is_firedancer ) ) {
    CFG_POP      ( uint,   rpc.block_index_max                            );
    CFG_POP      ( uint,   rpc.txn_index_max                              );
    CFG_POP      ( uint,   rpc.acct_index_max                             );
    CFG_POP      ( cstr,   rpc.history_file                               );
  }

  CFG_POP      ( cstr,   layout.affinity                                  );
  CFG_POP      ( uint,   layout.net_tile_count                            );
  CFG_POP      ( uint,   layout.quic_tile_count                           );
  CFG_POP      ( uint,   layout.resolv_tile_count                         );
  CFG_POP      ( uint,   layout.verify_tile_count                         );
  CFG_POP      ( uint,   layout.bank_tile_count                           );
  CFG_POP      ( uint,   layout.shred_tile_count                          );

  CFG_POP      ( cstr,   hugetlbfs.mount_path                             );
  CFG_POP      ( cstr,   hugetlbfs.max_page_size                          );
  CFG_POP      ( ulong,  hugetlbfs.gigantic_page_threshold_mib            );

  CFG_POP      ( cstr,   net.interface                                    );
  CFG_POP      ( cstr,   net.bind_address                                 );
  CFG_POP      ( cstr,   net.provider                                     );
  CFG_POP      ( uint,   net.ingress_buffer_size                          );
  CFG_POP      ( cstr,   net.xdp.xdp_mode                                 );
  CFG_POP      ( bool,   net.xdp.xdp_zero_copy                            );
  CFG_POP      ( uint,   net.xdp.xdp_rx_queue_size                        );
  CFG_POP      ( uint,   net.xdp.xdp_tx_queue_size                        );
  CFG_POP      ( uint,   net.xdp.flush_timeout_micros                     );
  CFG_POP      ( uint,   net.socket.receive_buffer_size                   );
  CFG_POP      ( uint,   net.socket.send_buffer_size                      );

  CFG_POP      ( ulong,  tiles.netlink.max_routes                         );
  CFG_POP      ( ulong,  tiles.netlink.max_neighbors                      );

  CFG_POP      ( ushort, tiles.quic.regular_transaction_listen_port       );
  CFG_POP      ( ushort, tiles.quic.quic_transaction_listen_port          );
  CFG_POP      ( uint,   tiles.quic.txn_reassembly_count                  );
  CFG_POP      ( uint,   tiles.quic.max_concurrent_connections            );
  CFG_POP      ( uint,   tiles.quic.max_concurrent_handshakes             );
  CFG_POP      ( uint,   tiles.quic.idle_timeout_millis                   );
  CFG_POP      ( uint,   tiles.quic.ack_delay_millis                      );
  CFG_POP      ( bool,   tiles.quic.retry                                 );

  CFG_POP      ( uint,   tiles.verify.signature_cache_size                );
  CFG_POP      ( uint,   tiles.verify.receive_buffer_size                 );
  CFG_POP      ( uint,   tiles.verify.mtu                                 );

  CFG_POP      ( uint,   tiles.dedup.signature_cache_size                 );

  CFG_POP      ( bool,   tiles.bundle.enabled                             );
  CFG_POP      ( cstr,   tiles.bundle.url                                 );
  CFG_POP      ( cstr,   tiles.bundle.tls_domain_name                     );
  CFG_POP      ( cstr,   tiles.bundle.tip_distribution_program_addr       );
  CFG_POP      ( cstr,   tiles.bundle.tip_payment_program_addr            );
  CFG_POP      ( cstr,   tiles.bundle.tip_distribution_authority          );
  CFG_POP      ( uint,   tiles.bundle.commission_bps                      );
  CFG_POP      ( ulong,  tiles.bundle.keepalive_interval_millis           );
  CFG_POP      ( bool,   tiles.bundle.tls_cert_verify                     );

  CFG_POP      ( uint,   tiles.pack.max_pending_transactions              );
  CFG_POP      ( bool,   tiles.pack.use_consumed_cus                      );
  CFG_POP      ( cstr,   tiles.pack.schedule_strategy                     );

  CFG_POP      ( bool,   tiles.poh.lagged_consecutive_leader_start        );

  CFG_POP      ( uint,   tiles.shred.max_pending_shred_sets               );
  CFG_POP      ( ushort, tiles.shred.shred_listen_port                    );
  CFG_POP      ( cstr,   tiles.shred.additional_shred_destination         );

  CFG_POP      ( cstr,   tiles.metric.prometheus_listen_address           );
  CFG_POP      ( ushort, tiles.metric.prometheus_listen_port              );

  CFG_POP      ( bool,   tiles.gui.enabled                                );
  CFG_POP      ( cstr,   tiles.gui.gui_listen_address                     );
  CFG_POP      ( ushort, tiles.gui.gui_listen_port                        );
  CFG_POP      ( ulong,  tiles.gui.max_http_connections                   );
  CFG_POP      ( ulong,  tiles.gui.max_websocket_connections              );
  CFG_POP      ( ulong,  tiles.gui.max_http_request_length                );
  CFG_POP      ( ulong,  tiles.gui.send_buffer_size_mb                    );

  CFG_POP      ( ushort, tiles.repair.repair_intake_listen_port           );
  CFG_POP      ( ushort, tiles.repair.repair_serve_listen_port            );
  CFG_POP      ( cstr,   tiles.repair.good_peer_cache_file                );
  CFG_POP      ( ulong,  tiles.repair.slot_max                           );

  CFG_POP      ( ulong,  capture.capture_start_slot                       );
  CFG_POP      ( cstr,   capture.solcap_capture                           );
  CFG_POP      ( cstr,   capture.dump_proto_dir                           );
  CFG_POP      ( bool,   capture.dump_syscall_to_pb                       );
  CFG_POP      ( bool,   capture.dump_instr_to_pb                          );
  CFG_POP      ( bool,   capture.dump_txn_to_pb                           );
  CFG_POP      ( bool,   capture.dump_block_to_pb                         );

  CFG_POP      ( cstr,   tiles.replay.funk_checkpt                        );
  CFG_POP      ( cstr,   tiles.replay.genesis                             );
  CFG_POP      ( cstr,   tiles.replay.incremental                         );
  CFG_POP      ( cstr,   tiles.replay.incremental_url                     );
  CFG_POP      ( cstr,   tiles.replay.slots_replayed                      );
  CFG_POP      ( cstr,   tiles.replay.snapshot                            );
  CFG_POP      ( cstr,   tiles.replay.snapshot_url                        );
  CFG_POP      ( cstr,   tiles.replay.snapshot_dir                        );
  CFG_POP      ( cstr,   tiles.replay.status_cache                        );
  CFG_POP      ( cstr,   tiles.replay.cluster_version                     );
  CFG_POP      ( cstr,   tiles.replay.tower_checkpt                       );
  CFG_POP_ARRAY( cstr,   tiles.replay.enable_features                     );

  CFG_POP      ( cstr,   tiles.store_int.slots_pending                    );
  CFG_POP      ( cstr,   tiles.store_int.shred_cap_archive                );
  CFG_POP      ( cstr,   tiles.store_int.shred_cap_replay                 );
  CFG_POP      ( ulong,  tiles.store_int.shred_cap_end_slot               );

  CFG_POP      ( ushort, tiles.send.send_src_port                         );

  CFG_POP      ( bool,   tiles.archiver.enabled                           );
  CFG_POP      ( ulong,  tiles.archiver.end_slot                          );
  CFG_POP      ( cstr,   tiles.archiver.archiver_path                     );

  if( FD_UNLIKELY( config->is_firedancer ) ) {
    CFG_POP      ( bool,    tiles.shredcap.enabled                           );
    CFG_POP      ( cstr,    tiles.shredcap.folder_path                       );
    CFG_POP      ( ulong,   tiles.shredcap.write_buffer_size                  );
  }

  CFG_POP      ( bool,   development.sandbox                              );
  CFG_POP      ( bool,   development.no_clone                             );
  CFG_POP      ( bool,   development.core_dump                            );
  CFG_POP      ( bool,   development.no_agave                             );
  CFG_POP      ( bool,   development.bootstrap                            );

  CFG_POP      ( bool,   development.netns.enabled                        );
  CFG_POP      ( cstr,   development.netns.interface0                     );
  CFG_POP      ( cstr,   development.netns.interface0_mac                 );
  CFG_POP      ( cstr,   development.netns.interface0_addr                );
  CFG_POP      ( cstr,   development.netns.interface1                     );
  CFG_POP      ( cstr,   development.netns.interface1_mac                 );
  CFG_POP      ( cstr,   development.netns.interface1_addr                );

  CFG_POP      ( bool,   development.gossip.allow_private_address         );

  CFG_POP      ( ulong,  development.genesis.hashes_per_tick              );
  CFG_POP      ( ulong,  development.genesis.target_tick_duration_micros  );
  CFG_POP      ( ulong,  development.genesis.ticks_per_slot               );
  CFG_POP      ( ulong,  development.genesis.fund_initial_accounts        );
  CFG_POP      ( ulong,  development.genesis.fund_initial_amount_lamports );
  CFG_POP      ( ulong,  development.genesis.vote_account_stake_lamports  );
  CFG_POP      ( bool,   development.genesis.warmup_epochs                );

  CFG_POP      ( uint,   development.bench.benchg_tile_count              );
  CFG_POP      ( uint,   development.bench.benchs_tile_count              );
  CFG_POP      ( cstr,   development.bench.affinity                       );
  CFG_POP      ( bool,   development.bench.larger_max_cost_per_block      );
  CFG_POP      ( bool,   development.bench.larger_shred_limits_per_block  );
  CFG_POP      ( ulong,  development.bench.disable_blockstore_from_slot   );
  CFG_POP      ( bool,   development.bench.disable_status_cache           );

  CFG_POP      ( cstr,   development.bundle.ssl_key_log_file              );
  CFG_POP      ( uint,   development.bundle.buffer_size_kib               );
  CFG_POP      ( uint,   development.bundle.ssl_heap_size_mib             );

  CFG_POP      ( cstr,   development.pktgen.affinity                      );
  CFG_POP      ( cstr,   development.pktgen.fake_dst_ip                   );

  if( FD_UNLIKELY( config->is_firedancer ) ) {
    if( FD_UNLIKELY( !fd_config_extract_podf( pod, &config->firedancer ) ) ) return NULL;
    fd_config_check_configf( config, &config->firedancer );
  } else {
    if( FD_UNLIKELY( !fd_config_extract_podh( pod, &config->frankendancer ) ) ) return NULL;
  }

  /* Renamed config options */

# define CFG_RENAMED( old_path, new_path )                             \
  do {                                                                 \
    char const * key = #old_path;                                      \
    fd_pod_info_t info[1];                                             \
    if( FD_UNLIKELY( !fd_pod_query( pod, key, info ) ) ) {             \
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

# undef CFG_RENAMED

  if( FD_UNLIKELY( !fdctl_pod_find_leftover( pod ) ) ) return NULL;
  return config;
}

#undef CFG_POP
#undef CFG_ARRAY
