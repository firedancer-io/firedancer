#include "fd_config_private.h"

/* Pod query utils ****************************************************/

static int
fdctl_cfg_get_cstr_( char *                out,
                     ulong                 out_sz,
                     fd_pod_info_t const * info,
                     char const *          path ) {
  if( FD_UNLIKELY( info->val_type != FD_POD_VAL_TYPE_CSTR ) ) {
    FD_LOG_WARNING(( "invalid value for `%s`", path ));
    return 0;
  }
  char const * str = info->val;
  ulong        sz  = strlen( str ) + 1;
  if( FD_UNLIKELY( sz > out_sz ) ) {
    FD_LOG_WARNING(( "`%s`: too long (max %ld)", path, (long)out_sz-1L ));
    return 0;
  }
  fd_memcpy( out, str, sz );
  return 1;
}

#define fdctl_cfg_get_cstr( out, out_sz, info, path ) \
  fdctl_cfg_get_cstr_( *out, out_sz, info, path )

static int
fdctl_cfg_get_ulong( ulong *               out,
                     ulong                 out_sz FD_PARAM_UNUSED,
                     fd_pod_info_t const * info,
                     char const *          path ) {

  ulong num;
  switch( info->val_type ) {
  case FD_POD_VAL_TYPE_LONG:
    fd_ulong_svw_dec( (uchar const *)info->val, &num );
    long snum = fd_long_zz_dec( num );
    if( snum < 0L ) {
      FD_LOG_WARNING(( "`%s` cannot be negative", path ));
      return 0;
    }
    num = (ulong)snum;
    break;
  case FD_POD_VAL_TYPE_ULONG:
    fd_ulong_svw_dec( (uchar const *)info->val, &num );
    break;
  default:
    FD_LOG_WARNING(( "invalid value for `%s`", path ));
    return 0;
  }

  *out = num;
  return 1;
}

static int
fdctl_cfg_get_uint( uint *                out,
                    ulong                 out_sz FD_PARAM_UNUSED,
                    fd_pod_info_t const * info,
                    char const *          path ) {
  ulong num;
  if( FD_UNLIKELY( !fdctl_cfg_get_ulong( &num, sizeof(num), info, path ) ) ) return 0;
  if( num > UINT_MAX ) {
    FD_LOG_WARNING(( "`%s` is out of bounds (%lx)", path, num ));
    return 0;
  }
  *out = (uint)num;
  return 1;
}

static int
fdctl_cfg_get_ushort( ushort *              out,
                      ulong                 out_sz FD_PARAM_UNUSED,
                      fd_pod_info_t const * info,
                      char const *          path ) {
  ulong num;
  if( FD_UNLIKELY( !fdctl_cfg_get_ulong( &num, sizeof(num), info, path ) ) ) return 0;
  if( num > USHORT_MAX ) {
    FD_LOG_WARNING(( "`%s` is out of bounds (%lx)", path, num ));
    return 0;
  }
  *out = (ushort)num;
  return 1;
}

static int
fdctl_cfg_get_bool( int *                 out,
                    ulong                 out_sz FD_PARAM_UNUSED,
                    fd_pod_info_t const * info,
                    char const *          path ) {
  if( FD_UNLIKELY( info->val_type != FD_POD_VAL_TYPE_INT ) ) {
    FD_LOG_WARNING(( "invalid value for `%s`", path ));
    return 0;
  }
  ulong u; fd_ulong_svw_dec( (uchar const *)info->val, &u );
  *out = fd_int_zz_dec( (uint)u );
  return 1;
}

/* Find leftover ******************************************************/

/* fdctl_pod_find_leftover recursively searches for non-subpod keys in
   pod.  Prints to the warning log if it finds any.  Used to detect
   config keys that were not recognized by fdctl.  Returns 0 if no
   leftover key was found.  Otherwise, returns a non-zero number of
   segments of the leftover key.  The key can be reassembled by joining
   stack[0] .. stack[depth-1].

   Not thread safe (uses global buffer). */

# define FDCTL_CFG_MAX_DEPTH (16)

static ulong
fdctl_pod_find_leftover_recurse( uchar *       pod,
                                 char const ** stack,
                                 ulong         depth ) {

  if( FD_UNLIKELY( depth+1 >= FDCTL_CFG_MAX_DEPTH ) ) {
    FD_LOG_WARNING(( "configuration file has too many nested keys" ));
    return depth;
  }

  for( fd_pod_iter_t iter = fd_pod_iter_init( pod ); !fd_pod_iter_done( iter ); iter = fd_pod_iter_next( iter ) ) {
    fd_pod_info_t info = fd_pod_iter_info( iter );
    stack[ depth ] = info.key;
    depth++;
    if( FD_LIKELY( info.val_type == FD_POD_VAL_TYPE_SUBPOD ) ) {
      ulong sub_depth = fdctl_pod_find_leftover_recurse( (uchar *)info.val, stack, depth );
      if( FD_UNLIKELY( sub_depth ) ) return sub_depth;
    } else {
      return depth;
    }
    depth--;
  }

  return 0;
}

static int
fdctl_pod_find_leftover( uchar * pod ) {

  static char const * stack[ FDCTL_CFG_MAX_DEPTH ];
  ulong depth = fdctl_pod_find_leftover_recurse( pod, stack, 0UL );
  if( FD_LIKELY( !depth ) ) return 1;

  static char path[ 64*FDCTL_CFG_MAX_DEPTH + 4 ];
  char * c   = fd_cstr_init( path );
  char * end = path + 64*FDCTL_CFG_MAX_DEPTH - 1;
  for( ulong j=0UL; j<depth; j++ ) {
    char const * key     = stack[j];
    ulong        key_len = strlen( key );
    if( c+key_len+1 >= end ) {
      c = fd_cstr_append_text( c, "...", 3UL );
      break;
    }
    c = fd_cstr_append_text( c, key, key_len );
    c = fd_cstr_append_char( c, '.' );
  }
  c -= 1;
  fd_cstr_fini( c );

  FD_LOG_WARNING(( "Config file contains unrecognized key `%s`", path ));
  return 0;
}

/* Converter **********************************************************/

#define CFG_POP( type, cfg_path )                                      \
  do {                                                                 \
    char const * key = #cfg_path;                                      \
    fd_pod_info_t info[1];                                             \
    if( fd_pod_query( pod, key, info ) ) break;                        \
    if( FD_UNLIKELY( !fdctl_cfg_get_##type( &config->cfg_path, sizeof(config->cfg_path), \
        info, key ) ) )                                                \
      return NULL;                                                     \
    fd_pod_remove( pod, key );                                         \
  } while(0)

#define CFG_POP1( type, toml_path, cfg_path )                          \
  do {                                                                 \
    char const * key = #toml_path;                                      \
    fd_pod_info_t info[1];                                             \
    if( fd_pod_query( pod, key, info ) ) break;                        \
    if( FD_UNLIKELY( !fdctl_cfg_get_##type( &config->cfg_path, sizeof(config->cfg_path), \
        info, key ) ) )                                                \
      return NULL;                                                     \
    fd_pod_remove( pod, key );                                         \
  } while(0)

#define CFG_POP_ARRAY( type, cfg_path )                                \
  do {                                                                 \
    char const * key = #cfg_path;                                      \
    fd_pod_info_t info[1];                                             \
    if( fd_pod_query( pod, key, info ) ) break;                        \
    if( FD_UNLIKELY( info->val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) {      \
      FD_LOG_WARNING(( "`%s`: expected array", key ));                 \
      return NULL;                                                     \
    }                                                                  \
    ulong  arr_len = sizeof( config->cfg_path ) / sizeof( config->cfg_path[ 0 ] ); \
    ulong  j       = 0UL;                                              \
    for( fd_pod_iter_t iter = fd_pod_iter_init( info->val ); !fd_pod_iter_done( iter ); iter = fd_pod_iter_next( iter ) ) { \
      if( FD_UNLIKELY( j>=arr_len ) ) {                                \
        FD_LOG_WARNING(( "`%s`: too many values (max %lu)", key, arr_len )); \
        return NULL;                                                   \
      }                                                                \
      fd_pod_info_t sub_info = fd_pod_iter_info( iter );               \
      fdctl_cfg_get_##type( &config->cfg_path[j], sizeof(config->cfg_path[j]), &sub_info, key ); \
      j++;                                                             \
    }                                                                  \
    config->cfg_path ## _cnt = j;                                      \
    fd_pod_remove( pod, key );                                         \
  } while(0)

#define CFG_POP1_ARRAY( type, toml_path, cfg_path )                    \
  do {                                                                 \
    char const * key = #toml_path;                                     \
    fd_pod_info_t info[1];                                             \
    if( fd_pod_query( pod, key, info ) ) break;                        \
    if( FD_UNLIKELY( info->val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) {      \
      FD_LOG_WARNING(( "`%s`: expected array", key ));                 \
      return NULL;                                                     \
    }                                                                  \
    ulong  arr_len = sizeof( config->cfg_path ) / sizeof( config->cfg_path[ 0 ] ); \
    ulong  j       = 0UL;                                              \
    for( fd_pod_iter_t iter = fd_pod_iter_init( info->val ); !fd_pod_iter_done( iter ); iter = fd_pod_iter_next( iter ) ) { \
      if( FD_UNLIKELY( j>=arr_len ) ) {                                \
        FD_LOG_WARNING(( "`%s`: too many values (max %lu)", key, arr_len )); \
        return NULL;                                                   \
      }                                                                \
      fd_pod_info_t sub_info = fd_pod_iter_info( iter );               \
      fdctl_cfg_get_##type( &config->cfg_path[j], sizeof(config->cfg_path[j]), &sub_info, key ); \
      j++;                                                             \
    }                                                                  \
    config->cfg_path ## _cnt = j;                                      \
    fd_pod_remove( pod, key );                                         \
  } while(0)

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
  CFG_POP      ( ulong,  blockstore.txn_max                               );
  CFG_POP      ( ulong,  blockstore.alloc_max                             );
  CFG_POP      ( cstr,   blockstore.file                                  );
  CFG_POP      ( cstr,   blockstore.checkpt                               );
  CFG_POP      ( cstr,   blockstore.restore                               );

  CFG_POP      ( bool,   consensus.vote                                   );

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

  CFG_POP      ( cstr,   tiles.net.interface                              );
  CFG_POP      ( cstr,   tiles.net.bind_address                           );
  CFG_POP      ( cstr,   tiles.net.xdp_mode                               );
  CFG_POP      ( bool,   tiles.net.xdp_zero_copy                          );
  CFG_POP      ( uint,   tiles.net.xdp_rx_queue_size                      );
  CFG_POP      ( uint,   tiles.net.xdp_tx_queue_size                      );
  CFG_POP      ( uint,   tiles.net.flush_timeout_micros                   );
  CFG_POP      ( uint,   tiles.net.send_buffer_size                       );

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

  CFG_POP      ( uint,   tiles.pack.max_pending_transactions              );
  CFG_POP      ( bool,   tiles.pack.use_consumed_cus                      );

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

  CFG_POP      ( cstr,   tiles.replay.capture                             );
  CFG_POP      ( cstr,   tiles.replay.funk_checkpt                        );
  CFG_POP      ( uint,   tiles.replay.funk_rec_max                        );
  CFG_POP      ( ulong,  tiles.replay.funk_sz_gb                          );
  CFG_POP      ( ulong,  tiles.replay.funk_txn_max                        );
  CFG_POP      ( cstr,   tiles.replay.funk_file                           );
  CFG_POP      ( cstr,   tiles.replay.genesis                             );
  CFG_POP      ( cstr,   tiles.replay.incremental                         );
  CFG_POP      ( cstr,   tiles.replay.incremental_url                     );
  CFG_POP      ( cstr,   tiles.replay.slots_replayed                      );
  CFG_POP      ( cstr,   tiles.replay.snapshot                            );
  CFG_POP      ( cstr,   tiles.replay.snapshot_url                        );
  CFG_POP      ( cstr,   tiles.replay.status_cache                        );
  CFG_POP      ( cstr,   tiles.replay.cluster_version                     );
  CFG_POP      ( cstr,   tiles.replay.tower_checkpt                       );

  CFG_POP      ( cstr,   tiles.store_int.slots_pending                    );
  CFG_POP      ( cstr,   tiles.store_int.shred_cap_archive                );
  CFG_POP      ( cstr,   tiles.store_int.shred_cap_replay                 );
  CFG_POP      ( ulong,  tiles.store_int.shred_cap_end_slot               );

  CFG_POP      ( ulong,  tiles.batch.full_interval                        );
  CFG_POP      ( ulong,  tiles.batch.incremental_interval                 );
  CFG_POP      ( cstr,   tiles.batch.out_dir                              );

  CFG_POP      ( bool,   tiles.restart.in_wen_restart                     );
  CFG_POP      ( cstr,   tiles.restart.wen_restart_coordinator            );
  CFG_POP      ( cstr,   tiles.restart.genesis_hash                       );

  CFG_POP      ( bool,   tiles.archiver.enabled                           );
  CFG_POP      ( cstr,   tiles.archiver.archiver_path                     );

  CFG_POP      ( bool,   development.sandbox                              );
  CFG_POP      ( bool,   development.no_clone                             );
  CFG_POP      ( bool,   development.core_dump                            );
  CFG_POP      ( bool,   development.no_agave                             );
  CFG_POP      ( bool,   development.bootstrap                            );

  CFG_POP      ( cstr,   development.net.provider                         );
  CFG_POP      ( uint,   development.net.sock_receive_buffer_size         );
  CFG_POP      ( uint,   development.net.sock_send_buffer_size            );

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

  CFG_POP      ( cstr,   development.pktgen.affinity                      );
  CFG_POP      ( cstr,   development.pktgen.fake_dst_ip                   );

  if( FD_UNLIKELY( config->is_firedancer ) ) {
    if( FD_UNLIKELY( !fd_config_extract_podf( pod, &config->firedancer ) ) ) return NULL;
  } else {
    if( FD_UNLIKELY( !fd_config_extract_podh( pod, &config->frankendancer ) ) ) return NULL;
  }

  if( FD_UNLIKELY( !fdctl_pod_find_leftover( pod ) ) ) return NULL;
  return config;
}

#undef CFG_POP
#undef CFG_ARRAY
