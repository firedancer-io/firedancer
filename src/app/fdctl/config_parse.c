#include "config_parse.h"

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
  *out = (int)u;
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
  if( FD_LIKELY( !depth ) ) return 0;

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

  FD_LOG_WARNING(( "Unrecognized key `%s`", path ));
  return 1;
}

/* Converter **********************************************************/

config_t *
fdctl_pod_to_cfg( config_t * config,
                  uchar *    pod ) {

# define CFG_POP( type, edot, esection, ekey )                         \
  do {                                                                 \
    char const * key = #esection #edot #ekey;                          \
    fd_pod_info_t info[1];                                             \
    if( fd_pod_query( pod, key, info ) ) break;                        \
    if( FD_UNLIKELY( !fdctl_cfg_get_##type(                            \
        &config->esection edot ekey,sizeof(config->esection edot ekey),\
        info, key ) ) )                                                \
      return NULL;                                                     \
    fd_pod_remove( pod, key );                                         \
  } while(0)

# define CFG_POP_ARRAY( type, edot, esection, ekey )                   \
  do {                                                                 \
    char const * key = #esection #edot #ekey;                          \
    fd_pod_info_t info[1];                                             \
    if( fd_pod_query( pod, key, info ) ) break;                        \
    if( FD_UNLIKELY( info->val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) {      \
      FD_LOG_WARNING(( "`%s`: expected array", key ));                 \
      return NULL;                                                     \
    }                                                                  \
    ulong  arr_len = sizeof( config->esection edot ekey ) / sizeof( config->esection edot ekey[ 0 ] ); \
    ulong  j       = 0UL;                                              \
    for( fd_pod_iter_t iter = fd_pod_iter_init( info->val ); !fd_pod_iter_done( iter ); iter = fd_pod_iter_next( iter ) ) { \
      if( FD_UNLIKELY( j>=arr_len ) ) {                                \
        FD_LOG_WARNING(( "`%s`: too many values (max %lu)", key, arr_len )); \
        return NULL;                                                   \
      }                                                                \
      fdctl_cfg_get_##type( &config->esection edot ekey[j], sizeof(config->esection edot ekey[j]), info, key ); \
      j++;                                                             \
    }                                                                  \
    config->esection edot ekey ## _cnt = j;                            \
    fd_pod_remove( pod, key );                                         \
  } while(0)

  CFG_POP      ( cstr,    , ,                    name                                                      );
  CFG_POP      ( cstr,    , ,                    user                                                      );
  CFG_POP      ( cstr,    , ,                    scratch_directory                                         );
  CFG_POP      ( cstr,    , ,                    dynamic_port_range                                        );

  CFG_POP      ( cstr,   ., log,                 path                                                      );
  CFG_POP      ( cstr,   ., log,                 colorize                                                  );
  CFG_POP      ( cstr,   ., log,                 level_logfile                                             );
  CFG_POP      ( cstr,   ., log,                 level_stderr                                              );
  CFG_POP      ( cstr,   ., log,                 level_flush                                               );

  CFG_POP      ( cstr,   ., ledger,              path                                                      );
  CFG_POP      ( cstr,   ., ledger,              accounts_path                                             );
  CFG_POP      ( uint,   ., ledger,              limit_size                                                );
  CFG_POP_ARRAY( cstr,   ., ledger,              account_indexes                                           );
  CFG_POP_ARRAY( cstr,   ., ledger,              account_index_exclude_keys                                );
  CFG_POP      ( bool,   ., ledger,              require_tower                                             );
  CFG_POP      ( cstr,   ., ledger,              snapshot_archive_format                                   );

  CFG_POP_ARRAY( cstr,   ., gossip,              entrypoints                                               );
  CFG_POP      ( bool,   ., gossip,              port_check                                                );
  CFG_POP      ( ushort, ., gossip,              port                                                      );
  CFG_POP      ( cstr,   ., gossip,              host                                                      );

  CFG_POP      ( cstr,   ., consensus,           identity_path                                             );
  CFG_POP      ( cstr,   ., consensus,           vote_account_path                                         );
  CFG_POP      ( bool,   ., consensus,           snapshot_fetch                                            );
  CFG_POP      ( bool,   ., consensus,           genesis_fetch                                             );
  CFG_POP      ( bool,   ., consensus,           poh_speed_test                                            );
  CFG_POP      ( cstr,   ., consensus,           expected_genesis_hash                                     );
  CFG_POP      ( uint,   ., consensus,           wait_for_supermajority_at_slot                            );
  CFG_POP      ( cstr,   ., consensus,           expected_bank_hash                                        );
  CFG_POP      ( ushort, ., consensus,           expected_shred_version                                    );
  CFG_POP      ( bool,   ., consensus,           wait_for_vote_to_start_leader                             );
  CFG_POP_ARRAY( uint,   ., consensus,           hard_fork_at_slots                                        );
  CFG_POP_ARRAY( cstr,   ., consensus,           known_validators                                          );
  CFG_POP      ( bool,   ., consensus,           os_network_limits_test                                    );

  CFG_POP      ( ushort, ., rpc,                 port                                                      );
  CFG_POP      ( bool,   ., rpc,                 full_api                                                  );
  CFG_POP      ( bool,   ., rpc,                 private                                                   );
  CFG_POP      ( bool,   ., rpc,                 transaction_history                                       );
  CFG_POP      ( bool,   ., rpc,                 extended_tx_metadata_storage                              );
  CFG_POP      ( bool,   ., rpc,                 only_known                                                );
  CFG_POP      ( bool,   ., rpc,                 pubsub_enable_block_subscription                          );
  CFG_POP      ( bool,   ., rpc,                 pubsub_enable_vote_subscription                           );
  CFG_POP      ( bool,   ., rpc,                 bigtable_ledger_storage                                   );

  CFG_POP      ( bool,   ., snapshots,           incremental_snapshots                                     );
  CFG_POP      ( uint,   ., snapshots,           full_snapshot_interval_slots                              );
  CFG_POP      ( uint,   ., snapshots,           incremental_snapshot_interval_slots                       );
  CFG_POP      ( cstr,   ., snapshots,           path                                                      );

  CFG_POP      ( cstr,   ., layout,              affinity                                                  );
  CFG_POP      ( cstr,   ., layout,              solana_labs_affinity                                      );
  CFG_POP      ( uint,   ., layout,              net_tile_count                                            );
  CFG_POP      ( uint,   ., layout,              quic_tile_count                                           );
  CFG_POP      ( uint,   ., layout,              verify_tile_count                                         );
  CFG_POP      ( uint,   ., layout,              bank_tile_count                                           );
  CFG_POP      ( uint,   ., layout,              shred_tile_count                                          );

  CFG_POP      ( cstr,   ., hugetlbfs,           mount_path                                                );

  CFG_POP      ( cstr,   ., tiles.net,           interface                                                 );
  CFG_POP      ( cstr,   ., tiles.net,           xdp_mode                                                  );
  CFG_POP      ( uint,   ., tiles.net,           xdp_rx_queue_size                                         );
  CFG_POP      ( uint,   ., tiles.net,           xdp_tx_queue_size                                         );
  CFG_POP      ( uint,   ., tiles.net,           xdp_aio_depth                                             );
  CFG_POP      ( uint,   ., tiles.net,           send_buffer_size                                          );

  CFG_POP      ( ushort, ., tiles.quic,          regular_transaction_listen_port                           );
  CFG_POP      ( ushort, ., tiles.quic,          quic_transaction_listen_port                              );
  CFG_POP      ( uint,   ., tiles.quic,          txn_reassembly_count                                      );
  CFG_POP      ( uint,   ., tiles.quic,          max_concurrent_connections                                );
  CFG_POP      ( uint,   ., tiles.quic,          max_concurrent_streams_per_connection                     );
  CFG_POP      ( uint,   ., tiles.quic,          stream_pool_cnt                                           );
  CFG_POP      ( uint,   ., tiles.quic,          max_concurrent_handshakes                                 );
  CFG_POP      ( uint,   ., tiles.quic,          max_inflight_quic_packets                                 );
  CFG_POP      ( uint,   ., tiles.quic,          tx_buf_size                                               );
  CFG_POP      ( uint,   ., tiles.quic,          idle_timeout_millis                                       );
  CFG_POP      ( bool,   ., tiles.quic,          retry                                                     );

  CFG_POP      ( uint,   ., tiles.verify,        receive_buffer_size                                       );
  CFG_POP      ( uint,   ., tiles.verify,        mtu                                                       );

  CFG_POP      ( uint,   ., tiles.dedup,         signature_cache_size                                      );

  CFG_POP      ( uint,   ., tiles.pack,          max_pending_transactions                                  );

  CFG_POP      ( uint,   ., tiles.shred,         max_pending_shred_sets                                    );
  CFG_POP      ( ushort, ., tiles.shred,         shred_listen_port                                         );

  CFG_POP      ( ushort, ., tiles.metric,        prometheus_listen_port                                    );

  CFG_POP      ( bool,   ., development,         sandbox                                                   );
  CFG_POP      ( bool,   ., development,         no_clone                                                  );
  CFG_POP      ( bool,   ., development,         no_solana_labs                                            );
  CFG_POP      ( bool,   ., development,         bootstrap                                                 );
  CFG_POP      ( cstr,   ., development,         topology                                                  );

  CFG_POP      ( bool,   ., development.netns,   enabled                                                   );
  CFG_POP      ( cstr,   ., development.netns,   interface0                                                );
  CFG_POP      ( cstr,   ., development.netns,   interface0_mac                                            );
  CFG_POP      ( cstr,   ., development.netns,   interface0_addr                                           );
  CFG_POP      ( cstr,   ., development.netns,   interface1                                                );
  CFG_POP      ( cstr,   ., development.netns,   interface1_mac                                            );
  CFG_POP      ( cstr,   ., development.netns,   interface1_addr                                           );

  CFG_POP      ( bool,   ., development.gossip,  allow_private_address                                     );

  CFG_POP      ( ulong,  ., development.genesis, hashes_per_tick                                           );
  CFG_POP      ( ulong,  ., development.genesis, target_tick_duration_micros                               );
  CFG_POP      ( ulong,  ., development.genesis, ticks_per_slot                                            );
  CFG_POP      ( ulong,  ., development.genesis, fund_initial_accounts                                     );
  CFG_POP      ( ulong,  ., development.genesis, fund_initial_amount_lamports                              );
  CFG_POP      ( ulong,  ., development.genesis, vote_account_stake_lamports                               );
  CFG_POP      ( bool,   ., development.genesis, warmup_epochs                                             );

  CFG_POP      ( uint,   ., development.bench,   benchg_tile_count                                         );
  CFG_POP      ( uint,   ., development.bench,   benchs_tile_count                                         );
  CFG_POP      ( cstr,   ., development.bench,   affinity                                                  );
  CFG_POP      ( bool,   ., development.bench,   larger_max_cost_per_block                                 );
  CFG_POP      ( bool,   ., development.bench,   larger_shred_limits_per_block                             );
  CFG_POP      ( bool,   ., development.bench,   rocksdb_disable_wal                                       );

  /* Firedancer-only configuration */

  CFG_POP_ARRAY( cstr,   ., tiles.gossip,        entrypoints                                               );
  CFG_POP      ( ushort, ., tiles.gossip,        gossip_listen_port                                        );
  CFG_POP_ARRAY( ushort, ., tiles.gossip,        peer_ports                                                );

  CFG_POP      ( bool,   ., consensus,           vote                                                      );

  CFG_POP      ( ushort, ., tiles.repair,        repair_intake_listen_port                                 );
  CFG_POP      ( ushort, ., tiles.repair,        repair_serve_listen_port                                  );

  CFG_POP      ( cstr,   ., tiles.replay,        blockstore_checkpt                                        );
  CFG_POP      ( cstr,   ., tiles.replay,        capture                                                   );
  CFG_POP      ( ulong,  ., tiles.replay,        funk_rec_max                                              );
  CFG_POP      ( ulong,  ., tiles.replay,        funk_sz_gb                                                );
  CFG_POP      ( ulong,  ., tiles.replay,        funk_txn_max                                              );
  CFG_POP      ( cstr,   ., tiles.replay,        genesis                                                   );
  CFG_POP      ( cstr,   ., tiles.replay,        incremental                                               );
  CFG_POP      ( cstr,   ., tiles.replay,        slots_replayed                                            );
  CFG_POP      ( cstr,   ., tiles.replay,        snapshot                                                  );
  CFG_POP      ( ulong,  ., tiles.replay,        tpool_thread_count                                        );

  CFG_POP      ( cstr,   ., tiles.store_int,     blockstore_restore                                        );
  CFG_POP      ( cstr,   ., tiles.store_int,     slots_pending                                             );

# undef CFG_POP
# undef CFG_ARRAY

  if( FD_UNLIKELY( !fdctl_pod_find_leftover( pod ) ) ) return NULL;
  return config;
}
