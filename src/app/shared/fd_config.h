#ifndef HEADER_fd_src_app_shared_fd_config_h
#define HEADER_fd_src_app_shared_fd_config_h

#include "../../disco/topo/fd_topo.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../waltz/http/fd_url.h"

#include <net/if.h>

#define NAME_SZ                     (256UL)
#define AFFINITY_SZ                 (2048UL) /* FD_TOPO_MAX_TILES entries of "s1023," */
#define CONFIGURE_STAGE_COUNT       ( 24UL)
#define GOSSIP_TILE_ENTRYPOINTS_MAX ( 16UL)

/* FD_CONFIG_STRS_SZ is the size of the string arena that all
   fd_topo_str_t fields of fd_config_t point into. */

#define FD_CONFIG_STRS_SZ           (1UL<<18)

struct fd_configh {
  fd_topo_str_t dynamic_port_range;

  struct {
    fd_topo_str_t ledger;
    fd_topo_str_t accounts_path;
    ulong authorized_voter_paths_cnt;
    fd_topo_str_t authorized_voter_paths[ 16 ];
  } paths;

  struct {
    fd_topo_str_t solana_metrics_config;
  } reporting;

  struct {
    uint  limit_size;
    ulong account_indexes_cnt;
    fd_topo_str_t account_indexes[ 4 ];
    ulong account_index_include_keys_cnt;
    fd_topo_str_t account_index_include_keys[ 32 ];
    ulong account_index_exclude_keys_cnt;
    fd_topo_str_t account_index_exclude_keys[ 32 ];
    int   enable_accounts_disk_index;
    fd_topo_str_t accounts_index_path;
    fd_topo_str_t accounts_hash_cache_path;
    int   require_tower;
    fd_topo_str_t snapshot_archive_format;
  } ledger;

  struct {
    int    port_check;
  } gossip;

  struct {
    int    snapshot_fetch;
    int    genesis_fetch;
    int    poh_speed_test;
    fd_topo_str_t expected_genesis_hash;
    uint   wait_for_supermajority_at_slot;
    fd_topo_str_t expected_bank_hash;
    int    wait_for_vote_to_start_leader;
    ulong  hard_fork_at_slots_cnt;
    uint   hard_fork_at_slots[ 32 ];
    ulong  known_validators_cnt;
    fd_topo_str_t known_validators[ 16 ];
    int    os_network_limits_test;
  } consensus;

  struct {
    ushort port;
    int    extended_tx_metadata_storage;
    int    full_api;
    int    private;
    fd_topo_str_t bind_address;
    fd_topo_str_t public_address;
    int    transaction_history;
    int    only_known;
    int    pubsub_enable_block_subscription;
    int    pubsub_enable_vote_subscription;
    int    bigtable_ledger_storage;
  } rpc;

  struct {
    int  enabled;
    int  incremental_snapshots;
    uint full_snapshot_interval_slots;
    uint incremental_snapshot_interval_slots;
    uint minimum_snapshot_download_speed;
    uint maximum_snapshot_download_abort;
    uint maximum_full_snapshots_to_retain;
    uint maximum_incremental_snapshots_to_retain;
    fd_topo_str_t path;
    fd_topo_str_t incremental_path;
  } snapshots;

  struct {
    uint bank_tile_count;
    uint resolh_tile_count;
    fd_topo_str_t agave_affinity;
    uint agave_unified_scheduler_handler_threads;
  } layout;
};

typedef struct fd_configh fd_configh_t;

struct fd_configf {
  struct {
    ulong max_accounts;
    ulong cache_size_gib;
  } accounts;

  struct {
    int  enable_block_production;
    int  enable_snapshot_production;
    uint sign_tile_count;
    uint gossvf_tile_count;
    uint resolv_tile_count;
    uint execle_tile_count;
    uint execrp_tile_count;
    uint snapdc_tile_count;
    uint snapzp_tile_count;
    uint snapsv_tile_count;
    uint snapsv_io_worker_count;
  } layout;

  struct {
    ulong max_live_slots;
    ulong max_fork_width;

    struct {
      ulong heap_size_mib;
      ulong mean_cache_entry_size;
    } program_cache;
  } runtime;

  struct {
    fd_topo_str_t host;
  } gossip;

  struct {
    fd_topo_str_t wait_for_supermajority_with_bank_hash;
  } consensus;

  struct {
    struct {
      uint max_local_full_effective_age;
      uint max_local_incremental_age;

      struct {
        int   allow_any;
        ulong allow_list_cnt;
        fd_topo_str_t allow_list[ FD_TOPO_SNAPSHOTS_GOSSIP_LIST_MAX ];
        ulong block_list_cnt;
        fd_topo_str_t block_list[ FD_TOPO_SNAPSHOTS_GOSSIP_LIST_MAX ];
      } gossip;

      ulong servers_cnt;
      fd_topo_str_t servers[ FD_TOPO_SNAPSHOTS_SERVERS_MAX ];
    } sources;

    int  incremental_snapshots;
    int  genesis_download;
    uint max_full_snapshots_to_keep;
    uint max_incremental_snapshots_to_keep;
    uint max_retry_abort;
    uint min_download_speed_mibs;
    ulong wait_for_peers_timeout_seconds;
    ulong full_snapshot_interval_blocks;
    ulong incremental_snapshot_interval_blocks;
    ulong max_incremental_snapshot_accounts;

    struct {
      int enabled;
      fd_topo_str_t http_listen_address;
      uint http_listen_port;
      ulong max_http_connections;
      ulong idle_timeout_millis;
      ulong send_timeout_millis;
      ulong send_buffer_size_kib;
    } server;
  } snapshots;

  struct {
    int hard_fork_fatal;
    int fixed_fec_sets;
    int alpenglow;

    struct {
      ushort quic_client_listen_port;
      ushort quic_server_listen_port;
    } votor;

    struct {
      int   validate_genesis_hash;
      ulong max_file_size_mib;
    } genesis;

    struct {
      fd_topo_str_t format;
      fd_topo_str_t path;
      ulong end_slot;
    } ledger_input;

    struct {
      fd_topo_str_t affinity;
      ulong root_distance;
    } backtest;

    struct {
      fd_topo_str_t affinity;
    } forktest;
  } development;

  struct {
    fd_topo_str_t path;
  } capctx;

  struct {
    ulong authorized_voter_paths_cnt;
    fd_topo_str_t authorized_voter_paths[ 16 ];
  } paths;

};

typedef struct fd_configf fd_configf_t;

struct fd_config_net {
  fd_topo_str_t provider; /* "auto", "xdp", "socket" or "mlx5" */

  fd_topo_str_t interface;
  fd_topo_str_t bind_address;
  uint bind_address_parsed;
  uint ip_addr;

  uint ingress_buffer_size;

  struct {
    fd_topo_str_t xdp_mode; /* "drv", "skb" or "auto" */
    int  xdp_zero_copy; /* true/false or "auto" */
    fd_topo_str_t poll_mode; /* "prefbusy", "softirq" or "auto" */

    uint xdp_rx_queue_size;
    uint xdp_tx_queue_size;
    uint flush_timeout_micros;
    fd_topo_str_t rss_queue_mode; /* "simple", "dedicated" or "auto" */
    int  listen_gre; /* true/false or "auto" */
    int  native_bond; /* true/false or "auto" */
  } xdp;

  struct {
    uint rx_queue_size;
    uint tx_queue_size;
  } mlx5;

  struct {
    uint receive_buffer_size;
    uint send_buffer_size;
  } socket;
};
typedef struct fd_config_net fd_config_net_t;

struct fd_config {
  fd_topo_str_t name;
  fd_topo_str_t user;
  char hostname[ FD_LOG_NAME_MAX ];

  int telemetry;

  double tick_per_ns_mu;
  double tick_per_ns_sigma;

  long boot_timestamp_nanos;

  /* Sizing ceilings for every per-slot structure, derived at load: the
     largest values the consensus limits can take, or the raised
     [development.bench] limits.  txn/slot is min-cost txns against the
     cost ceiling and min-size txns against the shred ceiling, the same
     two bounds as FD_MAX_TXN_PER_SLOT_{CU,SHRED}.  The chain's live
     limits (cost tracker, shred and replay tiles) are floored by the raw
     [development.bench] values, which are 0 in production. */
  struct {
    ulong max_cost_per_block;
    ulong max_shreds_per_block;
    ulong max_txn_per_slot;
  } limits;

  fd_topo_t topo;

  char cluster[ 32 ];
  int is_live_cluster;

  uint uid;
  uint gid;

  int is_firedancer;
  int is_dev;
  int has_user_config;

  ulong user_config_len;
  char  user_config[ 131072 ];
  union {
    fd_configh_t frankendancer;
    fd_configf_t firedancer;
  };

  /* The name of the action being executed (e.g. "run", "dev",
     "backtest").  Populated by fd_main before topo_init runs. */
  char action[ 16 ];

  struct {
    fd_topo_str_t base;
    fd_topo_str_t identity_key;
    fd_topo_str_t vote_account;
    fd_topo_str_t snapshots;
    fd_topo_str_t genesis;
    fd_topo_str_t accounts;
    fd_topo_str_t shredb;
    fd_topo_str_t guidb;
  } paths;

  struct {
    fd_topo_str_t path;
    fd_topo_str_t colorize;
    int  colorize1;
    fd_topo_str_t level_logfile;
    int  level_logfile1;
    fd_topo_str_t level_stderr;
    int  level_stderr1;
    fd_topo_str_t level_flush;
    int  level_flush1;

    /* File descriptor used for logging to the log file.  Stashed
       here for easy communication to child processes. */
    int  log_fd;
  } log;

  /* Necessary to output auto config's decisions/observed system info
     to log file, since auto config runs before the log file is setup. */
  char auto_config_log[ 512 ];

  struct {
    ushort expected_shred_version;
    fd_topo_str_t expected_genesis_hash;

    int wait_for_vote_to_start_leader;
  } consensus;

  struct {
    ulong         entrypoints_cnt;
    fd_topo_str_t entrypoints[ GOSSIP_TILE_ENTRYPOINTS_MAX ];
    ushort        port;
  } gossip;

  struct {
    fd_topo_str_t affinity;
    fd_topo_str_t blocklist_cores;

    uint net_tile_count;
    uint quic_tile_count;
    uint verify_tile_count;
    uint shred_tile_count;
  } layout;

  struct {
    fd_topo_str_t gigantic_page_mount_path;
    fd_topo_str_t huge_page_mount_path;
    fd_topo_str_t normal_page_mount_path;
    fd_topo_str_t mount_path;
    fd_topo_str_t max_page_size;
    ulong gigantic_page_threshold_mib;
  } hugetlbfs;

  fd_config_net_t net;

  struct {
    int sandbox;
    int no_clone;
    int no_agave;
    int bootstrap;

    fd_topo_str_t core_dump;
    int core_dump_level;

    struct {
      int allow_private_address;
    } gossip;

    struct {
      ulong hashes_per_tick;
      ulong target_tick_duration_micros;
      ulong ticks_per_slot;
      ulong fund_initial_accounts;
      ulong fund_initial_amount_lamports;
      ulong vote_account_stake_lamports;
      int   warmup_epochs;
    } genesis;

    struct {
      uint  benchg_tile_count;
      uint  benchs_tile_count;
      fd_topo_str_t affinity;
      fd_topo_str_t transaction_mode;
      ulong max_cost_per_block;
      ulong max_shreds_per_block;
      ulong disable_blockstore_from_slot;
      int   disable_status_cache;
    } bench;

    struct {
      fd_topo_str_t ssl_key_log_file;
      uint buffer_size_kib;
    } bundle;

    struct {
      int report_shreds;
      int report_transactions;
      int report_runtime_diffs;
    } event;

    struct {
      fd_topo_str_t affinity;
      fd_topo_str_t fake_dst_ip;
    } pktgen;

    struct {
      fd_topo_str_t affinity;
    } udpecho;

    struct {
      fd_topo_str_t affinity;
    } snapshot_load;

    struct {
      int websocket_compression;
    } gui;

    struct {
      ulong partition_size_gib;
    } accdb;

    struct {
      int min_size;
    } hugetlbfs;
  } development;

  struct {
    struct {
      ulong max_routes;
      ulong max_peer_routes;
      ulong max_neighbors;
    } netlink;

    struct {
      ulong max_entries;
    } gossip;

    struct {
      ushort regular_transaction_listen_port;
      ushort quic_transaction_listen_port;

      uint txn_reassembly_count;
      uint max_concurrent_connections;
      uint max_concurrent_handshakes;
      uint idle_timeout_millis;
      uint ack_delay_millis;
      int  retry;

      fd_topo_str_t ssl_key_log_file;
    } quic;

    struct {
      ushort txsend_src_port;
    } txsend;

    struct {
      uint signature_cache_size;
      uint receive_buffer_size;
      uint mtu;
    } verify;

    struct {
      uint signature_cache_size;
    } dedup;

    struct {
      int  enabled;
      fd_topo_str_t url;
      fd_topo_str_t tls_domain_name;
      fd_topo_str_t tip_distribution_program_addr;
      fd_topo_str_t tip_payment_program_addr;
      fd_topo_str_t tip_distribution_authority;
      uint commission_bps;
      ulong keepalive_interval_millis;
      int   tls_cert_verify;
    } bundle;

    struct {
      uint  max_pending_transactions;
      int   use_consumed_cus;
      fd_topo_str_t schedule_strategy;
      int   schedule_strategy_enum;
      ulong account_blocklist_cnt;
      fd_topo_str_t account_blocklist[ FD_PACK_ACCT_BLOCKLIST_MAX ];
    } pack;

    struct {
      int lagged_consecutive_leader_start;
    } pohh;

    struct {
      uint   max_pending_shred_sets;
      ushort shred_listen_port;
      ulong  additional_shred_destinations_retransmit_cnt;
      fd_topo_str_t additional_shred_destinations_retransmit[ FD_TOPO_ADTL_DESTS_MAX ];
      ulong  additional_shred_destinations_leader_cnt;
      fd_topo_str_t additional_shred_destinations_leader[ FD_TOPO_ADTL_DESTS_MAX ];
      ulong  shred_cache_size_mib;
    } shred;

    struct {
      fd_topo_str_t prometheus_listen_address;
      ushort prometheus_listen_port;
    } metric;

    struct {
      fd_topo_str_t url;
    } event;

    struct {
      int    enabled;
      fd_topo_str_t gui_listen_address;
      ushort gui_listen_port;
      ulong  max_http_connections;
      ulong  max_websocket_connections;
      ulong  max_http_request_length;
      ulong  send_buffer_size_mb;
      ulong  db_size_gib;
    } gui;

    struct {
      int    enabled;
      fd_topo_str_t rpc_listen_address;
      ushort rpc_listen_port;
      ulong  max_http_connections;
      ulong  max_websocket_connections;
      ulong  max_http_request_length;
      ulong  send_buffer_size_mb;
      int    delay_startup;
    } rpc;

    struct {
      ushort repair_client_listen_port;
      ulong  slot_max;
    } repair;

    struct {
      ulong  slot_max;
    } rotor;

    struct {
      int    enabled;
      ushort repair_serve_listen_port;
      ulong  shred_storage_limit_gib;
    } rserve;

    struct {
      ulong max_transaction_lookahead_buffer_size;
      ulong enable_features_cnt;
      fd_topo_str_t enable_features[ 16 ];
    } replay;

  } tiles;
  struct {
    ulong capture_start_slot;
    fd_topo_str_t dump_proto_dir;
    fd_topo_str_t dump_syscall_name_filter;
    fd_topo_str_t dump_instr_program_id_filter;
    fd_topo_str_t solcap_capture;
    int   recent_only;
    ulong recent_slots_per_file;
    int   dump_syscall_to_pb;
    int   dump_instr_to_pb;
    int   dump_txn_to_pb;
    int   dump_txn_as_fixture;
    int   dump_block_to_pb;
  } capture;

  ulong strs_len;
  char  strs[ FD_CONFIG_STRS_SZ ];
};

typedef struct fd_config fd_config_t;
typedef struct fd_config config_t;

FD_PROTOTYPES_BEGIN

/* fd_config_load() loads a fd_config_t object from the contents of a
   configuration file.  This is not a simple transformation of the file,
   and involves multiple steps.  The default configuration file is
   loaded first, and then the user configuration file (if non-NULL) is
   loaded and overlaid on top of it.

   The resulting raw configuration is then transformed to a full config
   object by doing various parsing, validation, and filling in of extra
   data from the operating system.

   This function will not return on error, and will print an error
   message and exit the process.  On success, the config object will be
   returned as a fully filled in, validated, and ready to use object. */

void
fd_config_load( int           is_firedancer,
                int           is_local_cluster,
                char const *  default_config,
                ulong         default_config_sz,
                char const *  override_config,
                char const *  override_config_path,
                ulong         override_config_sz,
                char const *  user_config,
                ulong         user_config_sz,
                char const *  user_config_path,
                fd_config_t * config,
                int           dev );

/* Create a memfd and write the raw underlying bytes of the provided
   config struct into it.  On success returns a file descriptor
   representing the memfd.  On failure, returns -1 and errno will be
   set appropriately.

   The memfd is created with flags of 0.  The caller of the function can
   use it to pass a loaded config struct to child processes that are
   spawned with `execve(2)`, which would otherwise not be able to share
   memory with the forking process. */

int
fd_config_to_memfd( fd_config_t const * config );

/* fd_config_str_set appends [str,str+len) plus a NUL to the config string
   arena and points s at it.  str may alias the arena.  Returns 1 on
   success and 0 if the arena is full (s is left unchanged). */

int
fd_config_str_set( fd_config_t *   config,
                   fd_topo_str_t * s,
                   char const *    str,
                   ulong           len );

/* fd_config_str_printf formats into the config string arena and points
   s at the result.  Returns 1 on success and 0 if the arena is full
   (s is left unchanged). */

int
fd_config_str_printf( fd_config_t *   config,
                      fd_topo_str_t * s,
                      char const *    fmt, ... ) __attribute__((format(printf,3,4)));

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_fd_config_h */
