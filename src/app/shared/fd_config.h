#ifndef HEADER_fd_src_app_shared_fd_config_h
#define HEADER_fd_src_app_shared_fd_config_h

#include "../../disco/topo/fd_topo.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../util/net/fd_net_headers.h"

#include <net/if.h>

#define NAME_SZ                          (256UL)
#define AFFINITY_SZ                      (256UL)
#define CONFIGURE_STAGE_COUNT            ( 12UL)
#define GOSSIP_TILE_ENTRYPOINTS_MAX      ( 16UL)
#define SNAPSHOT_TILE_HTTP_PEERS_MAX     ( 16UL)
#define IP4_PORT_STR_MAX                 ( 22UL)

struct fd_configh {
  char dynamic_port_range[ 32 ];

  struct {
    char  accounts_path[ PATH_MAX ];
    ulong authorized_voter_paths_cnt;
    char  authorized_voter_paths[ 16 ][ PATH_MAX ];
  } paths;

  struct {
    char solana_metrics_config[ 512 ];
  } reporting;

  struct {
    uint  limit_size;
    ulong account_indexes_cnt;
    char  account_indexes[ 4 ][ 32 ];
    ulong account_index_include_keys_cnt;
    char  account_index_include_keys[ 32 ][ FD_BASE58_ENCODED_32_SZ ];
    ulong account_index_exclude_keys_cnt;
    char  account_index_exclude_keys[ 32 ][ FD_BASE58_ENCODED_32_SZ ];
    char  accounts_index_path[ PATH_MAX ];
    char  accounts_hash_cache_path[ PATH_MAX ];
    int   enable_accounts_disk_index;
    int   require_tower;
    char  snapshot_archive_format[ 10 ];
  } ledger;

  struct {
    int    port_check;
  } gossip;

  struct {
    int    snapshot_fetch;
    int    genesis_fetch;
    int    poh_speed_test;
    char   expected_genesis_hash[ FD_BASE58_ENCODED_32_SZ ];
    uint   wait_for_supermajority_at_slot;
    char   expected_bank_hash[ FD_BASE58_ENCODED_32_SZ ];
    int    wait_for_vote_to_start_leader;
    ulong  hard_fork_at_slots_cnt;
    uint   hard_fork_at_slots[ 32 ];
    ulong  known_validators_cnt;
    char   known_validators[ 16 ][ 256 ];
    int    os_network_limits_test;
  } consensus;

  struct {
    int    full_api;
    int    private;
    char   bind_address[ 16 ];
    char   public_address[ IP4_PORT_STR_MAX ];
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
    char path[ PATH_MAX ];
    char incremental_path[ PATH_MAX ];
  } snapshots;

  struct {
    char agave_affinity[ AFFINITY_SZ ];
    uint agave_unified_scheduler_handler_threads;
  } layout;
};

typedef struct fd_configh fd_configh_t;

struct fd_configf {
  struct {
    ulong max_account_records;
    ulong heap_size_gib;
    ulong max_database_transactions;
    int   lock_pages;
  } funk;

  struct {
    uint exec_tile_count; /* TODO: redundant ish with bank tile cnt */
    uint sign_tile_count;
    uint gossvf_tile_count;
    uint snaplta_tile_count;
  } layout;

  struct {
    ulong max_live_slots;
    ulong max_vote_accounts;
    ulong max_fork_width;
  } runtime;

  struct {
    char host[ 256 ];
  } gossip;

  struct {

    struct {

      struct {
        int enabled;
      } entrypoints;

      struct {
        int enabled;
      } gossip;

      struct {
        ulong            peers_cnt;
        struct {
          int  enabled;
          char url[ PATH_MAX ];
        } peers[ SNAPSHOT_TILE_HTTP_PEERS_MAX ];
      } http;

    } sources;

    int   incremental_snapshots;
    uint  maximum_local_snapshot_age;
    int   genesis_download;
    int   download;
    ulong known_validators_cnt;
    char  known_validators[ 16 ][ 256 ];
    uint  minimum_download_speed_mib;
    uint  maximum_download_retry_abort;
    uint  max_full_snapshots_to_keep;
    uint  max_incremental_snapshots_to_keep;
  } snapshots;

  struct {
    ulong max_completed_shred_sets;
  } store;
};

typedef struct fd_configf fd_configf_t;

struct fd_config_net {
  char provider[ 8 ]; /* "xdp" or "socket" */

  char interface[ IF_NAMESIZE ];
  char bind_address[ 16 ];
  uint bind_address_parsed;
  uint ip_addr;

  uint ingress_buffer_size;

  struct {
    char xdp_mode[ 8 ];
    int  xdp_zero_copy;

    uint xdp_rx_queue_size;
    uint xdp_tx_queue_size;
    uint flush_timeout_micros;
    char rss_queue_mode[ 16 ]; /* "simple" or "dedicated" */
  } xdp;

  struct {
    uint receive_buffer_size;
    uint send_buffer_size;
  } socket;
};
typedef struct fd_config_net fd_config_net_t;

struct fd_config {
  char name[ NAME_SZ ];
  char user[ 256 ];
  char hostname[ FD_LOG_NAME_MAX ];

  double tick_per_ns_mu;
  double tick_per_ns_sigma;

  long boot_timestamp_nanos;

  fd_topo_t topo;

  char cluster[ 32 ];
  int is_live_cluster;

  uint uid;
  uint gid;

  int is_firedancer;
  union {
    fd_configh_t frankendancer;
    fd_configf_t firedancer;
  };

  struct {
    char base[ PATH_MAX ];
    char ledger[ PATH_MAX ];
    char identity_key[ PATH_MAX ];
    char vote_account[ PATH_MAX ];
    char snapshots[ PATH_MAX ];
    char genesis[ PATH_MAX ];
  } paths;

  struct {
    char path[ PATH_MAX ];
    char colorize[ 6 ];
    int  colorize1;
    char level_logfile[ 8 ];
    int  level_logfile1;
    char level_stderr[ 8 ];
    int  level_stderr1;
    char level_flush[ 8 ];
    int  level_flush1;

    /* File descriptor used for logging to the log file.  Stashed
       here for easy communication to child processes. */
    int  log_fd;

    /* Shared memfd_create file descriptor where the first 4
       bytes are the lock object for log sequencing.  Kind of
       gross to stash this in here. */
    int  lock_fd;
  } log;

  struct {
    ushort expected_shred_version;
    char   expected_genesis_hash[ FD_BASE58_ENCODED_32_SZ ];
  } consensus;

  struct {
    ulong         entrypoints_cnt;
    char          entrypoints[ GOSSIP_TILE_ENTRYPOINTS_MAX ][ 262 ];
    fd_ip4_port_t resolved_entrypoints[ GOSSIP_TILE_ENTRYPOINTS_MAX ];

    ushort        port;
  } gossip;

  struct {
    ushort port;
    int    extended_tx_metadata_storage;
    uint   block_index_max;
    uint   txn_index_max;
    uint   acct_index_max;
    char   history_file[ PATH_MAX ];
  } rpc;

  struct {
    char affinity[ AFFINITY_SZ ];

    uint net_tile_count;
    uint quic_tile_count;
    uint resolv_tile_count;
    uint verify_tile_count;
    uint bank_tile_count;
    uint shred_tile_count;
  } layout;

  struct {
    char  gigantic_page_mount_path[ PATH_MAX ];
    char  huge_page_mount_path[ PATH_MAX ];
    char  normal_page_mount_path[ PATH_MAX ];
    char  mount_path[ PATH_MAX ];
    char  max_page_size[ 16 ];
    ulong gigantic_page_threshold_mib;
    int   allow_hugepage_increase;
  } hugetlbfs;

  fd_config_net_t net;

  struct {
    int sandbox;
    int no_clone;
    int core_dump;
    int no_agave;
    int bootstrap;
    uint debug_tile;

    struct {
      int  enabled;
      char interface0     [ 16 ];
      char interface0_mac [ 32 ];
      char interface0_addr[ 16 ];
      char interface1     [ 16 ];
      char interface1_mac [ 32 ];
      char interface1_addr[ 16 ];
    } netns;

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
      char  affinity[ AFFINITY_SZ ];
      int   larger_max_cost_per_block;
      int   larger_shred_limits_per_block;
      ulong disable_blockstore_from_slot;
      int   disable_status_cache;
    } bench;

    struct {
      char ssl_key_log_file[ PATH_MAX ];
      uint buffer_size_kib;
      uint ssl_heap_size_mib;
    } bundle;

    struct {
      char affinity[ AFFINITY_SZ ];
      char fake_dst_ip[ 16 ];
    } pktgen;

    struct {
      char affinity[ AFFINITY_SZ ];
    } udpecho;

    struct {
      char affinity[ AFFINITY_SZ ];
    } snapshot_load;

    struct {
      int websocket_compression;
      char frontend_release_channel[ 16 ];
      int  frontend_release_channel_enum;
    } gui;
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

      char ssl_key_log_file[ PATH_MAX ];
    } quic;

    struct {
      ushort send_src_port;
    } send;

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
      char url[ 256 ];
      char tls_domain_name[ 256 ];
      char tip_distribution_program_addr[ FD_BASE58_ENCODED_32_SZ ];
      char tip_payment_program_addr[ FD_BASE58_ENCODED_32_SZ ];
      char tip_distribution_authority[ FD_BASE58_ENCODED_32_SZ ];
      uint commission_bps;
      ulong keepalive_interval_millis;
      int   tls_cert_verify;
    } bundle;

    struct {
      uint max_pending_transactions;
      int  use_consumed_cus;
      char schedule_strategy[ 16 ];
      int  schedule_strategy_enum;
    } pack;

    struct {
      int lagged_consecutive_leader_start;
    } poh;

    struct {
      uint   max_pending_shred_sets;
      ushort shred_listen_port;
      ulong  additional_shred_destinations_retransmit_cnt;
      char   additional_shred_destinations_retransmit[ FD_TOPO_ADTL_DESTS_MAX ][ sizeof("255.255.255.255:65536") ];
      ulong  additional_shred_destinations_leader_cnt;
      char   additional_shred_destinations_leader[ FD_TOPO_ADTL_DESTS_MAX ][ sizeof("255.255.255.255:65536") ];
    } shred;

    struct {
      char   prometheus_listen_address[ 16 ];
      ushort prometheus_listen_port;
    } metric;

    struct {
      int    enabled;
      char   gui_listen_address[ 16 ];
      ushort gui_listen_port;
      ulong  max_http_connections;
      ulong  max_websocket_connections;
      ulong  max_http_request_length;
      ulong  send_buffer_size_mb;
    } gui;

    struct {
      ushort repair_intake_listen_port;
      ushort repair_serve_listen_port;
      ulong  slot_max;
    } repair;

    struct {
      char  cluster_version[ 32 ];
      ulong enable_features_cnt;
      char  enable_features[ 16 ][ FD_BASE58_ENCODED_32_SZ ];
      ulong heap_size_gib;
    } replay;

    struct {
      char  slots_pending[PATH_MAX];
      char  shred_cap_archive[ PATH_MAX ];
      char  shred_cap_replay[ PATH_MAX ];
      ulong shred_cap_end_slot;
    } store_int;

    struct {
      int   enabled;
      ulong end_slot;
      char  rocksdb_path[ PATH_MAX ];
      char  shredcap_path[ PATH_MAX ];
      char  bank_hash_path[ PATH_MAX ];
      char  ingest_mode[ 32 ];
    } archiver;

    struct {
      int   enabled;
      char  folder_path[ PATH_MAX ];
      ulong write_buffer_size;
    } shredcap;

  } tiles;
  struct {
    ulong capture_start_slot;
    char  dump_proto_dir[ PATH_MAX ];
    char  solcap_capture[ PATH_MAX ];
    int   dump_elf_to_pb;
    int   dump_syscall_to_pb;
    int   dump_instr_to_pb;
    int   dump_txn_to_pb;
    int   dump_block_to_pb;
  } capture;
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
                int           netns,
                int           is_local_cluster,
                char const *  default_config,
                ulong         default_config_sz,
                char const *  override_config,
                char const *  override_config_path,
                ulong         override_config_sz,
                char const *  user_config,
                ulong         user_config_sz,
                char const *  user_config_path,
                fd_config_t * config );

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

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_fd_config_h */
