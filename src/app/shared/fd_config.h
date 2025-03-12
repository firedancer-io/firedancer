#ifndef HEADER_fd_src_app_shared_fd_config_h
#define HEADER_fd_src_app_shared_fd_config_h

#include "fd_cap_chk.h"
#include "../../disco/topo/fd_topo.h"
#include "../../util/net/fd_net_headers.h" /* fd_ip4_port_t */

#include <net/if.h>
#include <linux/limits.h>

#define NAME_SZ 256
#define AFFINITY_SZ 256
#define CONFIGURE_STAGE_COUNT 12

union fdctl_args {
  struct {
    char  tile_name[ 7UL ];
    ulong kind_id;
    int   pipe_fd;
  } run1;

  struct {
    long dt_min;
    long dt_max;
    long duration;
    uint seed;
    double ns_per_tic;
    int drain_output_fd;
    int with_bench;
    int with_sankey;
  } monitor;

  struct {
    int                      command;
    struct configure_stage * stages[ CONFIGURE_STAGE_COUNT ];
  } configure;

  struct {
    int     require_tower;
    int     force;
    uchar * keypair;
  } set_identity;

  struct {
    int  parent_pipefd;
    int  monitor;
    int  no_configure;
    int  no_init_workspaces;
    int  no_agave;
    char debug_tile[ 32 ];
  } dev;

  struct {
    char tile_name[ 7UL ];
    int  no_configure;
  } dev1;

  struct {
    ulong cmd;
    char  file_path[ 256 ];
  } keys;

  struct {
    const char * payload_base64;
    ulong  count;
    const char * dst_ip;
    ushort dst_port;
  } txn;

  struct {
    char link_name[ 64UL ];
    char pcap_path[ 256UL ];
  } dump;

  struct {
    char name[ 13UL ];
  } flame;

  struct {
    char    affinity[ AFFINITY_SZ ];
    uint    tpu_ip;
    uint    rpc_ip;
    ushort  tpu_port;
    ushort  rpc_port;
    ulong   accounts;
    ulong   connections;
    ulong   benchg;
    ulong   benchs;
    int     no_quic;
    int     transaction_mode;
    float   contending_fraction;
    float   cu_price_spread;
  } load; /* also used by bench */

  struct {
    int event;
    int dump; /* whether the user requested --dump */
  } quic_trace;
};

typedef union fdctl_args args_t;

struct fd_config {
  char name[ NAME_SZ ];
  char user[ 256 ];
  char hostname[ FD_LOG_NAME_MAX ];

  double tick_per_ns_mu;
  double tick_per_ns_sigma;

  fd_topo_t topo;

  char cluster[ 32 ];
  int is_live_cluster;

  uint uid;
  uint gid;

  char scratch_directory[ PATH_MAX ];

  char dynamic_port_range[ 32 ];

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
    char solana_metrics_config[ 512 ];
  } reporting;

  struct {
    char  path[ PATH_MAX ];
    char  accounts_path[ PATH_MAX ];
    uint  limit_size;
    ulong account_indexes_cnt;
    char  account_indexes[ 4 ][ 32 ];
    ulong account_index_include_keys_cnt;
    char  account_index_include_keys[ 32 ][ FD_BASE58_ENCODED_32_SZ ];
    ulong account_index_exclude_keys_cnt;
    char  account_index_exclude_keys[ 32 ][ FD_BASE58_ENCODED_32_SZ ];
    char  accounts_index_path[ PATH_MAX ];
    char  accounts_hash_cache_path[ PATH_MAX ];
    int   require_tower;
    char  snapshot_archive_format[ 10 ];
  } ledger;

  struct {
#   define FD_CONFIG_GOSSIP_ENTRYPOINTS_MAX 16
    ulong  entrypoints_cnt;
    char   entrypoints[ FD_CONFIG_GOSSIP_ENTRYPOINTS_MAX ][ 262 ];
    ulong         resolved_entrypoints_cnt;
    fd_ip4_port_t resolved_entrypoints[ FD_CONFIG_GOSSIP_ENTRYPOINTS_MAX ];
    int    port_check;
    ushort port;
    char   host[ 256 ];
  } gossip;

  struct {
    int    vote;
    char   identity_path[ PATH_MAX ];
    char   vote_account_path[ PATH_MAX ];
    ulong  authorized_voter_paths_cnt;
    char   authorized_voter_paths[ 16 ][ PATH_MAX ];
    int    snapshot_fetch;
    int    genesis_fetch;
    int    poh_speed_test;
    char   expected_genesis_hash[ FD_BASE58_ENCODED_32_SZ ];
    uint   wait_for_supermajority_at_slot;
    char   expected_bank_hash[ FD_BASE58_ENCODED_32_SZ ];
    ushort expected_shred_version;
    int    wait_for_vote_to_start_leader;
    ulong  hard_fork_at_slots_cnt;
    uint   hard_fork_at_slots[ 32 ];
    ulong  known_validators_cnt;
    char   known_validators[ 16 ][ 256 ];
    int    os_network_limits_test;
  } consensus;

  struct {
    ushort port;
    int    full_api;
    int    private;
    char   bind_address[ 16 ];
    int    transaction_history;
    int    extended_tx_metadata_storage;
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
    uint maximum_full_snapshots_to_retain;
    uint maximum_incremental_snapshots_to_retain;
    char path[ PATH_MAX ];
    char incremental_path[ PATH_MAX ];
  } snapshots;

  struct {
    char affinity[ AFFINITY_SZ ];
    char agave_affinity[ AFFINITY_SZ ];

    uint agave_unified_scheduler_handler_threads;
    uint net_tile_count;
    uint quic_tile_count;
    uint resolv_tile_count;
    uint verify_tile_count;
    uint bank_tile_count;
    uint shred_tile_count;
    uint exec_tile_count; /* TODO: redundant ish with bank tile cnt */
  } layout;

  struct {
    char gigantic_page_mount_path[ PATH_MAX ];
    char huge_page_mount_path[ PATH_MAX ];
    char mount_path[ PATH_MAX ];
    char max_page_size[ 16 ];
    ulong gigantic_page_threshold_mib;
  } hugetlbfs;

  struct {
    ulong shred_max;
    ulong block_max;
    ulong idx_max;
    ulong txn_max;
    ulong alloc_max;
    char  file[PATH_MAX];
    char  checkpt[PATH_MAX];
    char  restore[PATH_MAX];
  } blockstore;

  struct {
    int sandbox;
    int no_clone;
    int core_dump;
    int no_agave;
    int bootstrap;
    uint debug_tile;

    struct {
      char provider[ 8 ];
    } net;

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
      char affinity[ AFFINITY_SZ ];
      char fake_dst_ip[ 16 ];
    } pktgen;
  } development;

  struct {
    struct {
      char   interface[ IF_NAMESIZE ];
      uint   ip_addr;
      char   xdp_mode[ 8 ];
      int    xdp_zero_copy;

      uint xdp_rx_queue_size;
      uint xdp_tx_queue_size;
      uint flush_timeout_micros;

      uint send_buffer_size;
    } net;

    struct {
      ulong max_routes;
      ulong max_neighbors;
    } netlink;

    struct {
      ushort regular_transaction_listen_port;
      ushort quic_transaction_listen_port;

      uint txn_reassembly_count;
      uint max_concurrent_connections;
      uint max_concurrent_handshakes;
      uint idle_timeout_millis;
      uint ack_delay_millis;
      int  retry;

    } quic;

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
    } bundle;

    struct {
      uint max_pending_transactions;
      int  use_consumed_cus;
    } pack;

    struct {
      int lagged_consecutive_leader_start;
    } poh;

    struct {
      uint   max_pending_shred_sets;
      ushort shred_listen_port;
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

    /* Firedancer-only tile configs */

    struct {
      ushort repair_intake_listen_port;
      ushort repair_serve_listen_port;
      char   good_peer_cache_file[ PATH_MAX ];
    } repair;

    struct {
      char  capture[ PATH_MAX ];
      char  funk_checkpt[ PATH_MAX ];
      ulong funk_rec_max;
      ulong funk_sz_gb;
      ulong funk_txn_max;
      char  funk_file[ PATH_MAX ];
      char  genesis[ PATH_MAX ];
      char  incremental[ PATH_MAX ];
      char  slots_replayed[PATH_MAX ];
      char  snapshot[ PATH_MAX ];
      char  status_cache[ PATH_MAX ];
      ulong tpool_thread_count;
      char  cluster_version[ 32 ];
      char  tower_checkpt[ PATH_MAX ];
    } replay;

    struct {
      char  slots_pending[PATH_MAX];
      char  shred_cap_archive[ PATH_MAX ];
      char  shred_cap_replay[ PATH_MAX ];
      ulong shred_cap_end_slot;
    } store_int;

    struct {
      ulong full_interval;
      ulong incremental_interval;
      char  out_dir[ PATH_MAX ];
      ulong hash_tpool_thread_count;
    } batch;

    struct {
      int   in_wen_restart;
      char  genesis_hash[ FD_BASE58_ENCODED_32_SZ ];
      char  wen_restart_coordinator[ FD_BASE58_ENCODED_32_SZ ];
    } restart;

  } tiles;
};

typedef struct fd_config fd_config_t;
typedef struct fd_config config_t;

struct fd_action {
  const char * name;
  const char * description;
  uchar        is_diagnostic;  /* 1 implies action should be allowed for prod debugging */

  void       (*args)( int * pargc, char *** pargv, args_t * args );
  void       (*perm)( args_t * args, fd_cap_chk_t * chk, config_t const * config );
  void       (*fn  )( args_t * args, config_t * config );
};

typedef struct fd_action action_t;

FD_PROTOTYPES_BEGIN

/* fdctl_cfg_from_env() loads a full configuration object from the provided
   arguments or the environment. First, the `default.toml` file is
   loaded as a base, and then if a FIREDANCER_CONFIG_FILE environment
   variable is provided, or a --config <path> command line argument, the
   `toml` file at that path is loaded and applied on top of the default
   configuration. This exits the program if it encounters any issue
   while loading or parsing the configuration. */

void
fdctl_cfg_from_env( int *      pargc,
                    char ***   pargv,
                    config_t * config );

/* Create a memfd and write the contents of the config struct into it.
   Used when execve() a child process so that it can read back in the
   same config as we did. */

int
fdctl_cfg_to_memfd( config_t const * config );

/* fdctl_cfg_net_auto attempts to automatically select an interface
   index and publicly routable IP address based on the current net
   configuration.  Existing interface/IP address config overrules the
   auto-selection logic. */

void
fdctl_cfg_net_auto( config_t * config );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_fd_config_h */
