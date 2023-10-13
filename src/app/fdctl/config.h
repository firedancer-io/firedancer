#ifndef HEADER_fd_src_app_fdctl_config_h
#define HEADER_fd_src_app_fdctl_config_h

#include "../../ballet/base58/fd_base58.h"

#include <net/if.h>
#include <linux/limits.h>

/* Maximum size of the name of this Firedancer instance. */
#define NAME_SZ 256

/* Maximum size of the string describing the CPU affinity of Firedancer */
#define AFFINITY_SZ 256

typedef enum {
  wksp_netmux_inout,
  wksp_quic_verify,
  wksp_verify_dedup,
  wksp_dedup_pack,
  wksp_pack_bank,
  wksp_bank_shred,
  wksp_net,
  wksp_netmux,
  wksp_quic,
  wksp_verify,
  wksp_dedup,
  wksp_pack,
  wksp_bank,
  wksp_metrics,
  wksp_metrics_quic,
  wksp_metrics_verify,
  wksp_metrics_dedup,
  wksp_metrics_pack,
  wksp_metrics_bank,
} workspace_kind_t;

FD_FN_CONST char *
workspace_kind_str( workspace_kind_t kind );

typedef struct {
  workspace_kind_t kind;
  char * name;
  ulong page_size;
  ulong num_pages;
} workspace_config_t;

/* config_t represents all available configuration options that could be
   set in a user defined configuration toml file. For information about
   the options, see the `default.toml` file provided. */
typedef struct {
  char name[ NAME_SZ ];
  char user[ 256 ];

  int is_live_cluster;

  uint uid;
  uint gid;

  char scratch_directory[ PATH_MAX ];

  char dynamic_port_range[ 32 ];

  struct {
    char  path[ PATH_MAX ];
    char  accounts_path[ PATH_MAX ];
    uint  limit_size;
    int   bigtable_storage;
    ulong account_indexes_cnt;
    char  account_indexes[ 4 ][ 32 ];
    ulong account_index_exclude_keys_cnt;
    char  account_index_exclude_keys[ 32 ][ 32 ];
    int   require_tower;
    char  snapshot_archive_format[ 10 ];
  } ledger;

  struct {
    ulong  entrypoints_cnt;
    char   entrypoints[ 16 ][ 256 ];
    int    port_check;
    ushort port;
    char   host[ 256 ];
  } gossip;

  struct {
    char   identity_path[ PATH_MAX ];
    char   vote_account_path[ PATH_MAX ];
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
    int    transaction_history;
    int    extended_tx_metadata_storage;
    int    only_known;
    int    pubsub_enable_block_subscription;
    int    pubsub_enable_vote_subscription;
    int    incremental_snapshots;
  } rpc;

  struct {
    char affinity[ AFFINITY_SZ ];
    uint net_tile_count;
    uint verify_tile_count;
    uint bank_tile_count;
  } layout;

  struct {
    char gigantic_page_mount_path[ PATH_MAX ];
    char huge_page_mount_path[ PATH_MAX ];

    ulong workspaces_cnt;
    workspace_config_t workspaces[ 256 ];
  } shmem;

  struct {
    int sandbox;
    struct {
      int  enabled;
      char interface0     [ 256 ];
      char interface0_mac [ 32 ];
      char interface0_addr[ 32 ];
      char interface1     [ 256 ];
      char interface1_mac [ 32 ];
      char interface1_addr[ 32 ];
    } netns;
  } development;

  struct {
    struct {
      char   interface[ IF_NAMESIZE ];
      uint   ip_addr;
      uchar  mac_addr[6];
      char   xdp_mode[ 8 ];

      uint xdp_rx_queue_size;
      uint xdp_tx_queue_size;
      uint xdp_aio_depth;

      uint send_buffer_size;
    } net;

    struct {
      ushort transaction_listen_port;
      ushort quic_transaction_listen_port;

      uint max_concurrent_connections;
      uint max_concurrent_streams_per_connection;
      uint max_concurrent_handshakes;
      uint max_inflight_quic_packets;
      uint tx_buf_size;

    } quic;

    struct {
      uint receive_buffer_size;
      uint mtu;
    } verify;

    struct {
      uint max_pending_transactions;
    } pack;

    struct {
      uint receive_buffer_size;
    } bank;

    struct {
      uint   depth;
      uint   buffer_size;
      char   server[ PATH_MAX ];
      ushort port;
      char   user_pass[ PATH_MAX ];
      char   db[ PATH_MAX ];
      uint   post_interval_ms;
    } metrics;

    struct {
      uint signature_cache_size;
    } dedup;
  } tiles;
} config_t;

/* memlock_max_bytes() returns, for the entire Firedancer application,
   what the maximum total amount of `mlock()`ed memory will be in any
   one process, aka. what the RLIMIT_MLOCK must be set to so that all
   `mlock()` calls we wish to make will always succeed. The upper
   bound here is the sum of all workspace sizes, but the real number
   is lower because no process uses all of the workspaces at once. */
ulong
memlock_max_bytes( config_t * const config );

/* config_parse() loads a full configuration object from the provided
   arguments or the environment. First, the `default.toml` file is
   loaded as a base, and then if a FIREDANCER_CONFIG_FILE environment
   variable is provided, or a --config <path> command line argument, the
   `toml` file at that path is loaded and applied on top of the default
   configuration. This exits the program if it encounters any issue
   while loading or parsing the configuration. */
config_t
config_parse( int *    pargc,
              char *** pargv );

#endif /* HEADER_fd_src_app_fdctl_config_h */
