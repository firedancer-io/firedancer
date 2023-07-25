#ifndef HEADER_fd_src_app_fdctl_config_h
#define HEADER_fd_src_app_fdctl_config_h

#include <net/if.h>
#include <linux/limits.h>

/* Maximum size of the name of this Firedancer instance. */
#define NAME_SZ 256

/* Maximum size of the string describing the CPU affinity of Firedancer */
#define AFFINITY_SZ 256

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
    char   expected_genesis_hash[ 32 ];
    uint   wait_for_supermajority_at_slot;
    char   expected_bank_hash[ 32 ];
    ushort expected_shred_version;
    int    wait_for_vote_to_start_leader;
    ulong  hard_fork_at_slots_cnt;
    uint   hard_fork_at_slots[ 32 ];
    ulong  known_validators_cnt;
    char   known_validators[ 16 ][ 256 ];
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
    uint         verify_tile_count;
  } layout;

  struct {
    char gigantic_page_mount_path[ PATH_MAX ];
    char huge_page_mount_path[ PATH_MAX ];

    uint min_kernel_gigantic_pages;
    uint min_kernel_huge_pages;

    char workspace_page_size[ 32 ];
    uint workspace_page_count;
  } shmem;

  struct {
    int sandbox;
    int sudo;
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
      ushort listen_port;
      char   xdp_mode[ 8 ];

      uint max_concurrent_connections;
      uint max_concurrent_connection_ids_per_connection;
      uint max_concurrent_streams_per_connection;
      uint max_concurrent_handshakes;
      uint max_inflight_quic_packets;
      uint tx_buf_size;
      uint xdp_rx_queue_size;
      uint xdp_tx_queue_size;
      uint xdp_aio_depth;
    } quic;

    struct {
      uint receive_buffer_size;
      uint mtu;
    } verify;

    struct {
      uint max_pending_transactions;
      uint compute_unit_estimator_table_size;
      uint compute_unit_estimator_ema_history;
      uint compute_unit_estimator_ema_default;
      uint solana_labs_bank_thread_count;
      uint solana_labs_bank_thread_compute_units_executed_per_second;
    } pack;

    struct {
      uint signature_cache_size;
    } dedup;
  } tiles;
} config_t;

/* workspace_bytes() returns the size in bytes of the workspace specified in
   the configuration. For a workspace backed by gigantic pages, this is
   1GiB multiplied by the number of gigantic pages used. */
ulong
workspace_bytes( config_t * const config );

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

/* dump_vars() prints a bash file to the scratch directory. This bash
   file has variables set to locate the pod and main cnc structure. This
   is so that other processes know where to find our pod and data
   structures. */
void
dump_vars( config_t * const config,
           const char *     pod,
           const char *     main_cnc );

/* load_var_pod() reads the location of the pod in the workspace file
   from a bash variable file that was dumped. */
const char *
load_var_pod( config_t * const config,
              char *           name,
              char             line[4096] );

#endif /* HEADER_fd_src_app_fdctl_config_h */
