#include "fd_topo.h"

#include "../../util/net/fd_ip4.h"

#include <stdarg.h>
#include <errno.h>
#include <pthread.h>

struct fd_run_solana_args {
  char const * app_name;

  char const * identity_path;
  char const * vote_account_path;
  char const * ledger_path;
  char const * accounts_path;

  char const * expected_genesis_hash;
  char const * expected_bank_hash;

  char const * dynamic_port_range;

  ushort regular_transaction_listen_port;
  ushort shred_listen_port;

  ushort expected_shred_version;

  int    no_snapshot_fetch;
  int    no_genesis_fetch;
  int    no_poh_speed_test;
  int    no_os_network_limits_test;
  int    no_port_check;
  int    allow_private_address;

  int    wait_for_vote_to_start_leader;
  uint   wait_for_supermajority_at_slot;

  ulong  hard_fork_at_slots_cnt;
  uint   hard_fork_at_slots[ 32 ];
  ulong  known_validators_cnt;
  char   known_validators[ 16 ][ 256 ];

  int          require_tower;
  char const * snapshot_archive_format;

  uint  limit_ledger_size;

  int   bigtable_storage;

  ulong account_indexes_cnt;
  char const * account_indexes[ 4 ];
  ulong account_index_exclude_keys_cnt;
  char const * account_index_exclude_keys[ 32 ];

  ulong        entrypoints_cnt;
  char const * entrypoints[ 16 ];

  ushort       gossip_port;
  char const * gossip_host;

  uint ip_addr;

  ushort rpc_port;
  int    rpc_full_api;
  int    rpc_private;
  int    rpc_transaction_history;
  int    rpc_extended_tx_metadata_storage;
  int    rpc_only_known;
  int    rpc_pubsub_enable_block_subscription;
  int    rpc_pubsub_enable_vote_subscription;

  int  incremental_snapshots;
  uint full_snapshot_interval_slots;
  uint incremental_snapshot_interval_slots;
  char const * snapshots_path;

  int log_colorize;
};

typedef struct fd_run_solana_args fd_run_solana_args_t;

extern void fd_ext_validator_main( const char ** args );

/* FIXME: USE FD_CSTR_PRINTF */
static char *
snprintf1( char * s,
           ulong  maxlen,
           char * format,
           ... ) {
  va_list args;
  va_start( args, format );
  int len = vsnprintf( s, maxlen, format, args );
  va_end( args );
  if( FD_UNLIKELY( len<0 ) )
    FD_LOG_ERR(( "vsnprintf failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( (ulong)len >= maxlen ) )
    FD_LOG_ERR(( "vsnprintf truncated output (maxlen=%lu)", maxlen ));
  return s;
}

static void
fd_topo_run1_solana_labs( fd_run_solana_args_t const * args ) {
  uint idx = 0;
  char const * argv[ 128 ];
  uint bufidx = 0;
  char buffer[ 32 ][ 16 ];
#define ADD1( arg ) do { argv[ idx++ ] = arg; } while( 0 )
#define ADD( arg, val ) do { argv[ idx++ ] = arg; argv[ idx++ ] = val; } while( 0 )
#define ADDU( arg, val ) do { argv[ idx++ ] = arg; snprintf1( buffer[ bufidx ], 16, "%u", val ); argv[ idx++ ] = buffer[ bufidx++ ]; } while( 0 )
#define ADDH( arg, val ) do { argv[ idx++ ] = arg; snprintf1( buffer[ bufidx ], 16, "%hu", val ); argv[ idx++ ] = buffer[ bufidx++ ]; } while( 0 )

  ADD1( "fdctl" );
  ADD( "--log", "-" );

  if( FD_UNLIKELY( strcmp( args->dynamic_port_range, "" ) ) )
    ADD( "--dynamic-port-range", args->dynamic_port_range );

  ADDU( "--firedancer-tpu-port", args->regular_transaction_listen_port );
  ADDU( "--firedancer-tvu-port", args->shred_listen_port              );

  /* consensus */
  ADD( "--identity", args->identity_path );
  if( strcmp( args->vote_account_path, "" ) )
    ADD( "--vote-account", args->vote_account_path );
  if( args->no_snapshot_fetch ) ADD1( "--no-snapshot-fetch" );
  if( args->no_genesis_fetch  ) ADD1( "--no-genesis-fetch"  );
  if( args->no_poh_speed_test ) ADD1( "--no-poh-speed-test" );
  if( strcmp( args->expected_genesis_hash, "" ) )
    ADD( "--expected-genesis-hash", args->expected_genesis_hash );
  if( args->wait_for_supermajority_at_slot ) {
    ADDU( "--wait-for-supermajority", args->wait_for_supermajority_at_slot );
    if( strcmp( args->expected_bank_hash, "" ) )
      ADD( "--expected-bank-hash", args->expected_bank_hash );
  }
  if( args->expected_shred_version )
    ADDH( "--expected-shred-version", args->expected_shred_version );
  if( !args->wait_for_vote_to_start_leader )
    ADD1( "--no-wait-for-vote-to-start-leader");
  for( uint const * p = args->hard_fork_at_slots; *p; p++ ) ADDU( "--hard-fork", *p );
  for( ulong i=0; i<args->known_validators_cnt; i++ )
    ADD( "--known-validator", args->known_validators[ i ] );

  ADD( "--snapshot-archive-format", args->snapshot_archive_format );
  if( FD_UNLIKELY( args->require_tower ) ) ADD1( "--require-tower" );

  if( FD_UNLIKELY( args->no_os_network_limits_test ) )
    ADD1( "--no-os-network-limits-test" );

  /* ledger */
  ADD( "--ledger", args->ledger_path );
  if( strcmp( "", args->accounts_path ) ) ADD( "--accounts", args->accounts_path );
  ADDU( "--limit-ledger-size", args->limit_ledger_size );
  if( args->bigtable_storage ) ADD1( "--enable-rpc-bigtable-ledger-storage" );
  for( ulong i=0; i<args->account_indexes_cnt; i++ )
    ADD( "--account-index", args->account_indexes[ i ] );
  for( ulong i=0; i<args->account_index_exclude_keys_cnt; i++ )
    ADD( "--account-index-exclude-key", args->account_index_exclude_keys[ i ] );

  /* gossip */
  for( ulong i=0; i<args->entrypoints_cnt; i++ ) ADD( "--entrypoint", args->entrypoints[ i ] );
  if( !args->no_port_check ) ADD1( "--no-port-check" );
  ADDH( "--gossip-port", args->gossip_port );
  if( strcmp( args->gossip_host, "" ) ) {
    ADD( "--gossip-host", args->gossip_host );
  } else {
    char ip_addr[16];
    snprintf1( ip_addr, 16, FD_IP4_ADDR_FMT, FD_IP4_ADDR_FMT_ARGS( args->ip_addr ) );
    ADD( "--gossip-host", ip_addr );
  }
  if( args->allow_private_address ) {
    ADD1( "--allow-private-addr" );
  }

  /* rpc */
  if( args->rpc_port ) ADDH( "--rpc-port", args->rpc_port );
  if( args->rpc_full_api ) ADD1( "--full-rpc-api" );
  if( args->rpc_private ) ADD1( "--private-rpc" );
  if( args->rpc_transaction_history ) ADD1( "--enable-rpc-transaction-history" );
  if( args->rpc_extended_tx_metadata_storage ) ADD1( "--enable-extended-tx-metadata-storage" );
  if( args->rpc_only_known ) ADD1( "--only-known-rpc" );
  if( args->rpc_pubsub_enable_block_subscription ) ADD1( "--rpc-pubsub-enable-block-subscription" );
  if( args->rpc_pubsub_enable_vote_subscription ) ADD1( "--rpc-pubsub-enable-vote-subscription" );

  /* snapshots */
  if( !args->incremental_snapshots ) ADD1( "--no-incremental-snapshots" );
  ADDU( "--full-snapshot-interval-slots", args->full_snapshot_interval_slots );
  ADDU( "--incremental-snapshot-interval-slots", args->incremental_snapshot_interval_slots );
  ADD( "--snapshots", args->snapshots_path );

  argv[ idx ] = NULL;

  /* silence a bunch of solana_metrics INFO spam */
  if( FD_UNLIKELY( setenv( "RUST_LOG", "solana=info,solana_metrics::metrics=warn", 1 ) ) )
    FD_LOG_ERR(( "setenv() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  char const * log_style = args->log_colorize ? "always" : "never";
  if( FD_UNLIKELY( setenv( "RUST_LOG_STYLE", log_style, 1 ) ) )
    FD_LOG_ERR(( "setenv() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  FD_LOG_INFO(( "Running Solana Labs validator with the following arguments:" ));
  for( ulong j=0UL; j<idx; j++ ) FD_LOG_INFO(( "%s", argv[j] ));

  /* solana labs main will exit(1) if it fails, so no return code */
  fd_ext_validator_main( (const char **)argv );
}

void
fd_topo_run1_solana( fd_topo_run_args_t const * args ) {
  fd_topo_t const * topo = args->topo;
  fd_topo_edge_runnable_t const * run = args->run;

  /* Clone the child tiles that live in the Solana Labs address space. */
  pthread_t ignored[ FD_TOPO_VERT_MAX ];
  fd_topo_run_single_process( topo, topo->vv[ run->base.dst ], ignored );

  int pid = fd_topo_getpid();
  fd_topo_check_wait_debugger( topo, run, pid );
  fd_topo_initialize_logging( run, pid );

  fd_sandbox( 0, topo->app->uid, topo->app->gid, 0UL, 0, NULL, 0, NULL );

  fd_topo_run1_solana_labs( (fd_run_solana_args_t const *)run->args );
}
