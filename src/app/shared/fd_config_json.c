#include "fd_config_json.h"

#include "../../ballet/toml/fd_toml.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* Renders every member of the config; a config layout change breaks
   this assert so the new field is considered here (rendered, redacted,
   or knowingly skipped) before the constant is bumped.  String keys of
   the user's own file are separately forced through the classification
   lists below. */
FD_STATIC_ASSERT( sizeof(fd_config_t)==22970296UL, update_fd_config_to_json_for_the_layout_change );

#define REDACTED "[redacted]"

struct jw {
  char * buf;
  char * cur;
  ulong  rem;
  int    fail;
  int    first; /* no comma needed before the next member */
};

typedef struct jw jw_t;

static void
jw_raw( jw_t * w, char const * fmt, ... ) __attribute__((format(printf,2,3)));

static void
jw_raw( jw_t * w, char const * fmt, ... ) {
  if( FD_UNLIKELY( w->fail ) ) return;
  va_list ap;
  va_start( ap, fmt );
  int n = vsnprintf( w->cur, w->rem, fmt, ap );
  va_end( ap );
  if( FD_UNLIKELY( n<0 || (ulong)n>=w->rem ) ) { w->fail = 1; return; }
  w->cur += n; w->rem -= (ulong)n;
}

static void
jw_comma( jw_t * w ) {
  if( !w->first ) jw_raw( w, "," );
  w->first = 0;
}

static void
jw_cstr( jw_t * w, char const * s ) {
  if( FD_UNLIKELY( w->fail ) ) return;
  jw_raw( w, "\"" );
  for( ; *s && !w->fail; s++ ) {
    uchar c = (uchar)*s;
    if(      c=='"' || c=='\\' ) jw_raw( w, "\\%c", (char)c );
    else if( c<0x20 )            jw_raw( w, "\\u%04x", (uint)c );
    else                         jw_raw( w, "%c", (char)c );
  }
  jw_raw( w, "\"" );
}

static void jw_obj_open ( jw_t * w, char const * key ) { jw_comma( w ); if( key ) { jw_cstr( w, key ); jw_raw( w, ":" ); } jw_raw( w, "{" ); w->first = 1; }
static void jw_obj_close( jw_t * w )                   { jw_raw( w, "}" ); w->first = 0; }
static void jw_arr_open ( jw_t * w, char const * key ) { jw_comma( w ); jw_cstr( w, key ); jw_raw( w, ":[" ); w->first = 1; }
static void jw_arr_close( jw_t * w )                   { jw_raw( w, "]" ); w->first = 0; }

static void jw_str  ( jw_t * w, char const * key, char const * val ) { jw_comma( w ); jw_cstr( w, key ); jw_raw( w, ":" ); jw_cstr( w, val ); }
static void jw_ulong( jw_t * w, char const * key, ulong val )        { jw_comma( w ); jw_cstr( w, key ); jw_raw( w, ":%lu", val ); }
static void jw_long ( jw_t * w, char const * key, long val )         { jw_comma( w ); jw_cstr( w, key ); jw_raw( w, ":%ld", val ); }
static void jw_f64  ( jw_t * w, char const * key, double val )       { jw_comma( w ); jw_cstr( w, key ); jw_raw( w, ":%.17g", val ); }
static void jw_bool ( jw_t * w, char const * key, int val )          { jw_comma( w ); jw_cstr( w, key ); jw_raw( w, ":%s", val ? "true" : "false" ); }

/* a path (or other host-identifying string) is reported only as
   present-or-empty */
static void jw_path ( jw_t * w, char const * key, char const * val ) { jw_str( w, key, val[ 0 ] ? REDACTED : "" ); }

/* external service URLs (bundle, event, snapshot servers) can carry
   secrets anywhere in them (credentials, path tokens, query api keys),
   so they are reported only as present-or-empty, like paths */
static void jw_url( jw_t * w, char const * key, char const * val ) { jw_path( w, key, val ); }

static void
jw_str_arr( jw_t * w, char const * key, char const * vals, ulong stride, ulong cnt ) {
  jw_arr_open( w, key );
  for( ulong i=0UL; i<cnt; i++ ) { jw_comma( w ); jw_cstr( w, vals+i*stride ); }
  jw_arr_close( w );
}

static void
jw_path_arr( jw_t * w, char const * key, ulong cnt ) {
  jw_arr_open( w, key );
  for( ulong i=0UL; i<cnt; i++ ) { jw_comma( w ); jw_cstr( w, REDACTED ); }
  jw_arr_close( w );
}

/* generic pod rendering for the user's override TOML: every
   string-valued key must appear in exactly one of the lists below,
   either redacted (the value could identify the host or carry a
   secret) or reported verbatim.  A string key in neither list aborts,
   so a new config setting must be classified before it ships in the
   boot event; test_config_json renders the full default.toml
   vocabulary through this, so an unclassified key fails the unit test
   rather than an operator's boot. */

static char const * const jw_redacted_keys[] = {
  "user",
  "paths.base",
  "paths.identity_key",
  "paths.vote_account",
  "paths.authorized_voter_paths",
  "paths.snapshots",
  "paths.genesis",
  "paths.accounts",
  "paths.shredb",
  "paths.guidb",
  "log.path",
  "gossip.host",
  "snapshots.sources.servers",
  "snapshots.server.http_listen_address",
  "hugetlbfs.mount_path",
  "net.bind_address",
  "tiles.quic.ssl_key_log_file",
  "tiles.bundle.url",
  "tiles.event.url",
  "tiles.shred.additional_shred_destinations_retransmit",
  "tiles.shred.additional_shred_destinations_leader",
  "tiles.metric.prometheus_listen_address",
  "gossip.entrypoints",
  "tiles.gui.gui_listen_address",
  "tiles.rpc.rpc_listen_address",
  "development.bundle.ssl_key_log_file",
  "development.ledger_input.path",
  "capture.dump_proto_dir",
  "capture.dump_syscall_name_filter",
  "capture.solcap_capture",
  /* legacy aliases accepted by the extractor but not in default.toml */
  "consensus.identity_path",
  "consensus.vote_account_path",
  "ledger.path",
  "scratch_directory",
};

static char const * const jw_reported_keys[] = {
  "name",
  "log.colorize",
  "log.level_logfile",
  "log.level_stderr",
  "log.level_flush",
  "snapshots.sources.gossip.allow_list",
  "snapshots.sources.gossip.block_list",
  "consensus.expected_genesis_hash",
  "consensus.wait_for_supermajority_with_bank_hash",
  "layout.affinity",
  "layout.blocklist_cores",
  "hugetlbfs.max_page_size",
  "net.provider",
  "net.interface",
  "net.xdp.xdp_mode",
  "net.xdp.xdp_zero_copy",
  "net.xdp.poll_mode",
  "net.xdp.rss_queue_mode",
  "net.xdp.listen_gre",
  "net.xdp.native_bond",
  "tiles.bundle.tls_domain_name",
  "tiles.bundle.tip_distribution_program_addr",
  "tiles.bundle.tip_payment_program_addr",
  "tiles.bundle.tip_distribution_authority",
  "tiles.pack.schedule_strategy",
  "tiles.pack.account_blocklist",
  "tiles.replay.enable_features",
  "development.core_dump",
  "development.bench.affinity",
  "development.pktgen.affinity",
  "development.pktgen.fake_dst_ip",
  "development.udpecho.affinity",
  "development.ledger_input.format",
  "development.backtest.affinity",
  "development.forktest.affinity",
  "capture.dump_instr_program_id_filter",
};

static int
jw_key_redacted( char const * path ) {
  for( ulong i=0UL; i<sizeof(jw_redacted_keys)/sizeof(jw_redacted_keys[0]); i++ ) if( !strcmp( path, jw_redacted_keys[ i ] ) ) return 1;
  for( ulong i=0UL; i<sizeof(jw_reported_keys)/sizeof(jw_reported_keys[0]); i++ ) if( !strcmp( path, jw_reported_keys[ i ] ) ) return 0;
  FD_LOG_ERR(( "config key %s is not classified for telemetry redaction; add it to jw_redacted_keys or jw_reported_keys in fd_config_json.c", path ));
}

/* an empty toml array parses to an empty subpod, indistinguishable
   from an empty table; the array-valued keys of the config vocabulary
   are listed so they render as [] */

static char const * const jw_array_keys[] = {
  "paths.authorized_voter_paths",
  "gossip.entrypoints",
  "snapshots.sources.gossip.allow_list",
  "snapshots.sources.gossip.block_list",
  "snapshots.sources.servers",
  "tiles.pack.account_blocklist",
  "tiles.replay.enable_features",
  "tiles.shred.additional_shred_destinations_retransmit",
  "tiles.shred.additional_shred_destinations_leader",
};

static int
jw_key_is_array( char const * path ) {
  for( ulong i=0UL; i<sizeof(jw_array_keys)/sizeof(jw_array_keys[0]); i++ ) if( !strcmp( path, jw_array_keys[ i ] ) ) return 1;
  return 0;
}

static int
jw_key_is_index( char const * key ) {
  for( ; *key; key++ ) if( *key<'0' || *key>'9' ) return 0;
  return 1;
}

static void
jw_pod( jw_t * w, uchar const * pod, char const * prefix ) {
  fd_pod_iter_t head = fd_pod_iter_init( pod );
  int arr = fd_pod_iter_done( head ) ? jw_key_is_array( prefix )
                                     : !strcmp( fd_pod_iter_info( head ).key, "0" ); /* fd_toml keys arrays 0,1,... */
  jw_raw( w, arr ? "[" : "{" );
  w->first = 1;
  for( fd_pod_iter_t iter=fd_pod_iter_init( pod ); !fd_pod_iter_done( iter ); iter=fd_pod_iter_next( iter ) ) {
    fd_pod_info_t info = fd_pod_iter_info( iter );
    char path[ 512 ];
    if( jw_key_is_index( info.key ) )   FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s", prefix ) ); /* array elements classify as the array */
    else if( prefix[ 0 ] )              FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s.%s", prefix, info.key ) );
    else                                FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s", info.key ) );
    jw_comma( w );
    if( !arr ) { jw_cstr( w, info.key ); jw_raw( w, ":" ); }
    switch( info.val_type ) {
      case FD_POD_VAL_TYPE_SUBPOD:
        if( FD_UNLIKELY( jw_key_is_index( info.key ) ) ) FD_LOG_ERR(( "config array %s has a table or nested array element which cannot be classified for telemetry redaction", path ));
        jw_pod( w, (uchar const *)info.val, path );
        break;
      case FD_POD_VAL_TYPE_CSTR: {
        char const * val = info.val_sz ? (char const *)info.val : "";
        jw_cstr( w, ( jw_key_redacted( path ) && val[ 0 ] ) ? REDACTED : val );
        break;
      }
      case FD_POD_VAL_TYPE_LONG: { /* toml integer */
        ulong u; fd_ulong_svw_dec( (uchar const *)info.val, &u );
        jw_raw( w, "%ld", fd_long_zz_dec( u ) );
        break;
      }
      case FD_POD_VAL_TYPE_INT: { /* toml bool */
        ulong u; fd_ulong_svw_dec( (uchar const *)info.val, &u );
        jw_raw( w, "%s", fd_long_zz_dec( u ) ? "true" : "false" );
        break;
      }
      case FD_POD_VAL_TYPE_FLOAT: {
        float val; memcpy( &val, info.val, sizeof(float) );
        jw_raw( w, "%.9g", (double)val );
        break;
      }
      default:
        FD_LOG_ERR(( "unexpected pod value type %d for key %s", info.val_type, info.key ));
    }
  }
  jw_raw( w, arr ? "]" : "}" );
  w->first = 0;
}

ulong
fd_config_user_toml_to_json( fd_config_t const * config,
                             char *              buf,
                             ulong               buf_sz ) {
  if( FD_UNLIKELY( !buf_sz ) ) FD_LOG_ERR(( "zero sized buffer" ));
  buf[ 0 ] = '\0';
  if( FD_UNLIKELY( !config->user_config_len ) ) return 0UL;

  static uchar pod_mem[ 1UL<<20 ];
  uchar * pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );
  FD_TEST( pod );

  uchar scratch[ 4096 ];
  int err = fd_toml_parse( config->user_config, config->user_config_len, pod, scratch, sizeof(scratch), NULL );
  if( FD_UNLIKELY( err!=FD_TOML_SUCCESS ) ) FD_LOG_ERR(( "failed to re-parse the user config (%i-%s)", err, fd_toml_strerror( err ) ));

  jw_t w = { .buf = buf, .cur = buf, .rem = buf_sz, .fail = 0, .first = 1 };
  jw_pod( &w, pod, "" );

  fd_pod_delete( fd_pod_leave( pod ) );

  if( FD_UNLIKELY( w.fail ) ) FD_LOG_ERR(( "user config json does not fit in %lu bytes", buf_sz ));
  return (ulong)( w.cur-buf );
}

ulong
fd_config_to_json( fd_config_t const * config,
                   char *              buf,
                   ulong               buf_sz ) {
  FD_TEST( config->is_firedancer );
  fd_configf_t const * f = &config->firedancer;

  jw_t w = { .buf = buf, .cur = buf, .rem = buf_sz, .fail = !buf_sz, .first = 1 };

  jw_raw( &w, "{" );
  jw_str  ( &w, "name",              config->name );
  jw_path ( &w, "user",              config->user );
  jw_path ( &w, "hostname",          config->hostname );
  jw_bool ( &w, "telemetry",         config->telemetry );
  jw_f64  ( &w, "tick_per_ns_mu",    config->tick_per_ns_mu );
  jw_f64  ( &w, "tick_per_ns_sigma", config->tick_per_ns_sigma );
  jw_long ( &w, "boot_timestamp_nanos", config->boot_timestamp_nanos );
  jw_str  ( &w, "cluster",           config->cluster );
  jw_bool ( &w, "is_live_cluster",   config->is_live_cluster );
  jw_ulong( &w, "uid",               config->uid );
  jw_ulong( &w, "gid",               config->gid );
  jw_bool ( &w, "is_firedancer",     config->is_firedancer );
  jw_bool ( &w, "is_dev",            config->is_dev );
  jw_bool ( &w, "has_user_config",   config->has_user_config );
  jw_str  ( &w, "action",            config->action );

  jw_obj_open( &w, "paths" );
    jw_path( &w, "base",         config->paths.base );
    jw_path( &w, "identity_key", config->paths.identity_key );
    jw_path( &w, "vote_account", config->paths.vote_account );
    jw_path( &w, "snapshots",    config->paths.snapshots );
    jw_path( &w, "genesis",      config->paths.genesis );
    jw_path( &w, "accounts",     config->paths.accounts );
    jw_path( &w, "shredb",       config->paths.shredb );
    jw_path( &w, "guidb",        config->paths.guidb );
    jw_path_arr( &w, "authorized_voter_paths", f->paths.authorized_voter_paths_cnt );
  jw_obj_close( &w );

  jw_obj_open( &w, "log" );
    jw_path( &w, "path",          config->log.path );
    jw_str ( &w, "colorize",      config->log.colorize );
    jw_str ( &w, "level_logfile", config->log.level_logfile );
    jw_str ( &w, "level_stderr",  config->log.level_stderr );
    jw_str ( &w, "level_flush",   config->log.level_flush );
  jw_obj_close( &w );

  jw_obj_open( &w, "consensus" );
    jw_ulong( &w, "expected_shred_version",        config->consensus.expected_shred_version );
    jw_str  ( &w, "expected_genesis_hash",         config->consensus.expected_genesis_hash );
    jw_bool ( &w, "wait_for_vote_to_start_leader", config->consensus.wait_for_vote_to_start_leader );
    jw_str  ( &w, "wait_for_supermajority_with_bank_hash", f->consensus.wait_for_supermajority_with_bank_hash );
  jw_obj_close( &w );

  jw_obj_open( &w, "gossip" );
    jw_path_arr( &w, "entrypoints", config->gossip.entrypoints_cnt );
    jw_ulong( &w, "port", config->gossip.port );
    jw_path ( &w, "host", f->gossip.host );
  jw_obj_close( &w );

  jw_obj_open( &w, "layout" );
    jw_str  ( &w, "affinity",          config->layout.affinity );
    jw_str  ( &w, "blocklist_cores",   config->layout.blocklist_cores );
    jw_ulong( &w, "net_tile_count",    config->layout.net_tile_count );
    jw_ulong( &w, "quic_tile_count",   config->layout.quic_tile_count );
    jw_ulong( &w, "verify_tile_count", config->layout.verify_tile_count );
    jw_ulong( &w, "shred_tile_count",  config->layout.shred_tile_count );
    jw_bool ( &w, "enable_block_production",    f->layout.enable_block_production );
    jw_bool ( &w, "enable_snapshot_production", f->layout.enable_snapshot_production );
    jw_ulong( &w, "sign_tile_count",            f->layout.sign_tile_count );
    jw_ulong( &w, "gossvf_tile_count",          f->layout.gossvf_tile_count );
    jw_ulong( &w, "resolv_tile_count",          f->layout.resolv_tile_count );
    jw_ulong( &w, "execle_tile_count",          f->layout.execle_tile_count );
    jw_ulong( &w, "execrp_tile_count",          f->layout.execrp_tile_count );
    jw_ulong( &w, "snapzp_tile_count",          f->layout.snapzp_tile_count );
    jw_ulong( &w, "snapsv_tile_count",          f->layout.snapsv_tile_count );
    jw_ulong( &w, "snapsv_io_worker_count",     f->layout.snapsv_io_worker_count );
  jw_obj_close( &w );

  jw_obj_open( &w, "accounts" );
    jw_ulong( &w, "max_accounts",   f->accounts.max_accounts );
    jw_ulong( &w, "cache_size_gib", f->accounts.cache_size_gib );
  jw_obj_close( &w );

  jw_obj_open( &w, "runtime" );
    jw_ulong( &w, "max_live_slots", f->runtime.max_live_slots );
    jw_ulong( &w, "max_fork_width", f->runtime.max_fork_width );
    jw_obj_open( &w, "program_cache" );
      jw_ulong( &w, "heap_size_mib",         f->runtime.program_cache.heap_size_mib );
      jw_ulong( &w, "mean_cache_entry_size", f->runtime.program_cache.mean_cache_entry_size );
    jw_obj_close( &w );
  jw_obj_close( &w );

  jw_obj_open( &w, "snapshots" );
    jw_obj_open( &w, "sources" );
      jw_ulong( &w, "max_local_full_effective_age", f->snapshots.sources.max_local_full_effective_age );
      jw_ulong( &w, "max_local_incremental_age",    f->snapshots.sources.max_local_incremental_age );
      jw_obj_open( &w, "gossip" );
        jw_bool( &w, "allow_any", f->snapshots.sources.gossip.allow_any );
        jw_str_arr( &w, "allow_list", f->snapshots.sources.gossip.allow_list[ 0 ], sizeof(f->snapshots.sources.gossip.allow_list[ 0 ]), f->snapshots.sources.gossip.allow_list_cnt );
        jw_str_arr( &w, "block_list", f->snapshots.sources.gossip.block_list[ 0 ], sizeof(f->snapshots.sources.gossip.block_list[ 0 ]), f->snapshots.sources.gossip.block_list_cnt );
      jw_obj_close( &w );
      jw_path_arr( &w, "servers", f->snapshots.sources.servers_cnt );
    jw_obj_close( &w );
    jw_bool ( &w, "incremental_snapshots",               f->snapshots.incremental_snapshots );
    jw_bool ( &w, "genesis_download",                    f->snapshots.genesis_download );
    jw_ulong( &w, "max_full_snapshots_to_keep",          f->snapshots.max_full_snapshots_to_keep );
    jw_ulong( &w, "max_incremental_snapshots_to_keep",   f->snapshots.max_incremental_snapshots_to_keep );
    jw_ulong( &w, "max_retry_abort",                     f->snapshots.max_retry_abort );
    jw_ulong( &w, "min_download_speed_mibs",             f->snapshots.min_download_speed_mibs );
    jw_ulong( &w, "wait_for_peers_timeout_seconds",      f->snapshots.wait_for_peers_timeout_seconds );
    jw_ulong( &w, "full_snapshot_interval_blocks",       f->snapshots.full_snapshot_interval_blocks );
    jw_ulong( &w, "incremental_snapshot_interval_blocks",f->snapshots.incremental_snapshot_interval_blocks );
    jw_ulong( &w, "max_incremental_snapshot_accounts",   f->snapshots.max_incremental_snapshot_accounts );
    jw_obj_open( &w, "server" );
      jw_bool ( &w, "enabled",              f->snapshots.server.enabled );
      jw_path ( &w, "http_listen_address",  f->snapshots.server.http_listen_address );
      jw_ulong( &w, "http_listen_port",     f->snapshots.server.http_listen_port );
      jw_ulong( &w, "max_http_connections", f->snapshots.server.max_http_connections );
      jw_ulong( &w, "idle_timeout_millis",  f->snapshots.server.idle_timeout_millis );
      jw_ulong( &w, "send_timeout_millis",  f->snapshots.server.send_timeout_millis );
      jw_ulong( &w, "send_buffer_size_kib", f->snapshots.server.send_buffer_size_kib );
    jw_obj_close( &w );
  jw_obj_close( &w );

  jw_obj_open( &w, "hugetlbfs" );
    jw_path ( &w, "gigantic_page_mount_path",    config->hugetlbfs.gigantic_page_mount_path );
    jw_path ( &w, "huge_page_mount_path",        config->hugetlbfs.huge_page_mount_path );
    jw_path ( &w, "normal_page_mount_path",      config->hugetlbfs.normal_page_mount_path );
    jw_path ( &w, "mount_path",                  config->hugetlbfs.mount_path );
    jw_str  ( &w, "max_page_size",               config->hugetlbfs.max_page_size );
    jw_ulong( &w, "gigantic_page_threshold_mib", config->hugetlbfs.gigantic_page_threshold_mib );
  jw_obj_close( &w );

  jw_obj_open( &w, "net" );
    jw_str  ( &w, "provider",            config->net.provider );
    jw_str  ( &w, "interface",           config->net.interface );
    jw_path ( &w, "bind_address",        config->net.bind_address );
    jw_ulong( &w, "ingress_buffer_size", config->net.ingress_buffer_size );
    jw_obj_open( &w, "xdp" );
      jw_str  ( &w, "xdp_mode",             config->net.xdp.xdp_mode );
      jw_bool ( &w, "xdp_zero_copy",        config->net.xdp.xdp_zero_copy );
      jw_str  ( &w, "poll_mode",            config->net.xdp.poll_mode );
      jw_ulong( &w, "xdp_rx_queue_size",    config->net.xdp.xdp_rx_queue_size );
      jw_ulong( &w, "xdp_tx_queue_size",    config->net.xdp.xdp_tx_queue_size );
      jw_ulong( &w, "flush_timeout_micros", config->net.xdp.flush_timeout_micros );
      jw_str  ( &w, "rss_queue_mode",       config->net.xdp.rss_queue_mode );
      jw_bool ( &w, "listen_gre",           config->net.xdp.listen_gre );
      jw_bool ( &w, "native_bond",          config->net.xdp.native_bond );
    jw_obj_close( &w );
    jw_obj_open( &w, "socket" );
      jw_ulong( &w, "receive_buffer_size", config->net.socket.receive_buffer_size );
      jw_ulong( &w, "send_buffer_size",    config->net.socket.send_buffer_size );
    jw_obj_close( &w );
    jw_obj_open( &w, "mlx5" );
      jw_ulong( &w, "rx_queue_size", config->net.mlx5.rx_queue_size );
      jw_ulong( &w, "tx_queue_size", config->net.mlx5.tx_queue_size );
    jw_obj_close( &w );
  jw_obj_close( &w );

  jw_obj_open( &w, "development" );
    jw_bool( &w, "sandbox",   config->development.sandbox );
    jw_bool( &w, "no_clone",  config->development.no_clone );
    jw_bool( &w, "no_agave",  config->development.no_agave );
    jw_bool( &w, "bootstrap", config->development.bootstrap );
    jw_str ( &w, "core_dump", config->development.core_dump );
    jw_bool( &w, "hard_fork_fatal", f->development.hard_fork_fatal );
    jw_bool( &w, "fixed_fec_sets",  f->development.fixed_fec_sets );
    jw_bool( &w, "alpenglow",       f->development.alpenglow );
    jw_obj_open( &w, "votor" );
      jw_ulong( &w, "quic_client_listen_port", f->development.votor.quic_client_listen_port );
      jw_ulong( &w, "quic_server_listen_port", f->development.votor.quic_server_listen_port );
    jw_obj_close( &w );
    jw_obj_open( &w, "gossip" );
      jw_bool( &w, "allow_private_address", config->development.gossip.allow_private_address );
    jw_obj_close( &w );
    jw_obj_open( &w, "genesis" );
      jw_ulong( &w, "hashes_per_tick",              config->development.genesis.hashes_per_tick );
      jw_ulong( &w, "target_tick_duration_micros",  config->development.genesis.target_tick_duration_micros );
      jw_ulong( &w, "ticks_per_slot",               config->development.genesis.ticks_per_slot );
      jw_ulong( &w, "fund_initial_accounts",        config->development.genesis.fund_initial_accounts );
      jw_ulong( &w, "fund_initial_amount_lamports", config->development.genesis.fund_initial_amount_lamports );
      jw_ulong( &w, "vote_account_stake_lamports",  config->development.genesis.vote_account_stake_lamports );
      jw_bool ( &w, "warmup_epochs",                config->development.genesis.warmup_epochs );
      jw_bool ( &w, "validate_genesis_hash",        f->development.genesis.validate_genesis_hash );
      jw_ulong( &w, "max_file_size_mib",            f->development.genesis.max_file_size_mib );
    jw_obj_close( &w );
    jw_obj_open( &w, "ledger_input" );
      jw_str  ( &w, "format",   f->development.ledger_input.format );
      jw_path ( &w, "path",     f->development.ledger_input.path );
      jw_ulong( &w, "end_slot", f->development.ledger_input.end_slot );
    jw_obj_close( &w );
    jw_obj_open( &w, "backtest" );
      jw_str  ( &w, "affinity",      f->development.backtest.affinity );
      jw_ulong( &w, "root_distance", f->development.backtest.root_distance );
    jw_obj_close( &w );
    jw_obj_open( &w, "forktest" );
      jw_str( &w, "affinity", f->development.forktest.affinity );
    jw_obj_close( &w );
    jw_obj_open( &w, "bench" );
      jw_ulong( &w, "benchg_tile_count",            config->development.bench.benchg_tile_count );
      jw_ulong( &w, "benchs_tile_count",            config->development.bench.benchs_tile_count );
      jw_str  ( &w, "affinity",                     config->development.bench.affinity );
      jw_bool ( &w, "larger_max_cost_per_block",    config->development.bench.larger_max_cost_per_block );
      jw_bool ( &w, "larger_shred_limits_per_block",config->development.bench.larger_shred_limits_per_block );
      jw_ulong( &w, "disable_blockstore_from_slot", config->development.bench.disable_blockstore_from_slot );
      jw_bool ( &w, "disable_status_cache",         config->development.bench.disable_status_cache );
    jw_obj_close( &w );
    jw_obj_open( &w, "bundle" );
      jw_path ( &w, "ssl_key_log_file",  config->development.bundle.ssl_key_log_file );
      jw_ulong( &w, "buffer_size_kib",   config->development.bundle.buffer_size_kib );
      jw_ulong( &w, "ssl_heap_size_mib", config->development.bundle.ssl_heap_size_mib );
    jw_obj_close( &w );
    jw_obj_open( &w, "event" );
      jw_bool( &w, "report_shreds",            config->development.event.report_shreds );
      jw_bool( &w, "report_transactions",      config->development.event.report_transactions );
      jw_bool( &w, "report_transaction_diffs", config->development.event.report_transaction_diffs );
    jw_obj_close( &w );
    jw_obj_open( &w, "pktgen" );
      jw_str( &w, "affinity",    config->development.pktgen.affinity );
      jw_str( &w, "fake_dst_ip", config->development.pktgen.fake_dst_ip );
    jw_obj_close( &w );
    jw_obj_open( &w, "udpecho" );
      jw_str( &w, "affinity", config->development.udpecho.affinity );
    jw_obj_close( &w );
    jw_obj_open( &w, "snapshot_load" );
      jw_str( &w, "affinity", config->development.snapshot_load.affinity );
    jw_obj_close( &w );
    jw_obj_open( &w, "gui" );
      jw_bool( &w, "websocket_compression", config->development.gui.websocket_compression );
    jw_obj_close( &w );
    jw_obj_open( &w, "accdb" );
      jw_ulong( &w, "partition_size_gib", config->development.accdb.partition_size_gib );
    jw_obj_close( &w );
    jw_obj_open( &w, "hugetlbfs" );
      jw_bool( &w, "min_size", config->development.hugetlbfs.min_size );
    jw_obj_close( &w );
  jw_obj_close( &w );

  jw_obj_open( &w, "tiles" );
    jw_obj_open( &w, "netlink" );
      jw_ulong( &w, "max_routes",      config->tiles.netlink.max_routes );
      jw_ulong( &w, "max_peer_routes", config->tiles.netlink.max_peer_routes );
      jw_ulong( &w, "max_neighbors",   config->tiles.netlink.max_neighbors );
    jw_obj_close( &w );
    jw_obj_open( &w, "gossip" );
      jw_ulong( &w, "max_entries", config->tiles.gossip.max_entries );
    jw_obj_close( &w );
    jw_obj_open( &w, "quic" );
      jw_ulong( &w, "regular_transaction_listen_port", config->tiles.quic.regular_transaction_listen_port );
      jw_ulong( &w, "quic_transaction_listen_port",    config->tiles.quic.quic_transaction_listen_port );
      jw_ulong( &w, "txn_reassembly_count",            config->tiles.quic.txn_reassembly_count );
      jw_ulong( &w, "max_concurrent_connections",      config->tiles.quic.max_concurrent_connections );
      jw_ulong( &w, "max_concurrent_handshakes",       config->tiles.quic.max_concurrent_handshakes );
      jw_ulong( &w, "idle_timeout_millis",             config->tiles.quic.idle_timeout_millis );
      jw_ulong( &w, "ack_delay_millis",                config->tiles.quic.ack_delay_millis );
      jw_bool ( &w, "retry",                           config->tiles.quic.retry );
      jw_path ( &w, "ssl_key_log_file",                config->tiles.quic.ssl_key_log_file );
    jw_obj_close( &w );
    jw_obj_open( &w, "txsend" );
      jw_ulong( &w, "txsend_src_port", config->tiles.txsend.txsend_src_port );
    jw_obj_close( &w );
    jw_obj_open( &w, "verify" );
      jw_ulong( &w, "signature_cache_size", config->tiles.verify.signature_cache_size );
      jw_ulong( &w, "receive_buffer_size",  config->tiles.verify.receive_buffer_size );
      jw_ulong( &w, "mtu",                  config->tiles.verify.mtu );
    jw_obj_close( &w );
    jw_obj_open( &w, "dedup" );
      jw_ulong( &w, "signature_cache_size", config->tiles.dedup.signature_cache_size );
    jw_obj_close( &w );
    jw_obj_open( &w, "bundle" );
      jw_bool ( &w, "enabled",                       config->tiles.bundle.enabled );
      jw_url  ( &w, "url",                           config->tiles.bundle.url );
      jw_str  ( &w, "tls_domain_name",               config->tiles.bundle.tls_domain_name );
      jw_str  ( &w, "tip_distribution_program_addr", config->tiles.bundle.tip_distribution_program_addr );
      jw_str  ( &w, "tip_payment_program_addr",      config->tiles.bundle.tip_payment_program_addr );
      jw_str  ( &w, "tip_distribution_authority",    config->tiles.bundle.tip_distribution_authority );
      jw_ulong( &w, "commission_bps",                config->tiles.bundle.commission_bps );
      jw_ulong( &w, "keepalive_interval_millis",     config->tiles.bundle.keepalive_interval_millis );
      jw_bool ( &w, "tls_cert_verify",               config->tiles.bundle.tls_cert_verify );
    jw_obj_close( &w );
    jw_obj_open( &w, "pack" );
      jw_ulong( &w, "max_pending_transactions", config->tiles.pack.max_pending_transactions );
      jw_bool ( &w, "use_consumed_cus",         config->tiles.pack.use_consumed_cus );
      jw_str  ( &w, "schedule_strategy",        config->tiles.pack.schedule_strategy );
      jw_str_arr( &w, "account_blocklist", config->tiles.pack.account_blocklist[ 0 ], sizeof(config->tiles.pack.account_blocklist[ 0 ]), config->tiles.pack.account_blocklist_cnt );
    jw_obj_close( &w );
    jw_obj_open( &w, "poh" );
      jw_bool( &w, "lagged_consecutive_leader_start", config->tiles.pohh.lagged_consecutive_leader_start );
    jw_obj_close( &w );
    jw_obj_open( &w, "shred" );
      jw_ulong( &w, "max_pending_shred_sets", config->tiles.shred.max_pending_shred_sets );
      jw_ulong( &w, "shred_listen_port",      config->tiles.shred.shred_listen_port );
      jw_path_arr( &w, "additional_shred_destinations_retransmit", config->tiles.shred.additional_shred_destinations_retransmit_cnt );
      jw_path_arr( &w, "additional_shred_destinations_leader",     config->tiles.shred.additional_shred_destinations_leader_cnt );
      jw_ulong( &w, "shred_cache_size_mib",   config->tiles.shred.shred_cache_size_mib );
    jw_obj_close( &w );
    jw_obj_open( &w, "metric" );
      jw_path ( &w, "prometheus_listen_address", config->tiles.metric.prometheus_listen_address );
      jw_ulong( &w, "prometheus_listen_port",    config->tiles.metric.prometheus_listen_port );
    jw_obj_close( &w );
    jw_obj_open( &w, "event" );
      jw_url( &w, "url", config->tiles.event.url );
    jw_obj_close( &w );
    jw_obj_open( &w, "gui" );
      jw_bool ( &w, "enabled",                   config->tiles.gui.enabled );
      jw_path ( &w, "gui_listen_address",        config->tiles.gui.gui_listen_address );
      jw_ulong( &w, "gui_listen_port",           config->tiles.gui.gui_listen_port );
      jw_ulong( &w, "max_http_connections",      config->tiles.gui.max_http_connections );
      jw_ulong( &w, "max_websocket_connections", config->tiles.gui.max_websocket_connections );
      jw_ulong( &w, "max_http_request_length",   config->tiles.gui.max_http_request_length );
      jw_ulong( &w, "send_buffer_size_mb",       config->tiles.gui.send_buffer_size_mb );
      jw_ulong( &w, "db_size_gib",               config->tiles.gui.db_size_gib );
    jw_obj_close( &w );
    jw_obj_open( &w, "rpc" );
      jw_bool ( &w, "enabled",                   config->tiles.rpc.enabled );
      jw_path ( &w, "rpc_listen_address",        config->tiles.rpc.rpc_listen_address );
      jw_ulong( &w, "rpc_listen_port",           config->tiles.rpc.rpc_listen_port );
      jw_ulong( &w, "max_http_connections",      config->tiles.rpc.max_http_connections );
      jw_ulong( &w, "max_websocket_connections", config->tiles.rpc.max_websocket_connections );
      jw_ulong( &w, "max_http_request_length",   config->tiles.rpc.max_http_request_length );
      jw_ulong( &w, "send_buffer_size_mb",       config->tiles.rpc.send_buffer_size_mb );
      jw_bool ( &w, "delay_startup",             config->tiles.rpc.delay_startup );
    jw_obj_close( &w );
    jw_obj_open( &w, "repair" );
      jw_ulong( &w, "repair_client_listen_port", config->tiles.repair.repair_client_listen_port );
      jw_ulong( &w, "slot_max",                  config->tiles.repair.slot_max );
    jw_obj_close( &w );
    jw_obj_open( &w, "rotor" );
      jw_ulong( &w, "slot_max",                  config->tiles.rotor.slot_max );
    jw_obj_close( &w );
    jw_obj_open( &w, "rserve" );
      jw_bool ( &w, "enabled",                   config->tiles.rserve.enabled );
      jw_ulong( &w, "repair_serve_listen_port",  config->tiles.rserve.repair_serve_listen_port );
      jw_ulong( &w, "shred_storage_limit_gib",   config->tiles.rserve.shred_storage_limit_gib );
    jw_obj_close( &w );
    jw_obj_open( &w, "replay" );
      jw_ulong( &w, "max_transaction_lookahead_buffer_size", config->tiles.replay.max_transaction_lookahead_buffer_size );
      jw_str_arr( &w, "enable_features", config->tiles.replay.enable_features[ 0 ], sizeof(config->tiles.replay.enable_features[ 0 ]), config->tiles.replay.enable_features_cnt );
    jw_obj_close( &w );
  jw_obj_close( &w );

  jw_obj_open( &w, "capture" );
    jw_ulong( &w, "capture_start_slot",           config->capture.capture_start_slot );
    jw_path ( &w, "dump_proto_dir",               config->capture.dump_proto_dir );
    jw_path ( &w, "dump_syscall_name_filter",     config->capture.dump_syscall_name_filter );
    jw_str  ( &w, "dump_instr_program_id_filter", config->capture.dump_instr_program_id_filter );
    jw_path ( &w, "solcap_capture",               config->capture.solcap_capture );
    jw_bool ( &w, "recent_only",                  config->capture.recent_only );
    jw_ulong( &w, "recent_slots_per_file",        config->capture.recent_slots_per_file );
    jw_bool ( &w, "dump_syscall_to_pb",           config->capture.dump_syscall_to_pb );
    jw_bool ( &w, "dump_instr_to_pb",             config->capture.dump_instr_to_pb );
    jw_bool ( &w, "dump_txn_to_pb",               config->capture.dump_txn_to_pb );
    jw_bool ( &w, "dump_txn_as_fixture",          config->capture.dump_txn_as_fixture );
    jw_bool ( &w, "dump_block_to_pb",             config->capture.dump_block_to_pb );
  jw_obj_close( &w );

  jw_obj_open( &w, "capctx" );
    jw_path( &w, "path", f->capctx.path );
  jw_obj_close( &w );


  jw_raw( &w, "}" );

  if( FD_UNLIKELY( w.fail ) ) FD_LOG_ERR(( "config json does not fit in %lu bytes", buf_sz ));
  return (ulong)( w.cur-buf );
}
