#include "../../shared/fd_config.h"
#include "../../shared/commands/run/run.h"
#include "../../../disco/tiles.h"
#include "../../../disco/topo/fd_topob.h"

#include <unistd.h> /* pause */

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

static void
bundle_client_topo( config_t *   config ) {
  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );

  fd_topob_wksp( topo, "metric_in" );

  /* Tiles */

  fd_topob_wksp( topo, "bundle" );
  fd_topo_tile_t * bundle_tile = fd_topob_tile( topo, "bundle", "bundle", "metric_in", ULONG_MAX, 0, 1 );

  fd_topob_wksp( topo, "sign" );
  fd_topo_tile_t * sign_tile = fd_topob_tile( topo, "sign", "sign", "metric_in", ULONG_MAX, 0, 1 );

  fd_topob_wksp( topo, "metric" );
  fd_topo_tile_t * metric_tile = fd_topob_tile( topo, "metric", "metric", "metric_in", ULONG_MAX, 0, 0 );

  /* Links */

  fd_topob_link( topo, "bundle_verif", "bundle", config->tiles.verify.receive_buffer_size, FD_TPU_PARSED_MTU, 1UL )
    ->permit_no_consumers = 1;
  fd_topob_link( topo, "bundle_sign",  "bundle", 65536UL,  9UL, 1UL );
  fd_topob_link( topo, "sign_bundle",  "bundle", 128UL,   64UL, 1UL );

  fd_topob_tile_out( topo, "bundle", 0UL, "bundle_verif", 0UL );
  fd_topob_tile_out( topo, "bundle", 0UL, "bundle_sign", 0UL );
  fd_topob_tile_out( topo, "sign", 0UL, "sign_bundle", 0UL );
  fd_topob_tile_in( topo, "bundle", 0UL, "metric_in", "sign_bundle", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  fd_topob_tile_in( topo, "sign", 0UL, "metric_in", "bundle_sign", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );

  /* Tile config */

  strncpy( bundle_tile->bundle.url, config->tiles.bundle.url, sizeof(bundle_tile->bundle.url) );
  bundle_tile->bundle.url_len = strnlen( config->tiles.bundle.url, 255 );
  strncpy( bundle_tile->bundle.sni, config->tiles.bundle.tls_domain_name, 256 );
  bundle_tile->bundle.sni_len = strnlen( config->tiles.bundle.tls_domain_name, 255 );
  strncpy( bundle_tile->bundle.identity_key_path, config->paths.identity_key, sizeof(bundle_tile->bundle.identity_key_path) );
  strncpy( bundle_tile->bundle.key_log_path, config->development.bundle.ssl_key_log_file, sizeof(bundle_tile->bundle.key_log_path) );
  bundle_tile->bundle.buf_sz = config->development.bundle.buffer_size_kib<<10;
  bundle_tile->bundle.ssl_heap_sz = config->development.bundle.ssl_heap_size_mib<<20;
  bundle_tile->bundle.keepalive_interval_nanos = config->tiles.bundle.keepalive_interval_millis * (ulong)1e6;
  bundle_tile->bundle.tls_cert_verify = !!config->tiles.bundle.tls_cert_verify;

  strncpy( sign_tile->sign.identity_key_path, config->paths.identity_key, sizeof(sign_tile->sign.identity_key_path) );

  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.metric.prometheus_listen_address, &metric_tile->metric.prometheus_listen_addr ) ) )
    FD_LOG_ERR(( "failed to parse prometheus listen address `%s`", config->tiles.metric.prometheus_listen_address ));
  metric_tile->metric.prometheus_listen_port = config->tiles.metric.prometheus_listen_port;

  /* Wrap up */

  fd_topob_finish( topo, CALLBACKS );
  fd_topo_print_log( /* stdout */ 1, topo );
}

static void
bundle_client_cmd_args( int *    pargc,
                        char *** pargv,
                        args_t * args ) {
  (void)pargc; (void)pargv; (void)args;
}

static void
bundle_client_cmd_fn( args_t *   args,
                      config_t * config ) {
  (void)args;
  fd_topo_t * topo = &config->topo;
  bundle_client_topo( config );
  initialize_workspaces( config );
  initialize_stacks( config );
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topo_run_single_process( topo, 2, config->uid, config->gid, fdctl_tile_run );

  for(;;) pause();
}

action_t fd_action_bundle_client = {
  .name          = "bundle-client",
  .args          = bundle_client_cmd_args,
  .fn            = bundle_client_cmd_fn,
  .perm          = NULL,
  .description   = "Run the bundle tile in isolation",
  .is_diagnostic = 1 /* allow running against live clusters */
};
