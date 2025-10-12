#include "../fd_config.h"
#include "../fd_action.h"

#include "../../../disco/metrics/fd_prometheus.h"
#include "../../../waltz/http/fd_http_server_private.h"

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

extern action_t * ACTIONS[];

static void
metrics_cmd_args( int *    pargc,
                  char *** pargv,
                  args_t * args ) {
  char const * topo_name = fd_env_strip_cmdline_cstr( pargc, pargv, "--topo", NULL, "" );

  ulong topo_name_len = strlen( topo_name );
  if( FD_UNLIKELY( topo_name_len > sizeof(args->metrics.topo)-1 ) ) FD_LOG_ERR(( "Unknown --topo %s", topo_name ));
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( args->metrics.topo ), topo_name, topo_name_len ) );
}

static void
reconstruct_topo( config_t *   config,
                  char const * topo_name ) {
  if( !topo_name[0] ) return; /* keep default action topo */

  action_t const * selected = NULL;
  for( action_t ** a=ACTIONS; a; a++ ) {
    action_t const * action = *a;
    if( 0==strcmp( action->name, topo_name ) ) {
      selected = action;
      break;
    }
  }

  if( !selected       ) FD_LOG_ERR(( "Unknown --topo %s", topo_name ));
  if( !selected->topo ) FD_LOG_ERR(( "Cannot recover topology for --topo %s", topo_name ));

  selected->topo( config );
}

static void
metrics_cmd_fn( args_t *   args,
                config_t * config ) {
  reconstruct_topo( config, args->metrics.topo );

  fd_http_server_params_t params = {
    .max_connection_cnt    = 0UL,
    .max_ws_connection_cnt = 0UL,
    .max_request_len       = 0UL,
    .max_ws_recv_frame_len = 0UL,
    .max_ws_send_frame_cnt = 0UL,
    .outgoing_buffer_sz    = (1UL<<28UL), /* 256MiB */
  };

  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_ONLY );
  fd_topo_fill( &config->topo );

  void * mem = aligned_alloc( fd_http_server_align(), fd_http_server_footprint( params ) );
  FD_TEST( mem );
  fd_http_server_t * http = fd_http_server_new( mem, params, (fd_http_server_callbacks_t){0}, NULL );
  fd_prometheus_render_all( &config->topo, http );

  ulong bytes_written;
  int err = fd_io_write( STDOUT_FILENO, http->oring, http->stage_len, http->stage_len, &bytes_written );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "write(STDOUT_FILENO,metrics,...) failed: %i-%s", err, fd_io_strerror( err ) ));
  }
}

action_t fd_action_metrics = {
  .name          = "metrics",
  .args          = metrics_cmd_args,
  .fn            = metrics_cmd_fn,
  .perm          = NULL,
  .description   = "Print the current validator Prometheus metrics to STDOUT",
  .is_immediate  = 0,
  .is_diagnostic = 1,
};
