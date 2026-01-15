#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"
#include "../../../disco/metrics/fd_metrics.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern action_t * ACTIONS[];

static int running = 1;

static void
exit_signal( int sig FD_PARAM_UNUSED ) {
  running = 0;
}

static void
metrics_record_cmd_args( int *    pargc,
                         char *** pargv,
                         args_t * args ) {

  if( fd_env_strip_cmdline_contains( pargc, pargv, "--help" ) ||
      fd_env_strip_cmdline_contains( pargc, pargv, "-h" )     ||
      fd_env_strip_cmdline_contains( pargc, pargv, "help" ) ) {
    fputs(
      "\nUsage: firedancer-dev metrics-record [GLOBAL FLAGS] [FLAGS] metric0 metric1 ... metricN\n"
      "\n"
      "Flags:\n"
      "  --topo TOPO          Attach to metrics of non-standard topo, such as snapshot-load\n"
      "  --interval SECONDS   How frequently to print a row. Defaults to 1.0 seconds.\n"
      "\n"
      "Metrics:\n"
      "  Selector format: `metric_name[,tile_kind[,tile_kind_id]]`\n"
      "\n"
      "  Metrics are primarily identified by their name string.  A tile kind string can also\n"
      "  be given to limit the given metric to only one specific tile type.  Similarly, a\n"
      "  tile kind id can be given (only if tile_kind is also given) to limit to a particular\n"
      "  tile instance.  If these tile kind filters are not given, all matching metrics will\n"
      "  be recorded.\n"
      "\n"
      "  Examples:\n"
      "    tile_pid\n"
      "    tile_backpressure_count,gossip\n"
      "    tile_status,net,1\n"
      "\n",
      stderr );
    exit( EXIT_SUCCESS );
  }

  fd_memset( &args->metrics_record, 0, sizeof(args->metrics_record) );
  fd_cstr_ncpy( args->metrics_record.topo, fd_env_strip_cmdline_cstr( pargc, pargv, "--topo", NULL, "" ), sizeof(args->metrics_record.topo) );

  float _interval = fd_env_strip_cmdline_float( pargc, pargv, "--interval", NULL, 1.0f );
  args->metrics_record.interval_ns = fd_ulong_max( 1UL, (ulong)(_interval*1.0e9f) );

  ulong const selectors_cnt_max = sizeof(args->metrics_record.selectors)/sizeof(args->metrics_record.selectors[0]);
  while( *pargc ) {
    if( FD_UNLIKELY( args->metrics_record.selectors_cnt>=selectors_cnt_max ) ) FD_LOG_ERR(( "too many metric selectors given %lu", selectors_cnt_max ));
    struct fd_action_metrics_record_selector * selector = &args->metrics_record.selectors[ args->metrics_record.selectors_cnt++ ];

    char * name = *pargv[ 0 ];
    char * kind = strchr( name, ',' );
    char * kind_id = NULL;
    if( kind!=NULL ) {
      fd_cstr_fini( kind );
      kind += 1;
      kind_id = strchr( kind, ',' );
      if( kind_id!=NULL ) {
        fd_cstr_fini( kind_id );
        kind_id += 1;
        if( FD_UNLIKELY( NULL!=strchr( kind_id, ',' ) ) ) FD_LOG_ERR(( "invalid metric selector %s %s %s", name, kind, kind_id ));
      }
    }
    *pargc -= 1;
    *pargv += 1;

    if( FD_UNLIKELY( NULL==name || strlen( name )>=sizeof(selector->name)) ) FD_LOG_ERR(( "invalid metric selector name %s", name ));
    fd_cstr_ncpy( selector->name, name, sizeof(selector->name) );
    if( FD_UNLIKELY( NULL!=kind && strlen( kind )>=sizeof(selector->kind)) ) FD_LOG_ERR(( "invalid metric selector kind %s", kind ));
    fd_cstr_ncpy( selector->kind, kind, sizeof(selector->kind) );
    selector->kind_id = NULL==kind_id ? ULONG_MAX : fd_cstr_to_ulong( kind_id );
  }
}

static int
selector_matches( struct fd_action_metrics_record_selector const * selector,
                  char const *                                     metric_name,
                  char const *                                     tile_name,
                  ulong                                            tile_id ) {
  if( 0!=strcmp( metric_name, selector->name ) ) return 0;
  if( selector->kind[ 0 ] && 0!=strcmp( tile_name, selector->kind ) ) return 0;
  if( ULONG_MAX!=selector->kind_id && tile_id!=selector->kind_id ) return 0;
  return 1;
}

static void
reconstruct_topo( fd_config_t * config,
                  char const *  topo_name ) {
  if( !topo_name[0] ) return; /* keep default action topo */

  action_t const * selected = NULL;
  for( action_t ** a=ACTIONS; a!=NULL; a++ ) {
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
metrics_record_cmd_fn( args_t *      args,
                       fd_config_t * config ) {

  struct sigaction sa = { .sa_handler = exit_signal };
  if( FD_UNLIKELY( sigaction( SIGTERM, &sa, NULL ) ) ) FD_LOG_ERR(( "sigaction(SIGTERM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( sigaction( SIGINT,  &sa, NULL ) ) ) FD_LOG_ERR(( "sigaction(SIGINT) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  reconstruct_topo( config, args->metrics_record.topo );

  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  fd_topo_fill( &config->topo );

  uchar write_buf[ 4096 ];
  fd_io_buffered_ostream_t out[1];
  FD_TEST( out==fd_io_buffered_ostream_init( out, STDOUT_FILENO, write_buf, sizeof(write_buf) ) );

  fd_io_buffered_ostream_write( out, "timestamp", 9 );

  ulong metrics_cnt = 0UL;
  struct {
    fd_metrics_meta_t const * meta;
    volatile ulong const *    value;
  } metrics[ 4096 ];

  for( ulong i=0UL; i<FD_METRICS_ALL_TOTAL; i++ ) {
    fd_metrics_meta_t const * metric = &FD_METRICS_ALL[ i ];
    if( metric->type!=FD_METRICS_TYPE_GAUGE && metric->type!=FD_METRICS_TYPE_COUNTER ) continue;
    for( ulong j=0UL; j<config->topo.tile_cnt; j++ ) {
      fd_topo_tile_t const * tile      = &config->topo.tiles[ j ];
      char const *           tile_name = tile->metrics_name[ 0 ] ? tile->metrics_name : tile->name;
      for( ulong s=0UL; s<args->metrics_record.selectors_cnt; s++ ) {
        if( FD_LIKELY( !selector_matches( &args->metrics_record.selectors[ s ], metric->name, tile_name, tile->kind_id ) ) ) continue;
        if( FD_UNLIKELY( metrics_cnt>=(sizeof(metrics)/sizeof(metrics[0])) ) ) FD_LOG_ERR(( "too many metrics %lu", metrics_cnt ));
        metrics[ metrics_cnt ].meta  = metric;
        metrics[ metrics_cnt ].value = fd_metrics_tile( tile->metrics ) + metric->offset;
        ++metrics_cnt;

        char buf[ 1024 ];
        char * p = fd_cstr_append_printf( fd_cstr_init( buf ), ",%s{kind=%s kind_id=%lu", metric->name, tile->name, tile->kind_id );
        if( metric->enum_name ) p = fd_cstr_append_printf( p, " %s=%s", metric->enum_name, metric->enum_variant );
        p = fd_cstr_append_char( p, '}' );
        fd_io_buffered_ostream_write( out, buf, (ulong)(p-buf) );
        break;
      }
    }
  }

  /* TODO: Add support for in/out link metrics */

  for( ulong i=0UL; i<FD_METRICS_TILE_KIND_CNT; i++ ) {
    for( ulong j=0UL; j<FD_METRICS_TILE_KIND_SIZES[ i ]; j++ ) {
      fd_metrics_meta_t const * metric = &FD_METRICS_TILE_KIND_METRICS[ i ][ j ];
      if( metric->type!=FD_METRICS_TYPE_GAUGE && metric->type!=FD_METRICS_TYPE_COUNTER ) continue;
      for( ulong k=0UL; k<config->topo.tile_cnt; k++ ) {
        fd_topo_tile_t const * tile      = &config->topo.tiles[ k ];
        char const *           tile_name = tile->metrics_name[ 0 ] ? tile->metrics_name : tile->name;
        if( 0!=strcmp( tile_name, FD_METRICS_TILE_KIND_NAMES[ i ] ) ) continue;
        for( ulong s=0UL; s<args->metrics_record.selectors_cnt; s++ ) {
          if( FD_LIKELY( !selector_matches( &args->metrics_record.selectors[ s ], metric->name, tile_name, tile->kind_id ) ) ) continue;
          if( FD_UNLIKELY( metrics_cnt>=(sizeof(metrics)/sizeof(metrics[0])) ) ) FD_LOG_ERR(( "too many metrics %lu", metrics_cnt ));
          metrics[ metrics_cnt ].meta  = metric;
          metrics[ metrics_cnt ].value = fd_metrics_tile( tile->metrics ) + metric->offset;
          ++metrics_cnt;

          char buf[ 1024 ];
          char * p = fd_cstr_append_printf( fd_cstr_init( buf ), ",%s{kind=%s kind_id=%lu", metric->name, tile->name, tile->kind_id );
          if( metric->enum_name ) p = fd_cstr_append_printf( p, " %s=%s", metric->enum_name, metric->enum_variant );
          p = fd_cstr_append_char( p, '}' );
          fd_io_buffered_ostream_write( out, buf, (ulong)(p-buf) );
          break;
        }
      }
    }
  }

  if( FD_UNLIKELY( metrics_cnt==0UL ) ) FD_LOG_ERR(( "no matching metrics found" ));
  fd_io_buffered_ostream_write( out, "\n", 1 );
  fd_io_buffered_ostream_flush( out );

  ulong count = 0UL, skip = 0UL;
  long const start = fd_log_wallclock();
  long const interval = (long)args->metrics_record.interval_ns;
  long next = ((start/interval)*interval)+interval;
  while( running ) {
    long now = fd_log_wait_until( next );
    for( next+=interval; next<=now; next+=interval ) skip++;

    char * const b = fd_io_buffered_ostream_peek( out );
    char * const e = b + fd_io_buffered_ostream_peek_sz( out );
    char * p = b;
    if( FD_UNLIKELY( e-p<=20L ) ) FD_LOG_ERR(( "increase write buffer size" ));
    p = fd_cstr_append_ulong_as_text( p, ' ', '\0', (ulong)now, fd_ulong_base10_dig_cnt( (ulong)now ) );

    for( ulong i=0UL; i<metrics_cnt; i++ ) {
      ulong value = *metrics[ i ].value;
      switch( metrics[ i ].meta->converter ) {
        case FD_METRICS_CONVERTER_NANOSECONDS: value = fd_metrics_convert_ticks_to_nanoseconds( value ); break;
        case FD_METRICS_CONVERTER_SECONDS:     value = (ulong)(fd_metrics_convert_ticks_to_seconds( value ) + 0.5); /* round, not truncate */ break;
        case FD_METRICS_CONVERTER_NONE: break;
        default: FD_LOG_ERR(( "unknown converter %i", metrics[ i ].meta->converter ));
      }
      if( FD_UNLIKELY( e-p<=22L ) ) FD_LOG_ERR(( "increase write buffer size" ));
      p = fd_cstr_append_char( p, ',' );
      p = fd_cstr_append_ulong_as_text( p, ' ', '\0', value, fd_ulong_base10_dig_cnt( value ) );
    }
    p = fd_cstr_append_char( p, '\n' );
    fd_io_buffered_ostream_seek( out, (ulong)(p-b) );
    fd_io_buffered_ostream_flush( out );
    count++;
  }

  FD_LOG_NOTICE(( "recorded %lu samples in %f seconds", count, (double)(fd_log_wallclock()-start)/1.0e9 ));
  if( skip ) FD_LOG_WARNING(( "skipped %lu samples, try reducing metric count or increasing interval", skip ));

  fd_io_buffered_ostream_flush( out );
  fd_io_buffered_ostream_fini( out );

  fd_topo_leave_workspaces( &config->topo );
}

action_t fd_action_metrics_record = {
  .name          = "metrics-record",
  .description   = "Continuously print a select subset of metrics to STDOUT in CSV format",
  .is_diagnostic = 1,
  .args          = metrics_record_cmd_args,
  .fn            = metrics_record_cmd_fn,
};
