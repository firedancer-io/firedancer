#include "fd_prometheus.h"

#include "fd_metrics.h"

#include "../topo/fd_topo.h"
#include "../../waltz/http/fd_http_server.h"

struct fd_prom_render {
  fd_http_server_t * http;
  ulong              last_name_hash;
};

typedef struct fd_prom_render fd_prom_render_t;

fd_prom_render_t
fd_prom_render_create( fd_http_server_t * http ) {
  return (fd_prom_render_t) {
    .http           = http,
    .last_name_hash = 0UL
  };
}

static void
render_header( fd_prom_render_t *        r,
               fd_metrics_meta_t const * metric ) {
  /* Only render header once per metric name */
  ulong hash = fd_cstr_hash( metric->name );
  if( r->last_name_hash != hash ) {
    if( r->last_name_hash ) {
      fd_http_server_printf( r->http, "\n" );
    }
    fd_http_server_printf( r->http, "# HELP %s %s\n# TYPE %s %s\n", metric->name, metric->desc, metric->name, fd_metrics_meta_type_str( metric ) );
    r->last_name_hash = hash;
  }
}

static void
render_link( fd_prom_render_t *        r,
             fd_metrics_meta_t const * metric,
             fd_topo_tile_t const *    tile,
             fd_topo_link_t const *    link,
             ulong                     value ) {
  render_header( r, metric );
  switch( metric->converter ) {
  case FD_METRICS_CONVERTER_NANOSECONDS:
    value = fd_metrics_convert_ticks_to_nanoseconds( value );
    break;
  case FD_METRICS_CONVERTER_NONE:
    break;
  default:
    FD_LOG_ERR(( "unknown converter %i", metric->converter ));
  }
  fd_http_server_printf( r->http, "%s{kind=\"%s\",kind_id=\"%lu\",link_kind=\"%s\",link_kind_id=\"%lu\"} %lu\n", metric->name, tile->name, tile->kind_id, link->name, link->kind_id, value );
}

static void
render_histogram( fd_prom_render_t *        r,
                  fd_metrics_meta_t const * metric,
                  fd_topo_tile_t const *    tile ) {
  render_header( r, metric );

  fd_histf_t hist[1];
  if( FD_LIKELY( metric->converter==FD_METRICS_CONVERTER_SECONDS ) )
    FD_TEST( fd_histf_new( hist, fd_metrics_convert_seconds_to_ticks( metric->histogram.seconds.min ), fd_metrics_convert_seconds_to_ticks ( metric->histogram.seconds.max ) ) );
  else if( FD_LIKELY( metric->converter==FD_METRICS_CONVERTER_NONE ) )
    FD_TEST( fd_histf_new( hist, metric->histogram.none.min, metric->histogram.none.max ) );
  else FD_LOG_ERR(( "unknown converter %i", metric->converter ));

  ulong value = 0;
  char value_str[ 64 ];
  for( ulong k=0; k<FD_HISTF_BUCKET_CNT; k++ ) {
    value += *(fd_metrics_tile( tile->metrics ) + metric->offset + k);

    char * le; /* le here means "less then or equal" not "left edge" */
    char le_str[ 64 ];
    if( FD_UNLIKELY( k==FD_HISTF_BUCKET_CNT-1UL ) ) le = "+Inf";
    else {
      ulong edge = fd_histf_right( hist, k );
      if( FD_LIKELY( metric->converter==FD_METRICS_CONVERTER_SECONDS ) ) {
        double edgef = fd_metrics_convert_ticks_to_seconds( edge-1 );
        FD_TEST( fd_cstr_printf_check( le_str, sizeof( le_str ), NULL, "%.17g", edgef ) );
      } else {
        FD_TEST( fd_cstr_printf_check( le_str, sizeof( le_str ), NULL, "%lu", edge-1 ) );
      }
      le = le_str;
    }

    FD_TEST( fd_cstr_printf_check( value_str, sizeof( value_str ), NULL, "%lu", value ));
    fd_http_server_printf( r->http, "%s_bucket{kind=\"%s\",kind_id=\"%lu\",le=\"%s\"} %s\n", metric->name, tile->name, tile->kind_id, le, value_str );
  }

  char sum_str[ 64 ];
  if( FD_LIKELY( metric->converter==FD_METRICS_CONVERTER_SECONDS ) ) {
    double sumf = fd_metrics_convert_ticks_to_seconds( *(fd_metrics_tile( tile->metrics ) + metric->offset + FD_HISTF_BUCKET_CNT) );
    FD_TEST( fd_cstr_printf_check( sum_str, sizeof( sum_str ), NULL, "%.17g", sumf ) );
  } else {
    FD_TEST( fd_cstr_printf_check( sum_str, sizeof( sum_str ), NULL, "%lu", *(fd_metrics_tile( tile->metrics ) + metric->offset + FD_HISTF_BUCKET_CNT) ));
  }

  fd_http_server_printf( r->http, "%s_sum{kind=\"%s\",kind_id=\"%lu\"} %s\n", metric->name, tile->name, tile->kind_id, sum_str );
  fd_http_server_printf( r->http, "%s_count{kind=\"%s\",kind_id=\"%lu\"} %s\n", metric->name, tile->name, tile->kind_id, value_str );
}

static void
render_counter( fd_prom_render_t *        r,
                fd_metrics_meta_t const * metric,
                fd_topo_tile_t const *    tile ) {
  render_header( r, metric );
  ulong value = *(fd_metrics_tile( tile->metrics ) + metric->offset);

  switch( metric->converter ) {
    case FD_METRICS_CONVERTER_NANOSECONDS:
      value = fd_metrics_convert_ticks_to_nanoseconds( value );
      break;
    case FD_METRICS_CONVERTER_SECONDS:
      value = (ulong)(fd_metrics_convert_ticks_to_seconds( value ) + 0.5); /* round, not truncate */
      break;
    case FD_METRICS_CONVERTER_NONE:
      break;
    default:
      FD_LOG_ERR(( "unknown converter %i", metric->converter ));
  }

  fd_http_server_printf( r->http, "%s{kind=\"%s\",kind_id=\"%lu\"", metric->name, tile->name, tile->kind_id );
  if( metric->enum_name ) {
    fd_http_server_printf( r->http, ",%s=\"%s\"", metric->enum_name, metric->enum_variant );
  }
  fd_http_server_printf( r->http, "} %lu\n", value );
}

static void
render_links_in( fd_prom_render_t *        r,
                 fd_topo_t const *         topo,
                 ulong                     metrics_cnt,
                 fd_metrics_meta_t const * metrics ) {
  for( ulong i=0UL; i<metrics_cnt; i++ ) {
    fd_metrics_meta_t const * metric = &metrics[ i ];
    for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
      fd_topo_tile_t const * tile = &topo->tiles[ j ];
      ulong polled_in_idx = 0UL;
      for( ulong k=0UL; k<tile->in_cnt; k++ ) {
        if( FD_UNLIKELY( !tile->in_link_poll[ k ] ) ) continue;
        fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ k ] ];
        ulong value = *(fd_metrics_link_in( tile->metrics, polled_in_idx ) + metric->offset );
        render_link( r, metric, tile, link, value );
        polled_in_idx++;
      }
    }
  }
}

static void
render_tile_metric( fd_prom_render_t *        r,
                    fd_topo_tile_t const *    tile,
                    fd_metrics_meta_t const * metric ) {
  if( FD_LIKELY( metric->type==FD_METRICS_TYPE_COUNTER || metric->type==FD_METRICS_TYPE_GAUGE ) ) {
    render_counter( r, metric, tile );
  } else if( FD_LIKELY( metric->type==FD_METRICS_TYPE_HISTOGRAM ) ) {
    render_histogram( r, metric, tile );
  }
}

static void
render_tile( fd_prom_render_t *        r,
             fd_topo_t const *         topo,
             char const *              tile_name,
             ulong                     metrics_cnt,
             fd_metrics_meta_t const * metrics ) {
  for( ulong i=0UL; i<metrics_cnt; i++ ) {
    for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
      /* FIXME: This is O(n^2) rather than O(n). */
      char const * name = topo->tiles[ j ].metrics_name[ 0 ] ? topo->tiles[ j ].metrics_name : topo->tiles[ j ].name;
      if( FD_LIKELY( tile_name!=NULL && 0!=strcmp( name, tile_name ) ) ) continue;
      render_tile_metric( r, topo->tiles+j, metrics+i );
    }
  }
}

void
fd_prometheus_render_tile( fd_http_server_t *        http,
                           fd_topo_tile_t const *    tile,
                           fd_metrics_meta_t const * metrics,
                           ulong                     metrics_cnt ) {
  fd_prom_render_t r = fd_prom_render_create( http );
  for( ulong i=0UL; i<metrics_cnt; i++ ) {
    render_tile_metric( &r, tile, metrics+i );
  }
}

void
fd_prometheus_render_all( fd_topo_t const *  topo,
                          fd_http_server_t * http ) {
  fd_prom_render_t r = fd_prom_render_create( http );
  render_tile( &r, topo, NULL, FD_METRICS_ALL_TOTAL, FD_METRICS_ALL );
  render_links_in( &r, topo, FD_METRICS_ALL_LINK_IN_TOTAL, FD_METRICS_ALL_LINK_IN );
  for( ulong i=0UL; i<FD_METRICS_TILE_KIND_CNT; i++ ) {
    render_tile( &r, topo, FD_METRICS_TILE_KIND_NAMES[ i ], FD_METRICS_TILE_KIND_SIZES[ i ], FD_METRICS_TILE_KIND_METRICS[ i ] );
  }
}
