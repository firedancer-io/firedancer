#include "fd_prometheus.h"

#include "../topo/fd_topo.h"

#include "../../ballet/http/fd_http_server.h"

#define PRINT_LINK_IN  (0)
#define PRINT_LINK_OUT (1)
#define PRINT_TILE     (2)

static ulong
find_producer_out_idx( fd_topo_t const *      topo,
                       fd_topo_tile_t const * producer,
                       fd_topo_tile_t const * consumer,
                       ulong                  consumer_in_idx ) {
  /* This finds all reliable consumers of the producers primary output,
     and then returns the position of the consumer (specified by tile
     and index of the in of that tile) in that list. The list ordering
     is not important, except that it matches the ordering of fseqs
     provided to the mux tile, so that metrics written for each link
     index are retrieved at the same index here.

     This is why we only count reliable links, because the mux tile only
     looks at and writes producer side diagnostics (is the link slow)
     for reliable links. */

  ulong count = 0UL;
  for( ulong i=0; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * consumer_tile = &topo->tiles[ i ];
    for( ulong j=0; j<consumer_tile->in_cnt; j++ ) {
      if( FD_UNLIKELY( consumer_tile->in_link_id[ j ] == producer->out_link_id_primary && consumer_tile->in_link_reliable[ j ] ) ) {
        if( FD_UNLIKELY( consumer==consumer_tile && consumer_in_idx==j ) ) return count;
        count++;
      }
    }
  }
  return ULONG_MAX;
}

static void
prometheus_print1( fd_topo_t const *         topo,
                   fd_http_server_t *        http,
                   char const *              tile_name,
                   ulong                     metrics_cnt,
                   fd_metrics_meta_t const * metrics,
                   int                       print_mode ) {
  for( ulong i=0UL; i<metrics_cnt; i++ ) {
    fd_metrics_meta_t const * metric = &metrics[ i ];
    fd_http_server_printf( http, "# HELP %s %s\n# TYPE %s %s\n", metric->name, metric->desc, metric->name, fd_metrics_meta_type_str( metric ) );

    for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
      fd_topo_tile_t const * tile = &topo->tiles[ j ];
      if( FD_LIKELY( tile_name!=NULL && strcmp( tile->name, tile_name ) ) ) continue;

      if( FD_LIKELY( metric->type==FD_METRICS_TYPE_COUNTER || metric->type==FD_METRICS_TYPE_GAUGE ) ) {
        if( FD_LIKELY( print_mode==PRINT_TILE ) ) {
          ulong value = *(fd_metrics_tile( tile->metrics ) + metric->offset);
          fd_http_server_printf( http, "%s{kind=\"%s\",kind_id=\"%lu\"} %lu\n", metric->name, tile->name, tile->kind_id, value );
        } else {
          if( FD_LIKELY( print_mode==PRINT_LINK_IN ) ) {
            for( ulong k=0; k<tile->in_cnt; k++ ) {
              fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ k ] ];
              ulong value = *(fd_metrics_link_in( tile->metrics, k ) + metric->offset );
              fd_http_server_printf( http, "%s{kind=\"%s\",kind_id=\"%lu\",link_kind=\"%s\",link_kind_id=\"%lu\"} %lu\n", metric->name, tile->name, tile->kind_id, link->name, link->kind_id, value );
            }
          } else if( FD_LIKELY( print_mode==PRINT_LINK_OUT ) ) {
            for( ulong k=0; k<tile->in_cnt; k++ ) {
              fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ k ] ];
              if( FD_UNLIKELY( !tile->in_link_reliable[ k ] ) ) continue;

              ulong producer_idx = fd_topo_find_link_producer( topo, link );
              if( FD_UNLIKELY( producer_idx==ULONG_MAX ) ) continue;
              
              fd_topo_tile_t const * producer = &topo->tiles[ producer_idx ];
              if( FD_UNLIKELY( producer->out_link_id_primary!=link->id ) ) continue;

              /* This index needs to line up with what the mux tile thinks the index is
                 of that tile in its consumer list. */
              ulong producer_out_idx = find_producer_out_idx( topo, producer, tile, k );
              ulong value = *(fd_metrics_link_out( producer->metrics, producer_out_idx ) + metric->offset );

              fd_http_server_printf( http, "%s{kind=\"%s\",kind_id=\"%lu\",link_kind=\"%s\",link_kind_id=\"%lu\"} %lu\n", metric->name, tile->name, tile->kind_id, link->name, link->kind_id, value );
            }
          }
        }
      } else if( FD_LIKELY( metric->type==FD_METRICS_TYPE_HISTOGRAM ) ) {
        fd_histf_t hist[1];
        if( FD_LIKELY( metric->histogram.converter==FD_METRICS_CONVERTER_SECONDS ) )
          FD_TEST( fd_histf_new( hist, fd_metrics_convert_seconds_to_ticks( metric->histogram.seconds.min ), fd_metrics_convert_seconds_to_ticks ( metric->histogram.seconds.max ) ) );
        else if( FD_LIKELY( metric->histogram.converter==FD_METRICS_CONVERTER_NONE ) )
          FD_TEST( fd_histf_new( hist, metric->histogram.none.min, metric->histogram.none.max ) );
        else FD_LOG_ERR(( "unknown histogram converter %i", metric->histogram.converter ));

        ulong value = 0;
        char value_str[ 64 ];
        for( ulong k=0; k<FD_HISTF_BUCKET_CNT; k++ ) {
          value += *(fd_metrics_tile( tile->metrics ) + metric->offset + k);

          char * le;
          char le_str[ 64 ];
          if( FD_UNLIKELY( k==FD_HISTF_BUCKET_CNT-1UL ) ) le = "+Inf";
          else {
            ulong edge = fd_histf_right( hist, k );
            if( FD_LIKELY( metric->histogram.converter==FD_METRICS_CONVERTER_SECONDS ) ) {
              double edgef = fd_metrics_convert_ticks_to_seconds( edge-1 );
              FD_TEST( fd_cstr_printf_check( le_str, sizeof( le_str ), NULL, "%.17g", edgef ) );
            } else {
              FD_TEST( fd_cstr_printf_check( le_str, sizeof( le_str ), NULL, "%lu", edge-1 ) );
            }
            le = le_str;
          }

          FD_TEST( fd_cstr_printf_check( value_str, sizeof( value_str ), NULL, "%lu", value ));
          fd_http_server_printf( http, "%s_bucket{kind=\"%s\",kind_id=\"%lu\",le=\"%s\"} %s\n", metric->name, tile->name, tile->kind_id, le, value_str );
        }

        char sum_str[ 64 ];
        if( FD_LIKELY( metric->histogram.converter==FD_METRICS_CONVERTER_SECONDS ) ) {
          double sumf = fd_metrics_convert_ticks_to_seconds( *(fd_metrics_tile( tile->metrics ) + metric->offset + FD_HISTF_BUCKET_CNT) );
          FD_TEST( fd_cstr_printf_check( sum_str, sizeof( sum_str ), NULL, "%.17g", sumf ) );
        } else {
          FD_TEST( fd_cstr_printf_check( sum_str, sizeof( sum_str ), NULL, "%lu", *(fd_metrics_tile( tile->metrics ) + metric->offset + FD_HISTF_BUCKET_CNT) ));
        }

        fd_http_server_printf( http, "%s_sum{kind=\"%s\",kind_id=\"%lu\"} %s\n", metric->name, tile->name, tile->kind_id, sum_str );
        fd_http_server_printf( http, "%s_count{kind=\"%s\",kind_id=\"%lu\"} %s\n", metric->name, tile->name, tile->kind_id, value_str );
      }
    }

    if( FD_LIKELY( i!=metrics_cnt-1 ) ) fd_http_server_printf( http, "\n" );
  }
}

void
fd_prometheus_format( fd_topo_t const *  topo,
                      fd_http_server_t * http ) {
  prometheus_print1( topo, http, NULL, FD_METRICS_ALL_TOTAL, FD_METRICS_ALL, PRINT_TILE );
  fd_http_server_printf( http, "\n" );
  prometheus_print1( topo, http, NULL, FD_METRICS_ALL_LINK_IN_TOTAL, FD_METRICS_ALL_LINK_IN, PRINT_LINK_IN );
  fd_http_server_printf( http, "\n" );
  prometheus_print1( topo, http, NULL, FD_METRICS_ALL_LINK_OUT_TOTAL, FD_METRICS_ALL_LINK_OUT, PRINT_LINK_OUT );

  for( ulong i=0UL; i<FD_METRICS_TILE_KIND_CNT; i++ ) {
    fd_http_server_printf( http, "\n" );
    prometheus_print1( topo, http, FD_METRICS_TILE_KIND_NAMES[ i ], FD_METRICS_TILE_KIND_SIZES[ i ], FD_METRICS_TILE_KIND_METRICS[ i ], PRINT_TILE );
  }
}
