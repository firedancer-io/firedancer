#include "fd_prometheus.h"

#include "fd_metrics.h"

#include "../topo/fd_topo.h"
#include "../../ballet/http/fd_http_server.h"

#define PRINT_LINK_IN  (0)
#define PRINT_LINK_OUT (1)
#define PRINT_TILE     (2)

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
      
      /* FIXME: This is O(n^2) rather than O(n). */
      if( FD_LIKELY( tile_name!=NULL && strcmp( tile->name, tile_name ) ) ) continue;

      if( FD_LIKELY( metric->type==FD_METRICS_TYPE_COUNTER || metric->type==FD_METRICS_TYPE_GAUGE ) ) {
        if( FD_LIKELY( print_mode==PRINT_TILE ) ) {
          ulong value = *(fd_metrics_tile( tile->metrics ) + metric->offset);
          fd_http_server_printf( http, "%s{kind=\"%s\",kind_id=\"%lu\"} %lu\n", metric->name, tile->name, tile->kind_id, value );
        } else {
          if( FD_LIKELY( print_mode==PRINT_LINK_IN ) ) {
            ulong polled_in_idx = 0UL;
            for( ulong k=0UL; k<tile->in_cnt; k++ ) {
              if( FD_UNLIKELY( !tile->in_link_poll[ k ] ) ) continue;

              fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ k ] ];
              ulong value = *(fd_metrics_link_in( tile->metrics, polled_in_idx ) + metric->offset );
              switch( metric->converter ) {
                case FD_METRICS_CONVERTER_NANOSECONDS:
                  value = fd_metrics_convert_ticks_to_nanoseconds( value );
                  break;
                case FD_METRICS_CONVERTER_NONE:
                  break;
                default:
                  FD_LOG_ERR(( "unknown converter %i", metric->converter ));
              }
              fd_http_server_printf( http, "%s{kind=\"%s\",kind_id=\"%lu\",link_kind=\"%s\",link_kind_id=\"%lu\"} %lu\n", metric->name, tile->name, tile->kind_id, link->name, link->kind_id, value );
              polled_in_idx++;
            }
          } else if( FD_LIKELY( print_mode==PRINT_LINK_OUT ) ) {
            ulong reliable_conns_idx = 0UL;
            for( ulong k=0UL; k<topo->tile_cnt; k++ ) {
              fd_topo_tile_t const * consumer_tile = &topo->tiles[ k ];
              for( ulong l=0UL; l<consumer_tile->in_cnt; l++ ) {
                for( ulong m=0UL; m<tile->out_cnt; m++ ) {
                  if( FD_UNLIKELY( consumer_tile->in_link_id[ l ]==tile->out_link_id[ m ] && consumer_tile->in_link_reliable[ l ] ) ) {
                    fd_topo_link_t const * link = &topo->links[ consumer_tile->in_link_id[ l ] ];

                    ulong value = *(fd_metrics_link_out( tile->metrics, reliable_conns_idx ) + metric->offset );
                    switch( metric->converter ) {
                      case FD_METRICS_CONVERTER_NANOSECONDS:
                        value = fd_metrics_convert_ticks_to_nanoseconds( value );
                        break;
                      case FD_METRICS_CONVERTER_NONE:
                        break;
                      default:
                        FD_LOG_ERR(( "unknown converter %i", metric->converter ));
                    }
                    fd_http_server_printf( http, "%s{kind=\"%s\",kind_id=\"%lu\",link_kind=\"%s\",link_kind_id=\"%lu\"} %lu\n", metric->name, tile->name, tile->kind_id, link->name, link->kind_id, value );
                    reliable_conns_idx++;
                  }
                }
              }
            }
          }
        }
      } else if( FD_LIKELY( metric->type==FD_METRICS_TYPE_HISTOGRAM ) ) {
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

          char * le;
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
          fd_http_server_printf( http, "%s_bucket{kind=\"%s\",kind_id=\"%lu\",le=\"%s\"} %s\n", metric->name, tile->name, tile->kind_id, le, value_str );
        }

        char sum_str[ 64 ];
        if( FD_LIKELY( metric->converter==FD_METRICS_CONVERTER_SECONDS ) ) {
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
