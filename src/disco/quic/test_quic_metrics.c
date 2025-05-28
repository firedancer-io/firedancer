#include "../metrics/fd_metrics.h"
#include "../metrics/fd_prometheus.h"
#include "../metrics/generated/fd_metrics_quic.h"
#include "../../waltz/http/fd_http_server_private.h"
#include <stdio.h> /* puts, fwrite */
#include <stdlib.h> /* aligned_alloc, free */

FD_IMPORT_BINARY( metrics_fixture, "src/disco/quic/test_quic_metrics.txt" );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Make test deterministic */
  fd_tempo_set_tick_per_ns( 1UL, 0UL );

  fd_http_server_params_t params = {
    .max_connection_cnt    = 1UL,
    .max_ws_connection_cnt = 0UL,
    .max_request_len       = 1024,
    .max_ws_recv_frame_len = 2048,
    .max_ws_send_frame_cnt = 100,
    .outgoing_buffer_sz    = 100000UL
  };

  fd_http_server_callbacks_t callbacks = {0};

  uchar * http_mem = aligned_alloc( fd_http_server_align(), fd_http_server_footprint( params ) );
  fd_http_server_t * http = fd_http_server_join( fd_http_server_new( http_mem, params, callbacks, NULL ) );

  void * metric_mem = aligned_alloc( FD_METRICS_ALIGN, FD_METRICS_FOOTPRINT( 0, 0 ) );
  ulong * metrics = fd_metrics_join( fd_metrics_new( metric_mem, 0, 0 ) );

  /* Write some fake metric values */
  ulong volatile * tile_metrics = fd_metrics_tile( metrics );
  for( ulong j=0UL; j<(FD_METRICS_TOTAL_SZ>>3); j++ ) {
    tile_metrics[j] = j;
  }

  fd_topo_tile_t tile = { .name="quic", .metrics=metrics };
  fd_prometheus_render_tile( http, &tile, FD_METRICS_QUIC, FD_METRICS_QUIC_TOTAL );

  fd_http_server_response_t resp = {0};
  FD_TEST( fd_http_server_stage_body( http, &resp )==0 );

  /* FIXME hacky */
  char const * body     = (char const *)http->oring + resp._body_off;
  ulong        body_len = resp._body_len;

  puts( "\"\"\"" );
  fwrite( body, 1, body_len, stdout );
  puts( "\"\"\"" );

  if( FD_UNLIKELY( metrics_fixture_sz!=body_len || !fd_memeq( body, metrics_fixture, metrics_fixture_sz ) ) ) {
    FILE * f = fopen( "src/disco/quic/test_quic_metrics.txt", "w" );
    fwrite( body, 1, body_len, f );
    fclose( f );
    FD_LOG_ERR(( "Metrics didn't match. Updated src/disco/quic/test_quic_metrics.txt" ));
  }

  free( fd_metrics_delete( fd_metrics_leave( metrics ) ) );
  free( fd_http_server_delete( fd_http_server_leave( http ) ) );

  fd_halt();
  return 0;
}
