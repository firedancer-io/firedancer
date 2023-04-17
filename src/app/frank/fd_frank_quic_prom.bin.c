#include "fd_frank.h"
#include "../../tango/quic/fd_quic.h"
#include "../../disco/quic/fd_quic.h"

#if FD_HAS_FRANK

/**********************************************************************/
/* This app scrapes periodically scrapes metrics from each QUIC tile, and writes these to
   a file in the Prometheus metric format. */

#include <stdio.h>

/**********************************************************************/

/* snap reads all the QUIC diagnostics in a frank instance and stores
   them into the easy to process structure snap */

struct snap {
  ulong quic_seq;
  ulong quic_chunk_idx;
  ulong quic_tpu_publish_txns_total;
  ulong quic_tpu_publish_bytes_total;
  ulong quic_net_rx_packets_total;
  ulong quic_net_tx_packets_total;
  long quic_active_conns;
  ulong quic_created_conns_total;
  ulong quic_closed_conns_total_graceful;
  ulong quic_closed_conns_total_aborted;
  ulong quic_closed_conns_total_no_free_slots;
  ulong quic_closed_conns_total_tls_fail;
  ulong quic_opened_streams_total_bidi_client;
  ulong quic_opened_streams_total_bidi_server;
  ulong quic_opened_streams_total_uni_client;
  ulong quic_opened_streams_total_uni_server;
  ulong quic_closed_streams_total_bidi_client;
  ulong quic_closed_streams_total_bidi_server;
  ulong quic_closed_streams_total_uni_client;
  ulong quic_closed_streams_total_uni_server;
  int quic_active_streams_bidi_client;
  int quic_active_streams_bidi_server;
  int quic_active_streams_uni_client;
  int quic_active_streams_uni_server;
  ulong quic_stream_rx_events_total;
  ulong quic_stream_rx_bytes_total;
};

typedef struct snap snap_t;

static void
snap( ulong             tile_cnt,     /* Number of QUIC tiles to snapshot */
      snap_t *          snap_cur,     /* Snaphot for each QUIC tile, indexed [0,tile_cnt) */
      fd_cnc_t **       tile_cnc,     /* Local cnc    joins for each QUIC tile, NULL if n/a, indexed [0,tile_cnt) */
      fd_frag_meta_t ** tile_mcache,  /* Local mcache joins for each QUIC tile, NULL if n/a, indexed [0,tile_cnt) */
      fd_quic_t **      tile_quic ) { /* Local QUIC   joins for each QUIC tile, NULL if n/a, indexed [0,tile_cnt) */

  for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
    snap_t * snap = &snap_cur[ tile_idx ];

    fd_frag_meta_t const * mcache = tile_mcache[ tile_idx ];
    if( FD_LIKELY( mcache ) ) {
      ulong const * seq = (ulong const *)fd_mcache_seq_laddr_const( mcache );
      snap->quic_seq = fd_mcache_seq_query( seq );
    }

    fd_cnc_t const * cnc = tile_cnc[ tile_idx ];
    if( FD_LIKELY( cnc ) ) {
      ulong const * cnc_diag = (ulong const *)fd_cnc_app_laddr_const( cnc );
      FD_COMPILER_MFENCE();
      snap->quic_chunk_idx               = cnc_diag[ FD_QUIC_CNC_DIAG_CHUNK_IDX    ];
      snap->quic_tpu_publish_txns_total  = cnc_diag[ FD_QUIC_CNC_DIAG_TPU_PUB_CNT    ];
      snap->quic_tpu_publish_bytes_total = cnc_diag[ FD_QUIC_CNC_DIAG_TPU_PUB_SZ    ];
      FD_COMPILER_MFENCE();
    }

    fd_quic_t const * quic = tile_quic[ tile_idx ];
    if( FD_LIKELY( quic ) ) {
      snap->quic_net_rx_packets_total             = quic->metrics.net_rx_pkt_cnt;
      snap->quic_net_tx_packets_total             = quic->metrics.net_tx_pkt_cnt;
      snap->quic_active_conns                     = quic->metrics.conn_active_cnt;
      snap->quic_created_conns_total              = quic->metrics.conn_created_cnt;
      snap->quic_closed_conns_total_graceful      = quic->metrics.conn_closed_cnt;
      snap->quic_closed_conns_total_aborted       = quic->metrics.conn_aborted_cnt;
      snap->quic_closed_conns_total_no_free_slots = quic->metrics.conn_err_no_slots_cnt;
      snap->quic_closed_conns_total_tls_fail      = quic->metrics.conn_err_tls_fail_cnt;
      snap->quic_opened_streams_total_bidi_client = quic->metrics.stream_opened_cnt[ FD_QUIC_STREAM_TYPE_BIDI_CLIENT ];
      snap->quic_opened_streams_total_bidi_server = quic->metrics.stream_opened_cnt[ FD_QUIC_STREAM_TYPE_BIDI_SERVER ];
      snap->quic_opened_streams_total_uni_client  = quic->metrics.stream_opened_cnt[ FD_QUIC_STREAM_TYPE_UNI_CLIENT ];
      snap->quic_opened_streams_total_uni_server  = quic->metrics.stream_opened_cnt[ FD_QUIC_STREAM_TYPE_UNI_SERVER ];
      snap->quic_closed_streams_total_bidi_client = quic->metrics.stream_closed_cnt[ FD_QUIC_STREAM_TYPE_BIDI_CLIENT ];
      snap->quic_closed_streams_total_bidi_server = quic->metrics.stream_closed_cnt[ FD_QUIC_STREAM_TYPE_BIDI_SERVER ];
      snap->quic_closed_streams_total_uni_client  = quic->metrics.stream_closed_cnt[ FD_QUIC_STREAM_TYPE_UNI_CLIENT ];
      snap->quic_closed_streams_total_uni_server  = quic->metrics.stream_closed_cnt[ FD_QUIC_STREAM_TYPE_UNI_SERVER ];
      snap->quic_active_streams_bidi_client       = quic->metrics.stream_active_cnt[ FD_QUIC_STREAM_TYPE_BIDI_CLIENT ];
      snap->quic_active_streams_bidi_server       = quic->metrics.stream_active_cnt[ FD_QUIC_STREAM_TYPE_BIDI_SERVER ];
      snap->quic_active_streams_uni_client        = quic->metrics.stream_active_cnt[ FD_QUIC_STREAM_TYPE_UNI_CLIENT ];
      snap->quic_active_streams_uni_server        = quic->metrics.stream_active_cnt[ FD_QUIC_STREAM_TYPE_UNI_SERVER ];
      snap->quic_stream_rx_events_total           = quic->metrics.stream_rx_event_cnt;
      snap->quic_stream_rx_bytes_total            = quic->metrics.stream_rx_byte_cnt;
    }

  }
}

/**********************************************************************/

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Parse command line arguments */

  char const * pod_gaddr =       fd_env_strip_cmdline_cstr  ( &argc, &argv, "--pod",      NULL, NULL                 );
  char const * cfg_path  =       fd_env_strip_cmdline_cstr  ( &argc, &argv, "--cfg",      NULL, NULL                 );
  char const * out_path  =       fd_env_strip_cmdline_cstr  ( &argc, &argv, "--out",      NULL, NULL                 );
  long         dt_min    = (long)fd_env_strip_cmdline_double( &argc, &argv, "--dt-min",   NULL,   66666667.          );
  long         dt_max    = (long)fd_env_strip_cmdline_double( &argc, &argv, "--dt-max",   NULL, 1333333333.          );
  long         duration  = (long)fd_env_strip_cmdline_double( &argc, &argv, "--duration", NULL,          0.          );
  uint         seed      =       fd_env_strip_cmdline_uint  ( &argc, &argv, "--seed",     NULL, (uint)fd_tickcount() );

  if( FD_UNLIKELY( !pod_gaddr   ) ) FD_LOG_ERR(( "--pod not specified"                  ));
  if( FD_UNLIKELY( !cfg_path    ) ) FD_LOG_ERR(( "--cfg not specified"                  ));
  if( FD_UNLIKELY( !out_path    ) ) FD_LOG_ERR(( "--out not specified"                  ));
  if( FD_UNLIKELY( dt_min<0L    ) ) FD_LOG_ERR(( "--dt-min should be positive"          ));
  if( FD_UNLIKELY( dt_max<dt_min) ) FD_LOG_ERR(( "--dt-max should be at least --dt-min" ));
  if( FD_UNLIKELY( duration<0L  ) ) FD_LOG_ERR(( "--duration should be non-negative"    ));

  /* Load up the configuration */

  FD_LOG_INFO(( "using configuration in pod --pod %s at path --cfg %s", pod_gaddr, cfg_path ));

  uchar const * pod     = fd_wksp_pod_attach( pod_gaddr );
  uchar const * cfg_pod = fd_pod_query_subpod( pod, cfg_path );
  if( FD_UNLIKELY( !cfg_pod ) ) FD_LOG_ERR(( "path not found" ));

  uchar const * quic_pods = fd_pod_query_subpod( cfg_pod, "quic" );
  ulong quic_cnt = fd_pod_cnt_subpod( quic_pods );
  FD_LOG_INFO(( "%lu quic found", quic_cnt ));

  /* We are only monitoring QUIC tiles */
  ulong tile_cnt = quic_cnt;

  /* Join all IPC objects */
  char const **     tile_name   = fd_alloca( alignof(char const *    ), sizeof(char const *    )*tile_cnt );
  fd_cnc_t **       tile_cnc    = fd_alloca( alignof(fd_cnc_t *      ), sizeof(fd_cnc_t *      )*tile_cnt );
  fd_frag_meta_t ** tile_mcache = fd_alloca( alignof(fd_frag_meta_t *), sizeof(fd_frag_meta_t *)*tile_cnt );
  fd_quic_t **      tile_quic   = fd_alloca( alignof(fd_quic_t *     ), sizeof(fd_quic_t *         )*tile_cnt );
  if( FD_UNLIKELY( (!tile_name) | (!tile_cnc) | (!tile_mcache) | (!tile_quic) ) ) FD_LOG_ERR(( "fd_alloca failed" )); /* paranoia */

  do {
    ulong tile_idx = 0UL;

    for( fd_pod_iter_t iter = fd_pod_iter_init( quic_pods ); !fd_pod_iter_done( iter ); iter = fd_pod_iter_next( iter ) ) {
      fd_pod_info_t info = fd_pod_iter_info( iter );
      if( FD_UNLIKELY( info.val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) continue;
      char const  * quic_name =                info.key;
      uchar const * quic_pod  = (uchar const *)info.val;

      FD_LOG_INFO(( "joining %s.quic.%s.cnc", cfg_path, quic_name ));
      tile_name[ tile_idx ] = quic_name;
      tile_cnc [ tile_idx ] = fd_cnc_join( fd_wksp_pod_map( quic_pod, "cnc" ) );
      if( FD_UNLIKELY( !tile_cnc[tile_idx] ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
      if( FD_UNLIKELY( fd_cnc_app_sz( tile_cnc[ tile_idx ] )<64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));

      FD_LOG_INFO(( "joining %s.quic.%s.mcache", cfg_path, quic_name ));
      tile_mcache[ tile_idx ] = fd_mcache_join( fd_wksp_pod_map( quic_pod, "mcache" ) );
      if( FD_UNLIKELY( !tile_mcache[ tile_idx ] ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));

      FD_LOG_INFO(( "joining %s.quic.%s.quic", cfg_path, quic_name ));
      tile_quic[ tile_idx ] = fd_quic_join( fd_wksp_pod_map( quic_pod, "quic" ) );
      if( FD_UNLIKELY( !tile_quic[ tile_idx ] ) ) { FD_LOG_ERR(( "fd_quic_join failed" )); }

      tile_idx++;
    }
  } while(0);

  /* Setup local objects used by this app */
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );

  snap_t * snap_prv = (snap_t *)fd_alloca( alignof(snap_t), sizeof(snap_t)*2UL*tile_cnt );
  if( FD_UNLIKELY( !snap_prv ) ) FD_LOG_ERR(( "fd_alloca failed" )); /* Paranoia */
  snap_t * snap_cur = snap_prv + tile_cnt;

  /* Get the inital reference diagnostic snapshot */

  snap( tile_cnt, snap_prv, tile_cnc, tile_mcache, tile_quic );
  long then; long tic; fd_tempo_observe_pair( &then, &tic );

  /* Monitor for duration ns.  Note that for duration==0, this
     will still do exactly one pretty print. */

  FD_LOG_NOTICE(( "monitoring --dt-min %li ns, --dt-max %li ns, --duration %li ns, --seed %u", dt_min, dt_max, duration, seed ));

  long stop = then + duration;
  for(;;) {

    /* Wait a somewhat randomized amount and then make a diagnostic
       snapshot */

    fd_log_wait_until( then + dt_min + (long)fd_rng_ulong_roll( rng, 1UL+(ulong)(dt_max-dt_min) ) );

    snap( tile_cnt, snap_cur, tile_cnc, tile_mcache, tile_quic );
    long now; long toc; fd_tempo_observe_pair( &now, &toc );

    /* Write the snapshot out to a file using the Promethesus metrics format */
      FILE * out_file = fopen ( out_path , "w" );
      if ( !out_file ) {
        FD_LOG_ERR(( "opening out_file failed" ));
      }

      fprintf( out_file, "# HELP firedancer_quic_seq publish mcache sequence number of QUIC tile\n" );
      fprintf( out_file, "# TYPE firedancer_quic_seq gauge\n" );
      for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
        fprintf( out_file, "firedancer_quic_seq{tile=\"%s\"} %lu\n", tile_name[ tile_idx ], snap_cur[ tile_idx ].quic_seq );
      }

      fprintf( out_file, "# HELP firedancer_quic_chunk_idx publish dcache chunk index of QUIC tile\n" );
      fprintf( out_file, "# TYPE firedancer_quic_chunk_idx gauge\n" );
      for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
        fprintf( out_file, "firedancer_quic_chunk_idx{tile=\"%s\"} %lu\n", tile_name[ tile_idx ], snap_cur[ tile_idx ].quic_chunk_idx );
      }

      fprintf( out_file, "# HELP firedancer_quic_tpu_publish_txns_total Number of TPU txns published by QUIC tile\n" );
      fprintf( out_file, "# TYPE firedancer_quic_tpu_publish_txns_total counter\n" );
      for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
        fprintf( out_file, "firedancer_quic_tpu_publish_txns_total{tile=\"%s\"} %lu\n", tile_name[ tile_idx ], snap_cur[ tile_idx ].quic_tpu_publish_txns_total );
      }

      fprintf( out_file, "# HELP firedancer_quic_tpu_publish_bytes_total Cumulative byte size of TPU txns published by QUIC tile\n" );
      fprintf( out_file, "# TYPE firedancer_quic_tpu_publish_bytes_total counter\n" );
      for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
        fprintf( out_file, "firedancer_quic_tpu_publish_bytes_total{tile=\"%s\"} %lu\n", tile_name[ tile_idx ], snap_cur[ tile_idx ].quic_tpu_publish_bytes_total );
      }

      fprintf( out_file, "# HELP firedancer_quic_net_rx_packets_total Number of packets received by QUIC tile\n" );
      fprintf( out_file, "# TYPE firedancer_quic_net_rx_packets_total counter\n" );
      for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
        fprintf( out_file, "firedancer_quic_net_rx_packets_total{tile=\"%s\"} %lu\n", tile_name[ tile_idx ], snap_cur[ tile_idx ].quic_net_rx_packets_total );
      }

      fprintf( out_file, "# HELP firedancer_quic_net_tx_packets_total Number of packets sent by QUIC tile\n" );
      fprintf( out_file, "# TYPE firedancer_quic_net_tx_packets_total counter\n" );
      for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
        fprintf( out_file, "firedancer_quic_net_tx_packets_total{tile=\"%s\"} %lu\n", tile_name[ tile_idx ], snap_cur[ tile_idx ].quic_net_tx_packets_total );
      }

      fprintf( out_file, "# HELP firedancer_quic_active_conns Number of active QUIC connections\n" );
      fprintf( out_file, "# TYPE firedancer_quic_active_conns gauge\n" );
      for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
        fprintf( out_file, "firedancer_quic_active_conns{tile=\"%s\"} %ld\n", tile_name[ tile_idx ], snap_cur[ tile_idx ].quic_active_conns );
      }

      fprintf( out_file, "# HELP firedancer_quic_created_conns_total Number of QUIC connections created\n" );
      fprintf( out_file, "# TYPE firedancer_quic_created_conns_total counter\n" );
      for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
        fprintf( out_file, "firedancer_quic_created_conns_total{tile=\"%s\"} %lu\n", tile_name[ tile_idx ], snap_cur[ tile_idx ].quic_created_conns_total );
      }

      fprintf( out_file, "# HELP firedancer_quic_closed_conns_total Number of QUIC connections closed\n" );
      fprintf( out_file, "# TYPE firedancer_quic_closed_conns_total counter\n" );
      for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
        fprintf( out_file, "firedancer_quic_closed_conns_total{tile=\"%s\",reason=\"graceful\"} %lu\n", tile_name[ tile_idx ], snap_cur[ tile_idx ].quic_closed_conns_total_graceful );
        fprintf( out_file, "firedancer_quic_closed_conns_total{tile=\"%s\",reason=\"aborted\"} %lu\n", tile_name[ tile_idx ], snap_cur[ tile_idx ].quic_closed_conns_total_aborted );
        fprintf( out_file, "firedancer_quic_closed_conns_total{tile=\"%s\",reason=\"no_free_slots\"} %lu\n", tile_name[ tile_idx ], snap_cur[ tile_idx ].quic_closed_conns_total_no_free_slots );
        fprintf( out_file, "firedancer_quic_closed_conns_total{tile=\"%s\",reason=\"no_free_slots\"} %lu\n", tile_name[ tile_idx ], snap_cur[ tile_idx ].quic_closed_conns_total_tls_fail );
      }

      fprintf( out_file, "# HELP firedancer_quic_opened_streams_total Number of QUIC streams opened\n" );
      fprintf( out_file, "# TYPE firedancer_quic_opened_streams_total counter\n" );
      for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
        fprintf( out_file, "firedancer_quic_opened_streams_total{tile=\"%s\",reason=\"bidi_client\"} %lu\n", tile_name[ tile_idx ], snap_cur[ tile_idx ].quic_opened_streams_total_bidi_client );
        fprintf( out_file, "firedancer_quic_opened_streams_total{tile=\"%s\",reason=\"bidi_server\"} %lu\n", tile_name[ tile_idx ], snap_cur[ tile_idx ].quic_opened_streams_total_bidi_server );
        fprintf( out_file, "firedancer_quic_opened_streams_total{tile=\"%s\",reason=\"uni_client\"} %lu\n", tile_name[ tile_idx ], snap_cur[ tile_idx ].quic_opened_streams_total_uni_client );
        fprintf( out_file, "firedancer_quic_opened_streams_total{tile=\"%s\",reason=\"uni_server\"} %lu\n", tile_name[ tile_idx ], snap_cur[ tile_idx ].quic_opened_streams_total_uni_server );
      }

      fprintf( out_file, "# HELP firedancer_quic_active_streams Number of active QUIC streams\n" );
      fprintf( out_file, "# TYPE firedancer_quic_active_streams gauge\n" );
      for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
        fprintf( out_file, "firedancer_quic_active_streams{tile=\"%s\",reason=\"bidi_client\"} %d\n", tile_name[ tile_idx ], snap_cur[ tile_idx ].quic_active_streams_bidi_client );
        fprintf( out_file, "firedancer_quic_active_streams{tile=\"%s\",reason=\"bidi_server\"} %d\n", tile_name[ tile_idx ], snap_cur[ tile_idx ].quic_active_streams_bidi_server );
        fprintf( out_file, "firedancer_quic_active_streams{tile=\"%s\",reason=\"uni_client\"} %d\n", tile_name[ tile_idx ], snap_cur[ tile_idx ].quic_active_streams_uni_client );
        fprintf( out_file, "firedancer_quic_active_streams{tile=\"%s\",reason=\"uni_server\"} %d\n", tile_name[ tile_idx ], snap_cur[ tile_idx ].quic_active_streams_uni_server );
      }

      fprintf( out_file, "# HELP firedancer_quic_stream_rx_events_total Number of QUIC stream receive events\n" );
      fprintf( out_file, "# TYPE firedancer_quic_stream_rx_events_total counter\n" );
      for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
        fprintf( out_file, "firedancer_quic_stream_rx_events_total{tile=\"%s\"} %lu\n", tile_name[ tile_idx ], snap_cur[ tile_idx ].quic_stream_rx_events_total );
      }

      fprintf( out_file, "# HELP firedancer_quic_stream_rx_bytes_total Number of bytes received via QUIC streams\n" );
      fprintf( out_file, "# TYPE firedancer_quic_stream_rx_bytes_total counter\n" );
      for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
        fprintf( out_file, "firedancer_quic_stream_rx_bytes_total{tile=\"%s\"} %lu\n", tile_name[ tile_idx ], snap_cur[ tile_idx ].quic_stream_rx_bytes_total );
      }

      fclose (out_file);


    /* Stop once we've been monitoring for duration ns */

    if( FD_UNLIKELY( (now-stop)>=0L ) ) break;

    /* Still more monitoring to do ... wind up for the next iteration by
       swaping the two snap arrays. */

    then = now; tic = toc;
    snap_t * tmp = snap_prv; snap_prv = snap_cur; snap_cur = tmp;
  }

  /* Monitoring done ... clean up */

  FD_LOG_NOTICE(( "cleaning up" ));
  fd_rng_delete( fd_rng_leave( rng ) );
  for( ulong tile_idx=tile_cnt; tile_idx; tile_idx-- ) {
    if( FD_LIKELY( tile_quic  [ tile_idx-1UL ] ) ) fd_wksp_pod_unmap( tile_quic[ tile_idx-1UL ] );
    if( FD_LIKELY( tile_mcache[ tile_idx-1UL ] ) ) fd_wksp_pod_unmap( fd_mcache_leave( tile_mcache[ tile_idx-1UL ] ) );
    if( FD_LIKELY( tile_cnc   [ tile_idx-1UL ] ) ) fd_wksp_pod_unmap( fd_cnc_leave   ( tile_cnc   [ tile_idx-1UL ] ) );
  }
  fd_wksp_pod_detach( pod );
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_ERR(( "unsupported for this build target" ));
  fd_halt();
  return 0;
}

#endif

