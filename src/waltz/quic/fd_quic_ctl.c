#include "fd_quic.h"

FD_IMPORT_CSTR( fd_quic_ctl_help, "src/waltz/quic/fd_quic_ctl_help" );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

# define SHIFT(n) argv+=(n),argc-=(n)

  if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "no arguments" ));
  char const * bin = argv[0];
  SHIFT(1);

  ulong tag = 1UL;

  int cnt = 0;
  while( argc ) {
    char const * cmd = argv[0];
    SHIFT(1);

    if( 0==strcmp( cmd, "help" ) ) {

      fputs( fd_quic_ctl_help, stdout );

      FD_LOG_NOTICE(( "%i: %s: success", cnt, cmd ));

    } else if( 0==strcmp( cmd, "new-quic" ) ) {

      /* TODO only read args up to next command */
      fd_quic_limits_t limits = {0};
      fd_quic_limits_from_env( &argc, &argv, &limits );

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _wksp = argv[0];

      ulong align     = fd_quic_align();
      ulong footprint = fd_quic_footprint( &limits );
      if( FD_UNLIKELY( !footprint ) )
        FD_LOG_ERR(( "%i: %s: invalid params\n\tDo %s help for help", cnt, cmd, bin ));

      fd_wksp_t * wksp = fd_wksp_attach( _wksp );
      if( FD_UNLIKELY( !wksp ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_attach( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _wksp, bin ));

      ulong gaddr = fd_wksp_alloc( wksp, align, footprint, tag );
      if( FD_UNLIKELY( !gaddr ) ) {
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_alloc( \"%s\", %lu, %lu, %lu ) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, align, footprint, tag, bin ));
      }

      void * shmem = fd_wksp_laddr( wksp, gaddr );
      if( FD_UNLIKELY( !shmem ) ) {
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_laddr( \"%s\", %lu ) failed\n\tDo %s help for help", cnt, cmd, _wksp, gaddr, bin ));
      }

      void * shquic = fd_quic_new( shmem, &limits );
      if( FD_UNLIKELY( !shquic ) ) {
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_quic_new failed\n\tDo %s help for help",
                     cnt, cmd, bin ));
      }

      char buf[ FD_WKSP_CSTR_MAX ];
      printf( "%s\n", fd_wksp_cstr( wksp, gaddr, buf ) );

      fd_wksp_detach( wksp );

      FD_LOG_NOTICE(( "%i: %s %s"
                      " --quic-conns %lu"
                      " --quic-conn-ids %lu"
                      " --quic-streams %lu"
                      " --quic-handshakes %lu"
                      " --quic-inflight-pkts %lu"
                      " --quic-tx-buf-sz %lu"
                      ": success",
                      cnt, cmd, _wksp,
                      limits.conn_cnt,
                      limits.conn_id_cnt,
                      limits.stream_cnt[ FD_QUIC_STREAM_TYPE_UNI_CLIENT ],
                      limits.handshake_cnt,
                      limits.inflight_pkt_cnt,
                      limits.tx_buf_sz ));
      SHIFT( 1 );

    } else if( 0==strcmp( cmd, "delete-quic" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * gaddr = argv[0];

      void * _quic = fd_wksp_map( gaddr );
      if( FD_UNLIKELY( !_quic ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, gaddr, bin ));
      fd_quic_delete( _quic );
      fd_wksp_unmap( _quic );

      fd_wksp_cstr_free( gaddr );

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, gaddr ));
      SHIFT( 1 );

    } else if( 0==strcmp( cmd, "metrics" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * gaddr = argv[0];

      void * _quic = fd_wksp_map( gaddr );
      if( FD_UNLIKELY( !_quic ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, gaddr, bin ));

      fd_quic_t * quic = fd_quic_join( _quic );
      if( FD_UNLIKELY( !quic ) ) {
        fd_wksp_unmap( _quic );
        FD_LOG_ERR(( "%i: %s: fd_quic_join( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, gaddr, bin ));
      }

      /* Copy metrics from tile.  Ensure that reads are done such that
         they are atomic at ulong alignment. */

      FD_COMPILER_MFENCE();
      fd_quic_metrics_t metrics[1];
      for( ulong i=0UL; i < sizeof(metrics)/8UL; i++ )
        metrics->ul[ i ] = FD_VOLATILE_CONST( quic->metrics.ul[ i ] );
      FD_COMPILER_MFENCE();

      /* Display metrics */

      printf( "Metrics for QUIC tile %s\n", gaddr );
      printf( "\n\t  net_rx_pkt_cnt          %20lu"
              "\n\t  net_rx_byte_cnt         %20lu"
              "\n\t  net_tx_pkt_cnt          %20lu"
              "\n\t  net_tx_byte_cnt         %20lu"
              "\n",
              metrics->net_rx_pkt_cnt,
              metrics->net_rx_byte_cnt,
              metrics->net_tx_pkt_cnt,
              metrics->net_tx_byte_cnt );

      printf( "\n\t  conn_active_cnt         %20ld"
              "\n\t  conn_created_cnt        %20lu"
              "\n\t  conn_closed_cnt         %20lu"
              "\n\t  conn_aborted_cnt        %20lu"
              "\n\t  conn_retry_cnt          %20lu"
              "\n",
              metrics->conn_active_cnt,
              metrics->conn_created_cnt,
              metrics->conn_closed_cnt,
              metrics->conn_aborted_cnt,
              metrics->conn_retry_cnt );

      printf( "\n\t  conn_err_no_slots_cnt   %20lu"
              "\n\t  conn_err_tls_fail_cnt   %20lu"
              "\n\t  conn_err_retry_fail_cnt %20lu"
              "\n",
              metrics->conn_err_no_slots_cnt,
              metrics->conn_err_tls_fail_cnt,
              metrics->conn_err_retry_fail_cnt );

      printf( "\n\t  hs_created_cnt          %20lu"
              "\n\t  hs_err_alloc_fail_cnt   %20lu"
              "\n",
              metrics->hs_created_cnt,
              metrics->hs_err_alloc_fail_cnt );

      printf( "\n\t  stream_opened_cnt       %20lu"
              "\n\t  stream_closed_cnt       %20lu"
              "\n\t  stream_active_cnt       %20lu"
              "\n\t  stream_rx_event_cnt     %20lu"
              "\n\t  stream_rx_byte_cnt      %20lu"
              "\n",

                metrics->stream_opened_cnt[0]
              + metrics->stream_opened_cnt[1]
              + metrics->stream_opened_cnt[2]
              + metrics->stream_opened_cnt[3],

                metrics->stream_closed_cnt[0]
              + metrics->stream_closed_cnt[1]
              + metrics->stream_closed_cnt[2]
              + metrics->stream_closed_cnt[3],

                metrics->stream_active_cnt[0]
              + metrics->stream_active_cnt[1]
              + metrics->stream_active_cnt[2]
              + metrics->stream_active_cnt[3],

                metrics->stream_rx_event_cnt,
                metrics->stream_rx_byte_cnt );

      puts("");
      fd_wksp_unmap( fd_quic_leave( quic ) );

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, gaddr ));
      SHIFT( 1 );

    } else {

      FD_LOG_ERR(( "%i: %s: unknown command\n\t"
                   "Do %s help for help", cnt, cmd, bin ));

    }
    cnt++;
  }

  FD_LOG_NOTICE(( "processed %i commands", cnt ));

# undef SHIFT
  fd_halt();
  return 0;
}
