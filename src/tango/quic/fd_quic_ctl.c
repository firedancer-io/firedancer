#include "fd_quic.h"

FD_IMPORT_CSTR( fd_quic_ctl_help, "src/tango/quic/fd_quic_ctl_help" );

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

      fd_ip_t * ip = fd_ip_join( fd_ip_new( fd_wksp_alloc_laddr( wksp, fd_ip_align(), fd_ip_footprint( 256UL, 256UL ), 1UL ), 256UL, 256UL ) );
      void * shquic = fd_quic_new( shmem, &limits, ip );
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
