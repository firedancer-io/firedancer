#include "../fd_util.h"
#include "fd_pcap.h"

FD_STATIC_ASSERT( FD_PCAP_ITER_TYPE_ETHERNET==0UL, unit_test );
FD_STATIC_ASSERT( FD_PCAP_ITER_TYPE_COOKED  ==1UL, unit_test );

#if FD_HAS_HOSTED

#include <stdio.h>

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * in_path  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--in",  NULL, NULL );
  char const * out_path = fd_env_strip_cmdline_cstr ( &argc, &argv, "--out", NULL, NULL );
  ulong        out_rem  = fd_env_strip_cmdline_ulong( &argc, &argv, "--max", NULL, 10UL );

  FILE * stream_in;
  if( in_path ) {
    FD_LOG_NOTICE(( "Streaming from --in %s", in_path ));
    stream_in = fopen( in_path, "r" );
    if( FD_UNLIKELY( !stream_in ) ) FD_LOG_ERR(( "fopen failed" ));
  } else {
    FD_LOG_NOTICE(( "Streaming from stdin" ));
    stream_in = stdin;
  }

  FILE * stream_out;
  if( ((!!out_path) & (!!out_rem)) ) {
    FD_LOG_NOTICE(( "Streaming up to --max %lu packets to --out %s", out_rem, out_path ));
    stream_out = fopen( out_path, "w" );
    if( FD_UNLIKELY( !stream_out ) ) FD_LOG_ERR(( "fopen failed" ));
    FD_TEST( fd_pcap_fwrite_hdr( stream_out )==1UL );
  } else {
    FD_LOG_NOTICE(( "--out not specified and/or --max is zero; not streaming out" ));
    stream_out = NULL;
    out_rem    = 0UL;
  }

  fd_pcap_iter_t * iter = fd_pcap_iter_new( stream_in ); FD_TEST( iter );

  FD_TEST( fd_pcap_iter_file( iter )==stream_in );

  FD_LOG_NOTICE(( "Cooked pcap: %s", fd_pcap_iter_type( iter )==FD_PCAP_ITER_TYPE_COOKED ? "yes" : "no" ));

  ulong cnt = 0UL;
  for(;;) {
    uchar pkt[ 2048UL ];
    long  ts;
    ulong sz = fd_pcap_iter_next( iter, pkt, 2048UL, &ts );
    if( FD_UNLIKELY( !sz ) ) break;
  //FD_LOG_NOTICE(( "sz %4lu ts %20li 0000: " FD_LOG_HEX16_FMT, sz, ts, FD_LOG_HEX16_FMT_ARGS( pkt ) ));
    if( FD_UNLIKELY( sz<64UL ) ) {
      FD_LOG_WARNING(( "pcap appears to contain a runt frame (%lu); skipping", sz ));
      continue;
    }
    if( out_rem ) {
      uint fcs = *(uint *)(pkt+sz-4UL); /* Assumes fcs in capture */
      FD_TEST( fd_pcap_fwrite_pkt( ts, NULL, 0UL, pkt, sz-4UL, fcs, stream_out )==1UL );
      out_rem--;
    }
    cnt++;
  }

  FD_LOG_NOTICE(( "%lu packets in pcap", cnt ));

  FD_TEST( fd_pcap_iter_delete( iter )==stream_in );

  if( stream_out && FD_UNLIKELY( fclose( stream_out ) ) ) FD_LOG_ERR(( "fclose failed" ));
  if( in_path    && FD_UNLIKELY( fclose( stream_in  ) ) ) FD_LOG_ERR(( "fclose failed" ));

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_NOTICE(( "skip: unit test requires FD_HAS_HOSTED" ));
  fd_halt();
  return 0;
}

#endif

