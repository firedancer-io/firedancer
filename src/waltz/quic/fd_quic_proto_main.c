#include "templ/fd_quic_transport_params.h"
#include "fd_quic_conn_id.h"
#include "fd_quic_proto.h"
#include "../../ballet/hex/fd_hex.h"
#include "../../util/fd_util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>

static int
help( void ) {
  puts(
    "fd_quic_proto provides QUIC wire format utilities\n"
    "\n"
    "Usage: fd_quic_params CMD TYPE [flags]\n"
    "\n"
    "where  CMD := { encode | encode FILE\n"
    "                decode | encode FILE }\n"
    "       TYPE := { tp }"
  );
  return 0;
}

static int
invalid_usage( void ) {
  fputs( "Invalid command-line args. Try --help\n", stderr );
  return 1;
}

#define CMD_DECODE 1
#define CMD_ENCODE 2

#define CODEC_TP 1

static uchar buf[ 16384 ];

static void
decode_quic_tp( uchar const * buf,
                ulong         buf_sz ) {

  fd_quic_transport_params_t params[1] = {0};
  if( FD_UNLIKELY( 0!=fd_quic_decode_transport_params( params, buf, buf_sz ) ) ) {
    fputs( "Failed to decode QUIC transport parameters\n", stderr );
    exit(1);
  }

  if( params->original_destination_connection_id_present ) {
    char conn_id_hex[ FD_QUIC_MAX_CONN_ID_SZ*2 ];
    fputs( "original_destination_connection_id = \"", stdout );
    fd_hex_encode( conn_id_hex, params->original_destination_connection_id, params->original_destination_connection_id_len );
    fwrite( conn_id_hex, params->original_destination_connection_id_len*2U, 1, stdout );
    fputs( "\"\n", stdout );
  }
  if( params->max_idle_timeout_present ) {
    fprintf( stdout, "max_idle_timeout = %lu\n", params->max_idle_timeout );
  }
  if( params->stateless_reset_token_present ) {
    fputs( "stateless_reset_token = \"", stdout );
    for( uint i=0; i<params->stateless_reset_token_len; i++ ) {
      fprintf( stdout, "%02x", params->stateless_reset_token[i] );
    }
    fputs( "\"\n", stdout );
  }
  if( params->max_udp_payload_size_present ) {
    fprintf( stdout, "max_udp_payload_size = %lu\n", params->max_udp_payload_size );
  }
  if( params->initial_max_data_present ) {
    fprintf( stdout, "initial_max_data = %lu\n", params->initial_max_data );
  }
  if( params->initial_max_stream_data_bidi_local_present ) {
    fprintf( stdout, "initial_max_stream_data_bidi_local = %lu\n", params->initial_max_stream_data_bidi_local );
  }
  if( params->initial_max_stream_data_bidi_remote_present ) {
    fprintf( stdout, "initial_max_stream_data_bidi_remote = %lu\n", params->initial_max_stream_data_bidi_remote );
  }
  if( params->initial_max_stream_data_uni_present ) {
    fprintf( stdout, "initial_max_stream_data_uni = %lu\n", params->initial_max_stream_data_uni );
  }
  if( params->initial_max_streams_bidi_present ) {
    fprintf( stdout, "initial_max_streams_bidi = %lu\n", params->initial_max_streams_bidi );
  }
  if( params->initial_max_streams_uni_present ) {
    fprintf( stdout, "initial_max_streams_uni = %lu\n", params->initial_max_streams_uni );
  }
  if( params->ack_delay_exponent_present ) {
    fprintf( stdout, "ack_delay_exponent = %lu\n", params->ack_delay_exponent );
  }
  if( params->max_ack_delay_present ) {
    fprintf( stdout, "max_ack_delay = %lu\n", params->max_ack_delay );
  }
  if( params->disable_active_migration_present ) {
    fprintf( stdout, "disable_active_migration = true\n" );
  }
  if( params->active_connection_id_limit_present ) {
    fprintf( stdout, "active_connection_id_limit = %lu\n", params->active_connection_id_limit );
  }
  if( params->initial_source_connection_id_present ) {
    char conn_id_hex[ FD_QUIC_MAX_CONN_ID_SZ*2 ];
    fputs( "initial_source_connection_id = \"", stdout );
    fd_hex_encode( conn_id_hex, params->initial_source_connection_id, params->initial_source_connection_id_len );
    fwrite( conn_id_hex, params->initial_source_connection_id_len*2U, 1, stdout );
    fputs( "\"\n", stdout );
  }
  if( params->retry_source_connection_id_present ) {
    char conn_id_hex[ FD_QUIC_MAX_CONN_ID_SZ*2 ];
    fputs( "retry_source_connection_id = \"", stdout );
    fd_hex_encode( conn_id_hex, params->retry_source_connection_id, params->retry_source_connection_id_len );
    fwrite( conn_id_hex, params->retry_source_connection_id_len*2U, 1, stdout );
    fputs( "\"\n", stdout );
  }

  /* Comes last because it starts a new TOML table */
  if( params->preferred_address_present ) {
    fputs( "[preferred_address]", stderr );
    fd_quic_preferred_address_t preferred_address = {0};
    if( FD_UNLIKELY( fd_quic_decode_preferred_address( &preferred_address, params->preferred_address, params->preferred_address_len )!=params->preferred_address_len ) ) {
      fputs( "Invalid preferred address!\n", stderr );
      fputs( "raw = \"", stdout );
      for( uint i=0; i<params->preferred_address_len; i++ ) {
        fprintf( stdout, "%02x", params->preferred_address[i] );
      }
      fputs( "\"\n", stdout );
    } else {
      printf( "  ipv4_address = \"" FD_IP4_ADDR_FMT "\"\n",
          FD_IP4_ADDR_FMT_ARGS( FD_IP4_ADDR(
            preferred_address.ipv4_address[0],
            preferred_address.ipv4_address[1],
            preferred_address.ipv4_address[2],
            preferred_address.ipv4_address[3] ) ) );

      printf( "  ipv4_port = %u\n", (uint)preferred_address.ipv4_port );

      char ipv6_addr_cstr[ INET6_ADDRSTRLEN ];
      struct in6_addr in6a = {0};
      memcpy( in6a.s6_addr, preferred_address.ipv6_address, 16 );
      printf( "  ipv6_address = \"%s\"",
          inet_ntop( AF_INET6, &in6a, ipv6_addr_cstr, INET6_ADDRSTRLEN ) );

      printf( "  ipv6_port = %u\n", (uint)preferred_address.ipv6_port );

      fputs( "conn_id = \"", stdout );
      char conn_id_hex[ sizeof(preferred_address.conn_id)*2 ];
      fd_hex_encode( conn_id_hex, preferred_address.conn_id, preferred_address.conn_id_len );
      fwrite( conn_id_hex, preferred_address.conn_id_len*2U, 1, stdout );
      fputs( "\"\n", stdout );

      char reset_token_hex[ 32 ];
      fd_hex_encode( reset_token_hex, preferred_address.reset_token, 16 );
      fputs( "reset_token = \"", stdout );
      fwrite( reset_token_hex, 32, 1, stdout );
      fputs( "\"\n", stdout );
    }
  }

}

static void
cmd_decode( FILE * in_file,
            int    codec ) {
  size_t n = fread( buf, 1, sizeof(buf), in_file );
  int err = ferror( in_file );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fread failed (%i-%s)", err, fd_io_strerror( err ) ));
  if( FD_UNLIKELY( !feof( in_file ) ) ) FD_LOG_ERR(( "Input too large" ));

  switch( codec ) {
  case CODEC_TP:
    decode_quic_tp( buf, n );
    break;
  default:
    __builtin_unreachable();
  }
}

static void
cmd_encode( FILE * in_file,
            int    codec ) {
  size_t n = fread( buf, 1, sizeof(buf), in_file );
  int err = ferror( in_file );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fread failed (%i-%s)", err, fd_io_strerror( err ) ));
  if( FD_UNLIKELY( !feof( in_file ) ) ) FD_LOG_ERR(( "Input too large" ));
  (void)n;

  switch( codec ) {
  default:
    __builtin_unreachable();
  }
}

int
main( int     argc,
      char ** argv ) {
  for( int arg=1; arg<argc; arg++ ) {
    if( 0==strcmp( argv[arg], "--help" ) ) return help();
  }
  if( argc<3 ) return invalid_usage();

  argc--; argv++;

  char * arg_cmd = argv[0];
  int    cmd     = 0;
  if( /**/ 0==strcmp( arg_cmd, "decode" ) ) cmd = CMD_DECODE;
  else if( 0==strcmp( arg_cmd, "encode" ) ) cmd = CMD_ENCODE;
  else {
    fprintf( stderr, "Unknown command \"%s\"\n", arg_cmd );
    return invalid_usage();
  }

  argc--; argv++;

  char * arg_codec = argv[0];
  int    codec     = 0;
  if( 0==strcmp( arg_codec, "tp" ) ) codec = CODEC_TP;
  else {
    fprintf( stderr, "Unknown type \"%s\"\n", arg_codec );
    return invalid_usage();
  }

  argc--; argv++;

  FILE * in_file = stdin;
  if( argc>0 ) {
    in_file = fopen( argv[0], "rb" );
    if( FD_UNLIKELY( !in_file ) ) { FD_LOG_ERR(( "fopen(%s) failed (%i-%s)", argv[0], errno, fd_io_strerror( errno ) )); }
    argc--; argv++;
  }
  if( argc>0 ) { fputs( "Unexpected argument!\n", stderr ); return invalid_usage(); }

  switch( cmd ) {
  case CMD_DECODE:
    cmd_decode( in_file, codec );
    break;

  case CMD_ENCODE:
    cmd_encode( in_file, codec );
    break;

  default:
    __builtin_unreachable();
    break;
  }

  fclose( in_file );
  return 0;
}
