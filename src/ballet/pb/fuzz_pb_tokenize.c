#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_pb_tokenize.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set(3); /* crash on warning log */
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  fd_pb_inbuf_t buf[1];
  FD_TEST( fd_pb_inbuf_init( buf, data, size ) );
  while( fd_pb_inbuf_sz( buf ) ) {
    fd_pb_tlv_t tlv[1];
    if( !fd_pb_read_tlv( buf, tlv ) ) return 0;
    switch( tlv->wire_type ) {
    case FD_PB_WIRE_TYPE_VARINT:
    case FD_PB_WIRE_TYPE_I64:
    case FD_PB_WIRE_TYPE_I32:
      break;
    case FD_PB_WIRE_TYPE_LEN:
      if( fd_pb_inbuf_sz( buf )<tlv->len ) return 0;
      fd_pb_inbuf_skip( buf, tlv->len );
      break;
    default:
      FD_LOG_CRIT(( "invalid wire type" ));
    }
  }
  return 0;
}
