#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

/* fuzz_tls_msg_parser specifically targets the parsers of some complex
   message types.  It might be obsoleted by fuzz_tls. */

#include "fd_tls_proto.h"

#include <stdlib.h>

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {

  fd_tls_msg_hdr_t hdr = {0};
  long res = fd_tls_decode_msg_hdr( &hdr, data, data_sz );
  if( res<0L ) return 0;
  FD_TEST( res==4L );
  data    += 4UL;
  data_sz -= 4UL;

  uint rec_sz = fd_tls_u24_to_uint( hdr.sz );
  if( rec_sz > data_sz ) return 0;

  switch( hdr.type ) {
    case FD_TLS_MSG_CLIENT_HELLO: {
      fd_tls_client_hello_t ch = {0};
      fd_tls_decode_client_hello( &ch, data, rec_sz );
      break;
    }
    case FD_TLS_MSG_SERVER_HELLO: {
      fd_tls_server_hello_t sh = {0};
      fd_tls_decode_server_hello( &sh, data, rec_sz );
      break;
    }
    case FD_TLS_MSG_ENCRYPTED_EXT: {
      fd_tls_enc_ext_t ee = {0};
      fd_tls_decode_enc_ext( &ee, data, rec_sz );
      break;
    }
    case FD_TLS_MSG_CERT_VERIFY: {
      fd_tls_cert_verify_t cv = {0};
      fd_tls_decode_cert_verify( &cv, data, rec_sz );
      break;
    }
    case FD_TLS_MSG_FINISHED: {
      fd_tls_finished_t fin = {0};
      fd_tls_decode_finished( &fin, data, rec_sz );
      break;
    }
  }
  return 0;
}
