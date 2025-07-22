#include "../fd_util.h"
#include "fd_textstream.h"

#include <stdlib.h>
#include <stdint.h>

#define PART_RAW_SZ (720UL)
#define PART_BLK_SZ (4UL*(PART_RAW_SZ+2UL)/3UL)

int
LLVMFuzzerInitialize( int *argc,
                      char ***argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  (void) atexit( fd_halt );
  fd_log_level_core_set( 1 );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const *data,
                        ulong        size ) {
  fd_valloc_t valloc = fd_libc_alloc_virtual();

  ulong metadata_size = sizeof(uint8_t);
  if (size < metadata_size) {
    return 0;
  }

  uint8_t choice = FD_LOAD( uint8_t, data+0 );
  size -= metadata_size;

  uchar* content = (uchar*)data + metadata_size;

  fd_textstream_t  _data_out[1];
  fd_textstream_t * data_out = fd_textstream_new( _data_out, valloc, PART_BLK_SZ );
  switch (choice) {
    case 0: {
        fd_textstream_encode_base64( data_out, content, size );
        break;
    }
    case 1: {
        fd_textstream_encode_base58( data_out, content, size );
        break;
    }
    case 2: {
        fd_textstream_encode_hex( data_out, content, size );
        break;
    }
    case 3: {
        uint *utf8_content = (uint*)content;
        ulong utf8_size = ((size*sizeof(uchar))/sizeof(uint));
        fd_textstream_encode_utf8( data_out, utf8_content, utf8_size );
        break;
    } case 4: {
        fd_textstream_append( data_out, (const char*)content, size);
        break;
    }
    default: {
        goto cleanup;
    }
  }

  FD_TEST( 1UL==fd_textstream_get_iov_count( data_out ) );
  struct fd_iovec iov[1];
  FD_TEST( 0  ==fd_textstream_get_iov( data_out, iov ) );

  ulong total_size = fd_textstream_total_size( data_out );
  char *output = malloc( total_size );
  if ( output == NULL ) {
    goto cleanup;
  }
  FD_TEST( 0==fd_textstream_get_output( data_out, output ) );
  free( output );


cleanup:
  fd_textstream_destroy( data_out );
  return 0;
}
