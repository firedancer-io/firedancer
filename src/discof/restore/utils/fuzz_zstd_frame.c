#include "fd_zstd_frame.h"

#include "../../../util/fd_util.h"

#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

#include <stdlib.h>

struct scan_result {
  int   rc;
  ulong consumed;
};

typedef struct scan_result scan_result_t;

#define ORACLE_OUTPUT_MAX (1UL<<17)

static ZSTD_DCtx * oracle_dctx;
static uchar       oracle_output[ ORACLE_OUTPUT_MAX ];

static int
zstd_accepts( uchar const * data,
              ulong         data_sz ) {
  FD_TEST( !ZSTD_isError( ZSTD_DCtx_reset( oracle_dctx, ZSTD_reset_session_only ) ) );

  ZSTD_inBuffer input = { .src=data, .size=data_sz, .pos=0UL };
  for( ulong iter=0UL; iter<=data_sz+1UL; iter++ ) {
    ZSTD_outBuffer output = {
      .dst  = oracle_output,
      .size = iter ? sizeof(oracle_output) : 0UL,
      .pos  = 0UL
    };
    ulong prev_pos = input.pos;
    ulong rc = ZSTD_decompressStream( oracle_dctx, &output, &input );
    if( ZSTD_isError( rc ) ) return 0;
    if( !rc ) return input.pos==input.size;
    if( input.pos==prev_pos && !output.pos ) return 0;
  }
  return 0;
}

static scan_result_t
scan_fragments( uchar const * data,
                ulong         data_sz,
                int           mode ) {
  fd_zstd_frame_t frame[1];
  FD_TEST( fd_zstd_frame_new( frame )==frame );

  uint rng = 2166136261U;
  for( ulong i=0UL; i<fd_ulong_min( data_sz, 16UL ); i++ )
    rng = (rng^(uint)data[i])*16777619U;

  int   rc  = FD_ZSTD_FRAME_MORE;
  ulong off = 0UL;
  do {
    ulong frag_sz;
    if( mode==0 ) {
      frag_sz = data_sz;
    } else if( mode==1 ) {
      frag_sz = fd_ulong_min( 1UL, data_sz-off );
    } else {
      rng = rng*1664525U + 1013904223U;
      frag_sz = fd_ulong_min( 1UL+(ulong)(rng%257U), data_sz-off );
    }

    ulong consumed = ULONG_MAX;
    rc = fd_zstd_frame_advance( frame, data+off, frag_sz, &consumed );
    FD_TEST( consumed<=frag_sz );
    off += consumed;

    if( rc!=FD_ZSTD_FRAME_MORE ) break;
    FD_TEST( consumed==frag_sz );
  } while( off<data_sz );

  return (scan_result_t){ .rc=rc, .consumed=off };
}

static void
check_input( uchar const * data,
             ulong         data_sz ) {
  scan_result_t whole      = scan_fragments( data, data_sz, 0 );
  scan_result_t one_byte   = scan_fragments( data, data_sz, 1 );
  scan_result_t randomized = scan_fragments( data, data_sz, 2 );

  FD_TEST( whole.rc==one_byte.rc );
  FD_TEST( whole.rc==randomized.rc );
  if( whole.rc==FD_ZSTD_FRAME_END ) {
    FD_TEST( whole.consumed==one_byte.consumed );
    FD_TEST( whole.consumed==randomized.consumed );
  }

  ulong oracle_sz = ZSTD_findFrameCompressedSize( data, data_sz );
  if( whole.rc==FD_ZSTD_FRAME_END ) {
    FD_TEST( !ZSTD_isError( oracle_sz ) );
    FD_TEST( whole.consumed==oracle_sz );
  }

  uint magic = data_sz>=4UL
             ? (uint)data[0]       | ((uint)data[1]<< 8)
             | ((uint)data[2]<<16) | ((uint)data[3]<<24)
             : 0U;
  int standard = magic==0xfd2fb528U ||
                 (magic & 0xfffffff0U)==0x184d2a50U;
  if( standard && !ZSTD_isError( oracle_sz ) &&
      zstd_accepts( data, oracle_sz ) ) {
    FD_TEST( whole.rc==FD_ZSTD_FRAME_END );
    FD_TEST( whole.consumed==oracle_sz );
    FD_TEST( one_byte.consumed==oracle_sz );
    FD_TEST( randomized.consumed==oracle_sz );
  }
}

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set   ( 4 );
  fd_log_level_logfile_set( 4 );
  oracle_dctx = ZSTD_createDCtx();
  FD_TEST( oracle_dctx );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {
  check_input( data, data_sz );

  ulong payload_sz = fd_ulong_min( data_sz, 1024UL );
  uchar frame[ 9UL+1024UL ];
  frame[0] = 0x28U;
  frame[1] = 0xb5U;
  frame[2] = 0x2fU;
  frame[3] = 0xfdU;
  frame[4] = 0U; /* Unknown content size */
  frame[5] = 0U; /* 1 KiB window */
  uint block_header = ((uint)payload_sz<<3) | 1U;
  frame[6] = (uchar)(block_header    );
  frame[7] = (uchar)(block_header>> 8);
  frame[8] = (uchar)(block_header>>16);
  fd_memcpy( frame+9UL, data, payload_sz );
  check_input( frame, 9UL+payload_sz );

  return 0;
}
