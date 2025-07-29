#include "fd_snapshot_parser.h"
#include <assert.h>
#include <stdlib.h>

#define ACCV_LG_SLOT_CNT 8 /* 256 hashmap slots */

static void * parser_mem;

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set   ( 4 );
  fd_log_level_logfile_set( 4 );

  parser_mem = aligned_alloc( fd_snapshot_parser_align(), fd_snapshot_parser_footprint( 1024UL ) );
  assert( parser_mem );

  return 0;
}

static void
manifest_cb( void * _ctx,
             ulong  manifest_sz ) {
  (void)_ctx; (void)manifest_sz;
}

static void
acc_hdr_cb( void *                          _ctx,
            fd_solana_account_hdr_t const * hdr ) {
  (void)_ctx; (void)hdr;
}

static void
acc_data_cb( void *        _ctx,
             uchar const * buf,
             ulong         data_sz ) {
  (void)_ctx; (void)buf; (void)data_sz;
}

int
LLVMFuzzerTestOneInput( uchar const * const data,
                        ulong         const size ) {
  fd_snapshot_parser_t * parser = fd_snapshot_parser_new( parser_mem, NULL, 42UL, 1024UL, manifest_cb, acc_hdr_cb, acc_data_cb );
  assert( parser );
  /* FIXME split input in the future */
  uchar const * p   = data;
  uchar const * end = data+size;
  while( p<end ) {
    p = fd_snapshot_parser_process_chunk( parser, data, size );
  }
  assert( p==end );
  return 0;
}
