#include "fd_solcap_writer.h"
#include "fd_pkt_w_pcapng.h"
#include "fd_pkt_w_tango.h"
#include "../../tango/mcache/fd_mcache.h"
#include "../../util/net/fd_pcapng.h"
#include <errno.h>
#include <fcntl.h> /* open */
#include <stdlib.h> /* aligned_alloc */
#include <stdio.h> /* FILE */
#include <unistd.h> /* unlink */

/* End-to-end test writing solcap records to a pcapng file */

static void
test_solcap_pcapng( char const * path ) {

  /* Create a solcap pcapng file */

  char _path[] = "/tmp/test_solcap_writer.XXXXXX";

  int fd;
  if( FD_UNLIKELY( path ) ) {
    FD_LOG_NOTICE(( "Using --path %s for the test storage", path ));
    fd = open( path, O_RDWR | O_CREAT | O_EXCL, (mode_t)0644 );
    if( FD_UNLIKELY( fd==-1 ) ) FD_LOG_ERR(( "open failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  } else {
    FD_LOG_NOTICE(( "--path not specified, using a temp file for test storage" ));
    fd = mkstemp( _path );
    if( FD_UNLIKELY( fd==-1 ) ) FD_LOG_ERR(( "mkstemp failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    path = _path;
    FD_LOG_NOTICE(( "temp file at %s", path ));
  }

  /* Write a couple events to it */

  ulong   depth       = 4UL;
  ulong   mtu         = 1024UL;
  ulong   req_data_sz = fd_dcache_req_data_sz( mtu, depth, 1UL, 1 );
  void *  dcache_mem  = aligned_alloc( fd_dcache_align(), fd_dcache_footprint( req_data_sz, 0UL ) );
  uchar * dcache      = fd_dcache_join( fd_dcache_new( dcache_mem, req_data_sz, 0UL ) );
  FD_TEST( dcache_mem ); FD_TEST( dcache );

  fd_pkt_w_pcapng_t w_pcapng[1];
  fd_pkt_writer_t * writer = fd_pkt_w_pcapng_new( w_pcapng, fd, dcache, mtu );
  FD_TEST( writer );

  fd_solcap_bank_create( writer, 1UL, 42UL );

  fd_solcap_txn_exec_start_t txn_start = {
    .bank_id           = 1UL,
    .serialized_txn    = (uchar const *)"bla",
    .serialized_txn_sz = 3UL
  };
  fd_solcap_txn_exec_start( writer, &txn_start );

  /* Close writer */

  fd_pkt_writer_fini( writer );
  FD_TEST( fd_dcache_delete( fd_dcache_leave( dcache ) ) );
  free( dcache_mem );

  /* Parse packets */

  FILE * file = fopen( path, "rb" );
  FD_TEST( file );
  void * iter_mem = aligned_alloc( fd_pcapng_iter_align(), fd_pcapng_iter_footprint() );
  FD_TEST( iter_mem );
  fd_pcapng_iter_t * iter = fd_pcapng_iter_new( iter_mem, file );
  FD_TEST( iter );

  for(;;) {
    fd_pcapng_frame_t * frame = fd_pcapng_iter_next( iter );
    if( !frame ) {
      FD_TEST( fd_pcapng_iter_err( iter )==EOF );
      break;
    }
    FD_TEST( frame->type==FD_PCAPNG_FRAME_ENHANCED );
  }

  FD_TEST( fd_pcapng_iter_delete( iter ) );
  free( iter_mem );
  FD_TEST( 0==fclose( file ) );

  /* Clean up */

  if( FD_UNLIKELY( unlink( path ) ) ) FD_LOG_WARNING(( "unlink failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

/* End-to-end test writing solcap records into a shm queue */

static void
test_solcap_tango( void ) {
}

/* Test MTU violation
   Should silently increment an error counter */

static void
test_solcap_mtu( void ) {

  ulong   depth       = 4UL;
  ulong   mtu         = 1024UL;
  ulong   req_data_sz = fd_dcache_req_data_sz( mtu, depth, 1UL, 1 );
  void *  dcache_mem  = aligned_alloc( fd_dcache_align(), fd_dcache_footprint( req_data_sz, 0UL ) );
  uchar * dcache      = fd_dcache_join( fd_dcache_new( dcache_mem, req_data_sz, 0UL ) );
  FD_TEST( dcache_mem ); FD_TEST( dcache );
  uchar * base        = dcache;

  void *           mcache_mem = aligned_alloc( fd_mcache_align(), fd_mcache_footprint( depth, 0UL ) );
  fd_frag_meta_t * mcache     = fd_mcache_join( fd_mcache_new( mcache_mem, depth, 0UL, 0UL ) );
  FD_TEST( mcache_mem ); FD_TEST( mcache );

  fd_pkt_w_tango_t w_tango[1];
  fd_pkt_writer_t * writer = fd_pkt_w_tango_new( w_tango, mcache, dcache, base, mtu );
  FD_TEST( writer );

  fd_solcap_bank_create( writer, 1UL, 42UL );

  fd_solcap_txn_exec_start_t txn_start = {
    .bank_id           = 1UL,
    .serialized_txn    = (uchar const *)"bla",
    .serialized_txn_sz = 3UL
  };
  fd_solcap_txn_exec_start( writer, &txn_start );

  /* Close writer */

  fd_pkt_writer_fini( writer );

  /* Clean up */
  fd_mcache_delete( fd_mcache_leave( mcache ) );
  fd_dcache_delete( fd_dcache_leave( dcache ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * path = fd_env_strip_cmdline_cstr( &argc, &argv, "--path", NULL, NULL );

  test_solcap_pcapng( path );
  test_solcap_tango();
  test_solcap_mtu();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
