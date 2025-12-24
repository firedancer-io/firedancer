#include "fd_solcap_writer.h"
#include "fd_pkt_w_pcapng.h"
#include "fd_pkt_w_tango.h"
#include "../../ballet/pb/fd_pb_tokenize.h"
#include "../../tango/mcache/fd_mcache.h"
#include "../../util/net/fd_pcapng.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"
#include <errno.h>
#include <fcntl.h> /* open */
#include <stdlib.h> /* aligned_alloc */
#include <stdio.h> /* FILE */
#include <unistd.h> /* unlink */

/* Validate the top and second level of a solcap event (Protobuf encoded) */

static void
validate_protobuf( uchar const * msg,
                   ulong         msg_sz,
                   ulong         msg_type ) {
  fd_pb_inbuf_t inbuf[1];
  FD_TEST( fd_pb_inbuf_init( inbuf, msg, msg_sz ) );

  /* open submessage */
  fd_pb_tlv_t tlv[1];
  FD_TEST( fd_pb_read_tlv( inbuf, tlv ) );
  FD_TEST( tlv->field_id ==msg_type );
  FD_TEST( tlv->wire_type==FD_PB_WIRE_TYPE_LEN );
  FD_TEST( fd_pb_inbuf_sz( inbuf )==tlv->len );

  /* validate submessage */
  while( fd_pb_inbuf_sz( inbuf ) ) {
    fd_pb_tlv_t tlv[1];
    FD_TEST( fd_pb_read_tlv( inbuf, tlv ) );
    if( tlv->wire_type==FD_PB_WIRE_TYPE_LEN ) {
      FD_TEST( fd_pb_inbuf_sz( inbuf )>=tlv->len );
      fd_pb_inbuf_skip( inbuf, tlv->len );
    }
  }
}

/* Validates a solcap Protobuf event wrapped in fake network headers */

static void
validate_protobuf_fakenet( uchar const * pkt,
                           ulong         pkt_sz,
                           ulong         msg_type ) {
  FD_TEST( pkt_sz > sizeof(uint)+sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t) );

  uint         proto   = FD_LOAD( uint,         pkt+ 0 );  /* BSD loopback */
  fd_ip4_hdr_t ip4_hdr = FD_LOAD( fd_ip4_hdr_t, pkt+ 4 );
  fd_udp_hdr_t udp_hdr = FD_LOAD( fd_udp_hdr_t, pkt+24 );

  FD_TEST( proto==2 ); /* IPv4 */
  FD_TEST( ip4_hdr.verihl  ==FD_IP4_VERIHL( 4,5 ) );
  FD_TEST( ip4_hdr.tos     ==0 );
  FD_TEST( ip4_hdr.protocol==FD_IP4_HDR_PROTOCOL_UDP );
  FD_TEST( fd_ip4_hdr_check_fast( &ip4_hdr )==0 );
  FD_TEST( udp_hdr.check==0 );

  uchar const * msg    = pkt   +32;
  ulong         msg_sz = pkt_sz-32;

  FD_TEST( fd_ushort_bswap( udp_hdr.net_len     )==(ushort)(  8+msg_sz ) );
  FD_TEST( fd_ushort_bswap( ip4_hdr.net_tot_len )==(ushort)( 28+msg_sz ) );

  validate_protobuf( msg, msg_sz, msg_type );
}

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

  /* Write a couple events */

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

  fd_pcapng_frame_t * frame;

  FD_TEST( (frame = fd_pcapng_iter_next( iter )) );
  FD_TEST( frame->type==FD_PCAPNG_FRAME_ENHANCED );
  validate_protobuf_fakenet( frame->data, frame->data_sz, FD_SOLCAP_MSG_BANK_CREATE );

  FD_TEST( (frame = fd_pcapng_iter_next( iter )) );
  FD_TEST( frame->type==FD_PCAPNG_FRAME_ENHANCED );
  validate_protobuf_fakenet( frame->data, frame->data_sz, FD_SOLCAP_MSG_TXN_EXEC_START );

  FD_TEST( !fd_pcapng_iter_next( iter ) );
  FD_TEST( fd_pcapng_iter_err( iter )==EOF );

  FD_TEST( fd_pcapng_iter_delete( iter ) );
  free( iter_mem );
  FD_TEST( 0==fclose( file ) );

  /* Clean up */

  if( FD_UNLIKELY( unlink( path ) ) ) FD_LOG_WARNING(( "unlink failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

/* End-to-end test writing solcap records into a shm queue */

static void
test_solcap_tango( void ) {

  /* Create a solcap tango writer */

  ulong   depth       = 4UL;
  ulong   mtu         = 1024UL;
  ulong   req_data_sz = fd_dcache_req_data_sz( mtu, depth, 1UL, 1 );
  void *  dcache_mem  = aligned_alloc( fd_dcache_align(), fd_dcache_footprint( req_data_sz, 0UL ) );
  uchar * dcache      = fd_dcache_join( fd_dcache_new( dcache_mem, req_data_sz, 0UL ) );
  FD_TEST( dcache_mem ); FD_TEST( dcache );
  void *  base        = dcache_mem;

  void *           mcache_mem = aligned_alloc( fd_mcache_align(), fd_mcache_footprint( depth, 0UL ) );
  fd_frag_meta_t * mcache     = fd_mcache_join( fd_mcache_new( mcache_mem, depth, 0UL, 0UL ) );
  FD_TEST( mcache_mem ); FD_TEST( mcache );

  fd_pkt_w_tango_t w_tango[1];
  fd_pkt_writer_t * writer = fd_pkt_w_tango_new( w_tango, mcache, dcache, base, mtu );
  FD_TEST( writer );

  /* Write a couple events */

  fd_solcap_bank_create( writer, 1UL, 43UL );

  fd_solcap_txn_exec_start_t txn_start = {
    .bank_id           = 1UL,
    .serialized_txn    = (uchar const *)"foo",
    .serialized_txn_sz = 3UL
  };
  fd_solcap_txn_exec_start( writer, &txn_start );

  /* Parse packets */

  FD_TEST( mcache[ 0 ].seq==0UL );
  uchar const * msg0 = fd_chunk_to_laddr( base, mcache[ 0 ].chunk );
  FD_TEST(        fd_ulong_extract( mcache[ 0 ].sig,  0,  7 )==FD_SOLCAP_MSG_BANK_CREATE );
  ulong msg0_sz = fd_ulong_extract( mcache[ 0 ].sig,  8, 31 );
  FD_TEST(        fd_ulong_extract( mcache[ 0 ].sig, 32, 63 )==0UL );
  FD_TEST( mcache[ 0 ].sz    ==0UL );
  FD_TEST( mcache[ 0 ].ctl   ==0UL );
  FD_TEST( mcache[ 0 ].tsorig==0UL );
  FD_TEST( mcache[ 0 ].tspub ==0UL );
  validate_protobuf( msg0, msg0_sz, FD_SOLCAP_MSG_BANK_CREATE );

  FD_TEST( mcache[ 1 ].seq==1UL );
  uchar const * msg1 = fd_chunk_to_laddr( base, mcache[ 1 ].chunk );
  FD_TEST(        fd_ulong_extract( mcache[ 1 ].sig,  0,  7 )==FD_SOLCAP_MSG_TXN_EXEC_START );
  ulong msg1_sz = fd_ulong_extract( mcache[ 1 ].sig,  8, 31 );
  FD_TEST(        fd_ulong_extract( mcache[ 1 ].sig, 32, 63 )==0UL );
  FD_TEST( mcache[ 1 ].sz    ==0UL );
  FD_TEST( mcache[ 1 ].ctl   ==0UL );
  FD_TEST( mcache[ 1 ].tsorig==0UL );
  FD_TEST( mcache[ 1 ].tspub ==0UL );
  validate_protobuf( msg1, msg1_sz, FD_SOLCAP_MSG_TXN_EXEC_START );

  /* Close writer */

  fd_pkt_writer_fini( writer );

  /* Clean up */

  FD_TEST( fd_mcache_leave( mcache ) );
  free( mcache_mem );
  FD_TEST( fd_dcache_leave( dcache ) );
  free( dcache_mem );

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
