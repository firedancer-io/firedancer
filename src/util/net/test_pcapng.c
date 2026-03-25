#include "fd_pcapng.h"
#include "fd_pcapng_private.h"
#include "../fd_util.h"

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#if FD_USING_GCC && __GNUC__ >= 15
#pragma GCC diagnostic ignored "-Wunterminated-string-initialization"
#endif

FD_STATIC_ASSERT( offsetof( fd_pcapng_shb_t, block_type       )== 0UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_shb_t, block_sz         )== 4UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_shb_t, byte_order_magic )== 8UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_shb_t, version_major    )==12UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_shb_t, version_minor    )==14UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_shb_t, section_sz       )==16UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_pcapng_shb_t                   )==24UL, layout );

FD_STATIC_ASSERT( offsetof( fd_pcapng_idb_t, block_type       )== 0UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_idb_t, block_sz         )== 4UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_idb_t, link_type        )== 8UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_idb_t, snap_len         )==12UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_pcapng_idb_t                   )==16UL, layout );

FD_STATIC_ASSERT( offsetof( fd_pcapng_epb_t, block_type       )== 0UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_epb_t, block_sz         )== 4UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_epb_t, if_idx           )== 8UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_epb_t, ts_hi            )==12UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_epb_t, ts_lo            )==16UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_epb_t, cap_len          )==20UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_epb_t, orig_len         )==24UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_pcapng_epb_t                   )==28UL, layout );

FD_STATIC_ASSERT( offsetof( fd_pcapng_spb_t, block_type       )== 0UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_spb_t, block_sz         )== 4UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_spb_t, orig_len         )== 8UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_pcapng_spb_t                   )==12UL, layout );

FD_STATIC_ASSERT( offsetof( fd_pcapng_dsb_t, block_type       )== 0UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_dsb_t, block_sz         )== 4UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_dsb_t, secret_type      )== 8UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_dsb_t, secret_sz        )==12UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_pcapng_dsb_t                   )==16UL, layout );


static void
test_pcapng_fwrite_shb( void ) {
  uchar buf[ 512UL ]={0};
  FILE * pcap = fmemopen( &buf, 512UL, "wb+" );
  FD_TEST( pcap );

  FD_LOG_INFO(( "TEST: Section Header Block" ));

  fd_pcapng_shb_opts_t opts = {
    .hardware = "x86_64",
    .os       = "Linux",
    .userappl = "Firedancer"
  };
  FD_TEST( 1UL==fd_pcapng_fwrite_shb( &opts, pcap ) );

  long pos = ftell( pcap );
  FD_TEST( pos>=0 );
  FD_TEST( 0==fclose( pcap ) );

  FD_LOG_HEXDUMP_INFO(( "shb", buf, (ulong)pos ));
}

static void
test_pcapng_fwrite_idb( void ) {
  uchar buf[ 512UL ]={0};
  FILE * pcap = fmemopen( &buf, 512UL, "wb+" );
  FD_TEST( pcap );

  FD_LOG_INFO(( "TEST: Interface Description Block" ));

  fd_pcapng_idb_opts_t opts = {
    .name     = "eth0",
    .ip4_addr = {10, 0, 0, 1},
    .mac_addr = {0x06, 0x00, 0xde, 0xad, 0xbe, 0xef},
    .hardware = "A fake NIC"
  };
  FD_TEST( 1UL==fd_pcapng_fwrite_idb( FD_PCAPNG_LINKTYPE_ETHERNET, &opts, pcap ) );

  long pos = ftell( pcap );
  FD_TEST( pos>=0 );
  FD_TEST( 0==fclose( pcap ) );

  FD_LOG_HEXDUMP_INFO(( "idb", buf, (ulong)pos ));
}

static void
test_pcapng_fwrite_pkt( void ) {
  uchar buf[ 512UL ]={0};
  FILE * pcap = fmemopen( &buf, 512UL, "wb+" );
  FD_TEST( pcap );

  FD_LOG_INFO(( "TEST: Packet" ));

  long ts = 0x12345678;
  uchar pkt[6UL] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
  FD_TEST( 1UL==fd_pcapng_fwrite_pkt( ts, pkt, 6UL, pcap ) );

  long pos = ftell( pcap );
  FD_TEST( pos>=0 );
  FD_TEST( 0==fclose( pcap ) );

  FD_LOG_HEXDUMP_INFO(( "epb", buf, (ulong)pos ));
}

static void
test_pcapng_fwrite_tls_key_log( void ) {
  uchar buf[ 512UL ]={0};
  FILE * pcap = fmemopen( &buf, 512UL, "wb+" );
  FD_TEST( pcap );

  FD_LOG_INFO(( "TEST: TLS key log" ));

  char const log[161UL] = "CLIENT_HANDSHAKE_TRAFFIC_SECRET 02570ac63a054d088e8bce573c9a77cbf356f0f4fef9022f361df83015203dd7 acb8b6dc42125d9a74484460dffa8618fc1fb1ec97be8bd9cc88b14f7b427343";
  FD_TEST( 1UL==fd_pcapng_fwrite_tls_key_log( (uchar const *)log, 161UL, pcap ) );

  long pos = ftell( pcap );
  FD_TEST( pos>=0 );
  FD_TEST( 0==fclose( pcap ) );

  FD_LOG_HEXDUMP_INFO(( "dsb", buf, (ulong)pos ));
}

/* Write a pcapng and then consume it */

static void
test_pcapng_dogfood( void ) {
  static uchar buf[ 0x134 ]={0};

  FILE * pcap = fmemopen( &buf, sizeof(buf), "wb+" );
  FD_TEST( pcap );

  FD_LOG_INFO(( "TEST: dogfood" ));

  /* Write section 0 */

  fd_pcapng_shb_opts_t shb_opts = {
    .hardware = "x86_64",
    .os       = "Linux",
    .userappl = "Firedancer"
  };
  FD_TEST( 1UL==fd_pcapng_fwrite_shb( &shb_opts, pcap ) );
  FD_LOG_DEBUG(( "Wrote SHB (end=%#lx)", (ulong)ftell( pcap ) ));

  fd_pcapng_idb_opts_t idb_opts = {
    .name     = "eth0",
    .ip4_addr = {10, 0, 0, 1},
    .mac_addr = {0x06, 0x00, 0xde, 0xad, 0xbe, 0xef},
    .hardware = "A fake NIC"
  };
  FD_TEST( 1UL==fd_pcapng_fwrite_idb( FD_PCAPNG_LINKTYPE_ETHERNET, &idb_opts, pcap ) );
  FD_LOG_DEBUG(( "Wrote IDB (end=%#lx)", (ulong)ftell( pcap ) ));

  long ts = 0x12345678;
  uchar pkt[6UL] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
  FD_TEST( 1UL==fd_pcapng_fwrite_pkt( ts, pkt,   6UL, pcap ) ); FD_LOG_DEBUG(( "Wrote EPB (end=%#lx)", (ulong)ftell( pcap ) ));
  FD_TEST( 1UL==fd_pcapng_fwrite_pkt( ts, pkt+1, 5UL, pcap ) ); FD_LOG_DEBUG(( "Wrote EPB (end=%#lx)", (ulong)ftell( pcap ) ));

  fd_pcapng_fwrite_tls_key_log( (uchar const *)"secret", 6UL, pcap );
  FD_LOG_DEBUG(( "Wrote DSB (end=%#lx)", (ulong)ftell( pcap ) ));

  FD_TEST( 1UL==fd_pcapng_fwrite_pkt( ts, pkt+2, 4UL, pcap ) ); FD_LOG_DEBUG(( "Wrote EPB (end=%#lx)", (ulong)ftell( pcap ) ));

  /* Read */

  FD_TEST( 0==fflush( pcap ) );
  long pos = ftell( pcap ); FD_TEST( pos>=0 );
  FD_LOG_HEXDUMP_DEBUG(( "stream", buf, (ulong)pos ));

  rewind( pcap );
  fd_pcapng_iter_t iter_mem[1];
  FD_TEST( alignof(fd_pcapng_iter_t)==fd_pcapng_iter_align() );
  FD_TEST( alignof(fd_pcapng_iter_t)==FD_PCAPNG_ITER_ALIGN );
  FD_TEST( sizeof(iter_mem)==fd_pcapng_iter_footprint() );
  fd_pcapng_iter_t * iter = fd_pcapng_iter_new( iter_mem, pcap );
  FD_TEST( iter );

  fd_pcapng_frame_t const * frame;

  frame = fd_pcapng_iter_next( iter );
  FD_TEST( frame );
  FD_TEST( fd_pcapng_is_pkt( frame ) );
  FD_TEST( frame->type   ==FD_PCAPNG_FRAME_ENHANCED );
  FD_TEST( 0==memcmp( pkt, frame->data, 6UL ) );
  FD_TEST( frame->data_sz==6UL );
  FD_TEST( frame->orig_sz==6UL );
  FD_TEST( frame->if_idx ==0UL );
  FD_TEST( iter->iface[ frame->if_idx ].link_type==FD_PCAPNG_LINKTYPE_ETHERNET );

  frame = fd_pcapng_iter_next( iter );
  FD_TEST( frame );
  FD_TEST( fd_pcapng_is_pkt( frame ) );
  FD_TEST( frame->type   ==FD_PCAPNG_FRAME_ENHANCED );
  FD_TEST( 0==memcmp( pkt+1, frame->data, 5UL ) );
  FD_TEST( frame->data_sz==5UL );
  FD_TEST( frame->orig_sz==5UL );
  FD_TEST( frame->if_idx ==0UL );

  frame = fd_pcapng_iter_next( iter );
  FD_TEST( frame );
  FD_TEST( !fd_pcapng_is_pkt( frame ) );
  FD_TEST( frame->type   ==FD_PCAPNG_FRAME_TLSKEYS );
  FD_TEST( 0==memcmp( "secret", frame->data, 6UL ) );
  FD_TEST( frame->data_sz==6UL );

  frame = fd_pcapng_iter_next( iter );
  FD_TEST( frame );
  FD_TEST( fd_pcapng_is_pkt( frame ) );
  FD_TEST( frame->type   ==FD_PCAPNG_FRAME_ENHANCED );
  FD_TEST( 0==memcmp( pkt+2, frame->data, 4UL ) );
  FD_TEST( frame->data_sz==4UL );
  FD_TEST( frame->orig_sz==4UL );
  FD_TEST( frame->if_idx ==0UL );

  frame = fd_pcapng_iter_next( iter );
  FD_TEST( !frame );
  FD_TEST( fd_pcapng_iter_err( iter )==-1 );

  /* Write section 1 */

  FD_TEST( 1UL==fd_pcapng_fwrite_shb( &shb_opts, pcap ) );

}

/* An Enhanced Packet Block might not have space for any options */

static void
test_pcapng_epb_noopts( void ) {
  static uchar const epb_noopts[] = {
    0x0a, 0x0d, 0x0d, 0x0a, 0x48, 0x00, 0x00, 0x00, 0x4d, 0x3c, 0x2b, 0x1a, 0x01, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x06, 0x00, 0x78, 0x38, 0x36, 0x5f,
    0x36, 0x34, 0x00, 0x00, 0x03, 0x00, 0x05, 0x00, 0x4c, 0x69, 0x6e, 0x75, 0x78, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x0a, 0x00, 0x46, 0x69, 0x72, 0x65, 0x64, 0x61, 0x6e, 0x63, 0x65, 0x72, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x01, 0x00, 0x09, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x04, 0x00, 0x65, 0x74, 0x68, 0x30, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x83, 0x1e, 0x86, 0x18,
    0x6f, 0xfc, 0xcf, 0xce, 0x2a, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x45, 0x00, 0x00, 0x26, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x3c, 0xc5, 0x7f, 0x00, 0x00, 0x01,
    0x7f, 0x00, 0x00, 0x01, 0x76, 0x34, 0x76, 0x34, 0x00, 0x12, 0x00, 0x00, 0x0a, 0x84, 0x80, 0x80,
    0x80, 0x00, 0x08, 0x01, 0x10, 0x2a, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00
  };
  FILE * pcap = fmemopen( (uchar *)epb_noopts, sizeof(epb_noopts), "rb" );
  FD_TEST( pcap );
  fd_pcapng_iter_t * iter = fd_pcapng_iter_new( aligned_alloc( fd_pcapng_iter_align(), fd_pcapng_iter_footprint() ), pcap );
  FD_TEST( iter );

  fd_pcapng_frame_t const * frame = fd_pcapng_iter_next( iter );
  FD_TEST( frame );
  FD_TEST( 0==fd_pcapng_iter_err( iter ) );
  FD_TEST( frame->type==FD_PCAPNG_FRAME_ENHANCED );
  FD_TEST( frame->data_sz==42UL );

  FD_TEST( !fd_pcapng_iter_next( iter ) );
  FD_TEST( -1==fd_pcapng_iter_err( iter ) );

  free( fd_pcapng_iter_delete( iter ) );
  FD_TEST( 0==fclose( pcap ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_pcapng_fwrite_shb();
  test_pcapng_fwrite_idb();
  test_pcapng_fwrite_pkt();
  test_pcapng_fwrite_tls_key_log();
  test_pcapng_dogfood();
  test_pcapng_epb_noopts();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

