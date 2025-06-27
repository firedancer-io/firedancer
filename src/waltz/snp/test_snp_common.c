#include "fd_snp_common.h"
#include "../../util/fd_util.h"

static void
test_tlv_parsing( void ) {
#define BUF_SZ ( 2048UL )
  FD_LOG_NOTICE(( "test_tlv_parsing" ));
  fd_rng_t _rng[ 1 ]; fd_rng_t * r = fd_rng_join( fd_rng_new( _rng, (uint)fd_tickcount() /*seed*/, 0UL ) );
  uchar     buf[ BUF_SZ ];
  tlv_meta_t tlv_meta[ 1024UL ];
  for( ulong i=0UL; i<128UL; i++ ) {
    ulong cnt = 0UL;
    ulong sz  = 0UL;
    while( sz < BUF_SZ ) {
      uchar type = fd_rng_uchar( r );
      ushort len = fd_rng_ushort_roll( r, 16UL )+1UL;
      if( ( sz + len + 3UL ) <= BUF_SZ ) {
        tlv_meta[ cnt ].type = type;
        tlv_meta[ cnt ].len  = len;
        tlv_meta[ cnt ].u64  = 0UL; /* reset v */
        if(      len == 1UL ) tlv_meta[ cnt ].u8  = fd_rng_uchar( r );
        else if( len == 2UL ) tlv_meta[ cnt ].u16 = fd_rng_ushort( r );
        else if( len == 4UL ) tlv_meta[ cnt ].u32 = fd_rng_uint( r );
        else if( len == 8UL ) tlv_meta[ cnt ].u64 = fd_rng_ulong( r );
        else                  tlv_meta[ cnt ].ptr = &buf[ sz + 3UL ];
        fd_memcpy( buf + sz + 0UL, &type, 1UL );
        fd_memcpy( buf + sz + 1UL,  &len, 2UL );
        if( len == 1UL || len == 2UL || len == 4UL || len == 8UL ) {
          fd_memcpy( buf + sz + 3UL, &tlv_meta[ cnt ].u64, 8UL );
        } else {
          for( ulong k=0; k<len; k++ ) buf[ sz + 3UL + k ] = fd_rng_uchar( r );
        }
        cnt++;
      }
      sz += len + 3UL;
    }
    FD_TEST( cnt > 0 );
    ulong off = 0UL;
    for( ulong j=0UL; j<cnt; j++ ) {
      tlv_meta_t meta[1];
      off = fd_snp_tlv_extract( buf, off, meta );
      FD_TEST( meta[0].type == tlv_meta[ j ].type );
      FD_TEST( meta[0].len  == tlv_meta[ j ].len  );
      FD_TEST( meta[0].u8   == tlv_meta[ j ].u8   );
      FD_TEST( meta[0].u16  == tlv_meta[ j ].u16  );
      FD_TEST( meta[0].u32  == tlv_meta[ j ].u32  );
      FD_TEST( meta[0].u64  == tlv_meta[ j ].u64  );
      FD_TEST( meta[0].ptr  == tlv_meta[ j ].ptr  );
    }
  }
  fd_rng_delete( fd_rng_leave( r ) );
#undef BUF_SZ
}

static void
test_meta( void ) {
  FD_LOG_NOTICE(( "test_meta" ));
#define BUF_SZ ( 2048UL )
  fd_rng_t _rng[ 1 ]; fd_rng_t * r = fd_rng_join( fd_rng_new( _rng, (uint)fd_tickcount() /*seed*/, 0UL ) );
  ulong  exp_snp_proto[ BUF_SZ ];
  uchar  exp_snp_app_id[ BUF_SZ ];
  uint   exp_ip4[ BUF_SZ ];
  ushort exp_port[ BUF_SZ ];
  fd_snp_meta_t meta[ BUF_SZ ];
  for( ulong i=0UL; i<BUF_SZ; i++ ) {
    exp_snp_proto[ i ]  = fd_rng_ulong( r ) & FD_SNP_META_PROTO_MASK;
    exp_snp_app_id[ i ] = fd_rng_uchar( r ) & 0xf;
    exp_ip4[ i ]        = fd_rng_uint( r );
    exp_port[ i ]       = fd_rng_ushort( r );
    meta[ i ]           = fd_snp_meta_from_parts( exp_snp_proto[ i ], exp_snp_app_id[ i ], exp_ip4[ i ], exp_port[ i ] );
  }
  for( ulong i=0UL; i<BUF_SZ; i++ ) {
    ulong  got_snp_proto  = 0UL;
    uchar  got_snp_app_id = 0;
    uint   got_ip4        = 0;
    ushort got_port       = 0;
    fd_snp_meta_into_parts( &got_snp_proto, &got_snp_app_id, &got_ip4, &got_port, meta[ i ] );
    FD_TEST( got_snp_proto  == exp_snp_proto[ i ]  );
    FD_TEST( got_snp_app_id == exp_snp_app_id[ i ] );
    FD_TEST( got_ip4        == exp_ip4[ i ]        );
    FD_TEST( got_port       == exp_port[ i ]       );
  }
  fd_rng_delete( fd_rng_leave( r ) );
#undef BUF_SZ
}

static void
test_peer_addr( void ) {
  FD_LOG_NOTICE(( "test_peer_addr" ));
#define BUF_SZ ( 2048UL )
  fd_rng_t _rng[ 1 ]; fd_rng_t * r = fd_rng_join( fd_rng_new( _rng, (uint)fd_tickcount() /*seed*/, 0UL ) );
  uint   exp_ip4[ BUF_SZ ];
  ushort exp_port[ BUF_SZ ];
  ulong  peer_addr[ BUF_SZ ];
  ulong  meta[ BUF_SZ ];
  for( ulong i=0UL; i<BUF_SZ; i++ ) {
    exp_ip4[ i ]   = fd_rng_uint( r );
    exp_port[ i ]  = fd_rng_ushort( r );
    peer_addr[ i ] = ( ((ulong)exp_port[ i ])<<32 ) | ( ((ulong)exp_ip4[ i ])<<0 );
    meta[ i ]      = ( fd_rng_ulong( r ) & ~FD_SNP_META_PEER_MASK ) | peer_addr[ i ];
  }
  for( ulong i=0UL; i<BUF_SZ; i++ ) {
    FD_TEST( peer_addr[ i ] == fd_snp_peer_addr_from_meta( meta[ i ] ) );
    FD_TEST( peer_addr[ i ] == fd_snp_peer_addr_from_parts( exp_ip4[ i ], exp_port[ i ] ) );
    uint   got_ip4  = 0;
    ushort got_port = 0;
    fd_snp_peer_addr_into_parts( &got_ip4, &got_port, peer_addr[ i ] );
    FD_TEST( got_ip4  == exp_ip4[ i ]  );
    FD_TEST( got_port == exp_port[ i ] );
  }
  fd_rng_delete( fd_rng_leave( r ) );
#undef BUF_SZ
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_tlv_parsing();

  test_meta();

  test_peer_addr();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}