#include "fd_snp_common.h"
#include "../../util/fd_util.h"

static void
test_tlv_parsing( void ) {
#define BUF_SZ ( 2048UL )
  FD_LOG_NOTICE(( "test_tlv_parsing" ));
  fd_rng_t _rng[ 1 ]; fd_rng_t * r = fd_rng_join( fd_rng_new( _rng, (uint)fd_tickcount() /*seed*/, 0UL ) );
  uchar     buf[ BUF_SZ ];
  fd_snp_tlv_t exp[ 1024UL ];
  for( ulong i=0UL; i<128UL; i++ ) {
    ulong cnt = 0UL;
    ulong sz  = 0UL;
    ulong buf_sz = 0UL;
    while( sz < BUF_SZ ) {
      uchar type = fd_rng_uchar( r );
      ushort len = fd_rng_ushort_roll( r, 16UL )+1UL;
      if( ( sz + len + 3UL ) <= BUF_SZ ) {
        exp[ cnt ].type = type;
        exp[ cnt ].len  = len;
        exp[ cnt ].ptr  = &buf[ sz + 3UL ];
        fd_memcpy( buf + sz + 0UL, &type, 1UL );
        fd_memcpy( buf + sz + 1UL,  &len, 2UL );
        for( ulong k=0; k<len; k++ ) buf[ sz + 3UL + k ] = fd_rng_uchar( r );
        buf_sz += len + 3UL;
        cnt++;
      }
      sz += len + 3UL;
    }
    FD_TEST( cnt > 0 );
    /* test tlv extract */
    ulong off = 0UL;
    for( ulong j=0UL; j<cnt; j++ ) {
      FD_TEST( fd_snp_tlv_extract_type( buf + off ) == exp[ j ].type );
      FD_TEST( fd_snp_tlv_extract_len(  buf + off ) == exp[ j ].len  );
      FD_TEST( fd_snp_tlv_extract_ptr(  buf + off ) == exp[ j ].ptr  );
      fd_snp_tlv_t got = fd_snp_tlv_extract_tlv( buf + off );
      FD_TEST( got.type == exp[ j ].type );
      FD_TEST( got.len  == exp[ j ].len  );
      FD_TEST( got.ptr  == exp[ j ].ptr  );
      off += got.len + 3UL;
    }
    /* test tlv iterator */
    ulong k = 0;
    fd_snp_tlv_iter_t iter = fd_snp_tlv_iter_init( buf_sz );
    for( ;    !fd_snp_tlv_iter_done( iter, buf );
        iter = fd_snp_tlv_iter_next( iter, buf ) ) {
      FD_TEST( fd_snp_tlv_iter_type( iter, buf ) == exp[ k ].type );
      FD_TEST( fd_snp_tlv_iter_len(  iter, buf ) == exp[ k ].len  );
      FD_TEST( fd_snp_tlv_iter_ptr(  iter, buf ) == exp[ k ].ptr  );
      fd_snp_tlv_t got = fd_snp_tlv_iter_tlv( iter, buf );
      FD_TEST( got.type == exp[ k ].type );
      FD_TEST( got.len  == exp[ k ].len  );
      FD_TEST( got.ptr  == exp[ k ].ptr  );
      k++;
    }
    FD_TEST( k==cnt );
    FD_TEST( iter.off == buf_sz );
    FD_TEST( iter.rem == 0L );
  }
  fd_rng_delete( fd_rng_leave( r ) );
#undef BUF_SZ
}

static void
test_tlv_parsing_len_error( void ) {
#define BUF_SZ ( 256L )
#define TLV_SZ ( 128L )
  FD_LOG_NOTICE(( "test_tlv_parsing_len_error" ));
  fd_rng_t _rng[ 1 ]; fd_rng_t * r = fd_rng_join( fd_rng_new( _rng, (uint)fd_tickcount() /*seed*/, 0UL ) );
  uchar     buf[ BUF_SZ ];
  long      len0 = TLV_SZ-3L;
  for( long len=(len0-2L); len<(len0+4L); len++ ) {
    fd_snp_tlv_t exp;
    exp.type = fd_rng_uchar( r );
    exp.len  = (ushort)len;
    exp.ptr  = &buf[ 3UL ];
    fd_memcpy( buf + 0UL, &exp.type, 1UL );
    fd_memcpy( buf + 1UL, &exp.len,  2UL );
    for( long k=0; k<len; k++ ) buf[ 3L + k ] = fd_rng_uchar( r );
    /* test tlv extract */
    FD_TEST( fd_snp_tlv_extract_type( buf ) == exp.type );
    FD_TEST( fd_snp_tlv_extract_len(  buf ) == exp.len  );
    FD_TEST( fd_snp_tlv_extract_ptr(  buf ) == exp.ptr  );
    fd_snp_tlv_t got = fd_snp_tlv_extract_tlv( buf );
    FD_TEST( got.type == exp.type );
    FD_TEST( got.len  == exp.len  );
    FD_TEST( got.ptr  == exp.ptr  );
    /* test tlv iterator */
    int k = 0;
    fd_snp_tlv_iter_t iter = fd_snp_tlv_iter_init( TLV_SZ );
    for( ;    !fd_snp_tlv_iter_done( iter, buf );
        iter = fd_snp_tlv_iter_next( iter, buf ) ) {
      FD_TEST( fd_snp_tlv_iter_type( iter, buf ) == exp.type );
      FD_TEST( fd_snp_tlv_iter_len(  iter, buf ) == exp.len  );
      FD_TEST( fd_snp_tlv_iter_ptr(  iter, buf ) == exp.ptr  );
      fd_snp_tlv_t got = fd_snp_tlv_iter_tlv( iter, buf );
      FD_TEST( got.type == exp.type );
      FD_TEST( got.len  == exp.len  );
      FD_TEST( got.ptr  == exp.ptr  );
      k++;
    }
    FD_TEST( k==1 );
    FD_TEST( iter.off == (ulong)( len + 3L ) );
    FD_TEST( iter.rem == ( (long)len0 - (long)len ) );
  }
  fd_rng_delete( fd_rng_leave( r ) );
#undef TLV_SZ
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

  test_tlv_parsing_len_error();

  test_meta();

  test_peer_addr();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}