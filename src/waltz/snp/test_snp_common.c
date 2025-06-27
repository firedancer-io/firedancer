#include "fd_snp_common.h"
#include "../../util/fd_util.h"

static void
test_tlv_parsing( void ) {
#define BUF_SZ ( 2048UL )
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
#undef BUF_SZ
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_tlv_parsing();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}