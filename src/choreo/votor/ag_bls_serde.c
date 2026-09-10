#include "ag_bls_serde.h"

#define FAIL( cond, err ) do { if( FD_UNLIKELY( cond ) ) return AG_BLS_DE_ERR_##err; } while( 0 )

#define BASE2_BITMAP (0)
#define BASE3_BITMAP (1)

static ulong
agg_bit_cnt( fd_bls_agg_t const * agg ) {
  return fd_ulong_min( FD_BLS_SET_MAX, fd_bls_set_last( agg->set )+1UL );
}

ulong
ag_bls_agg_ser_sz( fd_bls_agg_t const * agg ) {
  return AG_BLS_AGG_SER_SZ( agg_bit_cnt( agg ) );
}

ulong
ag_bls_agg_pair_ser_sz( fd_bls_agg_t const * agg,
                        fd_bls_agg_t const * agg_fb ) {
  return AG_BLS_AGG_PAIR_SER_SZ( fd_ulong_max( agg_bit_cnt( agg ), agg_bit_cnt( agg_fb ) ) );
}

ulong
ag_bls_agg_ser( fd_bls_agg_t const * agg,
                uchar *              buf ) {

  ulong bit_cnt = agg_bit_cnt( agg );

  ag_bls_agg_serde_t serde[1];
  serde->version = (uchar)BASE2_BITMAP;
  serde->bit_cnt = (ushort)bit_cnt;
  serde->payload    = NULL;
  serde->payload_sz = ag_bls_agg_ser_sz( agg ) - AG_BLS_AGG_HDR_SZ;

  ulong off = 0UL;
  buf[ off ] = serde->version;                 off += sizeof(uchar);
  FD_STORE( ushort, buf+off, serde->bit_cnt ); off += sizeof(ushort);

  uchar * payload = buf+off;
  fd_memset( payload, 0, serde->payload_sz );
  for( ulong i=0UL; i<bit_cnt; i++ ) {
    if( FD_LIKELY( fd_bls_set_test( agg->set, i ) ) ) payload[ i>>3 ] |= (uchar)( 1U << (i&7U) );
  }
  off += serde->payload_sz;

  return off;
}

ulong
ag_bls_agg_pair_ser( fd_bls_agg_t const * agg,
                     fd_bls_agg_t const * agg_fb,
                     uchar *              buf ) {

  ulong bit_cnt = fd_ulong_max( agg_bit_cnt( agg ), agg_bit_cnt( agg_fb ) );

  ag_bls_agg_serde_t serde[1];
  serde->version = (uchar)BASE3_BITMAP;
  serde->bit_cnt = (ushort)bit_cnt;
  serde->payload    = NULL;
  serde->payload_sz = ag_bls_agg_pair_ser_sz( agg, agg_fb ) - AG_BLS_AGG_HDR_SZ;

  ulong off = 0UL;
  buf[ off ] = serde->version;                 off += sizeof(uchar);
  FD_STORE( ushort, buf+off, serde->bit_cnt ); off += sizeof(ushort);

  uchar * payload = buf+off;
  for( ulong chunk=0UL; chunk<serde->payload_sz; chunk++ ) {
    ulong start_bit = chunk*5UL;
    ulong end_bit   = fd_ulong_min( start_bit+5UL, bit_cnt );
    uint  block     = 0U;
    uint  place     = 1U;
    for( ulong i=start_bit; i<end_bit; i++ ) {
      uint digit = fd_bls_set_test( agg->set,    i ) ? 1U
                 : fd_bls_set_test( agg_fb->set, i ) ? 2U : 0U;
      block += digit*place;
      place *= 3U;
    }
    payload[ chunk ] = (uchar)block;
  }
  off += serde->payload_sz;

  return off;
}

static int
bitmap_hdr( ag_bls_agg_serde_t * serde,
            uchar const *        buf,
            ulong                buf_sz ) {
  FAIL( buf_sz<AG_BLS_AGG_HDR_SZ, SZ );

  serde->version    = buf[ 0 ];
  serde->bit_cnt    = FD_LOAD( ushort, buf+1UL );
  serde->payload    = buf+AG_BLS_AGG_HDR_SZ;
  serde->payload_sz = buf_sz-AG_BLS_AGG_HDR_SZ;

  return AG_BLS_DE_SUCCESS;
}

static int
base2_de( fd_bls_agg_t *             agg,
          ag_bls_agg_serde_t const * serde ) {
  ulong bit_cnt = (ulong)serde->bit_cnt;
  FAIL( bit_cnt>FD_BLS_SET_MAX,                                            SZ    );
  FAIL( serde->payload_sz!=AG_BLS_AGG_SER_SZ( bit_cnt )-AG_BLS_AGG_HDR_SZ, INVAL );

  memset( agg, 0, sizeof(fd_bls_agg_t) ); /* zero is the point at infinity */

  for( ulong i=0UL; i<bit_cnt; i++ ) {
    if( FD_LIKELY( (serde->payload[ i>>3 ] >> (i&7U)) & 1U ) ) fd_bls_set_insert( agg->set, i );
  }
  return AG_BLS_DE_SUCCESS;
}

static int
base3_de( fd_bls_agg_t *             agg,
          fd_bls_agg_t *             agg_fb,
          ag_bls_agg_serde_t const * serde ) {
  ulong bit_cnt   = (ulong)serde->bit_cnt;
  ulong chunk_cnt = AG_BLS_AGG_PAIR_SER_SZ( bit_cnt )-AG_BLS_AGG_HDR_SZ;
  FAIL( bit_cnt>FD_BLS_SET_MAX, SZ );
  FAIL( serde->payload_sz!=chunk_cnt, INVAL );

  memset( agg,  0, sizeof(fd_bls_agg_t) ); /* zero is the point at infinity */
  memset( agg_fb, 0, sizeof(fd_bls_agg_t) );

  for( ulong chunk=0UL; chunk<chunk_cnt; chunk++ ) {
    uint  block     = (uint)serde->payload[ chunk ];
    ulong start_bit = chunk*5UL;
    ulong end_bit   = fd_ulong_min( start_bit+5UL, bit_cnt );
    for( ulong i=start_bit; i<end_bit; i++ ) {
      uint digit = block % 3U; block /= 3U;
      if(      FD_LIKELY  ( digit==1U ) ) fd_bls_set_insert( agg->set,    i );
      else if( FD_UNLIKELY( digit==2U ) ) fd_bls_set_insert( agg_fb->set, i );
    }
  }
  return AG_BLS_DE_SUCCESS;
}

int
ag_bls_agg_de( fd_bls_agg_t * agg,
               uchar const *  buf,
               ulong          buf_sz ) {
  ag_bls_agg_serde_t serde[1];

  int err = bitmap_hdr( serde, buf, buf_sz );
  if( FD_UNLIKELY( err                       ) ) return err;
  FAIL( serde->version!=BASE2_BITMAP, INVAL );

  return base2_de( agg, serde );
}

int
ag_bls_agg_pair_de( fd_bls_agg_t * agg,
                    fd_bls_agg_t * agg_fb,
                    uchar const *  buf,
                    ulong          buf_sz ) {
  ag_bls_agg_serde_t serde[1];

  int err = bitmap_hdr( serde, buf, buf_sz );
  if( FD_UNLIKELY( err ) ) return err;

  switch( serde->version ) {
  case BASE2_BITMAP:
    err = base2_de( agg, serde );
    if( FD_UNLIKELY( err ) ) return err;
    memset( agg_fb, 0, sizeof(fd_bls_agg_t) );
    return AG_BLS_DE_SUCCESS;
  case BASE3_BITMAP:
    return base3_de( agg, agg_fb, serde );
  default:
    return AG_BLS_DE_ERR_INVAL;
  }
}
