#include "ag_bls_serde.h"

#define FAIL( cond, err ) do { if( FD_UNLIKELY( cond ) ) return AG_BLS_DE_ERR_##err; } while( 0 )

#define BASE2_BITMAP (0)
#define BASE3_BITMAP (1)

static ulong
bit_cnt( fd_bls_agg_t const * agg ) {
  return fd_ulong_min( FD_BLS_SET_MAX, fd_bls_set_last( agg->set )+1UL );
}

ulong
ag_bls_agg_ser_sz( fd_bls_agg_t const * agg ) {
  return AG_BLS_AGG_SER_SZ( bit_cnt( agg ) );
}

ulong
ag_bls_agg_pair_ser_sz( fd_bls_agg_t const * agg,
                        fd_bls_agg_t const * agg2 ) {
  return AG_BLS_AGG_PAIR_SER_SZ( fd_ulong_max( bit_cnt( agg ), bit_cnt( agg2 ) ) );
}

ulong
ag_bls_agg_ser( fd_bls_agg_t const * agg,
                uchar *              buf ) {

  ulong bits = bit_cnt( agg );

  ag_bls_agg_serde_t serde[1];
  serde->version = (uchar)BASE2_BITMAP;
  serde->bit_cnt = (ushort)bits;
  serde->payload    = NULL;
  serde->payload_sz = ag_bls_agg_ser_sz( agg ) - AG_BLS_AGG_HDR_SZ;

  ulong off = 0UL;
  buf[ off ] = serde->version;                 off += sizeof(uchar);
  FD_STORE( ushort, buf+off, serde->bit_cnt ); off += sizeof(ushort);

  uchar * p = buf+off;
  fd_memset( p, 0, serde->payload_sz );
  for( ulong i=0UL; i<bits; i++ ) {
    if( FD_LIKELY( fd_bls_set_test( agg->set, i ) ) ) p[ i>>3 ] |= (uchar)( 1U << (i&7U) );
  }
  off += serde->payload_sz;

  return off;
}

ulong
ag_bls_agg_pair_ser( fd_bls_agg_t const * agg,
                     fd_bls_agg_t const * agg2,
                     uchar *              buf ) {

  ulong bits = fd_ulong_max( bit_cnt( agg ), bit_cnt( agg2 ) );

  ag_bls_agg_serde_t serde[1];
  serde->version = (uchar)BASE3_BITMAP;
  serde->bit_cnt = (ushort)bits;
  serde->payload    = NULL;
  serde->payload_sz = ag_bls_agg_pair_ser_sz( agg, agg2 ) - AG_BLS_AGG_HDR_SZ;

  ulong off = 0UL;
  buf[ off ] = serde->version;                 off += sizeof(uchar);
  FD_STORE( ushort, buf+off, serde->bit_cnt ); off += sizeof(ushort);

  uchar * p = buf+off;
  for( ulong chunk=0UL; chunk<serde->payload_sz; chunk++ ) {
    ulong start = chunk*5UL;
    ulong end   = fd_ulong_min( start+5UL, bits );
    uint  block = 0U;
    uint  place = 1U;
    for( ulong i=start; i<end; i++ ) {
      uint digit = fd_bls_set_test( agg->set,  i ) ? 1U
                 : fd_bls_set_test( agg2->set, i ) ? 2U : 0U;
      block += digit*place;
      place *= 3U;
    }
    p[ chunk ] = (uchar)block;
  }
  off += serde->payload_sz;

  return off;
}

static int
bitmap_hdr( ag_bls_agg_serde_t * bm,
            uchar const *        b,
            ulong                b_sz ) {
  FAIL( b_sz<AG_BLS_AGG_HDR_SZ, SZ );

  bm->version    = b[ 0 ];
  bm->bit_cnt    = FD_LOAD( ushort, b+1UL );
  bm->payload    = b+AG_BLS_AGG_HDR_SZ;
  bm->payload_sz = b_sz-AG_BLS_AGG_HDR_SZ;

  return AG_BLS_DE_SUCCESS;
}

static int
base2_de( fd_bls_agg_t *             agg,
          ag_bls_agg_serde_t const * bm ) {
  ulong bits = (ulong)bm->bit_cnt;
  FAIL( bits>FD_BLS_SET_MAX,                                         SZ );
  FAIL( bm->payload_sz!=AG_BLS_AGG_SER_SZ( bits )-AG_BLS_AGG_HDR_SZ, INVAL );

  memset( agg, 0, sizeof(fd_bls_agg_t) ); /* zero is the point at infinity */

  for( ulong i=0UL; i<bits; i++ ) {
    if( FD_LIKELY( (bm->payload[ i>>3 ] >> (i&7U)) & 1U ) ) fd_bls_set_insert( agg->set, i );
  }
  return AG_BLS_DE_SUCCESS;
}

static int
base3_de( fd_bls_agg_t *             agg,
          fd_bls_agg_t *             agg2,
          ag_bls_agg_serde_t const * bm ) {
  ulong bits    = (ulong)bm->bit_cnt;
  ulong nchunks = AG_BLS_AGG_PAIR_SER_SZ( bits )-AG_BLS_AGG_HDR_SZ;
  FAIL( bits>FD_BLS_SET_MAX, SZ );
  FAIL( bm->payload_sz!=nchunks, INVAL );

  memset( agg,  0, sizeof(fd_bls_agg_t) ); /* zero is the point at infinity */
  memset( agg2, 0, sizeof(fd_bls_agg_t) );

  for( ulong chunk=0UL; chunk<nchunks; chunk++ ) {
    uint  block = (uint)bm->payload[ chunk ];
    ulong start = chunk*5UL;
    ulong end   = fd_ulong_min( start+5UL, bits );
    for( ulong i=start; i<end; i++ ) {
      uint digit = block % 3U; block /= 3U;
      if(      FD_LIKELY  ( digit==1U ) ) fd_bls_set_insert( agg->set,  i );
      else if( FD_UNLIKELY( digit==2U ) ) fd_bls_set_insert( agg2->set, i );
    }
  }
  return AG_BLS_DE_SUCCESS;
}

int
ag_bls_agg_de( fd_bls_agg_t * agg,
               uchar const *  b,
               ulong          b_sz ) {
  ag_bls_agg_serde_t bm[1];

  int err = bitmap_hdr( bm, b, b_sz );
  if( FD_UNLIKELY( err                       ) ) return err;
  FAIL( bm->version!=BASE2_BITMAP, INVAL );

  return base2_de( agg, bm );
}

int
ag_bls_agg_pair_de( fd_bls_agg_t * agg,
                    fd_bls_agg_t * agg2,
                    uchar const *  b,
                    ulong          b_sz ) {
  ag_bls_agg_serde_t bm[1];

  int err = bitmap_hdr( bm, b, b_sz );
  if( FD_UNLIKELY( err ) ) return err;

  switch( bm->version ) {
  case BASE2_BITMAP:
    err = base2_de( agg, bm );
    if( FD_UNLIKELY( err ) ) return err;
    memset( agg2, 0, sizeof(fd_bls_agg_t) );
    return AG_BLS_DE_SUCCESS;
  case BASE3_BITMAP:
    return base3_de( agg, agg2, bm );
  default:
    return AG_BLS_DE_ERR_INVAL;
  }
}
