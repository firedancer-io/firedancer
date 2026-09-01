#include "ag_bls_serde.h"

/* FAIL returns the named AG_BLS_DE_ code when cond holds. */

#define FAIL( cond, err ) do { if( FD_UNLIKELY( cond ) ) return AG_BLS_DE_ERR_##err; } while( 0 )

#define BASE2_BITMAP (0)
#define BASE3_BITMAP (1)

/* One past the highest rank, or zero when nobody signed.  Agave trims
   the rank bitvec to exactly this width when it builds a certificate, and
   to the wider of the two partitions for base3. */

static ulong
bit_cnt( ag_bls_agg_t const * agg ) {
  return fd_ulong_min( AG_BLS_SIGNERS_MAX, signer_set_last( agg->bitmask )+1UL );
}

ulong
ag_bls_agg_ser_sz( ag_bls_agg_t const * agg ) {
  return AG_BLS_AGG_SER_SZ( bit_cnt( agg ) );
}

ulong
ag_bls_agg_pair_ser_sz( ag_bls_agg_t const * base,
                        ag_bls_agg_t const * fb ) {
  return AG_BLS_AGG_PAIR_SER_SZ( fd_ulong_max( bit_cnt( base ), bit_cnt( fb ) ) );
}

ulong
ag_bls_agg_ser( ag_bls_agg_t const * agg,
                uchar *              buf ) {
  ag_bls_agg_serde_t bm[1];

  ulong bits = bit_cnt( agg );

  bm->version = (uchar)BASE2_BITMAP;
  bm->bit_cnt = (ushort)bits;
  bm->payload    = NULL; /* the packed ranks exist nowhere to point at, so they go
                            into buf below rather than being copied out of agg */
  bm->payload_sz = ag_bls_agg_ser_sz( agg ) - AG_BLS_AGG_HDR_SZ;

  ulong off = 0UL;
  buf[ off ] = bm->version;                 off += sizeof(uchar);
  FD_STORE( ushort, buf+off, bm->bit_cnt ); off += sizeof(ushort);

  uchar * p = buf+off;
  fd_memset( p, 0, bm->payload_sz );
  for( ulong i=0UL; i<bits; i++ ) {
    if( signer_set_test( agg->bitmask, i ) ) p[ i>>3 ] |= (uchar)( 1U << (i&7U) );
  }
  off += bm->payload_sz;

  return off;
}

ulong
ag_bls_agg_pair_ser( ag_bls_agg_t const * base,
                     ag_bls_agg_t const * fb,
                     uchar *              buf ) {
  ag_bls_agg_serde_t bm[1];

  ulong bits = fd_ulong_max( bit_cnt( base ), bit_cnt( fb ) );

  bm->version = (uchar)BASE3_BITMAP;
  bm->bit_cnt = (ushort)bits;
  bm->payload    = NULL; /* as in ag_bls_agg_ser: packed into buf, not copied */
  bm->payload_sz = ag_bls_agg_pair_ser_sz( base, fb ) - AG_BLS_AGG_HDR_SZ;

  ulong off = 0UL;
  buf[ off ] = bm->version;                 off += sizeof(uchar);
  FD_STORE( ushort, buf+off, bm->bit_cnt ); off += sizeof(ushort);

  uchar * p = buf+off;
  for( ulong chunk=0UL; chunk<bm->payload_sz; chunk++ ) {
    ulong start = chunk*5UL;
    ulong end   = fd_ulong_min( start+5UL, bits );
    uint  block = 0U;
    uint  place = 1U;
    for( ulong i=start; i<end; i++ ) {
      uint digit = signer_set_test( base->bitmask, i ) ? 1U
                 : signer_set_test( fb->bitmask,   i ) ? 2U : 0U;
      block += digit*place;
      place *= 3U;
    }
    p[ chunk ] = (uchar)block;
  }
  off += bm->payload_sz;

  return off;
}

/* bitmap_hdr reads the bitmap's framing out of b.  b_sz is the whole
   bitmap, so whatever is left after the framing is the payload. */

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
base2_de( ag_bls_agg_t *             agg,
          ag_bls_agg_serde_t const * bm ) {
  ulong bits = (ulong)bm->bit_cnt;
  FAIL( bits>AG_BLS_SIGNERS_MAX,                                     SZ );
  FAIL( bm->payload_sz!=AG_BLS_AGG_SER_SZ( bits )-AG_BLS_AGG_HDR_SZ, INVAL );

  ag_bls_agg_zero( agg );

  for( ulong i=0UL; i<bits; i++ ) {
    if( (bm->payload[ i>>3 ] >> (i&7U)) & 1U ) signer_set_insert( agg->bitmask, i );
  }
  return AG_BLS_DE_SUCCESS;
}

static int
base3_de( ag_bls_agg_t *             base,
          ag_bls_agg_t *             fb,
          ag_bls_agg_serde_t const * bm ) {
  ulong bits    = (ulong)bm->bit_cnt;
  ulong nchunks = AG_BLS_AGG_PAIR_SER_SZ( bits )-AG_BLS_AGG_HDR_SZ;
  FAIL( bits>AG_BLS_SIGNERS_MAX, SZ );
  FAIL( bm->payload_sz!=nchunks, INVAL );

  ag_bls_agg_zero( base );
  ag_bls_agg_zero( fb   );

  for( ulong chunk=0UL; chunk<nchunks; chunk++ ) {
    uint  block = (uint)bm->payload[ chunk ];
    ulong start = chunk*5UL;
    ulong end   = fd_ulong_min( start+5UL, bits );
    for( ulong i=start; i<end; i++ ) {
      uint digit = block % 3U; block /= 3U;
      if(      digit==1U ) signer_set_insert( base->bitmask, i );
      else if( digit==2U ) signer_set_insert( fb->bitmask,   i );
    }
  }
  return AG_BLS_DE_SUCCESS;
}

int
ag_bls_agg_de( ag_bls_agg_t * agg,
               uchar const *  b,
               ulong          b_sz ) {
  ag_bls_agg_serde_t bm[1];

  int err = bitmap_hdr( bm, b, b_sz );
  if( FD_UNLIKELY( err                       ) ) return err;
  FAIL( bm->version!=BASE2_BITMAP, INVAL );

  return base2_de( agg, bm );
}

int
ag_bls_agg_pair_de( ag_bls_agg_t * base,
                    ag_bls_agg_t * fb,
                    uchar const *  b,
                    ulong          b_sz ) {
  ag_bls_agg_serde_t bm[1];

  int err = bitmap_hdr( bm, b, b_sz );
  if( FD_UNLIKELY( err ) ) return err;

  switch( bm->version ) {
  case BASE2_BITMAP:
    /* one partition: everyone who signed is in the base set */
    err = base2_de( base, bm );
    if( FD_UNLIKELY( err ) ) return err;
    ag_bls_agg_zero( fb );
    return AG_BLS_DE_SUCCESS;
  case BASE3_BITMAP:
    return base3_de( base, fb, bm );
  default:
    return AG_BLS_DE_ERR_INVAL;
  }
}
