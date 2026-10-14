#include "fd_bls.h"

#include "../../third_party/blst/bindings/blst.h"

void
fd_bls_sec_to_pub( fd_bls_sec_t const * sk,
                   fd_bls_pub_t *       pk ) {
  blst_sk_to_pk_in_g1( pk, sk );
}

void
fd_bls_sec_sign( fd_bls_sec_t const * sk,
                 uchar const *        msg,
                 ulong                msg_sz,
                 fd_bls_sig_t *       sig ) {
  blst_p2 hash[1];
  blst_p2 p[1];
  blst_hash_to_g2( hash, msg, msg_sz, (uchar const *)FD_BLS_DST, FD_BLS_DST_SZ, NULL, 0UL );
  blst_sign_pk_in_g1( p, hash, sk );
  blst_p2_to_affine( sig, p );
}

void
fd_bls_sec_derive( fd_bls_sec_t * sk,
                   uchar const *  ikm,
                   ulong          ikm_sz ) {
  FD_TEST( ikm_sz>=32UL );
  blst_keygen( sk, ikm, ikm_sz, NULL, 0UL );
}

void
fd_bls_sig_ser( fd_bls_sig_t const * sig,
                uchar                buf[ static FD_BLS_SIG_SZ ] ) {
  blst_p2_affine_serialize( buf, sig );
}

int
fd_bls_sig_de( fd_bls_sig_t * sig,
               uchar const    buf[ static FD_BLS_SIG_SZ ] ) {
  if( FD_UNLIKELY( blst_p2_deserialize( sig, buf )!=BLST_SUCCESS ) ) return -1;
  if( FD_UNLIKELY( !blst_p2_affine_in_g2( sig ) ) )                  return -1;
  return 0;
}

static int
pub_from_bytes( blst_p1_affine * out,
                uchar const *    in,
                ulong            in_sz ) {
  BLST_ERROR err;
  switch( in_sz ) {
  case FD_BLS_PUB_COMPRESSED_SZ: err = blst_p1_uncompress ( out, in ); break;
  case FD_BLS_PUB_SZ:
    if( FD_UNLIKELY( in[0]&0xA0U ) ) return 0;
    err = blst_p1_deserialize( out, in );
    break;
  default: return 0;
  }
  return err==BLST_SUCCESS &&
         !blst_p1_affine_is_inf( out ) &&
         blst_p1_affine_in_g1( out );
}

int
fd_bls_pub_de( fd_bls_pub_t * pub,
               uchar const *  buf,
               ulong          buf_sz ) {
  blst_p1_affine a[1];
  if( FD_UNLIKELY( !pub_from_bytes( a, buf, buf_sz ) ) ) return -1;
  blst_p1_from_affine( pub, a );
  return 0;
}

fd_bls_agg_t *
fd_bls_agg_null( fd_bls_agg_t * agg ) {
  fd_memset( &agg->pub, 0, sizeof(fd_bls_pub_t) );
  fd_memset( &agg->sig, 0, sizeof(blst_p2) );
  fd_bls_set_null( agg->set );
  return agg;
}

fd_bls_agg_t *
fd_bls_agg_construct( fd_bls_agg_t *       agg,
                      fd_bls_pub_t const * pub,
                      fd_bls_sig_t const * sig,
                      fd_bls_set_t const * set ) {
  fd_bls_set_copy( agg->set, set );
  for( ulong rank = fd_bls_set_const_iter_init( set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( set, rank ) ) {
    blst_p1_add_or_double( &agg->pub, &agg->pub, pub+rank );
    blst_p2_add_or_double_affine( &agg->sig, &agg->sig, sig+rank );
  }
  return agg;
}

fd_bls_pub_t *
fd_bls_pub_sum( fd_bls_pub_t *         pub,
                blst_p1_affine const * key,
                ulong                  key_cnt,
                fd_bls_set_t const *   set,
                fd_bls_pub_t const *   full ) {
  fd_memset( pub, 0, sizeof(fd_bls_pub_t) ); /* point at infinity */

  if( FD_LIKELY( !full || 2UL*fd_bls_set_cnt( set )<=key_cnt ) ) {
    for( ulong rank=0UL; rank<key_cnt; rank++ ) {
      if( fd_bls_set_test( set, rank ) ) blst_p1_add_or_double_affine( pub, pub, key+rank );
    }
    return pub;
  }

  /* full minus the keys not in set */
  for( ulong rank=0UL; rank<key_cnt; rank++ ) {
    if( !fd_bls_set_test( set, rank ) ) blst_p1_add_or_double_affine( pub, pub, key+rank );
  }
  blst_p1_cneg( pub, 1 );
  blst_p1_add_or_double( pub, full, pub );
  return pub;
}


void
fd_bls_hash_msg( uchar const *    msg,
                 ulong            msg_sz,
                 blst_p2_affine * h ) {
  blst_p2 p[1];
  blst_hash_to_g2( p, msg, msg_sz, (uchar const *)FD_BLS_DST, FD_BLS_DST_SZ, NULL, 0UL );
  blst_p2_to_affine( h, p );
}

/* agg_pairing computes gt = e(pub,h) / e(G1,sig), which is the identity iff
   sig is a valid signature on h under pub. */

static blst_fp12 *
agg_pairing( blst_fp12 *            gt,
        blst_p2_affine const * h,
        fd_bls_pub_t const *   pub,
        blst_p2 const *        sig ) {
  blst_p1_affine         a[2];
  blst_p2_affine         b[2];
  blst_p1_affine const * aptr[2];
  blst_p2_affine const * bptr[2];
  ulong                  n = 0UL;
  if( FD_LIKELY( !blst_p1_is_inf( pub ) && !blst_p2_affine_is_inf( h ) ) ) { blst_p1_to_affine( a+n, pub ); b[n] = *h;                     aptr[n] = a+n; bptr[n] = b+n; n++; }
  if( FD_LIKELY( !blst_p2_is_inf( sig )                                ) ) { a[n] = BLS12_381_NEG_G1;       blst_p2_to_affine( b+n, sig ); aptr[n] = a+n; bptr[n] = b+n; n++; }
  if( FD_UNLIKELY( !n ) ) { *gt = *blst_fp12_one(); return gt; }
  blst_miller_loop_n( gt, bptr, aptr, n );
  blst_final_exp( gt, gt );
  return gt;
}

int
fd_bls_agg_verify_hashed( blst_p2_affine const * h,
                          fd_bls_pub_t const *   pub,
                          blst_p2 const *        sig ) {
  if( FD_UNLIKELY( blst_p2_affine_is_inf( h ) || blst_p1_is_inf( pub ) || blst_p2_is_inf( sig ) ) ) return 0;
  blst_fp12 gt[1];
  return !!blst_fp12_is_one( agg_pairing( gt, h, pub, sig ) );
}

int
fd_bls_agg_verify( uchar const *        msg,
                   ulong                msg_sz,
                   fd_bls_pub_t const * pub,
                   blst_p2 const *      sig ) {
  if( FD_UNLIKELY( blst_p1_is_inf( pub ) || blst_p2_is_inf( sig ) ) ) return 0;
  blst_p2_affine h[1];
  fd_bls_hash_msg( msg, msg_sz, h );
  return fd_bls_agg_verify_hashed( h, pub, sig );
}

static fd_bls_set_t *
verify_linear_hashed( fd_bls_agg_t const *   agg,
                      blst_p2_affine const * h,
                      fd_bls_pub_t const *   pub,
                      fd_bls_sig_t const *   sig,
                      fd_bls_set_t *         bad ) {
  fd_bls_set_null( bad );
  for( ulong rank = fd_bls_set_const_iter_init( agg->set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( agg->set, rank ) ) {
    blst_p2 one;
    blst_p2_from_affine( &one, sig+rank );
    if( FD_UNLIKELY( !fd_bls_agg_verify_hashed( h, pub+rank, &one ) ) ) fd_bls_set_insert( bad, rank );
  }
  return bad;
}

/* A bisect frame is a sub-aggregate over the contiguous run
   ranks[ lo, hi ) of the signer list, with its pub and sig sums and
   its gt (see agg_pairing).

   Invariants: Every frame on the stack has gt!=1, i.e. it contains a
   bad signer.  Halving the signer list at each split bounds the depth
   by log2 of the set capacity, and a split pushes at most two frames,
   so the stack never holds more than two frames per level. */

struct bisect_frame {
  ushort       lo;
  ushort       hi;
  fd_bls_pub_t pub;
  blst_p2      sig;
  blst_fp12    gt;
};
typedef struct bisect_frame bisect_frame_t;

#define BISECT_DEPTH_MAX (11UL)
#define BISECT_STACK_MAX (2UL*BISECT_DEPTH_MAX+2UL)
FD_STATIC_ASSERT( FD_BLS_SET_MAX<=(1UL<<BISECT_DEPTH_MAX), bisect_depth );

static fd_bls_set_t *
verify_bisect_hashed( fd_bls_agg_t const *   agg,
                      blst_p2_affine const * h,
                      fd_bls_pub_t const *   pub,
                      fd_bls_sig_t const *   sig,
                      fd_bls_set_t *         bad ) {
  fd_bls_set_null( bad );

  ushort ranks[ FD_BLS_SET_MAX ];
  ulong  cnt = 0UL;
  for( ulong rank = fd_bls_set_const_iter_init( agg->set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( agg->set, rank ) ) {
    ranks[ cnt++ ] = (ushort)rank;
  }
  if( FD_UNLIKELY( !cnt ) ) return bad;

  bisect_frame_t stack[ BISECT_STACK_MAX ];
  ulong          depth = 0UL;
  stack[ 0 ] = (bisect_frame_t){ .lo = 0, .hi = (ushort)cnt, .pub = agg->pub, .sig = agg->sig };
  agg_pairing( &stack[ 0 ].gt, h, &agg->pub, &agg->sig );
  if( FD_UNLIKELY( blst_fp12_is_one( &stack[ 0 ].gt ) ) ) return bad;
  depth++;

  while( FD_LIKELY( depth ) ) {
    bisect_frame_t range = stack[ --depth ];
    if( FD_UNLIKELY( range.hi-range.lo==1 ) ) { fd_bls_set_insert( bad, ranks[ range.lo ] ); continue; }

    ushort         mid = (ushort)( range.lo + ( range.hi-range.lo )/2 );
    bisect_frame_t lo  = { .lo = range.lo, .hi = mid      }; /* pub, sig start at infinity */
    bisect_frame_t hi  = { .lo = mid,      .hi = range.hi };
    for( ulong i=range.lo; i<mid; i++ ) {
      blst_p1_add_or_double( &lo.pub, &lo.pub, pub+ranks[ i ] );
      blst_p2_add_or_double_affine( &lo.sig, &lo.sig, sig+ranks[ i ] );
    }
    hi.pub = lo.pub; blst_p1_cneg( &hi.pub, 1 ); blst_p1_add_or_double( &hi.pub, &hi.pub, &range.pub );
    hi.sig = lo.sig; blst_p2_cneg( &hi.sig, 1 ); blst_p2_add_or_double( &hi.sig, &hi.sig, &range.sig );

    agg_pairing( &lo.gt, h, &lo.pub, &lo.sig );
    hi.gt = lo.gt; blst_fp12_conjugate( &hi.gt ); blst_fp12_mul( &hi.gt, &hi.gt, &range.gt ); /* conjugate inverts in GT */

    FD_TEST( depth+2UL<=BISECT_STACK_MAX );
    if( FD_LIKELY( !blst_fp12_is_one( &hi.gt ) ) ) stack[ depth++ ] = hi;
    if( FD_LIKELY( !blst_fp12_is_one( &lo.gt ) ) ) stack[ depth++ ] = lo; /* popped first: lower ranks are higher stake */
  }
  return bad;
}

fd_bls_set_t *
fd_bls_agg_verify_linear( fd_bls_agg_t const * agg,
                          uchar const *        msg,
                          ulong                msg_sz,
                          fd_bls_pub_t const * pub,
                          fd_bls_sig_t const * sig,
                          fd_bls_set_t *       bad ) {
  blst_p2_affine h[1];
  fd_bls_hash_msg( msg, msg_sz, h );
  return verify_linear_hashed( agg, h, pub, sig, bad );
}

fd_bls_set_t *
fd_bls_agg_verify_bisect( fd_bls_agg_t const * agg,
                          uchar const *        msg,
                          ulong                msg_sz,
                          fd_bls_pub_t const * pub,
                          fd_bls_sig_t const * sig,
                          fd_bls_set_t *       bad ) {
  blst_p2_affine h[1];
  fd_bls_hash_msg( msg, msg_sz, h );
  return verify_bisect_hashed( agg, h, pub, sig, bad );
}

int
fd_bls_agg_verify_subtract( fd_bls_agg_t *       agg,
                            uchar const *        msg,
                            ulong                msg_sz,
                            fd_bls_pub_t const * pub,
                            fd_bls_sig_t const * sig,
                            fd_bls_set_t *       bad ) {
  blst_p2_affine h[1];
  fd_bls_hash_msg( msg, msg_sz, h );
  verify_bisect_hashed( agg, h, pub, sig, bad );
  if( FD_UNLIKELY( !fd_bls_set_is_null( bad ) ) ) {
    fd_bls_agg_t sub = { 0 };
    fd_bls_agg_construct( &sub, pub, sig, bad );
    blst_p1_cneg( &sub.pub, 1 ); blst_p1_add_or_double( &agg->pub, &agg->pub, &sub.pub );
    blst_p2_cneg( &sub.sig, 1 ); blst_p2_add_or_double( &agg->sig, &agg->sig, &sub.sig );
    fd_bls_set_subtract( agg->set, agg->set, bad );
  }
  /* an aggregate whose keys cancel to infinity carries no stake even
     when every signer is individually valid */
  if( FD_UNLIKELY( blst_p1_is_inf( &agg->pub ) ) ) return -1;
  return 0;
}