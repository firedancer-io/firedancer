#include "fd_bls.h"

#include "fd_bls12_381.h"
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
  blst_hash_to_g2( hash, msg, msg_sz, (uchar const *)FD_BLS_DST, FD_BLS_DST_SZ, NULL, 0UL );
  blst_sign_pk_in_g1( sig, hash, sk );
}

void
fd_bls_sec_derive( fd_bls_sec_t * sk,
                   uchar const *  ikm,
                   ulong          ikm_sz ) {
  FD_TEST( ikm_sz>=32UL );
  blst_keygen( sk, ikm, ikm_sz, NULL, 0UL );
}

void
fd_bls_sig_ser( uchar                out[ static FD_BLS_SIG_SZ ],
                fd_bls_sig_t const * sig ) {
  blst_p2_affine a[1];
  blst_p2_to_affine( a, sig );
  blst_p2_affine_serialize( out, a );
}

int
fd_bls_sig_de( fd_bls_sig_t * sig,
               uchar const    in[ static FD_BLS_SIG_SZ ] ) {
  blst_p2_affine a[1];
  if( FD_UNLIKELY( blst_p2_deserialize( a, in )!=BLST_SUCCESS ) ) return -1;
  if( FD_UNLIKELY( !blst_p2_affine_in_g2( a ) ) )                 return -1;
  blst_p2_from_affine( sig, a );
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
fd_bls_pub_try_from_bytes( fd_bls_pub_t * out,
                           uchar const *  in,
                           ulong          in_sz ) {
  blst_p1_affine pub[1];
  if( FD_UNLIKELY( !pub_from_bytes( pub, in, in_sz ) ) ) return -1;
  blst_p1_from_affine( out, pub );
  return 0;
}

int
fd_bls_agg_verify( fd_bls_pub_t const * pub,
                   fd_bls_sig_t const * agg,
                   uchar const *        msg,
                   ulong                msg_sz ) {
  if( FD_UNLIKELY( blst_p1_is_inf( pub ) || blst_p2_is_inf( agg ) ) ) return 0; /* the miller loop is wrong on an infinity operand */

  blst_p1_affine a[2];
  blst_p2_affine b[2];
  blst_p2        h[1];
  blst_p1_to_affine( a, pub );
  blst_hash_to_g2( h, msg, msg_sz, (uchar const *)FD_BLS_DST, FD_BLS_DST_SZ, NULL, 0UL );
  blst_p2_to_affine( b, h );
  a[1] = BLS12_381_NEG_G1;
  blst_p2_to_affine( b+1, agg );

  blst_p1_affine const * aptr[2] = { a, a+1 };
  blst_p2_affine const * bptr[2] = { b, b+1 };
  blst_fp12 r[1];
  blst_miller_loop_n( r, bptr, aptr, 2UL );
  return !!blst_fp12_finalverify( r, blst_fp12_one() );
}
