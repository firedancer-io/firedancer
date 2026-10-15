#include "../fd_bls.h"
#include "../fd_bls_backend.h"
#include "fd_bls_miller.h"

/* AVX-512 backend entry points.  Native paths cover the pairing family,
   hash-to-curve, aggregate verification, pub_sum, and G2 subgroup
   validation; everything else dispatches to the reference backend via
   fd_bls_backend.h.

   Deliberately left on the reference backend:
   - sig_add: the native affine-pair addition's entry/export overhead
     (K-mul entry + rescale export) exceeds blst's add_or_double.
   - pairing_bytes: wire validation is sqrt/deserialize dominated. */

/* Native internals defined elsewhere in this translation unit
   (fd_bls_backend.c compiles the whole backend as one unit). */

void fd_bls_g1_pub_sum_avx512( fd_bls_pub_t * out, fd_bls_pub_t const * pubs,
                               fd_bls_set_t const * set );
int  fd_bls_g2_validate_mont_avx512( ulong const xyz[ 3 ][ 2 ][ 6 ] );
void fd_bls_g2_hash_msg_avx512( uchar const * msg, ulong msg_sz,
                                uchar const * dst, ulong dst_len,
                                fd_bls_hash_t * h );

/* blst's affine shape carries Z = (ONE_MONT_P, zero) -- the form both
   fd_bls_ref_sig_de and fd_bls_ref_pub_de always produce. */
static ulong const fd_bls_z_one_limbs[2][6] = {
  { 0x760900000002fffdUL, 0xebf4000bc40c0002UL, 0x5f48985753c758baUL,
    0x77ce585370525745UL, 0x5c071a97a256ec6dUL, 0x15f65ec3fa80e493UL },
  { 0UL, 0UL, 0UL, 0UL, 0UL, 0UL } };

static inline int
fd_bls_p1_is_affine_shape( fd_bls_pub_t const * p ) {
  /* blst_p1's Z is a single blst_fp (48 bytes) at offset 96. */
  ulong const * z = (ulong const *)&p->z;
  return !memcmp( z, fd_bls_z_one_limbs, 48 );
}

/* --- pairing family --- */

int
fd_bls_avx512_g2_prepare( fd_bls_g2_prepared_t * out,
                          fd_bls_g2_t const *    q ) {
  if( FD_UNLIKELY( !out || !q ) ) return -1;
  return fd_bls_g2_prepare_avx512( out, q );
}

int
fd_bls_avx512_pairing_finalverify_prepared_checked(
    fd_bls_g1_t const *          p_prepared,
    fd_bls_g2_prepared_t const * q_prepared,
    fd_bls_g1_t const *          p_checked,
    fd_bls_g2_t const *          q_checked ) {
  if( FD_UNLIKELY( !p_prepared || !q_prepared || !p_checked || !q_checked ) ) return -1;
  return fd_bls_pairing_finalverify_prepared_checked_avx512( p_prepared, q_prepared,
                                                             p_checked, q_checked );
}

int
fd_bls_avx512_pairing_finalverify( fd_bls_g1_t const * p,
                                   fd_bls_g2_t const * q,
                                   ulong               cnt ) {
  if( FD_UNLIKELY( !p || !q || !cnt || cnt>FD_BLS_PAIR_MAX ) ) return -1;
  return fd_bls_pairing_finalverify_avx512( p, q, cnt );
}

int
fd_bls_avx512_pairing_finalverify_checked( fd_bls_g1_t const * p,
                                           fd_bls_g2_t const * q,
                                           ulong               cnt,
                                           ulong               q_subgroup_mask ) {
  if( FD_UNLIKELY( !p || !q || !cnt || cnt>FD_BLS_PAIR_MAX ) ) return -1;
  return fd_bls_pairing_finalverify_checked_avx512( p, q, cnt, q_subgroup_mask );
}

int
fd_bls_avx512_pairing( ulong               out[12][6],
                       fd_bls_g1_t const * p,
                       fd_bls_g2_t const * q,
                       ulong               cnt ) {
  if( FD_UNLIKELY( !out || cnt>FD_BLS_PAIR_MAX || (cnt && (!p || !q)) ) ) return -1;
  vroom_fp12_t result;
  if( FD_UNLIKELY( fd_bls_pairing_avx512( &result, p, q, cnt ) ) ) return -1;
  for( int i=0; i<12; i++ ) vroom_fp_to_uint64( out[i], &result.c[i] );
  return 0;
}

/* --- hash-to-curve --- */

void
fd_bls_avx512_hash_msg( uchar const *   msg,
                        ulong           msg_sz,
                        fd_bls_hash_t * h ) {
  fd_bls_g2_hash_msg_avx512( msg, msg_sz, (uchar const *)FD_BLS_DST,
                             FD_BLS_DST_SZ, h );
}

/* --- aggregate verification: reference conversion + native pairing --- */

int
fd_bls_avx512_agg_verify_hashed( fd_bls_hash_t const * h,
                                 fd_bls_pub_t const *  pub,
                                 fd_bls_hash_t const * h_fb,
                                 fd_bls_pub_t const *  pub_fb,
                                 fd_bls_sig_t const *  sig ) {
  fd_bls_g1_t p[3];
  fd_bls_g2_t q[3];
  ulong cnt;
  if( FD_UNLIKELY( !fd_bls_ref_agg_to_pair( h, pub, h_fb, pub_fb, sig, p, q, &cnt ) ) ) return 0;
  return fd_bls_pairing_finalverify_avx512( p, q, cnt )==1;
}

/* --- G1 public-key aggregation: native when every key is affine --- */

void
fd_bls_avx512_pub_sum( fd_bls_pub_t *       out,
                       fd_bls_pub_t const * pubs,
                       fd_bls_set_t const * set ) {
  for( ulong rank = fd_bls_set_const_iter_init( set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( set, rank ) ) {
    if( FD_UNLIKELY( !fd_bls_p1_is_affine_shape( pubs+rank ) ) ) {
      fd_bls_ref_pub_sum( out, pubs, set );
      return;
    }
  }
  fd_bls_g1_pub_sum_avx512( out, pubs, set );
}

/* --- G2 signature validation and deserialization --- */

int
fd_bls_avx512_sig_validate( fd_bls_sig_t const * sig ) {
  if( FD_UNLIKELY( fd_bls_ref_sig_is_inf( sig ) ) )
    return fd_bls_ref_sig_validate( sig ); /* infinity delegates so acceptance matches blst */
  return fd_bls_g2_validate_mont_avx512( (ulong const (*)[2][6])sig );
}

int
fd_bls_avx512_sig_de( fd_bls_sig_t * sig,
                      uchar const    buf[ static FD_BLS_SIG_SZ ] ) {
  /* Deserialize without blst's subgroup gate, then run the native
     subgroup check (faster than blst in_g2). */
  if( FD_UNLIKELY( fd_bls_ref_sig_de_unchecked( sig, buf ) ) ) return -1;
  if( FD_UNLIKELY( !fd_bls_avx512_sig_validate( sig ) ) )      return -1;
  return 0;
}

int
fd_bls_avx512_sig_de_compressed( fd_bls_sig_t * sig,
                                 uchar const    buf[ static FD_BLS_SIG_COMPRESSED_SZ ] ) {
  /* Uncompress (sqrt dominated, stays on blst), then the native
     subgroup check in place of blst's in_g2. */
  blst_p2_affine a[1];
  if( FD_UNLIKELY( blst_p2_uncompress( a, buf )!=BLST_SUCCESS ) ) return -1;
  blst_p2_from_affine( sig, a );
  if( FD_UNLIKELY( !fd_bls_avx512_sig_validate( sig ) ) )         return -1;
  return 0;
}
