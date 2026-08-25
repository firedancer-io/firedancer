#include "../fd_bls.h"
#include "fd_bls_miller.h"

int
fd_bls_g2_prepare( fd_bls_g2_prepared_t * out,
                   fd_bls_g2_t const *     q ) {
  if( FD_UNLIKELY( !out || !q ) ) return -1;
  return fd_bls_g2_prepare_avx512( out, q );
}

int
fd_bls_pairing_finalverify_prepared_checked(
    fd_bls_g1_t const *          p_prepared,
    fd_bls_g2_prepared_t const * q_prepared,
    fd_bls_g1_t const *          p_checked,
    fd_bls_g2_t const *          q_checked ) {
  if( FD_UNLIKELY( !p_prepared || !q_prepared || !p_checked || !q_checked ) ) return -1;
  return fd_bls_pairing_finalverify_prepared_checked_avx512( p_prepared, q_prepared,
                                                           p_checked, q_checked );
}

int
fd_bls_pairing_finalverify( fd_bls_g1_t const * p,
                            fd_bls_g2_t const * q,
                            ulong               cnt ) {
  if( FD_UNLIKELY( !p || !q || !cnt || cnt>FD_BLS_PAIR_MAX ) ) return -1;
  return fd_bls_pairing_finalverify_avx512( p, q, cnt );
}

int
fd_bls_pairing_finalverify_checked( fd_bls_g1_t const * p,
                                    fd_bls_g2_t const * q,
                                    ulong               cnt,
                                    ulong               q_subgroup_mask ) {
  if( FD_UNLIKELY( !p || !q || !cnt || cnt>FD_BLS_PAIR_MAX ) ) return -1;
  return fd_bls_pairing_finalverify_checked_avx512( p, q, cnt, q_subgroup_mask );
}

int
fd_bls_pairing( ulong               out[12][6],
                fd_bls_g1_t const * p,
                fd_bls_g2_t const * q,
                ulong               cnt ) {
  if( FD_UNLIKELY( !out || cnt>FD_BLS_PAIR_MAX || (cnt && (!p || !q)) ) ) return -1;
  fd_bls_fp12_t result;
  if( FD_UNLIKELY( fd_bls_pairing_avx512( &result, p, q, cnt ) ) ) return -1;
  for( int i=0; i<12; i++ ) fd_bls_fp_to_uint64( out[i], &result.c[i] );
  return 0;
}
