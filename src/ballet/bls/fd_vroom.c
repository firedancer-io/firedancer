#include "fd_vroom.h"

#include "vroom/fd_vroom_miller.h"
#include "../../third_party/blst/bindings/blst.h"

static void
g1_from_blst( fd_vroom_g1_affine_t * out,
              blst_p1_affine const * in ) {
  blst_uint64_from_fp( out->x, &in->x );
  blst_uint64_from_fp( out->y, &in->y );
}

static void
g2_from_blst( fd_vroom_g2_affine_t * out,
              blst_p2_affine const * in ) {
  blst_uint64_from_fp( out->x[0], &in->x.fp[0] );
  blst_uint64_from_fp( out->x[1], &in->x.fp[1] );
  blst_uint64_from_fp( out->y[0], &in->y.fp[0] );
  blst_uint64_from_fp( out->y[1], &in->y.fp[1] );
}

int
fd_vroom_g2_prepare_normal( fd_vroom_g2_prepared_t *    out,
                            fd_vroom_g2_affine_t const * q ) {
  if( !out || !q ) return -1;
  return fd_vroom_g2_prepare_c( out, q );
}

int
fd_vroom_pairing_finalverify_prepared_normal_checked(
    fd_vroom_g1_affine_t const *   p_prepared,
    fd_vroom_g2_prepared_t const * q_prepared,
    fd_vroom_g1_affine_t const *   p_checked,
    fd_vroom_g2_affine_t const *   q_checked ) {
  if( !p_prepared || !q_prepared || !p_checked || !q_checked ) return -1;
  return fd_vroom_pairing_finalverify_prepared_checked_c( p_prepared, q_prepared,
                                                           p_checked, q_checked );
}

int
fd_vroom_pairing_finalverify_normal( fd_vroom_g1_affine_t const * p,
                                     fd_vroom_g2_affine_t const * q,
                                     unsigned long                cnt ) {
  return fd_vroom_pairing_finalverify_c( p, q, cnt );
}

int
fd_vroom_pairing_finalverify_normal_checked( fd_vroom_g1_affine_t const * p,
                                             fd_vroom_g2_affine_t const * q,
                                             unsigned long                cnt,
                                             unsigned long                q_subgroup_mask ) {
  return fd_vroom_pairing_finalverify_checked_c( p, q, cnt, q_subgroup_mask );
}

int
fd_vroom_pairing_finalverify( void const *  p,
                              void const *  q,
                              unsigned long cnt ) {
  if( !p || !q || !cnt || cnt>FD_VROOM_PAIR_MAX ) return -1;
  fd_vroom_g1_affine_t pn[ FD_VROOM_PAIR_MAX ];
  fd_vroom_g2_affine_t qn[ FD_VROOM_PAIR_MAX ];
  for( unsigned long i=0UL; i<cnt; i++ ) {
    g1_from_blst( pn+i, ((blst_p1_affine const *)p)+i );
    g2_from_blst( qn+i, ((blst_p2_affine const *)q)+i );
  }
  return fd_vroom_pairing_finalverify_c( pn, qn, cnt );
}

int
fd_vroom_pairing_finalverify_checked( void const *  p,
                                      void const *  q,
                                      unsigned long cnt,
                                      unsigned long q_subgroup_mask ) {
  if( !p || !q || !cnt || cnt>FD_VROOM_PAIR_MAX ) return -1;
  fd_vroom_g1_affine_t pn[ FD_VROOM_PAIR_MAX ];
  fd_vroom_g2_affine_t qn[ FD_VROOM_PAIR_MAX ];
  for( unsigned long i=0UL; i<cnt; i++ ) {
    g1_from_blst( pn+i, ((blst_p1_affine const *)p)+i );
    g2_from_blst( qn+i, ((blst_p2_affine const *)q)+i );
  }
  return fd_vroom_pairing_finalverify_checked_c( pn, qn, cnt, q_subgroup_mask );
}

int
fd_vroom_g2_prepare( fd_vroom_g2_prepared_t * out,
                     void const *             q ) {
  if( !out || !q ) return -1;
  fd_vroom_g2_affine_t qn[1];
  g2_from_blst( qn, (blst_p2_affine const *)q );
  return fd_vroom_g2_prepare_c( out, qn );
}

int
fd_vroom_pairing_finalverify_prepared_checked(
    void const *                       p_prepared,
    fd_vroom_g2_prepared_t const *     q_prepared,
    void const *                       p_checked,
    void const *                       q_checked ) {
  if( !p_prepared || !q_prepared || !p_checked || !q_checked ) return -1;
  fd_vroom_g1_affine_t pn[2];
  fd_vroom_g2_affine_t qn[1];
  g1_from_blst( pn,   (blst_p1_affine const *)p_prepared );
  g1_from_blst( pn+1, (blst_p1_affine const *)p_checked  );
  g2_from_blst( qn,   (blst_p2_affine const *)q_checked  );
  return fd_vroom_pairing_finalverify_prepared_checked_c( pn, q_prepared, pn+1, qn );
}
