/* Top-level fd_bls API: thin dispatch to the selected backend
   (fd_bls_backend.h) plus the aggregate bookkeeping and bad-signer
   search algorithms, which are backend-neutral. */

#include "fd_bls.h"
#include "fd_bls_backend.h"

void
fd_bls_sec_to_pub( fd_bls_sec_t const * sec,
                   fd_bls_pub_t *       pub ) {
  fd_bls_backend_sec_to_pub( sec, pub );
}

void
fd_bls_sec_derive( fd_bls_sec_t * sec,
                   uchar const *  ikm,
                   ulong          ikm_sz ) {
  fd_bls_backend_sec_derive( sec, ikm, ikm_sz );
}

void
fd_bls_sec_sign( fd_bls_sec_t const * sec,
                 uchar const *        msg,
                 ulong                msg_sz,
                 fd_bls_sig_t *       sig ) {
  fd_bls_backend_sec_sign( sec, msg, msg_sz, sig );
}

void
fd_bls_pub_ser( fd_bls_pub_t const * pub,
                uchar                buf[ static FD_BLS_PUB_SZ ] ) {
  fd_bls_backend_pub_ser( pub, buf );
}

void
fd_bls_pub_compress( fd_bls_pub_t const * pub,
                     uchar                buf[ static FD_BLS_PUB_COMPRESSED_SZ ] ) {
  fd_bls_backend_pub_compress( pub, buf );
}

int
fd_bls_pub_de( fd_bls_pub_t * pub,
               uchar const *  buf,
               ulong          buf_sz ) {
  return fd_bls_backend_pub_de( pub, buf, buf_sz );
}

int
fd_bls_pub_de_compressed( fd_bls_pub_t * pub,
                          uchar const    buf[ static FD_BLS_PUB_COMPRESSED_SZ ] ) {
  return fd_bls_backend_pub_de_compressed( pub, buf );
}

void
fd_bls_pub_add( fd_bls_pub_t *       out,
                fd_bls_pub_t const * a,
                fd_bls_pub_t const * b ) {
  fd_bls_backend_pub_add( out, a, b );
}

void
fd_bls_pub_neg( fd_bls_pub_t *       out,
                fd_bls_pub_t const * a ) {
  fd_bls_backend_pub_neg( out, a );
}

int
fd_bls_pub_is_inf( fd_bls_pub_t const * pub ) {
  return fd_bls_backend_pub_is_inf( pub );
}

int
fd_bls_pub_eq( fd_bls_pub_t const * a,
               fd_bls_pub_t const * b ) {
  return fd_bls_backend_pub_eq( a, b );
}

void
fd_bls_pub_sum( fd_bls_pub_t *       out,
                fd_bls_pub_t const * pubs,
                fd_bls_set_t const * set ) {
  fd_bls_backend_pub_sum( out, pubs, set );
}

void
fd_bls_sig_ser( fd_bls_sig_t const * sig,
                uchar                buf[ static FD_BLS_SIG_SZ ] ) {
  fd_bls_backend_sig_ser( sig, buf );
}

void
fd_bls_sig_compress( fd_bls_sig_t const * sig,
                     uchar                buf[ static FD_BLS_SIG_COMPRESSED_SZ ] ) {
  fd_bls_backend_sig_compress( sig, buf );
}

int
fd_bls_sig_de( fd_bls_sig_t * sig,
               uchar const    buf[ static FD_BLS_SIG_SZ ] ) {
  return fd_bls_backend_sig_de( sig, buf );
}

int
fd_bls_sig_de_compressed( fd_bls_sig_t * sig,
                          uchar const    buf[ static FD_BLS_SIG_COMPRESSED_SZ ] ) {
  return fd_bls_backend_sig_de_compressed( sig, buf );
}

int
fd_bls_sig_de_unchecked( fd_bls_sig_t * sig,
                         uchar const    buf[ static FD_BLS_SIG_SZ ] ) {
  return fd_bls_backend_sig_de_unchecked( sig, buf );
}

void
fd_bls_sig_add( fd_bls_sig_t *       out,
                fd_bls_sig_t const * a,
                fd_bls_sig_t const * b ) {
  fd_bls_backend_sig_add( out, a, b );
}

void
fd_bls_sig_neg( fd_bls_sig_t *       out,
                fd_bls_sig_t const * a ) {
  fd_bls_backend_sig_neg( out, a );
}

int
fd_bls_sig_validate( fd_bls_sig_t const * sig ) {
  return fd_bls_backend_sig_validate( sig );
}

int
fd_bls_sig_is_inf( fd_bls_sig_t const * sig ) {
  return fd_bls_backend_sig_is_inf( sig );
}

int
fd_bls_sig_eq( fd_bls_sig_t const * a,
               fd_bls_sig_t const * b ) {
  return fd_bls_backend_sig_eq( a, b );
}

void
fd_bls_hash_msg( uchar const *  msg,
                 ulong          msg_sz,
                 fd_bls_hash_t * h ) {
  fd_bls_backend_hash_msg( msg, msg_sz, h );
}

fd_bls_agg_t *
fd_bls_agg_null( fd_bls_agg_t * agg ) {
  fd_memset( &agg->pub, 0, sizeof(fd_bls_pub_t) );
  fd_memset( &agg->sig, 0, sizeof(fd_bls_sig_t) );
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
    fd_bls_pub_add( &agg->pub, &agg->pub, pub+rank );
    fd_bls_sig_add( &agg->sig, &agg->sig, sig+rank );
  }
  return agg;
}

int
fd_bls_agg_verify_hashed( fd_bls_hash_t const * h,
                          fd_bls_pub_t const *  pub,
                          fd_bls_sig_t const *  sig ) {
  return fd_bls_backend_agg_verify_hashed( h, pub, NULL, NULL, sig );
}

int
fd_bls_agg_verify( uchar const *        msg,
                   ulong                msg_sz,
                   fd_bls_pub_t const * pub,
                   fd_bls_sig_t const * sig ) {
  fd_bls_hash_t h[1];
  fd_bls_hash_msg( msg, msg_sz, h );
  return fd_bls_agg_verify_hashed( h, pub, sig );
}

int
fd_bls_agg_verify_pair( uchar const *        msg,
                        ulong                msg_sz,
                        fd_bls_pub_t const * pub,
                        uchar const *        msg_fb,
                        ulong                msg_fb_sz,
                        fd_bls_pub_t const * pub_fb,
                        fd_bls_sig_t const * sig ) {
  if( FD_UNLIKELY( !msg_fb || !pub_fb ) ) return 0;
  fd_bls_hash_t h[1], h_fb[1];
  fd_bls_hash_msg( msg, msg_sz, h );
  fd_bls_hash_msg( msg_fb, msg_fb_sz, h_fb );
  return fd_bls_backend_agg_verify_hashed( h, pub, h_fb, pub_fb, sig );
}

fd_bls_set_t *
fd_bls_agg_verify_linear( fd_bls_agg_t const * agg,
                          uchar const *        msg,
                          ulong                msg_sz,
                          fd_bls_pub_t const * pub,
                          fd_bls_sig_t const * sig,
                          fd_bls_set_t *       bad ) {
  fd_bls_set_null( bad );
  for( ulong rank = fd_bls_set_const_iter_init( agg->set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( agg->set, rank ) ) {
    if( FD_UNLIKELY( !fd_bls_agg_verify( msg, msg_sz, pub+rank, sig+rank ) ) ) fd_bls_set_insert( bad, rank );
  }
  return bad;
}

fd_bls_set_t *
fd_bls_agg_verify_bisect( fd_bls_agg_t const * agg,
                          uchar const *        msg,
                          ulong                msg_sz,
                          fd_bls_pub_t const * pub,
                          fd_bls_sig_t const * sig,
                          fd_bls_set_t *       bad ) {
  fd_bls_set_null( bad );
  fd_bls_agg_t key = *agg;
  ulong        cnt = fd_bls_set_cnt( key.set );
  while( FD_LIKELY( cnt>1UL ) ) {
    fd_bls_agg_t lo = { 0 };
    fd_bls_agg_t hi; fd_bls_set_null( hi.set );
    ulong        mid = 0UL;
    for( ulong rank = fd_bls_set_const_iter_init( key.set );
                     !fd_bls_set_const_iter_done( rank );
               rank = fd_bls_set_const_iter_next( key.set, rank ) ) {
      if( FD_LIKELY( mid++<cnt/2UL ) ) { fd_bls_set_insert( lo.set, rank ); fd_bls_pub_add( &lo.pub, &lo.pub, pub+rank ); fd_bls_sig_add( &lo.sig, &lo.sig, sig+rank ); }
      else                             { fd_bls_set_insert( hi.set, rank ); }
    }
    hi.pub = lo.pub; fd_bls_pub_neg( &hi.pub, &hi.pub ); fd_bls_pub_add( &hi.pub, &hi.pub, &key.pub );
    hi.sig = lo.sig; fd_bls_sig_neg( &hi.sig, &hi.sig ); fd_bls_sig_add( &hi.sig, &hi.sig, &key.sig );

    int lo_ok = fd_bls_agg_verify( msg, msg_sz, &lo.pub, &lo.sig ); /* verify lo first, because agg is sorted by stake, so lo has higher-staked validators (which we assume are more likely to be honest) */
    if( FD_LIKELY( lo_ok ) ) key = hi; /* lo is good */
    else { /* lo is bad */
      int hi_ok = fd_bls_agg_verify( msg, msg_sz, &hi.pub, &hi.sig );
      if( FD_UNLIKELY( !hi_ok ) ) break; /* hi is also bad... have to linear scan */
      key = lo;
    }
    cnt = fd_bls_set_cnt( key.set );
  }
  return fd_bls_agg_verify_linear( &key, msg, msg_sz, pub, sig, bad );
}

int
fd_bls_agg_verify_subtract( fd_bls_agg_t *       agg,
                            uchar const *        msg,
                            ulong                msg_sz,
                            fd_bls_pub_t const * pub,
                            fd_bls_sig_t const * sig,
                            fd_bls_set_t *       bad ) {
  if( FD_LIKELY( fd_bls_agg_verify( msg, msg_sz, &agg->pub, &agg->sig ) ) ) { fd_bls_set_null( bad ); return 0; }
  fd_bls_agg_verify_bisect( agg, msg, msg_sz, pub, sig, bad );
  fd_bls_agg_t sub = { 0 };
  fd_bls_agg_construct( &sub, pub, sig, bad );
  fd_bls_pub_neg( &sub.pub, &sub.pub ); fd_bls_pub_add( &agg->pub, &agg->pub, &sub.pub );
  fd_bls_sig_neg( &sub.sig, &sub.sig ); fd_bls_sig_add( &agg->sig, &agg->sig, &sub.sig );
  fd_bls_set_subtract( agg->set, agg->set, bad );
  if( FD_UNLIKELY( fd_bls_pub_is_inf( &agg->pub ) ) ) return -1;
  return 0;
}

int
fd_bls_g1_decompress( uchar       out[ 96 ],
                      uchar const in [ 48 ],
                      int         big_endian ) {
  return fd_bls_backend_g1_decompress( out, in, big_endian );
}

int
fd_bls_g1_validate( uchar const in [ 96 ],
                    int         big_endian ) {
  return fd_bls_backend_g1_validate( in, big_endian );
}

int
fd_bls_g1_add( uchar       out[ 96 ],
               uchar const a  [ 96 ],
               uchar const b  [ 96 ],
               int         big_endian ) {
  return fd_bls_backend_g1_add( out, a, b, big_endian );
}

int
fd_bls_g1_sub( uchar       out[ 96 ],
               uchar const a  [ 96 ],
               uchar const b  [ 96 ],
               int         big_endian ) {
  return fd_bls_backend_g1_sub( out, a, b, big_endian );
}

int
fd_bls_g1_mul( uchar       out[ 96 ],
               uchar const scalar[ 32 ],
               uchar const a     [ 96 ],
               int         big_endian ) {
  return fd_bls_backend_g1_mul( out, scalar, a, big_endian );
}

int
fd_bls_g2_decompress( uchar       out[ 192 ],
                      uchar const in [  96 ],
                      int         big_endian ) {
  return fd_bls_backend_g2_decompress( out, in, big_endian );
}

int
fd_bls_g2_compress( uchar       out[  96 ],
                    uchar const in [ 192 ],
                    int         big_endian ) {
  return fd_bls_backend_g2_compress( out, in, big_endian );
}

int
fd_bls_g2_validate( uchar const in [ 192 ],
                    int         big_endian ) {
  return fd_bls_backend_g2_validate( in, big_endian );
}

int
fd_bls_g2_add( uchar       out[ 192 ],
               uchar const a  [ 192 ],
               uchar const b  [ 192 ],
               int         big_endian ) {
  return fd_bls_backend_g2_add( out, a, b, big_endian );
}

int
fd_bls_g2_sub( uchar       out[ 192 ],
               uchar const a  [ 192 ],
               uchar const b  [ 192 ],
               int         big_endian ) {
  return fd_bls_backend_g2_sub( out, a, b, big_endian );
}

int
fd_bls_g2_mul( uchar       out[ 192 ],
               uchar const scalar[  32 ],
               uchar const a     [ 192 ],
               int         big_endian ) {
  return fd_bls_backend_g2_mul( out, scalar, a, big_endian );
}

int
fd_bls_pairing_bytes( uchar       out[ 48*12 ],
                      uchar const g1 [],
                      uchar const g2 [],
                      ulong       cnt,
                      int         big_endian ) {
  return fd_bls_backend_pairing_bytes( out, g1, g2, cnt, big_endian );
}

int
fd_bls_verify( uchar const  msg[],
               ulong        msg_sz,
               uchar const  signature[ 96 ],
               uchar const  public_key[ 48 ],
               char const * domain,
               ulong        domain_len ) {
  return fd_bls_ref_verify( msg, msg_sz, signature, public_key,
                            domain, domain_len );
}

int
fd_bls_g2_prepare( fd_bls_g2_prepared_t * out,
                   fd_bls_g2_t const *     q ) {
  return fd_bls_backend_g2_prepare( out, q );
}

int
fd_bls_pairing_finalverify_prepared_checked(
    fd_bls_g1_t const *          p_prepared,
    fd_bls_g2_prepared_t const * q_prepared,
    fd_bls_g1_t const *          p_checked,
    fd_bls_g2_t const *          q_checked ) {
  return fd_bls_backend_pairing_finalverify_prepared_checked( p_prepared, q_prepared,
                                                               p_checked, q_checked );
}

int
fd_bls_pairing_finalverify( fd_bls_g1_t const * p,
                            fd_bls_g2_t const * q,
                            ulong               cnt ) {
  return fd_bls_backend_pairing_finalverify( p, q, cnt );
}

int
fd_bls_pairing_finalverify_checked( fd_bls_g1_t const * p,
                                    fd_bls_g2_t const * q,
                                    ulong               cnt,
                                    ulong               q_subgroup_mask ) {
  return fd_bls_backend_pairing_finalverify_checked( p, q, cnt, q_subgroup_mask );
}

int
fd_bls_pairing( ulong               out[12][6],
                fd_bls_g1_t const * p,
                fd_bls_g2_t const * q,
                ulong               cnt ) {
  return fd_bls_backend_pairing( out, p, q, cnt );
}
