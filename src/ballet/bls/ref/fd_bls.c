#include "../fd_bls.h"

/* --- secret keys --- */

void
fd_bls_sec_to_pub( fd_bls_sec_t const * sec,
                   fd_bls_pub_t *       pub ) {
  blst_sk_to_pk_in_g1( pub, sec );
}

void
fd_bls_sec_derive( fd_bls_sec_t * sec,
                   uchar const *  ikm,
                   ulong          ikm_sz ) {
  FD_TEST( ikm_sz>=32UL );
  blst_keygen( sec, ikm, ikm_sz, NULL, 0UL );
}

void
fd_bls_sec_sign( fd_bls_sec_t const * sec,
                 uchar const *        msg,
                 ulong                msg_sz,
                 fd_bls_sig_t *       sig ) {
  blst_p2 hash[1];
  blst_hash_to_g2( hash, msg, msg_sz, (uchar const *)FD_BLS_DST,
                   FD_BLS_DST_SZ, NULL, 0UL );
  blst_sign_pk_in_g1( sig, hash, sec );
}


/* --- public keys (G1) --- */

void
fd_bls_pub_compress( fd_bls_pub_t const * pub,
                     uchar                buf[ static FD_BLS_PUB_COMPRESSED_SZ ] ) {
  blst_p1_affine a[1];
  blst_p1_to_affine( a, pub );
  blst_p1_affine_compress( buf, a );
}

static int
fd_bls_pub_from_bytes( blst_p1_affine * out,
                       uchar const *    in,
                       ulong            in_sz ) {
  BLST_ERROR err;
  switch( in_sz ) {
  case FD_BLS_PUB_COMPRESSED_SZ: err = blst_p1_uncompress( out, in ); break;
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
  if( FD_UNLIKELY( !fd_bls_pub_from_bytes( a, buf, buf_sz ) ) ) return -1;
  blst_p1_from_affine( pub, a );
  return 0;
}

int
fd_bls_pub_de_unchecked( fd_bls_pub_t * pub,
                         uchar const    buf[ static FD_BLS_PUB_SZ ] ) {
  blst_p1_affine a[1];
  if( FD_UNLIKELY( blst_p1_deserialize( a, buf )!=BLST_SUCCESS ) ) return -1;
  blst_p1_from_affine( pub, a );
  return 0;
}

void
fd_bls_pub_add( fd_bls_pub_t *       out,
                fd_bls_pub_t const * a,
                fd_bls_pub_t const * b ) {
  blst_p1_add_or_double( out, a, b );
}

void
fd_bls_pub_neg( fd_bls_pub_t *       out,
                fd_bls_pub_t const * a ) {
  *out = *a;
  blst_p1_cneg( out, 1 );
}

int
fd_bls_pub_is_inf( fd_bls_pub_t const * pub ) {
  return !!blst_p1_is_inf( pub );
}

int
fd_bls_pub_eq( fd_bls_pub_t const * a,
                   fd_bls_pub_t const * b ) {
  return !!blst_p1_is_equal( a, b );
}

static void
fd_bls_pub_add_many( fd_bls_pub_t *               out,
                     fd_bls_pub_t const * const * pubs,
                     ulong                        pub_cnt ) {
  fd_bls_pub_t const * finite[ FD_BLS_SET_MAX ];
  ulong finite_cnt = 0UL;
  for( ulong i=0UL; i<pub_cnt; i++ )
    if( FD_LIKELY( !fd_bls_pub_is_inf( pubs[ i ] ) ) ) finite[ finite_cnt++ ] = pubs[ i ];
  if( FD_UNLIKELY( !finite_cnt ) ) { fd_memset( out, 0, sizeof(fd_bls_pub_t) ); return; }

  /* blst_p1s_to_affine cannot normalize infinity safely. */
  blst_p1_affine         affine    [ FD_BLS_SET_MAX ];
  blst_p1_affine const * affine_ptr[ FD_BLS_SET_MAX ];
  blst_p1s_to_affine( affine, finite, finite_cnt );
  for( ulong i=0UL; i<finite_cnt; i++ ) affine_ptr[ i ] = affine+i;
  blst_p1s_add( out, affine_ptr, finite_cnt );
}

void
fd_bls_pub_sum( fd_bls_pub_t *       out,
                fd_bls_pub_t const * pubs,
                fd_bls_set_t const * set ) {
  fd_bls_pub_t const * pub_ptr[ FD_BLS_SET_MAX ];
  ulong                pub_cnt = 0UL;
  for( ulong rank = fd_bls_set_const_iter_init( set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( set, rank ) ) {
    pub_ptr[ pub_cnt++ ] = pubs+rank;
  }
  fd_bls_pub_add_many( out, pub_ptr, pub_cnt );
}

void
fd_bls_pub_sum_cached( fd_bls_pub_t *       out,
                       fd_bls_pub_t const * pubs,
                       ulong                pub_cnt,
                       fd_bls_set_t const * set,
                       fd_bls_pub_t const * full ) {
  if( FD_LIKELY( !full || 2UL*fd_bls_set_cnt( set )<=pub_cnt ) ) {
    fd_bls_pub_sum( out, pubs, set );
    return;
  }

  /* For a dense signer set, normalize and sum only the complement, then
     subtract that from the cached epoch total. */
  fd_bls_pub_t const * missing[ FD_BLS_SET_MAX ];
  ulong missing_cnt = 0UL;
  for( ulong rank=0UL; rank<pub_cnt; rank++ )
    if( !fd_bls_set_test( set, rank ) ) missing[ missing_cnt++ ] = pubs+rank;
  fd_bls_pub_add_many( out, missing, missing_cnt );
  fd_bls_pub_neg( out, out );
  fd_bls_pub_add( out, full, out );
}

/* --- signatures (G2) --- */

void
fd_bls_sig_ser( fd_bls_sig_t const * sig,
                uchar                buf[ static FD_BLS_SIG_SZ ] ) {
  blst_p2_affine a[1];
  blst_p2_to_affine( a, sig );
  blst_p2_affine_serialize( buf, a );
}

void
fd_bls_sig_compress( fd_bls_sig_t const * sig,
                     uchar                buf[ static FD_BLS_SIG_COMPRESSED_SZ ] ) {
  blst_p2_affine a[1];
  blst_p2_to_affine( a, sig );
  blst_p2_affine_compress( buf, a );
}

int
fd_bls_sig_de( fd_bls_sig_t * sig,
                   uchar const    buf[ static FD_BLS_SIG_SZ ] ) {
  blst_p2_affine a[1];
  if( FD_UNLIKELY( blst_p2_deserialize( a, buf )!=BLST_SUCCESS ) ) return -1;
  if( FD_UNLIKELY( !blst_p2_affine_in_g2( a ) ) )                  return -1;
  blst_p2_from_affine( sig, a );
  return 0;
}

int
fd_bls_sig_de_unchecked( fd_bls_sig_t * sig,
                         uchar const    buf[ static FD_BLS_SIG_SZ ] ) {
  blst_p2_affine a[1];
  if( FD_UNLIKELY( blst_p2_deserialize( a, buf )!=BLST_SUCCESS ) ) return -1;
  blst_p2_from_affine( sig, a );
  return 0;
}

int
fd_bls_sig_de_compressed( fd_bls_sig_t * sig,
                          uchar const    buf[ static FD_BLS_SIG_COMPRESSED_SZ ] ) {
  blst_p2_affine a[1];
  if( FD_UNLIKELY( blst_p2_uncompress( a, buf )!=BLST_SUCCESS ) ) return -1;
  if( FD_UNLIKELY( !blst_p2_affine_in_g2( a ) ) )                 return -1;
  blst_p2_from_affine( sig, a );
  return 0;
}

void
fd_bls_sig_add( fd_bls_sig_t *       out,
                fd_bls_sig_t const * a,
                fd_bls_sig_t const * b ) {
  blst_p2_add_or_double( out, a, b );
}

void
fd_bls_sig_neg( fd_bls_sig_t *       out,
                fd_bls_sig_t const * a ) {
  *out = *a;
  blst_p2_cneg( out, 1 );
}

int
fd_bls_sig_validate( fd_bls_sig_t const * sig ) {
  return !!blst_p2_in_g2( sig );
}

int
fd_bls_sig_is_inf( fd_bls_sig_t const * sig ) {
  return !!blst_p2_is_inf( sig );
}

int
fd_bls_sig_eq( fd_bls_sig_t const * a,
               fd_bls_sig_t const * b ) {
  return !!blst_p2_is_equal( a, b );
}

static void
fd_bls_sig_add_many( fd_bls_sig_t *               out,
                     fd_bls_sig_t const * const * sigs,
                     ulong                        sig_cnt ) {
  fd_bls_sig_t const * finite[ FD_BLS_SET_MAX ];
  ulong finite_cnt = 0UL;
  for( ulong i=0UL; i<sig_cnt; i++ )
    if( FD_LIKELY( !fd_bls_sig_is_inf( sigs[ i ] ) ) ) finite[ finite_cnt++ ] = sigs[ i ];
  if( FD_UNLIKELY( !finite_cnt ) ) { fd_memset( out, 0, sizeof(fd_bls_sig_t) ); return; }

  /* blst_p2s_to_affine cannot normalize infinity safely.  Filtering it
     here does not remove the corresponding rank from an aggregate set. */
  blst_p2_affine         affine    [ FD_BLS_SET_MAX ];
  blst_p2_affine const * affine_ptr[ FD_BLS_SET_MAX ];
  blst_p2s_to_affine( affine, finite, finite_cnt );
  for( ulong i=0UL; i<finite_cnt; i++ ) affine_ptr[ i ] = affine+i;
  blst_p2s_add( out, affine_ptr, finite_cnt );
}

/* --- hash-to-curve --- */

void
fd_bls_hash_msg( uchar const *  msg,
                 ulong          msg_sz,
                 fd_bls_hash_t * hash ) {
  blst_p2 point[1];
  blst_hash_to_g2( point, msg, msg_sz, (uchar const *)FD_BLS_DST,
                   FD_BLS_DST_SZ, NULL, 0UL );
  blst_p2_to_affine( hash, point );
}

int
fd_bls_hash_eq( fd_bls_hash_t const * a,
                fd_bls_hash_t const * b ) {
  return !!blst_p2_affine_is_equal( a, b );
}

static int
fd_bls_hash_is_inf( fd_bls_hash_t const * hash ) {
  return !!blst_p2_affine_is_inf( hash );
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
  fd_bls_pub_t const * pub_ptr[ FD_BLS_SET_MAX ];
  fd_bls_sig_t const * sig_ptr[ FD_BLS_SET_MAX ];
  ulong                cnt = 0UL;
  fd_bls_set_copy( agg->set, set );
  for( ulong rank = fd_bls_set_const_iter_init( set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( set, rank ) ) {
    pub_ptr[ cnt   ] = pub+rank;
    sig_ptr[ cnt++ ] = sig+rank;
  }
  fd_bls_pub_add_many( &agg->pub, pub_ptr, cnt );
  fd_bls_sig_add_many( &agg->sig, sig_ptr, cnt );
  return agg;
}

static int
fd_bls_verify_hash_pair( fd_bls_hash_t const * h,
                         fd_bls_pub_t const *  pub,
                         fd_bls_hash_t const * h_fallback,
                         fd_bls_pub_t const *  pub_fallback,
                         fd_bls_sig_t const *  sig ) {
  ulong pair_cnt = 1UL + !!pub_fallback;
  if( FD_UNLIKELY( fd_bls_hash_is_inf( h ) || fd_bls_pub_is_inf( pub ) ||
                   (pub_fallback && (fd_bls_hash_is_inf( h_fallback ) || fd_bls_pub_is_inf( pub_fallback ))) ||
                   fd_bls_sig_is_inf( sig ) ) ) return 0;

  blst_p1_affine p[3];
  blst_p2_affine q[3];
  blst_p1_to_affine( p, pub ); q[0] = *h;
  if( pub_fallback ) { blst_p1_to_affine( p+1, pub_fallback ); q[1] = *h_fallback; }
  p[pair_cnt] = BLS12_381_NEG_G1;
  blst_p2_to_affine( q+pair_cnt, sig );
  blst_p1_affine const * pp[3] = { p, p+1, p+2 };
  blst_p2_affine const * qq[3] = { q, q+1, q+2 };
  blst_fp12 product[1];
  blst_miller_loop_n( product, qq, pp, pair_cnt+1UL );
  return !!blst_fp12_finalverify( product, blst_fp12_one() );
}

int
fd_bls_agg_verify_hashed( fd_bls_hash_t const * h,
                          fd_bls_pub_t const *  pub,
                          fd_bls_sig_t const *  sig ) {
  return fd_bls_verify_hash_pair( h, pub, NULL, NULL, sig );
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
                        uchar const *        msg_fallback,
                        ulong                msg_fallback_sz,
                        fd_bls_pub_t const * pub_fallback,
                        fd_bls_sig_t const * sig ) {
  if( FD_UNLIKELY( !msg_fallback || !pub_fallback ) ) return 0;
  fd_bls_hash_t h[1], h_fallback[1];
  fd_bls_hash_msg( msg,          msg_sz,          h );
  fd_bls_hash_msg( msg_fallback, msg_fallback_sz, h_fallback );
  return fd_bls_verify_hash_pair( h, pub, h_fallback, pub_fallback, sig );
}

static void
fd_bls_agg_gt( blst_fp12 *          gt,
               fd_bls_hash_t const * h,
               fd_bls_pub_t const *  pub,
               fd_bls_sig_t const *  sig ) {
  blst_p1_affine p[2]; blst_p2_affine q[2];
  blst_p1_affine const * pp[2]; blst_p2_affine const * qq[2]; ulong cnt=0UL;
  if( FD_LIKELY( !fd_bls_pub_is_inf( pub ) ) ) {
    blst_p1_to_affine( p+cnt,pub );
    q[cnt]=*h; pp[cnt]=p+cnt; qq[cnt]=q+cnt;
    cnt++;
  }
  if( FD_LIKELY( !fd_bls_sig_is_inf( sig ) ) ) {
    p[cnt]=BLS12_381_NEG_G1;
    blst_p2_to_affine( q+cnt,sig );
    pp[cnt]=p+cnt; qq[cnt]=q+cnt;
    cnt++;
  }
  if( FD_UNLIKELY( !cnt ) ) {
    *gt = *blst_fp12_one();
    return;
  }
  blst_fp12 miller;
  blst_miller_loop_n( &miller, qq, pp, cnt );
  blst_final_exp( gt, &miller );
}

/* Compute the left GT value and derive right=parent/left. */
static void
fd_bls_agg_bisect_run( fd_bls_hash_t const *       h,
                       fd_bls_pub_t const * const   pub[],
                       fd_bls_sig_t const * const   sig[],
                       ushort const *               rank,
                       ulong                        lo,
                       ulong                        hi,
                       fd_bls_pub_t const *         sum_pub,
                       fd_bls_sig_t const *         sum_sig,
                       blst_fp12 const *            gt,
                       fd_bls_set_t *               bad ) {
  if( FD_UNLIKELY( hi-lo==1UL ) ) { fd_bls_set_insert(bad,rank[lo]); return; }
  ulong mid=lo+(hi-lo)/2UL;

  fd_bls_pub_t lpub,hpub;
  fd_bls_sig_t lsig,hsig;
  fd_bls_pub_add_many( &lpub,pub+lo,mid-lo );
  fd_bls_sig_add_many( &lsig,sig+lo,mid-lo );
  fd_bls_pub_neg( &hpub,&lpub ); fd_bls_pub_add( &hpub,&hpub,sum_pub );
  fd_bls_sig_neg( &hsig,&lsig ); fd_bls_sig_add( &hsig,&hsig,sum_sig );

  blst_fp12 lgt,hgt;
  fd_bls_agg_gt( &lgt,h,&lpub,&lsig );
  hgt = lgt;
  blst_fp12_conjugate( &hgt );
  blst_fp12_mul( &hgt, &hgt, gt );

  int l_ok=blst_fp12_is_one(&lgt) && !fd_bls_pub_is_inf(&lpub) && !fd_bls_sig_is_inf(&lsig);
  int h_ok=blst_fp12_is_one(&hgt) && !fd_bls_pub_is_inf(&hpub) && !fd_bls_sig_is_inf(&hsig);
  if( FD_UNLIKELY(!l_ok) ) fd_bls_agg_bisect_run( h,pub,sig,rank,lo,mid,&lpub,&lsig,&lgt,bad );
  if( FD_UNLIKELY(!h_ok) ) fd_bls_agg_bisect_run( h,pub,sig,rank,mid,hi,&hpub,&hsig,&hgt,bad );
}

static fd_bls_set_t *
fd_bls_agg_verify_bisect_hashed( fd_bls_agg_t const * agg,
                                 fd_bls_hash_t const * h,
                                 blst_fp12 const * gt,
                                 fd_bls_pub_t const * pub,
                                 fd_bls_sig_t const * sig,
                                 fd_bls_set_t * bad ) {
  fd_bls_set_null(bad);
  ulong cnt = fd_bls_set_cnt(agg->set);
  if( FD_UNLIKELY(!cnt) ) return bad;
  if( FD_LIKELY( blst_fp12_is_one(gt) && !fd_bls_pub_is_inf(&agg->pub) && !fd_bls_sig_is_inf(&agg->sig) ) ) return bad;

  fd_bls_pub_t const * pubs[FD_BLS_SET_MAX];
  fd_bls_sig_t const * sigs[FD_BLS_SET_MAX];
  ushort ranks[FD_BLS_SET_MAX];
  ulong n=0UL;
  for( ulong r=fd_bls_set_const_iter_init(agg->set); !fd_bls_set_const_iter_done(r); r=fd_bls_set_const_iter_next(agg->set,r) ) {
    pubs[n] = pub+r;
    sigs[n] = sig+r;
    ranks[n] = (ushort)r;
    n++;
  }
  fd_bls_agg_bisect_run( h,pubs,sigs,ranks,0UL,cnt,&agg->pub,&agg->sig,gt,bad );
  return bad;
}

int
fd_bls_agg_verify_subtract( fd_bls_agg_t *       agg,
                            uchar const *        msg,
                            ulong                msg_sz,
                            fd_bls_pub_t const * pub,
                            fd_bls_sig_t const * sig,
                            fd_bls_set_t *       bad ) {
  fd_bls_hash_t h; blst_fp12 gt;
  fd_bls_hash_msg( msg, msg_sz, &h );
  fd_bls_agg_gt( &gt, &h, &agg->pub, &agg->sig );
  if( FD_LIKELY( blst_fp12_is_one( &gt ) && !fd_bls_pub_is_inf( &agg->pub ) && !fd_bls_sig_is_inf( &agg->sig ) ) ) {
    fd_bls_set_null( bad );
    return 0;
  }

  fd_bls_agg_verify_bisect_hashed( agg, &h, &gt, pub, sig, bad );
  fd_bls_agg_t sub = { 0 };
  fd_bls_agg_construct( &sub, pub, sig, bad );
  fd_bls_pub_neg( &sub.pub, &sub.pub ); fd_bls_pub_add( &agg->pub, &agg->pub, &sub.pub );
  fd_bls_sig_neg( &sub.sig, &sub.sig ); fd_bls_sig_add( &agg->sig, &agg->sig, &sub.sig );
  fd_bls_set_subtract( agg->set, agg->set, bad );
  if( FD_UNLIKELY( fd_bls_pub_is_inf( &agg->pub ) ) ) return -1;
  return 0;
}
