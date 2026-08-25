#include "ag_bls.h"

#include "../../ballet/bls/fd_bls12_381.h"
#include "../../third_party/blst/bindings/blst.h"
#if FD_HAS_AVX512
#include "../../ballet/bls/fd_vroom.h"
#endif

#define AG_BLS_DST        "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
#define AG_BLS_DST_SZ     (sizeof(AG_BLS_DST)-1UL)

#define AG_BLS_VERIFY_MAX (2UL)

FD_STATIC_ASSERT( sizeof(ag_bls_pub_native_t)==sizeof(blst_p1_affine), native_pub_sz );
FD_STATIC_ASSERT( alignof(ag_bls_pub_native_t)>=alignof(blst_p1_affine), native_pub_align );
FD_STATIC_ASSERT( sizeof(ag_bls_hash_native_t)==sizeof(blst_p2_affine), native_hash_sz );
FD_STATIC_ASSERT( alignof(ag_bls_hash_native_t)>=alignof(blst_p2_affine), native_hash_align );
FD_STATIC_ASSERT( !(AG_BLS_HASH_CACHE_CNT & (AG_BLS_HASH_CACHE_CNT-1UL)), hash_cache_pow2 );

void
ag_bls_sec_to_pub( ag_bls_sec_t const sk,
                   ag_bls_pub_t *     pk ) {
  blst_scalar    scalar[1];
  blst_p1        p[1];
  blst_p1_affine a[1];
  blst_scalar_from_lendian( scalar, sk );
  blst_sk_to_pk_in_g1( p, scalar );
  blst_p1_to_affine( a, p );
  blst_p1_affine_serialize( pk->bytes, a );
}

void
ag_bls_sec_sign( ag_bls_sec_t const sk,
                 ag_bls_sig_t       sig,
                 uchar const *      msg,
                 ulong              msg_sz ) {
  blst_scalar    scalar[1];
  blst_p2        hash[1];
  blst_p2        s[1];
  blst_p2_affine a[1];
  blst_scalar_from_lendian( scalar, sk );
  blst_hash_to_g2( hash, msg, msg_sz, (uchar const *)AG_BLS_DST, AG_BLS_DST_SZ, NULL, 0UL );
  blst_sign_pk_in_g1( s, hash, scalar );
  blst_p2_to_affine( a, s );
  blst_p2_affine_serialize( sig, a );
}

void
ag_bls_sec_derive( ag_bls_sec_t  sk,
                   uchar const * ikm,
                   ulong         ikm_sz ) {
  FD_TEST( ikm_sz>=32UL );
  blst_scalar scalar[1];
  blst_keygen( scalar, ikm, ikm_sz, NULL, 0UL );
  fd_memcpy( sk, scalar->b, AG_BLS_SEC_SZ );
}

/* ag_bls_pub_t values have already passed the subgroup check at their
   construction boundary. */

static int
pub_deserialize( blst_p1_affine * out,
                 ag_bls_pub_t const * in ) {
  return blst_p1_deserialize( out, in->bytes )==BLST_SUCCESS &&
         !blst_p1_affine_is_inf( out );
}

static int
pub_from_bytes( blst_p1_affine * out,
                uchar const *    in,
                ulong            in_sz ) {
  BLST_ERROR err;
  switch( in_sz ) {
  case AG_BLS_PUB_COMPRESSED_SZ: err = blst_p1_uncompress ( out, in ); break;
  case AG_BLS_PUB_SZ:            err = blst_p1_deserialize( out, in ); break;
  default: return 0;
  }
  return err==BLST_SUCCESS &&
         !blst_p1_affine_is_inf( out ) &&
         blst_p1_affine_in_g1( out );
}

static int
pub_aggregate( blst_p1_affine *    out,
               ag_bls_pub_t const * pks,
               signer_set_t const * signers,
               ulong                pk_cnt ) {
  if( FD_UNLIKELY( !pk_cnt || pk_cnt>AG_BLS_SIGNERS_MAX ) ) return -1;

  static FD_TL blst_p1_affine         affine[ AG_BLS_SIGNERS_MAX ];
  static FD_TL blst_p1_affine const * points[ AG_BLS_SIGNERS_MAX ];
  ulong point_cnt = 0UL;
  for( ulong i=0UL; i<pk_cnt; i++ ) {
    if( signers && !signer_set_test( signers, i ) ) continue;
    if( FD_UNLIKELY( !pub_deserialize( affine+point_cnt, pks+i ) ) ) return -1;
    points[ point_cnt ] = affine+point_cnt;
    point_cnt++;
  }
  if( FD_UNLIKELY( !point_cnt ) ) return -1;

  blst_p1 sum[1];
  blst_p1s_add( sum, points, point_cnt );
  blst_p1_to_affine( out, sum );
  return 0;
}

int
ag_bls_pub_try_from_bytes( ag_bls_pub_t * out,
                           uchar const *  in,
                           ulong          in_sz ) {
  blst_p1_affine pub[1];
  if( FD_UNLIKELY( !pub_from_bytes( pub, in, in_sz ) ) ) return -1;
  blst_p1_affine_serialize( out->bytes, pub );
  return 0;
}

int
ag_bls_pub_native_from_bytes( ag_bls_pub_native_t * out,
                              ag_bls_pub_t const *   in ) {
  return pub_deserialize( (blst_p1_affine *)out, in ) ? 0 : -1;
}

void
ag_bls_pub_native_aggregate( ag_bls_pub_native_t *       out,
                             ag_bls_pub_native_t const * pks,
                             ulong                       cnt ) {
  FD_TEST( out && pks && cnt && cnt<=AG_BLS_PUB_BLOCK_SZ );
  blst_p1_affine const * points[ AG_BLS_PUB_BLOCK_SZ ];
  for( ulong i=0UL; i<cnt; i++ ) points[i] = (blst_p1_affine const *)(pks+i);
  blst_p1 sum[1];
  blst_p1s_add( sum, points, cnt );
  blst_p1_to_affine( (blst_p1_affine *)out, sum );
}

void
ag_bls_pub_cache_init( ag_bls_pub_cache_t *        cache,
                       ag_bls_pub_native_t const * pks,
                       ulong                       pk_cnt ) {
  FD_TEST( cache && pk_cnt<=AG_BLS_SIGNERS_MAX );
  if( FD_UNLIKELY( !pk_cnt ) ) {
    fd_memset( cache, 0, sizeof(ag_bls_pub_cache_t) );
    return;
  }
  FD_TEST( pks );

  ulong block_cnt = (pk_cnt + AG_BLS_PUB_BLOCK_SZ - 1UL) / AG_BLS_PUB_BLOCK_SZ;
  for( ulong block=0UL; block<block_cnt; block++ ) {
    ulong begin = block * AG_BLS_PUB_BLOCK_SZ;
    ulong cnt   = fd_ulong_min( AG_BLS_PUB_BLOCK_SZ, pk_cnt-begin );
    ag_bls_pub_native_aggregate( cache->block+block, pks+begin, cnt );
  }
  if( FD_LIKELY( block_cnt>1UL ) )
    ag_bls_pub_native_aggregate( &cache->total, cache->block, block_cnt );
  else
    cache->total = cache->block[0];
}

static int
verify_affine_pairs( blst_p1_affine const * a,
                     uchar const * const *  msgs,
                     ulong const *          msg_szs,
                     ulong                  cnt,
                     uchar const *          sig,
                     ag_bls_hash_cache_t *  hash_cache ) {
  if( FD_UNLIKELY( !cnt || cnt>AG_BLS_VERIFY_MAX ) ) return 0;
#if FD_HAS_AVX512
  ulong prepared_candidate = ULONG_MAX;
#endif
  blst_p2_affine b[ AG_BLS_VERIFY_MAX ];
  for( ulong i=0UL; i<cnt; i++ ) {
    ulong tag = fd_hash( 0x9e3779b97f4a7c15UL, msgs[i], msg_szs[i] );
    ag_bls_hash_cache_entry_t * entry = NULL;
    int hit = 0;
    if( FD_LIKELY( hash_cache && msg_szs[i]<=AG_BLS_HASH_MSG_MAX ) ) {
      for( ulong j=0UL; j<AG_BLS_HASH_CACHE_CNT; j++ ) {
        ag_bls_hash_cache_entry_t * candidate = hash_cache->entry+j;
        if( candidate->valid && candidate->tag==tag && candidate->msg_sz==msg_szs[i] &&
            fd_memeq( candidate->msg, msgs[i], msg_szs[i] ) ) {
          entry = candidate;
          hit   = 1;
          break;
        }
      }
      if( FD_UNLIKELY( !hit ) ) {
        entry = hash_cache->entry + ((hash_cache->next++) & (AG_BLS_HASH_CACHE_CNT-1UL));
#if FD_HAS_AVX512
        ulong entry_idx = (ulong)(entry-hash_cache->entry);
        hash_cache->prepared[entry_idx].valid = 0;
#endif
      }
    }
    if( FD_LIKELY( hit ) ) {
      fd_memcpy( b+i, &entry->point, sizeof(blst_p2_affine) );
#if FD_HAS_AVX512
      if( cnt==1UL ) prepared_candidate = (ulong)(entry-hash_cache->entry);
#endif
    } else {
      blst_p2 h[1];
      blst_hash_to_g2( h, msgs[i], msg_szs[i], (uchar const *)AG_BLS_DST, AG_BLS_DST_SZ, NULL, 0UL );
      blst_p2_to_affine( b+i, h );
      if( FD_LIKELY( entry ) ) {
        entry->valid  = 0;
        entry->tag    = tag;
        entry->msg_sz = msg_szs[i];
        fd_memcpy( entry->msg, msgs[i], msg_szs[i] );
        fd_memcpy( &entry->point, b+i, sizeof(blst_p2_affine) );
        entry->valid  = 1;
#if FD_HAS_AVX512
        if( cnt==1UL ) prepared_candidate = (ulong)(entry-hash_cache->entry);
#endif
      }
    }
  }

  blst_p2_affine signature[1];
  if( FD_UNLIKELY( blst_p2_deserialize( signature, sig )!=BLST_SUCCESS ) ) return 0;
  if( FD_UNLIKELY( blst_p2_affine_is_inf( signature )                  ) ) return 0;

  blst_p1_affine const * aptr[ AG_BLS_VERIFY_MAX+1UL ];
  blst_p2_affine const * bptr[ AG_BLS_VERIFY_MAX+1UL ];
  for( ulong i=0UL; i<cnt; i++ ) { aptr[i] = a+i; bptr[i] = b+i; }
  aptr[cnt] = &BLS12_381_NEG_G1;
  bptr[cnt] = signature;

#if FD_HAS_AVX512
  fd_vroom_g2_prepared_t const * prepared = NULL;
  if( FD_LIKELY( prepared_candidate!=ULONG_MAX ) ) {
    ag_bls_prepared_cache_entry_t * prepared_entry = hash_cache->prepared+prepared_candidate;
    if( FD_UNLIKELY( !prepared_entry->valid ) ) {
      prepared_entry->valid = 0;
      if( FD_UNLIKELY( fd_vroom_g2_prepare( &prepared_entry->point, b ) ) ) return 0;
      prepared_entry->valid = 1;
    }
    prepared = &prepared_entry->point;
  }

  blst_p1_affine pair_p[ AG_BLS_VERIFY_MAX+1UL ];
  blst_p2_affine pair_q[ AG_BLS_VERIFY_MAX+1UL ];
  for( ulong i=0UL; i<cnt; i++ ) { pair_p[i] = a[i]; pair_q[i] = b[i]; }
  pair_p[cnt] = BLS12_381_NEG_G1;
  pair_q[cnt] = *signature;
  int vroom_result;
  if( FD_LIKELY( cnt==1UL && prepared ) )
    vroom_result = fd_vroom_pairing_finalverify_prepared_checked(
        pair_p, prepared, pair_p+1, pair_q+1 );
  else
    vroom_result = fd_vroom_pairing_finalverify_checked( pair_p, pair_q, cnt+1UL, 1UL<<cnt );
  if( FD_LIKELY( vroom_result>=0 ) ) return vroom_result;
#endif

  if( FD_UNLIKELY( !blst_p2_affine_in_g2( signature ) ) ) return 0;
  blst_fp12 r[1];
  blst_miller_loop_n( r, bptr, aptr, cnt+1UL );
  return !!blst_fp12_finalverify( r, blst_fp12_one() );
}

int
ag_bls_sig_verify( ag_bls_sig_t const self,
                   ag_bls_pub_t const * pk,
                   uchar const *        msg,
                   ulong                msg_sz ) {
  blst_p1_affine pub[1];
  if( FD_UNLIKELY( !pub_deserialize( pub, pk ) ) ) return 0;
  uchar const * msgs   [1] = { msg    };
  ulong         msg_szs[1] = { msg_sz };
  return verify_affine_pairs( pub, msgs, msg_szs, 1UL, self, NULL );
}

void
ag_bls_hash_cache_init( ag_bls_hash_cache_t * cache ) {
  FD_TEST( cache );
  fd_memset( cache, 0, sizeof(ag_bls_hash_cache_t) );
}

int
ag_bls_sig_verify_hash_cached( ag_bls_sig_t const   self,
                               ag_bls_pub_t const * pk,
                               uchar const *        msg,
                               ulong                msg_sz,
                               ag_bls_hash_cache_t * hash_cache ) {
  if( FD_UNLIKELY( !hash_cache ) ) return 0;
  blst_p1_affine pub[1];
  if( FD_UNLIKELY( !pub_deserialize( pub, pk ) ) ) return 0;
  uchar const * msgs   [1] = { msg    };
  ulong         msg_szs[1] = { msg_sz };
  return verify_affine_pairs( pub, msgs, msg_szs, 1UL, self, hash_cache );
}

void
ag_bls_agg_zero( ag_bls_agg_t * agg ) {
  fd_memset( agg->sig, 0, AG_BLS_SIG_SZ );
  signer_set_null( agg->bitmask );
}

void
ag_bls_agg_add( ag_bls_agg_t *     self,
                ulong              signer_idx,
                ag_bls_sig_t const sig ) {
  FD_TEST( signer_idx<AG_BLS_SIGNERS_MAX );
  FD_TEST( !signer_set_test( self->bitmask, signer_idx ) );

  int first = ( signer_set_cnt( self->bitmask )==0UL );
  signer_set_insert( self->bitmask, signer_idx );

  if( FD_UNLIKELY( first ) ) {
    fd_memcpy( self->sig, sig, AG_BLS_SIG_SZ );
    return;
  }

  fd_bls12_381_g2_add_syscall( self->sig, self->sig, sig, 1 );
}

void
ag_bls_agg_merge( ag_bls_agg_t * dst,
                  ag_bls_agg_t * src ) {
  if( FD_UNLIKELY( signer_set_cnt( src->bitmask )==0UL ) ) return;

  if( signer_set_cnt( dst->bitmask )==0UL ) {
    fd_memcpy( dst->sig, src->sig, AG_BLS_SIG_SZ );
  } else {
    fd_bls12_381_g2_add_syscall( dst->sig, dst->sig, src->sig, 1 );
  }
  fd_memset( src->sig, 0, AG_BLS_SIG_SZ );
}

int
ag_bls_agg_is_identity( ag_bls_agg_t const * self ) {
  blst_p2_affine a[1];
  if( FD_UNLIKELY( blst_p2_deserialize( a, self->sig )!=BLST_SUCCESS ) ) return 0;
  return !!blst_p2_affine_is_inf( a );
}

int
ag_bls_agg_verify( ag_bls_agg_t const * self,
                   uchar const *        msg,
                   ulong                msg_sz,
                   ag_bls_pub_t const * pks,
                   ulong                pk_cnt ) {
  if( FD_UNLIKELY( fd_ulong_min( AG_BLS_SIGNERS_MAX, signer_set_last( self->bitmask )+1UL )>pk_cnt ) ) return 0;
  if( FD_UNLIKELY( !pks                                                                            ) ) return 0;

  blst_p1_affine apk[1];
  if( FD_UNLIKELY( pub_aggregate( apk, pks, self->bitmask, pk_cnt ) ) ) return 0;

  uchar const * msgs   [1] = { msg    };
  ulong         msg_szs[1] = { msg_sz };
  return verify_affine_pairs( apk, msgs, msg_szs, 1UL, self->sig, NULL );
}

static inline ulong
native_valid_mask( ulong cnt ) {
  return cnt==AG_BLS_PUB_BLOCK_SZ ? ~0UL : ((1UL<<cnt)-1UL);
}

/* Aggregate the set bits without ever converting a key back through its wire
   encoding.  A cached block represents a full/empty 64-key word as one point.
   For partial words, choose the cheaper of summing signers directly or
   subtracting non-signers from the epoch total. */
static int
aggregate_native_mask( blst_p1_affine *             out,
                       signer_set_t const *          mask,
                       ag_bls_pub_native_t const *   pks,
                       ag_bls_pub_cache_t const *    cache,
                       ulong                         pk_cnt ) {
  static FD_TL blst_p1_affine const * points[ AG_BLS_SIGNERS_MAX ];
  ulong block_cnt = (pk_cnt + AG_BLS_PUB_BLOCK_SZ - 1UL) / AG_BLS_PUB_BLOCK_SZ;
  ulong direct_cost = 0UL;
  ulong missing_cost = 0UL;
  for( ulong block=0UL; block<block_cnt; block++ ) {
    ulong begin = block*AG_BLS_PUB_BLOCK_SZ;
    ulong cnt   = fd_ulong_min( AG_BLS_PUB_BLOCK_SZ, pk_cnt-begin );
    ulong valid = native_valid_mask( cnt );
    ulong bits  = mask[block] & valid;
    direct_cost  += bits==valid ? 1UL : (ulong)fd_ulong_popcnt( bits );
    ulong missing = bits ^ valid;
    missing_cost += missing==valid ? 1UL : (ulong)fd_ulong_popcnt( missing );
  }
  if( FD_UNLIKELY( !direct_cost ) ) return 0;

  int complement = !!cache && missing_cost<direct_cost;
  ulong k = 0UL;
  for( ulong block=0UL; block<block_cnt; block++ ) {
    ulong begin = block*AG_BLS_PUB_BLOCK_SZ;
    ulong cnt   = fd_ulong_min( AG_BLS_PUB_BLOCK_SZ, pk_cnt-begin );
    ulong valid = native_valid_mask( cnt );
    ulong bits  = mask[block] & valid;
    if( complement ) bits ^= valid;
    if( FD_LIKELY( cache ) && bits==valid ) {
      points[k++] = (blst_p1_affine const *)(cache->block+block);
    } else {
      while( bits ) {
        ulong bit = (ulong)fd_ulong_find_lsb( bits );
        points[k++] = (blst_p1_affine const *)(pks+begin+bit);
        bits = fd_ulong_pop_lsb( bits );
      }
    }
  }

  if( FD_LIKELY( !complement ) ) {
    if( FD_LIKELY( k>1UL ) ) {
      blst_p1 sum[1];
      blst_p1s_add( sum, points, k );
      blst_p1_to_affine( out, sum );
    } else {
      *out = *points[0];
    }
    return 1;
  }

  blst_p1_affine total[1];
  fd_memcpy( total, &cache->total, sizeof(blst_p1_affine) );
  if( FD_UNLIKELY( !k ) ) {
    *out = total[0];
    return 1;
  }

  blst_p1 delta[1];
  if( FD_LIKELY( k>1UL ) ) blst_p1s_add( delta, points, k );
  else                     blst_p1_from_affine( delta, points[0] );
  blst_p1_cneg( delta, 1 );

  blst_p1 sum[1];
  blst_p1_from_affine( sum, total );
  blst_p1_add_or_double( sum, sum, delta );
  blst_p1_to_affine( out, sum );
  return 1;
}

static int
agg_verify_native_impl( ag_bls_agg_t const *        self,
                        uchar const *               msg,
                        ulong                       msg_sz,
                        ag_bls_pub_native_t const * pks,
                        ag_bls_pub_cache_t const *  cache,
                        ulong                       pk_cnt,
                        ag_bls_hash_cache_t *       hash_cache ) {
  if( FD_UNLIKELY( fd_ulong_min( AG_BLS_SIGNERS_MAX, signer_set_last( self->bitmask )+1UL )>pk_cnt ) ) return 0;
  if( FD_UNLIKELY( !pks || !pk_cnt ) ) return 0;

  blst_p1_affine apk[1];
  if( FD_UNLIKELY( !aggregate_native_mask( apk, self->bitmask, pks, cache, pk_cnt ) ) ) return 0;

  uchar const * msgs   [1] = { msg    };
  ulong         msg_szs[1] = { msg_sz };
  return verify_affine_pairs( apk, msgs, msg_szs, 1UL, self->sig, hash_cache );
}

int
ag_bls_agg_verify_native( ag_bls_agg_t const *        self,
                          uchar const *               msg,
                          ulong                       msg_sz,
                          ag_bls_pub_native_t const * pks,
                          ulong                       pk_cnt ) {
  return agg_verify_native_impl( self, msg, msg_sz, pks, NULL, pk_cnt, NULL );
}

int
ag_bls_agg_verify_native_cached( ag_bls_agg_t const *        self,
                                 uchar const *               msg,
                                 ulong                       msg_sz,
                                 ag_bls_pub_native_t const * pks,
                                 ag_bls_pub_cache_t const *  cache,
                                 ulong                       pk_cnt ) {
  return agg_verify_native_impl( self, msg, msg_sz, pks, cache, pk_cnt, NULL );
}

int
ag_bls_agg_verify_native_hash_cached( ag_bls_agg_t const *        self,
                                      uchar const *               msg,
                                      ulong                       msg_sz,
                                      ag_bls_pub_native_t const * pks,
                                      ag_bls_pub_cache_t const *  cache,
                                      ulong                       pk_cnt,
                                      ag_bls_hash_cache_t *       hash_cache ) {
  if( FD_UNLIKELY( !cache ) ) return 0;
  return agg_verify_native_impl( self, msg, msg_sz, pks, cache, pk_cnt, hash_cache );
}

int
ag_bls_agg_verify_without_bitmask( ag_bls_agg_t const * self,
                                   uchar const *        msg,
                                   ulong                msg_sz,
                                   ag_bls_pub_t const * pks,
                                   ulong                pk_cnt ) {
  if( FD_UNLIKELY( ag_bls_agg_signer_cnt( self )!=pk_cnt ) ) return 0;
  if( FD_UNLIKELY( !pks || !pk_cnt                          ) ) return 0;

  blst_p1_affine apk[1];
  if( FD_UNLIKELY( pub_aggregate( apk, pks, NULL, pk_cnt ) ) ) return 0;

  uchar const * msgs   [1] = { msg    };
  ulong         msg_szs[1] = { msg_sz };
  return verify_affine_pairs( apk, msgs, msg_szs, 1UL, self->sig, NULL );
}

int
ag_bls_agg_verify_merged( ag_bls_agg_t const * agg_base,
                         uchar const *        msg_base,
                         ulong                msg_base_sz,
                         ag_bls_agg_t const * agg_fb,
                         uchar const *        msg_fb,
                         ulong                msg_fb_sz,
                         ag_bls_pub_t const * pks,
                         ulong                pk_cnt ) {
  if( FD_UNLIKELY( fd_ulong_min( AG_BLS_SIGNERS_MAX, signer_set_last( agg_base->bitmask )+1UL )>pk_cnt ) ) return 0;
  if( FD_UNLIKELY( fd_ulong_min( AG_BLS_SIGNERS_MAX, signer_set_last( agg_fb->bitmask   )+1UL )>pk_cnt ) ) return 0;
  if( FD_UNLIKELY( !pks                                                                                ) ) return 0;

  blst_p1_affine apk[2];
  signer_set_t const * masks[2] = { agg_base->bitmask, agg_fb->bitmask };
  ulong cnt[2] = { 0UL, 0UL };
  for( ulong g=0UL; g<2UL; g++ ) {
    cnt[g] = signer_set_cnt( masks[g] );
    if( cnt[g] && FD_UNLIKELY( pub_aggregate( apk+g, pks, masks[g], pk_cnt ) ) ) return 0;
  }

  if( FD_UNLIKELY( cnt[0]==0UL && cnt[1]==0UL ) ) return 0;

  blst_p1_affine packed_apk[ AG_BLS_VERIFY_MAX ];
  uchar const * msgs   [ AG_BLS_VERIFY_MAX ];
  ulong         msg_szs[ AG_BLS_VERIFY_MAX ];
  ulong         n = 0UL;
  if( cnt[0] ) { packed_apk[n] = apk[0]; msgs[n] = msg_base; msg_szs[n] = msg_base_sz; n++; }
  if( cnt[1] ) { packed_apk[n] = apk[1]; msgs[n] = msg_fb;   msg_szs[n] = msg_fb_sz;   n++; }

  return verify_affine_pairs( packed_apk, msgs, msg_szs, n, agg_base->sig, NULL );
}

static int
agg_verify_merged_native_impl( ag_bls_agg_t const *        agg_base,
                               uchar const *               msg_base,
                               ulong                       msg_base_sz,
                               ag_bls_agg_t const *        agg_fb,
                               uchar const *               msg_fb,
                               ulong                       msg_fb_sz,
                               ag_bls_pub_native_t const * pks,
                               ag_bls_pub_cache_t const *  cache,
                               ulong                       pk_cnt,
                               ag_bls_hash_cache_t *       hash_cache ) {
  if( FD_UNLIKELY( fd_ulong_min( AG_BLS_SIGNERS_MAX, signer_set_last( agg_base->bitmask )+1UL )>pk_cnt ) ) return 0;
  if( FD_UNLIKELY( fd_ulong_min( AG_BLS_SIGNERS_MAX, signer_set_last( agg_fb->bitmask   )+1UL )>pk_cnt ) ) return 0;
  if( FD_UNLIKELY( !pks || !pk_cnt ) ) return 0;

  blst_p1_affine apk[2];
  signer_set_t const * masks[2] = { agg_base->bitmask, agg_fb->bitmask };
  int present[2];
  for( ulong g=0UL; g<2UL; g++ ) present[g] = aggregate_native_mask( apk+g, masks[g], pks, cache, pk_cnt );
  if( FD_UNLIKELY( !present[0] && !present[1] ) ) return 0;

  blst_p1_affine packed_apk[2];
  uchar const * msgs[2];
  ulong msg_szs[2];
  ulong n = 0UL;
  if( present[0] ) { packed_apk[n] = apk[0]; msgs[n] = msg_base; msg_szs[n] = msg_base_sz; n++; }
  if( present[1] ) { packed_apk[n] = apk[1]; msgs[n] = msg_fb;   msg_szs[n] = msg_fb_sz;   n++; }
  return verify_affine_pairs( packed_apk, msgs, msg_szs, n, agg_base->sig, hash_cache );
}
int
ag_bls_agg_verify_merged_native( ag_bls_agg_t const *        agg_base,
                                 uchar const *               msg_base,
                                 ulong                       msg_base_sz,
                                 ag_bls_agg_t const *        agg_fb,
                                 uchar const *               msg_fb,
                                 ulong                       msg_fb_sz,
                                 ag_bls_pub_native_t const * pks,
                                 ulong                       pk_cnt ) {
  return agg_verify_merged_native_impl( agg_base, msg_base, msg_base_sz,
                                        agg_fb, msg_fb, msg_fb_sz,
                                        pks, NULL, pk_cnt, NULL );
}

int
ag_bls_agg_verify_merged_native_cached( ag_bls_agg_t const *        agg_base,
                                        uchar const *               msg_base,
                                        ulong                       msg_base_sz,
                                        ag_bls_agg_t const *        agg_fb,
                                        uchar const *               msg_fb,
                                        ulong                       msg_fb_sz,
                                        ag_bls_pub_native_t const * pks,
                                        ag_bls_pub_cache_t const *  cache,
                                        ulong                       pk_cnt ) {
  return agg_verify_merged_native_impl( agg_base, msg_base, msg_base_sz,
                                        agg_fb, msg_fb, msg_fb_sz,
                                        pks, cache, pk_cnt, NULL );
}

int
ag_bls_agg_verify_merged_native_hash_cached( ag_bls_agg_t const *        agg_base,
                                             uchar const *               msg_base,
                                             ulong                       msg_base_sz,
                                             ag_bls_agg_t const *        agg_fb,
                                             uchar const *               msg_fb,
                                             ulong                       msg_fb_sz,
                                             ag_bls_pub_native_t const * pks,
                                             ag_bls_pub_cache_t const *  cache,
                                             ulong                       pk_cnt,
                                             ag_bls_hash_cache_t *       hash_cache ) {
  if( FD_UNLIKELY( !cache ) ) return 0;
  return agg_verify_merged_native_impl( agg_base, msg_base, msg_base_sz,
                                        agg_fb, msg_fb, msg_fb_sz,
                                        pks, cache, pk_cnt, hash_cache );
}
