#ifndef HEADER_fd_src_choreo_votor_test_fd_cert_builder_h
#define HEADER_fd_src_choreo_votor_test_fd_cert_builder_h

/* Certificates are built incrementally in fd_votor_pool.c as votes
   arrive.  These rebuild one from a complete vote list, which tests
   need to get a cert in isolation; they are not part of the fd_cert
   API. */

#include "fd_cert.h"
#include "fd_epoch_info.h"
#include "fd_vote.h"

static inline void
bls_key_from_sec( uchar                out[ FD_BLS_PUB_COMPRESSED_SZ ],
                  fd_bls_sec_t const * sec ) {
  fd_bls_pub_t pub[1];
  fd_bls_sec_to_pub( sec, pub );
  fd_bls_pub_compress( pub, out );
}

/* epoch_info_build fills epoch_info from an already ranked validator
   list.  Production ranks in the votor tile (handle_epoch). */

static inline void
epoch_info_build( fd_epoch_info_t *           epoch_info,
                  fd_validator_info_t const * validators,
                  ulong                       validator_cnt ) {
  epoch_info->total_stake = 0UL;
  for( ulong i=0UL; i<validator_cnt; i++ ) {
    FD_TEST( validators[i].id==i );
    epoch_info->validators[i] = validators[i];
    FD_TEST( !fd_bls_pub_de( &epoch_info->pubkeys[i], validators[i].bls_key, FD_BLS_PUB_COMPRESSED_SZ ) );
    epoch_info->total_stake  += validators[i].stake;
  }
  epoch_info->validator_cnt = validator_cnt;
}

static uchar const test_bls_public_key[ FD_BLS_PUB_COMPRESSED_SZ ] = {0};

/* A valid affine G2 point outside the prime-order subgroup. */
static inline void
test_bls_torsion( fd_bls_sig_t * out ) {
  static uchar const bytes[ FD_BLS_SIG_SZ ] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x17, 0x2e, 0x93, 0xdb, 0x76, 0x4a, 0x84, 0x00, 0xa7, 0xd5, 0x07, 0x1b, 0x6b, 0x6f, 0x5d, 0xe0,
    0xda, 0x2f, 0x0f, 0x4a, 0x06, 0x31, 0x19, 0xab, 0xca, 0x01, 0x40, 0x06, 0xb7, 0xc4, 0x0a, 0x2c,
    0xfe, 0x29, 0x1a, 0x19, 0x24, 0xe6, 0x5d, 0xb0, 0xd6, 0xd0, 0xfc, 0xfb, 0xf3, 0xbf, 0x3d, 0x5c,
    0x18, 0xc6, 0xb8, 0x64, 0xae, 0x17, 0xdc, 0x9d, 0xa6, 0x42, 0x03, 0xff, 0xef, 0xb9, 0x66, 0x30,
    0x64, 0x25, 0xa7, 0xbc, 0x6a, 0xeb, 0x7c, 0x75, 0x24, 0x74, 0x38, 0x37, 0x27, 0x16, 0x28, 0x4a,
    0x41, 0x73, 0x83, 0x04, 0x20, 0xcd, 0x47, 0x6b, 0xa1, 0xa3, 0x65, 0xb9, 0x5b, 0xfc, 0xec, 0x38
  };
  FD_TEST( !fd_bls_sig_de_unchecked( out, bytes ) );
  FD_TEST( !fd_bls_sig_validate( out ) );
}

/* test_bls_mul sets out = [k]a, k a big endian scalar of k_sz bytes,
   by double and add with fd_bls_sig_add (complete, also on points
   outside G2). */
static inline void
test_bls_mul( fd_bls_sig_t *       out,
              fd_bls_sig_t const * a,
              uchar const *        k,
              ulong                k_sz ) {
  fd_bls_sig_t acc; memset( &acc, 0, sizeof(acc) );
  for( ulong i=0UL; i<k_sz; i++ ) {
    for( int b=7; b>=0; b-- ) {
      fd_bls_sig_add( &acc, &acc, &acc );
      if( (k[i]>>b)&1 ) fd_bls_sig_add( &acc, &acc, a );
    }
  }
  *out = acc;
}

/* test_bls_pure_torsion sets out to [r]X for X = test_bls_torsion, a
   point of the cofactor torsion (no G2 component). */
static inline void
test_bls_pure_torsion( fd_bls_sig_t * out ) {
  static uchar const r[ 32 ] = {
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01 };
  fd_bls_sig_t x; test_bls_torsion( &x );
  test_bls_mul( out, &x, r, sizeof(r) );
  FD_TEST( !fd_bls_sig_is_inf( out ) && !fd_bls_sig_validate( out ) );
}

/* test_bls_small_torsion sets out to [r*h2/13]X, of order 13 unless
   infinity (returns 0 then). */
static inline int
test_bls_small_torsion( fd_bls_sig_t * out ) {
  static uchar const k[ 95 ] = {
    0x34, 0x04, 0x47, 0xbf, 0x71, 0x7d, 0x85, 0x7b, 0xfc, 0x7f, 0x74, 0x82, 0xa1, 0x2a, 0x4d, 0x11,
    0x73, 0x6d, 0x9b, 0x77, 0x43, 0xb6, 0xab, 0x6a, 0x60, 0x6e, 0xa3, 0x2b, 0x6e, 0xa8, 0x4b, 0x19,
    0xe5, 0x65, 0xec, 0x15, 0x73, 0x85, 0xb9, 0xc4, 0x17, 0x7b, 0xc8, 0xd9, 0x58, 0x12, 0x62, 0x8e,
    0x1b, 0xcd, 0xcf, 0x49, 0xd0, 0xa2, 0xb2, 0xe1, 0x8f, 0x8d, 0x56, 0x0d, 0xd5, 0xf2, 0x3d, 0xa2,
    0x65, 0x45, 0x4a, 0x42, 0x1f, 0x19, 0x2d, 0x21, 0x46, 0xae, 0xa0, 0xf3, 0xe0, 0x4f, 0xa0, 0x7b,
    0x50, 0x1b, 0xee, 0xa0, 0x94, 0x60, 0x83, 0x21, 0x6f, 0x89, 0xd8, 0x78, 0x57, 0x8e, 0x39 };
  fd_bls_sig_t x; test_bls_torsion( &x );
  test_bls_mul( out, &x, k, sizeof(k) );
  if( fd_bls_sig_is_inf( out ) ) return 0;
  FD_TEST( !fd_bls_sig_validate( out ) );
  return 1;
}

/* sec_sign_fn is the fd_bls_sign_fn of a test that holds the secret
   key in memory; ctx points to the fd_bls_sec_t. */

static inline void
sec_sign_fn( void *         ctx,
             fd_bls_sig_t * sig,
             uchar const *  public_key,
             uchar const *  msg,
             ulong          msg_sz ) {
  (void)public_key;
  fd_bls_sec_sign( (fd_bls_sec_t const *)ctx, msg, msg_sz, sig );
}

static inline void
agg_add( fd_bls_agg_t *       agg,
         ulong                rank,
         fd_bls_sig_t const * sig ) {
  fd_bls_set_insert( agg->set, rank );
  fd_bls_sig_add( &agg->sig, &agg->sig, sig );
}

static inline int
agg_is_identity( fd_bls_agg_t const * agg ) {
  return !!fd_bls_sig_is_inf( &agg->sig );
}

static inline fd_cert_t
cert_build_final( fd_vote_final_t const * votes, ulong vote_cnt, fd_epoch_info_t const * epoch_info );
static inline fd_cert_t
cert_build_fast_final( fd_vote_notar_t const * votes, ulong vote_cnt, fd_epoch_info_t const * epoch_info );
static inline fd_cert_t
cert_build_notar( fd_vote_notar_t const * votes, ulong vote_cnt, fd_epoch_info_t const * epoch_info );
static inline fd_cert_t
cert_build_notar_fallback( fd_vote_notar_t const * votes, ulong vote_cnt, fd_vote_notar_fallback_t const * fallback_votes, ulong fallback_vote_cnt, fd_epoch_info_t const * epoch_info );
static inline fd_cert_t
cert_build_skip( fd_vote_skip_t const * votes, ulong vote_cnt, fd_vote_skip_fallback_t const * fallback_votes, ulong fallback_vote_cnt, fd_epoch_info_t const * epoch_info );

static inline fd_cert_t
cert_build_final( fd_vote_final_t const * votes,
                  ulong                   vote_cnt,
                  fd_epoch_info_t const * epoch_info ) {
  fd_validator_info_t const * validators = fd_epoch_info_validators( epoch_info );
  FD_TEST( vote_cnt>0UL );
  ulong slot  = votes[0].slot;
  ulong stake = 0UL;
  for( ulong i=0UL; i<vote_cnt; i++ ) {
    FD_TEST( votes[i].slot==slot );
    stake += validators[ votes[i].rank ].stake;
  }
  fd_cert_final_t cert;
  cert.slot = slot; cert.stake = stake; cert.shred_version = votes[0].shred_version;
  memset( &cert.agg, 0, sizeof(fd_bls_agg_t) );
  for( ulong i=0UL; i<vote_cnt; i++ ) agg_add( &cert.agg, votes[i].rank, &votes[i].sig );
  return (fd_cert_t){ .kind = FD_CERT_KIND_FINAL, .final = cert };
}

static inline fd_cert_t
cert_build_fast_final( fd_vote_notar_t const * votes,
                       ulong                   vote_cnt,
                       fd_epoch_info_t const * epoch_info ) {
  fd_cert_notar_t      notar = cert_build_notar( votes, vote_cnt, epoch_info ).notar;
  fd_cert_fast_final_t cert;
  cert.slot = notar.slot; cert.stake = notar.stake; cert.agg = notar.agg; cert.shred_version = notar.shred_version;
  memcpy( &cert.block_hash, &notar.block_hash, sizeof(fd_block_hash_t) );
  return (fd_cert_t){ .kind = FD_CERT_KIND_FAST_FINAL, .fast_final = cert };
}

static inline fd_cert_t
cert_build_notar( fd_vote_notar_t const * votes,
                  ulong                   vote_cnt,
                  fd_epoch_info_t const * epoch_info ) {
  fd_validator_info_t const * validators = fd_epoch_info_validators( epoch_info );
  FD_TEST( vote_cnt>0UL );
  ulong           slot  = votes[0].slot;
  ulong           stake = 0UL;
  fd_block_hash_t block_hash;
  memcpy( &block_hash, &votes[0].block_hash, sizeof(fd_block_hash_t) );
  for( ulong i=0UL; i<vote_cnt; i++ ) {
    FD_TEST( votes[i].slot==slot );
    FD_TEST( !memcmp( &votes[i].block_hash, &block_hash, sizeof(fd_block_hash_t) ) );
    stake += validators[ votes[i].rank ].stake;
  }
  fd_cert_notar_t cert;
  cert.slot = slot; cert.stake = stake; cert.shred_version = votes[0].shred_version;
  memcpy( &cert.block_hash, &block_hash, sizeof(fd_block_hash_t) );
  memset( &cert.agg, 0, sizeof(fd_bls_agg_t) );
  for( ulong i=0UL; i<vote_cnt; i++ ) agg_add( &cert.agg, votes[i].rank, &votes[i].sig );
  return (fd_cert_t){ .kind = FD_CERT_KIND_NOTAR, .notar = cert };
}

static inline fd_cert_t
cert_build_notar_fallback( fd_vote_notar_t const *          votes,
                           ulong                            vote_cnt,
                           fd_vote_notar_fallback_t const * fallback_votes,
                           ulong                            fallback_vote_cnt,
                           fd_epoch_info_t const *          epoch_info ) {
  fd_validator_info_t const * validators = fd_epoch_info_validators( epoch_info );
  FD_TEST( vote_cnt>0UL || fallback_vote_cnt>0UL );
  ulong           slot;
  fd_block_hash_t block_hash;
  if( vote_cnt>0UL ) { slot = votes[0].slot;                   memcpy( &block_hash, &votes[0].block_hash,                   sizeof(fd_block_hash_t) ); }
  else               { slot = fallback_votes[0].slot; memcpy( &block_hash, &fallback_votes[0].block_hash, sizeof(fd_block_hash_t) ); }

  ulong stake = 0UL;
  for( ulong i=0UL; i<vote_cnt; i++ ) {
    FD_TEST( votes[i].slot==slot );
    FD_TEST( !memcmp( &votes[i].block_hash, &block_hash, sizeof(fd_block_hash_t) ) );
    stake += validators[ votes[i].rank ].stake;
  }
  ulong stake_fallback = 0UL;
  for( ulong i=0UL; i<fallback_vote_cnt; i++ ) {
    FD_TEST( fallback_votes[i].slot==slot );
    FD_TEST( !memcmp( &fallback_votes[i].block_hash, &block_hash, sizeof(fd_block_hash_t) ) );
    stake_fallback += validators[ fallback_votes[i].rank ].stake;
  }

  fd_cert_notar_fallback_t cert;
  cert.slot = slot; cert.shred_version = vote_cnt>0UL ? votes[0].shred_version : fallback_votes[0].shred_version;
  memcpy( &cert.block_hash, &block_hash, sizeof(fd_block_hash_t) );
  memset( &cert.agg_notar, 0, sizeof(fd_bls_agg_t) );
  for( ulong i=0UL; i<vote_cnt; i++ ) agg_add( &cert.agg_notar, votes[i].rank, &votes[i].sig );
  if( FD_UNLIKELY( agg_is_identity( &cert.agg_notar ) ) ) {
    memset( &cert.agg_notar, 0, sizeof(fd_bls_agg_t) );
    stake = 0UL;
  }
  memset( &cert.agg_notar_fallback, 0, sizeof(fd_bls_agg_t) );
  for( ulong i=0UL; i<fallback_vote_cnt; i++ ) agg_add( &cert.agg_notar_fallback, fallback_votes[i].rank, &fallback_votes[i].sig );
  if( FD_UNLIKELY( agg_is_identity( &cert.agg_notar_fallback ) ) ) {
    memset( &cert.agg_notar_fallback, 0, sizeof(fd_bls_agg_t) );
    stake_fallback = 0UL;
  }
  cert.stake = stake + stake_fallback;
  return (fd_cert_t){ .kind = FD_CERT_KIND_NOTAR_FALLBACK, .notar_fallback = cert };
}

static inline fd_cert_t
cert_build_skip( fd_vote_skip_t const *          votes,
                 ulong                           vote_cnt,
                 fd_vote_skip_fallback_t const * fallback_votes,
                 ulong                           fallback_vote_cnt,
                 fd_epoch_info_t const *         epoch_info ) {
  fd_validator_info_t const * validators = fd_epoch_info_validators( epoch_info );
  FD_TEST( vote_cnt>0UL || fallback_vote_cnt>0UL );
  ulong slot = vote_cnt>0UL ? votes[0].slot : fallback_votes[0].slot;

  ulong stake = 0UL;
  for( ulong i=0UL; i<vote_cnt; i++ ) {
    FD_TEST( votes[i].slot==slot );
    stake += validators[ votes[i].rank ].stake;
  }
  ulong stake_fallback = 0UL;
  for( ulong i=0UL; i<fallback_vote_cnt; i++ ) {
    FD_TEST( fallback_votes[i].slot==slot );
    stake_fallback += validators[ fallback_votes[i].rank ].stake;
  }

  fd_cert_skip_t cert;
  cert.slot = slot; cert.shred_version = vote_cnt>0UL ? votes[0].shred_version : fallback_votes[0].shred_version;
  memset( &cert.agg_skip, 0, sizeof(fd_bls_agg_t) );
  for( ulong i=0UL; i<vote_cnt; i++ ) agg_add( &cert.agg_skip, votes[i].rank, &votes[i].sig );
  if( FD_UNLIKELY( agg_is_identity( &cert.agg_skip ) ) ) {
    memset( &cert.agg_skip, 0, sizeof(fd_bls_agg_t) );
    stake = 0UL;
  }
  memset( &cert.agg_skip_fallback, 0, sizeof(fd_bls_agg_t) );
  for( ulong i=0UL; i<fallback_vote_cnt; i++ ) agg_add( &cert.agg_skip_fallback, fallback_votes[i].rank, &fallback_votes[i].sig );
  if( FD_UNLIKELY( agg_is_identity( &cert.agg_skip_fallback ) ) ) {
    memset( &cert.agg_skip_fallback, 0, sizeof(fd_bls_agg_t) );
    stake_fallback = 0UL;
  }
  cert.stake = stake + stake_fallback;
  return (fd_cert_t){ .kind = FD_CERT_KIND_SKIP, .skip = cert };
}

#endif
