#ifndef HEADER_fd_src_choreo_votor_test_ag_cert_builder_h
#define HEADER_fd_src_choreo_votor_test_ag_cert_builder_h

/* Certificates are built incrementally in ag_slot_state.c as votes
   arrive.  These rebuild one from a complete vote list, which tests
   need to get a cert in isolation; they are not part of the ag_cert
   API. */

#include "ag_cert.h"
#include "ag_epoch_info.h"
#include "ag_vote.h"

/* sec_sign_fn is the ag_bls_sign_fn of a test that holds the secret
   key in memory; ctx points to the ag_bls_sec_t. */

static void
sec_sign_fn( void *         ctx,
             ag_bls_sig_t * sig,
             uchar const *  msg,
             ulong          msg_sz ) {
  ag_bls_sec_sign( (ag_bls_sec_t const *)ctx, msg, msg_sz, sig );
}

static inline void
agg_add( ag_bls_agg_t *       agg,
         ulong                rank,
         ag_bls_sig_t const * sig ) {
  ag_bls_set_insert( agg->set, rank );
  blst_p2_add_or_double( &agg->sig, &agg->sig, sig );
}

static inline int
agg_is_identity( ag_bls_agg_t const * agg ) {
  return !!blst_p2_is_inf( &agg->sig );
}

static inline ag_cert_t
cert_build_final( ag_vote_final_t const * votes, ulong vote_cnt, ag_epoch_info_t const * epoch_info );
static inline ag_cert_t
cert_build_fast_final( ag_vote_notar_t const * votes, ulong vote_cnt, ag_epoch_info_t const * epoch_info );
static inline ag_cert_t
cert_build_notar( ag_vote_notar_t const * votes, ulong vote_cnt, ag_epoch_info_t const * epoch_info );
static inline ag_cert_t
cert_build_notar_fallback( ag_vote_notar_t const * votes, ulong vote_cnt, ag_vote_notar_fallback_t const * fallback_votes, ulong fallback_vote_cnt, ag_epoch_info_t const * epoch_info );
static inline ag_cert_t
cert_build_skip( ag_vote_skip_t const * votes, ulong vote_cnt, ag_vote_skip_fallback_t const * fallback_votes, ulong fallback_vote_cnt, ag_epoch_info_t const * epoch_info );

static inline ag_cert_t
cert_build_final( ag_vote_final_t const * votes,
                  ulong                   vote_cnt,
                  ag_epoch_info_t const * epoch_info ) {
  ag_validator_info_t const * validators = ag_epoch_info_validators( epoch_info );
  FD_TEST( vote_cnt>0UL );
  ulong slot  = votes[0].slot;
  ulong stake = 0UL;
  for( ulong i=0UL; i<vote_cnt; i++ ) {
    FD_TEST( votes[i].slot==slot );
    stake += validators[ votes[i].rank ].stake;
  }
  ag_cert_final_t cert;
  cert.slot = slot; cert.stake = stake;
  memset( &cert.agg, 0, sizeof(ag_bls_agg_t) );
  for( ulong i=0UL; i<vote_cnt; i++ ) agg_add( &cert.agg, votes[i].rank, &votes[i].sig );
  return (ag_cert_t){ .kind = AG_CERT_KIND_FINAL, .final = cert };
}

static inline ag_cert_t
cert_build_fast_final( ag_vote_notar_t const * votes,
                       ulong                   vote_cnt,
                       ag_epoch_info_t const * epoch_info ) {
  ag_cert_notar_t      notar = cert_build_notar( votes, vote_cnt, epoch_info ).notar;
  ag_cert_fast_final_t cert;
  cert.slot = notar.slot; cert.stake = notar.stake; cert.agg = notar.agg;
  memcpy( cert.block_hash, notar.block_hash, sizeof(ag_block_hash_t) );
  return (ag_cert_t){ .kind = AG_CERT_KIND_FAST_FINAL, .fast_final = cert };
}

static inline ag_cert_t
cert_build_notar( ag_vote_notar_t const * votes,
                  ulong                   vote_cnt,
                  ag_epoch_info_t const * epoch_info ) {
  ag_validator_info_t const * validators = ag_epoch_info_validators( epoch_info );
  FD_TEST( vote_cnt>0UL );
  ulong           slot  = votes[0].slot;
  ulong           stake = 0UL;
  ag_block_hash_t block_hash;
  memcpy( block_hash, votes[0].block_hash, sizeof(ag_block_hash_t) );
  for( ulong i=0UL; i<vote_cnt; i++ ) {
    FD_TEST( votes[i].slot==slot );
    FD_TEST( !memcmp( votes[i].block_hash, block_hash, sizeof(ag_block_hash_t) ) );
    stake += validators[ votes[i].rank ].stake;
  }
  ag_cert_notar_t cert;
  cert.slot = slot; cert.stake = stake;
  memcpy( cert.block_hash, block_hash, sizeof(ag_block_hash_t) );
  memset( &cert.agg, 0, sizeof(ag_bls_agg_t) );
  for( ulong i=0UL; i<vote_cnt; i++ ) agg_add( &cert.agg, votes[i].rank, &votes[i].sig );
  return (ag_cert_t){ .kind = AG_CERT_KIND_NOTAR, .notar = cert };
}

static inline ag_cert_t
cert_build_notar_fallback( ag_vote_notar_t const *          votes,
                           ulong                            vote_cnt,
                           ag_vote_notar_fallback_t const * fallback_votes,
                           ulong                            fallback_vote_cnt,
                           ag_epoch_info_t const *          epoch_info ) {
  ag_validator_info_t const * validators = ag_epoch_info_validators( epoch_info );
  FD_TEST( vote_cnt>0UL || fallback_vote_cnt>0UL );
  ulong           slot;
  ag_block_hash_t block_hash;
  if( vote_cnt>0UL ) { slot = votes[0].slot;                   memcpy( block_hash, votes[0].block_hash,                   sizeof(ag_block_hash_t) ); }
  else               { slot = fallback_votes[0].slot; memcpy( block_hash, fallback_votes[0].block_hash, sizeof(ag_block_hash_t) ); }

  ulong stake = 0UL;
  for( ulong i=0UL; i<vote_cnt; i++ ) {
    FD_TEST( votes[i].slot==slot );
    FD_TEST( !memcmp( votes[i].block_hash, block_hash, sizeof(ag_block_hash_t) ) );
    stake += validators[ votes[i].rank ].stake;
  }
  ulong stake_fallback = 0UL;
  for( ulong i=0UL; i<fallback_vote_cnt; i++ ) {
    FD_TEST( fallback_votes[i].slot==slot );
    FD_TEST( !memcmp( fallback_votes[i].block_hash, block_hash, sizeof(ag_block_hash_t) ) );
    stake_fallback += validators[ fallback_votes[i].rank ].stake;
  }

  ag_cert_notar_fallback_t cert;
  cert.slot = slot;
  memcpy( cert.block_hash, block_hash, sizeof(ag_block_hash_t) );
  memset( &cert.agg_notar, 0, sizeof(ag_bls_agg_t) );
  for( ulong i=0UL; i<vote_cnt; i++ ) agg_add( &cert.agg_notar, votes[i].rank, &votes[i].sig );
  if( FD_UNLIKELY( agg_is_identity( &cert.agg_notar ) ) ) {
    memset( &cert.agg_notar, 0, sizeof(ag_bls_agg_t) );
    stake = 0UL;
  }
  memset( &cert.agg_notar_fallback, 0, sizeof(ag_bls_agg_t) );
  for( ulong i=0UL; i<fallback_vote_cnt; i++ ) agg_add( &cert.agg_notar_fallback, fallback_votes[i].rank, &fallback_votes[i].sig );
  if( FD_UNLIKELY( agg_is_identity( &cert.agg_notar_fallback ) ) ) {
    memset( &cert.agg_notar_fallback, 0, sizeof(ag_bls_agg_t) );
    stake_fallback = 0UL;
  }
  cert.stake = stake + stake_fallback;
  return (ag_cert_t){ .kind = AG_CERT_KIND_NOTAR_FALLBACK, .notar_fallback = cert };
}

static inline ag_cert_t
cert_build_skip( ag_vote_skip_t const *          votes,
                 ulong                           vote_cnt,
                 ag_vote_skip_fallback_t const * fallback_votes,
                 ulong                           fallback_vote_cnt,
                 ag_epoch_info_t const *         epoch_info ) {
  ag_validator_info_t const * validators = ag_epoch_info_validators( epoch_info );
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

  ag_cert_skip_t cert;
  cert.slot = slot;
  memset( &cert.agg_skip, 0, sizeof(ag_bls_agg_t) );
  for( ulong i=0UL; i<vote_cnt; i++ ) agg_add( &cert.agg_skip, votes[i].rank, &votes[i].sig );
  if( FD_UNLIKELY( agg_is_identity( &cert.agg_skip ) ) ) {
    memset( &cert.agg_skip, 0, sizeof(ag_bls_agg_t) );
    stake = 0UL;
  }
  memset( &cert.agg_skip_fallback, 0, sizeof(ag_bls_agg_t) );
  for( ulong i=0UL; i<fallback_vote_cnt; i++ ) agg_add( &cert.agg_skip_fallback, fallback_votes[i].rank, &fallback_votes[i].sig );
  if( FD_UNLIKELY( agg_is_identity( &cert.agg_skip_fallback ) ) ) {
    memset( &cert.agg_skip_fallback, 0, sizeof(ag_bls_agg_t) );
    stake_fallback = 0UL;
  }
  cert.stake = stake + stake_fallback;
  return (ag_cert_t){ .kind = AG_CERT_KIND_SKIP, .skip = cert };
}

#endif
