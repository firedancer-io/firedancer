#ifndef HEADER_fd_src_choreo_votor_test_ag_cert_builder_h
#define HEADER_fd_src_choreo_votor_test_ag_cert_builder_h

/* Certificates are built incrementally in ag_slot_state.c as votes
   arrive.  These rebuild one from a complete vote list, which tests
   need to get a cert in isolation; they are not part of the ag_cert
   API. */

#include "ag_cert.h"
#include "ag_epoch_info.h"
#include "ag_vote.h"

static inline void
bls_key_from_sec( ag_bls_key_t         out,
                  fd_bls_sec_t const * sec ) {
  fd_bls_pub_t pub[1];
  fd_bls_sec_to_pub( sec, pub );
  fd_bls_pub_compress( pub, out );
}

/* epoch_info_build fills epoch_info from an already ranked validator
   list.  Production ranks in the votor tile (rank_voters). */

static inline void
epoch_info_build( ag_epoch_info_t *           epoch_info,
                  ag_validator_info_t const * validators,
                  ulong                       validator_cnt ) {
  epoch_info->total_stake = 0UL;
  for( ulong i=0UL; i<validator_cnt; i++ ) {
    FD_TEST( validators[i].id==i );
    epoch_info->validators[i] = validators[i];
    FD_TEST( !fd_bls_pub_de( &epoch_info->pubkeys[i], validators[i].bls_key, sizeof(ag_bls_key_t) ) );
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
  cert.slot = slot; cert.stake = stake; cert.shred_version = votes[0].shred_version;
  memset( &cert.agg, 0, sizeof(fd_bls_agg_t) );
  for( ulong i=0UL; i<vote_cnt; i++ ) agg_add( &cert.agg, votes[i].rank, &votes[i].sig );
  return (ag_cert_t){ .kind = AG_CERT_KIND_FINAL, .final = cert };
}

static inline ag_cert_t
cert_build_fast_final( ag_vote_notar_t const * votes,
                       ulong                   vote_cnt,
                       ag_epoch_info_t const * epoch_info ) {
  ag_cert_notar_t      notar = cert_build_notar( votes, vote_cnt, epoch_info ).notar;
  ag_cert_fast_final_t cert;
  cert.slot = notar.slot; cert.stake = notar.stake; cert.agg = notar.agg; cert.shred_version = notar.shred_version;
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
  cert.slot = slot; cert.stake = stake; cert.shred_version = votes[0].shred_version;
  memcpy( cert.block_hash, block_hash, sizeof(ag_block_hash_t) );
  memset( &cert.agg, 0, sizeof(fd_bls_agg_t) );
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
  cert.slot = slot; cert.shred_version = vote_cnt>0UL ? votes[0].shred_version : fallback_votes[0].shred_version;
  memcpy( cert.block_hash, block_hash, sizeof(ag_block_hash_t) );
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
  return (ag_cert_t){ .kind = AG_CERT_KIND_SKIP, .skip = cert };
}

#endif
