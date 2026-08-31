#include "ag_cert_serde.h"

#include "../../third_party/blst/bindings/blst.h"

#define TEST_SHRED_VERSION ((ushort)514)
#include <stdlib.h>

#define MAXV 128UL

static ag_bls_sec_t     g_sk  [ MAXV ];
static ag_validator_info_t g_info[ MAXV ];

static void
create_signers( ulong n ) {
  FD_TEST( n<=MAXV );
  for( ulong i=0UL; i<n; i++ ) {
    fd_memset( g_sk[i], 0, AG_BLS_SEC_SZ );
    g_sk[i][0] = (uchar)( i+1UL );
    memset( &g_info[i], 0, sizeof(ag_validator_info_t) );
    g_info[i].id    = i;
    g_info[i].stake = 1UL;
    ag_bls_sec_to_pub( g_sk[i], g_info[i].bls_key );
  }
}

static ag_epoch_info_t *
make_epoch( ulong   n,
            void ** out_mem ) {
  ag_epoch_info_t * epoch_info = aligned_alloc( alignof(ag_epoch_info_t), sizeof(ag_epoch_info_t) );
  FD_TEST( epoch_info );
  *out_mem = epoch_info;
  ag_epoch_info( epoch_info, g_info, n );
  return epoch_info;
}

static void
mk_notar( ag_vote_notar_t *           o,
          ulong                 slot,
          ag_block_hash_t const h,
          ulong                 lo,
          ulong                 n ) {
  for( ulong i=0UL; i<n; i++ ) o[i] = ag_vote_construct_notar( slot, h, g_sk[lo+i], (ushort)(lo+i), TEST_SHRED_VERSION ).notar;
}
static void
mk_nf( ag_vote_notar_fallback_t *           o,
       ulong                 slot,
       ag_block_hash_t const h,
       ulong                 lo,
       ulong                 n ) {
  for( ulong i=0UL; i<n; i++ ) o[i] = ag_vote_construct_notar_fallback( slot, h, g_sk[lo+i], (ushort)(lo+i), TEST_SHRED_VERSION ).notar_fallback;
}
static void
mk_skip( ag_vote_skip_t * o,
         ulong       slot,
         ulong       lo,
         ulong       n ) {
  for( ulong i=0UL; i<n; i++ ) o[i] = ag_vote_construct_skip( slot, g_sk[lo+i], (ushort)(lo+i), TEST_SHRED_VERSION ).skip;
}
static void
mk_sf( ag_vote_skip_fallback_t * o,
       ulong       slot,
       ulong       lo,
       ulong       n ) {
  for( ulong i=0UL; i<n; i++ ) o[i] = ag_vote_construct_skip_fallback( slot, g_sk[lo+i], (ushort)(lo+i), TEST_SHRED_VERSION ).skip_fallback;
}
static void
mk_final( ag_vote_final_t * o,
          ulong       slot,
          ulong       lo,
          ulong       n ) {
  for( ulong i=0UL; i<n; i++ ) o[i] = ag_vote_construct_final( slot, g_sk[lo+i], (ushort)(lo+i), TEST_SHRED_VERSION ).final;
}

static ulong
cert_stake( ag_cert_t const * c ) {
  switch( c->kind ) {
  case AG_CERT_KIND_NOTAR:          return c->notar.stake;
  case AG_CERT_KIND_FAST_FINAL:     return c->fast_final.stake;
  case AG_CERT_KIND_FINAL:          return c->final.stake;
  case AG_CERT_KIND_NOTAR_FALLBACK: return c->notar_fallback.stake;
  default:                          return c->skip.stake;
  }
}

static int
cert_is_signer( ag_cert_t const * c,
                ulong             v ) {
  switch( c->kind ) {
  case AG_CERT_KIND_NOTAR:      return ag_bls_agg_is_signer( &c->notar.agg_sig,      v );
  case AG_CERT_KIND_FAST_FINAL: return ag_bls_agg_is_signer( &c->fast_final.agg_sig, v );
  case AG_CERT_KIND_FINAL:      return ag_bls_agg_is_signer( &c->final.agg_sig,      v );
  case AG_CERT_KIND_NOTAR_FALLBACK: {
    ag_cert_notar_fallback_t const * n = &c->notar_fallback;
    return ag_bls_agg_is_signer( &n->agg_sig_notar, v ) || ag_bls_agg_is_signer( &n->agg_sig_notar_fallback, v );
  }
  default: {
    ag_cert_skip_t const * s = &c->skip;
    return ag_bls_agg_is_signer( &s->agg_sig_skip, v ) || ag_bls_agg_is_signer( &s->agg_sig_skip_fallback, v );
  }
  }
}

static int
cert_verify( ag_cert_t const *       c,
             ag_epoch_info_t const * epoch_info ) {
  return ag_cert_verify( c, epoch_info, TEST_SHRED_VERSION );
}

static void
check_full_cert( ag_cert_t const * c,
                 ulong             n ) {
  void *            mem = NULL;
  ag_epoch_info_t * epoch_info = make_epoch( n, &mem );
  FD_TEST( cert_verify( c, epoch_info ) );
  free( mem );
  FD_TEST( cert_stake( c )==n );
  for( ulong i=0UL; i<n; i++ ) FD_TEST( cert_is_signer( c, g_info[i].id ) );
}

/* src/consensus/cert.rs::create */

static void
test_create( void ) {
  ulong n = 100UL;
  create_signers( n );
  void * em; ag_epoch_info_t * e = make_epoch( n, &em );
  ag_block_hash_t h; memset( h, 0x42, sizeof(ag_block_hash_t) );

  ag_vote_notar_t nv[ 100 ];
  ag_vote_notar_fallback_t fv[ 100 ];
  ag_vote_skip_t sv[ 100 ];
  ag_vote_final_t ev[ 100 ];
  ag_cert_t c;

  mk_notar( nv, 0UL, h, 0UL, n );
    c = ag_cert_construct_notar( nv, n, e );
  check_full_cert( &c, n );
  FD_TEST( ag_cert_block_hash( &c ) && !memcmp( ag_cert_block_hash(&c), h, sizeof(ag_block_hash_t) ) );

  mk_nf( fv, 0UL, h, 0UL, n );
    c = ag_cert_construct_notar_fallback( NULL, 0UL, fv, n, e );
  check_full_cert( &c, n );

  mk_skip( sv, 0UL, 0UL, n );
    c = ag_cert_construct_skip( sv, n, NULL, 0UL, e );
  check_full_cert( &c, n );
  FD_TEST( ag_cert_block_hash( &c )==NULL );

  mk_notar( nv, 0UL, h, 0UL, n );
    c = ag_cert_construct_fast_final( nv, n, e );
  check_full_cert( &c, n );

  mk_final( ev, 0UL, 0UL, n );
    c = ag_cert_construct_final( ev, n, e );
  check_full_cert( &c, n );
  FD_TEST( ag_cert_block_hash( &c )==NULL );

  free( em );
}

/* src/consensus/cert.rs::mixed_notar_fallback, ::mixed_skip */

static void
test_mixed( void ) {
  create_signers( 2UL );
  void * em; ag_epoch_info_t * e = make_epoch( 2UL, &em );
  ag_block_hash_t h; memset( h, 0x42, sizeof(ag_block_hash_t) );

  ag_vote_notar_t nv[1]; mk_notar( nv, 0UL, h, 0UL, 1UL );
  ag_vote_notar_fallback_t fv[1]; mk_nf   ( fv, 0UL, h, 1UL, 1UL );
  ag_cert_t c = ag_cert_construct_notar_fallback( nv, 1UL, fv, 1UL, e );
  check_full_cert( &c, 2UL );

  ag_vote_skip_t sv[1]; mk_skip( sv, 0UL, 0UL, 1UL );
  ag_vote_skip_fallback_t fv2[1]; mk_sf ( fv2, 0UL, 1UL, 1UL );
    c = ag_cert_construct_skip( sv, 1UL, fv2, 1UL, e );
  check_full_cert( &c, 2UL );

  free( em );
}

/* src/consensus/cert.rs::{notar,notar_fallback,skip,fast_final,final}_failure_cases

   The reference's try_new rejects a vote set that disagrees on slot or block
   hash.  There is no try_new here: a cert is either ours, and construct
   FD_TESTs that agreement because disagreeing votes are a bug rather than an
   input, or it is the network's, and arrives as (slot, hash, aggregate) with
   no votes to disagree in the first place.  So the same defect is caught one
   step later -- an aggregate signed over a different slot or block hash than
   the cert records fails verify.  Stake is untouched by the tampering, so
   check_threshold still passes and only check_sig can be rejecting. */

static void
test_failure_cases( void ) {
  ulong n = 11UL;
  create_signers( n );
  void * em; ag_epoch_info_t * e = make_epoch( n, &em );
  ag_block_hash_t h;     memset( h,     0x42, sizeof(ag_block_hash_t) );
  ag_block_hash_t other; memset( other, 0x43, sizeof(ag_block_hash_t) );

  ulong const signers = 9UL; /* clears every kind's threshold, fast-final included */
  ulong const slot    = 1UL;

  ag_vote_notar_t nv [ 11 ];
  ag_vote_notar_fallback_t fv [ 11 ];
  ag_vote_skip_t sv [ 11 ];
  ag_vote_skip_fallback_t sfv[ 11 ];
  ag_vote_final_t ev [ 11 ];
  ag_cert_t c, bad;

  /* notar: slot mismatch, then block hash mismatch */
  mk_notar( nv, slot, h, 0UL, signers );
  c = ag_cert_construct_notar( nv, signers, e );
  FD_TEST( cert_verify( &c, e ) );
  bad = c; bad.notar.slot = slot+1UL;   FD_TEST( !cert_verify( &bad, e ) );
  bad = c; memcpy( bad.notar.block_hash, other, sizeof(ag_block_hash_t) ); FD_TEST( !cert_verify( &bad, e ) );

  /* notar-fallback: slot mismatch, then block hash mismatch */
  mk_notar( nv, slot, h, 0UL,      5UL );
  mk_nf   ( fv, slot, h, 5UL,      4UL );
    c = ag_cert_construct_notar_fallback( nv, 5UL, fv, 4UL, e );
  FD_TEST( cert_verify( &c, e ) );
  bad = c; bad.notar_fallback.slot = slot+1UL;   FD_TEST( !cert_verify( &bad, e ) );
  bad = c; memcpy( bad.notar_fallback.block_hash, other, sizeof(ag_block_hash_t) ); FD_TEST( !cert_verify( &bad, e ) );

  /* skip: slot mismatch (skip certs carry no block hash) */
  mk_skip( sv,  slot, 0UL, 5UL );
  mk_sf  ( sfv, slot, 5UL, 4UL );
    c = ag_cert_construct_skip( sv, 5UL, sfv, 4UL, e );
  FD_TEST( cert_verify( &c, e ) );
  bad = c; bad.skip.slot = slot+1UL; FD_TEST( !cert_verify( &bad, e ) );

  /* fast-final: slot mismatch, then block hash mismatch */
  mk_notar( nv, slot, h, 0UL, signers );
  c = ag_cert_construct_fast_final( nv, signers, e );
  FD_TEST( cert_verify( &c, e ) );
  bad = c; bad.fast_final.slot = slot+1UL;   FD_TEST( !cert_verify( &bad, e ) );
  bad = c; memcpy( bad.fast_final.block_hash, other, sizeof(ag_block_hash_t) ); FD_TEST( !cert_verify( &bad, e ) );

  /* final: slot mismatch (final certs carry no block hash) */
  mk_final( ev, slot, 0UL, signers );
  c = ag_cert_construct_final( ev, signers, e );
  FD_TEST( cert_verify( &c, e ) );
  bad = c; bad.final.slot = slot+1UL; FD_TEST( !cert_verify( &bad, e ) );

  free( em );
}

/* src/consensus/cert.rs::{notar,notar_fallback,skip,final,fast_final}_stake_threshold
   src/consensus/validated_cert.rs::valid_cert, ::threshold_not_met */

static void
test_thresholds( void ) {
  ulong n = 11UL;
  create_signers( n );
  void * em; ag_epoch_info_t * e = make_epoch( n, &em );
  ag_block_hash_t h; memset( h, 0x42, sizeof(ag_block_hash_t) );

  ag_vote_notar_t nv[ 11 ];
  ag_vote_notar_fallback_t fv[ 11 ];
  ag_vote_skip_t sv[ 11 ];
  ag_vote_final_t ev[ 11 ];
  ag_cert_t c;

  mk_notar( nv, 1UL, h, 0UL, 7UL );
  c = ag_cert_construct_notar( nv, 7UL, e );
  FD_TEST(  cert_verify( &c, e ) );
  mk_notar( nv, 1UL, h, 0UL, 6UL );
  c = ag_cert_construct_notar( nv, 6UL, e );
  FD_TEST( !cert_verify( &c, e ) );

  mk_notar( nv, 1UL, h, 0UL, 4UL );
  mk_nf   ( fv, 1UL, h, 4UL, 3UL );
    c = ag_cert_construct_notar_fallback( nv, 4UL, fv, 3UL, e );
  FD_TEST(  cert_verify( &c, e ) );
  mk_notar( nv, 1UL, h, 0UL, 3UL );
  mk_nf   ( fv, 1UL, h, 3UL, 3UL );
  c = ag_cert_construct_notar_fallback( nv, 3UL, fv, 3UL, e );
  FD_TEST( !cert_verify( &c, e ) );

  mk_skip( sv, 1UL, 0UL, 7UL );
  c = ag_cert_construct_skip( sv, 7UL, NULL, 0UL, e );
  FD_TEST(  cert_verify( &c, e ) );
  mk_skip( sv, 1UL, 0UL, 6UL );
  c = ag_cert_construct_skip( sv, 6UL, NULL, 0UL, e );
  FD_TEST( !cert_verify( &c, e ) );

  mk_final( ev, 1UL, 0UL, 7UL );
  c = ag_cert_construct_final( ev, 7UL, e );
  FD_TEST(  cert_verify( &c, e ) );
  mk_final( ev, 1UL, 0UL, 6UL );
  c = ag_cert_construct_final( ev, 6UL, e );
  FD_TEST( !cert_verify( &c, e ) );

  mk_notar( nv, 1UL, h, 0UL, 9UL );
  c = ag_cert_construct_fast_final( nv, 9UL, e );
  FD_TEST(  cert_verify( &c, e ) );
  mk_notar( nv, 1UL, h, 0UL, 8UL );
  c = ag_cert_construct_fast_final( nv, 8UL, e );
  FD_TEST( !cert_verify( &c, e ) );

  free( em );
}

/* src/consensus/cert.rs::{notar,notar_fallback,skip,final,fast_final}_sig_validity
   src/consensus/validated_cert.rs::invalid_signature

   Validator 0 signs with validator 1's key while still claiming rank 0, so
   the aggregate is built over a signature that its recorded rank's pubkey
   cannot verify.  Nine signers either way, so the threshold is met in both
   halves and only check_sig separates them. */

static void
test_sig_validity( void ) {
  ulong n = 11UL;
  create_signers( n );
  void * em; ag_epoch_info_t * e = make_epoch( n, &em );
  ag_block_hash_t h; memset( h, 0x42, sizeof(ag_block_hash_t) );

  ulong const slot = 1UL;

  ag_vote_notar_t nv [ 11 ];
  ag_vote_notar_fallback_t fv [ 11 ];
  ag_vote_skip_t sv [ 11 ];
  ag_vote_final_t ev [ 11 ];
  ag_cert_t c;

  /* notar */
  mk_notar( nv, slot, h, 0UL, 9UL );
  c = ag_cert_construct_notar( nv, 9UL, e );
  FD_TEST( cert_verify( &c, e ) );
  nv[0] = ag_vote_construct_notar( slot, h, g_sk[1], 0, TEST_SHRED_VERSION ).notar; /* wrong key for rank 0 */
  c = ag_cert_construct_notar( nv, 9UL, e );
  FD_TEST( !cert_verify( &c, e ) );

  /* notar-fallback */
  mk_notar( nv, slot, h, 0UL, 5UL );
  mk_nf   ( fv, slot, h, 5UL, 4UL );
    c = ag_cert_construct_notar_fallback( nv, 5UL, fv, 4UL, e );
  FD_TEST( cert_verify( &c, e ) );
  nv[0] = ag_vote_construct_notar( slot, h, g_sk[1], 0, TEST_SHRED_VERSION ).notar;
  c = ag_cert_construct_notar_fallback( nv, 5UL, fv, 4UL, e );
  FD_TEST( !cert_verify( &c, e ) );

  /* skip */
  mk_skip( sv, slot, 0UL, 9UL );
  c = ag_cert_construct_skip( sv, 9UL, NULL, 0UL, e );
  FD_TEST( cert_verify( &c, e ) );
  sv[0] = ag_vote_construct_skip( slot, g_sk[1], 0, TEST_SHRED_VERSION ).skip;
  c = ag_cert_construct_skip( sv, 9UL, NULL, 0UL, e );
  FD_TEST( !cert_verify( &c, e ) );

  /* final */
  mk_final( ev, slot, 0UL, 9UL );
  c = ag_cert_construct_final( ev, 9UL, e );
  FD_TEST( cert_verify( &c, e ) );
  ev[0] = ag_vote_construct_final( slot, g_sk[1], 0, TEST_SHRED_VERSION ).final;
  c = ag_cert_construct_final( ev, 9UL, e );
  FD_TEST( !cert_verify( &c, e ) );

  /* fast-final */
  mk_notar( nv, slot, h, 0UL, 9UL );
  c = ag_cert_construct_fast_final( nv, 9UL, e );
  FD_TEST( cert_verify( &c, e ) );
  nv[0] = ag_vote_construct_notar( slot, h, g_sk[1], 0, TEST_SHRED_VERSION ).notar;
  c = ag_cert_construct_fast_final( nv, 9UL, e );
  FD_TEST( !cert_verify( &c, e ) );

  free( em );
}

/* agave votor/src/aggregate_accumulator.rs:124-125

   "Individually valid votes can still be chosen such that their signatures
   cancel to the identity within one partition, making any certificate
   containing that partition invalid.  Treat an identity partition as absent
   and do not count its stake."  Ranks 9 and 10 hold negated keys -- proof of
   possession does not prevent that -- so their two fallback signatures over
   the same payload sum to the point at infinity.  The research reference has
   no such check, so there is no test of it to mirror. */

static void
negate_sec( ag_bls_sec_t       out,
            ag_bls_sec_t const in ) {
  blst_scalar s[1];
  blst_fr     f[1];
  blst_scalar_from_lendian( s, in );
  blst_fr_from_scalar( f, s );
  blst_fr_cneg( f, f, 1 );
  blst_scalar_from_fr( s, f );
  memcpy( out, s->b, AG_BLS_SEC_SZ );
}

/* the bitmap version byte of a serialized notar-fallback cert: 0 is base2
   (one partition), 1 is base3 (two).  The bitmap follows the head, whose
   size includes the block hash. */

static uchar
bitmap_version( ag_cert_t const * c ) {
  uchar buf[ AG_CERT_SER_MAX ];
  ag_cert_ser( c, TEST_SHRED_VERSION, buf );
  return buf[ sizeof(ag_cert_serde_t) ];
}

static void
test_identity_partition( void ) {
  ulong n = 11UL;
  create_signers( n );
  negate_sec( g_sk[10], g_sk[9] );
  ag_bls_sec_to_pub( g_sk[10], g_info[10].bls_key );
  void * em; ag_epoch_info_t * e = make_epoch( n, &em );
  ag_block_hash_t h; memset( h, 0x42, sizeof(ag_block_hash_t) );

  ag_vote_notar_t nv [ 11 ];
  ag_vote_notar_fallback_t fv [ 11 ];
  ag_vote_skip_t sv [ 11 ];
  ag_vote_skip_fallback_t sfv[ 11 ];
  ag_cert_t c;

  /* control: ranks 8 and 9 do not cancel, so both partitions survive */
  mk_notar( nv, 1UL, h, 0UL, 7UL );
  mk_nf   ( fv, 1UL, h, 8UL, 2UL );
  c = ag_cert_construct_notar_fallback( nv, 7UL, fv, 2UL, e );
  FD_TEST( cert_stake( &c )==9UL );
  FD_TEST( cert_is_signer( &c, 8UL ) && cert_is_signer( &c, 9UL ) );
  FD_TEST( bitmap_version( &c )==1 );
  FD_TEST( cert_verify( &c, e ) );

  /* ranks 9 and 10 cancel: the fallback partition is absent, its stake is not
     counted, and the cert degrades to the single partition form */
  mk_nf( fv, 1UL, h, 9UL, 2UL );
  c = ag_cert_construct_notar_fallback( nv, 7UL, fv, 2UL, e );
  FD_TEST( ag_bls_agg_signer_cnt( &c.notar_fallback.agg_sig_notar_fallback )==0UL );
  FD_TEST( !cert_is_signer( &c, 9UL ) && !cert_is_signer( &c, 10UL ) );
  FD_TEST( cert_stake( &c )==7UL );
  FD_TEST( bitmap_version( &c )==0 );
  FD_TEST( cert_verify( &c, e ) ); /* the 7 surviving notar votes still clear 60% */

  /* same in a skip cert's fallback partition */
  mk_skip( sv,  1UL, 0UL, 7UL );
  mk_sf  ( sfv, 1UL, 9UL, 2UL );
    c = ag_cert_construct_skip( sv, 7UL, sfv, 2UL, e );
  FD_TEST( ag_bls_agg_signer_cnt( &c.skip.agg_sig_skip_fallback )==0UL );
  FD_TEST( !cert_is_signer( &c, 9UL ) && !cert_is_signer( &c, 10UL ) );
  FD_TEST( cert_stake( &c )==7UL );
  FD_TEST( cert_verify( &c, e ) );

  /* without the dropped partition the remaining stake can fall short, which is
     what stops ag_slot_state.c from emitting the cert at all */
  mk_notar( nv, 1UL, h, 0UL, 6UL );
    c = ag_cert_construct_notar_fallback( nv, 6UL, fv, 2UL, e );
  FD_TEST( cert_stake( &c )==6UL );
  FD_TEST( !cert_verify( &c, e ) );

  free( em );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_create();
  test_mixed();
  test_failure_cases();
  test_thresholds();
  test_sig_validity();
  test_identity_partition();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
