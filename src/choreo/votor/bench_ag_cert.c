#include "ag_cert.h"
#include "../../ballet/bls/fd_bls12_381.h"
#include "../../third_party/blst/bindings/blst.h"
#if FD_HAS_AVX512
#include "../../ballet/bls/fd_vroom.h"
#endif

#define SAMPLE_MAX (10001UL)
#define BENCH_DST "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
#define BENCH_DST_SZ (sizeof(BENCH_DST)-1UL)
#define BENCH_GT_SZ (48UL*12UL)

static ag_validator_info_t validators[ AG_BLS_SIGNERS_MAX ];
static ag_epoch_info_t     epoch_info[1];

static long
sample_median( long * samples,
               ulong  sample_cnt ) {
  for( ulong i=1UL; i<sample_cnt; i++ ) {
    long  x = samples[i];
    ulong j = i;
    while( j && samples[j-1UL]>x ) { samples[j] = samples[j-1UL]; j--; }
    samples[j] = x;
  }
  return samples[sample_cnt/2UL];
}

/* Isolate the prepared-line cache working set.  This intentionally uses the
   public individual-key API; absolute time includes key validation, while the
   difference between working sets is the preparation-cache behavior. */
static void
bench_hash_working_set( ulong working_set,
                        ulong sample_cnt ) {
  FD_TEST( working_set && working_set<=AG_BLS_HASH_CACHE_CNT );
  FD_TEST( sample_cnt && sample_cnt<=SAMPLE_MAX );

  uchar ikm[32] = {7U};
  ag_bls_sec_t sk;
  ag_bls_pub_t pub;
  ag_bls_sig_t sig[ AG_BLS_HASH_CACHE_CNT ];
  uchar msg[ AG_BLS_HASH_CACHE_CNT ];
  ag_bls_sec_derive( sk, ikm, sizeof(ikm) );
  ag_bls_sec_to_pub( sk, &pub );
  for( ulong i=0UL; i<working_set; i++ ) {
    msg[i] = (uchar)i;
    ag_bls_sec_sign( sk, sig[i], msg+i, 1UL );
  }

  ag_bls_hash_cache_t cache[1];
  ag_bls_hash_cache_init( cache );
  for( int pass=0; pass<2; pass++ )
    for( ulong i=0UL; i<working_set; i++ )
      FD_TEST( ag_bls_sig_verify_hash_cached( sig[i], &pub, msg+i, 1UL, cache ) );

  static long samples[ SAMPLE_MAX ];
  for( ulong i=0UL; i<sample_cnt; i++ ) {
    ulong j = i % working_set;
    long then = fd_log_wallclock();
    int ok = ag_bls_sig_verify_hash_cached( sig[j], &pub, msg+j, 1UL, cache );
    samples[i] = fd_log_wallclock()-then;
    FD_TEST( ok );
  }
  FD_LOG_NOTICE(( "hash-cache-hit working-set=%lu median=%.3f ms",
                  working_set, (double)sample_median( samples, sample_cnt )/1e6 ));
}

#if FD_HAS_AVX512
static void
bench_breakdown( ag_cert_t const *       cert,
                 ag_epoch_info_t const * epoch,
                 ulong                   sample_cnt ) {
  static long samples[7][ SAMPLE_MAX ];
  uchar msg[ AG_VOTE_PAYLOAD_MAX ];
  ulong msg_sz = ag_vote_payload_bytes_to_sign( msg, AG_VOTE_KIND_FINAL,
                                                 cert->inner.final.slot, NULL, 1U );

  blst_p1_affine pair_p[2];
  fd_memcpy( pair_p, &epoch->pubkey_cache.total, sizeof(blst_p1_affine) );
  pair_p[1] = BLS12_381_NEG_G1;
  blst_p2        hash[1];
  blst_p2_affine pair_q[2];
  int sink = 0;

  for( ulong i=0UL; i<sample_cnt; i++ ) {
    long then = fd_log_wallclock();
    ulong stake = 0UL;
    for( ulong j=0UL; j<epoch->validator_cnt; j++ )
      if( signer_set_test( cert->inner.final.agg_sig.bitmask, epoch->validators[j].id ) )
        stake += epoch->validators[j].stake;
    sink += ag_epoch_info_is_quorum( epoch, stake );
    samples[0][i] = fd_log_wallclock()-then;

    then = fd_log_wallclock();
    blst_hash_to_g2( hash, msg, msg_sz, (uchar const *)BENCH_DST, BENCH_DST_SZ, NULL, 0UL );
    samples[1][i] = fd_log_wallclock()-then;

    then = fd_log_wallclock();
    blst_p2_to_affine( pair_q, hash );
    samples[2][i] = fd_log_wallclock()-then;

    then = fd_log_wallclock();
    sink += blst_p2_deserialize( pair_q+1, cert->inner.final.agg_sig.sig )==BLST_SUCCESS;
    samples[3][i] = fd_log_wallclock()-then;

    then = fd_log_wallclock();
    sink += blst_p2_affine_in_g2( pair_q+1 );
    sink += !blst_p2_affine_is_inf( pair_q+1 );
    samples[4][i] = fd_log_wallclock()-then;

    then = fd_log_wallclock();
    sink += fd_vroom_pairing_finalverify( pair_p, pair_q, 2UL );
    samples[5][i] = fd_log_wallclock()-then;

    then = fd_log_wallclock();
    sink += fd_vroom_pairing_finalverify_checked( pair_p, pair_q, 2UL, 2UL );
    samples[6][i] = fd_log_wallclock()-then;
  }
  FD_COMPILER_FORGET( sink );

  static char const * const label[7] = {
    "threshold scan", "hash-to-G2", "G2 affine normalization",
    "signature deserialize", "BLST standalone subgroup", "VROOM pair product",
    "VROOM pair + subgroup"
  };
  for( ulong stage=0UL; stage<7UL; stage++ )
    FD_LOG_NOTICE(( "breakdown %-27s median=%.3f ms", label[stage],
                    (double)sample_median( samples[stage], sample_cnt )/1e6 ));
}
#endif

/* Exact pre-optimization final-certificate signature path. */

static int
original_pub_validate( uchar const * pk ) {
  if( FD_UNLIKELY( !fd_bls12_381_g1_validate_syscall( pk, 1 ) ) ) return 0;
  blst_p1_affine a[1];
  if( FD_UNLIKELY( blst_p1_deserialize( a, pk )!=BLST_SUCCESS ) ) return 0;
  return !blst_p1_affine_is_inf( a );
}

static int
original_pub_aggregate( uchar *       out,
                        uchar const * pks,
                        ulong         cnt,
                        int           validate_each ) {
  if( FD_UNLIKELY( !cnt ) ) return -1;
  for( ulong i=0UL; i<cnt; i++ ) {
    uchar const * pk = pks+i*AG_BLS_PUB_SZ;
    if( FD_UNLIKELY( validate_each && !original_pub_validate( pk ) ) ) return -1;
    if( !i ) { fd_memcpy( out, pk, AG_BLS_PUB_SZ ); continue; }
    if( FD_UNLIKELY( fd_bls12_381_g1_add_syscall( out, out, pk, 1 ) ) ) return -1;
  }
  return 0;
}

static int
original_final_verify( ag_cert_t const *       cert,
                       ag_epoch_info_t const * epoch,
                       int                     validate_each ) {
  ulong stake = 0UL;
  for( ulong i=0UL; i<epoch->validator_cnt; i++ ) {
    if( signer_set_test( cert->inner.final.agg_sig.bitmask, epoch->validators[i].id ) ) stake += epoch->validators[i].stake;
  }
  if( FD_UNLIKELY( !ag_epoch_info_is_quorum( epoch, stake ) ) ) return 0;

  static FD_TL uchar gathered[ AG_BLS_SIGNERS_MAX*AG_BLS_PUB_SZ ];
  ulong k = 0UL;
  for( ulong i=0UL; i<epoch->validator_cnt; i++ ) {
    if( signer_set_test( cert->inner.final.agg_sig.bitmask, i ) ) {
      fd_memcpy( gathered+k*AG_BLS_PUB_SZ, epoch->validators[i].bls_key, AG_BLS_PUB_SZ );
      k++;
    }
  }
  uchar apk[ AG_BLS_PUB_SZ ];
  if( FD_UNLIKELY( original_pub_aggregate( apk, gathered, k, validate_each ) ) ) return 0;

  uchar msg[ AG_VOTE_PAYLOAD_MAX ];
  ulong msg_sz = ag_vote_payload_bytes_to_sign( msg, AG_VOTE_KIND_FINAL, cert->inner.final.slot, NULL, 1U );
  blst_p2 hash[1];
  blst_p2_affine hash_affine[1];
  uchar hash_bytes[ AG_BLS_SIG_SZ ];
  blst_hash_to_g2( hash, msg, msg_sz, (uchar const *)BENCH_DST, BENCH_DST_SZ, NULL, 0UL );
  blst_p2_to_affine( hash_affine, hash );
  blst_p2_affine_serialize( hash_bytes, hash_affine );

  uchar a[ 2UL*AG_BLS_PUB_SZ ];
  uchar b[ 2UL*AG_BLS_SIG_SZ ];
  fd_memcpy( a, apk, AG_BLS_PUB_SZ );
  blst_p1_affine_serialize( a+AG_BLS_PUB_SZ, &BLS12_381_NEG_G1 );
  fd_memcpy( b,                hash_bytes,                     AG_BLS_SIG_SZ );
  fd_memcpy( b+AG_BLS_SIG_SZ, cert->inner.final.agg_sig.sig, AG_BLS_SIG_SZ );

  uchar r[ BENCH_GT_SZ ];
  uchar identity[ BENCH_GT_SZ ];
  if( FD_UNLIKELY( fd_bls12_381_pairing_syscall( r,        a, b, 2UL, 1 ) ) ) return 0;
  if( FD_UNLIKELY( fd_bls12_381_pairing_syscall( identity, a, b, 0UL, 1 ) ) ) return 0;
  return fd_memeq( r, identity, BENCH_GT_SZ );
}

static void
bench( ulong validator_cnt,
       ulong signer_cnt,
       ulong sample_cnt,
       int   current_only,
       int   warm_only,
       int   breakdown ) {
  FD_TEST( sample_cnt && sample_cnt<=SAMPLE_MAX );
  FD_TEST( validator_cnt && validator_cnt<=AG_BLS_SIGNERS_MAX );
  FD_TEST( signer_cnt<=validator_cnt );
  uchar payload[ AG_VOTE_PAYLOAD_MAX ];
  ulong payload_sz = ag_vote_payload_bytes_to_sign( payload, AG_VOTE_KIND_FINAL, 42UL, NULL, 1U );

  ag_cert_t cert[1];
  fd_memset( cert, 0, sizeof(cert) );
  cert->kind             = AG_CERT_KIND_FINAL;
  cert->inner.final.slot = 42UL;
  ag_bls_agg_zero( &cert->inner.final.agg_sig );

  for( ulong i=0UL; i<validator_cnt; i++ ) {
    uchar ikm[32];
    fd_memset( ikm, 0, sizeof(ikm) );
    FD_STORE( ulong, ikm, i+1UL );

    ag_bls_sec_t sk;
    ag_bls_sec_derive( sk, ikm, sizeof(ikm) );
    ag_bls_sec_to_pub( sk, &validators[i].bls_key );

    validators[i].id    = i;
    validators[i].stake = 1UL;
    if( i<signer_cnt ) {
      ag_bls_sig_t sig;
      ag_bls_sec_sign( sk, sig, payload, payload_sz );
      ag_bls_agg_add( &cert->inner.final.agg_sig, i, sig );
    }
  }
  ag_epoch_info( epoch_info, validators, validator_cnt );
  FD_TEST( ag_epoch_info_is_quorum( epoch_info, signer_cnt ) );

  if( FD_LIKELY( !current_only ) ) {
    FD_TEST( original_final_verify( cert, epoch_info, 1 ) );
    FD_TEST( original_final_verify( cert, epoch_info, 0 ) );
  }
  FD_TEST( ag_cert_verify( cert, epoch_info, 1U ) );
  ag_bls_hash_cache_t hash_cache[1];
  ag_bls_hash_cache_init( hash_cache );
  FD_TEST( ag_cert_verify_hash_cached( cert, epoch_info, 1U, hash_cache ) ); /* prime */

#if FD_HAS_AVX512
  if( FD_UNLIKELY( breakdown ) ) {
    FD_TEST( signer_cnt==validator_cnt );
    bench_breakdown( cert, epoch_info, sample_cnt );
  }
#else
  (void)breakdown;
#endif

  static long original_samples[ SAMPLE_MAX ];
  static long trusted_samples [ SAMPLE_MAX ];
  static long current_samples [ SAMPLE_MAX ];
  static long warm_samples    [ SAMPLE_MAX ];
  for( ulong i=0UL; i<sample_cnt; i++ ) {
    if( FD_LIKELY( !current_only ) ) {
      long then = fd_log_wallclock();
      int  ok   = original_final_verify( cert, epoch_info, 1 );
      original_samples[i] = fd_log_wallclock() - then;
      FD_TEST( ok );

      then = fd_log_wallclock();
      ok   = original_final_verify( cert, epoch_info, 0 );
      trusted_samples[i] = fd_log_wallclock() - then;
      FD_TEST( ok );
    }

    long then;
    int  ok;
    if( FD_LIKELY( !warm_only ) ) {
      then = fd_log_wallclock();
      ok   = ag_cert_verify( cert, epoch_info, 1U );
      current_samples[i] = fd_log_wallclock() - then;
      FD_TEST( ok );
    }

    then = fd_log_wallclock();
    ok   = ag_cert_verify_hash_cached( cert, epoch_info, 1U, hash_cache );
    warm_samples[i] = fd_log_wallclock() - then;
    FD_TEST( ok );
  }
  for( ulong i=1UL; i<sample_cnt; i++ ) {
    long  x;
    ulong j;
    if( FD_LIKELY( !current_only ) ) {
      x = original_samples[i];
      j = i;
      while( j && original_samples[j-1UL]>x ) { original_samples[j] = original_samples[j-1UL]; j--; }
      original_samples[j] = x;

      x = trusted_samples[i];
      j = i;
      while( j && trusted_samples[j-1UL]>x ) { trusted_samples[j] = trusted_samples[j-1UL]; j--; }
      trusted_samples[j] = x;
    }

    if( FD_LIKELY( !warm_only ) ) {
      x = current_samples[i];
      j = i;
      while( j && current_samples[j-1UL]>x ) { current_samples[j] = current_samples[j-1UL]; j--; }
      current_samples[j] = x;
    }

    x = warm_samples[i];
    j = i;
    while( j && warm_samples[j-1UL]>x ) { warm_samples[j] = warm_samples[j-1UL]; j--; }
    warm_samples[j] = x;
  }

  if( FD_LIKELY( !current_only ) ) {
    FD_LOG_NOTICE(( "original ag_cert_verify validators=%lu signers=%lu median=%.3f ms min=%.3f ms max=%.3f ms",
                    validator_cnt,
                    signer_cnt,
                    (double)original_samples[sample_cnt/2UL]/1e6,
                    (double)original_samples[0]/1e6,
                    (double)original_samples[sample_cnt-1UL]/1e6 ));
    FD_LOG_NOTICE(( "trusted-key original   validators=%lu signers=%lu median=%.3f ms min=%.3f ms max=%.3f ms",
                    validator_cnt,
                    signer_cnt,
                    (double)trusted_samples[sample_cnt/2UL]/1e6,
                    (double)trusted_samples[0]/1e6,
                    (double)trusted_samples[sample_cnt-1UL]/1e6 ));
  }
  if( FD_LIKELY( !warm_only ) )
    FD_LOG_NOTICE(( "current cold-hash verify validators=%lu signers=%lu median=%.3f ms min=%.3f ms max=%.3f ms",
                    validator_cnt,
                    signer_cnt,
                    (double)current_samples[sample_cnt/2UL]/1e6,
                    (double)current_samples[0]/1e6,
                    (double)current_samples[sample_cnt-1UL]/1e6 ));
  FD_LOG_NOTICE(( "current warm-hash verify validators=%lu signers=%lu median=%.3f ms min=%.3f ms max=%.3f ms",
                  validator_cnt,
                  signer_cnt,
                  (double)warm_samples[sample_cnt/2UL]/1e6,
                  (double)warm_samples[0]/1e6,
                  (double)warm_samples[sample_cnt-1UL]/1e6 ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  ulong validators = fd_env_strip_cmdline_ulong( &argc, &argv, "--validators", NULL, 0UL );
  ulong signers    = fd_env_strip_cmdline_ulong( &argc, &argv, "--signers",    NULL, 0UL );
  ulong samples    = fd_env_strip_cmdline_ulong( &argc, &argv, "--samples",    NULL, 11UL );
  int current_only = fd_env_strip_cmdline_contains( &argc, &argv, "--current-only" );
  int warm_only    = fd_env_strip_cmdline_contains( &argc, &argv, "--warm-only" );
  int breakdown    = fd_env_strip_cmdline_contains( &argc, &argv, "--breakdown" );
  ulong hash_working_set = fd_env_strip_cmdline_ulong( &argc, &argv, "--hash-working-set", NULL, 0UL );
  current_only |= warm_only;
  if( hash_working_set ) {
    FD_TEST( !validators && !signers && !breakdown );
    bench_hash_working_set( hash_working_set, samples );
  } else if( validators ) bench( validators, signers ? signers : validators, samples, current_only, warm_only, breakdown );
  else {
    FD_TEST( !signers );
    bench( 80UL,   80UL,   samples, current_only, warm_only, breakdown );
    bench( 2000UL, 2000UL, samples, current_only, warm_only, breakdown );
  }
  fd_halt();
  return 0;
}
