/* bench_fd_votor_pool: fd_votor_pool_add_vote cost per vote below
   quorum (no aggregate verify) and at quorum (verify, cert), and the
   receive cost of a duplicate cert. */
#define _GNU_SOURCE
#include "fd_votor_pool.c"
#include "test_fd_cert_builder.h"
#include "fd_cert_serde.h"
#include <stdlib.h>
#include <sys/mman.h>

#define NV        (200UL)
#define SLOT_MAX  (64UL)
#define BURST     (9UL)
#define SV        ((ushort)1)

static fd_bls_sec_t        sk  [ NV ];
static fd_validator_info_t info[ NV ];
static fd_epoch_info_t     epoch_info[1];

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  for( ulong i=0UL; i<NV; i++ ) {
    memset( &sk[i], 0, FD_BLS_SEC_SZ ); ((uchar *)&sk[i])[ 16 ] = (uchar)(i+1UL); ((uchar *)&sk[i])[ 17 ] = (uchar)((i+1UL)>>8);
    memset( &info[i], 0, sizeof(fd_validator_info_t) ); info[i].id = i; info[i].stake = 1UL;
    bls_key_from_sec( info[i].bls_key, &sk[i] );
  }
  epoch_info_build( epoch_info, info, NV );
  int fd = memfd_create( "spill", 0 ); FD_TEST( fd>=0 );
  ulong sig_pg_max = SLOT_MAX*FD_VOTOR_VOTES_PER_SLOT_MAX*fd_bls_set_word_cnt;
  ulong fp = fd_votor_pool_footprint( SLOT_MAX, BURST, sig_pg_max );
  void * mem = aligned_alloc( fd_votor_pool_align(), fd_ulong_align_up( fp, fd_votor_pool_align() ) ); FD_TEST( mem );
  fd_votor_pool_t * pool = fd_votor_pool_join( fd_votor_pool_new( mem, SLOT_MAX, BURST, sig_pg_max, 42UL, fd ) );
  fd_votor_pool_from_genesis( pool, &(fd_block_id_t){ .slot = 0UL } );
  fd_votor_pool_advance_epoch( pool, epoch_info, USHORT_MAX, 0UL );

  ulong const slots = 40UL;
  ulong const below = (NV*3UL)/5UL - 1UL; /* one short of quorum */
  static fd_vote_t votes[ 40 ][ NV ];
  fd_block_hash_t hash[ 40 ];
  for( ulong s=0UL; s<slots; s++ ) {
    memset( &hash[s], 0, sizeof(fd_block_hash_t) ); hash[s].uc[0] = (uchar)(s+1UL); hash[s].uc[31] = 0x5a;
    for( ulong v=0UL; v<NV; v++ ) votes[s][v] = fd_vote_construct_notar( sec_sign_fn, &sk[v], test_bls_public_key, s+1UL, &hash[s], (ushort)v, SV );
  }
  fd_bls_set_t bad[ fd_bls_set_word_cnt ]; uchar q;

  long t0 = fd_log_wallclock();
  for( ulong s=0UL; s<slots; s++ ) for( ulong v=0UL; v<below; v++ ) FD_TEST( fd_votor_pool_add_vote( pool, &votes[s][v], 0, bad, &q )==FD_VOTOR_POOL_SUCCESS );
  long t1 = fd_log_wallclock();
  for( ulong s=0UL; s<slots; s++ ) FD_TEST( fd_votor_pool_add_vote( pool, &votes[s][below], 0, bad, &q )==FD_VOTOR_POOL_SUCCESS && fd_bls_set_is_null( bad ) );
  long t2 = fd_log_wallclock();
  ulong n_below = slots*below;
  FD_LOG_NOTICE(( "add_vote below quorum: %lu votes %.2f us/vote", n_below, (double)(t1-t0)/1e3/(double)n_below ));
  FD_LOG_NOTICE(( "add_vote reaching quorum (agg verify, cert): %lu votes %.2f us/vote", slots, (double)(t2-t1)/1e3/(double)slots ));
  FD_LOG_NOTICE(( "total %.2f us/vote over %lu votes", (double)(t2-t0)/1e3/(double)(n_below+slots), n_below+slots ));

  /* raw primitive costs */
  fd_bls_sig_t sig = votes[0][0].notar.sig;
  ulong const iter = 2000UL; int acc = 0;
  long a0 = fd_log_wallclock(); for( ulong i=0UL; i<iter; i++ ) { acc += fd_bls_sig_validate( &sig ); FD_COMPILER_FORGET( acc ); } long a1 = fd_log_wallclock();
  FD_TEST( acc==(int)iter );
  FD_LOG_NOTICE(( "fd_bls_sig_validate %.2f us", (double)(a1-a0)/1e3/(double)iter ));
  uchar sig_buf[ FD_BLS_SIG_SZ ]; fd_bls_sig_ser( &sig, sig_buf ); fd_bls_sig_t sig_de;
  a0 = fd_log_wallclock(); for( ulong i=0UL; i<iter; i++ ) { acc += !fd_bls_sig_de_unchecked( &sig_de, sig_buf ); FD_COMPILER_FORGET( acc ); } a1 = fd_log_wallclock();
  FD_LOG_NOTICE(( "fd_bls_sig_de_unchecked %.2f us", (double)(a1-a0)/1e3/(double)iter ));

  /* duplicate cert receive: full decode then add_cert, vs the header
     parse and dup query (mainnet sized bitmap of 1300 ranks). */
  uchar dup_buf[ 2 ][ FD_CERT_SER_MAX ]; ulong dup_sz[ 2 ];
  for( ulong k=0UL; k<2UL; k++ ) {
    fd_cert_t c = cert_build_notar( &votes[0][0].notar, 1UL, epoch_info ); /* sig over slot 1 */
    fd_bls_agg_t * agg = &c.notar.agg;
    if( k ) { /* skip cert, base3 bitmap */
      fd_cert_t sc = { .kind = FD_CERT_KIND_SKIP, .skip = { .slot = 1UL, .agg_skip = *agg, .shred_version = SV } };
      fd_bls_set_null( sc.skip.agg_skip_fallback.set );
      c = sc; agg = &c.skip.agg_skip;
    }
    for( ulong i=0UL; i<1300UL; i++ ) if( i%3UL ) fd_bls_set_insert( agg->set, i );
    if( k ) for( ulong i=0UL; i<1300UL; i+=3UL ) fd_bls_set_insert( c.skip.agg_skip_fallback.set, i );
    fd_bls_set_t verified_bad[ fd_bls_set_word_cnt ];
    FD_TEST( fd_votor_pool_add_cert( pool, &c, 1, verified_bad )==( k ? FD_VOTOR_POOL_SUCCESS : FD_VOTOR_POOL_ERR_DUPLICATE ) ); /* slot 1 has a notar cert from the votes */
    dup_sz[ k ] = fd_cert_ser( &c, dup_buf[ k ] );
  }
  static fd_cert_t dc;
  for( ulong k=0UL; k<2UL; k++ ) {
    ulong const dup_iter = 200000UL;
    ulong bc;
    long d0 = fd_log_wallclock();
    for( ulong i=0UL; i<dup_iter; i++ ) {
      FD_TEST( !fd_cert_de( &dc, &bc, dup_buf[ k ], dup_sz[ k ] ) );
      FD_TEST( fd_votor_pool_add_cert( pool, &dc, 0, bad )==FD_VOTOR_POOL_ERR_DUPLICATE );
    }
    long d1 = fd_log_wallclock();
    for( ulong i=0UL; i<dup_iter; i++ ) {
      fd_cert_serde_t hdr;
      FD_TEST( !fd_cert_de_peek( &hdr, &bc, dup_buf[ k ], dup_sz[ k ] ) );
      FD_TEST( fd_votor_pool_cert_is_dup( pool, (uint)hdr.tag-FD_CERT_SERDE_TAG_FINAL, hdr.slot, (fd_block_hash_t const *)hdr.block_id ) );
    }
    long d2 = fd_log_wallclock();
    for( ulong i=0UL; i<dup_iter; i++ ) { /* plus the bitmap decode the tile does for a notar duplicate event */
      fd_cert_serde_t hdr;
      FD_TEST( !fd_cert_de_peek( &hdr, &bc, dup_buf[ k ], dup_sz[ k ] ) );
      FD_TEST( fd_votor_pool_cert_is_dup( pool, (uint)hdr.tag-FD_CERT_SERDE_TAG_FINAL, hdr.slot, (fd_block_hash_t const *)hdr.block_id ) );
      FD_TEST( !fd_bls_agg_pair_de( &dc.skip.agg_skip, &dc.skip.agg_skip_fallback, &bc, hdr.bitmap, hdr.bitmap_sz ) );
    }
    long d3 = fd_log_wallclock();
    FD_LOG_NOTICE(( "duplicate %s cert: fd_cert_de+add_cert %.3f us, fd_cert_de_peek+cert_is_dup %.3f us, +bitmap decode %.3f us",
                    k ? "skip" : "notar", (double)(d1-d0)/1e3/(double)dup_iter, (double)(d2-d1)/1e3/(double)dup_iter, (double)(d3-d2)/1e3/(double)dup_iter ));
  }

  fd_halt();
  return 0;
}
