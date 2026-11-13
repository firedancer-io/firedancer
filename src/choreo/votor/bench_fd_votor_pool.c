/* bench_fd_votor_pool: fd_votor_pool_add_vote cost per vote below
   quorum (no aggregate verify) and at quorum (verify, cert). */
#define _GNU_SOURCE
#include "fd_votor_pool.c"
#include "test_fd_cert_builder.h"
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
  fd_halt();
  return 0;
}
