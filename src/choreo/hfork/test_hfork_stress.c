#include "fd_hfork.h"
#include <stdlib.h>

/* Stress hfork at real tower-tile params: per_vtr_max=128 vtr_max=2000.
   max = pow2_up(128*pow2_up(2000)) = 2^18 = 262,144.
   Drive vte/bhm/blk pools to their worst-case honest+adversarial fill:
   2000 voters x 128 votes each = 256,000 vtes, each for a UNIQUE
   (block_id, bank_hash) pair so bhm and blk pools fill equally.
   Exercises indices > 2^16 and near pool capacity, then evicts via
   quota wraparound and update_voters teardown. */

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong per_vtr_max = 128UL;
  ulong vtr_max     = 2000UL;

  ulong footprint = fd_hfork_footprint( per_vtr_max, vtr_max );
  FD_LOG_NOTICE(( "footprint(128,2000) = %lu bytes (%.1f MiB)", footprint, (double)footprint/1048576.0 ));

  void * mem = aligned_alloc( fd_hfork_align(), footprint );
  FD_TEST( mem );

  fd_hfork_t * hfork = fd_hfork_join( fd_hfork_new( mem, per_vtr_max, vtr_max, 42UL ) );
  FD_TEST( hfork );

  ulong vtr_cnt = 2000UL;
  fd_pubkey_t * vote_accs = malloc( vtr_cnt*sizeof(fd_pubkey_t) );
  for( ulong i=0UL; i<vtr_cnt; i++ ) { memset( &vote_accs[i], 0, 32UL ); vote_accs[i].ul[0] = i+1UL; }
  fd_hfork_update_voters( hfork, vote_accs, vtr_cnt );

  ulong total_stake = 2000UL * 100UL;

  /* Fill: every voter votes on per_vtr_max distinct blocks; every
     (voter,block) unique block_id AND unique bank_hash -> 256,000 vte +
     bhm + blk. */
  ulong counter = 0UL;
  for( ulong v=0UL; v<vtr_cnt; v++ ) {
    for( ulong s=0UL; s<per_vtr_max; s++ ) {
      fd_hash_t block_id;  memset( &block_id, 0, 32UL );
      fd_hash_t bank_hash; memset( &bank_hash, 0, 32UL );
      counter++;
      block_id.ul[0]  = counter;  block_id.ul[1]  = counter;
      bank_hash.ul[0] = counter;  bank_hash.ul[1] = counter*2654435761UL;
      int err = fd_hfork_count_vote( hfork, &vote_accs[v], &block_id, &bank_hash, s+1UL, 100UL, total_stake );
      if( FD_UNLIKELY( err<0 ) ) FD_LOG_ERR(( "count_vote failed v=%lu s=%lu err=%d", v, s, err ));
    }
  }
  FD_LOG_NOTICE(( "filled %lu votes", counter ));

  /* Quota wraparound: every voter votes per_vtr_max MORE times on new unique
     blocks, forcing eviction of all old vtes (exercises bhm_remove /
     blk release paths with high indices). */
  for( ulong v=0UL; v<vtr_cnt; v++ ) {
    for( ulong s=0UL; s<per_vtr_max; s++ ) {
      fd_hash_t block_id;  memset( &block_id, 0, 32UL );
      fd_hash_t bank_hash; memset( &bank_hash, 0, 32UL );
      counter++;
      block_id.ul[0]  = counter;  block_id.ul[1]  = counter;
      bank_hash.ul[0] = counter;  bank_hash.ul[1] = counter*2654435761UL;
      int err = fd_hfork_count_vote( hfork, &vote_accs[v], &block_id, &bank_hash, per_vtr_max+s+1UL, 100UL, total_stake );
      if( FD_UNLIKELY( err<0 ) ) FD_LOG_ERR(( "count_vote wrap failed v=%lu s=%lu err=%d", v, s, err ));
    }
  }
  FD_LOG_NOTICE(( "wraparound complete, %lu total votes", counter ));

  /* Converge all voters on one block with matching stake >52%, plus
     record our (different) bank hash -> must detect mismatch. */
  fd_hash_t conv_block;  memset( &conv_block, 0, 32UL ); conv_block.ul[0] = 0xdeadbeefUL; conv_block.ul[1] = 0xdeadbeefUL;
  fd_hash_t conv_hash;   memset( &conv_hash, 0, 32UL );  conv_hash.ul[0]  = 0xfeedUL;     conv_hash.ul[1]  = 0xfeedUL;
  fd_hash_t our_hash;    memset( &our_hash, 0, 32UL );   our_hash.ul[0]   = 0x0ddUL;      our_hash.ul[1]   = 0x0ddUL;
  FD_TEST( 0==fd_hfork_record_our_bank_hash( hfork, &conv_block, &our_hash, total_stake ) );
  int mismatched = 0;
  for( ulong v=0UL; v<vtr_cnt; v++ ) {
    int err = fd_hfork_count_vote( hfork, &vote_accs[v], &conv_block, &conv_hash, 4096UL, 100UL, total_stake );
    if( err==-1 ) mismatched = 1;
    else FD_TEST( err==0 );
  }
  FD_TEST( mismatched );
  FD_LOG_NOTICE(( "hard fork mismatch detected correctly" ));

  /* Epoch churn: replace the whole voter set (exercises update_voters
     mark/sweep with uint next flag at scale). */
  for( ulong i=0UL; i<vtr_cnt; i++ ) vote_accs[i].ul[0] = 1000000UL+i;
  fd_hfork_update_voters( hfork, vote_accs, vtr_cnt );
  for( ulong i=0UL; i<vtr_cnt; i++ ) vote_accs[i].ul[0] = i+1UL;
  fd_hfork_update_voters( hfork, vote_accs, vtr_cnt );
  /* Old voters gone: their votes should now be rejected as unknown?  No
     — they were re-added fresh.  Verify fresh vote works. */
  fd_hash_t nb; memset( &nb, 0, 32UL ); nb.ul[0]=77UL; nb.ul[1]=77UL;
  FD_TEST( 0==fd_hfork_count_vote( hfork, &vote_accs[0], &nb, &conv_hash, 5000UL, 100UL, total_stake ) );
  FD_LOG_NOTICE(( "epoch churn ok" ));

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
