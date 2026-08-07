#include "fd_ssmanifest_writer.h"
#include "fd_txncache_writer.h"
#include "../restore/utils/fd_ssmanifest_parser.h"
#include "../restore/utils/fd_slot_delta_parser.h"
#include "../../flamenco/runtime/tests/fd_svm_mini.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/runtime/fd_txncache_shmem.h"

#include <stdlib.h>
#include <string.h>

#define MAX_LIVE_SLOTS      16UL
#define MAX_TXN_PER_SLOT    4096UL
#define VALIDATOR_CNT       3UL
#define ROOT_SLOT           474UL /* epoch 1 with 432 slots/epoch */
#define EPOCH_CREDITS_CNT   3UL

/* The mock validators created by svm_mini have empty credit histories,
   which leaves the encoder's base/delta reconstruction unexercised.
   Seed distinct base, credits, and previous credits per entry so a
   dropped base or a swapped credits/prev_credits pair is caught. */

static void
seed_epoch_credits( fd_bank_t * bank ) {
  ulong len = *fd_bank_epoch_credits_len( bank );
  FD_TEST( len==VALIDATOR_CNT );
  FD_TEST( EPOCH_CREDITS_CNT<=FD_EPOCH_CREDITS_MAX );
  for( ulong i=0UL; i<len; i++ ) {
    fd_epoch_credits_t * ec = &fd_bank_epoch_credits( bank )[ i ];
    ec->cnt          = EPOCH_CREDITS_CNT;
    ec->base_credits = 10000UL + 1000UL*i;
    for( ulong j=0UL; j<EPOCH_CREDITS_CNT; j++ ) {
      ec->epoch[ j ]              = (ushort)( j+1UL );
      ec->prev_credits_delta[ j ] = (uint)( 100UL*j + 7UL*i );
      ec->credits_delta[ j ]      = (uint)( 100UL*j + 7UL*i + 50UL );
    }
  }
}

static void
check_epoch_credits( fd_bank_t *                                bank,
                     fd_snapshot_manifest_vote_stakes_t const * vs ) {
  fd_epoch_credits_t const * ec  = NULL;
  ulong                      len = *fd_bank_epoch_credits_len( bank );
  for( ulong i=0UL; i<len; i++ ) {
    fd_epoch_credits_t const * cand = &fd_bank_epoch_credits( bank )[ i ];
    if( !memcmp( cand->pubkey, vs->vote, 32UL ) ) { ec = cand; break; }
  }
  FD_TEST( ec );
  FD_TEST( ec->cnt==EPOCH_CREDITS_CNT );
  FD_TEST( vs->epoch_credits_history_len==ec->cnt );
  for( ulong j=0UL; j<ec->cnt; j++ ) {
    FD_TEST( vs->epoch_credits[j].epoch       ==(ulong)ec->epoch[j] );
    FD_TEST( vs->epoch_credits[j].credits     ==ec->base_credits+(ulong)ec->credits_delta[j] );
    FD_TEST( vs->epoch_credits[j].prev_credits==ec->base_credits+(ulong)ec->prev_credits_delta[j] );
  }
}

#define EXTRA_DELEGATION_CNT 2UL

static void
seed_stake_delegations( fd_bank_t * bank,
                        fd_pubkey_t stake_keys[ EXTRA_DELEGATION_CNT ],
                        fd_pubkey_t vote_keys [ EXTRA_DELEGATION_CNT ] ) {
  fd_stake_delegations_t * sd = fd_bank_stake_delegations_modify( bank );
  FD_TEST( fd_stake_delegations_base_cnt( sd )==VALIDATOR_CNT );
  for( ulong i=0UL; i<EXTRA_DELEGATION_CNT; i++ ) {
    stake_keys[i] = (fd_pubkey_t){ .ul = { 0xD0D0D0D0UL, i+1UL, 0UL, 0UL } };
    vote_keys [i] = (fd_pubkey_t){ .ul = { 0xE0E0E0E0UL, i+1UL, 0UL, 0UL } };
    fd_stake_delegations_root_update( sd,
                                      &stake_keys[i], &vote_keys[i],
                                      7000000000UL + i,
                                      i+1UL,   /* activation_epoch   */
                                      i+9UL,   /* deactivation_epoch */
                                      0UL,     /* credits_observed   */
                                      0UL,     /* lamports, not serialized */
                                      0U,      /* acc_dlen, not serialized */
                                      FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
  }
}

static void
check_stake_delegations( fd_snapshot_manifest_t const * manifest,
                         fd_pubkey_t const              stake_keys[ EXTRA_DELEGATION_CNT ],
                         fd_pubkey_t const              vote_keys [ EXTRA_DELEGATION_CNT ] ) {
  FD_TEST( manifest->stake_delegations_len==VALIDATOR_CNT+EXTRA_DELEGATION_CNT );

  ulong bootstrap_cnt = 0UL;
  ulong extra_cnt     = 0UL;
  for( ulong i=0UL; i<manifest->stake_delegations_len; i++ ) {
    fd_snapshot_manifest_stake_delegation_t const * d = &manifest->stake_delegations[i];

    ulong j;
    for( j=0UL; j<EXTRA_DELEGATION_CNT; j++ ) {
      if( !memcmp( d->stake_pubkey, &stake_keys[j], 32UL ) ) break;
    }
    if( j==EXTRA_DELEGATION_CNT ) {
      /* One of svm_mini's bootstrap delegations. */
      FD_TEST( d->activation_epoch    ==ULONG_MAX );
      FD_TEST( d->deactivation_epoch  ==ULONG_MAX );
      FD_TEST( d->stake_delegation    ==1000000000UL );
      FD_TEST( d->warmup_cooldown_rate==FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_025 );
      bootstrap_cnt++;
      continue;
    }

    FD_TEST( !memcmp( d->vote_pubkey, &vote_keys[j], 32UL ) );
    FD_TEST( d->stake_delegation    ==7000000000UL+j );
    FD_TEST( d->activation_epoch    ==j+1UL );
    FD_TEST( d->deactivation_epoch  ==j+9UL );
    FD_TEST( d->warmup_cooldown_rate==FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_009 );
    extra_cnt++;
  }
  FD_TEST( bootstrap_cnt==VALIDATOR_CNT );
  FD_TEST( extra_cnt==EXTRA_DELEGATION_CNT );
}

typedef struct {
  fd_txncache_t * tc;
  void *          shmem;
  void *          ljoin;
} test_txncache_t;

static test_txncache_t
create_txncache( void ) {
  ulong shmem_fp = fd_txncache_shmem_footprint( MAX_LIVE_SLOTS, MAX_TXN_PER_SLOT, 0 );
  void * shmem_raw = aligned_alloc( fd_txncache_shmem_align(), shmem_fp );
  FD_TEST( shmem_raw );
  fd_txncache_shmem_t * shmem = fd_txncache_shmem_join( fd_txncache_shmem_new( shmem_raw, MAX_LIVE_SLOTS, MAX_TXN_PER_SLOT, 0, 1UL ) );
  FD_TEST( shmem );

  ulong ljoin_fp = fd_txncache_footprint( MAX_LIVE_SLOTS );
  void * ljoin_raw = aligned_alloc( fd_txncache_align(), ljoin_fp );
  FD_TEST( ljoin_raw );
  fd_txncache_t * tc = fd_txncache_join( fd_txncache_new( ljoin_raw, shmem ) );
  FD_TEST( tc );
  return (test_txncache_t){ .tc = tc, .shmem = shmem_raw, .ljoin = ljoin_raw };
}

#define NULL_FORK ((fd_txncache_fork_id_t){ .val = USHORT_MAX })

static void
populate_txncache( fd_txncache_t * tc,
                   uchar           blockhashes[ 4 ][ 32 ],
                   uchar           txnhashes[ 6 ][ 20 ] ) {
  for( ulong bh=0UL; bh<3UL; bh++ ) {
    memset( blockhashes[bh], 0, 32UL );
    blockhashes[bh][0] = (uchar)(bh+1U);
    blockhashes[bh][1] = 0xAB;
  }
  memset( blockhashes[3], 0xFF, 32UL );

  /* Build a chain where each slot finalizes with a blockhash,
     making it available for txn inserts in the next slot.
     root  -> finalize(bh0)
     s1    -> insert(bh0, txn0..1) -> finalize(bh1)
     s2    -> insert(bh1, txn2..3) -> finalize(bh2)
     s3    -> insert(bh2, txn4..5) -> finalize(final_bh)
     advance root to s3 */

  fd_txncache_fork_id_t root = fd_txncache_attach_child( tc, NULL_FORK );
  fd_txncache_finalize_fork( tc, root, 0UL, blockhashes[0] );

  fd_txncache_fork_id_t s1 = fd_txncache_attach_child( tc, root );
  for( ulong tx=0UL; tx<2UL; tx++ ) {
    memset( txnhashes[tx], 0, 20UL );
    txnhashes[tx][0] = (uchar)(tx+1U);
    txnhashes[tx][1] = 0xCD;
    fd_txncache_insert( tc, s1, blockhashes[0], txnhashes[tx] );
  }
  fd_txncache_finalize_fork( tc, s1, 0UL, blockhashes[1] );
  fd_txncache_advance_root( tc, s1 );

  fd_txncache_fork_id_t s2 = fd_txncache_attach_child( tc, s1 );
  for( ulong tx=0UL; tx<2UL; tx++ ) {
    ulong idx = 2UL + tx;
    memset( txnhashes[idx], 0, 20UL );
    txnhashes[idx][0] = (uchar)(idx+1U);
    txnhashes[idx][1] = 0xCD;
    fd_txncache_insert( tc, s2, blockhashes[1], txnhashes[idx] );
  }
  fd_txncache_finalize_fork( tc, s2, 0UL, blockhashes[2] );
  fd_txncache_advance_root( tc, s2 );

  fd_txncache_fork_id_t s3 = fd_txncache_attach_child( tc, s2 );
  for( ulong tx=0UL; tx<2UL; tx++ ) {
    ulong idx = 4UL + tx;
    memset( txnhashes[idx], 0, 20UL );
    txnhashes[idx][0] = (uchar)(idx+1U);
    txnhashes[idx][1] = 0xCD;
    fd_txncache_insert( tc, s3, blockhashes[2], txnhashes[idx] );
  }
  fd_txncache_finalize_fork( tc, s3, 0UL, blockhashes[3] );
  fd_txncache_advance_root( tc, s3 );

  fd_txncache_fork_id_t future = fd_txncache_attach_child( tc, s3 );
  for( ulong tx=0UL; tx<2UL; tx++ ) {
    uchar future_txnhash[ 20UL ];
    memset( future_txnhash, 0, 20UL );
    future_txnhash[0] = (uchar)(0x80U+tx);
    future_txnhash[1] = 0xCD;
    fd_txncache_insert( tc, future, tx ? blockhashes[2] : blockhashes[3], future_txnhash );
  }
}

static void
test_manifest_roundtrip( fd_bank_t * bank ) {
  FD_LOG_NOTICE(( "test_manifest_roundtrip" ));

  static fd_hash_t const block_id = { .ul = { 0x0123456789ABCDEFUL, 0xFEDCBA9876543210UL, 0x0F1E2D3C4B5A6978UL, 0x8877665544332211UL } };
  bank->f.block_id = block_id;

  /* Select two existing vote accounts, then set non-default SIMD-0232
     collectors: distinct inflation and block collectors for vote0 on
     the t_1 tag (epoch), and a block-only override for vote1 on the
     t_2 tag (epoch-1). */
  FD_TEST( bank->f.epoch>=1UL );
  fd_top_votes_t const * top_votes = fd_bank_top_votes_t_1_query( bank );
  uchar __attribute__((aligned(FD_TOP_VOTES_ITER_ALIGN))) iter_mem[ FD_TOP_VOTES_ITER_FOOTPRINT ];
  fd_top_votes_iter_t * iter = fd_top_votes_iter_init( top_votes, iter_mem );
  FD_TEST( !fd_top_votes_iter_done( top_votes, iter ) );
  fd_pubkey_t vote0;
  fd_top_votes_iter_ele( top_votes, iter, &vote0, NULL, NULL, NULL, NULL, NULL, NULL );
  fd_top_votes_iter_next( top_votes, iter );
  FD_TEST( !fd_top_votes_iter_done( top_votes, iter ) );
  fd_pubkey_t vote1;
  fd_top_votes_iter_ele( top_votes, iter, &vote1, NULL, NULL, NULL, NULL, NULL, NULL );

  fd_pubkey_t infl0 = { .ul = { 0xAA, 1 } };
  fd_pubkey_t blk0  = { .ul = { 0xBB, 2 } };
  fd_pubkey_t blk1  = { .ul = { 0xCC, 3 } };
  fd_collector_overrides_t * co = fd_bank_collector_overrides( bank );
  ushort co_root = fd_collector_overrides_get_root_idx( co );
  fd_collector_overrides_upsert( co, co_root, bank->f.epoch,     &vote0, 1, &infl0, 1, &blk0 );
  fd_collector_overrides_upsert( co, co_root, bank->f.epoch-1UL, &vote1, 0, NULL,   1, &blk1 );

  seed_epoch_credits( bank );

  fd_pubkey_t extra_stake_keys[ EXTRA_DELEGATION_CNT ];
  fd_pubkey_t extra_vote_keys [ EXTRA_DELEGATION_CNT ];
  seed_stake_delegations( bank, extra_stake_keys, extra_vote_keys );

  ulong manifest_sz = fd_snap_manifest_serialized_sz( bank );
  FD_TEST( manifest_sz>0UL );
  FD_LOG_NOTICE(( "manifest serialized size: %lu", manifest_sz ));

  uchar * buf = aligned_alloc( 1UL, manifest_sz );
  FD_TEST( buf );

  uchar * chunk_buf = aligned_alloc( 1UL, FD_SSMANIFEST_BUF_MIN );
  FD_TEST( chunk_buf );

  fd_ssmanifest_writer_t writer[1];
  fd_ssmanifest_writer_init( writer, bank );
  ulong total_written = 0UL;
  for(;;) {
    ulong sz = fd_snap_manifest_serialize( writer, chunk_buf, FD_SSMANIFEST_BUF_MIN );
    if( !sz ) break;
    FD_TEST( total_written + sz <= manifest_sz );
    memcpy( buf + total_written, chunk_buf, sz );
    total_written += sz;
  }
  FD_TEST( total_written==manifest_sz );

  fd_snapshot_manifest_t * manifest = aligned_alloc( alignof(fd_snapshot_manifest_t), sizeof(fd_snapshot_manifest_t) );
  FD_TEST( manifest );
  memset( manifest, 0, sizeof(fd_snapshot_manifest_t) );

  void * parser_mem = aligned_alloc( fd_ssmanifest_parser_align(), fd_ssmanifest_parser_footprint() );
  FD_TEST( parser_mem );
  fd_ssmanifest_parser_t * parser = fd_ssmanifest_parser_join( fd_ssmanifest_parser_new( parser_mem ) );
  FD_TEST( parser );
  fd_ssmanifest_parser_init( parser, manifest );

  int result = fd_ssmanifest_parser_consume( parser, buf, total_written );
  FD_TEST( result==FD_SSMANIFEST_PARSER_ADVANCE_DONE || result==FD_SSMANIFEST_PARSER_ADVANCE_AGAIN );
  FD_TEST( fd_ssmanifest_parser_fini( parser )==FD_SSMANIFEST_PARSER_ADVANCE_DONE );

  FD_TEST( manifest->slot==bank->f.slot );
  FD_TEST( manifest->block_height==bank->f.block_height );
  FD_TEST( manifest->capitalization==bank->f.capitalization );
  FD_TEST( manifest->ticks_per_slot==bank->f.ticks_per_slot );
  FD_TEST( manifest->epoch_schedule_params.slots_per_epoch==bank->f.epoch_schedule.slots_per_epoch );
  FD_TEST( manifest->rent_params.lamports_per_uint8_year==bank->f.rent.lamports_per_uint8_year );
  FD_TEST( manifest->rent_params.burn_percent==bank->f.rent.burn_percent );
  FD_TEST( manifest->has_block_id );
  FD_TEST( !memcmp( manifest->block_id, block_id.uc, sizeof(fd_hash_t) ) );

  check_stake_delegations( manifest, extra_stake_keys, extra_vote_keys );

  /* Collector round-trip: the encoder tags t_1 entries (epoch_stakes
     key epoch+1) with the epoch override tag and t_2 entries (key
     epoch) with the epoch-1 tag; t_3 entries (key epoch-1) are encoded
     with zero collectors. */
  {
    fd_snapshot_manifest_epoch_stakes_t const * t1 = NULL;
    fd_snapshot_manifest_epoch_stakes_t const * t2 = NULL;
    fd_snapshot_manifest_epoch_stakes_t const * t3 = NULL;
    for( ulong i=0UL; i<3UL; i++ ) {
      if( manifest->epoch_stakes[i].epoch==bank->f.epoch+1UL ) t1 = &manifest->epoch_stakes[i];
      if( manifest->epoch_stakes[i].epoch==bank->f.epoch     ) t2 = &manifest->epoch_stakes[i];
      if( manifest->epoch_stakes[i].epoch==bank->f.epoch-1UL ) t3 = &manifest->epoch_stakes[i];
    }
    FD_TEST( t1 && t2 && t3 );

    static uchar const zero32[ 32UL ] = {0};
    int seen_t1_vote0 = 0; int seen_t1_vote1 = 0;
    for( ulong i=0UL; i<t1->vote_stakes_len; i++ ) {
      fd_snapshot_manifest_vote_stakes_t const * vs = &t1->vote_stakes[i];
      check_epoch_credits( bank, vs );
      if( !memcmp( vs->vote, &vote0, 32UL ) ) {
        FD_TEST( !memcmp( vs->commission_inflation, &infl0, 32UL ) );
        FD_TEST( !memcmp( vs->commission_block,     &blk0,  32UL ) );
        seen_t1_vote0 = 1;
      } else {
        /* default collectors: inflation is the vote account, block is
           the node identity */
        FD_TEST( !memcmp( vs->commission_inflation, vs->vote,     32UL ) );
        FD_TEST( !memcmp( vs->commission_block,     vs->identity, 32UL ) );
        if( !memcmp( vs->vote, &vote1, 32UL ) ) seen_t1_vote1 = 1;
      }
    }
    FD_TEST( seen_t1_vote0 && seen_t1_vote1 );

    /* Only the t_1 entries carry credit histories. */
    int seen_t2_vote1 = 0; int seen_t2_vote0 = 0;
    for( ulong i=0UL; i<t2->vote_stakes_len; i++ ) {
      fd_snapshot_manifest_vote_stakes_t const * vs = &t2->vote_stakes[i];
      FD_TEST( !vs->epoch_credits_history_len );
      if( !memcmp( vs->vote, &vote1, 32UL ) ) {
        FD_TEST( !memcmp( vs->commission_inflation, vs->vote, 32UL ) );
        FD_TEST( !memcmp( vs->commission_block,     &blk1,    32UL ) );
        seen_t2_vote1 = 1;
      } else {
        FD_TEST( !memcmp( vs->commission_inflation, vs->vote,     32UL ) );
        FD_TEST( !memcmp( vs->commission_block,     vs->identity, 32UL ) );
        if( !memcmp( vs->vote, &vote0, 32UL ) ) seen_t2_vote0 = 1;
      }
    }
    FD_TEST( seen_t2_vote1 && seen_t2_vote0 );

    for( ulong i=0UL; i<t3->vote_stakes_len; i++ ) {
      FD_TEST( !memcmp( t3->vote_stakes[i].commission_inflation, zero32, 32UL ) );
      FD_TEST( !memcmp( t3->vote_stakes[i].commission_block,     zero32, 32UL ) );
      FD_TEST( !t3->vote_stakes[i].epoch_credits_history_len );
    }
  }

  ulong expected_epoch_cnt = (bank->f.epoch > 0UL) ? 3UL : 2UL;
  for( ulong i=0UL; i<expected_epoch_cnt; i++ ) {
    FD_LOG_NOTICE(( "epoch_stakes[%lu]: epoch=%lu total_stake=%lu vote_stakes_len=%lu",
                    i,
                    manifest->epoch_stakes[i].epoch,
                    manifest->epoch_stakes[i].total_stake,
                    manifest->epoch_stakes[i].vote_stakes_len ));
    ulong expected_vote_cnt = (bank->f.epoch>0UL && i==0UL) ? 0UL : VALIDATOR_CNT;
    FD_TEST( manifest->epoch_stakes[i].vote_stakes_len==expected_vote_cnt );
    for( ulong j=0UL; j<manifest->epoch_stakes[i].vote_stakes_len; j++ ) {
      FD_TEST( manifest->epoch_stakes[i].vote_stakes[j].commission==1234U );
    }
  }

  free( parser_mem );
  free( manifest );
  free( chunk_buf );
  free( buf );
}

static void
test_txncache_roundtrip( void ) {
  FD_LOG_NOTICE(( "test_txncache_roundtrip" ));

  test_txncache_t test_tc = create_txncache();
  fd_txncache_t * tc = test_tc.tc;

  uchar blockhashes[4][32];
  uchar txnhashes[6][20];
  populate_txncache( tc, blockhashes, txnhashes );

  ulong tc_sz = fd_txncache_writer_serialized_sz( tc, ROOT_SLOT );
  FD_TEST( tc_sz>0UL );
  FD_LOG_NOTICE(( "txncache serialized size: %lu", tc_sz ));

  uchar * buf = aligned_alloc( 1UL, tc_sz );
  FD_TEST( buf );

  uchar * chunk_buf = aligned_alloc( 1UL, FD_TXNCACHE_WRITER_BUF_MIN );
  FD_TEST( chunk_buf );

  fd_txncache_writer_t writer[1];
  fd_txncache_writer_init( writer, tc, ROOT_SLOT );
  ulong total_written = 0UL;
  for(;;) {
    ulong sz = fd_txncache_writer_serialize( writer, chunk_buf, FD_TXNCACHE_WRITER_BUF_MIN );
    if( !sz ) break;
    FD_TEST( total_written + sz <= tc_sz );
    memcpy( buf + total_written, chunk_buf, sz );
    total_written += sz;
  }
  FD_TEST( total_written==tc_sz );

  void * parser_mem = aligned_alloc( fd_slot_delta_parser_align(), fd_slot_delta_parser_footprint() );
  FD_TEST( parser_mem );
  fd_slot_delta_parser_t * parser = fd_slot_delta_parser_join( fd_slot_delta_parser_new( parser_mem ) );
  FD_TEST( parser );
  fd_slot_delta_parser_init( parser );

  ulong entries_parsed = 0UL;
  ulong groups_parsed  = 0UL;
  uchar const * p = buf;
  ulong remaining = total_written;
  for(;;) {
    fd_slot_delta_parser_advance_result_t result[1];
    int res = fd_slot_delta_parser_consume( parser, p, remaining, result );
    FD_TEST( res>=0 );

    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_DONE ) break;

    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_ENTRY ) {
      fd_sstxncache_entry_t const * entry = result->entry;
      FD_TEST( entry->slot==ROOT_SLOT );
      FD_TEST( entry->result==0U );

      int found = 0;
      for( ulong i=0UL; i<6UL; i++ ) {
        if( 0==memcmp( entry->txnhash, txnhashes[i], 20UL ) ) { found = 1; break; }
      }
      FD_TEST( found );
      entries_parsed++;
    }

    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_GROUP ) {
      int found = 0;
      for( ulong i=0UL; i<4UL; i++ ) {
        if( 0==memcmp( result->group.blockhash, blockhashes[i], 32UL ) ) { found = 1; break; }
      }
      FD_TEST( found );
      groups_parsed++;
    }

    p         += result->bytes_consumed;
    remaining -= result->bytes_consumed;
  }

  FD_TEST( entries_parsed==6UL );
  FD_TEST( groups_parsed==4UL );
  FD_LOG_NOTICE(( "parsed %lu entries across %lu groups", entries_parsed, groups_parsed ));

  free( fd_slot_delta_parser_delete( fd_slot_delta_parser_leave( parser ) ) );
  free( chunk_buf );
  free( buf );
  free( test_tc.ljoin );
  free( test_tc.shmem );
}

static void
test_stake_delegations_fallback( fd_bank_t * bank,
                                 ulong       max_stake_accounts ) {
  FD_LOG_NOTICE(( "test_stake_delegations_fallback" ));

  fd_stake_delegations_t * sd = fd_bank_stake_delegations_modify( bank );
  FD_TEST( !fd_stake_delegations_pubkey_fallback( sd ) );

  ulong overflow = max_stake_accounts + 16UL;
  for( ulong i=0UL; i<overflow; i++ ) {
    fd_pubkey_t stake_key = { .ul = { 0xF0F0F0F0UL, i, 0UL, 0UL } };
    fd_pubkey_t vote_key  = { .ul = { 0xF1F1F1F1UL, i, 0UL, 0UL } };
    fd_stake_delegations_root_update( sd, &stake_key, &vote_key,
                                      1000UL, ULONG_MAX, ULONG_MAX, 0UL, 0UL, 0U,
                                      FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
  }

  FD_TEST( fd_stake_delegations_pubkey_fallback( sd ) );

  ulong base_cnt   = fd_stake_delegations_base_cnt( sd );
  ulong pubkey_cnt = fd_stake_delegations_pubkey_cnt( sd );
  FD_TEST( base_cnt==max_stake_accounts );
  FD_TEST( base_cnt<pubkey_cnt );
  FD_LOG_INFO(( "fallback mode: %lu of %lu stake accounts in the root map", base_cnt, pubkey_cnt ));
}

int
main( int     argc,
      char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );
  FD_TEST( mini );

  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->mock_validator_cnt = VALIDATOR_CNT;
  params->root_slot          = ROOT_SLOT;
  params->slots_per_epoch    = 432UL;
  /* Place the bank in epoch 1 so the t_1 (epoch) and t_2 (epoch-1)
     collector override tags are distinct. */
  fd_sol_sysvar_clock_t clock = { .slot = ROOT_SLOT, .epoch = 1UL, .leader_schedule_epoch = 2UL };
  params->clock              = &clock;
  ulong bank_idx = fd_svm_mini_reset( mini, params );
  fd_bank_t * bank = fd_svm_mini_bank( mini, bank_idx );
  FD_TEST( bank );

  test_manifest_roundtrip( bank );
  test_txncache_roundtrip();
  test_stake_delegations_fallback( bank, limits->max_stake_accounts );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
