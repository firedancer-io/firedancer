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
    ec->commission   = (ushort)( 4321U + i );
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
                   uchar           txnhashes[ 8 ][ 20 ] ) {
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
     s3    -> insert(bh2, txn4..5), insert(bh1, txn6..7) -> finalize(final_bh)
     advance root to s3

     s2 and s3 both reference bh1, so that blockcache has to be split
     across two slot deltas on serialization. */

  fd_txncache_fork_id_t root = fd_txncache_attach_child( tc, NULL_FORK, ROOT_SLOT-3UL );
  fd_txncache_finalize_fork( tc, root, 0UL, blockhashes[0] );

  fd_txncache_fork_id_t s1 = fd_txncache_attach_child( tc, root, ROOT_SLOT-2UL );
  for( ulong tx=0UL; tx<2UL; tx++ ) {
    memset( txnhashes[tx], 0, 20UL );
    txnhashes[tx][0] = (uchar)(tx+1U);
    txnhashes[tx][1] = 0xCD;
    fd_txncache_insert( tc, s1, blockhashes[0], txnhashes[tx] );
  }
  fd_txncache_finalize_fork( tc, s1, 0UL, blockhashes[1] );
  fd_txncache_advance_root( tc, s1 );

  fd_txncache_fork_id_t s2 = fd_txncache_attach_child( tc, s1, ROOT_SLOT-1UL );
  for( ulong tx=0UL; tx<2UL; tx++ ) {
    ulong idx = 2UL + tx;
    memset( txnhashes[idx], 0, 20UL );
    txnhashes[idx][0] = (uchar)(idx+1U);
    txnhashes[idx][1] = 0xCD;
    fd_txncache_insert( tc, s2, blockhashes[1], txnhashes[idx] );
  }
  fd_txncache_finalize_fork( tc, s2, 0UL, blockhashes[2] );
  fd_txncache_advance_root( tc, s2 );

  fd_txncache_fork_id_t s3 = fd_txncache_attach_child( tc, s2, ROOT_SLOT );
  for( ulong tx=0UL; tx<4UL; tx++ ) {
    ulong idx = 4UL + tx;
    memset( txnhashes[idx], 0, 20UL );
    txnhashes[idx][0] = (uchar)(idx+1U);
    txnhashes[idx][1] = 0xCD;
    fd_txncache_insert( tc, s3, blockhashes[ tx<2UL ? 2UL : 1UL ], txnhashes[idx] );
  }
  fd_txncache_finalize_fork( tc, s3, 0UL, blockhashes[3] );
  fd_txncache_advance_root( tc, s3 );

  fd_txncache_fork_id_t future = fd_txncache_attach_child( tc, s3, ROOT_SLOT+1UL );
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
  bank->f.parent_txn_count = 1234UL;
  bank->f.txn_count        =   56UL;

  /* Select two existing vote accounts, then set non-default SIMD-0232
     collectors: distinct inflation and block collectors for vote0 on
     the t_1 tag (epoch), and a block-only override for vote1 on the
     t_2 tag (epoch-1). */
  FD_TEST( bank->f.epoch>=1UL );
  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank );
  ulong              fork_id     = bank->vote_stakes_fork_id;
  uchar __attribute__((aligned(FD_VOTE_STAKES_T_1_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_T_1_ITER_FOOTPRINT ];
  fd_vote_stakes_t_1_iter_t * iter = fd_vote_stakes_t_1_iter_init( vote_stakes, fork_id, iter_mem );
  FD_TEST( !fd_vote_stakes_t_1_iter_done( vote_stakes, fork_id, iter ) );
  fd_pubkey_t vote0;
  fd_vote_stakes_t_1_iter_ele( vote_stakes, fork_id, iter, &vote0, NULL, NULL, NULL, NULL );
  fd_vote_stakes_t_1_iter_next( vote_stakes, fork_id, iter );
  FD_TEST( !fd_vote_stakes_t_1_iter_done( vote_stakes, fork_id, iter ) );
  fd_pubkey_t vote1;
  fd_vote_stakes_t_1_iter_ele( vote_stakes, fork_id, iter, &vote1, NULL, NULL, NULL, NULL );

  fd_pubkey_t infl0 = { .ul = { 0xAA, 1 } };
  fd_pubkey_t blk0  = { .ul = { 0xBB, 2 } };
  fd_pubkey_t blk1  = { .ul = { 0xCC, 3 } };
  fd_collector_overrides_t * co = fd_bank_collector_overrides( bank );
  ushort co_root = fd_collector_overrides_get_root_idx( co );
  fd_collector_overrides_upsert( co, co_root, bank->f.epoch,     &vote0, 1, &infl0, 1, &blk0 );
  fd_collector_overrides_upsert( co, co_root, bank->f.epoch-1UL, &vote1, 0, NULL,   1, &blk1 );

  seed_epoch_credits( bank );

  ulong manifest_sz = fd_snap_manifest_serialized_sz( bank );
  FD_TEST( manifest_sz>0UL );
  FD_LOG_NOTICE(( "manifest serialized size: %lu", manifest_sz ));

  /* The writer emits an empty primary stake-delegations map.  Inject
     one entry to verify that the parser consumes but does not retain
     primary stake delegations in fd_snapshot_manifest_t. */
  fd_pubkey_t ignored_stake_pubkey;
  fd_pubkey_t ignored_vote_pubkey;
  for( ulong i=0UL; i<sizeof(fd_pubkey_t); i++ ) {
    ignored_stake_pubkey.uc[i] = (uchar)(0x80UL+i);
    ignored_vote_pubkey.uc[i]  = (uchar)(0xC0UL+i);
  }
  ulong const stake_delegation_sz = 2UL*sizeof(fd_pubkey_t) + 3UL*sizeof(ulong) + sizeof(double);

  uchar * buf = aligned_alloc( 1UL, manifest_sz+stake_delegation_sz );
  FD_TEST( buf );

  uchar * chunk_buf = aligned_alloc( 1UL, FD_SSMANIFEST_BUF_MIN );
  FD_TEST( chunk_buf );

  fd_ssmanifest_writer_t writer[1];
  fd_ssmanifest_writer_init( writer, bank );
  ulong total_written = 0UL;
  int   injected      = 0;
  for(;;) {
    ulong sz = fd_snap_manifest_serialize( writer, chunk_buf, FD_SSMANIFEST_BUF_MIN );
    if( !sz ) break;
    FD_TEST( total_written + sz <= manifest_sz+stake_delegation_sz );

    /* This uniquely identifies the writer's vote-accounts chunk:
       empty vote accounts, empty stake delegations, unused=0, epoch. */
    if( FD_UNLIKELY( !injected &&
                     sz==4UL*sizeof(ulong) &&
                     FD_LOAD( ulong, chunk_buf     )==0UL &&
                     FD_LOAD( ulong, chunk_buf+ 8UL )==0UL &&
                     FD_LOAD( ulong, chunk_buf+16UL )==0UL &&
                     FD_LOAD( ulong, chunk_buf+24UL )==bank->f.epoch ) ) {
      uchar * dst = buf+total_written;
      memcpy( dst, chunk_buf, 8UL );
      dst += 8UL;
      FD_STORE( ulong, dst, 1UL );
      dst += 8UL;
      memcpy( dst, &ignored_stake_pubkey, sizeof(fd_pubkey_t) );
      dst += sizeof(fd_pubkey_t);
      memcpy( dst, &ignored_vote_pubkey, sizeof(fd_pubkey_t) );
      dst += sizeof(fd_pubkey_t);
      FD_STORE( ulong, dst, 1234UL ); dst += sizeof(ulong);
      FD_STORE( ulong, dst, 5UL    ); dst += sizeof(ulong);
      FD_STORE( ulong, dst, 9UL    ); dst += sizeof(ulong);
      FD_STORE( double, dst, 0.25  ); dst += sizeof(double);
      memcpy( dst, chunk_buf+16UL, sz-16UL );
      total_written += sz+stake_delegation_sz;
      injected = 1;
    } else {
      memcpy( buf + total_written, chunk_buf, sz );
      total_written += sz;
    }
  }
  FD_TEST( injected );
  FD_TEST( total_written==manifest_sz+stake_delegation_sz );

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
  FD_TEST( manifest->transaction_count==bank->f.parent_txn_count+bank->f.txn_count );
  FD_TEST( manifest->ticks_per_slot==bank->f.ticks_per_slot );
  FD_TEST( manifest->epoch_schedule_params.slots_per_epoch==bank->f.epoch_schedule.slots_per_epoch );
  FD_TEST( manifest->rent_params.lamports_per_uint8_year==bank->f.rent.lamports_per_uint8_year );
  FD_TEST( manifest->rent_params.burn_percent==bank->f.rent.burn_percent );
  FD_TEST( manifest->has_block_id );
  FD_TEST( !memcmp( manifest->block_id, block_id.uc, sizeof(fd_hash_t) ) );

  int found_stake_delegation = 0;
  for( ulong i=0UL; i+sizeof(fd_pubkey_t)<=sizeof(*manifest); i++ ) {
    if( !memcmp( (uchar const *)manifest+i, &ignored_stake_pubkey, sizeof(fd_pubkey_t) ) ||
        !memcmp( (uchar const *)manifest+i, &ignored_vote_pubkey,  sizeof(fd_pubkey_t) ) ) {
      found_stake_delegation = 1;
      break;
    }
  }
  FD_TEST( !found_stake_delegation );

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
      fd_snapshot_manifest_vote_stakes_t const * vs = &t3->vote_stakes[i];
      FD_TEST( !memcmp( vs->commission_inflation, zero32, 32UL ) );
      FD_TEST( !memcmp( vs->commission_block,     zero32, 32UL ) );
      FD_TEST( !vs->epoch_credits_history_len );

      int found = 0;
      for( ulong j=0UL; j<*fd_bank_epoch_credits_len( bank ); j++ ) {
        fd_epoch_credits_t const * ec = &fd_bank_epoch_credits( bank )[ j ];
        if( memcmp( vs->vote, ec->pubkey, 32UL ) ) continue;
        FD_TEST( vs->commission==ec->commission );
        found = 1;
        break;
      }
      FD_TEST( found );
    }
  }

  ulong expected_epoch_cnt = (bank->f.epoch > 0UL) ? 3UL : 2UL;
  for( ulong i=0UL; i<expected_epoch_cnt; i++ ) {
    FD_LOG_NOTICE(( "epoch_stakes[%lu]: epoch=%lu total_stake=%lu vote_stakes_len=%lu",
                    i,
                    manifest->epoch_stakes[i].epoch,
                    manifest->epoch_stakes[i].total_stake,
                    manifest->epoch_stakes[i].vote_stakes_len ));
    ulong expected_vote_cnt = VALIDATOR_CNT;
    FD_TEST( manifest->epoch_stakes[i].vote_stakes_len==expected_vote_cnt );
    if( manifest->epoch_stakes[i].epoch!=bank->f.epoch-1UL ) {
      for( ulong j=0UL; j<manifest->epoch_stakes[i].vote_stakes_len; j++ ) {
        FD_TEST( manifest->epoch_stakes[i].vote_stakes[j].commission==1234U );
      }
    }
  }

  free( parser_mem );
  free( manifest );
  free( chunk_buf );
  free( buf );
}

/* test_txncache_roundtrip serializes a small txncache and parses it back
   with the snapshot loader's parser.  slot_history is optional, when
   provided the writer pads the output with empty slot deltas. */

static void
test_txncache_roundtrip( fd_slot_history_view_t const * slot_history,
                         ulong                          expected_slots ) {
  FD_LOG_NOTICE(( "test_txncache_roundtrip (slot_history=%s)", slot_history ? "yes" : "no" ));

  test_txncache_t test_tc = create_txncache();
  fd_txncache_t * tc = test_tc.tc;

  uchar blockhashes[4][32];
  uchar txnhashes[8][20];
  populate_txncache( tc, blockhashes, txnhashes );

  /* The slot each transaction executed in, in txnhashes order. */
  ulong const exec_slot[8] = {
    ROOT_SLOT-2UL, ROOT_SLOT-2UL,
    ROOT_SLOT-1UL, ROOT_SLOT-1UL,
    ROOT_SLOT,     ROOT_SLOT,
    ROOT_SLOT,     ROOT_SLOT
  };

  fd_txncache_writer_t writer[1];
  fd_txncache_writer_init( writer, tc, slot_history );

  ulong tc_sz = fd_txncache_writer_serialized_sz( writer );
  FD_TEST( tc_sz>0UL );
  FD_LOG_NOTICE(( "txncache serialized size: %lu", tc_sz ));

  uchar * buf = aligned_alloc( 1UL, tc_sz );
  FD_TEST( buf );

  uchar * chunk_buf = aligned_alloc( 1UL, FD_TXNCACHE_WRITER_BUF_MIN );
  FD_TEST( chunk_buf );
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
  ulong slots_parsed   = 0UL;
  ulong prev_slot      = 0UL;
  uchar const * p = buf;
  ulong remaining = total_written;
  for(;;) {
    fd_slot_delta_parser_advance_result_t result[1];
    int res = fd_slot_delta_parser_consume( parser, p, remaining, result );
    FD_TEST( res>=0 );

    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_DONE ) break;

    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_ENTRY ) {
      fd_sstxncache_entry_t const * entry = result->entry;
      FD_TEST( entry->result==0U );

      int found = 0;
      for( ulong i=0UL; i<8UL; i++ ) {
        if( 0==memcmp( entry->txnhash, txnhashes[i], 20UL ) ) {
          /* Each transaction must be reported in the slot it executed
             in, not the snapshot slot. */
          FD_TEST( entry->slot==exec_slot[i] );
          found = 1;
          break;
        }
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

    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_SLOT ) {
      /* Slot deltas are written oldest first, and the padding must not
         claim slots that were never rooted. */
      FD_TEST( !slots_parsed || result->slot>prev_slot );
      FD_TEST( !slot_history || fd_sysvar_slot_history_find_slot( slot_history, result->slot )==FD_SLOT_HISTORY_SLOT_FOUND );
      prev_slot = result->slot;
      slots_parsed++;
    }

    p         += result->bytes_consumed;
    remaining -= result->bytes_consumed;
  }

  /* One slot delta per rooted slot (root, s1, s2, s3) plus any padding.
     root executed nothing so it contributes no groups; s1 and s2
     contribute one group each, and s3 two because it referenced two
     blockhashes. */
  FD_TEST( slots_parsed==expected_slots );
  FD_TEST( prev_slot==ROOT_SLOT );
  FD_TEST( groups_parsed==4UL );
  FD_TEST( entries_parsed==8UL );
  FD_LOG_NOTICE(( "parsed %lu entries across %lu groups in %lu slot deltas", entries_parsed, groups_parsed, slots_parsed ));

  free( fd_slot_delta_parser_delete( fd_slot_delta_parser_leave( parser ) ) );
  free( chunk_buf );
  free( buf );
  free( test_tc.ljoin );
  free( test_tc.shmem );
}

/* The status cache must contain a slot delta for each of the 300 most
   recent rooted slots, but the txncache only holds 151 of them, so the
   writer pads the rest out as empty deltas.  Feed it a slot history with
   two skipped slots and check the padding respects them. */

#define GAP_SLOT_A (ROOT_SLOT-10UL)
#define GAP_SLOT_B (ROOT_SLOT-20UL)

static void
test_txncache_slot_history_padding( void ) {
  FD_LOG_NOTICE(( "test_txncache_slot_history_padding" ));

  ulong   blocks_len = FD_SLOT_HISTORY_MAX_ENTRIES/64UL;
  ulong   data_sz    = 9UL + blocks_len*sizeof(ulong) + 16UL;
  uchar * data       = aligned_alloc( 8UL, fd_ulong_align_up( data_sz, 8UL ) );
  FD_TEST( data );
  memset( data, 0, data_sz );

  data[ 0 ] = 1; /* has_bits */
  FD_STORE( ulong, data+1, blocks_len );
  uchar * bits   = data+9UL;
  uchar * footer = bits + blocks_len*sizeof(ulong);
  FD_STORE( ulong, footer,     FD_SLOT_HISTORY_MAX_ENTRIES );
  FD_STORE( ulong, footer+8UL, ROOT_SLOT+1UL               ); /* next_slot */

  for( ulong slot=0UL; slot<=ROOT_SLOT; slot++ ) {
    if( FD_UNLIKELY( slot==GAP_SLOT_A || slot==GAP_SLOT_B ) ) continue;
    uchar * word = bits + ((slot/64UL)%blocks_len)*sizeof(ulong);
    FD_STORE( ulong, word, FD_LOAD( ulong, word ) | (1UL<<(slot%64UL)) );
  }

  fd_slot_history_view_t view[1];
  FD_TEST( fd_sysvar_slot_history_view( view, data, data_sz )==view );
  FD_TEST( fd_sysvar_slot_history_find_slot( view, GAP_SLOT_A )==FD_SLOT_HISTORY_SLOT_NOT_FOUND );
  FD_TEST( fd_sysvar_slot_history_find_slot( view, ROOT_SLOT  )==FD_SLOT_HISTORY_SLOT_FOUND     );

  /* Every slot below the txncache is rooted bar the two gaps, so the
     padding fills all the way up to the cap. */
  test_txncache_roundtrip( view, FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS );

  free( data );
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
  test_txncache_roundtrip( NULL, 4UL );
  test_txncache_slot_history_padding();

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
