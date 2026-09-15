#include "fd_ssmanifest_writer.h"
#include "fd_txncache_writer.h"
#include "../restore/utils/fd_ssmanifest_parser.h"
#include "../restore/utils/fd_slot_delta_parser.h"
#include "../../flamenco/runtime/tests/fd_svm_mini.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/runtime/fd_txncache_shmem.h"
#include "../../flamenco/runtime/fd_txncache_private.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_slot_history.h"
#if FD_HAS_RACESAN
#include "../../util/racesan/fd_racesan.h"
#endif

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_LIVE_SLOTS      16UL
#define MAX_TXN_PER_SLOT    4096UL
#define VALIDATOR_CNT       3UL
#define ROOT_SLOT           474UL /* epoch 1 with 432 slots/epoch */
#define EPOCH_CREDITS_CNT   3UL

#define TEST_WKSP_TAG           43UL
#define TEST_WKSP_ADDL_SZ       (256UL<<20)
#define TEST_WKSP_ADDL_PART_CNT (64UL)

/* The writer emits one slot delta per recent slot with a block, so the
   parser must accept at least that many. */

FD_STATIC_ASSERT( FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS<=FD_SLOT_DELTA_MAX_ENTRIES, slot_delta_cnt );

static void *
test_alloc( fd_wksp_t * wksp,
            ulong       align,
            ulong       sz ) {
  void * mem = fd_wksp_alloc_laddr( wksp, align, sz, TEST_WKSP_TAG );
  FD_TEST( mem );
  return mem;
}

static void
test_allocs_reclaim( fd_wksp_t * wksp ) {
  ulong tag = TEST_WKSP_TAG;
  fd_wksp_tag_free( wksp, &tag, 1UL );
}

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
  fd_txncache_t *       tc;
  fd_txncache_shmem_t * shmem;
} test_txncache_t;

static test_txncache_t
create_txncache_sized( fd_wksp_t * wksp,
                       ulong       max_live_slots,
                       ulong       max_txn_per_slot ) {
  ulong shmem_fp = fd_txncache_shmem_footprint( max_live_slots, max_txn_per_slot );
  void * shmem_raw = test_alloc( wksp, fd_txncache_shmem_align(), shmem_fp );
  fd_txncache_shmem_t * shmem = fd_txncache_shmem_join( fd_txncache_shmem_new( shmem_raw, max_live_slots, max_txn_per_slot, 1UL ) );
  FD_TEST( shmem );

  ulong ljoin_fp = fd_txncache_footprint( max_live_slots );
  void * ljoin_raw = test_alloc( wksp, fd_txncache_align(), ljoin_fp );
  fd_txncache_t * tc = fd_txncache_join( fd_txncache_new( ljoin_raw, shmem ) );
  FD_TEST( tc );
  return (test_txncache_t){ .tc = tc, .shmem = shmem };
}

static test_txncache_t
create_txncache( fd_wksp_t * wksp ) {
  return create_txncache_sized( wksp, MAX_LIVE_SLOTS, MAX_TXN_PER_SLOT );
}

#define NULL_FORK ((fd_txncache_fork_id_t){ .val = USHORT_MAX })

#define SLOT_HISTORY_BLOCKS (FD_SLOT_HISTORY_MAX_ENTRIES/64UL)

/* mock_slot_history writes the bincode form of a SlotHistory sysvar
   account into buf, in which every slot in [first,last] has a block
   except the skip_cnt slots listed in skip.  Returns buf. */

static uchar *
mock_slot_history( uchar *       buf,
                   ulong         first,
                   ulong         last,
                   ulong const * skip,
                   ulong         skip_cnt ) {
  memset( buf, 0, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );

  buf[ 0 ] = 1; /* bits present */
  FD_STORE( ulong, buf+1UL, SLOT_HISTORY_BLOCKS );

  uchar * bits   = buf+9UL;
  uchar * footer = bits + SLOT_HISTORY_BLOCKS*sizeof(ulong);
  FD_STORE( ulong, footer,     FD_SLOT_HISTORY_MAX_ENTRIES );
  FD_STORE( ulong, footer+8UL, last+1UL /* next_slot */    );

  for( ulong slot=first; slot<=last; slot++ ) {
    int skipped = 0;
    for( ulong i=0UL; i<skip_cnt; i++ ) skipped |= skip[ i ]==slot;
    if( skipped ) continue;

    uchar * word = bits + ((slot/64UL)%SLOT_HISTORY_BLOCKS)*sizeof(ulong);
    FD_STORE( ulong, word, FD_LOAD( ulong, word ) | (1UL<<(slot%64UL)) );
  }

  return buf;
}

/* populate_txncache fills tc and returns the newest root, s3. */

static fd_txncache_fork_id_t
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

  return s3;
}

static void
test_manifest_roundtrip( fd_wksp_t * wksp,
                         fd_bank_t * bank ) {
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
  uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
  fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_1, iter_mem );
  FD_TEST( !fd_vote_stakes_iter_done( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_1, iter ) );
  fd_pubkey_t vote0;
  fd_vote_stakes_iter_ele( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_1, iter, &vote0, NULL, NULL,
                           NULL, NULL, NULL, NULL, NULL, NULL, NULL );
  fd_vote_stakes_iter_next( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_1, iter );
  FD_TEST( !fd_vote_stakes_iter_done( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_1, iter ) );
  fd_pubkey_t vote1;
  fd_vote_stakes_iter_ele( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_1, iter, &vote1, NULL, NULL,
                           NULL, NULL, NULL, NULL, NULL, NULL, NULL );

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

  uchar * buf       = test_alloc( wksp, alignof(uchar), manifest_sz+stake_delegation_sz );
  uchar * chunk_buf = test_alloc( wksp, alignof(uchar), FD_SSMANIFEST_BUF_MIN );

  fd_ssmanifest_writer_t writer[1];
  fd_ssmanifest_writer_init( writer, bank );
  ulong total_written             = 0UL;
  ulong stake_delegations_len_off = ULONG_MAX;
  int   injected                  = 0;
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
      stake_delegations_len_off = (ulong)(dst-buf);
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
  FD_TEST( stake_delegations_len_off!=ULONG_MAX );
  FD_TEST( total_written==manifest_sz+stake_delegation_sz );

  fd_snapshot_manifest_t * manifest = test_alloc( wksp, alignof(fd_snapshot_manifest_t), sizeof(fd_snapshot_manifest_t) );
  memset( manifest, 0, sizeof(fd_snapshot_manifest_t) );

  void * parser_mem = test_alloc( wksp, fd_ssmanifest_parser_align(), fd_ssmanifest_parser_footprint() );
  fd_ssmanifest_parser_t * parser = fd_ssmanifest_parser_join( fd_ssmanifest_parser_new( parser_mem ) );
  FD_TEST( parser );

  /* The primary delegation map is skipped and reconstructed from the
     account stream, so its declared length is not bounded by the
     in-memory delegation cache capacity. */
  FD_STORE( ulong, buf+stake_delegations_len_off, FD_RUNTIME_MAX_STAKE_ACCOUNTS+1UL );
  fd_ssmanifest_parser_init( parser, manifest );
  FD_TEST( fd_ssmanifest_parser_consume( parser, buf, stake_delegations_len_off+sizeof(ulong) )==
           FD_SSMANIFEST_PARSER_ADVANCE_AGAIN );

  FD_STORE( ulong, buf+stake_delegations_len_off, 1UL );
  memset( manifest, 0, sizeof(fd_snapshot_manifest_t) );
  fd_ssmanifest_parser_init( parser, manifest );

  int result = fd_ssmanifest_parser_consume( parser, buf, total_written );
  FD_TEST( result==FD_SSMANIFEST_PARSER_ADVANCE_DONE || result==FD_SSMANIFEST_PARSER_ADVANCE_AGAIN );
  FD_TEST( fd_ssmanifest_parser_fini( parser )==FD_SSMANIFEST_PARSER_ADVANCE_DONE );
  fd_wksp_free_laddr( parser_mem );

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
}

static uchar *
serialize_all( fd_wksp_t *            wksp,
               fd_txncache_writer_t * writer,
               ulong                  chunk_sz,
               ulong *                out_sz ) {
  ulong const cap   = fd_txncache_writer_serialized_sz( writer );
  uchar *     buf   = test_alloc( wksp, alignof(uchar), cap      );
  uchar *     chunk = test_alloc( wksp, alignof(uchar), chunk_sz );
  ulong       sz    = 0UL;
  for(;;) {
    ulong n = fd_txncache_writer_serialize( writer, chunk, chunk_sz );
    if( !n ) break;
    FD_TEST( n<=chunk_sz );
    FD_TEST( sz<=cap );
    FD_TEST( n<=cap-sz );
    memcpy( buf+sz, chunk, n );
    sz += n;
  }
  FD_TEST( sz==cap );
  fd_wksp_free_laddr( chunk );
  *out_sz = sz;
  return buf;
}

/* The writer is too large for the stack. */
static fd_txncache_writer_t *
new_writer( fd_wksp_t * wksp ) {
  return test_alloc( wksp, alignof(fd_txncache_writer_t), sizeof(fd_txncache_writer_t) );
}

/* new_arena returns a 64 byte aligned arena holding entry_cnt hashes;
   *out_sz receives its size. */
static void *
new_arena( fd_wksp_t * wksp,
           ulong       entry_cnt,
           ulong *     out_sz ) {
  *out_sz = fd_ulong_align_up( entry_cnt*20UL, fd_txncache_writer_arena_align() );
  return test_alloc( wksp, fd_txncache_writer_arena_align(), *out_sz );
}

/* An expected status cache entry: txnhash executed in exec_slot,
   referencing blockhash. */
struct expect {
  uchar txnhash[ 20UL ];
  uchar blockhash[ 32UL ];
  ulong exec_slot;
  ulong blockhash_i;
  int   seen;
};
typedef struct expect expect_t;

/* expect_chain fills the expectations for populate_txncache's chain:
   txn0,1 ran in s1 = ROOT_SLOT-2 referencing bh0, txn2,3 in s2
   referencing bh1, txn4,5 in s3 = ROOT_SLOT referencing bh2. */
static void
expect_chain( expect_t exp[ static 6 ],
              uchar    blockhashes[ 4 ][ 32 ],
              uchar    txnhashes[ 6 ][ 20 ] ) {
  for( ulong tx=0UL; tx<6UL; tx++ ) {
    memcpy( exp[ tx ].txnhash,   txnhashes[ tx ],       20UL );
    memcpy( exp[ tx ].blockhash, blockhashes[ tx/2UL ], 32UL );
    exp[ tx ].exec_slot   = ROOT_SLOT-2UL+tx/2UL;
    exp[ tx ].blockhash_i = tx/2UL;
  }
}

#define SINGLE_BUCKET_STALE_CNT (FD_TXNCACHE_TXNS_PER_PAGE-2UL)

/* A full page in one bucket: two rooted transactions separated by stale
   entries.  Walking it crosses the periodic generation check; inserting
   another transaction triggers compaction. */
struct single_bucket {
  test_txncache_t        test_tc;
  fd_txncache_fork_id_t  winner;
  uchar                  blockhash[ 32 ];
  expect_t               exp[ 2 ];
  uchar *                slot_history;
  fd_txncache_writer_t * writer;
  void *                 arena;
  ulong                  arena_sz;
};
typedef struct single_bucket single_bucket_t;

static void
single_bucket_init( single_bucket_t * sb,
                    fd_wksp_t *       wksp ) {
  sb->test_tc = create_txncache_sized( wksp, 1UL, 1UL );
  fd_txncache_t * tc = sb->test_tc.tc;
  FD_TEST( sb->test_tc.shmem->bucket_cnt==1UL );
  FD_TEST( sb->test_tc.shmem->txnpages_per_blockhash_max==1UL );

  memset( sb->blockhash, 0, 32UL );
  sb->blockhash[ 0 ] = 1;
  uchar loser_hash [ 32 ] = {2};
  uchar winner_hash[ 32 ] = {3};
  fd_txncache_fork_id_t root = fd_txncache_attach_child( tc, NULL_FORK );
  fd_txncache_finalize_fork( tc, root, 0UL, sb->blockhash );
  fd_txncache_fork_id_t loser = fd_txncache_attach_child( tc, root );
  sb->winner = fd_txncache_attach_child( tc, root );

  uchar txnhashes[ 2 ][ 32 ] = {{0}};
  for( ulong i=0UL; i<2UL; i++ ) {
    FD_STORE( ulong, txnhashes[ i ], i+1UL );
    txnhashes[ i ][ 8 ] = 0xA5;
    memcpy( sb->exp[ i ].txnhash,   txnhashes[ i ], 20UL );
    memcpy( sb->exp[ i ].blockhash, sb->blockhash,  32UL );
    sb->exp[ i ].exec_slot   = 1UL;
    sb->exp[ i ].blockhash_i = 0UL;
  }

  fd_txncache_insert( tc, sb->winner, sb->blockhash, txnhashes[ 0 ] );
  for( ulong i=0UL; i<SINGLE_BUCKET_STALE_CNT; i++ ) {
    uchar txnhash[ 32 ] = {0};
    FD_STORE( ulong, txnhash, i+10UL );
    fd_txncache_insert( tc, loser, sb->blockhash, txnhash );
  }
  fd_txncache_insert( tc, sb->winner, sb->blockhash, txnhashes[ 1 ] );

  fd_txncache_finalize_fork( tc, loser,      0UL, loser_hash  );
  fd_txncache_finalize_fork( tc, sb->winner, 0UL, winner_hash );
  fd_txncache_advance_root( tc, sb->winner );

  sb->slot_history = test_alloc( wksp, alignof(uchar), FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
  mock_slot_history( sb->slot_history, 1UL, 1UL, NULL, 0UL );
  sb->writer = new_writer( wksp );
  sb->arena  = new_arena( wksp, 4UL, &sb->arena_sz );
}

static fd_txncache_writer_t *
single_bucket_writer_init( single_bucket_t * sb ) {
  FD_TEST( fd_txncache_writer_init( sb->writer, sb->test_tc.tc, sb->winner, 1UL, sb->slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, sb->arena, sb->arena_sz ) );
  return sb->writer;
}

/* parse_and_check parses a serialized status cache and checks that
   every entry is one of exp, appears once, sits in the slot delta of
   its execution slot under its blockhash with offset txnhash_offset and
   an Ok result; that slot events ascend and groups follow blockhash
   descriptor order; that no group is empty (Agave never writes one);
   and that slot_cnt slot deltas are named.  Returns the number of
   groups parsed.  If out_parser is non-NULL the parser is handed to the
   caller (for its slot set) instead of being freed. */
static ulong
parse_and_check( fd_wksp_t *               wksp,
                 uchar const *             buf,
                 ulong                     sz,
                 expect_t *                exp,
                 ulong                     exp_cnt,
                 ulong                     slot_cnt,
                 ulong                     txnhash_offset,
                 fd_slot_delta_parser_t ** out_parser ) {
  void * parser_mem = test_alloc( wksp, fd_slot_delta_parser_align(), fd_slot_delta_parser_footprint() );
  fd_slot_delta_parser_t * parser = fd_slot_delta_parser_join( fd_slot_delta_parser_new( parser_mem ) );
  FD_TEST( parser );
  fd_slot_delta_parser_init( parser );

  for( ulong i=0UL; i<exp_cnt; i++ ) exp[ i ].seen = 0;
  ulong groups = 0UL, entries = 0UL, group_entries = 0UL;
  ulong cur_slot        = ULONG_MAX;
  ulong prev_blockhash_i = ULONG_MAX;
  int   in_group = 0;
  uchar const * p = buf;
  ulong remaining = sz;
  for(;;) {
    fd_slot_delta_parser_advance_result_t result[1];
    int res = fd_slot_delta_parser_consume( parser, p, remaining, result );
    FD_TEST( res>=0 );
    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_DONE || res==FD_SLOT_DELTA_PARSER_ADVANCE_SLOT || res==FD_SLOT_DELTA_PARSER_ADVANCE_GROUP ) {
      if( in_group ) FD_TEST( group_entries>0UL );
      in_group = 0;
    }
    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_DONE ) break;
    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_SLOT ) {
      if( cur_slot!=ULONG_MAX ) FD_TEST( result->slot>cur_slot );
      cur_slot         = result->slot;
      prev_blockhash_i = ULONG_MAX;
    }
    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_GROUP ) {
      FD_TEST( result->group.slot==cur_slot );
      FD_TEST( result->group.txnhash_offset==txnhash_offset );
      ulong blockhash_i = ULONG_MAX;
      for( ulong i=0UL; i<exp_cnt; i++ ) {
        if( exp[ i ].exec_slot==cur_slot && !memcmp( result->group.blockhash, exp[ i ].blockhash, 32UL ) ) {
          blockhash_i = exp[ i ].blockhash_i;
          break;
        }
      }
      FD_TEST( blockhash_i!=ULONG_MAX );
      if( prev_blockhash_i!=ULONG_MAX ) FD_TEST( blockhash_i>prev_blockhash_i );
      prev_blockhash_i = blockhash_i;
      groups++;
      in_group      = 1;
      group_entries = 0UL;
    }
    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_ENTRY ) {
      fd_sstxncache_entry_t const * entry = result->entry;
      expect_t * e = NULL;
      for( ulong i=0UL; i<exp_cnt; i++ ) if( !memcmp( entry->txnhash, exp[ i ].txnhash, 20UL ) ) { e = &exp[ i ]; break; }
      FD_TEST( e && !e->seen );
      e->seen = 1;
      FD_TEST( entry->slot==e->exec_slot );
      FD_TEST( !memcmp( entry->blockhash, e->blockhash, 32UL ) );
      FD_TEST( entry->result==0U );
      entries++;
      group_entries++;
    }
    p         += result->bytes_consumed;
    remaining -= result->bytes_consumed;
  }
  FD_TEST( entries==exp_cnt );
  for( ulong i=0UL; i<exp_cnt; i++ ) FD_TEST( exp[ i ].seen );
  fd_slot_delta_slot_set_t slot_set = fd_slot_delta_parser_slot_set( parser );
  FD_TEST( slot_set.ele_cnt==slot_cnt );

  if( out_parser ) *out_parser = parser;
  else fd_wksp_free_laddr( fd_slot_delta_parser_delete( fd_slot_delta_parser_leave( parser ) ) );
  return groups;
}

static void
test_txncache_writer_arena_sz( void ) {
  FD_LOG_NOTICE(( "test_txncache_writer_arena_sz" ));
  FD_TEST( fd_txncache_writer_arena_sz(  98039UL )==67108864UL );
  FD_TEST( fd_txncache_writer_arena_sz( 838861UL )==67108880UL );
}

static void
test_txncache_roundtrip_empty( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "test_txncache_roundtrip_empty" ));

  test_txncache_t test_tc = create_txncache( wksp );
  fd_txncache_t * tc = test_tc.tc;

  static uchar const blockhash[ 32UL ] = { 0xA1 };
  fd_txncache_fork_id_t root = fd_txncache_attach_child( tc, NULL_FORK );
  fd_txncache_finalize_fork( tc, root, 0UL, blockhash );

  uchar * slot_history = test_alloc( wksp, alignof(uchar), FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
  mock_slot_history( slot_history, ROOT_SLOT, ROOT_SLOT, NULL, 0UL );

  fd_txncache_writer_t * writer = new_writer( wksp );
  ulong arena_sz;
  void * arena = new_arena( wksp, 4UL, &arena_sz );
  FD_TEST( fd_txncache_writer_init( writer, tc, root, ROOT_SLOT, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, arena, arena_sz ) );
  FD_TEST( fd_txncache_writer_serialized_sz( writer )==25UL );

  ulong total_written;
  uchar * buf = serialize_all( wksp, writer, FD_TXNCACHE_WRITER_BUF_MIN, &total_written );
  FD_TEST( total_written==25UL );

  uchar expected[ 25UL ] = {0};
  FD_STORE( ulong, expected,      1UL       );
  FD_STORE( ulong, expected+8UL,  ROOT_SLOT );
  expected[ 16UL ] = 1U;
  FD_STORE( ulong, expected+17UL, 0UL       );
  FD_TEST( !memcmp( buf, expected, sizeof(expected) ) );
  FD_TEST( parse_and_check( wksp, buf, total_written, NULL, 0UL, 1UL, 0UL, NULL )==0UL );
}

static void
test_txncache_roundtrip_genesis_blockhash( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "test_txncache_roundtrip_genesis_blockhash" ));

  test_txncache_t test_tc = create_txncache( wksp );
  fd_txncache_t * tc = test_tc.tc;

  static ulong const snapshot_slot = 1UL;
  static ulong const txnhash_offset = 5UL;
  static uchar const initial_blockhash[ 32UL ] = { 0xA1 };
  static uchar const child_blockhash[ 32UL ]   = { 0xB2 };

  fd_txncache_fork_id_t initial = fd_txncache_attach_child( tc, NULL_FORK );
  fd_txncache_finalize_fork( tc, initial, txnhash_offset, initial_blockhash );

  fd_txncache_fork_id_t child = fd_txncache_attach_child( tc, initial );
  uchar txnhash[ 32UL ];
  for( ulong i=0UL; i<sizeof(txnhash); i++ ) txnhash[ i ] = (uchar)( 0x20UL+i );
  fd_txncache_insert( tc, child, initial_blockhash, txnhash );
  fd_txncache_finalize_fork( tc, child, 0UL, child_blockhash );
  fd_txncache_advance_root( tc, child );

  uchar * slot_history = test_alloc( wksp, alignof(uchar), FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
  mock_slot_history( slot_history, snapshot_slot, snapshot_slot, NULL, 0UL );

  fd_txncache_writer_t * writer = new_writer( wksp );
  ulong arena_sz;
  void * arena = new_arena( wksp, 4UL, &arena_sz );
  FD_TEST( fd_txncache_writer_init( writer, tc, child, snapshot_slot, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, arena, arena_sz ) );
  FD_TEST( fd_txncache_writer_serialized_sz( writer )==97UL );

  ulong total_written;
  uchar * buf = serialize_all( wksp, writer, FD_TXNCACHE_WRITER_BUF_MIN, &total_written );
  FD_TEST( total_written==97UL );

  expect_t exp[ 1 ];
  memset( exp, 0, sizeof(exp) );
  memcpy( exp[ 0 ].txnhash,   txnhash+txnhash_offset, 20UL );
  memcpy( exp[ 0 ].blockhash, initial_blockhash,      32UL );
  exp[ 0 ].exec_slot   = snapshot_slot;
  exp[ 0 ].blockhash_i = 0UL;
  FD_TEST( parse_and_check( wksp, buf, total_written, exp, 1UL, 1UL, txnhash_offset, NULL )==1UL );
}

/* test_txncache_roundtrip writes populate_txncache's chain and checks
   that every transaction lands in the slot delta of the slot it
   executed in, under the blockhash it referenced: the shape Agave
   writes.  The root's own blockhash, which nothing rooted references,
   gets no group. */
static void
test_txncache_roundtrip( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "test_txncache_roundtrip" ));

  test_txncache_t test_tc = create_txncache( wksp );
  fd_txncache_t * tc = test_tc.tc;

  uchar blockhashes[4][32];
  uchar txnhashes[6][20];
  fd_txncache_fork_id_t root = populate_txncache( tc, blockhashes, txnhashes );
  expect_t exp[ 6 ];
  expect_chain( exp, blockhashes, txnhashes );

  uchar * slot_history = test_alloc( wksp, alignof(uchar), FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
  mock_slot_history( slot_history, ROOT_SLOT-3UL, ROOT_SLOT, NULL, 0UL );

  fd_txncache_writer_t * writer = new_writer( wksp );
  ulong  arena_sz = fd_txncache_writer_arena_sz( MAX_TXN_PER_SLOT );
  FD_TEST( arena_sz>=4UL*MAX_TXN_PER_SLOT*20UL );
  void * arena = test_alloc( wksp, fd_txncache_writer_arena_align(), arena_sz );

  FD_TEST( fd_txncache_writer_init( writer, tc, root, ROOT_SLOT, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, arena, arena_sz ) );
  /* 1 slot_deltas_len + 4 slot deltas + 3 groups + 6 txns */
  ulong expected_sz = 8UL + 4UL*17UL + 3UL*48UL + 6UL*24UL;
  FD_TEST( fd_txncache_writer_serialized_sz( writer )==expected_sz );

  ulong   total_written;
  uchar * buf = serialize_all( wksp, writer, FD_TXNCACHE_WRITER_BUF_MIN, &total_written );
  FD_LOG_NOTICE(( "txncache serialized size: %lu", total_written ));
  FD_TEST( total_written==expected_sz );
  FD_TEST( parse_and_check( wksp, buf, total_written, exp, 6UL, 4UL, 0UL, NULL )==3UL );

  /* The output does not depend on the chunking. */
  FD_TEST( fd_txncache_writer_init( writer, tc, root, ROOT_SLOT, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, arena, arena_sz ) );
  ulong   total2;
  uchar * buf2 = serialize_all( wksp, writer, 1UL<<20, &total2 );
  FD_TEST( total2==total_written && !memcmp( buf, buf2, total_written ) );
}

/* test_txncache_roundtrip_slot_history checks that the writer names a
   slot delta for every recent slot that has a block, up to Agave's
   MAX_CACHE_ENTRIES, and skips the slots that do not.  Snapshot load
   walks the same SlotHistory sysvar and rejects the snapshot if any of
   those slots is missing a delta.  The named slots also decide which
   slot each rooted block's transactions are attributed to. */

static void
test_txncache_roundtrip_slot_history( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "test_txncache_roundtrip_slot_history" ));

  test_txncache_t test_tc = create_txncache( wksp );
  fd_txncache_t * tc = test_tc.tc;

  uchar blockhashes[4][32];
  uchar txnhashes[6][20];
  fd_txncache_fork_id_t root = populate_txncache( tc, blockhashes, txnhashes );
  expect_t exp[ 6 ];
  expect_chain( exp, blockhashes, txnhashes );

  /* Two leaders skipped their slot, so the newest MAX_CACHE_ENTRIES
     slots with a block reach two slots further back than a naive
     "snapshot slot minus i" walk would. */

  static ulong const skipped[ 2 ] = { ROOT_SLOT-4UL, ROOT_SLOT-14UL };
  ulong const skipped_cnt  = sizeof(skipped)/sizeof(ulong);
  ulong const oldest_named = ROOT_SLOT+1UL - (FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS+skipped_cnt);

  uchar * slot_history = test_alloc( wksp, alignof(uchar), FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
  mock_slot_history( slot_history, 0UL, ROOT_SLOT, skipped, skipped_cnt );

  fd_txncache_writer_t * writer = new_writer( wksp );
  ulong  arena_sz = fd_txncache_writer_arena_sz( MAX_TXN_PER_SLOT );
  void * arena    = test_alloc( wksp, fd_txncache_writer_arena_align(), arena_sz );
  FD_TEST( fd_txncache_writer_init( writer, tc, root, ROOT_SLOT, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, arena, arena_sz ) );
  ulong   total_written;
  uchar * buf = serialize_all( wksp, writer, FD_TXNCACHE_WRITER_BUF_MIN, &total_written );
  FD_TEST( total_written==8UL + FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS*17UL + 3UL*48UL + 6UL*24UL );
  FD_TEST( total_written==fd_txncache_writer_serialized_sz( writer ) );

  FD_TEST( parse_and_check( wksp, buf, total_written, exp, 6UL, FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS, 0UL, NULL )==3UL );

  /* A real snapshot is taken from a frozen bank whose sysvar cache was
     last refreshed at the start of that block, so the cached SlotHistory
     ends at the snapshot parent and is missing the snapshot slot.  The
     writer must force the snapshot slot back in. */

  mock_slot_history( slot_history, 0UL, ROOT_SLOT-1UL, skipped, skipped_cnt );
  FD_TEST( fd_txncache_writer_init( writer, tc, root, ROOT_SLOT, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, arena, arena_sz ) );
  ulong   stale_written;
  uchar * stale_buf = serialize_all( wksp, writer, FD_TXNCACHE_WRITER_BUF_MIN, &stale_written );
  FD_TEST( stale_written==total_written && !memcmp( stale_buf, buf, total_written ) );

  fd_slot_delta_parser_t * parser;
  FD_TEST( parse_and_check( wksp, stale_buf, stale_written, exp, 6UL, FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS, 0UL, &parser )==3UL );
  fd_slot_delta_slot_set_t slot_set = fd_slot_delta_parser_slot_set( parser );
  ulong snapshot = ROOT_SLOT;
  ulong parent_1 = ROOT_SLOT-1UL;
  ulong parent_2 = ROOT_SLOT-2UL;
  ulong before   = oldest_named-1UL;
  FD_TEST(  slot_set_ele_query( slot_set.map, &snapshot,     NULL, slot_set.pool ) );
  FD_TEST(  slot_set_ele_query( slot_set.map, &parent_1,     NULL, slot_set.pool ) );
  FD_TEST(  slot_set_ele_query( slot_set.map, &parent_2,     NULL, slot_set.pool ) );
  FD_TEST(  slot_set_ele_query( slot_set.map, &oldest_named, NULL, slot_set.pool ) );
  FD_TEST( !slot_set_ele_query( slot_set.map, &skipped[ 0 ], NULL, slot_set.pool ) );
  FD_TEST( !slot_set_ele_query( slot_set.map, &skipped[ 1 ], NULL, slot_set.pool ) );
  FD_TEST( !slot_set_ele_query( slot_set.map, &before,       NULL, slot_set.pool ) );

  /* Any fork but the newest root means replay moved on from the bank
     being snapshotted, which the writer must refuse. */

  fd_txncache_fork_id_t stale = { .val = (ushort)(root.val+1U) };
  FD_TEST( !fd_txncache_writer_init( writer, tc, stale, ROOT_SLOT, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, arena, arena_sz ) );
  FD_TEST( !fd_txncache_writer_init( writer, tc, NULL_FORK, ROOT_SLOT, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, arena, arena_sz ) );

  fd_wksp_free_laddr( fd_slot_delta_parser_delete( fd_slot_delta_parser_leave( parser ) ) );
}

/* test_txncache_roundtrip_large builds a longer chain whose slots hold
   many transactions under two blockhashes each, streams it through
   small output chunks and checks every entry's attribution.  It then
   expects byte-identical output from arenas that fit one or two groups. */

#define LARGE_SLOT_CNT (8UL)
#define LARGE_NEAR_CNT (500UL) /* txns per slot referencing the parent's blockhash */
#define LARGE_FAR_CNT  (300UL) /* txns per slot referencing the grandparent's blockhash */
#define LARGE_EXP_CNT  ((LARGE_SLOT_CNT-1UL)*LARGE_NEAR_CNT+(LARGE_SLOT_CNT-2UL)*LARGE_FAR_CNT)

static void
test_txncache_roundtrip_large( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "test_txncache_roundtrip_large" ));

  test_txncache_t test_tc = create_txncache( wksp );
  fd_txncache_t * tc = test_tc.tc;

  ulong const base_slot = ROOT_SLOT-LARGE_SLOT_CNT+1UL;
  uchar bh[ LARGE_SLOT_CNT ][ 32 ];
  for( ulong i=0UL; i<LARGE_SLOT_CNT; i++ ) { memset( bh[ i ], 0, 32UL ); bh[ i ][ 0 ] = 0xB0; bh[ i ][ 1 ] = (uchar)i; }

  expect_t * exp = test_alloc( wksp, alignof(expect_t), LARGE_EXP_CNT*sizeof(expect_t) );
  ulong exp_cnt = 0UL;

  fd_txncache_fork_id_t fork = fd_txncache_attach_child( tc, NULL_FORK );
  fd_txncache_finalize_fork( tc, fork, 0UL, bh[ 0 ] );
  for( ulong i=1UL; i<LARGE_SLOT_CNT; i++ ) {
    fd_txncache_fork_id_t child = fd_txncache_attach_child( tc, fork );
    for( ulong dist=1UL; dist<=2UL && dist<=i; dist++ ) {
      ulong cnt = dist==1UL ? LARGE_NEAR_CNT : LARGE_FAR_CNT;
      for( ulong k=0UL; k<cnt; k++ ) {
        expect_t * e = &exp[ exp_cnt++ ];
        memset( e->txnhash, 0, 20UL );
        e->txnhash[ 0 ] = 0xEE; e->txnhash[ 1 ] = (uchar)i; e->txnhash[ 2 ] = (uchar)dist;
        FD_STORE( ushort, e->txnhash+3UL, (ushort)k );
        memcpy( e->blockhash, bh[ i-dist ], 32UL );
        e->exec_slot   = base_slot+i;
        e->blockhash_i = i-dist;
        fd_txncache_insert( tc, child, bh[ i-dist ], e->txnhash );
      }
    }
    fd_txncache_finalize_fork( tc, child, 0UL, bh[ i ] );
    fd_txncache_advance_root( tc, child );
    fork = child;
  }
  FD_TEST( exp_cnt==LARGE_EXP_CNT );
  ulong const group_cnt = (LARGE_SLOT_CNT-1UL)+(LARGE_SLOT_CNT-2UL);

  uchar * slot_history = test_alloc( wksp, alignof(uchar), FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
  mock_slot_history( slot_history, base_slot, ROOT_SLOT, NULL, 0UL );

  fd_txncache_writer_t * writer = new_writer( wksp );
  ulong  arena_sz = fd_txncache_writer_arena_sz( MAX_TXN_PER_SLOT );
  void * arena    = test_alloc( wksp, fd_txncache_writer_arena_align(), arena_sz );
  FD_TEST( fd_txncache_writer_init( writer, tc, fork, ROOT_SLOT, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, arena, arena_sz ) );
  ulong expected_sz = 8UL + LARGE_SLOT_CNT*17UL + group_cnt*48UL + LARGE_EXP_CNT*24UL;
  FD_TEST( fd_txncache_writer_serialized_sz( writer )==expected_sz );
  ulong   total_written;
  uchar * buf = serialize_all( wksp, writer, FD_TXNCACHE_WRITER_BUF_MIN, &total_written );
  FD_TEST( total_written==expected_sz );
  FD_TEST( parse_and_check( wksp, buf, total_written, exp, exp_cnt, LARGE_SLOT_CNT, 0UL, NULL )==group_cnt );

  ulong  small_sz;
  void * small = new_arena( wksp, LARGE_NEAR_CNT+LARGE_FAR_CNT, &small_sz );
  FD_TEST( fd_txncache_writer_init( writer, tc, fork, ROOT_SLOT, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, small, small_sz ) );
  ulong   total_small;
  uchar * buf_small = serialize_all( wksp, writer, 1UL<<20, &total_small );
  FD_TEST( total_small==total_written && !memcmp( buf, buf_small, total_written ) );

  ulong  exact_sz;
  void * exact = new_arena( wksp, LARGE_NEAR_CNT, &exact_sz );
  FD_TEST( fd_txncache_writer_init( writer, tc, fork, ROOT_SLOT, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, exact, exact_sz ) );
  ulong   total_exact;
  uchar * buf_exact = serialize_all( wksp, writer, FD_TXNCACHE_WRITER_BUF_MIN, &total_exact );
  FD_TEST( total_exact==total_written && !memcmp( buf, buf_exact, total_written ) );
}

static void
test_txncache_roundtrip_many_roots( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "test_txncache_roundtrip_many_roots" ));

  test_txncache_t test_tc = create_txncache( wksp );
  fd_txncache_t * tc = test_tc.tc;

  ulong const root_slot = 1000UL;
  ulong const chunk_sz  = 48UL<<10;
  ulong const hold_cnt  = chunk_sz/24UL+1UL; /* the group alone overflows one output chunk */
  FD_TEST( hold_cnt<=MAX_TXN_PER_SLOT*FD_TXNCACHE_MAX_SLOT_DELTAS );

  uchar * slot_history = test_alloc( wksp, alignof(uchar), FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
  fd_txncache_writer_t * writer = new_writer( wksp );
  ulong  arena_sz = fd_txncache_writer_arena_sz( MAX_TXN_PER_SLOT );
  void * arena    = test_alloc( wksp, fd_txncache_writer_arena_align(), arena_sz );

  /* Linear chain, snapin style: attach, finalize, advance. */
  fd_txncache_fork_id_t fork = fd_txncache_attach_child( tc, NULL_FORK );
  uchar bh[ 32 ]; memset( bh, 0, 32UL ); FD_STORE( ulong, bh, 1UL );
  fd_txncache_finalize_fork( tc, fork, 0UL, bh );
  uchar ref_bh[ 32 ];
  ulong slot = 0UL;

  ulong const step_cnt = 2UL*FD_TXNCACHE_MAX_SLOT_DELTAS;
  for( ulong i=1UL; i<=step_cnt; i++ ) {
    fd_txncache_fork_id_t child = fd_txncache_attach_child( tc, fork );
    if( i==step_cnt ) { /* big group referencing the previous root's blockhash */
      memcpy( ref_bh, bh, 32UL );
      for( ulong t=0UL; t<hold_cnt; t++ ) {
        uchar txnhash[ 32 ]; memset( txnhash, 0, 32UL ); FD_STORE( ulong, txnhash, t+1UL ); txnhash[ 8 ] = 0xEE;
        fd_txncache_insert( tc, child, bh, txnhash );
      }
    }
    memset( bh, 0, 32UL ); FD_STORE( ulong, bh, i+1UL );
    fd_txncache_finalize_fork( tc, child, 0UL, bh );
    fd_txncache_advance_root( tc, child );
    fork = child;
    slot = root_slot+i;
  }

  /* Serialize the steady state with a large chunk and parse it back. */
  mock_slot_history( slot_history, 0UL, slot, NULL, 0UL );
  FD_TEST( fd_txncache_writer_init( writer, tc, fork, slot, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, arena, arena_sz ) );
  ulong expected_sz = 8UL + 300UL*17UL + 48UL + hold_cnt*24UL;
  FD_TEST( fd_txncache_writer_serialized_sz( writer )==expected_sz );
  ulong   total_written;
  uchar * buf = serialize_all( wksp, writer, chunk_sz, &total_written );
  FD_TEST( total_written==expected_sz );

  void * parser_mem = test_alloc( wksp, fd_slot_delta_parser_align(), fd_slot_delta_parser_footprint() );
  fd_slot_delta_parser_t * parser = fd_slot_delta_parser_join( fd_slot_delta_parser_new( parser_mem ) );
  FD_TEST( parser );
  fd_slot_delta_parser_init( parser );

  ulong groups_parsed = 0UL, entries_parsed = 0UL, slots_parsed = 0UL;
  uchar const * p = buf;
  ulong remaining = total_written;
  for(;;) {
    fd_slot_delta_parser_advance_result_t result[1];
    int res = fd_slot_delta_parser_consume( parser, p, remaining, result );
    FD_TEST( res>=0 );
    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_DONE ) break;
    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_SLOT  ) slots_parsed++;
    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_GROUP ) {
      FD_TEST( result->group.slot==slot );
      FD_TEST( !memcmp( result->group.blockhash, ref_bh, 32UL ) );
      groups_parsed++;
    }
    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_ENTRY ) {
      FD_TEST( result->entry->slot==slot );
      FD_TEST( !memcmp( result->entry->blockhash, ref_bh, 32UL ) );
      entries_parsed++;
    }
    p         += result->bytes_consumed;
    remaining -= result->bytes_consumed;
  }
  FD_TEST( slots_parsed==300UL );
  FD_TEST( groups_parsed==1UL );
  FD_TEST( entries_parsed==hold_cnt );
  FD_LOG_NOTICE(( "parsed %lu entries across %lu groups", entries_parsed, groups_parsed ));

  fd_wksp_free_laddr( fd_slot_delta_parser_delete( fd_slot_delta_parser_leave( parser ) ) );
}

static void
test_txncache_writer_rejects_excess_descriptors( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "test_txncache_writer_rejects_excess_descriptors" ));

  test_txncache_t test_tc = create_txncache( wksp );
  fd_txncache_t * tc = test_tc.tc;

  uchar blockhashes[ 3UL ][ 32UL ] = {{0}};
  for( ulong i=0UL; i<3UL; i++ ) blockhashes[ i ][ 0 ] = (uchar)( 0xA0UL+i );

  fd_txncache_fork_id_t fork = fd_txncache_attach_child( tc, NULL_FORK );
  fd_txncache_finalize_fork( tc, fork, 0UL, blockhashes[ 0UL ] );
  for( ulong i=1UL; i<3UL; i++ ) {
    fd_txncache_fork_id_t child = fd_txncache_attach_child( tc, fork );
    fd_txncache_finalize_fork( tc, child, 0UL, blockhashes[ i ] );
    fd_txncache_advance_root( tc, child );
    fork = child;
  }

  static ulong const snapshot_slot = 2UL;
  uchar * slot_history = test_alloc( wksp, alignof(uchar), FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
  mock_slot_history( slot_history, snapshot_slot, snapshot_slot, NULL, 0UL );

  fd_txncache_writer_t * writer = new_writer( wksp );
  ulong arena_sz;
  void * arena = new_arena( wksp, 4UL, &arena_sz );
  FD_TEST( !fd_txncache_writer_init( writer, tc, fork, snapshot_slot, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, arena, arena_sz ) );
}

static void
test_txncache_writer_root_advance_is_fatal( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "test_txncache_writer_root_advance_is_fatal" ));
  single_bucket_t fixture[ 1 ];
  single_bucket_init( fixture, wksp );
  fd_txncache_t * tc = fixture->test_tc.tc;
  fd_txncache_writer_t * writer = single_bucket_writer_init( fixture );
  uchar next_hash[ 32 ] = {4};
  fd_txncache_fork_id_t next = fd_txncache_attach_child( tc, fixture->winner );
  fd_txncache_finalize_fork( tc, next, 0UL, next_hash );
  fd_txncache_advance_root( tc, next );

  FILE * diagnostic = tmpfile();
  FD_TEST( diagnostic );
  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( pid==0 ) {
    FD_TEST( dup2( fileno( diagnostic ), STDERR_FILENO )==STDERR_FILENO );
    fd_log_level_logfile_set( 5 );
    fd_log_level_stderr_set( 5 );
    fd_log_level_core_set( 6 );
    uchar buf[ FD_TXNCACHE_WRITER_BUF_MIN ];
    while( fd_txncache_writer_serialize( writer, buf, sizeof(buf) ) ) {}
    _exit( 0 );
  }
  int status = 0;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( WIFEXITED( status ) && WEXITSTATUS( status )==1 );
  rewind( diagnostic );
  char message[ 1024 ];
  ulong message_sz = fread( message, 1UL, sizeof(message)-1UL, diagnostic );
  FD_TEST( !ferror( diagnostic ) );
  message[ message_sz ] = '\0';
  FD_TEST( strstr( message, "txncache root advanced while snapshot of slot 1 was in progress" ) );
  FD_TEST( !fclose( diagnostic ) );
}

#define STRESS_CANCEL_CYCLES (1024UL)

/* Repeatedly insert transactions from a temporary child into the
   root's blockhash cache, then cancel the child. */
struct cancel_mutator {
  fd_txncache_t *       tc;
  fd_txncache_fork_id_t root;
  uchar                 blockhash[ 32 ];
  atomic_ulong          cancel_cnt;
};

static void *
cancel_mutator_run( void * arg ) {
  struct cancel_mutator * m = arg;
  for( ulong n=0UL; n<STRESS_CANCEL_CYCLES; n++ ) {
    fd_txncache_fork_id_t child = fd_txncache_attach_child( m->tc, m->root );
    for( ulong t=0UL; t<8UL; t++ ) {
      uchar txnhash[ 32 ]; memset( txnhash, 0, 32UL ); FD_STORE( ulong, txnhash, n*8UL+t+1UL ); txnhash[ 8 ] = 0xC7;
      fd_txncache_insert( m->tc, child, m->blockhash, txnhash );
    }
    fd_txncache_cancel_fork( m->tc, child );
    atomic_store_explicit( &m->cancel_cnt, n+1UL, memory_order_release );
    FD_YIELD();
  }
  return NULL;
}

/* This best-effort real-hardware concurrency smoke test starts a
   cancellation thread, then repeatedly serializes the rooted set.  The
   scheduler may or may not overlap those operations.  The RaceSan
   tests below control the relevant schedules deterministically. */
static void
stress_txncache_writer_concurrent_cancels( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "stress_txncache_writer_concurrent_cancels" ));
  test_txncache_t test_tc = create_txncache( wksp );
  fd_txncache_t * tc = test_tc.tc;

  uchar blockhashes[4][32];
  uchar txnhashes[6][20];
  fd_txncache_fork_id_t root = populate_txncache( tc, blockhashes, txnhashes );

  uchar * slot_history = test_alloc( wksp, alignof(uchar), FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
  mock_slot_history( slot_history, ROOT_SLOT-3UL, ROOT_SLOT, NULL, 0UL );
  fd_txncache_writer_t * writer = new_writer( wksp );
  ulong  arena_sz;
  void * arena = new_arena( wksp, 64UL, &arena_sz );

  FD_TEST( fd_txncache_writer_init( writer, tc, root, ROOT_SLOT, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, arena, arena_sz ) );
  ulong   base_sz;
  uchar * base = serialize_all( wksp, writer, FD_TXNCACHE_WRITER_BUF_MIN, &base_sz );
  struct cancel_mutator m = { .tc = tc, .root = root, .cancel_cnt = 0UL };
  memcpy( m.blockhash, blockhashes[ 3 ], 32UL ); /* the root's own blockhash */
  pthread_t thread;
  FD_TEST( !pthread_create( &thread, NULL, cancel_mutator_run, &m ) );
  while( !atomic_load_explicit( &m.cancel_cnt, memory_order_acquire ) ) FD_YIELD();

  ulong iter_cnt = 0UL;
  do {
    FD_TEST( fd_txncache_writer_init( writer, tc, root, ROOT_SLOT, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, arena, arena_sz ) );
    ulong   sz;
    uchar * buf = serialize_all( wksp, writer, FD_TXNCACHE_WRITER_BUF_MIN, &sz );
    FD_TEST( sz==base_sz && !memcmp( buf, base, sz ) );
    fd_wksp_free_laddr( buf );
    iter_cnt++;
  } while( atomic_load_explicit( &m.cancel_cnt, memory_order_acquire )<STRESS_CANCEL_CYCLES );
  FD_TEST( !pthread_join( thread, NULL ) );
  FD_LOG_NOTICE(( "best-effort concurrency smoke test: %lu serializations overlapped %lu cancels", iter_cnt, STRESS_CANCEL_CYCLES ));
}

#define STRESS_COMPACT_CYCLES (256UL)

/* Each cycle fills the rooted blockcache's only txnpage from a child
   fork and cancels the child, so the next cycle's first insert finds
   the page full of stale entries and compacts it under the mutation
   bracket, rewriting in place the chain the serializer may be
   walking. */
struct compact_mutator {
  fd_txncache_t *       tc;
  fd_txncache_fork_id_t root;
  uchar                 blockhash[ 32 ];
  atomic_ulong          cycle_cnt;
};

static void *
compact_mutator_run( void * arg ) {
  struct compact_mutator * mutator = arg;
  for( ulong cycle=0UL; cycle<STRESS_COMPACT_CYCLES; cycle++ ) {
    fd_txncache_fork_id_t child = fd_txncache_attach_child( mutator->tc, mutator->root );
    for( ulong txn_idx=0UL; txn_idx<SINGLE_BUCKET_STALE_CNT; txn_idx++ ) {
      uchar txnhash[ 32 ] = {0};
      FD_STORE( ulong, txnhash, cycle*SINGLE_BUCKET_STALE_CNT+txn_idx+1UL );
      txnhash[ 8 ] = 0xC7;
      fd_txncache_insert( mutator->tc, child, mutator->blockhash, txnhash );
    }
    fd_txncache_cancel_fork( mutator->tc, child );
    atomic_store_explicit( &mutator->cycle_cnt, cycle+1UL, memory_order_release );
  }
  return NULL;
}

/* Compaction may reorder transactions within a group.  Compare parsed
   entries, since bytewise comparison would reject valid snapshots. */
static void
stress_txncache_writer_concurrent_compaction( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "stress_txncache_writer_concurrent_compaction" ));
  single_bucket_t sb[ 1 ];
  single_bucket_init( sb, wksp );

  ulong mutation_gen = sb->test_tc.shmem->mutation_gen;

  struct compact_mutator mutator = { .tc = sb->test_tc.tc, .root = sb->winner, .cycle_cnt = 0UL };
  memcpy( mutator.blockhash, sb->blockhash, 32UL );
  int log_level_stderr = fd_log_level_stderr();
  fd_log_level_stderr_set( 4 );
  pthread_t thread;
  FD_TEST( !pthread_create( &thread, NULL, compact_mutator_run, &mutator ) );

  ulong iter_cnt = 0UL;
  do {
    fd_txncache_writer_t * writer = single_bucket_writer_init( sb );
    ulong   sz;
    uchar * buf = serialize_all( wksp, writer, FD_TXNCACHE_WRITER_BUF_MIN, &sz );
    FD_TEST( parse_and_check( wksp, buf, sz, sb->exp, 2UL, 1UL, 0UL, NULL )==1UL );
    fd_wksp_free_laddr( buf );
    iter_cnt++;
  } while( atomic_load_explicit( &mutator.cycle_cnt, memory_order_acquire )<STRESS_COMPACT_CYCLES );
  FD_TEST( !pthread_join( thread, NULL ) );
  fd_log_level_stderr_set( log_level_stderr );

  FD_TEST( sb->test_tc.shmem->mutation_gen==mutation_gen+2UL*STRESS_COMPACT_CYCLES );
  FD_LOG_NOTICE(( "concurrency smoke test: %lu serializations, %lu compactions (overlap not guaranteed)", iter_cnt, STRESS_COMPACT_CYCLES ));
}

#if FD_HAS_RACESAN

struct cancel_inject {
  fd_txncache_t *       tc;
  fd_txncache_fork_id_t root;
  uchar                 blockhash[ 32 ];
  ulong                 cancel_cnt;
};

static void
inject_cancel( void * ctx,
               ulong  name_hash ) {
  (void)name_hash;
  struct cancel_inject * inject = ctx;

  fd_txncache_fork_id_t child = fd_txncache_attach_child( inject->tc, inject->root );
  uchar txnhash[ 32 ] = {0};
  FD_STORE( ulong, txnhash, ++inject->cancel_cnt );
  fd_txncache_insert( inject->tc, child, inject->blockhash, txnhash );
  fd_txncache_cancel_fork( inject->tc, child );
}

/* Force an unrooted cancellation between a bucket's generation reads.
   Since cancellation does not change the rooted transaction set, the
   writer must finish even when this happens at every retry point. */
static void
test_txncache_writer_ignores_unrooted_cancellation( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "test_txncache_writer_ignores_unrooted_cancellation" ));
  test_txncache_t test_tc = create_txncache( wksp );
  fd_txncache_t * tc = test_tc.tc;

  uchar blockhashes[ 4 ][ 32 ];
  uchar txnhashes  [ 6 ][ 20 ];
  fd_txncache_fork_id_t root = populate_txncache( tc, blockhashes, txnhashes );
  expect_t exp[ 6 ];
  expect_chain( exp, blockhashes, txnhashes );

  uchar * slot_history = test_alloc( wksp, alignof(uchar), FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
  mock_slot_history( slot_history, ROOT_SLOT-3UL, ROOT_SLOT, NULL, 0UL );

  fd_txncache_writer_t * writer = new_writer( wksp );
  ulong  arena_sz;
  void * arena = new_arena( wksp, 64UL, &arena_sz );

  struct cancel_inject inject = {
    .tc         = tc,
    .root       = root,
    .cancel_cnt = 0UL
  };
  memcpy( inject.blockhash, blockhashes[ 3 ], sizeof(inject.blockhash) );

  fd_racesan_t racesan[ 1 ];
  FD_TEST( fd_racesan_new( racesan, &inject ) );
  fd_racesan_inject( racesan, "txncache_writer:bucket_started", inject_cancel );
  FD_RACESAN_INJECT_BEGIN( racesan ) {
    FD_TEST( fd_txncache_writer_init( writer, tc, root, ROOT_SLOT, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, arena, arena_sz ) );
  } FD_RACESAN_INJECT_END;
  FD_TEST( inject.cancel_cnt );

  ulong   sz;
  uchar * buf = serialize_all( wksp, writer, FD_TXNCACHE_WRITER_BUF_MIN, &sz );
  FD_TEST( parse_and_check( wksp, buf, sz, exp, 6UL, 4UL, 0UL, NULL )==3UL );

  fd_racesan_delete( racesan );
}

struct spin_inject {
  fd_txncache_shmem_t * shmem;
  int                   begun;
  int                   ended;
};

static void
inject_spin_begin( void * ctx,
                   ulong  name_hash ) {
  (void)name_hash;
  struct spin_inject * inject = ctx;
  if( inject->begun ) return;
  inject->begun = 1;
  fd_txncache_mutation_begin( inject->shmem );
}

static void
inject_spin_end( void * ctx,
                 ulong  name_hash ) {
  (void)name_hash;
  struct spin_inject * inject = ctx;
  FD_TEST( inject->begun && !inject->ended );
  inject->ended = 1;
  fd_txncache_mutation_end( inject->shmem );
}

/* A mutation begins right after a walk attempt read an even
   generation.  That attempt must fail its final check, and the retry
   must wait for the mutation to end (odd generation) instead of
   reading the storage. */
static void
test_txncache_writer_waits_for_mutation_end( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "test_txncache_writer_waits_for_mutation_end" ));
  test_txncache_t test_tc = create_txncache( wksp );
  fd_txncache_t * tc = test_tc.tc;

  uchar blockhashes[ 4 ][ 32 ];
  uchar txnhashes  [ 6 ][ 20 ];
  fd_txncache_fork_id_t root = populate_txncache( tc, blockhashes, txnhashes );
  expect_t exp[ 6 ];
  expect_chain( exp, blockhashes, txnhashes );

  uchar * slot_history = test_alloc( wksp, alignof(uchar), FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
  mock_slot_history( slot_history, ROOT_SLOT-3UL, ROOT_SLOT, NULL, 0UL );
  fd_txncache_writer_t * writer = new_writer( wksp );
  ulong  arena_sz;
  void * arena = new_arena( wksp, 64UL, &arena_sz );

  struct spin_inject inject = { .shmem = test_tc.shmem };
  fd_racesan_t racesan[ 1 ];
  FD_TEST( fd_racesan_new( racesan, &inject ) );
  fd_racesan_inject( racesan, "txncache_writer:bucket_started",       inject_spin_begin );
  fd_racesan_inject( racesan, "txncache_writer:mutation_in_progress", inject_spin_end   );
  ulong mutation_gen = test_tc.shmem->mutation_gen;
  FD_RACESAN_INJECT_BEGIN( racesan ) {
    FD_TEST( fd_txncache_writer_init( writer, tc, root, ROOT_SLOT, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, arena, arena_sz ) );
  } FD_RACESAN_INJECT_END;
  FD_TEST( inject.begun && inject.ended );
  FD_TEST( test_tc.shmem->mutation_gen==mutation_gen+2UL );

  ulong   sz;
  uchar * buf = serialize_all( wksp, writer, FD_TXNCACHE_WRITER_BUF_MIN, &sz );
  FD_TEST( parse_and_check( wksp, buf, sz, exp, 6UL, 4UL, 0UL, NULL )==3UL );

  fd_racesan_delete( racesan );
}

struct compact_inject {
  fd_txncache_t *       tc;
  fd_txncache_fork_id_t fork;
  uchar                 blockhash[ 32 ];
  uchar                 txnhash[ 32 ];
  int                   fired;
};

static void
inject_compaction( void * ctx,
                   ulong  name_hash ) {
  (void)name_hash;
  struct compact_inject * inject = ctx;
  if( inject->fired ) return;
  inject->fired = 1;
  fd_txncache_insert( inject->tc, inject->fork, inject->blockhash, inject->txnhash );
}

static void
test_txncache_writer_retries_compaction( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "test_txncache_writer_retries_compaction" ));
  single_bucket_t sb[ 1 ];
  single_bucket_init( sb, wksp );
  fd_txncache_t * tc = sb->test_tc.tc;
  fd_txncache_fork_id_t child = fd_txncache_attach_child( tc, sb->winner );
  fd_txncache_writer_t * writer = single_bucket_writer_init( sb );

  struct compact_inject inject = {
    .tc    = tc,
    .fork  = child,
    .fired = 0
  };
  memcpy( inject.blockhash, sb->blockhash, 32UL );
  memset( inject.txnhash, 0xEE, 32UL );

  fd_racesan_t racesan[ 1 ];
  FD_TEST( fd_racesan_new( racesan, &inject ) );
  fd_racesan_inject( racesan, "txncache_writer:txnhash_staged", inject_compaction );
  ulong   mutation_gen = sb->test_tc.shmem->mutation_gen;
  ulong   sz           = 0UL;
  uchar * buf          = NULL;
  FD_RACESAN_INJECT_BEGIN( racesan ) {
    buf = serialize_all( wksp, writer, FD_TXNCACHE_WRITER_BUF_MIN, &sz );
  } FD_RACESAN_INJECT_END;
  FD_TEST( inject.fired );
  FD_TEST( sb->test_tc.shmem->mutation_gen==mutation_gen+2UL );
  FD_TEST( parse_and_check( wksp, buf, sz, sb->exp, 2UL, 1UL, 0UL, NULL )==1UL );

  fd_racesan_delete( racesan );
}

struct bracket_inject {
  fd_txncache_shmem_t * shmem;
  ulong                 attempt_cnt;
  ulong                 staged_cnt;
  ulong                 bracket_max;
  int                   bracketed;
};

static void
inject_bracket_attempt( void * ctx,
                        ulong  name_hash ) {
  (void)name_hash;
  struct bracket_inject * inject = ctx;
  inject->attempt_cnt++;
  inject->bracketed = 0;
}

/* Brackets an empty mutation at the first staged transaction of each
   of the first bracket_max walk attempts, as a compaction of some other
   blockcache would. */
static void
inject_bracket_staged( void * ctx,
                       ulong  name_hash ) {
  (void)name_hash;
  struct bracket_inject * inject = ctx;
  inject->staged_cnt++;
  if( inject->bracketed || inject->attempt_cnt>inject->bracket_max ) return;
  inject->bracketed = 1;
  fd_txncache_mutation_begin( inject->shmem );
  fd_txncache_mutation_end  ( inject->shmem );
}

/* Each interrupted attempt stages only the head transaction before the
   periodic check aborts the walk.  The successful retry stages both. */
static void
test_txncache_writer_retries_at_periodic_check( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "test_txncache_writer_retries_at_periodic_check" ));
  single_bucket_t sb[ 1 ];
  single_bucket_init( sb, wksp );
  fd_txncache_writer_t * writer = single_bucket_writer_init( sb );

  ulong const bracket_max = 3UL;
  struct bracket_inject inject = { .shmem = sb->test_tc.shmem, .bracket_max = bracket_max };
  fd_racesan_t racesan[ 1 ];
  FD_TEST( fd_racesan_new( racesan, &inject ) );
  fd_racesan_inject( racesan, "txncache_writer:bucket_started", inject_bracket_attempt );
  fd_racesan_inject( racesan, "txncache_writer:txnhash_staged", inject_bracket_staged  );
  ulong   mutation_gen = sb->test_tc.shmem->mutation_gen;
  ulong   sz           = 0UL;
  uchar * buf          = NULL;
  FD_RACESAN_INJECT_BEGIN( racesan ) {
    buf = serialize_all( wksp, writer, FD_TXNCACHE_WRITER_BUF_MIN, &sz );
  } FD_RACESAN_INJECT_END;

  FD_TEST( inject.attempt_cnt==bracket_max+1UL );
  FD_TEST( inject.staged_cnt ==bracket_max+2UL );
  FD_TEST( sb->test_tc.shmem->mutation_gen==mutation_gen+2UL*bracket_max );
  FD_TEST( parse_and_check( wksp, buf, sz, sb->exp, 2UL, 1UL, 0UL, NULL )==1UL );

  fd_racesan_delete( racesan );
}

struct cycle_inject {
  fd_txncache_shmem_t *      shmem;
  fd_txncache_single_txn_t * txn;
  uint                       head;
  uint                       next;
  int                        installed;
  int                        repaired;
  ulong                      staged_cnt;
};

static void
inject_cycle( void * ctx,
              ulong  name_hash ) {
  (void)name_hash;
  struct cycle_inject * inject = ctx;
  if( inject->installed ) return;
  inject->txn->blockcache_next = inject->head;
  inject->installed = 1;
}

static void
count_staged( void * ctx,
              ulong  name_hash ) {
  (void)name_hash;
  struct cycle_inject * inject = ctx;
  inject->staged_cnt++;
}

static void
repair_cycle( void * ctx,
              ulong  name_hash ) {
  (void)name_hash;
  struct cycle_inject * inject = ctx;
  FD_TEST( inject->installed && !inject->repaired );
  fd_txncache_mutation_begin( inject->shmem );
  inject->txn->blockcache_next = inject->next;
  fd_txncache_mutation_end( inject->shmem );
  inject->repaired = 1;
}

/* Count detects the self-loop at the chain-length bound; fill detects it
   at the group-size bound.  Both must retry when the generation changes. */
static void
test_txncache_writer_retries_transient_cycle( fd_wksp_t * wksp,
                                              int         during_fill ) {
  FD_LOG_NOTICE(( "test_txncache_writer_retries_transient_cycle (%s)", during_fill ? "fill" : "count" ));
  test_txncache_t test_tc = create_txncache_sized( wksp, 1UL, 1UL );
  fd_txncache_t * tc = test_tc.tc;

  uchar blockhash[ 32 ] = {1};
  uchar winner_hash[ 32 ] = {2};
  uchar txnhash[ 32 ] = {0};
  txnhash[ 0 ] = 7U;
  txnhash[ 8 ] = 0xA7;
  fd_txncache_fork_id_t root = fd_txncache_attach_child( tc, NULL_FORK );
  fd_txncache_finalize_fork( tc, root, 0UL, blockhash );
  fd_txncache_fork_id_t winner = fd_txncache_attach_child( tc, root );
  fd_txncache_insert( tc, winner, blockhash, txnhash );
  fd_txncache_finalize_fork( tc, winner, 0UL, winner_hash );
  fd_txncache_advance_root( tc, winner );

  uint head = tc->blockcache_pool[ root.val ].heads[ 0 ];
  FD_TEST( head!=UINT_MAX );
  fd_txncache_single_txn_t * txn = tc->txnpages[ head/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ head%FD_TXNCACHE_TXNS_PER_PAGE ];

  struct cycle_inject inject = {
    .shmem = test_tc.shmem,
    .txn   = txn,
    .head  = head,
    .next  = txn->blockcache_next
  };

  uchar * slot_history = test_alloc( wksp, alignof(uchar), FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
  mock_slot_history( slot_history, 1UL, 1UL, NULL, 0UL );
  fd_txncache_writer_t * writer = new_writer( wksp );
  ulong  arena_sz;
  void * arena = new_arena( wksp, 4UL, &arena_sz );

  fd_racesan_t racesan[ 1 ];
  FD_TEST( fd_racesan_new( racesan, &inject ) );
  fd_racesan_inject( racesan, "txncache_writer:bucket_started",   inject_cycle );
  fd_racesan_inject( racesan, "txncache_writer:txnhash_staged",   count_staged );
  fd_racesan_inject( racesan, "txncache_writer:anomaly_detected", repair_cycle );
  ulong   mutation_gen = test_tc.shmem->mutation_gen;
  ulong   sz           = 0UL;
  uchar * buf          = NULL;
  if( !during_fill ) {
    FD_RACESAN_INJECT_BEGIN( racesan ) {
      FD_TEST( fd_txncache_writer_init( writer, tc, winner, 1UL, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, arena, arena_sz ) );
    } FD_RACESAN_INJECT_END;
    buf = serialize_all( wksp, writer, FD_TXNCACHE_WRITER_BUF_MIN, &sz );
  } else {
    FD_TEST( fd_txncache_writer_init( writer, tc, winner, 1UL, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, arena, arena_sz ) );
    FD_RACESAN_INJECT_BEGIN( racesan ) {
      buf = serialize_all( wksp, writer, FD_TXNCACHE_WRITER_BUF_MIN, &sz );
    } FD_RACESAN_INJECT_END;
    FD_TEST( inject.staged_cnt==2UL );
  }
  FD_TEST( inject.installed && inject.repaired );
  FD_TEST( test_tc.shmem->mutation_gen==mutation_gen+2UL );

  expect_t exp[ 1 ] = {{
    .exec_slot   = 1UL,
    .blockhash_i = 0UL
  }};
  memcpy( exp->txnhash,   txnhash,   20UL );
  memcpy( exp->blockhash, blockhash, 32UL );
  FD_TEST( parse_and_check( wksp, buf, sz, exp, 1UL, 1UL, 0UL, NULL )==1UL );

  fd_racesan_delete( racesan );
}

#endif

int
main( int     argc,
      char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  limits->wksp_addl_sz       = TEST_WKSP_ADDL_SZ;
  limits->wksp_addl_part_cnt = TEST_WKSP_ADDL_PART_CNT;
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );
  FD_TEST( mini );
  fd_wksp_t * wksp = mini->wksp;

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

  test_manifest_roundtrip( wksp, bank );
  test_allocs_reclaim( wksp );
  test_txncache_writer_arena_sz();
  test_txncache_roundtrip_empty( wksp );
  test_allocs_reclaim( wksp );
  test_txncache_roundtrip_genesis_blockhash( wksp );
  test_allocs_reclaim( wksp );
  test_txncache_roundtrip( wksp );
  test_allocs_reclaim( wksp );
  test_txncache_roundtrip_slot_history( wksp );
  test_allocs_reclaim( wksp );
  test_txncache_roundtrip_large( wksp );
  test_allocs_reclaim( wksp );
  test_txncache_roundtrip_many_roots( wksp );
  test_allocs_reclaim( wksp );
  stress_txncache_writer_concurrent_cancels( wksp );
  test_allocs_reclaim( wksp );
  stress_txncache_writer_concurrent_compaction( wksp );
  test_allocs_reclaim( wksp );
#if FD_HAS_RACESAN
  test_txncache_writer_ignores_unrooted_cancellation( wksp );
  test_allocs_reclaim( wksp );
  test_txncache_writer_waits_for_mutation_end( wksp );
  test_allocs_reclaim( wksp );
  test_txncache_writer_retries_compaction( wksp );
  test_allocs_reclaim( wksp );
  test_txncache_writer_retries_at_periodic_check( wksp );
  test_allocs_reclaim( wksp );
  test_txncache_writer_retries_transient_cycle( wksp, 0 );
  test_allocs_reclaim( wksp );
  test_txncache_writer_retries_transient_cycle( wksp, 1 );
  test_allocs_reclaim( wksp );
#endif
  test_txncache_writer_rejects_excess_descriptors( wksp );
  test_allocs_reclaim( wksp );
  test_txncache_writer_root_advance_is_fatal( wksp );
  test_allocs_reclaim( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
