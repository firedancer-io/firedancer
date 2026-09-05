#include "fd_ssmanifest_writer.h"
#include "fd_txncache_writer.h"
#include "../restore/utils/fd_ssmanifest_parser.h"
#include "../restore/utils/fd_slot_delta_parser.h"
#include "../../flamenco/runtime/tests/fd_svm_mini.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/runtime/fd_txncache_shmem.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_slot_history.h"

#include <stdlib.h>
#include <string.h>

#define MAX_LIVE_SLOTS      16UL
#define MAX_TXN_PER_SLOT    4096UL
#define VALIDATOR_CNT       3UL
#define ROOT_SLOT           474UL /* epoch 1 with 432 slots/epoch */
#define EPOCH_CREDITS_CNT   3UL

/* The writer emits one slot delta per recent slot with a block, so the
   parser must accept at least that many. */

FD_STATIC_ASSERT( FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS<=FD_SLOT_DELTA_MAX_ENTRIES, slot_delta_cnt );

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
  uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
  fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_1, iter_mem );
  FD_TEST( !fd_vote_stakes_iter_done( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_1, iter ) );
  fd_pubkey_t vote0;
  fd_vote_stakes_iter_ele( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_1, iter, &vote0, NULL, NULL,
                           NULL, NULL, NULL, NULL, NULL, NULL );
  fd_vote_stakes_iter_next( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_1, iter );
  FD_TEST( !fd_vote_stakes_iter_done( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_1, iter ) );
  fd_pubkey_t vote1;
  fd_vote_stakes_iter_ele( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_1, iter, &vote1, NULL, NULL,
                           NULL, NULL, NULL, NULL, NULL, NULL );

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

/* serialize_all drives writer to completion into a malloc'd buffer,
   honoring placeholder/patch chunks the way snapmk does with raw
   Zstandard frames and pwrite.  chunk_sz is the output buffer offered
   per call.  Returns the buffer and its size in *out_sz. */

static uchar *
serialize_all( fd_txncache_writer_t * writer,
               ulong                  chunk_sz,
               ulong *                out_sz ) {
  uchar * chunk = malloc( chunk_sz );
  FD_TEST( chunk );
  ulong   cap = 0UL;
  ulong   sz  = 0UL;
  uchar * buf = NULL;
  ulong   ph_off = ULONG_MAX;
  for(;;) {
    int   kind;
    ulong n = fd_txncache_writer_serialize( writer, chunk, chunk_sz, &kind );
    if( !n ) break;
    FD_TEST( n<=chunk_sz );
    switch( kind ) {
    case FD_TXNCACHE_WRITER_CHUNK_PLACEHOLDER:
      FD_TEST( ph_off==ULONG_MAX ); /* one outstanding at a time */
      ph_off = sz;
      __attribute__((fallthrough));
    case FD_TXNCACHE_WRITER_CHUNK_DATA:
      if( sz+n>cap ) { cap = fd_ulong_max( 2UL*cap, sz+n ); buf = realloc( buf, cap ); FD_TEST( buf ); }
      memcpy( buf+sz, chunk, n );
      sz += n;
      break;
    case FD_TXNCACHE_WRITER_CHUNK_PATCH:
      FD_TEST( ph_off!=ULONG_MAX && ph_off+n<=sz );
      memcpy( buf+ph_off, chunk, n );
      ph_off = ULONG_MAX;
      break;
    default:
      FD_LOG_ERR(( "unexpected chunk kind %d", kind ));
    }
  }
  FD_TEST( ph_off==ULONG_MAX );
  free( chunk );
  *out_sz = sz;
  return buf;
}

static void
test_txncache_roundtrip( void ) {
  FD_LOG_NOTICE(( "test_txncache_roundtrip" ));

  test_txncache_t test_tc = create_txncache();
  fd_txncache_t * tc = test_tc.tc;

  uchar blockhashes[4][32];
  uchar txnhashes[6][20];
  fd_txncache_fork_id_t root = populate_txncache( tc, blockhashes, txnhashes );

  uchar * slot_history = malloc( FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
  FD_TEST( slot_history );
  mock_slot_history( slot_history, ROOT_SLOT-3UL, ROOT_SLOT, NULL, 0UL );

  fd_txncache_writer_t writer[1];
  FD_TEST( fd_txncache_writer_init( writer, tc, root, ROOT_SLOT, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ) );
  ulong   total_written;
  uchar * buf = serialize_all( writer, FD_TXNCACHE_WRITER_BUF_MIN, &total_written );
  FD_LOG_NOTICE(( "txncache serialized size: %lu", total_written ));
  /* 1 slot_deltas_len + 4 slot deltas + 4 groups + 6 txns */
  FD_TEST( total_written==8UL + 4UL*17UL + 4UL*48UL + 6UL*24UL );

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

  /* Every rooted slot must get a slot delta, even the ones that hold no
     transactions, or snapshot load rejects the status cache when it
     cross checks the slot deltas against the SlotHistory sysvar. */

  fd_slot_delta_slot_set_t slot_set = fd_slot_delta_parser_slot_set( parser );
  FD_TEST( slot_set.ele_cnt==4UL );
  for( ulong i=0UL; i<4UL; i++ ) {
    ulong slot = ROOT_SLOT-3UL+i;
    FD_TEST( slot_set_ele_query( slot_set.map, &slot, NULL, slot_set.pool ) );
  }

  free( slot_history );

  free( fd_slot_delta_parser_delete( fd_slot_delta_parser_leave( parser ) ) );
  free( buf );
  free( test_tc.ljoin );
  free( test_tc.shmem );
}

/* test_txncache_roundtrip_slot_history checks that the writer names a
   slot delta for every recent slot that has a block, up to Agave's
   MAX_CACHE_ENTRIES, and skips the slots that do not.  Snapshot load
   walks the same SlotHistory sysvar and rejects the snapshot if any of
   those slots is missing a delta. */

static void
test_txncache_roundtrip_slot_history( void ) {
  FD_LOG_NOTICE(( "test_txncache_roundtrip_slot_history" ));

  test_txncache_t test_tc = create_txncache();
  fd_txncache_t * tc = test_tc.tc;

  uchar blockhashes[4][32];
  uchar txnhashes[6][20];
  fd_txncache_fork_id_t root = populate_txncache( tc, blockhashes, txnhashes );

  /* Two leaders skipped their slot, so the newest MAX_CACHE_ENTRIES
     slots with a block reach two slots further back than a naive
     "snapshot slot minus i" walk would. */

  static ulong const skipped[ 2 ] = { ROOT_SLOT-4UL, ROOT_SLOT-14UL };
  ulong const skipped_cnt  = sizeof(skipped)/sizeof(ulong);
  ulong const oldest_named = ROOT_SLOT+1UL - (FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS+skipped_cnt);

  uchar * slot_history = malloc( FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
  FD_TEST( slot_history );
  mock_slot_history( slot_history, 0UL, ROOT_SLOT, skipped, skipped_cnt );

  fd_txncache_writer_t writer[1];
  FD_TEST( fd_txncache_writer_init( writer, tc, root, ROOT_SLOT, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ) );
  ulong   total_written;
  uchar * buf = serialize_all( writer, FD_TXNCACHE_WRITER_BUF_MIN, &total_written );
  FD_TEST( total_written==8UL + FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS*17UL + 4UL*48UL + 6UL*24UL );

  void * parser_mem = aligned_alloc( fd_slot_delta_parser_align(), fd_slot_delta_parser_footprint() );
  FD_TEST( parser_mem );
  fd_slot_delta_parser_t * parser = fd_slot_delta_parser_join( fd_slot_delta_parser_new( parser_mem ) );
  FD_TEST( parser );
  fd_slot_delta_parser_init( parser );

  ulong entries_parsed = 0UL;
  uchar const * p = buf;
  ulong remaining = total_written;
  for(;;) {
    fd_slot_delta_parser_advance_result_t result[1];
    int res = fd_slot_delta_parser_consume( parser, p, remaining, result );
    FD_TEST( res>=0 );
    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_DONE ) break;

    /* All transactions land in the snapshot slot's delta; the other
       slots are named with an empty status map. */
    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_ENTRY ) {
      FD_TEST( result->entry->slot==ROOT_SLOT );
      entries_parsed++;
    }

    p         += result->bytes_consumed;
    remaining -= result->bytes_consumed;
  }
  FD_TEST( entries_parsed==6UL );

  fd_slot_delta_slot_set_t slot_set = fd_slot_delta_parser_slot_set( parser );
  FD_TEST( slot_set.ele_cnt==FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS );

  for( ulong slot=oldest_named; slot<=ROOT_SLOT; slot++ ) {
    int skip = slot==skipped[0] || slot==skipped[1];
    FD_TEST( !!slot_set_ele_query( slot_set.map, &slot, NULL, slot_set.pool )==!skip );
  }

  /* One slot older than the window, and one slot newer than the
     snapshot, must both be absent. */
  ulong too_old = oldest_named-1UL;
  ulong future  = ROOT_SLOT+1UL;
  FD_TEST( !slot_set_ele_query( slot_set.map, &too_old, NULL, slot_set.pool ) );
  FD_TEST( !slot_set_ele_query( slot_set.map, &future,  NULL, slot_set.pool ) );

  FD_LOG_NOTICE(( "named %lu slots, oldest %lu", slot_set.ele_cnt, oldest_named ));

  /* A real snapshot is taken from a frozen bank whose sysvar cache was
     last refreshed at the start of that block, so the cached SlotHistory
     lags the snapshotted account: it is missing the snapshot slot, and
     any slot skipped between the parent and the snapshot slot.  The
     writer must name the snapshot slot anyway, and must not name the
     skipped ones. */

  mock_slot_history( slot_history, 0UL, ROOT_SLOT-3UL, skipped, skipped_cnt );
  FD_TEST( fd_txncache_writer_init( writer, tc, root, ROOT_SLOT, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ) );
  FD_TEST( writer->slot_cnt==FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS );
  FD_TEST( writer->slots[ writer->slot_cnt-1UL ]==ROOT_SLOT     ); /* forced in       */
  FD_TEST( writer->slots[ writer->slot_cnt-2UL ]==ROOT_SLOT-3UL ); /* -1, -2 skipped  */
  FD_TEST( writer->slots[ 0 ]==oldest_named-2UL                 ); /* two more needed */

  /* Any fork but the newest root means replay moved on from the bank
     being snapshotted, which the writer must refuse. */

  fd_txncache_fork_id_t stale = { .val = (ushort)(root.val+1U) };
  FD_TEST( !fd_txncache_writer_init( writer, tc, stale, ROOT_SLOT, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ) );
  FD_TEST( !fd_txncache_writer_init( writer, tc, NULL_FORK, ROOT_SLOT, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ) );

  free( fd_slot_delta_parser_delete( fd_slot_delta_parser_leave( parser ) ) );
  free( buf );
  free( slot_history );
  free( test_tc.ljoin );
  free( test_tc.shmem );
}

/* test_txncache_roundtrip_large streams a blockhash group that spans
   many output chunks, so group headers get patched with counts learned
   after the fact and buckets straddling a chunk boundary get rolled
   back and retried. */

static void
test_txncache_roundtrip_large( void ) {
  FD_LOG_NOTICE(( "test_txncache_roundtrip_large" ));

  test_txncache_t test_tc = create_txncache();
  fd_txncache_t * tc = test_tc.tc;

  uchar blockhashes[4][32];
  uchar txnhashes[6][20];
  fd_txncache_fork_id_t s3 = populate_txncache( tc, blockhashes, txnhashes );

  /* s4 references s3's blockhash (blockhashes[3]) with many txns */
  ulong const big_cnt = 2000UL;
  fd_txncache_fork_id_t s4 = fd_txncache_attach_child( tc, s3 );
  for( ulong i=0UL; i<big_cnt; i++ ) {
    uchar txnhash[ 32 ];
    memset( txnhash, 0, sizeof(txnhash) );
    FD_STORE( ulong, txnhash, i+1UL );
    txnhash[ 8 ] = 0xEE;
    fd_txncache_insert( tc, s4, blockhashes[3], txnhash );
  }
  uchar bh4[ 32 ]; memset( bh4, 0x44, 32UL );
  fd_txncache_finalize_fork( tc, s4, 0UL, bh4 );
  fd_txncache_advance_root( tc, s4 );

  uchar * slot_history = malloc( FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
  FD_TEST( slot_history );
  mock_slot_history( slot_history, ROOT_SLOT-4UL, ROOT_SLOT, NULL, 0UL );

  fd_txncache_writer_t writer[1];
  FD_TEST( fd_txncache_writer_init( writer, tc, s4, ROOT_SLOT, slot_history, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ) );
  ulong   total_written;
  uchar * buf = serialize_all( writer, FD_TXNCACHE_WRITER_BUF_MIN, &total_written );
  FD_TEST( total_written==8UL + 5UL*17UL + 5UL*48UL + (6UL+big_cnt)*24UL );

  void * parser_mem = aligned_alloc( fd_slot_delta_parser_align(), fd_slot_delta_parser_footprint() );
  FD_TEST( parser_mem );
  fd_slot_delta_parser_t * parser = fd_slot_delta_parser_join( fd_slot_delta_parser_new( parser_mem ) );
  FD_TEST( parser );
  fd_slot_delta_parser_init( parser );

  ulong entries_parsed = 0UL;
  ulong big_parsed     = 0UL;
  ulong groups_parsed  = 0UL;
  uchar const * p = buf;
  ulong remaining = total_written;
  for(;;) {
    fd_slot_delta_parser_advance_result_t result[1];
    int res = fd_slot_delta_parser_consume( parser, p, remaining, result );
    FD_TEST( res>=0 );
    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_DONE ) break;
    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_GROUP ) groups_parsed++;
    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_ENTRY ) {
      entries_parsed++;
      if( result->entry->txnhash[ 8 ]==0xEE ) {
        ulong i = FD_LOAD( ulong, result->entry->txnhash );
        FD_TEST( i>=1UL && i<=big_cnt );
        big_parsed++;
      }
    }
    p         += result->bytes_consumed;
    remaining -= result->bytes_consumed;
  }
  FD_TEST( groups_parsed==5UL );
  FD_TEST( entries_parsed==6UL+big_cnt );
  FD_TEST( big_parsed==big_cnt );
  FD_LOG_NOTICE(( "parsed %lu entries across %lu groups", entries_parsed, groups_parsed ));

  free( fd_slot_delta_parser_delete( fd_slot_delta_parser_leave( parser ) ) );
  free( buf );
  free( slot_history );
  free( test_tc.ljoin );
  free( test_tc.shmem );
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
  test_txncache_roundtrip_slot_history();
  test_txncache_roundtrip_large();

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
