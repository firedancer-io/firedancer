#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>
#include <string.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_execrp.h"
#include "fd_rdisp.h"
#include "fd_sched.h"
#include "../../ballet/block/fd_microblock.h"
#include "../../ballet/bmtree/fd_bmtree.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../flamenco/txn/fd_txn_generate.h"

/* Keep the generated cases small.  These limits are intentionally much
   smaller than production so the fuzzer stays cheap to run and easy to
   parallelize. */
#define TEST_MAX_BLOCKS         12UL
#define TEST_MAX_TXNS_PER_BLOCK 8UL
#define TEST_MAX_ACCTS_PER_TXN  8UL
#define TEST_MAX_MBLKS_PER_BLK  8UL
#define TEST_MAX_BLOCK_BYTES    4096UL
#define TEST_MAX_SEGMENTS       8UL
/* Production defaults to more execrp tiles.  Four is enough here to
   exercise task interleavings without making the state space blow up. */
#define TEST_EXEC_CNT           4UL
/* The mirror dispatcher only tracks these tiny synthetic blocks, so it
   does not need production-sized capacity. */
#define TEST_RDISP_DEPTH        32UL
#define TEST_RDISP_BLOCK_DEPTH  4UL
#define TEST_ROOT_SLOT          1000UL
#define TEST_ROOT_TICK_HEIGHT   5000UL
#define TEST_FAIL_NONE 0
#define TEST_FAIL_EXEC 1
#define TEST_FAIL_SIG  2
#define TEST_FAIL_POH  3

/* Pick any earlier bank, including the root.  This gives the fuzzer a
   wide mix of fork shapes with very little bias. */
#define TEST_PARENT_STYLE_ANY_PRIOR         0UL
/* Start with a few direct root children.  After that, attach only
   below those children so the tree fans out early and deepens later. */
#define TEST_PARENT_STYLE_ROOT_THEN_DEEPEN  1UL
/* Make the first four banks direct root children.  Later banks attach
   only to those first children, which keeps the tree shallow and wide. */
#define TEST_PARENT_STYLE_FIRST_FOUR_FANOUT 2UL
/* Usually extend the most recent bank.  Sometimes jump back to an
   earlier parent so the fuzzer still sees non-linear histories. */
#define TEST_PARENT_STYLE_MOSTLY_LINEAR     3UL
/* Start with a small fanout from the root.  After that, allow parents
   from anywhere in the existing tree, including the root again. */
#define TEST_PARENT_STYLE_ROOT_FANOUT_ANY   4UL
#define TEST_PARENT_STYLE_CNT               5UL

typedef struct {
  uchar const * data;
  ulong         data_sz;
  ulong         off;
  /* PRNG state used to synthesize deterministic trailing bytes after the
     fuzz input is exhausted. */
  ulong         salt;
} reader_t;

typedef struct {
  uchar  payload[ FD_TXN_MTU ];
  ushort payload_sz;
  uchar  acct_cnt;
  uchar  sig_cnt;
  ushort acct_id[ TEST_MAX_ACCTS_PER_TXN ];
  uchar  acct_writable[ TEST_MAX_ACCTS_PER_TXN ];
} txn_t;

typedef struct {
  uint  start_txn;
  uint  txn_cnt;
  ulong wire_hash_cnt;
} mblk_t;

typedef struct {
  ulong bank_idx;
  ulong parent_idx;
  ulong slot;
  ulong parent_slot;

  ulong tick_height;
  ulong max_tick_height;
  ulong hashes_per_tick;

  fd_hash_t start_poh[ 1 ];
  fd_hash_t end_poh[ 1 ];

  txn_t  txn [ TEST_MAX_TXNS_PER_BLOCK ];
  ulong                txn_cnt;
  ulong                pred_mask[ TEST_MAX_TXNS_PER_BLOCK ];

  mblk_t mblk[ TEST_MAX_MBLKS_PER_BLK ];
  ulong                mblk_cnt;
  fd_hash_t            mblk_start_hash[ TEST_MAX_MBLKS_PER_BLK ];
  fd_hash_t            mblk_hashed_hash[ TEST_MAX_MBLKS_PER_BLK ];
  ulong                poh_dispatch_mblk_cnt;

  uchar encoded[ TEST_MAX_BLOCK_BYTES ];
  ulong encoded_sz;
  uint  txn_end_off[ TEST_MAX_TXNS_PER_BLOCK ];
  uchar txn_mblk_idx[ TEST_MAX_TXNS_PER_BLOCK ];
  uint  seg_end[ TEST_MAX_SEGMENTS ];
  ulong seg_cnt;
  ulong ingested_seg_cnt;
  int   poh_params_set;

  int failure_mode;
  int failure_injected;

  ulong exec_done_mask;
  ulong sig_done_mask;
  int   start_seen;
  int   end_seen;
  int   dead_seen;
  int   ref_released_seen;
} block_t;

typedef struct {
  void *               mem;
  fd_sched_t *         sched;
  /* Number of fuzz-generated blocks in block[].  Bank 0 is the
     synthetic snapshot root, so block[i] corresponds to bank i+1. */
  ulong                block_cnt;
  fd_hash_t            root_hash[ 1 ];
  block_t block[ TEST_MAX_BLOCKS ];
} case_t;

typedef struct {
  ulong task_type;
  ulong bank_idx;
  ulong txn_idx;
  ulong exec_idx;
  ulong local_txn_idx;
  ulong mblk_idx;
  ulong local_mblk_idx;
  ulong hashcnt;
  fd_hash_t hash[ 1 ];
} inflight_t;

typedef struct {
  void *    mem            [ TEST_MAX_BLOCKS ];
  fd_rdisp_t * disp        [ TEST_MAX_BLOCKS ];
  ulong     txn_idx        [ TEST_MAX_BLOCKS ][ TEST_MAX_TXNS_PER_BLOCK ];
  ulong     txn_added_cnt  [ TEST_MAX_BLOCKS ];
  ulong     exec_done_mask [ TEST_MAX_BLOCKS ];
  ulong     reclaimed_mask [ TEST_MAX_BLOCKS ];
  uchar     block_added    [ TEST_MAX_BLOCKS ];
  uchar     block_retired  [ TEST_MAX_BLOCKS ];
  uint      verify_scratch [ TEST_MAX_BLOCKS ][ TEST_RDISP_DEPTH + 1UL ];
} mirror_t;

static uchar
read_uchar( reader_t * r ) {
  if( FD_LIKELY( r->off<r->data_sz ) ) return r->data[ r->off++ ];
  r->salt = 6364136223846793005UL*r->salt + 1442695040888963407UL;
  return (uchar)(r->salt >> 56);
}

static ulong
read_range( reader_t * r, ulong max ) {
  if( FD_UNLIKELY( !max ) ) return 0UL;
  return (ulong)read_uchar( r ) % max;
}

static void
pubkey_from_id( fd_pubkey_t * out,
                ushort        id ) {
  for( ulong i=0UL; i<sizeof(fd_pubkey_t)/sizeof(ushort); i++ ) FD_STORE( ushort, out->uc + 2UL*i, id );
}

static void
hash_from_seed( fd_hash_t * out,
                ulong       seed ) {
  for( ulong i=0UL; i<4UL; i++ ) out->ul[ i ] = seed ^ (0x9e3779b97f4a7c15UL * (i+1UL));
}

static int
has_ushort( ushort const * vals,
            ulong          cnt,
            ushort         val ) {
  for( ulong i=0UL; i<cnt; i++ ) if( FD_UNLIKELY( vals[ i ]==val ) ) return 1;
  return 0;
}

/* repeat_hash is fd_sha256_hash( fd_sha256_hash(  ... start ) )
   repeated cnt times. */
static void
repeat_hash( fd_hash_t *       out,
             fd_hash_t const * start,
             ulong             cnt ) {
  uchar cur[ 32 ];
  fd_memcpy( cur, start->hash, 32UL );
  for( ulong i=0UL; i<cnt; i++ ) fd_sha256_hash( cur, 32UL, cur );
  fd_memcpy( out->hash, cur, 32UL );
}

/* txn_conflicts returns 1 if the two txns conflict, zero otherwise */
static int
txn_conflicts( txn_t const * a,
               txn_t const * b ) {
  for( ulong i=0UL; i<a->acct_cnt; i++ ) {
    for( ulong j=0UL; j<b->acct_cnt; j++ ) {
      if( FD_UNLIKELY( a->acct_id[ i ]!=b->acct_id[ j ] ) ) continue;
      if( a->acct_writable[ i ] | b->acct_writable[ j ] ) return 1;
    }
  }
  return 0;
}

static void
merkle_root( fd_hash_t * out,
             txn_t const * txn,
             ulong         txn_cnt ) {
  uchar mem[ FD_BMTREE_COMMIT_FOOTPRINT( 0 ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( mem, 32UL, 1UL, 0UL );
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    uchar txn_meta[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
    fd_txn_t const * parsed = fd_type_pun_const( txn_meta );
    FD_TEST( fd_txn_parse( txn[ i ].payload, txn[ i ].payload_sz, txn_meta, NULL ) );
    for( ulong j=0UL; j<parsed->signature_cnt; j++ ) {
      fd_bmtree_node_t node[ 1 ];
      fd_bmtree_hash_leaf( node, txn[ i ].payload + parsed->signature_off + FD_TXN_SIGNATURE_SZ*j, FD_TXN_SIGNATURE_SZ, 1UL );
      fd_bmtree_commit_append( tree, node, 1UL );
    }
  }
  uchar * root = fd_bmtree_commit_fini( tree );
  fd_memcpy( out->hash, root, 32UL );
}

/* verify_block_encoding replays the builder's wire-format derivation
   from block->encoded and the cached per-transaction payloads.

   This is a harness self-check, not part of the scheduler model.  And
   is only called under FD_DEBUG.  It confirms that build_block()
   serialized exactly block->mblk_cnt microblocks, that each header
   still matches the cached mblk[] metadata, and that the byte cursor
   implied by those headers lands exactly on block->encoded_sz after
   consuming every transaction.

   For transaction microblocks, the function mirrors the production PoH
   convention used by the builder: hash_cnt includes one final count for
   the Merkle-root mixin, so the pure hash chain is replayed for
   hash_cnt-1 steps before combining with the Merkle root of the
   corresponding transaction slice.  Tick-only microblocks skip the
   mixin and just advance PoH for hash_cnt steps.  In both cases the
   recomputed header hash must match the serialized header.

   Walking the block this way also checks that the cached start_poh and
   end_poh values are internally consistent with the wire image.  If any
   assertion here fails, the fuzz case is malformed and the later
   scheduler checks would no longer be meaningful. */
FD_FN_UNUSED static void
verify_block_encoding( block_t const * block ) {
  FD_TEST( block->encoded_sz>=sizeof(ulong)+sizeof(fd_microblock_hdr_t) );
  FD_TEST( FD_LOAD( ulong, block->encoded )==block->mblk_cnt );

  ulong cursor = sizeof(ulong);
  ulong txn_off = 0UL;
  fd_hash_t prev_hash[ 1 ];
  fd_memcpy( prev_hash, block->start_poh, sizeof(fd_hash_t) );

  for( ulong i=0UL; i<block->mblk_cnt; i++ ) {
    FD_TEST( cursor + sizeof(fd_microblock_hdr_t) <= block->encoded_sz );
    fd_microblock_hdr_t const * hdr = fd_type_pun_const( block->encoded + cursor );
    cursor += sizeof(fd_microblock_hdr_t);

    if( FD_UNLIKELY( hdr->txn_cnt != block->mblk[ i ].txn_cnt ) ) {
      FD_LOG_ERR(( "builder txn_cnt mismatch on mblk %lu: hdr %lu expected %u cursor %lu encoded_sz %lu",
                   i, hdr->txn_cnt, block->mblk[ i ].txn_cnt, cursor-sizeof(fd_microblock_hdr_t), block->encoded_sz ));
    }
    if( FD_UNLIKELY( hdr->hash_cnt != block->mblk[ i ].wire_hash_cnt ) ) {
      FD_LOG_ERR(( "builder hash_cnt mismatch on mblk %lu: hdr %lu expected %lu cursor %lu encoded_sz %lu txn_off %lu txn_cnt %lu",
                   i, hdr->hash_cnt, block->mblk[ i ].wire_hash_cnt, cursor-sizeof(fd_microblock_hdr_t), block->encoded_sz, txn_off, (ulong)hdr->txn_cnt ));
    }

    if( FD_LIKELY( hdr->txn_cnt ) ) {
      fd_hash_t after_hashes[ 1 ];
      repeat_hash( after_hashes, prev_hash, hdr->hash_cnt-1UL );

      fd_hash_t merkle[ 1 ];
      merkle_root( merkle, block->txn + txn_off, hdr->txn_cnt );

      uchar mixin[ 64 ];
      fd_memcpy( mixin,      after_hashes->hash, 32UL );
      fd_memcpy( mixin+32UL, merkle->hash,       32UL );
      fd_hash_t end_hash[ 1 ];
      fd_sha256_hash( mixin, sizeof(mixin), end_hash->hash );

      if( FD_UNLIKELY( memcmp( hdr->hash, end_hash->hash, sizeof(fd_hash_t) ) ) ) {
        FD_BASE58_ENCODE_32_BYTES( hdr->hash, hdr_str );
        FD_BASE58_ENCODE_32_BYTES( end_hash->hash, expect_str );
        FD_LOG_ERR(( "builder hash mismatch on mblk %lu: hdr %s expected %s hash_cnt %lu txn_off %lu txn_cnt %lu",
                     i, hdr_str, expect_str, hdr->hash_cnt, txn_off, (ulong)hdr->txn_cnt ));
      }

      for( ulong j=0UL; j<hdr->txn_cnt; j++ ) cursor += block->txn[ txn_off + j ].payload_sz;
      txn_off += hdr->txn_cnt;
      fd_memcpy( prev_hash, end_hash, sizeof(fd_hash_t) );
    } else {
      fd_hash_t tick_end[ 1 ];
      repeat_hash( tick_end, prev_hash, hdr->hash_cnt );
      if( FD_UNLIKELY( memcmp( hdr->hash, tick_end->hash, sizeof(fd_hash_t) ) ) ) {
        FD_BASE58_ENCODE_32_BYTES( hdr->hash, hdr_str );
        FD_BASE58_ENCODE_32_BYTES( tick_end->hash, expect_str );
        FD_LOG_ERR(( "builder tick hash mismatch on mblk %lu: hdr %s expected %s hash_cnt %lu",
                     i, hdr_str, expect_str, hdr->hash_cnt ));
      }
      fd_memcpy( prev_hash, tick_end, sizeof(fd_hash_t) );
    }
  }

  FD_TEST( txn_off == block->txn_cnt );
  FD_TEST( cursor == block->encoded_sz );
  FD_TEST( !memcmp( prev_hash, block->end_poh, sizeof(fd_hash_t) ) );
}

static ulong
mblk_task_hashcnt( block_t const * block, ulong local_mblk_idx ) {
  FD_TEST( local_mblk_idx<block->mblk_cnt );
  mblk_t const * mblk = block->mblk + local_mblk_idx;
  return mblk->txn_cnt ? mblk->wire_hash_cnt-1UL : mblk->wire_hash_cnt;
}

static ulong
block_txn_mask( block_t const * block ) {
  return fd_ulong_mask_lsb( (int)block->txn_cnt );
}

/* build_txn constructs one small, well-formed legacy transaction for
   the replay scheduler harness.

   The transaction shape is intentionally narrow.  Every generated
   transaction has exactly one writable signer payer, zero to two extra
   writable accounts, zero to two extra readonly accounts, and one final
   readonly program account.  The payer id is chosen uniformly from the
   six-account shared pool [1,6].  Extra writable and readonly accounts
   are then sampled uniformly without replacement from that same pool,
   so each transaction uses distinct data-account ids internally while
   unrelated transactions still collide often.

   That distribution is deliberately conflict-heavy.  Every transaction
   contributes at least one writable shared-pool account, so two random
   transactions already conflict with probability at least 1/6 from the
   payer choice alone.  The optional extra accounts push that rate much
   higher, and because the shared ids are more likely to appear as
   writable than readonly, the generated overlaps are biased toward true
   scheduler dependencies instead of benign readonly sharing.

   The program account is derived from block_idx instead of the shared
   pool.  That keeps transactions within a block on the same synthetic
   program while avoiding accidental overlap with the data-account id
   space used to model conflicts.

   After fd_txn_base_generate() lays out the message, the function
   stamps deterministic signature bytes and appends one instruction that
   references every non-program account.  The instruction data records
   the generation choices so downstream debugging can recover the
   intended shape from the wire image alone.

   Finally, the builder reparses the finished payload and asserts that
   the parsed length matches payload_sz.  This keeps the harness focused
   on scheduler and dispatcher behavior rather than malformed synthetic
   transaction encodings. */
static ulong
build_txn( reader_t * r, ulong block_idx, ulong txn_idx, txn_t * out ) {
  ushort used[ TEST_MAX_ACCTS_PER_TXN ] = { 0 };
  ulong  used_cnt = 0UL;

  ushort payer_id = (ushort)(1U + read_range( r, 6UL ));
  used[ used_cnt++ ] = payer_id;

  ulong writable_extra = read_range( r, 3UL );
  ulong readonly_extra = read_range( r, 3UL );
  ulong acct_cnt       = 1UL + writable_extra + readonly_extra + 1UL; /* +1 program */
  FD_TEST( acct_cnt<=TEST_MAX_ACCTS_PER_TXN );

  fd_pubkey_t signer_w[ 1 ];
  fd_pubkey_t non_signer_w[ TEST_MAX_ACCTS_PER_TXN ];
  fd_pubkey_t non_signer_r[ TEST_MAX_ACCTS_PER_TXN ];

  pubkey_from_id( signer_w, payer_id );
  out->acct_id[ 0 ]       = payer_id;
  out->acct_writable[ 0 ] = 1U;
  out->acct_cnt           = (uchar)acct_cnt;
  out->sig_cnt            = 1U;

  for( ulong i=0UL; i<writable_extra; i++ ) {
    ushort id;
    do {
      id = (ushort)(1U + read_range( r, 6UL ));
    } while( has_ushort( used, used_cnt, id ) );
    used[ used_cnt++ ] = id;
    pubkey_from_id( non_signer_w + i, id );
    out->acct_id[ 1UL + i ]       = id;
    out->acct_writable[ 1UL + i ] = 1U;
  }

  for( ulong i=0UL; i<readonly_extra; i++ ) {
    ushort id;
    do {
      id = (ushort)(1U + read_range( r, 6UL ));
    } while( has_ushort( used, used_cnt, id ) );
    used[ used_cnt++ ] = id;
    pubkey_from_id( non_signer_r + i, id );
    out->acct_id[ 1UL + writable_extra + i ]       = id;
    out->acct_writable[ 1UL + writable_extra + i ] = 0U;
  }

  ushort program_id = (ushort)(0x7f00U + (ushort)block_idx);
  pubkey_from_id( non_signer_r + readonly_extra, program_id );
  out->acct_id[ acct_cnt-1UL ]       = program_id;
  out->acct_writable[ acct_cnt-1UL ] = 0U;

  fd_txn_accounts_t accounts = {
    .signature_cnt         = 1U,
    .readonly_signed_cnt   = 0U,
    .readonly_unsigned_cnt = (uchar)(readonly_extra + 1UL),
    .acct_cnt              = (ushort)acct_cnt,
    .signers_w             = signer_w,
    .signers_r             = NULL,
    .non_signers_w         = non_signer_w,
    .non_signers_r         = non_signer_r,
  };

  fd_memset( out->payload, 0, sizeof(out->payload) );
  uchar meta[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  fd_memset( meta, 0, sizeof(meta) );
  fd_txn_base_generate( meta, out->payload, 1UL, &accounts, NULL );

  for( ulong i=0UL; i<FD_TXN_SIGNATURE_SZ; i++ ) out->payload[ 1UL + i ] = (uchar)((block_idx<<4) ^ txn_idx ^ i);

  uchar instr_accounts[ TEST_MAX_ACCTS_PER_TXN ];
  ulong instr_accounts_sz = acct_cnt-1UL; /* omit program */
  for( ulong i=0UL; i<instr_accounts_sz; i++ ) instr_accounts[ i ] = (uchar)i;

  uchar instr_data[ 6 ] = {
    (uchar)block_idx,
    (uchar)txn_idx,
    (uchar)acct_cnt,
    (uchar)writable_extra,
    (uchar)readonly_extra,
    read_uchar( r )
  };
  out->payload_sz = (ushort)fd_txn_add_instr( meta, out->payload, (uchar)(acct_cnt-1UL), instr_accounts, instr_accounts_sz, instr_data, sizeof(instr_data) );

  uchar parsed[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  ulong parsed_pay_sz = 0UL;
  FD_TEST( fd_txn_parse_core( out->payload, out->payload_sz, fd_type_pun( parsed ), NULL, &parsed_pay_sz ) );
  FD_TEST( parsed_pay_sz == out->payload_sz );

  return out->payload_sz;
}

/* build_block synthesizes one scheduler-visible block from the fuzz
   stream and caches every intermediate artifact that later harness
   checks need.

   The generated wire image always has the form

     [ ulong mblk_cnt ][ txn microblock... ][ final tick microblock ]

   where each transaction microblock covers a contiguous slice of
   block->txn[].  For transaction microblocks, wire_hash_cnt is stored
   exactly as it would appear on the wire: pure_hash_cnt plus one extra
   count for the final PoH record/mixin.  The harness keeps both the
   start hash and the hash after the pure-hash portion so it can mirror
   the scheduler's split between PoH work and transaction dispatch.  A
   final tick-only microblock is always appended so every synthetic
   block advances exactly one tick and produces a deterministic
   hashes_per_tick value for fd_sched_set_poh_params().

   After encoding the block, the builder partitions the byte stream into
   fuzz-controlled segments for incremental FEC ingestion.  If the block
   contains anything beyond the leading microblock-count word, the first
   segment is forced to stop right after that word.  This keeps the
   parser's "new block" boundary stable while still letting later
   segments split headers and transactions at arbitrary offsets.

   The function also precomputes the transaction conflict predecessor
   masks and selects a failure_mode used later by the harness to inject
   exec, sigverify, or PoH faults at deterministic points. */
static void
build_block( reader_t *        r,
             fd_hash_t const * parent_hash,
             ulong             parent_tick_height,
             ulong             bank_idx,
             ulong             parent_idx,
             ulong             slot,
             ulong             parent_slot,
             block_t *         block ) {
  fd_memset( block, 0, sizeof(block_t) );
  block->bank_idx        = bank_idx;
  block->parent_idx      = parent_idx;
  block->slot            = slot;
  block->parent_slot     = parent_slot;
  block->tick_height     = parent_tick_height;
  block->max_tick_height = parent_tick_height + 1UL;

  fd_memcpy( block->start_poh, parent_hash, sizeof(fd_hash_t) );

  block->txn_cnt = 1UL + read_range( r, TEST_MAX_TXNS_PER_BLOCK );
  for( ulong i=0UL; i<block->txn_cnt; i++ ) build_txn( r, bank_idx, i, block->txn + i );

  for( ulong i=0UL; i<block->txn_cnt; i++ ) {
    ulong pred = 0UL;
    for( ulong j=0UL; j<i; j++ ) pred |= fd_ulong_if( txn_conflicts( block->txn + j, block->txn + i ), 1UL<<j, 0UL );
    block->pred_mask[ i ] = pred;
  }

  uchar * p = block->encoded;
  ulong txns_remaining = block->txn_cnt;
  ulong cursor         = 0UL;
  ulong txn_off        = 0UL;
  ulong tick_hash_cnt  = 0UL;
  fd_hash_t prev_hash[ 1 ];
  fd_memcpy( prev_hash, parent_hash, sizeof(fd_hash_t) );

  block->mblk_cnt = 0UL;
  while( txns_remaining ) {
    ulong tx_mblk_slots_rem = TEST_MAX_MBLKS_PER_BLK - block->mblk_cnt - 1UL; /* Reserve one slot for the final tick. */
    FD_TEST( tx_mblk_slots_rem>0UL );
    ulong min_group_txn_cnt = ( txns_remaining + tx_mblk_slots_rem - 1UL ) / tx_mblk_slots_rem;
    ulong group_txn_cnt = min_group_txn_cnt + read_range( r, txns_remaining - min_group_txn_cnt + 1UL );
    ulong pure_hash_cnt = 1UL + read_range( r, 3UL );
    ulong wire_hash_cnt = pure_hash_cnt + 1UL;

    fd_memcpy( block->mblk_start_hash + block->mblk_cnt, prev_hash, sizeof(fd_hash_t) );
    block->mblk[ block->mblk_cnt ].start_txn      = (uint)txn_off;
    block->mblk[ block->mblk_cnt ].txn_cnt        = (uint)group_txn_cnt;
    block->mblk[ block->mblk_cnt ].wire_hash_cnt  = wire_hash_cnt;
    block->mblk_cnt++;
    tick_hash_cnt += wire_hash_cnt;

    fd_hash_t after_hashes[ 1 ];
    repeat_hash( after_hashes, prev_hash, pure_hash_cnt );
    fd_memcpy( block->mblk_hashed_hash + block->mblk_cnt-1UL, after_hashes, sizeof(fd_hash_t) );

    fd_hash_t merkle[ 1 ];
    merkle_root( merkle, block->txn + txn_off, group_txn_cnt );

    uchar mixin[ 64 ];
    fd_memcpy( mixin,      after_hashes->hash, 32UL );
    fd_memcpy( mixin+32UL, merkle->hash,       32UL );
    fd_hash_t end_hash[ 1 ];
    fd_sha256_hash( mixin, sizeof(mixin), end_hash->hash );

    fd_microblock_hdr_t hdr = {
      .hash_cnt = wire_hash_cnt,
      .txn_cnt  = group_txn_cnt
    };
    fd_memcpy( hdr.hash, end_hash->hash, sizeof(fd_hash_t) );

    FD_TEST( cursor + sizeof(fd_microblock_hdr_t) <= sizeof(block->encoded) );
    fd_memcpy( p + cursor, &hdr, sizeof(fd_microblock_hdr_t) );
    cursor += sizeof(fd_microblock_hdr_t);
    for( ulong i=0UL; i<group_txn_cnt; i++ ) {
      FD_TEST( cursor + block->txn[ txn_off+i ].payload_sz <= sizeof(block->encoded) );
      fd_memcpy( p + cursor, block->txn[ txn_off+i ].payload, block->txn[ txn_off+i ].payload_sz );
      cursor += block->txn[ txn_off+i ].payload_sz;
      block->txn_end_off [ txn_off+i ] = (uint)cursor;
      block->txn_mblk_idx[ txn_off+i ] = (uchar)(block->mblk_cnt-1UL);
    }

    fd_memcpy( prev_hash, end_hash, sizeof(fd_hash_t) );
    txn_off        += group_txn_cnt;
    txns_remaining -= group_txn_cnt;
  }

  ulong tick_wire_hash_cnt = 1UL + read_range( r, 4UL );
  block->hashes_per_tick = tick_hash_cnt + tick_wire_hash_cnt;
  FD_TEST( block->mblk_cnt<TEST_MAX_MBLKS_PER_BLK );
  fd_memcpy( block->mblk_start_hash + block->mblk_cnt, prev_hash, sizeof(fd_hash_t) );
  block->mblk[ block->mblk_cnt ].start_txn     = (uint)block->txn_cnt;
  block->mblk[ block->mblk_cnt ].txn_cnt       = 0U;
  block->mblk[ block->mblk_cnt ].wire_hash_cnt = tick_wire_hash_cnt;
  block->mblk_cnt++;

  fd_hash_t tick_end[ 1 ];
  repeat_hash( tick_end, prev_hash, tick_wire_hash_cnt );
  fd_memcpy( block->mblk_hashed_hash + block->mblk_cnt-1UL, tick_end, sizeof(fd_hash_t) );
  fd_memcpy( block->end_poh, tick_end, sizeof(fd_hash_t) );

  fd_microblock_hdr_t tick_hdr = {
    .hash_cnt = tick_wire_hash_cnt,
    .txn_cnt  = 0UL
  };
  fd_memcpy( tick_hdr.hash, tick_end->hash, sizeof(fd_hash_t) );

  FD_TEST( cursor + sizeof(fd_microblock_hdr_t) + sizeof(ulong) <= sizeof(block->encoded) );
  memmove( block->encoded + sizeof(ulong), block->encoded, cursor );
  FD_STORE( ulong, block->encoded, block->mblk_cnt );
  for( ulong i=0UL; i<block->txn_cnt; i++ ) block->txn_end_off[ i ] += (uint)sizeof(ulong);
  cursor += sizeof(ulong);
  fd_memcpy( block->encoded + cursor, &tick_hdr, sizeof(fd_microblock_hdr_t) );
  cursor += sizeof(fd_microblock_hdr_t);
  block->encoded_sz = cursor;

  block->seg_cnt = 1UL + read_range( r, fd_ulong_min( TEST_MAX_SEGMENTS, block->encoded_sz ) );
  if( FD_LIKELY( block->encoded_sz>sizeof(ulong) ) ) block->seg_cnt = fd_ulong_max( block->seg_cnt, 2UL );
  ulong off = 0UL;
  if( FD_LIKELY( block->encoded_sz>sizeof(ulong) ) ) {
    off = sizeof(ulong);
    block->seg_end[ 0 ] = (uint)off;
    ulong rem = block->encoded_sz - off;
    for( ulong i=1UL; i<block->seg_cnt; i++ ) {
      ulong min_rem = block->seg_cnt-i-1UL;
      ulong len     = fd_ulong_if( i+1UL==block->seg_cnt, rem, 1UL + read_range( r, rem-min_rem ) );
      off += len;
      block->seg_end[ i ] = (uint)off;
      rem -= len;
    }
  } else {
    block->seg_end[ 0 ] = (uint)block->encoded_sz;
  }

  switch( read_range( r, 6UL ) ) {
    case 0UL: block->failure_mode = TEST_FAIL_EXEC; break;
    case 1UL: block->failure_mode = TEST_FAIL_SIG;  break;
    case 2UL: block->failure_mode = TEST_FAIL_POH;  break;
    default:  block->failure_mode = TEST_FAIL_NONE; break;
  }

#if FD_DEBUG
  verify_block_encoding( block );
#endif
}

static void
drain_refs( case_t * tc ) {
  for(;;) {
    ulong bank_idx = fd_sched_pruned_block_next( tc->sched );
    if( FD_UNLIKELY( bank_idx==ULONG_MAX ) ) break;
    FD_TEST( bank_idx>0UL && bank_idx<=tc->block_cnt );
    tc->block[ bank_idx-1UL ].ref_released_seen = 1;
  }
}

static ulong
find_txn( block_t const * block,
          fd_txn_p_t const * txn ) {
  for( ulong i=0UL; i<block->txn_cnt; i++ ) {
    if( FD_UNLIKELY( block->txn[ i ].payload_sz != txn->payload_sz ) ) continue;
    if( FD_UNLIKELY( memcmp( block->txn[ i ].payload, txn->payload, txn->payload_sz ) ) ) continue;
    return i;
  }
  return ULONG_MAX;
}

static int
block_can_ingest( case_t const * tc,
                  block_t const * block ) {
  if( FD_UNLIKELY( block->ingested_seg_cnt>=block->seg_cnt ) ) return 0;
  if( FD_UNLIKELY( block->ingested_seg_cnt>0UL             ) ) return 1;
  if( FD_LIKELY( block->parent_idx==0UL ) ) return 1;
  block_t const * parent = tc->block + (block->parent_idx-1UL);
  return parent->ingested_seg_cnt==parent->seg_cnt;
}

static void
prepare_fec( block_t const *  block,
             fd_store_fec_t * store_fec,
             fd_sched_fec_t * fec ) {
  ulong seg       = block->ingested_seg_cnt;
  ulong seg_start = seg ? (ulong)block->seg_end[ seg-1UL ] : 0UL;
  ulong seg_end   = block->seg_end[ seg ];
  ulong seg_sz    = seg_end - seg_start;

  fd_memset( store_fec, 0, sizeof(fd_store_fec_t) );
  store_fec->data_sz       = seg_sz;
  store_fec->shred_offs[0] = (uint)seg_sz;

  *fec = (fd_sched_fec_t) {
    .bank_idx           = block->bank_idx,
    .parent_bank_idx    = block->parent_idx,
    .slot               = block->slot,
    .parent_slot        = block->parent_slot,
    .fec                = store_fec,
    .data               = (uchar *)block->encoded + seg_start,
    .shred_cnt          = 1U,
    .is_last_in_batch   = (uint)(seg+1UL==block->seg_cnt),
    .is_last_in_block   = (uint)(seg+1UL==block->seg_cnt),
    .is_first_in_block  = (uint)(seg==0UL),
  };
}

static int
block_fec_can_ingest( case_t const * tc,
                      block_t const * block ) {
  if( FD_UNLIKELY( !block_can_ingest( tc, block ) ) ) return 0;
  fd_store_fec_t store_fec[ 1 ];
  fd_sched_fec_t fec[ 1 ];
  prepare_fec( block, store_fec, fec );
  return fd_sched_fec_can_ingest( tc->sched, fec );
}

static void
ingest_next_segment( case_t * tc,
                     block_t * block ) {
  FD_TEST( block_can_ingest( tc, block ) );

  fd_store_fec_t store_fec[ 1 ];
  fd_sched_fec_t fec[ 1 ];
  prepare_fec( block, store_fec, fec );
  FD_TEST( fd_sched_fec_can_ingest( tc->sched, fec ) );
  FD_TEST( fd_sched_fec_ingest( tc->sched, fec ) );
  block->ingested_seg_cnt++;
  if( FD_UNLIKELY( !block->poh_params_set ) ) {
    fd_sched_set_poh_params( tc->sched, block->bank_idx, block->tick_height, block->max_tick_height, block->hashes_per_tick, block->start_poh );
    block->poh_params_set = 1;
  }
}

/* build_case turns one fuzz input into a complete scheduler test case.

   It initializes a small fd_sched instance, seeds bank 0 as a
   synthetic snapshot root, then consumes the fuzz stream through
   reader_t to build a bounded set of descendant blocks.  The first few
   bytes choose the number of blocks and the parent-selection style,
   while build_block() consumes the rest to synthesize each block's
   transactions, microblocks, PoH state, wire image, and fault-injection
   mode.

   The slot/tick/hash arrays track the parent-visible state needed to
   make each child block internally consistent with the chain built so
   far.  After this returns, tc contains both the live scheduler under
   test and the cached per-block expectations the harness later checks
   against scheduler and mirror-dispatcher behavior. */
static void
build_case( case_t * tc, uchar const * data, ulong data_sz ) {
  fd_memset( tc, 0, sizeof(*tc) );

  reader_t r = {
    .data    = data,
    .data_sz = data_sz,
    .off     = 0UL,
    .salt    = 0x123456789abcdef0UL ^ data_sz
  };

  hash_from_seed( tc->root_hash, 0x51a0f95dUL );

  /* Production uses a much deeper scheduler.  The fuzzer keeps this
     small so each case is cheaper to build and run. */
  ulong depth         = 512UL;
  ulong block_cnt_max = TEST_MAX_BLOCKS + 1UL;
  ulong footprint     = fd_sched_footprint( depth, block_cnt_max );
  tc->mem = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( tc->mem );

  fd_rng_t rng[1];
  fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  tc->sched = fd_sched_join( fd_sched_new( tc->mem, rng, depth, block_cnt_max, TEST_EXEC_CNT ) );
  FD_TEST( tc->sched );

  /* Seed the scheduler with bank 0 as a completed snapshot root.  The
     notify/advance pair is a no-op for the current root, but using the
     same sequence as later root updates keeps the harness simpler. */
  fd_sched_block_add_done( tc->sched, 0UL, ULONG_MAX, TEST_ROOT_SLOT );
  fd_sched_root_notify( tc->sched, 0UL );
  fd_sched_advance_root( tc->sched, 0UL );

  /* Additional space (+2 for cnt) (+1 for indexing) for the synthetic
     snapshot root */
  tc->block_cnt = 2UL + read_range( &r, TEST_MAX_BLOCKS-1UL );

  ulong slot_by_bank[ TEST_MAX_BLOCKS + 1UL ] = { 0 };
  ulong tick_by_bank[ TEST_MAX_BLOCKS + 1UL ] = { 0 };
  fd_hash_t end_hash_by_bank[ TEST_MAX_BLOCKS + 1UL ];
  slot_by_bank[ 0 ] = TEST_ROOT_SLOT;
  tick_by_bank[ 0 ] = TEST_ROOT_TICK_HEIGHT;
  fd_memcpy( end_hash_by_bank + 0, tc->root_hash, sizeof(fd_hash_t) );

  ulong parent_style = read_range( &r, TEST_PARENT_STYLE_CNT );
  for( ulong bank_idx=1UL; bank_idx<=tc->block_cnt; bank_idx++ ) {
    ulong parent_idx;
    switch( parent_style ) {
      case TEST_PARENT_STYLE_ANY_PRIOR:
        parent_idx = read_range( &r, bank_idx );
        break;
      case TEST_PARENT_STYLE_ROOT_THEN_DEEPEN:
        parent_idx = fd_ulong_if( bank_idx<=5UL, 0UL, 1UL + read_range( &r, bank_idx-1UL ) );
        break;
      case TEST_PARENT_STYLE_FIRST_FOUR_FANOUT:
        if( FD_LIKELY( bank_idx<=4UL ) ) parent_idx = 0UL;
        else parent_idx = 1UL + read_range( &r, fd_ulong_min( bank_idx-1UL, 4UL ) );
        break;
      case TEST_PARENT_STYLE_MOSTLY_LINEAR:
        parent_idx = fd_ulong_if( bank_idx<=1UL, 0UL, bank_idx-1UL );
        if( FD_UNLIKELY( bank_idx>2UL && (read_uchar( &r )&1U) ) ) parent_idx = read_range( &r, bank_idx );
        break;
      case TEST_PARENT_STYLE_ROOT_FANOUT_ANY:
        parent_idx = fd_ulong_if( bank_idx<=4UL, 0UL, read_range( &r, bank_idx ) );
        break;
      default:
        FD_LOG_CRIT(( "unexpected parent_style %lu", parent_style ));
    }
    ulong slot = slot_by_bank[ parent_idx ] + 1UL + read_range( &r, 3UL );

    build_block( &r,
                 end_hash_by_bank + parent_idx,
                 tick_by_bank[ parent_idx ],
                 bank_idx,
                 parent_idx,
                 slot,
                 slot_by_bank[ parent_idx ],
                 tc->block + (bank_idx-1UL) );

    slot_by_bank[ bank_idx ] = slot;
    tick_by_bank[ bank_idx ] = tc->block[ bank_idx-1UL ].max_tick_height;
    fd_memcpy( end_hash_by_bank + bank_idx, tc->block[ bank_idx-1UL ].end_poh, sizeof(fd_hash_t) );
  }
}

static void
destroy_case( case_t * tc ) {
  if( FD_UNLIKELY( !tc->mem ) ) return;
  fd_sched_delete( fd_sched_leave( tc->sched ) );
  free( tc->mem );
  tc->mem   = NULL;
  tc->sched = NULL;
}

static ulong
ingestable_block_cnt( case_t const * tc ) {
  ulong cnt = 0UL;
  for( ulong i=0UL; i<tc->block_cnt; i++ ) cnt += (ulong)block_fec_can_ingest( tc, tc->block + i );
  return cnt;
}

static ulong
ingest_pending_block_idx( case_t *   tc,
                          reader_t * r ) {
  ulong ingestable_cnt = ingestable_block_cnt( tc );
  FD_TEST( ingestable_cnt>0UL );

  ulong pick = read_range( r, ingestable_cnt );
  for( ulong i=0UL; i<tc->block_cnt; i++ ) {
    block_t * block = tc->block + i;
    if( FD_UNLIKELY( !block_fec_can_ingest( tc, block ) ) ) continue;
    if( FD_LIKELY( pick--==0UL ) ) {
      ingest_next_segment( tc, block );
      return block->bank_idx;
    }
  }

  FD_LOG_ERR(( "failed to pick ingestable block" ));
  return ULONG_MAX;
}

static int
lineage_dead( case_t const * tc,
              ulong          bank_idx ) {
  while( bank_idx>0UL ) {
    block_t const * block = tc->block + (bank_idx-1UL);
    if( FD_UNLIKELY( block->dead_seen ) ) return 1;
    bank_idx = block->parent_idx;
  }
  return 0;
}

static int
descends_from( case_t const * tc,
               ulong          bank_idx,
               ulong          ancestor ) {
  while( bank_idx>0UL ) {
    if( bank_idx==ancestor ) return 1;
    bank_idx = tc->block[ bank_idx-1UL ].parent_idx;
  }
  return 0;
}

static void
complete_task( case_t *     tc,
               inflight_t * task ) {
  block_t * block = tc->block + (task->bank_idx-1UL);
  switch( task->task_type ) {
    case FD_SCHED_TT_TXN_EXEC: {
      fd_sched_txn_info_t * info = fd_sched_get_txn_info( tc->sched, task->txn_idx );
      FD_TEST( info );
      FD_TEST( !(info->flags & FD_SCHED_TXN_EXEC_DONE) );
      if( FD_UNLIKELY( block->failure_mode==TEST_FAIL_EXEC && !block->failure_injected ) ) {
        block->failure_injected = 1;
        block->dead_seen        = 1;
        fd_sched_block_abandon( tc->sched, task->bank_idx );
      }
      FD_TEST( 0==fd_sched_task_done( tc->sched, FD_SCHED_TT_TXN_EXEC, task->txn_idx, task->exec_idx, NULL ) );
      info = fd_sched_get_txn_info( tc->sched, task->txn_idx );
      FD_TEST( info && (info->flags & FD_SCHED_TXN_EXEC_DONE) );
      block->exec_done_mask |= 1UL << task->local_txn_idx;
      break;
    }
    case FD_SCHED_TT_TXN_SIGVERIFY: {
      fd_sched_txn_info_t * info = fd_sched_get_txn_info( tc->sched, task->txn_idx );
      FD_TEST( info );
      FD_TEST( !(info->flags & FD_SCHED_TXN_SIGVERIFY_DONE) );
      if( FD_UNLIKELY( block->failure_mode==TEST_FAIL_SIG && !block->failure_injected ) ) {
        block->failure_injected = 1;
        block->dead_seen        = 1;
        fd_sched_block_abandon( tc->sched, task->bank_idx );
      }
      FD_TEST( 0==fd_sched_task_done( tc->sched, FD_SCHED_TT_TXN_SIGVERIFY, task->txn_idx, task->exec_idx, NULL ) );
      info = fd_sched_get_txn_info( tc->sched, task->txn_idx );
      FD_TEST( info && (info->flags & FD_SCHED_TXN_SIGVERIFY_DONE) );
      block->sig_done_mask |= 1UL << task->local_txn_idx;
      break;
    }
    case FD_SCHED_TT_POH_HASH: {
      int is_lineage_dead = lineage_dead( tc, task->bank_idx );
      fd_execrp_poh_hash_done_msg_t msg[ 1 ];
      msg->mblk_idx = task->mblk_idx;
      msg->hashcnt  = task->hashcnt;
      FD_TEST( task->local_mblk_idx < block->mblk_cnt );
      FD_TEST( task->hashcnt == mblk_task_hashcnt( block, task->local_mblk_idx ) );
      FD_TEST( !memcmp( task->hash, block->mblk_start_hash + task->local_mblk_idx, sizeof(fd_hash_t) ) );
      repeat_hash( msg->hash, task->hash, task->hashcnt );
      FD_TEST( !memcmp( msg->hash, block->mblk_hashed_hash + task->local_mblk_idx, sizeof(fd_hash_t) ) );
      if( FD_UNLIKELY( block->failure_mode==TEST_FAIL_POH && !block->failure_injected ) ) {
        block->failure_injected = 1;
        msg->hash->hash[ 0 ]   ^= (uchar)0x80;
      }
      int rc = fd_sched_task_done( tc->sched, FD_SCHED_TT_POH_HASH, ULONG_MAX, task->exec_idx, msg );
      if( FD_UNLIKELY( block->failure_mode==TEST_FAIL_POH && block->failure_injected ) ) {
        FD_TEST( rc==0 || rc==-1 );
        if( FD_UNLIKELY( rc==-1 ) ) block->dead_seen = 1;
      } else if( FD_UNLIKELY( is_lineage_dead ) ) {
        FD_TEST( rc==0 || rc==-1 );
        if( FD_UNLIKELY( rc==-1 ) ) block->dead_seen = 1;
      } else {
        FD_TEST( rc==0 );
      }
      break;
    }
    default: FD_LOG_ERR(( "unexpected async task type %lu", task->task_type ));
  }
}

/* rdisp_mirror_verify does a rather expensive O(depth + edges) check,
   that we do a lot trading of exec/s for a very fine grained oracle.
   If we want to do this trade-off a different way, call this function
   behind pseudo-randomly. */
static void
rdisp_mirror_verify( mirror_t * mirror,
                     ulong      slot ) {
  FD_TEST( slot<TEST_MAX_BLOCKS );
  FD_TEST( mirror->disp[ slot ] );
  fd_rdisp_verify( mirror->disp[ slot ], mirror->verify_scratch[ slot ] );
}


static void
rdisp_mirror_destroy( mirror_t * mirror ) {
  for( ulong slot=0UL; slot<TEST_MAX_BLOCKS; slot++ ) {
    if( FD_UNLIKELY( !mirror->mem[ slot ] ) ) continue;
    fd_rdisp_delete( fd_rdisp_leave( mirror->disp[ slot ] ) );
    free( mirror->mem[ slot ] );
    mirror->mem [ slot ] = NULL;
    mirror->disp[ slot ] = NULL;
  }
}

static void
rdisp_mirror_ensure_block( mirror_t * mirror,
                           block_t const * block ) {
  ulong slot = block->bank_idx-1UL;
  if( FD_UNLIKELY( !mirror->mem[ slot ] ) ) {
    ulong footprint = fd_rdisp_footprint( TEST_RDISP_DEPTH, TEST_RDISP_BLOCK_DEPTH );
    mirror->mem[ slot ] = aligned_alloc( fd_rdisp_align(), footprint );
    FD_TEST( mirror->mem[ slot ] );
    mirror->disp[ slot ] = fd_rdisp_join( fd_rdisp_new( mirror->mem[ slot ],
                                                        TEST_RDISP_DEPTH,
                                                        TEST_RDISP_BLOCK_DEPTH,
                                                        0x51a0f95dUL + block->bank_idx ) );
    FD_TEST( mirror->disp[ slot ] );
  }

  if( FD_UNLIKELY( !mirror->block_added[ slot ] ) ) {
    FD_TEST( 0==fd_rdisp_add_block( mirror->disp[ slot ], block->bank_idx, FD_RDISP_UNSTAGED ) );
    mirror->block_added[ slot ] = 1U;
  }

  rdisp_mirror_verify( mirror, slot );
}

static ulong
rdisp_mirror_find_local( mirror_t const * mirror,
                         ulong            bank_idx,
                         ulong            txn_idx ) {
  FD_TEST( bank_idx>0UL && bank_idx<=TEST_MAX_BLOCKS );
  ulong slot = bank_idx-1UL;
  for( ulong i=mirror->txn_added_cnt[ slot ]; i>0UL; i-- ) {
    ulong local_txn_idx = i-1UL;
    if( FD_LIKELY( mirror->txn_idx[ slot ][ local_txn_idx ]==txn_idx ) ) return local_txn_idx;
  }
  return ULONG_MAX;
}

static int
rdisp_mirror_run_ready( mirror_t * mirror,
                        block_t const * block ) {
  ulong slot = block->bank_idx-1UL;
  if( FD_UNLIKELY( !mirror->block_added[ slot ] || mirror->block_retired[ slot ] ) ) return 0;

  ulong mirror_txn_idx = fd_rdisp_get_next_ready( mirror->disp[ slot ], block->bank_idx );
  if( FD_UNLIKELY( !mirror_txn_idx ) ) return 0;

  ulong local_txn_idx = rdisp_mirror_find_local( mirror, block->bank_idx, mirror_txn_idx );
  FD_TEST( local_txn_idx<mirror->txn_added_cnt[ slot ] );
  ulong mask = 1UL << local_txn_idx;
  FD_TEST( !(mirror->exec_done_mask[ slot ] & mask) );
  FD_TEST( ( mirror->exec_done_mask[ slot ] & block->pred_mask[ local_txn_idx ] ) == block->pred_mask[ local_txn_idx ] );
  fd_rdisp_complete_txn( mirror->disp[ slot ], mirror_txn_idx, 1 );
  mirror->exec_done_mask[ slot ] |= mask;
  mirror->reclaimed_mask[ slot ] |= mask;
  mirror->txn_idx[ slot ][ local_txn_idx ] = 0UL;
  rdisp_mirror_verify( mirror, slot );
  return 1;
}

static void
rdisp_mirror_drain_block( mirror_t * mirror,
                          block_t const * block ) {
  while( rdisp_mirror_run_ready( mirror, block ) ) {}
}

static void
rdisp_mirror_ingest_block( mirror_t * mirror,
                           block_t const * block ) {
  ulong slot = block->bank_idx-1UL;
  FD_TEST( block->ingested_seg_cnt>0UL );
  if( FD_UNLIKELY( mirror->block_retired[ slot ] ) ) return;
  rdisp_mirror_ensure_block( mirror, block );

  ulong seg_end = block->seg_end[ block->ingested_seg_cnt-1UL ];
  while( mirror->txn_added_cnt[ slot ]<block->txn_cnt ) {
    ulong local_txn_idx = mirror->txn_added_cnt[ slot ];
    if( FD_UNLIKELY( block->txn_end_off[ local_txn_idx ]>seg_end ) ) break;

    uchar meta[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
    ulong pay_sz = 0UL;
    ulong txn_sz = fd_txn_parse_core( block->txn[ local_txn_idx ].payload,
                                      block->txn[ local_txn_idx ].payload_sz,
                                      fd_type_pun( meta ),
                                      NULL,
                                      &pay_sz );
    FD_TEST( txn_sz );
    FD_TEST( pay_sz==block->txn[ local_txn_idx ].payload_sz );

    ulong txn_idx = fd_rdisp_add_txn( mirror->disp[ slot ],
                                      block->bank_idx,
                                      fd_type_pun_const( meta ),
                                      block->txn[ local_txn_idx ].payload,
                                      NULL,
                                      0 );
    FD_TEST( txn_idx!=0UL );
    mirror->txn_idx[ slot ][ local_txn_idx ] = txn_idx;
    mirror->txn_added_cnt[ slot ]++;
  }

  rdisp_mirror_verify( mirror, slot );
}

static void
rdisp_mirror_try_retire_dead_blocks( case_t const *  tc,
                                     mirror_t *      mirror ) {
  for( ulong i=0UL; i<tc->block_cnt; i++ ) {
    block_t const * block = tc->block + i;
    ulong slot = block->bank_idx-1UL;
    if( FD_UNLIKELY( !mirror->block_added [ slot ] ) ) continue;
    if( FD_UNLIKELY(  mirror->block_retired[ slot ] ) ) continue;
    if( FD_UNLIKELY( !block->dead_seen ) ) continue;
    FD_TEST( 0==fd_rdisp_abandon_block( mirror->disp[ slot ], block->bank_idx ) );
    mirror->block_retired[ slot ] = 1U;
    rdisp_mirror_verify( mirror, slot );
  }
}

static void
rdisp_mirror_remove_block( mirror_t * mirror,
                           block_t const * block ) {
  ulong slot = block->bank_idx-1UL;
  if( FD_UNLIKELY( !mirror->block_added[ slot ] || mirror->block_retired[ slot ] ) ) return;
  FD_TEST( mirror->txn_added_cnt[ slot ]==block->txn_cnt );
  FD_TEST( mirror->reclaimed_mask[ slot ]==block_txn_mask( block ) );
  FD_TEST( 0==fd_rdisp_remove_block( mirror->disp[ slot ], block->bank_idx ) );
  mirror->block_retired[ slot ] = 1U;
  rdisp_mirror_verify( mirror, slot );
}

static void
rdisp_mirror_fini( case_t const *  tc,
                   mirror_t *      mirror ) {
  rdisp_mirror_try_retire_dead_blocks( tc, mirror );
  for( ulong i=0UL; i<tc->block_cnt; i++ ) {
    block_t const * block = tc->block + i;
    ulong slot = block->bank_idx-1UL;
    if( FD_UNLIKELY( !mirror->block_added [ slot ] ) ) continue;
    if( FD_UNLIKELY(  mirror->block_retired[ slot ] ) ) continue;
    if( FD_LIKELY( block->end_seen ) ) {
      rdisp_mirror_drain_block( mirror, block );
      rdisp_mirror_remove_block( mirror, block );
    }
    else {
      FD_TEST( 0==fd_rdisp_abandon_block( mirror->disp[ slot ], block->bank_idx ) );
      mirror->block_retired[ slot ] = 1U;
      rdisp_mirror_verify( mirror, slot );
    }
  }
}

static void
encode_tick_block( uchar *           encoded,
                   ulong *           encoded_sz,
                   fd_hash_t const * start_poh,
                   ulong const *     tick_hashcnt,
                   ulong             tick_cnt ) {
  FD_STORE( ulong, encoded, tick_cnt );
  ulong cursor = sizeof(ulong);

  fd_hash_t prev_hash[ 1 ];
  fd_memcpy( prev_hash, start_poh, sizeof(fd_hash_t) );

  for( ulong i=0UL; i<tick_cnt; i++ ) {
    fd_hash_t end_hash[ 1 ];
    repeat_hash( end_hash, prev_hash, tick_hashcnt[ i ] );

    fd_microblock_hdr_t hdr = {
      .hash_cnt = tick_hashcnt[ i ],
      .txn_cnt  = 0UL
    };
    fd_memcpy( hdr.hash, end_hash->hash, sizeof(fd_hash_t) );
    fd_memcpy( encoded + cursor, &hdr, sizeof(fd_microblock_hdr_t) );
    cursor += sizeof(fd_microblock_hdr_t);
    fd_memcpy( prev_hash, end_hash, sizeof(fd_hash_t) );
  }

  *encoded_sz = cursor;
}

static void
run_bad_tick_case( fd_hash_t const * start_poh,
                   ulong const *     tick_hashcnt,
                   ulong             tick_cnt,
                   ulong             max_tick_height,
                   ulong             hashes_per_tick,
                   int               expect_mark_dead,
                   int               expect_poh_fail ) {
  /* Reuse the reduced fuzz depth here; this test only needs the root,
     the parent, the child under test, and one spare slot. */
  ulong depth         = fd_ulong_max( FD_SCHED_MIN_DEPTH, 512UL );
  ulong block_cnt_max = 4UL;
  ulong footprint     = fd_sched_footprint( depth, block_cnt_max );
  void * mem          = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( mem );

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, TEST_EXEC_CNT ) );
  FD_TEST( sched );

  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

  uchar encoded[ sizeof(ulong) + 4UL*sizeof(fd_microblock_hdr_t) ] = {0};
  ulong encoded_sz = 0UL;
  encode_tick_block( encoded, &encoded_sz, start_poh, tick_hashcnt, tick_cnt );

  fd_store_fec_t store_fec[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
  fd_memset( store_fec, 0, sizeof(fd_store_fec_t) );
  store_fec->data_sz       = encoded_sz;
  store_fec->shred_offs[0] = (uint)encoded_sz;

  fd_sched_fec_t fec[ 1 ] = {{
    .bank_idx          = 2UL,
    .parent_bank_idx   = 1UL,
    .slot              = TEST_ROOT_SLOT + 1UL,
    .parent_slot       = TEST_ROOT_SLOT,
    .fec               = store_fec,
    .data              = encoded,
    .shred_cnt         = 1U,
    .is_last_in_batch  = 1U,
    .is_last_in_block  = 1U,
    .is_first_in_block = 1U
  }};
  FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
  FD_TEST( fd_sched_fec_ingest( sched, fec ) );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, max_tick_height, hashes_per_tick, start_poh );

  fd_sched_task_t task[ 1 ];
  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START );
  FD_TEST( task->block_start->bank_idx==2UL );
  FD_TEST( 0==fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_START, ULONG_MAX, ULONG_MAX, NULL ) );

  int seen_mark_dead = 0;
  int seen_poh_fail  = 0;
  for(;;) {
    while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
    if( FD_UNLIKELY( !fd_sched_task_next_ready( sched, task ) ) ) break;
    switch( task->task_type ) {
      case FD_SCHED_TT_MARK_DEAD:
        FD_TEST( task->mark_dead->bank_idx==2UL );
        seen_mark_dead = 1;
        break;
      case FD_SCHED_TT_POH_HASH: {
        fd_execrp_poh_hash_done_msg_t msg[ 1 ];
        msg->mblk_idx = task->poh_hash->mblk_idx;
        msg->hashcnt  = task->poh_hash->hashcnt;
        repeat_hash( msg->hash, task->poh_hash->hash, task->poh_hash->hashcnt );
        int rc = fd_sched_task_done( sched, FD_SCHED_TT_POH_HASH, ULONG_MAX, task->poh_hash->exec_idx, msg );
        if( FD_UNLIKELY( rc==-1 ) ) seen_poh_fail = 1;
        else                        FD_TEST( rc==0 );
        break;
      }
      default:
        FD_LOG_ERR(( "unexpected task_type %lu in bad tick case", task->task_type ));
    }
  }

  FD_TEST( seen_mark_dead==expect_mark_dead );
  FD_TEST( seen_poh_fail ==expect_poh_fail  );
  FD_TEST( fd_sched_is_drained( sched ) );
  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}

  fd_sched_delete( fd_sched_leave( sched ) );
  free( mem );
}

static void
run_bad_tick_cases( uchar const * data,
                    ulong         data_sz ) {
  (void)data;

  fd_hash_t start_poh[ 1 ];
  hash_from_seed( start_poh, 0x4d85f12e7a9b3105UL ^ data_sz );

  {
    ulong tick_hashcnt[ 1 ] = { 1UL };
    run_bad_tick_case( start_poh,
                       tick_hashcnt,
                       1UL,
                       TEST_ROOT_TICK_HEIGHT + 2UL,
                       1UL,
                       1,
                       0 );
  }

  {
    ulong tick_hashcnt[ 2 ] = { 1UL, 1UL };
    run_bad_tick_case( start_poh,
                       tick_hashcnt,
                       2UL,
                       TEST_ROOT_TICK_HEIGHT + 1UL,
                       1UL,
                       0,
                       1 );
  }

  {
    ulong tick_hashcnt[ 2 ] = { 1UL, 2UL };
    run_bad_tick_case( start_poh,
                       tick_hashcnt,
                       2UL,
                       TEST_ROOT_TICK_HEIGHT + 2UL,
                       2UL,
                       0,
                       1 );
  }
}

static void
run_lane_policy_case( uchar const * data,
                      ulong         data_sz ) {
  (void)data;

  /* Reuse the reduced fuzz depth here; this test only needs the root
     and a handful of synthetic branches. */
  ulong depth         = fd_ulong_max( FD_SCHED_MIN_DEPTH, 512UL );
  ulong block_cnt_max = 8UL;
  ulong footprint     = fd_sched_footprint( depth, block_cnt_max );
  void * mem          = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( mem );

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, TEST_EXEC_CNT ) );
  FD_TEST( sched );

  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );
  FD_TEST( fd_sched_is_drained( sched ) );
  (void)fd_sched_can_ingest_cnt( sched );

  fd_hash_t start_poh[ 1 ];
  hash_from_seed( start_poh, 0x91b53d8a74f2c601UL ^ data_sz );

  for( ulong bank_idx=2UL; bank_idx<=5UL; bank_idx++ ) {
    fd_store_fec_t store_fec[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
    fd_memset( store_fec, 0, sizeof(fd_store_fec_t) );

    fd_sched_fec_t fec[ 1 ] = {{
      .bank_idx          = bank_idx,
      .parent_bank_idx   = 1UL,
      .slot              = TEST_ROOT_SLOT + bank_idx - 1UL,
      .parent_slot       = TEST_ROOT_SLOT,
      .fec               = store_fec,
      .shred_cnt         = 1U,
      .is_last_in_batch  = 0U,
      .is_last_in_block  = 0U,
      .is_first_in_block = 1U
    }};
    FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
    FD_TEST( fd_sched_fec_ingest( sched, fec ) );
    fd_sched_set_poh_params( sched, bank_idx, TEST_ROOT_TICK_HEIGHT + bank_idx, TEST_ROOT_TICK_HEIGHT + bank_idx + 1UL, 1UL, start_poh );

    fd_sched_task_t task[ 1 ];
    FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
    FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START );
    FD_TEST( task->block_start->bank_idx==bank_idx );
    FD_TEST( 0==fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_START, ULONG_MAX, ULONG_MAX, NULL ) );
    FD_TEST( fd_sched_is_drained( sched ) );
  }

  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "staged_bitset 15," ) );

  {
    ulong bank_idx = 6UL;
    fd_store_fec_t store_fec[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
    fd_memset( store_fec, 0, sizeof(fd_store_fec_t) );

    fd_sched_fec_t fec[ 1 ] = {{
      .bank_idx          = bank_idx,
      .parent_bank_idx   = 1UL,
      .slot              = TEST_ROOT_SLOT + bank_idx - 1UL,
      .parent_slot       = TEST_ROOT_SLOT,
      .fec               = store_fec,
      .shred_cnt         = 1U,
      .is_last_in_batch  = 0U,
      .is_last_in_block  = 0U,
      .is_first_in_block = 1U
    }};
    FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
    FD_TEST( fd_sched_fec_ingest( sched, fec ) );
    fd_sched_set_poh_params( sched, bank_idx, TEST_ROOT_TICK_HEIGHT + bank_idx, TEST_ROOT_TICK_HEIGHT + bank_idx + 1UL, 1UL, start_poh );
  }

  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 6, staged_bitset 1," ) );
  FD_TEST( strstr( state, "block_added_staged_cnt 4," ) );
  FD_TEST( strstr( state, "block_added_unstaged_cnt 1," ) );
  FD_TEST( strstr( state, "block_promoted_cnt 1," ) );
  FD_TEST( strstr( state, "block_demoted_cnt 4," ) );
  FD_TEST( strstr( state, "lane_promoted_cnt 1," ) );
  FD_TEST( strstr( state, "lane_demoted_cnt 4," ) );

  fd_sched_task_t task[ 1 ];
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START );
  FD_TEST( task->block_start->bank_idx==6UL );
  FD_TEST( 0==fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_START, ULONG_MAX, ULONG_MAX, NULL ) );
  FD_TEST( fd_sched_is_drained( sched ) );

  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx ULONG_MAX, staged_bitset 1," ) );

  fd_sched_delete( fd_sched_leave( sched ) );
  free( mem );
}

static void
run_sched_rdisp_case( uchar const * data, ulong data_sz ) {
  case_t tc[ 1 ];
  build_case( tc, data, data_sz );

  mirror_t mirror[ 1 ] = {0};

  inflight_t inflight[ TEST_EXEC_CNT * 4UL ];
  ulong inflight_cnt = 0UL;
  reader_t r = {
    .data    = data,
    .data_sz = data_sz,
    .off     = 0UL,
    .salt    = 0x83c41a8e7b81d7f1UL ^ data_sz
  };

  /* Main harness event loop.  At the fd_sched API boundary this drives
     the same protocol the production replay tile uses: blocks become
     visible via fd_sched_fec_ingest() and fd_sched_set_poh_params(),
     replay polls fd_sched_task_next_ready(), BLOCK_START/BLOCK_END and
     MARK_DEAD are handled locally, and TXN_EXEC/TXN_SIGVERIFY/POH_HASH
     are completed later with fd_sched_task_done() after worker
     responses arrive. */
  for( ulong steps=0UL; steps<100000UL; steps++ ) {
    drain_refs( tc );
    rdisp_mirror_try_retire_dead_blocks( tc, mirror );

    if( FD_LIKELY( inflight_cnt && ( fd_sched_is_drained( tc->sched ) || read_uchar( &r )&1U ) ) ) {
      ulong which = read_range( &r, inflight_cnt );
      inflight_t task = inflight[ which ];
      inflight[ which ] = inflight[ --inflight_cnt ];

      complete_task( tc, &task );
      rdisp_mirror_try_retire_dead_blocks( tc, mirror );
      continue;
    }

    ulong ingestable_cnt = ingestable_block_cnt( tc );
    if( FD_UNLIKELY( ingestable_cnt && ( !inflight_cnt || fd_sched_is_drained( tc->sched ) || !(read_uchar( &r )&3U) ) ) ) {
      ulong bank_idx = ingest_pending_block_idx( tc, &r );
      FD_TEST( bank_idx>0UL && bank_idx<=tc->block_cnt );
      block_t const * block = tc->block + (bank_idx-1UL);
      rdisp_mirror_ingest_block( mirror, block );
      if( read_uchar( &r )&1U ) (void)rdisp_mirror_run_ready( mirror, block );
      continue;
    }

    fd_sched_task_t task[ 1 ];
    if( FD_UNLIKELY( !fd_sched_task_next_ready( tc->sched, task ) ) ) {
      if( FD_UNLIKELY( ingestable_cnt ) ) {
        ulong bank_idx = ingest_pending_block_idx( tc, &r );
        FD_TEST( bank_idx>0UL && bank_idx<=tc->block_cnt );
        block_t const * block = tc->block + (bank_idx-1UL);
        rdisp_mirror_ingest_block( mirror, block );
        if( read_uchar( &r )&1U ) (void)rdisp_mirror_run_ready( mirror, block );
        continue;
      }
      if( FD_LIKELY( !inflight_cnt ) ) break;
      continue;
    }

    ulong bank_idx = ULONG_MAX;
    switch( task->task_type ) {
      case FD_SCHED_TT_BLOCK_START: {
        bank_idx = task->block_start->bank_idx;
        FD_TEST( bank_idx>0UL && bank_idx<=tc->block_cnt );
        block_t * block = tc->block + (bank_idx-1UL);
        FD_TEST( !block->start_seen );
        if( FD_LIKELY( block->parent_idx!=0UL ) ) FD_TEST( tc->block[ block->parent_idx-1UL ].end_seen );
        block->start_seen = 1;
        FD_TEST( 0==fd_sched_task_done( tc->sched, FD_SCHED_TT_BLOCK_START, ULONG_MAX, ULONG_MAX, NULL ) );
        break;
      }
      case FD_SCHED_TT_BLOCK_END: {
        bank_idx = task->block_end->bank_idx;
        FD_TEST( bank_idx>0UL && bank_idx<=tc->block_cnt );
        block_t * block = tc->block + (bank_idx-1UL);
        FD_TEST( block->start_seen );
        FD_TEST( !block->dead_seen );
        FD_TEST( block->exec_done_mask == block_txn_mask( block ) );
        FD_TEST( block->sig_done_mask  == block_txn_mask( block ) );
        FD_TEST( !memcmp( fd_sched_get_poh( tc->sched, bank_idx ), block->end_poh, sizeof(fd_hash_t) ) );
        FD_TEST( fd_sched_get_shred_cnt( tc->sched, bank_idx ) == (uint)block->seg_cnt );
        FD_TEST( 0==fd_sched_task_done( tc->sched, FD_SCHED_TT_BLOCK_END, ULONG_MAX, ULONG_MAX, NULL ) );
        block->end_seen = 1;
        rdisp_mirror_drain_block( mirror, block );
        rdisp_mirror_remove_block( mirror, block );
        break;
      }
      case FD_SCHED_TT_MARK_DEAD: {
        bank_idx = task->mark_dead->bank_idx;
        FD_TEST( bank_idx>0UL && bank_idx<=tc->block_cnt );
        tc->block[ bank_idx-1UL ].dead_seen = 1;
        rdisp_mirror_try_retire_dead_blocks( tc, mirror );
        break;
      }
      case FD_SCHED_TT_TXN_EXEC:
      case FD_SCHED_TT_TXN_SIGVERIFY: {
        bank_idx = fd_ulong_if( task->task_type==FD_SCHED_TT_TXN_EXEC, task->txn_exec->bank_idx, task->txn_sigverify->bank_idx );
        ulong txn_idx  = fd_ulong_if( task->task_type==FD_SCHED_TT_TXN_EXEC, task->txn_exec->txn_idx, task->txn_sigverify->txn_idx );
        ulong exec_idx = fd_ulong_if( task->task_type==FD_SCHED_TT_TXN_EXEC, task->txn_exec->exec_idx, task->txn_sigverify->exec_idx );
        FD_TEST( bank_idx>0UL && bank_idx<=tc->block_cnt );
        block_t * block = tc->block + (bank_idx-1UL);
        fd_txn_p_t * txn = fd_sched_get_txn( tc->sched, txn_idx );
        fd_sched_txn_info_t * info = fd_sched_get_txn_info( tc->sched, txn_idx );
        FD_TEST( txn );
        FD_TEST( info );
        ulong local = find_txn( block, txn );
        FD_TEST( local!=ULONG_MAX );
        FD_TEST( block->start_seen );
        if( FD_LIKELY( task->task_type==FD_SCHED_TT_TXN_EXEC ) )
          FD_TEST( (block->exec_done_mask & block->pred_mask[ local ]) == block->pred_mask[ local ] );
        if( FD_LIKELY( task->task_type==FD_SCHED_TT_TXN_EXEC ) ) FD_TEST( !(info->flags & FD_SCHED_TXN_EXEC_DONE) );
        else                                                     FD_TEST( !(info->flags & FD_SCHED_TXN_SIGVERIFY_DONE) );
        inflight[ inflight_cnt++ ] = (inflight_t) {
          .task_type     = task->task_type,
          .bank_idx      = bank_idx,
          .txn_idx       = txn_idx,
          .exec_idx      = exec_idx,
          .local_txn_idx = local,
        };
        break;
      }
      case FD_SCHED_TT_POH_HASH: {
        bank_idx = task->poh_hash->bank_idx;
        FD_TEST( bank_idx>0UL && bank_idx<=tc->block_cnt );
        block_t * block = tc->block + (bank_idx-1UL);
        FD_TEST( block->start_seen );
        FD_TEST( !block->end_seen );
        ulong local_mblk_idx = block->poh_dispatch_mblk_cnt++;
        FD_TEST( local_mblk_idx<block->mblk_cnt );
        FD_TEST( task->poh_hash->hashcnt == mblk_task_hashcnt( block, local_mblk_idx ) );
        FD_TEST( !memcmp( task->poh_hash->hash, block->mblk_start_hash + local_mblk_idx, sizeof(fd_hash_t) ) );
        inflight[ inflight_cnt++ ] = (inflight_t) {
          .task_type      = FD_SCHED_TT_POH_HASH,
          .bank_idx       = bank_idx,
          .exec_idx       = task->poh_hash->exec_idx,
          .mblk_idx       = task->poh_hash->mblk_idx,
          .local_mblk_idx = local_mblk_idx,
          .hashcnt        = task->poh_hash->hashcnt,
        };
        fd_memcpy( inflight[ inflight_cnt-1UL ].hash, task->poh_hash->hash, sizeof(fd_hash_t) );
        break;
      }
      default: FD_LOG_ERR(( "unexpected task_type %lu", task->task_type ));
    }
  }

  while( inflight_cnt ) {
    drain_refs( tc );
    inflight_t task = inflight[ --inflight_cnt ];
    complete_task( tc, &task );
    rdisp_mirror_try_retire_dead_blocks( tc, mirror );
  }
  drain_refs( tc );

  ulong leaf = 0UL;
  for( ulong i=0UL; i<tc->block_cnt; i++ ) {
    block_t const * block = tc->block + i;
    if( FD_UNLIKELY( block->dead_seen || !block->end_seen ) ) continue;
    if( leaf==0UL || block->slot > tc->block[ leaf-1UL ].slot ) leaf = block->bank_idx;
  }

  if( FD_LIKELY( leaf>0UL ) ) {
    drain_refs( tc );
    fd_sched_root_notify( tc->sched, leaf );
    drain_refs( tc );
    fd_sched_advance_root( tc->sched, leaf );
    drain_refs( tc );
  }

  FD_TEST( fd_sched_is_drained( tc->sched ) );
  FD_TEST( fd_sched_get_state_cstr( tc->sched ) );
  drain_refs( tc );
  FD_TEST( !fd_sched_task_next_ready( tc->sched, (fd_sched_task_t [1]){{0}} ) );

  for( ulong i=0UL; i<tc->block_cnt; i++ ) {
    FD_TEST( !tc->block[ i ].end_seen || tc->block[ i ].start_seen );
    if( FD_UNLIKELY( tc->block[ i ].start_seen && !tc->block[ i ].dead_seen ) ) FD_TEST( tc->block[ i ].end_seen );
  }

  /* After root advancement every ingested block that is not the new
     root or a descendant of it must have had its scheduler ref
     released via fd_sched_pruned_block_next. */
  if( FD_LIKELY( leaf>0UL ) ) {
    for( ulong i=0UL; i<tc->block_cnt; i++ ) {
      block_t const * block = tc->block + i;
      if( FD_UNLIKELY( !block->ingested_seg_cnt ) ) continue;
      if( descends_from( tc, block->bank_idx, leaf ) ) continue;
      FD_TEST( block->ref_released_seen );
    }
  }

  rdisp_mirror_fini( tc, mirror );
  rdisp_mirror_destroy( mirror );
  destroy_case( tc );
  run_lane_policy_case( data, data_sz );
  run_bad_tick_cases( data, data_sz );
}

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  fd_log_level_core_set( 3 );
  atexit( fd_halt );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  run_sched_rdisp_case( data, size );
  return 0;
}
