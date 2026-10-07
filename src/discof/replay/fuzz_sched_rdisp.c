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
#include "../../ballet/bmtree/fd_bmtree.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../flamenco/alpenglow/fd_block_marker_serde.h"
#include "../../flamenco/txn/fd_txn_generate.h"

/* Keep the generated cases small.  These limits are intentionally much
   smaller than production so the fuzzer stays cheap to run and easy to
   parallelize. */
#define TEST_MAX_BLOCKS         12UL
#define TEST_MAX_TXNS_PER_BLOCK 8UL
#define TEST_MAX_ACCTS_PER_TXN  8UL
/* Writable lookup table accounts of a version 0 transaction, which the
   scheduler learns of at completion, and start-of-block writes, which
   it learns of during BLOCK_START.  Both draw from the pool of shared
   data accounts [1,8], and start-of-block writes also from sysvar-like
   accounts, so the model's distinct accounts per block are bounded. */
#define TEST_MAX_ALTS_PER_TXN   2UL
#define TEST_MAX_START_WRITES   4UL
#define TEST_MAX_ACCTS_PER_BLOCK 16UL
#define TEST_SYSVAR_ID_BASE     0x100U
#define TEST_SYSVAR_CNT         4UL
#define TEST_MAX_MBLKS_PER_BLK  8UL
#define TEST_MAX_BLOCK_BYTES    8192UL
#define TEST_MAX_SEGMENTS       12UL /* header, up to 8 entry, up to 2 footer, tick */
/* Production defaults to more execrp tiles.  Four is enough here to
   exercise task interleavings without making the state space blow up. */
#define TEST_EXEC_CNT           4UL
/* The mirror dispatcher only tracks these tiny synthetic blocks, so it
   does not need production-sized capacity. */
#define TEST_RDISP_DEPTH        32UL
#define TEST_RDISP_BLOCK_DEPTH  4UL

#define TEST_SCHED_DEPTH         512UL
#define TEST_SCHED_BLOCK_CNT_MAX ( TEST_MAX_BLOCKS + 1UL )

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
  uchar  acct_cnt;                            /* Static accounts. */
  uchar  sig_cnt;
  ushort acct_id[ TEST_MAX_ACCTS_PER_TXN ];
  uchar  acct_writable[ TEST_MAX_ACCTS_PER_TXN ];
  uchar  is_alt;                              /* Version 0 with one lookup table.  Resolution is bypassed, so the
                                                 scheduler inserts it serializing and learns its writable lookup
                                                 table accounts only when it completes. */
  uchar  alt_cnt;                             /* Writable lookup table accounts, distinct from the static ones. */
  ushort alt_id[ TEST_MAX_ALTS_PER_TXN ];
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

  fd_hash_t start_poh[ 1 ];
  fd_hash_t end_poh[ 1 ];

  txn_t  txn [ TEST_MAX_TXNS_PER_BLOCK ];
  ulong                txn_cnt;
  ulong                pred_mask[ TEST_MAX_TXNS_PER_BLOCK ];

  mblk_t mblk[ TEST_MAX_MBLKS_PER_BLK ];
  ulong                mblk_cnt;
  fd_hash_t            mblk_start_hash[ TEST_MAX_MBLKS_PER_BLK ];
  fd_hash_t            mblk_hashed_hash[ TEST_MAX_MBLKS_PER_BLK ];
  ulong                mblk_pool_idx    [ TEST_MAX_MBLKS_PER_BLK ]; /* The scheduler's index of the microblock once a PoH task named it, else ULONG_MAX. */
  ulong                mblk_curr_hashcnt[ TEST_MAX_MBLKS_PER_BLK ];
  fd_hash_t            mblk_curr_hash   [ TEST_MAX_MBLKS_PER_BLK ];

  uchar encoded[ TEST_MAX_BLOCK_BYTES ];
  ulong encoded_sz;
  ulong entry_off;  /* Offsets of the entry batch, the footer batch and the alpentick batch in encoded. */
  ulong footer_off;
  ulong tick_off;
  uint  txn_end_off[ TEST_MAX_TXNS_PER_BLOCK ];
  uchar txn_mblk_idx[ TEST_MAX_TXNS_PER_BLOCK ];
  uint  seg_end[ TEST_MAX_SEGMENTS ];
  uchar seg_eob[ TEST_MAX_SEGMENTS ]; /* Whether the segment ends a batch. */
  ulong seg_cnt;
  ulong ingested_seg_cnt;
  int   poh_params_set;

  int failure_mode;
  int failure_injected;

  ulong exec_done_mask;
  ulong sig_done_mask;
  int   start_seen;
  int   inband;     /* BLOCK_START said the block hashes in band. */
  int   end_seen;
  int   dead_seen;
  int   ref_released_seen;

  /* The LtHash model.  An account's version is the number of writes to
     it the scheduler has been told of: start-of-block writes at
     BLOCK_START, a transaction's static writable accounts and the
     lookup table accounts it hands back at its completion.  The exec
     tile's value for a subtraction is the hash of version 0 and for an
     addition the hash of the account's version when the task is handed
     out, so the block's delta is right only if every addition the
     scheduler applied was hashed after the account's last write. */
  ushort acct_id       [ TEST_MAX_ACCTS_PER_BLOCK ];
  ulong  acct_write_cnt[ TEST_MAX_ACCTS_PER_BLOCK ];
  ulong  acct_cnt;
  /* The writer bound, see
     FD_SCHED_DEAD_REASON_TOO_MANY_WRITABLE_ACCOUNTS.  Write locks the
     scheduler has charged the block for: the static writable accounts
     of the transactions it parsed, by the mirror's rule of which
     segment completes a transaction, and the lookup table accounts
     registered at completion. */
  ulong  parsed_txn_cnt;
  ulong  writable_declared;
} block_t;

typedef struct {
  void *               mem;
  fd_sched_t *         sched;
  /* Number of fuzz-generated blocks in block[].  Bank 0 is the
     synthetic snapshot root, so block[i] corresponds to bank i+1. */
  ulong                block_cnt;
  fd_hash_t            root_hash[ 1 ];
  ulong                writers_max; /* The bound on a block's declared writable accounts, lowered in some cases. */
  block_t block[ TEST_MAX_BLOCKS ];
} case_t;

typedef struct {
  ulong task_type;
  ulong bank_idx;
  ulong txn_idx;
  ulong exec_idx;
  ulong local_txn_idx;
  ulong     poh_cnt;
  ulong     hashcnt;
  ulong     mblk_idx      [ FD_SCHED_POH_PARA ];
  ulong     local_mblk_idx[ FD_SCHED_POH_PARA ];
  fd_hash_t hash          [ FD_SCHED_POH_PARA ];
  fd_lthash_value_t lthash_value[ 1 ]; /* The exec tile's result for an LTHASH_SUB or LTHASH_ADD batch, computed when the task is handed out. */
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
  uint      verify_scratch [ TEST_MAX_BLOCKS ][ TEST_RDISP_DEPTH*(FD_RDISP_MAX_ACCT_PER_TXN+1)+2 ];
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

/* The id pubkey_from_id built the address from. */
static ushort
id_from_acct( fd_acct_addr_t const * acct ) {
  return FD_LOAD( ushort, acct->b );
}

/* fake_hash is the value the exec tile returns for one account of an
   LtHash task.  It hashes the account, the task kind and the account's
   version, so that an addition hashed one write too early leaves a
   trace in the delta unless the scheduler undoes it. */
static void
fake_hash( fd_lthash_value_t *    out,
           fd_acct_addr_t const * acct,
           int                    is_add,
           ulong                  version ) {
  ulong seed = FD_LOAD( ulong, acct->b ) ^ fd_ulong_if( is_add, 0x5a5a5a5a5a5a5a5aUL, 0UL ) ^ (version*0x9e3779b97f4a7c15UL);
  for( ulong i=0UL; i<FD_LTHASH_LEN_BYTES/sizeof(ulong); i++ ) {
    seed = fd_ulong_hash( seed ^ i );
    FD_STORE( ulong, out->bytes+i*sizeof(ulong), seed );
  }
}

/* The model's write count of account id in block, 0 if the block has
   not written it. */
static ulong
block_acct_write_cnt( block_t const * block,
                      ushort          id ) {
  for( ulong i=0UL; i<block->acct_cnt; i++ ) if( block->acct_id[ i ]==id ) return block->acct_write_cnt[ i ];
  return 0UL;
}

/* Records a write to account id in block. */
static void
block_write( block_t * block,
             ushort    id ) {
  for( ulong i=0UL; i<block->acct_cnt; i++ ) {
    if( block->acct_id[ i ]==id ) { block->acct_write_cnt[ i ]++; return; }
  }
  FD_TEST( block->acct_cnt<TEST_MAX_ACCTS_PER_BLOCK );
  block->acct_id       [ block->acct_cnt ] = id;
  block->acct_write_cnt[ block->acct_cnt ] = 1UL;
  block->acct_cnt++;
}

/* The delta a block must end with.  For every account it wrote, that
   is the hash of its final version minus the hash of its version in
   the parent. */
static void
block_expected_delta( block_t const *     block,
                      fd_lthash_value_t * out ) {
  fd_lthash_zero( out );
  for( ulong i=0UL; i<block->acct_cnt; i++ ) {
    fd_pubkey_t acct[ 1 ];
    pubkey_from_id( acct, block->acct_id[ i ] );
    fd_lthash_value_t h[ 1 ];
    fake_hash( h, fd_type_pun_const( acct ), 1, block->acct_write_cnt[ i ] ); fd_lthash_add( out, h );
    fake_hash( h, fd_type_pun_const( acct ), 0, 0UL );                        fd_lthash_sub( out, h );
  }
}

/* The exec tile's value for an LtHash task handed out now. */
static void
lthash_task_value( block_t const *         block,
                   fd_sched_task_t const * task,
                   fd_lthash_value_t *     out ) {
  int is_add = task->task_type==FD_SCHED_TT_LTHASH_ADD;
  fd_lthash_zero( out );
  for( ulong i=0UL; i<task->lthash->cnt; i++ ) {
    fd_acct_addr_t const * acct    = task->lthash->accts+i;
    ulong                  version = block_acct_write_cnt( block, id_from_acct( acct ) );
    /* An addition is sequenced after the account's last write so far. */
    FD_TEST( !is_add || version );
    fd_lthash_value_t h[ 1 ];
    fake_hash( h, acct, is_add, fd_ulong_if( is_add, version, 0UL ) );
    fd_lthash_add( out, h );
  }
}

/* The static writable accounts a transaction declares, a write lock
   each. */
static ulong
txn_writable_cnt( txn_t const * txn ) {
  ulong cnt = 0UL;
  for( ulong i=0UL; i<txn->acct_cnt; i++ ) cnt += (ulong)txn->acct_writable[ i ];
  return cnt;
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

/* txn_conflicts returns 1 if the two txns conflict, zero otherwise.  A
   lookup table transaction is serializing and conflicts with every
   other transaction of its block. */
static int
txn_conflicts( txn_t const * a,
               txn_t const * b ) {
  if( FD_UNLIKELY( a->is_alt | b->is_alt ) ) return 1;
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
   serialized the header marker, exactly block->mblk_cnt-1 transaction
   microblocks, the footer marker and the alpentick at the cached
   offsets, that each microblock header still matches the cached mblk[]
   metadata, and that the byte cursor implied by those headers lands
   exactly on block->encoded_sz after consuming every transaction.

   Every entry advances exactly one hash.  For a transaction
   microblock that hash is the mixin of the Merkle root of its
   transactions, and for the alpentick a plain hash.  In both cases the
   recomputed header hash must match the serialized header.

   Walking the block this way also checks that the cached start_poh and
   end_poh values are internally consistent with the wire image.  If any
   assertion here fails, the fuzz case is malformed and the later
   scheduler checks would no longer be meaningful. */
FD_FN_UNUSED static void
verify_block_encoding( block_t const * block ) {
  fd_block_marker_t marker[ 1 ];
  FD_TEST( !fd_block_marker_de( marker, block->encoded, block->entry_off ) && marker->kind==FD_BLOCK_MARKER_KIND_HEADER );
  FD_TEST( !fd_block_marker_de( marker, block->encoded+block->footer_off, block->tick_off-block->footer_off ) && marker->kind==FD_BLOCK_MARKER_KIND_FOOTER );

  ulong cursor = block->entry_off;
  FD_TEST( FD_LOAD( ulong, block->encoded+cursor )==block->mblk_cnt-1UL );
  cursor += sizeof(ulong);
  ulong txn_off = 0UL;
  fd_hash_t prev_hash[ 1 ];
  fd_memcpy( prev_hash, block->start_poh, sizeof(fd_hash_t) );

  for( ulong i=0UL; i<block->mblk_cnt-1UL; i++ ) {
    FD_TEST( cursor + sizeof(fd_microblock_hdr_t) <= block->footer_off );
    fd_microblock_hdr_t const * hdr = fd_type_pun_const( block->encoded + cursor );
    cursor += sizeof(fd_microblock_hdr_t);

    if( FD_UNLIKELY( hdr->txn_cnt != block->mblk[ i ].txn_cnt ) ) {
      FD_LOG_ERR(( "builder txn_cnt mismatch on mblk %lu: hdr %lu expected %u cursor %lu encoded_sz %lu",
                   i, hdr->txn_cnt, block->mblk[ i ].txn_cnt, cursor-sizeof(fd_microblock_hdr_t), block->encoded_sz ));
    }
    FD_TEST( hdr->txn_cnt && hdr->hash_cnt==1UL && block->mblk[ i ].wire_hash_cnt==1UL );

    fd_hash_t merkle[ 1 ];
    merkle_root( merkle, block->txn + txn_off, hdr->txn_cnt );

    uchar mixin[ 64 ];
    fd_memcpy( mixin,      prev_hash->hash, 32UL );
    fd_memcpy( mixin+32UL, merkle->hash,    32UL );
    fd_hash_t end_hash[ 1 ];
    fd_sha256_hash( mixin, sizeof(mixin), end_hash->hash );

    if( FD_UNLIKELY( memcmp( hdr->hash, end_hash->hash, sizeof(fd_hash_t) ) ) ) {
      FD_BASE58_ENCODE_32_BYTES( hdr->hash, hdr_str );
      FD_BASE58_ENCODE_32_BYTES( end_hash->hash, expect_str );
      FD_LOG_ERR(( "builder hash mismatch on mblk %lu: hdr %s expected %s txn_off %lu txn_cnt %lu",
                   i, hdr_str, expect_str, txn_off, (ulong)hdr->txn_cnt ));
    }

    for( ulong j=0UL; j<hdr->txn_cnt; j++ ) cursor += block->txn[ txn_off + j ].payload_sz;
    txn_off += hdr->txn_cnt;
    fd_memcpy( prev_hash, end_hash, sizeof(fd_hash_t) );
  }
  FD_TEST( txn_off == block->txn_cnt );
  FD_TEST( cursor == block->footer_off );

  cursor = block->tick_off;
  FD_TEST( FD_LOAD( ulong, block->encoded+cursor )==1UL );
  cursor += sizeof(ulong);
  fd_microblock_hdr_t const * tick = fd_type_pun_const( block->encoded + cursor );
  cursor += sizeof(fd_microblock_hdr_t);
  FD_TEST( !tick->txn_cnt && tick->hash_cnt==1UL );
  fd_hash_t tick_end[ 1 ];
  repeat_hash( tick_end, prev_hash, 1UL );
  if( FD_UNLIKELY( memcmp( tick->hash, tick_end->hash, sizeof(fd_hash_t) ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( tick->hash, hdr_str );
    FD_BASE58_ENCODE_32_BYTES( tick_end->hash, expect_str );
    FD_LOG_ERR(( "builder tick hash mismatch: hdr %s expected %s", hdr_str, expect_str ));
  }
  FD_TEST( cursor == block->encoded_sz );
  FD_TEST( !memcmp( tick_end, block->end_poh, sizeof(fd_hash_t) ) );
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

   One transaction in four is version 0 with one lookup table naming
   one or two writable accounts and up to one read-only account.  The
   scheduler cannot resolve the table, so it inserts the transaction
   serializing and the harness hands the writable accounts back at
   completion, as the exec tile would.  They are drawn from the shared
   pool extended to [1,8], distinct from the transaction's static
   accounts.

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

   After fd_txn_base_generate() lays out a legacy message, the function
   stamps deterministic signature bytes and appends one instruction that
   references every non-program account.  The instruction data records
   the generation choices so downstream debugging can recover the
   intended shape from the wire image alone.  A version 0 message is
   laid out by hand with the same accounts, instruction and signature,
   and the lookup table after the instruction.

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

  out->is_alt  = read_range( r, 4UL )==0UL;
  out->alt_cnt = 0U;
  ulong alt_readonly_cnt = 0UL;
  if( out->is_alt ) {
    out->alt_cnt     = (uchar)(1UL + read_range( r, TEST_MAX_ALTS_PER_TXN ));
    alt_readonly_cnt = read_range( r, 2UL );
    for( ulong i=0UL; i<out->alt_cnt; i++ ) {
      ushort id;
      do {
        id = (ushort)(1U + read_range( r, 8UL ));
      } while( has_ushort( used, used_cnt, id ) );
      used[ used_cnt++ ] = id;
      out->alt_id[ i ] = id;
    }
  }

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

  fd_memset( out->payload, 0, sizeof(out->payload) );
  if( !out->is_alt ) {
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
    uchar meta[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
    fd_memset( meta, 0, sizeof(meta) );
    fd_txn_base_generate( meta, out->payload, 1UL, &accounts, NULL );
    out->payload_sz = (ushort)fd_txn_add_instr( meta, out->payload, (uchar)(acct_cnt-1UL), instr_accounts, instr_accounts_sz, instr_data, sizeof(instr_data) );
  } else {
    uchar * p = out->payload;
    ulong   i = 0UL;
    p[ i++ ] = 1;                                                         /* signature count */
    i += FD_TXN_SIGNATURE_SZ;                                             /* signature, stamped below */
    p[ i++ ] = 0x80;                                                      /* version 0 */
    p[ i++ ] = 1;                                                         /* required signatures */
    p[ i++ ] = 0;                                                         /* read-only signed */
    p[ i++ ] = (uchar)(readonly_extra + 1UL);                             /* read-only unsigned */
    p[ i++ ] = (uchar)acct_cnt;                                           /* static accounts */
    fd_memcpy( p+i, signer_w, sizeof(fd_pubkey_t) );                      i += sizeof(fd_pubkey_t);
    fd_memcpy( p+i, non_signer_w, writable_extra*sizeof(fd_pubkey_t) );   i += writable_extra*sizeof(fd_pubkey_t);
    fd_memcpy( p+i, non_signer_r, (readonly_extra+1UL)*sizeof(fd_pubkey_t) ); i += (readonly_extra+1UL)*sizeof(fd_pubkey_t);
    fd_memset( p+i, 0x33, FD_TXN_BLOCKHASH_SZ );                          i += FD_TXN_BLOCKHASH_SZ; /* recent blockhash */
    p[ i++ ] = 1;                                                         /* instruction count */
    p[ i++ ] = (uchar)(acct_cnt-1UL);                                     /*   program index */
    p[ i++ ] = (uchar)instr_accounts_sz;                                  /*   account count */
    fd_memcpy( p+i, instr_accounts, instr_accounts_sz );                  i += instr_accounts_sz;
    p[ i++ ] = (uchar)sizeof(instr_data);                                 /*   data length */
    fd_memcpy( p+i, instr_data, sizeof(instr_data) );                     i += sizeof(instr_data);
    p[ i++ ] = 1;                                                         /* lookup table count */
    fd_memset( p+i, 0x44, sizeof(fd_pubkey_t) );                          i += sizeof(fd_pubkey_t); /*   table address */
    p[ i++ ] = out->alt_cnt;                                              /*   writable indices */
    for( ulong j=0UL; j<out->alt_cnt; j++ ) p[ i++ ] = (uchar)j;
    p[ i++ ] = (uchar)alt_readonly_cnt;                                   /*   read-only indices */
    for( ulong j=0UL; j<alt_readonly_cnt; j++ ) p[ i++ ] = (uchar)(out->alt_cnt+j);
    out->payload_sz = (ushort)i;
  }

  for( ulong i=0UL; i<FD_TXN_SIGNATURE_SZ; i++ ) out->payload[ 1UL + i ] = (uchar)((block_idx<<4) ^ txn_idx ^ i);

  uchar parsed[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  ulong parsed_pay_sz = 0UL;
  FD_TEST( fd_txn_parse_core( out->payload, out->payload_sz, fd_type_pun( parsed ), NULL, &parsed_pay_sz ) );
  FD_TEST( parsed_pay_sz == out->payload_sz );

  return out->payload_sz;
}

/* build_block synthesizes one scheduler-visible block from the fuzz
   stream and caches every intermediate artifact that later harness
   checks need.

   The generated wire image is an Alpenglow block, four batches:

     [ header marker ][ ulong mblk_cnt ][ txn microblock... ][ footer marker ][ alpentick ]

   where each transaction microblock covers a contiguous slice of
   block->txn[].  Every entry advances exactly one hash, which for a
   transaction microblock is the mixin of its Merkle root, so no PoH
   hashing is left for the exec tiles beyond the alpentick's one hash,
   and every block advances exactly one tick.  The harness keeps both
   the start hash and the hash after the pure-hash portion of each
   microblock so it can mirror the scheduler's split between PoH work
   and transaction dispatch.

   After encoding the block, the builder partitions the byte stream into
   segments for incremental FEC ingestion, one batch per FEC set as the
   scheduler assumes.  The header marker and the alpentick are a segment
   each, the footer marker is one segment or two, and the entry batch
   is cut into fuzz-controlled segments at arbitrary offsets.

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
  for( ulong i=0UL; i<TEST_MAX_MBLKS_PER_BLK; i++ ) block->mblk_pool_idx[ i ] = ULONG_MAX;
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
  fd_hash_t prev_hash[ 1 ];
  fd_memcpy( prev_hash, parent_hash, sizeof(fd_hash_t) );

  /* The header marker batch. */
  uchar marker_buf[ FD_BLOCK_MARKER_SER_MAX ] __attribute__((aligned(64)));
  fd_block_marker_t marker[ 1 ];
  fd_memset( marker, 0, sizeof(fd_block_marker_t) );
  marker->kind               = FD_BLOCK_MARKER_KIND_HEADER;
  marker->header.parent_slot = parent_slot;
  ulong marker_sz = fd_block_marker_ser( marker, marker_buf );
  FD_TEST( marker_sz && cursor + marker_sz <= sizeof(block->encoded) );
  fd_memcpy( p + cursor, marker_buf, marker_sz );
  cursor += marker_sz;

  /* The entry batch, whose microblock count is stored once the
     transactions are grouped. */
  block->entry_off = cursor;
  ulong mblk_cnt_off = cursor;
  cursor += sizeof(ulong);

  block->mblk_cnt = 0UL;
  while( txns_remaining ) {
    ulong tx_mblk_slots_rem = TEST_MAX_MBLKS_PER_BLK - block->mblk_cnt - 1UL; /* Reserve one slot for the alpentick. */
    FD_TEST( tx_mblk_slots_rem>0UL );
    ulong min_group_txn_cnt = ( txns_remaining + tx_mblk_slots_rem - 1UL ) / tx_mblk_slots_rem;
    ulong group_txn_cnt = min_group_txn_cnt + read_range( r, txns_remaining - min_group_txn_cnt + 1UL );

    fd_memcpy( block->mblk_start_hash + block->mblk_cnt, prev_hash, sizeof(fd_hash_t) );
    block->mblk[ block->mblk_cnt ].start_txn      = (uint)txn_off;
    block->mblk[ block->mblk_cnt ].txn_cnt        = (uint)group_txn_cnt;
    block->mblk[ block->mblk_cnt ].wire_hash_cnt  = 1UL;
    block->mblk_cnt++;

    /* No pure hashes, since the entry's one hash is the mixin. */
    fd_memcpy( block->mblk_hashed_hash + block->mblk_cnt-1UL, prev_hash, sizeof(fd_hash_t) );

    fd_hash_t merkle[ 1 ];
    merkle_root( merkle, block->txn + txn_off, group_txn_cnt );

    uchar mixin[ 64 ];
    fd_memcpy( mixin,      prev_hash->hash, 32UL );
    fd_memcpy( mixin+32UL, merkle->hash,    32UL );
    fd_hash_t end_hash[ 1 ];
    fd_sha256_hash( mixin, sizeof(mixin), end_hash->hash );

    fd_microblock_hdr_t hdr = {
      .hash_cnt = 1UL,
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
  FD_STORE( ulong, p + mblk_cnt_off, block->mblk_cnt );

  /* The footer marker batch. */
  block->footer_off = cursor;
  fd_memset( marker, 0, sizeof(fd_block_marker_t) );
  marker->kind = FD_BLOCK_MARKER_KIND_FOOTER;
  marker_sz = fd_block_marker_ser( marker, marker_buf );
  FD_TEST( marker_sz && cursor + marker_sz <= sizeof(block->encoded) );
  fd_memcpy( p + cursor, marker_buf, marker_sz );
  cursor += marker_sz;

  /* The alpentick, a batch of one tick advancing one hash. */
  block->tick_off = cursor;
  FD_TEST( block->mblk_cnt<TEST_MAX_MBLKS_PER_BLK );
  fd_memcpy( block->mblk_start_hash + block->mblk_cnt, prev_hash, sizeof(fd_hash_t) );
  block->mblk[ block->mblk_cnt ].start_txn     = (uint)block->txn_cnt;
  block->mblk[ block->mblk_cnt ].txn_cnt       = 0U;
  block->mblk[ block->mblk_cnt ].wire_hash_cnt = 1UL;
  block->mblk_cnt++;

  fd_hash_t tick_end[ 1 ];
  repeat_hash( tick_end, prev_hash, 1UL );
  fd_memcpy( block->mblk_hashed_hash + block->mblk_cnt-1UL, tick_end, sizeof(fd_hash_t) );
  fd_memcpy( block->end_poh, tick_end, sizeof(fd_hash_t) );

  fd_microblock_hdr_t tick_hdr = {
    .hash_cnt = 1UL,
    .txn_cnt  = 0UL
  };
  fd_memcpy( tick_hdr.hash, tick_end->hash, sizeof(fd_hash_t) );

  FD_TEST( cursor + sizeof(ulong) + sizeof(fd_microblock_hdr_t) <= sizeof(block->encoded) );
  FD_STORE( ulong, p + cursor, 1UL );
  cursor += sizeof(ulong);
  fd_memcpy( p + cursor, &tick_hdr, sizeof(fd_microblock_hdr_t) );
  cursor += sizeof(fd_microblock_hdr_t);
  block->encoded_sz = cursor;

  /* The FEC sets: the header batch, the entry batch cut into one to
     TEST_MAX_SEGMENTS-4 segments, the footer batch in one or two
     segments and the alpentick. */
  ulong entry_sz      = block->footer_off - block->entry_off;
  ulong entry_seg_cnt = 1UL + read_range( r, fd_ulong_min( TEST_MAX_SEGMENTS-4UL, entry_sz ) );
  ulong seg_cnt       = 0UL;
  block->seg_end[ seg_cnt ] = (uint)block->entry_off; block->seg_eob[ seg_cnt++ ] = 1U;
  ulong off = block->entry_off;
  ulong rem = entry_sz;
  for( ulong i=0UL; i<entry_seg_cnt; i++ ) {
    ulong min_rem = entry_seg_cnt-i-1UL;
    ulong len     = fd_ulong_if( i+1UL==entry_seg_cnt, rem, 1UL + read_range( r, rem-min_rem ) );
    off += len;
    rem -= len;
    block->seg_end[ seg_cnt ] = (uint)off; block->seg_eob[ seg_cnt++ ] = (uchar)(i+1UL==entry_seg_cnt);
  }
  FD_TEST( off==block->footer_off );
  ulong footer_sz = block->tick_off - block->footer_off;
  if( read_uchar( r )&1U ) {
    block->seg_end[ seg_cnt ] = (uint)(block->footer_off + 1UL + read_range( r, footer_sz-1UL )); block->seg_eob[ seg_cnt++ ] = 0U;
  }
  block->seg_end[ seg_cnt ] = (uint)block->tick_off;   block->seg_eob[ seg_cnt++ ] = 1U;
  block->seg_end[ seg_cnt ] = (uint)block->encoded_sz; block->seg_eob[ seg_cnt++ ] = 1U;
  block->seg_cnt = seg_cnt;
  FD_TEST( seg_cnt<=TEST_MAX_SEGMENTS );

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
lineage_dead( case_t const * tc,
              ulong          bank_idx );

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
  FD_TEST( seg_sz<=USHORT_MAX );
  store_fec->data_sz       = (uint)seg_sz;
  store_fec->shred_sz[ 0 ] = (ushort)seg_sz;

  *fec = (fd_sched_fec_t) {
    .bank_idx           = block->bank_idx,
    .parent_bank_idx    = block->parent_idx,
    .slot               = block->slot,
    .parent_slot        = block->parent_slot,
    .fec                = store_fec,
    .data               = (uchar *)block->encoded + seg_start,
    .shred_cnt          = 1U,
    .is_last_in_batch   = !!block->seg_eob[ seg ],
    .is_last_in_block   = seg+1UL==block->seg_cnt,
    .is_first_in_block  = seg==0UL,
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

  /* The transactions this segment completes are parsed in order and
     charged to the block's writer bound, and the first over the bound
     rules the block invalid.  A dying block's segments are ignored. */
  int   dying             = lineage_dead( tc, block->bank_idx );
  ulong parsed_txn_cnt    = block->parsed_txn_cnt;
  ulong writable_declared = block->writable_declared;
  int   over              = 0;
  while( parsed_txn_cnt<block->txn_cnt && block->txn_end_off[ parsed_txn_cnt ]<=block->seg_end[ block->ingested_seg_cnt ] ) {
    writable_declared += txn_writable_cnt( block->txn+parsed_txn_cnt );
    parsed_txn_cnt++;
    if( FD_UNLIKELY( writable_declared>tc->writers_max ) ) { over = 1; break; }
  }

  FD_TEST( fd_sched_fec_can_ingest( tc->sched, fec ) );
  if( FD_UNLIKELY( !fd_sched_fec_ingest( tc->sched, fec ) ) ) {
    /* The scheduler refused the FEC set and the replay tile would mark
       the bank dead.  A first FEC set that waited for a staging lane
       while its lineage died is added dead, and never enters the
       dispatcher.  A later FEC set that completes the transactions of a
       microblock whose tampered PoH result already landed has its
       mixin, and so the mismatch, found at ingest, unless a transaction
       over the writer bound comes first. */
    int dead_reason = fd_sched_get_dead_reason( tc->sched, block->bank_idx );
    if( fec->is_first_in_block ) {
      FD_TEST( lineage_dead( tc, block->parent_idx ) );
      FD_TEST( dead_reason==FD_SCHED_DEAD_REASON_DEAD_ANCESTOR );
    } else if( dead_reason==FD_SCHED_DEAD_REASON_TOO_MANY_WRITABLE_ACCOUNTS ) {
      FD_TEST( over && !dying );
    } else {
      FD_TEST( block->failure_mode==TEST_FAIL_POH && block->failure_injected );
      FD_TEST( dead_reason==FD_SCHED_DEAD_REASON_ENTRY_HASH_MISMATCH_INGEST );
    }
    block->dead_seen        = 1;
    block->ingested_seg_cnt = block->seg_cnt;
    return;
  }
  FD_TEST( !over || dying );
  block->parsed_txn_cnt    = parsed_txn_cnt;
  block->writable_declared = writable_declared;
  block->ingested_seg_cnt++;
  if( FD_UNLIKELY( !block->poh_params_set ) ) {
    fd_sched_set_poh_params( tc->sched, block->bank_idx, block->tick_height, block->max_tick_height, block->start_poh );
    block->poh_params_set = 1;
  }
}

/* The scheduler memory, allocated once in LLVMFuzzerInitialize. */
static void * g_sched_mem;

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
  ulong depth         = TEST_SCHED_DEPTH;
  ulong block_cnt_max = TEST_SCHED_BLOCK_CNT_MAX;
  tc->mem        = g_sched_mem;

  fd_rng_t rng[1];
  fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  tc->sched = fd_sched_join( fd_sched_new( tc->mem, rng, depth, block_cnt_max, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, TEST_EXEC_CNT ) );
  /* There is no accounts database to resolve lookup tables against. */
  fd_sched_set_bypass_alut_resolution( tc->sched, 1 );

  /* One case in four lowers the writer bound to within reach of its
     few transactions, so that blocks get ruled invalid for it at parse
     and at a lookup table transaction's completion. */
  tc->writers_max = FD_SCHED_LTHASH_TXN_WRITERS_MAX;
  if( FD_UNLIKELY( read_range( &r, 4UL )==0UL ) ) {
    tc->writers_max = 1UL + read_range( &r, 24UL );
    fd_sched_set_lthash_txn_writers_max( tc->sched, tc->writers_max );
  }

  /* One case in four leaves room for one or two out-of-band blocks, so
     that blocks on further forks hash in band. */
  if( FD_UNLIKELY( read_range( &r, 4UL )==0UL ) ) fd_sched_set_lthash_oob_block_max( tc->sched, 1UL+read_range( &r, 2UL ) );

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
        fd_sched_block_abandon( tc->sched, task->bank_idx, FD_SCHED_ABANDON_INVALID );
      }
      /* A lookup table transaction hands back its writable lookup table
         accounts, which the scheduler registers as written, or refuses
         if they put the block over the writer bound.  A dying block
         gets no verdict. */
      txn_t const *       txn   = block->txn + task->local_txn_idx;
      int                 dying = lineage_dead( tc, task->bank_idx );
      fd_acct_addr_t      alt_addr[ TEST_MAX_ALTS_PER_TXN ];
      fd_sched_txn_alts_t alts[ 1 ] = {{ .cnt = txn->alt_cnt, .addrs = alt_addr }};
      for( ulong i=0UL; i<txn->alt_cnt; i++ ) pubkey_from_id( fd_type_pun( alt_addr+i ), txn->alt_id[ i ] );
      int over = txn->is_alt && block->writable_declared+txn->alt_cnt>tc->writers_max;
      int rc   = fd_sched_task_done( tc->sched, FD_SCHED_TT_TXN_EXEC, task->txn_idx, task->exec_idx, txn->is_alt ? alts : NULL );
      if( FD_UNLIKELY( over && !dying ) ) {
        FD_TEST( rc==FD_SCHED_DEAD_REASON_TOO_MANY_WRITABLE_ACCOUNTS );
        block->dead_seen = 1;
      } else {
        FD_TEST( rc==0 );
        if( txn->is_alt && !dying ) block->writable_declared += txn->alt_cnt;
      }
      for( ulong i=0UL; i<txn->acct_cnt; i++ ) if( txn->acct_writable[ i ] ) block_write( block, txn->acct_id[ i ] );
      for( ulong i=0UL; i<txn->alt_cnt;  i++ ) block_write( block, txn->alt_id[ i ] );
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
        fd_sched_block_abandon( tc->sched, task->bank_idx, FD_SCHED_ABANDON_INVALID );
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
      msg->cnt = task->poh_cnt;
      for( ulong i=0UL; i<task->poh_cnt; i++ ) {
        ulong local_mblk_idx = task->local_mblk_idx[ i ];
        FD_TEST( local_mblk_idx < block->mblk_cnt );
        FD_TEST( !memcmp( task->hash+i, block->mblk_curr_hash + local_mblk_idx, sizeof(fd_hash_t) ) );
        repeat_hash( msg->hash+i, task->hash+i, task->hashcnt );
        block->mblk_curr_hashcnt[ local_mblk_idx ] += task->hashcnt;
        FD_TEST( block->mblk_curr_hashcnt[ local_mblk_idx ] <= mblk_task_hashcnt( block, local_mblk_idx ) );
        fd_memcpy( block->mblk_curr_hash + local_mblk_idx, msg->hash+i, sizeof(fd_hash_t) );
        if( block->mblk_curr_hashcnt[ local_mblk_idx ] == mblk_task_hashcnt( block, local_mblk_idx ) ) {
          FD_TEST( !memcmp( msg->hash+i, block->mblk_hashed_hash + local_mblk_idx, sizeof(fd_hash_t) ) );
        }
      }
      if( FD_UNLIKELY( block->failure_mode==TEST_FAIL_POH && !block->failure_injected ) ) {
        for( ulong i=0UL; i<task->poh_cnt; i++ ) {
          ulong local_mblk_idx = task->local_mblk_idx[ i ];
          if( block->mblk_curr_hashcnt[ local_mblk_idx ] == mblk_task_hashcnt( block, local_mblk_idx ) ) {
            block->failure_injected  = 1;
            msg->hash[ i ].hash[ 0 ] ^= (uchar)0x80;
            break;
          }
        }
      }
      int rc = fd_sched_task_done( tc->sched, FD_SCHED_TT_POH_HASH, ULONG_MAX, task->exec_idx, msg );
      if( FD_UNLIKELY( block->failure_mode==TEST_FAIL_POH && block->failure_injected ) ) {
        FD_TEST( rc>=0 );
        if( FD_UNLIKELY( rc ) ) block->dead_seen = 1;
      } else if( FD_UNLIKELY( is_lineage_dead ) ) {
        FD_TEST( rc>=0 );
        if( FD_UNLIKELY( rc ) ) block->dead_seen = 1;
      } else {
        FD_TEST( rc==0 );
      }
      break;
    }
    case FD_SCHED_TT_LTHASH_SUB:
    case FD_SCHED_TT_LTHASH_ADD:
      FD_TEST( 0==fd_sched_task_done( tc->sched, task->task_type, ULONG_MAX, task->exec_idx, task->lthash_value ) );
      break;
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

static void * g_rdisp_mem[ TEST_MAX_BLOCKS ] = { 0 };

static void
rdisp_mirror_destroy( mirror_t * mirror ) {
  for( ulong slot=0UL; slot<TEST_MAX_BLOCKS; slot++ ) {
    if( FD_UNLIKELY( !mirror->disp[ slot ] ) ) continue;
    fd_rdisp_delete( fd_rdisp_leave( mirror->disp[ slot ] ) );
    mirror->mem [ slot ] = NULL;
    mirror->disp[ slot ] = NULL;
  }
}

static void
rdisp_mirror_ensure_block( mirror_t * mirror,
                           block_t const * block ) {
  ulong slot = block->bank_idx-1UL;
  if( FD_UNLIKELY( !mirror->mem[ slot ] ) ) {
    if( FD_UNLIKELY( !g_rdisp_mem[ slot ] ) ) {
      ulong footprint = fd_rdisp_footprint( TEST_RDISP_DEPTH, TEST_RDISP_BLOCK_DEPTH, 0UL );
      g_rdisp_mem[ slot ] = aligned_alloc( fd_rdisp_align(), footprint );
      FD_TEST( g_rdisp_mem[ slot ] );
    }
    mirror->mem[ slot ]  = g_rdisp_mem[ slot ];
    mirror->disp[ slot ] = fd_rdisp_join( fd_rdisp_new( g_rdisp_mem[ slot ], TEST_RDISP_DEPTH, TEST_RDISP_BLOCK_DEPTH, 0UL, 0x51a0f95dUL + block->bank_idx ) );
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
                                      block->txn[ local_txn_idx ].is_alt,
                                      NULL );
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
     MARK_DEAD are handled locally, and TXN_EXEC/TXN_SIGVERIFY/POH_HASH/
     LTHASH_SUB/LTHASH_ADD are completed later with fd_sched_task_done()
     after worker responses arrive.  Start-of-block writes are reported
     during BLOCK_START, and the block's LtHash delta is checked against
     the model at BLOCK_END. */
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
        block->inband     = task->block_start->lthash_inband;
        /* Start-of-block processing writes a few accounts, shared data
           accounts and sysvar-like ones, duplicates included, and
           reports them before BLOCK_START completes.  An in-band block
           reports nothing. */
        fd_acct_addr_t start_addr[ TEST_MAX_START_WRITES ];
        ulong start_cnt = read_range( &r, TEST_MAX_START_WRITES+1UL );
        for( ulong i=0UL; i<start_cnt; i++ ) {
          ulong  pick = read_range( &r, 6UL+TEST_SYSVAR_CNT );
          ushort id   = pick<6UL ? (ushort)(1UL+pick) : (ushort)(TEST_SYSVAR_ID_BASE+pick-6UL);
          pubkey_from_id( fd_type_pun( start_addr+i ), id );
          block_write( block, id );
        }
        if( start_cnt && !block->inband ) fd_sched_block_start_writes( tc->sched, bank_idx, start_addr, start_cnt );
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
        /* The delta is read before completion, as the replay tile does,
           and holds exactly one subtraction and one addition at the
           final version per account the block wrote.  An in-band block
           has an empty delta. */
        fd_lthash_value_t expected[ 1 ];
        block_expected_delta( block, expected );
        if( block->inband ) FD_TEST( fd_lthash_is_zero( fd_sched_lthash_delta( tc->sched, bank_idx ) ) );
        else                FD_TEST( fd_lthash_eq( fd_sched_lthash_delta( tc->sched, bank_idx ), expected ) );
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
        FD_TEST( info->slot==block->slot );
        FD_TEST( info->index_in_slot==local );
        if( FD_LIKELY( task->task_type==FD_SCHED_TT_TXN_EXEC ) )
          FD_TEST( (block->exec_done_mask & block->pred_mask[ local ]) == block->pred_mask[ local ] );
        if( FD_LIKELY( task->task_type==FD_SCHED_TT_TXN_EXEC ) ) {
          FD_TEST( !(info->flags & FD_SCHED_TXN_EXEC_DONE) );
          FD_TEST( !!(info->flags & FD_SCHED_TXN_ALT_UNRESOLVED)==block->txn[ local ].is_alt );
        } else {
          FD_TEST( !(info->flags & FD_SCHED_TXN_SIGVERIFY_DONE) );
          FD_TEST( info->sigverify_exec_tile_idx==exec_idx );
        }
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
        FD_TEST( task->poh_hash->cnt && task->poh_hash->cnt<=FD_SCHED_POH_PARA );
        inflight_t * entry = inflight + inflight_cnt++;
        *entry = (inflight_t) {
          .task_type = FD_SCHED_TT_POH_HASH,
          .bank_idx  = bank_idx,
          .exec_idx  = task->poh_hash->exec_idx,
          .poh_cnt   = task->poh_hash->cnt,
          .hashcnt   = task->poh_hash->hashcnt,
        };
        ulong min_todo = ULONG_MAX;
        for( ulong i=0UL; i<task->poh_hash->cnt; i++ ) {
          ulong pool_idx       = task->poh_hash->mblk_idx[ i ];
          ulong local_mblk_idx = ULONG_MAX;
          /* Microblocks are hashed independently, each from its
             predecessor's claimed end hash, so their tasks come in any
             order.  A microblock with hashing left is known by the
             scheduler's index, a new one by the hash it starts from,
             which is distinct per microblock. */
          for( ulong l=0UL; l<block->mblk_cnt; l++ ) {
            if( block->mblk_pool_idx[ l ]==pool_idx && block->mblk_curr_hashcnt[ l ]<mblk_task_hashcnt( block, l ) ) { local_mblk_idx = l; break; }
          }
          if( local_mblk_idx==ULONG_MAX ) {
            for( ulong l=0UL; l<block->mblk_cnt; l++ ) {
              if( block->mblk_pool_idx[ l ]==ULONG_MAX && !memcmp( task->poh_hash->hash+i, block->mblk_start_hash + l, sizeof(fd_hash_t) ) ) { local_mblk_idx = l; break; }
            }
            FD_TEST( local_mblk_idx!=ULONG_MAX );
            block->mblk_pool_idx    [ local_mblk_idx ] = pool_idx;
            block->mblk_curr_hashcnt[ local_mblk_idx ] = 0UL;
            fd_memcpy( block->mblk_curr_hash + local_mblk_idx, block->mblk_start_hash + local_mblk_idx, sizeof(fd_hash_t) );
          }
          FD_TEST( !memcmp( task->poh_hash->hash+i, block->mblk_curr_hash + local_mblk_idx, sizeof(fd_hash_t) ) );
          min_todo = fd_ulong_min( min_todo, mblk_task_hashcnt( block, local_mblk_idx )-block->mblk_curr_hashcnt[ local_mblk_idx ] );
          entry->mblk_idx      [ i ] = pool_idx;
          entry->local_mblk_idx[ i ] = local_mblk_idx;
          fd_memcpy( entry->hash+i, task->poh_hash->hash+i, sizeof(fd_hash_t) );
        }
        FD_TEST( task->poh_hash->hashcnt==min_todo ); /* one hash per tick, none per txn microblock */
        break;
      }
      case FD_SCHED_TT_LTHASH_SUB:
      case FD_SCHED_TT_LTHASH_ADD: {
        bank_idx = task->lthash->bank_idx;
        FD_TEST( bank_idx>0UL && bank_idx<=tc->block_cnt );
        block_t * block = tc->block + (bank_idx-1UL);
        FD_TEST( block->start_seen );
        FD_TEST( !block->inband );
        FD_TEST( !block->end_seen );
        FD_TEST( task->lthash->cnt && task->lthash->cnt<=FD_SCHED_LTHASH_BATCH_MAX );
        FD_TEST( task->lthash->exec_idx<TEST_EXEC_CNT );
        inflight_t * entry = inflight + inflight_cnt++;
        *entry = (inflight_t) {
          .task_type = task->task_type,
          .bank_idx  = bank_idx,
          .exec_idx  = task->lthash->exec_idx,
        };
        lthash_task_value( block, task, entry->lthash_value );
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
}

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  fd_log_level_core_set( 3 );
  atexit( fd_halt );

  ulong footprint = fd_sched_footprint( TEST_SCHED_DEPTH, TEST_SCHED_BLOCK_CNT_MAX, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT );
  FD_TEST( footprint );
  g_sched_mem = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( g_sched_mem );

  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  run_sched_rdisp_case( data, size );
  return 0;
}
