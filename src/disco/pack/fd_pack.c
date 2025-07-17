#define FD_UNALIGNED_ACCESS_STYLE 0
#include "fd_pack.h"
#include "fd_pack_cost.h"
#include "fd_compute_budget_program.h"
#include "fd_pack_bitset.h"
#include "fd_pack_unwritable.h"
#include "fd_chkdup.h"
#include "fd_pack_tip_prog_blacklist.h"
#include <math.h> /* for sqrt */
#include <stddef.h> /* for offsetof */
#include "../metrics/fd_metrics.h"

#define FD_PACK_USE_NON_TEMPORAL_MEMCPY 1

/* Declare a bunch of helper structs used for pack-internal data
   structures. */
typedef struct {
  fd_ed25519_sig_t sig;
} wrapped_sig_t;

/* fd_pack_ord_txn_t: An fd_txn_p_t with information required to order
   it by priority. */
struct fd_pack_private_ord_txn {
  /* It's important that there be no padding here (asserted below)
     because the code casts back and forth from pointers to this element
     to pointers to the whole struct. */
  union {
    fd_txn_p_t   txn[1];  /* txn is an alias for txn_e->txnp */
    fd_txn_e_t   txn_e[1];
    fd_txn_e_t   _txn_e;  /* Non-array type needed for map_chain */
    struct{ uchar _sig_cnt; wrapped_sig_t sig; };
  };

  /* Since this struct can be in one of several trees, it's helpful to
     store which tree.  This should be one of the FD_ORD_TXN_ROOT_*
     values. */
  int root;

  /* The sig2txn map_chain fields */
  ushort sigmap_next;
  ushort sigmap_prev;

  /* Each transaction is inserted with an expiration "time."  This code
     doesn't care about the units (blocks, rdtsc tick, ns, etc.), and
     doesn't require transactions to be inserted in expiration date
     order. */
  ulong expires_at;
  /* expq_idx: When this object is part of one of the treaps, it's
     also in the expiration priority queue.  This field (which is
     manipulated behind the scenes by the fd_prq code) stores where so
     that if we delete this transaction, we can also delete it from the
     expiration priority queue. */
  ulong expq_idx;

  /* The noncemap map_chain fields */
  ushort noncemap_next;
  ushort noncemap_prev;

  /* We want rewards*compute_est to fit in a ulong so that r1/c1 < r2/c2 can be
     computed as r1*c2 < r2*c1, with the product fitting in a ulong.
     compute_est has a small natural limit of mid-20 bits. rewards doesn't have
     a natural limit, so there is some argument to be made for raising the
     limit for rewards to 40ish bits. The struct has better packing with
     uint/uint though. */
  uint                __attribute__((aligned(64))) /* We want the treap fields and the bitsets
                                                       to be on the same double cache line pair */
               rewards;     /* in Lamports */
  uint         compute_est; /* in compute units */

  /* The treap fields */
  ushort left;
  ushort right;
  ushort parent;
  ushort prio;
  ushort prev;
  ushort next;

  /* skip: if we skip this transaction more than FD_PACK_SKIP_CNT times
     for reasons that won't go away until the end of the block, then we
     want to skip it very quickly.  If skip is in [1, FD_PACK_SKIP_CNT],
     then that means we have to skip it `skip` more times before taking
     any action.  If skip>FD_PACK_SKIP_CNT, then it is a compressed slot
     number during which it should be skipped, and we'll skip it until
     the compressed slot reaches a new value.  skip is never 0. */
  ushort skip;

  FD_PACK_BITSET_DECLARE( rw_bitset ); /* all accts this txn references */
  FD_PACK_BITSET_DECLARE(  w_bitset ); /* accts this txn write-locks    */

};
typedef struct fd_pack_private_ord_txn fd_pack_ord_txn_t;

/* What we want is that the payload starts at byte 0 of
   fd_pack_ord_txn_t so that the trick with the signature map works
   properly.  GCC and Clang seem to disagree on the rules of offsetof.
   */
FD_STATIC_ASSERT( offsetof( fd_pack_ord_txn_t, txn          )==0UL, fd_pack_ord_txn_t );
FD_STATIC_ASSERT( offsetof( fd_pack_ord_txn_t, sig          )==1UL, fd_pack_ord_txn_t );
#if FD_USING_CLANG
FD_STATIC_ASSERT( offsetof( fd_txn_p_t,             payload )==0UL, fd_pack_ord_txn_t );
#else
FD_STATIC_ASSERT( offsetof( fd_pack_ord_txn_t, txn->payload )==0UL, fd_pack_ord_txn_t );
FD_STATIC_ASSERT( offsetof( fd_pack_ord_txn_t, txn_e->txnp  )==0UL, fd_pack_ord_txn_t );
#endif

/* FD_ORD_TXN_ROOT is essentially a small union packed into an int.  The low
   byte is the "tag".  The higher 3 bytes depend on the low byte. */
#define FD_ORD_TXN_ROOT_TAG_MASK        0xFF
#define FD_ORD_TXN_ROOT_FREE            0
#define FD_ORD_TXN_ROOT_PENDING         1
#define FD_ORD_TXN_ROOT_PENDING_VOTE    2
#define FD_ORD_TXN_ROOT_PENDING_BUNDLE  3
#define FD_ORD_TXN_ROOT_PENALTY( idx ) (4 | (idx)<<8)

/* if root & TAG_MASK == PENALTY, then PENALTY_ACCT_IDX(root) gives the index
   in the transaction's list of account addresses of which penalty treap the
   transaction is in. */
#define FD_ORD_TXN_ROOT_PENALTY_ACCT_IDX( root ) (((root) & 0xFF00)>>8)

#define FD_PACK_IN_USE_WRITABLE    (0x8000000000000000UL)
#define FD_PACK_IN_USE_BIT_CLEARED (0x4000000000000000UL)

/* Each non-empty microblock we schedule also has an overhead of 48
   bytes that counts towards shed limits.  That comes from the 32 byte
   hash, the hash count (8 bytes) and the transaction count (8 bytes).
   We don't have to pay this overhead if the microblock is empty, since
   those microblocks get dropped. */
#define MICROBLOCK_DATA_OVERHEAD 48UL

/* Keep track of accounts that are written to in each block so that we
   can reset the writer costs to 0.  If the number of accounts that are
   written to is above or equal to this, we'll just clear the whole
   writer cost map instead of only removing the elements we increased. */
#define DEFAULT_WRITTEN_LIST_MAX 16384UL

/* fd_pack_addr_use_t: Used for three distinct purposes:
    -  to record that an address is in use and can't be used again until
         certain microblocks finish execution
    -  to keep track of the cost of all transactions that write to the
         specified account.
    -  to keep track of the write cost for accounts referenced by
         transactions in a bundle and which transactions use which
         accounts.
   Making these separate structs might make it more clear, but then
   they'd have identical shape and result in several fd_map_dynamic sets
   of functions with identical code.  It doesn't seem like the compiler
   is very good at merging code like that, so in order to reduce code
   bloat, we'll just combine them. */
struct fd_pack_private_addr_use_record {
  fd_acct_addr_t key; /* account address */
  union {
    ulong          _;
    ulong          in_use_by;  /* Bitmask indicating which banks */
    ulong          total_cost; /* In cost units/CUs */
    struct { uint    carried_cost;   /* In cost units */
             ushort  ref_cnt;        /* In transactions */
             ushort  last_use_in; }; /* In transactions */
  };
};
typedef struct fd_pack_private_addr_use_record fd_pack_addr_use_t;


/* fd_pack_expq_t: An element of an fd_prq to sort the transactions by
   timeout.  This structure has several invariants for entries
   corresponding to pending transactions:
     expires_at == txn->expires_at
     txn->exp_prq_idx is the index of this structure
   Notice that prq is an array-based heap, which means the indexes of
   elements change.  The PRQ_TMP_ST macro is hijacked to keep that
   invariant up to date.

   Note: this could be easier if fd_heap supported deleting from the
   middle, but that's not possible with the current design of fd_heap,
   which omits a parent pointer for improved performance. */
struct fd_pack_expq {
  ulong               expires_at;
  fd_pack_ord_txn_t * txn;
};
typedef struct fd_pack_expq fd_pack_expq_t;


/* fd_pack_bitset_acct_mapping_t: An element of an fd_map_dynamic that
   maps an account address to the number of transactions that are
   referencing it and the bit that is reserved to indicate it in the
   bitset, if any. */
struct fd_pack_bitset_acct_mapping {
  fd_acct_addr_t key; /* account address */
  ulong          ref_cnt;

  /* first_instance and first_instance_was_write are only valid when
     bit==FD_PACK_BITSET_FIRST_INSTANCE, which is set when ref_cnt
     transitions from 0 to 1.  These just exist to implement the
     optimization that accounts referenced a single time aren't
     allocated a bit, but this seems to be an important optimization. */
  fd_pack_ord_txn_t * first_instance;
  int                 first_instance_was_write;

  /* bit is in [0, FD_PACK_BITSET_MAX) U
     { FD_PACK_BITSET_FIRST_INSTANCE, FD_PACK_BITSET_SLOWPATH }. */
  ushort              bit;
};
typedef struct fd_pack_bitset_acct_mapping fd_pack_bitset_acct_mapping_t;



/* pack maintains a small state machine related to initializer bundles.
   See the header file for more details about it, but it's
   also summarized here:
   * NOT_INITIALIZED: The starting state for each block
   * PENDING: an initializer bundle has been scheduled, but pack has
     not observed its result yet, so we don't know if it was successful
     or not.
   * FAILED: the most recently scheduled initializer bundle failed
     for reasons other than already being executed.  Most commonly, this
     could be because of a bug in the code that generated the
     initializer bundle, a lack of fee payer balance, or an expired
     blockhash.
   * READY: the most recently scheduled initialization bundle succeeded
     and normal bundles can be scheduled in this slot. */
#define FD_PACK_IB_STATE_NOT_INITIALIZED 0
#define FD_PACK_IB_STATE_PENDING         1
#define FD_PACK_IB_STATE_FAILED          2
#define FD_PACK_IB_STATE_READY           3


/* Returns 1 if x.rewards/x.compute < y.rewards/y.compute. Not robust. */
#define COMPARE_WORSE(x,y) ( ((ulong)((x)->rewards)*(ulong)((y)->compute_est)) < ((ulong)((y)->rewards)*(ulong)((x)->compute_est)) )

/* Declare all the data structures */


/* Define the big max-"heap" that we pull transactions off to schedule.
   The priority is given by reward/compute.  We may want to add in some
   additional terms at a later point.  In order to cheaply remove nodes,
   we actually use a treap.  */
#define POOL_NAME       trp_pool
#define POOL_T          fd_pack_ord_txn_t
#define POOL_IDX_T      ushort
#define POOL_NEXT       parent
#include "../../util/tmpl/fd_pool.c"

#define TREAP_T         fd_pack_ord_txn_t
#define TREAP_NAME      treap
#define TREAP_QUERY_T   void *                                         /* We don't use query ... */
#define TREAP_CMP(a,b)  (__extension__({ (void)(a); (void)(b); -1; })) /* which means we don't need to give a real
                                                                          implementation to cmp either */
#define TREAP_IDX_T     ushort
#define TREAP_OPTIMIZE_ITERATION 1
#define TREAP_LT        COMPARE_WORSE
#include "../../util/tmpl/fd_treap.c"


#define MAP_NAME              sig2txn
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#define MAP_MULTI              1
#define MAP_ELE_T              fd_pack_ord_txn_t
#define MAP_PREV               sigmap_prev
#define MAP_NEXT               sigmap_next
#define MAP_IDX_T              ushort
#define MAP_KEY_T              wrapped_sig_t
#define MAP_KEY                sig
#define MAP_KEY_EQ(k0,k1)      (!memcmp( (k0),(k1), FD_TXN_SIGNATURE_SZ) )
#define MAP_KEY_HASH(key,seed) fd_hash( (seed), (key), 64UL )
#include "../../util/tmpl/fd_map_chain.c"


/* noncemap: A map from (nonce account, nonce authority, recent
   blockhash) to a durable nonce transaction containing it.  We only
   want to allow one transaction in the pool at a time with a given
   (nonce account, recent blockhash) tuple value.  The question is: can
   adding this limitation cause us to throw out potentially valuable
   transaction?  The answer is yes, but only very rarely, and the
   savings are worth it.  Suppose we have durable nonce transactions t1
   and t2 that advance the same nonce account and have the same value
   for the recent blockhash.

   - If t1 lands on chain, then it will advance the nonce account, and
   t2 will certainly not land on chain.
   - If t1 fails with AlreadyExecuted, that means the nonce account was
   advanced when t1 landed in a previous block, so t2 will certainly not
   land on chain.
   - If t1 fails with BlockhashNotFound, then the nonce account was
   advanced in some previous transaction, so again, t2 will certainly
   not land on chain.
   - If t1 does not land on chain because of an issue with the fee
   payer, it's possible that t2 could land on chain if it used a
   different fee payer, but historical data shows this is unlikely.
   - If t1 does not land on chain because it is part of a bundle that
   fails for an unrelated reason, it's possible that t2 could land on
   chain, but again, historical data says this is rare.

   We need to include the nonce authority in the hash to prevent one
   user from being able to DoS another user. */

typedef struct {
  uchar const * recent_blockhash;
  fd_acct_addr_t const * nonce_acct;
  fd_acct_addr_t const * nonce_auth;
} noncemap_extract_t;

/* k must be a valid, durable nonce transaction.  No error checking is
   done. */
static inline void
noncemap_extract( fd_txn_e_t const   * k,
                  noncemap_extract_t * out ) {
  fd_txn_t const * txn = TXN(k->txnp);
  out->recent_blockhash = fd_txn_get_recent_blockhash( txn, k->txnp->payload );

  ulong nonce_idx = k->txnp->payload[ txn->instr[ 0 ].acct_off+0 ];
  ulong autho_idx = k->txnp->payload[ txn->instr[ 0 ].acct_off+2 ];

  ulong imm_cnt = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM );
  fd_acct_addr_t const * accts   = fd_txn_get_acct_addrs( txn, k->txnp->payload );
  fd_acct_addr_t const * alt_adj = k->alt_accts - imm_cnt;
  out->nonce_acct = fd_ptr_if( nonce_idx<imm_cnt, accts, alt_adj )+nonce_idx;
  /* The nonce authority must be a signer, so it must be an immediate
     account. */
  out->nonce_auth = accts+autho_idx;
}

static inline int
noncemap_key_eq_internal( fd_txn_e_t const * k0,
                          fd_txn_e_t const * k1 ) {
  noncemap_extract_t e0[1], e1[1];
  noncemap_extract( k0, e0 );
  noncemap_extract( k1, e1 );

  if( FD_UNLIKELY( memcmp( e0->recent_blockhash, e1->recent_blockhash, 32UL ) ) ) return 0;
  if( FD_UNLIKELY( memcmp( e0->nonce_acct,       e1->nonce_acct,       32UL ) ) ) return 0;
  if( FD_UNLIKELY( memcmp( e0->nonce_auth,       e1->nonce_auth,       32UL ) ) ) return 0;
  return 1;
}

static inline ulong
noncemap_key_hash_internal( ulong              seed,
                            fd_txn_e_t const * k ) {
  /* TODO: This takes >100 cycles! */
  noncemap_extract_t e[1];
  noncemap_extract( k, e );
  return fd_hash( seed,              e->recent_blockhash, 32UL ) ^
         fd_hash( seed+ 864394383UL, e->nonce_acct,       32UL ) ^
         fd_hash( seed+3818662446UL, e->nonce_auth,       32UL );
}

#define MAP_NAME               noncemap
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#define MAP_MULTI              0
#define MAP_ELE_T              fd_pack_ord_txn_t
#define MAP_PREV               noncemap_prev
#define MAP_NEXT               noncemap_next
#define MAP_IDX_T              ushort
#define MAP_KEY_T              fd_txn_e_t
#define MAP_KEY                _txn_e
#define MAP_KEY_EQ(k0,k1)      noncemap_key_eq_internal( (k0), (k1) )
#define MAP_KEY_HASH(key,seed) noncemap_key_hash_internal( (seed), (key) )
#include "../../util/tmpl/fd_map_chain.c"


static const fd_acct_addr_t null_addr = { 0 };

#define MAP_NAME              acct_uses
#define MAP_T                 fd_pack_addr_use_t
#define MAP_KEY_T             fd_acct_addr_t
#define MAP_KEY_NULL          null_addr
#if FD_HAS_AVX
# define MAP_KEY_INVAL(k)     _mm256_testz_si256( wb_ldu( (k).b ), wb_ldu( (k).b ) )
#else
# define MAP_KEY_INVAL(k)     MAP_KEY_EQUAL(k, null_addr)
#endif
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp((k0).b,(k1).b, FD_TXN_ACCT_ADDR_SZ))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_MEMOIZE           0
#define MAP_KEY_HASH(key)     ((uint)fd_ulong_hash( fd_ulong_load_8( (key).b ) ))
#include "../../util/tmpl/fd_map_dynamic.c"


#define MAP_NAME              bitset_map
#define MAP_T                 fd_pack_bitset_acct_mapping_t
#define MAP_KEY_T             fd_acct_addr_t
#define MAP_KEY_NULL          null_addr
#if FD_HAS_AVX
# define MAP_KEY_INVAL(k)     _mm256_testz_si256( wb_ldu( (k).b ), wb_ldu( (k).b ) )
#else
# define MAP_KEY_INVAL(k)     MAP_KEY_EQUAL(k, null_addr)
#endif
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp((k0).b,(k1).b, FD_TXN_ACCT_ADDR_SZ))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_MEMOIZE           0
#define MAP_KEY_HASH(key)     ((uint)fd_ulong_hash( fd_ulong_load_8( (key).b ) ))
#include "../../util/tmpl/fd_map_dynamic.c"


/* Since transactions can also expire, we also maintain a parallel
   priority queue.  This means elements are simultaneously part of the
   treap (ordered by priority) and the expiration queue (ordered by
   expiration).  It's tempting to use the priority field of the treap
   for this purpose, but that can result in degenerate treaps in some
   cases. */
#define PRQ_NAME             expq
#define PRQ_T                fd_pack_expq_t
#define PRQ_TIMEOUT_T        ulong
#define PRQ_TIMEOUT          expires_at
#define PRQ_TMP_ST(p,t)      do {                                   \
                               (p)[0] = (t);                        \
                               t.txn->expq_idx = (ulong)((p)-heap); \
                             } while( 0 )
#include "../../util/tmpl/fd_prq.c"

/* fd_pack_smallest: We want to keep track of the smallest transaction
   in each treap.  That way, if we know the amount of space left in the
   block is less than the smallest transaction in the heap, we can just
   skip the heap.  Since transactions can be deleted, etc. maintaining
   this precisely is hard, but we can maintain a conservative value
   fairly cheaply.  Since the CU limit or the byte limit can be the one
   that matters, we keep track of the smallest by both. */
struct fd_pack_smallest {
  ulong cus;
  ulong bytes;
};
typedef struct fd_pack_smallest fd_pack_smallest_t;


/* With realistic traffic patterns, we often see many, many transactions
   competing for the same writable account.  Since only one of these can
   execute at a time, we sometimes waste lots of scheduling time going
   through them one at a time.  To combat that, when a transaction
   writes to an account with more than PENALTY_TREAP_THRESHOLD
   references (readers or writers), instead of inserting it into the
   main treap, we insert it into a penalty treap for that specific hot
   account address.  These transactions are not immediately available
   for scheduling.  Then, when a transaction that writes to the hot
   address completes, we move the most lucrative transaction from the
   penalty treap to the main treap, making it available for scheduling.
   This policy may slightly violate the price-time priority scheduling
   approach pack normally uses: if the most lucrative transaction
   competing for hot state arrives after PENALTY_TREAP_THRESHOLD has
   been hit, it may be scheduled second instead of first.  However, if
   the account is in use at the time the new transaction arrives, it
   will be scheduled next, as desired.  This minor difference seems
   reasonable to reduce complexity.

   fd_pack_penalty_treap is one account-specific penalty treap.  All the
   transactions in the penalty_treap treap write to key.

   penalty_map is the fd_map_dynamic that maps accounts to their
   respective penalty treaps. */
struct fd_pack_penalty_treap {
  fd_acct_addr_t key;
  treap_t penalty_treap[1];
};
typedef struct fd_pack_penalty_treap fd_pack_penalty_treap_t;

#define MAP_NAME              penalty_map
#define MAP_T                 fd_pack_penalty_treap_t
#define MAP_KEY_T             fd_acct_addr_t
#define MAP_KEY_NULL          null_addr
#if FD_HAS_AVX
# define MAP_KEY_INVAL(k)     _mm256_testz_si256( wb_ldu( (k).b ), wb_ldu( (k).b ) )
#else
# define MAP_KEY_INVAL(k)     MAP_KEY_EQUAL(k, null_addr)
#endif
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp((k0).b,(k1).b, FD_TXN_ACCT_ADDR_SZ))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_MEMOIZE           0
#define MAP_KEY_HASH(key)     ((uint)fd_ulong_hash( fd_ulong_load_8( (key).b ) ))
#include "../../util/tmpl/fd_map_dynamic.c"

/* PENALTY_TREAP_THRESHOLD: How many references to an account do we
   allow before subsequent transactions that write to the account go to
   the penalty treap. */
#define PENALTY_TREAP_THRESHOLD 64UL


/* FD_PACK_SKIP_CNT: How many times we'll skip a transaction (for
   reasons other than account conflicts) before we won't consider it
   until the next slot.  For performance reasons, this doesn't reset at
   the end of a slot, so e.g. we might skip twice in slot 1, then three
   times in slot 2, which would be enough to prevent considering it
   until slot 3.  The main reason this is not 1 is that some skips that
   seem permanent until the end of the slot can actually go away based
   on rebates. */
#define FD_PACK_SKIP_CNT 5UL

/* Finally, we can now declare the main pack data structure */
struct fd_pack_private {
  ulong      pack_depth;
  ulong      bundle_meta_sz; /* if 0, bundles are disabled */
  ulong      bank_tile_cnt;

  fd_pack_limits_t lim[1];

  ulong      pending_txn_cnt; /* Summed across all treaps */
  ulong      microblock_cnt; /* How many microblocks have we
                                generated in this block? */
  ulong      data_bytes_consumed; /* How much data is in this block so
                                     far ? */
  fd_rng_t * rng;

  ulong      cumulative_block_cost;
  ulong      cumulative_vote_cost;

  /* expire_before: Any transactions with expires_at strictly less than
     the current expire_before are removed from the available pending
     transaction.  Here, "expire" is used as a verb: cause all
     transactions before this time to expire. */
  ulong      expire_before;

  /* outstanding_microblock_mask: a bitmask indicating which banking
     tiles have outstanding microblocks, i.e. fd_pack has generated a
     microblock for that banking tile and the banking tile has not yet
     notified fd_pack that it has completed it. */
  ulong      outstanding_microblock_mask;

  /* The actual footprint for the pool and maps is allocated
     in the same order in which they are declared immediately following
     the struct.  I.e. these pointers point to memory not far after the
     struct.  The trees are just pointers into the pool so don't take up
     more space. */

  fd_pack_ord_txn_t * pool;

  /* Treaps (sorted by priority) of pending transactions.  We store the
     pending simple votes and transactions that come from bundles
     separately. */
  treap_t pending[1];
  treap_t pending_votes[1];
  treap_t pending_bundles[1];

  /* penalty_treaps: an fd_map_dynamic mapping hotly contended account
     addresses to treaps of transactions that write to them.  We try not
     to allow more than roughly PENALTY_TREAP_THRESHOLD transactions in
     the main treap that write to each account, though this is not
     exact. */
  fd_pack_penalty_treap_t * penalty_treaps;

  /* initializer_bundle_state: The current state of the initialization
     bundle state machine.  One of the FD_PACK_IB_STATE_* values.  See
     the long comment in the header and the comments attached to the
     respective values for a discussion of what each state means and the
     transitions between them. */
  int   initializer_bundle_state;

  /* pending_bundle_cnt: the number of bundles in pending_bundles. */
  ulong pending_bundle_cnt;

  /* relative_bundle_idx: the number of bundles that have been inserted
     since the last time pending_bundles was empty.  See the long
     comment about encoding this index in the rewards field of each
     transaction in the bundle, and why it is important that this reset
     to 0 as frequently as possible. */
  ulong relative_bundle_idx;

  /* pending{_votes}_smallest: keep a conservative estimate of the
     smallest transaction (by cost units and by bytes) in each heap.
     Both CUs and bytes should be set to ULONG_MAX is the treap is
     empty. */
  fd_pack_smallest_t pending_smallest[1];
  fd_pack_smallest_t pending_votes_smallest[1];

  /* expiration_q: At the same time that a transaction is in exactly one
     of the above treaps, it is also in the expiration queue, sorted by
     its expiration time.  This enables deleting all transactions that
     have expired, regardless of which treap they are in. */
  fd_pack_expq_t * expiration_q;

  /* acct_in_use: Map from account address to bitmask indicating which
     bank tiles are using the account and whether that use is read or
     write (msb). */
  fd_pack_addr_use_t   * acct_in_use;

  /* bitset_{w, rw}_in_use stores a subset of the information in
     acct_in_use using the compressed set format explained at the top of
     this file.  rw_in_use stores accounts in use for read or write
     while w_in_use stores only those in use for write. */
  FD_PACK_BITSET_DECLARE( bitset_rw_in_use );
  FD_PACK_BITSET_DECLARE( bitset_w_in_use  );

  /* writer_costs: Map from account addresses to the sum of costs of
     transactions that write to the account.  Used for enforcing limits
     on the max write cost per account per block. */
  fd_pack_addr_use_t   * writer_costs;

  /* At the end of every slot, we have to clear out writer_costs.  The
     map is large, but typically very sparsely populated.  As an
     optimization, we keep track of the elements of the map that we've
     actually used, up to a maximum.  If we use more than the maximum,
     we revert to the old way of just clearing the whole map.

     written_list indexed [0, written_list_cnt).
     written_list_cnt in  [0, written_list_max).

     written_list_cnt==written_list_max-1 means that the list may be
     incomplete and should be ignored. */
  fd_pack_addr_use_t * * written_list;
  ulong                  written_list_cnt;
  ulong                  written_list_max;

  /* Noncemap is a map_chain that maps from tuples (nonce account,
     recent blockhash value, nonce authority) to a transaction.  This
     map stores exactly the transactions in pool that have the nonce
     flag set. */
  noncemap_t * noncemap;

  sig2txn_t * signature_map; /* Stores pointers into pool for deleting by signature */

  /* bundle_temp_map: A fd_map_dynamic (although it could be an fd_map)
     used during fd_pack_try_schedule_bundle to store information about
     what accounts are used by transactions in the bundle.  It's empty
     (in a map sense) outside of calls to try_schedule_bundle, and each
     call to try_schedule_bundle clears it after use.  If bundles are
     disabled, this is a valid fd_map_dynamic, but it's as small as
     convenient and remains empty. */
  fd_pack_addr_use_t * bundle_temp_map;


  /* use_by_bank: An array of size (max_txn_per_microblock *
     FD_TXN_ACCT_ADDR_MAX) for each banking tile.  Only the MSB of
     in_use_by is relevant.  Addressed use_by_bank[i][j] where i is in
     [0, bank_tile_cnt) and j is in [0, use_by_bank_cnt[i]).  Used
     mostly for clearing the proper bits of acct_in_use when a
     microblock finishes.

     use_by_bank_txn: indexed [i][j], where i is in [0, bank_tile_cnt)
     and j is in [0, max_txn_per_microblock).  Transaction j in the
     microblock currently scheduled to bank i uses account addresses in
     use_by_bank[i][k] where k is in [0, use_by_bank[i][j]).  For
     example, if use_by_bank[i][0] = 2 and use_by_bank[i][1] = 3, then
     all the accounts that the first transaction in the outstanding
     microblock for bank 0 uses are contained in the set
               { use_by_bank[i][0], use_by_bank[i][1] },
     and all the accounts in the second transaction in the microblock
     are in the set
        { use_by_bank[i][0], use_by_bank[i][1], use_by_bank[i][2] }.
     Each transaction writes to at least one account (the fee payer)
     that no other transaction scheduled to the bank uses, which means
     that use_by_bank_txn[i][j] - use_by_bank_txn[i][j-1] >= 1 (with 0
     for use_by_bank_txn[i][-1]).  This means we can stop iterating when
     use_by_bank_txn[i][j] == use_by_bank_cnt[i].  */
  fd_pack_addr_use_t * use_by_bank    [ FD_PACK_MAX_BANK_TILES ];
  ulong                use_by_bank_cnt[ FD_PACK_MAX_BANK_TILES ];
  ulong *              use_by_bank_txn[ FD_PACK_MAX_BANK_TILES ];

  fd_histf_t txn_per_microblock [ 1 ];
  fd_histf_t vote_per_microblock[ 1 ];

  fd_histf_t scheduled_cus_per_block[ 1 ];
  fd_histf_t rebated_cus_per_block  [ 1 ];
  fd_histf_t net_cus_per_block      [ 1 ];
  fd_histf_t pct_cus_per_block      [ 1 ];
  ulong      cumulative_rebated_cus;


  /* compressed_slot_number: a number in (FD_PACK_SKIP_CNT, USHORT_MAX]
     that advances each time we start packing for a new slot. */
  ushort     compressed_slot_number;

  /* bitset_avail: a stack of which bits are not currently reserved and
     can be used to represent an account address.
     Indexed [0, bitset_avail_cnt].  Element 0 is fixed at
     FD_PACK_BITSET_SLOWPATH. */
  ushort bitset_avail[ 1UL+FD_PACK_BITSET_MAX ];
  ulong  bitset_avail_cnt;

  /* acct_to_bitset: an fd_map_dynamic that maps acct addresses to the
     reference count, which bit, etc. */
  fd_pack_bitset_acct_mapping_t * acct_to_bitset;

  /* chdkup: scratch memory chkdup needs for its internal processing */
  fd_chkdup_t chkdup[ 1 ];

  /* bundle_meta: an array, parallel to the pool, with each element
     having size bundle_meta_sz.  I.e. if pool[i] has an associated
     bundle meta, it's located at bundle_meta[j] for j in
     [i*bundle_meta_sz, (i+1)*bundle_meta_sz). */
  void * bundle_meta;
};

typedef struct fd_pack_private fd_pack_t;

FD_STATIC_ASSERT( offsetof(fd_pack_t, pending_txn_cnt)==FD_PACK_PENDING_TXN_CNT_OFF, txn_cnt_off );

/* Forward-declare some helper functions */
static ulong delete_transaction( fd_pack_t * pack, fd_pack_ord_txn_t * txn, int delete_full_bundle, int move_from_penalty_treap );
static inline void insert_bundle_impl( fd_pack_t * pack, ulong bundle_idx, ulong txn_cnt, fd_pack_ord_txn_t * * bundle, ulong expires_at );

FD_FN_PURE ulong
fd_pack_footprint( ulong                    pack_depth,
                   ulong                    bundle_meta_sz,
                   ulong                    bank_tile_cnt,
                   fd_pack_limits_t const * limits         ) {
  if( FD_UNLIKELY( (bank_tile_cnt==0) | (bank_tile_cnt>FD_PACK_MAX_BANK_TILES) ) ) return 0UL;
  if( FD_UNLIKELY( pack_depth<4UL ) ) return 0UL;

  int enable_bundles = !!bundle_meta_sz;
  ulong l;
  ulong extra_depth        = fd_ulong_if( enable_bundles, 1UL+2UL*FD_PACK_MAX_TXN_PER_BUNDLE, 1UL ); /* space for use between init and fini */
  ulong max_acct_in_treap  = pack_depth * FD_TXN_ACCT_ADDR_MAX;
  ulong max_txn_per_mblk   = fd_ulong_max( limits->max_txn_per_microblock,
                                           fd_ulong_if( enable_bundles, FD_PACK_MAX_TXN_PER_BUNDLE, 0UL ) );
  ulong max_acct_in_flight = bank_tile_cnt * (FD_TXN_ACCT_ADDR_MAX * max_txn_per_mblk + 1UL);
  ulong max_txn_in_flight  = bank_tile_cnt * max_txn_per_mblk;

  ulong max_w_per_block    = fd_ulong_min( limits->max_cost_per_block / FD_PACK_COST_PER_WRITABLE_ACCT,
                                           max_txn_per_mblk * limits->max_microblocks_per_block * FD_TXN_ACCT_ADDR_MAX );
  ulong written_list_max   = fd_ulong_min( max_w_per_block>>1, DEFAULT_WRITTEN_LIST_MAX );
  ulong bundle_temp_accts  = fd_ulong_if( enable_bundles, FD_PACK_MAX_TXN_PER_BUNDLE*FD_TXN_ACCT_ADDR_MAX, 1UL );
  ulong sig_chain_cnt      = sig2txn_chain_cnt_est( pack_depth );
  ulong nonce_chain_cnt    = noncemap_chain_cnt_est( pack_depth );

  /* log base 2, but with a 2* so that the hash table stays sparse */
  int lg_uses_tbl_sz = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_acct_in_flight                        ) );
  int lg_max_writers = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_w_per_block                           ) );
  int lg_acct_in_trp = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_acct_in_treap                         ) );
  int lg_penalty_trp = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_acct_in_treap/PENALTY_TREAP_THRESHOLD ) );
  int lg_bundle_temp = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*bundle_temp_accts                         ) );

  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_PACK_ALIGN,       sizeof(fd_pack_t)                               );
  l = FD_LAYOUT_APPEND( l, trp_pool_align (),   trp_pool_footprint ( pack_depth+extra_depth   ) ); /* pool           */
  l = FD_LAYOUT_APPEND( l, penalty_map_align(), penalty_map_footprint( lg_penalty_trp         ) ); /* penalty_treaps */
  l = FD_LAYOUT_APPEND( l, expq_align     (),   expq_footprint     ( pack_depth               ) ); /* expiration prq */
  l = FD_LAYOUT_APPEND( l, acct_uses_align(),   acct_uses_footprint( lg_uses_tbl_sz           ) ); /* acct_in_use    */
  l = FD_LAYOUT_APPEND( l, acct_uses_align(),   acct_uses_footprint( lg_max_writers           ) ); /* writer_costs   */
  l = FD_LAYOUT_APPEND( l, 32UL,                sizeof(fd_pack_addr_use_t*)*written_list_max    ); /* written_list   */
  l = FD_LAYOUT_APPEND( l, noncemap_align (),   noncemap_footprint ( nonce_chain_cnt          ) ); /* noncemap       */
  l = FD_LAYOUT_APPEND( l, sig2txn_align  (),   sig2txn_footprint  ( sig_chain_cnt            ) ); /* signature_map  */
  l = FD_LAYOUT_APPEND( l, acct_uses_align(),   acct_uses_footprint( lg_bundle_temp           ) ); /* bundle_temp_map*/
  l = FD_LAYOUT_APPEND( l, 32UL,                sizeof(fd_pack_addr_use_t)*max_acct_in_flight   ); /* use_by_bank    */
  l = FD_LAYOUT_APPEND( l, 32UL,                sizeof(ulong)*max_txn_in_flight                 ); /* use_by_bank_txn*/
  l = FD_LAYOUT_APPEND( l, bitset_map_align(),  bitset_map_footprint( lg_acct_in_trp          ) ); /* acct_to_bitset */
  l = FD_LAYOUT_APPEND( l, 64UL,                (pack_depth+extra_depth)*bundle_meta_sz         ); /* bundle_meta */
  return FD_LAYOUT_FINI( l, FD_PACK_ALIGN );
}

void *
fd_pack_new( void                   * mem,
             ulong                    pack_depth,
             ulong                    bundle_meta_sz,
             ulong                    bank_tile_cnt,
             fd_pack_limits_t const * limits,
             fd_rng_t               * rng           ) {

  int enable_bundles = !!bundle_meta_sz;
  ulong extra_depth        = fd_ulong_if( enable_bundles, 1UL+2UL*FD_PACK_MAX_TXN_PER_BUNDLE, 1UL );
  ulong max_acct_in_treap  = pack_depth * FD_TXN_ACCT_ADDR_MAX;
  ulong max_txn_per_mblk   = fd_ulong_max( limits->max_txn_per_microblock,
                                           fd_ulong_if( enable_bundles, FD_PACK_MAX_TXN_PER_BUNDLE, 0UL ) );
  ulong max_acct_in_flight = bank_tile_cnt * (FD_TXN_ACCT_ADDR_MAX * max_txn_per_mblk + 1UL);
  ulong max_txn_in_flight  = bank_tile_cnt * max_txn_per_mblk;

  ulong max_w_per_block    = fd_ulong_min( limits->max_cost_per_block / FD_PACK_COST_PER_WRITABLE_ACCT,
                                           max_txn_per_mblk * limits->max_microblocks_per_block * FD_TXN_ACCT_ADDR_MAX );
  ulong written_list_max   = fd_ulong_min( max_w_per_block>>1, DEFAULT_WRITTEN_LIST_MAX );
  ulong bundle_temp_accts  = fd_ulong_if( enable_bundles, FD_PACK_MAX_TXN_PER_BUNDLE*FD_TXN_ACCT_ADDR_MAX, 1UL );
  ulong sig_chain_cnt      = sig2txn_chain_cnt_est( pack_depth );
  ulong nonce_chain_cnt    = noncemap_chain_cnt_est( pack_depth );

  /* log base 2, but with a 2* so that the hash table stays sparse */
  int lg_uses_tbl_sz = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_acct_in_flight                        ) );
  int lg_max_writers = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_w_per_block                           ) );
  int lg_acct_in_trp = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_acct_in_treap                         ) );
  int lg_penalty_trp = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_acct_in_treap/PENALTY_TREAP_THRESHOLD ) );
  int lg_bundle_temp = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*bundle_temp_accts                         ) );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_pack_t * pack    = FD_SCRATCH_ALLOC_APPEND( l,  FD_PACK_ALIGN,       sizeof(fd_pack_t)                             );
  /* The pool has one extra element that is used between insert_init and
     cancel/fini. */
  void * _pool        = FD_SCRATCH_ALLOC_APPEND( l,  trp_pool_align(),    trp_pool_footprint ( pack_depth+extra_depth ) );
  void * _penalty_map = FD_SCRATCH_ALLOC_APPEND( l,  penalty_map_align(), penalty_map_footprint( lg_penalty_trp       ) );
  void * _expq        = FD_SCRATCH_ALLOC_APPEND( l,  expq_align(),        expq_footprint     ( pack_depth             ) );
  void * _uses        = FD_SCRATCH_ALLOC_APPEND( l,  acct_uses_align(),   acct_uses_footprint( lg_uses_tbl_sz         ) );
  void * _writer_cost = FD_SCRATCH_ALLOC_APPEND( l,  acct_uses_align(),   acct_uses_footprint( lg_max_writers         ) );
  void * _written_lst = FD_SCRATCH_ALLOC_APPEND( l,  32UL,                sizeof(fd_pack_addr_use_t*)*written_list_max  );
  void * _noncemap    = FD_SCRATCH_ALLOC_APPEND( l,  noncemap_align(),    noncemap_footprint ( nonce_chain_cnt        ) );
  void * _sig_map     = FD_SCRATCH_ALLOC_APPEND( l,  sig2txn_align(),     sig2txn_footprint  ( sig_chain_cnt          ) );
  void * _bundle_temp = FD_SCRATCH_ALLOC_APPEND( l,  acct_uses_align(),   acct_uses_footprint( lg_bundle_temp         ) );
  void * _use_by_bank = FD_SCRATCH_ALLOC_APPEND( l,  32UL,                sizeof(fd_pack_addr_use_t)*max_acct_in_flight );
  void * _use_by_txn  = FD_SCRATCH_ALLOC_APPEND( l,  32UL,                sizeof(ulong)*max_txn_in_flight               );
  void * _acct_bitset = FD_SCRATCH_ALLOC_APPEND( l,  bitset_map_align(),  bitset_map_footprint( lg_acct_in_trp        ) );
  void * bundle_meta  = FD_SCRATCH_ALLOC_APPEND( l,  64UL,                (pack_depth+extra_depth)*bundle_meta_sz       );

  pack->pack_depth                  = pack_depth;
  pack->bundle_meta_sz              = bundle_meta_sz;
  pack->bank_tile_cnt               = bank_tile_cnt;
  pack->lim[0]                      = *limits;
  pack->pending_txn_cnt             = 0UL;
  pack->microblock_cnt              = 0UL;
  pack->data_bytes_consumed         = 0UL;
  pack->rng                         = rng;
  pack->cumulative_block_cost       = 0UL;
  pack->cumulative_vote_cost        = 0UL;
  pack->expire_before               = 0UL;
  pack->outstanding_microblock_mask = 0UL;
  pack->cumulative_rebated_cus      = 0UL;


  trp_pool_new(  _pool,        pack_depth+extra_depth );

  fd_pack_ord_txn_t * pool = trp_pool_join( _pool );
  treap_seed( pool, pack_depth+extra_depth, fd_rng_ulong( rng ) );
  for( ulong i=0UL; i<pack_depth+extra_depth; i++ ) pool[i].root = FD_ORD_TXN_ROOT_FREE;

  (void)trp_pool_leave( pool );

  penalty_map_new( _penalty_map, lg_penalty_trp );

  /* These treaps can have at most pack_depth elements at any moment,
     but they come from a pool of size pack_depth+extra_depth. */
  treap_new( (void*)pack->pending,         pack_depth+extra_depth );
  treap_new( (void*)pack->pending_votes,   pack_depth+extra_depth );
  treap_new( (void*)pack->pending_bundles, pack_depth+extra_depth );

  pack->pending_smallest->cus         = ULONG_MAX;
  pack->pending_smallest->bytes       = ULONG_MAX;
  pack->pending_votes_smallest->cus   = ULONG_MAX;
  pack->pending_votes_smallest->bytes = ULONG_MAX;

  expq_new( _expq, pack_depth );

  FD_PACK_BITSET_CLEAR( pack->bitset_rw_in_use );
  FD_PACK_BITSET_CLEAR( pack->bitset_w_in_use  );

  acct_uses_new( _uses,        lg_uses_tbl_sz );
  acct_uses_new( _writer_cost, lg_max_writers );
  acct_uses_new( _bundle_temp, lg_bundle_temp );

  pack->written_list     = _written_lst;
  pack->written_list_cnt = 0UL;
  pack->written_list_max = written_list_max;

  noncemap_new( _noncemap, nonce_chain_cnt, fd_rng_ulong( rng ) );

  sig2txn_new( _sig_map, sig_chain_cnt, fd_rng_ulong( rng ) );

  fd_pack_addr_use_t * use_by_bank     = (fd_pack_addr_use_t *)_use_by_bank;
  ulong *              use_by_bank_txn = (ulong *)_use_by_txn;
  for( ulong i=0UL; i<bank_tile_cnt; i++ ) {
    pack->use_by_bank    [i] = use_by_bank + i*(FD_TXN_ACCT_ADDR_MAX*max_txn_per_mblk+1UL);
    pack->use_by_bank_cnt[i] = 0UL;
    pack->use_by_bank_txn[i] = use_by_bank_txn + i*max_txn_per_mblk;
    pack->use_by_bank_txn[i][0] = 0UL;
  }
  for( ulong i=bank_tile_cnt; i<FD_PACK_MAX_BANK_TILES; i++ ) {
    pack->use_by_bank    [i] = NULL;
    pack->use_by_bank_cnt[i] = 0UL;
    pack->use_by_bank_txn[i] = NULL;
  }

  fd_histf_new( pack->txn_per_microblock,  FD_MHIST_MIN( PACK, TOTAL_TRANSACTIONS_PER_MICROBLOCK_COUNT ),
                                           FD_MHIST_MAX( PACK, TOTAL_TRANSACTIONS_PER_MICROBLOCK_COUNT ) );
  fd_histf_new( pack->vote_per_microblock, FD_MHIST_MIN( PACK, VOTES_PER_MICROBLOCK_COUNT ),
                                           FD_MHIST_MAX( PACK, VOTES_PER_MICROBLOCK_COUNT ) );

  fd_histf_new( pack->scheduled_cus_per_block, FD_MHIST_MIN( PACK, CUS_SCHEDULED ),
                                               FD_MHIST_MAX( PACK, CUS_SCHEDULED ) );
  fd_histf_new( pack->rebated_cus_per_block,   FD_MHIST_MIN( PACK, CUS_REBATED   ),
                                               FD_MHIST_MAX( PACK, CUS_REBATED   ) );
  fd_histf_new( pack->net_cus_per_block,       FD_MHIST_MIN( PACK, CUS_NET       ),
                                               FD_MHIST_MAX( PACK, CUS_NET       ) );
  fd_histf_new( pack->pct_cus_per_block,       FD_MHIST_MIN( PACK, CUS_PCT       ),
                                               FD_MHIST_MAX( PACK, CUS_PCT       ) );

  pack->compressed_slot_number = (ushort)(FD_PACK_SKIP_CNT+1);

  pack->bitset_avail[ 0 ] = FD_PACK_BITSET_SLOWPATH;
  for( ulong i=0UL; i<FD_PACK_BITSET_MAX; i++ ) pack->bitset_avail[ i+1UL ] = (ushort)i;
  pack->bitset_avail_cnt = FD_PACK_BITSET_MAX;

  bitset_map_new( _acct_bitset, lg_acct_in_trp );

  fd_chkdup_new( pack->chkdup, rng );

  pack->bundle_meta = bundle_meta;

  return mem;
}

fd_pack_t *
fd_pack_join( void * mem ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_pack_t * pack  = FD_SCRATCH_ALLOC_APPEND( l, FD_PACK_ALIGN, sizeof(fd_pack_t) );

  int enable_bundles = !!pack->bundle_meta_sz;
  ulong pack_depth             = pack->pack_depth;
  ulong extra_depth            = fd_ulong_if( enable_bundles, 1UL+2UL*FD_PACK_MAX_TXN_PER_BUNDLE, 1UL );
  ulong bank_tile_cnt          = pack->bank_tile_cnt;
  ulong max_txn_per_microblock = fd_ulong_max( pack->lim->max_txn_per_microblock,
                                               fd_ulong_if( enable_bundles, FD_PACK_MAX_TXN_PER_BUNDLE, 0UL ) );

  ulong max_acct_in_treap  = pack_depth * FD_TXN_ACCT_ADDR_MAX;
  ulong max_acct_in_flight = bank_tile_cnt * (FD_TXN_ACCT_ADDR_MAX * max_txn_per_microblock + 1UL);
  ulong max_txn_in_flight  = bank_tile_cnt * max_txn_per_microblock;
  ulong max_w_per_block    = fd_ulong_min( pack->lim->max_cost_per_block / FD_PACK_COST_PER_WRITABLE_ACCT,
                                           max_txn_per_microblock * pack->lim->max_microblocks_per_block * FD_TXN_ACCT_ADDR_MAX );
  ulong written_list_max   = fd_ulong_min( max_w_per_block>>1, DEFAULT_WRITTEN_LIST_MAX );
  ulong bundle_temp_accts  = fd_ulong_if( enable_bundles, FD_PACK_MAX_TXN_PER_BUNDLE*FD_TXN_ACCT_ADDR_MAX, 1UL );
  ulong sig_chain_cnt      = sig2txn_chain_cnt_est( pack_depth );
  ulong nonce_chain_cnt    = noncemap_chain_cnt_est( pack_depth );

  int lg_uses_tbl_sz = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_acct_in_flight                        ) );
  int lg_max_writers = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_w_per_block                           ) );
  int lg_acct_in_trp = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_acct_in_treap                         ) );
  int lg_penalty_trp = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_acct_in_treap/PENALTY_TREAP_THRESHOLD ) );
  int lg_bundle_temp = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*bundle_temp_accts                         ) );


  pack->pool          = trp_pool_join(   FD_SCRATCH_ALLOC_APPEND( l, trp_pool_align(),   trp_pool_footprint   ( pack_depth+extra_depth  ) ) );
  pack->penalty_treaps= penalty_map_join(FD_SCRATCH_ALLOC_APPEND( l, penalty_map_align(),penalty_map_footprint( lg_penalty_trp          ) ) );
  pack->expiration_q  = expq_join    (   FD_SCRATCH_ALLOC_APPEND( l, expq_align(),       expq_footprint       ( pack_depth              ) ) );
  pack->acct_in_use   = acct_uses_join(  FD_SCRATCH_ALLOC_APPEND( l, acct_uses_align(),  acct_uses_footprint  ( lg_uses_tbl_sz          ) ) );
  pack->writer_costs  = acct_uses_join(  FD_SCRATCH_ALLOC_APPEND( l, acct_uses_align(),  acct_uses_footprint  ( lg_max_writers          ) ) );
  /* */                                  FD_SCRATCH_ALLOC_APPEND( l, 32UL,               sizeof(fd_pack_addr_use_t*)*written_list_max       );
  pack->noncemap      = noncemap_join(   FD_SCRATCH_ALLOC_APPEND( l, noncemap_align(),   noncemap_footprint   ( nonce_chain_cnt         ) ) );
  pack->signature_map = sig2txn_join(    FD_SCRATCH_ALLOC_APPEND( l, sig2txn_align(),    sig2txn_footprint    ( sig_chain_cnt           ) ) );
  pack->bundle_temp_map=acct_uses_join(  FD_SCRATCH_ALLOC_APPEND( l, acct_uses_align(),  acct_uses_footprint  ( lg_bundle_temp          ) ) );
  /* */                                  FD_SCRATCH_ALLOC_APPEND( l, 32UL,               sizeof(fd_pack_addr_use_t)*max_acct_in_flight      );
  /* */                                  FD_SCRATCH_ALLOC_APPEND( l, 32UL,               sizeof(ulong)*max_txn_in_flight                    );
  pack->acct_to_bitset= bitset_map_join( FD_SCRATCH_ALLOC_APPEND( l, bitset_map_align(), bitset_map_footprint( lg_acct_in_trp           ) ) );
  /* */                                  FD_SCRATCH_ALLOC_APPEND( l, 64UL,               (pack_depth+extra_depth)*pack->bundle_meta_sz      );

  FD_MGAUGE_SET( PACK, PENDING_TRANSACTIONS_HEAP_SIZE, pack->pack_depth );
  return pack;
}


/* Returns 0 on failure, 1 on success for a vote, 2 on success for a
   non-vote. */
static int
fd_pack_estimate_rewards_and_compute( fd_txn_e_t        * txne,
                                      fd_pack_ord_txn_t * out ) {
  fd_txn_t * txn = TXN(txne->txnp);
  ulong sig_rewards = FD_PACK_FEE_PER_SIGNATURE * txn->signature_cnt; /* Easily in [5000, 635000] */

  ulong requested_execution_cus;
  ulong priority_rewards;
  ulong precompile_sigs;
  ulong requested_loaded_accounts_data_cost;
  ulong cost_estimate = fd_pack_compute_cost( txn, txne->txnp->payload, &txne->txnp->flags, &requested_execution_cus, &priority_rewards, &precompile_sigs, &requested_loaded_accounts_data_cost );

  if( FD_UNLIKELY( !cost_estimate ) ) return 0;

  /* precompile_sigs <= 16320, so after the addition,
     sig_rewards < 83,000,000 */
  sig_rewards += FD_PACK_FEE_PER_SIGNATURE * precompile_sigs;
  sig_rewards = sig_rewards * FD_PACK_TXN_FEE_BURN_PCT / 100UL;

  /* No fancy CU estimation in this version of pack
  for( ulong i=0UL; i<(ulong)txn->instr_cnt; i++ ) {
    uchar prog_id_idx = txn->instr[ i ].program_id;
    fd_acct_addr_t const * acct_addr = fd_txn_get_acct_addrs( txn, txnp->payload ) + (ulong)prog_id_idx;
  }
  */
  out->rewards                              = (priority_rewards < (UINT_MAX - sig_rewards)) ? (uint)(sig_rewards + priority_rewards) : UINT_MAX;
  out->compute_est                          = (uint)cost_estimate;
  out->txn->pack_cu.requested_exec_plus_acct_data_cus = (uint)(requested_execution_cus + requested_loaded_accounts_data_cost);
  out->txn->pack_cu.non_execution_cus       = (uint)(cost_estimate - requested_execution_cus - requested_loaded_accounts_data_cost);

  return fd_int_if( txne->txnp->flags & FD_TXN_P_FLAGS_IS_SIMPLE_VOTE, 1, 2 );
}

/* Returns 0 on failure, 1 if not a durable nonce transaction, and 2 if
   it is.  FIXME: These return codes are set to harmonize with
   estimate_rewards_and_compute but -1/0/1 makes a lot more sense to me.
   */
static int
fd_pack_validate_durable_nonce( fd_txn_e_t * txne ) {
  fd_txn_t const * txn = TXN(txne->txnp);

  /* First instruction invokes system program with 4 bytes of
     instruction data with the little-endian value 4.  It also has 3
     accounts: the nonce account, recent blockhashes sysvar, and the
     nonce authority.  It seems like technically the nonce authority may
     not need to be passed in, but we disallow that.  We also allow
     trailing data and trailing accounts.  We want to organize the
     checks somewhat to minimize cache misses. */
  if( FD_UNLIKELY( txn->instr_cnt==0            ) ) return 1;
  if( FD_UNLIKELY( txn->instr[ 0 ].data_sz<4UL  ) ) return 1;
  if( FD_UNLIKELY( txn->instr[ 0 ].acct_cnt<3UL ) ) return 1; /* It seems like technically 2 is allowed, but never used */
  if( FD_LIKELY  ( fd_uint_load_4( txne->txnp->payload + txn->instr[ 0 ].data_off )!=4U ) ) return 1;
  /* The program has to be a static account */
  fd_acct_addr_t const * accts = fd_txn_get_acct_addrs( txn, txne->txnp->payload );
  if( FD_UNLIKELY( !fd_memeq( accts[ txn->instr[ 0 ].program_id ].b, null_addr.b, 32UL       ) ) ) return 1;
  if( FD_UNLIKELY( !fd_txn_is_signer( txn, txne->txnp->payload[ txn->instr[ 0 ].acct_off+2 ] ) ) ) return 0;
  /* We could check recent blockhash, but it's not necessary */
  return 2;
}

/* Can the fee payer afford to pay a transaction with the specified
   price?  Returns 1 if so, 0 otherwise.  This is just a stub that
   always returns 1 for now, and the real check is deferred to the bank
   tile.  In general, this function can't be totally accurate, because
   the transactions immediately prior to this one can affect the balance
   of this fee payer, but a simple check here may be helpful for
   reducing spam. */
static int
fd_pack_can_fee_payer_afford( fd_acct_addr_t const * acct_addr,
                              ulong                  price /* in lamports */) {
  (void)acct_addr;
  (void)price;
  return 1;
}





fd_txn_e_t * fd_pack_insert_txn_init(   fd_pack_t * pack                   ) { return trp_pool_ele_acquire( pack->pool )->txn_e; }
void         fd_pack_insert_txn_cancel( fd_pack_t * pack, fd_txn_e_t * txn ) { trp_pool_ele_release( pack->pool, (fd_pack_ord_txn_t*)txn ); }

#define REJECT( reason ) do {                                       \
                           trp_pool_ele_release( pack->pool, ord ); \
                           return FD_PACK_INSERT_REJECT_ ## reason; \
                         } while( 0 )

/* These require txn, accts, and alt_adj to be defined as per usual */
#define ACCT_IDX_TO_PTR( idx ) (__extension__( {                                               \
      ulong __idx = (idx);                                                                     \
      fd_ptr_if( __idx<fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM ), accts, alt_adj )+__idx; \
      }))
#define ACCT_ITER_TO_PTR( iter ) (__extension__( {                                             \
      ulong __idx = fd_txn_acct_iter_idx( iter );                                              \
      fd_ptr_if( __idx<fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM ), accts, alt_adj )+__idx; \
      }))


/* Tries to find the worst transaction in any treap in pack.  If that
   transaction's score is worse than or equal to threshold_score, it
   initiates a delete and returns the number of deleted transactions
   (potentially more than 1 for a bundle).  If it's higher than
   threshold_score, it returns 0.  To force this function to delete the
   worst transaction if there are any eligible ones, pass FLT_MAX as
   threshold_score. */
static inline ulong
delete_worst( fd_pack_t * pack,
              float       threshold_score,
              int         is_vote ) {
  /* If the tree is full, we want to see if this is better than the
     worst element in the pool before inserting.  If the new transaction
     is better than that one, we'll delete it and insert the new
     transaction. Otherwise, we'll throw away this transaction.

     We want to bias the definition of "worst" here to provide better
     quality of service.  For example, if the pool is filled with
     transactions that all write to the same account or are all votes,
     we want to bias towards treating one of those transactions as the
     worst, even if they pay slightly higher fees per computer unit,
     since we know we won't actually be able to schedule them all.

     This is a tricky task, however.  All our notions of priority and
     better/worse are based on static information about the transaction,
     and there's not an easy way to take into account global
     information, for example, how many other transactions contend with
     this one.  One idea is to build a heap (not a treap, since we only
     need pop-min, insert, and delete) with one element for each element
     in the pool, with a "delete me" score that's related but not
     identical to the normal score.  This would allow building in some
     global information.  The downside is that the global information
     that gets integrated is static.  E.g. if you bias a transaction's
     "delete me" score to make it more likely to be deleted because
     there are many conflicting transactions in the pool, the score
     stays biased, even if the global conditions change (unless you come
     up with some complicated re-scoring scheme).  This can work, since
     when the pool is full, the global bias factors are unlikely to
     change significantly at the relevant timescales.

     However, rather than this, we implement a simpler probabilistic
     scheme.  We'll sample M transactions, find the worst transaction in
     each of the M treaps, compute a "delete me" score for those <= M
     transactions, and delete the worst.  If one penalty treap is
     starting to get big, then it becomes very likely that the random
     sample will find it and choose to delete a transaction from it.

     The exact formula for the "delete me" score should be the matter of
     some more intense quantitative research.  For now, we'll just use
     this:

     Treap with N transactions        Scale Factor
     Pending                      1.0 unless inserting a vote and votes < 25%
     Pending votes                1.0 until 75% of depth, then 0
     Penalty treap                1.0 at <= 100 transactions, then sqrt(100/N)
     Pending bundles              inf (since the rewards value is fudged)

     We'll also use M=8. */

  float worst_score = FLT_MAX;
  fd_pack_ord_txn_t * worst = NULL;
  for( ulong i=0UL; i<8UL; i++ ) {
    uint  pool_max = (uint)trp_pool_max( pack->pool );
    ulong sample_i = fd_rng_uint_roll( pack->rng, pool_max );

    fd_pack_ord_txn_t * sample = &pack->pool[ sample_i ];
    /* Presumably if we're calling this, the pool is almost entirely
       full, so the probability of choosing a free one is small.  If
       it does happen, find the first one that isn't free. */
    while( FD_UNLIKELY( sample->root==FD_ORD_TXN_ROOT_FREE ) ) sample = &pack->pool[ (++sample_i)%pool_max ];

    int       root_idx   = sample->root;
    float     multiplier = 0.0f; /* The smaller this is, the more biased we'll be to deleting it */
    treap_t * treap;
    switch( root_idx & FD_ORD_TXN_ROOT_TAG_MASK ) {
      default:
      case FD_ORD_TXN_ROOT_FREE: {
        FD_LOG_CRIT(( "Double free detected" ));
        return ULONG_MAX; /* Can't be hit */
      }
      case FD_ORD_TXN_ROOT_PENDING: {
        treap = pack->pending;
        ulong vote_cnt = treap_ele_cnt( pack->pending_votes );
        if( FD_LIKELY( !is_vote || (vote_cnt>=pack->pack_depth/4UL ) ) ) multiplier = 1.0f;
        break;
      }
      case FD_ORD_TXN_ROOT_PENDING_VOTE: {
        treap = pack->pending_votes;
        ulong vote_cnt = treap_ele_cnt( pack->pending_votes );
        if( FD_LIKELY( is_vote || (vote_cnt<=3UL*pack->pack_depth/4UL ) ) ) multiplier = 1.0f;
        break;
      }
      case FD_ORD_TXN_ROOT_PENDING_BUNDLE: {
        /* We don't have a way to tell how much these actually pay in
           rewards, so we just assume they are very high. */
        treap = pack->pending_bundles;
        /* We cap rewards at UINT_MAX lamports for estimation, and min
           CUs is about 1000, which means rewards/compute < 5e6.
           FLT_MAX is around 3e38. That means, 1e20*rewards/compute is
           much less than FLT_MAX, so we won't have any issues with
           overflow.  On the other hand, if rewards==1 lamport and
           compute is 2 million CUs, 1e20*1/2e6 is still higher than any
           normal transaction. */
        multiplier = 1e20f;
        break;
      }
      case FD_ORD_TXN_ROOT_PENALTY( 0 ): {
        fd_txn_t * txn = TXN( sample->txn );
        fd_acct_addr_t const * accts   = fd_txn_get_acct_addrs( txn, sample->txn->payload );
        fd_acct_addr_t const * alt_adj = sample->txn_e->alt_accts - fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM );
        fd_acct_addr_t penalty_acct = *ACCT_IDX_TO_PTR( FD_ORD_TXN_ROOT_PENALTY_ACCT_IDX( root_idx ) );
        fd_pack_penalty_treap_t * q = penalty_map_query( pack->penalty_treaps, penalty_acct, NULL );
        FD_TEST( q );
        ulong cnt = treap_ele_cnt( q->penalty_treap );
        treap = q->penalty_treap;

        multiplier = sqrtf( 100.0f / (float)fd_ulong_max( 100UL, cnt ) );
        break;
      }
    }
    /* Get the worst from the sampled treap */
    treap_fwd_iter_t _cur=treap_fwd_iter_init( treap, pack->pool );
    FD_TEST( !treap_fwd_iter_done( _cur ) ); /* It can't be empty because we just sampled an element from it. */
    sample = treap_fwd_iter_ele( _cur, pack->pool );

    float score = multiplier * (float)sample->rewards / (float)sample->compute_est;
    worst = fd_ptr_if( score<worst_score, sample, worst );
    worst_score = fd_float_if( worst_score<score, worst_score, score );
  }

  if( FD_UNLIKELY( !worst                      ) ) return 0;
  if( FD_UNLIKELY( threshold_score<worst_score ) ) return 0;

  return delete_transaction( pack, worst, 1, 1 );
}

static inline int
validate_transaction( fd_pack_t               * pack,
                      fd_pack_ord_txn_t const * ord,
                      fd_txn_t          const * txn,
                      fd_acct_addr_t    const * accts,
                      fd_acct_addr_t    const * alt_adj,
                      int                       check_bundle_blacklist ) {
  int writes_to_sysvar = 0;
  for( fd_txn_acct_iter_t iter=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE );
      iter!=fd_txn_acct_iter_end(); iter=fd_txn_acct_iter_next( iter ) ) {
    writes_to_sysvar |= fd_pack_unwritable_contains( ACCT_ITER_TO_PTR( iter ) );
  }

  int bundle_blacklist = 0;
  if( FD_UNLIKELY( check_bundle_blacklist ) ) {
    for( fd_txn_acct_iter_t iter=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_ALL );
        iter!=fd_txn_acct_iter_end(); iter=fd_txn_acct_iter_next( iter ) ) {
      bundle_blacklist |= (3==fd_pack_tip_prog_check_blacklist( ACCT_ITER_TO_PTR( iter ) ));
    }
  }

  fd_acct_addr_t const * alt     = ord->txn_e->alt_accts;
  fd_chkdup_t * chkdup = pack->chkdup;
  ulong imm_cnt = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM );
  ulong alt_cnt = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_ALT );

  /* Throw out transactions ... */
  /*           ... that are unfunded */
  if( FD_UNLIKELY( !fd_pack_can_fee_payer_afford( accts, ord->rewards    ) ) ) return FD_PACK_INSERT_REJECT_UNAFFORDABLE;
  /*           ... that are so big they'll never run */
  if( FD_UNLIKELY( ord->compute_est >= pack->lim->max_cost_per_block       ) ) return FD_PACK_INSERT_REJECT_TOO_LARGE;
  /*           ... that load too many accounts (ignoring 9LZdXeKGeBV6hRLdxS1rHbHoEUsKqesCC2ZAPTPKJAbK) */
  if( FD_UNLIKELY( fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_ALL )>64UL     ) ) return FD_PACK_INSERT_REJECT_ACCOUNT_CNT;
  /*           ... that duplicate an account address */
  if( FD_UNLIKELY( fd_chkdup_check( chkdup, accts, imm_cnt, alt, alt_cnt ) ) ) return FD_PACK_INSERT_REJECT_DUPLICATE_ACCT;
  /*           ... that try to write to a sysvar */
  if( FD_UNLIKELY( writes_to_sysvar                                        ) ) return FD_PACK_INSERT_REJECT_WRITES_SYSVAR;
  /*           ... that use an account that violates bundle rules */
  if( FD_UNLIKELY( bundle_blacklist & 1                                    ) ) return FD_PACK_INSERT_REJECT_BUNDLE_BLACKLIST;

  return 0;
}



/* returns cumulative penalty "points", i.e. the sum of the populated
   section of penalties (which also tells the caller how much of the
   array is populated. */
static inline ulong
populate_bitsets( fd_pack_t         * pack,
                  fd_pack_ord_txn_t * ord,
                  ushort              penalties  [ static FD_TXN_ACCT_ADDR_MAX ],
                  uchar               penalty_idx[ static FD_TXN_ACCT_ADDR_MAX ] ) {
  FD_PACK_BITSET_CLEAR( ord->rw_bitset );
  FD_PACK_BITSET_CLEAR( ord->w_bitset  );

  fd_txn_t * txn   = TXN(ord->txn);
  uchar * payload  = ord->txn->payload;

  fd_acct_addr_t const * accts   = fd_txn_get_acct_addrs( txn, payload );
  /* alt_adj is the pointer to the ALT expansion, adjusted so that if
     account address n is the first that comes from the ALT, it can be
     accessed with adj_lut[n]. */
  fd_acct_addr_t const * alt_adj = ord->txn_e->alt_accts - fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM );

  ulong  cumulative_penalty = 0UL;
  ulong  penalty_i          = 0UL;

  for( fd_txn_acct_iter_t iter=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE );
      iter!=fd_txn_acct_iter_end(); iter=fd_txn_acct_iter_next( iter ) ) {
    fd_acct_addr_t acct = *ACCT_ITER_TO_PTR( iter );
    fd_pack_bitset_acct_mapping_t * q = bitset_map_query( pack->acct_to_bitset, acct, NULL );
    if( FD_UNLIKELY( q==NULL ) ) {
      q = bitset_map_insert( pack->acct_to_bitset, acct );
      q->ref_cnt                  = 0UL;
      q->first_instance           = ord;
      q->first_instance_was_write = 1;
      q->bit                      = FD_PACK_BITSET_FIRST_INSTANCE;
    } else if( FD_UNLIKELY( q->bit == FD_PACK_BITSET_FIRST_INSTANCE ) ) {
      q->bit = pack->bitset_avail[ pack->bitset_avail_cnt ];
      pack->bitset_avail_cnt = fd_ulong_if( !!pack->bitset_avail_cnt, pack->bitset_avail_cnt-1UL, 0UL );

      FD_PACK_BITSET_SETN( q->first_instance->rw_bitset, q->bit );
      if( q->first_instance_was_write ) FD_PACK_BITSET_SETN( q->first_instance->w_bitset, q->bit );
    }
    ulong penalty = fd_ulong_max( q->ref_cnt, PENALTY_TREAP_THRESHOLD )-PENALTY_TREAP_THRESHOLD;
    if( FD_UNLIKELY( penalty ) ) {
      penalties  [ penalty_i ] = (ushort)penalty;
      penalty_idx[ penalty_i ] = (uchar )fd_txn_acct_iter_idx( iter );
      penalty_i++;
      cumulative_penalty += penalty;
    }

    q->ref_cnt++;
    FD_PACK_BITSET_SETN( ord->rw_bitset, q->bit );
    FD_PACK_BITSET_SETN( ord->w_bitset , q->bit );
  }

  for( fd_txn_acct_iter_t iter=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_READONLY );
      iter!=fd_txn_acct_iter_end(); iter=fd_txn_acct_iter_next( iter ) ) {

    fd_acct_addr_t acct = *ACCT_ITER_TO_PTR( iter );
    if( FD_UNLIKELY( fd_pack_unwritable_contains( &acct ) ) ) continue;

    fd_pack_bitset_acct_mapping_t * q = bitset_map_query( pack->acct_to_bitset, acct, NULL );
    if( FD_UNLIKELY( q==NULL ) ) {
      q = bitset_map_insert( pack->acct_to_bitset, acct );
      q->ref_cnt                  = 0UL;
      q->first_instance           = ord;
      q->first_instance_was_write = 0;
      q->bit                      = FD_PACK_BITSET_FIRST_INSTANCE;
    } else if( FD_UNLIKELY( q->bit == FD_PACK_BITSET_FIRST_INSTANCE ) ) {
      q->bit = pack->bitset_avail[ pack->bitset_avail_cnt ];
      pack->bitset_avail_cnt = fd_ulong_if( !!pack->bitset_avail_cnt, pack->bitset_avail_cnt-1UL, 0UL );

      FD_PACK_BITSET_SETN( q->first_instance->rw_bitset, q->bit );
      if( q->first_instance_was_write ) FD_PACK_BITSET_SETN( q->first_instance->w_bitset, q->bit );
    }

    q->ref_cnt++;
    FD_PACK_BITSET_SETN( ord->rw_bitset, q->bit );
  }
  return cumulative_penalty;
}

int
fd_pack_insert_txn_fini( fd_pack_t  * pack,
                         fd_txn_e_t * txne,
                         ulong        expires_at,
                         ulong      * delete_cnt ) {

  fd_pack_ord_txn_t * ord = (fd_pack_ord_txn_t *)txne;

  fd_txn_t * txn   = TXN(txne->txnp);
  uchar * payload  = txne->txnp->payload;

  fd_acct_addr_t const * accts   = fd_txn_get_acct_addrs( txn, payload );
  /* alt_adj is the pointer to the ALT expansion, adjusted so that if
     account address n is the first that comes from the ALT, it can be
     accessed with adj_lut[n]. */
  fd_acct_addr_t const * alt_adj = ord->txn_e->alt_accts - fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM );

  ord->expires_at = expires_at;

  int est_result = fd_pack_estimate_rewards_and_compute( txne, ord );
  if( FD_UNLIKELY( !est_result ) ) REJECT( ESTIMATION_FAIL );
  int is_vote          = est_result==1;

  int nonce_result = fd_pack_validate_durable_nonce( txne );
  if( FD_UNLIKELY( !nonce_result ) ) REJECT( INVALID_NONCE );
  int is_durable_nonce = nonce_result==2;
  ord->txn->flags &= ~FD_TXN_P_FLAGS_DURABLE_NONCE;
  ord->txn->flags |= fd_uint_if( is_durable_nonce, FD_TXN_P_FLAGS_DURABLE_NONCE, 0U );

  int validation_result = validate_transaction( pack, ord, txn, accts, alt_adj, !!pack->bundle_meta_sz );
  if( FD_UNLIKELY( validation_result ) ) {
    trp_pool_ele_release( pack->pool, ord );
    return validation_result;
  }

  /* Reject any transactions that have already expired */
  if( FD_UNLIKELY( expires_at<pack->expire_before                          ) ) REJECT( EXPIRED          );

  int replaces = 0;
  *delete_cnt = 0UL;
  /* If it's a durable nonce and we already have one, delete one or the
     other. */
  if( FD_UNLIKELY( is_durable_nonce ) ) {
    fd_pack_ord_txn_t * same_nonce = noncemap_ele_query( pack->noncemap, txne, NULL, pack->pool );
    if( FD_LIKELY( same_nonce ) ) { /* Seems like most nonce transactions are effectively duplicates */
      if( FD_LIKELY( same_nonce->root == FD_ORD_TXN_ROOT_PENDING_BUNDLE || COMPARE_WORSE( ord, same_nonce ) ) ) REJECT( NONCE_PRIORITY );
      ulong _delete_cnt = delete_transaction( pack, same_nonce, 0, 0 ); /* Not a bundle, so delete_full_bundle is 0 */
      *delete_cnt += _delete_cnt;
      replaces = 1;
    }
  }

  if( FD_UNLIKELY( pack->pending_txn_cnt == pack->pack_depth ) ) {
    float threshold_score = (float)ord->rewards/(float)ord->compute_est;
    ulong _delete_cnt = delete_worst( pack, threshold_score, is_vote );
    *delete_cnt += _delete_cnt;
    if( FD_UNLIKELY( !_delete_cnt ) ) REJECT( PRIORITY );
    replaces = 1;
  }

  ord->txn->flags &= ~(FD_TXN_P_FLAGS_BUNDLE | FD_TXN_P_FLAGS_INITIALIZER_BUNDLE);
  ord->skip = FD_PACK_SKIP_CNT;

  /* At this point, we know we have space to insert the transaction and
     we've committed to insert it. */

  /* Since the pool uses ushorts, the size of the pool is < USHORT_MAX.
     Each transaction can reference an account at most once, which means
     that the total number of references for an account is < USHORT_MAX.
     If these were ulongs, the array would be 512B, which is kind of a
     lot to zero out.*/
  ushort penalties[ FD_TXN_ACCT_ADDR_MAX ] = {0};
  uchar  penalty_idx[ FD_TXN_ACCT_ADDR_MAX ];
  ulong cumulative_penalty = populate_bitsets( pack, ord, penalties, penalty_idx );

  treap_t * insert_into = pack->pending;

  if( FD_UNLIKELY( cumulative_penalty && !is_vote ) ) { /* Optimize for high parallelism case */
    /* Compute a weighted random choice */
    ulong roll = (ulong)fd_rng_uint_roll( pack->rng, (uint)cumulative_penalty ); /* cumulative_penalty < USHORT_MAX*64 < UINT_MAX */
    ulong i = 0UL;
    /* Find the right one.  This can be done in O(log N), but I imagine
       N is normally so small that doesn't matter. */
    while( roll>=penalties[i] ) roll -= (ulong)penalties[i++];

    fd_acct_addr_t penalty_acct = *ACCT_IDX_TO_PTR( penalty_idx[i] );
    fd_pack_penalty_treap_t * q = penalty_map_query( pack->penalty_treaps, penalty_acct, NULL );
    if( FD_UNLIKELY( q==NULL ) ) {
      q = penalty_map_insert( pack->penalty_treaps, penalty_acct );
      treap_new( q->penalty_treap, pack->pack_depth );
    }
    insert_into = q->penalty_treap;
    ord->root = FD_ORD_TXN_ROOT_PENALTY( penalty_idx[i] );
  } else {
    ord->root = fd_int_if( is_vote, FD_ORD_TXN_ROOT_PENDING_VOTE, FD_ORD_TXN_ROOT_PENDING );

    fd_pack_smallest_t * smallest = fd_ptr_if( is_vote, &pack->pending_votes_smallest[0], pack->pending_smallest );
    smallest->cus   = fd_ulong_min( smallest->cus,   ord->compute_est       );
    smallest->bytes = fd_ulong_min( smallest->bytes, txne->txnp->payload_sz );
  }

  pack->pending_txn_cnt++;

  sig2txn_ele_insert( pack->signature_map, ord, pack->pool );

  if( FD_UNLIKELY( is_durable_nonce ) ) noncemap_ele_insert( pack->noncemap, ord, pack->pool );

  fd_pack_expq_t temp[ 1 ] = {{ .expires_at = expires_at, .txn = ord }};
  expq_insert( pack->expiration_q, temp );

  if( FD_LIKELY( is_vote ) ) insert_into = pack->pending_votes;

  treap_ele_insert( insert_into, ord, pack->pool );
  return (is_vote) | (replaces<<1) | (is_durable_nonce<<2);
}
#undef REJECT

fd_txn_e_t * const *
fd_pack_insert_bundle_init( fd_pack_t          * pack,
                            fd_txn_e_t *       * bundle,
                            ulong                txn_cnt ) {
  FD_TEST( txn_cnt<=FD_PACK_MAX_TXN_PER_BUNDLE  );
  FD_TEST( trp_pool_free( pack->pool )>=txn_cnt );
  for( ulong i=0UL; i<txn_cnt; i++ ) bundle[ i ] = trp_pool_ele_acquire( pack->pool )->txn_e;
  return bundle;
}

void
fd_pack_insert_bundle_cancel( fd_pack_t          * pack,
                              fd_txn_e_t * const * bundle,
                              ulong                txn_cnt ) {
  /* There's no real reason these have to be released in reverse, but it
     seems fitting to release them in the opposite order they were
     acquired. */
  for( ulong i=0UL; i<txn_cnt; i++ ) trp_pool_ele_release( pack->pool, (fd_pack_ord_txn_t*)bundle[ txn_cnt-1UL-i ] );
}

/* Explained below */
#define BUNDLE_L_PRIME 37896771UL
#define BUNDLE_N       312671UL
#define RC_TO_REL_BUNDLE_IDX( r, c ) (BUNDLE_N - ((ulong)(r) * 1UL<<32)/((ulong)(c) * BUNDLE_L_PRIME))

int
fd_pack_insert_bundle_fini( fd_pack_t          * pack,
                            fd_txn_e_t * const * bundle,
                            ulong                txn_cnt,
                            ulong                expires_at,
                            int                  initializer_bundle,
                            void         const * bundle_meta,
                            ulong              * delete_cnt ) {

  int err = 0;
  *delete_cnt = 0UL;

  ulong pending_b_txn_cnt = treap_ele_cnt( pack->pending_bundles );
    /* We want to prevent bundles from consuming the whole treap, but in
       general, we assume bundles are lucrative.  We'll set the policy
       on capping bundles at half of the pack depth.  We assume that the
       bundles are coming in a pre-prioritized order, so it doesn't make
       sense to drop an earlier bundle for this one.  That means that
       really, the best thing to do is drop this one. */
  if( FD_UNLIKELY( (!initializer_bundle)&(pending_b_txn_cnt+txn_cnt>pack->pack_depth/2UL) ) ) err = FD_PACK_INSERT_REJECT_PRIORITY;

  if( FD_UNLIKELY( expires_at<pack->expire_before                                         ) ) err = FD_PACK_INSERT_REJECT_EXPIRED;


  int   replaces      = 0;
  ulong nonce_txn_cnt = 0UL;

  /* Collect nonce hashes to detect duplicate nonces.
     Use a constant-time duplicate-detection algorithm -- Vacant entries
     have the MSB set, occupied entries are the noncemap hash, with the
     MSB set to 0. */
  ulong nonce_hash63[ FD_PACK_MAX_TXN_PER_BUNDLE ];
  for( ulong i=0UL; i<FD_PACK_MAX_TXN_PER_BUNDLE; i++ ) {
    nonce_hash63[ i ] = ULONG_MAX-i;
  }

  for( ulong i=0UL; (i<txn_cnt) && !err; i++ ) {
    fd_pack_ord_txn_t * ord = (fd_pack_ord_txn_t *)bundle[ i ];

    fd_txn_t const * txn     = TXN(bundle[ i ]->txnp);
    uchar    const * payload = bundle[ i ]->txnp->payload;

    fd_acct_addr_t const * accts   = fd_txn_get_acct_addrs( txn, payload );
    fd_acct_addr_t const * alt_adj = ord->txn_e->alt_accts - fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM );

    int est_result = fd_pack_estimate_rewards_and_compute( bundle[ i ], ord );
    if( FD_UNLIKELY( !est_result   ) ) { err = FD_PACK_INSERT_REJECT_ESTIMATION_FAIL; break; }
    int nonce_result = fd_pack_validate_durable_nonce( ord->txn_e );
    if( FD_UNLIKELY( !nonce_result ) ) { err = FD_PACK_INSERT_REJECT_INVALID_NONCE;   break; }
    int is_durable_nonce = nonce_result==2;
    nonce_txn_cnt += !!is_durable_nonce;

    bundle[ i ]->txnp->flags |= FD_TXN_P_FLAGS_BUNDLE;
    bundle[ i ]->txnp->flags &= ~(FD_TXN_P_FLAGS_INITIALIZER_BUNDLE | FD_TXN_P_FLAGS_DURABLE_NONCE);
    bundle[ i ]->txnp->flags |= fd_uint_if( initializer_bundle, FD_TXN_P_FLAGS_INITIALIZER_BUNDLE, 0U );
    bundle[ i ]->txnp->flags |= fd_uint_if( is_durable_nonce,   FD_TXN_P_FLAGS_DURABLE_NONCE,      0U );
    ord->expires_at = expires_at;

    if( FD_UNLIKELY( is_durable_nonce ) ) {
      nonce_hash63[ i ] = noncemap_key_hash( ord->txn_e, pack->noncemap->seed ) & 0x7FFFFFFFFFFFFFFFUL;
      fd_pack_ord_txn_t * same_nonce = noncemap_ele_query( pack->noncemap, ord->txn_e, NULL, pack->pool );
      if( FD_LIKELY( same_nonce ) ) {
        /* bundles take priority over non-bundles, and earlier bundles
           take priority over later bundles. */
        if( FD_UNLIKELY( same_nonce->txn->flags & FD_TXN_P_FLAGS_BUNDLE ) ) {
          err = FD_PACK_INSERT_REJECT_NONCE_PRIORITY;
          break;
        } else {
          ulong _delete_cnt = delete_transaction( pack, same_nonce, 0, 0 );
          *delete_cnt += _delete_cnt;
          replaces = 1;
        }
      }
    }

    int validation_result = validate_transaction( pack, ord, txn, accts, alt_adj, !initializer_bundle );
    if( FD_UNLIKELY( validation_result ) ) { err = validation_result; break; }
  }

  if( FD_UNLIKELY( err ) ) {
    fd_pack_insert_bundle_cancel( pack, bundle, txn_cnt );
    return err;
  }

  if( FD_UNLIKELY( initializer_bundle && pending_b_txn_cnt>0UL ) ) {
    treap_rev_iter_t _cur=treap_rev_iter_init( pack->pending_bundles, pack->pool );
    FD_TEST( !treap_rev_iter_done( _cur ) );
    fd_pack_ord_txn_t * cur = treap_rev_iter_ele( _cur, pack->pool );
    int is_ib = !!(cur->txn->flags & FD_TXN_P_FLAGS_INITIALIZER_BUNDLE);

    /* Delete the previous IB if there is one */
    if( FD_UNLIKELY( is_ib && 0UL==RC_TO_REL_BUNDLE_IDX( cur->rewards, cur->compute_est ) ) ) {
      ulong _delete_cnt = delete_transaction( pack, cur, 1, 0 );
      *delete_cnt += _delete_cnt;
    }
  }

  while( FD_UNLIKELY( pack->pending_txn_cnt+txn_cnt > pack->pack_depth ) ) {
    ulong _delete_cnt = delete_worst( pack, FLT_MAX, 0 );
    *delete_cnt += _delete_cnt;
    if( FD_UNLIKELY( !_delete_cnt ) ) {
      fd_pack_insert_bundle_cancel( pack, bundle, txn_cnt );
      return FD_PACK_INSERT_REJECT_PRIORITY;
    }
    replaces = 1;
  }

  if( FD_UNLIKELY( !pending_b_txn_cnt ) ) {
    pack->relative_bundle_idx = 1UL;
  }

  if( FD_LIKELY( bundle_meta ) ) {
    memcpy( (uchar *)pack->bundle_meta + (ulong)((fd_pack_ord_txn_t *)bundle[0]-pack->pool)*pack->bundle_meta_sz, bundle_meta, pack->bundle_meta_sz );
  }

  if( FD_UNLIKELY( nonce_txn_cnt>1UL ) ) {
    /* Do a ILP-friendly duplicate detect, naive O(n^2) algo.  With max
       5 txns per bundle, this requires 10 comparisons.  ~ 25 cycle.  */
    uint conflict_detected = 0u;
    for( ulong i=0UL; i<FD_PACK_MAX_TXN_PER_BUNDLE-1; i++ ) {
      for( ulong j=i+1; j<FD_PACK_MAX_TXN_PER_BUNDLE; j++ ) {
        ulong const ele_i = nonce_hash63[ i ];
        ulong const ele_j = nonce_hash63[ j ];
        conflict_detected |= (ele_i==ele_j);
      }
    }
    if( FD_UNLIKELY( conflict_detected ) ) {
      fd_pack_insert_bundle_cancel( pack, bundle, txn_cnt );
      return FD_PACK_INSERT_REJECT_NONCE_CONFLICT;
    }
  }

  /* We put bundles in a treap just like all the other transactions, but
     we actually want to sort them in a very specific order; the order
     within the bundle is determined at bundle creation time, and the
     order among the bundles is FIFO.  However, it's going to be a pain
     to use a different sorting function for this treap, since it's
     fixed as part of the treap creation for performance.  Don't fear
     though; we can pull a cool math trick out of the bag to shoehorn
     the order we'd like into the sort function we need, and to get even
     more.

     Recall that the sort function is r_i/c_i, smallest to largest,
     where r_i is the rewards and c_i is the cost units.  r_i and c_i
     are both uints, and the comparison is done by cross-multiplication
     as ulongs.  We actually use the c_i value for testing if
     transactions fit, etc.  so let's assume that's fixed, and we know
     it's in the range [1020, 1,556,782].

     This means, if c_0, c_1, ... c_4 are the CU costs of the
     transactions in the first bundle, we require r_0/c_0 > r_1/c_1 >
     ... > r_4/c_4.  Then, if c_5, ... c_9 are the CU costs of the
     transactions in the second bundle, we also require that r_4/c_4 >
     r_5/c_5.  For convenience, we'll impose a slightly stronger
     constraint: we want the kth bundle to obey L*(N-k) <= r_i/c_i <
     L*(N+1-k), for fixed constants L and N, real and integer,
     respectively, that we'll determine. For example, this means r_4/c_4
     >= L*N > r_5/c_5.  This enables us to group the transactions in the
     same bundle more easily.

     For convenience in the math below, we'll set j=N-k and relabel the
     transactions from the jth bundle c_0, ... c_4.
     From above, we know that Lj <= r_4/c_4.  We'd like to make it as
     close as possible given that r_4 is an integers.  Thus, put
     r_4 = ceil( c_4 * Lj ).  r_4 is clearly an integer, and it satisfies
     the required inequality because:
            r_4/c_4 = ceil( c_4 * Lj)/c_4 >= c_4*Lj / c_4 >= Lj.

     Following in the same spirit, put r_3 = ceil( c_3 * (r_4+1)/c_4 ).
     Again, r_3 is clearly an integer, and
                r_3/c_3  = ceil(c_3*(r_4+1)/c_4)/c_3
                        >= (c_3*(r_4+1))/(c_3 * c_4)
                        >= r_4/c_4 + 1/c_4
                        >  r_4/c_4.
     Following the pattern, we put
                r_2 = ceil( c_2 * (r_3+1)/c_3 )
                r_1 = ceil( c_1 * (r_2+1)/c_2 )
                r_0 = ceil( c_0 * (r_1+1)/c_1 )
     which work for the same reason that as r_3.

     We now need for r_0 to satisfy the final inequality with L, and
     we'll use this to guide our choice of L.  Theoretically, r_0 can be
     expressed in terms of L, j, and c_0, ... c_4, but that's a truly
     inscrutible expression.  Instead, we need some bounds so we can get
     rid of all the ceil using the property that x <= ceil(x) < x+1.
                     c_4 * Lj <= r_4 < c_4 * Lj + 1
     The lower bound on r_3 is easy:
         r_3 >= c_3 * (c_4 * Lj + 1)/c_4 = c_3 * Lj + c_3/c_4
     For the upper bound,
         r_3 < 1 + c_3*(r_4+1)/c_4 < 1 + c_3*(c_4*Lj+1 + 1)/c_4
                                   = 1 + c_3 * Lj + 2*c_3/c_4
     Continuing similarly gives
       c_2*Lj +                     c_2/c_3 + c_2/c_4 <= r_2
       c_1*Lj +           c_1/c_2 + c_1/c_c + c_1/c_4 <= r_1
       c_0*Lj + c_0/c_1 + c_0/c_2 + c_0/c_3 + c_0/c_4 <= r_0
     and
       r_2 < 1 + c_2*Lj +                       2c_2/c_3 + 2c_2/c_4
       r_1 < 1 + c_1*Lj +            2c_1/c_2 + 2c_1/c_3 + 2c_1/c_4
       r_0 < 1 + c_0*Lj + 2c_0/c_1 + 2c_0/c_2 + 2c_0/c_3 + 2c_0/c_4.

     Setting L(j+1)>=(1 + c_0*Lj+2c_0/c_1+2c_0/c_2+2c_0/c_3+2c_0/c_4)/c_0
     is then sufficient to ensure the whole sequence of 5 fits between Lj
     and L(j+1).  Simplifying gives
              L<= 1/c_0 + 2/c_1 + 2/c_2 + 2/c_3 + 2/c_4
     but L must be a constant and not depend on individual values of c_i,
     so, given that c_i >= 1020, we set L = 9/1020.

     Now all that remains is to determine N.  It's a bit unfortunate
     that we require N, since it limits our capacity, but it's necessary
     in any system that tries to compute priorities to enforce a FIFO
     order.  If we've inserted more than N bundles without ever having
     the bundle treap go empty, we'll briefly break the FIFO ordering as
     we underflow.

     Thus, we'd like to make N as big as possible, avoiding overflow.
     r_0, ..., r_4 are all uints, and taking the bounds from above,
     given that for any i, i' c_i/c_{i'} < 1527, we have
               r_i < 1 + 1556782 * Lj + 8*1527.
     To avoid overflow, we assert the right-hand side is < 2^32, which
     implies N <= 312671.

     We want to use a fixed point representation for L so that the
     entire computation can be done with integer arithmetic.  We can do
     the arithmetic as ulongs, which means defining L' >= L * 2^s, and
     we compute ceil( c_4*Lj ) as floor( (c_4 * L' * j + 2^s - 1)/2^s ),
     so c_4 * L' * j + 2^s should fit in a ulong.  With j<=N, this gives
     s<=32, so we set s=32, which means L' = 37896771 >= 9/1020 * 2^32.
     Note that 1 + 1556782 * L' * N + 8*1527 + 2^32 is approximately
     2^63.999993.

     Note that this is all checked by a proof of the code translated
     into Z3.  Unfortunately CBMC was too slow to prove this code
     directly. */
#define BUNDLE_L_PRIME 37896771UL
#define BUNDLE_N       312671UL

  if( FD_UNLIKELY( pack->relative_bundle_idx>BUNDLE_N ) ) {
    FD_LOG_WARNING(( "Too many bundles inserted without allowing pending bundles to go empty. "
                     "Ordering of bundles may be incorrect." ));
    pack->relative_bundle_idx = 1UL;
  }
  ulong bundle_idx = fd_ulong_if( initializer_bundle, 0UL, pack->relative_bundle_idx );
  insert_bundle_impl( pack, bundle_idx, txn_cnt, (fd_pack_ord_txn_t * *)bundle, expires_at );
  /* if IB this is max( 1, x ), which is x.  Otherwise, this is max(x,
     x+1) which is x++ */
  pack->relative_bundle_idx = fd_ulong_max( bundle_idx+1UL, pack->relative_bundle_idx );

  return (0) | (replaces<<1) | ((!!nonce_txn_cnt)<<2);
}
static inline void
insert_bundle_impl( fd_pack_t           * pack,
                    ulong                 bundle_idx,
                    ulong                 txn_cnt,
                    fd_pack_ord_txn_t * * bundle,
                    ulong                 expires_at ) {
  ulong prev_reward = ((BUNDLE_L_PRIME * (BUNDLE_N - bundle_idx))) - 1UL;
  ulong prev_cost = 1UL<<32;

  /* Assign last to first */
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_pack_ord_txn_t * ord = bundle[ txn_cnt-1UL - i ];
    ord->rewards = (uint)(((ulong)ord->compute_est * (prev_reward + 1UL) + prev_cost-1UL)/prev_cost);
    ord->root    = FD_ORD_TXN_ROOT_PENDING_BUNDLE;
    prev_reward = ord->rewards;
    prev_cost   = ord->compute_est;

    /* The penalty information isn't used for bundles. */
    ushort penalties  [ FD_TXN_ACCT_ADDR_MAX ];
    uchar  penalty_idx[ FD_TXN_ACCT_ADDR_MAX ];
    populate_bitsets( pack, ord, penalties, penalty_idx );

    treap_ele_insert( pack->pending_bundles, ord, pack->pool );
    pack->pending_txn_cnt++;

    if( FD_UNLIKELY( ord->txn->flags & FD_TXN_P_FLAGS_DURABLE_NONCE ) ) noncemap_ele_insert( pack->noncemap, ord, pack->pool );
    sig2txn_ele_insert( pack->signature_map, ord, pack->pool );

    fd_pack_expq_t temp[ 1 ] = {{ .expires_at = expires_at, .txn = ord }};
    expq_insert( pack->expiration_q, temp );
  }

}

void const *
fd_pack_peek_bundle_meta( fd_pack_t const * pack ) {
  int ib_state = pack->initializer_bundle_state;
  if( FD_UNLIKELY( (ib_state==FD_PACK_IB_STATE_PENDING) | (ib_state==FD_PACK_IB_STATE_FAILED) ) ) return NULL;

  treap_rev_iter_t _cur=treap_rev_iter_init( pack->pending_bundles, pack->pool );
  if( FD_UNLIKELY( treap_rev_iter_done( _cur ) ) ) return NULL; /* empty */

  fd_pack_ord_txn_t * cur = treap_rev_iter_ele( _cur, pack->pool );
  int is_ib = !!(cur->txn->flags & FD_TXN_P_FLAGS_INITIALIZER_BUNDLE);
  if( FD_UNLIKELY( is_ib ) ) return NULL;

  return (void const *)((uchar const *)pack->bundle_meta + (ulong)_cur * pack->bundle_meta_sz);
}

void
fd_pack_set_initializer_bundles_ready( fd_pack_t * pack ) {
  pack->initializer_bundle_state = FD_PACK_IB_STATE_READY;
}

void
fd_pack_metrics_write( fd_pack_t const * pack ) {
  ulong pending_regular = treap_ele_cnt( pack->pending        );
  ulong pending_votes  = treap_ele_cnt( pack->pending_votes   );
  ulong pending_bundle = treap_ele_cnt( pack->pending_bundles );
  ulong conflicting    = pack->pending_txn_cnt - pending_votes - pending_bundle - treap_ele_cnt( pack->pending );
  FD_MGAUGE_SET( PACK, AVAILABLE_TRANSACTIONS_ALL,         pack->pending_txn_cnt       );
  FD_MGAUGE_SET( PACK, AVAILABLE_TRANSACTIONS_REGULAR,     pending_regular             );
  FD_MGAUGE_SET( PACK, AVAILABLE_TRANSACTIONS_VOTES,       pending_votes               );
  FD_MGAUGE_SET( PACK, AVAILABLE_TRANSACTIONS_CONFLICTING, conflicting                 );
  FD_MGAUGE_SET( PACK, AVAILABLE_TRANSACTIONS_BUNDLES,     pending_bundle              );
  FD_MGAUGE_SET( PACK, SMALLEST_PENDING_TRANSACTION,       pack->pending_smallest->cus );
}

typedef struct {
  ushort clear_rw_bit;
  ushort clear_w_bit;
} release_result_t;

static inline release_result_t
release_bit_reference( fd_pack_t            * pack,
                       fd_acct_addr_t const * acct ) {

  fd_pack_bitset_acct_mapping_t * q = bitset_map_query( pack->acct_to_bitset, *acct, NULL );
  FD_TEST( q ); /* q==NULL not be possible */

  q->ref_cnt--;

  if( FD_UNLIKELY( q->ref_cnt==0UL ) ) {
    ushort bit = q->bit;
    bitset_map_remove( pack->acct_to_bitset, q );
    if( FD_LIKELY( bit<FD_PACK_BITSET_MAX ) ) pack->bitset_avail[ ++(pack->bitset_avail_cnt) ] = bit;

    fd_pack_addr_use_t * use = acct_uses_query( pack->acct_in_use,  *acct, NULL );
    if( FD_LIKELY( use ) ) {
      use->in_use_by |= FD_PACK_IN_USE_BIT_CLEARED;
      release_result_t ret = { .clear_rw_bit = bit,
                               .clear_w_bit = fd_ushort_if( !!(use->in_use_by & FD_PACK_IN_USE_WRITABLE), bit, FD_PACK_BITSET_MAX ) };
      return ret;
    }
  }
  release_result_t ret = { .clear_rw_bit = FD_PACK_BITSET_MAX, .clear_w_bit = FD_PACK_BITSET_MAX };
  return ret;
}

typedef struct {
  ulong cus_scheduled;
  ulong txns_scheduled;
  ulong bytes_scheduled;
} sched_return_t;

static inline sched_return_t
fd_pack_schedule_impl( fd_pack_t          * pack,
                       treap_t            * sched_from,
                       ulong                cu_limit,
                       ulong                txn_limit,
                       ulong                byte_limit,
                       ulong                bank_tile,
                       fd_pack_smallest_t * smallest_in_treap,
                       ulong              * use_by_bank_txn,
                       fd_txn_p_t         * out ) {

  fd_pack_ord_txn_t  * pool         = pack->pool;
  fd_pack_addr_use_t * acct_in_use  = pack->acct_in_use;
  fd_pack_addr_use_t * writer_costs = pack->writer_costs;

  fd_pack_addr_use_t ** written_list     = pack->written_list;
  ulong                 written_list_cnt = pack->written_list_cnt;
  ulong                 written_list_max = pack->written_list_max;

  FD_PACK_BITSET_DECLARE( bitset_rw_in_use );
  FD_PACK_BITSET_DECLARE( bitset_w_in_use  );
  FD_PACK_BITSET_COPY( bitset_rw_in_use, pack->bitset_rw_in_use );
  FD_PACK_BITSET_COPY( bitset_w_in_use,  pack->bitset_w_in_use  );

  fd_pack_addr_use_t * use_by_bank     = pack->use_by_bank    [bank_tile];
  ulong                use_by_bank_cnt = pack->use_by_bank_cnt[bank_tile];

  ulong max_write_cost_per_acct = pack->lim->max_write_cost_per_acct;

  ushort compressed_slot_number = pack->compressed_slot_number;

  ulong txns_scheduled  = 0UL;
  ulong cus_scheduled   = 0UL;
  ulong bytes_scheduled = 0UL;

  ulong bank_tile_mask = 1UL << bank_tile;

  ulong fast_path     = 0UL;
  ulong slow_path     = 0UL;
  ulong cu_limit_c    = 0UL;
  ulong byte_limit_c  = 0UL;
  ulong write_limit_c = 0UL;
  ulong skip_c        = 0UL;

  ulong min_cus   = ULONG_MAX;
  ulong min_bytes = ULONG_MAX;

  if( FD_UNLIKELY( (cu_limit<smallest_in_treap->cus) | (txn_limit==0UL) | (byte_limit<smallest_in_treap->bytes) ) ) {
    sched_return_t to_return = { .cus_scheduled = 0UL, .txns_scheduled = 0UL, .bytes_scheduled = 0UL };
    return to_return;
  }

  treap_rev_iter_t prev = treap_idx_null();
  for( treap_rev_iter_t _cur=treap_rev_iter_init( sched_from, pool ); !treap_rev_iter_done( _cur ); _cur=prev ) {
    /* Capture next so that we can delete while we iterate. */
    prev = treap_rev_iter_next( _cur, pool );

#   if FD_HAS_X86
    _mm_prefetch( &(pool[ prev ].prev),      _MM_HINT_T0 );
#   endif

    fd_pack_ord_txn_t * cur = treap_rev_iter_ele( _cur, pool );

    min_cus   = fd_ulong_min( min_cus,   cur->compute_est     );
    min_bytes = fd_ulong_min( min_bytes, cur->txn->payload_sz );

    ulong conflicts = 0UL;

    if( FD_UNLIKELY( cur->compute_est>cu_limit ) ) {
      /* Too big to be scheduled at the moment, but might be okay for
         the next microblock, so we don't want to delay it. */
      cu_limit_c++;
      continue;
    }

    /* Likely? Unlikely? */
    if( FD_LIKELY( !FD_PACK_BITSET_INTERSECT4_EMPTY( bitset_rw_in_use, bitset_w_in_use, cur->w_bitset, cur->rw_bitset ) ) ) {
      fast_path++;
      continue;
    }

    if( FD_UNLIKELY( cur->skip==compressed_slot_number ) ) {
      skip_c++;
      continue;
    }

    /* If skip>FD_PACK_MAX_SKIP but not compressed_slot_number, it means
       it's the compressed slot number of a previous slot.  We don't
       care unless we're going to update the value though, so we don't
       need to eagerly reset it to FD_PACK_MAX_SKIP.
       compressed_slot_number is a ushort, so it's possible for it to
       roll over, but the transaction lifetime is much shorter than
       that, so it won't be a problem. */

    if( FD_UNLIKELY( cur->txn->payload_sz>byte_limit ) ) {
      byte_limit_c++;
      continue;
    }


    fd_txn_t const * txn = TXN(cur->txn);
    fd_acct_addr_t const * accts   = fd_txn_get_acct_addrs( txn, cur->txn->payload );
    fd_acct_addr_t const * alt_adj = cur->txn_e->alt_accts - fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM );
    /* Check conflicts between this transaction's writable accounts and
       current readers */
    for( fd_txn_acct_iter_t iter=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE );
        iter!=fd_txn_acct_iter_end(); iter=fd_txn_acct_iter_next( iter ) ) {

      fd_acct_addr_t acct = *ACCT_ITER_TO_PTR( iter );

      fd_pack_addr_use_t * in_wcost_table = acct_uses_query( writer_costs, acct, NULL );
      if( FD_UNLIKELY( in_wcost_table && in_wcost_table->total_cost+cur->compute_est > max_write_cost_per_acct ) ) {
        /* Can't be scheduled until the next block */
        conflicts = ULONG_MAX;
        break;
      }

      fd_pack_addr_use_t * use = acct_uses_query( acct_in_use, acct, NULL );
      if( FD_UNLIKELY( use ) ) conflicts |= use->in_use_by; /* break? */
    }

    if( FD_UNLIKELY( conflicts==ULONG_MAX ) ) {
      /* The logic for how to adjust skip is a bit complicated, and we
         want to do it branchlessly.
           Before                   After
             1               compressed_slot_number
           x in [2, 5]               x-1
           x where x>5                4

         Set A=min(x, 5), B=min(A-2, compressed_slot_number-1), and
         note that compressed_slot_number is in [6, USHORT_MAX].
         Then:
             x                A     A-2          B      B+1
             1                1  USHORT_MAX    csn-1    csn
           x in [2, 5]        x     x-2         x-2     x-1
           x where x>5        5      3           3       4
         So B+1 is the desired value. */
      cur->skip = (ushort)(1+fd_ushort_min( (ushort)(compressed_slot_number-1),
                                            (ushort)(fd_ushort_min( cur->skip, FD_PACK_SKIP_CNT )-2) ) );
      write_limit_c++;
      continue;
    }

    if( FD_UNLIKELY( conflicts ) ) {
      slow_path++;
      continue;
    }

    /* Check conflicts between this transaction's readonly accounts and
       current writers */
    for( fd_txn_acct_iter_t iter=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_READONLY );
        iter!=fd_txn_acct_iter_end(); iter=fd_txn_acct_iter_next( iter ) ) {

      fd_acct_addr_t const * acct = ACCT_ITER_TO_PTR( iter );
      if( fd_pack_unwritable_contains( acct ) ) continue; /* No need to track sysvars because they can't be writable */

      fd_pack_addr_use_t * use = acct_uses_query( acct_in_use,  *acct, NULL );
      if( use ) conflicts |= (use->in_use_by & FD_PACK_IN_USE_WRITABLE) ? use->in_use_by : 0UL;
    }

    if( FD_UNLIKELY( conflicts ) ) {
      slow_path++;
      continue;
    }

    /* Include this transaction in the microblock! */
    FD_PACK_BITSET_OR( bitset_rw_in_use, cur->rw_bitset );
    FD_PACK_BITSET_OR( bitset_w_in_use,  cur->w_bitset  );

    if(
#if FD_HAS_AVX512 && FD_PACK_USE_NON_TEMPORAL_MEMCPY
        FD_LIKELY( cur->txn->payload_sz>=1024UL )
#else
        0
#endif
      ) {
#if FD_HAS_AVX512 && FD_PACK_USE_NON_TEMPORAL_MEMCPY
      _mm512_stream_si512( (void*)(out->payload+   0UL), _mm512_load_epi64( cur->txn->payload+   0UL ) );
      _mm512_stream_si512( (void*)(out->payload+  64UL), _mm512_load_epi64( cur->txn->payload+  64UL ) );
      _mm512_stream_si512( (void*)(out->payload+ 128UL), _mm512_load_epi64( cur->txn->payload+ 128UL ) );
      _mm512_stream_si512( (void*)(out->payload+ 192UL), _mm512_load_epi64( cur->txn->payload+ 192UL ) );
      _mm512_stream_si512( (void*)(out->payload+ 256UL), _mm512_load_epi64( cur->txn->payload+ 256UL ) );
      _mm512_stream_si512( (void*)(out->payload+ 320UL), _mm512_load_epi64( cur->txn->payload+ 320UL ) );
      _mm512_stream_si512( (void*)(out->payload+ 384UL), _mm512_load_epi64( cur->txn->payload+ 384UL ) );
      _mm512_stream_si512( (void*)(out->payload+ 448UL), _mm512_load_epi64( cur->txn->payload+ 448UL ) );
      _mm512_stream_si512( (void*)(out->payload+ 512UL), _mm512_load_epi64( cur->txn->payload+ 512UL ) );
      _mm512_stream_si512( (void*)(out->payload+ 576UL), _mm512_load_epi64( cur->txn->payload+ 576UL ) );
      _mm512_stream_si512( (void*)(out->payload+ 640UL), _mm512_load_epi64( cur->txn->payload+ 640UL ) );
      _mm512_stream_si512( (void*)(out->payload+ 704UL), _mm512_load_epi64( cur->txn->payload+ 704UL ) );
      _mm512_stream_si512( (void*)(out->payload+ 768UL), _mm512_load_epi64( cur->txn->payload+ 768UL ) );
      _mm512_stream_si512( (void*)(out->payload+ 832UL), _mm512_load_epi64( cur->txn->payload+ 832UL ) );
      _mm512_stream_si512( (void*)(out->payload+ 896UL), _mm512_load_epi64( cur->txn->payload+ 896UL ) );
      _mm512_stream_si512( (void*)(out->payload+ 960UL), _mm512_load_epi64( cur->txn->payload+ 960UL ) );
      _mm512_stream_si512( (void*)(out->payload+1024UL), _mm512_load_epi64( cur->txn->payload+1024UL ) );
      _mm512_stream_si512( (void*)(out->payload+1088UL), _mm512_load_epi64( cur->txn->payload+1088UL ) );
      _mm512_stream_si512( (void*)(out->payload+1152UL), _mm512_load_epi64( cur->txn->payload+1152UL ) );
      _mm512_stream_si512( (void*)(out->payload+1216UL), _mm512_load_epi64( cur->txn->payload+1216UL ) );
      /* Copied out to 1280 bytes, which copies some other fields we needed to
         copy anyway. */
      FD_STATIC_ASSERT( offsetof(fd_txn_p_t, payload_sz     )+sizeof(((fd_txn_p_t*)NULL)->payload_sz    )<=1280UL, nt_memcpy );
      FD_STATIC_ASSERT( offsetof(fd_txn_p_t, blockhash_slot )+sizeof(((fd_txn_p_t*)NULL)->blockhash_slot)<=1280UL, nt_memcpy );
      FD_STATIC_ASSERT( offsetof(fd_txn_p_t, flags          )+sizeof(((fd_txn_p_t*)NULL)->flags         )<=1280UL, nt_memcpy );
      FD_STATIC_ASSERT( offsetof(fd_txn_p_t, scheduler_arrival_time_nanos )+sizeof(((fd_txn_p_t*)NULL)->scheduler_arrival_time_nanos )<=1280UL, nt_memcpy );
      FD_STATIC_ASSERT( offsetof(fd_txn_p_t, _              )                                            <=1280UL, nt_memcpy );
      const ulong offset_into_txn = 1280UL - offsetof(fd_txn_p_t, _ );
      fd_memcpy( offset_into_txn+(uchar *)TXN(out), offset_into_txn+(uchar const *)txn,
          fd_ulong_max( offset_into_txn, fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt ) )-offset_into_txn );
#endif
    } else {
      fd_memcpy( out->payload, cur->txn->payload, cur->txn->payload_sz                                           );
      fd_memcpy( TXN(out),     txn,               fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt ) );
      out->payload_sz                      = cur->txn->payload_sz;
      out->pack_cu.requested_exec_plus_acct_data_cus = cur->txn->pack_cu.requested_exec_plus_acct_data_cus;
      out->pack_cu.non_execution_cus       = cur->txn->pack_cu.non_execution_cus;
      out->flags                           = cur->txn->flags;
      out->scheduler_arrival_time_nanos    = cur->txn->scheduler_arrival_time_nanos;
    }
    out++;

    for( fd_txn_acct_iter_t iter=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE );
        iter!=fd_txn_acct_iter_end(); iter=fd_txn_acct_iter_next( iter ) ) {
      fd_acct_addr_t acct_addr = *ACCT_ITER_TO_PTR( iter );

      fd_pack_addr_use_t * in_wcost_table = acct_uses_query( writer_costs, acct_addr, NULL );
      if( !in_wcost_table ) {
        in_wcost_table = acct_uses_insert( writer_costs, acct_addr );
        in_wcost_table->total_cost = 0UL;
        written_list[ written_list_cnt ] = in_wcost_table;
        written_list_cnt = fd_ulong_min( written_list_cnt+1UL, written_list_max-1UL );
      }
      in_wcost_table->total_cost += cur->compute_est;

      fd_pack_addr_use_t * use = acct_uses_insert( acct_in_use, acct_addr );
      use->in_use_by = bank_tile_mask | FD_PACK_IN_USE_WRITABLE;

      use_by_bank[use_by_bank_cnt++] = *use;

      /* If there aren't any more references to this account in the
         heap, it can't cause any conflicts.  That means we actually
         don't need to record that we are using it, which is good
         because we want to release the bit. */
      release_result_t ret = release_bit_reference( pack, &acct_addr );
      FD_PACK_BITSET_CLEARN( bitset_rw_in_use, ret.clear_rw_bit );
      FD_PACK_BITSET_CLEARN( bitset_w_in_use,  ret.clear_w_bit  );
    }
    for( fd_txn_acct_iter_t iter=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_READONLY );
        iter!=fd_txn_acct_iter_end(); iter=fd_txn_acct_iter_next( iter ) ) {

      fd_acct_addr_t acct_addr = *ACCT_ITER_TO_PTR( iter );

      if( fd_pack_unwritable_contains( &acct_addr ) ) continue; /* No need to track sysvars because they can't be writable */

      fd_pack_addr_use_t * use = acct_uses_query( acct_in_use,  acct_addr, NULL );
      if( !use ) { use = acct_uses_insert( acct_in_use, acct_addr ); use->in_use_by = 0UL; }

      if( !(use->in_use_by & bank_tile_mask) ) use_by_bank[use_by_bank_cnt++] = *use;
      use->in_use_by |= bank_tile_mask;
      use->in_use_by &= ~FD_PACK_IN_USE_BIT_CLEARED;


      release_result_t ret = release_bit_reference( pack, &acct_addr );
      FD_PACK_BITSET_CLEARN( bitset_rw_in_use, ret.clear_rw_bit );
      FD_PACK_BITSET_CLEARN( bitset_w_in_use,  ret.clear_w_bit  );
    }

    txns_scheduled  += 1UL;                      txn_limit       -= 1UL;
    cus_scheduled   += cur->compute_est;         cu_limit        -= cur->compute_est;
    bytes_scheduled += cur->txn->payload_sz;     byte_limit      -= cur->txn->payload_sz;

    *(use_by_bank_txn++) = use_by_bank_cnt;

    if( FD_UNLIKELY( cur->txn->flags & FD_TXN_P_FLAGS_DURABLE_NONCE ) ) noncemap_ele_remove_fast( pack->noncemap, cur, pack->pool );
    sig2txn_ele_remove_fast( pack->signature_map, cur, pool );

    cur->root = FD_ORD_TXN_ROOT_FREE;
    expq_remove( pack->expiration_q, cur->expq_idx );
    treap_idx_remove( sched_from, _cur, pool );
    trp_pool_idx_release( pool, _cur );
    pack->pending_txn_cnt--;

    if( FD_UNLIKELY( (cu_limit<smallest_in_treap->cus) | (txn_limit==0UL) | (byte_limit<smallest_in_treap->bytes) ) ) break;
  }

  FD_MCNT_INC( PACK, TRANSACTION_SCHEDULE_TAKEN,      txns_scheduled );
  FD_MCNT_INC( PACK, TRANSACTION_SCHEDULE_CU_LIMIT,   cu_limit_c     );
  FD_MCNT_INC( PACK, TRANSACTION_SCHEDULE_FAST_PATH,  fast_path      );
  FD_MCNT_INC( PACK, TRANSACTION_SCHEDULE_BYTE_LIMIT, byte_limit_c   );
  FD_MCNT_INC( PACK, TRANSACTION_SCHEDULE_WRITE_COST, write_limit_c  );
  FD_MCNT_INC( PACK, TRANSACTION_SCHEDULE_SLOW_PATH,  slow_path      );
  FD_MCNT_INC( PACK, TRANSACTION_SCHEDULE_DEFER_SKIP, skip_c         );

  /* If we scanned the whole treap and didn't break early, we now have a
     better estimate of the smallest. */
  if( FD_UNLIKELY( treap_rev_iter_done( prev ) ) ) {
    smallest_in_treap->cus   = min_cus;
    smallest_in_treap->bytes = min_bytes;
  }

  pack->use_by_bank_cnt[bank_tile] = use_by_bank_cnt;
  FD_PACK_BITSET_COPY( pack->bitset_rw_in_use, bitset_rw_in_use );
  FD_PACK_BITSET_COPY( pack->bitset_w_in_use,  bitset_w_in_use  );

  pack->written_list_cnt = written_list_cnt;

  sched_return_t to_return = { .cus_scheduled=cus_scheduled, .txns_scheduled=txns_scheduled, .bytes_scheduled=bytes_scheduled };
  return to_return;
}

int
fd_pack_microblock_complete( fd_pack_t * pack,
                             ulong       bank_tile ) {
  /* If the account is in use writably, and it's in use by this banking
     tile, then this banking tile must be the sole writer to it, so it's
     always okay to clear the writable bit. */
  ulong clear_mask = ~((1UL<<bank_tile) | FD_PACK_IN_USE_WRITABLE);

  /* If nothing outstanding, bail quickly */
  if( FD_UNLIKELY( !(pack->outstanding_microblock_mask & (1UL<<bank_tile)) ) ) return 0;

  FD_PACK_BITSET_DECLARE( bitset_rw_in_use );
  FD_PACK_BITSET_DECLARE( bitset_w_in_use  );
  FD_PACK_BITSET_COPY( bitset_rw_in_use, pack->bitset_rw_in_use );
  FD_PACK_BITSET_COPY( bitset_w_in_use,  pack->bitset_w_in_use  );

  fd_pack_addr_use_t * base = pack->use_by_bank[bank_tile];

  fd_pack_ord_txn_t       * best         = NULL;
  fd_pack_penalty_treap_t * best_penalty = NULL;
  ulong                     txn_cnt      = 0UL;

  for( ulong i=0UL; i<pack->use_by_bank_cnt[bank_tile]; i++ ) {
    fd_pack_addr_use_t * use = acct_uses_query( pack->acct_in_use, base[i].key, NULL );
    FD_TEST( use );
    use->in_use_by &= clear_mask;

    /* In order to properly bound the size of bitset_map, we need to
       release the "reference" to the account when we schedule it.
       However, that poses a bit of a problem here, because by the time
       we complete the microblock, that account could have been assigned
       a different bit in the bitset.  The scheduling step tells us if
       that is the case, and if so, we know that the bits in
       bitset_w_in_use and bitset_rw_in_use were already cleared as
       necessary.

       Note that it's possible for BIT_CLEARED to be set and then unset
       by later uses, but then the account would be in use on other
       banks, so we wouldn't try to observe the old value.  For example:
       Suppose bit 0->account A, bit 1->account B, and we have two
       transactions that read A, B.  We schedule a microblock to bank 0,
       taking both transactions, which sets the counts for A, B to 0,
       and releases the bits, clearing bits 0 and 1, and setting
       BIT_CLEARED.  Then we get two more transactions that read
       accounts C, D, A, B, and they get assigned 0->C, 1->D, 2->A,
       3->B.  We try to schedule a microblock to bank 1 that takes one
       of those transactions.  This unsets BIT_CLEARED for A, B.
       Finally, the first microblock completes.  Even though the bitset
       map has the new bits for A and B which are "wrong" compared to
       when the transaction was initially scheduled, those bits have
       already been cleared and reset properly in the bitset as needed.
       A and B will still be in use by bank 1, so we won't clear any
       bits.  If, on the other hand, the microblock scheduled to bank 1
       completes first, bits 0 and 1 will be cleared for accounts C and
       D, while bits 2 and 3 will remain set, which is correct.  Then
       when bank 0 completes, bits 2 and 3 will be cleared. */
    if( FD_LIKELY( !use->in_use_by ) ) { /* if in_use_by==0, doesn't include BIT_CLEARED */
      fd_pack_bitset_acct_mapping_t * q = bitset_map_query( pack->acct_to_bitset, base[i].key, NULL );
      FD_TEST( q );
      FD_PACK_BITSET_CLEARN( bitset_w_in_use,  q->bit );
      FD_PACK_BITSET_CLEARN( bitset_rw_in_use, q->bit );

      /* Because this account is no longer in use, it might be possible
         to schedule a transaction that writes to it.  Check its
         penalty treap if it has one, and potentially move it to the
         main treap. */
      fd_pack_penalty_treap_t * p_trp = penalty_map_query( pack->penalty_treaps, base[i].key, NULL );
      if( FD_UNLIKELY( p_trp ) ) {
        fd_pack_ord_txn_t * best_in_trp = treap_rev_iter_ele( treap_rev_iter_init( p_trp->penalty_treap, pack->pool ), pack->pool );
        if( FD_UNLIKELY( !best || COMPARE_WORSE( best, best_in_trp ) ) ) {
          best         = best_in_trp;
          best_penalty = p_trp;
        }
      }
    }

    if( FD_LIKELY( !(use->in_use_by & ~FD_PACK_IN_USE_BIT_CLEARED) ) ) acct_uses_remove( pack->acct_in_use, use );

    if( FD_UNLIKELY( i+1UL==pack->use_by_bank_txn[ bank_tile ][ txn_cnt ] ) ) {
      txn_cnt++;
      if( FD_LIKELY( best ) ) {
        /* move best to the main treap */
        treap_ele_remove( best_penalty->penalty_treap, best, pack->pool );
        best->root = FD_ORD_TXN_ROOT_PENDING;
        treap_ele_insert( pack->pending,               best, pack->pool );

        pack->pending_smallest->cus   = fd_ulong_min( pack->pending_smallest->cus,   best->compute_est             );
        pack->pending_smallest->bytes = fd_ulong_min( pack->pending_smallest->bytes, best->txn_e->txnp->payload_sz );

        if( FD_UNLIKELY( !treap_ele_cnt( best_penalty->penalty_treap ) ) ) {
          treap_delete( treap_leave( best_penalty->penalty_treap ) );
          /* Removal invalidates any pointers we got from
             penalty_map_query, but we immediately set these to NULL, so
             we're not keeping any pointers around. */
          penalty_map_remove( pack->penalty_treaps, best_penalty );
        }
        best         = NULL;
        best_penalty = NULL;
      }
    }
  }

  pack->use_by_bank_cnt[bank_tile] = 0UL;

  FD_PACK_BITSET_COPY( pack->bitset_rw_in_use, bitset_rw_in_use );
  FD_PACK_BITSET_COPY( pack->bitset_w_in_use,  bitset_w_in_use  );

  /* outstanding_microblock_mask never has the writable bit set, so we
     don't care about clearing it here either. */
  pack->outstanding_microblock_mask &= clear_mask;
  return 1;
}

#define TRY_BUNDLE_NO_READY_BUNDLES      0
#define TRY_BUNDLE_HAS_CONFLICTS       (-1)
#define TRY_BUNDLE_DOES_NOT_FIT        (-2)
#define TRY_BUNDLE_SUCCESS(n)          ( n) /* schedule bundle with n transactions */
static inline int
fd_pack_try_schedule_bundle( fd_pack_t  * pack,
                             ulong        bank_tile,
                             fd_txn_p_t * out ) {
  int state = pack->initializer_bundle_state;
  if( FD_UNLIKELY( (state==FD_PACK_IB_STATE_PENDING) | (state==FD_PACK_IB_STATE_FAILED ) ) ) return TRY_BUNDLE_NO_READY_BUNDLES;

  fd_pack_ord_txn_t * pool    = pack->pool;
  treap_t           * bundles = pack->pending_bundles;

  int require_ib;
  if( FD_UNLIKELY( state==FD_PACK_IB_STATE_NOT_INITIALIZED ) ) { require_ib = 1; }
  if( FD_LIKELY  ( state==FD_PACK_IB_STATE_READY           ) ) { require_ib = 0; }

  treap_rev_iter_t _cur  = treap_rev_iter_init( bundles, pool );
  ulong bundle_idx = ULONG_MAX;

  if( FD_UNLIKELY( treap_rev_iter_done( _cur ) ) ) return TRY_BUNDLE_NO_READY_BUNDLES;

  treap_rev_iter_t   _txn0 = _cur;
  fd_pack_ord_txn_t * txn0 = treap_rev_iter_ele( _txn0, pool );
  int is_ib = !!(txn0->txn->flags & FD_TXN_P_FLAGS_INITIALIZER_BUNDLE);
  bundle_idx = RC_TO_REL_BUNDLE_IDX( txn0->rewards, txn0->compute_est );

  if( FD_UNLIKELY( require_ib & !is_ib ) ) return TRY_BUNDLE_NO_READY_BUNDLES;

  /* At this point, we have our candidate bundle, so we'll schedule it
     if we can.  If we can't, we won't schedule anything. */


  fd_pack_addr_use_t * bundle_temp_inserted[ FD_PACK_MAX_TXN_PER_BUNDLE * FD_TXN_ACCT_ADDR_MAX ];
  ulong bundle_temp_inserted_cnt = 0UL;

  ulong bank_tile_mask = 1UL << bank_tile;

  int doesnt_fit   = 0;
  int has_conflict = 0;
  ulong txn_cnt = 0UL;

  ulong cu_limit         = pack->lim->max_cost_per_block        - pack->cumulative_block_cost;
  ulong byte_limit       = pack->lim->max_data_bytes_per_block  - pack->data_bytes_consumed;
  ulong microblock_limit = pack->lim->max_microblocks_per_block - pack->microblock_cnt;

  FD_PACK_BITSET_DECLARE( bitset_rw_in_use );
  FD_PACK_BITSET_DECLARE( bitset_w_in_use  );
  FD_PACK_BITSET_COPY( bitset_rw_in_use, pack->bitset_rw_in_use );
  FD_PACK_BITSET_COPY( bitset_w_in_use,  pack->bitset_w_in_use  );

  /* last_use_in_txn_cnt[i+1] Keeps track of the number of accounts that
     have their last reference in transaction i of the bundle.  This
     esoteric value is important for computing use_by_bank_txn.
     last_use_in_txn_cnt[0] is garbage. */
  ulong last_use_in_txn_cnt[ 1UL+FD_PACK_MAX_TXN_PER_BUNDLE ] = { 0UL };

  fd_pack_addr_use_t   null_use[1]    = {{{{ 0 }}, { 0 }}};

  while( !(doesnt_fit | has_conflict) & !treap_rev_iter_done( _cur ) ) {
    fd_pack_ord_txn_t * cur = treap_rev_iter_ele( _cur, pool );
    ulong this_bundle_idx = RC_TO_REL_BUNDLE_IDX( cur->rewards, cur->compute_est );
    if( FD_UNLIKELY( this_bundle_idx!=bundle_idx ) ) break;

    if( FD_UNLIKELY( cur->compute_est>cu_limit ) ) {
      doesnt_fit = 1;
      FD_MCNT_INC( PACK, TRANSACTION_SCHEDULE_CU_LIMIT,   1UL );
      break;
    }
    cu_limit -= cur->compute_est;

    /* Each transaction in a bundle turns into a microblock */
    if( FD_UNLIKELY( microblock_limit==0UL ) ) {
      doesnt_fit = 1;
      FD_MCNT_INC( PACK, MICROBLOCK_PER_BLOCK_LIMIT, 1UL );
      break;
    }
    microblock_limit--;

    if( FD_UNLIKELY( cur->txn->payload_sz+MICROBLOCK_DATA_OVERHEAD>byte_limit ) ) {
      doesnt_fit = 1;
      FD_MCNT_INC( PACK, TRANSACTION_SCHEDULE_BYTE_LIMIT, 1UL );
      break;
    }
    byte_limit -= cur->txn->payload_sz + MICROBLOCK_DATA_OVERHEAD;

    if( FD_UNLIKELY( !FD_PACK_BITSET_INTERSECT4_EMPTY( pack->bitset_rw_in_use, pack->bitset_w_in_use, cur->w_bitset, cur->rw_bitset ) ) ) {
      has_conflict = 1;
      FD_MCNT_INC( PACK, TRANSACTION_SCHEDULE_FAST_PATH,  1UL );
      break;
    }

    /* Don't update the actual in-use bitset, because the transactions
       in the bundle are allowed to conflict with each other. */
    FD_PACK_BITSET_OR( bitset_rw_in_use, cur->rw_bitset );
    FD_PACK_BITSET_OR( bitset_w_in_use,  cur->w_bitset  );


    fd_txn_t const * txn = TXN(cur->txn);
    fd_acct_addr_t const * accts   = fd_txn_get_acct_addrs( txn, cur->txn->payload );
    fd_acct_addr_t const * alt_adj = cur->txn_e->alt_accts - fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM );

    /* Check conflicts between this transaction's writable accounts and
       current readers */
    for( fd_txn_acct_iter_t iter=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE );
        iter!=fd_txn_acct_iter_end(); iter=fd_txn_acct_iter_next( iter ) ) {

      fd_acct_addr_t acct = *ACCT_ITER_TO_PTR( iter );

      fd_pack_addr_use_t * in_bundle_temp = acct_uses_query( pack->bundle_temp_map, acct, null_use );
      ulong current_cost                  = acct_uses_query( pack->writer_costs,    acct, null_use )->total_cost;
      ulong carried_cost                  = (ulong)in_bundle_temp->carried_cost;
      if( FD_UNLIKELY( current_cost + carried_cost + cur->compute_est > pack->lim->max_write_cost_per_acct ) ) {
        doesnt_fit = 1;
        FD_MCNT_INC( PACK, TRANSACTION_SCHEDULE_WRITE_COST, 1UL );
        break;
      }

      if( FD_LIKELY( in_bundle_temp==null_use ) ) { /* Not in temp bundle table yet */
        in_bundle_temp    = acct_uses_insert( pack->bundle_temp_map, acct );
        in_bundle_temp->_ = 0UL;
        bundle_temp_inserted[ bundle_temp_inserted_cnt++ ] = in_bundle_temp;
      }
      in_bundle_temp->carried_cost += (uint)cur->compute_est; /* < 2^21, but >0 */
      in_bundle_temp->ref_cnt++;
      last_use_in_txn_cnt[ in_bundle_temp->last_use_in ]--;
      in_bundle_temp->last_use_in = (ushort)(txn_cnt+1UL);
      last_use_in_txn_cnt[ in_bundle_temp->last_use_in ]++;

      if( FD_UNLIKELY( acct_uses_query( pack->acct_in_use, acct, null_use )->in_use_by ) ) {
        has_conflict = 1;
        FD_MCNT_INC( PACK, TRANSACTION_SCHEDULE_SLOW_PATH,  1UL );
        break;
      }
    }
    if( has_conflict | doesnt_fit ) break;

    /* Check conflicts between this transaction's readonly accounts and
       current writers */
    for( fd_txn_acct_iter_t iter=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_READONLY );
        iter!=fd_txn_acct_iter_end(); iter=fd_txn_acct_iter_next( iter ) ) {

      fd_acct_addr_t const * acct = ACCT_ITER_TO_PTR( iter );
      if( fd_pack_unwritable_contains( acct ) ) continue; /* No need to track sysvars because they can't be writable */

      fd_pack_addr_use_t * in_bundle_temp = acct_uses_query( pack->bundle_temp_map, *acct, null_use );
      if( FD_LIKELY( in_bundle_temp==null_use ) ) { /* Not in temp bundle table yet */
        in_bundle_temp = acct_uses_insert( pack->bundle_temp_map, *acct );
        in_bundle_temp->_ = 0UL;
        bundle_temp_inserted[ bundle_temp_inserted_cnt++ ] = in_bundle_temp;
      }
      in_bundle_temp->ref_cnt++;
      last_use_in_txn_cnt[ in_bundle_temp->last_use_in ]--;
      in_bundle_temp->last_use_in = (ushort)(txn_cnt+1UL);
      last_use_in_txn_cnt[ in_bundle_temp->last_use_in ]++;

      if( FD_UNLIKELY( acct_uses_query( pack->acct_in_use,  *acct, null_use )->in_use_by & FD_PACK_IN_USE_WRITABLE ) ) {
        has_conflict = 1;
        FD_MCNT_INC( PACK, TRANSACTION_SCHEDULE_SLOW_PATH,  1UL );
        break;
      }
    }

    if( has_conflict | doesnt_fit ) break;

    txn_cnt++;
    _cur = treap_rev_iter_next( _cur, pool );
  }
  int retval = fd_int_if( doesnt_fit, TRY_BUNDLE_DOES_NOT_FIT,
                                      fd_int_if( has_conflict, TRY_BUNDLE_HAS_CONFLICTS, TRY_BUNDLE_SUCCESS( (int)txn_cnt ) ) );

  if( FD_UNLIKELY( retval<=0 ) ) {
    for( ulong i=0UL; i<bundle_temp_inserted_cnt; i++ ) {
      acct_uses_remove( pack->bundle_temp_map, bundle_temp_inserted[ bundle_temp_inserted_cnt-i-1UL ] );
    }
    FD_TEST( acct_uses_key_cnt( pack->bundle_temp_map )==0UL );
    return retval;
  }

  /* This bundle passed validation, so now we'll take it! */
  pack->outstanding_microblock_mask |= bank_tile_mask;

  treap_rev_iter_t   _end  = _cur;
  treap_rev_iter_t   _next;

  /* We'll carefully incrementally construct use_by_bank and
     use_by_bank_txn based on the contents of bundle_temp and
     last_use_in_txn_cnt. */
  fd_pack_addr_use_t * use_by_bank     = pack->use_by_bank    [bank_tile];
  ulong              * use_by_bank_txn = pack->use_by_bank_txn[bank_tile];
  ulong cum_sum = 0UL;
  for( ulong k=0UL; k<txn_cnt; k++ ) { use_by_bank_txn[k] = cum_sum; cum_sum += last_use_in_txn_cnt[ k+1UL ]; }
  pack->use_by_bank_cnt[bank_tile] = cum_sum;


  for( _cur=_txn0; _cur!=_end; _cur=_next ) {
    _next = treap_rev_iter_next( _cur, pool );

    fd_pack_ord_txn_t * cur = treap_rev_iter_ele( _cur, pool );
    fd_txn_t const    * txn = TXN(cur->txn);
    fd_memcpy( out->payload, cur->txn->payload, cur->txn->payload_sz                                           );
    fd_memcpy( TXN(out),     txn,               fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt ) );
    out->payload_sz                      = cur->txn->payload_sz;
    out->pack_cu.requested_exec_plus_acct_data_cus = cur->txn->pack_cu.requested_exec_plus_acct_data_cus;
    out->pack_cu.non_execution_cus       = cur->txn->pack_cu.non_execution_cus;
    out->flags                           = cur->txn->flags;
    out->scheduler_arrival_time_nanos    = cur->txn->scheduler_arrival_time_nanos;
    out++;

    pack->cumulative_block_cost += cur->compute_est;
    pack->data_bytes_consumed   += cur->txn->payload_sz + MICROBLOCK_DATA_OVERHEAD;
    pack->microblock_cnt        += 1UL;

    if( FD_UNLIKELY( cur->txn->flags & FD_TXN_P_FLAGS_DURABLE_NONCE ) ) noncemap_ele_remove_fast( pack->noncemap, cur, pack->pool );
    sig2txn_ele_remove_fast( pack->signature_map, cur, pack->pool );

    cur->root = FD_ORD_TXN_ROOT_FREE;
    expq_remove( pack->expiration_q, cur->expq_idx );
    treap_idx_remove( pack->pending_bundles, _cur, pack->pool );
    trp_pool_idx_release( pack->pool, _cur );
    pack->pending_txn_cnt--;
  }


  for( ulong i=0UL; i<bundle_temp_inserted_cnt; i++ ) {
    /* In order to clear bundle_temp_map with the typical trick, we need
       to iterate through bundle_temp_inserted backwards. */
    fd_pack_addr_use_t * addr_use = bundle_temp_inserted[ bundle_temp_inserted_cnt-i-1UL ];

    int any_writers = addr_use->carried_cost>0U; /* Did any transaction in this bundle write lock this account address? */

    if( FD_LIKELY( any_writers ) ) { /* UNLIKELY? */
      fd_pack_addr_use_t * in_wcost_table = acct_uses_query( pack->writer_costs, addr_use->key, NULL );
      if( !in_wcost_table ) {
        in_wcost_table = acct_uses_insert( pack->writer_costs, addr_use->key );
        in_wcost_table->total_cost = 0UL;
        pack->written_list[ pack->written_list_cnt ] = in_wcost_table;
        pack->written_list_cnt = fd_ulong_min( pack->written_list_cnt+1UL, pack->written_list_max-1UL );
      }
      in_wcost_table->total_cost += (ulong)addr_use->carried_cost;
    }

    /* in_use_by must be set before releasing the bit reference */
    fd_pack_addr_use_t * use = acct_uses_query( pack->acct_in_use, addr_use->key, NULL );
    if( !use ) { use = acct_uses_insert( pack->acct_in_use, addr_use->key ); use->in_use_by = 0UL; }
    use->in_use_by |= bank_tile_mask | fd_ulong_if( any_writers, FD_PACK_IN_USE_WRITABLE, 0UL );
    use->in_use_by &= ~FD_PACK_IN_USE_BIT_CLEARED;

    use_by_bank[ use_by_bank_txn[ addr_use->last_use_in-1UL ]++ ] = *use;

    for( ulong k=0UL; k<(ulong)addr_use->ref_cnt; k++ ) {
      release_result_t ret = release_bit_reference( pack, &(addr_use->key) );
      FD_PACK_BITSET_CLEARN( bitset_rw_in_use, ret.clear_rw_bit );
      FD_PACK_BITSET_CLEARN( bitset_w_in_use,  ret.clear_w_bit  );
    }

    acct_uses_remove( pack->bundle_temp_map, addr_use );
  }

  FD_PACK_BITSET_COPY( pack->bitset_rw_in_use, bitset_rw_in_use );
  FD_PACK_BITSET_COPY( pack->bitset_w_in_use,  bitset_w_in_use  );

  if( FD_UNLIKELY( is_ib ) ) {
    pack->initializer_bundle_state = FD_PACK_IB_STATE_PENDING;
  }
  return retval;
}


ulong
fd_pack_schedule_next_microblock( fd_pack_t *  pack,
                                  ulong        total_cus,
                                  float        vote_fraction,
                                  ulong        bank_tile,
                                  int          schedule_flags,
                                  fd_txn_p_t * out ) {

  /* TODO: Decide if these are exactly how we want to handle limits */
  total_cus = fd_ulong_min( total_cus, pack->lim->max_cost_per_block - pack->cumulative_block_cost );
  ulong vote_cus = fd_ulong_min( (ulong)((float)total_cus * vote_fraction),
                                 pack->lim->max_vote_cost_per_block - pack->cumulative_vote_cost );
  ulong vote_reserved_txns = fd_ulong_min( vote_cus/FD_PACK_SIMPLE_VOTE_COST,
                                           (ulong)((float)pack->lim->max_txn_per_microblock * vote_fraction) );


  if( FD_UNLIKELY( (pack->microblock_cnt>=pack->lim->max_microblocks_per_block) ) ) {
    FD_MCNT_INC( PACK, MICROBLOCK_PER_BLOCK_LIMIT, 1UL );
    return 0UL;
  }
  if( FD_UNLIKELY( pack->data_bytes_consumed+MICROBLOCK_DATA_OVERHEAD+FD_TXN_MIN_SERIALIZED_SZ>pack->lim->max_data_bytes_per_block) ) {
    FD_MCNT_INC( PACK, DATA_PER_BLOCK_LIMIT, 1UL );
    return 0UL;
  }

  ulong * use_by_bank_txn = pack->use_by_bank_txn[ bank_tile ];

  ulong cu_limit  = total_cus - vote_cus;
  ulong txn_limit = pack->lim->max_txn_per_microblock - vote_reserved_txns;
  ulong scheduled = 0UL;
  ulong byte_limit = pack->lim->max_data_bytes_per_block - pack->data_bytes_consumed - MICROBLOCK_DATA_OVERHEAD;

  sched_return_t status = {0}, status1 = {0};

  if( FD_LIKELY( schedule_flags & FD_PACK_SCHEDULE_VOTE ) ) {
    /* Schedule vote transactions */
    status1= fd_pack_schedule_impl( pack, pack->pending_votes, vote_cus, vote_reserved_txns, byte_limit, bank_tile, pack->pending_votes_smallest, use_by_bank_txn, out+scheduled );

    scheduled                   += status1.txns_scheduled;
    pack->cumulative_vote_cost  += status1.cus_scheduled;
    pack->cumulative_block_cost += status1.cus_scheduled;
    pack->data_bytes_consumed   += status1.bytes_scheduled;
    byte_limit                  -= status1.bytes_scheduled;
    use_by_bank_txn             += status1.txns_scheduled;
    /* Add any remaining CUs/txns to the non-vote limits */
    txn_limit += vote_reserved_txns - status1.txns_scheduled;
    cu_limit  += vote_cus - status1.cus_scheduled;
  }

  /* Bundle can't mix with votes, so only try to schedule a bundle if we
     didn't get any votes. */
  if( FD_UNLIKELY( !!(schedule_flags & FD_PACK_SCHEDULE_BUNDLE) & (status1.txns_scheduled==0UL) ) ) {
    int bundle_result = fd_pack_try_schedule_bundle( pack, bank_tile, out );
    if( FD_UNLIKELY( bundle_result>0                         ) ) return (ulong)bundle_result;
    if( FD_UNLIKELY( bundle_result==TRY_BUNDLE_HAS_CONFLICTS ) ) return 0UL;
    /* in the NO_READY_BUNDLES or DOES_NOT_FIT case, we schedule like
       normal. */
    /* We have the early returns here because try_schedule_bundle does
       the bookeeping internally, since the calculations are a bit
       different in that case. */
  }


  /* Fill any remaining space with non-vote transactions */
  if( FD_LIKELY( schedule_flags & FD_PACK_SCHEDULE_TXN ) ) {
    status = fd_pack_schedule_impl( pack, pack->pending,       cu_limit, txn_limit,          byte_limit, bank_tile, pack->pending_smallest,       use_by_bank_txn, out+scheduled );

    scheduled                   += status.txns_scheduled;
    pack->cumulative_block_cost += status.cus_scheduled;
    pack->data_bytes_consumed   += status.bytes_scheduled;
  }

  ulong nonempty = (ulong)(scheduled>0UL);
  pack->microblock_cnt              += nonempty;
  pack->outstanding_microblock_mask |= nonempty << bank_tile;
  pack->data_bytes_consumed         += nonempty * MICROBLOCK_DATA_OVERHEAD;

  /* Update metrics counters */
  fd_pack_metrics_write( pack );
  FD_MGAUGE_SET( PACK, CUS_CONSUMED_IN_BLOCK,         pack->cumulative_block_cost          );

  fd_histf_sample( pack->txn_per_microblock,  scheduled              );
  fd_histf_sample( pack->vote_per_microblock, status1.txns_scheduled );

#if FD_HAS_AVX512 && FD_PACK_USE_NON_TEMPORAL_MEMCPY
  _mm_sfence();
#endif

  return scheduled;
}

ulong fd_pack_bank_tile_cnt     ( fd_pack_t const * pack ) { return pack->bank_tile_cnt;         }
ulong fd_pack_current_block_cost( fd_pack_t const * pack ) { return pack->cumulative_block_cost; }


void
fd_pack_set_block_limits( fd_pack_t * pack, fd_pack_limits_t const * limits ) {
  FD_TEST( limits->max_cost_per_block      >= FD_PACK_MAX_COST_PER_BLOCK_LOWER_BOUND      );
  FD_TEST( limits->max_vote_cost_per_block >= FD_PACK_MAX_VOTE_COST_PER_BLOCK_LOWER_BOUND );
  FD_TEST( limits->max_write_cost_per_acct >= FD_PACK_MAX_WRITE_COST_PER_ACCT_LOWER_BOUND );

  pack->lim->max_microblocks_per_block = limits->max_microblocks_per_block;
  pack->lim->max_data_bytes_per_block  = limits->max_data_bytes_per_block;
  pack->lim->max_cost_per_block        = limits->max_cost_per_block;
  pack->lim->max_vote_cost_per_block   = limits->max_vote_cost_per_block;
  pack->lim->max_write_cost_per_acct   = limits->max_write_cost_per_acct;
}

void
fd_pack_rebate_cus( fd_pack_t              * pack,
                    fd_pack_rebate_t const * rebate ) {
  if( FD_UNLIKELY( (rebate->ib_result!=0) & (pack->initializer_bundle_state==FD_PACK_IB_STATE_PENDING ) ) ) {
    pack->initializer_bundle_state = fd_int_if( rebate->ib_result==1, FD_PACK_IB_STATE_READY, FD_PACK_IB_STATE_FAILED );
  }

  pack->cumulative_block_cost  -= rebate->total_cost_rebate;
  pack->cumulative_vote_cost   -= rebate->vote_cost_rebate;
  pack->data_bytes_consumed    -= rebate->data_bytes_rebate;
  pack->cumulative_rebated_cus += rebate->total_cost_rebate;
  /* For now, we want to ignore the microblock count rebate.  There are
     3 places the microblock count is kept (here, in the pack tile, and
     in the PoH tile), and they all need to count microblocks that end
     up being empty in the same way.  It would be better from a
     DoS-resistance perspective for them all not to count empty
     microblocks towards the total, but there's a race condition:
     suppose pack schedules a microblock containing one transaction that
     doesn't land on chain, the slot ends, and then pack informs PoH of
     the number of microblocks before the final rebate comes through.
     This isn't unsolvable, but it's pretty gross, so it's probably
     better to just not apply the rebate for now. */
  (void)rebate->microblock_cnt_rebate;

  fd_pack_addr_use_t * writer_costs = pack->writer_costs;
  for( ulong i=0UL; i<rebate->writer_cnt; i++ ) {
    fd_pack_addr_use_t * in_wcost_table = acct_uses_query( writer_costs, rebate->writer_rebates[i].key, NULL );
    if( FD_UNLIKELY( !in_wcost_table ) ) FD_LOG_ERR(( "Rebate to unknown written account" ));
    in_wcost_table->total_cost -= rebate->writer_rebates[i].rebate_cus;
    /* Important: Even if this is 0, don't delete it from the table so
       that the insert order doesn't get messed up. */
  }
}


ulong
fd_pack_expire_before( fd_pack_t * pack,
                       ulong       expire_before ) {
  expire_before = fd_ulong_max( expire_before, pack->expire_before );
  ulong deleted_cnt = 0UL;
  fd_pack_expq_t * prq = pack->expiration_q;
  while( (expq_cnt( prq )>0UL) & (prq->expires_at<expire_before) ) {
    fd_pack_ord_txn_t * expired = prq->txn;

    /* fd_pack_delete_transaction also removes it from the heap */
    /* All the transactions in the same bundle have the same expiration
       time, so this loop will end up deleting them all, even with
       delete_full_bundle set to 0. */
    ulong _delete_cnt = delete_transaction( pack, expired, 0, 1 );
    deleted_cnt += _delete_cnt;
    FD_TEST( _delete_cnt );
  }

  pack->expire_before = expire_before;
  return deleted_cnt;
}

void
fd_pack_end_block( fd_pack_t * pack ) {
  /* rounded division */
  ulong pct_cus_per_block = (pack->cumulative_block_cost*100UL + (pack->lim->max_cost_per_block>>1))/pack->lim->max_cost_per_block;
  fd_histf_sample( pack->pct_cus_per_block,       pct_cus_per_block                                          );
  fd_histf_sample( pack->net_cus_per_block,       pack->cumulative_block_cost                                );
  fd_histf_sample( pack->rebated_cus_per_block,   pack->cumulative_rebated_cus                               );
  fd_histf_sample( pack->scheduled_cus_per_block, pack->cumulative_rebated_cus + pack->cumulative_block_cost );

  pack->microblock_cnt              = 0UL;
  pack->data_bytes_consumed         = 0UL;
  pack->cumulative_block_cost       = 0UL;
  pack->cumulative_vote_cost        = 0UL;
  pack->cumulative_rebated_cus      = 0UL;
  pack->outstanding_microblock_mask = 0UL;

  pack->initializer_bundle_state = FD_PACK_IB_STATE_NOT_INITIALIZED;

  acct_uses_clear( pack->acct_in_use  );

  if( FD_LIKELY( pack->written_list_cnt<pack->written_list_max-1UL ) ) {
    /* The less dangerous way of doing this is to instead record the
       keys we inserted and do a query followed by a delete for each
       key.  The downside of that is that keys are 32 bytes and a
       pointer is only 8 bytes, plus the computational cost for the
       query.

       However, if we're careful, we can pull this off.  We require two
       things.  First, we started from an empty map and did nothing but
       insert and update.  In particular, no deletions.  Second, we have
       to be careful to delete in the opposite order that we inserted.
       This is essentially like unwinding the inserts we did.  The
       common case is that the element after the one we delete will be
       empty, so we'll hit that case.  It's possible that there's
       another independent probe sequence that will be entirely intact
       starting in the element after, but we'll never hit the MAP_MOVE
       case. */
    for( ulong i=0UL; i<pack->written_list_cnt; i++ ) {
      /* Clearing the cost field here is unnecessary (since it gets
         cleared on insert), but makes debugging a bit easier. */
      pack->written_list[ pack->written_list_cnt - 1UL - i ]->total_cost = 0UL;
      acct_uses_remove( pack->writer_costs, pack->written_list[ pack->written_list_cnt - 1UL - i ] );
    }
  } else {
    acct_uses_clear( pack->writer_costs );
  }
  pack->written_list_cnt = 0UL;

  /* compressed_slot_number is > FD_PACK_SKIP_CNT, which means +1 is the
     max unless it overflows. */
  pack->compressed_slot_number = fd_ushort_max( (ushort)(pack->compressed_slot_number+1), (ushort)(FD_PACK_SKIP_CNT+1) );

  FD_PACK_BITSET_CLEAR( pack->bitset_rw_in_use );
  FD_PACK_BITSET_CLEAR( pack->bitset_w_in_use  );

  for( ulong i=0UL; i<pack->bank_tile_cnt; i++ ) pack->use_by_bank_cnt[i] = 0UL;

  /* If our stake is low and we don't become leader often, end_block
     might get called on the order of O(1/hr), which feels too
     infrequent to do anything related to metrics.  However, we only
     update the histograms when we are leader, so this is actually a
     good place to copy them. */
  FD_MHIST_COPY( PACK, TOTAL_TRANSACTIONS_PER_MICROBLOCK_COUNT, pack->txn_per_microblock  );
  FD_MHIST_COPY( PACK, VOTES_PER_MICROBLOCK_COUNT,              pack->vote_per_microblock );

  FD_MGAUGE_SET( PACK, CUS_CONSUMED_IN_BLOCK, 0UL                           );
  FD_MHIST_COPY( PACK, CUS_SCHEDULED,         pack->scheduled_cus_per_block );
  FD_MHIST_COPY( PACK, CUS_REBATED,           pack->rebated_cus_per_block   );
  FD_MHIST_COPY( PACK, CUS_NET,               pack->net_cus_per_block       );
  FD_MHIST_COPY( PACK, CUS_PCT,               pack->pct_cus_per_block       );
}

static void
release_tree( treap_t           * treap,
              sig2txn_t         * signature_map,
              noncemap_t        * noncemap,
              fd_pack_ord_txn_t * pool ) {
  treap_fwd_iter_t next;
  for( treap_fwd_iter_t it=treap_fwd_iter_init( treap, pool ); !treap_fwd_iter_done( it ); it=next ) {
    next = treap_fwd_iter_next( it, pool );
    ulong idx = treap_fwd_iter_idx( it );
    pool[ idx ].root = FD_ORD_TXN_ROOT_FREE;
    treap_idx_remove       ( treap,         idx, pool );
    sig2txn_idx_remove_fast( signature_map, idx, pool );
    trp_pool_idx_release   ( pool,          idx       );
    if( pool[ idx ].txn->flags & FD_TXN_P_FLAGS_DURABLE_NONCE ) {
      noncemap_idx_remove_fast( noncemap, idx, pool );
    }
  }
}

void
fd_pack_clear_all( fd_pack_t * pack ) {
  pack->pending_txn_cnt        = 0UL;
  pack->microblock_cnt         = 0UL;
  pack->cumulative_block_cost  = 0UL;
  pack->cumulative_vote_cost   = 0UL;
  pack->cumulative_rebated_cus = 0UL;

  pack->pending_smallest->cus         = ULONG_MAX;
  pack->pending_smallest->bytes       = ULONG_MAX;
  pack->pending_votes_smallest->cus   = ULONG_MAX;
  pack->pending_votes_smallest->bytes = ULONG_MAX;

  release_tree( pack->pending,         pack->signature_map, pack->noncemap, pack->pool );
  release_tree( pack->pending_votes,   pack->signature_map, pack->noncemap, pack->pool );
  release_tree( pack->pending_bundles, pack->signature_map, pack->noncemap, pack->pool );

  ulong const pool_max = trp_pool_max( pack->pool );
  for( ulong i=0UL; i<pool_max; i++ ) {
    if( FD_UNLIKELY( pack->pool[ i ].root!=FD_ORD_TXN_ROOT_FREE ) ) {
      fd_pack_ord_txn_t * const del = pack->pool + i;
      fd_txn_t * txn = TXN( del->txn );
      fd_acct_addr_t const * accts   = fd_txn_get_acct_addrs( txn, del->txn->payload );
      fd_acct_addr_t const * alt_adj = del->txn_e->alt_accts - fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM );
      fd_acct_addr_t penalty_acct = *ACCT_IDX_TO_PTR( FD_ORD_TXN_ROOT_PENALTY_ACCT_IDX( del->root ) );
      fd_pack_penalty_treap_t * penalty_treap = penalty_map_query( pack->penalty_treaps, penalty_acct, NULL );
      FD_TEST( penalty_treap );
      release_tree( penalty_treap->penalty_treap, pack->signature_map, pack->noncemap, pack->pool );
    }
  }

  pack->compressed_slot_number = (ushort)(FD_PACK_SKIP_CNT+1);

  expq_remove_all( pack->expiration_q );

  acct_uses_clear( pack->acct_in_use  );
  acct_uses_clear( pack->writer_costs );

  penalty_map_clear( pack->penalty_treaps );

  FD_PACK_BITSET_CLEAR( pack->bitset_rw_in_use );
  FD_PACK_BITSET_CLEAR( pack->bitset_w_in_use  );
  bitset_map_clear( pack->acct_to_bitset );
  pack->bitset_avail[ 0 ] = FD_PACK_BITSET_SLOWPATH;
  for( ulong i=0UL; i<FD_PACK_BITSET_MAX; i++ ) pack->bitset_avail[ i+1UL ] = (ushort)i;
  pack->bitset_avail_cnt = FD_PACK_BITSET_MAX;

  for( ulong i=0UL; i<pack->bank_tile_cnt; i++ ) pack->use_by_bank_cnt[i] = 0UL;
}


/* If delete_full_bundle is non-zero and the transaction to delete is
   part of a bundle, the rest of the bundle it is part of will be
   deleted as well.
   If move_from_penalty_treap is non-zero and the transaction to delete
   is in the pending treap, move the best transaction in any of the
   conflicting penalty treaps to the pending treap (if there is one). */
static ulong
delete_transaction( fd_pack_t         * pack,
                    fd_pack_ord_txn_t * containing,
                    int                 delete_full_bundle,
                    int                 move_from_penalty_treap ) {

  fd_txn_t * txn = TXN( containing->txn );
  fd_acct_addr_t const * accts   = fd_txn_get_acct_addrs( txn, containing->txn->payload );
  fd_acct_addr_t const * alt_adj = containing->txn_e->alt_accts - fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM );

  treap_t * root = NULL;
  int root_idx = containing->root;
  fd_pack_penalty_treap_t * penalty_treap = NULL;
  switch( root_idx & FD_ORD_TXN_ROOT_TAG_MASK ) {
    case FD_ORD_TXN_ROOT_FREE:           FD_LOG_CRIT(( "Double free detected" ));
    case FD_ORD_TXN_ROOT_PENDING:        root = pack->pending;         break;
    case FD_ORD_TXN_ROOT_PENDING_VOTE:   root = pack->pending_votes;   break;
    case FD_ORD_TXN_ROOT_PENDING_BUNDLE: root = pack->pending_bundles; break;
    case FD_ORD_TXN_ROOT_PENALTY( 0 ): {
      fd_acct_addr_t penalty_acct = *ACCT_IDX_TO_PTR( FD_ORD_TXN_ROOT_PENALTY_ACCT_IDX( root_idx ) );
      penalty_treap = penalty_map_query( pack->penalty_treaps, penalty_acct, NULL );
      FD_TEST( penalty_treap );
      root = penalty_treap->penalty_treap;
      break;
    }
  }

  ulong delete_cnt = 0UL;
  if( FD_UNLIKELY( delete_full_bundle & (root==pack->pending_bundles) ) ) {
    /* When we delete, the structure of the treap may move around, but
       pointers to inside the pool will remain valid */
    fd_pack_ord_txn_t * bundle_ptrs[ FD_PACK_MAX_TXN_PER_BUNDLE-1UL ];
    fd_pack_ord_txn_t * pool       = pack->pool;
    ulong               cnt        = 0UL;
    ulong               bundle_idx = RC_TO_REL_BUNDLE_IDX( containing->rewards, containing->compute_est );

    /* Iterate in both directions from the current transaction */
    for( treap_fwd_iter_t _cur=treap_fwd_iter_next( (treap_fwd_iter_t)treap_idx_fast( containing, pool ), pool );
        !treap_fwd_iter_done( _cur ); _cur=treap_fwd_iter_next( _cur, pool ) ) {
      fd_pack_ord_txn_t * cur = treap_fwd_iter_ele( _cur, pool );
      if( FD_LIKELY( bundle_idx==RC_TO_REL_BUNDLE_IDX( cur->rewards, cur->compute_est ) ) ) {
        bundle_ptrs[ cnt++ ] = cur;
      } else {
        break;
      }
      FD_TEST( cnt<FD_PACK_MAX_TXN_PER_BUNDLE );
    }

    for( treap_rev_iter_t _cur=treap_rev_iter_next( (treap_rev_iter_t)treap_idx_fast( containing, pool ), pool );
        !treap_rev_iter_done( _cur ); _cur=treap_rev_iter_next( _cur, pool ) ) {
      fd_pack_ord_txn_t * cur = treap_rev_iter_ele( _cur, pool );
      if( FD_LIKELY( bundle_idx==RC_TO_REL_BUNDLE_IDX( cur->rewards, cur->compute_est ) ) ) {
        bundle_ptrs[ cnt++ ] = cur;
      } else {
        break;
      }
      FD_TEST( cnt<FD_PACK_MAX_TXN_PER_BUNDLE );
    }

    /* Delete them each, setting delete_full_bundle to 0 to avoid
       infinite recursion. */
    for( ulong k=0UL; k<cnt; k++ ) delete_cnt += delete_transaction( pack, bundle_ptrs[ k ], 0, 0 );
  }


  if( FD_UNLIKELY( move_from_penalty_treap & (root==pack->pending) ) ) {

    fd_pack_ord_txn_t       * best         = NULL;
    fd_pack_penalty_treap_t * best_penalty = NULL;

    for( fd_txn_acct_iter_t iter=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE );
        iter!=fd_txn_acct_iter_end(); iter=fd_txn_acct_iter_next( iter ) ) {
      fd_pack_penalty_treap_t * p_trp = penalty_map_query( pack->penalty_treaps, *ACCT_ITER_TO_PTR( iter ), NULL );
      if( FD_UNLIKELY( p_trp ) ) {
        fd_pack_ord_txn_t * best_in_trp = treap_rev_iter_ele( treap_rev_iter_init( p_trp->penalty_treap, pack->pool ), pack->pool );
        if( FD_UNLIKELY( !best || COMPARE_WORSE( best, best_in_trp ) ) ) {
          best         = best_in_trp;
          best_penalty = p_trp;
        }
      }
    }

    if( FD_LIKELY( best ) ) {
      /* move best to the main treap */
      treap_ele_remove( best_penalty->penalty_treap, best, pack->pool );
      best->root = FD_ORD_TXN_ROOT_PENDING;
      treap_ele_insert( pack->pending,               best, pack->pool );

      pack->pending_smallest->cus   = fd_ulong_min( pack->pending_smallest->cus,   best->compute_est             );
      pack->pending_smallest->bytes = fd_ulong_min( pack->pending_smallest->bytes, best->txn_e->txnp->payload_sz );

      if( FD_UNLIKELY( !treap_ele_cnt( best_penalty->penalty_treap ) ) ) {
        treap_delete( treap_leave( best_penalty->penalty_treap ) );
        penalty_map_remove( pack->penalty_treaps, best_penalty );
      }
    }
  }

  for( fd_txn_acct_iter_t iter=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_ALL );
      iter!=fd_txn_acct_iter_end(); iter=fd_txn_acct_iter_next( iter ) ) {
    if( FD_UNLIKELY( fd_pack_unwritable_contains( ACCT_ITER_TO_PTR( iter ) ) ) ) continue;

    release_result_t ret = release_bit_reference( pack, ACCT_ITER_TO_PTR( iter ) );
    FD_PACK_BITSET_CLEARN( pack->bitset_rw_in_use, ret.clear_rw_bit );
    FD_PACK_BITSET_CLEARN( pack->bitset_w_in_use,  ret.clear_w_bit  );
  }

  if( FD_UNLIKELY( containing->txn->flags & FD_TXN_P_FLAGS_DURABLE_NONCE ) ) {
    noncemap_ele_remove_fast( pack->noncemap, containing, pack->pool );
  }
  expq_remove( pack->expiration_q, containing->expq_idx );
  containing->root = FD_ORD_TXN_ROOT_FREE;
  treap_ele_remove( root, containing, pack->pool );
  sig2txn_ele_remove_fast( pack->signature_map, containing, pack->pool );
  trp_pool_ele_release( pack->pool, containing );

  delete_cnt += 1UL;
  pack->pending_txn_cnt--;

  if( FD_UNLIKELY( penalty_treap && treap_ele_cnt( root )==0UL ) ) {
    penalty_map_remove( pack->penalty_treaps, penalty_treap );
  }

  return delete_cnt;
}

ulong
fd_pack_delete_transaction( fd_pack_t              * pack,
                            fd_ed25519_sig_t const * sig0 ) {
  ulong cnt = 0;
  ulong next = ULONG_MAX;
  for( ulong idx = sig2txn_idx_query_const( pack->signature_map, (wrapped_sig_t const *)sig0, ULONG_MAX, pack->pool );
      idx!=ULONG_MAX; idx=next ) {
    /* Iterating while deleting, not just this element, but perhaps the
       whole bundle, feels a bit dangerous, but is actually fine because
       a bundle can't contain two transactions with the same signature.
       That means we know next is not part of the same bundle as idx,
       which means that deleting idx will not delete next. */
    next = sig2txn_idx_next_const( idx, ULONG_MAX, pack->pool );
    cnt += delete_transaction( pack, pack->pool+idx, 1, 1 );
  }

  return cnt;
}


int
fd_pack_verify( fd_pack_t * pack,
                void      * scratch ) {
  /* Invariants:
     sig2txn_query has exact same contents as all treaps combined
     root matches treap
     Keys of acct_to_bitset is exactly union of all accounts in all
            transactions in treaps, with ref counted appropriately
     bits in bitset_avail is complement of bits allocated in
            acct_to_bitset
     expires_at consistent between treap, prq
     use_by_bank does not contain duplicates
     use_by_bank consistent with acct_in_use
     elements in pool but not in a treap have root set to free
     all penalty treaps have at least one transaction
     all elements in penalty treaps are in the one that the root indicates
     */

  /* TODO:
     bitset_{r}w_in_use = bitset_map_query( everything in acct_in_use that doesn't have FD_PACK_IN_USE_BIT_CLEARED )
     bitset_w_in_use & bitset_rw_in_use == bitset_w_in_use
     */
#define VERIFY_TEST( cond, ... ) do {   \
    if( FD_UNLIKELY( !(cond) ) ) {      \
      FD_LOG_WARNING(( __VA_ARGS__ ));  \
      return -(__LINE__);               \
    }                                   \
  } while( 0 )

  ulong max_acct_in_treap  = pack->pack_depth * FD_TXN_ACCT_ADDR_MAX;
  int lg_acct_in_trp = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_acct_in_treap  ) );
  void * _bitset_map_copy = scratch;
  void * _bitset_map_orig = bitset_map_leave( pack->acct_to_bitset );
  fd_memcpy( _bitset_map_copy, _bitset_map_orig, bitset_map_footprint( lg_acct_in_trp ) );

  fd_pack_bitset_acct_mapping_t * bitset_copy = bitset_map_join( _bitset_map_copy );

  /* Check that each bit is in exactly one place */
  FD_PACK_BITSET_DECLARE( processed ); FD_PACK_BITSET_CLEAR( processed );
  FD_PACK_BITSET_DECLARE( bit       ); FD_PACK_BITSET_CLEAR( bit       );
  FD_PACK_BITSET_DECLARE( full      ); FD_PACK_BITSET_CLEAR( full      );

  if( FD_UNLIKELY( pack->bitset_avail[0]!=FD_PACK_BITSET_SLOWPATH ) ) return -1;
  for( ulong i=1UL; i<=pack->bitset_avail_cnt; i++ ) {
    FD_PACK_BITSET_CLEAR( bit );
    FD_PACK_BITSET_SETN( bit, pack->bitset_avail[ i ] );
    VERIFY_TEST( FD_PACK_BITSET_INTERSECT4_EMPTY( bit, bit, processed, processed ),
        "bit %hu in avail set twice", pack->bitset_avail[ i ] );
    FD_PACK_BITSET_OR( processed, bit );
  }

  ulong total_references = 0UL;
  for( ulong i=0UL; i<bitset_map_slot_cnt( bitset_copy ); i++ ) {
    if( !bitset_map_key_inval( bitset_copy[ i ].key ) ) {
      VERIFY_TEST( bitset_copy[ i ].ref_cnt>0UL, "account address in table with 0 ref count" );

      total_references += bitset_copy[ i ].ref_cnt;

      FD_PACK_BITSET_CLEAR( bit );
      FD_PACK_BITSET_SETN( bit, bitset_copy[ i ].bit );
      VERIFY_TEST( FD_PACK_BITSET_INTERSECT4_EMPTY( bit, bit, processed, processed ), "bit %hu used twice", bitset_copy[ i ].bit );
      FD_PACK_BITSET_OR( processed, bit );
    }
  }
  for( ulong i=0UL; i<FD_PACK_BITSET_MAX; i++ ) {
    FD_PACK_BITSET_CLEAR( bit );
    FD_PACK_BITSET_SETN( bit, i );
    VERIFY_TEST( !FD_PACK_BITSET_INTERSECT4_EMPTY( bit, bit, processed, processed ), "bit %lu missing", i );
    FD_PACK_BITSET_SETN( full, i );
  }


  fd_pack_ord_txn_t  * pool = pack->pool;
  treap_t * treaps[ 3 ] = { pack->pending, pack->pending_votes, pack->pending_bundles };
  ulong txn_cnt = 0UL;

  for( ulong k=0UL; k<3UL+penalty_map_slot_cnt( pack->penalty_treaps ); k++ ) {
    treap_t * treap = NULL;

    if( k<3UL ) treap = treaps[ k ];
    else if( FD_LIKELY( penalty_map_key_inval( pack->penalty_treaps[ k-3UL ].key ) ) ) continue;
    else {
      treap = pack->penalty_treaps[ k-3UL ].penalty_treap;
      VERIFY_TEST( treap_ele_cnt( treap )>0UL, "empty penalty treap in map" );
    }

    for( treap_rev_iter_t _cur=treap_rev_iter_init( treap, pool ); !treap_rev_iter_done( _cur );
        _cur=treap_rev_iter_next( _cur, pool ) ) {
      txn_cnt++;
      fd_pack_ord_txn_t const * cur = treap_rev_iter_ele_const( _cur, pool );
      fd_txn_t const * txn = TXN(cur->txn);
      fd_acct_addr_t const * accts   = fd_txn_get_acct_addrs( txn, cur->txn->payload );
      fd_acct_addr_t const * alt_adj = cur->txn_e->alt_accts - fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM );

      fd_ed25519_sig_t const * sig0 = fd_txn_get_signatures( txn, cur->txn->payload );

      fd_pack_ord_txn_t const * in_tbl = sig2txn_ele_query_const( pack->signature_map, (wrapped_sig_t const *)sig0, NULL, pool );
      VERIFY_TEST( in_tbl, "signature missing from sig2txn" );

      VERIFY_TEST( (ulong)(cur->root & FD_ORD_TXN_ROOT_TAG_MASK)==fd_ulong_min( k, 3UL )+1UL, "treap element had bad root" );
      if( FD_LIKELY( (cur->root & FD_ORD_TXN_ROOT_TAG_MASK)==FD_ORD_TXN_ROOT_PENALTY(0) ) ) {
        fd_acct_addr_t const * penalty_acct = ACCT_IDX_TO_PTR( FD_ORD_TXN_ROOT_PENALTY_ACCT_IDX( cur->root ) );
        VERIFY_TEST( !memcmp( penalty_acct, pack->penalty_treaps[ k-3UL ].key.b, 32UL ), "transaction in wrong penalty treap" );
      }
      VERIFY_TEST( cur->expires_at>=pack->expire_before, "treap element expired" );

      fd_pack_expq_t const * eq = pack->expiration_q + cur->expq_idx;
      VERIFY_TEST( eq->txn==cur, "expq inconsistent" );
      VERIFY_TEST( eq->expires_at==cur->expires_at, "expq expires_at inconsistent" );

      FD_PACK_BITSET_DECLARE( complement );
      FD_PACK_BITSET_COPY( complement, full );
      for( fd_txn_acct_iter_t iter=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE );
          iter!=fd_txn_acct_iter_end(); iter=fd_txn_acct_iter_next( iter ) ) {
        fd_acct_addr_t acct = *ACCT_ITER_TO_PTR( iter );

        fd_pack_bitset_acct_mapping_t * q = bitset_map_query( bitset_copy, acct, NULL );
        VERIFY_TEST( q, "account in transaction missing from bitset mapping" );
        VERIFY_TEST( q->ref_cnt>0UL, "account in transaction ref_cnt already 0" );
        q->ref_cnt--;
        total_references--;

        FD_PACK_BITSET_CLEAR( bit );
        FD_PACK_BITSET_SETN( bit, q->bit );
        if( q->bit<FD_PACK_BITSET_MAX ) {
          VERIFY_TEST( !FD_PACK_BITSET_INTERSECT4_EMPTY( bit, bit, cur->rw_bitset, cur->rw_bitset ), "missing from rw bitset" );
          VERIFY_TEST( !FD_PACK_BITSET_INTERSECT4_EMPTY( bit, bit, cur->w_bitset,  cur->w_bitset  ), "missing from w bitset" );
        }
        FD_PACK_BITSET_CLEARN( complement, q->bit );
      }
      VERIFY_TEST( FD_PACK_BITSET_INTERSECT4_EMPTY( complement, complement, cur->w_bitset,  cur->w_bitset ), "extra in w bitset" );

      for( fd_txn_acct_iter_t iter=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_READONLY );
          iter!=fd_txn_acct_iter_end(); iter=fd_txn_acct_iter_next( iter ) ) {

        fd_acct_addr_t acct = *ACCT_ITER_TO_PTR( iter );
        if( FD_UNLIKELY( fd_pack_unwritable_contains( &acct ) ) ) continue;
        fd_pack_bitset_acct_mapping_t * q = bitset_map_query( bitset_copy, acct, NULL );
        VERIFY_TEST( q, "account in transaction missing from bitset mapping" );
        VERIFY_TEST( q->ref_cnt>0UL, "account in transaction ref_cnt already 0" );
        q->ref_cnt--;
        total_references--;

        FD_PACK_BITSET_CLEAR( bit );
        FD_PACK_BITSET_SETN( bit, q->bit );
        if( q->bit<FD_PACK_BITSET_MAX ) {
          VERIFY_TEST( !FD_PACK_BITSET_INTERSECT4_EMPTY( bit, bit, cur->rw_bitset, cur->rw_bitset ), "missing from rw bitset" );
        }
        FD_PACK_BITSET_CLEARN( complement, q->bit );
      }
      VERIFY_TEST( FD_PACK_BITSET_INTERSECT4_EMPTY( complement, complement, cur->rw_bitset,  cur->rw_bitset ), "extra in rw bitset" );
    }
  }

  bitset_map_leave( bitset_copy );
  VERIFY_TEST( txn_cnt==pack->pending_txn_cnt, "txn_cnt" );

  VERIFY_TEST( total_references==0UL, "extra references in bitset mapping" );
  ulong sig2txn_key_cnt = 0UL;
  for( sig2txn_iter_t iter = sig2txn_iter_init( pack->signature_map, pool );
      !sig2txn_iter_done( iter, pack->signature_map, pool );
      iter = sig2txn_iter_next( iter, pack->signature_map, pool ) ) {
    sig2txn_key_cnt++;
  }
  VERIFY_TEST( txn_cnt==sig2txn_key_cnt, "extra signatures in sig2txn" );
  VERIFY_TEST( !sig2txn_verify( pack->signature_map, trp_pool_max( pool ), pool ), "sig2txn corrupt" );

  /* Count noncemap keys */
  ulong noncemap_key_cnt = 0UL;
  for( noncemap_iter_t iter = noncemap_iter_init( pack->noncemap, pool );
      !noncemap_iter_done( iter, pack->noncemap, pool );
      iter = noncemap_iter_next( iter, pack->noncemap, pool ) ) {
    noncemap_key_cnt++;
    /* Ensure element is in pool */
    fd_pack_ord_txn_t const * ord = noncemap_iter_ele_const( iter, pack->noncemap, pool );
    VERIFY_TEST( ord->txn->flags & FD_TXN_P_FLAGS_DURABLE_NONCE, "invalid entry in noncemap" );

    /* Although pack allows multiple transactions with the same
       signature in sig2txn (MAP_MULTI==1), the noncemap checks prevent
       multiple nonce transactions with the same signature. */
    wrapped_sig_t sig = FD_LOAD( wrapped_sig_t, fd_txn_get_signatures( TXN( ord->txn ), ord->txn->payload ) );
    VERIFY_TEST( ord==sig2txn_ele_query_const( pack->signature_map, &sig, NULL, pool ), "noncemap and sig2txn desynced" );
  }
  VERIFY_TEST( txn_cnt>=noncemap_key_cnt, "phantom txns in noncemap" );
  VERIFY_TEST( !noncemap_verify( pack->noncemap, trp_pool_max( pool ), pool ), "noncemap corrupt" );

  ulong slots_found = 0UL;
  ulong const pool_max = trp_pool_max( pool );
  for( ulong i=0UL; i<pool_max; i++ ) {
    fd_pack_ord_txn_t * ord = pack->pool + i;
    if( ord->root!=FD_ORD_TXN_ROOT_FREE ) slots_found++;
  }
  VERIFY_TEST( slots_found==txn_cnt, "phantom slots in pool" );

  bitset_map_join( _bitset_map_orig );

  int lg_uses_tbl_sz = acct_uses_lg_slot_cnt( pack->acct_in_use );

  void * _acct_in_use_copy = scratch;
  void * _acct_in_use_orig = acct_uses_leave( pack->acct_in_use );
  fd_memcpy( _acct_in_use_copy, _acct_in_use_orig, acct_uses_footprint( lg_uses_tbl_sz ) );

  fd_pack_addr_use_t * acct_in_use_copy = acct_uses_join( _acct_in_use_copy );

  FD_PACK_BITSET_DECLARE(  w_complement );
  FD_PACK_BITSET_DECLARE( rw_complement );
  FD_PACK_BITSET_COPY(  w_complement, full );
  FD_PACK_BITSET_COPY( rw_complement, full );

  FD_PACK_BITSET_DECLARE( rw_bitset );  FD_PACK_BITSET_COPY( rw_bitset, pack->bitset_rw_in_use );
  FD_PACK_BITSET_DECLARE(  w_bitset );  FD_PACK_BITSET_COPY(  w_bitset, pack->bitset_w_in_use  );


  ulong const EMPTY_MASK = ~(FD_PACK_IN_USE_WRITABLE | FD_PACK_IN_USE_BIT_CLEARED);

  for( ulong bank=0UL; bank<pack->bank_tile_cnt; bank++ ) {

    fd_pack_addr_use_t const * base = pack->use_by_bank[ bank ];
    ulong bank_mask = 1UL << bank;

    for( ulong i=0UL; i<pack->use_by_bank_cnt[ bank ]; i++ ) {
      fd_pack_addr_use_t * use = acct_uses_query( acct_in_use_copy, base[i].key, NULL );
      VERIFY_TEST( use, "acct in use by bank not in acct_in_use, or in uses_by_bank twice" );

      VERIFY_TEST( use->in_use_by & bank_mask, "acct in uses_by_bank doesn't have corresponding bit set in acct_in_use, or it was in the list twice" );

      fd_pack_bitset_acct_mapping_t * q = bitset_map_query( pack->acct_to_bitset, base[i].key, NULL );
      /* The normal case is that the acct->bit mapping is preserved
         while in use by other transactions in the pending list.  This
         might not always happen though.  It's okay for the mapping to
         get deleted while the acct is in use, which is noted with
         BIT_CLEARED.  If that is set, the mapping may not exist, or it
         may have been re-created, perhaps with a different bit. */
      if( q==NULL ) VERIFY_TEST( use->in_use_by & FD_PACK_IN_USE_BIT_CLEARED, "acct in use not in acct_to_bitset, but not marked as cleared" );
      else if( !(use->in_use_by & FD_PACK_IN_USE_BIT_CLEARED) ) {
        FD_PACK_BITSET_CLEAR( bit );
        FD_PACK_BITSET_SETN( bit, q->bit );
        if( q->bit<FD_PACK_BITSET_MAX ) {
          VERIFY_TEST( !FD_PACK_BITSET_INTERSECT4_EMPTY( bit, bit, rw_bitset, rw_bitset ), "missing from rw bitset" );
          if( use->in_use_by & FD_PACK_IN_USE_WRITABLE ) {
            VERIFY_TEST( !FD_PACK_BITSET_INTERSECT4_EMPTY( bit, bit, w_bitset, w_bitset ), "missing from w bitset" );
            FD_PACK_BITSET_CLEARN( w_complement, q->bit );
          }
        }
        FD_PACK_BITSET_CLEARN( rw_complement, q->bit );
      }
      if( use->in_use_by & FD_PACK_IN_USE_WRITABLE ) VERIFY_TEST( (use->in_use_by & EMPTY_MASK)==bank_mask, "writable, but in use by multiple" );

      use->in_use_by &= ~bank_mask;
      if( !(use->in_use_by & EMPTY_MASK) ) acct_uses_remove( acct_in_use_copy, use );
    }
  }
  VERIFY_TEST( acct_uses_key_cnt( acct_in_use_copy )==0UL, "stray uses in acct_in_use" );
  VERIFY_TEST( FD_PACK_BITSET_INTERSECT4_EMPTY( rw_complement, rw_complement, rw_bitset,  rw_bitset ), "extra in rw bitset" );
  VERIFY_TEST( FD_PACK_BITSET_INTERSECT4_EMPTY(  w_complement,  w_complement,  w_bitset,   w_bitset ), "extra in w bitset" );

  acct_uses_leave( acct_in_use_copy );

  acct_uses_join( _acct_in_use_orig );
  return 0;
}

void * fd_pack_leave ( fd_pack_t * pack ) { FD_COMPILER_MFENCE(); return (void *)pack; }
void * fd_pack_delete( void      * mem  ) { FD_COMPILER_MFENCE(); return mem;          }
