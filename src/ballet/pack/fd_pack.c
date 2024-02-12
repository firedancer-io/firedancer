#define FD_UNALIGNED_ACCESS_STYLE 0
#include "fd_pack.h"
#include "fd_pack_cost.h"
#include "fd_compute_budget_program.h"
#include "fd_pack_bitset.h"
#include <math.h> /* for sqrt */
#include <stddef.h> /* for offsetof */
#include "../../disco/metrics/fd_metrics.h"

/* Declare a bunch of helper structs used for pack-internal data
   structures. */

/* fd_pack_ord_txn_t: An fd_txn_p_t with information required to order
   it by priority. */
struct fd_pack_private_ord_txn {
  /* It's important that there be no padding here (asserted below)
     because the code casts back and forth from pointers to this element
     to pointers to the whole struct. */
  fd_txn_p_t   txn[1];

  /* Since this struct can be in one of several trees, it's helpful to
     store which tree.  This should be one of the FD_ORD_TXN_ROOT_*
     values. */
  int root;

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

  /* We want rewards*compute_est to fit in a ulong so that r1/c1 < r2/c2 can be
     computed as r1*c2 < r2*c1, with the product fitting in a ulong.
     compute_est has a small natural limit of mid-20 bits. rewards doesn't have
     a natural limit, so there is some argument to be made for raising the
     limit for rewards to 40ish bits. The struct has better packing with
     uint/uint though. */
  uint         rewards;     /* in Lamports */
  uint         compute_est; /* in compute units */

  /* The treap fields */
  ulong left;
  ulong right;
  ulong parent;
  ulong prio;

  FD_PACK_BITSET_DECLARE( rw_bitset ); /* all accts this txn references */
  FD_PACK_BITSET_DECLARE(  w_bitset ); /* accts this txn write-locks    */

};
typedef struct fd_pack_private_ord_txn fd_pack_ord_txn_t;

/* What we want is that the payload starts at byte 0 of
   fd_pack_ord_txn_t so that the trick with the signature map works
   properly.  GCC and Clang seem to disagree on the rules of offsetof.
   */
FD_STATIC_ASSERT( offsetof( fd_pack_ord_txn_t, txn          )==0UL, fd_pack_ord_txn_t );
#if FD_USING_CLANG
FD_STATIC_ASSERT( offsetof( fd_txn_p_t,             payload )==0UL, fd_pack_ord_txn_t );
#else
FD_STATIC_ASSERT( offsetof( fd_pack_ord_txn_t, txn->payload )==0UL, fd_pack_ord_txn_t );
#endif

#define FD_ORD_TXN_ROOT_FREE            0
#define FD_ORD_TXN_ROOT_PENDING         1
#define FD_ORD_TXN_ROOT_PENDING_VOTE    2
#define FD_ORD_TXN_ROOT_DELAY_END_BLOCK 3
#define FD_ORD_TXN_ROOT_DELAY_BANK_BASE 4 /* [4, 4+FD_PACK_MAX_BANK_TILES) */

#define FD_PACK_IN_USE_WRITABLE    (0x8000000000000000UL)
#define FD_PACK_IN_USE_BIT_CLEARED (0x4000000000000000UL)

/* fd_pack_addr_use_t: Used for two distinct purposes:
    -  to record that an address is in use and can't be used again until
         certain microblocks finish execution
    -  to keep track of the cost of all transactions that write to the
         specified account.
   Making these separate structs might make it more clear, but then
   they'd have identical shape and result in two fd_map_dynamic sets of
   functions with identical code.  It doesn't seem like the compiler is
   very good at merging code like that, so in order to reduce code
   bloat, we'll just combine them. */
struct fd_pack_private_addr_use_record {
  fd_acct_addr_t key; /* account address */
  union {
    ulong          in_use_by;  /* Bitmask indicating which banks */
    ulong          total_cost; /* In cost units/CUs */
  };
};
typedef struct fd_pack_private_addr_use_record fd_pack_addr_use_t;


/* fd_pack_sig_to_entry_t: An element of an fd_map that maps the first
   transaction signature to the corresponding fd_pack_ord_txn_t so that
   pending transactions can be deleted by signature.  Note: this
   implicitly relies on the fact that for Solana transactions the
   signature_offset is always 1.  If that fact changes, this will need
   to become a real struct. */
struct fd_pack_sig_to_txn {
  fd_ed25519_sig_t const * key;
};
typedef struct fd_pack_sig_to_txn fd_pack_sig_to_txn_t;

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

/* Table of special addresses that are not allowed to be written to.  We
   immediately reject and refuse to pack any transaction that tries to
   write to one of these accounts.  Because we reject any writes to any
   of these accounts, we actually don't need to track reads of them
   either.  This is nice, because fd_map_dynamic requires a null address
   that we promise never to insert.  The zero address is a sysvar, so
   now we meet that part of the fd_map_dynamic contract. */
#define MAP_PERFECT_NAME      fd_pack_unwritable
#define MAP_PERFECT_LG_TBL_SZ 5
#define MAP_PERFECT_T         fd_acct_addr_t
#define MAP_PERFECT_HASH_C    1402126759U
#define MAP_PERFECT_KEY       b
#define MAP_PERFECT_KEY_T     fd_acct_addr_t const *
#define MAP_PERFECT_ZERO_KEY  (0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define MAP_PERFECT_COMPLEX_KEY 1
#define MAP_PERFECT_KEYS_EQUAL(k1,k2) (!memcmp( (k1), (k2), 32UL ))

#define PERFECT_HASH( u ) (((MAP_PERFECT_HASH_C*(u))>>27)&0x1FU)

#define MAP_PERFECT_HASH_PP( a00,a01,a02,a03,a04,a05,a06,a07,a08,a09,a10,a11,a12,a13,a14,a15, \
                             a16,a17,a18,a19,a20,a21,a22,a23,a24,a25,a26,a27,a28,a29,a30,a31) \
                                          PERFECT_HASH( (a08 | (a09<<8) | (a10<<16) | (a11<<24)) )
#define MAP_PERFECT_HASH_R( ptr ) PERFECT_HASH( fd_uint_load_4( (uchar const *)ptr->b + 8UL ) )

/* This list is a superset of what Lab's is_builtin_key_or_sysvar checks. */
/* Sysvars */
#define MAP_PERFECT_0  ( SYSVAR_CLOCK_ID          ),
#define MAP_PERFECT_1  ( SYSVAR_EPOCH_SCHED_ID    ),
#define MAP_PERFECT_2  ( SYSVAR_FEES_ID           ),
#define MAP_PERFECT_3  ( SYSVAR_RECENT_BLKHASH_ID ),
#define MAP_PERFECT_4  ( SYSVAR_RENT_ID           ),
#define MAP_PERFECT_5  ( SYSVAR_REWARDS_ID        ),
#define MAP_PERFECT_6  ( SYSVAR_SLOT_HASHES_ID    ),
#define MAP_PERFECT_7  ( SYSVAR_SLOT_HIST_ID      ),
#define MAP_PERFECT_8  ( SYSVAR_STAKE_HIST_ID     ),
#define MAP_PERFECT_9  ( SYSVAR_INSTRUCTIONS_ID   ),
#define MAP_PERFECT_10 ( SYSVAR_EPOCH_REWARDS_ID  ),
#define MAP_PERFECT_11 ( SYSVAR_LAST_RESTART_ID   ),
/* Programs */
#define MAP_PERFECT_12 ( CONFIG_PROG_ID           ),
#define MAP_PERFECT_13 ( FEATURE_ID               ),
#define MAP_PERFECT_14 ( NATIVE_LOADER_ID         ),
#define MAP_PERFECT_15 ( STAKE_PROG_ID            ),
#define MAP_PERFECT_16 ( STAKE_CONFIG_PROG_ID     ),
#define MAP_PERFECT_17 ( VOTE_PROG_ID             ),
#define MAP_PERFECT_18 ( SYS_PROG_ID              ), /* Do not remove. See above. */
#define MAP_PERFECT_19 ( BPF_LOADER_1_PROG_ID     ),
#define MAP_PERFECT_20 ( BPF_LOADER_2_PROG_ID     ),
#define MAP_PERFECT_21 ( BPF_UPGRADEABLE_PROG_ID  ),
/* Extras */
#define MAP_PERFECT_22 ( ED25519_SV_PROG_ID       ),
#define MAP_PERFECT_23 ( KECCAK_SECP_PROG_ID      ),
#define MAP_PERFECT_24 ( COMPUTE_BUDGET_PROG_ID   ),
#define MAP_PERFECT_25 ( ADDR_LUT_PROG_ID         ),
#define MAP_PERFECT_26 ( NATIVE_MINT_ID           ),
#define MAP_PERFECT_27 ( TOKEN_PROG_ID            ),
#define MAP_PERFECT_28 ( SYSVAR_PROG_ID           ),

#include "../../util/tmpl/fd_map_perfect.c"


/* Returns 1 if x.rewards/x.compute < y.rewards/y.compute. Not robust. */
#define COMPARE_WORSE(x,y) ( ((ulong)((x)->rewards)*(ulong)((y)->compute_est)) < ((ulong)((y)->rewards)*(ulong)((x)->compute_est)) )

/* Declare all the data structures */


/* Define the big max-"heap" that we pull transactions off to schedule.
   The priority is given by reward/compute.  We may want to add in some
   additional terms at a later point.  In order to cheaply remove nodes,
   we actually use a treap.  */
#define POOL_NAME       trp_pool
#define POOL_T          fd_pack_ord_txn_t
#define POOL_NEXT       parent
#include "../../util/tmpl/fd_pool.c"

#define TREAP_T         fd_pack_ord_txn_t
#define TREAP_NAME      treap
#define TREAP_QUERY_T   void *                                         /* We don't use query ... */
#define TREAP_CMP(a,b)  (__extension__({ (void)(a); (void)(b); -1; })) /* which means we don't need to give a real
                                                                          implementation to cmp either */
#define TREAP_LT        COMPARE_WORSE
#include "../../util/tmpl/fd_treap.c"


/* Define a strange map where key and value are kind of the same
   variable.  Essentially, it maps the contents to which the pointer
   points to the value of the pointer. */
#define MAP_NAME              sig2txn
#define MAP_T                 fd_pack_sig_to_txn_t
#define MAP_KEY_T             fd_ed25519_sig_t const *
#define MAP_KEY_NULL          NULL
#define MAP_KEY_INVAL(k)      !(k)
#define MAP_MEMOIZE           0
#define MAP_KEY_EQUAL(k0,k1)  (((!!(k0))&(!!(k1)))&&(!memcmp((k0),(k1), FD_TXN_SIGNATURE_SZ)))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH(key)     fd_uint_load_4( (key) ) /* first 4 bytes of signature */
#include "../../util/tmpl/fd_map_dynamic.c"


static const fd_acct_addr_t null_addr = { 0 };

#define MAP_NAME              acct_uses
#define MAP_T                 fd_pack_addr_use_t
#define MAP_KEY_T             fd_acct_addr_t
#define MAP_KEY_NULL          null_addr
#define MAP_KEY_INVAL(k)      MAP_KEY_EQUAL(k, null_addr)
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp((k0).b,(k1).b, FD_TXN_ACCT_ADDR_SZ))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_MEMOIZE           0
#define MAP_KEY_HASH(key)     ((uint)fd_ulong_hash( fd_ulong_load_8( (key).b ) ))
#include "../../util/tmpl/fd_map_dynamic.c"


#define MAP_NAME              bitset_map
#define MAP_T                 fd_pack_bitset_acct_mapping_t
#define MAP_KEY_T             fd_acct_addr_t
#define MAP_KEY_NULL          null_addr
#define MAP_KEY_INVAL(k)      MAP_KEY_EQUAL(k, null_addr)
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

/* Finally, we can now declare the main pack data structure */
struct fd_pack_private {
  ulong      pack_depth;
  ulong      bank_tile_cnt;
  ulong      max_txn_per_microblock;
  ulong      max_microblocks_per_block;

  ulong      pending_txn_cnt;
  ulong      microblock_cnt; /* How many microblocks have we
                                generated in this block? */
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

  /* Transactions in the pool can be in one of various trees.  The
     default situation is that the transaction is in pending or
     pending_votes, depending on whether it is a vote or not.

     If this were the only storage for transactions though, in the case
     that there are a lot of transactions that conflict, we'd end up
     going through transactions a bunch of times.  To optimize that,
     when we know that we won't be able to consider a transaction until
     at least a certain microblock finishes, we stick it in a "data
     structure" like a bucket queue based on which currently scheduled
     microblocks it conflicts with.

     This is just a performance optimization and done on a best effort
     basis; a transaction coming out of conflicting_with might still not
     be available because of new conflicts.  Transactions in pending
     might have conflicts we just haven't discovered yet.  The
     authoritative source for conflicts is acct_uses_{read,write}. */

  treap_t pending[1];
  treap_t pending_votes[1];
  treap_t delay_end_block[1];
  treap_t conflicting_with[ FD_PACK_MAX_BANK_TILES ];

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

  fd_pack_addr_use_t   * writer_costs;
  fd_pack_sig_to_txn_t * signature_map; /* Stores pointers into pool for deleting by signature */

  /* use_by_bank: An array of size (max_txn_per_microblock *
     FD_TXN_ACCT_ADDR_MAX) for each banking tile.  Only the MSB of
     in_use_by is relevant.  Addressed use_by_bank[i][j] where i is in
     [0, bank_tile_cnt) and j is in [0, use_by_bank_cnt[i]).  Used
     mostly for clearing the proper bits of acct_in_use when a
     microblock finishes. */
  fd_pack_addr_use_t * use_by_bank    [ FD_PACK_MAX_BANK_TILES ];
  ulong                use_by_bank_cnt[ FD_PACK_MAX_BANK_TILES ];

  fd_histf_t txn_per_microblock [ 1 ];
  fd_histf_t vote_per_microblock[ 1 ];
  /* bitset_avail: a stack of which bits are not currently reserved and
     can be used to represent an account address.
     Indexed [0, bitset_avail_cnt].  Element 0 is fixed at
     FD_PACK_BITSET_SLOWPATH. */
  ushort bitset_avail[ 1UL+FD_PACK_BITSET_MAX ];
  ulong  bitset_avail_cnt;

  /* acct_to_bitset: an fd_map_dynamic that maps acct addresses to the
     reference count, which bit, etc. */
  fd_pack_bitset_acct_mapping_t * acct_to_bitset;
};

typedef struct fd_pack_private fd_pack_t;

ulong
fd_pack_footprint( ulong pack_depth,
                   ulong bank_tile_cnt,
                   ulong max_txn_per_microblock ) {
  if( FD_UNLIKELY( (bank_tile_cnt==0) | (bank_tile_cnt>FD_PACK_MAX_BANK_TILES) ) ) return 0UL;

  ulong l;
  ulong max_acct_in_treap  = pack_depth * FD_TXN_ACCT_ADDR_MAX;
  ulong max_acct_in_flight = bank_tile_cnt * (FD_TXN_ACCT_ADDR_MAX * max_txn_per_microblock + 1UL);
  ulong max_txn_per_block  = FD_PACK_MAX_COST_PER_BLOCK / FD_PACK_MIN_TXN_COST;

  /* log base 2, but with a 2* so that the hash table stays sparse */
  int lg_uses_tbl_sz = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_acct_in_flight ) );
  int lg_max_txn     = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_txn_per_block  ) );
  int lg_depth       = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*pack_depth         ) );
  int lg_acct_in_trp = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_acct_in_treap  ) );

  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_PACK_ALIGN,      sizeof(fd_pack_t)                               );
  l = FD_LAYOUT_APPEND( l, trp_pool_align (),  trp_pool_footprint ( pack_depth+1UL           ) ); /* pool           */
  l = FD_LAYOUT_APPEND( l, expq_align     (),  expq_footprint     ( pack_depth+1UL           ) ); /* expiration prq */
  l = FD_LAYOUT_APPEND( l, acct_uses_align(),  acct_uses_footprint( lg_uses_tbl_sz           ) ); /* acct_in_use    */
  l = FD_LAYOUT_APPEND( l, acct_uses_align(),  acct_uses_footprint( lg_max_txn               ) ); /* writer_costs   */
  l = FD_LAYOUT_APPEND( l, sig2txn_align  (),  sig2txn_footprint  ( lg_depth                 ) ); /* signature_map  */
  l = FD_LAYOUT_APPEND( l, 32UL,               sizeof(fd_pack_addr_use_t)*max_acct_in_flight   ); /* use_by_bank    */
  l = FD_LAYOUT_APPEND( l, bitset_map_align(), bitset_map_footprint( lg_acct_in_trp          ) ); /* acct_to_bitset */
  return FD_LAYOUT_FINI( l, FD_PACK_ALIGN );
}

void *
fd_pack_new( void *     mem,
             ulong      pack_depth,
             ulong      bank_tile_cnt,
             ulong      max_txn_per_microblock,
             ulong      max_microblocks_per_block,
             fd_rng_t * rng                       ) {

  ulong max_acct_in_treap  = pack_depth * FD_TXN_ACCT_ADDR_MAX;
  ulong max_acct_in_flight = bank_tile_cnt * (FD_TXN_ACCT_ADDR_MAX * max_txn_per_microblock + 1UL);
  ulong max_txn_per_block  = FD_PACK_MAX_COST_PER_BLOCK / FD_PACK_MIN_TXN_COST;

  /* log base 2, but with a 2* so that the hash table stays sparse */
  int lg_uses_tbl_sz = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_acct_in_flight ) );
  int lg_max_txn     = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_txn_per_block  ) );
  int lg_depth       = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*pack_depth         ) );
  int lg_acct_in_trp = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_acct_in_treap  ) );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_pack_t * pack    = FD_SCRATCH_ALLOC_APPEND( l,  FD_PACK_ALIGN,       sizeof(fd_pack_t)                             );
  /* The pool has one extra element that is used between insert_init and
     cancel/fini. */
  void * _pool        = FD_SCRATCH_ALLOC_APPEND( l,  trp_pool_align(),    trp_pool_footprint ( pack_depth+1UL         ) );
  void * _expq        = FD_SCRATCH_ALLOC_APPEND( l,  expq_align(),        expq_footprint     ( pack_depth+1UL         ) );
  void * _uses        = FD_SCRATCH_ALLOC_APPEND( l,  acct_uses_align(),   acct_uses_footprint( lg_uses_tbl_sz         ) );
  void * _writer_cost = FD_SCRATCH_ALLOC_APPEND( l,  acct_uses_align(),   acct_uses_footprint( lg_max_txn             ) );
  void * _sig_map     = FD_SCRATCH_ALLOC_APPEND( l,  sig2txn_align(),     sig2txn_footprint  ( lg_depth               ) );
  void * _use_by_bank = FD_SCRATCH_ALLOC_APPEND( l,  32UL,                sizeof(fd_pack_addr_use_t)*max_acct_in_flight );
  void * _acct_bitset = FD_SCRATCH_ALLOC_APPEND( l,  bitset_map_align(),  bitset_map_footprint( lg_acct_in_trp        ) );

  pack->pack_depth                  = pack_depth;
  pack->bank_tile_cnt               = bank_tile_cnt;
  pack->max_txn_per_microblock      = max_txn_per_microblock;
  pack->max_microblocks_per_block   = max_microblocks_per_block;
  pack->pending_txn_cnt             = 0UL;
  pack->microblock_cnt              = 0UL;
  pack->rng                         = rng;
  pack->cumulative_block_cost       = 0UL;
  pack->cumulative_vote_cost        = 0UL;
  pack->expire_before               = 0UL;
  pack->outstanding_microblock_mask = 0UL;


  trp_pool_new(  _pool,        pack_depth+1UL );

  fd_pack_ord_txn_t * pool = trp_pool_join( _pool );
  treap_seed( pool, pack_depth+1UL, fd_rng_ulong( rng ) );
  (void)trp_pool_leave( pool );


  treap_new( (void*)pack->pending,         pack_depth );
  treap_new( (void*)pack->pending_votes,   pack_depth );
  treap_new( (void*)pack->delay_end_block, pack_depth );
  for( ulong i=0UL; i<FD_PACK_MAX_BANK_TILES; i++ ) treap_new( (void*)(pack->conflicting_with+i), pack_depth );

  expq_new( _expq, pack_depth+1UL );

  FD_PACK_BITSET_CLEAR( pack->bitset_rw_in_use );
  FD_PACK_BITSET_CLEAR( pack->bitset_w_in_use  );

  acct_uses_new( _uses,        lg_uses_tbl_sz );
  acct_uses_new( _writer_cost, lg_max_txn     );
  sig2txn_new(   _sig_map,     lg_depth       );

  fd_pack_addr_use_t * use_by_bank = (fd_pack_addr_use_t *)_use_by_bank;
  for( ulong i=0UL; i<bank_tile_cnt; i++ ) pack->use_by_bank[i]=use_by_bank + i*(FD_TXN_ACCT_ADDR_MAX*max_txn_per_microblock+1UL);
  for( ulong i=0UL; i<bank_tile_cnt; i++ ) pack->use_by_bank_cnt[i]=0UL;

  fd_histf_new( pack->txn_per_microblock,  FD_MHIST_MIN( PACK, TOTAL_TRANSACTIONS_PER_MICROBLOCK_COUNT ),
                                           FD_MHIST_MAX( PACK, TOTAL_TRANSACTIONS_PER_MICROBLOCK_COUNT ) );
  fd_histf_new( pack->vote_per_microblock, FD_MHIST_MIN( PACK, VOTES_PER_MICROBLOCK_COUNT ),
                                           FD_MHIST_MAX( PACK, VOTES_PER_MICROBLOCK_COUNT ) );

  pack->bitset_avail[ 0 ] = FD_PACK_BITSET_SLOWPATH;
  for( ulong i=0UL; i<FD_PACK_BITSET_MAX; i++ ) pack->bitset_avail[ i+1UL ] = (ushort)i;
  pack->bitset_avail_cnt = FD_PACK_BITSET_MAX;

  bitset_map_new( _acct_bitset, lg_acct_in_trp );

  return mem;
}

fd_pack_t *
fd_pack_join( void * mem ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_pack_t * pack  = FD_SCRATCH_ALLOC_APPEND( l, FD_PACK_ALIGN, sizeof(fd_pack_t) );

  ulong pack_depth             = pack->pack_depth;
  ulong bank_tile_cnt          = pack->bank_tile_cnt;
  ulong max_txn_per_microblock = pack->max_txn_per_microblock;

  ulong max_acct_in_treap  = pack_depth * FD_TXN_ACCT_ADDR_MAX;
  ulong max_acct_in_flight = bank_tile_cnt * (FD_TXN_ACCT_ADDR_MAX * max_txn_per_microblock + 1UL);
  ulong max_txn_per_block  = FD_PACK_MAX_COST_PER_BLOCK / FD_PACK_MIN_TXN_COST;
  int lg_uses_tbl_sz = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_acct_in_flight ) );
  int lg_max_txn     = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_txn_per_block  ) );
  int lg_depth       = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*pack_depth         ) );
  int lg_acct_in_trp = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_acct_in_treap  ) );


  pack->pool          = trp_pool_join(   FD_SCRATCH_ALLOC_APPEND( l, trp_pool_align(),   trp_pool_footprint ( pack_depth+1UL ) ) );
  pack->expiration_q  = expq_join    (   FD_SCRATCH_ALLOC_APPEND( l, expq_align(),       expq_footprint     ( pack_depth+1UL ) ) );
  pack->acct_in_use   = acct_uses_join(  FD_SCRATCH_ALLOC_APPEND( l, acct_uses_align(),  acct_uses_footprint( lg_uses_tbl_sz ) ) );
  pack->writer_costs  = acct_uses_join(  FD_SCRATCH_ALLOC_APPEND( l, acct_uses_align(),  acct_uses_footprint( lg_max_txn     ) ) );
  pack->signature_map = sig2txn_join(    FD_SCRATCH_ALLOC_APPEND( l, sig2txn_align(),    sig2txn_footprint  ( lg_depth       ) ) );
  /* */                                  FD_SCRATCH_ALLOC_APPEND( l, 32UL,               sizeof(fd_pack_addr_use_t)*max_acct_in_flight );
  pack->acct_to_bitset= bitset_map_join( FD_SCRATCH_ALLOC_APPEND( l, bitset_map_align(), bitset_map_footprint( lg_acct_in_trp) ) );

  FD_MGAUGE_SET( PACK, PENDING_TRANSACTIONS_HEAP_SIZE, pack_depth );
  return pack;
}



static int
fd_pack_estimate_rewards_and_compute( fd_txn_p_t        * txnp,
                                      fd_pack_ord_txn_t * out ) {
  fd_txn_t * txn = TXN(txnp);
  ulong sig_rewards = FD_PACK_FEE_PER_SIGNATURE * txn->signature_cnt;

  ulong cost = fd_pack_compute_cost( txnp, &txnp->flags );

  if( FD_UNLIKELY( !cost ) ) return 0;

  fd_compute_budget_program_state_t cb_prog_st = {0};

  /* TODO: Refactor so that this doesn't scan all the instructions a
     second time after scanning them in fd_pack_compute_cost. */
  for( ulong i=0UL; i<(ulong)txn->instr_cnt; i++ ) {
    uchar prog_id_idx = txn->instr[ i ].program_id;
    fd_acct_addr_t const * acct_addr = fd_txn_get_acct_addrs( txn, txnp->payload ) + (ulong)prog_id_idx;

    if( FD_UNLIKELY( !memcmp( acct_addr, FD_COMPUTE_BUDGET_PROGRAM_ID, FD_TXN_ACCT_ADDR_SZ ) ) ) {
      /* Parse the compute budget program instruction */
      if( FD_UNLIKELY( !fd_compute_budget_program_parse( txnp->payload+txn->instr[ i ].data_off, txn->instr[ i ].data_sz, &cb_prog_st )))
        return 0;
    } else {
      /* No fancy CU estimation in this version of pack */
    }
  }
  ulong adtl_rewards = 0UL;
  uint  compute_max  = 0UL;
  fd_compute_budget_program_finalize( &cb_prog_st, txn->instr_cnt, &adtl_rewards, &compute_max );
  out->rewards     = (adtl_rewards < (UINT_MAX - sig_rewards)) ? (uint)(sig_rewards + adtl_rewards) : UINT_MAX;
  out->compute_est = (uint)cost;

  out->root = (txnp->flags & FD_TXN_P_FLAGS_IS_SIMPLE_VOTE) ? FD_ORD_TXN_ROOT_PENDING_VOTE : FD_ORD_TXN_ROOT_PENDING;

#if DETAILED_LOGGING
  FD_LOG_NOTICE(( "TXN estimated compute %lu+-%f. Rewards: %lu + %lu", compute_expected, (double)compute_variance, sig_rewards, adtl_rewards ));
#endif

  return 1;
}

/* Can the fee payer afford to pay a transaction with the specified
   price?  Returns 1 if so, 0 otherwise.  This is just a stub that
   always returns 1 for now.  In general, this function can't be totally
   accurate, because the transactions immediately prior to this one can
   affect the balance of this fee payer, but a simple check here may be
   helpful for reducing spam. */
static int
fd_pack_can_fee_payer_afford( fd_acct_addr_t const * acct_addr,
                              ulong                  price /* in lamports */) {
  (void)acct_addr;
  (void)price;
  return 1;
}





fd_txn_p_t * fd_pack_insert_txn_init(   fd_pack_t * pack                   ) { return trp_pool_ele_acquire( pack->pool )->txn; }
void         fd_pack_insert_txn_cancel( fd_pack_t * pack, fd_txn_p_t * txn ) { trp_pool_ele_release( pack->pool, (fd_pack_ord_txn_t*)txn ); }

#define REJECT( reason ) do {                                       \
                           trp_pool_ele_release( pack->pool, ord ); \
                           return FD_PACK_INSERT_REJECT_ ## reason; \
                         } while( 0 )

int
fd_pack_insert_txn_fini( fd_pack_t  * pack,
                         fd_txn_p_t * txnp,
                         ulong        expires_at ) {

  fd_pack_ord_txn_t * ord = (fd_pack_ord_txn_t *)txnp;

  fd_txn_t * txn   = TXN(txnp);
  uchar * payload  = txnp->payload;

  fd_acct_addr_t const * accts = fd_txn_get_acct_addrs( txn, payload );

  if( FD_UNLIKELY( !fd_pack_estimate_rewards_and_compute( txnp, ord ) ) ) REJECT( ESTIMATION_FAIL );

  ord->expires_at = expires_at;

  fd_txn_acct_iter_t ctrl[1];
  int writes_to_sysvar = 0;
  for( ulong i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE & FD_TXN_ACCT_CAT_IMM, ctrl ); i<fd_txn_acct_iter_end();
      i=fd_txn_acct_iter_next( i, ctrl ) ) {
    writes_to_sysvar |= fd_pack_unwritable_contains( accts+i );
  }

  fd_ed25519_sig_t const * sig = fd_txn_get_signatures( txn, payload );

  /* Throw out transactions ... */
  /*           ... that are unfunded */
  if( FD_UNLIKELY( !fd_pack_can_fee_payer_afford( accts, ord->rewards ) ) ) REJECT( UNAFFORDABLE  );
  /*           ... that are so big they'll never run */
  if( FD_UNLIKELY( ord->compute_est >= FD_PACK_MAX_COST_PER_BLOCK       ) ) REJECT( TOO_LARGE     );
  /*           ... that try to write to a sysvar */
  if( FD_UNLIKELY( writes_to_sysvar                                     ) ) REJECT( WRITES_SYSVAR );
  /*           ... that we already know about */
  if( FD_UNLIKELY( sig2txn_query( pack->signature_map, sig, NULL )      ) ) REJECT( DUPLICATE     );
  /*           ... that have already expired */
  if( FD_UNLIKELY( expires_at<pack->expire_before                       ) ) REJECT( EXPIRED       );


  int replaces = 0;
  if( FD_UNLIKELY( pack->pending_txn_cnt == pack->pack_depth ) ) {
    /* If the tree is full, we'll double check to make sure this is
       better than the worst element in the tree before inserting.  If
       the new transaction is better than that one, we'll delete it and
       insert the new transaction. Otherwise, we'll throw away this
       transaction. */
    fd_pack_ord_txn_t * worst = treap_fwd_iter_ele( treap_fwd_iter_init( pack->pending, pack->pool ), pack->pool );
    if( FD_UNLIKELY( !worst ) ) {
      /* We have nothing to sacrifice because they're all in other
         trees. */
      REJECT( FULL );
    }
    else if( !COMPARE_WORSE( worst, ord ) ) {
      /* What we have in the tree is better than this transaction, so just
         pretend this transaction never happened */
      REJECT( PRIORITY );
    } else {
      /* Remove the worst from the tree */
      replaces = 1;
      fd_ed25519_sig_t const * worst_sig = fd_txn_get_signatures( TXN( worst->txn ), worst->txn->payload );
      fd_pack_delete_transaction( pack, worst_sig );
    }
  }

  FD_PACK_BITSET_CLEAR( ord->rw_bitset );
  FD_PACK_BITSET_CLEAR( ord->w_bitset  );

  for( ulong i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE & FD_TXN_ACCT_CAT_IMM, ctrl ); i<fd_txn_acct_iter_end();
      i=fd_txn_acct_iter_next( i, ctrl ) ) {
    fd_pack_bitset_acct_mapping_t * q = bitset_map_query( pack->acct_to_bitset, accts[i], NULL );
    if( FD_UNLIKELY( q==NULL ) ) {
      q = bitset_map_insert( pack->acct_to_bitset, accts[i] );
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

    q->ref_cnt++;
    FD_PACK_BITSET_SETN( ord->rw_bitset, q->bit );
    FD_PACK_BITSET_SETN( ord->w_bitset , q->bit );
  }

  for( ulong i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_READONLY & FD_TXN_ACCT_CAT_IMM, ctrl ); i<fd_txn_acct_iter_end();
      i=fd_txn_acct_iter_next( i, ctrl ) ) {
    if( FD_UNLIKELY( fd_pack_unwritable_contains( accts+i ) ) ) continue;

    fd_pack_bitset_acct_mapping_t * q = bitset_map_query( pack->acct_to_bitset, accts[i], NULL );
    if( FD_UNLIKELY( q==NULL ) ) {
      q = bitset_map_insert( pack->acct_to_bitset, accts[i] );
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

  pack->pending_txn_cnt++;

  sig2txn_insert( pack->signature_map, fd_txn_get_signatures( txn, payload ) );

  fd_pack_expq_t temp[ 1 ] = {{ .expires_at = expires_at, .txn = ord }};
  expq_insert( pack->expiration_q, temp );

  if( FD_LIKELY( ord->root == FD_ORD_TXN_ROOT_PENDING_VOTE ) ) {
    treap_ele_insert( pack->pending_votes, ord, pack->pool );
    return replaces ? FD_PACK_INSERT_ACCEPT_VOTE_REPLACE : FD_PACK_INSERT_ACCEPT_VOTE_ADD;
  } else {
    treap_ele_insert( pack->pending,       ord, pack->pool );
    return replaces ? FD_PACK_INSERT_ACCEPT_NONVOTE_REPLACE : FD_PACK_INSERT_ACCEPT_NONVOTE_ADD;
  }
}
#undef REJECT

typedef struct {
  ulong cus_scheduled;
  ulong txns_scheduled;
} sched_return_t;

static inline sched_return_t
fd_pack_schedule_microblock_impl( fd_pack_t  * pack,
                                  treap_t    * sched_from,
                                  int          move_delayed,
                                  ulong        cu_limit,
                                  ulong        txn_limit,
                                  ulong        bank_tile,
                                  fd_txn_p_t * out ) {
  /* With the bitset account representation, it's faster to skip a
     transaction close to 20 times than to move it to the delayed heap
     and then move it back. */
  move_delayed = 0;

  fd_pack_ord_txn_t  * pool         = pack->pool;
  fd_pack_addr_use_t * acct_in_use  = pack->acct_in_use;
  fd_pack_addr_use_t * writer_costs = pack->writer_costs;

  FD_PACK_BITSET_DECLARE( bitset_rw_in_use );
  FD_PACK_BITSET_DECLARE( bitset_w_in_use  );
  FD_PACK_BITSET_COPY( bitset_rw_in_use, pack->bitset_rw_in_use );
  FD_PACK_BITSET_COPY( bitset_w_in_use,  pack->bitset_w_in_use  );

  fd_pack_addr_use_t * use_by_bank     = pack->use_by_bank    [bank_tile];
  ulong                use_by_bank_cnt = pack->use_by_bank_cnt[bank_tile];

  ulong txns_considered = 0UL;
  ulong txns_scheduled  = 0UL;
  ulong cus_scheduled   = 0UL;

  ulong bank_tile_mask = 1UL << bank_tile;

  ulong fast_path = 0UL;
  ulong slow_path = 0UL;
  ulong cu_limit_c = 0UL;

  treap_rev_iter_t prev;
  for( treap_rev_iter_t _cur=treap_rev_iter_init( sched_from, pool );
      (cu_limit>=FD_PACK_MIN_TXN_COST) & (txn_limit>0) & !treap_rev_iter_done( _cur ); _cur=prev ) {
    prev = treap_rev_iter_next( _cur, pool );

    txns_considered++;

    fd_pack_ord_txn_t * cur = treap_rev_iter_ele( _cur, pool );

    fd_txn_t * txn = TXN(cur->txn);
    fd_acct_addr_t const * acct = fd_txn_get_acct_addrs( txn, cur->txn->payload );

    ulong conflicts = 0UL;
    int   delay_end_block = 0;

    if( FD_UNLIKELY( cur->compute_est>cu_limit ) ) {
      /* Too big to be scheduled at the moment, but might be okay for
         the next microblock, so we don't want to delay it. */
      cu_limit_c++;
      continue;
    }

    if( FD_UNLIKELY( txn->addr_table_adtl_cnt>0UL ) ) {
      /* This transaction reads or writes to additional accounts from
         an address lookup table.  We don't yet know what they are
         so we can't check for conflicts and instead just never schedule
         the transaction.

         TODO: We should load the accounts here and check them for
         conflicts properly.  The accounts can change with the bank so
         it's non-trivial. */
      continue;
    }

    if( FD_PACK_BITSET_INTERSECT4_EMPTY( bitset_rw_in_use, bitset_w_in_use, cur->w_bitset, cur->rw_bitset ) ) {
      fd_txn_acct_iter_t ctrl[1];
      /* Check conflicts between this transaction's writable accounts and
         current readers */
      for( ulong i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE & FD_TXN_ACCT_CAT_IMM, ctrl ); i<fd_txn_acct_iter_end();
          i=fd_txn_acct_iter_next( i, ctrl ) ) {

        fd_pack_addr_use_t * in_wcost_table = acct_uses_query( writer_costs, acct[i], NULL );
        if( in_wcost_table && in_wcost_table->total_cost+cur->compute_est > FD_PACK_MAX_WRITE_COST_PER_ACCT ) {
          /* Can't be scheduled until the next block */
          conflicts = ULONG_MAX;
          delay_end_block = 1;
          break;
        }

        fd_pack_addr_use_t * use = acct_uses_query( acct_in_use, acct[i], NULL );
        if( use ) conflicts |= use->in_use_by; /* break? */
      }

      /* Check conflicts between this transaction's readonly accounts and
         current writers */
      for( ulong i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_READONLY & FD_TXN_ACCT_CAT_IMM, ctrl ); i<fd_txn_acct_iter_end();
          i=fd_txn_acct_iter_next( i, ctrl ) ) {
        if( fd_pack_unwritable_contains( acct+i ) ) continue; /* No need to track sysvars because they can't be writable */

        fd_pack_addr_use_t * use = acct_uses_query( acct_in_use,  acct[i], NULL );
        if( use ) conflicts |= (use->in_use_by & FD_PACK_IN_USE_WRITABLE) ? use->in_use_by : 0UL;
      }
      slow_path++;
    } else {
      conflicts = bank_tile_mask;
      fast_path++;
    }

    if( conflicts==0UL ) {
      /* Include this transaction in the microblock! */
      txns_scheduled++;
      cus_scheduled += cur->compute_est;
      cu_limit -= cur->compute_est;
      txn_limit--;

      FD_PACK_BITSET_OR( bitset_rw_in_use, cur->rw_bitset );
      FD_PACK_BITSET_OR( bitset_w_in_use,  cur->w_bitset  );

      fd_memcpy( out->payload, cur->txn->payload, cur->txn->payload_sz                                           );
      fd_memcpy( TXN(out),     txn,               fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt ) );
      out->payload_sz = cur->txn->payload_sz;
      out->meta       = cur->txn->meta;
      out->flags      = cur->txn->flags;
      out++;

      fd_txn_acct_iter_t ctrl[1];
      for( ulong i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE & FD_TXN_ACCT_CAT_IMM, ctrl ); i<fd_txn_acct_iter_end();
          i=fd_txn_acct_iter_next( i, ctrl ) ) {
        fd_acct_addr_t acct_addr = acct[i];

        fd_pack_addr_use_t * in_wcost_table = acct_uses_query( writer_costs, acct_addr, NULL );
        if( !in_wcost_table ) { in_wcost_table = acct_uses_insert( writer_costs, acct_addr );   in_wcost_table->total_cost = 0UL; }
        in_wcost_table->total_cost += cur->compute_est;

        fd_pack_addr_use_t * use = acct_uses_insert( acct_in_use, acct_addr );
        use->in_use_by = bank_tile_mask | FD_PACK_IN_USE_WRITABLE;

        use_by_bank[use_by_bank_cnt++] = *use;

        fd_pack_bitset_acct_mapping_t * q = bitset_map_query( pack->acct_to_bitset, acct[i], NULL );
        if( FD_UNLIKELY( !(--q->ref_cnt) ) ) {
          ushort bit = q->bit;
          bitset_map_remove( pack->acct_to_bitset, q );
          /* There aren't any more references to this transaction in the
             heap, so it can't cause any conflicts.  That means we
             actually don't need to record that we are using it, which
             is good because we want to release the bit. */
          FD_PACK_BITSET_CLEARN( bitset_rw_in_use, bit );
          FD_PACK_BITSET_CLEARN( bitset_w_in_use,  bit );

          use->in_use_by |= FD_PACK_IN_USE_BIT_CLEARED;
          if( FD_LIKELY( bit<FD_PACK_BITSET_MAX ) ) pack->bitset_avail[ ++(pack->bitset_avail_cnt) ] = bit;
        }
      }
      for( ulong i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_READONLY & FD_TXN_ACCT_CAT_IMM, ctrl ); i<fd_txn_acct_iter_end();
          i=fd_txn_acct_iter_next( i, ctrl ) ) {
        fd_acct_addr_t acct_addr = acct[i];

        if( fd_pack_unwritable_contains( acct+i ) ) continue; /* No need to track sysvars because they can't be writable */

        fd_pack_addr_use_t * use = acct_uses_query( acct_in_use,  acct_addr, NULL );
        if( !use ) { use = acct_uses_insert( acct_in_use, acct_addr ); use->in_use_by = 0UL; }

        if( !(use->in_use_by & bank_tile_mask) ) use_by_bank[use_by_bank_cnt++] = *use;
        use->in_use_by |= bank_tile_mask;

        fd_pack_bitset_acct_mapping_t * q = bitset_map_query( pack->acct_to_bitset, acct[i], NULL );
        if( FD_UNLIKELY( !(--q->ref_cnt) ) ) {
          ushort bit = q->bit;
          bitset_map_remove( pack->acct_to_bitset, q );
          FD_PACK_BITSET_CLEARN( bitset_rw_in_use, bit );

          use->in_use_by |= FD_PACK_IN_USE_BIT_CLEARED;
          if( FD_LIKELY( bit<FD_PACK_BITSET_MAX ) ) pack->bitset_avail[ ++(pack->bitset_avail_cnt) ] = bit;
        }
      }

      fd_ed25519_sig_t const * sig0 = fd_txn_get_signatures( txn, cur->txn->payload );

      fd_pack_sig_to_txn_t * in_tbl = sig2txn_query( pack->signature_map, sig0, NULL );
      sig2txn_remove( pack->signature_map, in_tbl );

      expq_remove( pack->expiration_q, cur->expq_idx );
      treap_ele_remove( sched_from, cur, pool );
      trp_pool_ele_release( pool, cur );
      pack->pending_txn_cnt--;

    } else if( move_delayed ) {
      /* TODO: it would be better if this took a random set bit, but I
         don't know any bit twiddling tricks to get it. */
      int r = fd_ulong_find_lsb( conflicts );
      treap_t * move_to = fd_ptr_if( delay_end_block, (treap_t*) pack->delay_end_block, pack->conflicting_with+r          );
      cur->root         = fd_int_if( delay_end_block, FD_ORD_TXN_ROOT_DELAY_END_BLOCK,  FD_ORD_TXN_ROOT_DELAY_BANK_BASE+r );

      treap_ele_remove( sched_from, cur, pool );
      treap_ele_insert( move_to,    cur, pool );
    }
  }
  FD_MCNT_INC( PACK, TRANSACTION_SKIPPED, txns_considered-txns_scheduled );
#if DETAILED_LOGGING
  FD_LOG_NOTICE(( "cu_limit: %lu, fast_path: %lu, slow_path: %lu", cu_limit_c, fast_path, slow_path ));
#else
  (void)cu_limit_c;
  (void)fast_path;
  (void)slow_path;
#endif

  pack->use_by_bank_cnt[bank_tile] = use_by_bank_cnt;
  FD_PACK_BITSET_COPY( pack->bitset_rw_in_use, bitset_rw_in_use );
  FD_PACK_BITSET_COPY( pack->bitset_w_in_use,  bitset_w_in_use  );

  sched_return_t to_return = { .cus_scheduled = cus_scheduled, .txns_scheduled = txns_scheduled };
  return to_return;
}

void
fd_pack_microblock_complete( fd_pack_t * pack,
                             ulong       bank_tile ) {
  /* Move all the transactions that were delayed until now back into
     pending so they'll be reconsidered. */
  treap_merge( pack->pending, pack->conflicting_with + bank_tile, pack->pool );

  /* If the account is in use writably, and it's in use by this banking
     tile, then this banking tile must be the sole writer to it, so it's
     always okay to clear the writable bit. */
  ulong clear_mask = ~((1UL<<bank_tile) | FD_PACK_IN_USE_WRITABLE);

  FD_PACK_BITSET_DECLARE( bitset_rw_in_use );
  FD_PACK_BITSET_DECLARE( bitset_w_in_use  );
  FD_PACK_BITSET_COPY( bitset_rw_in_use, pack->bitset_rw_in_use );
  FD_PACK_BITSET_COPY( bitset_w_in_use,  pack->bitset_w_in_use  );

  fd_pack_addr_use_t * base = pack->use_by_bank[bank_tile];
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
       of those transactions.   This unsets BIT_CLEARED for A, B.
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
    }
    use->in_use_by &= ~FD_PACK_IN_USE_BIT_CLEARED;
    if( FD_LIKELY( !use->in_use_by ) ) acct_uses_remove( pack->acct_in_use, use );
  }

  pack->use_by_bank_cnt[bank_tile] = 0UL;

  FD_PACK_BITSET_COPY( pack->bitset_rw_in_use, bitset_rw_in_use );
  FD_PACK_BITSET_COPY( pack->bitset_w_in_use,  bitset_w_in_use  );

  /* outstanding_microblock_mask never has the writable bit set, so we
     don't care about clearing it here either. */
  pack->outstanding_microblock_mask &= clear_mask;
}


ulong
fd_pack_schedule_next_microblock( fd_pack_t *  pack,
                                  ulong        total_cus,
                                  float        vote_fraction,
                                  ulong        bank_tile,
                                  fd_txn_p_t * out ) {

  /* TODO: Decide if these are exactly how we want to handle limits */
  total_cus = fd_ulong_min( total_cus, FD_PACK_MAX_COST_PER_BLOCK - pack->cumulative_block_cost );
  ulong vote_cus = fd_ulong_min( (ulong)((float)total_cus * vote_fraction), FD_PACK_MAX_VOTE_COST_PER_BLOCK - pack->cumulative_vote_cost );
  ulong vote_reserved_txns = fd_ulong_min( vote_cus/FD_PACK_TYPICAL_VOTE_COST,
                                           (ulong)((float)pack->max_txn_per_microblock * vote_fraction) );

  if( FD_UNLIKELY( pack->microblock_cnt >= pack->max_microblocks_per_block ) ) {
    FD_MCNT_INC( PACK, MICROBLOCK_PER_BLOCK_LIMIT, 1UL );
    return 0UL;
  }

  ulong cu_limit  = total_cus - vote_cus;
  ulong txn_limit = pack->max_txn_per_microblock - vote_reserved_txns;
  ulong scheduled = 0UL;

  sched_return_t status, status1;

  /* Try to schedule non-vote transactions */
  status = fd_pack_schedule_microblock_impl( pack, pack->pending,       1, cu_limit, txn_limit,          bank_tile, out+scheduled );

  scheduled += status.txns_scheduled;
  txn_limit -= status.txns_scheduled;
  cu_limit  -= status.cus_scheduled;
  pack->cumulative_block_cost += status.cus_scheduled;


  /* Schedule vote transactions */
  status1= fd_pack_schedule_microblock_impl( pack, pack->pending_votes, 0, vote_cus, vote_reserved_txns, bank_tile, out+scheduled );

  scheduled                   += status1.txns_scheduled;
  pack->cumulative_vote_cost  += status1.cus_scheduled;
  pack->cumulative_block_cost += status1.cus_scheduled;
  /* Add any remaining CUs/txns to the non-vote limits */
  txn_limit += vote_reserved_txns - status1.txns_scheduled;
  cu_limit  += vote_cus - status1.cus_scheduled;


  /* Fill any remaining space with non-vote transactions */
  status = fd_pack_schedule_microblock_impl( pack, pack->pending,       1, cu_limit, txn_limit,          bank_tile, out+scheduled );

  scheduled                   += status.txns_scheduled;
  pack->cumulative_block_cost += status.cus_scheduled;

  pack->microblock_cnt += (ulong)(scheduled>0UL);
  pack->outstanding_microblock_mask |= 1UL << bank_tile;

  /* Update metrics counters */
  FD_MGAUGE_SET( PACK, AVAILABLE_TRANSACTIONS,      pack->pending_txn_cnt                );
  FD_MGAUGE_SET( PACK, AVAILABLE_VOTE_TRANSACTIONS, treap_ele_cnt( pack->pending_votes ) );

  fd_histf_sample( pack->txn_per_microblock,  scheduled              );
  fd_histf_sample( pack->vote_per_microblock, status1.txns_scheduled );

  return scheduled;
}

ulong fd_pack_avail_txn_cnt( fd_pack_t * pack ) { return pack->pending_txn_cnt; }
ulong fd_pack_bank_tile_cnt( fd_pack_t * pack ) { return pack->bank_tile_cnt;   }

ulong
fd_pack_expire_before( fd_pack_t * pack,
                       ulong       expire_before ) {
  expire_before = fd_ulong_max( expire_before, pack->expire_before );
  ulong deleted_cnt = 0UL;
  fd_pack_expq_t * prq = pack->expiration_q;
  while( (expq_cnt( prq )>0UL) & (prq->expires_at<expire_before) ) {
    fd_pack_ord_txn_t * expired = prq->txn;

    fd_ed25519_sig_t const * expired_sig = fd_txn_get_signatures( TXN( expired->txn ), expired->txn->payload );
    /* fd_pack_delete_transaction also removes it from the heap */
    fd_pack_delete_transaction( pack, expired_sig );
    deleted_cnt++;
  }

  pack->expire_before = expire_before;
  return deleted_cnt;
}

void
fd_pack_end_block( fd_pack_t * pack ) {
  pack->microblock_cnt        = 0UL;
  pack->cumulative_block_cost = 0UL;
  pack->cumulative_vote_cost  = 0UL;

  for( ulong i=0UL; i<pack->bank_tile_cnt; i++ ) treap_merge( pack->pending, pack->conflicting_with+i, pack->pool );
  treap_merge( pack->pending, pack->delay_end_block, pack->pool );

  acct_uses_clear( pack->acct_in_use  );
  acct_uses_clear( pack->writer_costs );

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
}

static void
release_tree( treap_t           * treap,
              fd_pack_ord_txn_t * pool ) {
  treap_fwd_iter_t next;
  for( treap_fwd_iter_t it=treap_fwd_iter_init( treap, pool ); !treap_fwd_iter_idx( it ); it=next ) {
    next = treap_fwd_iter_next( it, pool );
    ulong idx = treap_fwd_iter_idx( it );
    treap_idx_remove    ( treap, idx, pool );
    trp_pool_idx_release( pool,  idx       );
  }
}

void
fd_pack_clear_all( fd_pack_t * pack ) {
  pack->pending_txn_cnt       = 0UL;
  pack->microblock_cnt        = 0UL;
  pack->cumulative_block_cost = 0UL;
  pack->cumulative_vote_cost  = 0UL;

  release_tree( pack->pending,         pack->pool );
  release_tree( pack->pending_votes,   pack->pool );
  release_tree( pack->delay_end_block, pack->pool );
  for( ulong i=0UL; i<FD_PACK_MAX_BANK_TILES; i++ ) { release_tree( pack->conflicting_with+i, pack->pool ); }

  expq_remove_all( pack->expiration_q );

  acct_uses_clear( pack->acct_in_use  );
  acct_uses_clear( pack->writer_costs );

  sig2txn_clear( pack->signature_map );

  FD_PACK_BITSET_CLEAR( pack->bitset_rw_in_use );
  FD_PACK_BITSET_CLEAR( pack->bitset_w_in_use  );
  bitset_map_clear( pack->acct_to_bitset );
  pack->bitset_avail[ 0 ] = FD_PACK_BITSET_SLOWPATH;
  for( ulong i=0UL; i<FD_PACK_BITSET_MAX; i++ ) pack->bitset_avail[ i+1UL ] = (ushort)i;
  pack->bitset_avail_cnt = FD_PACK_BITSET_MAX;

  for( ulong i=0UL; i<pack->bank_tile_cnt; i++ ) pack->use_by_bank_cnt[i] = 0UL;
}

int
fd_pack_delete_transaction( fd_pack_t              * pack,
                            fd_ed25519_sig_t const * txn ) {
  fd_pack_sig_to_txn_t * in_tbl = sig2txn_query( pack->signature_map, txn, NULL );

  if( !in_tbl )
    return 0;

  /* The static asserts enforce that the payload of the transaction is
     the first element of the fd_pack_ord_txn_t struct.  The signature
     we insert is 1 byte into the start of the payload. */
  fd_pack_ord_txn_t * containing = (fd_pack_ord_txn_t *)( (uchar*)in_tbl->key - 1UL );
  treap_t * root = NULL;
  int root_idx = containing->root;
  switch( root_idx ) {
    case FD_ORD_TXN_ROOT_FREE:             /* Should be impossible */                                                return 0;
    case FD_ORD_TXN_ROOT_PENDING:          root = pack->pending;                                                     break;
    case FD_ORD_TXN_ROOT_PENDING_VOTE:     root = pack->pending_votes;                                               break;
    case FD_ORD_TXN_ROOT_DELAY_END_BLOCK:  root = pack->delay_end_block;                                             break;
    default:                               root = pack->conflicting_with+(root_idx-FD_ORD_TXN_ROOT_DELAY_BANK_BASE); break;
  }

  fd_txn_t * _txn = TXN( containing->txn );
  fd_acct_addr_t const * accts = fd_txn_get_acct_addrs( _txn, containing->txn->payload );
  fd_txn_acct_iter_t ctrl[1];
  for( ulong i=fd_txn_acct_iter_init( _txn, FD_TXN_ACCT_CAT_WRITABLE & FD_TXN_ACCT_CAT_IMM, ctrl ); i<fd_txn_acct_iter_end();
      i=fd_txn_acct_iter_next( i, ctrl ) ) {
    fd_pack_bitset_acct_mapping_t * q = bitset_map_query( pack->acct_to_bitset, accts[i], NULL );
    FD_TEST( q ); /* q==NULL not be possible */

    q->ref_cnt--;

    if( FD_UNLIKELY( q->ref_cnt==0UL ) ) {
      ushort bit = q->bit;
      bitset_map_remove( pack->acct_to_bitset, q );

      if( FD_LIKELY( bit<FD_PACK_BITSET_MAX ) ) pack->bitset_avail[ ++(pack->bitset_avail_cnt) ] = bit;
      fd_pack_addr_use_t * use = acct_uses_query( pack->acct_in_use,  accts[i], NULL );
      if( FD_LIKELY( use ) ) {
          FD_PACK_BITSET_CLEARN( pack->bitset_rw_in_use, bit );
          FD_PACK_BITSET_CLEARN( pack->bitset_w_in_use,  bit );
          use->in_use_by |= FD_PACK_IN_USE_BIT_CLEARED;
      }
    }
  }
  for( ulong i=fd_txn_acct_iter_init( _txn, FD_TXN_ACCT_CAT_READONLY & FD_TXN_ACCT_CAT_IMM, ctrl ); i<fd_txn_acct_iter_end();
      i=fd_txn_acct_iter_next( i, ctrl ) ) {
    if( FD_UNLIKELY( fd_pack_unwritable_contains( accts+i ) ) ) continue;

    fd_pack_bitset_acct_mapping_t * q = bitset_map_query( pack->acct_to_bitset, accts[i], NULL );
    FD_TEST( q ); /* q==NULL not be possible */

    q->ref_cnt--;

    if( FD_UNLIKELY( q->ref_cnt==0UL ) ) {
      ushort bit = q->bit;
      bitset_map_remove( pack->acct_to_bitset, q );

      if( FD_LIKELY( bit<FD_PACK_BITSET_MAX ) ) pack->bitset_avail[ ++(pack->bitset_avail_cnt) ] = bit;
      fd_pack_addr_use_t * use = acct_uses_query( pack->acct_in_use,  accts[i], NULL );
      if( FD_LIKELY( use ) ) {
          FD_PACK_BITSET_CLEARN( pack->bitset_rw_in_use, bit );
          use->in_use_by |= FD_PACK_IN_USE_BIT_CLEARED;
      }
    }
  }
  expq_remove( pack->expiration_q, containing->expq_idx );
  treap_ele_remove( root, containing, pack->pool );
  trp_pool_ele_release( pack->pool, containing );
  sig2txn_remove( pack->signature_map, in_tbl );
  pack->pending_txn_cnt--;

  return 1;
}


void * fd_pack_leave ( fd_pack_t * pack ) { FD_COMPILER_MFENCE(); return (void *)pack; }
void * fd_pack_delete( void      * mem  ) { FD_COMPILER_MFENCE(); return mem;          }
