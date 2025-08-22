#include "fd_rdisp.h"

/* The conflict graph that this file builds is not a general DAG, but
   the union of several special account-conflict graphs.  Each
   account-conflict graph has special structure:
                           ---> 3 --
                          /          \
                         /            v
               1  ---> 2 -----> 4 --> 6 ----> 7
                        \             ^
                         \           /
                          ----> 5 --

   That is, the graph is almost a line, but may have fan-out and fan-in
   regions.  The tricky part about representing a graph like this
   without dynamic memory allocation is that nodes may have arbitrary
   in-degree and out-degree.  Thus, we use a pretty standard trick and
   use sibling pointers, denoted below with dotted lines.  Each node
   maintains at most one successor pointer and at most one sibling
   pointer.  Although not shown below, the sibling pointers are
   circularly linked, so 5's sibling is 3.  Additionally, though not
   shown below, the child of the last node (7) stores information about
   what account address all this is for, which facilitates deleting the
   last node in the graph.


                             ---> 3 --
                            /     :    \
                           /      V     v
                 1  ---> 2        4 --> 6 ----> 7
                                  :     ^
                                  V    /
                                  5 --

   The normal edge 2->3 along with the sibling edge 3..>4 implies a
   normal edge 2->4.  That then transitively implies an edge 2->5.

   We want each node to maintain a count of its in-degree so that we
   know when it can be executed.  The implied edges also count for the
   in-degree.  In this example, node 1 has in-degree 0, node 6 has
   in-degree 3, and the rest have in-degree 1.

   Maintaining each account-conflict graph is relatively easy given the
   operations we want to support.  Only the details about sibling edges
   are worth mentioning.  For example, when deleting node 2, we
   decrement the in-degree count for its successor, and then follow the
   sibling pointers, decrementing all the in-degree counts as we go to
   mark the deletion of the implied edges.

   When building the graph, we maintain a map of account to the last
   node that references it, whether that was a read or write, and
   whether there are any writers to that account in the graph right now.
   If the new node reads from an account that was last read, the new
   node becomes a sibling of the last read, with in-degree increased if
   there are any writers.  Otherwise, it becomes a successor of the node
   that last referenced the account. */

/* For a task like this with lots of graph traversal and pointer
   chasing, performance is typically limited by memory latency.  That
   means that the more that can fit in cache, the better the
   performance.  This implementation uses a lot of bit-packing to
   improve cache footprint. */

/* The following structs are all very local to this compilation unit,
   and so they don't have globally acceptable type names (e.g.
   fd_replay_disp_edge2_t). */

/* Everything is set up to allow this to be 128, but we can save the
   space until it's necessary. */
#define MAX_ACCT_PER_TXN 64UL

/* edge_t: Fields typed edge_t are actually a bitfield, but C bitfields
   are gross, so we just do it manually with macros.  If the high bit is
   set, that means it's the last in the DAG, and the lower 31 bits are
   an index in the map_pool for the pubkey that points to it.  If the
   high bit is not set, then the next 23 bits are the transaction index,
   and the lowest 8 bits are the edge number within that transaction of
   the edge that corresponds to the same account address as this edge.
   Because the max depth is 2^23-1, and each transaction can reference
   128 accounts, the max accounts that can be referenced fits in 30
   bits.
   The proper type would be something like
   typedef union {
     struct {
       uint is_last:1;
       uint map_pool_idx:31;
     } last;
     struct {
       uint is_last:1;
       uint txn_idx:23;
       uint edge_idx:8;
     } e;
   } edge_t;

   */
typedef uint edge_t;

#define EDGE_IS_LAST(x) ((x)&0x80000000U)
/* FOLLOW_EDGE must not be called on last */
#define FOLLOW_EDGE(base, x) (__extension__({ uint __e = (x); ((base)+(__e>>8))->edges + (__e & 0xFFU); }))
#define FOLLOW_EDGE_TXN(base, x) ( (base)+((x)>>8) )

struct edge2 {
  edge_t child;
  edge_t sibli;
};
typedef struct edge2 edge2_t;

/* txn_node_t is the representation of a transaction as a node in the
   DAG. */
struct fd_rdisp_txn {
  /* in_degree: in the worst case, all the other transactions in the
     pool read from each of the max number of accounts that this
     transaction writes to,  so there are MAX_ACCT_LOCKS*depth edges
     that come into this node, which is less than UINT_MAX.  If
     in_degree == UINT_MAX, it means the transaction is not staged. */
  uint    in_degree;

  /* score: integer part stores how many transactions in the block must
     have completed before this transaction can be scheduled.  This is
     useful for transactions marked as serializing.  The fractional part
     gives some measure of how urgent the transaction is, where lower is
     better.  This means we can't have more transactions in a block
     marked as serializing than the first integer that a float cannot
     represent.  That value is about 16M, which is much higher than the
     maximum number of transactions in a block, so this is not a
     problem.  If in the very rare case that there are more than just a
     few serializing transactions, we will lose a bit of precision for
     the fractional portion, which makes total sense; if there's not
     much room for parallel execution, having the optimal parallel
     execution is not very important. */
  float   score;

  /* edge_cnt_etc:
     0xFFFFFE00 (23 bits) for linear block number,
     0x00000180 (2 bits) for concurrency lane,
     0x0000007F (7 bits) for edge_cnt
     If UNSTAGED or FREE, the next pointer is also here. */
  uint    edge_cnt_etc;

  edge2_t edges[MAX_ACCT_PER_TXN]; /* addressed [0, edge_cnt) */
};
typedef struct fd_rdisp_txn fd_rdisp_txn_t;

/* The pool and slist are almost the same, but they are used
   differently, so keep them as different structures for now. */

#define POOL_NAME     pool
#define POOL_T        fd_rdisp_txn_t
#define POOL_IDX_T    uint
#define POOL_NEXT     edge_cnt_etc
#define POOL_SENTINEL 1
#include "../../util/tmpl/fd_pool.c"

#define SLIST_NAME unstaged_txn_ll
#define SLIST_ELE_T fd_rdisp_txn_t
#define SLIST_IDX_T uint
#define SLIST_NEXT edge_cnt_etc
#include "../../util/tmpl/fd_slist.c"


/* ACCT_INFO_FLAG: It's a bit unfortunate that we have to maintain these
   flags, but basically we need to be able to distinguish the case where
   there are only readers so that we don't increment in_degree when
   adding a new txn_node.  If we have any writers, the only way to
   transition into a state where there are only readers is to complete
   the last writer.  We know we are in this case when the completed
   node's child doesn't have a child, and the completed node's child is
   a reader, as indicated by the LAST_REF_WAS_WRITE bit.
   LAST_REFERENCE_WAS_WRITE also has the advantage of being easy to
   maintain. */
#define ACCT_INFO_FLAG_LAST_REF_WAS_WRITE(lane) (((uchar)1)<<(2*(lane)))
#define ACCT_INFO_FLAG_ANY_WRITERS(       lane) (((uchar)2)<<(2*(lane)))

/* acct_info_t is a node in a map_chain that contains the metadata for a
   single account address's conflict graph DAG.  In particular, it
   contains the information needed to know where to insert a node that
   reads from or writes to the account.  The objects of this type follow
   this state machine:

                 FREE  -----> ACTIVE ----> CACHED
                                ^            |
                                |-------------
   When FREE, it is in free_acct_dlist only.  When ACTIVE, it is in
   acct_map only.  When CACHED, it is in both free_acct_dlist and
   cached_acct_map.
*/
struct acct_info {
  /* key, next, and prev are the map_chain fields. Used in the ACTIVE
     and CACHED states.  next and prev set to 0 when in the FREE state.
     Element 0 is a sentinel and isn't inserted to the free_acct_dlist,
     so this is unambiguous. */
  fd_acct_addr_t key;
  uint next;
  uint prev;

  union {
    struct {
      /* This is effectively a pointer to the last node in the DAG for
         this pubkey, one for each staging lane.
         EDGE_IS_LAST(FOLLOW_EDGE(base, last_reference[i])) is non-zero.
         */
      edge_t last_reference[4];

    }; /* When in the ACTIVE state */
    struct {
      uint free_ll_next;
      uint free_ll_prev;
      /* 8 bytes of padding here */
    }; /* When not in the ACTIVE state, used by the free_acct_dlist */
  };
  /* flags: a combination of ACCT_INFO_FLAG_* bitfields above.  Used
     when ACTIVE. */
  uint flags:8;


  /* We want to dispatch the READY transactions in an order that
     maximizes parallelism, but we also want to be able to start
     dispatching transactions decently well before we have the full
     conflict graph.  We can do that because we know that contentious
     accounts tend to stay contentious and uncontentious accounts tend
     to stay uncontentious.

     To accomplish this, we maintain a special EMA.  Let x_i be 1 if
     transaction i references it and 0 if not.  If we squint and assume
     the transactions are independent and all drawn from some
     distribution (which is not true, but that's why we squint), an EMA
     of x_i estimates the probability that the next transaction
     references this account.  How we use this value is detailed later.

     We can't update this value for every pubkey for each transaction,
     so we maintain it in a lazy way, by applying updates only when we
     need to read the value, which also happens to be every time we want
     to add a 1 value to the EMA.  We then just need to maintain the
     last index i at which x_i was updated and the current value.  We
     only have 24 bits for the index, which means that we can't maintain
     it in a fork-aware way, which doesn't seem like a problem.  Also,
     it's possible it can overflow, and that can result in an incorrect
     value, but that means the account is only referenced ~ 1/2^24
     transactions, which is also fine.

     last_ref is in the domain of global_inserted_txn_cnt.  ema_refs is
     in [0, 1].  Both fields are used in ACTIVE and CACHED.  Maintaining
     these fields is actually the main reason CACHED exists. */
  uint   last_ref:24;
  float  ema_refs;
};
typedef struct acct_info acct_info_t;

FD_STATIC_ASSERT( sizeof(acct_info_t)==64UL, acct_info_t );

/* For the acct_map and the free_acct_map */
#define MAP_NAME          acct_map
#define MAP_ELE_T         acct_info_t
#define MAP_IDX_T         uint
#define MAP_KEY_T         fd_acct_addr_t
#define MAP_KEY_HASH(k,s) fd_hash( (s), (k)->b, 32UL )
#define MAP_KEY_EQ(k0,k1) (!memcmp( (k0)->b, (k1)->b, 32UL ))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"


#define DLIST_IDX_T uint
#define DLIST_PREV  free_ll_prev
#define DLIST_NEXT  free_ll_next
#define DLIST_NAME  free_dlist
#define DLIST_ELE_T acct_info_t
#include "../../util/tmpl/fd_dlist.c"


struct pending_prq_ele {
  /* lower score means should be scheduled sooner.  Integer part has a
     special meaning as explained above. */
  float score;

  uint linear_block_number;
  uint txn_idx;

  /* It seems like we should be able to get this whole struct in 8
     bytes, but we're a few bits over.

     23 bits for txn_idx
     22 bit for compressed_block_number, maybe as low as 10-16 bits
        would be okay
     Then the integer part of the score needs to be at least 18 or 19
     bits, but we can't use a custom floating point number. */
};

typedef struct pending_prq_ele pending_prq_ele_t;


#define PRQ_NAME pending_prq
#define PRQ_T    pending_prq_ele_t
#define PRQ_EXPLICIT_TIMEOUT 0
/* returns 1 if x is strictly after y */
#define PRQ_AFTER(x,y) (__extension__( {                                            \
            int cmp0 = (int)(x).linear_block_number - (int)(y).linear_block_number; \
            fd_int_if( cmp0!=0, cmp0>0, (x).score>(y).score );                      \
            }))
#include "../../util/tmpl/fd_prq.c"

/* fd_rdisp_blockinfo_t maintains a little metadata about transactions for each
   slot.  It's primary use is to identify when we've finished
   dispatching transactions for slot N so that we know to pause until
   the slot is advanced before dispatching transactions for slot N+1. */
struct fd_rdisp_blockinfo {
  FD_RDISP_BLOCK_TAG_T block;
  uint  linear_block_number;

  uint  insert_ready:1;
  uint  schedule_ready:1;
  uint  staged:1;
  uint  staging_lane:2; /* ignored if staged==0 */
  uint  last_insert_was_serializing:1;

  uint inserted_cnt;
  uint dispatched_cnt;
  uint completed_cnt;
  uint last_serializing;

  uint map_chain_next;
  uint ll_next;
  unstaged_txn_ll_t ll[ 1 ]; /* used only when unstaged */
};
typedef struct fd_rdisp_blockinfo fd_rdisp_blockinfo_t;

#define POOL_NAME     block_pool
#define POOL_T        fd_rdisp_blockinfo_t
#define POOL_IDX_T    uint
#define POOL_NEXT     ll_next
#define POOL_SENTINEL 1
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  block_map
#define MAP_ELE_T fd_rdisp_blockinfo_t
#define MAP_KEY_T FD_RDISP_BLOCK_TAG_T
#define MAP_KEY   block
#define MAP_NEXT  map_chain_next
#define MAP_IDX_T uint
#include "../../util/tmpl/fd_map_chain.c"

#define SLIST_NAME  block_slist
#define SLIST_ELE_T fd_rdisp_blockinfo_t
#define SLIST_IDX_T uint
#define SLIST_NEXT  ll_next
#include "../../util/tmpl/fd_slist.c"

struct fd_rdisp_unstaged {
  FD_RDISP_BLOCK_TAG_T block;

  uint writable_cnt;
  uint readonly_cnt;
  fd_acct_addr_t keys[MAX_ACCT_PER_TXN];
};
typedef struct fd_rdisp_unstaged fd_rdisp_unstaged_t;

typedef struct {
  pending_prq_ele_t * pending;
  ulong               linear_block_number;
  block_slist_t       block_ll[1];
  ulong               inserted_cnt;
  ulong               dispatched_cnt;
  ulong               completed_cnt;
} per_lane_info_t;

/* We maintain two maps from pubkeys to acct_info_t.  The first one is
   the main acct_map, just called acct_map.  All pubkeys in this map
   have >0 references in the one of the staging lane DAGs.  When an
   account goes to 0 references, it gets removed from main map_chain and
   moved to free map_chain, called free_acct_map.  The free_acct_map
   exists to maintain the reference count EMA information lazily.
   Unless we need the acct_info_t for something in the DAG, we might as
   well maintain the EMA info.

   When we start up, all the acct_info_t structs are in the
   free_acct_dlist.  Whenever something is added to the free_acct_map,
   it's also added to the tail of the free_acct_dlist.  When we need an
   acct_info_t that's not in the free_acct_map, we pop the head of the
   free_acct_dlist.  In general, the free_acct_dlist contains everything
   in the free_acct_map, potentially plus some elements that have never
   been used; all acct_info_t objects are in exactly one of the main
   acct_map and the free_acct_dlist (not free_acct_map).  See
   acct_info_t for more information about this. */

struct fd_rdisp {
  ulong depth;
  ulong block_depth;

  ulong global_insert_cnt;
  ulong unstaged_lblk_num;

  /* pool: an fd_pool, indexed [0, depth+1), with 0 being a sentinel */
  fd_rdisp_txn_t       * pool;
  fd_rdisp_unstaged_t  * unstaged; /* parallel to pool with additional info */

  block_map_t          * blockmap; /* map chain */
  fd_rdisp_blockinfo_t * block_pool;

  int free_lanes; /* a bitmask */
  per_lane_info_t lanes[4];

  acct_map_t   * acct_map;
  acct_map_t   * free_acct_map;
  /* acct_pool is not an fd_pool, but is just a flat array, since we
     don't need to acquire and release from it because of the dlist. */
  acct_info_t  * acct_pool;
  free_dlist_t   free_acct_dlist[1];
};

typedef struct fd_rdisp fd_rdisp_t;


 #define ACCT_ITER_TO_PTR( iter ) (__extension__( {                                             \
       ulong __idx = fd_txn_acct_iter_idx( iter );                                              \
       fd_ptr_if( __idx<fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM ), accts, alt_adj )+__idx; \
       }))
// 
// ulong
// fd_replay_disp_add_txn( fd_replay_disp_t     * disp,
//                         fd_txn_t const       * txn,
//                         uchar const          * payload,
//                         fd_acct_addr_t const * alt_expanded ) {
// 
//   ulong in_degree = 0UL;
// 
//   fd_acct_addr_t const * accts   = fd_txn_get_acct_addrs( txn, payload );
//   /* alt_adj is the pointer to the ALT expansion, adjusted so that if
//      account address n is the first that comes from the ALT, it can be
//      accessed with adj_lut[n]. */
//   fd_acct_addr_t const * alt_adj = alt_expanded - fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM );
// 
//   for( fd_txn_acct_iter_t iter=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE );
//       iter!=fd_txn_acct_iter_end(); iter=fd_txn_acct_iter_next( iter ) ) {
//     fd_acct_addr_t const * acct = ACCT_ITER_TO_PTR( iter );
//     acct_info_t * a_info = acct_map_ele_query( disp->acct_map, acct, NULL, disp->acct_pool );
//     if( FD_LIKELY( a_
// 
//   }




//FIXME: Make sure this is the largest alignment
ulong fd_rdisp_align( void ) { return alignof(fd_rdisp_t); }

ulong
fd_rdisp_footprint( ulong depth,
                    ulong block_depth ) {
  if( FD_UNLIKELY( (depth>FD_RDISP_MAX_DEPTH) | (block_depth>FD_RDISP_MAX_BLOCK_DEPTH) ) ) return 0UL;

  ulong chain_cnt      = block_map_chain_cnt_est( block_depth );
  ulong acct_depth     = depth*MAX_ACCT_PER_TXN;
  ulong acct_chain_cnt = acct_map_chain_cnt_est( acct_depth );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_rdisp_align(),             sizeof(fd_rdisp_t)                              );
  l = FD_LAYOUT_APPEND( l, pool_align(),                 pool_footprint              ( depth+1UL       ) ); /* pool       */
  l = FD_LAYOUT_APPEND( l, alignof(fd_rdisp_unstaged_t), sizeof(fd_rdisp_unstaged_t)*( depth+1UL       ) ); /* unstaged   */
  l = FD_LAYOUT_APPEND( l, block_map_align(),            block_map_footprint         ( chain_cnt       ) ); /* blockmap   */
  l = FD_LAYOUT_APPEND( l, block_pool_align(),           block_pool_footprint        ( block_depth+1UL ) ); /* block_pool */
  l = FD_LAYOUT_APPEND( l, pending_prq_align(),          4UL*pending_prq_footprint   ( depth           ) ); /* pending    */
  l = FD_LAYOUT_APPEND( l, acct_map_align(),             acct_map_footprint          ( acct_chain_cnt  ) ); /* acct_map   */
  l = FD_LAYOUT_APPEND( l, acct_map_align(),             acct_map_footprint          ( acct_chain_cnt  ) ); /* free_acct_map */
  l = FD_LAYOUT_APPEND( l, alignof(acct_info_t),         (acct_depth+1UL)*sizeof(acct_info_t)            ); /* acct_pool  */
  return FD_LAYOUT_FINI( l, fd_rdisp_align() );
}

void *
fd_rdisp_new( void * mem,
              ulong  depth,
              ulong  block_depth ) {
  if( FD_UNLIKELY( (depth>FD_RDISP_MAX_DEPTH) | (block_depth>FD_RDISP_MAX_BLOCK_DEPTH) ) ) return NULL;

  ulong chain_cnt      = block_map_chain_cnt_est( block_depth );
  ulong acct_depth     = depth*MAX_ACCT_PER_TXN;
  ulong acct_chain_cnt = acct_map_chain_cnt_est( acct_depth );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_rdisp_t * disp   = FD_SCRATCH_ALLOC_APPEND( l, fd_rdisp_align(),             sizeof(fd_rdisp_t)                              );
  void  * _pool       = FD_SCRATCH_ALLOC_APPEND( l, pool_align(),                 pool_footprint              ( depth+1UL       ) );
  void  * _unstaged   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rdisp_unstaged_t), sizeof(fd_rdisp_unstaged_t)*( depth+1UL       ) );
  void  * _bmap       = FD_SCRATCH_ALLOC_APPEND( l, block_map_align(),            block_map_footprint         ( chain_cnt       ) );
  void  * _bpool      = FD_SCRATCH_ALLOC_APPEND( l, block_pool_align(),           block_pool_footprint        ( block_depth+1UL ) );
  uchar * _pending    = FD_SCRATCH_ALLOC_APPEND( l, pending_prq_align(),          4UL*pending_prq_footprint   ( depth           ) );
  void  * _acct_map   = FD_SCRATCH_ALLOC_APPEND( l, acct_map_align(),             acct_map_footprint          ( acct_chain_cnt  ) );
  void  * _freea_map  = FD_SCRATCH_ALLOC_APPEND( l, acct_map_align(),             acct_map_footprint          ( acct_chain_cnt  ) );
  acct_info_t * apool = FD_SCRATCH_ALLOC_APPEND( l, alignof(acct_info_t),         (acct_depth+1UL)*sizeof(acct_info_t)            );
  FD_SCRATCH_ALLOC_FINI( l, fd_rdisp_align() );

  disp->depth             = depth;
  disp->block_depth       = block_depth;
  disp->global_insert_cnt = 0UL;
  disp->unstaged_lblk_num = 0UL;

  pool_new( _pool, depth );
  memset( _unstaged, '\0', sizeof(fd_rdisp_unstaged_t)*(depth+1UL) );

  ulong seed = (ulong)fd_tickcount(); /* TODO: better seed */
  block_map_new ( _bmap,  chain_cnt, seed );
  block_pool_new( _bpool, block_depth+1UL );

  disp->free_lanes = 0xF;
  for( ulong i=0UL; i<4UL; i++ ) {
    pending_prq_new( _pending, depth );
    _pending += pending_prq_footprint( depth );

    disp->lanes[i].linear_block_number = 0UL;
    disp->lanes[i].inserted_cnt        = 0U;
    disp->lanes[i].dispatched_cnt      = 0U;
    disp->lanes[i].completed_cnt       = 0U;
  }

  acct_map_new( _acct_map,  acct_chain_cnt, fd_ulong_hash( seed+1UL ) );
  acct_map_new( _freea_map, acct_chain_cnt, fd_ulong_hash( seed+2UL ) );

  free_dlist_t * temp_join = free_dlist_join( free_dlist_new( disp->free_acct_dlist ) );
  for( ulong i=1UL; i<acct_depth+1UL; i++ ) {
    apool[ i ].next = apool[ i ].prev = 0U;
    free_dlist_idx_push_tail( disp->free_acct_dlist, i, apool );
  }
  free_dlist_leave( temp_join );

  return disp;
}

fd_rdisp_t *
fd_rdisp_join( void * mem ) {
  fd_rdisp_t * disp = (fd_rdisp_t *)mem;

  ulong depth          = disp->depth;
  ulong block_depth    = disp->block_depth;
  ulong chain_cnt      = block_map_chain_cnt_est( block_depth );
  ulong acct_depth     = depth*MAX_ACCT_PER_TXN;
  ulong acct_chain_cnt = acct_map_chain_cnt_est( acct_depth );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  /*                 */ FD_SCRATCH_ALLOC_APPEND( l, fd_rdisp_align(),             sizeof(fd_rdisp_t)                              );
  void  * _pool       = FD_SCRATCH_ALLOC_APPEND( l, pool_align(),                 pool_footprint              ( depth+1UL       ) );
  void  * _unstaged   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rdisp_unstaged_t), sizeof(fd_rdisp_unstaged_t)*( depth+1UL       ) );
  void  * _bmap       = FD_SCRATCH_ALLOC_APPEND( l, block_map_align(),            block_map_footprint         ( chain_cnt       ) );
  void  * _bpool      = FD_SCRATCH_ALLOC_APPEND( l, block_pool_align(),           block_pool_footprint        ( block_depth+1UL ) );
  uchar * _pending    = FD_SCRATCH_ALLOC_APPEND( l, pending_prq_align(),          4UL*pending_prq_footprint   ( depth           ) );
  void  * _acct_map   = FD_SCRATCH_ALLOC_APPEND( l, acct_map_align(),             acct_map_footprint          ( acct_chain_cnt  ) );
  void  * _freea_map  = FD_SCRATCH_ALLOC_APPEND( l, acct_map_align(),             acct_map_footprint          ( acct_chain_cnt  ) );
  acct_info_t * apool = FD_SCRATCH_ALLOC_APPEND( l, alignof(acct_info_t),         (acct_depth+1UL)*sizeof(acct_info_t)            );
  FD_SCRATCH_ALLOC_FINI( l, fd_rdisp_align() );

  disp->pool       = pool_join( _pool );
  disp->unstaged   = (fd_rdisp_unstaged_t *)_unstaged;
  disp->blockmap   = block_map_join( _bmap );
  disp->block_pool = block_pool_join( _bpool );

  for( ulong i=0UL; i<4UL; i++ ) {
    disp->lanes[i].pending = pending_prq_join( _pending );
    _pending += pending_prq_footprint( depth );
  }

  disp->acct_map      = acct_map_join( _acct_map );
  disp->free_acct_map = acct_map_join( _freea_map );
  disp->acct_pool     = apool;
  free_dlist_join( disp->free_acct_dlist );

  return disp;
}

static inline void
free_lane( fd_rdisp_t * disp,
           ulong        staging_lane ) {
  disp->free_lanes |= 1<<staging_lane;
  per_lane_info_t * l = disp->lanes+staging_lane;
  FD_TEST( pending_prq_cnt( l->pending )==0UL );
  l->linear_block_number = 0UL;
  l->inserted_cnt   = 0UL;
  l->dispatched_cnt = 0UL;
  l->completed_cnt  = 0UL;
  block_slist_delete( block_slist_leave( l->block_ll ) );
}

static inline void
alloc_lane( fd_rdisp_t * disp,
            ulong        staging_lane ) {
  disp->free_lanes &= ~(1<<staging_lane);
  block_slist_join( block_slist_new( disp->lanes[staging_lane].block_ll ) );
}

int
fd_rdisp_add_block( fd_rdisp_t          * disp,
                   FD_RDISP_BLOCK_TAG_T   new_block,
                   ulong                  staging_lane ) {
  fd_rdisp_blockinfo_t * block_pool = disp->block_pool;

  if( FD_UNLIKELY( !block_pool_free( block_pool )                                                             ) ) return -1;
  if( FD_UNLIKELY(  ULONG_MAX!=block_map_idx_query_const( disp->blockmap, &new_block, ULONG_MAX, block_pool ) ) ) return -1;
  fd_rdisp_blockinfo_t * block = block_pool_ele_acquire( block_pool );
  block->block = new_block;
  block_map_ele_insert( disp->blockmap, block, block_pool );

  block->insert_ready = 1;
  block->staged       = staging_lane!=FD_RDISP_UNSTAGED;
  block->staging_lane = (uint)(staging_lane & 0x3UL);
  block->last_insert_was_serializing = 0U;

  block->inserted_cnt     = 0U;
  block->dispatched_cnt   = 0U;
  block->completed_cnt    = 0U;
  block->last_serializing = 0U;

  if( FD_UNLIKELY( staging_lane==FD_RDISP_UNSTAGED ) ) {
    block->schedule_ready = 1;
    block->linear_block_number = (uint)disp->unstaged_lblk_num++;
    unstaged_txn_ll_join( unstaged_txn_ll_new( block->ll ) );
  } else {
    block->linear_block_number = (uint)disp->lanes[staging_lane].linear_block_number++;
    block->schedule_ready      = (uint)(1 & (disp->free_lanes >> staging_lane));

    if( FD_LIKELY( disp->free_lanes & (1<<staging_lane) ) ) alloc_lane( disp, staging_lane );

    block_slist_t * sl = disp->lanes[staging_lane].block_ll;
    if( FD_LIKELY( !block_slist_is_empty( sl, block_pool ) ) )  block_slist_ele_peek_tail( sl, block_pool )->insert_ready = 0;
    block_slist_ele_push_tail( sl, block, block_pool );
  }
  return 0;
}



int
fd_rdisp_remove_block( fd_rdisp_t          * disp,
                       FD_RDISP_BLOCK_TAG_T   block_tag ) {
  fd_rdisp_blockinfo_t * block_pool = disp->block_pool;

  fd_rdisp_blockinfo_t * block   = block_map_ele_query( disp->blockmap, &block_tag, NULL, block_pool );
  if( FD_UNLIKELY( block==NULL ) ) return -1;

  FD_TEST( block->schedule_ready );
  FD_TEST( block->completed_cnt==block->inserted_cnt );

  if( FD_LIKELY( block->staged ) ) {
    ulong staging_lane = (ulong)block->staging_lane;
    block_slist_t * sl = disp->lanes[staging_lane].block_ll;

    FD_TEST( block==block_slist_ele_peek_head( sl, block_pool ) );
    block_slist_idx_pop_head( sl, block_pool );
    if( FD_LIKELY( !block_slist_is_empty( sl, block_pool ) ) ) block_slist_ele_peek_head( sl, block_pool )->schedule_ready = 1;
    else                                                       free_lane( disp, staging_lane );
  } else {
    unstaged_txn_ll_delete( unstaged_txn_ll_leave( block->ll ) );
  }
  block_pool_idx_release( block_pool, block_map_idx_remove( disp->blockmap, &block_tag, ULONG_MAX, block_pool ) );

  return 0;
}


int
fd_rdisp_abandon_block( fd_rdisp_t          * disp,
                        FD_RDISP_BLOCK_TAG_T   block_tag ) {
  fd_rdisp_blockinfo_t * block_pool = disp->block_pool;

  fd_rdisp_blockinfo_t * block   = block_map_ele_query( disp->blockmap, &block_tag, NULL, disp->block_pool );
  if( FD_UNLIKELY( block==NULL ) ) return -1;

  FD_TEST( block->schedule_ready );
  FD_TEST( block->dispatched_cnt==block->completed_cnt ); /* TODO: remove this when it can call complete properly */
  while( block->completed_cnt<block->inserted_cnt ) {
    /* because there is nothing DISPATCHED, there has to be something
       READY */
    ulong txn = fd_rdisp_get_next_ready( disp, block_tag );
    FD_TEST( txn );
    fd_rdisp_complete_txn( disp, txn );
  }

  if( FD_LIKELY( block->staged ) ) {
    ulong staging_lane = (ulong)block->staging_lane;
    block_slist_t * sl = disp->lanes[staging_lane].block_ll;

    FD_TEST( block==block_slist_ele_peek_head( sl, block_pool ) );
    block_slist_idx_pop_head( sl, block_pool );
    if( FD_LIKELY( !block_slist_is_empty( sl, block_pool ) ) ) block_slist_ele_peek_head( sl, block_pool )->schedule_ready = 1;
    else                                                       free_lane( disp, staging_lane );
  } else {
    unstaged_txn_ll_delete( unstaged_txn_ll_leave( block->ll ) );
  }
  block_pool_idx_release( disp->block_pool, block_map_idx_remove( disp->blockmap, &block_tag, ULONG_MAX, disp->block_pool ) );

  return 0;
}

static void
add_edges( fd_rdisp_t           * disp,
           fd_rdisp_txn_t       * ele,
           fd_acct_addr_t const * addr,
           ulong                  addr_cnt,
           uint                   staging_lane,
           int                    writable,
           int                    update_score );
/* updates in_degree, edge_cnt_etc */

int
fd_rdisp_promote_block( fd_rdisp_t *          disp,
                        FD_RDISP_BLOCK_TAG_T  block_tag,
                        ulong                 staging_lane ) {
  fd_rdisp_blockinfo_t * block_pool = disp->block_pool;
  per_lane_info_t * lane = disp->lanes + staging_lane;
  block_slist_t * sl = lane->block_ll;

  fd_rdisp_blockinfo_t * block   = block_map_ele_query( disp->blockmap, &block_tag, NULL, block_pool );
  if( FD_UNLIKELY( block==NULL   ) ) return -1;
  if( FD_UNLIKELY( block->staged ) ) return -1;

  block->staged = 1;
  block->staging_lane = (uint)(staging_lane & 0x3);
  block->insert_ready = 1;
  block->schedule_ready = (uint)(1 & (disp->free_lanes >> staging_lane));

  if( FD_LIKELY( disp->free_lanes & (1<<staging_lane) ) ) alloc_lane( disp, staging_lane );

  if( FD_LIKELY( !block_slist_is_empty( sl, block_pool ) ) )  block_slist_ele_peek_tail( sl, block_pool )->insert_ready = 0;
  block_slist_ele_push_tail( sl, block, block_pool );
  uint linear_block_number = (uint)lane->linear_block_number++;
  block->linear_block_number = linear_block_number;

  unstaged_txn_ll_iter_t next;
  for( unstaged_txn_ll_iter_t iter = unstaged_txn_ll_iter_init( block->ll, disp->pool );
      !unstaged_txn_ll_iter_done( iter, block->ll, disp->pool );
      iter = next ) {
      next = unstaged_txn_ll_iter_next( iter, block->ll, disp->pool );

    fd_rdisp_txn_t      * ele = unstaged_txn_ll_iter_ele( iter, block->ll, disp->pool );
    fd_rdisp_unstaged_t * uns = disp->unstaged + unstaged_txn_ll_iter_idx( iter, block->ll, disp->pool );
    FD_TEST( ele->in_degree==UINT_MAX );

    ele->in_degree    = 0U;
    ele->edge_cnt_etc = 0U;

    add_edges( disp, ele, uns->keys,                   uns->writable_cnt, (uint)staging_lane, 1, 0 );
    add_edges( disp, ele, uns->keys+uns->writable_cnt, uns->readonly_cnt, (uint)staging_lane, 0, 0 );

    ele->edge_cnt_etc |= (uint)staging_lane<<7;
    ele->edge_cnt_etc |= linear_block_number<<9;

    if( FD_UNLIKELY( ele->in_degree==0U ) ) {
      pending_prq_ele_t temp[1] = {{ .score = ele->score, .linear_block_number = linear_block_number, .txn_idx = (uint)(ele-disp->pool)}};
      pending_prq_insert( lane->pending, temp );
    }
  }
  unstaged_txn_ll_delete( unstaged_txn_ll_leave( block->ll ) );

  lane->inserted_cnt   += block->inserted_cnt;
  lane->dispatched_cnt += block->dispatched_cnt;
  lane->completed_cnt  += block->completed_cnt;

  return 0;
}

int
fd_rdisp_demote_block( fd_rdisp_t *          disp,
                       FD_RDISP_BLOCK_TAG_T  block_tag ) {
  fd_rdisp_blockinfo_t * block_pool = disp->block_pool;

  fd_rdisp_blockinfo_t * block   = block_map_ele_query( disp->blockmap, &block_tag, NULL, block_pool );
  if( FD_UNLIKELY(  block==NULL           ) ) return -1;
  if( FD_UNLIKELY( !block->staged         ) ) return -1;
  if( FD_UNLIKELY( !block->schedule_ready ) ) return -1;
  if( FD_UNLIKELY(  block->completed_cnt!=block->inserted_cnt ) ) FD_LOG_ERR(( "demote_block called with non-empty block" ));
  ulong staging_lane = block->staging_lane;
  block->staged = 0;

  per_lane_info_t * lane = disp->lanes + staging_lane;
  block_slist_t * sl = lane->block_ll;

  lane->inserted_cnt   -= block->inserted_cnt;
  lane->dispatched_cnt -= block->dispatched_cnt;
  lane->completed_cnt  -= block->completed_cnt;

  block->linear_block_number = (uint)disp->unstaged_lblk_num++;

  /* staged and schedule_ready means it must be the head of the staging lane */
  FD_TEST( block_slist_ele_peek_head( sl, block_pool )==block );
  block_slist_idx_pop_head( sl, block_pool );

  unstaged_txn_ll_join( unstaged_txn_ll_new( block->ll ) );

  if( FD_LIKELY( !block_slist_is_empty( sl, block_pool ) ) ) block_slist_ele_peek_head( sl, block_pool )->schedule_ready = 1;
  else                                                       free_lane( disp, staging_lane );
  return 0;
}

static inline float
update_ema( acct_info_t * info,
            ulong global_insert_cnt ) {
  (void)info;
  (void)global_insert_cnt;
  return 0.0f; // TODO
}

static void
add_edges( fd_rdisp_t           * disp,
           fd_rdisp_txn_t       * ele,
           fd_acct_addr_t const * addrs,
           ulong                  addr_cnt,
           uint                   lane,
           int                    writable,
           int                    update_score ) {
/* updates in_degree, edge_cnt_etc */

  for( ulong i=0UL; i<addr_cnt; i++ ) {
    fd_acct_addr_t const * addr = addrs+i;
    acct_info_t * ai = NULL;

    /* Step 1: lookup the pubkey */
    ulong idx = acct_map_idx_query( disp->acct_map, addr, ULONG_MAX, disp->acct_pool );
    if( FD_UNLIKELY( idx==ULONG_MAX ) ) {
      idx = acct_map_idx_query( disp->free_acct_map, addr, ULONG_MAX, disp->acct_pool );
      if( FD_UNLIKELY( idx==ULONG_MAX ) ) {
        /* The acct pool is sized so that the list cannot be empty at this
           point.  However, the element at the head might be the free
           map with a different pubkey. */
        idx = free_dlist_idx_peek_head( disp->free_acct_dlist, disp->acct_pool );
        ai = disp->acct_pool+idx;

        /* CACHED -> FREE transition */
        if( FD_LIKELY( ai->next!=0U ) ) acct_map_idx_remove_fast( disp->free_acct_map, idx, disp->acct_pool );

        /* FREE -> ACTIVE transition */
        ai->key      = *addr;
        ai->flags    = 0U;
        ai->last_ref = 0U;
        ai->ema_refs = 0.0f;
      } else {
        /* CACHED -> ACTIVE transition */
        ai = disp->acct_pool+idx;
        ai->flags    = 0U; /* FIXME: unnecessary */
        acct_map_idx_remove_fast( disp->free_acct_map, idx, disp->acct_pool );
      }
      /* In either case, at this point, the element is not in any map
         but is in free_acct_dlist.  It has the right key. last_ref, and
         ema_refs are valid. flags is 0. */
      free_dlist_idx_remove( disp->free_acct_dlist, idx, disp->acct_pool );
      memset( ai->last_reference, '\0', sizeof(ai->last_reference) );
      acct_map_idx_insert( disp->acct_map, idx, disp->acct_pool );
    }
    ai = disp->acct_pool+idx;
    /* At this point, in all cases, the acct_info is now in the ACTIVE
       state.  It's in acct_map, not in free_acct_map, and not in
       free_acct_dlist. */

    /* update_score should be constant propogated */
    // FIXME: This is not the right way to use the ema
    if( update_score ) ai->ema_refs = update_ema( ai, disp->global_insert_cnt );

    /* Step 2: add edge. There are 4 cases depending on whether this is
       a writer or not and whether the previous reference was a writer
       or not. */
    uint edge_cnt = ele->edge_cnt_etc & 0x7FU;

    edge2_t * pa        = FOLLOW_EDGE( disp->pool, ai->last_reference[ lane ] );
    edge2_t * me        = ele->edges + edge_cnt;
    edge_t    ref_to_me = (((uint)(ele - disp->pool))<<8) | edge_cnt;

    /* In the case that this is the first txn in the DAG, pa will point
       to edges[0] of the sentinel element, pool[0].  We don't care
       about what is stored there, so just set it up as a dummy element
       to make the rest of the code work properly in this case too.  If
       this is a read, we want me->sibli to ref_to_me in case 4; if this
       is a write, we want to set me->sibli to 0 in case 2, but we need
       to make sure pb==pa. */
    disp->pool->edges->child = (1U<<31) | (uint)idx;
    disp->pool->edges->sibli = fd_uint_if( writable, 0U, ref_to_me );

    ulong flags = ai->flags;

    if( writable ) { /* also should be known at compile time */
      if( flags & ACCT_INFO_FLAG_LAST_REF_WAS_WRITE( lane ) ) { /* unclear prob */
        /* Case 1: w-w. The parent's child field is the special last pointer,
           and pa's sibli field is 0. */
        me->child = pa->child;
        me->sibli = 0U;
        pa->child = ref_to_me;
      } else {
        /* Case 2: r-w. This is the tricky case because there could be
           multiple readers.  We need to set all the last reader's child
           pointer to me. */
        me->child = pa->child;
        me->sibli = 0U;
        pa->child = ref_to_me;
        edge2_t * pb = FOLLOW_EDGE( disp->pool, pa->sibli );
        /* Intentionally skip the first in_degree increment, because it
           will be done later */
        while( pb!=pa ) {
          pb->child = ref_to_me;
          ele->in_degree++;
          pb = FOLLOW_EDGE( disp->pool, pb->sibli );
        }
        flags |= ACCT_INFO_FLAG_LAST_REF_WAS_WRITE( lane ) | ACCT_INFO_FLAG_ANY_WRITERS( lane );
      }
    } else {
      if( flags & ACCT_INFO_FLAG_LAST_REF_WAS_WRITE( lane ) ) { /* unclear prob */
        /* Case 3: w-r. The parent's fields are in the same state as
           case 1, but the only difference is that my sibli field needs
           to be myself. */
        me->child = pa->child;
        me->sibli = ref_to_me;
        pa->child = ref_to_me;
        flags &= ~(ulong)ACCT_INFO_FLAG_LAST_REF_WAS_WRITE( lane ); /* clear bit */
      } else {
        /* Case 4: r-r. Add myself as a sibling instead of a child */
        me->child = pa->child;
        me->sibli = pa->sibli;
        pa->sibli = ref_to_me;
      }
    }

    /* Step 3: Update the final values */
    /* In general, we want to increment the in_degree unless this
       transaction is the first to reference this account.  The
       exception is that if this account has only readers, including
       this transaction, we don't want to increment the in_degree
       either.  At this point, we can tell if that is the case based on
       ANY_WRITERS.  */
    ele->in_degree += (ai->last_reference[ lane ]!=0U) & !!(flags & ACCT_INFO_FLAG_ANY_WRITERS( lane ));
    ai->last_reference[ lane ] = ref_to_me;
    ai->flags                  = (uchar)flags;
    ele->edge_cnt_etc++;  /* The edge cnt is in the low bits and can't
                            overflow, so no masks required */
  }
}


/* should be called with all writable accounts first */
static void
add_unstaged_edges( fd_rdisp_t * disp,
                    fd_rdisp_txn_t       * ele,
                    fd_rdisp_unstaged_t  * unstaged,
                    fd_acct_addr_t const * addr,
                    ulong                  addr_cnt,
                    int                    writable,
                    int                    update_score ) {
  ulong base_idx = unstaged->writable_cnt+unstaged->readonly_cnt;
  FD_TEST( !writable || unstaged->readonly_cnt==0U );
  for( ulong i=0UL; i<addr_cnt; i++ ) {
    unstaged->keys[ base_idx+i ] = addr[i];
    if( FD_LIKELY( update_score ) ) {
      ulong idx = acct_map_idx_query( disp->acct_map, addr+i, ULONG_MAX, disp->acct_pool );
      if( FD_UNLIKELY( idx==ULONG_MAX ) ) idx = acct_map_idx_query( disp->free_acct_map, addr+i, ULONG_MAX, disp->acct_pool );
      /* since these are unstaged, we don't bother moving accounts
         around */
      float score_change = 1.0f;
      if( FD_LIKELY( idx!=ULONG_MAX ) ) score_change = 1.0f - update_ema( disp->acct_pool+idx, disp->global_insert_cnt );
      ele->score *= fd_float_if( writable, score_change, 1.0f );
    }
  }
  *(fd_ptr_if( writable, &(unstaged->writable_cnt), &(unstaged->readonly_cnt) ) ) += (uint)addr_cnt;
}

ulong
fd_rdisp_add_txn( fd_rdisp_t          *  disp,
                  FD_RDISP_BLOCK_TAG_T   insert_block,
                  fd_txn_t const       * txn,
                  uchar const          * payload,
                  fd_acct_addr_t const * alts,
                  int                    serializing ) {

  fd_rdisp_blockinfo_t * block   = block_map_ele_query( disp->blockmap, &insert_block, NULL, disp->block_pool );
  if( FD_UNLIKELY( !block || !block->insert_ready ) ) return 0UL;
  if( FD_UNLIKELY( !pool_free( disp->pool       ) ) ) return 0UL;

  ulong idx = pool_idx_acquire( disp->pool );
  fd_rdisp_txn_t * rtxn = disp->pool + idx;

  fd_acct_addr_t const * imm_addrs = fd_txn_get_acct_addrs( txn, payload );

  if( FD_UNLIKELY( !block->staged ) ) {
    rtxn->in_degree = UINT_MAX;
    rtxn->score     = 0.999f;

    fd_rdisp_unstaged_t * unstaged = disp->unstaged + idx;
    unstaged->block = insert_block;
    unstaged->writable_cnt = 0U;
    unstaged->readonly_cnt = 0U;

    add_unstaged_edges( disp, rtxn, unstaged, imm_addrs,
                                                        fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE_SIGNER        ), 1, 1 );
    add_unstaged_edges( disp, rtxn, unstaged, imm_addrs+fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_SIGNER ),
                                                        fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE_NONSIGNER_IMM ), 1, 1 );
    add_unstaged_edges( disp, rtxn, unstaged, alts,
                                                        fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE_ALT ),           1, 1 );
    add_unstaged_edges( disp, rtxn, unstaged, imm_addrs+fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE_SIGNER ),
                                                        fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_READONLY_SIGNER        ), 0, 1 );
    add_unstaged_edges( disp, rtxn, unstaged, imm_addrs+fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_SIGNER | FD_TXN_ACCT_CAT_WRITABLE_NONSIGNER_IMM ),
                                                        fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_READONLY_NONSIGNER_IMM ), 0, 1 );
    add_unstaged_edges( disp, rtxn, unstaged, alts     +fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE_ALT ),
                                                        fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_READONLY_ALT ),           0, 1 );

    unstaged_txn_ll_ele_push_tail( block->ll, rtxn, disp->pool );
  } else {
    uint lane = block->staging_lane;

    rtxn->in_degree    = 0U;
    rtxn->score        = 0.999f;
    rtxn->edge_cnt_etc = (block->linear_block_number<<9) | (lane<<7);

    add_edges( disp, rtxn, imm_addrs,
                                     fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE_SIGNER        ), lane, 1, 1 );
    add_edges( disp, rtxn, imm_addrs+fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE_SIGNER ),
                                     fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_READONLY_SIGNER        ), lane, 0, 1 );
    add_edges( disp, rtxn, imm_addrs+fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_SIGNER ),
                                     fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE_NONSIGNER_IMM ), lane, 1, 1 );
    add_edges( disp, rtxn, imm_addrs+fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_SIGNER | FD_TXN_ACCT_CAT_WRITABLE_NONSIGNER_IMM ),
                                     fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_READONLY_NONSIGNER_IMM ), lane, 0, 1 );
    add_edges( disp, rtxn, alts,
                                     fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE_ALT ),           lane, 1, 1 );
    add_edges( disp, rtxn, alts     +fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE_ALT ),
                                     fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_READONLY_ALT ),           lane, 0, 1 );
  }

  if( FD_UNLIKELY( serializing | block->last_insert_was_serializing ) ) {
    block->last_serializing = block->inserted_cnt;
  }
  block->last_insert_was_serializing = (uint)!!serializing;
  rtxn->score += (float)block->last_serializing;

  block->inserted_cnt++;
  disp->global_insert_cnt++;

  if( FD_LIKELY( (block->staged) & (rtxn->in_degree==0U) ) ) {
    pending_prq_ele_t temp[1] = {{ .score = rtxn->score, .linear_block_number = block->linear_block_number, .txn_idx = (uint)idx }};
    pending_prq_insert( disp->lanes[ block->staging_lane ].pending, temp );
  }

  return idx;
}

ulong
fd_rdisp_get_next_ready( fd_rdisp_t           * disp,
                         FD_RDISP_BLOCK_TAG_T   schedule_block ) {
  fd_rdisp_blockinfo_t * block   = block_map_ele_query( disp->blockmap, &schedule_block, NULL, disp->block_pool );
  if( FD_UNLIKELY( !block || !block->schedule_ready ) ) return 0UL;

  ulong idx;
  if( FD_LIKELY( block->staged ) ) {
    ulong staging_lane = block->staging_lane;
    per_lane_info_t * l = disp->lanes + staging_lane;

    if( FD_UNLIKELY( !pending_prq_cnt( l->pending )                                ) ) return 0UL;
    if( FD_UNLIKELY( l->pending->linear_block_number != block->linear_block_number ) ) return 0UL;
    /* e.g. when completed_cnt==0, we can accept any score below 1.0 */
    if( FD_UNLIKELY( l->pending->score>=(float)(block->completed_cnt+1U)           ) ) return 0UL;
    idx = l->pending->txn_idx;
    pending_prq_remove_min( l->pending );
  } else {
    if( FD_UNLIKELY( block->dispatched_cnt!=block->completed_cnt       ) ) return 0UL;
    if( FD_UNLIKELY( unstaged_txn_ll_is_empty( block->ll, disp->pool ) ) ) return 0UL;
    idx = unstaged_txn_ll_idx_peek_head( block->ll, disp->pool );
  }
  block->dispatched_cnt++;

  return idx;
}

void
fd_rdisp_complete_txn( fd_rdisp_t * disp,
                       ulong        txn_idx ) {

  fd_rdisp_txn_t * rtxn = disp->pool + txn_idx;

  if( FD_UNLIKELY( rtxn->in_degree==UINT_MAX ) ) {
    /* Unstaged */
    fd_rdisp_blockinfo_t * block = block_map_ele_query( disp->blockmap, &disp->unstaged[ txn_idx ].block, NULL, disp->block_pool );
    FD_TEST( rtxn==unstaged_txn_ll_ele_peek_head( block->ll, disp->pool ) );
    unstaged_txn_ll_ele_pop_head( block->ll, disp->pool );
    block->completed_cnt++;
  } else {
    /* Staged */
    ulong edge_cnt = rtxn->edge_cnt_etc      & 0x7FU;
    ulong lane     = (rtxn->edge_cnt_etc>>7) & 0x3U;
    for( ulong i=0UL; i<edge_cnt; i++ ) {
      edge2_t const * e  = rtxn->edges+i;
      edge_t  const   e0 = e->child;
      if( FD_UNLIKELY( EDGE_IS_LAST( e0 ) ) ) {
        ulong acct_idx = e0 & 0x7FFFFFFFU;
        acct_info_t * ai = disp->acct_pool + acct_idx;
        ai->last_reference[ lane ] = 0U;

        /* Potentially transition from ACTIVE -> CACHED */
        if( FD_UNLIKELY( (ai->last_reference[ 0 ]==0U)&(ai->last_reference[ 1 ]==0U)&
                         (ai->last_reference[ 2 ]==0U)&(ai->last_reference[ 3 ]==0U) ) ) {
          ai->flags = 0;
          acct_map_idx_remove_fast( disp->acct_map,      acct_idx, disp->acct_pool );
          acct_map_idx_insert     ( disp->free_acct_map, acct_idx, disp->acct_pool );
        }
      } else {
        edge_t next_e = e->child;
        edge2_t const * child_edge;
        do {
          /*            */ child_edge = FOLLOW_EDGE(     disp->pool, next_e );
          fd_rdisp_txn_t * child_txn  = FOLLOW_EDGE_TXN( disp->pool, next_e );
          next_e = child_edge->sibli;
          FD_TEST( child_txn->in_degree>0U );
          if( FD_UNLIKELY( 0U==(--(child_txn->in_degree)) ) ) {
            pending_prq_ele_t temp[1] = {{ .score               = child_txn->score,
                                           .linear_block_number = child_txn->edge_cnt_etc>>9,
                                           .txn_idx             = (uint)(child_txn-disp->pool) }};
            pending_prq_insert( disp->lanes[ lane ].pending, temp );
          }
        } while( (next_e>0U) & (next_e!=e0) );

        if( FD_UNLIKELY( EDGE_IS_LAST( child_edge->child ) ) ) {
          /* There's either exactly one writer and no readers left in
             the DAG or there are 0 writers and >=1 readers left in the
             DAG.  Either way, we want to set ANY_WRITERS to
             LAST_REF_WAS_WRITER. */
          acct_info_t * ai = disp->acct_pool + (child_edge->child & 0x7FFFFFFFU);
          ulong flags = ai->flags;
          flags &= ~(ulong)ACCT_INFO_FLAG_ANY_WRITERS( lane );
          flags |= (flags & ACCT_INFO_FLAG_LAST_REF_WAS_WRITE( lane ))<<1;
          ai->flags = (uchar)flags;
        }
      }
    }
    block_slist_ele_peek_head( disp->lanes[ lane ].block_ll, disp->block_pool )->completed_cnt++;
  }
}


ulong
fd_rdisp_staging_lane_info( fd_rdisp_t           const * disp,
                            fd_rdisp_staging_lane_info_t out_sched[ static 4 ] ) {
  (void)out_sched; /* TODO: poplulate */
  return 0xFUL & ~(ulong)disp->free_lanes;
}

void * fd_rdisp_leave ( fd_rdisp_t * disp ) { return disp; }
void * fd_rdisp_delete( void * mem        ) { return  mem; }
