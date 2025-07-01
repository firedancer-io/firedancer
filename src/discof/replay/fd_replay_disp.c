
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


/* The following structs are all very local to this compilation unit,
   and so they don't have globally acceptable type names (e.g.
   fd_replay_disp_edge2_t). */

/* edge_t: Fields typed edge_t are actually a bitfield, but C bitfields
   are gross, so we just do it manually with macros.  If the high bit is
   set, that means it's the last in the DAG, and the lower 31 bits are
   an index in the map_pool for the pubkey that points to it.  If the
   high bit is not set, then the next 23 bits are the transaction index,
   and the lowest 8 bits are the edge number within that transaction of
   the edge that corresponds to the same account address as this edge.
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
  edge_t neigh;
};
typedef struct edge2 edge2_t;

/* txn_node_t is the representation of a transaction as a node in the
   DAG. */
struct txn_node {
  /* in_degree: in the worst case, all the other transactions in the
     pool read from each of the max number of accounts that this
     transaction writes to,  so there are MAX_ACCT_LOCKS*depth edges
     that come into this node, which is less than UINT_MAX. */
  uint    in_degree;
  float   score;
  uint    edge_cnt; /* also stores concurrency lane */
  edge2_t edges[128]; /* addressed [0, edge_cnt) */
};
typedef struct txn_node txn_node_t;

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
#define ACCT_INFO_FLAG_LAST_REF_WAS_WRITE ((uchar)1)
#define ACCT_INFO_FLAG_ANY_WRITERS        ((uchar)2)

/* acct_info_t is a node in a map_chain that contains the metadata for a
   single account address's conflict graph DAG.  In particular, it
   contains the information needed to know where to insert a node that
   reads from or writes to the account. */
struct acct_info {
  fd_pubkey_t key;
  uint next;
  uint prev;

  union {
    struct {
      /* This is effectively a pointer to the last node in the DAG for
         this pubkey.  EDGE_IS_LAST(FOLLOW_EDGE(base, last_reference))
         is non-zero. */
      edge_t last_reference;

      /* flags: a combination of ACCT_INFO_FLAG_* bitfields above. */
      uchar flags;
      /* 3 bytes and 6 bits of unused space here */

    }; /* When in the main map_chain */
    struct {
      uint free_ll_next;
      uint free_ll_prev;
    }; /* When not in the main map_chain */
  };


  /* We want to dispatch the READY transactions in an order that
     maximizes parallelism, but we also want to be able to start
     dispatching transactions decently well before we have the full
     conflict graph.  We can do that because we know that contentious
     accounts tend to stay contentious and uncontentious accounts tend
     to stay uncontentious.  To that end, we maintain an EMA of the
     number of transactions that touch the account per block.  This kind
     of EMA needs 3 variables: the current value, an accumulator for the
     current block, and some kind of indicator of how old the current
     block is.  When adding a new transaction, if the transaction is in
     the same block as the accumulator, it's just an increment.  If it's
     in a different block, then we mix the accumulator into the EMA
     value and reset the accumulator before incrementing. */
  ushort compressed_slotidx;
  ushort ref_cnt;
  float  ema_refs;
};
typedef acct_info acct_info_t;

/* For the acct_map and the free_acct_map */
#define MAP_NAME          acct_map
#define MAP_ELE_T         acct_info_t
#define MAP_IDX_T         uint
#define MAP_KEY_T         fd_pubkey_t
#define MAP_KEY_HASH(k,s) fd_hash( (s), (k)->b, 32UL )
#define MAP_KEY_EQ(k0,k1) (!memcmp((*(k0))->b, (*(k1))->b, 32UL))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"


#define DLIST_IDX_T uint
#define DLIST_PREV  free_ll_prev
#define DLIST_NEXT  free_ll_next
#define DLIST_NAME  free_dlist
#define DLIST_ELE_T acct_info_t
#include "../../util/tmpl/fd_dlist.c"


/* For the freelist of txn indices */
#define QUEUE_NAME txn_freelist
#define QUEUE_T    uint
#include "util/tmpl/fd_queue.c"


struct pending_prq_ele {
  /* higher score means should be scheduled sooner */
  float score;

  /* idx_slot: The high 23 bits are the transaction index.  The low 9
     bits are the compressed slot index.  As long as the pending
     transactions span less than 256 slots, we can always tell which one
     is actually the lower number, in spite of overflow:
        slot1 = slot1_hi * 2^9 + slot1_lo, where slot1_lo in [0, 2^9)
        slot2 = slot2_hi * 2^9 + slot2_lo, where slot2_lo in [0, 2^9)
     Put x = slot1-slot2.  |x|<2^8, which means x can be identified
     uniquely by knowing its equivalence class mod 2^9.

     x = slot1-slot2 = (slot1_hi-slot2_hi)*2^9 + slot1_lo - slot2_lo
               == slot1_lo - slot2_lo  (mod 2^9)

     However, C's % operator is a bit funky when it comes to negative
     numbers.  x+256 is strictly positive, so we can compute the
     equivalence class of x+256 with bitwise operations.
     Then consider the cases:
        -2^8<x<0:
             Then 0<x+256<256,
             so   0<(slot1_lo-slot2_lo+256) & (2^9-1)<256
         x==0:
             Then x+256==256,
             so   (slot1_lo-slot2_lo+256) & (2^9-1) == 256
         0<x<2^8:
             Then 256<x+256<2^9,
             so   256<(slot1_lo-slot2_lo+256) & (2^9-1)<2^9.

     If we're only interested in returning the right sign, ala strcmp,
     then ((slot1_lo - slot2_lo + 256) & (2^9-1))-256 gives the right
     answer. */

  uint  idx_slot;
};

typedef struct pending_prq_ele pending_prq_ele_t;


#define PRQ_NAME pending_prq
#define PRQ_T    pending_prq_ele_t
#define PRQ_EXPLICIT_TIMEOUT 0
#define PRQ_AFTER(x,y) (__extension__( {                   \
            uint __slot1_lo = x.idx_slot & 0x1FFU;         \
            uint __slot2_lo = y.idx_slot & 0x1FFU;         \
            int slot_cmp = -256 + (int)(((256U + slot1_lo - slot2_lo) & ((1U<<9)-1U))); \
            fd_int_if( slot_cmp!=0, slot_cmp>0, x.score<y.score ); \
            }))

/* per_slot_t maintains a little metadata about transactions for each
   slot.  It's primary use is to identify when we've finished
   dispatching transactions for slot N so that we know to pause until
   the slot is advanced before dispatching transactions for slot N+1. */
struct per_slot {
  ulong slot_idx; /* the compressed slot_idx */
  ulong opaque_slot_number;
  ulong inserted_cnt;
  ulong dispatched_cnt;
};
typedef struct per_slot per_slot_t;


/* We maintain two maps from pubkeys to acct_info_t.  The first one is
   the main acct_map, just called acct_map.  All pubkeys in this map
   have >0 references in the current DAG.  When an account goes to 0
   references, it gets removed from main map_chain and moved to free
   map_chain, called free_acct_map.  The free_acct_map exists to
   maintain the reference count EMA information lazily.  Unless we need
   the acct_info_t for something in the DAG, we might as well maintain
   the EMA info.

   When we start up, all the acct_info_t structs are in the
   free_acct_dlist.  Whenever something is added to the free_acct_map,
   it's also added to the tail of the free_acct_dlist.  When we need an
   acct_info_t that's not in the free_acct_map, we pop the head of the
   free_acct_dlist.  In general, the free_acct_dlist contains everything
   in the free_acct_map, potentially plus some elements that have never
   been used; all acct_info_t objects are in exactly one of the main
   acct_map and the free_acct_dlist (not free_acct_map). */

struct fd_replay_disp {
  acct_map_t   * acct_map;
  acct_map_t   * free_acct_map;
  acct_info_t  * acct_pool;
  free_dlist_t * free_acct_dlist;

  ulong        max_txns;
  txn_node_t * txns; /* indexed [0, max_txns), with 0 being a sentinel */
  uint       * txn_freelist; /* an fd_queue_dynamic */

  pending_prq_ele_t * pending_prq;
  per_slot_t * per_slot_q; /* an fd_queue_dynamic */
};


e = 2*( 1 bit is last, 23 bits txn idx, 8 bits edge num )

base_ptr + (129*8)*(x>>8) + 8 + 8*(x&0xFF)

If high bit set for child, then 31 bits are index in map

#define ACCT_ITER_TO_PTR( iter ) (__extension__( {                                             \
      ulong __idx = fd_txn_acct_iter_idx( iter );                                              \
      fd_ptr_if( __idx<fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM ), accts, alt_adj )+__idx; \
      }))

ulong
fd_replay_disp_add_txn( fd_replay_disp_t     * disp,
                        fd_txn_t const       * txn,
                        uchar const          * payload,
                        fd_acct_addr_t const * alt_expanded ) {

  ulong in_degree = 0UL;

  fd_acct_addr_t const * accts   = fd_txn_get_acct_addrs( txn, payload );
  /* alt_adj is the pointer to the ALT expansion, adjusted so that if
     account address n is the first that comes from the ALT, it can be
     accessed with adj_lut[n]. */
  fd_acct_addr_t const * alt_adj = alt_expanded - fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM );

  for( fd_txn_acct_iter_t iter=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE );
      iter!=fd_txn_acct_iter_end(); iter=fd_txn_acct_iter_next( iter ) ) {
    fd_acct_addr_t const * acct = ACCT_ITER_TO_PTR( iter );
    acct_info_t * a_info = acct_map_ele_query( disp->acct_map, acct, NULL, disp->acct_pool );
    if( FD_LIKELY( a_

  }
Adding:

iterate over all accounts. Look up in map.
If account in map:
  them-me

  r-r:
    copy their child, sibling to my child field, sibling field
    clear their child field
    set their sibling to me

  w-r:
    copy their child to my child field
    set their child to me
    set my sibling field to myself
    clear last_reference_was_write

  w-w:
    copy their child to my child field
    set my sibling to 0
    set their child to me

  r-w:
    copy their child to my child field
    set my sibling to 0
    set last_reference_was_write
    set any_writers
    increment writer_cnt
    inital_them = them
    while true {
      set their child to me
      increment my in_degree
      if their sibling is initial_them, break
      them = their sibling
    }

 set last_reference to me
 increment my in_degree unless any_writers==0 and r-r

If account not in map:
 insert into map
 set my child to 1<<31 | map slot id
 if read, set sibling to myself
 if write, set sibling to 0
 set any_writers, last_reference_was_write

If in_degree is 0 in the end, add to ready queue



Scheduling:
Pop something from ready list if anything


Completing:
iterate over all edges

If I have a child, decrement their in_degree
Do the same for any siblings of child
If my child's "child" is the map field, set any_writers to last_reference_was_write

If I don't have a child, delete from map



When trying to allocate an account, call map_remove on it in the free list.
If hit, remove from free_list.
Otherwise, remove the head of the free_list.
  If free_next != UINT_MAX, remove it
