#include "fd_rdisp.h"
#include "fd_rdisp_mq.h"
#include "../../util/fd_hash32.h"
#include <math.h> /* for the EMA */

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


                              --> 3 --
                             /    ^   \
                            /     :    \
                           /      V     v
                 1  ---> 2        4 --> 6 ----> 7
                                  ^     ^
                                  :    /
                                  V   /
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
   mark the deletion of the implied edges.  Sibling edges also need to
   be doubly linked, so that e.g. nodes 3 and 5 can be re-linked in O(1)
   if node 4 is deleted.  They're also circularly linked as well for
   convenience.

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
   fd_rdisp_edge_t). */

#define MAX_ACCT_PER_TXN FD_TXN_ACCT_ADDR_MAX
FD_STATIC_ASSERT( MAX_ACCT_PER_TXN<=128UL, max_acct_per_txn );

/* edge_t: Fields typed edge_t represent an edge in one of the parallel
   account-conflict DAGs.  Each transaction stores a list of all its
   outgoing edges.  The type is actually a union of bitfield, but C
   bitfields are gross, so we just do it manually with macros.
   If the high bit is not set, then the next 23 bits store the
   destination of the edge, represented by its index in the pool of
   transactions.  Then the lowest 8 bits store the account index within
   that transaction of the edge that is part of the same
   account-specific DAG as this edge.  Because the max depth is 2^23-1,
   and each transaction can reference FD_TXN_ACCT_ADDR_MAX accounts,
   the max accounts that can be referenced fits in 30 bits.

   If the high bit is set, the second highest bit indicates whether it's
   a pseudo transaction or if the transaction storing this edge_t value
   is the last in this specific DAG.  Either way, the lower 30 bits of
   the value are the index.  This index is in the map_pool for the
   account pubkey for this DAG if it's a final transaction, and an index
   into the pseudo transaction pool if it's a pseudo-transaction.  See
   the comments about the hidden edge outgoing from node 7 in the DAG at
   the top of this file for an example.
   Because the max depth is 2^23-1, and each transaction can reference
   128 accounts, the max accounts that can be referenced fits in 30
   bits.
   The proper type would be something like
   typedef union {
     struct {
       uint is_special:1; // == 0
       uint txn_idx:23;
       uint acct_idx:8;
     } e;
     struct {
       uint is_special:1; // == 1
       uint is_last:1;    // == 1
       uint map_pool_idx:30;
     } last;
     struct {
       uint is_special:1; // == 1
       uint is_last:1;    // == 0
       uint pseudo_txn_idx:30;
     } pseudo;
   } edge_t;

   */
typedef uint edge_t;

#define EDGE_SPECIAL_PTXN     0x80000000U
#define EDGE_SPECIAL_LAST     0xC0000000U
#define EDGE_SPECIAL_MASK     0xC0000000U

#define EDGE_IS_LAST(x)        (((x)&EDGE_SPECIAL_MASK)==EDGE_SPECIAL_LAST)
#define EDGE_IS_PTXN(x)        (((x)&EDGE_SPECIAL_MASK)==EDGE_SPECIAL_PTXN)
#define EDGE_SPECIAL_IDX(x)    ((x)&(~EDGE_SPECIAL_MASK))
#define EDGE_MAKE_SPECIAL(k,x) ((x)|FD_CONCAT2(EDGE_SPECIAL_,k))

FD_STATIC_ASSERT( MAX_ACCT_PER_TXN<=128UL, max_acct_per_txn );

/* fd_rdisp_txn is the representation of a transaction as a node in the
   DAG. */
struct fd_rdisp_txn {
  /* in_degree: The total number of edges summed across all account DAGs
     with this node as their destination.  In the worst case, all the
     other transactions in the pool read from each of the max number of
     accounts that this transaction writes to,  so there are
     FD_RDISP_MAX_ACCT_PER_TXN*depth edges that come into this node,
     which fits in about 30 bits, so we have some room for special
     values.  If in_degree is one of the following values, then the
     transaction is: */
#define IN_DEGREE_FREE                (UINT_MAX   )
#define IN_DEGREE_UNSTAGED            (UINT_MAX-1U)/* unstaged, not dispatched */
#define IN_DEGREE_DISPATCHED          (UINT_MAX-2U)/* staged,   dispatched */
#define IN_DEGREE_UNSTAGED_DISPATCHED (UINT_MAX-3U)/* unstaged, dispatched */
#define IN_DEGREE_ZOMBIE              (UINT_MAX-4U)/* zombie */
  /* a transaction that is staged and dispatched is must have an
     in_degree of 0.  in_degree isn't a meaningful concept for unstaged
     transactions. */
  uint    in_degree;

  /* score: integer part stores how many transactions in the block must
     have completed before this transaction can be scheduled.  This is
     useful for transactions marked as serializing.  The fractional part
     gives some measure of how urgent the transaction is, where lower is
     more urgent.  This means we can't have more transactions in a block
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
     0xFFFF0000 (16 bits) for linear block number,
     0x0000C000 (2 bits) for concurrency lane,
     0x00003F80 (7 bits) for r_cnt
     0x0000007F (7 bits) for w_cnt_1.  Transactions have at least one
     writable account and at most MAX_ACCT_PER_TXN total accounts, so
     storing w_cnt_1 = w_cnt - 1 fits in 7 bits. */
  union {
    uint edge_cnt_etc;
    /* edge_cnt_etc is only used when the transaction is STAGED and
       PENDING, READY, or DISPATCHED.  If UNSTAGED or FREE, the next
       pointer is also here.  It can't be UNSTAGED and FREE at the same
       time, so there's no conflict with storage there either. */
    uint unstaged_next;
    uint free_next;
    /* If ZOMBIE, pointer back to block is here.  No storage conflict
       because ZOMBIE is an exclusive state. */
    uint block_idx;
  };


  /* When a transaction writes to an account, it only creates one
     link.  When a transaction reads from an account, we need the full
     doubly linked list with its siblings, so it creates 3 edges
     (child, next, prev).  All edges from writable accounts come first,
     and we keep track of how many there are.  In the worst case, all
     accounts are reads, so we size it appropriately. */
  edge_t edges[3UL*FD_RDISP_MAX_ACCT_PER_TXN]; /* addressed [0, w_cnt_1+1+3*r_cnt) */
};
typedef struct fd_rdisp_txn fd_rdisp_txn_t;

struct fd_rdisp_ptxn {
  /* These fields have the same meaning as in fd_rdisp_txn_t */
  uint  in_degree;
  float score;
  union {
    uint edge_cnt_etc; /* r_cnt == 1 and w_cnt_1 is 0x7F, but ignored */
    uint free_next;
  };
  /* The whole reason for the difference between a normal transaction
     and a pseudo-transaction is that this array can be a lot smaller.
     */
  edge_t edges[3];
  /* last maps back to the account for which this pseudo-transaction is an
     LtHash addition task.  It's normally the same as edges[0], but if a
     writer is added after this pseudo-transaction is added (for
     example, in the next block), then edges[0] may have a different
     value, but we still need to be able to map back to the account
     address. */
  edge_t last;
};
typedef struct fd_rdisp_ptxn fd_rdisp_ptxn_t;

#define POOL_NAME  ptxn_pool
#define POOL_NEXT  free_next
#define POOL_IDX_T uint
#define POOL_T     fd_rdisp_ptxn_t
#include "../../util/tmpl/fd_pool.c"

/* Two more definitions:
   An edge index is an array position within the edges array.  An
   account index is a position within a transaction's account addresses,
   reordered so that the writable ones come first.  Since writable
   accounts use one position in the edges array per account address,
   these often coincide. */


/* FOLLOW_EDGE and FOLLOW_EDGE_TXN are helper macros for dealing with
   edges.  Given an edge_t x, and rdisp disp, FOLLOW_EDGE_TXN
   returns a pointer to transaction that the edge points to; FOLLOW_EDGE
   returns a pointer to the (first) edge_t within that transaction that
   is part of the same DAG as this edge.  FOLLOW_EDGE and
   FOLLOW_EDGE_TXN must not be called if EDGE_IS_LAST is non-zero.

   Then the edge index, i.e. the position in the edges array of the
   (first) edge for an account index is:
          acct_idx                              if acct_idx<=w_cnt_1
          w_cnt_1+1 + 3*(acct_idx-w_cnt_1-1)    else.
  Simplifying gives
         acct_idx + 2*signed_max( 0, acct_idx-w_cnt_1-1 ).
  If the edge points to a pseudo-transaction, then __w_cnt_1 is a
  garbage value, but __idx is forced to 0, which means its value is not
  used.
  In doing this calculation, we also basically get for free whether the
  edge is for a writable account or a readonly account, so we return
  that as well via the w parameter.  If the child transaction only reads
  the account address for this DAG, then the next and prev pointers can
  be accessed using the returned value +1 and +2, respectively. */
#define FOLLOW_EDGE(disp, x, w) (__extension__({                                                                     \
        fd_rdisp_t const * __disp = (disp);                                                                          \
        uint __e = (x);                                                                                              \
        fd_rdisp_txn_t * __txn = EDGE_IS_PTXN(__e) ? (fd_rdisp_txn_t *)((__disp)->ptxn_pool+EDGE_SPECIAL_IDX(__e)) : \
                                                     ((__disp)->pool+(__e>>8));                                      \
        uint __w_cnt_1 = __txn->edge_cnt_etc & 0x7FU;                                                                \
        uint __idx  = fd_uint_if( EDGE_IS_PTXN(__e), 0U, (__e & 0xFFU) );                                            \
        (w) = (!EDGE_IS_PTXN(__e)) & (__idx<=__w_cnt_1);                                                             \
        (void)(w);  /* not robust... */                                                                              \
        __txn->edges + __idx + 2*fd_int_max( 0, (int)(__idx)-(int)(__w_cnt_1)-1 ); }))

#define FOLLOW_EDGE_TXN(disp, x) (__extension__({                                                                    \
        fd_rdisp_t const * __disp = (disp);                                                                          \
        uint __e = (x);                                                                                              \
        EDGE_IS_PTXN(__e) ? (fd_rdisp_txn_t *)((__disp)->ptxn_pool+EDGE_SPECIAL_IDX(__e)) :                          \
                            ((__disp)->pool+(__e>>8)); }))



/* The pool and slist are almost the same, but they are used
   differently, so keep them as different structures for now. */

#define POOL_NAME     pool
#define POOL_T        fd_rdisp_txn_t
#define POOL_IDX_T    uint
#define POOL_NEXT     free_next
#define POOL_SENTINEL 1
#include "../../util/tmpl/fd_pool.c"

#define SLIST_NAME unstaged_txn_ll
#define SLIST_ELE_T fd_rdisp_txn_t
#define SLIST_IDX_T uint
#define SLIST_NEXT  unstaged_next
#include "../../util/tmpl/fd_slist.c"

#define DLIST_IDX_T uint
#define DLIST_PREV  edges[0]
#define DLIST_NEXT  edges[1]
#define DLIST_NAME  zombie_dlist
#define DLIST_ELE_T fd_rdisp_txn_t
#include "../../util/tmpl/fd_dlist.c"


/* ACCT_INFO_STATE: We need to keep just a little metadata about writers
   in the DAG for an account.  In particular, for correctness, we need
   to be able to distinguish the case where there are only readers so
   that we don't increment in_degree when adding a new fd_rdisp_txn.  If
   we have any writers, the only way to transition into a state where
   there are only readers is to complete the last writer.  We know we
   are in this case when the completed node's child doesn't have a
   child, and the completed node's child is a reader, as indicated by
   the LAST_REF_WAS_WRITE bit.  LAST_REF_WAS_WRITE also has the
   advantage of being easy to maintain.  You'd think with those two
   binary states we'd have used up our 2 bits, but actually, there are
   only states there, which means we can almost cram in a little more
   information for free.  In particular, whether we need to create a
   LtHash addition hash is also very related to ANY_WRITERS and
   LAST_REF_WAS_WRITE, via the state machine below, which has only 5
   accessible states out of 8 possible states (we can add a reader or
   writer from any state. If there are any writers, we can complete the
   last writer. If it needs an LtHash add pseudo transaction, then we
   may add a pseudo transaction).

         add reader
         |--------|
         V        |
      0-----------------
      | No writers,    |<-------------------------------------------
      | which implies  |                                           |
      | LRWW==0 and    |<---------------------------------         |
      | NEEDS_LTADD==0 |     complete last writer        |         |
      ------------------                                 |         |
              |                                          |         |
          add |             complete last writer         |         |
       writer |       -----------------------------------+-------  |
              V       |                                  |      |  |
      1-----------------        add writer               |      |  |
      | ANY_WRITERS==1 |<---------------------------|    |      |  |
   |->| LRWW==1 and    |------------------------    |    |      |  |
   |  | NEEDS_LTADD==1 |<---|        add pseudo|    |    |      |  |
   |  ------------------    | add          txn |    |    |      |  |
   |         ^  |     |     | writer           V    |    |      |  |
   |         |  |     |-----|          2*--------------------   |  |
   |     add |  | add                  | Last is pseudo txn |   |  |
   |  writer |  | reader           |-->| ANY_WRITERS==1     |   |  |
   |         |  V              add |   | LRWW==0 and        |   |  |
   |  2-----------------    reader |---| NEEDS_LTADD==0     |   |  |
   |  | ANY_WRITERS==1 |               ----------------------   |  |
   |  | LRWW==0 and    |                        ^               |  |
   |  | NEEDS_LTADD==1 |------------------------|               |  |
   |  ------------------     add pseudo txn                     |  |
   |     |        ^  |                                          |  |
   |     |        |  |                                          |  |
   |     ----------  |                3------------------       |  |
   |     add reader  |                | ANY_WRITERS==0  |       |  |
   |                 ---------------->| LRWW==0 and     |<-------  |
   |                   complete last  | NEEDS_LTADD==1  |-----------
   |                      writer      ------------------- add pseudo
   |                                   |   |        ^       txn
   |       add writer                  |   |        |
   |------------------------------------   ----------
                                           add reader

   Sadly, we still only have 2 bits, so we collapse the top-left and
   bottom right states into one state.  The only difference between the
   two states is whether it is possible to add a pseudo-txn, and that's
   driven by the rdisp_mq anyway. */
/*                                                 AW  LRWW   NLT */
#define ACCT_INFO_STATE_NO_WRITERS             0U /*0    0      0  */
#define ACCT_INFO_STATE_LAST_REF_WAS_WRITE     1U /*1    1      1  */
#define ACCT_INFO_STATE_LAST_REF_WAS_READ      2U /*1    0      ?  */
#define ACCT_INFO_STATE_NEEDS_PTXN             3U /*0    0      1  */

#define ACCT_INFO_STATE_IS( val, lane, state) ( (((val)>>(2U*(lane)))&3) == FD_CONCAT2(ACCT_INFO_STATE_, state) )
#define ACCT_INFO_STATE_SET(val, lane, state) (((val) & (uchar)(~(3U<<(2U*(lane))))) | (uchar)(FD_CONCAT2(ACCT_INFO_STATE_, state)<<(2U*(lane))) )


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
   cached_acct_map. */

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
         EDGE_IS_LAST(FOLLOW_EDGE(disp, last_reference[i])) is non-zero.
         */
      edge_t last_reference[4];

    }; /* When in the ACTIVE state */
    struct {
      uint free_ll_next;
      uint free_ll_prev;
      /* 8 bytes of padding here */
    }; /* When not in the ACTIVE state, used by the free_acct_dlist */
  };
  /* states: a combination of ACCT_INFO_STATE fields above.  Used when
     ACTIVE. */
  uint states:8;


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
#define MAP_KEY_HASH(k,s) fd_hash32( (k)->b, (s) )
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
     16 bit for linear_block_number
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

/* We need yet another data structure to keep track of accounts that
   need LtHash addition tasks for unstaged transactions.  These are part
   of a map keyed by (block, acct), as stored in ustlt_key_t so that we
   can quickly query whether the account address is "new" (in the sense
   explained in the header).  In addition to possibly being part of the
   map, these are also part of one of several linked lists: FREE,
   NEEDED, CREATED.  When in the CREATED state and list, there's a
   pseudo-txn with a last field pointing to it.  When in the NEEDED
   state and list, it's part of the map_chain.  Technically FREE could
   be an slist/fd_pool, but it's easier to reason about correctness when
   each element is in exactly one of three lists at all times. */
typedef struct {
  uint           block_idx;
  fd_acct_addr_t acct;
} ustlt_key_t;

struct ustlt {
  ustlt_key_t key;
  uint map_prev;
  uint map_next;
  uint ll_prev;
  uint ll_next;
  uint ptxn_idx; /* when CREATED */
};
typedef struct ustlt ustlt_t;

#define MAP_NAME  ustlt_map
#define MAP_ELE_T ustlt_t
#define MAP_IDX_T uint
#define MAP_KEY_T ustlt_key_t
#define MAP_NEXT  map_next
#define MAP_PREV  map_prev
#define MAP_KEY_HASH(k,s) fd_hash32( (k)->acct.b, (s)+((k)->block_idx) )
#define MAP_KEY_EQ(a,b)   (0==memcmp( (a), (b), sizeof(ustlt_key_t) ))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  ustlt_dlist
#define DLIST_ELE_T ustlt_t
#define DLIST_IDX_T uint
#define DLIST_PREV  ll_prev
#define DLIST_NEXT  ll_next
#include "../../util/tmpl/fd_dlist.c"



/* fd_rdisp_blockinfo_t maintains a little metadata about transactions for each
   slot.  */
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
  zombie_dlist_t    zombie_list[ 1 ];
  /* When unstaged: */
  unstaged_txn_ll_t ll[ 1 ];
  ustlt_dlist_t     ustlt_needed[ 1 ];
  ustlt_dlist_t     ustlt_created[ 1 ];
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
  uint block_idx;

  uint writable_cnt;
  uint readonly_cnt;
  fd_acct_addr_t keys[FD_RDISP_MAX_ACCT_PER_TXN];
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
  /* ptxn_pool: an fd_pool, also indexed [0, depth*128+1), with 0 as a
     sentinel. */
  fd_rdisp_ptxn_t      * ptxn_pool;
  fd_rdisp_mq_t        * mq;

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

  /* Unfortunately, the LtHash info for unstaged transactions needs to
     be stored completely separately. */
  ustlt_t          * ustlt_pool; /* a flat array, not an fd_pool */
  ustlt_map_t      * ustlt_map;
  ustlt_dlist_t      ustlt_free[ 1 ];
};

typedef struct fd_rdisp fd_rdisp_t;


 #define ACCT_ITER_TO_PTR( iter ) (__extension__( {                                             \
       ulong __idx = fd_txn_acct_iter_idx( iter );                                              \
       fd_ptr_if( __idx<fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM ), accts, alt_adj )+__idx; \
       }))

#define MAX_WRITERS_PER_BLOCK 245376UL /* floor(75M/(128*300+720))*128 */

ulong fd_rdisp_align( void ) { return 128UL; }

ulong
fd_rdisp_footprint( ulong depth,
                    ulong block_depth ) {
  if( FD_UNLIKELY( (depth>FD_RDISP_MAX_DEPTH)             | (depth<2UL) |
                   (block_depth>FD_RDISP_MAX_BLOCK_DEPTH) | (block_depth<4UL) ) ) return 0UL;

  ulong chain_cnt      = block_map_chain_cnt_est( block_depth );
  ulong acct_depth     = depth*FD_RDISP_MAX_ACCT_PER_TXN;
  ulong acct_chain_cnt = acct_map_chain_cnt_est( acct_depth );
  ulong mq_footprint   = fd_rdisp_mq_footprint( acct_depth, MAX_WRITERS_PER_BLOCK );
  ulong full_depth     = depth*(FD_RDISP_MAX_ACCT_PER_TXN+1UL); /* normal and pseudo transactions */

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_rdisp_align(),             sizeof(fd_rdisp_t)                              );
  l = FD_LAYOUT_APPEND( l, pool_align(),                 pool_footprint              ( depth+1UL       ) ); /* pool       */
  l = FD_LAYOUT_APPEND( l, alignof(fd_rdisp_unstaged_t), sizeof(fd_rdisp_unstaged_t)*( depth+1UL       ) ); /* unstaged   */
  l = FD_LAYOUT_APPEND( l, ptxn_pool_align(),            ptxn_pool_footprint         ( acct_depth+1UL  ) ); /* ptxn_pool  */
  l = FD_LAYOUT_APPEND( l, fd_rdisp_mq_align(),          mq_footprint                                    ); /* mq         */
  l = FD_LAYOUT_APPEND( l, block_map_align(),            block_map_footprint         ( chain_cnt       ) ); /* blockmap   */
  l = FD_LAYOUT_APPEND( l, block_pool_align(),           block_pool_footprint        ( block_depth+1UL ) ); /* block_pool */
  l = FD_LAYOUT_APPEND( l, pending_prq_align(),          4UL*pending_prq_footprint   ( full_depth      ) ); /* pending    */
  l = FD_LAYOUT_APPEND( l, acct_map_align(),             acct_map_footprint          ( acct_chain_cnt  ) ); /* acct_map   */
  l = FD_LAYOUT_APPEND( l, acct_map_align(),             acct_map_footprint          ( acct_chain_cnt  ) ); /* free_acct_map */
  l = FD_LAYOUT_APPEND( l, alignof(acct_info_t),         (acct_depth+1UL)*sizeof(acct_info_t)            ); /* acct_pool  */
  l = FD_LAYOUT_APPEND( l, alignof(ustlt_t),             (acct_depth+1UL)*sizeof(ustlt_t)                ); /* ustlt_pool */
  l = FD_LAYOUT_APPEND( l, ustlt_map_align(),            ustlt_map_footprint         ( acct_chain_cnt  ) ); /* ustlt_map  */
  return FD_LAYOUT_FINI( l, fd_rdisp_align() );
}

void *
fd_rdisp_new( void * mem,
              ulong  depth,
              ulong  block_depth,
              ulong  seed ) {
  if( FD_UNLIKELY( (depth>FD_RDISP_MAX_DEPTH)             | (depth<2UL) |
                   (block_depth>FD_RDISP_MAX_BLOCK_DEPTH) | (block_depth<4UL) ) ) return NULL;

  ulong chain_cnt      = block_map_chain_cnt_est( block_depth );
  ulong acct_depth     = depth*FD_RDISP_MAX_ACCT_PER_TXN;
  ulong acct_chain_cnt = acct_map_chain_cnt_est( acct_depth );
  ulong mq_footprint   = fd_rdisp_mq_footprint( acct_depth, MAX_WRITERS_PER_BLOCK );
  ulong full_depth     = depth*(FD_RDISP_MAX_ACCT_PER_TXN+1UL);

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_rdisp_t * disp   = FD_SCRATCH_ALLOC_APPEND( l, fd_rdisp_align(),             sizeof(fd_rdisp_t)                              );
  void  * _pool       = FD_SCRATCH_ALLOC_APPEND( l, pool_align(),                 pool_footprint              ( depth+1UL       ) );
  void  * _unstaged   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rdisp_unstaged_t), sizeof(fd_rdisp_unstaged_t)*( depth+1UL       ) );
  void  * _ptxn_pool  = FD_SCRATCH_ALLOC_APPEND( l, ptxn_pool_align(),            ptxn_pool_footprint         ( acct_depth+1UL  ) );
  void  * _mq         = FD_SCRATCH_ALLOC_APPEND( l, fd_rdisp_mq_align(),          mq_footprint                                    );
  void  * _bmap       = FD_SCRATCH_ALLOC_APPEND( l, block_map_align(),            block_map_footprint         ( chain_cnt       ) );
  void  * _bpool      = FD_SCRATCH_ALLOC_APPEND( l, block_pool_align(),           block_pool_footprint        ( block_depth+1UL ) );
  uchar * _pending    = FD_SCRATCH_ALLOC_APPEND( l, pending_prq_align(),          4UL*pending_prq_footprint   ( full_depth      ) );
  void  * _acct_map   = FD_SCRATCH_ALLOC_APPEND( l, acct_map_align(),             acct_map_footprint          ( acct_chain_cnt  ) );
  void  * _freea_map  = FD_SCRATCH_ALLOC_APPEND( l, acct_map_align(),             acct_map_footprint          ( acct_chain_cnt  ) );
  acct_info_t * apool = FD_SCRATCH_ALLOC_APPEND( l, alignof(acct_info_t),         (acct_depth+1UL)*sizeof(acct_info_t)            );
  ustlt_t     * upool = FD_SCRATCH_ALLOC_APPEND( l, alignof(ustlt_t),             (acct_depth+1UL)*sizeof(ustlt_t)                );
  void  * _ustlt_map  = FD_SCRATCH_ALLOC_APPEND( l, ustlt_map_align(),            ustlt_map_footprint         ( acct_chain_cnt  ) );
  FD_SCRATCH_ALLOC_FINI( l, fd_rdisp_align() );

  disp->depth             = depth;
  disp->block_depth       = block_depth;
  disp->global_insert_cnt = 0UL;
  disp->unstaged_lblk_num = 0UL;

  fd_rdisp_txn_t * temp_pool_join = pool_join( pool_new( _pool, depth+1UL ) );
  for( ulong i=0UL; i<depth+1UL; i++ ) temp_pool_join[ i ].in_degree = IN_DEGREE_FREE;
  pool_leave( temp_pool_join );

  memset( _unstaged, '\0', sizeof(fd_rdisp_unstaged_t)*(depth+1UL) );

  fd_rdisp_ptxn_t * temp_ppool_join = ptxn_pool_join( ptxn_pool_new( _ptxn_pool, acct_depth+1UL ) );
  for( ulong i=0UL; i<acct_depth+1UL; i++ ) temp_ppool_join[ i ].in_degree = IN_DEGREE_FREE;
  ptxn_pool_leave( temp_ppool_join );

  fd_rdisp_mq_new( _mq, acct_depth, MAX_WRITERS_PER_BLOCK );

  block_map_new ( _bmap,  chain_cnt, seed );
  block_pool_new( _bpool, block_depth+1UL );

  fd_rdisp_blockinfo_t * bpool_temp_join = block_pool_join( _bpool );
  for( ulong i=0UL; i<block_depth+1UL; i++ ) zombie_dlist_new( bpool_temp_join[ i ].zombie_list );
  block_pool_leave( bpool_temp_join );

  disp->free_lanes = 0xF;
  for( ulong i=0UL; i<4UL; i++ ) {
    pending_prq_new( _pending, depth );
    _pending += pending_prq_footprint( full_depth );

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

  ustlt_map_new( _ustlt_map, acct_chain_cnt, fd_ulong_hash( seed+3UL ) );

  ustlt_dlist_t * temp_join_ustlt = ustlt_dlist_join( ustlt_dlist_new( disp->ustlt_free ) );
  for( ulong i=1UL; i<acct_depth+1UL; i++ ) {
    upool[ i ].ll_next = upool[ i ].ll_prev = 0U;
    ustlt_dlist_idx_push_tail( disp->ustlt_free, i, upool );
  }
  ustlt_dlist_leave( temp_join_ustlt );


  return disp;
}

fd_rdisp_t *
fd_rdisp_join( void * mem ) {
  fd_rdisp_t * disp = (fd_rdisp_t *)mem;

  ulong depth          = disp->depth;
  ulong block_depth    = disp->block_depth;
  ulong chain_cnt      = block_map_chain_cnt_est( block_depth );
  ulong acct_depth     = depth*FD_RDISP_MAX_ACCT_PER_TXN;
  ulong acct_chain_cnt = acct_map_chain_cnt_est( acct_depth );
  ulong mq_footprint   = fd_rdisp_mq_footprint( acct_depth, MAX_WRITERS_PER_BLOCK );
  ulong full_depth     = depth*(FD_RDISP_MAX_ACCT_PER_TXN+1UL);

  FD_SCRATCH_ALLOC_INIT( l, mem );
  /*                 */ FD_SCRATCH_ALLOC_APPEND( l, fd_rdisp_align(),             sizeof(fd_rdisp_t)                              );
  void  * _pool       = FD_SCRATCH_ALLOC_APPEND( l, pool_align(),                 pool_footprint              ( depth+1UL       ) );
  void  * _unstaged   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rdisp_unstaged_t), sizeof(fd_rdisp_unstaged_t)*( depth+1UL       ) );
  void  * _ptxn_pool  = FD_SCRATCH_ALLOC_APPEND( l, ptxn_pool_align(),            ptxn_pool_footprint         ( acct_depth+1UL  ) );
  void  * _mq         = FD_SCRATCH_ALLOC_APPEND( l, fd_rdisp_mq_align(),          mq_footprint                                    );
  void  * _bmap       = FD_SCRATCH_ALLOC_APPEND( l, block_map_align(),            block_map_footprint         ( chain_cnt       ) );
  void  * _bpool      = FD_SCRATCH_ALLOC_APPEND( l, block_pool_align(),           block_pool_footprint        ( block_depth+1UL ) );
  uchar * _pending    = FD_SCRATCH_ALLOC_APPEND( l, pending_prq_align(),          4UL*pending_prq_footprint   ( full_depth      ) );
  void  * _acct_map   = FD_SCRATCH_ALLOC_APPEND( l, acct_map_align(),             acct_map_footprint          ( acct_chain_cnt  ) );
  void  * _freea_map  = FD_SCRATCH_ALLOC_APPEND( l, acct_map_align(),             acct_map_footprint          ( acct_chain_cnt  ) );
  acct_info_t * apool = FD_SCRATCH_ALLOC_APPEND( l, alignof(acct_info_t),         (acct_depth+1UL)*sizeof(acct_info_t)            );
  ustlt_t     * upool = FD_SCRATCH_ALLOC_APPEND( l, alignof(ustlt_t),             (acct_depth+1UL)*sizeof(ustlt_t)                );
  void  * _ustlt_map  = FD_SCRATCH_ALLOC_APPEND( l, ustlt_map_align(),            ustlt_map_footprint         ( acct_chain_cnt  ) );
  FD_SCRATCH_ALLOC_FINI( l, fd_rdisp_align() );

  disp->pool       = pool_join( _pool );
  disp->unstaged   = (fd_rdisp_unstaged_t *)_unstaged;
  disp->ptxn_pool  = ptxn_pool_join( _ptxn_pool );
  disp->mq         = fd_rdisp_mq_join( _mq );
  disp->blockmap   = block_map_join( _bmap );
  disp->block_pool = block_pool_join( _bpool );

  for( ulong i=0UL; i<block_depth+1UL; i++ ) zombie_dlist_join( disp->block_pool[ i ].zombie_list );

  for( ulong i=0UL; i<4UL; i++ ) {
    disp->lanes[i].pending = pending_prq_join( _pending );
    _pending += pending_prq_footprint( full_depth );
  }

  disp->acct_map      = acct_map_join( _acct_map );
  disp->free_acct_map = acct_map_join( _freea_map );
  disp->acct_pool     = apool;
  free_dlist_join( disp->free_acct_dlist );

  disp->ustlt_pool    = upool;
  disp->ustlt_map     = ustlt_map_join( _ustlt_map );
  ustlt_dlist_join( disp->ustlt_free );

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

ulong
fd_rdisp_suggest_staging_lane( fd_rdisp_t const *   disp,
                               FD_RDISP_BLOCK_TAG_T parent_block,
                               int                  duplicate ) {

  /* 1. If it's a duplicate, suggest FD_RDISP_UNSTAGED */
  if( FD_UNLIKELY( duplicate ) ) return FD_RDISP_UNSTAGED;

  /* 2. If parent is the last block in any existing staging lane, suggest
        that lane */
  fd_rdisp_blockinfo_t const * block_pool = disp->block_pool;
  fd_rdisp_blockinfo_t const * block = block_map_ele_query_const( disp->blockmap, &parent_block, NULL, block_pool );
  if( FD_LIKELY( block && block->insert_ready && block->staged ) ) return block->staging_lane;

  /* 3. If there is at least one free lane, suggest a free lane */
  if( FD_LIKELY( disp->free_lanes!=0 ) ) return (ulong)fd_uint_find_lsb( (uint)disp->free_lanes );

  /* 4. Else, suggest FD_RDISP_UNSTAGED */
  return FD_RDISP_UNSTAGED;
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
    unstaged_txn_ll_join( unstaged_txn_ll_new( block->ll            ) );
    ustlt_dlist_join(     ustlt_dlist_new    ( block->ustlt_needed  ) );
    ustlt_dlist_join(     ustlt_dlist_new    ( block->ustlt_created ) );
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
                       FD_RDISP_BLOCK_TAG_T  block_tag ) {
  fd_rdisp_blockinfo_t * block_pool = disp->block_pool;

  fd_rdisp_blockinfo_t * block   = block_map_ele_query( disp->blockmap, &block_tag, NULL, block_pool );
  if( FD_UNLIKELY( block==NULL ) ) return -1;

  FD_TEST( block->schedule_ready );
  FD_TEST( block->completed_cnt==block->inserted_cnt );
  FD_TEST( zombie_dlist_is_empty( block->zombie_list, disp->pool ) );

  if( FD_LIKELY( block->staged ) ) {
    ulong staging_lane = (ulong)block->staging_lane;
    block_slist_t * sl = disp->lanes[staging_lane].block_ll;

    FD_TEST( block==block_slist_ele_peek_head( sl, block_pool ) );
    block_slist_idx_pop_head( sl, block_pool );
    if( FD_LIKELY( !block_slist_is_empty( sl, block_pool ) ) ) block_slist_ele_peek_head( sl, block_pool )->schedule_ready = 1;
    else                                                       free_lane( disp, staging_lane );
  } else {
    unstaged_txn_ll_delete( unstaged_txn_ll_leave( block->ll            ) );
    ustlt_dlist_delete    ( ustlt_dlist_leave    ( block->ustlt_needed  ) );
    ustlt_dlist_delete    ( ustlt_dlist_leave    ( block->ustlt_created ) );
  }
  block_pool_idx_release( block_pool, block_map_idx_remove( disp->blockmap, &block_tag, ULONG_MAX, block_pool ) );

  return 0;
}


int
fd_rdisp_abandon_block( fd_rdisp_t          * disp,
                        FD_RDISP_BLOCK_TAG_T  block_tag ) {
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
    fd_rdisp_complete_txn( disp, txn, 1 );
  }
  while( !zombie_dlist_is_empty( block->zombie_list, disp->pool ) ) {
    /* rdisp_complete_txn removes the peeked head */
    fd_rdisp_complete_txn( disp, zombie_dlist_idx_peek_head( block->zombie_list, disp->pool ), 1 );
  }

  if( FD_LIKELY( block->staged ) ) {
    ulong staging_lane = (ulong)block->staging_lane;

    block_slist_t * sl = disp->lanes[staging_lane].block_ll;

    FD_TEST( block==block_slist_ele_peek_head( sl, block_pool ) );
    block_slist_idx_pop_head( sl, block_pool );
    if( FD_LIKELY( !block_slist_is_empty( sl, block_pool ) ) ) block_slist_ele_peek_head( sl, block_pool )->schedule_ready = 1;
    else {
      /* It's schedule-ready, so it's possible there are some accounts
         in the NEEDS_PTXN state (add writer, schedule, complete it).
         However, if it's not insert-ready, then we know the caller
         would already have created the pseudo-transactions if they were
         needed, so we don't need to do anything in that case. */
      while( fd_rdisp_mq_cnt( disp->mq, staging_lane ) ) {
        ulong acct_idx = fd_rdisp_mq_pop( disp->mq, staging_lane );
        acct_info_t * ai = disp->acct_pool + acct_idx;
        uint s = ai->states;
        if( FD_UNLIKELY( ACCT_INFO_STATE_IS(s, staging_lane, NEEDS_PTXN) ) ) {
          ai->states = (uchar)ACCT_INFO_STATE_SET(s, staging_lane, NO_WRITERS);

          /* Potentially transition from ACTIVE -> CACHED */
          if( FD_UNLIKELY( (ai->states==0)&
                (ai->last_reference[ 0 ]==0U)&(ai->last_reference[ 1 ]==0U)&
                (ai->last_reference[ 2 ]==0U)&(ai->last_reference[ 3 ]==0U) ) ) {
            acct_map_idx_remove_fast( disp->acct_map,        acct_idx, disp->acct_pool );
            acct_map_idx_insert     ( disp->free_acct_map,   acct_idx, disp->acct_pool );
            free_dlist_idx_push_tail( disp->free_acct_dlist, acct_idx, disp->acct_pool );
          }
        }
      }

      free_lane( disp, staging_lane );
    }
  } else {
    while( !ustlt_dlist_is_empty( block->ustlt_created, disp->ustlt_pool ) ) {
      ustlt_t * ele = ustlt_dlist_ele_peek_head( block->ustlt_created, disp->ustlt_pool );
      /* Free the created ones */
      fd_rdisp_ptxn_t * ptxn = disp->ptxn_pool + EDGE_SPECIAL_IDX( ele->ptxn_idx );
      ptxn->in_degree        = IN_DEGREE_FREE;
      ptxn_pool_ele_release( disp->ptxn_pool, ptxn );

      ustlt_dlist_ele_remove   ( block->ustlt_created, ele, disp->ustlt_pool );
      ustlt_dlist_ele_push_tail( disp->ustlt_free,     ele, disp->ustlt_pool );
    }

    while( !ustlt_dlist_is_empty( block->ustlt_needed, disp->ustlt_pool ) ) {
      ustlt_t * ele = ustlt_dlist_ele_peek_head( block->ustlt_needed, disp->ustlt_pool );
      ustlt_dlist_ele_remove   ( block->ustlt_needed, ele, disp->ustlt_pool );
      ustlt_map_ele_remove_fast( disp->ustlt_map,     ele, disp->ustlt_pool );
      ustlt_dlist_ele_push_tail( disp->ustlt_free,    ele, disp->ustlt_pool );
    }

    unstaged_txn_ll_delete( unstaged_txn_ll_leave( block->ll ) );
    ustlt_dlist_delete    ( ustlt_dlist_leave    ( block->ustlt_needed  ) );
    ustlt_dlist_delete    ( ustlt_dlist_leave    ( block->ustlt_created ) );
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
           int                    update_score,
           fd_rdisp_neww_t *      new_wr,
           ulong                  new_wr_offset );
/* updates in_degree, edge_cnt_etc */


static inline ulong
lookup_pubkey( fd_rdisp_t * disp,
               fd_acct_addr_t const * addr );

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
    FD_TEST( ele->in_degree==IN_DEGREE_UNSTAGED );

    ele->in_degree    = 0U;
    ele->edge_cnt_etc = (uint)(-1); /* set w_cnt_1 to -1 */

    /* Ignore LtHash accounts here since we have the precise list in
       ustlt_needed. */
    add_edges( disp, ele, uns->keys,                   uns->writable_cnt, (uint)staging_lane, 1, 0, NULL, 0UL );
    add_edges( disp, ele, uns->keys+uns->writable_cnt, uns->readonly_cnt, (uint)staging_lane, 0, 0, NULL, 0UL );

    ele->edge_cnt_etc &= 0x3FFFU;
    ele->edge_cnt_etc |= (uint)staging_lane<<14;
    ele->edge_cnt_etc |= linear_block_number<<16;

    if( FD_UNLIKELY( ele->in_degree==0U ) ) {
      pending_prq_ele_t temp[1] = {{ .score = ele->score, .linear_block_number = linear_block_number, .txn_idx = (uint)(ele-disp->pool)}};
      pending_prq_insert( lane->pending, temp );
    }
  }
  unstaged_txn_ll_delete( unstaged_txn_ll_leave( block->ll ) );

  while( !ustlt_dlist_is_empty( block->ustlt_created, disp->ustlt_pool ) ) {
    ustlt_t * ele = ustlt_dlist_ele_peek_head( block->ustlt_created, disp->ustlt_pool );

    /* Free the created ones */
    fd_rdisp_ptxn_t * ptxn = disp->ptxn_pool + EDGE_SPECIAL_IDX( ele->ptxn_idx );
    ptxn->in_degree        = IN_DEGREE_FREE;
    ptxn_pool_ele_release( disp->ptxn_pool, ptxn );

    ustlt_dlist_ele_remove   ( block->ustlt_created, ele, disp->ustlt_pool );
    ustlt_dlist_ele_push_tail( disp->ustlt_free,     ele, disp->ustlt_pool );
    block->inserted_cnt--;
  }

  while( !ustlt_dlist_is_empty( block->ustlt_needed, disp->ustlt_pool ) ) {
    ustlt_t * ele = ustlt_dlist_ele_peek_head( block->ustlt_needed, disp->ustlt_pool );

    ulong acct_idx = lookup_pubkey( disp, &(ele->key.acct) );
    acct_info_t * ai = disp->acct_pool + acct_idx;
    /* If it's NO_WRITERS, we need to transition to NEEDS_PTXN, but
       otherwise it's fine. */
    uint s = ai->states;
    s = fd_uint_if( ACCT_INFO_STATE_IS(s, staging_lane, NO_WRITERS), ACCT_INFO_STATE_SET(s, staging_lane, NEEDS_PTXN), s );
    ai->states = (uchar)s;

    fd_rdisp_mq_insert( disp->mq, acct_idx, staging_lane, disp->acct_pool[acct_idx].ema_refs );

    ustlt_dlist_ele_remove   ( block->ustlt_needed, ele, disp->ustlt_pool );
    ustlt_map_ele_remove_fast( disp->ustlt_map,     ele, disp->ustlt_pool );
    ustlt_dlist_ele_push_tail( disp->ustlt_free,    ele, disp->ustlt_pool );
  }

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

  unstaged_txn_ll_join( unstaged_txn_ll_new( block->ll            ) );
  ustlt_dlist_join(     ustlt_dlist_new    ( block->ustlt_needed  ) );
  ustlt_dlist_join(     ustlt_dlist_new    ( block->ustlt_created ) );


  if( FD_LIKELY( !block_slist_is_empty( sl, block_pool ) ) ) block_slist_ele_peek_head( sl, block_pool )->schedule_ready = 1;
  else {
    /* If it was insert-ready, we need to carry over the LtHash addition
       information.  If it wasn't, then that information should have
       been encoded in the created LtHash addition tasks, but the block
       can't contain any PENDING transactions by contract... */
    while( fd_rdisp_mq_cnt( disp->mq, staging_lane ) ) {
      ulong acct_idx = fd_rdisp_mq_pop( disp->mq, staging_lane );
      acct_info_t * ai = disp->acct_pool + acct_idx;

      ulong ustlt_idx = ustlt_dlist_idx_pop_head( disp->ustlt_free, disp->ustlt_pool );
      disp->ustlt_pool[ ustlt_idx ].key.acct      = ai->key;
      disp->ustlt_pool[ ustlt_idx ].key.block_idx = (uint)(block-block_pool);
      ustlt_map_idx_insert( disp->ustlt_map, ustlt_idx, disp->ustlt_pool );
      ustlt_dlist_idx_push_tail( block->ustlt_needed, ustlt_idx, disp->ustlt_pool );

      uint s = ai->states;
      if( FD_UNLIKELY( ACCT_INFO_STATE_IS(s, staging_lane, NEEDS_PTXN) ) ) {
        ai->states = (uchar)ACCT_INFO_STATE_SET(s, staging_lane, NO_WRITERS);

        /* Potentially transition from ACTIVE -> CACHED */
        if( FD_UNLIKELY( (ai->states==0)&
              (ai->last_reference[ 0 ]==0U)&(ai->last_reference[ 1 ]==0U)&
              (ai->last_reference[ 2 ]==0U)&(ai->last_reference[ 3 ]==0U) ) ) {
          acct_map_idx_remove_fast( disp->acct_map,        acct_idx, disp->acct_pool );
          acct_map_idx_insert     ( disp->free_acct_map,   acct_idx, disp->acct_pool );
          free_dlist_idx_push_tail( disp->free_acct_dlist, acct_idx, disp->acct_pool );
        }
      }
    }
    free_lane( disp, staging_lane );
  }
  return 0;
}

int
fd_rdisp_rekey_block( fd_rdisp_t *           disp,
                      FD_RDISP_BLOCK_TAG_T   new_tag,
                      FD_RDISP_BLOCK_TAG_T   old_tag ) {
  fd_rdisp_blockinfo_t * block_pool = disp->block_pool;

  if( FD_UNLIKELY(        NULL!= block_map_ele_query_const( disp->blockmap, &new_tag, NULL, block_pool ) ) ) return -1;
  fd_rdisp_blockinfo_t * block = block_map_ele_query      ( disp->blockmap, &old_tag, NULL, block_pool );
  if( FD_UNLIKELY(        NULL== block ) )                                                                   return -1;

  block_map_idx_remove( disp->blockmap, &old_tag, ULONG_MAX, block_pool );
  block->block = new_tag;
  block_map_ele_insert( disp->blockmap, block, block_pool );
  return 0;
}


/* "Registers" a reference to the account in info at transaction
   global_insert_cnt.  Returns the value of the EMA, which is an
   estimate of the probability that the next transaction also references
   the account.  This value does not matter for correctness, other than
   that it is in [0, 1), which is why floating point arithmetic is
   acceptable here. */
static inline float
update_ema( acct_info_t * info,
            ulong         global_insert_cnt ) {
#if FD_RDISP_DISABLE_EMA
  (void)info;
  (void)global_insert_cnt;
  return 0.0f;
#else
#define ALPHA 0.005f
  /* The normal EMA update equation is
                e_i = (alpha) * x_i + (1-alpha)*e_{i-1},
     where alpha is a constant in (0,1).  Let L be the last reference of
     the account, and G be the current global_insert_cnt value.  We know
     that e_L = ema_refs, and that for i in [L+1, G), x_i = 0.
     That means
               e_{G-1} =         (1-alpha)^(G-L-1) * ema_refs
               e_G     = alpha + (1-alpha)^(G-L)   * ema_refs
   */
  /* last_ref only captures the low 24 bits, so we guess its the highest
     value for them that would still make it less than
     global_insert_cnt.  Turns out, we can calculate that with just an
     AND.  We need to make sure that in the rare case it is actually
     2^24 away, we don't use a delta of 0.  We also want to make sure
     that even with inexact float math, we never get to 1.0, so we bias
     the exponent up slightly. */
  ulong last_ref = (ulong)info->last_ref;
  ulong delta = fd_ulong_max( (global_insert_cnt - last_ref) & 0xFFFFFFUL, 1UL );
  float ema_refs = ALPHA + powf( 1.0f-ALPHA, 0.05f+(float)delta ) * info->ema_refs;

  info->ema_refs = ema_refs;
  info->last_ref = (uint)(global_insert_cnt & 0xFFFFFFUL);
#undef ALPHA

  return ema_refs;
#endif
}

static inline ulong
lookup_pubkey( fd_rdisp_t * disp,
               fd_acct_addr_t const * addr ) {
    ulong idx = acct_map_idx_query( disp->acct_map, addr, ULONG_MAX, disp->acct_pool );
    if( FD_LIKELY( idx!=ULONG_MAX) ) return idx;

    acct_info_t * ai = NULL;
    idx = acct_map_idx_query( disp->free_acct_map, addr, ULONG_MAX, disp->acct_pool );
    if( FD_UNLIKELY( idx==ULONG_MAX ) ) {
      /* The acct pool is sized so that the list cannot be empty at this
         point.  However, the element at the head might be the free
         map with a different pubkey. */
      idx = free_dlist_idx_peek_head( disp->free_acct_dlist, disp->acct_pool );
      ai = disp->acct_pool+idx;

      /* CACHED -> FREE transition */
      if( FD_LIKELY( ai->next!=0U ) ) {
        acct_map_idx_remove_fast( disp->free_acct_map, idx, disp->acct_pool );
      }

      /* FREE -> ACTIVE transition */
      ai->key      = *addr;
      ai->states   = 0U;
      ai->last_ref = 0U;
      ai->ema_refs = 0.0f;
    } else {
      /* CACHED -> ACTIVE transition */
      ai = disp->acct_pool+idx;
      ai->states   = 0U; /* FIXME: unnecessary */
      acct_map_idx_remove_fast( disp->free_acct_map, idx, disp->acct_pool );
    }
    /* In either case, at this point, the element is not in any map
       but is in free_acct_dlist.  It has the right key. last_ref, and
       ema_refs are valid. states is 0. */

    free_dlist_idx_remove( disp->free_acct_dlist, idx, disp->acct_pool );
    memset( ai->last_reference, '\0', sizeof(ai->last_reference) );
    acct_map_idx_insert( disp->acct_map, idx, disp->acct_pool );
    return idx;
}

static void
add_edges( fd_rdisp_t           * disp,
           fd_rdisp_txn_t       * ele,
           fd_acct_addr_t const * addrs,
           ulong                  addr_cnt,
           uint                   lane,
           int                    writable,
           int                    update_score,
           fd_rdisp_neww_t *      new_wr,
           ulong                  new_wr_offset ) {
  /* When we first start, the low 14 bits are 0x3FFF, so that gives us
     w_cnt==0, r_cnt==0, as desired.  Then otherwise, the low 7 bits are
     w_cnt_1, so adding 1 gives w_cnt.  If we've actually added
     MAX_ACCT_PER_TXN writable accounts, then r_cnt will be incorrect,
     but then we actually can't add any more readonly accounts, so the
     function call will be a no-op. */

  ulong w_cnt =  (ele->edge_cnt_etc + 1U)     & 0x7FU;
  ulong r_cnt = ((ele->edge_cnt_etc + 1U)>>7) & 0x7FU;
  ulong acct_idx = w_cnt +     r_cnt;
  ulong edge_idx = w_cnt + 3UL*r_cnt;

  for( ulong i=0UL; i<addr_cnt; i++ ) {
    fd_acct_addr_t const * addr = addrs+i;
    acct_info_t * ai = NULL;

    /* Step 1: lookup the pubkey */
    ulong idx = lookup_pubkey( disp, addr );
    ai = disp->acct_pool+idx;
    /* At this point, in all cases, the acct_info is now in the ACTIVE
       state.  It's in acct_map, not in free_acct_map, and not in
       free_acct_dlist. */

    /* Assume that transactions are drawn randomly from some large
       distribution of potential transactions.  We want to estimate the
       expected value of the probability that this transaction conflicts
       with the next transaction that is sampled.  Two transactions
       conflict if they conflict on any account, and in general, they
       conflict if they both reference the same account, unless both
       this transaction and the next one only read it.  We don't have
       read/write info, so the best guess we have is that the next
       transaction does the same thing to the account that this one
       does.  That means we only really care about the accounts that
       this transaction writes to.  Label those a_1, a_2, ..., a_i, and
       suppose the probability that the next transaction references a_i
       is p_i (determined using the EMA).  Now then, assuming accounts
       are independent (which is false, but whatever), then the
       probability that the next transaction does not conflict with this
       account is:
                     (1-p_1) * (1-p_2) * (1 - p_i).

       Since for the treap, a lower value means we'll schedule it
       earlier, we'll use the probability of non-conflict as the
       fractional part of the score. */
    if( FD_LIKELY( update_score ) ) {
      float score_change = 1.0f - update_ema( ai, disp->global_insert_cnt );
      ele->score *= fd_float_if( writable, score_change, 1.0f );
    }

    /* Step 2: add edge. There are 4 cases depending on whether this is
       a writer or not and whether the previous reference was a writer
       or not. */
    int      _ignore;

    edge_t   ref_to_pa = ai->last_reference[ lane ];
    ulong    displ0    = ((ulong)ele - (ulong)disp->pool     )/sizeof(fd_rdisp_txn_t);
    ulong    displ1    = ((ulong)ele - (ulong)disp->ptxn_pool)/sizeof(fd_rdisp_ptxn_t);
    edge_t   ref_to_me = (uint)fd_ulong_if( displ0>disp->depth, EDGE_MAKE_SPECIAL(PTXN, displ1), (displ0<<8)|acct_idx );
    edge_t * pa        = FOLLOW_EDGE( disp, ai->last_reference[ lane ], _ignore );
    edge_t * me        = ele->edges + edge_idx;

    /* In the case that this is the first txn in the DAG, pa will point
       to edges[0] of the sentinel element, pool[0].  We don't care
       about what is stored there, so just set it up as a dummy element
       to make the rest of the code work properly in this case too.  If
       this is a read, we want me->sibli to ref_to_me in case 4; if this
       is a write, we want to set me->sibli to 0 in case 2, but we need
       to make sure pb==pa. */
    disp->pool->edges[0] = EDGE_MAKE_SPECIAL(LAST, (uint)idx);
    disp->pool->edges[1] = fd_uint_if( writable, 0U, ref_to_me );
    disp->pool->edges[2] = fd_uint_if( writable, 0U, ref_to_me );

    int states = ai->states;

    if( writable ) { /* also should be known at compile time */
      if( ACCT_INFO_STATE_IS( states, lane, LAST_REF_WAS_WRITE ) ) { /* unclear prob */
        /* Case 1: w-w. The parent is the special last pointer.  Point
           the parent to me, and set me to the last pointer. */
        *me = *pa;
        *pa = ref_to_me;
      } else {
        /* Case 2: r-w. This is the tricky case because there could be
           multiple readers.  We need to set all the last readers' child
           pointers to me. */
        *me = *pa;
        *pa = ref_to_me;
        edge_t * pb = FOLLOW_EDGE( disp, pa[1], _ignore );
        /* Intentionally skip the first in_degree increment, because it
           will be done later */
        while( pb!=pa ) {
          *pb = ref_to_me;
          ele->in_degree++;
          pb = FOLLOW_EDGE( disp, pb[1], _ignore );
        }
        states = ACCT_INFO_STATE_SET( states, lane, LAST_REF_WAS_WRITE );
      }
    } else {
      if( ACCT_INFO_STATE_IS( states, lane, LAST_REF_WAS_WRITE ) ) { /* unclear prob */
        /* Case 3: w-r. Similar to case 1, but need to initialize my
           next and prev sibling pointers too. */
        *me = *pa;
        *pa = ref_to_me;
        me[1] = ref_to_me; /* next */
        me[2] = ref_to_me; /* prev */
        states = ACCT_INFO_STATE_SET( states, lane, LAST_REF_WAS_READ );
      } else {
        /* Case 4: r-r. Add myself as a sibling instead of a child */
        *me = *pa;
        FOLLOW_EDGE( disp, pa[1], _ignore )[2] = ref_to_me;  /* prev->next->prev = me   */
        me[1] = pa[1];                                       /* me->next   = prev->next */
        me[2] = ref_to_pa;                                   /* me->prev   = prev       */
        pa[1] = ref_to_me;                                   /* prev->next = me         */
      }
    }

    /* Step 3: Update new_wr */
    if( ((!!writable) & FD_LIKELY( !!new_wr )) && !fd_rdisp_mq_test( disp->mq, idx, lane ) ) {
      fd_rdisp_mq_insert( disp->mq, idx, lane, ai->ema_refs );
      fd_rdisp_neww_insert( new_wr, new_wr_offset+i );
    }

    /* Step 4: Update the final values */
    /* In general, we want to increment the in_degree unless this
       transaction is the first to reference this account.  The
       exception is that if this account has only readers, including
       this transaction, we don't want to increment the in_degree
       either.  At this point, we can tell if that is the case based on
       states.  */
    int any_write = ACCT_INFO_STATE_IS( states, lane, LAST_REF_WAS_READ ) | ACCT_INFO_STATE_IS( states, lane, LAST_REF_WAS_WRITE );
    ele->in_degree += (uint)((ai->last_reference[ lane ]!=0U) & any_write);
    ai->last_reference[ lane ] = ref_to_me;
    ai->states                 = (uchar)states;
    edge_idx += fd_uint_if( writable, 1U, 3U );
    acct_idx++;
  }
  /* Can't overflow by construction, except for the intentional overflow on the first time. */
  ele->edge_cnt_etc += (uint)addr_cnt<<fd_int_if( writable, 0, 7 );
}


/* should be called with all writable accounts first */
static void
add_unstaged_edges( fd_rdisp_t * disp,
                    fd_rdisp_txn_t       * ele,
                    fd_rdisp_unstaged_t  * unstaged,
                    fd_acct_addr_t const * addr,
                    ulong                  addr_cnt,
                    int                    writable,
                    int                    update_score,
                    fd_rdisp_neww_t      * new_wr,
                    ulong                  new_wr_offset ) {
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
      ele->score *= fd_float_if( writable & update_score, score_change, 1.0f );
    }
    if( ((!!writable) & FD_LIKELY( !!new_wr )) ) {
      ustlt_key_t query[1] = {{
        .block_idx = unstaged->block_idx,
        .acct      = addr[i]
      }};
      int new = (ustlt_map_idx_query( disp->ustlt_map, query, ULONG_MAX, disp->ustlt_pool )==ULONG_MAX);
      fd_rdisp_neww_insert_if( new_wr, new, new_wr_offset+i );
      if( FD_UNLIKELY( new ) ) {
        ulong ustlt_idx = ustlt_dlist_idx_pop_head( disp->ustlt_free, disp->ustlt_pool );
        disp->ustlt_pool[ ustlt_idx ].key = *query;
        ustlt_map_idx_insert( disp->ustlt_map, ustlt_idx, disp->ustlt_pool );
        ustlt_dlist_idx_push_tail( disp->block_pool[ unstaged->block_idx ].ustlt_needed, ustlt_idx, disp->ustlt_pool );
      }
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
                  int                    serializing,
                  fd_rdisp_neww_t      * new_writable ) {
  if( FD_LIKELY( new_writable ) ) fd_rdisp_neww_new( new_writable ); /* clear it */

  fd_rdisp_blockinfo_t * block   = block_map_ele_query( disp->blockmap, &insert_block, NULL, disp->block_pool );
  if( FD_UNLIKELY( !block || !block->insert_ready ) ) return 0UL;
  if( FD_UNLIKELY( !pool_free( disp->pool       ) ) ) return 0UL;

  ulong idx = pool_idx_acquire( disp->pool );
  fd_rdisp_txn_t * rtxn = disp->pool + idx;
  if( FD_UNLIKELY( rtxn->in_degree!=IN_DEGREE_FREE ) ) FD_LOG_CRIT(( "pool[%lu].in_degree==%u but free", idx, rtxn->in_degree ));

  fd_acct_addr_t const * imm_addrs = fd_txn_get_acct_addrs( txn, payload );

  ulong ws = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE_SIGNER );
  ulong rs = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_READONLY_SIGNER );
  ulong wn = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE_NONSIGNER_IMM );
  ulong rn = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_READONLY_NONSIGNER_IMM );
  ulong wa = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE_ALT );
  ulong ra = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_READONLY_ALT );

  if( FD_UNLIKELY( !block->staged ) ) {
    rtxn->in_degree = IN_DEGREE_UNSTAGED;
    rtxn->score     = 1.0f;

    fd_rdisp_unstaged_t * unstaged = disp->unstaged + idx;
    unstaged->block_idx    = (uint)(block-disp->block_pool);
    unstaged->writable_cnt = 0U;
    unstaged->readonly_cnt = 0U;

    add_unstaged_edges(   disp, rtxn, unstaged, imm_addrs,          ws, 1, 1, new_writable, 0UL            );
    add_unstaged_edges(   disp, rtxn, unstaged, imm_addrs+ws+rs,    wn, 1, 1, new_writable, ws+rs          );
    if( FD_LIKELY( alts ) )
      add_unstaged_edges( disp, rtxn, unstaged, alts,               wa, 1, 1, new_writable, ws+rs+wn+rn    );
    add_unstaged_edges(   disp, rtxn, unstaged, imm_addrs+ws,       rs, 0, 1, new_writable, ws             );
    add_unstaged_edges(   disp, rtxn, unstaged, imm_addrs+ws+rs+wn, rn, 0, 1, new_writable, ws+rs+wn       );
    if( FD_LIKELY( alts ) )
      add_unstaged_edges( disp, rtxn, unstaged, alts+wa,            ra, 0, 1, new_writable, ws+rs+wn+rn+wa );

    unstaged_txn_ll_ele_push_tail( block->ll, rtxn, disp->pool );
  } else {
    uint lane = block->staging_lane;

    rtxn->in_degree    = 0U;
    rtxn->score        = 1.0f;
    /* There's not a good way to initialize w_cnt_1 to -1, which is what
       it should be at this point, but this is close.  We must be sure
       to add at least one writer (which we are assured of because we
       know the transaction passed fd_txn_parse) to correct this value. */
    rtxn->edge_cnt_etc = ((block->linear_block_number<<16) | (lane<<14)) - 1U;

    add_edges(   disp, rtxn, imm_addrs,          ws, lane, 1, 1, new_writable, 0UL            );
    add_edges(   disp, rtxn, imm_addrs+ws+rs,    wn, lane, 1, 1, new_writable, ws+rs          );
    if( FD_LIKELY( alts ) )
      add_edges( disp, rtxn, alts,               wa, lane, 1, 1, new_writable, ws+rs+wn+rn    );
    add_edges(   disp, rtxn, imm_addrs+ws,       rs, lane, 0, 1, new_writable, ws             );
    add_edges(   disp, rtxn, imm_addrs+ws+rs+wn, rn, lane, 0, 1, new_writable, ws+rs+wn       );
    if( FD_LIKELY( alts ) )
      add_edges( disp, rtxn, alts+wa,            ra, lane, 0, 1, new_writable, ws+rs+wn+rn+wa );
  }
  if( FD_UNLIKELY( rtxn->score>FD_RDISP_MAX_SCORE ) ) rtxn->score=FD_RDISP_MAX_SCORE;

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
    if( FD_UNLIKELY( EDGE_IS_PTXN(idx) ) ) disp->ptxn_pool[ EDGE_SPECIAL_IDX( idx ) ].in_degree = IN_DEGREE_DISPATCHED;
    else                                   disp->pool     [                   idx   ].in_degree = IN_DEGREE_DISPATCHED;
  } else {
    if( FD_UNLIKELY( block->dispatched_cnt!=block->completed_cnt       ) ) return 0UL;
    if( FD_UNLIKELY( !unstaged_txn_ll_is_empty( block->ll, disp->pool ) ) ) {
      idx = unstaged_txn_ll_idx_peek_head( block->ll, disp->pool );
      disp->pool[ idx ].in_degree = IN_DEGREE_UNSTAGED_DISPATCHED;
    } else if( FD_UNLIKELY( !ustlt_dlist_is_empty( block->ustlt_created, disp->ustlt_pool ) ) ) {
      idx = ustlt_dlist_ele_peek_head( block->ustlt_created, disp->ustlt_pool )->ptxn_idx;
      disp->ptxn_pool[ idx ].in_degree = IN_DEGREE_UNSTAGED_DISPATCHED;
      idx = EDGE_MAKE_SPECIAL(PTXN, idx);
    } else {
      return 0UL;
    }
  }
  block->dispatched_cnt++;

  return idx;
}

void
fd_rdisp_complete_txn( fd_rdisp_t * disp,
                       ulong        txn_idx,
                       int          reclaim ) {

  int ptxn = EDGE_IS_PTXN( txn_idx );
  fd_rdisp_txn_t * rtxn = (!ptxn) ? disp->pool + txn_idx : (fd_rdisp_txn_t *)(disp->ptxn_pool + EDGE_SPECIAL_IDX(txn_idx));
  fd_rdisp_blockinfo_t * block = NULL;

  if( FD_UNLIKELY( rtxn->in_degree==IN_DEGREE_UNSTAGED_DISPATCHED ) ) {
    /* Unstaged */
    if( FD_UNLIKELY( ptxn ) ) {
      fd_rdisp_ptxn_t  * ptxn_e    = (fd_rdisp_ptxn_t *)rtxn;
      ustlt_t          * ustlt_ele = disp->ustlt_pool + ptxn_e->last;
      block = disp->block_pool + ustlt_ele->key.block_idx;
      FD_TEST( ustlt_ele==ustlt_dlist_ele_pop_head( block->ustlt_created, disp->ustlt_pool ) );
      /* ptxn_e gets freed below */
      ustlt_dlist_ele_push_tail( disp->ustlt_free, ustlt_ele, disp->ustlt_pool );

    } else {
      block = disp->block_pool + disp->unstaged[ txn_idx ].block_idx;
      FD_TEST( rtxn==unstaged_txn_ll_ele_peek_head( block->ll, disp->pool ) );
      unstaged_txn_ll_ele_pop_head( block->ll, disp->pool );
    }
    block->completed_cnt++;
  } else if( FD_LIKELY( rtxn->in_degree==IN_DEGREE_DISPATCHED ) ) {
    /* Staged */
    ulong w_cnt = fd_ulong_if( ptxn, 0UL, 1UL + ((rtxn->edge_cnt_etc    ) & 0x7FU) );
    ulong r_cnt = (rtxn->edge_cnt_etc>> 7) & 0x7FU;
    ulong lane  = (rtxn->edge_cnt_etc>>14) & 0x3U;
    uint  tail_linear_block_num = (uint)(disp->lanes[lane].linear_block_number);
    ulong edge_idx = 0UL;
    for( ulong i=0UL; i<w_cnt+r_cnt; i++ ) {
      edge_t const * e = rtxn->edges+edge_idx;
      edge_t const  e0 = *e;
      edge_t ref_to_me = (uint)fd_ulong_if( ptxn, txn_idx, ((txn_idx<<8) | i) );

      /* To help with explanations, consider the following DAG:

           --> B --\   --> E --\
          /         V /         V
         A           D         (G)
          \         ^ \         ^
           --> C --/   --> F --/     */

      if( FD_UNLIKELY( EDGE_IS_LAST( e0 ) ) ) {
        ulong acct_idx = EDGE_SPECIAL_IDX( e0 );
        acct_info_t * ai = disp->acct_pool + acct_idx;
        /* If this is a writer, e.g. node G above, we know it's the last
           one, so we can clear last_reference.  We know it has to go to
           the NEEDS_PTXN state unless LtHash tracking was disabled for it.
           If this is a reader, e.g. node E and F above, if node G
           didn't exist, we need to check if it's the last one
           (me==me->next).  If so, we can clear last_reference.  If not,
           we need to delete this node from the linked list.  In either
           case, there are only readers or pseudo-transactions, so we're
           either in NO_WRITERS or NEEDS_PTXN states, and we stay in
           that state. */
        if( edge_idx<w_cnt ) {
          ai->last_reference[ lane ] = 0U;
          ai->states = fd_uchar_if( fd_rdisp_mq_test( disp->mq, acct_idx, lane ), ACCT_INFO_STATE_SET(ai->states, lane, NEEDS_PTXN),
                                                                                  ACCT_INFO_STATE_SET(ai->states, lane, NO_WRITERS));
        } else if( e[1]==ref_to_me ) {
          ai->last_reference[ lane ] = 0U;
        } else {
          int _ignore;
          FOLLOW_EDGE( disp, e[1], _ignore )[2] = e[2];  /* me->next->prev = me->prev */
          FOLLOW_EDGE( disp, e[2], _ignore )[1] = e[1];  /* me->prev->next = me->next */
          ai->last_reference[ lane ]= fd_uint_if( ai->last_reference[ lane ]==ref_to_me, e[1], ai->last_reference[ lane ] );
        }

        /* Potentially transition from ACTIVE -> CACHED */
        if( FD_UNLIKELY( (ai->states==0)&
                         (ai->last_reference[ 0 ]==0U)&(ai->last_reference[ 1 ]==0U)&
                         (ai->last_reference[ 2 ]==0U)&(ai->last_reference[ 3 ]==0U) ) ) {
          acct_map_idx_remove_fast( disp->acct_map,        acct_idx, disp->acct_pool );
          acct_map_idx_insert     ( disp->free_acct_map,   acct_idx, disp->acct_pool );
          free_dlist_idx_push_tail( disp->free_acct_dlist, acct_idx, disp->acct_pool );
        }
      } else {
        int child_is_writer;

        edge_t next_e = e0;
        edge_t const * child_edge;
        while( 1 ) {
          /* This loop first traverses the me->child link, and then
             traverses any sibling links.  For example, in the case that
             we're completing node D above, the first child_txn is E,
             and the second child_txn is F.  child_txn might be a
             pseudo-transaction. */
          /*            */ child_edge = FOLLOW_EDGE(     disp, next_e, child_is_writer );
          fd_rdisp_txn_t * child_txn  = FOLLOW_EDGE_TXN( disp, next_e                  );

          /* Sanity test */
          FD_TEST( child_txn->in_degree>0U                   );
          FD_TEST( child_txn->in_degree<IN_DEGREE_DISPATCHED );

          if( FD_UNLIKELY( 0U==(--(child_txn->in_degree)) ) ) {
            /* We need an operation something like
               fd_frag_meta_ts_decomp. child_txn has the low 16 bits,
               and tail_linear_block_num has the full 32 bits, except
               for tail_linear_block_num refers to a block < block_depth
               later.  Since block_depth<2^16, that means we can resolve
               this unambiguously.  Basically, we copy the high 16 bits
               frorm tail_linear_block_num unless that would make
               linear_block_num larger than tail_linear_block_num, in
               which case, we subtract 2^16. */
            uint low_16_bits = child_txn->edge_cnt_etc>>16;
            uint linear_block_num = ((tail_linear_block_num & ~0xFFFFU) | low_16_bits) - (uint)((low_16_bits>(tail_linear_block_num&0xFFFFU))<<16);
            pending_prq_ele_t temp[1] = {{ .score               = child_txn->score,
                                           .linear_block_number = linear_block_num,
                                           .txn_idx             = fd_uint_if( EDGE_IS_PTXN(next_e), next_e, next_e>>8 ) }};
            pending_prq_insert( disp->lanes[ lane ].pending, temp );
          }
          if( child_is_writer || child_edge[1]==e0 ) break;
          next_e = child_edge[1];
        }
        /* In the case that the completed transaction is a reader, say B
           or C above, it seems like we should need to remove it from
           the doubly linked list, but we actually don't.  The times
           that we need to read the sibling pointers are:
            1. Completing the writer before a reader (e.g. completing A)
            2. Completing a reader that's the last in the DAG (e.g.
               completing E/F if G didn't exist)
            3. Adding another reader to the same set of readers (e.g. if
               G were added as a reader instead of a writer)
            4. Adding a writer after a set of readers (e.g. adding G).

           Supposing that the completed transaction is a reader, since
           we checked EDGE_IS_LAST( e0 ), we know that there is at least
           one writer that follows this reader, e.g. D above.

           And so none of these reason can apply to this group of readers:
            1. Completing B or C implies that A has already completed,
               so it can't complete again.
            2. We know that we're not in that case because we checked
               EDGE_IS_LAST( e0 ), and if we're not last now, we cannot
               become last later, because the growth happens in the
               other direction.
            3. Similarly, because we checked EDGE_IS_LAST, any future
               additions of readers won't be to this group of readers.
            4. Similarly, we know that there already is a writer that
               follows this group of readers, so a later writer would
               not read this set of readers.

           So then, we don't need to deal with the sibling edges.  The
           fact that we only need to do it in one case almost calls into
           question whether we need to maintain the whole circular
           system in the first place, and whether we could get away with
           a reference count or something instead, but it's important in
           one critical case: suppose we add a bunch of readers, then
           some of them complete, and then we add a writer (case 4
           above).  We need to be able to enumerate the nodes in the DAG
           that have not yet completed, and we need to be able to remove
           them from that set in O(1).  Those two requirements don't
           leave us with many alternatives besides a doubly linked list. */

        if( FD_UNLIKELY( EDGE_IS_LAST( *child_edge ) ) ) {
          /* For example, either:
             1. completing D if G didn't exist
             2. completing E or F with G in the DAG

             After completing this transaction, there's either 0 writers
             left (case 1) or 1 writer left (case 2) in the DAG. and if
             there is one, it is the last reference.  In case 1, we need
             to know if we have a pending LtHash psuedo-transaction to
             determine whether we transition to state NO_WRITERS or
             NEEDS_PTXN.  In case 2, we must be in LAST_REF_WAS_WRITE
             and we stay there. */

          acct_info_t * ai = disp->acct_pool + EDGE_SPECIAL_IDX(*child_edge);
          uint s = ai->states;
          if( !ACCT_INFO_STATE_IS( s, lane, LAST_REF_WAS_WRITE ) ) {
            int needs_ptxn = fd_rdisp_mq_test( disp->mq, EDGE_SPECIAL_IDX( *child_edge ), lane );
            s = fd_uint_if( needs_ptxn, ACCT_INFO_STATE_SET(s, lane, NEEDS_PTXN), ACCT_INFO_STATE_SET(s, lane, NO_WRITERS) );
            ai->states = (uchar)s;
          }
        }
      }
      edge_idx += fd_ulong_if( i<w_cnt, 1UL, 3UL );
    }
    block = block_slist_ele_peek_head( disp->lanes[ lane ].block_ll, disp->block_pool );
    block->completed_cnt++;
  } else if( FD_LIKELY( rtxn->in_degree==IN_DEGREE_ZOMBIE ) ) {
    FD_TEST( reclaim );
    FD_TEST( !ptxn   );
    block = block_pool_ele( disp->block_pool, rtxn->block_idx );
    zombie_dlist_ele_remove( block->zombie_list, rtxn, disp->pool );
    /* Fall through to the pool release branch below. */
  } else {
    FD_LOG_CRIT(( "completed un-dispatched transaction %lu", txn_idx ));
  }
  if( reclaim|ptxn ) {
    /* For testing purposes, to make sure we don't read a completed
       transaction, we can clobber the memory. */
    /* memset( disp->pool+txn_idx, '\xCC', sizeof(fd_rdisp_txn_t) ); */
    rtxn->in_degree = IN_DEGREE_FREE;
    if( FD_LIKELY( !ptxn ) ) pool_idx_release     ( disp->pool,                        txn_idx   );
    else                     ptxn_pool_idx_release( disp->ptxn_pool, EDGE_SPECIAL_IDX( txn_idx ) );
  } else {
    rtxn->in_degree = IN_DEGREE_ZOMBIE;
    zombie_dlist_ele_push_tail( block->zombie_list, rtxn, disp->pool );
    rtxn->block_idx = (uint)block_pool_idx( disp->block_pool, block );
  }
}

ulong
fd_rdisp_staging_lane_info( fd_rdisp_t           const * disp,
                            fd_rdisp_staging_lane_info_t out_sched[ static 4 ] ) {
  for( ulong i=0UL; i<4UL; i++ ) {
    if( !(disp->free_lanes & (1<<i) ) ) {
      block_slist_t const * sl = disp->lanes[ i ].block_ll;
      out_sched[ i ].insert_ready_block   = block_slist_ele_peek_tail( sl, disp->block_pool )->block;
      out_sched[ i ].schedule_ready_block = block_slist_ele_peek_head( sl, disp->block_pool )->block;
    }
  }
  return 0xFUL & ~(ulong)disp->free_lanes;
}

void
fd_rdisp_pseudo_txn_to_addr( fd_rdisp_t const * disp,
                             ulong              txn_idx,
                             fd_acct_addr_t   * out ) {
  FD_TEST( txn_idx & FD_RDISP_LTHASH_PSEUDO_TXN );
  txn_idx ^= FD_RDISP_LTHASH_PSEUDO_TXN;
  fd_rdisp_ptxn_t const * ptxn = disp->ptxn_pool + txn_idx;

  if( FD_LIKELY( (ptxn->in_degree!=IN_DEGREE_UNSTAGED) & (ptxn->in_degree!=IN_DEGREE_UNSTAGED_DISPATCHED) ) ) {
    *out = disp->acct_pool[ EDGE_SPECIAL_IDX(ptxn->last) ].key;
  } else {
    *out = disp->ustlt_pool[ EDGE_SPECIAL_IDX(ptxn->last) ].key.acct;
  }
}

void
fd_rdisp_add_all_pseudo_txn( fd_rdisp_t          *  disp,
                             FD_RDISP_BLOCK_TAG_T   insert_block ) {
  while( fd_rdisp_add_pseudo_txn( disp, insert_block ) );
}

ulong
fd_rdisp_add_pseudo_txn( fd_rdisp_t          *  disp,
                         FD_RDISP_BLOCK_TAG_T   insert_block ) {
  fd_rdisp_blockinfo_t * block   = block_map_ele_query( disp->blockmap, &insert_block, NULL, disp->block_pool );
  if( FD_UNLIKELY( !block || !block->insert_ready ) ) return 0UL;

  fd_rdisp_ptxn_t * ptxn;
  uint ptxn_idx;

  if( FD_LIKELY( block->staged ) ) {
    uint lane = block->staging_lane;
    if( FD_UNLIKELY( !fd_rdisp_mq_cnt( disp->mq, lane ) ) ) return 0UL;

    ptxn = ptxn_pool_ele_acquire( disp->ptxn_pool );
    ptxn_idx = EDGE_MAKE_SPECIAL(PTXN, (uint)(ptxn - disp->ptxn_pool));

    ulong acct_idx = fd_rdisp_mq_pop( disp->mq, lane );
    acct_info_t * ai = disp->acct_pool + acct_idx;

    ptxn->in_degree = 0U;
    /* lower txn score means higher priority, and we want pseudo-
       transactions for less frequently accessed accounts, i.e. those
       with lower EMA value to be higher priority, so we just use that
       value directly, with the last_serializing addition. */
    if( FD_UNLIKELY( block->last_insert_was_serializing ) ) {
      block->last_serializing = block->inserted_cnt;
    }
    block->last_insert_was_serializing = 0U;
    ptxn->score = (ai->ema_refs<FD_RDISP_MAX_SCORE ? ai->ema_refs : FD_RDISP_MAX_SCORE) + (float)block->last_serializing;

    /* see add_txn for this line */
    ptxn->edge_cnt_etc = ((block->linear_block_number<<16) | (lane<<14)) - 1U;

    /* add_edges is more general than what we need, but it's better to
       have all the logic in one place.  We don't need to pass new_wr
       because it's only a reader, so it won't be accessed anyway. */
    add_edges( disp, (fd_rdisp_txn_t *)ptxn, &(ai->key), 1UL, lane, 0, 0, NULL, 0UL );
    /* since we're kind of cheating with edge_cnt_etc, we need to fix it
       here */
    ptxn->edge_cnt_etc += 1U<<7;
    ptxn->last = EDGE_MAKE_SPECIAL(LAST, (uint)acct_idx);

    /* add_edge handles most of the state transitions, but it treats the
       pseudo-transaction like a reader, so it needs a little fixing. */
    uint states = ai->states;
    states = fd_uint_if( ACCT_INFO_STATE_IS( states, lane, NEEDS_PTXN ), ACCT_INFO_STATE_SET( states, lane, NO_WRITERS ), states );
    ai->states = (uchar)states;

    if( FD_LIKELY( ptxn->in_degree==0U ) ) {
      pending_prq_ele_t temp[1] = {{ .score = ptxn->score, .linear_block_number = block->linear_block_number, .txn_idx = ptxn_idx }};
      pending_prq_insert( disp->lanes[ block->staging_lane ].pending, temp );
    }
  } else {
    if( FD_UNLIKELY( ustlt_dlist_is_empty( block->ustlt_needed, disp->ustlt_pool ) ) ) return 0UL;

    ptxn = ptxn_pool_ele_acquire( disp->ptxn_pool );
    ptxn_idx = EDGE_MAKE_SPECIAL(PTXN, (uint)(ptxn - disp->ptxn_pool));

    ustlt_t * ustlt_ele = ustlt_dlist_ele_pop_head( block->ustlt_needed, disp->ustlt_pool );
    ustlt_map_ele_remove_fast( disp->ustlt_map, ustlt_ele, disp->ustlt_pool );
    ptxn->in_degree = IN_DEGREE_UNSTAGED;
    ptxn->score = 0.0f;

    ptxn->edge_cnt_etc = 0U;

    ptxn->last          = (uint)(ustlt_ele - disp->ustlt_pool);
    ustlt_ele->ptxn_idx = (uint)(ptxn      - disp->ptxn_pool );

    ustlt_dlist_ele_push_tail( block->ustlt_created, ustlt_ele, disp->ustlt_pool );
  }
  block->inserted_cnt++;
  return ptxn_idx;
}

void
fd_rdisp_verify( fd_rdisp_t const * disp,
                 uint             * scratch ) {
  ulong acct_depth  = disp->depth*FD_RDISP_MAX_ACCT_PER_TXN;
  ulong block_depth = disp->block_depth;
  FD_TEST( 0==acct_map_verify ( disp->acct_map,      acct_depth+1UL,  disp->acct_pool  ) );
  FD_TEST( 0==acct_map_verify ( disp->free_acct_map, acct_depth+1UL,  disp->acct_pool  ) );
  FD_TEST( 0==block_map_verify( disp->blockmap,      block_depth+1UL, disp->block_pool ) );
  FD_TEST( 0==ustlt_map_verify( disp->ustlt_map,     acct_depth+1UL,  disp->ustlt_pool ) );

  /* Check all the in degree counts are right */
  memset( scratch, '\0', sizeof(uint)*disp->depth*(FD_RDISP_MAX_ACCT_PER_TXN+1UL)+2UL );
  scratch[ 0 ] = UINT_MAX;

  for( ulong j=0UL; j<disp->depth*(FD_RDISP_MAX_ACCT_PER_TXN+1UL)+2UL; j++ ) {
    int ptxn = j>disp->depth;
    fd_rdisp_txn_t const * rtxn = !ptxn ? disp->pool+j : (fd_rdisp_txn_t const *)(disp->ptxn_pool+(j-disp->depth-1UL));
    if( rtxn->in_degree==IN_DEGREE_FREE ) { scratch[ j ]=UINT_MAX; continue; }

    if( (rtxn->in_degree==IN_DEGREE_UNSTAGED_DISPATCHED) |
        (rtxn->in_degree==IN_DEGREE_UNSTAGED)            |
        (rtxn->in_degree==IN_DEGREE_ZOMBIE) ) continue;

    ulong w_cnt = fd_ulong_if( ptxn, 0UL, 1UL + ((rtxn->edge_cnt_etc    ) & 0x7FU) );
    ulong r_cnt = (rtxn->edge_cnt_etc>> 7) & 0x7FU;
    ulong edge_idx = 0UL;

    for( ulong i=0UL; i<w_cnt+r_cnt; i++ ) {
      edge_t const * e = rtxn->edges+edge_idx;
      edge_t const  e0 = *e;

      edge_idx += fd_ulong_if( i<w_cnt, 1UL, 3UL );

      if( FD_UNLIKELY( EDGE_IS_LAST( e0 ) ) ) {
        /* Make sure acct is ACTIVE */
        acct_info_t * ai = disp->acct_pool + EDGE_SPECIAL_IDX(e0);
        FD_TEST( !( (ai->states==0)&
                    (ai->last_reference[ 0 ]==0U)&(ai->last_reference[ 1 ]==0U)&
                    (ai->last_reference[ 2 ]==0U)&(ai->last_reference[ 3 ]==0U) ) );
        FD_TEST( EDGE_SPECIAL_IDX(e0)==acct_map_idx_query_const( disp->acct_map, &(ai->key), ULONG_MAX, disp->acct_pool ) );
        continue;
      }

      edge_t next_e = e0;
      edge_t const * child_edge;
      edge_t last_e = 0U;
      while( 1 ) {
        int child_is_writer;
        /* This loop first traverses the me->child link, and then
           traverses any sibling links.  For example, in the case that
           we're completing node D above, the first child_txn is E,
           and the second child_txn is F. */
        child_edge = FOLLOW_EDGE(     disp, next_e, child_is_writer );

        scratch[ fd_ulong_if( EDGE_IS_PTXN(next_e), EDGE_SPECIAL_IDX(next_e)+disp->depth+1UL, next_e>>8 ) ]++;

        if( child_is_writer || child_edge[1]==e0 ) break;
        if( last_e!=0U ) FD_TEST( child_edge[2]==last_e );
        last_e = next_e;
        next_e = child_edge[1];
        FD_TEST( next_e>=0x100U );
      }
    }
  }
  for( ulong i=0UL; i<disp->depth*(FD_RDISP_MAX_ACCT_PER_TXN+1UL)+2UL; i++ ) {
    fd_rdisp_txn_t const * rtxn = i<=disp->depth ? disp->pool+i : (fd_rdisp_txn_t const *)(disp->ptxn_pool+(i-disp->depth-1UL));
    FD_TEST( scratch[ i ]==UINT_MAX ||
             rtxn->in_degree==IN_DEGREE_DISPATCHED ||
             rtxn->in_degree==IN_DEGREE_UNSTAGED ||
             rtxn->in_degree==IN_DEGREE_UNSTAGED_DISPATCHED ||
             rtxn->in_degree==IN_DEGREE_ZOMBIE ||
             rtxn->in_degree==scratch[ i ] );
  }
}

void * fd_rdisp_leave ( fd_rdisp_t * disp ) { return disp; }
void * fd_rdisp_delete( void * mem        ) { return  mem; }
