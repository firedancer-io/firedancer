/* Generate prototypes, inlines and/or implementations for an ultra high
   performance bplus-tree-based key-val store.  A bplus tree can be
   persisted beyond the lifetime of creating process, used concurrently,
   used IPC, relocated in memory, naively serialized/deserialized and/or
   moved between hosts.  Virtually all operations on a bplus tree are a
   fast O(lg N) (where N is the number of elements stored) or better in
   worst case.

   At its core, this is fast binary search on a sorted array.  But the
   sorted array has been partition into leaves where each leaf is
   responsible for a continuous disjoint portion of the key space and
   union of the ranges covered by the leaves covers the entire key
   space.  The leaves are stored in a tree whose nodes have a large and
   flexible number of branches per each node that specify how leaves
   completely partition key space.  Further, to support fast forward and
   reverse iteration, the leaves are organized into a sorted doubly
   linked list.  Lastly, the interior nodes and leaves are guaranteed to
   be full enough that query has a fast O(lg N) worst case and have
   enough slack that insert / upsert / remove also have fast O(lg N)
   worst case.

   This leads to a number of improvements over textbook bplus trees,
   including:

   - Removal doesn't require nearly as much reshuffling of the interior
     nodes.  The only requirement here is that interior nodes form a
     complete partitioning of the key space.  (There is no requirement
     that interior nodes store copy of keys found in leaf nodes.)

   - No extra storage in the node is required for identifying whether or
     not an interior node or a leaf.

   - The leaf pair max radix can be independently tuned from the
     interior node pair radix (especially useful if sizing interior
     nodes and leaves to match things like memory page sizes).

   - Supports fast reverse iteration.

   Typical usage:

     struct mypair {
       mykey_t key;

       ... key can be located arbitrarily in struct (and renamed if
       ... needed ... see BPLUS_PAIR_KEY).  It is managed by the bplus
       ... tree and should not be modified).

       ... IMPORTANT SAFETY TIP!  The location of a pair can be changed
       ... by insert / upsert / remove operations.

     };

     typedef struct mypair mypair_t;

     #define BPLUS_NAME         mybplus
     #define BPLUS_KEY_T        mykey_t
     #define BPLUS_PAIR_T       mypair_t
     #define BPLUS_KEY_CMP(a,b) mykeycmp( (a), (b) )
     #include "fd_bplus.c"

   will provide the following APIs as a header only style library in the
   compilation unit:

     // A myplus_t is an opaque handle to a join to a bplus tree

     struct mybplus_private;
     typedef struct mybplus_private bplus_t;

     // A myplus_iter_t is an opaque handle to a bplus tree iterator

     struct mybplus_private_iter;
     typedef struct mybplus_private_iter mybplus_iter_t;

     // Constructors

     // mybplus_{leaf,node}_max_est returns a conservative estimate of
     // the number of {leaves,nodes} needed for a worst case bplus tree
     // containing ele_max_est elements.

     ulong mybplus_leaf_max_est( ulong ele_max_est );
     ulong mybplus_node_max_est( ulong ele_max_est );

     // mybplus_{align,footprint,new,join,leave,delete} have the usual
     // persistent IPC object constructors / destructors semantics.

     ulong mybplus_align    ( void );
     ulong mybplus_footprint( ulong node_max, ulong leaf_max );

     void      * mybplus_new   ( void * shmem, ulong node_max, ulong leaf_max );
     mybplus_t * mybplus_join  ( void * shbplus );
     void      * mybplus_leave ( mybplus_t * join );
     void      * mybplus_delete( void * shbplus );

     // Accessors

     // mybplus_{node,leaf}_max return the {node,leaf}_max values used
     // to construct the bplus tree.  Assumes join is a current local
     // join.  Fast O(1) worst case.

     ulong mybplus_node_max( mybplus_t const * join );
     ulong mybplus_leaf_max( mybplus_t const * join );

     // mybplus_is_empty returns 1 if the bplus tree contains no pairs
     // and 0 otherwise.  Assumes join is a current local join.  Fast
     // O(1) worst case.

     int mybplus_is_empty( mybplus_t const * join );

     // mybplus_{min,max} return the pointer in the caller's local
     // address space to the pair in the bplus tree with the {min,max}
     // key.  Assumes join is a current local join and bplus tree is not
     // empty.  The lifetime of the returned pointer is the lesser of
     // the lifetime of the local join or the next insert / upsert /
     // remove operation on the bplus tree.  The bplus tree retains
     // ownership of the returned pair and the caller should not modify
     // the pair key field.  Fast O(1) worst case.
     //
     // mybplus_{min,max}_const is a const-correct version.

     mypair_t const * mybplus_min_const( mybplus_t const * join );
     mypair_t const * mybplus_max_const( mybplus_t const * join );
     mypair_t       * mybplus_min      ( mybplus_t       * join );
     mypair_t       * mybplus_max      ( mybplus_t       * join );

     // mybplus_query returns the pointer in the caller's local address
     // space to the pair in the bplus tree that matches the key pointed
     // to by query or NULL if there is no key matching query in the
     // bplus tree.  Assumes join is a current local join.  The lifetime
     // of the returned pointer is the lesser of the lifetime of the
     // local join or the next insert / upsert / remove operation on the
     // bplus tree.  The bplus tree retains ownership of the returned
     // pair and the caller should not modify the key field.  The bplus
     // tree has no interest in query in return.  Fast O(lg N) worst
     // case.
     //
     // mybplus_query_const is a const-correct version.

     mypair_t const * mybplus_query_const( mybplus_t const * join, mykey_t const * query );
     mypair_t *       mybplus_query(       mybplus_t       * join, mykey_t const * query );

     // Operations

     // mybplus_insert inserts a key into the bplus tree.  Assumes join
     // is a current local join and key points in the caller's address
     // space to the key to insert.  The bplus tree has no interest in
     // key in return.
     //
     // On success, returns the location in the caller's address space
     // where key was inserted.  The lifetime of the returned pointer is
     // the lesser of the lifetime of the local join or there is an
     // insert / upsert / remove operation on the bplus tree.  The
     // caller should not modify the pair key field but is free to
     // modify all the other values.
     //
     // On failure, returns NULL.  Reasons for failure are the key was
     // already in the tree (locations of pairs might have changed),
     // there were not enough nodes (locations of pairs did not change)
     // or there were not enough leaves available to complete the insert
     // (locations of pairs did not change).
     //
     // mybplus_upsert is nearly equivalent to:
     //
     //   int insert;
     //   mypair_t *    pair = mybplus_query ( join, key ); insert = 0;
     //   if( !pair ) { pair = mybplus_insert( join, key ); insert = 1; }
     //   if( pair && _opt_insert ) *_opt_insert = insert;
     //
     // but potentially faster as it only traverses the bplus tree once.
     // The "nearly" qualifier is that, unlike the above snippet, the
     // upsert might change the location of keys even if key is already
     // in the bplus tree.  Fast O(lg N) worst case.

     mypair_t * mybplus_insert( mybplus_t * join, mykey_t const * key );
     mypair_t * mybplus_upsert( mybplus_t * join, mykey_t const * key, int * _opt_insert );

     // mybplus_remove_key removes a key from the bplus tree.  Assumes
     // join is a current local join and key points in the caller's
     // address space to the key to remove.  Returns 0 on success and -1
     // if the key was not found in the tree.  The bplus tree has no
     // interest in key in return.  Fast O(lg N) worst case.

     int mybplus_remove_key( mybplus_t * join, mykey_t const * key );

     // mybplus_remove removes the pair pointed to by pair from the
     // bplus tree.  Assumes join is a current local join and pair is a
     // pointer in the caller's local address space to a pair that is
     // currently in the bplus tree.  The pair is no longer in the bplus
     // tree on return.  Fast O(lg N) worst case.

     void mybplus_remove( mybplus_t * join, mypair_t * pair );

     // mybplus_flush removes all pairs from the bplus tree.  Assumes
     // join is a current local join.  There are no pairs in the bplus
     // tree on return.  Fast O( node_max + leaf_max ) worst case.

     void mybplus_flush( mybplus_t * join );

     // mybplus_verify validates the bplus tree pointed by join.
     // Returns 0 on success and -1 on failure (logs details).
     // O(node_max+leaf_max) worst case.

     int mybplus_verify( mybplus_t const * join );

     // Iteration

     // mybplus_iter_nul returns an iterator positioned at nul.  Fast
     // O(1) worst case.
     //
     // mybplus_iter_min returns an iterator positioned at the min pair
     // or nul if the bplus is empty.  Fast O(1) worst case.
     //
     // mybplus_iter_max returns an iterator positioned at the max pair
     // or nul if the bplus is empty.  Fast O(1) worst case.
     //
     // mybplus_iter_ge returns an iterator positioned at the first pair
     // greater than or equal to query or at nul if all keys are less
     // than query.  query==NULL is equivalent to "+inf".  Fast O(lg N)
     // worst case.
     //
     // mybplus_iter_gt returns an iterator positioned at the first pair
     // greater than query or at nul if all keys are less than or equal
     // to query.  query==NULL is equivalent to "+inf".  Fast O(lg N)
     // worst case.
     //
     // mybplus_iter_le returns an iterator positioned at the last pair
     // less than or equal to query or at nul if all keys are greater
     // than query.  query==NULL is equivalent to "-inf".  Fast O(lg N)
     // worst case.
     //
     // mybplus_iter_lt returns an iterator positioned at the last pair
     // less than to query or at nul if all keys are greater than or
     // equal to query.  query==NULL is equivalent to "-inf".  Fast
     // O(lg N) worst case.
     //
     // mybplus_iter_next returns an iterator positioned at the next
     // pair or nul if the iterator is currently positioned at last
     // pair.  Fast O(1) worst case.
     //
     // mybplus_iter_prev returns an iterator positioned at the previous
     // pair or nul if the iterator is currently positioned at first
     // pair.  Fast O(1) worst case.
     //
     // mybplus_iter_eq returns true if iter is positioned at the same
     // place fini is positioned.  Fast O(1) worst case.
     //
     // mybplus_iter_pair returns a pair associated with the current
     // iteration position.  mybplus_iter_pair_const is a const correct
     // version.  Fast O(1) worst case.
     //
     // Assumes join is a current local join and query points to a valid
     // key in the caller's local address space.  Retains no interest in
     // query on return.
     //
     // Example: iterate over all pairs in ascending order:
     //
     //   for( mybplus_iter_t iter = mybplus_iter_min( bplus );
     //        !mybplus_iter_eq_nul( bplus, iter );
     //        iter = mybplus_iter_next( bplus, iter ) ) {
     //     mypair_t * pair = mybplus_iter_pair( bplus, iter );
     //     ... process pair here
     //     ... do not insert, upsert remove keys from bplus here
     //     ... do not modify key of pair here
     //   }
     //
     // Example: iterate over all pairs in descending order:
     //
     //   for( mybplus_iter_t iter = mybplus_iter_max( bplus );
     //        !mybplus_iter_eq_nul( bplus, iter );
     //        iter = mybplus_iter_prev( bplus, iter ) ) {
     //     mypair_t * pair = mybplus_iter_pair( bplus, iter );
     //     ... process pair here
     //     ... do not insert, upsert remove keys from bplus here
     //     ... do not modify key of pair here
     //   }
     //
     // Example: iterate over all pairs with keys in [key0,key1) in
     // ascending order (assumes key1>=key0):
     //
     //   mybplus_iter_t iter = mybplus_iter_ge( bplus, key0 );
     //   mybplus_iter_t fini = mybplus_iter_ge( bplus, key1 ); // key1==NULL will iterate over all pairs with keys >= key0
     //   while( !mybplus_iter_eq( bplus, iter, fini ) ) {
     //     mypair_t * pair = mybplus_iter_pair( bplus, iter );
     //
     //     ... process pair here
     //     ... do not insert, upsert or remove keys from bplus here
     //     ... do not modify key of pair here
     //
     //     iter = mybplus_iter_next( bplus, iter );
     //   }
     //
     // Example: iterate over all pairs with keys in [key0,key1] in
     // ascending order (assumes key1>=key0):
     //
     //   mybplus_iter_t iter = mybplus_iter_ge( bplus, key0 );
     //   mybplus_iter_t fini = mybplus_iter_gt( bplus, key1 ); // key1==NULL will iterate over all pairs with keys >= key0
     //   while( !mybplus_iter_eq( bplus, iter, fini ) ) {
     //     mypair_t * pair = mybplus_iter_pair( bplus, iter );
     //
     //     ... process pair here
     //     ... do not insert, upsert or remove keys from bplus here
     //     ... do not modify key of pair here
     //
     //     iter = mybplus_iter_next( bplus, iter );
     //   }
     //
     // Example: iterate over all pairs with keys in (key0,key1) in
     // ascending order (assumes key1>=key0):
     //
     //   mybplus_iter_t iter = mybplus_iter_gt( bplus, key0 );
     //   mybplus_iter_t fini = mybplus_iter_ge( bplus, key1 ); // key1==NULL will iterate over all pairs with keys > key0
     //   while( !mybplus_iter_eq( bplus, iter, fini ) ) {
     //     mypair_t * pair = mybplus_iter_pair( bplus, iter );
     //
     //     ... process pair here
     //     ... do not insert, upsert or remove keys from bplus here
     //     ... do not modify key of pair here
     //
     //     iter = mybplus_iter_next( bplus, iter );
     //   }
     //
     // Example: iterate over all pairs with keys in (key0,key1] in
     // ascending order (assumes key1>=key0):
     //
     //   mybplus_iter_t iter = mybplus_iter_gt( bplus, key0 );
     //   mybplus_iter_t fini = mybplus_iter_gt( bplus, key1 ); // key1==NULL will iterate over all pairs with keys > key0
     //   while( !mybplus_iter_eq( bplus, iter, fini ) ) {
     //     mypair_t * pair = mybplus_iter_pair( bplus, iter );
     //
     //     ... process pair here
     //     ... do not insert, upsert or remove keys from bplus here
     //     ... do not modify key of pair here
     //
     //     iter = mybplus_iter_next( bplus, iter );
     //   }
     //
     // Example: iterate over all pairs with keys in [key0,key1) in
     // descending order (assumes key1>=key0):
     //
     //   mybplus_iter_t iter = mybplus_iter_lt( bplus, key1 );
     //   mybplus_iter_t fini = mybplus_iter_lt( bplus, key0 ); // key0==NULL will iterate over all pairs with keys < key1
     //   while( !mybplus_iter_eq( bplus, iter, fini ) ) {
     //     mypair_t * pair = mybplus_iter_pair( bplus, iter );
     //
     //     ... process pair here
     //     ... do not insert, upsert or remove keys from bplus here
     //     ... do not modify key of pair here
     //
     //     iter = mybplus_iter_prev( bplus, iter );
     //   }
     //
     // Example: iterate over all pairs with keys in [key0,key1] in
     // descending order (assumes key1>=key0):
     //
     //   mybplus_iter_t iter = mybplus_iter_le( bplus, key1 );
     //   mybplus_iter_t fini = mybplus_iter_lt( bplus, key0 ); // key0==NULL will iterate over all pairs with keys <= key1
     //   while( !mybplus_iter_eq( bplus, iter, fini ) ) {
     //     mypair_t * pair = mybplus_iter_pair( bplus, iter );
     //
     //     ... process pair here
     //     ... do not insert, upsert or remove keys from bplus here
     //     ... do not modify key of pair here
     //
     //     iter = mybplus_iter_prev( bplus, iter );
     //   }
     //
     // Example: iterate over all pairs with keys in (key0,key1) in
     // descending order (assumes key1>=key0):
     //
     //   mybplus_iter_t iter = mybplus_iter_lt( bplus, key1 );
     //   mybplus_iter_t fini = mybplus_iter_le( bplus, key0 ); // key0==NULL will iterate over all pairs with keys < key1
     //   while( !mybplus_iter_eq( bplus, iter, fini ) ) {
     //     mypair_t * pair = mybplus_iter_pair( bplus, iter );
     //
     //     ... process pair here
     //     ... do not insert, upsert or remove keys from bplus here
     //     ... do not modify key of pair here
     //
     //     iter = mybplus_iter_prev( bplus, iter );
     //   }
     //
     // Example: iterate over all pairs with keys in (key0,key1] in
     // descending order (assumes key1>=key0):
     //
     //   mybplus_iter_t iter = mybplus_iter_le( bplus, key1 );
     //   mybplus_iter_t fini = mybplus_iter_le( bplus, key0 ); // key0==NULL will iterate over all pairs with keys < key1
     //   while( !mybplus_iter_eq( bplus, iter, fini ) ) {
     //     mypair_t * pair = mybplus_iter_pair( bplus, iter );
     //
     //     ... process pair here
     //     ... do not insert, upsert or remove keys from bplus here
     //     ... do not modify key of pair here
     //
     //     iter = mybplus_iter_prev( bplus, iter );
     //   }

     mybplus_iter_t mybplus_iter_nul( mybplus_t const * join );
     mybplus_iter_t mybplus_iter_min( mybplus_t const * join );
     mybplus_iter_t mybplus_iter_max( mybplus_t const * join );

     mybplus_iter_t mybplus_iter_ge( mybplus_t const * join, mykey_t const * query );
     mybplus_iter_t mybplus_iter_gt( mybplus_t const * join, mykey_t const * query );
     mybplus_iter_t mybplus_iter_le( mybplus_t const * join, mykey_t const * query );
     mybplus_iter_t mybplus_iter_lt( mybplus_t const * join, mykey_t const * query );

     int mybplus_iter_eq    ( mybplus_t const * join, mybplus_iter_t i0, mybplus_iter_t i1 );
     int mybplus_iter_eq_nul( mybplus_t const * join, mybplus_iter_t iter );

     mybplus_iter_t mybplus_iter_next( mybplus_t const * join, mybplus_iter_t iter );
     mybplus_iter_t mybplus_iter_prev( mybplus_t const * join, mybplus_iter_t iter );

     mypair_t const * mybplus_iter_pair_const( mybplus_t const * join, mybplus_iter_t iter );
     mypair_t       * mybplus_iter_pair      ( mybplus_t *       join, mybplus_iter_t iter );

   You can do this as often as you like in a compilation unit to get
   different types of bplus trees.  Variants exist for making header
   protoypes only and/or implementations if doing a library with
   multiple compilation units.  Further, options exist to use different
   hashing functions, comparison functions, etc as detailed below. */

/* BPLUS_NAME gives the API prefix. */

#ifndef BPLUS_NAME
#error "Define BPLUS_NAME"
#endif

/* BPLUS_KEY_T gives the key type.  Should be a plain-old-data type with
   a total order. */

#ifndef BPLUS_KEY_T
#error "Define BPLUS_KEY_T"
#endif

/* BPLUS_PAIR_T gives the pair type.  Should be a structure of the form:

     typedef struct BPLUS_PAIR {
       BPLUS_KEY_T key; // Can be arbitrarily placed in structure, should not be modified by the user
       ... arbitrary user fields
     } BPLUS_PAIR_T;

  (Or the appropriate field name given BPLUS_PAIR_KEY below.) */

#ifndef BPLUS_PAIR_T
#error "Define BPLUS_PAIR_T"
#endif

/* BPLUS_PAIR_KEY gives the name of the key field in the BPLUS_PAIR_KEY.
   Defaults to key. */

#ifndef BPLUS_PAIR_KEY
#define BPLUS_PAIR_KEY key
#endif

/* BPLUS_KEY_CMP compares the keys pointed to by a and b and returns
   {<0,0,>0} if the a is {less than,equal to,greater than}.  a and b
   will be valid pointers to key .  Defaults to memcmp based. */

#ifndef BPLUS_KEY_CMP
#define BPLUS_KEY_CMP(a,b) memcmp( (a), (b), sizeof(*(a)) )
#endif

/* BPLUS_TREE_MAX is the maximum number of children a non-leaf node can
   have.  Must be even, >=4 and <<< ULONG_MAX.  Defaults to 128. */

#ifndef BPLUS_TREE_MAX
#define BPLUS_TREE_MAX 128
#endif

/* BPLUS_PAIR_MAX is the maximum number of children a leaf node can
   have.  Must be even, >=4 and <<< ULONG_MAX.  Defaults to 128. */

#ifndef BPLUS_PAIR_MAX
#define BPLUS_PAIR_MAX 128
#endif

/* BPLUS_ALIGN gives the default alignment of the BPLUS region.  Should
   be a positive integer power of 2.  Defaults to 128. */

#ifndef BPLUS_ALIGN
#define BPLUS_ALIGN 128
#endif

/* BPLUS_NODE_ALIGN gives the default alignment of an interior node.
   Should be a positive integer power of 2 of at most BPLUS_ALIGN.
   Defaults to 128. */

#ifndef BPLUS_NODE_ALIGN
#define BPLUS_NODE_ALIGN 128
#endif

/* BPLUS_LEAF_ALIGN gives the default alignment of a leaf node.  Should
   be a positive integer power of 2 of at most BPLUS_ALIGN.  Defaults to
   128. */

#ifndef BPLUS_LEAF_ALIGN
#define BPLUS_LEAF_ALIGN 128
#endif

/* BPLUS_MAGIC is the structure magic number to use to aid in persistent
   and or IPC usage. */

#ifndef BPLUS_MAGIC
#define BPLUS_MAGIC (0xfdb91c53a61c0000UL) /* FD BPLUS MAGIC 0000 */
#endif

/* BPLUS_IMPL_STYLE indicates what this generator should output:
     0 - static implementation
     1 - library header
     2 - library implementation */

#ifndef BPLUS_IMPL_STYLE
#define BPLUS_IMPL_STLYE 0
#endif

/**********************************************************************/

#define BPLUS_(name)FD_EXPAND_THEN_CONCAT3(BPLUS_NAME,_,name)

#if BPLUS_IMPL_STYLE==0
#define BPLUS_STATIC FD_FN_UNUSED static
#else
#define BPLUS_STATIC
#endif

#if BPLUS_IMPL_STYLE==0 || BPLUS_IMPL_STYLE==1

/* Header *************************************************************/

#include "../log/fd_log.h"

struct BPLUS_(private);
typedef struct BPLUS_(private) BPLUS_(t);

struct BPLUS_(private_iter);
typedef struct BPLUS_(private_iter) BPLUS_(iter_t);

/* Internal use only */

/* A bplus_private_node_t is used for finding leaves that might contain
   an element fast. */

struct __attribute__((aligned(BPLUS_NODE_ALIGN))) BPLUS_(private_node) {

  /* This point is BPLUS_NODE_ALIGN aligned */

  ulong       tree_cnt;                     /* if acquired, in [0,BPLUS_TREE_MAX],  else ignored */
  ulong       tree_off[ BPLUS_TREE_MAX   ]; /* if acquired, indexed [0,tree_cnt),   else
                                               tree_off[0]==node pool next offset (0 if last node in pool) */
  BPLUS_KEY_T pivot   [ BPLUS_TREE_MAX-1 ]; /* if acquired, indexed [0,tree_cnt-1), else ignored */

  /* tree i handles keys in [ pivot[i-1], pivot[i] ), pivot[-1] /
     pivot[tree_cnt-1] are implied to be the previous / next pivot in an
     in-order traversal of the bplus tree node pivots (or -/+inf if
     leftmost/rightmost). */
};

typedef struct BPLUS_(private_node) BPLUS_(private_node_t);

/* A bplus_private_leaf_t holds up to pair_cnt elements of pairs in the
   tree in a sorted order. */

struct __attribute__((aligned(BPLUS_LEAF_ALIGN))) BPLUS_(private_leaf) {

  /* This point is BPLUS_LEAF_ALIGN aligned */

  ulong        pair_cnt;               /* if acquired, in [0,BPLUS_PAIR_MAX],                                    else ignored */
  ulong        prev_off;               /* if acquired, prev leaf offset (or 0 if first leaf),                    else ignored */
  ulong        next_off;               /* if acquired, next leaf offset (or 0 if last  leaf),
                                          else leaf pool next offset (0 if last node in pool) */
  BPLUS_PAIR_T pair[ BPLUS_PAIR_MAX ]; /* if acquired, indexed [0,pair_cnt), unique keys and in ascending order, else ignored */
};

typedef struct BPLUS_(private_leaf) BPLUS_(private_leaf_t);

/* A bplus_private_t is a continguous region of memory that holds a
   bplus tree.  Important invariants:

   - Empty trees have no root.
   - If root is a leaf, it has [1,pair_max] pairs.
   - If root is a node, it has [2,tree_max] trees.
   - Non-root nodes  have [tree_min,tree_max] trees.
   - Non-root leaves have [pair_min,pair_max] pairs.
   - Children of a node are not a mix of nodes and leaves. */

struct __attribute__((aligned(BPLUS_ALIGN))) BPLUS_(private) {

  /* This point is aligned BPLUS_ALIGN */

  ulong magic;                              /* ==BPLUS_MAGIC */
  ulong node_max;      ulong leaf_max;      /* maximum number of node/leaf in the store */
  ulong node_lo;       ulong leaf_lo;       /* offset from the first byte of bplus header to the node/leaf storage */
  ulong node_pool_off; ulong leaf_pool_off; /* first node/leaf in node/leaf pool, 0 if no node/leaf in pool */
  ulong root_off;                           /* offset of node/leaf to tree root (or 0 if empty) */
  ulong leaf_min_off;                       /* offset of leaf with minimum pair (or 0 if empty) */
  ulong leaf_max_off;                       /* offset of leaf with maximum pair (or 0 if empty) */

  /* padding to BPLUS_NODE_ALIGN here */
  /* node_lo points here, node_max elements, indexed [0,node_max) */
  /* padding to BPLUS_LEAF_ALIGN here */
  /* leaf_lo points here, leaf_max elements, indexed [0,leaf_max) */
  /* padding to BPLUS_ALIGN here */

};

typedef struct BPLUS_(private) BPLUS_(private_t);

struct BPLUS_(private_iter) {
  ulong leaf_off; /* offset to current leaf */
  ulong pair_idx; /* current pair in current leaf */
};

FD_PROTOTYPES_BEGIN

/* bplus_private_{pair,tree}_{min,max} return the corresponding
   configuration values for this bplus implementation. */

FD_FN_CONST static inline ulong BPLUS_(private_pair_min)( void ) { return (ulong)(BPLUS_PAIR_MAX/2); } /* exact */
FD_FN_CONST static inline ulong BPLUS_(private_pair_max)( void ) { return (ulong) BPLUS_PAIR_MAX;    }

FD_FN_CONST static inline ulong BPLUS_(private_tree_min)( void ) { return (ulong)(BPLUS_TREE_MAX/2); } /* exact */
FD_FN_CONST static inline ulong BPLUS_(private_tree_max)( void ) { return (ulong) BPLUS_TREE_MAX;    }

/* bplus_private_{node,leaf}_max_max return a value for {node,leaf}_max
   such that the {node,leaf} storage of the bplus tree will require at
   most 2^62 bytes. */

FD_FN_CONST static inline ulong
BPLUS_(private_node_max_max)( void ) {
  return ((1UL<<62)-BPLUS_NODE_ALIGN+1UL) / sizeof( BPLUS_(private_node_t));
}

FD_FN_CONST static inline ulong
BPLUS_(private_leaf_max_max)( void ) {
  return ((1UL<<62)-BPLUS_LEAF_ALIGN+1UL) / sizeof( BPLUS_(private_leaf_t));
}

/* bplus_private_key_cmp gives BPLUS_KEY_CMP the exact function
   signature used by the below implementations. */

FD_FN_PURE static inline int
BPLUS_(private_key_cmp)( BPLUS_KEY_T const * a,
                         BPLUS_KEY_T const * b ) {
  return BPLUS_KEY_CMP(a,b);
}

/* bplus_private_is_leaf returns 1 if the root of the tree at bplus
   global offset is a leaf or 0 if it is a node.  leaf_lo is the bplus
   global offset of the leaf preallocated storage.  Assumes tree_off and
   leaf_lo are valid. */

FD_FN_CONST static inline int BPLUS_(private_is_leaf)( ulong tree_off, ulong leaf_lo ) { return tree_off>=leaf_lo; }

/* bplus_private returns location of the bplus private metadata in the
   caller's address space given a valid local join.  Lifetime of the
   returned pointer is the lifetime of the join.  bplus_private_const is
   a const correct version. */

FD_FN_CONST static inline BPLUS_(private_t) *
BPLUS_(private)( BPLUS_(t) * join ) {
  return (BPLUS_(private_t) *)join;
}

FD_FN_CONST static inline BPLUS_(private_t) const *
BPLUS_(private_const)( BPLUS_(t) const * join ) {
  return (BPLUS_(private_t) const *)join;
}

/* bplus_private_{node,leaf} return the pointer in the caller's local
   address space of the {node,leaf} located at bplus global
   {node,leaf}_off.  The lifetime of the returned pointer is the
   lifetime of the local join.  Assumes bplus and node_off are valid. */

FD_FN_CONST static inline BPLUS_(private_node_t) *
BPLUS_(private_node)( BPLUS_(private_t) * bplus,
                      ulong               node_off ) {
  return (BPLUS_(private_node_t) *)((ulong)bplus + node_off);
}

FD_FN_CONST static inline BPLUS_(private_leaf_t) *
BPLUS_(private_leaf)( BPLUS_(private_t) * bplus,
                      ulong               leaf_off ) {
  return (BPLUS_(private_leaf_t) *)((ulong)bplus + leaf_off);
}

FD_FN_CONST static inline BPLUS_(private_node_t) const *
BPLUS_(private_node_const)( BPLUS_(private_t) const * bplus,
                            ulong                     node_off ) {
  return (BPLUS_(private_node_t) const *)((ulong)bplus + node_off);
}

FD_FN_CONST static inline BPLUS_(private_leaf_t) const *
BPLUS_(private_leaf_const)( BPLUS_(private_t) const * bplus,
                            ulong                     leaf_off ) {
  return (BPLUS_(private_leaf_t) const *)((ulong)bplus + leaf_off);
}

/* bplus_private_off returns the bplus global offset for the given
   address in the caller's address space.  Assumes bplus is valid and
   addr is non-NULL and into the bplus memory region. */

FD_FN_CONST static inline ulong
BPLUS_(private_off)( BPLUS_(private_t) const * bplus,
                     void const *              addr ) {
  return (ulong)addr - (ulong)bplus;
}

/* bplus_private_node_acquire acquires a node from the bplus's node pool
   and returns a pointer to it in the caller's address space.  Assumes
   bplus is valid.  Returns NULL if bplus node pool is empty.

   bplus_private_node_release releases a node to the bplus's node pool.
   Assumes bplus is valid, node is valid and node is not currently in
   the pool.

   Similarly for bplus_private_leaf_{acquire,release}. */

static inline BPLUS_(private_node_t) *
BPLUS_(private_node_acquire)( BPLUS_(private_t) * bplus ) {
  ulong node_off = bplus->node_pool_off;
  if( FD_UNLIKELY( !node_off ) ) return NULL;
  BPLUS_(private_node_t *) node = BPLUS_(private_node)( bplus, node_off );
  bplus->node_pool_off = node->tree_off[0];
  return node;
}

static inline void
BPLUS_(private_node_release)( BPLUS_(private_t)      * bplus,
                              BPLUS_(private_node_t) * node ) {
  node->tree_off[0]    = bplus->node_pool_off;
  bplus->node_pool_off = BPLUS_(private_off)( bplus, node );
}

static inline BPLUS_(private_leaf_t) *
BPLUS_(private_leaf_acquire)( BPLUS_(private_t) * bplus ) {
  ulong leaf_off = bplus->leaf_pool_off;
  if( FD_UNLIKELY( !leaf_off ) ) return NULL;
  BPLUS_(private_leaf_t *) leaf = BPLUS_(private_leaf)( bplus, leaf_off );
  bplus->leaf_pool_off = leaf->next_off;
  return leaf;
}

static inline void
BPLUS_(private_leaf_release)( BPLUS_(private_t)      * bplus,
                              BPLUS_(private_leaf_t) * leaf ) {
  leaf->next_off       = bplus->leaf_pool_off;
  bplus->leaf_pool_off = BPLUS_(private_off)( bplus, leaf );
}

/* bplus_private_insert inserts or upserts a key into a bplus tree.
   Assumes join is a current local join and key points to a valid key in
   the caller's address space and upsert is in [0,1].

   upsert 0: key will inserted into bplus.  On success, returns the pair
   where key was inserted and, on return, *_insert will be 1.  Caller
   can update all fields in the pair except the key.  Lifetime of the
   returned pointer is until the next insert / upsert / remove.  Returns
   NULL if there was no room in the bplus tree or if key was already in
   the bplus tree (might have moved pairs around in bplus tree on
   failure) and _insert will be untouched.

   upsert 1: key will inserted or updated into bplus.  If key is already
   present in the bplus tree, returns the location in the caller's
   address space of the pair with the matching key and, on return,
   *_insert will be 0.  If not, inserts the key and requires the
   location in the caller's address space where pair was inserted and,
   on return, *_insert will be 1.  In both cases, the lifetime of the
   returned pointer is until the next insert / upsert / remove.  Returns
   NULL if there was no room in the bplus tree to insert (might have
   moved pairs around in bplus tree on failure) and _insert will be
   untouched.

   The bplus retains no interest in query on return. */

BPLUS_STATIC BPLUS_PAIR_T *
BPLUS_(private_insert)( BPLUS_(t)         * join,
                        BPLUS_KEY_T const * key,
                        int                 upsert,
                        int *               _insert );

/* bplus_private_iter returns the iterator corresponding to query and
   op.  Assumes join is a current local join, query points to a valid
   key in the caller's address space or is NULL and op is in [0,3].
   Returns an iter positioned at:

     op     | position
     -------+-------------------------------------------------------------------------------------------------------------------
     0 (GE) | the first pair with a key greater than or equal to query (or nul if all have keys less than query)
     1 (GT) | the first pair with a key greater than             query (or nul if all have keys less than or equal to query)
     2 (LE) | the last  pair with a key less    than or equal to query (or nul if all have keys greater than query)
     3 (LT) | the last  pair with a key less    than             query (or nul if all have keys greater than or equal to query)

   If query is NULL, iteration will be positioned as though:

     op     | query
     -------+-------
     0 (GE) | +inf
     1 (GT) | +inf
     2 (LE) | -inf
     3 (LT) | -inf

   The bplus retains no interest in query on return. */

FD_FN_PURE BPLUS_STATIC BPLUS_(iter_t)
BPLUS_(private_iter)( BPLUS_(t)   const * join,
                      BPLUS_KEY_T const * query,
                      int                 op );

FD_PROTOTYPES_END

/* End internal use only */

FD_PROTOTYPES_BEGIN

/* Constructors */

FD_FN_CONST BPLUS_STATIC ulong BPLUS_(leaf_max_est)( ulong ele_max_est );
FD_FN_CONST BPLUS_STATIC ulong BPLUS_(node_max_est)( ulong ele_max_est );

FD_FN_CONST BPLUS_STATIC ulong BPLUS_(align)    ( void );
FD_FN_CONST BPLUS_STATIC ulong BPLUS_(footprint)( ulong node_max, ulong leaf_max );

BPLUS_STATIC void      * BPLUS_(new)   ( void *      shmem, ulong node_max, ulong leaf_max );
BPLUS_STATIC BPLUS_(t) * BPLUS_(join)  ( void *      shbplus );
BPLUS_STATIC void      * BPLUS_(leave) ( BPLUS_(t) * join );
BPLUS_STATIC void      * BPLUS_(delete)( void *      shbplus );

/* Accessors */

FD_FN_PURE static inline ulong BPLUS_(node_max)( BPLUS_(t) const * join ) { return BPLUS_(private_const)( join )->node_max; }
FD_FN_PURE static inline ulong BPLUS_(leaf_max)( BPLUS_(t) const * join ) { return BPLUS_(private_const)( join )->leaf_max; }

FD_FN_PURE static inline int BPLUS_(is_empty)( BPLUS_(t) const * join ) { return !BPLUS_(private_const)( join )->root_off; }

FD_FN_PURE static inline BPLUS_PAIR_T const *
BPLUS_(min_const)( BPLUS_(t) const * join ) {
  BPLUS_(t) const * bplus = BPLUS_(private_const)( join );
  BPLUS_(private_leaf_t) const * leaf = BPLUS_(private_leaf_const)( bplus, bplus->leaf_min_off );
  return &leaf->pair[0];
}

FD_FN_PURE static inline BPLUS_PAIR_T const *
BPLUS_(max_const)( BPLUS_(t) const * join ) {
  BPLUS_(t) const * bplus = BPLUS_(private_const)( join );
  BPLUS_(private_leaf_t) const * leaf = BPLUS_(private_leaf_const)( bplus, bplus->leaf_max_off );
  return &leaf->pair[ leaf->pair_cnt-1UL ];
}

FD_FN_PURE static inline BPLUS_PAIR_T * BPLUS_(min)( BPLUS_(t) * join ) { return (BPLUS_PAIR_T *)BPLUS_(min_const)( join ); }
FD_FN_PURE static inline BPLUS_PAIR_T * BPLUS_(max)( BPLUS_(t) * join ) { return (BPLUS_PAIR_T *)BPLUS_(max_const)( join ); }

FD_FN_PURE BPLUS_STATIC BPLUS_PAIR_T const * BPLUS_(query_const)( BPLUS_(t) const * join, BPLUS_KEY_T const * query );

FD_FN_PURE static inline BPLUS_PAIR_T *
BPLUS_(query)( BPLUS_(t)         * join,
               BPLUS_KEY_T const * query ) {
  return (BPLUS_PAIR_T *)BPLUS_(query_const)( join, query );
}

/* Operations */

static inline BPLUS_PAIR_T *
BPLUS_(insert)( BPLUS_(t) *         join,
                BPLUS_KEY_T const * key ) {
  int dummy;
  return BPLUS_(private_insert)( join, key, 0, &dummy );
}

static inline BPLUS_PAIR_T *
BPLUS_(upsert)( BPLUS_(t) *         join,
                BPLUS_KEY_T const * key,
                int *               _opt_insert ) {
  int dummy;
  if( !_opt_insert ) _opt_insert = &dummy; /* compile time */
  return BPLUS_(private_insert)( join, key, 1, _opt_insert );
}

BPLUS_STATIC int BPLUS_(remove_key)( BPLUS_(t) * join, BPLUS_KEY_T const * key );

static inline void BPLUS_(remove)( BPLUS_(t) * join, BPLUS_PAIR_T * pair ) { BPLUS_(remove_key)( join, &pair->BPLUS_PAIR_KEY ); }

BPLUS_STATIC void BPLUS_(flush)( BPLUS_(t) * join );

BPLUS_STATIC int BPLUS_(verify)( BPLUS_(t) const * join );

/* Iteration */
/* FIXME: FD_FN_CONST for nul/eq/eq_nul/pair/pair_const?  FD_FN_PURE for
   min/max/prev/next? */

static inline BPLUS_(iter_t)
BPLUS_(iter_nul)( BPLUS_(t) const * join ) {
  (void)join;
  BPLUS_(iter_t) iter;
  iter.leaf_off = 0UL;
  iter.pair_idx = 0UL;
  return iter;
}

static inline BPLUS_(iter_t)
BPLUS_(iter_min)( BPLUS_(t) const * join ) {
  BPLUS_(private_t) const * bplus = BPLUS_(private_const)( join );
  ulong leaf_off = bplus->leaf_min_off;
  BPLUS_(iter_t) iter;
  iter.leaf_off = leaf_off;
  iter.pair_idx = 0UL;
  return iter;
}

static inline BPLUS_(iter_t)
BPLUS_(iter_max)( BPLUS_(t) const * join ) {
  BPLUS_(private_t) const * bplus = BPLUS_(private_const)( join );
  ulong leaf_off = bplus->leaf_max_off;
  BPLUS_(iter_t) iter;
  iter.leaf_off = leaf_off;
  iter.pair_idx = (FD_UNLIKELY( !leaf_off ) ? 1UL : BPLUS_(private_leaf_const)( bplus, leaf_off )->pair_cnt) - 1UL;
  return iter;
}

FD_FN_PURE static inline BPLUS_(iter_t)
BPLUS_(iter_ge)( BPLUS_(t)   const * join,
                 BPLUS_KEY_T const * query ) {
  return BPLUS_(private_iter)( join, query, 0 );
}

FD_FN_PURE static inline BPLUS_(iter_t)
BPLUS_(iter_gt)( BPLUS_(t)   const * join,
                 BPLUS_KEY_T const * query ) {
  return BPLUS_(private_iter)( join, query, 1 );
}

FD_FN_PURE static inline BPLUS_(iter_t)
BPLUS_(iter_le)( BPLUS_(t)   const * join,
                 BPLUS_KEY_T const * query ) {
  return BPLUS_(private_iter)( join, query, 2 );
}

FD_FN_PURE static inline BPLUS_(iter_t)
BPLUS_(iter_lt)( BPLUS_(t)   const * join,
                 BPLUS_KEY_T const * query ) {
  return BPLUS_(private_iter)( join, query, 3 );
}

static inline int
BPLUS_(iter_eq)( BPLUS_(t) const * join,
                 BPLUS_(iter_t)    iter,
                 BPLUS_(iter_t)    fini ) {
  (void)join;
  return (iter.leaf_off==fini.leaf_off) & (iter.pair_idx==fini.pair_idx);
}

static inline int
BPLUS_(iter_eq_nul)( BPLUS_(t) const * join,
                     BPLUS_(iter_t)    iter ) {
  (void)join;
  return !iter.leaf_off;
}

static inline BPLUS_(iter_t)
BPLUS_(iter_next)( BPLUS_(t) const * join,
                   BPLUS_(iter_t)    iter ) {
  BPLUS_(private_t) const * bplus = BPLUS_(private_const)( join );

  ulong leaf_off = iter.leaf_off;
  ulong pair_idx = iter.pair_idx;

  BPLUS_(private_leaf_t) const * leaf = BPLUS_(private_leaf_const)( bplus, leaf_off );

  pair_idx++;
  if( FD_UNLIKELY( pair_idx>=leaf->pair_cnt ) ) { /* optimize for high radix */
    leaf_off = leaf->next_off;
    pair_idx = 0UL;
  }

  iter.leaf_off = leaf_off;
  iter.pair_idx = pair_idx;
  return iter;
}

static inline BPLUS_(iter_t)
BPLUS_(iter_prev)( BPLUS_(t) const * join,
                   BPLUS_(iter_t)    iter ) {
  BPLUS_(private_t) const * bplus = BPLUS_(private_const)( join );

  ulong leaf_off = iter.leaf_off;
  ulong pair_idx = iter.pair_idx;

  BPLUS_(private_leaf_t) const * leaf = BPLUS_(private_leaf_const)( bplus, leaf_off );

  if( FD_UNLIKELY( !pair_idx ) ) { /* optimize for high radix */
    leaf_off = leaf->prev_off;
    pair_idx = FD_UNLIKELY( !leaf_off ) ? 1UL : BPLUS_(private_leaf_const)( bplus, leaf_off )->pair_cnt;
  }
  pair_idx--;

  iter.leaf_off = leaf_off;
  iter.pair_idx = pair_idx;
  return iter;
}

static inline BPLUS_PAIR_T const *
BPLUS_(iter_pair_const)( BPLUS_(t) const * join,
                         BPLUS_(iter_t)    iter ) {
  return BPLUS_(private_leaf_const)( BPLUS_(private_const)( join ), iter.leaf_off )->pair + iter.pair_idx;
}

static inline BPLUS_PAIR_T *
BPLUS_(iter_pair)( BPLUS_(t) *    join,
                   BPLUS_(iter_t) iter ) {
  return BPLUS_(private_leaf)( BPLUS_(private)( join ), iter.leaf_off )->pair + iter.pair_idx;
}

FD_PROTOTYPES_END

#endif

#if BPLUS_IMPL_STYLE==0 || BPLUS_IMPL_STYLE==2

/* Implementation *****************************************************/

/* bplus_private_node_query returns the index of a node's child tree,
   in [0,tree_cnt), that might contain query.

     tree 0          covers keys [ -inf,              pivot[0] )
          i          covers keys [ pivot[i-1],        pivot[i] )
          tree_cnt-1 covers keys [ pivot[tree_cnt-2], +inf     )

   Assumes pivot contains unique keys in ascending order, tree_cnt is in
   [2,tree_max], tree_max <<< ULONG_MAX and query is valid. */

FD_FN_PURE static ulong
BPLUS_(private_node_query)( BPLUS_KEY_T const * FD_RESTRICT pivot,
                            ulong                           tree_cnt,
                            BPLUS_KEY_T const * FD_RESTRICT query ) {
  ulong i0 = 0UL;
  ulong i1 = tree_cnt;

  do {

    /* At this point, query might be found in trees in [i0,i1) and this
       range contains at least two trees.  Test the middle tree.  If it
       matches exactly, we are done.  Otherwise, recurse on the
       appropriate half of the range. */

    ulong im = (i0+i1) >> 1; /* No overflow, at least 1 */

    int cmp = BPLUS_(private_key_cmp)( query, &pivot[im-1UL] );
    if( FD_UNLIKELY( !cmp ) ) return im; /* (optional) early abort, optimize for big trees */
    i0 = fd_ulong_if( cmp<0, i0, im );
    i1 = fd_ulong_if( cmp<0, im, i1 );

  } while( FD_LIKELY( (i1-i0)>1UL) ); /* optimize for big trees */

  return i0;
}

/* bplus_private_pair_query returns the index of a leaf's pair, in
   [0,pair_cnt), that exactly matches query or pair if there is no
   matching pair.  Assumes pair keys are unique and ascending sorted,
   pair_cnt is in [1,pair_max], pair_max <<< ULONG_MAX and query is
   valid. */

FD_FN_PURE static ulong
BPLUS_(private_pair_query)( BPLUS_PAIR_T const * FD_RESTRICT pair,
                            ulong                            pair_cnt,
                            BPLUS_KEY_T  const * FD_RESTRICT query ) {
  ulong i0 = 0UL;
  ulong i1 = pair_cnt;

  do {

    /* At this point, query might match one of the pairs in [i0,i1) and
       this range is not empty.  Test the pair in the middle.  If it
       matches, we found the pair.  Otherwise, recurse appropriate half
       of the range (exclusive of our query). */

    ulong im = (i0+i1) >> 1; /* No overflow */

    int cmp = BPLUS_(private_key_cmp)( query, &pair[im].BPLUS_PAIR_KEY );
    if( FD_UNLIKELY( !cmp ) ) return im; /* Found, optimize for big trees */
    i0 = fd_ulong_if( cmp<0, i0, im+1UL );
    i1 = fd_ulong_if( cmp<0, im, i1     );

  } while( FD_LIKELY( i1-i0 ) ); /* optimize for big trees */

  return pair_cnt; /* not found */
}

/* bplus_private_child_insert inserts a child at position child_idx into
   parent.  Parent should have a tree_cnt in [1,tree_max-1] and
   child_idx should be in [1,tree_cnt] (such that the child is never
   inserted into a parent with no children or a parent with the maximum
   number of children and is never inserted as the first born child).
   child_off is the bplus global offset of the child.  This can be a
   node or leaf but it should match parent's current children.
   child_pivot is the pivot value associated with the child and the
   child_idx should preserve the parent's pivot sorting.  Further, child
   should not contain any keys that outside the parent's pivot range
   after the insert. */

static void
BPLUS_(private_child_insert)( BPLUS_(private_node_t) * FD_RESTRICT parent,
                              ulong                                child_idx,
                              ulong                                child_off,
                              BPLUS_KEY_T const      * FD_RESTRICT child_pivot ) {
  ulong                     tree_cnt = parent->tree_cnt;
  ulong       * FD_RESTRICT tree_off = parent->tree_off;
  BPLUS_KEY_T * FD_RESTRICT pivot    = parent->pivot;

  /* Make room for child at child_idx by shifting childen currently at
     or after child_idx up one. */

  for( ulong sibling_idx=tree_cnt; sibling_idx>child_idx; sibling_idx-- ) {
    tree_off[sibling_idx    ] = tree_off[sibling_idx-1UL];
    pivot   [sibling_idx-1UL] = pivot   [sibling_idx-2UL];
  }

  /* Insert the child at child_idx */

  tree_off[child_idx    ] = child_off;
  pivot   [child_idx-1UL] = child_pivot[0];

  parent->tree_cnt = tree_cnt + 1UL; /* In [2,tree_max] */
}

/* bplus_private_child_remove removes the child child_idx from the bplus
   node parent.  Assumes parent is valid with a tree cnt in [2,tree_max]
   and that child is in [1,tree_cnt) (as such, this will never remove
   the first born child). */

static void
BPLUS_(private_child_remove)( BPLUS_(private_node_t) * FD_RESTRICT parent,
                              ulong                                child_idx ) {
  ulong                     tree_cnt = parent->tree_cnt;
  ulong       * FD_RESTRICT tree_off = parent->tree_off;
  BPLUS_KEY_T * FD_RESTRICT pivot    = parent->pivot;

  /* Fill the hole at child_idx by shifting childen currently at or
     after child_idx down one. */

  tree_cnt--;
  for( ulong sibling_idx=child_idx; sibling_idx<tree_cnt; sibling_idx++ ) {
    tree_off[sibling_idx    ] = tree_off[sibling_idx+1UL];
    pivot   [sibling_idx-1UL] = pivot   [sibling_idx    ];
  }

  parent->tree_cnt = tree_cnt; /* In [1,tree_max-1] */
}

ulong
BPLUS_(leaf_max_est)( ulong ele_max_est ) {

  /* No leaves needed for always empty trees */

  if( FD_UNLIKELY( !ele_max_est ) ) return 0UL;

  /* Trivial bplus trees have just a root leaf */

  if( FD_UNLIKELY( ele_max_est<=BPLUS_(private_pair_max)() ) ) return 1UL;

  /* In a non-trivial bplus tree, each leaf has at least
     pair_min==pair_max/2 elements.  So, we require:

          leaf_max*pair_min >= ele_max_est
       -> leaf_max >= ele_max_est / pair_min

     The smallest leaf_max that satisfies this is:

          ceil( ele_max_est / pair_min )
       -> floor( (ele_max_est + pair_min - 1) / pair_min )
       -> 1 + floor( (ele_max_est - 1) / pair_min */

  return 1UL + ((ele_max_est-1UL) / BPLUS_(private_pair_min)()); /* No overflow */
}

ulong
BPLUS_(node_max_est)( ulong ele_max_est ) {

  /* Start at the leaf layer with leaf_max trees */

  ulong node_max = 0UL;
  ulong tree_cnt = BPLUS_(leaf_max_est)( ele_max_est );

  while( tree_cnt>1UL ) {

    /* At this point, we have more than one tree in the current layer.
       To reduce the number of trees, we create a new layer of nodes
       above it and make each new node responsible for up to
       tree_min==tree_max/2 of the trees in the current layer to give a
       reasonably tight bound to the worst case.  That implies this new
       layer will need at most:

            ceil( tree_cnt / tree_min )
         -> floor( (tree_cnt + tree_min - 1) / tree_min )
         -> 1 + floor( (tree_cnt - 1) / tree_min )

       nodes and this layer will reduce to the number of trees to the
       same number. */

    tree_cnt = 1UL + ((tree_cnt-1UL) / BPLUS_(private_tree_min)()); /* No overflow */
    node_max += tree_cnt;

  }

  return node_max;
}

ulong
BPLUS_(align)( void ) {
  return BPLUS_ALIGN;
}

ulong
BPLUS_(footprint)( ulong node_max,
                   ulong leaf_max ) {

  if( FD_UNLIKELY( (node_max > BPLUS_(private_node_max_max)()) | (leaf_max > BPLUS_(private_leaf_max_max)()) ) ) return 0UL;

  /* At this point, the needed node and leaf storage is at most 2^63,
     which is impractically large but also with plenty of room left over
     for the metadata and remaining alignment padding. */

  ulong off = 0UL;                                  /**/                     off +=          sizeof( BPLUS_(private_t)      );
  off = fd_ulong_align_up( off, BPLUS_NODE_ALIGN ); /*ulong node_lo = off;*/ off += node_max*sizeof( BPLUS_(private_node_t) );
  off = fd_ulong_align_up( off, BPLUS_LEAF_ALIGN ); /*ulong leaf_lo = off;*/ off += leaf_max*sizeof( BPLUS_(private_leaf_t) );
  off = fd_ulong_align_up( off, BPLUS_ALIGN );

  return off;
}

void
BPLUS_(flush)( BPLUS_(t) * bplus ) {
  bplus->node_pool_off = 0UL;
  bplus->leaf_pool_off = 0UL;
  bplus->root_off      = 0UL;
  bplus->leaf_min_off  = 0UL;
  bplus->leaf_max_off  = 0UL;

  BPLUS_(private_node_t) * node = BPLUS_(private_node)( bplus, bplus->node_lo );
  for( ulong node_rem=bplus->node_max; node_rem; node_rem-- ) BPLUS_(private_node_release)( bplus, &node[ node_rem-1UL ] );

  BPLUS_(private_leaf_t) * leaf = BPLUS_(private_leaf)( bplus, bplus->leaf_lo );
  for( ulong leaf_rem=bplus->leaf_max; leaf_rem; leaf_rem-- ) BPLUS_(private_leaf_release)( bplus, &leaf[ leaf_rem-1UL ] );
}

void *
BPLUS_(new)( void * shmem,
             ulong  node_max,
             ulong  leaf_max ) {
  BPLUS_(private_t) * bplus = (BPLUS_(private_t) *)shmem;

  if( FD_UNLIKELY( !bplus ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)bplus, BPLUS_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = BPLUS_(footprint)( node_max, leaf_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad node_max and/or leaf_max" ));
    return NULL;
  }

  /* Note: it is the caller's responsibility to clear the memory because
     it is potentially very big and very time consuming to do so and may
     already have been cleared (e.g. mmap from the OS) */

  ulong off;
  off = 0UL;                                        /**/                 off +=          sizeof( BPLUS_(private_t)      );
  off = fd_ulong_align_up( off, BPLUS_NODE_ALIGN ); ulong node_lo = off; off += node_max*sizeof( BPLUS_(private_node_t) );
  off = fd_ulong_align_up( off, BPLUS_LEAF_ALIGN ); ulong leaf_lo = off; off += leaf_max*sizeof( BPLUS_(private_leaf_t) );
  off = fd_ulong_align_up( off, BPLUS_ALIGN );

  bplus->node_max      = node_max; bplus->leaf_max      = leaf_max;
  bplus->node_lo       = node_lo;  bplus->leaf_lo       = leaf_lo;

  BPLUS_(flush)( bplus );

  FD_COMPILER_MFENCE();
  bplus->magic = BPLUS_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

BPLUS_(t) *
BPLUS_(join)( void * shbplus ) {
  BPLUS_(private_t) * bplus = (BPLUS_(private_t) *)shbplus;

  if( FD_UNLIKELY( !bplus ) ) {
    FD_LOG_WARNING(( "NULL shbplus" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)bplus, BPLUS_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned shbplus" ));
    return NULL;
  }

  if( FD_UNLIKELY( bplus->magic!=BPLUS_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return (BPLUS_(t) *)bplus;
}

void *
BPLUS_(leave)( BPLUS_(t) * join ) {
  if( FD_UNLIKELY( !join ) ) {
    FD_LOG_WARNING(( "NULL join" ));
    return NULL;
  }

  return (void *)join;
}

void *
BPLUS_(delete)( void * shbplus ) {
  BPLUS_(private_t) * bplus = (BPLUS_(private_t) *)shbplus;

  if( FD_UNLIKELY( !bplus ) ) {
    FD_LOG_WARNING(( "NULL shbplus" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)bplus, BPLUS_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned shbplus" ));
    return NULL;
  }

  if( FD_UNLIKELY( bplus->magic!=BPLUS_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  bplus->magic = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)bplus;
}

BPLUS_PAIR_T const *
BPLUS_(query_const)( BPLUS_(t)   const * join,
                     BPLUS_KEY_T const * query ) {
  BPLUS_(private_t) const * bplus = BPLUS_(private_const)( join );

  /* If an empty bplus tree, not found */

  ulong tree_off = bplus->root_off;
  if( FD_UNLIKELY( !tree_off ) ) return NULL; /* optimize for big trees */

  /* At this point, the bplus tree is not empty.  Find the leaf that
     might contain query. */

  ulong leaf_lo = bplus->leaf_lo;
  while( FD_LIKELY( !BPLUS_(private_is_leaf)( tree_off, leaf_lo ) ) ) { /* optimize for big trees */
    BPLUS_(private_node_t) const * node = BPLUS_(private_node_const)( bplus, tree_off );
    tree_off = node->tree_off[ BPLUS_(private_node_query)( node->pivot, node->tree_cnt, query ) ];
  }
  BPLUS_(private_leaf_t) const * leaf = BPLUS_(private_leaf_const)( bplus, tree_off );

  /* At this point, leaf might contain query.  Query the leaf */

  pair_t const * pair     = leaf->pair;
  ulong          pair_cnt = leaf->pair_cnt;
  ulong          pair_idx = BPLUS_(private_pair_query)( pair, pair_cnt, query );

  return fd_ptr_if( pair_idx<pair_cnt, &pair[ pair_idx ], NULL );
}

BPLUS_PAIR_T *
BPLUS_(private_insert)( BPLUS_(t) *         join,
                        BPLUS_KEY_T const * key,
                        int                 upsert,
                        int *               _insert ) {
  BPLUS_(private_t) * bplus = BPLUS_(private)( join );

  /* If the bplus tree is empty, create the root leaf and insert the key
     into it */

  ulong tree_off = bplus->root_off;
  if( FD_UNLIKELY( !tree_off ) ) { /* Empty bplus, optimize for big */

    BPLUS_(private_leaf_t) * root = BPLUS_(private_leaf_acquire)( bplus );
    if( FD_UNLIKELY( !root ) ) return NULL; /* no room for insert */

    root->prev_off               = 0UL;
    root->next_off               = 0UL;
    root->pair_cnt               = 1UL;
    root->pair[0].BPLUS_PAIR_KEY = key[0];
    ulong root_off = BPLUS_(private_off)( bplus, root );
    bplus->root_off     = root_off;
    bplus->leaf_min_off = root_off;
    bplus->leaf_max_off = root_off;

    *_insert = 1;
    return &root->pair[0];

  }

  /* At this point, the bplus tree is not empty.  We recurse through
     interior nodes to find the leaf that should hold key, splitting
     interior nodes as we go. */

  ulong tree_min = BPLUS_(private_tree_min)();
  ulong tree_max = BPLUS_(private_tree_max)(); /* ==tree_min*2 */

  BPLUS_(private_node_t) * parent    = NULL;
  ulong                    child_idx = 0UL;

  ulong leaf_lo = bplus->leaf_lo;
  while( FD_LIKELY( !BPLUS_(private_is_leaf)( tree_off, leaf_lo ) ) ) { /* Optimize for big trees */
    BPLUS_(private_node_t) * node = BPLUS_(private_node)( bplus, tree_off );

    /* At this point, we should insert key into one of the node's trees
       and tree_cnt is in [2,tree_max] (root) or [tree_min,tree_max]
       (non-root).  If the node has a parent, parent and all node's
       siblings are nodes and parent has in [2,tree_max-1] (root parent)
       or [tree_min,tree_max-1] (non-root parent) children.  (tree_max-1
       because if it had tree_max children when insert started, we would
       have split it on the previous iteration).

       If the node is full, split it. */

    ulong tree_cnt = node->tree_cnt;
    if( FD_UNLIKELY( tree_cnt==tree_max ) ) { /* Optimize for high radix */

      /* Acquire resources.  If node is the root, this includes making a
         new root node and making the new root node's parent. */

      BPLUS_(private_node_t) * new_node = BPLUS_(private_node_acquire)( bplus );
      if( FD_UNLIKELY( !new_node ) ) return NULL; /* No room for insert */

      if( FD_UNLIKELY( !parent ) ) {
        parent = BPLUS_(private_node_acquire)( bplus );
        if( FD_UNLIKELY( !parent ) ) {
          BPLUS_(private_node_release)( bplus, new_node );
          return NULL; /* No room for insert */
        }

        bplus->root_off = BPLUS_(private_off)( bplus, parent );

        parent->tree_cnt    = 1UL; /* Will be incremented to 2 by the child_insert below. */
        parent->tree_off[0] = BPLUS_(private_off)( bplus, node );

        child_idx = 0UL;
      }

      /* At this point, node is child child_idx of parent and we need to
         split node.  Further, new_node is the node that will be created
         by the split and parent has room to insert a link to new_node.
         Split node evenly into new_node and update the parent
         accordingly. */

      BPLUS_KEY_T const * median = &node->pivot[ tree_min-1UL ];

      node->tree_cnt = tree_min;

      new_node->tree_cnt = tree_min;
      memcpy( new_node->tree_off, node->tree_off + tree_min, sizeof(ulong)      * tree_min      );
      memcpy( new_node->pivot,    node->pivot    + tree_min, sizeof(BPLUS_KEY_T)*(tree_min-1UL) );

      BPLUS_(private_child_insert)( parent, child_idx+1UL, BPLUS_(private_off)( bplus, new_node ), median );

      /* Move into the appropriate split */

      node     = fd_ptr_if( BPLUS_(private_key_cmp)( key, median )<0, node, new_node );
      tree_cnt = tree_min;
    }

    /* At this point, we should insert key into one of the node's trees
       and tree_cnt is in [2,tree_max-1] (root) or [tree_min,tree_max-1]
       (non root) such that we are guaranteed to be able to insert. */

    parent    = node;
    child_idx = BPLUS_(private_node_query)( node->pivot, tree_cnt, key );
    tree_off  = node->tree_off[ child_idx ];
  }

  BPLUS_(private_leaf_t) * leaf = BPLUS_(private_leaf)( bplus, tree_off );

  /* At this point, we'd like to insert key into leaf.  But if leaf is
     full, we split it to make room. */

  ulong pair_min = BPLUS_(private_pair_min)();
  ulong pair_max = BPLUS_(private_pair_max)(); /* ==pair_min*2 */

  ulong pair_cnt = (ulong)leaf->pair_cnt;
  if( FD_UNLIKELY( pair_cnt==pair_max ) ) { /* optimize for high radix */

    /* Acquire resources.  If leaf is the root, this includes making a
       new root node and making the new root node's parent. */

    BPLUS_(private_leaf_t) * new_leaf = BPLUS_(private_leaf_acquire)( bplus );
    if( FD_UNLIKELY( !new_leaf ) ) return NULL; /* No room for insert */

    if( FD_UNLIKELY( !parent ) ) {
      parent = BPLUS_(private_node_acquire)( bplus );
      if( FD_UNLIKELY( !parent ) ) {
        BPLUS_(private_leaf_release)( bplus, new_leaf );
        return NULL; /* No room to insert */
      }

      bplus->root_off = BPLUS_(private_off)( bplus, parent );

      parent->tree_cnt    = 1UL; /* Will be incremented to 2 below */
      parent->tree_off[0] = BPLUS_(private_off)( bplus, leaf );

      child_idx = 0UL;
    }

    /* At this point, leaf is child child_idx of parent and we need to
       split leaf.  Further, new_leaf is the leaf that will be created
       by the split and parent has room to insert a link to new_leaf.
       Split leaf evenly into new_leaf and update the parent
       accordingly.  Splitting this leaf might make a new max leaf (it
       will never make a new min leaf). */

    BPLUS_KEY_T const * median = &leaf->pair[ pair_min ].BPLUS_PAIR_KEY;

    ulong next_off = leaf->next_off;

    leaf->pair_cnt = pair_min;
    leaf->next_off = BPLUS_(private_off)( bplus, new_leaf );

    new_leaf->pair_cnt = pair_min;
    new_leaf->prev_off = BPLUS_(private_off)( bplus, leaf );
    new_leaf->next_off = next_off;
    memcpy( &new_leaf->pair[0], &leaf->pair[pair_min], sizeof(pair_t)*pair_min );

    /* FIXME: BRANCHLESS? */
    ulong new_leaf_off = BPLUS_(private_off)( bplus, new_leaf );
    if( FD_UNLIKELY( !next_off ) ) bplus->leaf_max_off                               = new_leaf_off;
    else                           BPLUS_(private_leaf)( bplus, next_off )->prev_off = new_leaf_off;

    BPLUS_(private_child_insert)( parent, child_idx+1UL, new_leaf_off, median );

    /* Move into the appropriate split */

    leaf     = (BPLUS_(private_key_cmp)( key, median )<0) ? leaf : new_leaf;
    pair_cnt = pair_min;
  }

  /* At this point, leaf either contains key or is where we should
     insert key.  Further, pair_cnt is in [1,pair_max-1] (root) or
     [pair_min,pair_max-1] (non root).  Search for key in the leaf.  If
     key is not in the leaf, the search will reveal where to put the
     key. */

  BPLUS_PAIR_T * pair = leaf->pair;
  ulong          i0   = 0UL;
  ulong          i1   = pair_cnt;
  do {

    /* At this point, pairs in [0,i0) are before key, pairs in
       [i1,pair_cnt) are after key and pairs in [i0,i1) (non-empty) are
       not known.  Probe the middle of this range for key. */

    ulong im = (i0+i1) >> 1; /* no overflow */

    int cmp = BPLUS_(private_key_cmp)( &pair[ im ].BPLUS_PAIR_KEY, key );

    /* If cmp==0, pair im holds the key and we are done.  Otherwise, if
       cmp<0 / cmp>0, pair im is before / after key.  We adjust the
       ranges appropriately and recurse. */

    if( FD_UNLIKELY( !cmp ) ) { /* optimize for big trees */
      leaf->pair_cnt = pair_cnt;
      if( !upsert ) return NULL; /* compile time */
      *_insert = 0;
      return &pair[ im ];
    }
    i0 = fd_ulong_if( cmp>0, i0, im+1UL );
    i1 = fd_ulong_if( cmp>0, im, i1     );

  } while( i1>i0 );

  /* At this point, leaf does not contain key, pairs [0,i0) are before
     key, pairs [i0,pair_cnt) are after key and we have room for key.
     Move pairs [i0,pair_cnt) right 1 to make room and insert the key at
     pair i0. */

  memmove( pair+i0+1UL, pair+i0, (pair_cnt-i0)*sizeof(BPLUS_PAIR_T) );
  pair[ i0 ].BPLUS_PAIR_KEY = key[0];
  leaf->pair_cnt = pair_cnt + 1UL;
  *_insert = 1;
  return &pair[ i0 ];
}

int
BPLUS_(remove_key)( BPLUS_(t)         * join,
                    BPLUS_KEY_T const * key ) {
  BPLUS_(private_t) * bplus = BPLUS_(private)( join );

  /* If tree is empty, nothing to remove */

  ulong tree_off = bplus->root_off;
  if( FD_UNLIKELY( !tree_off ) ) return -1; /* not found, optimize for found */

  /* At this point, the tree is not empty.  Find the path through the
     tree to the leaf with the key to remove.  Note that 128 is more
     than enough given strong lg N depth algorithmic guarantees and wide
     radices. */

  BPLUS_(private_node_t) * path_node    [ 128 ];
  ulong                    path_tree_idx[ 128 ];
  ulong                    path_cnt = 0UL;

  ulong leaf_lo = bplus->leaf_lo;
  while( FD_LIKELY( !BPLUS_(private_is_leaf)( tree_off, leaf_lo ) ) ) { /* optimize for big trees */
    BPLUS_(private_node_t) * node = BPLUS_(private_node)( bplus, tree_off );

    ulong tree_idx = BPLUS_(private_node_query)( node->pivot, node->tree_cnt, key );

    path_node    [ path_cnt ] = node;
    path_tree_idx[ path_cnt ] = tree_idx;
    path_cnt++;

    tree_off = node->tree_off[ tree_idx ];
  }

  BPLUS_(private_leaf_t) * leaf = BPLUS_(private_leaf)( bplus, tree_off );

  /* At this point, leaf might contain key.  Search for key. */

  BPLUS_PAIR_T * pair     = leaf->pair;
  ulong          pair_cnt = leaf->pair_cnt;
  ulong          pair_idx = BPLUS_(private_pair_query)( pair, pair_cnt, key );

  if( FD_UNLIKELY( pair_idx>=pair_cnt ) ) return -1; /* not found, optimize for found */

  /* At this point, pair[ pair_idx ] is the pair to remove.  Remove it. */

  pair_cnt--;
  for( ulong idx=pair_idx; idx<pair_cnt; idx++ ) pair[idx] = pair[idx+1UL];
  leaf->pair_cnt = pair_cnt; /* FIXME: MOVE BELOW? */

  /* At this point, the leaf might be unbalanced but everything else in
     the bplus tree is balanced. */

  if( FD_UNLIKELY( !path_cnt ) ) { /* optimize for big trees */

    /* At this point, we removed a pair from the root leaf and the
       leaf's pair_cnt is in [0,pair_max-1] .  If there are still pairs
       in the leaf, the bplus tree is still balanced and we are done.
       Otherwise, we release the leaf and make an empty bplus tree
       (which is balanced by definition). */

    if( FD_LIKELY( pair_cnt ) ) return 0; /* optimize for big trees */
    bplus->root_off     = 0UL;
    bplus->leaf_min_off = 0UL;
    bplus->leaf_max_off = 0UL;
    BPLUS_(private_leaf_release)( bplus, leaf );
    return 0;

  }

  /* At this point, we removed a pair from a non-root leaf and the
     leaf's pair_cnt is in [pair_min-1,pair_max-1].  If there are at
     least pair_min pairs left in the leaf, the bplus tree is still
     balanced and we are done. */

  ulong pair_min = BPLUS_(private_pair_min)();
  ulong pair_max = BPLUS_(private_pair_max)();

  if( FD_LIKELY( pair_cnt>=pair_min ) ) return 0; /* optimize for big trees */

  /* At this point, we removed a pair from a non-root leaf and its
     pair_cnt is pair_min-1.  As such, it is not balanced with its
     siblings (leaf must have at least leaf_min-1 siblings that must
     also be leaves with a pair_cnt in [pair_min,pair_max]).  Determine
     which sibling to use for rebalancing and how to rebalance with this
     sibling.  This sibling will have a pair cnt in [pair_min,pair_max].

     Note: Could be more adaptive here (e.g. pick the larger sibling
     when leaf is a middle child). */

  path_cnt--;
  BPLUS_(private_node_t) * parent    = path_node    [ path_cnt ];
  ulong                    child_idx = path_tree_idx[ path_cnt ];

  ulong sib0_idx = child_idx - (ulong)(child_idx>0UL);
  ulong sib1_idx = sib0_idx  + 1UL;

  ulong sib0_off = parent->tree_off[ sib0_idx ];
  ulong sib1_off = parent->tree_off[ sib1_idx ];

  BPLUS_(private_leaf_t) * sib0 = BPLUS_(private_leaf)( bplus, sib0_off );
  BPLUS_(private_leaf_t) * sib1 = BPLUS_(private_leaf)( bplus, sib1_off );

  ulong sib0_pair_cnt = sib0->pair_cnt;
  ulong sib1_pair_cnt = sib1->pair_cnt;

  ulong reb_pair_cnt = sib0_pair_cnt + sib1_pair_cnt; /* in [pair_max-1,2*pair_max-1]. */
  if( FD_LIKELY( reb_pair_cnt>=pair_max ) ) {

    /* At this point, reb_pair_cnt is in [pair_max,2*pair_max-1].
       Divide these as evenly as possible between sib0 and sib1 and
       update the parent's pivot accordingly.  Since we do not remove
       any trees from the parent, this will rebalance the whole bplus
       tree fully and we are done. */

    ulong new_sib0_pair_cnt = reb_pair_cnt >> 1;
    ulong new_sib1_pair_cnt = reb_pair_cnt - new_sib0_pair_cnt;

    if( new_sib0_pair_cnt>sib0_pair_cnt ) { /* Shift pairs from sib1 into sib0 */

      ulong delta = new_sib0_pair_cnt - sib0_pair_cnt;
      memcpy ( sib0->pair + sib0_pair_cnt, sib1->pair,         sizeof(BPLUS_PAIR_T)*delta             );
      memmove( sib1->pair,                 sib1->pair + delta, sizeof(BPLUS_PAIR_T)*new_sib1_pair_cnt );

    } else { /* Shift pairs from sib0 into sib1 */

      ulong delta = sib0_pair_cnt - new_sib0_pair_cnt;
      memmove( sib1->pair + delta, sib1->pair,                     sizeof(BPLUS_PAIR_T)*sib1_pair_cnt );
      memcpy ( sib1->pair,         sib0->pair + new_sib0_pair_cnt, sizeof(BPLUS_PAIR_T)*delta         );

    }

    sib0->pair_cnt = new_sib0_pair_cnt;
    sib1->pair_cnt = new_sib1_pair_cnt;

    parent->pivot[sib0_idx] = sib1->pair[0].BPLUS_PAIR_KEY;
    return 0;
  }

  /* At this point, reb_pair_cnt is pair_max-1 such that these siblings
     must be merged to restore balance among the leaves.  This might
     change the leaf max from sib1 to sib0. */

  memcpy( sib0->pair + sib0_pair_cnt, sib1->pair, sizeof(BPLUS_PAIR_T)*sib1_pair_cnt );
  sib0->pair_cnt = reb_pair_cnt;

  ulong sib2_off = sib1->next_off;
  sib0->next_off = sib2_off;

  /* FIXME: DO BRANCHLESS? */
  if( FD_UNLIKELY( !sib2_off ) ) bplus->leaf_max_off                               = sib0_off;
  else                           BPLUS_(private_leaf)( bplus, sib2_off )->prev_off = sib0_off;

  BPLUS_(private_child_remove)( parent, sib1_idx );
  BPLUS_(private_leaf_release)( bplus, sib1 );

  /* The merge might have unbalance parent among its siblings.  If it
     has not, we are done.  Otherwise, we rebalance parent among its
     siblings.  That might unbalance the grandparent among its siblings.
     And so on along the path potentially all the back to the bplus tree
     root. */

  ulong tree_min = BPLUS_(private_tree_min)();
  ulong tree_max = BPLUS_(private_tree_max)();

  while( FD_LIKELY( path_cnt ) ) { /* optimize for big trees */
    BPLUS_(private_node_t) * child = parent;

    /* At this point, because we just removed a tree from child, child's
       tree_cnt is in [tree_min-1,tree_max-1] but everything else is
       balanced.  If the child has at least tree_min trees, the bplus
       tree is still balanced. */

    ulong child_tree_cnt = child->tree_cnt;
    if( FD_LIKELY( child_tree_cnt>=tree_min ) ) return 0; /* optimize for big trees */

    /* At this point, child's tree_cnt is tree_min-1.  As such, it is
       not balanced with its siblings (child must have at least
       leaf_min-1 siblings that must also be nodes with a tree_cnt in
       [tree_min,tree_max]).  Determine which sibling to use for
       rebalancing and how to rebalance.

       Note: Could be more adaptive here (e.g. pick the larger sibling
       if a middle child). */

    path_cnt--;
    parent    = path_node    [ path_cnt ];
    child_idx = path_tree_idx[ path_cnt ];

    ulong sib0_idx = child_idx - (ulong)(child_idx>0UL);
    ulong sib1_idx = sib0_idx  + 1UL;

    ulong sib0_off = parent->tree_off[ sib0_idx ];
    ulong sib1_off = parent->tree_off[ sib1_idx ];

    BPLUS_(private_node_t) * sib0 = BPLUS_(private_node)( bplus, sib0_off );
    BPLUS_(private_node_t) * sib1 = BPLUS_(private_node)( bplus, sib1_off );

    ulong sib0_tree_cnt = sib0->tree_cnt;
    ulong sib1_tree_cnt = sib1->tree_cnt;

    ulong reb_tree_cnt = sib0_tree_cnt + sib1_tree_cnt; /* in [tree_max-1,2*tree_max-1]. */
    if( FD_LIKELY( reb_tree_cnt>=tree_max ) ) {

      /* At this point, reb_tree_cnt is in [tree_max,2*tree_max-1].
         Divide these as evenly as possible between sib0 and sib1 and
         update the parent's pivot accordingly.  Since we do not remove
         any trees from parent, this will rebalance the whole bplus tree
         and we are done. */

      ulong new_sib0_tree_cnt = reb_tree_cnt >> 1;
      ulong new_sib1_tree_cnt = reb_tree_cnt - new_sib0_tree_cnt;

      if( new_sib0_tree_cnt>sib0_tree_cnt ) { /* Shift leading sib1 trees to trailing sib0 trees */

        ulong delta = new_sib0_tree_cnt - sib0_tree_cnt;
        memcpy ( sib0->tree_off + sib0_tree_cnt, sib1->tree_off,         sizeof(ulong)*delta             );
        memmove( sib1->tree_off,                 sib1->tree_off + delta, sizeof(ulong)*new_sib1_tree_cnt );

        /* Copy parent pivot and leading delta-1 sib1 pivots into sib0. */

        sib0->pivot[ sib0_tree_cnt-1UL ] = parent->pivot[ sib0_idx ];
        memcpy( sib0->pivot + sib0_tree_cnt, sib1->pivot, (delta-1UL)*sizeof(BPLUS_KEY_T) );

        /* At this point, there is 1 hole in the parent pivots and
           delta-1 holes in the leading sib1 pivots.  Copy the next sib1
           pivot to the parent. */

        parent->pivot[ sib0_idx ] = sib1->pivot[ delta-1UL ];

        /* At this point, there are delta holes in the leading sib1
           pivots.  Shift remaining sib1 pivots down delta. */

        memmove( sib1->pivot, sib1->pivot+delta, (new_sib1_tree_cnt-1UL)*sizeof(BPLUS_KEY_T) );

      } else { /* Shift trailing sib0 trees to leading sib1 trees */

        ulong delta = sib0_tree_cnt - new_sib0_tree_cnt;
        memmove( sib1->tree_off + delta, sib1->tree_off,                     sizeof(ulong)*sib1_tree_cnt );
        memcpy ( sib1->tree_off,         sib0->tree_off + new_sib0_tree_cnt, sizeof(ulong)*delta         );

        /* Shift sib1 pivots up delta. */

        memmove( sib1->pivot+delta, sib1->pivot, (sib1_tree_cnt-1UL)*sizeof(BPLUS_KEY_T) );

        /* At this point, there are delta holes in the leading sib1
           pivots.  Copy trailing delta-1 sib0 pivots and parent pivot
           into sib1. */

        memcpy( sib1->pivot, sib0->pivot+new_sib0_tree_cnt, (delta-1UL)*sizeof(BPLUS_KEY_T) );
        sib1->pivot[ delta-1UL ] = parent->pivot[ sib0_idx ];

        /* At this point, there is 1 hole in the parent pivot.  Copy
           trailing sib0 pivot into parent. */

        parent->pivot[ sib0_idx ] = sib0->pivot[ new_sib0_tree_cnt-1UL ];

      }

      sib0->tree_cnt = new_sib0_tree_cnt;
      sib1->tree_cnt = new_sib1_tree_cnt;
      return 0;
    }

    /* At this point, reb_tree_cnt is tree_max-1 such that these
       siblings must be merged to restore balance among siblings.  Since
       this might unbalance parent relative to its siblings, we need to
       keep iterating. */

    memcpy( sib0->tree_off + sib0_tree_cnt, sib1->tree_off, sizeof(ulong)*sib1_tree_cnt );

    sib0->pivot[ sib0_tree_cnt-1UL ] = parent->pivot[ sib0_idx ];
    memcpy( sib0->pivot + sib0_tree_cnt, sib1->pivot, sizeof(BPLUS_KEY_T)*(sib1_tree_cnt-1UL) );

    sib0->tree_cnt = reb_tree_cnt;

    BPLUS_(private_child_remove)( parent, sib1_idx );

    BPLUS_(private_node_release)( bplus, sib1 );
  }

  /* At this point, parent is the root node and we just removed a tree
     from it.  If parent still has more than 1 tree, the bplus tree is
     balanced and we are done.  Otherwise, we make parent's sole child
     the new root and release parent to finish balancing the tree. */

  if( FD_LIKELY( parent->tree_cnt>1UL ) ) return 0; /* optimize for big trees */

  bplus->root_off = parent->tree_off[ 0 ];
  BPLUS_(private_node_release)( bplus, parent );
  return 0;
}

BPLUS_(iter_t)
BPLUS_(private_iter)( BPLUS_(t)   const * join,
                      BPLUS_KEY_T const * query,
                      int                 op ) {
  BPLUS_(private_t) const * bplus = BPLUS_(private_const)( join );

  BPLUS_(iter_t) iter;

  /* If the bplus is empty or query is NULL, return nul */

  ulong tree_off = bplus->root_off;
  if( FD_UNLIKELY( (!tree_off) | (!query) ) ) { /* empty, optimize for big trees */
    iter.leaf_off = 0UL;
    iter.pair_idx = 0UL;
    return iter;
  }

  /* At this point, the bplus is not empty.  Find the leaf that might
     contain query. */

  ulong leaf_lo = bplus->leaf_lo;
  while( FD_LIKELY( !BPLUS_(private_is_leaf)( tree_off, leaf_lo ) ) ) { /* Optimize for big trees */
    BPLUS_(private_node_t) const * node = BPLUS_(private_node_const)( bplus, tree_off );
    tree_off = node->tree_off[ BPLUS_(private_node_query)( node->pivot, node->tree_cnt, query ) ];
  }
  BPLUS_(private_leaf_t) const * leaf = BPLUS_(private_leaf_const)( bplus, tree_off );

  /* At this point, pairs in the previous leaf (if any) have keys less
     than query and pairs in the next leaf (if any) have keys greater
     than query.  Search the leaf for query. */

  BPLUS_PAIR_T const * pair     = leaf->pair;
  ulong                pair_cnt = leaf->pair_cnt;

  ulong i0 = 0UL;
  ulong i1 = pair_cnt;

  do {

    /* At this point, the range [i0,i1) contains at least 1 pair.  Pairs
       [0,i0) have keys less than query, pairs [i1,pair_cnt) have keys
       greater than query and we don't know about pairs [i0,i1).  Test
       the pair in the middle.

       If this pair's key matches query, because all keys are unique, we
       know that pair im is the first pair greater than or equal to
       query and that pair im+1 is the first pair greater than query.

       If this pair's key is greater than query, we know all pairs in
       [im,pair_cnt) are greater than query so we update i1 to im.

       If this pair's key is less than query, we know that all pairs in
       [0,im+1) are less than query so we update i0 to im+1. */

    ulong im = (i0+i1) >> 1; /* No overflow */

    int cmp = BPLUS_(private_key_cmp)( &pair[im].BPLUS_PAIR_KEY, query );
    if( FD_UNLIKELY( !cmp ) ) { /* optimize for big trees */

      /* At this point, pairs [0,im) have keys less than query, pair im
         key matches query and pairs (im,pair_cnt) are greater than
         query.  If:

           op==0 (GE): pick i0 == im   such that [0,i0) are <  query and [i0,pair_cnt) are >= query
           op==1 (GT): pick i0 == im+1 such that [0,i0) are <= query and [i0,pair_cnt) are >  query
           op==2 (LE): pick i0 == im+1 such that [0,i0) are <= query and [i0,pair_cnt) are >  query
           op==3 (LT): pick i0 == im   such that [0,i0) are <  query and [i0,pair_cnt) are >= query */

      i0 = im + (ulong)((op==1) | (op==2)); /* compile time */
      break;
    }
    i0 = fd_ulong_if( cmp>0, i0, im+1UL );
    i1 = fd_ulong_if( cmp>0, im, i1     );

  } while( FD_LIKELY( i1-i0 ) ); /* optimize for big trees */

  /* At this point:

       op==0 (GE): pairs [i0,pair_cnt) have keys greater than or equal to query
       op==1 (GT): pairs [i0,pair_cnt) have keys greater than             query
       op==2 (LE): pairs [0,i0)        have keys less    than or equal to query
       op==3 (LT): pairs [0,i0)        have keys less    than             query */

  if( op<=1 ) { /* compile time */

    if( FD_UNLIKELY( i0==pair_cnt ) ) { /* optimize for big trees */

      /* At this point:

           op==0 (GE): all pairs have keys less than             query and pairs in any next leaf have keys greater than query
           op==1 (GT): all pairs have keys less than or equal to query and pairs in any next leaf have keys greater than query

         position iterator at first pair in next leaf (or nul if this is
         the max leaf). */

      tree_off = leaf->next_off;
      i0       = 0UL;
    }

  } else {

    if( FD_UNLIKELY( i0==0UL ) ) { /* optimize for big trees */

      /* At this point:

           op==2 (LE): all pairs have keys greater than             query and pairs in any prev leaf have keys less than query
           op==3 (LT): all pairs have keys greater than or equal to query and pairs in any prev leaf have keys less than query

         position iterator at last pair in previous leaf (or nul if this
         is the min leaf). */

      tree_off = leaf->prev_off;
      i0       = FD_UNLIKELY( !tree_off ) ? 1UL : BPLUS_(private_leaf_const)( bplus, tree_off )->pair_cnt;
    }
    i0--;

  }

  iter.leaf_off = tree_off;
  iter.pair_idx = i0;
  return iter;
}

int
BPLUS_(verify)( BPLUS_(t) const * join ) {

# define BPLUS_TEST(c) do {               \
    if( FD_UNLIKELY( !(c) ) ) {           \
      FD_LOG_WARNING(( "FAIL: %s", #c )); \
      return -1;                          \
    }                                     \
  } while(0)

  /* Verify join */

  BPLUS_TEST( join );

  BPLUS_(private_t) const * bplus = BPLUS_(private_const)( join );

  BPLUS_TEST( fd_ulong_is_aligned( (ulong)bplus, BPLUS_ALIGN ) );

  /* Verify header */

  BPLUS_TEST( bplus->magic==BPLUS_MAGIC );

  ulong node_max = bplus->node_max;
  ulong leaf_max = bplus->leaf_max;

  BPLUS_TEST( node_max<=BPLUS_(private_node_max_max)() );
  BPLUS_TEST( leaf_max<=BPLUS_(private_leaf_max_max)() );

  ulong node_lo = bplus->node_lo;
  ulong leaf_lo = bplus->leaf_lo;

  BPLUS_TEST( node_lo==fd_ulong_align_up(                    sizeof( BPLUS_(private_t)      ), BPLUS_NODE_ALIGN ) );
  BPLUS_TEST( leaf_lo==fd_ulong_align_up( node_lo + node_max*sizeof( BPLUS_(private_node_t) ), BPLUS_LEAF_ALIGN ) );

  ulong node_hi = node_lo + node_max*sizeof( BPLUS_(private_node_t) );
  ulong leaf_hi = leaf_lo + leaf_max*sizeof( BPLUS_(private_leaf_t) );

  ulong root_off     = bplus->root_off;
  ulong leaf_min_off = bplus->leaf_min_off;
  ulong leaf_max_off = bplus->leaf_max_off;

  if( FD_LIKELY( root_off ) ) {

    BPLUS_TEST( node_lo<=root_off ); BPLUS_TEST( root_off<leaf_hi  );
    BPLUS_TEST( fd_ulong_is_aligned( root_off, fd_ulong_if( !BPLUS_(private_is_leaf)( root_off, leaf_lo ),
                                                            BPLUS_NODE_ALIGN, BPLUS_LEAF_ALIGN ) ) );

    BPLUS_TEST( leaf_lo<=leaf_min_off ); BPLUS_TEST( leaf_min_off<leaf_hi  );
    BPLUS_TEST( fd_ulong_is_aligned( leaf_min_off, BPLUS_LEAF_ALIGN ) );

    BPLUS_TEST( leaf_lo<=leaf_max_off ); BPLUS_TEST( leaf_max_off<leaf_hi  );
    BPLUS_TEST( fd_ulong_is_aligned( leaf_max_off, BPLUS_LEAF_ALIGN ) );

  } else {

    BPLUS_TEST( !leaf_min_off );
    BPLUS_TEST( !leaf_max_off );

  }

  ulong node_rem = bplus->node_max;
  ulong leaf_rem = bplus->leaf_max;

  /* Verify node pool */

  ulong node_off = bplus->node_pool_off;
  while( FD_LIKELY( node_off ) ) {
    BPLUS_TEST( node_rem ); node_rem--;
    BPLUS_TEST( node_lo<=node_off ); BPLUS_TEST( node_off<node_hi  );
    BPLUS_TEST( fd_ulong_is_aligned( node_off, BPLUS_NODE_ALIGN ) );
    node_off = BPLUS_(private_node_const)( bplus, node_off )->tree_off[0];
  }

  /* Verify leaf pool */

  ulong leaf_off = bplus->leaf_pool_off;
  while( FD_LIKELY( leaf_off ) ) {
    BPLUS_TEST( leaf_rem ); leaf_rem--;
    BPLUS_TEST( leaf_lo<=leaf_off ); BPLUS_TEST( leaf_off<leaf_hi  );
    BPLUS_TEST( fd_ulong_is_aligned( leaf_off, BPLUS_LEAF_ALIGN ) );
    leaf_off = BPLUS_(private_leaf_const)( bplus, leaf_off )->next_off;
  }

  /* Verify the actual tree */

  ulong leaf_cnt = leaf_rem;

  if( FD_LIKELY( root_off ) ) { /* optimize for big trees */

    /* At this point, the tree is not empty */

    ulong tree_min = BPLUS_(private_tree_min)();
    ulong tree_max = BPLUS_(private_tree_max)();

    ulong pair_min = BPLUS_(private_pair_min)();
    ulong pair_max = BPLUS_(private_pair_max)();

    ulong               stack_tree_off   [ 128 ];
    ulong               stack_subtree_idx[ 128 ];
    BPLUS_KEY_T const * stack_key_lo     [ 128 ];
    BPLUS_KEY_T const * stack_key_hi     [ 128 ];
    ulong               stack_cnt = 0UL;
    ulong               stack_max = 128UL;

    ulong               tree_off    = root_off;
    ulong               subtree_idx = 0UL;
    BPLUS_KEY_T const * key_lo      = NULL;
    BPLUS_KEY_T const * key_hi      = NULL;

    for(;;) {

      /* At this point, we are still validating the tree rooted at
         tree_off and this tree should contain only keys in
         [key_lo,key_hi).  key_{lo,hi}==NULL indicates key_{lo,hi} is
         {-inf,+inf}.

         If tree is a node, we've validated all of tree's subtrees
         [0,subtree_idx).  subtree_idx==0 indicates this is the first
         time we've visited this node.

         If tree is a leaf, as we only visit each leaf exactly once,
         subtree_idx will be zero (and otherwise ignored). */

      if( FD_LIKELY( !BPLUS_(private_is_leaf)( tree_off, leaf_lo ) ) ) { /* tree is a node */

        /* If this is the first time visiting this node, validate it */

        if( FD_UNLIKELY( !subtree_idx ) ) {

          /* Validate no loops */

          BPLUS_TEST( node_rem ); node_rem--;

          /* Validate the node pointer */

          BPLUS_TEST( node_lo<=tree_off ); BPLUS_TEST( tree_off<node_hi );
          BPLUS_TEST( fd_ulong_is_aligned( tree_off, BPLUS_NODE_ALIGN ) );

          BPLUS_(private_node_t) const * node = BPLUS_(private_node_const)( bplus, tree_off );

          BPLUS_KEY_T const * subtree_pivot = node->pivot;
          ulong       const * subtree_off   = node->tree_off;
          ulong               subtree_cnt   = node->tree_cnt;

          /* Validate the node tree count */

          BPLUS_TEST( fd_ulong_if( tree_off!=root_off, tree_min, 2UL )<=subtree_cnt );
          BPLUS_TEST( subtree_cnt<=tree_max );

          /* Validate the node tree offsets */

          int is_leaf = BPLUS_(private_is_leaf)( subtree_off[0], leaf_lo );

          ulong lo    = fd_ulong_if( is_leaf, leaf_lo,          node_lo          );
          ulong hi    = fd_ulong_if( is_leaf, leaf_hi,          node_hi          );
          ulong align = fd_ulong_if( is_leaf, BPLUS_LEAF_ALIGN, BPLUS_NODE_ALIGN );

          for( ulong idx=0UL; idx<subtree_cnt; idx++ ) {
            ulong off = subtree_off[ idx ];
            BPLUS_TEST( lo<=off ); BPLUS_TEST( off<hi );
            BPLUS_TEST( fd_ulong_is_aligned( off, align ) );
          }

          /* Validate the node pivots */

          if( FD_LIKELY( key_lo ) ) BPLUS_TEST( BPLUS_(private_key_cmp)( key_lo, &subtree_pivot[0] )<0 );

          for( ulong idx=1UL; idx<subtree_cnt-1UL; idx++ )
            BPLUS_TEST( BPLUS_(private_key_cmp)( &subtree_pivot[idx-1UL], &subtree_pivot[idx] )<0 );

          if( FD_LIKELY( key_hi ) ) BPLUS_TEST( BPLUS_(private_key_cmp)( &subtree_pivot[subtree_cnt-2UL], key_hi )<0 );
        }

        /* At this point, tree_off is a bplus global offset of a
           verified node (verified either just now or on a previous
           iteration).  If subtree_idx isn't the last subtree, push
           subtree_idx+1 onto the stack for a later iteration. */

        BPLUS_(private_node_t) const * node = BPLUS_(private_node_const)( bplus, tree_off );

        BPLUS_KEY_T const * subtree_pivot = node->pivot;
        ulong       const * subtree_off   = node->tree_off;
        ulong               subtree_cnt   = node->tree_cnt;

        if( FD_LIKELY( (subtree_idx+1UL)<subtree_cnt ) ) {
          BPLUS_TEST( stack_cnt<stack_max );
          stack_tree_off   [ stack_cnt ] = tree_off;
          stack_subtree_idx[ stack_cnt ] = subtree_idx+1UL;
          stack_key_lo     [ stack_cnt ] = key_lo;
          stack_key_hi     [ stack_cnt ] = key_hi;
          stack_cnt++;
        }

        /* And recurse into subtree_idx for the next iteration.  Note
           this node's key_lo is subtree_idx 0's key_lo and this node's
           key_hi is subtree_idx tree_cnt-1's key_hi. */

        /**/                                           tree_off =  subtree_off  [ subtree_idx     ];
        if( FD_LIKELY( subtree_idx>0UL             ) ) key_lo   = &subtree_pivot[ subtree_idx-1UL ];
        if( FD_LIKELY( subtree_idx<subtree_cnt-1UL ) ) key_hi   = &subtree_pivot[ subtree_idx     ];
        subtree_idx = 0UL;
        continue;
      }

      /* At this point, tree is a leaf.  Validate no loops. */

      BPLUS_TEST( leaf_rem ); leaf_rem--;

      /* Validate the leaf pointer */

      BPLUS_TEST( leaf_lo<=tree_off ); BPLUS_TEST( tree_off<leaf_hi );
      BPLUS_TEST( fd_ulong_is_aligned( tree_off, BPLUS_LEAF_ALIGN ) );

      BPLUS_(private_leaf_t) const * leaf = BPLUS_(private_leaf_const)( bplus, tree_off );

      BPLUS_PAIR_T const * pair     = leaf->pair;
      ulong                pair_cnt = leaf->pair_cnt;

      /* Validate the leaf pair count */

      BPLUS_TEST( fd_ulong_if( tree_off!=root_off, pair_min, 1UL )<=pair_cnt );
      BPLUS_TEST( pair_cnt<=pair_max );

      /* Validate the leaf pairs */

      if( FD_LIKELY( key_lo ) ) BPLUS_TEST( BPLUS_(private_key_cmp)( key_lo, &pair[0].BPLUS_PAIR_KEY )<=0 );

      for( ulong idx=1UL; idx<pair_cnt; idx++ )
        BPLUS_TEST( BPLUS_(private_key_cmp)( &pair[idx-1UL].BPLUS_PAIR_KEY, &pair[idx].BPLUS_PAIR_KEY )<0 );

      if( FD_LIKELY( key_hi ) ) BPLUS_TEST( BPLUS_(private_key_cmp)( &pair[ pair_cnt-1UL ].BPLUS_PAIR_KEY, key_hi )<0 );

      /* (Note that we validate the leaf ordered iterator below.) */

      /* If no more work to do, abort.  Otherwise, get the next node to
         process. */

      if( FD_UNLIKELY( !stack_cnt ) ) break;
      stack_cnt--;
      tree_off    = stack_tree_off   [ stack_cnt ];
      subtree_idx = stack_subtree_idx[ stack_cnt ];
      key_lo      = stack_key_lo     [ stack_cnt ];
      key_hi      = stack_key_hi     [ stack_cnt ];
    }
  }

  /* Validate all nodes and leaves touched */

  BPLUS_TEST( !node_rem );
  BPLUS_TEST( !leaf_rem );

  /* Validate leaf iteration */

  leaf_rem = leaf_cnt;

  ulong leaf_prev_off = 0UL;
  /**/  leaf_off      = bplus->leaf_min_off;
  while( leaf_off ) { /* Validates leaf->next_off for last iteration */

    /* Validate no loops */

    BPLUS_TEST( leaf_rem ); leaf_rem--;

    /* Validate forward iteration (validates bplus->leaf_min_off first
       iteration, validates leaf->next_off interior iterations) */

    BPLUS_TEST( leaf_lo<=leaf_off ); BPLUS_TEST( leaf_off<leaf_hi );
    BPLUS_TEST( fd_ulong_is_aligned( leaf_off, BPLUS_LEAF_ALIGN ) );
    BPLUS_(private_leaf_t) const * leaf = BPLUS_(private_leaf_const)( bplus, leaf_off );

    /* Validate reverse iteration (validates leaf->prev_off,
       bplus->leaf_max_off validated below) */

    BPLUS_TEST( leaf->prev_off==leaf_prev_off );

    /* Validate ordered leaves */

    if( FD_LIKELY( leaf_prev_off ) ) {
      BPLUS_(private_leaf_t) const * prev = BPLUS_(private_leaf_const)( bplus, leaf_prev_off );
      BPLUS_TEST( BPLUS_(private_key_cmp)( &prev->pair[ prev->pair_cnt-1UL ].BPLUS_PAIR_KEY, &leaf->pair[ 0 ].BPLUS_PAIR_KEY )<0 );
    }

    leaf_prev_off = leaf_off;
    leaf_off      = leaf->next_off;
  }

  BPLUS_TEST( bplus->leaf_max_off==leaf_prev_off ); /* Validates bplus->leaf_max_off */
  BPLUS_TEST( !leaf_rem );                          /* All leaves in tree covered */

# undef BPLUS_TEST

  return 0;
}

#endif

#undef BPLUS_STATIC
#undef BPLUS_

#undef BPLUS_IMPL_STYLE
#undef BPLUS_MAGIC
#undef BPLUS_LEAF_ALIGN
#undef BPLUS_NODE_ALIGN
#undef BPLUS_ALIGN
#undef BPLUS_TREE_MAX
#undef BPLUS_NODE_MAX
#undef BPLUS_PAIR_T
#undef BPLUS_KEY_T
#undef BPLUS_NAME
