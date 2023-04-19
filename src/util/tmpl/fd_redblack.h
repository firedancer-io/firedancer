/* Declares a family of functions implementing a single-threaded
   fixed-capacity red-black tree designed for high performance
   contexts.

   A red-black tree is a type of self-balanced binary tree where the
   nodes are kept in sorted order. Queries, insertions, and deletions
   are O(log n) cost where n is the size of the tree. The implicit
   sorting makes in-order traversal very fast, something a hash table
   cannot do.

   There are two components to the implementation. The first is a
   fixed-size pool which is used for allocating tree nodes or
   elements. All nodes are drawn from this pool and must be returned
   to it after deletion. A pool is basically just a flat array of
   nodes which start in an uninitialized state. Trees cannot grow
   beyond this pool size.

   The second component is the tree itself. This is a balanced
   binary tree linked with pointers. A tree is referenced with just a
   pointer to the root node. The memory for the tree comes from the
   pool. Nodes are never copied and are always updated in place, so
   the data inside them is stable.

   Multiple trees can coexist in the same pool, provided the total
   size of all the trees does not exceed the pool size. This is
   convenient for deleting nodes from one tree and inserting them into
   another without copying the key or value.
   
   Example usage:

     typedef struct my_node my_node_t;
     #define REDBLK_T my_node_t
     #define REDBLK_NAME my_rb
     #include "util/tmpl/fd_redblack.h"

     struct my_node {
         ulong key;
         ulong value;
         redblack_member_t redblack;
     };
     #include "util/tmpl/fd_redblack.c"

   Note the order of declations and includes. REDBLK_T and REDBLK_NAME
   need to be defined before including this header, but the actual
   node type needs to be defined after. This is because of the
   required member declaration:

      redblack_member_t redblack;

   where the redblack_member_t type is defined herein. The red-black
   tree implementation keeps all pointers/colors inside this
   member. Everything else in the node type is up to the application.

   This example creates the following API for use in the local compilation unit:

    ulong my_rb_pool_align( void );
    ulong my_rb_pool_footprint( ulong max );
    ulong my_rb_pool_max_for_footprint( ulong footprint );
    void * my_rb_pool_new( void * shmem, ulong max );
    my_node_t * my_rb_pool_join( void * shmem );
    void * my_rb_pool_leave( my_node_t * join );
    void * my_rb_pool_delete( void * shmem );
    ulong my_rb_pool_max( my_node_t const * join );
    my_node_t * my_rb_pool_allocate( my_node_t * join );
    void my_rb_pool_release( my_node_t * join, my_node_t * node );
    void my_rb_pool_release_tree( my_node_t * join, my_node_t * root );
    long my_rb_pool_local_to_global( my_node_t * join, my_node_t * root );
    my_node_t * my_rb_pool_global_to_local( my_node_t * join, long root );

    my_node_t * my_rb_minimum(my_node_t * pool, my_node_t * root);
    my_node_t * my_rb_maximum(my_node_t * pool, my_node_t * root);
    my_node_t * my_rb_successor(my_node_t * pool, my_node_t * node);
    my_node_t * my_rb_predecessor(my_node_t * pool, my_node_t * node);
    my_node_t * my_rb_insert(my_node_t * pool, my_node_t ** root, my_node_t * x);
    my_node_t * my_rb_delete(my_node_t * pool, my_node_t ** root, my_node_t * z);
    my_node_t * my_rb_find(my_node_t * pool, my_node_t * root, my_node_t * key);

    void my_rb_verify(my_node_t * pool, my_node_t * root);

    long my_rb_compare(my_node_t * left, my_node_t * right);

  The specific usage and semantics of these methods is given below.

  A sample application is as follows:

    my_node_t* pool = my_rb_pool_join( my_rb_pool_new( shmem, 20 ) );
    my_node_t* root = NULL;
    for (ulong i = 0; i < 10; ++i) {
      my_node_t * n = my_rb_pool_allocate( join );
      n->key = 123 + i;
      n->value = 456 + i;
      my_rb_insert( &root, n );
    }
    for (ulong i = 0; i < 10; ++i) {
      my_node_t k;
      k.key = 123 + i;
      my_node_t * n = my_rb_find( root, &k );
      printf("key=%lu value=%lu\n", n->key, n->value);
      n = my_rb_delete( &root, n );
      my_rb_pool_release( pool, n );
    }
    my_rb_pool_delete( my_rb_pool_leave( pool ) );

*/

#ifndef REDBLK_NAME
#define "Define REDBLK_NAME"
#endif

#ifndef REDBLK_T
#define "Define REDBLK_T"
#endif

/* Tree node colors */
#define REDBLK_FREE -1
#define REDBLK_NEW 0
#define REDBLK_BLACK 1
#define REDBLK_RED 2

/* Structure which must be part of every node type. Always include
   this member declaration:
      redblack_member_t redblack;
*/ 
struct redblack_member {
    uint parent;
    uint left;
    uint right;
    int color;
};
typedef struct redblack_member redblack_member_t;

/* Namespace macros */
#define REDBLK_(n) FD_EXPAND_THEN_CONCAT3(REDBLK_NAME,_,n)
#define REDBLK_POOL_(n) FD_EXPAND_THEN_CONCAT3(REDBLK_NAME,_pool_,n)

/*
  E.g. ulong my_rb_pool_align( void );

  Return the byte alignment required by a node pool.
*/
ulong REDBLK_POOL_(align)( void );
/*
  E.g. ulong my_rb_pool_footprint( ulong max );

  Return the number of bytes of memory required by a pool with the
  given maximum number of nodes.
*/
ulong REDBLK_POOL_(footprint)( ulong max );
/*
  E.g. ulong my_rb_pool_max_for_footprint( ulong footprint );

  Return the recommended maximum number of nodes for a given memory
  footprint.
*/
ulong REDBLK_POOL_(max_for_footprint)( ulong footprint );
/*
  E.g. void * my_rb_pool_new( void * shmem, ulong max );

  Initialize memory for a node pool for a given maximum number of
  nodes. All nodes in the pool will be uninitialized and available for
  allocation to start. There must be enough memory for the required
  footprint. Note that a sentinel node which is not useful to the
  application always occupies on space.
*/
void * REDBLK_POOL_(new)( void * shmem, ulong  max );
/*
  E.g. my_node_t * my_rb_pool_join( void * shmem );

  Attach to a node pool which is already formatted (possibly in shared
  memory). The resulting pointer represents the pool. Only a single
  thread can join a pool at one time. Concurrent access is not supported.
*/
REDBLK_T * REDBLK_POOL_(join)( void * shmem );
/*
  E.g. void * my_rb_pool_leave( my_node_t * join );

  Detach from a node pool. This will not call any "destructors" on the
  nodes. If applications require additional memory management, they
  must solve this problem.
*/
void * REDBLK_POOL_(leave)( REDBLK_T * join );
/*
  E.g. void * my_rb_pool_delete( void * shmem );

  Mark a pool as deleted.
*/
void * REDBLK_POOL_(delete)( void * shmem );
/*
  E.g. ulong my_rb_pool_max( my_node_t const * join );

  Return the maximum number of nodes that the pool was configured with.
*/
ulong REDBLK_POOL_(max)( REDBLK_T const * join );
/*
  E.g. my_node_t * my_rb_pool_allocate( my_node_t * join );

  Allocate a node out of a pool. Returns NULL if the pool is fully
  utilized. The application must initialize any values in the node after
  allocation but before insertion. For example:

    my_node_t * n = my_rb_pool_allocate( join );
    n->key = 123;
    n->value = 456;
    my_rb_insert( &root, n );

  The "redblack" member is considered private and should not be touched
  by the application.
*/
REDBLK_T * REDBLK_POOL_(allocate)( REDBLK_T * join );
/*
  E.g. void my_rb_pool_release( my_node_t * join, my_node_t * node);

  Release a node back into the pool for later allocation. Typically,
  this is done after a deletion. For example:
 
    my_node_t * n = my_rb_find( root, &k );
    n = my_rb_delete( &root, n );
    my_rb_pool_release( pool, n );

  Delete and release are separate steps to allow an application to
  perform final cleanup on the node in between.
*/
void REDBLK_POOL_(release)( REDBLK_T * join, REDBLK_T * node );
/*
  E.g. void my_rb_pool_release_tree( my_node_t * join, my_node_t * root );

  Recursively release all nodes in a tree to a pool. The root argument
  is invalid after this method is called.
*/
void REDBLK_POOL_(release_tree)( REDBLK_T * join, REDBLK_T * root );
/*
  E.g. long my_rb_pool_local_to_global( my_node_t * join, my_node_t * root );

  Convert a local root pointer to a global address which can be stored
  in shared memory. This allows a pool to be relocated. Use
  global_to_local to convert back.
*/
long REDBLK_POOL_(local_to_global)( REDBLK_T * join, REDBLK_T * root );
/*
  E.g. my_node_t * my_rb_pool_global_to_local( my_node_t * join, long root );

  Convert a global address to a local root pointer. This allows a pool
  to be relocated.
*/
REDBLK_T * REDBLK_POOL_(global_to_local)( REDBLK_T * join, long root );

/*
  E.g. my_node_t * my_rb_minimum(my_node_t * pool, my_node_t * root);

  Return the node in a tree that has the smallest key (leftmost).
*/
REDBLK_T * REDBLK_(minimum)(REDBLK_T * pool, REDBLK_T * root);
/*
  E.g. my_node_t * my_rb_maximum(my_node_t * pool, my_node_t * node);

  Return the node in a tree that has the largest key (rightmost).
*/
REDBLK_T * REDBLK_(maximum)(REDBLK_T * pool, REDBLK_T * node);
/*
  E.g. my_node_t * my_rb_successor(my_node_t * pool, my_node_t * node);

  Return the next node which is larger than the given node. To iterate
  across the entire tree, do the following:

    for ( my_node_t* n = my_rb_minimum(root); n; n = my_rb_successor(n) ) {
      printf("key=%lu value=%lu\n", n->key, n->value);
    }

  To iterate safely while also deleting, do:

    my_node_t* nn;
    for ( my_node_t* n = my_rb_minimum(root); n; n = nn ) {
      nn = my_rb_successor(n);
      // Possibly delete n
    }
*/
REDBLK_T * REDBLK_(successor)(REDBLK_T * pool, REDBLK_T * node);
/*
  E.g. my_node_t * my_rb_predecessor(my_node_t * pool, my_node_t * node);

  Return the previous node which is smaller than the given node. To iterate
  across the entire tree backwards, do the following:

    for ( my_node_t* n = my_rb_maximum(root); n; n = my_rb_predecessor(n) ) {
      printf("key=%lu value=%lu\n", n->key, n->value);
    }

  To iterate safely while also deleting, do:

    my_node_t* nn;
    for ( my_node_t* n = my_rb_maximum(root); n; n = nn ) {
      nn = my_rb_predecessor(n);
      // Possibly delete n
    }
*/
REDBLK_T * REDBLK_(predecessor)(REDBLK_T * pool, REDBLK_T * node);
/*
  E.g. my_node_t * my_rb_insert(my_node_t * pool, my_node_t ** root, my_node_t * x);

  Insert a node into a tree. Typically, the node must be allocated
  from a pool first. The application must initialize any values in the
  node after allocation but before insertion. For example:

    my_node_t * n = my_rb_pool_allocate( join );
    n->key = 123;
    n->value = 456;
    n = my_rb_insert( &root, n );

  The inserted node is returned. The redblack member is considered
  private and should not be touched by the application.
*/
REDBLK_T * REDBLK_(insert)(REDBLK_T * pool, REDBLK_T ** root, REDBLK_T * x);
/*
  E.g. my_node_t * my_rb_delete(my_node_t * pool, my_node_t ** root, my_node_t * z);

  Remove a node from a tree. The node must be a member of the tree,
  usually the result of a find operation. The node is typically
  released to the pool afterwards. For example:
 
    my_node_t * n = my_rb_find( root, &k );
    n = my_rb_delete( &root, n );
    my_rb_pool_release( pool, n );

  Delete and release are separate steps to allow an application to
  perform final cleanup on the node in between. You can insert a node
  into a different tree after deletion if both trees share a pool. For
  example:

    n = my_rb_delete( &root, n );
    my_rb_insert( &root2, n );
*/
REDBLK_T * REDBLK_(delete)(REDBLK_T * pool, REDBLK_T ** root, REDBLK_T * z);
/*
  E.g. my_node_t * my_rb_find(my_node_t * pool, my_node_t * root, my_node_t * key);

  Search for a key in the tree. In this special case, the key can be a
  temporary instance of the node type rather than a properly
  allocated node. For example:

    my_node_t k;
    k.key = 123 + i;
    my_node_t * n = my_rb_find( root, &k );
    printf("key=%lu value=%lu\n", n->key, n->value);

  A NULL is returned if the find fails.
*/
REDBLK_T * REDBLK_(find)(REDBLK_T * pool, REDBLK_T * root, REDBLK_T * key);

/*
  E.g. void my_rb_verify(my_node_t * pool, my_node_t * root);

  Verify the integrity of the tree data structure. Useful for
  debugging memory corruption. FD_LOG_ERR is called if an error is
  detected.
*/
void REDBLK_(verify)(REDBLK_T * pool, REDBLK_T * root);

/*
  E.g. long my_rb_compare(my_node_t * left, my_node_t * right);
  
  Defined by application to implement key comparison. Returns a
  negative number, zero, or positive depending on whether the left is
  less than, equal to, or greater than right. For example:

    long my_rb_compare(my_node_t* left, my_node_t* right) {
      return (long)(left->key - right->key);
    }
*/
long REDBLK_(compare)(REDBLK_T * left, REDBLK_T * right);

#undef REDBLK_
#undef REDBLK_POOL_
