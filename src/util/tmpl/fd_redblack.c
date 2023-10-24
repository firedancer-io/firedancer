/* Declares a family of functions implementing a single-threaded
   fixed-capacity red-black tree designed for high performance
   contexts.

   A red-black tree is a type of self-balanced binary tree where the
   nodes are kept in sorted order. Queries, insertions, and deletions
   are O(log n) cost where n is the size of the tree. The implicit
   sorting makes in-order traversal very fast, something a hash table
   cannot do.

   Tree nodes are allocated from a pool before insertion. After
   removal, they are returned to the pool. The pool is the result of
   the join operation.
   
   Multiple trees can coexist in the same pool, provided the total
   size of all the trees does not exceed the pool size. This is
   convenient for removing nodes from one tree and inserting them into
   another without copying the key or value.
   
   Example usage:

     struct my_rb_node {
         ulong key;
         ulong val;
         ulong redblack_parent;
         ulong redblack_left;
         ulong redblack_right;
         int redblack_color;
     };
     typedef struct my_rb_node my_rb_node_t;
     #define REDBLK_T my_rb_node_t
     #define REDBLK_NAME my_rb
     #include "fd_redblack.c"

   Note the order of declations and includes. REDBLK_T and REDBLK_NAME
   need to be defined before including this template. REDBLK_T is the
   node or element type. It must include the following fields:

     ulong redblack_parent;
     ulong redblack_left;
     ulong redblack_right;
     int redblack_color;

   which are used by the redblack tree. Everything else in the node
   type is up to the application.

   This example creates the following API for use in the local compilation unit:

     ulong my_rb_max_for_footprint( ulong footprint );
     ulong my_rb_align( void );
     ulong my_rb_footprint( ulong max );
     void * my_rb_new( void * shmem, ulong max );
     my_rb_node_t * my_rb_join( void * shpool );
     void * my_rb_leave( my_rb_node_t * pool );
     void * my_rb_delete( void * shpool );
     ulong my_rb_max( my_rb_node_t const * pool );
     ulong my_rb_free( my_rb_node_t const * pool );
     ulong my_rb_idx( my_rb_node_t const * pool, my_rb_node_t const * node );
     my_rb_node_t * my_rb_node( my_rb_node_t * pool, ulong idx );
     my_rb_node_t * my_rb_acquire( my_rb_node_t * pool );
     void my_rb_release( my_rb_node_t * pool, my_rb_node_t * node );
     void my_rb_release_tree( my_rb_node_t * pool, my_rb_node_t * root );
     my_rb_node_t * my_rb_minimum(my_rb_node_t * pool, my_rb_node_t * root);
     my_rb_node_t * my_rb_maximum(my_rb_node_t * pool, my_rb_node_t * root);
     my_rb_node_t * my_rb_successor(my_rb_node_t * pool, my_rb_node_t * node);
     my_rb_node_t * my_rb_predecessor(my_rb_node_t * pool, my_rb_node_t * node);
     my_rb_node_t * my_rb_insert(my_rb_node_t * pool, my_rb_node_t ** root, my_rb_node_t * x);
     my_rb_node_t * my_rb_remove(my_rb_node_t * pool, my_rb_node_t ** root, my_rb_node_t * z);
     my_rb_node_t * my_rb_find(my_rb_node_t * pool, my_rb_node_t * root, my_rb_node_t * key);
     my_rb_node_t * my_rb_nearby(my_rb_node_t * pool, my_rb_node_t * root, my_rb_node_t * key);
     ulong my_rb_size(my_rb_node_t * pool, my_rb_node_t * root);
     int my_rb_verify(my_rb_node_t * pool, my_rb_node_t * root);
     long my_rb_compare(my_rb_node_t * left, my_rb_node_t * right);

   The specific usage and semantics of these methods is given below.

   A sample application is as follows:

     my_node_t* pool = my_rb_join( my_rb_new( shmem, 20 ) );
     my_node_t* root = NULL;
     for (ulong i = 0; i < 10; ++i) {
       my_node_t * n = my_rb_acquire( pool );
       n->key = 123 + i;
       n->value = 456 + i;
       my_rb_insert( pool, &root, n );
     }
     for (ulong i = 0; i < 10; ++i) {
       my_node_t k;
       k.key = 123 + i;
       my_node_t * n = my_rb_find( pool, root, &k );
       printf("key=%lu value=%lu\n", n->key, n->value);
       n = my_rb_remove( pool, &root, n );
       my_rb_release( pool, n );
     }
     my_rb_delete( my_rb_leave( pool ) );

   The aplication must provided the compare implementation. It must
   return a negative number, zero, or positive depending on whether
   the left is less than, equal to, or greater than right. For
   example:

     long my_rb_compare(my_node_t* left, my_node_t* right) {
       return (long)(left->key - right->key);
     }

*/

#ifndef REDBLK_NAME
#define "Define REDBLK_NAME"
#endif

#ifndef REDBLK_T
#define "Define REDBLK_T"
#endif

/* 0 - local use only
   1 - library header declaration
   2 - library implementation */
#ifndef REDBLK_IMPL_STYLE
#define REDBLK_IMPL_STYLE 0
#endif

/* Constructors and verification logs detail on failure (rest only needs
   fd_bits.h, consider making logging a compile time option). */

#include "../log/fd_log.h"

/* Namespace macro */
#define REDBLK_(n) FD_EXPAND_THEN_CONCAT3(REDBLK_NAME,_,n)

#if REDBLK_IMPL_STYLE==0 || REDBLK_IMPL_STYLE==1 /* need structures and inlines */

FD_PROTOTYPES_BEGIN

/*
  E.g. ulong my_rb_max_for_footprint( ulong footprint );

  Return the maximum number of nodes that will fit into a pool with
  the given footprint.
*/
FD_FN_CONST ulong REDBLK_(max_for_footprint)( ulong footprint );

/*
  E.g. ulong my_rb_align( void );

  Return the pool alignment.
*/
FD_FN_CONST ulong REDBLK_(align)( void );

/*
  E.g. ulong my_rb_footprint( ulong max );

  Return the minimum memory footprint needed for a pool with the given
  number of nodes.
*/
FD_FN_CONST ulong REDBLK_(footprint)( ulong max );

/*
  E.g. void * my_rb_new( void * shmem, ulong max );

  Initialize an allocation pool.
*/
void * REDBLK_(new)( void * shmem, ulong max );

/*
  E.g. my_rb_node_t * my_rb_join( void * shpool );

  Join an allocation pool.
*/
REDBLK_T * REDBLK_(join)( void * shpool );

/*
  E.g. void * my_rb_leave( my_rb_node_t * pool );

  Leave an allocation pool.
*/
void * REDBLK_(leave)( REDBLK_T * pool );

/*
  E.g. void * my_rb_delete( void * shpool );

  Delete an allocation pool.
*/
void * REDBLK_(delete)( void * shpool );

/*
  E.g. ulong my_rb_max( my_rb_node_t const * pool );

  Return the max value given when new was called.
*/
FD_FN_PURE ulong REDBLK_(max)( REDBLK_T const * pool );

/*
  E.g. ulong my_rb_free( my_rb_node_t const * pool );

  Return the number of available nodes in the free pool.
*/
FD_FN_PURE ulong REDBLK_(free)( REDBLK_T const * pool );

/*
  E.g. ulong my_rb_idx( my_rb_node_t const * pool, my_rb_node_t const * node );

  Return the logical index of the node in a pool. Useful when
  relocating a pool in memory.
  */
FD_FN_CONST ulong REDBLK_(idx)( REDBLK_T const * pool, REDBLK_T const * node );

/*
  E.g. my_rb_node_t * my_rb_node( my_rb_node_t * pool, ulong idx );

  Return the node at a logical index in a pool. Useful when relocating
  a pool in memory.
*/
FD_FN_CONST REDBLK_T * REDBLK_(node)( REDBLK_T * pool, ulong idx );

/*
  E.g. my_rb_node_t * my_rb_acquire( my_rb_node_t * pool );

  Acquire a node from the free pool. The result requires
  initialization before insertion. For example:

    my_node_t * n = my_rb_acquire( pool );
    n->key = 123 + i;
    n->value = 456 + i;
    my_rb_insert( pool, &root, n );
*/
REDBLK_T * REDBLK_(acquire)( REDBLK_T * pool );

/*
  E.g. void my_rb_release( my_rb_node_t * pool, my_rb_node_t * node );

  Return a node to the free pool. It must be removed from the tree
  first. For example:

    my_node_t * n = my_rb_find( pool, root, &k );
    n = my_rb_remove( pool, &root, n );
    my_rb_release( pool, n );
  
*/
void REDBLK_(release)( REDBLK_T * pool, REDBLK_T * node );

/*
  E.g. void my_rb_release_tree( my_node_t * pool, my_node_t * root );

  Recursively release all nodes in a tree to a pool. The root argument
  is invalid after this method is called.
*/
void REDBLK_(release_tree)( REDBLK_T * pool, REDBLK_T * root );

/*
  E.g. my_node_t * my_rb_minimum(my_node_t * pool, my_node_t * root);

  Return the node in a tree that has the smallest key (leftmost).
*/
REDBLK_T * REDBLK_(minimum)(REDBLK_T * pool, REDBLK_T * root);
REDBLK_T const * REDBLK_(minimum_const)(REDBLK_T const * pool, REDBLK_T const * root);

/*
  E.g. my_node_t * my_rb_maximum(my_node_t * pool, my_node_t * root);

  Return the node in a tree that has the largest key (rightmost).
*/
REDBLK_T * REDBLK_(maximum)(REDBLK_T * pool, REDBLK_T * root);
REDBLK_T const * REDBLK_(maximum_const)(REDBLK_T const * pool, REDBLK_T const * root);

/*
  E.g. my_node_t * my_rb_successor(my_node_t * pool, my_node_t * node);

  Return the next node which is larger than the given node. To iterate
  across the entire tree, do the following:

    for ( my_node_t* n = my_rb_minimum(pool, root); n; n = my_rb_successor(pool, n) ) {
      printf("key=%lu value=%lu\n", n->key, n->value);
    }

  To iterate safely while also deleting, do:

    my_node_t* nn;
    for ( my_node_t* n = my_rb_minimum(pool, root); n; n = nn ) {
      nn = my_rb_successor(pool, n);
      // Possibly delete n
    }
*/
REDBLK_T * REDBLK_(successor)(REDBLK_T * pool, REDBLK_T * node);
REDBLK_T const * REDBLK_(successor_const)(REDBLK_T const * pool, REDBLK_T const * node);
/*
  E.g. my_node_t * my_rb_predecessor(my_node_t * pool, my_node_t * node);

  Return the previous node which is smaller than the given node. To iterate
  across the entire tree backwards, do the following:

    for ( my_node_t* n = my_rb_maximum(pool, root); n; n = my_rb_predecessor(pool, n) ) {
      printf("key=%lu value=%lu\n", n->key, n->value);
    }

  To iterate safely while also deleting, do:

    my_node_t* nn;
    for ( my_node_t* n = my_rb_maximum(pool, root); n; n = nn ) {
      nn = my_rb_predecessor(pool, n);
      // Possibly delete n
    }
*/
REDBLK_T * REDBLK_(predecessor)(REDBLK_T * pool, REDBLK_T * node);
/*
  E.g. my_node_t * my_rb_insert(my_node_t * pool, my_node_t ** root, my_node_t * x);

  Insert a node into a tree. Typically, the node must be allocated
  from a pool first. The application must initialize any values in the
  node after allocation but before insertion. For example:

    my_node_t * n = my_rb_acquire( pool );
    n->key = 123;
    n->value = 456;
    n = my_rb_insert( pool, &root, n );

  The inserted node is returned.
*/
REDBLK_T * REDBLK_(insert)(REDBLK_T * pool, REDBLK_T ** root, REDBLK_T * x);
/*
  E.g. my_node_t * my_rb_remove(my_node_t * pool, my_node_t ** root, my_node_t * z);

  Remove a node from a tree. The node must be a member of the tree,
  usually the result of a find operation. The node is typically
  released to the pool afterwards. For example:
 
    my_node_t * n = my_rb_find( pool, root, &k );
    n = my_rb_remove( pool, &root, n );
    my_rb_pool_release( pool, n );

  Remove and release are separate steps to allow an application to
  perform final cleanup on the node in between. You can insert a node
  into a different tree after deletion if both trees share a pool. For
  example:

    n = my_rb_remove( pool, &root, n );
    my_rb_insert( pool, &root2, n );
*/
REDBLK_T * REDBLK_(remove)(REDBLK_T * pool, REDBLK_T ** root, REDBLK_T * z);
/*
  E.g. my_node_t * my_rb_find(my_node_t * pool, my_node_t * root, my_node_t * key);

  Search for a key in the tree. In this special case, the key can be a
  temporary instance of the node type rather than a properly
  allocated node. For example:

    my_node_t k;
    k.key = 123 + i;
    my_node_t * n = my_rb_find( pool, root, &k );
    printf("key=%lu value=%lu\n", n->key, n->value);

  A NULL is returned if the find fails.
*/
REDBLK_T * REDBLK_(find)(REDBLK_T * pool, REDBLK_T * root, REDBLK_T * key);
/*
  E.g. my_node_t * my_rb_nearby(my_node_t * pool, my_node_t * root, my_node_t * key);

  Search for a key in the tree. If the key can't be found, a nearby
  approximation is returned instead. This is either the greatest node
  less than the key, or the least node greater than the key. In this
  special case, the key can be a temporary instance of the node type
  rather than a properly allocated node. For example:

    my_node_t k;
    k.key = 123 + i;
    my_node_t * n = my_rb_nearby( pool, root, &k );
    printf("key=%lu value=%lu\n", n->key, n->value);

  A NULL is returned if the search fails.
*/
REDBLK_T * REDBLK_(nearby)(REDBLK_T * pool, REDBLK_T * root, REDBLK_T * key);
/*
  E.g. ulong my_rb_size(my_node_t * pool, my_node_t * root);

  Count the number of nodes in a tree.
*/
ulong REDBLK_(size)(REDBLK_T * pool, REDBLK_T * root);

/*
  E.g. int my_rb_verify(my_node_t * pool, my_node_t * root);

  Verify the integrity of the tree data structure. Useful for
  debugging memory corruption. A non-zero result is returned if an error
  is detected.
*/
int REDBLK_(verify)(REDBLK_T * pool, REDBLK_T * root);

/*
  E.g. long my_rb_compare(my_node_t * left, my_node_t * right);
  
  Defined by application to implement key comparison. Returns a
  negative number, zero, or positive depending on whether the left is
  less than, equal to, or greater than right. For example:

    long my_rb_compare(my_node_t* left, my_node_t* right) {
      return (long)(left->key - right->key);
    }

  Should be a pure function.  (FIXME: SHOULD TAKE CONST POINTERS?)
*/
FD_FN_PURE long REDBLK_(compare)(REDBLK_T * left, REDBLK_T * right);

FD_PROTOTYPES_END

#endif /* REDBLK_IMPL_STYLE==0 || REDBLK_IMPL_STYLE==1 */

#if REDBLK_IMPL_STYLE==0 || REDBLK_IMPL_STYLE==2 /* need implementations */

/* Tree node colors */
#define REDBLK_FREE -1
#define REDBLK_NEW 0
#define REDBLK_BLACK 1
#define REDBLK_RED 2

#ifndef REDBLK_PARENT
#define REDBLK_PARENT redblack_parent
#endif
#ifndef REDBLK_LEFT
#define REDBLK_LEFT redblack_left
#endif
#ifndef REDBLK_RIGHT
#define REDBLK_RIGHT redblack_right
#endif
#ifndef REDBLK_COLOR
#define REDBLK_COLOR redblack_color
#endif

#define POOL_NAME FD_EXPAND_THEN_CONCAT2(REDBLK_NAME,_pool)
#define POOL_T REDBLK_T
#define POOL_SENTINEL 1
#ifdef REDBLK_NEXTFREE
#define POOL_NEXT REDBLK_NEXTFREE
#else
#define POOL_NEXT REDBLK_RIGHT
#endif
#include "fd_pool.c"
#undef MAP_POOL_NAME
#undef MAP_POOL_T

#define REDBLK_POOL_(n) FD_EXPAND_THEN_CONCAT3(REDBLK_NAME,_pool_,n)

#define REDBLK_NIL 0UL /* Must be same as pool sentinel */

ulong REDBLK_(max_for_footprint)( ulong footprint ) {
  return REDBLK_POOL_(max_for_footprint)(footprint) - 1; /* Allow for sentinel */
}

ulong REDBLK_(align)( void ) {
  return REDBLK_POOL_(align)();
}

ulong REDBLK_(footprint)( ulong max ) {
  return REDBLK_POOL_(footprint)(max + 1); /* Allow for sentinel */
}

void * REDBLK_(new)( void * shmem, ulong max ) {
  void * shmem2 = REDBLK_POOL_(new)(shmem, max + 1); /* Allow for sentinel */
  if ( FD_UNLIKELY( shmem2 == NULL ) )
    return NULL;
  /* Initialize sentinel */
  REDBLK_T * pool = REDBLK_POOL_(join)(shmem2);
  if ( FD_UNLIKELY( pool == NULL ) )
    return NULL;
  REDBLK_T * node = REDBLK_POOL_(ele_sentinel)(pool);
  node->REDBLK_LEFT = REDBLK_NIL;
  node->REDBLK_RIGHT = REDBLK_NIL;
  node->REDBLK_PARENT = REDBLK_NIL;
  node->REDBLK_COLOR = REDBLK_BLACK;
  return shmem2;
}

REDBLK_T * REDBLK_(join)( void * shpool ) {
  FD_COMPILER_MFENCE();
  return REDBLK_POOL_(join)(shpool);
}

void * REDBLK_(leave)( REDBLK_T * pool ) {
  FD_COMPILER_MFENCE();
  return REDBLK_POOL_(leave)(pool);
}

void * REDBLK_(delete)( void * shpool ) {
  FD_COMPILER_MFENCE();
  return REDBLK_POOL_(delete)(shpool);
}

ulong REDBLK_(max)( REDBLK_T const * pool ) {
  return REDBLK_POOL_(max)(pool) - 1; /* Allow for sentinel */
}

ulong REDBLK_(free)( REDBLK_T const * pool ) {
  return REDBLK_POOL_(free)(pool);
}

ulong REDBLK_(idx)( REDBLK_T const * pool, REDBLK_T const * node ) {
  return REDBLK_POOL_(idx)(pool, node);
}

REDBLK_T * REDBLK_(node)( REDBLK_T * pool, ulong idx ) {
  return REDBLK_POOL_(ele)(pool, idx);
}

REDBLK_T * REDBLK_(acquire)( REDBLK_T * pool ) {
  if ( REDBLK_POOL_(free)( pool ) == 0 )
    return NULL;
  REDBLK_T * node = REDBLK_POOL_(ele_acquire)(pool);
  node->REDBLK_COLOR = REDBLK_NEW;
  return node;
}

#ifndef REDBLK_UNSAFE
void REDBLK_(validate_element)( REDBLK_T * pool, REDBLK_T * node ) {
  if ( !REDBLK_POOL_(ele_test)( pool, node ) )
    FD_LOG_ERR(( "invalid redblack node" ));
  if ( node && node->REDBLK_COLOR == REDBLK_FREE )
    FD_LOG_ERR(( "invalid redblack node" ));
}
void REDBLK_(validate_element_const)( REDBLK_T const * pool, REDBLK_T const * node ) {
  if ( !REDBLK_POOL_(ele_test)( pool, node ) )
    FD_LOG_ERR(( "invalid redblack node" ));
  if ( node && node->REDBLK_COLOR == REDBLK_FREE )
    FD_LOG_ERR(( "invalid redblack node" ));
}
#endif

void REDBLK_(release)( REDBLK_T * pool, REDBLK_T * node ) {
#ifndef REDBLK_UNSAFE
  REDBLK_(validate_element)(pool, node);
#endif

  node->REDBLK_COLOR = REDBLK_FREE;
  REDBLK_POOL_(ele_release)(pool, node);
}

/*
  Recursively release all nodes in a tree to a pool. The root argument
  is invalid after this method is called.
*/
void REDBLK_(release_tree)( REDBLK_T * pool, REDBLK_T * node ) {
  if (!node || node == &pool[REDBLK_NIL])
    return;

#ifndef REDBLK_UNSAFE
  REDBLK_(validate_element)(pool, node);
#endif
  
  REDBLK_T * left = &pool[node->REDBLK_LEFT];
  REDBLK_T * right = &pool[node->REDBLK_RIGHT];
  
  REDBLK_(release)(pool, node);

  REDBLK_(release_tree)(pool, left);
  REDBLK_(release_tree)(pool, right);
}

/*
  Return the node in a tree that has the smallest key (leftmost).
*/
REDBLK_T * REDBLK_(minimum)(REDBLK_T * pool, REDBLK_T * node) {
  if (!node || node == &pool[REDBLK_NIL])
    return NULL;
#ifndef REDBLK_UNSAFE
  REDBLK_(validate_element)(pool, node);
#endif
  while (node->REDBLK_LEFT != REDBLK_NIL) {
    node = &pool[node->REDBLK_LEFT];
  }
  return node;
}
REDBLK_T const * REDBLK_(minimum_const)(REDBLK_T const * pool, REDBLK_T const * node) {
  if (!node || node == &pool[REDBLK_NIL])
    return NULL;
#ifndef REDBLK_UNSAFE
  REDBLK_(validate_element_const)(pool, node);
#endif
  while (node->REDBLK_LEFT != REDBLK_NIL) {
    node = &pool[node->REDBLK_LEFT];
  }
  return node;
}

/*
  Return the node in a tree that has the largest key (rightmost).
*/
REDBLK_T * REDBLK_(maximum)(REDBLK_T * pool, REDBLK_T * node) {
  if (!node || node == &pool[REDBLK_NIL])
    return NULL;
#ifndef REDBLK_UNSAFE
  REDBLK_(validate_element)(pool, node);
#endif
  while (node->REDBLK_RIGHT != REDBLK_NIL) {
    node = &pool[node->REDBLK_RIGHT];
  }
  return node;
}
REDBLK_T const * REDBLK_(maximum_const)(REDBLK_T const * pool, REDBLK_T const * node) {
  if (!node || node == &pool[REDBLK_NIL])
    return NULL;
#ifndef REDBLK_UNSAFE
  REDBLK_(validate_element_const)(pool, node);
#endif
  while (node->REDBLK_RIGHT != REDBLK_NIL) {
    node = &pool[node->REDBLK_RIGHT];
  }
  return node;
}

/*
  Return the next node which is larger than the given node.
*/
REDBLK_T * REDBLK_(successor)(REDBLK_T * pool, REDBLK_T * x) {
#ifndef REDBLK_UNSAFE
  REDBLK_(validate_element)(pool, x);
#endif

  // if the right subtree is not null,
  // the successor is the leftmost node in the
  // right subtree
  if (x->REDBLK_RIGHT != REDBLK_NIL) {
    return REDBLK_(minimum)(pool, &pool[x->REDBLK_RIGHT]);
  }

  // else it is the lowest ancestor of x whose
  // left child is also an ancestor of x.
  for (;;) {
    if (x->REDBLK_PARENT == REDBLK_NIL)
      return NULL;
    REDBLK_T * y = &pool[x->REDBLK_PARENT];
    if (x == &pool[y->REDBLK_LEFT])
      return y;
    x = y;
  }
}
REDBLK_T const * REDBLK_(successor_const)(REDBLK_T const * pool, REDBLK_T const * x) {
#ifndef REDBLK_UNSAFE
  REDBLK_(validate_element_const)(pool, x);
#endif

  // if the right subtree is not null,
  // the successor is the leftmost node in the
  // right subtree
  if (x->REDBLK_RIGHT != REDBLK_NIL) {
    return REDBLK_(minimum_const)(pool, &pool[x->REDBLK_RIGHT]);
  }

  // else it is the lowest ancestor of x whose
  // left child is also an ancestor of x.
  for (;;) {
    if (x->REDBLK_PARENT == REDBLK_NIL)
      return NULL;
    REDBLK_T const * y = &pool[x->REDBLK_PARENT];
    if (x == &pool[y->REDBLK_LEFT])
      return y;
    x = y;
  }
}

/*
  Return the previous node which is smaller than the given node.
*/
REDBLK_T * REDBLK_(predecessor)(REDBLK_T * pool, REDBLK_T * x) {
#ifndef REDBLK_UNSAFE
  REDBLK_(validate_element)(pool, x);
#endif

  // if the left subtree is not null,
  // the predecessor is the rightmost node in the 
  // left subtree
  if (x->REDBLK_LEFT != REDBLK_NIL) {
    return REDBLK_(maximum)(pool, &pool[x->REDBLK_LEFT]);
  }

  // else it is the lowest ancestor of x whose
  // right child is also an ancestor of x.
  for (;;) {
    if (x->REDBLK_PARENT == REDBLK_NIL)
      return NULL;
    REDBLK_T * y = &pool[x->REDBLK_PARENT];
    if (x == &pool[y->REDBLK_RIGHT])
      return y;
    x = y;
  }
}
REDBLK_T const * REDBLK_(predecessor_const)(REDBLK_T const * pool, REDBLK_T const * x) {
#ifndef REDBLK_UNSAFE
  REDBLK_(validate_element_const)(pool, x);
#endif

  // if the left subtree is not null,
  // the predecessor is the rightmost node in the 
  // left subtree
  if (x->REDBLK_LEFT != REDBLK_NIL) {
    return REDBLK_(maximum_const)(pool, &pool[x->REDBLK_LEFT]);
  }

  // else it is the lowest ancestor of x whose
  // right child is also an ancestor of x.
  for (;;) {
    if (x->REDBLK_PARENT == REDBLK_NIL)
      return NULL;
    REDBLK_T const * y = &pool[x->REDBLK_PARENT];
    if (x == &pool[y->REDBLK_RIGHT])
      return y;
    x = y;
  }
}

/*
  Perform a left rotation around a node
*/
static void REDBLK_(rotateLeft)(REDBLK_T * pool, REDBLK_T ** root, REDBLK_T * x) {
  REDBLK_T * y = &pool[x->REDBLK_RIGHT];

  /* establish x->REDBLK_RIGHT link */
  x->REDBLK_RIGHT = y->REDBLK_LEFT;
  if (y->REDBLK_LEFT != REDBLK_NIL)
    pool[y->REDBLK_LEFT].REDBLK_PARENT = (uint)(x - pool);

  /* establish y->REDBLK_PARENT link */
  if (y != &pool[REDBLK_NIL])
    y->REDBLK_PARENT = x->REDBLK_PARENT;
  if (x->REDBLK_PARENT) {
    REDBLK_T * p = &pool[x->REDBLK_PARENT];
    if (x == &pool[p->REDBLK_LEFT])
      p->REDBLK_LEFT = (uint)(y - pool);
    else
      p->REDBLK_RIGHT = (uint)(y - pool);
  } else {
    *root = y;
  }

  /* link x and y */
  y->REDBLK_LEFT = (uint)(x - pool);
  if (x != &pool[REDBLK_NIL])
    x->REDBLK_PARENT = (uint)(y - pool);
}

/*
  Perform a right rotation around a node
*/
static void REDBLK_(rotateRight)(REDBLK_T * pool, REDBLK_T ** root, REDBLK_T * x) {
  REDBLK_T * y = &pool[x->REDBLK_LEFT];

  /* establish x->REDBLK_LEFT link */
  x->REDBLK_LEFT = y->REDBLK_RIGHT;
  if (y->REDBLK_RIGHT != REDBLK_NIL)
    pool[y->REDBLK_RIGHT].REDBLK_PARENT = (uint)(x - pool);

  /* establish y->REDBLK_PARENT link */
  if (y != &pool[REDBLK_NIL])
    y->REDBLK_PARENT = x->REDBLK_PARENT;
  if (x->REDBLK_PARENT) {
    REDBLK_T * p = &pool[x->REDBLK_PARENT];
    if (x == &pool[p->REDBLK_RIGHT])
      p->REDBLK_RIGHT = (uint)(y - pool);
    else
      p->REDBLK_LEFT = (uint)(y - pool);
  } else {
    *root = y;
  }

  /* link x and y */
  y->REDBLK_RIGHT = (uint)(x - pool);
  if (x != &pool[REDBLK_NIL])
    x->REDBLK_PARENT = (uint)(y - pool);
}

/*
  Restore tree invariants after an insert.
*/
static void REDBLK_(insertFixup)(REDBLK_T * pool, REDBLK_T ** root, REDBLK_T * x) {
  /* check Red-Black properties */
  REDBLK_T * p;
  while (x != *root && (p = &pool[x->REDBLK_PARENT])->REDBLK_COLOR == REDBLK_RED) {
    /* we have a violation */
    REDBLK_T * gp = &pool[p->REDBLK_PARENT];
    if (x->REDBLK_PARENT == gp->REDBLK_LEFT) {
      REDBLK_T * y = &pool[gp->REDBLK_RIGHT];
      if (y->REDBLK_COLOR == REDBLK_RED) {

        /* uncle is REDBLK_RED */
        p->REDBLK_COLOR = REDBLK_BLACK;
        y->REDBLK_COLOR = REDBLK_BLACK;
        gp->REDBLK_COLOR = REDBLK_RED;
        x = gp;
      } else {

        /* uncle is REDBLK_BLACK */
        if (x == &pool[p->REDBLK_RIGHT]) {
          /* make x a left child */
          x = p;
          REDBLK_(rotateLeft)(pool, root, x);
          p = &pool[x->REDBLK_PARENT];
          gp = &pool[p->REDBLK_PARENT];
        }

        /* recolor and rotate */
        p->REDBLK_COLOR = REDBLK_BLACK;
        gp->REDBLK_COLOR = REDBLK_RED;
        REDBLK_(rotateRight)(pool, root, gp);
      }
      
    } else {
      /* mirror image of above code */
      REDBLK_T * y = &pool[gp->REDBLK_LEFT];
      if (y->REDBLK_COLOR == REDBLK_RED) {

        /* uncle is REDBLK_RED */
        p->REDBLK_COLOR = REDBLK_BLACK;
        y->REDBLK_COLOR = REDBLK_BLACK;
        gp->REDBLK_COLOR = REDBLK_RED;
        x = gp;
      } else {

        /* uncle is REDBLK_BLACK */
        if (x == &pool[p->REDBLK_LEFT]) {
          x = p;
          REDBLK_(rotateRight)(pool, root, x);
          p = &pool[x->REDBLK_PARENT];
          gp = &pool[p->REDBLK_PARENT];
        }
        p->REDBLK_COLOR = REDBLK_BLACK;
        gp->REDBLK_COLOR = REDBLK_RED;
        REDBLK_(rotateLeft)(pool, root, gp);
      }
    }
  }

  (*root)->REDBLK_COLOR = REDBLK_BLACK;
}

/*
  Insert a node into a tree. Typically, the node must be allocated
  from a pool first.
*/
REDBLK_T * REDBLK_(insert)(REDBLK_T * pool, REDBLK_T ** root, REDBLK_T * x) {
#ifndef REDBLK_UNSAFE
  REDBLK_(validate_element)(pool, *root);
  REDBLK_(validate_element)(pool, x);
#endif

  REDBLK_T * current;
  REDBLK_T * parent;

  /* find where node belongs */
  current = *root;
  if (current == NULL)
    current = &pool[REDBLK_NIL];
  parent = &pool[REDBLK_NIL];
  while (current != &pool[REDBLK_NIL]) {
    long c = REDBLK_(compare)(x, current);
    parent = current;
    current = (c < 0 ? &pool[current->REDBLK_LEFT] : &pool[current->REDBLK_RIGHT]);
  }

  /* setup new node */
  x->REDBLK_PARENT = (uint)(parent - pool);
  x->REDBLK_LEFT = REDBLK_NIL;
  x->REDBLK_RIGHT = REDBLK_NIL;
  x->REDBLK_COLOR = REDBLK_RED;

  /* insert node in tree */
  if (parent != &pool[REDBLK_NIL]) {
    long c = REDBLK_(compare)(x, parent);
    if (c < 0)
      parent->REDBLK_LEFT = (uint)(x - pool);
    else
      parent->REDBLK_RIGHT = (uint)(x - pool);
  } else {
    *root = x;
  }

  REDBLK_(insertFixup)(pool, root, x);
  return x;
}

/*
  Restore tree invariants after a delete
*/
static void REDBLK_(deleteFixup)(REDBLK_T * pool, REDBLK_T ** root, REDBLK_T * x) {
  while (x != *root && x->REDBLK_COLOR == REDBLK_BLACK) {
    REDBLK_T * p = &pool[x->REDBLK_PARENT];
    if (x == &pool[p->REDBLK_LEFT]) {
      REDBLK_T * w = &pool[p->REDBLK_RIGHT];
      if (w->REDBLK_COLOR == REDBLK_RED) {
        w->REDBLK_COLOR = REDBLK_BLACK;
        p->REDBLK_COLOR = REDBLK_RED;
        REDBLK_(rotateLeft)(pool, root, p);
        p = &pool[x->REDBLK_PARENT];
        w = &pool[p->REDBLK_RIGHT];
      }
      if (pool[w->REDBLK_LEFT].REDBLK_COLOR == REDBLK_BLACK &&
         pool[w->REDBLK_RIGHT].REDBLK_COLOR == REDBLK_BLACK) {
        w->REDBLK_COLOR = REDBLK_RED;
        x = p;
      } else {
        if (pool[w->REDBLK_RIGHT].REDBLK_COLOR == REDBLK_BLACK) {
          pool[w->REDBLK_LEFT].REDBLK_COLOR = REDBLK_BLACK;
          w->REDBLK_COLOR = REDBLK_RED;
          REDBLK_(rotateRight)(pool, root, w);
          p = &pool[x->REDBLK_PARENT];
          w = &pool[p->REDBLK_RIGHT];
        }
        w->REDBLK_COLOR = p->REDBLK_COLOR;
        p->REDBLK_COLOR = REDBLK_BLACK;
        pool[w->REDBLK_RIGHT].REDBLK_COLOR = REDBLK_BLACK;
        REDBLK_(rotateLeft)(pool, root, p);
        x = *root;
      }
      
    } else {
      REDBLK_T * w = &pool[p->REDBLK_LEFT];
      if (w->REDBLK_COLOR == REDBLK_RED) {
        w->REDBLK_COLOR = REDBLK_BLACK;
        p->REDBLK_COLOR = REDBLK_RED;
        REDBLK_(rotateRight)(pool, root, p);
        p = &pool[x->REDBLK_PARENT];
        w = &pool[p->REDBLK_LEFT];
      }
      if (pool[w->REDBLK_RIGHT].REDBLK_COLOR == REDBLK_BLACK &&
          pool[w->REDBLK_LEFT].REDBLK_COLOR == REDBLK_BLACK) {
        w->REDBLK_COLOR = REDBLK_RED;
        x = p;
      } else {
        if (pool[w->REDBLK_LEFT].REDBLK_COLOR == REDBLK_BLACK) {
          pool[w->REDBLK_RIGHT].REDBLK_COLOR = REDBLK_BLACK;
          w->REDBLK_COLOR = REDBLK_RED;
          REDBLK_(rotateLeft)(pool, root, w);
          p = &pool[x->REDBLK_PARENT];
          w = &pool[p->REDBLK_LEFT];
        }
        w->REDBLK_COLOR = p->REDBLK_COLOR;
        p->REDBLK_COLOR = REDBLK_BLACK;
        pool[w->REDBLK_LEFT].REDBLK_COLOR = REDBLK_BLACK;
        REDBLK_(rotateRight)(pool, root, p);
        x = *root;
      }
    }
  }
  
  x->REDBLK_COLOR = REDBLK_BLACK;
}

/*
  Remove a node from a tree. The node must be a member of the tree,
  usually the result of a find operation. The node is typically
  released to the pool afterwards.
*/
REDBLK_T * REDBLK_(remove)(REDBLK_T * pool, REDBLK_T ** root, REDBLK_T * z) {
#ifndef REDBLK_UNSAFE
  REDBLK_(validate_element)(pool, *root);
  REDBLK_(validate_element)(pool, z);
#endif

  REDBLK_T * x;
  REDBLK_T * y;

  if (!z || z == &pool[REDBLK_NIL])
    return NULL;

  if (z->REDBLK_LEFT == REDBLK_NIL || z->REDBLK_RIGHT == REDBLK_NIL) {
    /* y has a REDBLK_NIL node as a child */
    y = z;
  } else {
    /* find tree successor with a REDBLK_NIL node as a child */
    y = &pool[z->REDBLK_RIGHT];
    while (y->REDBLK_LEFT != REDBLK_NIL)
      y = &pool[y->REDBLK_LEFT];
  }

  /* x is y's only child */
  if (y->REDBLK_LEFT != REDBLK_NIL)
    x = &pool[y->REDBLK_LEFT];
  else
    x = &pool[y->REDBLK_RIGHT];

  /* remove y from the parent chain */
  x->REDBLK_PARENT = y->REDBLK_PARENT;
  if (y->REDBLK_PARENT)
    if (y == &pool[pool[y->REDBLK_PARENT].REDBLK_LEFT])
      pool[y->REDBLK_PARENT].REDBLK_LEFT = (uint)(x - pool);
    else
      pool[y->REDBLK_PARENT].REDBLK_RIGHT = (uint)(x - pool);
  else
    *root = x;

  if (y->REDBLK_COLOR == REDBLK_BLACK)
    REDBLK_(deleteFixup)(pool, root, x);

  if (y != z) {
    /* we got rid of y instead of z. Oops! Replace z with y in the
     * tree so we don't lose y's key/value. */
    y->REDBLK_PARENT = z->REDBLK_PARENT;
    y->REDBLK_LEFT = z->REDBLK_LEFT;
    y->REDBLK_RIGHT = z->REDBLK_RIGHT;
    y->REDBLK_COLOR = z->REDBLK_COLOR;
    if (z == *root)
      *root = y;
    else if (&pool[pool[y->REDBLK_PARENT].REDBLK_LEFT] == z)
      pool[y->REDBLK_PARENT].REDBLK_LEFT = (uint)(y - pool);
    else
      pool[y->REDBLK_PARENT].REDBLK_RIGHT = (uint)(y - pool);
    pool[y->REDBLK_LEFT].REDBLK_PARENT = (uint)(y - pool);
    pool[y->REDBLK_RIGHT].REDBLK_PARENT = (uint)(y - pool);
  }

  if (*root == &pool[REDBLK_NIL])
    *root = NULL;
  z->REDBLK_COLOR = REDBLK_NEW;
  return z;
}

/*
  Search for a key in the tree. In this special case, the key can be a
  temporary instance of the node type rather than a properly
  allocated node.
*/
REDBLK_T * REDBLK_(find)(REDBLK_T * pool, REDBLK_T * root, REDBLK_T * key) {
#ifndef REDBLK_UNSAFE
  REDBLK_(validate_element)(pool, root);
#endif

  REDBLK_T * current = root;
  if (current == NULL || current == &pool[REDBLK_NIL])
    return NULL;
  while (current != &pool[REDBLK_NIL]) {
    long c = REDBLK_(compare)(key, current);
    if (c == 0)
      return current;
    current = (c < 0 ? &pool[current->REDBLK_LEFT] : &pool[current->REDBLK_RIGHT]);
  }
  return NULL;
}

/*
  Search for a key in the tree. If the key can't be found, a nearby
  approximation is returned instead. This is either the greatest node
  less than the key, or the least node greater than the key. In this
  special case, the key can be a temporary instance of the node type
  rather than a properly allocated node.
*/
REDBLK_T * REDBLK_(nearby)(REDBLK_T * pool, REDBLK_T * root, REDBLK_T * key) {
#ifndef REDBLK_UNSAFE
  REDBLK_(validate_element)(pool, root);
#endif

  REDBLK_T * current = root;
  if (current == NULL || current == &pool[REDBLK_NIL])
    return NULL;
  REDBLK_T * result = current;
  while (current != &pool[REDBLK_NIL]) {
    result = current; /* Return the last non-NIL node that was touched */
    long c = REDBLK_(compare)(key, current);
    if (c == 0)
      return current;
    current = (c < 0 ? &pool[current->REDBLK_LEFT] : &pool[current->REDBLK_RIGHT]);
  }
  return result;
}

/*
  Count the number of nodes in a tree.
*/
ulong REDBLK_(size)(REDBLK_T * pool, REDBLK_T * root) {
#ifndef REDBLK_UNSAFE
  REDBLK_(validate_element)(pool, root);
#endif
 if (!root || root == &pool[REDBLK_NIL])
   return 0;
 return 1 +
        REDBLK_(size)(pool, &pool[root->REDBLK_LEFT]) +
        REDBLK_(size)(pool, &pool[root->REDBLK_RIGHT]);
}

/*
  Recursive implementation of the verify function
*/
int REDBLK_(verify_private)(REDBLK_T * pool, REDBLK_T * node, REDBLK_T * parent, ulong curblkcnt, ulong correctblkcnt) {
# define REDBLK_TEST(c) do {                                                        \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return -1; } \
  } while(0)

  if (!node || node == &pool[REDBLK_NIL]) {
    REDBLK_TEST(curblkcnt == correctblkcnt);
    return 0;
  }

#ifndef REDBLK_UNSAFE
  REDBLK_(validate_element)(pool, node);
#endif
  
  REDBLK_TEST(&pool[node->REDBLK_PARENT] == parent);

  if (node->REDBLK_COLOR == REDBLK_BLACK)
    ++curblkcnt;
  else {
    REDBLK_TEST(node->REDBLK_COLOR == REDBLK_RED);
    REDBLK_TEST(parent->REDBLK_COLOR == REDBLK_BLACK);
  }
  
  if (node->REDBLK_LEFT != REDBLK_NIL)
    REDBLK_TEST(REDBLK_(compare)(&pool[node->REDBLK_LEFT], node) <= 0);
  if (node->REDBLK_RIGHT != REDBLK_NIL)
    REDBLK_TEST(REDBLK_(compare)(node, &pool[node->REDBLK_RIGHT]) <= 0);

  int err = REDBLK_(verify_private)(pool, &pool[node->REDBLK_LEFT], node, curblkcnt, correctblkcnt);
  if (err) return err;
  return REDBLK_(verify_private)(pool, &pool[node->REDBLK_RIGHT], node, curblkcnt, correctblkcnt);
}

/*
  Verify the integrity of the tree data structure. Useful for
  debugging memory corruption. A non-zero result is returned if an error
  is detected.
*/
int REDBLK_(verify)(REDBLK_T * pool, REDBLK_T * root) {
  REDBLK_TEST(pool[REDBLK_NIL].REDBLK_LEFT == REDBLK_NIL &&
       pool[REDBLK_NIL].REDBLK_RIGHT == REDBLK_NIL &&
       pool[REDBLK_NIL].REDBLK_COLOR == REDBLK_BLACK);

  if (!root || root == &pool[REDBLK_NIL])
    return 0; // Trivially correct
  REDBLK_TEST(root->REDBLK_COLOR == REDBLK_BLACK);

  ulong sz = REDBLK_(size)(pool, root);
  REDBLK_TEST(sz + 1 == REDBLK_POOL_(used)(pool));

  // Compute the correct number of black nodes on a path
  ulong blkcnt = 0;
  REDBLK_T * node = root;
  while (node != &pool[REDBLK_NIL]) {
    if (node->REDBLK_COLOR == REDBLK_BLACK)
      ++blkcnt;
    node = &pool[node->REDBLK_LEFT];
  }
  // Recursive check
  return REDBLK_(verify_private)(pool, root, &pool[REDBLK_NIL], 0, blkcnt);

#undef REDBLK_TEST
}

#undef REDBLK_FREE
#undef REDBLK_NEW
#undef REDBLK_BLACK
#undef REDBLK_RED
#undef REDBLK_POOL_
#undef REDBLK_PARENT
#undef REDBLK_LEFT
#undef REDBLK_RIGHT
#undef REDBLK_COLOR

#endif /* REDBLK_IMPL_STYLE==0 || REDBLK_IMPL_STYLE==2 */

#undef REDBLK_
#undef REDBLK_T
#undef REDBLK_IMPL_STYLE
