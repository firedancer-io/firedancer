#include "../log/fd_log.h"

#define REDBLK_(n) FD_EXPAND_THEN_CONCAT3(REDBLK_NAME,_,n)
#define REDBLK_POOL_(n) FD_EXPAND_THEN_CONCAT3(REDBLK_NAME,_pool_,n)

#ifndef REDBLK_MAGIC
#define REDBLK_MAGIC 3693906804964735521UL
#endif

#define REDBLK_NIL 0U /* all leafs are sentinels. this is always entry zero in the pool */

struct REDBLK_POOL_(private) {
  ulong magic;    /* REDBLK_MAGIC */
  ulong max;      /* Arbitrary */
  uint free;      /* head of free list */
};

typedef struct REDBLK_POOL_(private) REDBLK_POOL_(private_t);

/*
  Get the private metadata from a join pointer.
*/
static inline REDBLK_POOL_(private_t) *
  REDBLK_POOL_(private)( REDBLK_T * join ) {
  return (REDBLK_POOL_(private_t) *)(((ulong)join) - sizeof(REDBLK_POOL_(private_t)));
}

/*
  Get the private metadata from a join pointer as a const.
*/
static inline REDBLK_POOL_(private_t) const *
  REDBLK_POOL_(private_const)( REDBLK_T const * join ) {
  return (REDBLK_POOL_(private_t) const *)(((ulong)join) - sizeof(REDBLK_POOL_(private_t)));
}

/*
  E.g. ulong my_rb_pool_align( void );

  Return the byte alignment required by a node pool.
*/
ulong REDBLK_POOL_(align)( void ) {
  return fd_ulong_max( alignof(REDBLK_T), 128UL );
}

/*
  Get the footprint of the private metadata.
*/
static inline ulong REDBLK_POOL_(private_meta_footprint)( void ) {
  return fd_ulong_align_up( sizeof(REDBLK_POOL_(private_t)), REDBLK_POOL_(align)() );
}

/*
  E.g. ulong my_rb_pool_footprint( ulong max );

  Return the number of bytes of memory required by a pool with the
  given maximum number of nodes.
*/
ulong REDBLK_POOL_(footprint)( ulong max ) {
  ulong align          = REDBLK_POOL_(align)();
  ulong meta_footprint = REDBLK_POOL_(private_meta_footprint)(); /* Multiple of align */
  ulong data_footprint = fd_ulong_align_up( sizeof(REDBLK_T)*max, align );
  ulong thresh         = (ULONG_MAX - align - meta_footprint + 1UL) / sizeof(REDBLK_T);
  return fd_ulong_if( max > thresh, 0UL, meta_footprint + data_footprint );
}

/*
  E.g. ulong my_rb_pool_max_for_footprint( ulong footprint );

  Return the recommended maximum number of nodes for a given memory
  footprint.
*/
ulong REDBLK_POOL_(max_for_footprint)( ulong footprint ) {
  ulong meta_footprint = REDBLK_POOL_(private_meta_footprint)(); /* Multiple of align */
  return (footprint - meta_footprint) / sizeof(REDBLK_T);
}

/*
  E.g. void * my_rb_pool_new( void * shmem, ulong max );

  Initialize memory for a node pool for a given maximum number of
  nodes. All nodes in the pool will be uninitialized and available for
  allocation to start. There must be enough memory for the required
  footprint.
*/
void * REDBLK_POOL_(new)( void * shmem, ulong  max ) {
  if( FD_UNLIKELY( !shmem ) ) return NULL;

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, REDBLK_POOL_(align)() ) ) ) return NULL;

  if( FD_UNLIKELY( !REDBLK_POOL_(footprint)( max ) ) ) return NULL;

  /* Initialize the sentinel */
  REDBLK_T * join = (REDBLK_T *)(((ulong)shmem) + REDBLK_POOL_(private_meta_footprint)());
  join[REDBLK_NIL].redblack.left = REDBLK_NIL;
  join[REDBLK_NIL].redblack.right = REDBLK_NIL;
  join[REDBLK_NIL].redblack.parent = REDBLK_NIL;
  join[REDBLK_NIL].redblack.color = REDBLK_BLACK;
  
  /* Build free list */
  uint last = REDBLK_NIL;
  for (uint i = 1; i < max; ++i) {
    join[i].redblack.left = last;
    join[i].redblack.right = REDBLK_NIL;
    join[i].redblack.parent = REDBLK_NIL;
    join[i].redblack.color = REDBLK_FREE;
    last = i;
  }

  /* Init metadata */
  REDBLK_POOL_(private_t) * meta = REDBLK_POOL_(private)( join );
  meta->magic = REDBLK_MAGIC;
  meta->max = max;
  meta->free = last;
  return shmem;
}

/*
  E.g. my_node_t * my_rb_pool_join( void * shmem );

  Attach to a node pool which is already formatted (possibly in shared
  memory). The resulting pointer represents the pool. Only a single
  thread can join a pool at one time. Concurrent access is not supported.
*/
REDBLK_T * REDBLK_POOL_(join)( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) return NULL;

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, REDBLK_POOL_(align)() ) ) ) return NULL;

  REDBLK_T * join = (REDBLK_T *)(((ulong)shmem) + REDBLK_POOL_(private_meta_footprint)());
  REDBLK_POOL_(private_t) * meta = REDBLK_POOL_(private)( join );
  if ( meta->magic != REDBLK_MAGIC ) {
    FD_LOG_WARNING(("invalid pool pointer"));
    return NULL;
  }
  
  return join;
}

/*
  E.g. void * my_rb_pool_leave( my_node_t * join );

  Detach from a node pool. This will not call any "destructors" on the
  nodes. If applications require additional memory management, they
  must solve this problem.
*/
void * REDBLK_POOL_(leave)( REDBLK_T * join ) {

  if( FD_UNLIKELY( !join ) ) return NULL;

  return (void *)(((ulong)join) - REDBLK_POOL_(private_meta_footprint)());
}

/*
  E.g. void * my_rb_pool_delete( void * shmem );

  Mark a pool as deleted.
*/
void * REDBLK_POOL_(delete)( void * shmem ) {

  if( FD_UNLIKELY( !shmem ) ) return NULL;

  REDBLK_T * join = (REDBLK_T *)(((ulong)shmem) + REDBLK_POOL_(private_meta_footprint)());
  REDBLK_POOL_(private_t) * meta = REDBLK_POOL_(private)( join );
  meta->magic = 0;

  return shmem;
}

/*
  E.g. ulong my_rb_pool_max( my_node_t const * join );

  Return the maximum number of nodes that the pool was configured with.
*/
ulong REDBLK_POOL_(max)( REDBLK_T const * join ) {
  REDBLK_POOL_(private_t) const * meta = REDBLK_POOL_(private_const)( join );
#ifndef REDBLK_UNSAFE
  if ( FD_UNLIKELY(meta->magic != REDBLK_MAGIC) )
    FD_LOG_ERR(("invalid argument"));
#endif
  return meta->max;
}

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
REDBLK_T * REDBLK_POOL_(allocate)( REDBLK_T * join ) {
  REDBLK_POOL_(private_t) * meta = REDBLK_POOL_(private)( join );
#ifndef REDBLK_UNSAFE
  if ( FD_UNLIKELY(meta->magic != REDBLK_MAGIC) )
    FD_LOG_ERR(("invalid argument"));
#endif
  REDBLK_T * node = &join[meta->free];
  if (node == &join[REDBLK_NIL])
    return NULL;
#ifndef REDBLK_UNSAFE
  if ( FD_UNLIKELY(node->redblack.color != REDBLK_FREE) )
    FD_LOG_ERR(("tree corruption"));
#endif
  node->redblack.color = REDBLK_NEW;
  meta->free = node->redblack.left;
  return node;
}

#ifndef REDBLK_UNSAFE
/*
  Verify that a node is valid for a pool
*/
void REDBLK_POOL_(validate_node)( REDBLK_T * join, REDBLK_T * node ) {
  if ( FD_UNLIKELY(node == NULL) )
    return;
  REDBLK_POOL_(private_t) * meta = REDBLK_POOL_(private)( join );
  ulong index = (ulong)(node - join);
  if ( FD_UNLIKELY(meta->magic != REDBLK_MAGIC || index >= meta->max ||
                   node != join + index || node->redblack.color == REDBLK_FREE) )
    FD_LOG_ERR(("invalid node pointer"));
}
#endif

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
void REDBLK_POOL_(release)( REDBLK_T * join, REDBLK_T * node ) {
  REDBLK_POOL_(private_t) * meta = REDBLK_POOL_(private)( join );
#ifndef REDBLK_UNSAFE
  REDBLK_POOL_(validate_node)(join, node);
#endif
  node->redblack.left = meta->free;
  node->redblack.right = REDBLK_NIL;
  node->redblack.parent = REDBLK_NIL;
  node->redblack.color = REDBLK_FREE;
  meta->free = (uint)(node - join);
}

/*
  E.g. void my_rb_pool_release_tree( my_node_t * join, my_node_t * root );

  Recursively release all nodes in a tree to a pool. The root argument
  is invalid after this method is called.
*/
void REDBLK_POOL_(release_tree)( REDBLK_T * pool, REDBLK_T * node ) {
  if (!node || node == &pool[REDBLK_NIL])
    return;
  
  REDBLK_T * left = &pool[node->redblack.left];
  REDBLK_T * right = &pool[node->redblack.right];
  
  REDBLK_POOL_(private_t) * meta = REDBLK_POOL_(private)( pool );
#ifndef REDBLK_UNSAFE
  REDBLK_POOL_(validate_node)(pool, node);
#endif
  node->redblack.left = meta->free;
  node->redblack.right = REDBLK_NIL;
  node->redblack.parent = REDBLK_NIL;
  node->redblack.color = REDBLK_FREE;
  meta->free = (uint)(node - pool);

  REDBLK_POOL_(release_tree)(pool, left);
  REDBLK_POOL_(release_tree)(pool, right);
}

/*
  E.g. long my_rb_pool_local_to_global( my_node_t * join, my_node_t * root );

  Convert a local root pointer to a global address which can be stored
  in shared memory. This allows a pool to be relocated. Use
  global_to_local to convert back.
*/
long REDBLK_POOL_(local_to_global)( REDBLK_T * join, REDBLK_T * root ) {
  return (root == NULL ? -1 : (root - join));
}

/*
  E.g. my_node_t * my_rb_pool_global_to_local( my_node_t * join, long root );

  Convert a global address to a local root pointer. This allows a pool
  to be relocated.
*/
REDBLK_T * REDBLK_POOL_(global_to_local)( REDBLK_T * join, long root ) {
  return (root == -1 ? NULL : join + root);
}

/*
  E.g. my_node_t * my_rb_minimum(my_node_t * pool, my_node_t * root);

  Return the node in a tree that has the smallest key (leftmost).
*/
REDBLK_T * REDBLK_(minimum)(REDBLK_T * pool, REDBLK_T * node) {
  if (!node || node == &pool[REDBLK_NIL])
    return NULL;
#ifndef REDBLK_UNSAFE
  REDBLK_POOL_(validate_node)(pool, node);
#endif
  while (node->redblack.left != REDBLK_NIL) {
    node = &pool[node->redblack.left];
  }
  return node;
}

/*
  E.g. my_node_t * my_rb_maximum(my_node_t * pool, my_node_t * node);

  Return the node in a tree that has the largest key (rightmost).
*/
REDBLK_T * REDBLK_(maximum)(REDBLK_T * pool, REDBLK_T * node) {
  if (!node || node == &pool[REDBLK_NIL])
    return NULL;
#ifndef REDBLK_UNSAFE
  REDBLK_POOL_(validate_node)(pool, node);
#endif
  while (node->redblack.right != REDBLK_NIL) {
    node = &pool[node->redblack.right];
  }
  return node;
}

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
REDBLK_T * REDBLK_(successor)(REDBLK_T * pool, REDBLK_T * x) {
#ifndef REDBLK_UNSAFE
  REDBLK_POOL_(validate_node)(pool, x);
#endif

  // if the right subtree is not null,
  // the successor is the leftmost node in the
  // right subtree
  if (x->redblack.right != REDBLK_NIL) {
    return REDBLK_(minimum)(pool, &pool[x->redblack.right]);
  }

  // else it is the lowest ancestor of x whose
  // left child is also an ancestor of x.
  for (;;) {
    if (x->redblack.parent == REDBLK_NIL)
      return NULL;
    REDBLK_T * y = &pool[x->redblack.parent];
    if (x == &pool[y->redblack.left])
      return y;
    x = y;
  }
}

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
REDBLK_T * REDBLK_(predecessor)(REDBLK_T * pool, REDBLK_T * x) {
#ifndef REDBLK_UNSAFE
  REDBLK_POOL_(validate_node)(pool, x);
#endif

  // if the left subtree is not null,
  // the predecessor is the rightmost node in the 
  // left subtree
  if (x->redblack.left != REDBLK_NIL) {
    return REDBLK_(maximum)(pool, &pool[x->redblack.left]);
  }

  // else it is the lowest ancestor of x whose
  // right child is also an ancestor of x.
  for (;;) {
    if (x->redblack.parent == REDBLK_NIL)
      return NULL;
    REDBLK_T * y = &pool[x->redblack.parent];
    if (x == &pool[y->redblack.right])
      return y;
    x = y;
  }
}

/*
  Perform a left rotation around a node
*/
static void REDBLK_(rotateLeft)(REDBLK_T * pool, REDBLK_T ** root, REDBLK_T * x) {
  REDBLK_T * y = &pool[x->redblack.right];

  /* establish x->redblack.right link */
  x->redblack.right = y->redblack.left;
  if (y->redblack.left != REDBLK_NIL)
    pool[y->redblack.left].redblack.parent = (uint)(x - pool);

  /* establish y->redblack.parent link */
  if (y != &pool[REDBLK_NIL])
    y->redblack.parent = x->redblack.parent;
  if (x->redblack.parent) {
    REDBLK_T * p = &pool[x->redblack.parent];
    if (x == &pool[p->redblack.left])
      p->redblack.left = (uint)(y - pool);
    else
      p->redblack.right = (uint)(y - pool);
  } else {
    *root = y;
  }

  /* link x and y */
  y->redblack.left = (uint)(x - pool);
  if (x != &pool[REDBLK_NIL])
    x->redblack.parent = (uint)(y - pool);
}

/*
  Perform a right rotation around a node
*/
static void REDBLK_(rotateRight)(REDBLK_T * pool, REDBLK_T ** root, REDBLK_T * x) {
  REDBLK_T * y = &pool[x->redblack.left];

  /* establish x->redblack.left link */
  x->redblack.left = y->redblack.right;
  if (y->redblack.right != REDBLK_NIL)
    pool[y->redblack.right].redblack.parent = (uint)(x - pool);

  /* establish y->redblack.parent link */
  if (y != &pool[REDBLK_NIL])
    y->redblack.parent = x->redblack.parent;
  if (x->redblack.parent) {
    REDBLK_T * p = &pool[x->redblack.parent];
    if (x == &pool[p->redblack.right])
      p->redblack.right = (uint)(y - pool);
    else
      p->redblack.left = (uint)(y - pool);
  } else {
    *root = y;
  }

  /* link x and y */
  y->redblack.right = (uint)(x - pool);
  if (x != &pool[REDBLK_NIL])
    x->redblack.parent = (uint)(y - pool);
}

/*
  Restore tree invariants after an insert.
*/
static void REDBLK_(insertFixup)(REDBLK_T * pool, REDBLK_T ** root, REDBLK_T * x) {
  /* check Red-Black properties */
  REDBLK_T * p;
  while (x != *root && (p = &pool[x->redblack.parent])->redblack.color == REDBLK_RED) {
    /* we have a violation */
    REDBLK_T * gp = &pool[p->redblack.parent];
    if (x->redblack.parent == gp->redblack.left) {
      REDBLK_T * y = &pool[gp->redblack.right];
      if (y->redblack.color == REDBLK_RED) {

        /* uncle is REDBLK_RED */
        p->redblack.color = REDBLK_BLACK;
        y->redblack.color = REDBLK_BLACK;
        gp->redblack.color = REDBLK_RED;
        x = gp;
      } else {

        /* uncle is REDBLK_BLACK */
        if (x == &pool[p->redblack.right]) {
          /* make x a left child */
          x = p;
          REDBLK_(rotateLeft)(pool, root, x);
          p = &pool[x->redblack.parent];
          gp = &pool[p->redblack.parent];
        }

        /* recolor and rotate */
        p->redblack.color = REDBLK_BLACK;
        gp->redblack.color = REDBLK_RED;
        REDBLK_(rotateRight)(pool, root, gp);
      }
      
    } else {
      /* mirror image of above code */
      REDBLK_T * y = &pool[gp->redblack.left];
      if (y->redblack.color == REDBLK_RED) {

        /* uncle is REDBLK_RED */
        p->redblack.color = REDBLK_BLACK;
        y->redblack.color = REDBLK_BLACK;
        gp->redblack.color = REDBLK_RED;
        x = gp;
      } else {

        /* uncle is REDBLK_BLACK */
        if (x == &pool[p->redblack.left]) {
          x = p;
          REDBLK_(rotateRight)(pool, root, x);
          p = &pool[x->redblack.parent];
          gp = &pool[p->redblack.parent];
        }
        p->redblack.color = REDBLK_BLACK;
        gp->redblack.color = REDBLK_RED;
        REDBLK_(rotateLeft)(pool, root, gp);
      }
    }
  }

  (*root)->redblack.color = REDBLK_BLACK;
}

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
REDBLK_T * REDBLK_(insert)(REDBLK_T * pool, REDBLK_T ** root, REDBLK_T * x) {
#ifndef REDBLK_UNSAFE
  REDBLK_POOL_(validate_node)(pool, *root);
  REDBLK_POOL_(validate_node)(pool, x);
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
    if (c == 0)
      FD_LOG_ERR(("duplicate key"));
    parent = current;
    current = (c < 0 ? &pool[current->redblack.left] : &pool[current->redblack.right]);
  }

  /* setup new node */
  x->redblack.parent = (uint)(parent - pool);
  x->redblack.left = REDBLK_NIL;
  x->redblack.right = REDBLK_NIL;
  x->redblack.color = REDBLK_RED;

  /* insert node in tree */
  if (parent != &pool[REDBLK_NIL]) {
    long c = REDBLK_(compare)(x, parent);
    if (c < 0)
      parent->redblack.left = (uint)(x - pool);
    else
      parent->redblack.right = (uint)(x - pool);
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
  while (x != *root && x->redblack.color == REDBLK_BLACK) {
    REDBLK_T * p = &pool[x->redblack.parent];
    if (x == &pool[p->redblack.left]) {
      REDBLK_T * w = &pool[p->redblack.right];
      if (w->redblack.color == REDBLK_RED) {
        w->redblack.color = REDBLK_BLACK;
        p->redblack.color = REDBLK_RED;
        REDBLK_(rotateLeft)(pool, root, p);
        p = &pool[x->redblack.parent];
        w = &pool[p->redblack.right];
      }
      if (pool[w->redblack.left].redblack.color == REDBLK_BLACK &&
         pool[w->redblack.right].redblack.color == REDBLK_BLACK) {
        w->redblack.color = REDBLK_RED;
        x = p;
      } else {
        if (pool[w->redblack.right].redblack.color == REDBLK_BLACK) {
          pool[w->redblack.left].redblack.color = REDBLK_BLACK;
          w->redblack.color = REDBLK_RED;
          REDBLK_(rotateRight)(pool, root, w);
          p = &pool[x->redblack.parent];
          w = &pool[p->redblack.right];
        }
        w->redblack.color = p->redblack.color;
        p->redblack.color = REDBLK_BLACK;
        pool[w->redblack.right].redblack.color = REDBLK_BLACK;
        REDBLK_(rotateLeft)(pool, root, p);
        x = *root;
      }
      
    } else {
      REDBLK_T * w = &pool[p->redblack.left];
      if (w->redblack.color == REDBLK_RED) {
        w->redblack.color = REDBLK_BLACK;
        p->redblack.color = REDBLK_RED;
        REDBLK_(rotateRight)(pool, root, p);
        p = &pool[x->redblack.parent];
        w = &pool[p->redblack.left];
      }
      if (pool[w->redblack.right].redblack.color == REDBLK_BLACK &&
          pool[w->redblack.left].redblack.color == REDBLK_BLACK) {
        w->redblack.color = REDBLK_RED;
        x = p;
      } else {
        if (pool[w->redblack.left].redblack.color == REDBLK_BLACK) {
          pool[w->redblack.right].redblack.color = REDBLK_BLACK;
          w->redblack.color = REDBLK_RED;
          REDBLK_(rotateLeft)(pool, root, w);
          p = &pool[x->redblack.parent];
          w = &pool[p->redblack.left];
        }
        w->redblack.color = p->redblack.color;
        p->redblack.color = REDBLK_BLACK;
        pool[w->redblack.left].redblack.color = REDBLK_BLACK;
        REDBLK_(rotateRight)(pool, root, p);
        x = *root;
      }
    }
  }
  
  x->redblack.color = REDBLK_BLACK;
}

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
REDBLK_T * REDBLK_(delete)(REDBLK_T * pool, REDBLK_T ** root, REDBLK_T * z) {
#ifndef REDBLK_UNSAFE
  REDBLK_POOL_(validate_node)(pool, *root);
  REDBLK_POOL_(validate_node)(pool, z);
#endif

  REDBLK_T * x;
  REDBLK_T * y;

  if (!z || z == &pool[REDBLK_NIL])
    return NULL;

  if (z->redblack.left == REDBLK_NIL || z->redblack.right == REDBLK_NIL) {
    /* y has a REDBLK_NIL node as a child */
    y = z;
  } else {
    /* find tree successor with a REDBLK_NIL node as a child */
    y = &pool[z->redblack.right];
    while (y->redblack.left != REDBLK_NIL)
      y = &pool[y->redblack.left];
  }

  /* x is y's only child */
  if (y->redblack.left != REDBLK_NIL)
    x = &pool[y->redblack.left];
  else
    x = &pool[y->redblack.right];

  /* remove y from the parent chain */
  x->redblack.parent = y->redblack.parent;
  if (y->redblack.parent)
    if (y == &pool[pool[y->redblack.parent].redblack.left])
      pool[y->redblack.parent].redblack.left = (uint)(x - pool);
    else
      pool[y->redblack.parent].redblack.right = (uint)(x - pool);
  else
    *root = x;

  if (y->redblack.color == REDBLK_BLACK)
    REDBLK_(deleteFixup)(pool, root, x);

  if (y != z) {
    /* we got rid of y instead of z. Oops! Replace z with y in the
     * tree so we don't lose y's key/value. */
    y->redblack = z->redblack;
    if (z == *root)
      *root = y;
    else if (&pool[pool[y->redblack.parent].redblack.left] == z)
      pool[y->redblack.parent].redblack.left = (uint)(y - pool);
    else
      pool[y->redblack.parent].redblack.right = (uint)(y - pool);
    pool[y->redblack.left].redblack.parent = (uint)(y - pool);
    pool[y->redblack.right].redblack.parent = (uint)(y - pool);
  }

  if (*root == &pool[REDBLK_NIL])
    *root = NULL;
  z->redblack.color = REDBLK_NEW;
  return z;
}

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
REDBLK_T * REDBLK_(find)(REDBLK_T * pool, REDBLK_T * root, REDBLK_T * key) {
#ifndef REDBLK_UNSAFE
  REDBLK_POOL_(validate_node)(pool, root);
#endif

  REDBLK_T * current = root;
  if (current == NULL)
    return NULL;
  while (current != &pool[REDBLK_NIL]) {
    long c = REDBLK_(compare)(key, current);
    if (c == 0)
      return current;
    current = (c < 0 ? &pool[current->redblack.left] : &pool[current->redblack.right]);
  }
  return NULL;
}

/*
  Recursive implementation of the verify function
*/
void REDBLK_(verify_private)(REDBLK_T * pool, REDBLK_T * node, REDBLK_T * parent, ulong curblkcnt, ulong correctblkcnt) {
  if (!node || node == &pool[REDBLK_NIL]) {
    if (curblkcnt != correctblkcnt)
      FD_LOG_ERR(("incorrect black count"));
    return;
  }

#ifndef REDBLK_UNSAFE
  REDBLK_POOL_(validate_node)(pool, node);
#endif
  
  if (&pool[node->redblack.parent] != parent)
    FD_LOG_ERR(("incorrect parent"));

  if (node->redblack.color == REDBLK_BLACK)
    ++curblkcnt;
  else if (node->redblack.color == REDBLK_RED) {
    if (parent->redblack.color == REDBLK_RED)
      FD_LOG_ERR(("child of red must be black"));
  } else
    FD_LOG_ERR(("invalid color"));
  
  if (node->redblack.left != REDBLK_NIL) {
    if (REDBLK_(compare)(&pool[node->redblack.left], node) > 0)
      FD_LOG_ERR(("misordered node"));
  }
  if (node->redblack.right != REDBLK_NIL) {
    if (REDBLK_(compare)(node, &pool[node->redblack.right]) > 0)
      FD_LOG_ERR(("misordered node"));
  }

  REDBLK_(verify_private)(pool, &pool[node->redblack.left], node, curblkcnt, correctblkcnt);
  REDBLK_(verify_private)(pool, &pool[node->redblack.right], node, curblkcnt, correctblkcnt);
}

/*
  E.g. void my_rb_verify(my_node_t * pool, my_node_t * root);

  Verify the integrity of the tree data structure. Useful for
  debugging memory corruption. FD_LOG_ERR is called if an error is
  detected.
*/
void REDBLK_(verify)(REDBLK_T * pool, REDBLK_T * root) {
  if (pool[REDBLK_NIL].redblack.left != REDBLK_NIL ||
      pool[REDBLK_NIL].redblack.right != REDBLK_NIL ||
      pool[REDBLK_NIL].redblack.color != REDBLK_BLACK)
    FD_LOG_ERR(("corrupted NIL"));

  if (!root || root == &pool[REDBLK_NIL])
    return; // Trivially correct
  if (root->redblack.color != REDBLK_BLACK)
    FD_LOG_ERR(("root must be black"));

  // Compute the correct number of black nodes on a path
  ulong blkcnt = 0;
  REDBLK_T * node = root;
  while (node != &pool[REDBLK_NIL]) {
    if (node->redblack.color == REDBLK_BLACK)
      ++blkcnt;
    node = &pool[node->redblack.left];
  }
  // Recursive check
  REDBLK_(verify_private)(pool, root, &pool[REDBLK_NIL], 0, blkcnt);
}

#undef REDBLK_
#undef REDBLK_POOL_
#undef REDBLK_T
#undef REDBLK_NAME
#undef REDBLK_NIL
