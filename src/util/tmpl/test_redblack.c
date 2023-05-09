#include "../fd_util.h"
#include <stdlib.h>
#include <assert.h>

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

long my_rb_compare(my_rb_node_t* left, my_rb_node_t* right) {
  return (long)(left->key - right->key);
}

#define SCRATCH_ALIGN     (128UL)
#define SCRATCH_FOOTPRINT (1UL<<16)
uchar scratch[ SCRATCH_FOOTPRINT ] __attribute__((aligned(SCRATCH_ALIGN)));
uchar scratch2[ SCRATCH_FOOTPRINT ] __attribute__((aligned(SCRATCH_ALIGN)));

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong max = my_rb_max_for_footprint(SCRATCH_FOOTPRINT);
  if (my_rb_footprint(max) > SCRATCH_FOOTPRINT)
    FD_LOG_ERR(("footprint confusion"));
  my_rb_node_t * pool = my_rb_join( my_rb_new( scratch, max ) );
  if (my_rb_max(pool) != max)
    FD_LOG_ERR(("footprint confusion"));

  // Try 3 interesting cases
  for (ulong c = 0; c < 3; ++c) {
    my_rb_node_t* root = NULL;
    my_rb_node_t* node;
    for (ulong i = 0; i < max; ++i) {
      node = my_rb_acquire(pool);
      if (node == NULL)
        FD_LOG_ERR(("allocation failure"));
      switch (c) {
      case 0: node->key = i+1; break;
      case 1: node->key = max-i; break;
      case 2: node->key = (i*1543)%max + 1; break;
      }
      node->val = node->key*21UL;
      my_rb_insert(pool, &root, node);

      if (my_rb_find(pool, root, node) != node)
        FD_LOG_ERR(("did not find my own node"));
    }
    if (my_rb_acquire(pool) != NULL)
      FD_LOG_ERR(("did not get NULL as expected"));

    assert(!my_rb_verify(pool, root));

    for (ulong i = 0; i <= max+1; ++i) {
      my_rb_node_t key;
      key.key = i;
      key.val = 0;
      node = my_rb_find(pool, root, &key);
      if (i < 1 || i > max) {
        if (node != NULL)
          FD_LOG_ERR(("search result wrong"));
      } else {
        if (node == NULL || node->key != i || node->val != key.key*21UL)
          FD_LOG_ERR(("search result wrong"));
      }
    }

    my_rb_release_tree(pool, root);
  }
  
  ulong* list = (ulong*)malloc(max * sizeof(ulong));

  for (ulong iter = 0; iter < 1000; ++iter) {
    // Generate a random insertion ordering
    for (ulong i = 0; i < max; ++i)
      list[i] = i+1;
    for (ulong i = 0; i < max; ++i) {
      ulong j = fd_rng_ulong(rng) % max;
      ulong t = list[i]; list[i] = list[j]; list[j] = t;
    }

    my_rb_node_t* root = NULL;
    my_rb_node_t* node;
    for (ulong i = 0; i < max; ++i) {
      node = my_rb_acquire(pool);
      if (node == NULL)
        FD_LOG_ERR(("allocation failure"));
      node->key = list[i];
      node->val = list[i]*17UL;
      my_rb_insert(pool, &root, node);
      if (my_rb_find(pool, root, node) != node)
        FD_LOG_ERR(("search result wrong"));
    }
    if (my_rb_acquire(pool) != NULL)
      FD_LOG_ERR(("did not get NULL as expected"));

    assert(!my_rb_verify(pool, root));
    
    node = my_rb_minimum(pool, root);
    if (node->key != 1 || node->val != node->key*17UL)
      FD_LOG_ERR(("did not get right value"));
    ulong j = 1;
    while ((node = my_rb_successor(pool, node)) != NULL) {
      if (node->key != ++j || node->val != node->key*17UL)
        FD_LOG_ERR(("did not get right value"));
    }
      
    node = my_rb_maximum(pool, root);
    if (node->key != max || node->val != node->key*17UL)
      FD_LOG_ERR(("did not get right value"));
    j = max;
    while ((node = my_rb_predecessor(pool, node)) != NULL) {
      if (node->key != --j || node->val != node->key*17UL)
        FD_LOG_ERR(("did not get right value"));
    }
      
    for (ulong i = 0; i <= max+1; ++i) {
      my_rb_node_t key;
      key.key = i;
      key.val = 0;
      node = my_rb_find(pool, root, &key);
      if (i < 1 || i > max) {
        if (node != NULL)
          FD_LOG_ERR(("search result wrong"));
      } else {
        if (node == NULL || node->val != key.key*17UL)
          FD_LOG_ERR(("search result wrong"));
      }
    }

    // Generate a random deletion ordering
    for (ulong i = 0; i < max; ++i)
      list[i] = i+1;
    for (ulong i = 0; i < max; ++i) {
      ulong j = fd_rng_ulong(rng) % (max-1);
      ulong t = list[i]; list[i] = list[j]; list[j] = t;
    }

    for (ulong i = 0; i < max; ++i) {
      my_rb_node_t key;
      key.key = list[i];
      key.val = 0;
      node = my_rb_find(pool, root, &key);
      if (node == NULL || node->key != key.key || node->val != key.key*17UL)
        FD_LOG_ERR(("search result wrong"));
      node = my_rb_remove(pool, &root, node);
      if (node == NULL || node->key != key.key || node->val != key.key*17UL)
        FD_LOG_ERR(("delete result wrong"));
      my_rb_release(pool, node);
    }
    if (root != NULL)
      FD_LOG_ERR(("final root wrong"));
    
    assert(!my_rb_verify(pool, root));
  }

  free(list);
  
  // Try 3 interesting cases
  for (ulong c = 0; c < 3; ++c) {
    my_rb_node_t* root = NULL;
    my_rb_node_t* node;
    for (ulong i = 0; i < max/2; ++i) {
      node = my_rb_acquire(pool);
      if (node == NULL)
        FD_LOG_ERR(("allocation failure"));
      switch (c) {
      case 0: node->key = i+1; break;
      case 1: node->key = max-i; break;
      case 2: node->key = (i*1543)%max + 1; break;
      }
      node->val = node->key*21UL;
      my_rb_insert(pool, &root, node);
    }

    assert(!my_rb_verify(pool, root));

    // Move the pool somewhere else
    fd_memcpy(scratch2, scratch, SCRATCH_FOOTPRINT);
    my_rb_node_t * pool2 = my_rb_join( scratch2 );
    if (my_rb_max(pool2) != max)
      FD_LOG_ERR(("footprint confusion"));

    my_rb_node_t * root2 = my_rb_node(pool2, my_rb_idx(pool, root));
    assert(!my_rb_verify(pool2, root2));

    for (ulong i = 0; i <= max/2+1; ++i) {
      my_rb_node_t key;
      switch (c) {
      case 0: key.key = i+1; break;
      case 1: key.key = max-i; break;
      case 2: key.key = (i*1543)%max + 1; break;
      }
      key.val = 0;
      node = my_rb_find(pool2, root2, &key);
      if (i >= max/2) {
        if (node != NULL)
          FD_LOG_ERR(("search result wrong"));
      } else {
        if (node == NULL || node->key != key.key || node->val != key.key*21UL)
          FD_LOG_ERR(("search result wrong"));
      }
    }

    my_rb_release_tree(pool2, root2);
    my_rb_leave(pool2);

    my_rb_release_tree(pool, root);
  }
  
  (void) my_rb_delete( my_rb_leave( pool ));
  
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

