#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include <assert.h>
#include "../fd_util.h"

#define MIN INT_MIN
#define MAX INT_MAX
#define CHARS "ABCDEFGHIJ"

int mu_tests= 0, mu_fails = 0;

int permutation_error = 0;

struct rbnode_struct {
    int key;
    union {
        struct {
            uint parent;
            uint left;
            uint right;
            int color;
        } rb;
        ulong nf;
    } u;
};
typedef struct rbnode_struct rbnode;
#define REDBLK_T rbnode
#define REDBLK_NAME rb
#define REDBLK_PARENT u.rb.parent
#define REDBLK_LEFT u.rb.left
#define REDBLK_RIGHT u.rb.right
#define REDBLK_COLOR u.rb.color
#define REDBLK_NEXTFREE u.nf
#include "fd_redblack.c"

typedef rbnode rbtree;

static rbnode* pool = NULL;

long rb_compare(rbnode* left, rbnode* right) {
  return (long)(left->key - right->key);
}

static rbtree *tree_create( void );
static void tree_destroy(rbtree *rbt);
static rbnode *tree_find(rbtree *rbt, int key);
static int tree_check(rbtree *rbt);
static rbnode *tree_insert(rbtree **rbt, int key);
static int tree_delete(rbtree **rbt, int key);

static rbtree *make_black_tree( void );

static void swap(char *x, char *y);
static void permute(char *a, size_t start, size_t end, void func(char *));
static void permutation_insert(char *a);
static void permutation_delete(char *a);

static int unit_test_create( void );
static int unit_test_find( void );
static int unit_test_successor( void );
static int unit_test_atomic_insertion( void );
static int unit_test_chain_insertion( void );
static int unit_test_atomic_deletion( void );
static int unit_test_chain_deletion( void );
static int unit_test_permutation_insertion( void );
static int unit_test_permutation_deletion( void );
static int unit_test_random_insertion_deletion( void );
static int unit_test_min( void );

#define mu_test(_s, _c)                               \
  do {                                                \
    FD_LOG_WARNING(("#%03d %s ", ++mu_tests, _s));    \
    if (_c) {                                         \
      FD_LOG_INFO(("PASSED"));                        \
      if (correct_free != rb_free(pool))              \
        FD_LOG_WARNING(("INCORRECT FREES"));          \
    } else {                                          \
      FD_LOG_WARNING(("FAILED"));                     \
      mu_fails++;                                     \
    }                                                 \
    correct_free = rb_free(pool);                     \
  } while (0)

void all_tests( void )
{
  ulong correct_free = rb_free(pool);

  mu_test("unit_test_create", unit_test_create());

  mu_test("unit_test_find", unit_test_find());

  mu_test("unit_test_successor", unit_test_successor());

  mu_test("unit_test_atomic_insertion", unit_test_atomic_insertion());
  mu_test("unit_test_chain_insertion", unit_test_chain_insertion());

  mu_test("unit_test_atomic_deletion", unit_test_atomic_deletion());
  mu_test("unit_test_chain_deletion", unit_test_chain_deletion());

  mu_test("unit_test_permutation_insertion", unit_test_permutation_insertion());
  mu_test("unit_test_permutation_deletion", unit_test_permutation_deletion());

  mu_test("unit_test_random_insertion_deletion", unit_test_random_insertion_deletion());

  mu_test("unit_test_min", unit_test_min());
}

int main(int argc, char **argv)
{
  fd_boot( &argc, &argv );

#define SCRATCH_ALIGN     (128UL)
#define SCRATCH_FOOTPRINT (1UL<<17)
  uchar scratch[ SCRATCH_FOOTPRINT ] __attribute__((aligned(SCRATCH_ALIGN)));

  ulong max = rb_max_for_footprint(SCRATCH_FOOTPRINT);
  if (rb_footprint(max) > SCRATCH_FOOTPRINT)
    FD_LOG_ERR(("footprint confusion"));
  pool = rb_join( rb_new( scratch, max ) );
  if (rb_max(pool) != max)
    FD_LOG_ERR(("footprint confusion"));

  all_tests();

  (void) rb_delete( rb_leave( pool ));

  if (mu_fails) {
    FD_LOG_ERR(( "*** %d/%d TESTS FAILED ***", mu_fails, mu_tests ));
  } else {
    FD_LOG_NOTICE(( "pass" ));
    return 0;
  }

  fd_halt();
}

rbtree *tree_create( void )
{
  return NULL;
}

void tree_destroy(rbtree *rbt) {
  rb_release_tree(pool, rbt);
}

rbnode *tree_find(rbtree *rbt, int key)
{
  rbnode query;
  query.key = key;
  return rb_find(pool, rbt, &query);
}

int tree_check(rbtree *rbt)
{
  assert(!rb_verify(pool, rbt));
  return 1;
}

rbnode *tree_insert(rbtree **rbt, int key)
{
  rbnode *node;
  rbnode *data;

  if (key < MIN || key > MAX) {
    FD_LOG_WARNING(("tree_insert: invalid key %d", key));
    return NULL;
  }

  data = rb_acquire(pool);
  data->key = key;
  if ((node = rb_insert(pool, rbt, data)) == NULL) {
    FD_LOG_WARNING(("tree_insert: insert %d failed", key));
    free(data);
    return NULL;
  }

  return node;
}

int tree_delete(rbtree **rbt, int key)
{
  rbnode *node;

  rbnode key2;
  key2.key = key;
  if ((node = rb_find(pool, *rbt, &key2)) == NULL) {
    FD_LOG_WARNING(("tree_delete: %d not found", key));
    return 0;
  }

  rb_remove(pool, rbt, node);
  rb_release(pool, node);

  if (rb_find(pool, *rbt, &key2) != NULL) {
    FD_LOG_WARNING(("tree_delete: delete %d failed", key));
    return 0;
  }

  return 1;
}

void swap(char *x, char *y)
{
  char temp;
  temp = *x;
  *x = *y;
  *y = temp;
}

void permute(char *a, size_t start, size_t end, void func(char *))
{
  if (start == end) {
    func(a);
    return;
  }

  size_t i;
  for (i = start; i <= end; i++) {
    swap(a + start, a + i);
    permute(a, start + 1, end, func);
    swap(a + start, a + i);
  }
}

void permutation_insert(char *a)
{
  rbtree *rbt;
  rbnode *node;
  size_t i;

  rbt = tree_create();

  for (i = 0; i < strlen(a); i++) {
    if ((node = tree_insert(&rbt, a[i])) == NULL || tree_find(rbt, a[i]) != node || tree_check(rbt) != 1) {
      FD_LOG_WARNING(("insert %c failed", a[i]));
      permutation_error++;
      return;
    }
  }

  tree_destroy(rbt);
}

void permutation_delete(char *a)
{
  rbtree *rbt;
  rbnode *node;
  size_t i;

  rbt = tree_create();

  char b[] = CHARS;

  for (i = 0; i < strlen(b); i++) {
    if ((node = tree_insert(&rbt, b[i])) == NULL || tree_find(rbt, b[i]) != node || tree_check(rbt) != 1) {
      FD_LOG_WARNING(("insert %c failed", b[i]));
      permutation_error++;
      return;
    }
  }

  for (i = 0; i < strlen(a); i++) {
    if (tree_delete(&rbt, a[i]) != 1 || tree_check(rbt) != 1) {
      FD_LOG_WARNING(("delete %c failed", a[i]));
      permutation_error++;
      return;
    }
  }

  tree_destroy(rbt);
}


rbtree *make_black_tree( void )
{
  rbtree *rbt;
  rbnode *node;
  char a[] = "ABCDEFGHIJ";
  char b[] = "ACJ";
  char c[] = "BDEFGHI";
  size_t i, n;

  rbt = tree_create();

  n = strlen(a);
  for (i = 0; i < n; i++) {
    if (tree_insert(&rbt, a[i]) == NULL || tree_check(rbt) != 1)
      goto err;
  }

  n = strlen(b);
  for (i = 0; i < n; i++) {
    if (tree_delete(&rbt, b[i]) != 1 || tree_check(rbt) != 1)
      goto err;
  }

  n = strlen(c);
  for (i = 0; i < n; i++) {
    if ((node = tree_find(rbt, c[i])) == NULL || node->u.rb.color != 1 /*REDBLK_BLACK*/)
      goto err;
  }

  rbnode *nb, *nd, *ne, *nf, *ng, *nh, *ni;
  nb = tree_find(rbt, 'B');
  nd = tree_find(rbt, 'D');
  ne = tree_find(rbt, 'E');
  nf = tree_find(rbt, 'F');
  ng = tree_find(rbt, 'G');
  nh = tree_find(rbt, 'H');
  ni = tree_find(rbt, 'I');
  if (nf->u.rb.left + pool != nd || nf->u.rb.right + pool != nh || \
      nd->u.rb.left + pool != nb || nd->u.rb.right + pool != ne || \
      nh->u.rb.left + pool != ng || nh->u.rb.right + pool != ni) {
    goto err;
  }

  return rbt;

  err:
  tree_destroy(rbt);
  return NULL;
}

int unit_test_create( void )
{
  rbtree *rbt;

  rbt = tree_create();

  tree_destroy(rbt);
  return 1;
}

int unit_test_find( void )
{
  rbtree *rbt;
  rbnode *r, *e, *d, *s, *o, *x, *c, *u, *b, *t;

  rbt = tree_create();

  if ((r = tree_insert(&rbt, 'R')) == NULL || \
      (e = tree_insert(&rbt, 'E')) == NULL || \
      (d = tree_insert(&rbt, 'D')) == NULL || \
      (s = tree_insert(&rbt, 'S')) == NULL || \
      (o = tree_insert(&rbt, 'O')) == NULL || \
      (x = tree_insert(&rbt, 'X')) == NULL || \
      (c = tree_insert(&rbt, 'C')) == NULL || \
      (u = tree_insert(&rbt, 'U')) == NULL || \
      (b = tree_insert(&rbt, 'B')) == NULL || \
      (t = tree_insert(&rbt, 'T')) == NULL || \
      tree_check(rbt) != 1) {
    FD_LOG_WARNING(("init failed"));
    goto err;
  }

  if (tree_find(rbt, r->key) != r || \
      tree_find(rbt, e->key) != e || \
      tree_find(rbt, d->key) != d || \
      tree_find(rbt, s->key) != s || \
      tree_find(rbt, o->key) != o || \
      tree_find(rbt, x->key) != x || \
      tree_find(rbt, c->key) != c || \
      tree_find(rbt, u->key) != u || \
      tree_find(rbt, b->key) != b || \
      tree_find(rbt, t->key) != t) {
    FD_LOG_WARNING(("find failed"));
    goto err;
  }

  tree_destroy(rbt);
  return 1;

  err:
  tree_destroy(rbt);
  return 0;
}

int unit_test_successor( void )
{
  rbtree *rbt;
  rbnode *r, *e, *d, *s, *o, *x, *c, *u, *b, *t;

  rbt = tree_create();

  if ((r = tree_insert(&rbt, 'R')) == NULL || \
      (e = tree_insert(&rbt, 'E')) == NULL || \
      (d = tree_insert(&rbt, 'D')) == NULL || \
      (s = tree_insert(&rbt, 'S')) == NULL || \
      (o = tree_insert(&rbt, 'O')) == NULL || \
      (x = tree_insert(&rbt, 'X')) == NULL || \
      (c = tree_insert(&rbt, 'C')) == NULL || \
      (u = tree_insert(&rbt, 'U')) == NULL || \
      (b = tree_insert(&rbt, 'B')) == NULL || \
      (t = tree_insert(&rbt, 'T')) == NULL || \
      tree_delete(&rbt, 'O') != 1 || \
      tree_check(rbt) != 1) {
    FD_LOG_WARNING(("init failed"));
    goto err;
  }

  if (rb_successor(pool, b) != c || \
      rb_successor(pool, c) != d || \
      rb_successor(pool, d) != e || \
      rb_successor(pool, e) != r || \
      rb_successor(pool, r) != s || \
      rb_successor(pool, s) != t || \
      rb_successor(pool, t) != u || \
      rb_successor(pool, u) != x || \
      rb_successor(pool, x) != NULL) {
    FD_LOG_WARNING(("successor failed"));
    goto err;
  }

  tree_destroy(rbt);
  return 1;

  err:
  tree_destroy(rbt);
  return 0;
}

int unit_test_atomic_insertion( void )
{
  rbtree *rbt;
  size_t i, j;

  char cs[][30] = {
    /* empty node becomes 2-children node */
    {'D'}, /* (balanced) */

    /* 2-children node becomes 3-children node */
    {'D', 'B'}, /* d.left (balanced) */
    {'D', 'F'}, /* d.right (balanced) */

    /* 3-children node becomes 4-children node */
    {'D', 'F', 'B'}, /* d.left (balanced) */
    {'D', 'B', 'F'}, /* d.right (balanced) */
    {'D', 'B', 'A'}, /* d.left.left */
    {'D', 'B', 'C'}, /* d.left.right */
    {'D', 'F', 'E'}, /* d.right.left */
    {'D', 'F', 'G'}, /* d.right.right */

    /* 4-children node splits into 2-children node and 3-children node */
    {'D', 'B', 'F', 'A'}, /* d.left.left */
    {'D', 'B', 'F', 'C'}, /* d.left.right */
    {'D', 'B', 'F', 'E'}, /* d.right.left */
    {'D', 'B', 'F', 'G'}, /* d.right.right */
  };

  char *name[] = {
    "empty node becomes 2-children node: insert d",
    "2-children node becomes 3-children nodes: insert b",
    "2-children node becomes 3-children nodes: insert f",
    "3-children node becomes 4-children node: insert b",
    "3-children node becomes 4-children node: insert f",
    "3-children node becomes 4-children node: insert a",
    "3-children node becomes 4-children node: insert c",
    "3-children node becomes 4-children node: insert e",
    "3-children node becomes 4-children node: insert g",
    "4-children node splits: insert a",
    "4-children node splits: insert c",
    "4-children node splits: insert e",
    "4-children node splits: insert g",
  };

  for (i = 0; i < sizeof(cs) / sizeof(cs[0]); i++) {
    rbt = tree_create();

    for (j = 0; j < sizeof(cs[0]) / sizeof(cs[0][0]) && cs[i][j]; j++) {
      if (tree_insert(&rbt, cs[i][j]) == NULL || tree_check(rbt) != 1) {
        FD_LOG_WARNING(("%s - insert %c failed", name[i], cs[i][j]));
        goto err;
      }
    }

    tree_destroy(rbt);
  }

  return 1;

  err:
  tree_destroy(rbt);
  return 0;
}

int unit_test_chain_insertion( void )
{
  rbtree *rbt;
  size_t i, j;

  int a1[] = {1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 27, 29, 39, 41};
  int a2[] = {16, 8, 24, 4, 12, 20, 32, 2, 6, 10, 14, 18, 22, 28, 40};

  for (i = 0; i < sizeof(a1) / sizeof(a1[0]); i++) {
    rbt = tree_create();

    for (j = 0; j < sizeof(a2) / sizeof(a2[0]); j++) {
      if (tree_insert(&rbt, a2[j]) == NULL || tree_check(rbt) != 1) {
        FD_LOG_WARNING(("insert %d failed", a2[j]));
        goto err;
      }
    }

    if (tree_insert(&rbt, a1[i]) == NULL || tree_check(rbt) != 1) {
      FD_LOG_WARNING(("insert %d failed", a1[i]));
      goto err;
    }

    tree_destroy(rbt);
  }

  return 1;

  err:
  tree_destroy(rbt);
  return 0;
}

int unit_test_atomic_deletion( void )
{
  rbtree *rbt;
  size_t i, j;

  char cs[][2][30] = {
    /* 4-children node becomes 3-children node */
    {{'D', 'B', 'F'}, {'B'}}, /* d.left (balanced) */
    {{'D', 'B', 'F'}, {'D'}}, /* d (balanced) */
    {{'D', 'B', 'F'}, {'F'}}, /* d.right (balanced) */

    /* 3-children node becomes 2-children node */
    {{'D', 'B'}, {'B'}}, /* d.left (balanced) */
    {{'D', 'B'}, {'D'}}, /* d (balanced) */
    {{'D', 'F'}, {'D'}}, /* d (balanced) */
    {{'D', 'F'}, {'F'}}, /* d.right (balanced) */

    /* 2-children node becomes empty node */
    {{'D'}, {'D'}}, /* d (balanced) */

    /* 2-children node becomes 3-children node (transfer) */
    {{'D', 'B', 'F', 'E', 'G'}, {'B'}}, /* d->left */
    {{'D', 'B', 'F', 'A', 'C'}, {'F'}}, /* d->right */

    /* 2-children node becomes 2-children node (transfer) */
    {{'D', 'B', 'F', 'A'}, {'F'}}, /* d->right */
    {{'D', 'B', 'F', 'C'}, {'F'}}, /* d->right */
    {{'D', 'B', 'F', 'E'}, {'B'}}, /* d->left */
    {{'D', 'B', 'F', 'G'}, {'B'}}, /* d->left */

    /* 2-children node becomes 3-children node (fuse) */
    {{'D', 'B', 'F', 'A'}, {'A', 'B'}}, /* d->left */
    {{'D', 'B', 'F', 'A'}, {'A', 'F'}} /* d->right */
  };

  char *name[] = {
    "4-children node becomes 3-children node: delete b",
    "4-children node becomes 3-children node: delete d",
    "4-children node becomes 3-children node: delete f",
    "3-children node becomes 2-children node: delete b",
    "3-children node becomes 2-children node: delete d",
    "3-children node becomes 2-children node: delete d",
    "3-children node becomes 2-children node: delete f",
    "2-children node becomes empty node: delete d",
    "2-children node becomes 3-children node (transfer): delete b",
    "2-children node becomes 3-children node (transfer): delete f",
    "2-children node becomes 2-children node (transfer): delete f",
    "2-children node becomes 2-children node (transfer): delete f",
    "2-children node becomes 2-children node (transfer): delete b",
    "2-children node becomes 2-children node (transfer): delete b",
    "2-children node becomes 3-children node (fuse): delete b",
    "2-children node becomes 3-children node (fuse): delete f",
    "2-children node becomes 3-children node (fuse): delete f"
  };

  for (i = 0; i < sizeof(cs) / sizeof(cs[0]); i++) {
    rbt = tree_create();

    for (j = 0; j < sizeof(cs[0][0]) / sizeof(cs[0][0][0]) && cs[i][0][j]; j++) {
      if (tree_insert(&rbt, cs[i][0][j]) == NULL || tree_check(rbt) == 0) {
        FD_LOG_WARNING(("%s - insert %c failed", name[i], cs[i][0][j]));
        goto err;
      }
    }

    for (j = 0; j < sizeof(cs[0][0]) / sizeof(cs[0][0][0]) && cs[i][0][j]; j++) {
      if (tree_delete(&rbt, cs[i][0][j]) == 0 || tree_check(rbt) == 0) {
        FD_LOG_WARNING(("%s - delete %c failed", name[i], cs[i][0][j]));
        goto err;
      }
    }

    tree_destroy(rbt);
  }

  return 1;

  err:
  tree_destroy(rbt);
  return 0;
}

int unit_test_chain_deletion( void )
{
  rbtree *rbt;
  char a[] = "BEGI";
  size_t i, n;

  n = strlen(a);
  for (i = 0; i < n; i++) {
    if ((rbt = make_black_tree()) == NULL) {
      FD_LOG_WARNING(("make black tree failed"));
      goto err;
    }

    if (tree_delete(&rbt, a[i]) != 1 || tree_check(rbt) != 1) {
      FD_LOG_WARNING(("delete %c failed", a[i]));
      goto err;
    }

    tree_destroy(rbt);
  }

  return 1;

  err:
  if (rbt)
    tree_destroy(rbt);
  return 0;
}

int unit_test_permutation_insertion( void )
{
  char a[] = CHARS;

  permutation_error = 0;
  permute(a, 0, strlen(a) - 1, permutation_insert);
  return (permutation_error == 0);
}

int unit_test_permutation_deletion( void )
{
  char a[] = CHARS;

  permutation_error = 0;
  permute(a, 0, strlen(a) - 1, permutation_delete);
  return (permutation_error == 0);
}

int unit_test_random_insertion_deletion( void )
{
  rbtree *rbt;
  int ninsert, ndelete;
  int i, key, max;

  rbt = tree_create();

  ninsert = 0;
  ndelete = 0;
  max = 9999;

  srand((unsigned int) time(NULL));

  for (i = 1; i <= 1999; i++) {
    key = rand() % max;
    if (tree_find(rbt, key) != NULL)
      continue;
    ninsert++;
    if (tree_insert(&rbt, key) == NULL || tree_check(rbt) != 1) {
      FD_LOG_WARNING(("insert %d failed", key));
      goto err;
    }
  }

  for (i = 1; i < max; i++) {
    key = rand() % max;
    if (tree_find(rbt, key) == NULL)
      continue;
    ndelete++;
    if (tree_delete(&rbt, key) != 1 || tree_check(rbt) != 1) {
      FD_LOG_WARNING(("delete %d failed", key));
      goto err;
    }
  }

  FD_LOG_WARNING(("\tstat: ninsert=%d, ndelete=%d", ninsert, ndelete));

  tree_destroy(rbt);
  return 1;

  err:
  tree_destroy(rbt);
  return 0;
}

int unit_test_min( void )
{
  rbtree *rbt;

  rbt = tree_create();

#define RB_MINIMAL(_rbt_) rb_minimum(pool, _rbt_)
  if (RB_MINIMAL(rbt) != NULL || \
      tree_insert(&rbt, 'B') == NULL || RB_MINIMAL(rbt) != tree_find(rbt, 'B') || \
      tree_insert(&rbt, 'A') == NULL || RB_MINIMAL(rbt) != tree_find(rbt, 'A') || \
      tree_insert(&rbt, 'C') == NULL || RB_MINIMAL(rbt) != tree_find(rbt, 'A') || \
      tree_delete(&rbt, 'B') != 1 || RB_MINIMAL(rbt) != tree_find(rbt, 'A') || \
      tree_delete(&rbt, 'A') != 1 || RB_MINIMAL(rbt) != tree_find(rbt, 'C') || \
      tree_delete(&rbt, 'C') != 1 || RB_MINIMAL(rbt) != NULL) {
    FD_LOG_WARNING(("invalid min"));
    goto err;
  }

  tree_destroy(rbt);

  return 1;

  err:
  tree_destroy(rbt);
  return 0;
}
