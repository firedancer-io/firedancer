#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>
#include <string.h>

#include "../../util/fd_util.h"
#include "fd_txncache.h"
#include "fd_txncache_private.h"

#define FUZZ_MAX_LIVE_SLOTS    (4UL)
#define FUZZ_MAX_TXN_PER_SLOT  (256UL)
#define FUZZ_MAX_ACTIVE_SLOTS  (FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE+FUZZ_MAX_LIVE_SLOTS)
#define FUZZ_MAX_ACTIONS       (2048UL)
#define FUZZ_MAX_MODEL_TXNS    (4UL*FD_TXNCACHE_TXNS_PER_PAGE+2048UL)
#define FUZZ_ROOT_HISTORY_MAX  (FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE+FUZZ_MAX_ACTIONS+4UL)
#define FUZZ_BULK_OP_MAX       (2UL)

#define NULL_FORK ((fd_txncache_fork_id_t){ .val = USHORT_MAX })

/* Fork frozen states (mirror fd_txncache.c). */
#define FORK_NEW    (0)
#define FORK_HASHED (1)
#define FORK_FINAL  (2)

typedef struct fuzz_blockcache_private {
  fd_txncache_blockcache_shmem_t * shmem;
  uint *                           heads;
  ushort *                         pages;
  descends_set_t *                 descends;
} fuzz_blockcache_private_t;

struct fd_txncache_private {
  fd_txncache_shmem_t *            shmem;
  fd_txncache_blockcache_shmem_t * blockcache_shmem_pool;
  fuzz_blockcache_private_t *      blockcache_pool;
  blockhash_map_t *                blockhash_map;
  ushort *                         txnpages_free;
  fd_txncache_txnpage_t *          txnpages;
  ushort *                         scratch_pages;
  uint *                           scratch_heads;
  fd_txncache_txnpage_t *          scratch_txnpage;
};

typedef struct {
  uchar const * cur;
  ulong         rem;
} fuzz_cursor_t;

typedef struct {
  int       alive;
  int       frozen;     /* FORK_NEW / FORK_HASHED / FORK_FINAL */
  ushort    parent;
  uint      generation;
  ulong     txnhash_offset;
  fd_hash_t blockhash;
} model_fork_t;

typedef struct {
  int       used;
  ushort    block_fork;
  ushort    txn_fork;
  uint      generation;
  fd_hash_t txnhash;
} model_txn_t;

/* intentionally simple model that tracks the information we need
   to assert invariants we care about without trying to mirror the
   targets data structure, to find bugs in the target not the harness.
*/
typedef struct {
  fd_txncache_t * tc;
  ulong           max_live_slots;

  model_fork_t fork[ FUZZ_MAX_ACTIVE_SLOTS ];
  model_txn_t  txn [ FUZZ_MAX_MODEL_TXNS   ];
  ulong        txn_cnt;
  ulong        live_cnt;
  ulong        hash_nonce;
  ulong        bulk_cnt;

  ushort current_root;
  ushort roots[ FUZZ_ROOT_HISTORY_MAX ];
  ulong  roots_head;
  ulong  roots_tail;
  ulong  root_cnt;
} model_t;

static uchar * fuzz_shmem;
static uchar * fuzz_ljoin;
static ulong   fuzz_shmem_fp;
static ulong   fuzz_ljoin_fp;
static model_t fuzz_model[ 1 ];

static void
hash_from_counter( fd_hash_t * h,
                   ulong       tag,
                   ulong       cnt,
                   ulong       aux ) {
  h->ul[ 0 ] = tag;
  h->ul[ 1 ] = cnt;
  h->ul[ 2 ] = aux;
  h->ul[ 3 ] = tag ^ ~cnt ^ (aux << 32);
}

static uchar
fuzz_u8( fuzz_cursor_t * cur ) {
  if( FD_UNLIKELY( !cur->rem ) ) return 0U;
  uchar v = cur->cur[ 0 ];
  cur->cur++;
  cur->rem--;
  return v;
}

static ulong
fuzz_bounded( fuzz_cursor_t * cur,
              ulong           bound ) {
  if( FD_UNLIKELY( bound<=1UL ) ) return 0UL;

  ulong x = 0UL;
  for( ulong shift=0UL, max=bound-1UL; max; shift+=8UL, max>>=8UL )
    x |= (ulong)fuzz_u8( cur ) << shift;
  return x % bound;
}

static fd_txncache_t *
setup( ulong max_live_slots, ulong max_txn_per_slot ) {
  fd_txncache_shmem_t * shtc = fd_txncache_shmem_join( fd_txncache_shmem_new( fuzz_shmem, max_live_slots, max_txn_per_slot, 0, 0UL ) );
  FD_TEST( shtc );

  fd_txncache_t * tc = fd_txncache_join( fd_txncache_new( fuzz_ljoin, shtc ) );
  FD_TEST( tc );
  return tc;
}

static int
model_descends( model_t const * m,
                ushort          child,
                ushort          ancestor ) {
  if( FD_UNLIKELY( child>=FUZZ_MAX_ACTIVE_SLOTS || ancestor>=FUZZ_MAX_ACTIVE_SLOTS ) ) return 0;

  for( ushort cur=child; cur!=USHORT_MAX; ) {
    if( FD_UNLIKELY( !m->fork[ cur ].alive ) ) return 0;
    ushort parent = m->fork[ cur ].parent;
    if( parent==ancestor ) return 1;
    cur = parent;
  }
  return 0;
}

static int
model_in_current_tree( model_t const * m,
                       ushort          fork_id ) {
  return fork_id==m->current_root || model_descends( m, fork_id, m->current_root );
}

static ulong
model_current_tree_cnt( model_t const * m ) {
  ulong cnt = 0UL;
  for( ulong i=0UL; i<FUZZ_MAX_ACTIVE_SLOTS; i++ )
    if( m->fork[ i ].alive && model_in_current_tree( m, (ushort)i ) ) cnt++;
  return cnt;
}

/* model_pick_fork selects a uniformly-random alive fork that is in the
   current tree (if want_current_tree) and whose frozen state is in
   [frozen_lo,frozen_hi].  Returns USHORT_MAX if no fork qualifies. */

static ushort
model_pick_fork( model_t const * m,
                 fuzz_cursor_t * cur,
                 int             want_current_tree,
                 int             frozen_lo,
                 int             frozen_hi ) {
  ushort candidate[ FUZZ_MAX_ACTIVE_SLOTS ];
  ulong  candidate_cnt = 0UL;

  for( ulong i=0UL; i<FUZZ_MAX_ACTIVE_SLOTS; i++ ) {
    if( FD_UNLIKELY( !m->fork[ i ].alive ) ) continue;
    if( m->fork[ i ].frozen<frozen_lo || m->fork[ i ].frozen>frozen_hi ) continue;
    if( want_current_tree && !model_in_current_tree( m, (ushort)i ) ) continue;
    candidate[ candidate_cnt++ ] = (ushort)i;
  }

  if( FD_UNLIKELY( !candidate_cnt ) ) return USHORT_MAX;
  return candidate[ fuzz_bounded( cur, candidate_cnt ) ];
}

/* model_pick_strict_ancestor returns a random strict ancestor of
   fork_id that carries a usable blockhash.  For a query context
   (want_final) only FINAL ancestors qualify; for an insert context any
   ancestor with a blockhash (HASHED or FINAL) qualifies. */

static ushort
model_pick_strict_ancestor( model_t const * m,
                            fuzz_cursor_t * cur,
                            ushort          fork_id,
                            int             want_final ) {
  ushort candidate[ FUZZ_MAX_ACTIVE_SLOTS ];
  ulong  candidate_cnt = 0UL;

  for( ushort cur_id=m->fork[ fork_id ].parent; cur_id!=USHORT_MAX; cur_id=m->fork[ cur_id ].parent ) {
    if( FD_UNLIKELY( !m->fork[ cur_id ].alive ) ) break;
    int ok = want_final ? (m->fork[ cur_id ].frozen==FORK_FINAL) : (m->fork[ cur_id ].frozen>=FORK_HASHED);
    if( ok ) candidate[ candidate_cnt++ ] = cur_id;
  }

  if( FD_UNLIKELY( !candidate_cnt ) ) return USHORT_MAX;
  return candidate[ fuzz_bounded( cur, candidate_cnt ) ];
}

/* model_hash_on_related_fork returns 1 if any already-hashed live fork
   on fork_id's ancestry line holds blockhash.  Production blockhashes
   are unique along a chain. The fuzzer only creates duplicate
   blockhashes across unrelated branches. */

static int
model_hash_on_related_fork( model_t const *   m,
                            ushort            fork_id,
                            fd_hash_t const * blockhash ) {
  for( ulong i=0UL; i<FUZZ_MAX_ACTIVE_SLOTS; i++ ) {
    if( FD_UNLIKELY( !m->fork[ i ].alive || m->fork[ i ].frozen<FORK_HASHED ) ) continue;
    if( FD_UNLIKELY( i==fork_id ) ) continue;
    if( FD_UNLIKELY( !model_descends( m, fork_id, (ushort)i ) &&
                     !model_descends( m, (ushort)i, fork_id ) ) ) continue;
    if( fd_hash_eq( &m->fork[ i ].blockhash, blockhash ) ) return 1;
  }
  return 0;
}

/* model_make_fresh_hash produces a blockhash that does not collide with
   any blockhash already present on fork_id's ancestry line, so that
   blockhash_on_fork resolves unambiguously along that chain. */

static void
model_make_fresh_hash( model_t *   m,
                       ushort      fork_id,
                       fd_hash_t * blockhash ) {
  do {
    hash_from_counter( blockhash, 0xB10C000000000000UL, ++m->hash_nonce, fork_id );
  } while( model_hash_on_related_fork( m, fork_id, blockhash ) );
}

/* model_make_finalize_hash usually mints a fresh unique blockhash but,
   one time in four, reuses a blockhash from an unrelated fork to stress
   duplicate-blockhash handling (multiple entries in one map bucket,
   disambiguated by the descends set).  The reused hash is never one on
   fork_id's ancestry line. */

static void
model_make_finalize_hash( model_t *       m,
                          fuzz_cursor_t * cur,
                          ushort          fork_id,
                          fd_hash_t *     blockhash ) {
  int duplicate = !(fuzz_u8( cur ) & 3U);
  if( duplicate ) {
    ushort candidate[ FUZZ_MAX_ACTIVE_SLOTS ];
    ulong  candidate_cnt = 0UL;
    for( ulong i=0UL; i<FUZZ_MAX_ACTIVE_SLOTS; i++ ) {
      if( FD_UNLIKELY( !m->fork[ i ].alive ) ) continue;
      if( FD_UNLIKELY( m->fork[ i ].frozen<FORK_HASHED ) ) continue;
      if( FD_UNLIKELY( i==fork_id ) ) continue;
      if( FD_UNLIKELY( model_descends( m, fork_id, (ushort)i ) ||
                       model_descends( m, (ushort)i, fork_id ) ) ) continue;
      candidate[ candidate_cnt++ ] = (ushort)i;
    }
    if( candidate_cnt ) {
      ushort src = candidate[ fuzz_bounded( cur, candidate_cnt ) ];
      if( !model_hash_on_related_fork( m, fork_id, &m->fork[ src ].blockhash ) ) {
        *blockhash = m->fork[ src ].blockhash;
        return;
      }
    }
  }

  model_make_fresh_hash( m, fork_id, blockhash );
}

static void
model_add_fork( model_t *             m,
                fd_txncache_fork_id_t fork_id,
                ushort                parent,
                uint                  generation ) {
  FD_TEST( fork_id.val<FUZZ_MAX_ACTIVE_SLOTS );
  model_fork_t * fork = &m->fork[ fork_id.val ];
  memset( fork, 0, sizeof(*fork) );
  fork->alive      = 1;
  fork->frozen     = FORK_NEW;
  fork->parent     = parent;
  fork->generation = generation;
  m->live_cnt++;
}

static void
model_remove_only( model_t * m,
                   ushort    fork_id ) {
  if( FD_UNLIKELY( fork_id>=FUZZ_MAX_ACTIVE_SLOTS || !m->fork[ fork_id ].alive ) ) return;
  m->fork[ fork_id ].alive = 0;
  m->live_cnt--;
}

static void
model_remove_subtree( model_t * m,
                      ushort    fork_id ) {
  for( ulong i=0UL; i<FUZZ_MAX_ACTIVE_SLOTS; i++ ) {
    if( m->fork[ i ].alive && m->fork[ i ].parent==fork_id )
      model_remove_subtree( m, (ushort)i );
  }
  model_remove_only( m, fork_id );
}

static void
model_init( model_t *       m,
            fd_txncache_t * tc,
            ulong           max_live_slots ) {
  memset( m, 0, sizeof(model_t) );
  m->tc             = tc;
  m->max_live_slots = max_live_slots;

  /* add a root fork as finalized to start with */
  fd_txncache_fork_id_t root = fd_txncache_attach_child( tc, NULL_FORK );
  model_add_fork( m, root, USHORT_MAX, tc->blockcache_pool[ root.val ].shmem->generation );

  fd_hash_t blockhash[ 1 ];
  hash_from_counter( blockhash, 0xB10C000000000000UL, 0UL, 0UL );
  fd_txncache_finalize_fork( tc, root, 0UL, blockhash->uc );

  m->fork[ root.val ].frozen          = FORK_FINAL;
  m->fork[ root.val ].blockhash       = *blockhash;
  m->fork[ root.val ].txnhash_offset  = 0UL;
  m->current_root                     = root.val;
  m->roots[ m->roots_tail++ ]         = root.val;
}

static int
model_query( model_t const *   m,
             ushort            fork_id,
             ushort            block_fork,
             fd_hash_t const * txnhash ) {
  model_fork_t const * block = &m->fork[ block_fork ];
  ulong off = block->txnhash_offset;

  for( ulong i=0UL; i<m->txn_cnt; i++ ) {
    model_txn_t const * txn = &m->txn[ i ];
    if( FD_UNLIKELY( !txn->used ) ) continue;
    if( txn->block_fork!=block_fork ) continue;
    if( FD_UNLIKELY( txn->txn_fork>=FUZZ_MAX_ACTIVE_SLOTS ) ) continue;

    model_fork_t const * txn_fork = &m->fork[ txn->txn_fork ];
    if( FD_UNLIKELY( !txn_fork->alive ) ) continue;
    if( FD_UNLIKELY( txn_fork->generation!=txn->generation ) ) continue;
    if( !(txn->txn_fork==fork_id || model_descends( m, fork_id, txn->txn_fork )) ) continue;

    if( !memcmp( txnhash->uc+off, txn->txnhash.uc+off, 20UL ) ) return 1;
  }

  return 0;
}

static void
model_record_txn( model_t *       m,
                  ushort          block_fork,
                  ushort          txn_fork,
                  fd_hash_t const * txnhash ) {
  FD_TEST( m->txn_cnt<FUZZ_MAX_MODEL_TXNS );

  model_txn_t * txn = &m->txn[ m->txn_cnt++ ];
  txn->used       = 1;
  txn->block_fork = block_fork;
  txn->txn_fork   = txn_fork;
  txn->generation = m->fork[ txn_fork ].generation;
  txn->txnhash    = *txnhash;
}

static ulong
blockcache_txn_cnt( model_t const * m,
                    ushort          block_fork ) {
  fd_txncache_t * tc = m->tc;
  fuzz_blockcache_private_t const * bc = &tc->blockcache_pool[ block_fork ];

  ulong cnt = 0UL;
  for( ulong i=0UL; i<bc->shmem->pages_cnt; i++ ) {
    ushort page = bc->pages[ i ];
    FD_TEST( page<tc->shmem->max_txnpages );
    cnt += FD_TXNCACHE_TXNS_PER_PAGE - tc->txnpages[ page ].free;
  }
  return cnt;
}

static int
blockcache_needs_purge_for_insert( model_t const * m,
                                   ushort          block_fork ) {
  fd_txncache_t * tc = m->tc;
  fuzz_blockcache_private_t const * bc = &tc->blockcache_pool[ block_fork ];

  if( FD_UNLIKELY( !bc->shmem->pages_cnt ) ) return 0;
  if( FD_UNLIKELY( bc->shmem->pages_cnt!=tc->shmem->txnpages_per_blockhash_max ) ) return 0;

  ushort tail_page = bc->pages[ bc->shmem->pages_cnt-1UL ];
  FD_TEST( tail_page<tc->shmem->max_txnpages );
  return !tc->txnpages[ tail_page ].free;
}

static int
blockcache_has_stale_txn( model_t const * m,
                          ushort          block_fork ) {
  fd_txncache_t * tc = m->tc;
  fuzz_blockcache_private_t const * bc = &tc->blockcache_pool[ block_fork ];

  for( ulong i=0UL; i<bc->shmem->pages_cnt; i++ ) {
    ushort page = bc->pages[ i ];
    FD_TEST( page<tc->shmem->max_txnpages );

    ulong txn_cnt = FD_TXNCACHE_TXNS_PER_PAGE - tc->txnpages[ page ].free;
    for( ulong j=0UL; j<txn_cnt; j++ ) {
      fd_txncache_single_txn_t const * txn = tc->txnpages[ page ].txns[ j ];
      ushort txn_fork = txn->fork_id.val;
      FD_TEST( txn_fork<tc->shmem->active_slots_max );

      fuzz_blockcache_private_t const * fork = &tc->blockcache_pool[ txn_fork ];
      if( FD_UNLIKELY( fork->shmem->frozen<0 || fork->shmem->generation!=txn->generation ) ) return 1;
    }
  }

  return 0;
}

static void
target_purge_reachable( model_t const * m,
                        uchar *         reachable ) {
  fd_txncache_t * tc = m->tc;
  memset( reachable, 0, FUZZ_MAX_ACTIVE_SLOTS );

  fd_txncache_blockcache_shmem_t const * root =
    root_slist_ele_peek_head_const( tc->shmem->root_ll, tc->blockcache_shmem_pool );
  FD_TEST( root );

  ushort stack[ FUZZ_MAX_ACTIVE_SLOTS ];
  ulong  stack_cnt = 0UL;

  ulong root_idx = blockcache_pool_idx( tc->blockcache_shmem_pool, root );
  FD_TEST( root_idx<tc->shmem->active_slots_max );
  stack[ stack_cnt++ ] = (ushort)root_idx;

  while( stack_cnt ) {
    ushort idx = stack[ --stack_cnt ];
    FD_TEST( idx<tc->shmem->active_slots_max );
    if( reachable[ idx ] ) continue;
    reachable[ idx ] = 1U;

    ushort child_id = tc->blockcache_pool[ idx ].shmem->child_id.val;
    for( ulong depth=0UL; child_id!=USHORT_MAX; depth++ ) {
      FD_TEST( depth<tc->shmem->active_slots_max );
      FD_TEST( child_id<tc->shmem->active_slots_max );

      ushort next_child_id = tc->blockcache_pool[ child_id ].shmem->sibling_id.val;
      if( !reachable[ child_id ] ) {
        FD_TEST( stack_cnt<FUZZ_MAX_ACTIVE_SLOTS );
        stack[ stack_cnt++ ] = child_id;
      }
      child_id = next_child_id;
    }
  }
}

static void
model_check_query( model_t const *   m,
                   ushort            fork_id,
                   ushort            block_fork,
                   fd_hash_t const * txnhash ) {
  int actual = fd_txncache_query( m->tc,
                                  (fd_txncache_fork_id_t){ .val = fork_id },
                                  m->fork[ block_fork ].blockhash.uc,
                                  txnhash->uc );
  int expect = model_query( m, fork_id, block_fork, txnhash );
  FD_TEST( actual==expect );
}

static int
model_pick_visible_txn_query( model_t const * m,
                              fuzz_cursor_t * cur,
                              ushort *        fork_id,
                              ushort *        block_fork,
                              fd_hash_t *     txnhash ) {
  if( FD_UNLIKELY( !m->txn_cnt ) ) return 0;

  ulong start = fuzz_bounded( cur, m->txn_cnt );
  for( ulong n=0UL; n<m->txn_cnt; n++ ) {
    ulong txn_idx = (start+n) % m->txn_cnt;
    model_txn_t const * txn = &m->txn[ txn_idx ];
    if( FD_UNLIKELY( !txn->used ) ) continue;
    if( FD_UNLIKELY( txn->block_fork>=FUZZ_MAX_ACTIVE_SLOTS || txn->txn_fork>=FUZZ_MAX_ACTIVE_SLOTS ) ) continue;

    model_fork_t const * block = &m->fork[ txn->block_fork ];
    if( FD_UNLIKELY( !block->alive || block->frozen!=FORK_FINAL ) ) continue;

    model_fork_t const * txn_fork = &m->fork[ txn->txn_fork ];
    if( FD_UNLIKELY( !txn_fork->alive || txn_fork->generation!=txn->generation ) ) continue;

    ushort candidate[ FUZZ_MAX_ACTIVE_SLOTS ];
    ulong  candidate_cnt = 0UL;
    for( ulong i=0UL; i<FUZZ_MAX_ACTIVE_SLOTS; i++ ) {
      if( FD_UNLIKELY( !m->fork[ i ].alive ) ) continue;
      if( FD_UNLIKELY( !model_in_current_tree( m, (ushort)i ) ) ) continue;
      if( FD_UNLIKELY( !model_descends( m, (ushort)i, txn->block_fork ) ) ) continue;
      if( FD_UNLIKELY( txn->txn_fork!=(ushort)i && !model_descends( m, (ushort)i, txn->txn_fork ) ) ) continue;
      candidate[ candidate_cnt++ ] = (ushort)i;
    }

    if( candidate_cnt ) {
      *fork_id    = candidate[ fuzz_bounded( cur, candidate_cnt ) ];
      *block_fork = txn->block_fork;
      *txnhash    = txn->txnhash;
      return 1;
    }
  }

  return 0;
}

static int
model_pick_stale_txn_query( model_t const * m,
                            fuzz_cursor_t * cur,
                            ushort *        fork_id,
                            ushort *        block_fork,
                            fd_hash_t *     txnhash ) {
  if( FD_UNLIKELY( !m->txn_cnt ) ) return 0;

  ulong start = fuzz_bounded( cur, m->txn_cnt );
  for( ulong n=0UL; n<m->txn_cnt; n++ ) {
    ulong txn_idx = (start+n) % m->txn_cnt;
    model_txn_t const * txn = &m->txn[ txn_idx ];
    if( FD_UNLIKELY( !txn->used ) ) continue;
    if( FD_UNLIKELY( txn->block_fork>=FUZZ_MAX_ACTIVE_SLOTS || txn->txn_fork>=FUZZ_MAX_ACTIVE_SLOTS ) ) continue;

    model_fork_t const * block = &m->fork[ txn->block_fork ];
    if( FD_UNLIKELY( !block->alive || block->frozen!=FORK_FINAL ) ) continue;

    model_fork_t const * txn_fork = &m->fork[ txn->txn_fork ];
    int stale = !txn_fork->alive || txn_fork->generation!=txn->generation;
    if( FD_UNLIKELY( !stale ) ) continue;

    ushort candidate[ FUZZ_MAX_ACTIVE_SLOTS ];
    ulong  candidate_cnt = 0UL;
    for( ulong i=0UL; i<FUZZ_MAX_ACTIVE_SLOTS; i++ ) {
      if( FD_UNLIKELY( !m->fork[ i ].alive ) ) continue;
      if( FD_UNLIKELY( !model_in_current_tree( m, (ushort)i ) ) ) continue;
      if( FD_UNLIKELY( !model_descends( m, (ushort)i, txn->block_fork ) ) ) continue;
      candidate[ candidate_cnt++ ] = (ushort)i;
    }

    if( candidate_cnt ) {
      *fork_id    = candidate[ fuzz_bounded( cur, candidate_cnt ) ];
      *block_fork = txn->block_fork;
      *txnhash    = txn->txnhash;
      return 1;
    }
  }

  return 0;
}

/* check_invariants verifies the real structure's internal
   bookkeeping against the model. Its runtime is in
   O(active_slots + max_txnpages) */

static void
check_invariants( model_t const * m ) {
  fd_txncache_t * tc = m->tc;
  FD_TEST( tc->shmem->txnpages_free_cnt<=tc->shmem->max_txnpages );
  FD_TEST( tc->shmem->max_txnpages<=512U );

  ulong pool_free = blockcache_pool_free( tc->blockcache_shmem_pool );
  FD_TEST( pool_free + m->live_cnt == blockcache_pool_max( tc->blockcache_shmem_pool ) );

  /* Page ownership: every txnpage is owned by exactly one live fork or
     is on the free list, and all pages are accounted for. */
  uchar page_seen[ 512 ];
  memset( page_seen, 0, sizeof(page_seen) );
  ulong used_pages = 0UL;

  for( ulong i=0UL; i<FUZZ_MAX_ACTIVE_SLOTS; i++ ) {
    if( FD_UNLIKELY( !m->fork[ i ].alive ) ) continue;

    fuzz_blockcache_private_t const * bc = &tc->blockcache_pool[ i ];
    FD_TEST( bc->shmem->generation==m->fork[ i ].generation );
    FD_TEST( bc->shmem->pages_cnt<=tc->shmem->txnpages_per_blockhash_max );
    FD_TEST( bc->shmem->frozen==m->fork[ i ].frozen );

    for( ulong j=0UL; j<bc->shmem->pages_cnt; j++ ) {
      ushort page = bc->pages[ j ];
      FD_TEST( page<tc->shmem->max_txnpages );
      FD_TEST( !page_seen[ page ] );
      page_seen[ page ] = 1U;
      used_pages++;
    }
    for( ulong j=bc->shmem->pages_cnt; j<tc->shmem->txnpages_per_blockhash_max; j++ ) {
      FD_TEST( bc->pages[ j ]==USHORT_MAX );
    }
  }

  for( ulong i=0UL; i<tc->shmem->txnpages_free_cnt; i++ ) {
    ushort page = tc->txnpages_free[ i ];
    FD_TEST( page<tc->shmem->max_txnpages );
    FD_TEST( !page_seen[ page ] );
    page_seen[ page ] = 1U;
  }

  FD_TEST( used_pages + tc->shmem->txnpages_free_cnt == tc->shmem->max_txnpages );

  /* Root history: the real root slist must match the model's live root
     window exactly.  The list length is root_cnt+1: the original root
     plus one entry for each retained root advancement. */
  FD_TEST( tc->shmem->root_cnt==m->root_cnt );
  FD_TEST( m->roots_tail>=m->roots_head );
  FD_TEST( m->roots_tail-m->roots_head==m->root_cnt+1UL );

  uchar root_seen[ FUZZ_MAX_ACTIVE_SLOTS ];
  memset( root_seen, 0, sizeof(root_seen) );

  ulong root_idx = m->roots_head;
  for( root_slist_iter_t iter = root_slist_iter_init( tc->shmem->root_ll, tc->blockcache_shmem_pool );
       !root_slist_iter_done( iter, tc->shmem->root_ll, tc->blockcache_shmem_pool );
       iter = root_slist_iter_next( iter, tc->shmem->root_ll, tc->blockcache_shmem_pool ) ) {
    FD_TEST( root_idx<m->roots_tail );
    ulong idx = root_slist_iter_idx( iter, tc->shmem->root_ll, tc->blockcache_shmem_pool );
    FD_TEST( idx<FUZZ_MAX_ACTIVE_SLOTS );
    FD_TEST( idx==m->roots[ root_idx ] );
    FD_TEST( m->fork[ idx ].alive );
    FD_TEST( m->fork[ idx ].frozen==FORK_FINAL );
    FD_TEST( !root_seen[ idx ] );
    root_seen[ idx ] = 1U;
    root_idx++;
  }
  FD_TEST( root_idx==m->roots_tail );
  for( ulong i=m->roots_head; i<m->roots_tail; i++ ) FD_TEST( root_seen[ m->roots[ i ] ] );

  /* fd_txncache_insert relies on purge_stale making room when a blockhash
     has reached its page cap.  A capped blockhash containing stale txns
     must be reachable by the target's purge traversal from the oldest
     root; otherwise insert can retry purge forever. */
  uchar purge_reachable[ FUZZ_MAX_ACTIVE_SLOTS ];
  target_purge_reachable( m, purge_reachable );
  for( ulong i=0UL; i<FUZZ_MAX_ACTIVE_SLOTS; i++ ) {
    if( FD_UNLIKELY( !m->fork[ i ].alive ) ) continue;
    if( FD_UNLIKELY( !blockcache_needs_purge_for_insert( m, (ushort)i ) ) ) continue;
    if( FD_UNLIKELY( !blockcache_has_stale_txn( m, (ushort)i ) ) ) continue;
    FD_TEST( purge_reachable[ i ] );
  }

  /* Query ancestry is implemented by per-fork descends bitmaps, not by
     walking parent pointers at query time.  These must match the model's
     strict live ancestry exactly for every live fork. */
  for( ulong i=0UL; i<FUZZ_MAX_ACTIVE_SLOTS; i++ ) {
    if( FD_UNLIKELY( !m->fork[ i ].alive ) ) continue;

    fuzz_blockcache_private_t const * bc = &tc->blockcache_pool[ i ];
    for( ulong j=0UL; j<tc->shmem->active_slots_max; j++ ) {
      int expect = m->fork[ j ].alive && model_descends( m, (ushort)i, (ushort)j );
      int actual = descends_set_test( bc->descends, j );
      FD_TEST( !!actual==!!expect );
    }
  }

  /* The blockhash map must contain exactly the live forks with assigned
     blockhashes.  This catches both missing live entries and stale map
     links to released pool elements. */
  FD_TEST( !blockhash_map_verify( tc->blockhash_map, tc->shmem->active_slots_max, tc->blockcache_shmem_pool ) );

  ulong blockhash_map_cnt = 0UL;
  for( blockhash_map_iter_t iter = blockhash_map_iter_init( tc->blockhash_map, tc->blockcache_shmem_pool );
       !blockhash_map_iter_done( iter, tc->blockhash_map, tc->blockcache_shmem_pool );
       iter = blockhash_map_iter_next( iter, tc->blockhash_map, tc->blockcache_shmem_pool ) ) {
    ulong idx = blockhash_map_iter_idx( iter, tc->blockhash_map, tc->blockcache_shmem_pool );
    FD_TEST( idx<FUZZ_MAX_ACTIVE_SLOTS );
    FD_TEST( m->fork[ idx ].alive );
    FD_TEST( m->fork[ idx ].frozen>=FORK_HASHED );
    blockhash_map_cnt++;
  }

  ulong blockhash_model_cnt = 0UL;
  for( ulong i=0UL; i<FUZZ_MAX_ACTIVE_SLOTS; i++ ) {
    if( FD_UNLIKELY( !m->fork[ i ].alive || m->fork[ i ].frozen<FORK_HASHED ) ) continue;
    blockhash_model_cnt++;

    fuzz_blockcache_private_t const * bc = &tc->blockcache_pool[ i ];
    fd_txncache_blockcache_shmem_t const * ele =
      blockhash_map_ele_query_const( tc->blockhash_map, &bc->shmem->blockhash, NULL, tc->blockcache_shmem_pool );

    int found = 0;
    for( ulong depth=0UL; ele; depth++ ) {
      FD_TEST( depth<FUZZ_MAX_ACTIVE_SLOTS );
      if( blockcache_pool_idx( tc->blockcache_shmem_pool, ele )==i ) {
        found = 1;
        break;
      }
      ele = blockhash_map_ele_next_const( ele, NULL, tc->blockcache_shmem_pool );
    }
    FD_TEST( found );
  }
  FD_TEST( blockhash_map_cnt==blockhash_model_cnt );

  /* Fork tree: child/sibling lists reachable from retained roots must
     not contain cycles or duplicate matching live edges.  Current
     txncache can leave stale pruned siblings linked, and some
     page-pressure paths can orphan otherwise live children from these
     debug lists, so the query oracle remains the authoritative
     behavioral check for fork visibility. */
  ushort child_head[ FUZZ_MAX_ACTIVE_SLOTS ];
  ushort child_sib [ FUZZ_MAX_ACTIVE_SLOTS ];
  for( ulong i=0UL; i<FUZZ_MAX_ACTIVE_SLOTS; i++ ) {
    child_head[ i ] = USHORT_MAX;
    child_sib [ i ] = USHORT_MAX;
  }
  for( ulong i=0UL; i<FUZZ_MAX_ACTIVE_SLOTS; i++ ) {
    if( !m->fork[ i ].alive ) continue;
    ushort parent = m->fork[ i ].parent;
    if( parent<FUZZ_MAX_ACTIVE_SLOTS ) {
      child_sib[ i ]       = child_head[ parent ];
      child_head[ parent ] = (ushort)i;
    }
  }

  uchar  in_root_window[ FUZZ_MAX_ACTIVE_SLOTS ];
  ushort queue  [ FUZZ_MAX_ACTIVE_SLOTS ];
  memset( in_root_window, 0, sizeof(in_root_window) );
  ulong qhead = 0UL, qtail = 0UL;
  for( ulong i=m->roots_head; i<m->roots_tail; i++ ) {
    ushort root = m->roots[ i ];
    FD_TEST( root<FUZZ_MAX_ACTIVE_SLOTS );
    FD_TEST( m->fork[ root ].alive );
    if( !in_root_window[ root ] ) {
      in_root_window[ root ] = 1U;
      queue[ qtail++ ] = root;
    }
  }
  while( qhead<qtail ) {
    ushort p = queue[ qhead++ ];
    for( ushort c=child_head[ p ]; c!=USHORT_MAX; c=child_sib[ c ] ) {
      if( !in_root_window[ c ] ) { in_root_window[ c ] = 1U; queue[ qtail++ ] = c; }
    }
  }

  uchar reached[ FUZZ_MAX_ACTIVE_SLOTS ];
  memset( reached, 0, sizeof(reached) );
  for( ulong parent_id=0UL; parent_id<FUZZ_MAX_ACTIVE_SLOTS; parent_id++ ) {
    if( !in_root_window[ parent_id ] ) continue;

    ushort child_id = tc->blockcache_pool[ parent_id ].shmem->child_id.val;
    for( ulong depth=0UL; child_id!=USHORT_MAX; depth++ ) {
      FD_TEST( depth<FUZZ_MAX_ACTIVE_SLOTS );
      FD_TEST( child_id<FUZZ_MAX_ACTIVE_SLOTS );
      fuzz_blockcache_private_t const * child = &tc->blockcache_pool[ child_id ];
      ushort next_child_id = child->shmem->sibling_id.val;
      if( FD_UNLIKELY( !m->fork[ child_id ].alive ||
                       child->shmem->frozen<0     ||
                       !in_root_window[ child_id ] ||
                       m->fork[ child_id ].parent!=(ushort)parent_id ) ) {
        child_id = next_child_id;
        continue;
      }
      FD_TEST( !reached[ child_id ] );
      reached[ child_id ] = 1U;
      child_id = next_child_id;
    }
  }
}

static void
op_attach( model_t *       m,
           fuzz_cursor_t * cur ) {
  if( FD_UNLIKELY( model_current_tree_cnt( m )>=m->max_live_slots ) ) return;
  if( FD_UNLIKELY( !blockcache_pool_free( m->tc->blockcache_shmem_pool ) ) ) return;

  ushort parent = model_pick_fork( m, cur, 1, FORK_NEW, FORK_FINAL );
  if( FD_UNLIKELY( parent==USHORT_MAX ) ) return;

  fd_txncache_fork_id_t child = fd_txncache_attach_child( m->tc, (fd_txncache_fork_id_t){ .val = parent } );
  model_add_fork( m, child, parent, m->tc->blockcache_pool[ child.val ].shmem->generation );
}

static void
op_attach_blockhash( model_t *       m,
                     fuzz_cursor_t * cur ) {
  ushort fork_id = model_pick_fork( m, cur, 1, FORK_NEW, FORK_NEW );
  if( FD_UNLIKELY( fork_id==USHORT_MAX ) ) return;

  fd_hash_t blockhash[ 1 ];
  model_make_fresh_hash( m, fork_id, blockhash );

  fd_txncache_attach_blockhash( m->tc, (fd_txncache_fork_id_t){ .val = fork_id }, blockhash->uc );
  m->fork[ fork_id ].frozen         = FORK_HASHED;
  m->fork[ fork_id ].blockhash      = *blockhash;
  m->fork[ fork_id ].txnhash_offset = 0UL;
}

static void
op_finalize( model_t *       m,
             fuzz_cursor_t * cur ) {
  ushort fork_id = model_pick_fork( m, cur, 1, FORK_NEW, FORK_HASHED );
  if( FD_UNLIKELY( fork_id==USHORT_MAX ) ) return;

  fd_hash_t blockhash[ 1 ];
  if( m->fork[ fork_id ].frozen==FORK_HASHED ) {
    *blockhash = m->fork[ fork_id ].blockhash;
  } else {
    model_make_finalize_hash( m, cur, fork_id, blockhash );
  }
  ulong offset = fuzz_bounded( cur, 13UL );

  fd_txncache_finalize_fork( m->tc, (fd_txncache_fork_id_t){ .val = fork_id }, offset, blockhash->uc );
  m->fork[ fork_id ].frozen         = FORK_FINAL;
  m->fork[ fork_id ].blockhash      = *blockhash;
  m->fork[ fork_id ].txnhash_offset = offset;
}

static void
model_advance_to( model_t * m,
                  ushort    new_root );

static void
op_insert( model_t *       m,
           fuzz_cursor_t * cur ) {
  if( FD_UNLIKELY( m->txn_cnt>=FUZZ_MAX_MODEL_TXNS ) ) return;

  ushort fork_id = model_pick_fork( m, cur, 1, FORK_NEW, FORK_HASHED );
  if( FD_UNLIKELY( fork_id==USHORT_MAX ) ) return;

  ushort block_fork = model_pick_strict_ancestor( m, cur, fork_id, 0 );
  if( FD_UNLIKELY( block_fork==USHORT_MAX ) ) return;

  fd_hash_t txnhash[ 1 ];
  hash_from_counter( txnhash, 0x7A58000000000000UL, ++m->hash_nonce, fuzz_u8( cur ) );

  fd_txncache_fork_id_t block_fork_id = { .val = block_fork };

  fd_txncache_insert( m->tc, block_fork_id, m->fork[ block_fork ].blockhash.uc, txnhash->uc );

  model_record_txn( m, block_fork, fork_id, txnhash );
}

static ushort
model_attach_child( model_t * m,
                    ushort    parent ) {
  FD_TEST( model_current_tree_cnt( m )<m->max_live_slots );
  FD_TEST( blockcache_pool_free( m->tc->blockcache_shmem_pool ) );

  fd_txncache_fork_id_t child = fd_txncache_attach_child( m->tc, (fd_txncache_fork_id_t){ .val = parent } );
  model_add_fork( m, child, parent, m->tc->blockcache_pool[ child.val ].shmem->generation );
  return child.val;
}

static void
model_insert_one( model_t *       m,
                  ushort          fork_id,
                  ushort          block_fork,
                  fd_hash_t const * txnhash ) {
  fd_txncache_insert( m->tc,
                      (fd_txncache_fork_id_t){ .val = fork_id },
                      m->fork[ block_fork ].blockhash.uc,
                      txnhash->uc );
  model_record_txn( m, block_fork, fork_id, txnhash );
}

static int
op_bulk_second_page( model_t *       m,
                     fuzz_cursor_t * cur ) {
  if( FD_UNLIKELY( m->tc->shmem->txnpages_per_blockhash_max<2U ) ) return 0;

  ushort fork_id = model_pick_fork( m, cur, 1, FORK_NEW, FORK_HASHED );
  if( FD_UNLIKELY( fork_id==USHORT_MAX ) ) {
    if( FD_UNLIKELY( model_current_tree_cnt( m )>=m->max_live_slots ) ) return 0;
    if( FD_UNLIKELY( !blockcache_pool_free( m->tc->blockcache_shmem_pool ) ) ) return 0;
    fork_id = model_attach_child( m, m->current_root );
  }

  ushort block_fork = model_pick_strict_ancestor( m, cur, fork_id, 0 );
  if( FD_UNLIKELY( block_fork==USHORT_MAX ) ) return 0;

  ulong target = FD_TXNCACHE_TXNS_PER_PAGE+1UL;
  ulong used   = blockcache_txn_cnt( m, block_fork );
  if( FD_UNLIKELY( used>=target ) ) return 0;

  ulong cap = (ulong)m->tc->shmem->txnpages_per_blockhash_max * FD_TXNCACHE_TXNS_PER_PAGE;
  if( FD_UNLIKELY( target>cap ) ) return 0;

  ulong insert_cnt = target-used;
  if( FD_UNLIKELY( m->txn_cnt+insert_cnt>FUZZ_MAX_MODEL_TXNS ) ) return 0;

  for( ulong i=0UL; i<insert_cnt; i++ ) {
    fd_hash_t txnhash[ 1 ];
    hash_from_counter( txnhash, 0xB171000000000000UL, ++m->hash_nonce, i );
    model_insert_one( m, fork_id, block_fork, txnhash );
  }

  return 1;
}

static int
op_bulk_purge_stale( model_t *       m,
                     fuzz_cursor_t * cur ) {
  (void)cur;

  if( FD_UNLIKELY( m->tc->shmem->txnpages_per_blockhash_max!=1U ) ) return 0;
  if( FD_UNLIKELY( model_current_tree_cnt( m )+2UL>m->max_live_slots ) ) return 0;
  if( FD_UNLIKELY( blockcache_pool_free( m->tc->blockcache_shmem_pool )<2UL ) ) return 0;

  ushort block_fork = m->current_root;
  ulong  used       = blockcache_txn_cnt( m, block_fork );
  ulong  cap        = FD_TXNCACHE_TXNS_PER_PAGE;
  if( FD_UNLIKELY( used+1UL>=cap ) ) return 0;

  ulong stale_cnt = cap-used-1UL;
  if( FD_UNLIKELY( !stale_cnt ) ) return 0;
  if( FD_UNLIKELY( m->txn_cnt+stale_cnt+2UL>FUZZ_MAX_MODEL_TXNS ) ) return 0;

  ushort loser = model_attach_child( m, m->current_root );
  for( ulong i=0UL; i<stale_cnt; i++ ) {
    fd_hash_t txnhash[ 1 ];
    hash_from_counter( txnhash, 0x57A1E00000000000UL, ++m->hash_nonce, i );
    model_insert_one( m, loser, block_fork, txnhash );
  }

  fd_txncache_cancel_fork( m->tc, (fd_txncache_fork_id_t){ .val = loser } );
  model_remove_subtree( m, loser );

  ushort trigger = model_attach_child( m, m->current_root );
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_hash_t txnhash[ 1 ];
    hash_from_counter( txnhash, 0x7F16600000000000UL, ++m->hash_nonce, i );
    model_insert_one( m, trigger, block_fork, txnhash );
    check_invariants( m );
  }

  return 1;
}

/* This will slow down fuzzing speed quite a lot but is important to
   test page pressure, which is very uncommon in production */
static void
op_page_pressure( model_t *       m,
                  fuzz_cursor_t * cur ) {
  if( FD_UNLIKELY( m->bulk_cnt>=FUZZ_BULK_OP_MAX ) ) return;

  int prefer_second_page = (int)(fuzz_u8( cur ) & 1U);
  int ok = prefer_second_page ? op_bulk_second_page( m, cur ) : op_bulk_purge_stale( m, cur );
  if( FD_UNLIKELY( !ok ) ) {
    ok = prefer_second_page ? op_bulk_purge_stale( m, cur ) : op_bulk_second_page( m, cur );
  }
  if( ok ) m->bulk_cnt++;
}

static void
op_query( model_t *       m,
          fuzz_cursor_t * cur ) {
  ushort    fork_id;
  ushort    block_fork;
  fd_hash_t txnhash[ 1 ];

  switch( fuzz_u8( cur ) & 7U ) {
    case 0U:
    case 1U:
      if( model_pick_visible_txn_query( m, cur, &fork_id, &block_fork, txnhash ) ) {
        model_check_query( m, fork_id, block_fork, txnhash );
        return;
      }
      break;

    case 2U:
      if( model_pick_stale_txn_query( m, cur, &fork_id, &block_fork, txnhash ) ) {
        model_check_query( m, fork_id, block_fork, txnhash );
        return;
      }
      break;

    case 3U:
      /* Same bucket as a visible txn, but different stored 20-byte hash. */
      if( model_pick_visible_txn_query( m, cur, &fork_id, &block_fork, txnhash ) ) {
        ulong off = m->fork[ block_fork ].txnhash_offset;
        txnhash->uc[ off+8UL ] ^= (uchar)(1U | fuzz_u8( cur ));
        model_check_query( m, fork_id, block_fork, txnhash );
        return;
      }
      break;

    case 4U:
      /* Same stored 20-byte hash even though an ignored outer byte differs. */
      if( model_pick_visible_txn_query( m, cur, &fork_id, &block_fork, txnhash ) ) {
        ulong off = m->fork[ block_fork ].txnhash_offset;
        ulong idx = off ? 0UL : 20UL;
        txnhash->uc[ idx ] ^= (uchar)(1U | fuzz_u8( cur ));
        model_check_query( m, fork_id, block_fork, txnhash );
        return;
      }
      break;

    default:
      break;
  }

  fork_id = model_pick_fork( m, cur, 1, FORK_NEW, FORK_FINAL );
  if( FD_UNLIKELY( fork_id==USHORT_MAX ) ) return;

  block_fork = model_pick_strict_ancestor( m, cur, fork_id, 1 );
  if( FD_UNLIKELY( block_fork==USHORT_MAX ) ) return;

  int use_existing = (m->txn_cnt && (fuzz_u8( cur ) & 1U));
  if( use_existing ) {
    *txnhash = m->txn[ fuzz_bounded( cur, m->txn_cnt ) ].txnhash;
  } else {
    hash_from_counter( txnhash, 0xAB53000000000000UL, ++m->hash_nonce, fuzz_u8( cur ) );
  }

  model_check_query( m, fork_id, block_fork, txnhash );
}

static void
op_cancel( model_t *       m,
           fuzz_cursor_t * cur ) {
  ushort candidate[ FUZZ_MAX_ACTIVE_SLOTS ];
  ulong  candidate_cnt = 0UL;

  for( ulong i=0UL; i<FUZZ_MAX_ACTIVE_SLOTS; i++ ) {
    if( FD_UNLIKELY( !m->fork[ i ].alive ) ) continue;
    if( FD_UNLIKELY( i==m->current_root ) ) continue;
    if( FD_UNLIKELY( m->fork[ i ].parent==USHORT_MAX ) ) continue;
    if( FD_UNLIKELY( !model_descends( m, (ushort)i, m->current_root ) ) ) continue;
    candidate[ candidate_cnt++ ] = (ushort)i;
  }

  if( FD_UNLIKELY( !candidate_cnt ) ) return;

  ushort fork_id = candidate[ fuzz_bounded( cur, candidate_cnt ) ];
  fd_txncache_cancel_fork( m->tc, (fd_txncache_fork_id_t){ .val = fork_id } );
  model_remove_subtree( m, fork_id );
}

/* model_advance_to mirrors the model side of fd_txncache_advance_root:
   prune the old root's other subtrees, append the new root to the root
   history, and, once the blockhash-distance window is full, evict
   the oldest root and detach the new window head. */
static void
model_advance_to( model_t * m,
                  ushort    new_root ) {
  ushort old_root = m->current_root;

  for( ulong i=0UL; i<FUZZ_MAX_ACTIVE_SLOTS; i++ ) {
    if( m->fork[ i ].alive && m->fork[ i ].parent==old_root && i!=new_root )
      model_remove_subtree( m, (ushort)i );
  }

  m->current_root = new_root;
  FD_TEST( m->roots_tail<FUZZ_ROOT_HISTORY_MAX );
  m->roots[ m->roots_tail++ ] = new_root;
  m->root_cnt++;

  if( FD_UNLIKELY( m->root_cnt>FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE ) ) {
    ushort evicted = m->roots[ m->roots_head++ ];
    FD_TEST( m->roots_head<m->roots_tail );
    ushort new_head = m->roots[ m->roots_head ];
    model_remove_only( m, evicted );
    if( m->fork[ new_head ].alive ) m->fork[ new_head ].parent = USHORT_MAX;
    m->root_cnt--;
  }
}

static void
op_advance_root( model_t *       m,
                 fuzz_cursor_t * cur ) {
  ushort candidate[ FUZZ_MAX_ACTIVE_SLOTS ];
  ulong  candidate_cnt = 0UL;

  for( ulong i=0UL; i<FUZZ_MAX_ACTIVE_SLOTS; i++ ) {
    if( FD_UNLIKELY( !m->fork[ i ].alive ) ) continue;
    if( FD_UNLIKELY( m->fork[ i ].frozen!=FORK_FINAL ) ) continue;
    if( m->fork[ i ].parent==m->current_root ) candidate[ candidate_cnt++ ] = (ushort)i;
  }

  if( FD_UNLIKELY( !candidate_cnt ) ) return;

  ushort new_root = candidate[ fuzz_bounded( cur, candidate_cnt ) ];
  fd_txncache_advance_root( m->tc, (fd_txncache_fork_id_t){ .val = new_root } );
  model_advance_to( m, new_root );
}

/* op_extend_root grows the root chain by one in a single operation
   (attach a child off the root, finalize it, advance the root onto it).
   A run of this op drives root_cnt past FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE
   so the root-eviction path is reached. */

static void
op_extend_root( model_t *       m,
                fuzz_cursor_t * cur ) {
  if( FD_UNLIKELY( model_current_tree_cnt( m )>=m->max_live_slots ) ) return;
  if( FD_UNLIKELY( !blockcache_pool_free( m->tc->blockcache_shmem_pool ) ) ) return;

  ushort parent = m->current_root;
  fd_txncache_fork_id_t child = fd_txncache_attach_child( m->tc, (fd_txncache_fork_id_t){ .val = parent } );
  model_add_fork( m, child, parent, m->tc->blockcache_pool[ child.val ].shmem->generation );

  fd_hash_t blockhash[ 1 ];
  model_make_finalize_hash( m, cur, child.val, blockhash );
  ulong offset = fuzz_bounded( cur, 13UL );
  fd_txncache_finalize_fork( m->tc, child, offset, blockhash->uc );
  m->fork[ child.val ].frozen         = FORK_FINAL;
  m->fork[ child.val ].blockhash      = *blockhash;
  m->fork[ child.val ].txnhash_offset = offset;

  fd_txncache_advance_root( m->tc, child );
  model_advance_to( m, child.val );
}

static void
fuzz_cleanup( void ) {
  free( fuzz_shmem );
  free( fuzz_ljoin );
}

int
LLVMFuzzerInitialize( int *    argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  fd_log_level_core_set( 3 );
  fd_log_level_stderr_set( 4 );
  fd_log_level_logfile_set( 4 );
  atexit( fd_halt );

  fuzz_shmem_fp = fd_txncache_shmem_footprint( FUZZ_MAX_LIVE_SLOTS, FUZZ_MAX_TXN_PER_SLOT, 0 );
  fuzz_ljoin_fp = fd_txncache_footprint( FUZZ_MAX_LIVE_SLOTS );
  FD_TEST( fuzz_shmem_fp );
  FD_TEST( fuzz_ljoin_fp );

  ulong shmem_align = fd_txncache_shmem_align();
  ulong ljoin_align = fd_txncache_align();
  fuzz_shmem = aligned_alloc( shmem_align, FD_ULONG_ALIGN_UP( fuzz_shmem_fp, shmem_align ) );
  fuzz_ljoin = aligned_alloc( ljoin_align, FD_ULONG_ALIGN_UP( fuzz_ljoin_fp, ljoin_align ) );
  FD_TEST( fuzz_shmem );
  FD_TEST( fuzz_ljoin );
  atexit( fuzz_cleanup );

  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( !size ) ) return 0;

  fuzz_cursor_t cur = { .cur = data, .rem = size };

  static ulong const txn_per_slot_choice[] = { 1UL, 2UL, 4UL, 16UL, 64UL, 256UL };
  ulong max_live_slots   = 2UL + fuzz_bounded( &cur, FUZZ_MAX_LIVE_SLOTS-1UL );
  ulong max_txn_per_slot = txn_per_slot_choice[ fuzz_bounded( &cur, sizeof(txn_per_slot_choice)/sizeof(txn_per_slot_choice[0]) ) ];

  fd_txncache_t * tc = setup( max_live_slots, max_txn_per_slot );

  model_t * model = fuzz_model;
  model_init( model, tc, max_live_slots );
  FD_ONCE_BEGIN {
    check_invariants( model );
  } FD_ONCE_END;

  for( ulong action_idx=0UL; action_idx<FUZZ_MAX_ACTIONS && cur.rem; action_idx++ ) {
    switch( fuzz_u8( &cur ) & 15U ) {
      case  0U:
      case  1U:
      case  2U: op_attach          ( model, &cur ); break;
      case  3U: op_attach_blockhash( model, &cur ); break;
      case  4U:
      case  5U:
      case  6U: op_insert          ( model, &cur ); break;
      case  7U:
      case  8U: op_query           ( model, &cur ); break;
      case  9U:
      case 10U: op_finalize        ( model, &cur ); break;
      case 11U: op_cancel          ( model, &cur ); break;
      case 12U: op_advance_root    ( model, &cur ); break;
      case 13U: op_page_pressure   ( model, &cur ); break;
      default:  op_extend_root     ( model, &cur ); break;
    }

    check_invariants( model );
  }

  return 0;
}
