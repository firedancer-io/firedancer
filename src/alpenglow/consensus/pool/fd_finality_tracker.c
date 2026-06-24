#include "fd_finality_tracker.h"

/* status BTreeMap<Slot, FinalizationStatus>
   ----------------------------------------------------------------------
   Each status entry is a pool element keyed (in the map) by its slot and
   ordered (in the treap) by slot, so that the in-order range prune that
   mirrors Rust's BTreeMap::split_off(&root) can drop the contiguous
   prefix of slots below root in O(pruned). */

struct fd_ft_status_ele {
  ulong     slot;       /* map key + treap order key */
  int       status;     /* one of FD_FIN_STATUS_* */
  fd_hash_t hash;       /* block hash (meaningful for NOTARIZED/FINALIZED/IMPLICITLY_FINALIZED) */
  ulong     next;       /* reserved for status_map / status_pool */
  ulong     parent;     /* reserved for status_treap */
  ulong     left;       /* reserved for status_treap */
  ulong     right;      /* reserved for status_treap */
  ulong     prio;       /* reserved for status_treap */
};
typedef struct fd_ft_status_ele fd_ft_status_ele_t;

#define POOL_NAME status_pool
#define POOL_T    fd_ft_status_ele_t
#define POOL_NEXT next
#include "../../../util/tmpl/fd_pool.c"

#define MAP_NAME               status_map
#define MAP_ELE_T              fd_ft_status_ele_t
#define MAP_KEY                slot
#define MAP_KEY_T              ulong
#define MAP_KEY_EQ(k0,k1)      ((*(k0))==(*(k1)))
#define MAP_KEY_HASH(key,seed) (fd_ulong_hash( (*(key)) ^ (seed) ))
#define MAP_NEXT               next
#include "../../../util/tmpl/fd_map_chain.c"

#define TREAP_NAME      status_treap
#define TREAP_T         fd_ft_status_ele_t
#define TREAP_QUERY_T   ulong
#define TREAP_CMP(q,e)  ( ((q)<(e)->slot) ? -1 : ( ((q)>(e)->slot) ? 1 : 0 ) )
#define TREAP_LT(e0,e1) ( (e0)->slot < (e1)->slot )
#include "../../../util/tmpl/fd_treap.c"

/* parents BTreeMap<BlockId, BlockId>
   ----------------------------------------------------------------------
   Each parent edge is a pool element keyed (in the map) by the child
   block id and ordered (in the treap) by the child block's slot, so that
   the range prune that mirrors Rust's
   parents.retain(|(slot,_),_| slot >= root) can drop all edges whose
   child slot is below root in O(pruned).  When child slots collide the
   treap order among them is arbitrary, which is fine: prune drops them
   all-or-nothing relative to root. */

struct fd_ft_parent_ele {
  fd_block_id_t key;        /* map key = child block id; key.slot is treap order key */
  fd_block_id_t parent;     /* the recorded parent block id */
  ulong         next;       /* reserved for parent_map / parent_pool */
  ulong         tparent;    /* reserved for parent_treap */
  ulong         left;       /* reserved for parent_treap */
  ulong         right;      /* reserved for parent_treap */
  ulong         prio;       /* reserved for parent_treap */
};
typedef struct fd_ft_parent_ele fd_ft_parent_ele_t;

#define POOL_NAME parent_pool
#define POOL_T    fd_ft_parent_ele_t
#define POOL_NEXT next
#include "../../../util/tmpl/fd_pool.c"

#define MAP_NAME               parent_map
#define MAP_ELE_T              fd_ft_parent_ele_t
#define MAP_KEY                key
#define MAP_KEY_T              fd_block_id_t
#define MAP_KEY_EQ(k0,k1)      (fd_block_id_eq( (k0), (k1) ))
#define MAP_KEY_HASH(key,seed) (fd_hash( (seed), (key), sizeof(fd_block_id_t) ))
#define MAP_NEXT               next
#include "../../../util/tmpl/fd_map_chain.c"

#define TREAP_NAME      parent_treap
#define TREAP_T         fd_ft_parent_ele_t
#define TREAP_QUERY_T   ulong
#define TREAP_CMP(q,e)  ( ((q)<(e)->key.slot) ? -1 : ( ((q)>(e)->key.slot) ? 1 : 0 ) )
#define TREAP_LT(e0,e1) ( (e0)->key.slot < (e1)->key.slot )
#define TREAP_PARENT    tparent
#include "../../../util/tmpl/fd_treap.c"

/* fd_finality_tracker_t is the top-level structure.  Following the
   fd_ghost pattern it holds only ulong gaddrs (plus the two scalar
   watermark slots), and the pools / maps / treaps are bump-allocated
   contiguously after it.

   --------------------------- <- fd_finality_tracker_t *
   | fd_finality_tracker_t   |
   ---------------------------
   | status_pool             |
   ---------------------------
   | status_map              |
   ---------------------------
   | status_treap            |
   ---------------------------
   | parent_pool             |
   ---------------------------
   | parent_map              |
   ---------------------------
   | parent_treap            |
   --------------------------- */

struct __attribute__((aligned(128UL))) fd_finality_tracker {
  ulong wksp_gaddr;            /* wksp gaddr of this struct in the backing wksp */
  ulong status_pool_gaddr;
  ulong status_map_gaddr;
  ulong status_treap_gaddr;
  ulong parent_pool_gaddr;
  ulong parent_map_gaddr;
  ulong parent_treap_gaddr;
  ulong highest_finalized_slot; /* Rust: highest_finalized_slot */
  ulong first_unpruned_slot;    /* Rust: first_unpruned_slot */
};

typedef fd_ft_status_ele_t status_pool_t;
typedef fd_ft_parent_ele_t parent_pool_t;

/* wksp returns the local join to the wksp backing the tracker. */

FD_FN_PURE static inline fd_wksp_t *
wksp( fd_finality_tracker_t const * t ) {
  return (fd_wksp_t *)( ((ulong)t) - t->wksp_gaddr );
}

static inline status_pool_t *
status_pool( fd_finality_tracker_t * t ) {
  return (status_pool_t *)fd_wksp_laddr_fast( wksp( t ), t->status_pool_gaddr );
}

static inline status_pool_t const *
status_pool_const( fd_finality_tracker_t const * t ) {
  return (status_pool_t const *)fd_wksp_laddr_fast( wksp( t ), t->status_pool_gaddr );
}

static inline status_map_t *
status_map( fd_finality_tracker_t * t ) {
  return (status_map_t *)fd_wksp_laddr_fast( wksp( t ), t->status_map_gaddr );
}

static inline status_map_t const *
status_map_const( fd_finality_tracker_t const * t ) {
  return (status_map_t const *)fd_wksp_laddr_fast( wksp( t ), t->status_map_gaddr );
}

static inline status_treap_t *
status_treap( fd_finality_tracker_t * t ) {
  return (status_treap_t *)fd_wksp_laddr_fast( wksp( t ), t->status_treap_gaddr );
}

static inline parent_pool_t *
parent_pool( fd_finality_tracker_t * t ) {
  return (parent_pool_t *)fd_wksp_laddr_fast( wksp( t ), t->parent_pool_gaddr );
}

static inline parent_pool_t const *
parent_pool_const( fd_finality_tracker_t const * t ) {
  return (parent_pool_t const *)fd_wksp_laddr_fast( wksp( t ), t->parent_pool_gaddr );
}

static inline parent_map_t *
parent_map( fd_finality_tracker_t * t ) {
  return (parent_map_t *)fd_wksp_laddr_fast( wksp( t ), t->parent_map_gaddr );
}

static inline parent_map_t const *
parent_map_const( fd_finality_tracker_t const * t ) {
  return (parent_map_t const *)fd_wksp_laddr_fast( wksp( t ), t->parent_map_gaddr );
}

static inline parent_treap_t *
parent_treap( fd_finality_tracker_t * t ) {
  return (parent_treap_t *)fd_wksp_laddr_fast( wksp( t ), t->parent_treap_gaddr );
}

/* ---- internal status helpers --------------------------------------- */

/* status_get returns the status element for slot, or NULL if absent. */

static inline fd_ft_status_ele_t *
status_get( fd_finality_tracker_t * t, ulong slot ) {
  return status_map_ele_query( status_map( t ), &slot, NULL, status_pool( t ) );
}

/* status_insert inserts or overwrites the status for slot.  Mirrors the
   semantics of Rust's BTreeMap::insert: it returns the previous status
   (via *old_status / *old_hash and a 1 return) if slot was present, or 0
   if it was vacant.  hash is copied verbatim and is only meaningful for
   the variants that carry one. */

static int
status_insert( fd_finality_tracker_t * t,
               ulong                   slot,
               int                     status,
               fd_hash_t const *       hash,
               int *                   old_status,
               fd_hash_t *             old_hash ) {
  fd_ft_status_ele_t * e = status_get( t, slot );
  if( FD_LIKELY( e ) ) {
    if( old_status ) *old_status = e->status;
    if( old_hash   ) *old_hash   = e->hash;
    e->status = status;
    e->hash   = *hash;
    return 1;
  }
  status_pool_t * pool = status_pool( t );
  FD_TEST( status_pool_free( pool ) ); /* tracker full (slot_max too small) */
  e = status_pool_ele_acquire( pool );
  e->slot   = slot;
  e->status = status;
  e->hash   = *hash;
  status_map_ele_insert  ( status_map  ( t ), e, pool );
  status_treap_ele_insert( status_treap( t ), e, pool );
  return 0;
}

/* ---- event helpers ------------------------------------------------- */

static inline void
event_reset( fd_finalization_event_t * ev ) {
  ev->has_finalized = 0;
  ev->if_cnt        = 0UL;
  ev->is_cnt        = 0UL;
}

static inline void
event_push_implicitly_finalized( fd_finalization_event_t * ev, fd_block_id_t const * b ) {
  if( FD_UNLIKELY( ev->if_cnt>=FD_FINALITY_EVENT_CAP ) ) {
    FD_LOG_ERR(( "implicitly_finalized overflow (cap %lu)", FD_FINALITY_EVENT_CAP ));
  }
  ev->implicitly_finalized[ ev->if_cnt++ ] = *b;
}

static inline void
event_push_implicitly_skipped( fd_finalization_event_t * ev, ulong slot ) {
  if( FD_UNLIKELY( ev->is_cnt>=FD_FINALITY_EVENT_CAP ) ) {
    FD_LOG_ERR(( "implicitly_skipped overflow (cap %lu)", FD_FINALITY_EVENT_CAP ));
  }
  ev->implicitly_skipped[ ev->is_cnt++ ] = slot;
}

/* ---- internal recursion / pruning ---------------------------------- */

static void handle_finalized_block   ( fd_finality_tracker_t * t, fd_block_id_t const * finalized,                                  fd_finalization_event_t * ev );
static void handle_implicitly_finalized( fd_finality_tracker_t * t, ulong source_slot, fd_block_id_t const * implicitly_finalized, fd_finalization_event_t * ev );
static void ft_prune                  ( fd_finality_tracker_t * t );

/* handle_implicitly_finalized mirrors
   FinalityTracker::handle_implicitly_finalized.  The Rust version recurses
   through ancestors via a tail call; we flatten that tail recursion into
   a loop, carrying (source_slot, implicitly_finalized) forward. */

static void
handle_implicitly_finalized( fd_finality_tracker_t * t,
                             ulong                   source_slot,
                             fd_block_id_t const *   implicitly_finalized,
                             fd_finalization_event_t * ev ) {
  fd_block_id_t cur = *implicitly_finalized; /* local copy we advance up the chain */
  fd_hash_t     zero; fd_memset( &zero, 0, sizeof(fd_hash_t) ); /* hash is irrelevant for ImplicitlySkipped */

  for(;;) {
    FD_TEST( source_slot > cur.slot );

    /* parent slot may already be decided and pruned; consider a call to
       add_parent for the first_unpruned_slot. */

    if( FD_UNLIKELY( cur.slot < t->first_unpruned_slot ) ) return;

    /* implicitly skip slots in between */

    int returned = 0;
    for( ulong slot = cur.slot+1UL; ; slot++ ) {
      if( slot==source_slot ) break;
      int old_status; fd_hash_t old_hash;
      int had = status_insert( t, slot, FD_FIN_STATUS_IMPLICITLY_SKIPPED, &zero, &old_status, &old_hash );
      (void)old_hash;
      if( had ) {
        switch( old_status ) {
          case FD_FIN_STATUS_IMPLICITLY_SKIPPED:
            returned = 1; /* mirror Rust: early return from the whole function */
            break;
          case FD_FIN_STATUS_NOTARIZED:
            break;
          case FD_FIN_STATUS_FINAL_PENDING_NOTAR:
          case FD_FIN_STATUS_FINALIZED:
          case FD_FIN_STATUS_IMPLICITLY_FINALIZED:
          default:
            FD_LOG_ERR(( "consensus safety violation" ));
        }
      }
      if( FD_UNLIKELY( returned ) ) return;
      event_push_implicitly_skipped( ev, slot );
    }

    /* mark block as implicitly finalized */

    int old_status; fd_hash_t old_hash;
    int had = status_insert( t, cur.slot, FD_FIN_STATUS_IMPLICITLY_FINALIZED, &cur.hash, &old_status, &old_hash );
    if( had ) {
      switch( old_status ) {
        case FD_FIN_STATUS_FINALIZED:
        case FD_FIN_STATUS_IMPLICITLY_FINALIZED:
          FD_TEST( 0==memcmp( old_hash.uc, cur.hash.uc, sizeof(fd_hash_t) ) ); /* consensus safety violation */
          /* restore the previous status (Rust re-inserts the old status and returns) */
          { int s2; fd_hash_t h2; status_insert( t, cur.slot, old_status, &old_hash, &s2, &h2 ); }
          return;
        case FD_FIN_STATUS_NOTARIZED:
          FD_TEST( 0==memcmp( old_hash.uc, cur.hash.uc, sizeof(fd_hash_t) ) ); /* consensus safety violation */
          break;
        case FD_FIN_STATUS_FINAL_PENDING_NOTAR:
          break;
        case FD_FIN_STATUS_IMPLICITLY_SKIPPED:
        default:
          FD_LOG_ERR(( "consensus safety violation" ));
      }
    }
    event_push_implicitly_finalized( ev, &cur );

    /* recurse through ancestors (flattened tail call) */

    fd_ft_parent_ele_t * pe = parent_map_ele_query( parent_map( t ), &cur, NULL, parent_pool( t ) );
    if( FD_UNLIKELY( !pe ) ) return;
    source_slot = cur.slot;
    cur         = pe->parent;
  }
}

/* handle_finalized_block mirrors FinalityTracker::handle_finalized_block. */

static void
handle_finalized_block( fd_finality_tracker_t *   t,
                        fd_block_id_t const *     finalized,
                        fd_finalization_event_t * ev ) {
  ulong slot = finalized->slot;
  ev->has_finalized = 1;
  ev->finalized     = *finalized;
  t->highest_finalized_slot = fd_ulong_max( slot, t->highest_finalized_slot );

  fd_ft_parent_ele_t * pe = parent_map_ele_query( parent_map( t ), finalized, NULL, parent_pool( t ) );
  if( FD_LIKELY( pe ) ) {
    fd_block_id_t parent = pe->parent;
    handle_implicitly_finalized( t, slot, &parent, ev );
  }
  ft_prune( t );
}

/* ft_prune mirrors FinalityTracker::prune.  It advances first_unpruned_slot
   to the end of the contiguous prefix of decided slots, then drops all
   status / parent state strictly below the new watermark (Rust:
   status.split_off(&root) + parents.retain(|(slot,_),_| slot >= root)). */

static void
ft_prune( fd_finality_tracker_t * t ) {
  ulong next = t->first_unpruned_slot + 1UL;
  for(;;) {
    fd_ft_status_ele_t * e = status_get( t, next );
    if( FD_UNLIKELY( !e ) ) break;
    int decided = ( e->status==FD_FIN_STATUS_FINALIZED            ||
                    e->status==FD_FIN_STATUS_IMPLICITLY_FINALIZED ||
                    e->status==FD_FIN_STATUS_IMPLICITLY_SKIPPED   );
    if( FD_UNLIKELY( !decided ) ) break;
    t->first_unpruned_slot = next;
    next++;
  }
  ulong root = t->first_unpruned_slot;

  /* status.split_off(&root): drop every status entry with slot < root.
     Walk the treap in order from the smallest slot, removing while
     slot < root.  Each removal is from both the treap and the map. */

  {
    status_pool_t  * pool  = status_pool ( t );
    status_treap_t * treap = status_treap( t );
    status_map_t   * map   = status_map  ( t );
    for(;;) {
      status_treap_fwd_iter_t it = status_treap_fwd_iter_init( treap, pool );
      if( status_treap_fwd_iter_done( it ) ) break;
      fd_ft_status_ele_t * e = status_treap_fwd_iter_ele( it, pool );
      if( FD_LIKELY( e->slot >= root ) ) break; /* smallest is already >= root */
      status_treap_ele_remove( treap, e, pool );
      status_map_ele_remove( map, &e->slot, NULL, pool );
      status_pool_ele_release( pool, e );
    }
  }

  /* parents.retain(|(slot,_),_| slot >= root): drop every parent edge
     whose child slot is < root. */

  {
    parent_pool_t  * pool  = parent_pool ( t );
    parent_treap_t * treap = parent_treap( t );
    parent_map_t   * map   = parent_map  ( t );
    for(;;) {
      parent_treap_fwd_iter_t it = parent_treap_fwd_iter_init( treap, pool );
      if( parent_treap_fwd_iter_done( it ) ) break;
      fd_ft_parent_ele_t * e = parent_treap_fwd_iter_ele( it, pool );
      if( FD_LIKELY( e->key.slot >= root ) ) break;
      parent_treap_ele_remove( treap, e, pool );
      parent_map_ele_remove( map, &e->key, NULL, pool );
      parent_pool_ele_release( pool, e );
    }
  }
}

/* ---- constructors -------------------------------------------------- */

ulong
fd_finality_tracker_align( void ) {
  return alignof(fd_finality_tracker_t);
}

ulong
fd_finality_tracker_footprint( ulong slot_max,
                               ulong blockid_max ) {
  slot_max    = fd_ulong_pow2_up( slot_max    );
  blockid_max = fd_ulong_pow2_up( blockid_max );
  ulong status_chain_cnt = status_map_chain_cnt_est( slot_max    );
  ulong parent_chain_cnt = parent_map_chain_cnt_est( blockid_max );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_finality_tracker_t), sizeof(fd_finality_tracker_t)         ),
      status_pool_align(),  status_pool_footprint ( slot_max             )  ),
      status_map_align(),   status_map_footprint  ( status_chain_cnt     )  ),
      status_treap_align(), status_treap_footprint( slot_max             )  ),
      parent_pool_align(),  parent_pool_footprint ( blockid_max          )  ),
      parent_map_align(),   parent_map_footprint  ( parent_chain_cnt     )  ),
      parent_treap_align(), parent_treap_footprint( blockid_max          )  ),
    fd_finality_tracker_align() );
}

void *
fd_finality_tracker_new( void *            shmem,
                         ulong             slot_max,
                         ulong             blockid_max,
                         ulong             seed,
                         ulong             root_slot,
                         fd_hash_t const * root_hash ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_finality_tracker_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !slot_max || !blockid_max ) ) {
    FD_LOG_WARNING(( "zero slot_max / blockid_max" ));
    return NULL;
  }

  ulong footprint = fd_finality_tracker_footprint( slot_max, blockid_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max (%lu) / blockid_max (%lu)", slot_max, blockid_max ));
    return NULL;
  }

  slot_max    = fd_ulong_pow2_up( slot_max    );
  blockid_max = fd_ulong_pow2_up( blockid_max );

  fd_wksp_t * ws = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !ws ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  ulong status_chain_cnt = status_map_chain_cnt_est( slot_max    );
  ulong parent_chain_cnt = parent_map_chain_cnt_est( blockid_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_finality_tracker_t * t            = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_finality_tracker_t), sizeof(fd_finality_tracker_t)        );
  void *                  status_pool  = FD_SCRATCH_ALLOC_APPEND( l, status_pool_align(),  status_pool_footprint ( slot_max         )    );
  void *                  status_map   = FD_SCRATCH_ALLOC_APPEND( l, status_map_align(),   status_map_footprint  ( status_chain_cnt )    );
  void *                  status_treap = FD_SCRATCH_ALLOC_APPEND( l, status_treap_align(), status_treap_footprint( slot_max         )    );
  void *                  parent_pool  = FD_SCRATCH_ALLOC_APPEND( l, parent_pool_align(),  parent_pool_footprint ( blockid_max      )    );
  void *                  parent_map   = FD_SCRATCH_ALLOC_APPEND( l, parent_map_align(),   parent_map_footprint  ( parent_chain_cnt )    );
  void *                  parent_treap = FD_SCRATCH_ALLOC_APPEND( l, parent_treap_align(), parent_treap_footprint( blockid_max      )    );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_finality_tracker_align() ) == (ulong)shmem + footprint );

  status_pool_t * sp = status_pool_join( status_pool_new( status_pool, slot_max    ) );
  parent_pool_t * pp = parent_pool_join( parent_pool_new( parent_pool, blockid_max ) );

  t->wksp_gaddr        = fd_wksp_gaddr_fast( ws, t );
  t->status_pool_gaddr = fd_wksp_gaddr_fast( ws, sp );
  t->status_map_gaddr  = fd_wksp_gaddr_fast( ws, status_map_join  ( status_map_new  ( status_map,  status_chain_cnt, seed    ) ) );
  t->status_treap_gaddr= fd_wksp_gaddr_fast( ws, status_treap_join( status_treap_new( status_treap, slot_max                 ) ) );
  t->parent_pool_gaddr = fd_wksp_gaddr_fast( ws, pp );
  t->parent_map_gaddr  = fd_wksp_gaddr_fast( ws, parent_map_join  ( parent_map_new  ( parent_map,  parent_chain_cnt, seed    ) ) );
  t->parent_treap_gaddr= fd_wksp_gaddr_fast( ws, parent_treap_join( parent_treap_new( parent_treap, blockid_max              ) ) );

  /* Seed treap priorities once on the joined element storage (random
     fixed prios eliminate RNG cost in insert / remove).  These persist
     across acquire / release. */

  status_treap_seed( sp, slot_max,    seed );
  parent_treap_seed( pp, blockid_max, seed );

  t->highest_finalized_slot = root_slot;
  t->first_unpruned_slot    = root_slot;

  fd_hash_t zero; fd_memset( &zero, 0, sizeof(fd_hash_t) );
  status_insert( t, root_slot, FD_FIN_STATUS_NOTARIZED, root_hash ? root_hash : &zero, NULL, NULL );

  return shmem;
}

fd_finality_tracker_t *
fd_finality_tracker_join( void * shtracker ) {
  fd_finality_tracker_t * t = (fd_finality_tracker_t *)shtracker;
  if( FD_UNLIKELY( !t ) ) {
    FD_LOG_WARNING(( "NULL tracker" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)t, fd_finality_tracker_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned tracker" ));
    return NULL;
  }
  return t;
}

void *
fd_finality_tracker_leave( fd_finality_tracker_t const * t ) {
  if( FD_UNLIKELY( !t ) ) {
    FD_LOG_WARNING(( "NULL tracker" ));
    return NULL;
  }
  return (void *)t;
}

void *
fd_finality_tracker_delete( void * shtracker ) {
  if( FD_UNLIKELY( !shtracker ) ) {
    FD_LOG_WARNING(( "NULL tracker" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shtracker, fd_finality_tracker_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned tracker" ));
    return NULL;
  }
  return shtracker;
}

/* ---- operations ---------------------------------------------------- */

void
fd_finality_tracker_add_parent( fd_finality_tracker_t *   t,
                                fd_block_id_t const *     block,
                                fd_block_id_t const *     parent,
                                fd_finalization_event_t * out ) {
  event_reset( out );
  FD_TEST( block->slot > parent->slot );

  /* NOTE: This can genuinely happen if we see a finalization before the
     block. */

  if( FD_UNLIKELY( block->slot < t->first_unpruned_slot ) ) return;

  /* parents.entry(block): on Occupied, assert equal parent and return
     default; on Vacant, insert. */

  fd_ft_parent_ele_t * pe = parent_map_ele_query( parent_map( t ), block, NULL, parent_pool( t ) );
  if( FD_LIKELY( pe ) ) {
    FD_TEST( fd_block_id_eq( &pe->parent, parent ) );
    return;
  }
  {
    parent_pool_t * pool = parent_pool( t );
    FD_TEST( parent_pool_free( pool ) ); /* tracker full (blockid_max too small) */
    pe         = parent_pool_ele_acquire( pool );
    pe->key    = *block;
    pe->parent = *parent;
    parent_map_ele_insert  ( parent_map  ( t ), pe, pool );
    parent_treap_ele_insert( parent_treap( t ), pe, pool );
  }

  fd_ft_status_ele_t * se = status_get( t, block->slot );
  if( FD_UNLIKELY( !se ) ) return;

  switch( se->status ) {
    case FD_FIN_STATUS_FINALIZED:
    case FD_FIN_STATUS_IMPLICITLY_FINALIZED:
      if( 0==memcmp( block->hash.uc, se->hash.uc, sizeof(fd_hash_t) ) ) {
        fd_block_id_t p = *parent;
        handle_implicitly_finalized( t, block->slot, &p, out );
        ft_prune( t );
      }
      return;
    case FD_FIN_STATUS_NOTARIZED:
    case FD_FIN_STATUS_FINAL_PENDING_NOTAR:
    case FD_FIN_STATUS_IMPLICITLY_SKIPPED:
    default:
      return;
  }
}

void
fd_finality_tracker_mark_fast_finalized( fd_finality_tracker_t *   t,
                                         fd_block_id_t const *     block,
                                         fd_finalization_event_t * out ) {
  event_reset( out );
  if( FD_UNLIKELY( block->slot < t->first_unpruned_slot ) ) return;

  int old_status; fd_hash_t old_hash;
  int had = status_insert( t, block->slot, FD_FIN_STATUS_FINALIZED, &block->hash, &old_status, &old_hash );
  if( had ) {
    switch( old_status ) {
      case FD_FIN_STATUS_FINALIZED:
      case FD_FIN_STATUS_IMPLICITLY_FINALIZED:
        FD_TEST( 0==memcmp( old_hash.uc, block->hash.uc, sizeof(fd_hash_t) ) ); /* consensus safety violation */
        return;
      case FD_FIN_STATUS_NOTARIZED:
        FD_TEST( 0==memcmp( old_hash.uc, block->hash.uc, sizeof(fd_hash_t) ) ); /* consensus safety violation */
        break;
      case FD_FIN_STATUS_FINAL_PENDING_NOTAR:
        break;
      case FD_FIN_STATUS_IMPLICITLY_SKIPPED:
      default:
        FD_LOG_ERR(( "consensus safety violation" ));
    }
  }

  handle_finalized_block( t, block, out );
}

void
fd_finality_tracker_mark_notarized( fd_finality_tracker_t *   t,
                                    fd_block_id_t const *     block,
                                    fd_finalization_event_t * out ) {
  event_reset( out );
  if( FD_UNLIKELY( block->slot < t->first_unpruned_slot ) ) return;

  int old_status; fd_hash_t old_hash;
  int had = status_insert( t, block->slot, FD_FIN_STATUS_NOTARIZED, &block->hash, &old_status, &old_hash );
  if( FD_UNLIKELY( !had ) ) return;

  switch( old_status ) {
    case FD_FIN_STATUS_NOTARIZED:
    case FD_FIN_STATUS_FINALIZED:
    case FD_FIN_STATUS_IMPLICITLY_FINALIZED:
      FD_TEST( 0==memcmp( old_hash.uc, block->hash.uc, sizeof(fd_hash_t) ) ); /* consensus safety violation */
      return;
    case FD_FIN_STATUS_IMPLICITLY_SKIPPED:
      return;
    case FD_FIN_STATUS_FINAL_PENDING_NOTAR: {
      int s2; fd_hash_t h2;
      status_insert( t, block->slot, FD_FIN_STATUS_FINALIZED, &block->hash, &s2, &h2 );
      handle_finalized_block( t, block, out );
      return;
    }
    default:
      FD_LOG_ERR(( "unexpected status %d", old_status ));
  }
}

void
fd_finality_tracker_mark_finalized( fd_finality_tracker_t *   t,
                                    ulong                     slot,
                                    fd_finalization_event_t * out ) {
  event_reset( out );
  if( FD_UNLIKELY( slot < t->first_unpruned_slot ) ) return;

  fd_hash_t zero; fd_memset( &zero, 0, sizeof(fd_hash_t) );
  int old_status; fd_hash_t old_hash;
  int had = status_insert( t, slot, FD_FIN_STATUS_FINAL_PENDING_NOTAR, &zero, &old_status, &old_hash );
  if( FD_UNLIKELY( !had ) ) return;

  switch( old_status ) {
    case FD_FIN_STATUS_FINAL_PENDING_NOTAR:
    case FD_FIN_STATUS_FINALIZED:
    case FD_FIN_STATUS_IMPLICITLY_FINALIZED:
      /* Faithful to Rust: the unconditional insert above already
         overwrote the status with FinalPendingNotar and we return the
         default event without re-inserting.  (For these three arms Rust
         leaves the slot as FinalPendingNotar.) */
      return;
    case FD_FIN_STATUS_NOTARIZED: {
      fd_block_id_t block = { .slot=slot, .hash=old_hash };
      int s2; fd_hash_t h2;
      status_insert( t, slot, FD_FIN_STATUS_FINALIZED, &old_hash, &s2, &h2 );
      handle_finalized_block( t, &block, out );
      return;
    }
    case FD_FIN_STATUS_IMPLICITLY_SKIPPED:
    default:
      FD_LOG_ERR(( "consensus safety violation" ));
  }
}

/* ---- accessors ----------------------------------------------------- */

ulong
fd_finality_tracker_highest_finalized_slot( fd_finality_tracker_t const * t ) {
  return t->highest_finalized_slot;
}

ulong
fd_finality_tracker_first_unpruned_slot( fd_finality_tracker_t const * t ) {
  return t->first_unpruned_slot;
}

int
fd_finality_tracker_status( fd_finality_tracker_t const * t,
                            ulong                         slot,
                            fd_hash_t *                   out_hash ) {
  fd_ft_status_ele_t const * e = status_map_ele_query_const( status_map_const( t ), &slot, NULL, status_pool_const( t ) );
  if( FD_UNLIKELY( !e ) ) return -1;
  if( out_hash ) *out_hash = e->hash;
  return e->status;
}

int
fd_finality_tracker_has_parent( fd_finality_tracker_t const * t,
                                fd_block_id_t const *         block ) {
  return !!parent_map_ele_query_const( parent_map_const( t ), block, NULL, parent_pool_const( t ) );
}
