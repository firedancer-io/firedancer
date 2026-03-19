#include "../fd_choreo_base.h"
#include "fd_eqvoc.h"
#include "../../ballet/shred/fd_shred.h"

/* fd_eqvoc maintains four bounded maps:

   dup_map  (capacity dup_max): maps slot -> equivocation result,
            recording slots we've already verified are duplicates
            (equivocations).  LRU-evicts when at capacity: querying an
            entry moves it to the tail of the recency list; when an
            insert is needed and the map is full, the head
            (least-recently-used) entry is evicted.

   fec_map  (capacity fec_max): maps (slot, fec_set_idx) -> shred,
            storing the first shred seen in each FEC set so it can be
            compared against later siblings for equivocation.  Same LRU
            eviction policy as dup_map.  Entries are also explicitly
            removed when equivocation is confirmed (proof constructed).

   prf_map  (capacity per_vtr_max * vtr_max): maps (slot, voter_pubkey)
            -> in-progress proof ("chunks") assembly state, tracking
            proofs per voter per slot.  Entries are LRU-evicted per
            voter when that voter's in-progress proof count reaches
            per_vtr_max.  Entries are also removed when proof assembly
            completes (all chunks received), regardless of verification
            outcome, or when the corresponding voter is removed from
            vtr_map.

   vtr_map  (capacity vtr_max): maps voter pubkey -> per-voter proof-
            assembly state.  vtr entries are not evicted automatically;
            they are explicitly inserted and removed by
            fd_eqvoc_update_voters when the epoch stake set changes.
            Each vtr has a pre-allocated prf_dlist that tracks
            in-progress proofs for that voter.  Each voter's in-progress
            proof count is bounded by per_vtr_max; when that limit is
            reached, the oldest proof for that voter is evicted.

            dup_map                         fec_map
     map[0] +--------------------+   map[0] +--------------------+
            | (dup_t) {          |          | (fec_t) {          |
            |   .slot = 1,       |          |   .key  = 5|0,     |
            |   ...              |          |   ...              |
            | }                  |          | }                  |
     map[1] +--------------------+   map[1] +--------------------+
            | (dup_t) {          |          | (fec_t) {          |
            |   .slot = 2,       |          |   .key  = 6|0,     |
            |   ...              |          |   ...              |
            | }                  |          | }                  |
            +--------------------+          +--------------------+

            vtr_map                         prf_map
     map[0] +--------------------+   map[0] +--------------------+
            | (vtr_t) {          |          | (prf_t) {          |
            |   .from = X,       |          |   .key.slot = 5,   |
            |   ...              |          |   .key.from = Y,   |<-----+
            |   ...              |          |   ...              |      |
            | }                  |          | }                  |      |
     map[1] +--------------------+   map[1] +--------------------+      |
            | (vtr_t) {          |          | (prf_t) {          |      |
            |   .from = Y,       |          |   .key.slot = 6,   |      |
            |   ...              |          |   .key.from = Y,   |<--+  |
            |   .prf_dlist = +   |          |   ...              |   |  |
            | }              |   |          | }                  |   |  |
            +----------------|---+          +--------------------+   |  |
                             |                                       |  |
                             |                                       |  |
                             |              +------------------------+  |
                             |              |                           |
                             V              |        +------------------+
                             prf_dlist      |        |
                             +---------+---------+---------+
                             | (prf_t) | (prf_t) | (prf_t) |
                             |   ...   |   ...   |   ...   |
                             | }       | }       | }       |
                             +---------+---------+---------+
                             oldest                   newest

   Each vtr_t owns a prf_dlist of in-progress proofs (prf_t).
   prf_t elements are also in the global prf_map for lookup by
   (slot, from).  When prf_dlist_cnt == per_vtr_max, the oldest
   prf is evicted from both prf_dlist and prf_map. */

typedef struct {
  ulong slot;
  ulong next; /* pool next */
  struct {
    ulong prev;
    ulong next;
  } map;
  struct {
    ulong prev;
    ulong next;
  } dlist;
  int err; /* positive error code (FD_EQVOC_SUCCESS_{...}) if inserted */
} dup_t;

#define POOL_NAME dup_pool
#define POOL_T    dup_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME                           dup_map
#define MAP_ELE_T                          dup_t
#define MAP_KEY                            slot
#define MAP_PREV                           map.prev
#define MAP_NEXT                           map.next
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  dup_dlist
#define DLIST_ELE_T dup_t
#define DLIST_PREV  dlist.prev
#define DLIST_NEXT  dlist.next
#include "../../util/tmpl/fd_dlist.c"

typedef struct {
  ulong key;  /* 32 bits = slot | 32 lsb = fec_set_idx  */
  ulong next; /* pool next */
  struct {
    ulong prev;
    ulong next;
  } map;
  struct {
    ulong prev;
    ulong next;
  } dlist;
  union {
    fd_shred_t shred;
    uchar      bytes[FD_SHRED_MAX_SZ]; /* entire shred, both header and payload */
  };
} fec_t;

#define POOL_NAME fec_pool
#define POOL_T    fec_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME                           fec_map
#define MAP_ELE_T                          fec_t
#define MAP_PREV                           map.prev
#define MAP_NEXT                           map.next
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  fec_dlist
#define DLIST_ELE_T fec_t
#define DLIST_PREV  dlist.prev
#define DLIST_NEXT  dlist.next
#include "../../util/tmpl/fd_dlist.c"

typedef struct {
  ulong       slot;
  fd_pubkey_t from;
} xid_t;

struct prf {
  xid_t key;
  ulong next;
  struct {
    ulong prev;
    ulong next;
  } map;
  struct {
    ulong prev;
    ulong next;
  } dlist;
  uchar idxs; /* [0, 7]. bit vec encoding which of the chunk idxs have been received (at most FD_EQVOC_CHUNK_CNT = 3). */
  ulong buf_sz;
  uchar buf[2 * FD_SHRED_MAX_SZ + 2 * sizeof(ulong)];
};
typedef struct prf prf_t;

#define POOL_NAME prf_pool
#define POOL_T    prf_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME                           prf_map
#define MAP_ELE_T                          prf_t
#define MAP_KEY_T                          xid_t
#define MAP_PREV                           map.prev
#define MAP_NEXT                           map.next
#define MAP_KEY_EQ(k0,k1)                  ((((k0)->slot)==((k1)->slot)) & !(memcmp(((k0)->from.uc),((k1)->from.uc),sizeof(fd_pubkey_t))))
#define MAP_KEY_HASH(key,seed)             fd_ulong_hash( ((key)->slot) ^ ((key)->from.ul[0]) ^ (seed) )
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  prf_dlist
#define DLIST_ELE_T prf_t
#define DLIST_PREV  dlist.prev
#define DLIST_NEXT  dlist.next
#include "../../util/tmpl/fd_dlist.c"

struct vtr {
  fd_pubkey_t from;
  ulong       next; /* pool next; reused as kept flag during update_voters */
  struct {
    ulong prev;
    ulong next;
  } map;
  struct {
    ulong prev;
    ulong next;
  } dlist;
  ulong         prf_dlist_cnt;
  prf_dlist_t * prf_dlist;
};
typedef struct vtr vtr_t;

#define POOL_NAME vtr_pool
#define POOL_T    vtr_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME                           vtr_map
#define MAP_ELE_T                          vtr_t
#define MAP_KEY_T                          fd_pubkey_t
#define MAP_KEY                            from
#define MAP_PREV                           map.prev
#define MAP_NEXT                           map.next
#define MAP_KEY_EQ(k0,k1)                  (!memcmp((k0)->key,(k1)->key,sizeof(fd_pubkey_t)))
#define MAP_KEY_HASH(key,seed)             ((ulong)((key)->ul[1]^(seed)))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  vtr_dlist
#define DLIST_ELE_T vtr_t
#define DLIST_PREV  dlist.prev
#define DLIST_NEXT  dlist.next
#include "../../util/tmpl/fd_dlist.c"

struct fd_eqvoc {

  /* copy */

  ulong dup_max;
  ulong fec_max;
  ulong per_vtr_max;
  ulong vtr_max;

  /* owned */

  fd_sha512_t * sha512;
  void *        bmtree_mem;
  dup_t *       dup_pool;
  dup_map_t *   dup_map;
  dup_dlist_t * dup_dlist;
  fec_t *       fec_pool;
  fec_map_t *   fec_map;
  fec_dlist_t * fec_dlist;
  prf_t *       prf_pool;
  prf_map_t *   prf_map;
  vtr_t *       vtr_pool;
  vtr_map_t *   vtr_map;
  vtr_dlist_t * vtr_dlist;
};
typedef struct fd_eqvoc fd_eqvoc_t;

ulong
fd_eqvoc_align( void ) {
  return 128UL;
}

ulong
fd_eqvoc_footprint( ulong dup_max,
                    ulong fec_max,
                    ulong per_vtr_max,
                    ulong vtr_max ) {

  dup_max          = fd_ulong_pow2_up( dup_max );
  fec_max          = fd_ulong_pow2_up( fec_max );
  ulong prf_max    = per_vtr_max * vtr_max;
  vtr_max          = fd_ulong_pow2_up( vtr_max );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_eqvoc_t),    sizeof(fd_eqvoc_t)                                      );
  l = FD_LAYOUT_APPEND( l, fd_sha512_align(),      fd_sha512_footprint()                                   );
  l = FD_LAYOUT_APPEND( l, FD_BMTREE_COMMIT_ALIGN, FD_BMTREE_COMMIT_FOOTPRINT( FD_SHRED_MERKLE_LAYER_CNT ) );
  l = FD_LAYOUT_APPEND( l, dup_pool_align(),       dup_pool_footprint( dup_max )                           );
  l = FD_LAYOUT_APPEND( l, dup_map_align(),        dup_map_footprint( dup_map_chain_cnt_est( dup_max ) )   );
  l = FD_LAYOUT_APPEND( l, dup_dlist_align(),      dup_dlist_footprint()                                   );
  l = FD_LAYOUT_APPEND( l, fec_pool_align(),       fec_pool_footprint( fec_max )                           );
  l = FD_LAYOUT_APPEND( l, fec_map_align(),        fec_map_footprint( fec_map_chain_cnt_est( fec_max ) )   );
  l = FD_LAYOUT_APPEND( l, fec_dlist_align(),      fec_dlist_footprint()                                   );
  l = FD_LAYOUT_APPEND( l, prf_pool_align(),       prf_pool_footprint( prf_max )                           );
  l = FD_LAYOUT_APPEND( l, prf_map_align(),        prf_map_footprint( prf_map_chain_cnt_est( prf_max ) )   );
  l = FD_LAYOUT_APPEND( l, vtr_pool_align(),       vtr_pool_footprint( vtr_max )                           );
  l = FD_LAYOUT_APPEND( l, vtr_map_align(),        vtr_map_footprint( vtr_map_chain_cnt_est( vtr_max ) )   );
  l = FD_LAYOUT_APPEND( l, vtr_dlist_align(),      vtr_dlist_footprint()                                   );
  for( ulong i = 0UL; i < vtr_max; i++ ) {
    l = FD_LAYOUT_APPEND( l, prf_dlist_align(), prf_dlist_footprint() );
  }
  return FD_LAYOUT_FINI( l, fd_eqvoc_align() );
}

void *
fd_eqvoc_new( void * shmem,
              ulong  dup_max,
              ulong  fec_max,
              ulong  per_vtr_max,
              ulong  vtr_max,
              ulong  seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_eqvoc_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_eqvoc_footprint( dup_max, fec_max, per_vtr_max, vtr_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad dup_max (%lu), fec_max (%lu), or vtr_max (%lu)", dup_max, fec_max, vtr_max ));
    return NULL;
  }

  dup_max          = fd_ulong_pow2_up( dup_max );
  fec_max          = fd_ulong_pow2_up( fec_max );
  vtr_max          = fd_ulong_pow2_up( vtr_max );
  ulong prf_max    = per_vtr_max * vtr_max;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  void * eqvoc_mem  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_eqvoc_t),    sizeof(fd_eqvoc_t)                                      );
  void * sha512     = FD_SCRATCH_ALLOC_APPEND( l, fd_sha512_align(),      fd_sha512_footprint()                                   );
  void * bmtree_mem = FD_SCRATCH_ALLOC_APPEND( l, FD_BMTREE_COMMIT_ALIGN, FD_BMTREE_COMMIT_FOOTPRINT( FD_SHRED_MERKLE_LAYER_CNT ) );
  void * dup_pool   = FD_SCRATCH_ALLOC_APPEND( l, dup_pool_align(),       dup_pool_footprint( dup_max )                           );
  void * dup_map    = FD_SCRATCH_ALLOC_APPEND( l, dup_map_align(),        dup_map_footprint( dup_map_chain_cnt_est( dup_max ) )   );
  void * dup_dlist  = FD_SCRATCH_ALLOC_APPEND( l, dup_dlist_align(),      dup_dlist_footprint()                                   );
  void * fec_pool   = FD_SCRATCH_ALLOC_APPEND( l, fec_pool_align(),       fec_pool_footprint( fec_max )                           );
  void * fec_map    = FD_SCRATCH_ALLOC_APPEND( l, fec_map_align(),        fec_map_footprint( fec_map_chain_cnt_est( fec_max ) )   );
  void * fec_dlist  = FD_SCRATCH_ALLOC_APPEND( l, fec_dlist_align(),      fec_dlist_footprint()                                   );
  void * prf_pool   = FD_SCRATCH_ALLOC_APPEND( l, prf_pool_align(),       prf_pool_footprint( prf_max )                           );
  void * prf_map    = FD_SCRATCH_ALLOC_APPEND( l, prf_map_align(),        prf_map_footprint( prf_map_chain_cnt_est( prf_max ) )   );
  void * vtr_pool   = FD_SCRATCH_ALLOC_APPEND( l, vtr_pool_align(),       vtr_pool_footprint( vtr_max )                           );
  void * vtr_map    = FD_SCRATCH_ALLOC_APPEND( l, vtr_map_align(),        vtr_map_footprint( vtr_map_chain_cnt_est( vtr_max ) )   );
  void * vtr_dlist  = FD_SCRATCH_ALLOC_APPEND( l, vtr_dlist_align(),      vtr_dlist_footprint()                                   );

  fd_eqvoc_t * eqvoc = (fd_eqvoc_t *)eqvoc_mem;
  eqvoc->dup_max     = dup_max;
  eqvoc->fec_max     = fec_max;
  eqvoc->per_vtr_max = per_vtr_max;
  eqvoc->vtr_max     = vtr_max;

  eqvoc->sha512     = fd_sha512_new( sha512                                            );
  eqvoc->bmtree_mem = bmtree_mem;
  eqvoc->dup_pool   = dup_pool_new ( dup_pool, dup_max                                 );
  eqvoc->dup_map    = dup_map_new  ( dup_map,  dup_map_chain_cnt_est( dup_max ),  seed );
  eqvoc->dup_dlist  = dup_dlist_new( dup_dlist                                         );
  eqvoc->fec_pool   = fec_pool_new ( fec_pool, fec_max                                 );
  eqvoc->fec_map    = fec_map_new  ( fec_map,  fec_map_chain_cnt_est( fec_max ),  seed );
  eqvoc->fec_dlist  = fec_dlist_new( fec_dlist                                         );
  eqvoc->prf_pool   = prf_pool_new ( prf_pool, prf_max                                 );
  eqvoc->prf_map    = prf_map_new  ( prf_map,  prf_map_chain_cnt_est( prf_max ),  seed );
  eqvoc->vtr_pool   = vtr_pool_new ( vtr_pool, vtr_max                                 );
  eqvoc->vtr_map    = vtr_map_new  ( vtr_map,  vtr_map_chain_cnt_est( vtr_max ),  seed );
  eqvoc->vtr_dlist  = vtr_dlist_new( vtr_dlist                                         );

  vtr_t * pool_join = vtr_pool_join( eqvoc->vtr_pool );
  for( ulong i = 0UL; i < vtr_max; i++ ) {
    void * prf_dlist       = FD_SCRATCH_ALLOC_APPEND( l, prf_dlist_align(), prf_dlist_footprint() );
    pool_join[i].prf_dlist_cnt = 0;
    pool_join[i].prf_dlist     = prf_dlist_new( prf_dlist );
  }
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_eqvoc_align() )==(ulong)shmem + footprint );

  return shmem;
}

fd_eqvoc_t *
fd_eqvoc_join( void * sheqvoc ) {

  if( FD_UNLIKELY( !sheqvoc ) ) {
    FD_LOG_WARNING(( "NULL eqvoc" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)sheqvoc, fd_eqvoc_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned eqvoc" ));
    return NULL;
  }

  fd_eqvoc_t * eqvoc = (fd_eqvoc_t *)sheqvoc;
  eqvoc->sha512      = fd_sha512_join( eqvoc->sha512    );
  /* bmtree */
  eqvoc->dup_pool    = dup_pool_join ( eqvoc->dup_pool  );
  eqvoc->dup_map     = dup_map_join  ( eqvoc->dup_map   );
  eqvoc->dup_dlist   = dup_dlist_join( eqvoc->dup_dlist );
  eqvoc->fec_pool    = fec_pool_join ( eqvoc->fec_pool  );
  eqvoc->fec_map     = fec_map_join  ( eqvoc->fec_map   );
  eqvoc->fec_dlist   = fec_dlist_join( eqvoc->fec_dlist );
  eqvoc->prf_pool    = prf_pool_join ( eqvoc->prf_pool  );
  eqvoc->prf_map     = prf_map_join  ( eqvoc->prf_map   );
  eqvoc->vtr_pool    = vtr_pool_join ( eqvoc->vtr_pool  );
  eqvoc->vtr_map     = vtr_map_join  ( eqvoc->vtr_map   );
  eqvoc->vtr_dlist   = vtr_dlist_join( eqvoc->vtr_dlist );
  for( ulong i = 0UL; i < eqvoc->vtr_max; i++ ) {
    eqvoc->vtr_pool[i].prf_dlist = prf_dlist_join( eqvoc->vtr_pool[i].prf_dlist );
  }

  return (fd_eqvoc_t *)sheqvoc;
}

void *
fd_eqvoc_leave( fd_eqvoc_t const * eqvoc ) {

  if( FD_UNLIKELY( !eqvoc ) ) {
    FD_LOG_WARNING(( "NULL eqvoc" ));
    return NULL;
  }

  return (void *)eqvoc;
}

void *
fd_eqvoc_delete( void * eqvoc ) {

  if( FD_UNLIKELY( !eqvoc ) ) {
    FD_LOG_WARNING(( "NULL eqvoc" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)eqvoc, fd_eqvoc_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned eqvoc" ));
    return NULL;
  }

  return eqvoc;
}

static dup_t *
dup_query( fd_eqvoc_t * eqvoc,
           ulong        slot ) {
  dup_t * dup = dup_map_ele_query( eqvoc->dup_map, &slot, NULL, eqvoc->dup_pool );
  if( FD_LIKELY( dup ) ) {
    dup_dlist_ele_remove( eqvoc->dup_dlist, dup, eqvoc->dup_pool );
    dup_dlist_ele_push_tail( eqvoc->dup_dlist, dup, eqvoc->dup_pool );
  }
  return dup;
}

static fec_t *
fec_query( fd_eqvoc_t * eqvoc,
           ulong        slot,
           ulong        fec_set_idx ) {
  ulong   key = slot << 32 | fec_set_idx;
  fec_t * fec = fec_map_ele_query( eqvoc->fec_map, &key, NULL, eqvoc->fec_pool );
  if( FD_LIKELY( fec ) ) {
    fec_dlist_ele_remove( eqvoc->fec_dlist, fec, eqvoc->fec_pool );
    fec_dlist_ele_push_tail( eqvoc->fec_dlist, fec, eqvoc->fec_pool );
  }
  return fec;
}

static prf_t *
prf_query( fd_eqvoc_t * eqvoc,
           vtr_t *      vtr,
           ulong        slot ) {
  xid_t   key = { .slot = slot, .from = vtr->from };
  prf_t * prf = prf_map_ele_query( eqvoc->prf_map, &key, NULL, eqvoc->prf_pool );
  if( FD_LIKELY( prf ) ) {
    prf_dlist_ele_remove( vtr->prf_dlist, prf, eqvoc->prf_pool );
    prf_dlist_ele_push_tail( vtr->prf_dlist, prf, eqvoc->prf_pool );
  }
  return prf;
}

static dup_t *
dup_insert( fd_eqvoc_t       * eqvoc,
            ulong              slot ) {

  /* FIFO evict if full.  Invariant: iff in dlist then in map / pool. */

  if( FD_UNLIKELY( !dup_pool_free( eqvoc->dup_pool ) ) ) {
    dup_t * dup = dup_dlist_ele_pop_head( eqvoc->dup_dlist, eqvoc->dup_pool );
    dup_map_ele_remove_fast( eqvoc->dup_map, dup, eqvoc->dup_pool );
    dup_pool_ele_release( eqvoc->dup_pool, dup );
  }

  /* Insert.  Invariant: pool free => map / dlist free. */

  dup_t * dup = dup_pool_ele_acquire( eqvoc->dup_pool );
  dup->slot   = slot;
  dup_map_ele_insert( eqvoc->dup_map, dup, eqvoc->dup_pool );
  dup_dlist_ele_push_tail( eqvoc->dup_dlist, dup, eqvoc->dup_pool );
  return dup;
}

static fec_t *
fec_insert( fd_eqvoc_t * eqvoc,
            ulong        slot,
            uint         fec_set_idx ) {

  ulong key = slot << 32 | fec_set_idx;

  /* FIFO evict if full.  Invariant: iff in dlist then in map / pool. */

  if( FD_UNLIKELY( !fec_pool_free( eqvoc->fec_pool ) ) ) {
    fec_t * fec = fec_dlist_ele_pop_head( eqvoc->fec_dlist, eqvoc->fec_pool );
    fec_map_ele_remove_fast( eqvoc->fec_map, fec, eqvoc->fec_pool );
    fec_pool_ele_release( eqvoc->fec_pool, fec );
  }

  /* Insert.  Invariant: pool free => map / dlist free. */

  fec_t * fec = fec_pool_ele_acquire( eqvoc->fec_pool );
  fec->key    = key;
  fec_map_ele_insert( eqvoc->fec_map, fec, eqvoc->fec_pool );
  fec_dlist_ele_push_tail( eqvoc->fec_dlist, fec, eqvoc->fec_pool );
  return fec;
}

static prf_t *
prf_insert( fd_eqvoc_t *        eqvoc,
            ulong               slot,
            fd_pubkey_t const * from ) {

  vtr_t * vtr = vtr_map_ele_query( eqvoc->vtr_map, from, NULL, eqvoc->vtr_pool );
  FD_TEST( vtr );

  /* Each from pubkey in gossip is limited to per_vtr_max proofs.
     If we receive more than per_vtr_max from one pubkey, FIFO evict.
     We group by pubkey to prevent a single pubkey from spamming
     junk proofs. */

  if( FD_UNLIKELY( vtr->prf_dlist_cnt==eqvoc->per_vtr_max ) ) {
    prf_t * evict = prf_dlist_ele_pop_head( vtr->prf_dlist, eqvoc->prf_pool );
    prf_map_ele_remove_fast( eqvoc->prf_map, evict, eqvoc->prf_pool );
    prf_pool_ele_release( eqvoc->prf_pool, evict );
    vtr->prf_dlist_cnt--;
  }

  xid_t   key = { .slot = slot, .from = *from };
  prf_t * prf = prf_pool_ele_acquire( eqvoc->prf_pool );
  prf->key    = key;
  prf->idxs   = 0;
  prf->buf_sz = 0;
  prf_map_ele_insert( eqvoc->prf_map, prf, eqvoc->prf_pool );
  prf_dlist_ele_push_tail( vtr->prf_dlist, prf, eqvoc->prf_pool );
  vtr->prf_dlist_cnt++;
  return prf;
}

static int
is_last_shred( fd_shred_t const * shred ) {
  return fd_shred_is_data( fd_shred_type( shred->variant ) ) && shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE;
}

/* construct_proof constructs a DuplicateShred proof from shred1 and
   shred2.  Assumes shred1 and shred2 have already been verified via
   verify_proof.  On return, chunks_out will be populated with the
   serialized format of the proof.

   [ shred1_sz (8 bytes) | shred1 | shred2_sz (8 bytes) | shred2 ]

   Caller supplies `chunks_out`, which is an array that MUST contain
   FD_EQVOC_CHUNK_CNT elements. */

static void
construct_proof( fd_shred_t const *          shred1,
                 fd_shred_t const *          shred2,
                 fd_gossip_duplicate_shred_t chunks_out[static FD_EQVOC_CHUNK_CNT] ) {

  for (uchar i = 0; i < FD_EQVOC_CHUNK_CNT; i++ ) {
    chunks_out[i].index       = i;
    chunks_out[i].slot        = shred1->slot;
    chunks_out[i].num_chunks  = FD_EQVOC_CHUNK_CNT;
    chunks_out[i].chunk_index = i;
  }

  ulong shred1_sz = fd_shred_sz( shred1 );
  ulong shred2_sz = fd_shred_sz( shred2 );

  /* Populate chunk0 */

  FD_STORE( ulong, chunks_out[0].chunk, shred1_sz );
  memcpy( chunks_out[0].chunk + sizeof(ulong), shred1, FD_EQVOC_CHUNK_SZ - sizeof(ulong) );
  chunks_out[0].chunk_len = FD_EQVOC_CHUNK_SZ;

  /* Populate chunk1 */

  ulong shred1_off = FD_EQVOC_CHUNK_SZ - sizeof(ulong);
  ulong shred1_rem = shred1_sz - shred1_off;
  memcpy( chunks_out[1].chunk, (uchar *)shred1 + shred1_off, shred1_rem );
  FD_STORE( ulong, chunks_out[1].chunk + shred1_rem, shred2_sz );
  ulong chunk1_off = shred1_rem + sizeof(ulong);
  ulong chunk1_rem = FD_EQVOC_CHUNK_SZ - chunk1_off;
  memcpy( chunks_out[1].chunk + chunk1_off, shred2, chunk1_rem );
  chunks_out[1].chunk_len = FD_EQVOC_CHUNK_SZ;

  /* Populate chunk2 */

  ulong shred2_off = chunk1_rem;
  ulong shred2_rem = shred2_sz - shred2_off;
  memcpy( chunks_out[2].chunk, (uchar *)shred2 + shred2_off, shred2_rem );
  chunks_out[2].chunk_len = shred2_rem;
}

/* verify_proof verifies that the two shreds contained in `proof` do in
   fact equivocate.

   Returns: FD_EQVOC_SUCCESS if no effect
            FD_EQVOC_SUCCESS_{...} if they do
            FD_EQVOC_ERR_{...} if the shreds were not valid inputs

   The implementation mirrors the Agave version very closely. See: https://github.com/anza-xyz/agave/blob/v3.1/gossip/src/duplicate_shred.rs#L137-L142

   Two shreds equivocate if they satisfy any of the following:

   1. Both shreds specify the same index and shred type, however their
      payloads differ.
   2. Both shreds specify the same FEC set, however their merkle roots
      differ.
   3. Both shreds specify the same FEC set and are coding shreds,
      however their erasure configs conflict.
   4. The shreds specify different FEC sets, the lower index shred is a
      coding shred, and its erasure meta indicates an FEC set overlap.
   5. The shreds specify different FEC sets, the lower index shred has a
      merkle root that is not equal to the chained merkle root of the
      higher index shred.
   6. The shreds are data shreds with different indices and the shred
      with the lower index has the LAST_SHRED_IN_SLOT flag set.

   Ref: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0204-slashable-event-verification.md#proof-verification

   Note: two shreds are in the same FEC set if they have the same verified
   and FEC set index.

   To prevent false positives, this function also performs the following
   input validation on the shreds:

   1. shred1 and shred2 are for the same verified.
   2. shred1 and shred2 are both the expected shred_version.
   3. shred1 and shred2 are either chained merkle or chained resigned
      merkle variants.
   4. shred1 and shred2 contain valid signatures signed by the same
      producer pubkey.

   If any of the above input validation fails, this function returns
   FD_EQVOC_ERR_{...}.

   The validation does duplicate some of what's in the shred tile, but
   because this proof is sourced from gossip (which doesn't go through
   shred) we have to also do it. */

static int
verify_proof( fd_eqvoc_t const *         eqvoc,
              ushort                     shred_version,
              fd_epoch_leaders_t const * leader_schedule,
              fd_shred_t const *         shred1,
              fd_shred_t const *         shred2 ) {

  /* A valid duplicate proof must have shreds for the same slot. */

  if( FD_UNLIKELY( shred1->slot != shred2->slot ) ) return FD_EQVOC_ERR_SLOT;

  /* We only process proofs for the current shred version. */

  if( FD_UNLIKELY( shred1->version != shred_version ) ) return FD_EQVOC_ERR_VERSION;
  if( FD_UNLIKELY( shred2->version != shred_version ) ) return FD_EQVOC_ERR_VERSION;

  /* Dropping non-CMR shreds has been activated on mainnet, so we ignore
     any proofs containing non-CMR shreds. Currently Agave does not have
     an equivalent check. */

  if( FD_UNLIKELY( !fd_shred_is_chained ( fd_shred_type( shred1->variant ) ) &&
                   !fd_shred_is_resigned( fd_shred_type( shred1->variant ) ) ) ) {
    return FD_EQVOC_ERR_TYPE;
  }
  if( FD_UNLIKELY( !fd_shred_is_chained ( fd_shred_type( shred2->variant ) ) &&
                   !fd_shred_is_resigned( fd_shred_type( shred2->variant ) ) ) ) {
    return FD_EQVOC_ERR_TYPE;
  }

  /* Check both shreds contain valid signatures from the assigned leader
     to that verified. This requires deriving the merkle root and
     sig-verifying it, because the leader signs the merkle root for
     merkle shreds. */

  fd_bmtree_node_t root1;
  if( FD_UNLIKELY( !fd_shred_merkle_root( shred1, eqvoc->bmtree_mem, &root1 ) ) ) return FD_EQVOC_ERR_MERKLE;

  fd_bmtree_node_t root2;
  if( FD_UNLIKELY( !fd_shred_merkle_root( shred2, eqvoc->bmtree_mem, &root2 ) ) ) return FD_EQVOC_ERR_MERKLE;

  fd_pubkey_t const * leader = fd_epoch_leaders_get( leader_schedule, shred1->slot );
  if( FD_UNLIKELY( !leader ) ) return FD_EQVOC_ERR_SIG;
  FD_BASE58_ENCODE_32_BYTES( leader->uc, leader_b58 );

  fd_sha512_t _sha512[1];
  fd_sha512_t * sha512 = fd_sha512_join( fd_sha512_new( _sha512 ) );
  if( FD_UNLIKELY( FD_ED25519_SUCCESS != fd_ed25519_verify( root1.hash, 32UL, shred1->signature, leader->uc, sha512 ) ||
                   FD_ED25519_SUCCESS != fd_ed25519_verify( root2.hash, 32UL, shred2->signature, leader->uc, sha512 ) ) ) {
    return FD_EQVOC_ERR_SIG;
  }

  /* If both are data shreds, then check if one is marked the last shred
     in the verified and the other is a higher shred idx than that one. */

  if( FD_LIKELY( fd_shred_is_data( fd_shred_type( shred1->variant ) ) && fd_shred_is_data( fd_shred_type( shred2->variant ) ) ) ) {
    if( FD_LIKELY( ( shred1->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE && shred2->idx > shred1->idx ) ||
                   ( shred2->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE && shred1->idx > shred2->idx ) ) ) {
      return FD_EQVOC_SUCCESS_LAST;
    }
  }

  /* TODO remove below with fixed-32 */

  if( FD_UNLIKELY( shred1->fec_set_idx != shred2->fec_set_idx ) ) {

    /* Different FEC set index checks. Lower FEC set index shred must be a
      coding shred. */

    fd_shred_t const * lo = fd_ptr_if( shred1->fec_set_idx < shred2->fec_set_idx, shred1, shred2 );
    fd_shred_t const * hi = fd_ptr_if( shred1->fec_set_idx > shred2->fec_set_idx, shred1, shred2 );

    if( FD_UNLIKELY( fd_shred_is_code( fd_shred_type( lo->variant ) ) ) ) {

      /* Test for overlap. The FEC sets overlap if the lower fec_set_idx +
        data_cnt > higher fec_set_idx. We must have received at least one
        coding shred in the FEC set with the lower fec_set_idx to perform
        this check. */

      if( FD_UNLIKELY( lo->fec_set_idx + lo->code.data_cnt > hi->fec_set_idx ) ) {
        return FD_EQVOC_SUCCESS_OVERLAP;
      }

      /* Test for conflicting chained merkle roots when shred1 and shred2
        are in adjacent FEC sets. We know the FEC sets are adjacent if the
        last data shred index in the lower FEC set is one less than the
        first data shred index in the higher FEC set. */

      if( FD_UNLIKELY( lo->fec_set_idx + lo->code.data_cnt == hi->fec_set_idx ) ) {
        uchar * merkle_hash  = fd_ptr_if( shred1->fec_set_idx < shred2->fec_set_idx,
                                          (uchar *)shred1 + fd_shred_merkle_off( shred1 ),
                                          (uchar *)shred2 + fd_shred_merkle_off( shred2 ) );
        uchar * chained_hash = fd_ptr_if( shred1->fec_set_idx > shred2->fec_set_idx,
                                          (uchar *)shred1 + fd_shred_chain_off( shred1->variant ),
                                          (uchar *)shred2 + fd_shred_chain_off( shred2->variant ) );
        if( FD_LIKELY( 0!=memcmp( merkle_hash, chained_hash, FD_SHRED_MERKLE_ROOT_SZ ) ) ) {
          return FD_EQVOC_SUCCESS_CHAINED;
        }
      }
    }
    return FD_EQVOC_SUCCESS; /* these shreds in different FEC sets do not prove equivocation */
  }

  /* At this point, the two shreds are in the same FEC set. */

  /* If two shreds in the same FEC set have different merkle roots, they
     equivocate. */

  if( FD_LIKELY( 0!=memcmp( root1.hash, root2.hash, sizeof(root1.hash)) ) ) {
    return FD_EQVOC_SUCCESS_MERKLE;
  }

  /* Remaining checks require the two shreds to be the same type. */

  if( FD_UNLIKELY( fd_shred_type( shred1->variant )!=fd_shred_type( shred2->variant ) ) ) {
    return FD_EQVOC_SUCCESS;
  }

  /* Agave does a payload comparison if two shreds have the same index,
     but it's not necessary for us to do the same because we only
     process merkle shreds (see first conditional in this function).
     You can't generate the same merkle root from different payloads for
     the same leaf in the tree. */

  if( FD_UNLIKELY( shred1->idx==shred2->idx ) ) {
    return FD_EQVOC_SUCCESS;
  }

  /* If both are coding shreds, then check if they have the same meta.
     TODO fixed-32 remove. */

  if( FD_LIKELY( fd_shred_is_code( fd_shred_type( shred1->variant ) ) &&
                 ( shred1->code.code_cnt != shred2->code.code_cnt ||
                   shred1->code.data_cnt != shred2->code.data_cnt ||
                   shred1->idx - shred1->code.idx == shred2->idx - shred2->code.idx ) ) ) {
    return FD_EQVOC_SUCCESS_META;
  }

  /* Shreds do not prove equivocation. */

  return FD_EQVOC_SUCCESS;
}

int
fd_eqvoc_shred_insert( fd_eqvoc_t *                eqvoc,
                       ushort                      shred_version,
                       ulong                       root,
                       fd_epoch_leaders_t const *  leader_schedule,
                       fd_shred_t const *          shred,
                       fd_gossip_duplicate_shred_t chunks_out[static FD_EQVOC_CHUNK_CNT] ) {

  if( FD_UNLIKELY( !leader_schedule || shred->slot < root ) ) return FD_EQVOC_ERR_IGNORED_SLOT;

  /* Short-circuit if we already know this shred equivocates. */

  ulong   slot = shred->slot;
  dup_t * dup  = dup_query( eqvoc, slot );
  if( FD_UNLIKELY( dup && dup->err > FD_EQVOC_SUCCESS ) ) return FD_EQVOC_SUCCESS; /* already verified this slot equivocates */

  /* For FD_EQVOC_SUCCESS_LAST we specially index a key for the last
     shred in a slot.  If we get two shreds for the same slot but
     different index that are both marked last, that is a conflict. */

  if( FD_UNLIKELY( is_last_shred( shred ) ) ) {
    fec_t * last = fec_query( eqvoc, shred->slot, UINT_MAX );
    if( FD_LIKELY( !last ) ) {
      last = fec_insert( eqvoc, slot, UINT_MAX );
      fd_memcpy( &last->shred, shred, fd_shred_sz( shred ) ); /* shred is already validated */
    }
    if( FD_UNLIKELY( shred->idx!=last->shred.idx ) ) {
      construct_proof( shred, &last->shred, chunks_out );
      dup_t * dup = dup_insert( eqvoc, slot );
      dup->err    = FD_EQVOC_SUCCESS_LAST;
      return FD_EQVOC_SUCCESS_LAST;
    }
  }

  /* Every other equivocation check except FD_EQVOC_SUCCESS_LAST above
     is based on conflicts between two shreds within the same FEC set,
     so we index shreds by a composite key of 32 msb slot and 32 lsb
     fec_set_idx to compare sibling shreds in the same FEC set. */

  fec_t * fec = fec_query( eqvoc, shred->slot, shred->fec_set_idx );
  if( FD_UNLIKELY( !fec ) ) { /* no sibling yet, so nothing more to do */
    fec = fec_insert( eqvoc, shred->slot, shred->fec_set_idx );
    fd_memcpy( &fec->shred, shred, fd_shred_sz( shred ) ); /* shred is already validated */
    return FD_EQVOC_SUCCESS;
  }

  /* Verify if the shred equivocates and construct a proof if so. */

  int err = verify_proof( eqvoc, shred_version, leader_schedule, &fec->shred, shred );
  if( FD_UNLIKELY( err>FD_EQVOC_SUCCESS ) ) {
    construct_proof( &fec->shred, shred, chunks_out );
    dup_t * dup = dup_insert( eqvoc, slot );
    dup->err    = err;
    fec_dlist_ele_remove( eqvoc->fec_dlist, fec, eqvoc->fec_pool );
    fec_map_ele_remove_fast( eqvoc->fec_map, fec, eqvoc->fec_pool );
    fec_pool_ele_release( eqvoc->fec_pool, fec );
  }
  return err;
}

int
fd_eqvoc_chunk_insert( fd_eqvoc_t                        * eqvoc,
                       ushort                              shred_version,
                       ulong                               root,
                       fd_epoch_leaders_t const          * leader_schedule,
                       fd_pubkey_t const                 * from,
                       fd_gossip_duplicate_shred_t const * chunk,
                       fd_gossip_duplicate_shred_t         chunks_out[static FD_EQVOC_CHUNK_CNT] ) {

  if( FD_UNLIKELY( !leader_schedule || chunk->slot < root ) ) return FD_EQVOC_ERR_IGNORED_SLOT;

  vtr_t * vtr = vtr_map_ele_query( eqvoc->vtr_map, from, NULL, eqvoc->vtr_pool );
  if( FD_UNLIKELY( !vtr ) ) return FD_EQVOC_ERR_IGNORED_FROM;

  if( FD_UNLIKELY( chunk->num_chunks !=FD_EQVOC_CHUNK_CNT ) ) return FD_EQVOC_ERR_CHUNK_CNT;
  if( FD_UNLIKELY( chunk->chunk_index>=FD_EQVOC_CHUNK_CNT ) ) return FD_EQVOC_ERR_CHUNK_IDX;

  if( FD_UNLIKELY( chunk->chunk_index==0 && chunk->chunk_len!=FD_EQVOC_CHUNK0_LEN    ) ) return FD_EQVOC_ERR_CHUNK_LEN;
  if( FD_UNLIKELY( chunk->chunk_index==1 && chunk->chunk_len!=FD_EQVOC_CHUNK1_LEN    ) ) return FD_EQVOC_ERR_CHUNK_LEN;
  if( FD_UNLIKELY( chunk->chunk_index==2 && chunk->chunk_len!=FD_EQVOC_CHUNK2_LEN_CC &&
                                            chunk->chunk_len!=FD_EQVOC_CHUNK2_LEN_DD &&
                                            chunk->chunk_len!=FD_EQVOC_CHUNK2_LEN_DC &&
                                            chunk->chunk_len!=FD_EQVOC_CHUNK2_LEN_CD ) ) return FD_EQVOC_ERR_CHUNK_LEN;

  dup_t * dup = dup_query( eqvoc, chunk->slot );
  if( FD_UNLIKELY( dup && dup->err > FD_EQVOC_SUCCESS ) ) return FD_EQVOC_SUCCESS; /* already verified an equivocation proof for this slot */

  prf_t * prf = prf_query( eqvoc, vtr, chunk->slot );
  if( FD_UNLIKELY( !prf ) ) prf = prf_insert( eqvoc, chunk->slot, from );
  if( FD_UNLIKELY( fd_uchar_extract_bit( prf->idxs, chunk->chunk_index ) ) ) return FD_EQVOC_SUCCESS; /* already processed chunk */
  fd_memcpy( prf->buf + chunk->chunk_index * FD_EQVOC_CHUNK_SZ, chunk->chunk, chunk->chunk_len );
  prf->buf_sz += chunk->chunk_len;
  prf->idxs = fd_uchar_set_bit( prf->idxs, chunk->chunk_index );
  if( FD_UNLIKELY( prf->idxs!=(1 << FD_EQVOC_CHUNK_CNT) - 1 ) ) return FD_EQVOC_SUCCESS; /* not all chunks received yet */

  int err = FD_EQVOC_ERR_SERDE; ulong off = 0;

  if( FD_UNLIKELY( prf->buf_sz - off < sizeof(ulong) ) ) goto cleanup;
  ulong shred1_sz = fd_ulong_load_8( prf->buf );
  off += sizeof(ulong);

  if( FD_UNLIKELY( prf->buf_sz - off < shred1_sz ) ) goto cleanup;
  fd_shred_t const * shred1 = fd_shred_parse( prf->buf + off, shred1_sz );
  if( FD_UNLIKELY( !shred1 || fd_shred_sz( shred1 )!=shred1_sz ) ) goto cleanup; /* check the sz matches parsed shred's type */
  off += shred1_sz;

  if( FD_UNLIKELY( prf->buf_sz - off < sizeof(ulong) ) ) goto cleanup;
  ulong shred2_sz = fd_ulong_load_8( prf->buf + off );
  off += sizeof(ulong);

  if( FD_UNLIKELY( prf->buf_sz - off < shred2_sz ) ) goto cleanup;
  fd_shred_t const * shred2 = fd_shred_parse( prf->buf + off, shred2_sz );
  if( FD_UNLIKELY( !shred2 || fd_shred_sz( shred2 )!=shred2_sz ) ) goto cleanup; /* check the sz matches parsed shred's type */
  off += shred2_sz;

  if( FD_UNLIKELY( off!=prf->buf_sz ) ) goto cleanup;

  err = verify_proof( eqvoc, shred_version, leader_schedule, shred1, shred2 );
  if( FD_UNLIKELY( err > FD_EQVOC_SUCCESS ) ) {
    construct_proof( shred1, shred2, chunks_out );
    dup_t * dup = dup_insert( eqvoc, chunk->slot );
    dup->err    = err;
  }

cleanup:;
  prf_dlist_ele_remove( vtr->prf_dlist, prf, eqvoc->prf_pool );
  prf_map_ele_remove_fast( eqvoc->prf_map, prf, eqvoc->prf_pool );
  prf_pool_ele_release( eqvoc->prf_pool, prf );
  vtr->prf_dlist_cnt--;
  return err;
}

void
fd_eqvoc_update_voters( fd_eqvoc_t *              eqvoc,
                        fd_tower_voters_t const * tower_voters ) {

  for( vtr_dlist_iter_t iter = vtr_dlist_iter_fwd_init( eqvoc->vtr_dlist, eqvoc->vtr_pool );
       !vtr_dlist_iter_done( iter, eqvoc->vtr_dlist, eqvoc->vtr_pool );
       iter = vtr_dlist_iter_fwd_next( iter, eqvoc->vtr_dlist, eqvoc->vtr_pool ) ) {
    eqvoc->vtr_pool[iter].next = 1; /* mark for removal */
  }

  /* Move all voters in the new tower_voters set to the back of the
     dlist.  We mark them by setting their `next` field to null. */

  for( fd_tower_voters_iter_t iter = fd_tower_voters_iter_init( tower_voters );
                                    !fd_tower_voters_iter_done( tower_voters, iter );
                              iter = fd_tower_voters_iter_next( tower_voters, iter ) ) {
    fd_pubkey_t const * id  = &fd_tower_voters_iter_ele_const( tower_voters, iter )->id_key;
    vtr_t *             vtr = vtr_map_ele_query( eqvoc->vtr_map, id, NULL, eqvoc->vtr_pool );
    if( FD_UNLIKELY( !vtr ) ) {
      vtr                = vtr_pool_ele_acquire( eqvoc->vtr_pool );
      vtr->from          = *id;
      vtr->prf_dlist_cnt = 0;
      vtr_map_ele_insert( eqvoc->vtr_map, vtr, eqvoc->vtr_pool );
    } else {
      vtr_dlist_ele_remove( eqvoc->vtr_dlist, vtr, eqvoc->vtr_pool );
    }
    vtr->next = 0; /* unmark for removal */
    vtr_dlist_ele_push_tail( eqvoc->vtr_dlist, vtr, eqvoc->vtr_pool );
  }

  /* Pop unwanted voters from the head until we hit a kept voter. */

  while( FD_LIKELY( !vtr_dlist_is_empty( eqvoc->vtr_dlist, eqvoc->vtr_pool ) ) ) {
    vtr_t * vtr = vtr_dlist_ele_pop_head( eqvoc->vtr_dlist, eqvoc->vtr_pool );
    if( FD_UNLIKELY( !vtr->next ) ) { /* can short-circuit since all the existing and new voters were appended */
      vtr_dlist_ele_push_tail( eqvoc->vtr_dlist, vtr, eqvoc->vtr_pool );
      break;
    }
    while( FD_LIKELY( !prf_dlist_is_empty( vtr->prf_dlist, eqvoc->prf_pool ) ) ) {
      prf_t * prf = prf_dlist_ele_pop_head( vtr->prf_dlist, eqvoc->prf_pool );
      prf_map_ele_remove_fast( eqvoc->prf_map, prf, eqvoc->prf_pool );
      prf_pool_ele_release( eqvoc->prf_pool, prf );
    }
    vtr_map_ele_remove_fast( eqvoc->vtr_map, vtr, eqvoc->vtr_pool );
    vtr_pool_ele_release( eqvoc->vtr_pool, vtr );
  }
}
