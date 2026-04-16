#include "fd_hfork.h"

/* fd_hfork maintains four pools and four maps:

   bhm_pool (capacity max = per_vtr_max * vtr_max): pool of bhm_t
            elements, where bhm stands for "bank hash matcher".  Each
            bhm tracks the aggregate stake and vote count for a
            particular (block_id, bank_hash) pair.

   bhm_map  (capacity max): maps bhm_key_t (block_id, bank_hash) ->
            bhm_t for O(1) lookup of a specific bank hash matcher.

   blk_pool (capacity max): pool of blk_t elements.  Each blk_t stores
            per-block metadata (our_bank_hash, replayed, dead, matched,
            mismatched, checked) and owns a bhm_dlist of all bhm entries sharing the
            same block_id.

   blk_map  (capacity max): maps block_id -> blk_t for O(1) lookup of
            per-block metadata.

   vte_pool (capacity max): pool of vte_t elements.  Each vte
            records a single vote (block_id, bank_hash, slot, stake)
            from a voter, stored in that voter's vte_dlist.  When a
            voter's vte_dlist reaches per_vtr_max entries, the oldest vte
            is popped and its stake contribution is subtracted from
            the corresponding bhm.

   vte_map  (capacity max): maps vte_key_t (addr, block_id) -> vte_t
            for O(1) check of whether a voter has already voted for a
            given block_id.  If they have, the vote is ignored.

   vtr_map  (capacity vtr_max): maps addr -> vtr_t, tracking each
            known voter.  vtr entries are explicitly managed by
            fd_hfork_update_voters when the epoch stake set changes.
            Each vtr has a pre-allocated vte_dlist that tracks the
            voter's recent votes in FIFO order.

            vtr_map                        blk_map
     map[0] +--------------------+  map[0] +--------------------+
            | (vtr_t) {          |         | (blk_t) {          |
            |   .addr  = X,      |         |   .block_id  = A,  |
            |   ...              |         |   ...              |
            |   .vte_dlist = ... |         |   .bhm_dlist = ... |
            | }                  |         | }                  |
     map[1] +--------------------+  map[1] +--------------------+
            | (vtr_t) {          |         | (blk_t) {          |
            |   .addr  = Y,      |         |   .block_id = B    |
            |   ...              |         |   ...              |
            |   .vte_dlist = +   |         |   .bhm_dlist = +   |
            | }              |   |         | }              |   |
            +----------------|---+         +----------------|---+                |
                             |                              |
                             |                              |
                             |                              |
                             |             bhm_dlist <------+
                             |             +--------------+--------------+--------------+
                             |             | (bhm_t) {    | (bhm_t) {    | (bhm_t) {    |
                             |             |   .key = A0, |   .key = A1, |   .key = A2, |
                             |             |   ...        |   ...        |   ...        |
                             |             | }            | }            | }            |
                             |             +--------------+--------------+--------------+
                             |
                             V
                             vte_dlist
                             +------------------------+------------------------+------------------------+
                             | (vte_t) {              | (vte_t) {              | (vte_t) {              |
                             |   .key.addr = Y,       |   .key.addr = Y,       |   .key.addr = Y,       |
                             |   .key.block_id  = A,  |   .key.block_id  = C,  |   .key.block_id  = B,  |
                             |   .bank_hash     = A0, |   .bank_hash     = C0, |   .bank_hash     = B0, |
                             |   ...                  |   ...                  |   ...                  |
                             | }                      | }                      | }                      |
                             +------------------------+------------------------+------------------------+
                             oldest                                                    newest

   vte_map prevents a voter from voting for the same block_id twice.
   The adversary is bounded because when vte_cnt == per_vtr_max, the
   oldest vte is popped and its stake is subtracted from the matching
   bhm. */

typedef struct {
  fd_hash_t block_id;
  fd_hash_t bank_hash;
} bhm_key_t;

struct bhm {
  bhm_key_t key;      /* bhm_map key */
  ulong next;     /* pool next */
  struct {
    ulong prev;
    ulong next;
  } map;
  struct {
    ulong prev;
    ulong next;
  } dlist;        /* bhm_dlist (owned by blk_t) */
  ulong slot;
  ulong stake;
  ulong vtr_cnt;
};
typedef struct bhm bhm_t;

#define POOL_NAME bhm_pool
#define POOL_T    bhm_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME                           bhm_map
#define MAP_ELE_T                          bhm_t
#define MAP_KEY_T                          bhm_key_t
#define MAP_PREV                           map.prev
#define MAP_NEXT                           map.next
#define MAP_KEY_EQ(k0,k1)                  (!memcmp((k0)->block_id.key,(k1)->block_id.key,32UL) & \
                                            !memcmp((k0)->bank_hash.key,(k1)->bank_hash.key,32UL))
#define MAP_KEY_HASH(key,seed)             ((ulong)((key)->block_id.ul[1]^(key)->bank_hash.ul[1]^(seed)))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  bhm_dlist
#define DLIST_ELE_T bhm_t
#define DLIST_PREV  dlist.prev
#define DLIST_NEXT  dlist.next
#include "../../util/tmpl/fd_dlist.c"

struct blk {
  fd_hash_t block_id;      /* blk_map key */
  ulong     prev;          /* blk_map prev */
  ulong     next;          /* pool next / blk_map next */
  fd_hash_t our_bank_hash; /* our bank hash for this block id */
  int       replayed;      /* whether we've replayed this block  */
  int       dead;          /* whether we marked this block as dead */
  int       flag;          /* -1: mismatch, 0: not compared yet, 1: match */
  ulong     bhm_cnt;       /* number of competing bank hashes for this block id */
  void *    bhm_dlist;     /* dlist of bank hash objects for this block id */
};
typedef struct blk blk_t;

#define POOL_NAME blk_pool
#define POOL_T    blk_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME                           blk_map
#define MAP_ELE_T                          blk_t
#define MAP_KEY_T                          fd_hash_t
#define MAP_KEY                            block_id
#define MAP_PREV                           prev
#define MAP_NEXT                           next
#define MAP_KEY_EQ(k0,k1)                  (!memcmp((k0)->key,(k1)->key,32UL))
#define MAP_KEY_HASH(key,seed)             ((ulong)((key)->ul[1]^(seed)))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

typedef struct {
  fd_pubkey_t addr;
  fd_hash_t   block_id;
} vte_key_t;

struct vte {
  vte_key_t key; /* vte_map key: (addr, block_id) */
  ulong     next;
  struct {
    ulong prev;
    ulong next;
  } vte_map;
  struct {
    ulong prev;
    ulong next;
  } dlist;
  fd_hash_t bank_hash;
  ulong     slot;
  ulong     stake;
};
typedef struct vte vte_t;

#define POOL_NAME vte_pool
#define POOL_T    vte_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME                           vte_map
#define MAP_ELE_T                          vte_t
#define MAP_KEY_T                          vte_key_t
#define MAP_PREV                           vte_map.prev
#define MAP_NEXT                           vte_map.next
#define MAP_KEY_EQ(k0,k1)                  (!memcmp((k0)->addr.key,(k1)->addr.key,32UL) & \
                                            !memcmp((k0)->block_id.key,(k1)->block_id.key,32UL))
#define MAP_KEY_HASH(key,seed)             ((ulong)((key)->addr.ul[1]^(key)->block_id.ul[1]^(seed)))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  vte_dlist
#define DLIST_ELE_T vte_t
#define DLIST_PREV  dlist.prev
#define DLIST_NEXT  dlist.next
#include "../../util/tmpl/fd_dlist.c"

struct vtr {
  fd_pubkey_t addr;
  ulong       next; /* pool next; reused as kept flag during update_voters */
  struct {
    ulong prev;
    ulong next;
  } map;
  struct {
    ulong prev;
    ulong next;
  } dlist;
  ulong         vte_cnt;
  vte_dlist_t * vte_dlist;
};
typedef struct vtr vtr_t;

#define POOL_NAME vtr_pool
#define POOL_T    vtr_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME                           vtr_map
#define MAP_ELE_T                          vtr_t
#define MAP_KEY_T                          fd_pubkey_t
#define MAP_KEY                            addr
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

struct __attribute__((aligned(128UL))) fd_hfork {
  ulong         max;
  ulong         per_vtr_max;
  ulong         vtr_max;
  bhm_t *       bhm_pool;
  bhm_map_t *   bhm_map;
  blk_t *       blk_pool;
  blk_map_t *   blk_map;
  vte_t *       vte_pool;
  vte_map_t *   vte_map;
  vtr_t *       vtr_pool;
  vtr_map_t *   vtr_map;
  vtr_dlist_t * vtr_dlist;
};
typedef struct fd_hfork fd_hfork_t;


/* bhm_remove removes a bhm from bhm_map, its owning blk's bhm_dlist,
   and releases it back to bhm_pool.  If the blk has no remaining bhm
   entries, the blk is also removed and released. */

static void
bhm_remove( fd_hfork_t * hfork,
            bhm_t *      bhm ) {
  blk_t * blk = blk_map_ele_query( hfork->blk_map, &bhm->key.block_id, NULL, hfork->blk_pool );
  if( FD_LIKELY( blk ) ) {
    bhm_dlist_ele_remove( blk->bhm_dlist, bhm, hfork->bhm_pool );
    blk->bhm_cnt--;
    if( FD_UNLIKELY( !blk->bhm_cnt ) ) {
      blk_map_ele_remove_fast( hfork->blk_map, blk, hfork->blk_pool );
      blk_pool_ele_release( hfork->blk_pool, blk );
    }
  }
  bhm_map_ele_remove_fast( hfork->bhm_map, bhm, hfork->bhm_pool );
  bhm_pool_ele_release( hfork->bhm_pool, bhm );
}

static int
check( blk_t * blk,
       bhm_t * bhm,
       ulong   total_stake ) {

  if( FD_UNLIKELY( blk->flag      ) ) return blk->flag;
  if( FD_UNLIKELY( !blk->replayed ) ) return 0;
  if( FD_UNLIKELY( !total_stake   ) ) return 0;

  double pct = (double)bhm->stake * 100.0 / (double)total_stake;
  if( FD_UNLIKELY( pct < 52.0 ) ) return 0;

  if( FD_UNLIKELY( blk->dead                                                   ) ) return -1;
  if( FD_UNLIKELY( 0!=memcmp( &blk->our_bank_hash, &bhm->key.bank_hash, 32UL ) ) ) return -1;
  return 1;
}

ulong
fd_hfork_align( void ) {
  return 128UL;
}

ulong
fd_hfork_footprint( ulong per_vtr_max,
                    ulong vtr_max ) {

  ulong max = per_vtr_max * vtr_max;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_hfork_t), sizeof(fd_hfork_t)                                       );
  l = FD_LAYOUT_APPEND( l, bhm_pool_align(),    bhm_pool_footprint( max )                                 );
  l = FD_LAYOUT_APPEND( l, bhm_map_align(),     bhm_map_footprint( bhm_map_chain_cnt_est( max ) )         );
  l = FD_LAYOUT_APPEND( l, blk_pool_align(),    blk_pool_footprint( max )                                 );
  l = FD_LAYOUT_APPEND( l, blk_map_align(),     blk_map_footprint( blk_map_chain_cnt_est( max ) )         );
  l = FD_LAYOUT_APPEND( l, vte_pool_align(),    vte_pool_footprint( max )                                 );
  l = FD_LAYOUT_APPEND( l, vte_map_align(),     vte_map_footprint( vte_map_chain_cnt_est( max ) )         );
  l = FD_LAYOUT_APPEND( l, vtr_pool_align(),    vtr_pool_footprint( vtr_max )                                 );
  l = FD_LAYOUT_APPEND( l, vtr_map_align(),     vtr_map_footprint( vtr_map_chain_cnt_est( vtr_max ) )     );
  l = FD_LAYOUT_APPEND( l, vtr_dlist_align(),   vtr_dlist_footprint()                                     );
  for( ulong i = 0UL; i < max; i++ ) {
    l = FD_LAYOUT_APPEND( l, bhm_dlist_align(), bhm_dlist_footprint() );
  }
  for( ulong i = 0UL; i < vtr_max; i++ ) {
    l = FD_LAYOUT_APPEND( l, vte_dlist_align(), vte_dlist_footprint() );
  }
  return FD_LAYOUT_FINI( l, fd_hfork_align() );
}

void *
fd_hfork_new( void * shmem,
              ulong  per_vtr_max,
              ulong  vtr_max,
              ulong  seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_hfork_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_hfork_footprint( per_vtr_max, vtr_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad per_vtr_max (%lu) or vtr_max (%lu)", per_vtr_max, vtr_max ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  ulong max = per_vtr_max * vtr_max;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_hfork_t * hfork     = FD_SCRATCH_ALLOC_APPEND( l, fd_hfork_align(),  sizeof(fd_hfork_t)                                      );
  void *       bhm_pool  = FD_SCRATCH_ALLOC_APPEND( l, bhm_pool_align(),  bhm_pool_footprint( max )                               );
  void *       bhm_map   = FD_SCRATCH_ALLOC_APPEND( l, bhm_map_align(),   bhm_map_footprint( bhm_map_chain_cnt_est( max ) )       );
  void *       blk_pool  = FD_SCRATCH_ALLOC_APPEND( l, blk_pool_align(),  blk_pool_footprint( max )                               );
  void *       blk_map   = FD_SCRATCH_ALLOC_APPEND( l, blk_map_align(),   blk_map_footprint( blk_map_chain_cnt_est( max ) )       );
  void *       vte_pool  = FD_SCRATCH_ALLOC_APPEND( l, vte_pool_align(),  vte_pool_footprint( max )                               );
  void *       vte_map   = FD_SCRATCH_ALLOC_APPEND( l, vte_map_align(),   vte_map_footprint( vte_map_chain_cnt_est( max ) )       );
  void *       vtr_pool  = FD_SCRATCH_ALLOC_APPEND( l, vtr_pool_align(),  vtr_pool_footprint( vtr_max )                               );
  void *       vtr_map   = FD_SCRATCH_ALLOC_APPEND( l, vtr_map_align(),   vtr_map_footprint( vtr_map_chain_cnt_est( vtr_max ) )   );
  void *       vtr_dlist = FD_SCRATCH_ALLOC_APPEND( l, vtr_dlist_align(), vtr_dlist_footprint()                                   );

  hfork->max         = max;
  hfork->per_vtr_max = per_vtr_max;
  hfork->vtr_max     = vtr_max;
  hfork->bhm_pool    = bhm_pool_new( bhm_pool, max );
  hfork->bhm_map     = bhm_map_new( bhm_map, bhm_map_chain_cnt_est( max ), seed );
  hfork->blk_pool    = blk_pool_new( blk_pool, max );
  hfork->blk_map     = blk_map_new( blk_map, blk_map_chain_cnt_est( max ), seed );
  hfork->vte_pool    = vte_pool_new( vte_pool, max );
  hfork->vte_map     = vte_map_new( vte_map, vte_map_chain_cnt_est( max ), seed );
  hfork->vtr_pool    = vtr_pool_new( vtr_pool, vtr_max );
  hfork->vtr_map     = vtr_map_new( vtr_map, vtr_map_chain_cnt_est( vtr_max ), seed );
  hfork->vtr_dlist   = vtr_dlist_new( vtr_dlist );

  blk_t * blk_join = blk_pool_join( hfork->blk_pool );
  for( ulong i = 0UL; i < max; i++ ) {
    void * bhm_dlist       = FD_SCRATCH_ALLOC_APPEND( l, bhm_dlist_align(), bhm_dlist_footprint() );
    blk_join[i].bhm_cnt    = 0;
    blk_join[i].bhm_dlist  = bhm_dlist_new( bhm_dlist );
  }

  vtr_t * vtr_join = vtr_pool_join( hfork->vtr_pool );
  for( ulong i = 0UL; i < vtr_max; i++ ) {
    void * vte_dlist       = FD_SCRATCH_ALLOC_APPEND( l, vte_dlist_align(), vte_dlist_footprint() );
    vtr_join[i].vte_cnt    = 0;
    vtr_join[i].vte_dlist  = vte_dlist_new( vte_dlist );
  }
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_hfork_align() ) == (ulong)shmem + footprint );
  return shmem;
}

fd_hfork_t *
fd_hfork_join( void * shhfork ) {
  fd_hfork_t * hfork = (fd_hfork_t *)shhfork;

  if( FD_UNLIKELY( !hfork ) ) {
    FD_LOG_WARNING(( "NULL hfork" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)hfork, fd_hfork_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned hfork" ));
    return NULL;
  }

  hfork->bhm_pool  = bhm_pool_join( hfork->bhm_pool );
  hfork->bhm_map   = bhm_map_join( hfork->bhm_map );
  hfork->blk_pool  = blk_pool_join( hfork->blk_pool );
  hfork->blk_map   = blk_map_join( hfork->blk_map );
  hfork->vte_pool  = vte_pool_join( hfork->vte_pool );
  hfork->vte_map   = vte_map_join( hfork->vte_map );
  hfork->vtr_pool  = vtr_pool_join( hfork->vtr_pool );
  hfork->vtr_map   = vtr_map_join( hfork->vtr_map );
  hfork->vtr_dlist = vtr_dlist_join( hfork->vtr_dlist );
  for( ulong i = 0UL; i < hfork->max; i++ ) {
    hfork->blk_pool[i].bhm_dlist = bhm_dlist_join( hfork->blk_pool[i].bhm_dlist );
  }
  for( ulong i = 0UL; i < hfork->vtr_max; i++ ) {
    hfork->vtr_pool[i].vte_dlist = vte_dlist_join( hfork->vtr_pool[i].vte_dlist );
  }

  return hfork;
}

void *
fd_hfork_leave( fd_hfork_t const * hfork ) {

  if( FD_UNLIKELY( !hfork ) ) {
    FD_LOG_WARNING(( "NULL hfork" ));
    return NULL;
  }

  return (void *)hfork;
}

void *
fd_hfork_delete( void * hfork ) {

  if( FD_UNLIKELY( !hfork ) ) {
    FD_LOG_WARNING(( "NULL hfork" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)hfork, fd_hfork_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned hfork" ));
    return NULL;
  }

  return hfork;
}

static blk_t *
blk_insert( fd_hfork_t      * hfork,
             fd_hash_t const * block_id ) {
  blk_t * blk        = blk_pool_ele_acquire( hfork->blk_pool );
  blk->block_id      = *block_id;
  /* blk->our_bank_hash */
  blk->replayed      = 0; /* set by record_our_bank_hash */
  blk->dead          = 0; /* set by record_our_bank_hash */
  blk->flag          = 0; /* set by check: -1 mismatch, 0 unchecked, 1 match */
  blk->bhm_cnt       = 0;
  blk_map_ele_insert( hfork->blk_map, blk, hfork->blk_pool );
  return blk;
}

int
fd_hfork_count_vote( fd_hfork_t *        hfork,
                     fd_pubkey_t const * vote_acc,
                     fd_hash_t const *   block_id,
                     fd_hash_t const *   bank_hash,
                     ulong               slot,
                     ulong               stake,
                     ulong               total_stake ) {

  /* Get the vtr.  If not in the voter set, ignore. */

  vtr_t * vtr = vtr_map_ele_query( hfork->vtr_map, vote_acc, NULL, hfork->vtr_pool );
  if( FD_UNLIKELY( !vtr ) ) return FD_HFORK_ERR_UNKNOWN_VTR;

  /* If voter already voted for this block_id, ignore. */

  bhm_key_t bhm_key = { .block_id = *block_id, .bank_hash = *bank_hash };
  vte_key_t vte_key = { .addr = *vote_acc, .block_id = *block_id };
  if( FD_UNLIKELY( vte_map_ele_query_const( hfork->vte_map, &vte_key, NULL, hfork->vte_pool ) ) ) return FD_HFORK_ERR_ALREADY_VOTED;

  /* Only process newer votes (by vote slot) from a given voter. */

  if( FD_UNLIKELY( vtr->vte_cnt && vte_dlist_ele_peek_tail_const( vtr->vte_dlist, hfork->vte_pool )->slot >= slot ) ) return FD_HFORK_ERR_VOTE_TOO_OLD;

  /* If voter has reached their quota, evict their oldest vote. */

  if( FD_UNLIKELY( vtr->vte_cnt==hfork->per_vtr_max ) ) {
    vte_t * evicted_vte = vte_dlist_ele_pop_head( vtr->vte_dlist, hfork->vte_pool );
    vte_map_ele_remove_fast( hfork->vte_map, evicted_vte, hfork->vte_pool );

    bhm_key_t evicted_xid = { .block_id = evicted_vte->key.block_id, .bank_hash = evicted_vte->bank_hash };
    bhm_t * bhm = bhm_map_ele_query( hfork->bhm_map, &evicted_xid, NULL, hfork->bhm_pool );
    bhm->stake -= evicted_vte->stake;
    bhm->vtr_cnt--;
    if( FD_UNLIKELY( !bhm->vtr_cnt ) ) bhm_remove( hfork, bhm );
    vte_pool_ele_release( hfork->vte_pool, evicted_vte );
    vtr->vte_cnt--;
  }

  /* Find or insert the blk for this block_id. */

  blk_t * blk = blk_map_ele_query( hfork->blk_map, block_id, NULL, hfork->blk_pool );
  if( FD_UNLIKELY( !blk ) ) blk = blk_insert( hfork, block_id );

  /* Find or insert the bhm for this (block_id, bank_hash). */

  bhm_t * bhm = bhm_map_ele_query( hfork->bhm_map, &bhm_key, NULL, hfork->bhm_pool );
  if( FD_UNLIKELY( !bhm ) ) {
    bhm          = bhm_pool_ele_acquire( hfork->bhm_pool );
    bhm->key     = bhm_key;
    bhm->slot    = slot;
    bhm->stake   = 0UL;
    bhm->vtr_cnt = 0UL;
    bhm_map_ele_insert( hfork->bhm_map, bhm, hfork->bhm_pool );
    blk->bhm_cnt++;
    bhm_dlist_ele_push_tail( blk->bhm_dlist, bhm, hfork->bhm_pool );
  }

  /* Push the vote onto the vtr. */

  vte_t * vte    = vte_pool_ele_acquire( hfork->vte_pool );
  vte->key       = vte_key;
  vte->bank_hash = *bank_hash;
  vte->slot      = slot;
  vte->stake     = stake;
  vte_map_ele_insert( hfork->vte_map, vte, hfork->vte_pool );
  vte_dlist_ele_push_tail( vtr->vte_dlist, vte, hfork->vte_pool );
  vtr->vte_cnt++;

  bhm->vtr_cnt++;
  bhm->stake += stake;

  /* Check for hard forks. */

  blk->flag = check( blk, bhm, total_stake );
  return blk->flag;
}

int
fd_hfork_record_our_bank_hash( fd_hfork_t *      hfork,
                               fd_hash_t const * block_id,
                               fd_hash_t const * bank_hash,
                               ulong             total_stake ) {

  blk_t * blk = blk_map_ele_query( hfork->blk_map, block_id, NULL, hfork->blk_pool );
  if( FD_LIKELY( !blk      ) ) blk = blk_insert( hfork, block_id );
  if( FD_LIKELY( bank_hash ) ) blk->our_bank_hash = *bank_hash;
  blk->replayed = 1;
  blk->dead     = !bank_hash;

  /* Check all bhm entries for this block_id. */

  for( bhm_dlist_iter_t iter = bhm_dlist_iter_fwd_init( blk->bhm_dlist, hfork->bhm_pool );
                              !bhm_dlist_iter_done( iter, blk->bhm_dlist, hfork->bhm_pool );
                        iter = bhm_dlist_iter_fwd_next( iter, blk->bhm_dlist, hfork->bhm_pool ) ) {
    bhm_t * bhm = bhm_dlist_iter_ele( iter, blk->bhm_dlist, hfork->bhm_pool );
    blk->flag   = check( blk, bhm, total_stake );
  }
  return blk->flag;
}

void
fd_hfork_update_voters( fd_hfork_t *        hfork,
                        fd_pubkey_t const * vote_accs,
                        ulong               cnt ) {

  for( vtr_dlist_iter_t iter = vtr_dlist_iter_fwd_init( hfork->vtr_dlist, hfork->vtr_pool );
       !vtr_dlist_iter_done( iter, hfork->vtr_dlist, hfork->vtr_pool );
       iter = vtr_dlist_iter_fwd_next( iter, hfork->vtr_dlist, hfork->vtr_pool ) ) {
    hfork->vtr_pool[iter].next = 1; /* mark for removal */
  }

  /* Move all voters in the new voters set to the back of the
     dlist.  We mark them by setting their `next` field to null. */

  for( ulong i=0UL; i<cnt; i++ ) {
    fd_pubkey_t const * vote_acc = &vote_accs[i];
    vtr_t *             vtr      = vtr_map_ele_query( hfork->vtr_map, vote_acc, NULL, hfork->vtr_pool );
    if( FD_UNLIKELY( !vtr ) ) {
      vtr          = vtr_pool_ele_acquire( hfork->vtr_pool );
      vtr->addr    = *vote_acc;
      vtr->vte_cnt = 0;
      vtr_map_ele_insert( hfork->vtr_map, vtr, hfork->vtr_pool );
    } else {
      vtr_dlist_ele_remove( hfork->vtr_dlist, vtr, hfork->vtr_pool );
    }
    vtr->next = 0; /* unmark for removal */
    vtr_dlist_ele_push_tail( hfork->vtr_dlist, vtr, hfork->vtr_pool );
  }

  /* Pop unwanted voters from the head until we hit a kept voter. */

  while( FD_LIKELY( !vtr_dlist_is_empty( hfork->vtr_dlist, hfork->vtr_pool ) ) ) {
    vtr_t * vtr = vtr_dlist_ele_pop_head( hfork->vtr_dlist, hfork->vtr_pool );
    if( FD_UNLIKELY( !vtr->next ) ) { /* can short-circuit since all the existing and new voters were appended */
      vtr_dlist_ele_push_tail( hfork->vtr_dlist, vtr, hfork->vtr_pool );
      break;
    }
    while( FD_LIKELY( !vte_dlist_is_empty( vtr->vte_dlist, hfork->vte_pool ) ) ) {
      vte_t * vte = vte_dlist_ele_pop_head( vtr->vte_dlist, hfork->vte_pool );
      vte_map_ele_remove_fast( hfork->vte_map, vte, hfork->vte_pool );

      bhm_key_t vte_xid = { .block_id = vte->key.block_id, .bank_hash = vte->bank_hash };
      bhm_t * bhm = bhm_map_ele_query( hfork->bhm_map, &vte_xid, NULL, hfork->bhm_pool );
      if( FD_LIKELY( bhm ) ) {
        bhm->stake -= vte->stake;
        bhm->vtr_cnt--;
        if( FD_UNLIKELY( !bhm->vtr_cnt ) ) bhm_remove( hfork, bhm );
      }

      vte_pool_ele_release( hfork->vte_pool, vte );
    }
    vtr_map_ele_remove_fast( hfork->vtr_map, vtr, hfork->vtr_pool );
    vtr_pool_ele_release( hfork->vtr_pool, vtr );
  }
}
