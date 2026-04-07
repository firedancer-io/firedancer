#include "fd_votes.h"

/* fd_votes tracks blks, vtrs, and slots.

   blk_pool / blk_map (capacity blk_max = slot_max * vtr_max):

   Each blk tracks the aggregate stake voted for a particular block_id.

   vtr_pool / vtr_map / vtr_dlist / vtr_set (capacity vtr_max):

   Each vtr corresponds to a vote account address and has a bit position
   in the slot vtrs bitset and their stake.  vtr entries are explicitly
   managed by fd_votes_update_voters when the epoch stake set changes.
   dlist of all active voters, used for mark-sweep in
   fd_votes_update_voters.

   slot_pool / slot_map / blk_dlist (capacity slot_max):

   Each slot corresponds to a slot and tracks which voters have voted
   for that slot and all the blks that are associated for that slot.
   Each slot also tracks all the blks associated with that slot in
   blk_dlist.

            slot_map                           vtr_map
     map[0] +--------------------+     map[0] +--------------------+
            | (slot_t) {         |            | (vtr_t) {          |
            |   .slot = 100,     |            |   .vote_acc = X,   |
            |   .vtrs = ...,     |            |   .bit   = 0,      |
            |   .blk_dlist = ... |            |   .stake = 10,     |
            | }                  |            | }                  |
     map[1] +--------------------+     map[1] +--------------------+
            | (slot_t) {         |            | (vtr_t) {          |
            |   .slot = 101,     |            |   .vote_acc = Y,   |
            |   .vtrs = ...,     |            |   .bit   = 1,      |
            |   .blk_dlist = +   |            |   .stake = 51,     |
            | }              |   |            | }                  |
            +----------------|---+            +--------------------+
                             |
                             V
                             blk_dlist
                             +------------------+------------------+
                             | (blk_t) {        | (blk_t) {        |
                             |   .block_id = A, |   .block_id = B, |
                             |   .stake = 10,   |   .stake = 51,   |
                             |   ...            |   ...            |
                             | }                | }                |
                             +------------------+------------------+

   When a vote is counted, the voter's bit is set in the slot's vtrs
   bitset.  If the voter already voted for this slot (bit already set),
   the vote is ignored.  The vote's stake is added to both the slot's
   aggregate stake and the blk's stake.  blk entries are also in the
   global blk_map for O(1) lookup by block_id. */

typedef fd_votes_blk_t blk_t;

#define POOL_NAME blk_pool
#define POOL_T    blk_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME                           blk_map
#define MAP_ELE_T                          blk_t
#define MAP_KEY_T                          fd_votes_blk_key_t
#define MAP_KEY                            key
#define MAP_PREV                           map.prev
#define MAP_NEXT                           map.next
#define MAP_KEY_EQ(k0,k1)                  ((k0)->slot==(k1)->slot && !memcmp((k0)->block_id.key,(k1)->block_id.key,32UL))
#define MAP_KEY_HASH(key,seed)             ((ulong)((key)->block_id.ul[1]^(key)->slot^(seed)))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  blk_dlist
#define DLIST_ELE_T blk_t
#define DLIST_PREV  dlist.prev
#define DLIST_NEXT  dlist.next
#include "../../util/tmpl/fd_dlist.c"

struct vtr {
  fd_pubkey_t vote_acc; /* vtr_map key */
  ulong       next;     /* pool next */
  struct {
    ulong prev;
    ulong next;
  } map;
  struct {
    ulong prev;
    ulong next;
  } dlist;
  ulong bit;
  ulong stake;
};
typedef struct vtr vtr_t;

#define POOL_NAME vtr_pool
#define POOL_T    vtr_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME                           vtr_map
#define MAP_ELE_T                          vtr_t
#define MAP_KEY_T                          fd_pubkey_t
#define MAP_KEY                            vote_acc
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

struct slot {
  ulong slot; /* map key, vote slot */
  ulong next; /* pool next */
  struct {
    ulong prev;
    ulong next;
  } map;
  struct {
    ulong prev;
    ulong next;
  } dlist;
  blk_dlist_t * blks;
  ulong         blk_cnt; /* number of distinct block ids for this slot */
  slot_vtrs_t * vtrs;    /* who has voted for this slot, curr epoch */
};
typedef struct slot slot_t;

#define POOL_NAME slot_pool
#define POOL_T    slot_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME                           slot_map
#define MAP_ELE_T                          slot_t
#define MAP_KEY_T                          ulong
#define MAP_KEY                            slot
#define MAP_PREV                           map.prev
#define MAP_NEXT                           map.next
#define MAP_KEY_EQ(k0,k1)                  (*(k0)==*(k1))
#define MAP_KEY_HASH(key,seed)             ((*key)^(seed))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  slot_dlist
#define DLIST_ELE_T slot_t
#define DLIST_PREV  dlist.prev
#define DLIST_NEXT  dlist.next
#include "../../util/tmpl/fd_dlist.c"

struct __attribute__((aligned(128UL))) fd_votes {
  ulong          root;
  ulong          slot_max;
  ulong          vtr_max;
  ulong          blk_max;
  slot_t *       slot_pool;
  slot_map_t *   slot_map;
  slot_dlist_t * slot_dlist;
  blk_t *        blk_pool;
  blk_map_t *    blk_map;
  vtr_t *        vtr_pool;
  vtr_map_t *    vtr_map;
  vtr_dlist_t *  vtr_dlist;
  slot_vtrs_t *  vtr_set;
};

ulong
fd_votes_align( void ) {
  return 128UL;
}

ulong
fd_votes_footprint( ulong slot_max,
                    ulong vtr_max ) {

  ulong blk_max = slot_max * vtr_max;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, 128UL,              sizeof(fd_votes_t)                                       );
  l = FD_LAYOUT_APPEND( l, slot_pool_align(),  slot_pool_footprint( slot_max )                          );
  l = FD_LAYOUT_APPEND( l, slot_map_align(),   slot_map_footprint( slot_map_chain_cnt_est( slot_max ) ) );
  l = FD_LAYOUT_APPEND( l, slot_dlist_align(), slot_dlist_footprint()                                   );
  l = FD_LAYOUT_APPEND( l, blk_pool_align(),   blk_pool_footprint( blk_max )                            );
  l = FD_LAYOUT_APPEND( l, blk_map_align(),    blk_map_footprint( blk_map_chain_cnt_est( blk_max ) )    );
  l = FD_LAYOUT_APPEND( l, vtr_pool_align(),   vtr_pool_footprint( vtr_max )                            );
  l = FD_LAYOUT_APPEND( l, vtr_map_align(),    vtr_map_footprint( vtr_map_chain_cnt_est( vtr_max ) )    );
  l = FD_LAYOUT_APPEND( l, vtr_dlist_align(),  vtr_dlist_footprint()                                    );
  l = FD_LAYOUT_APPEND( l, slot_vtrs_align(),  slot_vtrs_footprint( vtr_max )                           );
  for( ulong i = 0UL; i < slot_max; i++ ) {
    l = FD_LAYOUT_APPEND( l, slot_vtrs_align(), slot_vtrs_footprint( vtr_max ) );
    l = FD_LAYOUT_APPEND( l, blk_dlist_align(), blk_dlist_footprint()          );
  }
  return FD_LAYOUT_FINI( l, fd_votes_align() );
}

void *
fd_votes_new( void * shmem,
              ulong  slot_max,
              ulong  vtr_max,
              ulong  seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_votes_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_votes_footprint( slot_max, vtr_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max (%lu) or vtr_max (%lu)", slot_max, vtr_max ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  ulong blk_max = slot_max * vtr_max;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_votes_t * votes      = FD_SCRATCH_ALLOC_APPEND( l, 128UL,              sizeof(fd_votes_t)                                       );
  void *       slot_pool  = FD_SCRATCH_ALLOC_APPEND( l, slot_pool_align(),  slot_pool_footprint( slot_max )                          );
  void *       slot_map   = FD_SCRATCH_ALLOC_APPEND( l, slot_map_align(),   slot_map_footprint( slot_map_chain_cnt_est( slot_max ) ) );
  void *       slot_dlist = FD_SCRATCH_ALLOC_APPEND( l, slot_dlist_align(), slot_dlist_footprint()                                   );
  void *       blk_pool   = FD_SCRATCH_ALLOC_APPEND( l, blk_pool_align(),   blk_pool_footprint( blk_max )                            );
  void *       blk_map    = FD_SCRATCH_ALLOC_APPEND( l, blk_map_align(),    blk_map_footprint( blk_map_chain_cnt_est( blk_max ) )    );
  void *       vtr_pool   = FD_SCRATCH_ALLOC_APPEND( l, vtr_pool_align(),   vtr_pool_footprint( vtr_max )                            );
  void *       vtr_map    = FD_SCRATCH_ALLOC_APPEND( l, vtr_map_align(),    vtr_map_footprint( vtr_map_chain_cnt_est( vtr_max ) )    );
  void *       vtr_dlist  = FD_SCRATCH_ALLOC_APPEND( l, vtr_dlist_align(),  vtr_dlist_footprint()                                    );
  void *       vtr_set    = FD_SCRATCH_ALLOC_APPEND( l, slot_vtrs_align(),  slot_vtrs_footprint( vtr_max )                           );

  votes->root       = ULONG_MAX;
  votes->slot_max   = slot_max;
  votes->vtr_max    = vtr_max;
  votes->blk_max    = blk_max;
  votes->slot_pool  = slot_pool_new ( slot_pool, slot_max                                 );
  votes->slot_map   = slot_map_new  ( slot_map,  slot_map_chain_cnt_est( slot_max ), seed );
  votes->slot_dlist = slot_dlist_new( slot_dlist                                          );
  votes->blk_pool   = blk_pool_new  ( blk_pool,  blk_max                                  );
  votes->blk_map    = blk_map_new   ( blk_map,   blk_map_chain_cnt_est( blk_max ),   seed );
  votes->vtr_pool   = vtr_pool_new  ( vtr_pool,  vtr_max                                  );
  votes->vtr_map    = vtr_map_new   ( vtr_map,   vtr_map_chain_cnt_est( vtr_max ),   seed );
  votes->vtr_dlist  = vtr_dlist_new ( vtr_dlist                                           );
  votes->vtr_set    = slot_vtrs_new ( vtr_set,   vtr_max                                  );

  /* Pre-allocate a vtrs set and blk_dlist per slot pool position. */

  slot_t * slot_join = slot_pool_join( votes->slot_pool );
  for( ulong i = 0UL; i < slot_max; i++ ) {
    void * vtrs            = FD_SCRATCH_ALLOC_APPEND( l, slot_vtrs_align(), slot_vtrs_footprint( vtr_max ) );
    void * blk_dlist       = FD_SCRATCH_ALLOC_APPEND( l, blk_dlist_align(), blk_dlist_footprint()          );
    slot_join[i].vtrs      = slot_vtrs_new( vtrs, vtr_max );
    slot_join[i].blks      = blk_dlist_new( blk_dlist );
    slot_join[i].blk_cnt   = 0;
  }
  slot_pool_leave( slot_join );

  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_votes_align() ) == (ulong)shmem + footprint );
  return shmem;
}

fd_votes_t *
fd_votes_join( void * shvotes ) {
  fd_votes_t * votes = (fd_votes_t *)shvotes;

  if( FD_UNLIKELY( !votes ) ) {
    FD_LOG_WARNING(( "NULL votes" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)votes, fd_votes_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned votes" ));
    return NULL;
  }

  votes->slot_pool  = slot_pool_join ( votes->slot_pool  );
  votes->slot_map   = slot_map_join  ( votes->slot_map   );
  votes->slot_dlist = slot_dlist_join( votes->slot_dlist );
  votes->blk_pool   = blk_pool_join  ( votes->blk_pool   );
  votes->blk_map    = blk_map_join   ( votes->blk_map    );
  votes->vtr_pool   = vtr_pool_join  ( votes->vtr_pool   );
  votes->vtr_map    = vtr_map_join   ( votes->vtr_map    );
  votes->vtr_dlist  = vtr_dlist_join ( votes->vtr_dlist  );
  votes->vtr_set    = slot_vtrs_join ( votes->vtr_set    );

  /* Re-join vtrs sets and blk_dlists per slot pool position. */

  for( ulong i = 0UL; i < votes->slot_max; i++ ) {
    votes->slot_pool[i].vtrs = slot_vtrs_join( votes->slot_pool[i].vtrs );
    votes->slot_pool[i].blks = blk_dlist_join( votes->slot_pool[i].blks );
  }

  return votes;
}

void *
fd_votes_leave( fd_votes_t const * votes ) {

  if( FD_UNLIKELY( !votes ) ) {
    FD_LOG_WARNING(( "NULL votes" ));
    return NULL;
  }

  return (void *)votes;
}

void *
fd_votes_delete( void * votes ) {

  if( FD_UNLIKELY( !votes ) ) {
    FD_LOG_WARNING(( "NULL votes" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)votes, fd_votes_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned votes" ));
    return NULL;
  }

  return votes;
}

int
fd_votes_count_vote( fd_votes_t *        votes,
                     fd_pubkey_t const * vote_acc,
                     ulong               vote_slot,
                     fd_hash_t const *   vote_block_id ) {

  if( FD_UNLIKELY( vote_slot >= votes->root + votes->slot_max ) ) return FD_VOTES_ERR_VOTE_TOO_NEW;

  vtr_t * vtr = vtr_map_ele_query( votes->vtr_map, vote_acc, NULL, votes->vtr_pool );
  if( FD_UNLIKELY( !vtr ) ) return FD_VOTES_ERR_UNKNOWN_VTR;

  /* Check we haven't already counted the voter's stake for this slot.
     If a voter votes for multiple block ids for the same slot, we only
     count their first one.  Honest voters never vote more than once for
     the same slot so the percentage of stake doing this should be small
     as only malicious voters would equivocate votes this way. */

  slot_t * slot = slot_map_ele_query( votes->slot_map, &vote_slot, NULL, votes->slot_pool );
  if( FD_UNLIKELY( !slot ) ) {
    slot          = slot_pool_ele_acquire( votes->slot_pool );
    slot->slot    = vote_slot;
    slot->blk_cnt = 0;
    slot_vtrs_null( slot->vtrs );
    slot_map_ele_insert( votes->slot_map, slot, votes->slot_pool );
    slot_dlist_ele_push_tail( votes->slot_dlist, slot, votes->slot_pool );
  }
  if( FD_UNLIKELY( slot_vtrs_test( slot->vtrs, vtr->bit ) ) ) return FD_VOTES_ERR_ALREADY_VOTED;
  slot_vtrs_insert( slot->vtrs, vtr->bit );

  fd_votes_blk_key_t blk_key = { .slot = vote_slot, .block_id = *vote_block_id };
  blk_t * blk = blk_map_ele_query( votes->blk_map, &blk_key, NULL, votes->blk_pool );
  if( FD_UNLIKELY( !blk ) ) {
    blk        = blk_pool_ele_acquire( votes->blk_pool );
    blk->key   = blk_key;
    blk->stake = 0;
    blk->flags = 0;
    blk_map_ele_insert( votes->blk_map, blk, votes->blk_pool );
    blk_dlist_ele_push_tail( slot->blks, blk, votes->blk_pool );
    slot->blk_cnt++;
  }
  blk->stake += vtr->stake;
  return FD_VOTES_SUCCESS;
}

fd_votes_blk_t *
fd_votes_query( fd_votes_t *      votes,
                ulong             slot,
                fd_hash_t const * block_id ) {

  if( FD_LIKELY( block_id ) ) {
    fd_votes_blk_key_t key = { .slot = slot, .block_id = *block_id };
    return blk_map_ele_query( votes->blk_map, &key, NULL, votes->blk_pool );
  }

  /* NULL block_id: search all block_ids for this slot, return the one
     with the highest forward confirmation level. */

  slot_t * votes_slot = slot_map_ele_query( votes->slot_map, &slot, NULL, votes->slot_pool );
  if( FD_UNLIKELY( !votes_slot ) ) return NULL;

  blk_t * best = NULL;
  for( blk_dlist_iter_t iter = blk_dlist_iter_fwd_init( votes_slot->blks, votes->blk_pool );
       !blk_dlist_iter_done( iter, votes_slot->blks, votes->blk_pool );
       iter = blk_dlist_iter_fwd_next( iter, votes_slot->blks, votes->blk_pool ) ) {
    blk_t * blk = blk_dlist_iter_ele( iter, votes_slot->blks, votes->blk_pool );
    if( FD_UNLIKELY( ( blk->flags >> 4 ) > ( best ? best->flags >> 4 : 0 ) ) ) best = blk;
  }
  return best;
}

void
fd_votes_publish( fd_votes_t * votes,
                  ulong        root ) {
  if( FD_UNLIKELY( votes->root==ULONG_MAX ) ) { votes->root = root; return; }
  for( ulong slot = votes->root; slot < root; slot++ ) {
    slot_t * votes_slot = slot_map_ele_query( votes->slot_map, &slot, NULL, votes->slot_pool );
    if( FD_LIKELY( votes_slot ) ) {
      while( FD_LIKELY( !blk_dlist_is_empty( votes_slot->blks, votes->blk_pool ) ) ) {
        blk_t * blk = blk_dlist_ele_pop_head( votes_slot->blks, votes->blk_pool );
        blk_map_ele_remove_fast( votes->blk_map, blk, votes->blk_pool );
        blk_pool_ele_release( votes->blk_pool, blk );
      }
      slot_dlist_ele_remove( votes->slot_dlist, votes_slot, votes->slot_pool );
      slot_map_ele_remove_fast( votes->slot_map, votes_slot, votes->slot_pool );
      slot_pool_ele_release( votes->slot_pool, votes_slot );
    }
  }
  votes->root = root;
}

void
fd_votes_update_voters( fd_votes_t *        votes,
                        fd_pubkey_t const * vote_accs,
                        ulong const *       stakes,
                        ulong               cnt ) {

  /* Mark all existing voters for removal. */

  for( vtr_dlist_iter_t iter = vtr_dlist_iter_fwd_init( votes->vtr_dlist, votes->vtr_pool );
       !vtr_dlist_iter_done( iter, votes->vtr_dlist, votes->vtr_pool );
       iter = vtr_dlist_iter_fwd_next( iter, votes->vtr_dlist, votes->vtr_pool ) ) {
    votes->vtr_pool[iter].next = 1; /* mark for removal */
  }

  /* Build a set of kept old bit positions.  Walk voters,
     keep/add matching voters, and update stakes.  Existing voters
     keep their old bit positions (no compaction). */

  slot_vtrs_null( votes->vtr_set );

  for( ulong i=0UL; i<cnt; i++ ) {
    fd_pubkey_t const * vote_acc = &vote_accs[i];
    vtr_t * vtr = vtr_map_ele_query( votes->vtr_map, vote_acc, NULL, votes->vtr_pool );
    if( FD_UNLIKELY( !vtr ) ) {
      vtr           = vtr_pool_ele_acquire( votes->vtr_pool );
      vtr->vote_acc = *vote_acc;
      vtr->bit      = ULONG_MAX;
      vtr->stake    = 0;
      vtr_map_ele_insert( votes->vtr_map, vtr, votes->vtr_pool );
    } else {
      vtr_dlist_ele_remove( votes->vtr_dlist, vtr, votes->vtr_pool );
      slot_vtrs_insert( votes->vtr_set, vtr->bit );
    }
    vtr->next = 0; /* unmark for removal */
    vtr_dlist_ele_push_tail( votes->vtr_dlist, vtr, votes->vtr_pool );

    vtr->stake = stakes[i];
  }

  /* Pop unwanted voters from the head until we hit a kept voter. */

  while( FD_LIKELY( !vtr_dlist_is_empty( votes->vtr_dlist, votes->vtr_pool ) ) ) {
    vtr_t * vtr = vtr_dlist_ele_pop_head( votes->vtr_dlist, votes->vtr_pool );
    if( FD_UNLIKELY( !vtr->next ) ) { /* can short-circuit since all the existing and new voters were appended */
      vtr_dlist_ele_push_tail( votes->vtr_dlist, vtr, votes->vtr_pool );
      break;
    }
    vtr_map_ele_remove_fast( votes->vtr_map, vtr, votes->vtr_pool );
    vtr_pool_ele_release( votes->vtr_pool, vtr );
  }

  /* Clear removed voters' bits from all existing slots' vtrs by
     intersecting with the kept set. */

  for( slot_dlist_iter_t iter = slot_dlist_iter_fwd_init( votes->slot_dlist, votes->slot_pool );
       !slot_dlist_iter_done( iter, votes->slot_dlist, votes->slot_pool );
       iter = slot_dlist_iter_fwd_next( iter, votes->slot_dlist, votes->slot_pool ) ) {
    slot_t * votes_slot = &votes->slot_pool[iter];
    slot_vtrs_intersect( votes_slot->vtrs, votes_slot->vtrs, votes->vtr_set );
  }

  /* Assign bit positions to new voters from freed positions. */

  ulong free_bit = 0;
  for( vtr_dlist_iter_t iter = vtr_dlist_iter_fwd_init( votes->vtr_dlist, votes->vtr_pool );
       !vtr_dlist_iter_done( iter, votes->vtr_dlist, votes->vtr_pool );
       iter = vtr_dlist_iter_fwd_next( iter, votes->vtr_dlist, votes->vtr_pool ) ) {
    vtr_t * vtr = &votes->vtr_pool[iter];
    if( FD_UNLIKELY( vtr->bit==ULONG_MAX ) ) {
      while( slot_vtrs_test( votes->vtr_set, free_bit ) ) free_bit++;
      vtr->bit = free_bit;
      slot_vtrs_insert( votes->vtr_set, free_bit );
      free_bit++;
    }
  }
}
