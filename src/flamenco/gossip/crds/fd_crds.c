#include "fd_crds.h"
#include "fd_crds_contact_info.c"
#include "../fd_gossip_types.h"

#include "../../../ballet/sha256/fd_sha256.h"
#include "../../../funk/fd_funk_base.h" /* no link dependency, only using hash */

#include <string.h>

FD_STATIC_ASSERT( CRDS_MAX_CONTACT_INFO==FD_CONTACT_INFO_TABLE_SIZE,
                  "CRDS_MAX_CONTACT_INFO must match FD_CONTACT_INFO_TABLE_SIZE" );

struct fd_crds_key {
  uchar tag;
  uchar pubkey[ 32UL ];
  union {
    uchar  vote_index;
    uchar  epoch_slots_index;
    ushort duplicate_shred_index;
  };
};

typedef struct fd_crds_key fd_crds_key_t;

/* The CRDS at a high level is just a list of all the messages we have
   received over gossip.  These are called the CRDS values.  Values
   are not arbitrary, and must conform to a strictly typed schema of
   around 10 different messages. */

struct fd_crds_entry_private {
  /* The core operation of the CRDS is to "upsert" a value.  Basically,
    all of the message types are keyed by the originators public key,
    and we only want to store the most recent message of each type.

    This key field is the key for the hash table. */
  fd_crds_key_t key;

  union {
    struct {
      fd_crds_contact_info_entry_t * ci;
      long                           instance_creation_wallclock_nanos;
      uchar                          is_active;
      ulong                          sampler_idx;

      /* A list of "fresh" contact info entries is maintained, holding
         entries that have been refreshed/inserted in the last 60s in
         upsertion order (oldest first).

         fd_crds_advance periodically checks for and removes peers from
         this list if they exceed the threshold. Peers removed in this
         loop are also re-scored in the peer sampler. This is different
         from dropping the CRDS entry entirely, which also removes the
         entry from this list. To avoid double-popping an entry we use
         in_list as a presence check prior to removing */
      struct {
        ulong prev;
        ulong next;
        uchar in_list; /* 1 if in the fresh list, 0 otherwise */
      } fresh_dlist;

      /* The contact info side table has a separate size limit, so
         we maintain a separate evict list to make space for new
         entries */
      struct {
        ulong prev;
        ulong next;
      } evict_dlist;

      /* TODO: stake-ordered treap/pq? */
    } contact_info;
    struct {
      ulong  token;
    } node_instance;
  };

  /* When an originator creates a CRDS message, they attach their local
    wallclock time to it.  This time is used to determine when a
    message should be upserted.  If messages have the same key, the
    newer one (as created by the originator) is used.

    Messages encode wallclock in millis, firedancer converts
    them into nanos internally. */
  long    wallclock_nanos;

  uchar   value_bytes[ FD_GOSSIP_CRDS_MAX_SZ ];
  ushort  value_sz;

  /* The value hash is the sha256 of the value_bytes.  It is used in
     bloom filter generation and as a tiebreaker when a
     fd_crds_checks_fast call returns CHECK_UNDETERMINED. */
  uchar   value_hash[ 32UL ];
  ulong   num_duplicates;
  ulong   stake;

  struct {
    ulong next;
  } pool;

  /* The CRDS needs to perform a variety of actions on the message table
     quickly, so there are various indexes woven through them values to
     support these actions.  They are ...

     lookup is used to enable the core map<key, value> functionality
     described for upserts defined by value->key. */
  struct {
    ulong next;
    ulong prev;
  } lookup;

  /* The table has a fixed size message capacity, and supports eviction
     so insertion never fails.  If the table is full and we wish to
     insert a new value, the "lowest priority" message is evicted to
     make room.  This is accomplished with a treap sorted by stake, so
     the lowest stake message is removed. */
  struct {
    ulong parent;
    ulong left;
    ulong right;
    ulong prio;
    ulong next;
    ulong prev;
  } evict;

  /* Values in the table expire after a pre-determined amount of time,
     so we also keep a linked list of values sorted by creation time.
     The time used here is our nodes wallclock when we received the
     CRDS, not the originators local wallclock, which they could skew
     to cause their values to live longer.

     There are actually two lists that reuse the same pointers here,
     and a value will be in exactly one of the lists.  One is for staked
     nodes, which values expire after 48 hours, and one is for unstaked
     nodes, which expire after 15 seconds. */
  struct {
    long  wallclock_nanos;
    ulong prev;
    ulong next;
  } expire;

  /* Finally, a core operation on the CRDS is to to query for values by
     hash, to respond to pull requests.  This is done with a treap
     sorted by hash, which is just the first 8 bytes value_hash. */
  struct {
    ulong hash;
    ulong parent;
    ulong left;
    ulong right;
    ulong next;
    ulong prev;
    ulong prio;
  } hash;
};

#define POOL_NAME   crds_pool
#define POOL_T      fd_crds_entry_t
#define POOL_NEXT   pool.next

#include "../../../util/tmpl/fd_pool.c"

#define TREAP_NAME      evict_treap
#define TREAP_T         fd_crds_entry_t
#define TREAP_QUERY_T   void *                                         /* We don't use query ... */
#define TREAP_CMP(q,e)  (__extension__({ (void)(q); (void)(e); -1; })) /* which means we don't need to give a real
                                                                          implementation to cmp either */
#define TREAP_IDX_T     ulong
#define TREAP_LT(e0,e1) ((e0)->stake<(e1)->stake)
#define TREAP_PARENT    evict.parent
#define TREAP_LEFT      evict.left
#define TREAP_RIGHT     evict.right
#define TREAP_PRIO      evict.prio
#define TREAP_OPTIMIZE_ITERATION 1
#define TREAP_NEXT      evict.next
#define TREAP_PREV      evict.prev

#include "../../../util/tmpl/fd_treap.c"

#define DLIST_NAME      staked_expire_dlist
#define DLIST_ELE_T     fd_crds_entry_t
#define DLIST_PREV      expire.prev
#define DLIST_NEXT      expire.next

#include "../../../util/tmpl/fd_dlist.c"

#define DLIST_NAME      unstaked_expire_dlist
#define DLIST_ELE_T     fd_crds_entry_t
#define DLIST_PREV      expire.prev
#define DLIST_NEXT      expire.next

#include "../../../util/tmpl/fd_dlist.c"


#define DLIST_NAME  crds_contact_info_fresh_list
#define DLIST_ELE_T fd_crds_entry_t
#define DLIST_PREV  contact_info.fresh_dlist.prev
#define DLIST_NEXT  contact_info.fresh_dlist.next
#include "../../../util/tmpl/fd_dlist.c"

#define DLIST_NAME  crds_contact_info_evict_dlist
#define DLIST_ELE_T fd_crds_entry_t
#define DLIST_PREV  contact_info.evict_dlist.prev
#define DLIST_NEXT  contact_info.evict_dlist.next
#include "../../../util/tmpl/fd_dlist.c"

#define TREAP_NAME      hash_treap
#define TREAP_T         fd_crds_entry_t
#define TREAP_QUERY_T   ulong
#define TREAP_CMP(q,e)  ((q>e->hash.hash)-(q<e->hash.hash))
#define TREAP_IDX_T     ulong
#define TREAP_OPTIMIZE_ITERATION 1
#define TREAP_NEXT      hash.next
#define TREAP_PREV      hash.prev
#define TREAP_LT(e0,e1) ((e0)->hash.hash<(e1)->hash.hash)

#define TREAP_PARENT    hash.parent
#define TREAP_LEFT      hash.left
#define TREAP_RIGHT     hash.right
#define TREAP_PRIO      hash.prio

#include "../../../util/tmpl/fd_treap.c"

static inline ulong
lookup_hash( fd_crds_key_t const * key,
             ulong                 seed ) {
  ulong hash_fn = ((ulong)key->tag)<<16;
  switch( key->tag ) {
  case FD_GOSSIP_VALUE_VOTE:
    hash_fn ^= key->vote_index;
    break;
  case FD_GOSSIP_VALUE_EPOCH_SLOTS:
    hash_fn ^= key->epoch_slots_index;
    break;
  case FD_GOSSIP_VALUE_DUPLICATE_SHRED:
    hash_fn ^= key->duplicate_shred_index;
    break;
  default:
    break;
  }
  return fd_funk_rec_key_hash1( key->pubkey, seed^hash_fn );
}

static inline int
lookup_eq( fd_crds_key_t const * key0,
           fd_crds_key_t const * key1 ) {
  if( FD_UNLIKELY( key0->tag!=key1->tag ) ) return 0;
  if( FD_UNLIKELY( !!memcmp( key0->pubkey, key1->pubkey, 32UL ) ) ) return 0;
  switch( key0->tag ) {
    case FD_GOSSIP_VALUE_VOTE:
      return key0->vote_index==key1->vote_index;
    case FD_GOSSIP_VALUE_EPOCH_SLOTS:
      return key0->epoch_slots_index==key1->epoch_slots_index;
    case FD_GOSSIP_VALUE_DUPLICATE_SHRED:
      return key0->duplicate_shred_index==key1->duplicate_shred_index;
    default:
      break;
  }
  return 1;
}

#define MAP_NAME          lookup_map
#define MAP_ELE_T         fd_crds_entry_t
#define MAP_KEY_T         fd_crds_key_t
#define MAP_KEY           key
#define MAP_IDX_T         ulong
#define MAP_NEXT          lookup.next
#define MAP_PREV          lookup.prev
#define MAP_KEY_HASH(k,s) (lookup_hash( k, s ))
#define MAP_KEY_EQ(k0,k1) (lookup_eq( k0, k1 ))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1

#include "../../../util/tmpl/fd_map_chain.c"

#include "fd_crds_peer_samplers.c"

struct fd_crds_purged {
  uchar hash[ 32UL ];
  struct {
    ulong next;
  } pool;

  /* Similar to fd_crds_entry, we want the ability to query and iterate
     through value by hash[:8] to generate pull requests. */
  struct {
    ulong parent;
    ulong left;
    ulong right;
    ulong next;
    ulong prev;
    ulong prio;
  } treap;

  /* Similar to fd_crds_entry, we keep a linked list of purged values sorted
     by insertion time. The time used here is our node's wallclock.

     There are actually two (mutually exclusive) lists that reuse the same
     pointers here: one for "purged" entries that expire in 60s and one for
     "failed_inserts" that expire after 20s. */
  struct {
    long  wallclock_nanos;
    ulong next;
    ulong prev;
  } expire;
};
typedef struct fd_crds_purged fd_crds_purged_t;

#define POOL_NAME purged_pool
#define POOL_T    fd_crds_purged_t
#define POOL_NEXT pool.next

#include "../../../util/tmpl/fd_pool.c"

#define TREAP_NAME      purged_treap
#define TREAP_T         fd_crds_purged_t
#define TREAP_QUERY_T   ulong
#define TREAP_CMP(q,e)  ((q>*(ulong *)(e->hash))-(q<*(ulong *)(e->hash)))
#define TREAP_OPTIMIZE_ITERATION 1
#define TREAP_NEXT      treap.next
#define TREAP_PREV      treap.prev
#define TREAP_LT(e0,e1) (*(ulong *)((e0)->hash)<*(ulong *)((e1)->hash))

#define TREAP_PARENT treap.parent
#define TREAP_LEFT   treap.left
#define TREAP_RIGHT  treap.right
#define TREAP_PRIO   treap.prio

#include "../../../util/tmpl/fd_treap.c"

#define DLIST_NAME  failed_inserts_dlist
#define DLIST_ELE_T fd_crds_purged_t
#define DLIST_PREV  expire.prev
#define DLIST_NEXT  expire.next

#include "../../../util/tmpl/fd_dlist.c"

#define DLIST_NAME  purged_dlist
#define DLIST_ELE_T fd_crds_purged_t
#define DLIST_PREV  expire.prev
#define DLIST_NEXT  expire.next

#include "../../../util/tmpl/fd_dlist.c"

struct fd_crds_private {
  fd_gossip_out_ctx_t * gossip_update;

  fd_sha256_t sha256[1];

  int has_staked_node;

  fd_crds_entry_t * pool;

  evict_treap_t *           evict_treap;
  staked_expire_dlist_t *   staked_expire_dlist;
  unstaked_expire_dlist_t * unstaked_expire_dlist;
  hash_treap_t *            hash_treap;
  lookup_map_t *            lookup_map;

  struct {
    fd_crds_purged_t *       pool;
    purged_treap_t *         treap;
    purged_dlist_t *         purged_dlist;
    failed_inserts_dlist_t * failed_inserts_dlist;
  } purged;

  struct {
    fd_crds_contact_info_entry_t *    pool;
    crds_contact_info_fresh_list_t *  fresh_dlist;
    crds_contact_info_evict_dlist_t * evict_dlist;
  } contact_info;

  crds_samplers_t samplers[1];

  fd_crds_metrics_t metrics[1];

  ulong magic;
};

FD_FN_CONST ulong
fd_crds_align( void ) {
  return FD_CRDS_ALIGN;
}

FD_FN_CONST ulong
fd_crds_footprint( ulong ele_max,
                   ulong purged_max ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_CRDS_ALIGN,                         sizeof(fd_crds_t) );
  l = FD_LAYOUT_APPEND( l, crds_pool_align(),                     crds_pool_footprint( ele_max )      );
  l = FD_LAYOUT_APPEND( l, evict_treap_align(),                   evict_treap_footprint( ele_max )    );
  l = FD_LAYOUT_APPEND( l, staked_expire_dlist_align(),           staked_expire_dlist_footprint()     );
  l = FD_LAYOUT_APPEND( l, unstaked_expire_dlist_align(),         unstaked_expire_dlist_footprint()   );
  l = FD_LAYOUT_APPEND( l, hash_treap_align(),                    hash_treap_footprint( ele_max )     );
  l = FD_LAYOUT_APPEND( l, lookup_map_align(),                    lookup_map_footprint( ele_max )     );
  l = FD_LAYOUT_APPEND( l, purged_pool_align(),                   purged_pool_footprint( purged_max ) );
  l = FD_LAYOUT_APPEND( l, purged_treap_align(),                  purged_treap_footprint( purged_max ) );
  l = FD_LAYOUT_APPEND( l, purged_dlist_align(),                  purged_dlist_footprint() );
  l = FD_LAYOUT_APPEND( l, failed_inserts_dlist_align(),          failed_inserts_dlist_footprint() );
  l = FD_LAYOUT_APPEND( l, crds_contact_info_pool_align(),        crds_contact_info_pool_footprint( CRDS_MAX_CONTACT_INFO ) );
  l = FD_LAYOUT_APPEND( l, crds_contact_info_fresh_list_align(),  crds_contact_info_fresh_list_footprint() );
  l = FD_LAYOUT_APPEND( l, crds_contact_info_evict_dlist_align(), crds_contact_info_evict_dlist_footprint() );
  return FD_LAYOUT_FINI( l, FD_CRDS_ALIGN );
}

void *
fd_crds_new( void *                    shmem,
             fd_rng_t *                rng,
             ulong                     ele_max,
             ulong                     purged_max,
             fd_gossip_out_ctx_t *     gossip_update_out ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_crds_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_pow2( ele_max ) ) ) {
    FD_LOG_WARNING(( "ele_max must be a power of 2" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_pow2( purged_max ) ) ) {
    FD_LOG_WARNING(( "purged_max must be a power of 2" ));
    return NULL;
  }

  if( FD_UNLIKELY( !rng ) ) {
    FD_LOG_WARNING(( "NULL rng" ));
    return NULL;
  }

  if( FD_UNLIKELY( !gossip_update_out ) ) {
    FD_LOG_WARNING(( "NULL gossip_out" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_crds_t * crds              = FD_SCRATCH_ALLOC_APPEND( l, FD_CRDS_ALIGN,                         sizeof(fd_crds_t) );
  void * _pool                  = FD_SCRATCH_ALLOC_APPEND( l, crds_pool_align(),                     crds_pool_footprint( ele_max ) );
  void * _evict_treap           = FD_SCRATCH_ALLOC_APPEND( l, evict_treap_align(),                   evict_treap_footprint( ele_max ) );
  void * _staked_expire_dlist   = FD_SCRATCH_ALLOC_APPEND( l, staked_expire_dlist_align(),           staked_expire_dlist_footprint() );
  void * _unstaked_expire_dlist = FD_SCRATCH_ALLOC_APPEND( l, unstaked_expire_dlist_align(),         unstaked_expire_dlist_footprint() );
  void * _hash_treap            = FD_SCRATCH_ALLOC_APPEND( l, hash_treap_align(),                    hash_treap_footprint( ele_max ) );
  void * _lookup_map            = FD_SCRATCH_ALLOC_APPEND( l, lookup_map_align(),                    lookup_map_footprint( ele_max ) );
  void * _purged_pool           = FD_SCRATCH_ALLOC_APPEND( l, purged_pool_align(),                   purged_pool_footprint( purged_max ) );
  void * _purged_treap          = FD_SCRATCH_ALLOC_APPEND( l, purged_treap_align(),                  purged_treap_footprint( purged_max ) );
  void * _purged_dlist          = FD_SCRATCH_ALLOC_APPEND( l, purged_dlist_align(),                  purged_dlist_footprint() );
  void * _failed_inserts_dlist  = FD_SCRATCH_ALLOC_APPEND( l, failed_inserts_dlist_align(),          failed_inserts_dlist_footprint() );
  void * _ci_pool               = FD_SCRATCH_ALLOC_APPEND( l, crds_contact_info_pool_align(),        crds_contact_info_pool_footprint( CRDS_MAX_CONTACT_INFO ) );
  void * _ci_dlist              = FD_SCRATCH_ALLOC_APPEND( l, crds_contact_info_fresh_list_align(),  crds_contact_info_fresh_list_footprint() );
  void * _ci_evict_dlist        = FD_SCRATCH_ALLOC_APPEND( l, crds_contact_info_evict_dlist_align(), crds_contact_info_evict_dlist_footprint() );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, FD_CRDS_ALIGN ) == (ulong)shmem + fd_crds_footprint( ele_max, purged_max ) );

  crds->pool = crds_pool_join( crds_pool_new( _pool, ele_max ) );
  FD_TEST( crds->pool );

  crds->evict_treap = evict_treap_join( evict_treap_new( _evict_treap, ele_max ) );
  FD_TEST( crds->evict_treap );
  evict_treap_seed( crds->pool, ele_max, fd_rng_ulong( rng ) );

  crds->staked_expire_dlist = staked_expire_dlist_join( staked_expire_dlist_new( _staked_expire_dlist ) );
  FD_TEST( crds->staked_expire_dlist );

  crds->unstaked_expire_dlist = unstaked_expire_dlist_join( unstaked_expire_dlist_new( _unstaked_expire_dlist ) );
  FD_TEST( crds->unstaked_expire_dlist );

  crds->hash_treap = hash_treap_join( hash_treap_new( _hash_treap, ele_max ) );
  FD_TEST( crds->hash_treap );
  hash_treap_seed( crds->pool, ele_max, fd_rng_ulong( rng ) );

  crds->lookup_map = lookup_map_join( lookup_map_new( _lookup_map, ele_max, fd_rng_ulong( rng ) ) );
  FD_TEST( crds->lookup_map );

  crds->purged.pool = purged_pool_join( purged_pool_new( _purged_pool, purged_max ) );
  FD_TEST( crds->purged.pool );

  crds->purged.treap = purged_treap_join( purged_treap_new( _purged_treap, purged_max ) );
  FD_TEST( crds->purged.treap );
  purged_treap_seed( crds->purged.pool, purged_max, fd_rng_ulong( rng ) );

  crds->purged.purged_dlist = purged_dlist_join( purged_dlist_new( _purged_dlist ) );
  FD_TEST( crds->purged.purged_dlist );

  crds->purged.failed_inserts_dlist = failed_inserts_dlist_join( failed_inserts_dlist_new( _failed_inserts_dlist ) );
  FD_TEST( crds->purged.failed_inserts_dlist );

  crds->contact_info.pool = crds_contact_info_pool_join( crds_contact_info_pool_new( _ci_pool, CRDS_MAX_CONTACT_INFO ) );
  FD_TEST( crds->contact_info.pool );

  crds->contact_info.fresh_dlist = crds_contact_info_fresh_list_join( crds_contact_info_fresh_list_new( _ci_dlist ) );
  FD_TEST( crds->contact_info.fresh_dlist );

  crds->contact_info.evict_dlist = crds_contact_info_evict_dlist_join( crds_contact_info_evict_dlist_new( _ci_evict_dlist ) );
  FD_TEST( crds->contact_info.evict_dlist );

  FD_TEST( fd_sha256_join( fd_sha256_new( crds->sha256 ) ) );

  crds_samplers_new( crds->samplers );

  memset( crds->metrics, 0, sizeof(fd_crds_metrics_t) );

  crds->gossip_update   = gossip_update_out;
  crds->has_staked_node = 0;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( crds->magic ) = FD_CRDS_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)crds;
}

fd_crds_t *
fd_crds_join( void * shcrds ) {
  if( FD_UNLIKELY( !shcrds ) ) {
    FD_LOG_WARNING(( "NULL shcrds" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shcrds, fd_crds_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shcrds" ));
    return NULL;
  }

  fd_crds_t * crds = (fd_crds_t *)shcrds;

  if( FD_UNLIKELY( crds->magic!=FD_CRDS_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return crds;
}

fd_crds_metrics_t const *
fd_crds_metrics( fd_crds_t const * crds ) {
  return crds->metrics;
}

static inline void
remove_contact_info( fd_crds_t *         crds,
                     fd_crds_entry_t *   ci,
                     long                now,
                     fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( !stem ) ) return;
  fd_gossip_update_message_t * msg = fd_gossip_out_get_chunk( crds->gossip_update );
  msg->tag = FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE;
  msg->wallclock_nanos = now;
  fd_memcpy( msg->origin_pubkey, ci->key.pubkey, 32UL );
  msg->contact_info_remove.idx = crds_contact_info_pool_idx( crds->contact_info.pool, ci->contact_info.ci );
  fd_gossip_tx_publish_chunk( crds->gossip_update, stem, (ulong)msg->tag, FD_GOSSIP_UPDATE_SZ_CONTACT_INFO_REMOVE, now );

  if( FD_LIKELY( ci->stake ) ) crds->metrics->peer_staked_cnt--;
  else                         crds->metrics->peer_unstaked_cnt--;

  crds->metrics->peer_visible_stake -= ci->stake;

  if( FD_LIKELY( !!ci->contact_info.fresh_dlist.in_list ) ) {
    crds_contact_info_fresh_list_ele_remove( crds->contact_info.fresh_dlist, ci, crds->pool );
  }
  crds_contact_info_evict_dlist_ele_remove( crds->contact_info.evict_dlist, ci, crds->pool );
  crds_contact_info_pool_ele_release( crds->contact_info.pool, ci->contact_info.ci );

  /* FIXME: If the peer is in any active set bucket, it is NOT removed
     here. If the peer is re-inserted into the CRDS table in the future,
     it is added back into the bucket's sampler. This means a peer can
     be sampled in a bucket (at least) twice during
     fd_active_set_rotate. */
  crds_samplers_rem_peer( crds->samplers, ci );
}

ulong
fd_crds_len( fd_crds_t const * crds ) {
  return crds_pool_used( crds->pool );
}

ulong
fd_crds_purged_len( fd_crds_t const * crds ) {
  return purged_pool_used( crds->purged.pool );
}

void
fd_crds_release( fd_crds_t *       crds,
                 fd_crds_entry_t * value ) {
  crds_pool_ele_release( crds->pool, value );
  crds->metrics->count[ value->key.tag ]--;
}

static inline void
expire( fd_crds_t *         crds,
        long                now,
        fd_stem_context_t * stem ){
  static const long SLOT_DURATION_NANOS            = 400L*1000L*1000L;
  static const long STAKED_EXPIRE_DURATION_NANOS   = 432000L*SLOT_DURATION_NANOS;
  static const long UNSTAKED_EXPIRE_DURATION_NANOS = 15L*1000L*1000L*1000L;

  while( !staked_expire_dlist_is_empty( crds->staked_expire_dlist, crds->pool ) ) {
    fd_crds_entry_t * head = staked_expire_dlist_ele_peek_head( crds->staked_expire_dlist, crds->pool );

    if( FD_LIKELY( head->expire.wallclock_nanos>now-STAKED_EXPIRE_DURATION_NANOS ) ) break;

    staked_expire_dlist_ele_pop_head( crds->staked_expire_dlist, crds->pool );
    hash_treap_ele_remove( crds->hash_treap, head, crds->pool );
    lookup_map_ele_remove( crds->lookup_map, &head->key, NULL, crds->pool );
    evict_treap_ele_remove( crds->evict_treap, head, crds->pool );

    if( FD_UNLIKELY( head->key.tag==FD_GOSSIP_VALUE_CONTACT_INFO ) ) remove_contact_info( crds, head, now, stem );
    fd_crds_release( crds, head );

    crds->metrics->expired_cnt++;
  }

  long unstaked_expire_duration_nanos = fd_long_if( crds->has_staked_node,
                                                    UNSTAKED_EXPIRE_DURATION_NANOS,
                                                    STAKED_EXPIRE_DURATION_NANOS );

  while( !unstaked_expire_dlist_is_empty( crds->unstaked_expire_dlist, crds->pool ) ) {
    fd_crds_entry_t * head = unstaked_expire_dlist_ele_peek_head( crds->unstaked_expire_dlist, crds->pool );

    if( FD_LIKELY( head->expire.wallclock_nanos>now-unstaked_expire_duration_nanos ) ) break;

    unstaked_expire_dlist_ele_pop_head( crds->unstaked_expire_dlist, crds->pool );
    hash_treap_ele_remove( crds->hash_treap, head, crds->pool );
    lookup_map_ele_remove( crds->lookup_map, &head->key, NULL, crds->pool );
    evict_treap_ele_remove( crds->evict_treap, head, crds->pool );

    if( FD_UNLIKELY( head->key.tag==FD_GOSSIP_VALUE_CONTACT_INFO ) ) remove_contact_info( crds, head, now, stem );
    fd_crds_release( crds, head );

    crds->metrics->expired_cnt++;
  }

  while( !purged_dlist_is_empty( crds->purged.purged_dlist, crds->purged.pool ) ) {
    fd_crds_purged_t * head = purged_dlist_ele_peek_head( crds->purged.purged_dlist, crds->purged.pool );

    if( FD_LIKELY( head->expire.wallclock_nanos>now-60L*1000L*1000L*1000L ) ) break;

    purged_dlist_ele_pop_head( crds->purged.purged_dlist, crds->purged.pool );
    purged_treap_ele_remove( crds->purged.treap, head, crds->purged.pool );
    purged_pool_ele_release( crds->purged.pool, head );

    crds->metrics->purged_cnt--;
    crds->metrics->purged_expired_cnt++;
  }

  while( !failed_inserts_dlist_is_empty( crds->purged.failed_inserts_dlist, crds->purged.pool ) ) {
    fd_crds_purged_t * head = failed_inserts_dlist_ele_peek_head( crds->purged.failed_inserts_dlist, crds->purged.pool );

    if( FD_LIKELY( head->expire.wallclock_nanos>now-20L*1000L*1000L*1000L ) ) break;

    failed_inserts_dlist_ele_pop_head( crds->purged.failed_inserts_dlist, crds->purged.pool );
    purged_treap_ele_remove( crds->purged.treap, head, crds->purged.pool );
    purged_pool_ele_release( crds->purged.pool, head );

    crds->metrics->purged_cnt--;
    crds->metrics->purged_expired_cnt++;
  }
}

void
unfresh( fd_crds_t * crds,
         long        now ) {
  while( !crds_contact_info_fresh_list_is_empty( crds->contact_info.fresh_dlist, crds->pool ) ) {
    fd_crds_entry_t * head = crds_contact_info_fresh_list_ele_peek_head( crds->contact_info.fresh_dlist, crds->pool );

    if( FD_LIKELY( head->expire.wallclock_nanos>now-60L*1000L*1000L*1000L ) ) break;

    head = crds_contact_info_fresh_list_ele_pop_head( crds->contact_info.fresh_dlist, crds->pool );
    head->contact_info.fresh_dlist.in_list = 0;
    crds_samplers_upd_peer_at_idx( crds->samplers, head, head->contact_info.sampler_idx, now );
  }
}

void
fd_crds_advance( fd_crds_t *         crds,
                 long                now,
                 fd_stem_context_t * stem ) {
  expire( crds, now, stem );
  unfresh( crds, now );
}

fd_crds_entry_t *
fd_crds_acquire( fd_crds_t *         crds,
                 long                now,
                 fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( !crds_pool_free( crds->pool ) ) ) {
    evict_treap_fwd_iter_t head = evict_treap_fwd_iter_init( crds->evict_treap, crds->pool );
    FD_TEST( !evict_treap_fwd_iter_done( head ) );
    fd_crds_entry_t * evict = evict_treap_fwd_iter_ele( head, crds->pool );

    if( FD_LIKELY( !evict->stake ) ) unstaked_expire_dlist_ele_remove( crds->unstaked_expire_dlist, evict, crds->pool );
    else                             staked_expire_dlist_ele_remove( crds->staked_expire_dlist, evict, crds->pool );

    hash_treap_ele_remove( crds->hash_treap, evict, crds->pool );
    lookup_map_ele_remove( crds->lookup_map, &evict->key, NULL, crds->pool );
    evict_treap_ele_remove( crds->evict_treap, evict, crds->pool );
    if( FD_UNLIKELY( evict->key.tag==FD_GOSSIP_VALUE_CONTACT_INFO ) ) remove_contact_info( crds, evict, now, stem );

    crds->metrics->evicted_cnt++;

    return evict;
  } else {
    return crds_pool_ele_acquire( crds->pool );
  }
}

int
fd_crds_has_staked_node( fd_crds_t const * crds ) {
  return crds->has_staked_node;
}

static inline void
generate_key( fd_gossip_view_crds_value_t const * view,
              uchar const *                       payload,
              fd_crds_key_t *                     out_key ) {
  out_key->tag = view->tag;
  fd_memcpy( out_key->pubkey, payload+view->pubkey_off, 32UL );

  switch( out_key->tag ) {
    case FD_GOSSIP_VALUE_VOTE:
      out_key->vote_index = view->vote->index;
      break;
    case FD_GOSSIP_VALUE_EPOCH_SLOTS:
      out_key->epoch_slots_index = view->epoch_slots->index;
      break;
    case FD_GOSSIP_VALUE_DUPLICATE_SHRED:
      out_key->duplicate_shred_index = view->duplicate_shred->index;
      break;
    default:
      break;
  }
}

void
fd_crds_generate_hash( fd_sha256_t * sha,
                       uchar const * crds_value,
                       ulong         crds_value_sz,
                       uchar         out_hash[ static 32UL ] ){
  fd_sha256_init( sha );
  fd_sha256_append( sha, crds_value, crds_value_sz );
  fd_sha256_fini( sha, out_hash );
}

static inline void
crds_entry_init( fd_gossip_view_crds_value_t const * view,
                 fd_sha256_t *                       sha,
                 uchar const *                       payload,
                 ulong                               stake,
                 fd_crds_entry_t *                   out_value ) {
  /* Construct key */
  fd_crds_key_t * key = &out_value->key;
  generate_key( view, payload, key );

  out_value->wallclock_nanos = view->wallclock_nanos;
  out_value->stake           = stake;

  fd_crds_generate_hash( sha, payload+view->value_off, view->length, out_value->value_hash );
  out_value->hash.hash = fd_ulong_load_8( out_value->value_hash );

  if( FD_UNLIKELY( view->tag==FD_GOSSIP_VALUE_NODE_INSTANCE ) ) {
    out_value->node_instance.token = view->node_instance->token;
  } else if( FD_UNLIKELY( key->tag==FD_GOSSIP_VALUE_CONTACT_INFO ) ) {
    out_value->contact_info.instance_creation_wallclock_nanos = view->ci_view->contact_info->instance_creation_wallclock_nanos;
    /* Contact Info entry will be added to sampler upon successful insertion */
    out_value->contact_info.sampler_idx = SAMPLE_IDX_SENTINEL;
  }
}

static inline void
purged_init( fd_crds_purged_t * purged,
             uchar const * hash,
             long          now ) {
  fd_memcpy( purged->hash, hash, 32UL );
  purged->expire.wallclock_nanos = now;
}

void
insert_purged( fd_crds_t *   crds,
               uchar const * hash,
               long          now ) {
  if( purged_treap_ele_query( crds->purged.treap, *(ulong *)hash, crds->purged.pool ) ) {
    return;
  }
  fd_crds_purged_t * purged;
  if( FD_UNLIKELY( !purged_pool_free( crds->purged.pool ) ) ) {
    purged = purged_dlist_ele_pop_head( crds->purged.purged_dlist, crds->purged.pool );
    purged_treap_ele_remove( crds->purged.treap, purged, crds->purged.pool );
    if( FD_LIKELY( crds->metrics ) ) {
      crds->metrics->purged_evicted_cnt++;
    }
  } else {
    purged = purged_pool_ele_acquire( crds->purged.pool );
    if( FD_LIKELY( crds->metrics ) ) {
      crds->metrics->purged_cnt++;
    }
  }
  purged_init( purged, hash, now );
  purged_treap_ele_insert( crds->purged.treap, purged, crds->purged.pool );
  purged_dlist_ele_push_tail( crds->purged.purged_dlist, purged, crds->purged.pool );
}

/* overrides_fast
    - returns 1 if candidate overrides existing (incumbent) CRDS value
    - returns 0 if candidate does not override existing CRDS value
    - return -1 if further checks are needed (e.g. hash comparison) */
int
overrides_fast( fd_crds_entry_t const *             incumbent,
                fd_gossip_view_crds_value_t const * candidate,
                uchar const *                       payload ){
  long existing_wc        = incumbent->wallclock_nanos;
  long candidate_wc       = candidate->wallclock_nanos;
  long existing_ci_onset  = incumbent->contact_info.instance_creation_wallclock_nanos;
  long candidate_ci_onset = candidate->ci_view->contact_info->instance_creation_wallclock_nanos;

  switch( candidate->tag ) {
    case FD_GOSSIP_VALUE_CONTACT_INFO:
      if( FD_UNLIKELY( candidate_ci_onset>existing_ci_onset ) ) return 1;
      else if( FD_UNLIKELY( candidate_ci_onset<existing_ci_onset ) ) return 0;
      else if( FD_UNLIKELY( candidate_wc>existing_wc ) ) return 1;
      else if( FD_UNLIKELY( candidate_wc<existing_wc ) ) return 0;
      break;
    case FD_GOSSIP_VALUE_NODE_INSTANCE:
      if( FD_LIKELY( candidate->node_instance->token==incumbent->node_instance.token ) ) break;
      else if( FD_LIKELY( memcmp( payload+candidate->pubkey_off, incumbent->key.pubkey, 32UL ) ) ) break;
      else if( FD_UNLIKELY( candidate_wc>existing_wc ) ) return 1;
      else if( FD_UNLIKELY( candidate_wc<existing_wc ) ) return 0;
      else if( candidate->node_instance->token<incumbent->node_instance.token ) return 0;;
      break;
    default:
      break;
  }

  if( FD_UNLIKELY( candidate_wc>existing_wc ) ) return 1;
  else if( FD_UNLIKELY( candidate_wc<existing_wc ) ) return 0;
  return -1;
}


void
fd_crds_insert_failed_insert( fd_crds_t *   crds,
                              uchar const * hash,
                              long          now ) {
  if( purged_treap_ele_query( crds->purged.treap, *(ulong *)hash, crds->purged.pool ) ) {
    return;
  }
  fd_crds_purged_t * failed;
  if( FD_UNLIKELY( !purged_pool_free( crds->purged.pool ) ) ) {
    failed = failed_inserts_dlist_ele_pop_head( crds->purged.failed_inserts_dlist, crds->purged.pool );
    purged_treap_ele_remove( crds->purged.treap, failed, crds->purged.pool );
    if( FD_LIKELY( crds->metrics ) ) {
      crds->metrics->purged_evicted_cnt++;
    }
  } else {
    failed = purged_pool_ele_acquire( crds->purged.pool );
    if( FD_LIKELY( crds->metrics ) ) {
      crds->metrics->purged_cnt++;
    }
  }
  purged_init( failed, hash, now );
  purged_treap_ele_insert( crds->purged.treap, failed, crds->purged.pool );
  failed_inserts_dlist_ele_push_tail( crds->purged.failed_inserts_dlist, failed, crds->purged.pool );
}

int
fd_crds_checks_fast( fd_crds_t *                         crds,
                     fd_gossip_view_crds_value_t const * candidate,
                     uchar const *                       payload,
                     uchar                               from_push_msg ) {
  fd_crds_key_t candidate_key;
  generate_key( candidate, payload, &candidate_key );
  fd_crds_entry_t * incumbent = lookup_map_ele_query( crds->lookup_map, &candidate_key, NULL, crds->pool );

  if( FD_UNLIKELY( !incumbent ) ) return FD_CRDS_UPSERT_CHECK_UPSERTS;

  if( FD_UNLIKELY( *(ulong *)incumbent->value_bytes==(*(ulong *)(payload+candidate->value_off)) ) ) {
    /* We have a duplicate, so we return the number of duplicates */
    return (int)(++incumbent->num_duplicates);
  }
  int overrides = overrides_fast( incumbent, candidate, payload );
  if( FD_LIKELY( overrides==1 ) ) return FD_CRDS_UPSERT_CHECK_UPSERTS;

  uchar cand_hash[ 32UL ];
  fd_crds_generate_hash( crds->sha256, payload+candidate->value_off, candidate->length, cand_hash );

  if( FD_UNLIKELY( overrides==-1 ) ) {
    /* Tiebreaker case, we compare hash values */
    int res = memcmp( cand_hash, incumbent->value_hash, 32UL );
    if( FD_UNLIKELY( !res ) ) {
      /* Hashes match, so we treat this as a duplicate */
      return (int)(++incumbent->num_duplicates);
    } else if( res>0 ) {
      /* Candidate hash is greater than incumbent hash, so we treat
        this as an upsert */
      return FD_CRDS_UPSERT_CHECK_UPSERTS;
    }
  }

  from_push_msg ? insert_purged( crds, cand_hash, candidate->wallclock_nanos ) :
                  fd_crds_insert_failed_insert( crds, cand_hash, candidate->wallclock_nanos );

  return FD_CRDS_UPSERT_CHECK_FAILS;
}

static inline void
publish_update_msg( fd_crds_t *                         crds,
                    fd_crds_entry_t *                   entry,
                    fd_gossip_view_crds_value_t const * entry_view,
                    uchar const *                       payload,
                    long                                now,
                    fd_stem_context_t *                 stem ) {
  if( FD_UNLIKELY( !stem ) ) return;
  if( FD_LIKELY( entry->key.tag!=FD_GOSSIP_VALUE_CONTACT_INFO    &&
                 entry->key.tag!=FD_GOSSIP_VALUE_LOWEST_SLOT     &&
                 entry->key.tag!=FD_GOSSIP_VALUE_VOTE            &&
                 entry->key.tag!=FD_GOSSIP_VALUE_DUPLICATE_SHRED &&
                 entry->key.tag!=FD_GOSSIP_VALUE_INC_SNAPSHOT_HASHES ) ) {
    return;
  }

  fd_gossip_update_message_t * msg = fd_gossip_out_get_chunk( crds->gossip_update );
  msg->wallclock_nanos = now;
  fd_memcpy( msg->origin_pubkey, entry->key.pubkey, 32UL );
  ulong sz;
  switch( entry->key.tag ) {
    case FD_GOSSIP_VALUE_CONTACT_INFO:
      msg->tag = FD_GOSSIP_UPDATE_TAG_CONTACT_INFO;
      *msg->contact_info.contact_info = *entry->contact_info.ci->contact_info;
      msg->contact_info.idx = crds_contact_info_pool_idx( crds->contact_info.pool, entry->contact_info.ci );
      sz = FD_GOSSIP_UPDATE_SZ_CONTACT_INFO;
      break;
    case FD_GOSSIP_VALUE_LOWEST_SLOT:
      msg->tag = FD_GOSSIP_UPDATE_TAG_LOWEST_SLOT;
      sz = FD_GOSSIP_UPDATE_SZ_LOWEST_SLOT;
      msg->lowest_slot = entry_view->lowest_slot;
      break;
    case FD_GOSSIP_VALUE_VOTE:
      msg->tag = FD_GOSSIP_UPDATE_TAG_VOTE;
      /* TODO: dynamic sizing */
      sz = FD_GOSSIP_UPDATE_SZ_VOTE;
      fd_crds_key_t lookup_ci;
      lookup_ci.tag = FD_GOSSIP_VALUE_CONTACT_INFO;
      fd_memcpy( &lookup_ci.pubkey, entry->key.pubkey, sizeof(fd_pubkey_t) );
      fd_crds_entry_t * ci = lookup_map_ele_query( crds->lookup_map, &lookup_ci, NULL, crds->pool );

      if( FD_LIKELY( ci && ci->key.tag == FD_GOSSIP_VALUE_CONTACT_INFO ) ) {
        msg->vote.socket = ci->contact_info.ci->contact_info->sockets[ FD_CONTACT_INFO_SOCKET_GOSSIP ];
      } else {
        msg->vote.socket = (fd_ip4_port_t){ 0 };
      }

      msg->vote.vote_tower_index = entry->key.vote_index;
      msg->vote.txn_sz = entry_view->vote->txn_sz;
      fd_memcpy( msg->vote.txn, payload+entry_view->vote->txn_off, entry_view->vote->txn_sz );
      break;
    case FD_GOSSIP_VALUE_DUPLICATE_SHRED:
      msg->tag = FD_GOSSIP_UPDATE_TAG_DUPLICATE_SHRED;
      /* TODO: dynamic sizing */
      sz = FD_GOSSIP_UPDATE_SZ_DUPLICATE_SHRED;
      {
        fd_gossip_view_duplicate_shred_t const * ds     = entry_view->duplicate_shred;
        fd_gossip_duplicate_shred_t *            ds_msg = &msg->duplicate_shred;

        ds_msg->index       = ds->index;
        ds_msg->slot        = ds->slot;
        ds_msg->num_chunks  = ds->num_chunks;
        ds_msg->chunk_index = ds->chunk_index;
        ds_msg->wallclock   = entry->wallclock_nanos;
        ds_msg->chunk_len   = ds->chunk_len;
        fd_memcpy( ds_msg->chunk, payload+ds->chunk_off, ds->chunk_len );
      }
      break;
    case FD_GOSSIP_VALUE_INC_SNAPSHOT_HASHES:
      msg->tag = FD_GOSSIP_UPDATE_TAG_SNAPSHOT_HASHES;
      /* TODO: dynamic sizing */
      sz = FD_GOSSIP_UPDATE_SZ_SNAPSHOT_HASHES;
      {
        fd_gossip_view_snapshot_hashes_t const * sh     = entry_view->snapshot_hashes;
        fd_gossip_snapshot_hashes_t *            sh_msg = &msg->snapshot_hashes;

        sh_msg->incremental_len = sh->inc_len;
        fd_memcpy( sh_msg->full, payload+sh->full_off, sizeof(fd_gossip_snapshot_hash_pair_t) );
        fd_memcpy( sh_msg->incremental,  payload+sh->inc_off, sh->inc_len*sizeof(fd_gossip_snapshot_hash_pair_t) );
      }
      break;
    default:
      FD_LOG_ERR(( "impossible" ));
  }
  fd_gossip_tx_publish_chunk( crds->gossip_update,
                              stem,
                              (ulong)msg->tag,
                              sz,
                              now );
}

fd_crds_entry_t const *
fd_crds_insert( fd_crds_t *                         crds,
                fd_gossip_view_crds_value_t const * candidate_view,
                uchar const *                       payload,
                ulong                               origin_stake,
                uchar                               is_from_me,
                long                                now ,
                fd_stem_context_t *                 stem ) {
  /* Update table count metrics at the end to avoid early return
     handling */
  fd_crds_entry_t * candidate = fd_crds_acquire( crds, now, stem );
  crds_entry_init( candidate_view, crds->sha256, payload, origin_stake, candidate );

  crds->metrics->count[ candidate->key.tag ]++;

  fd_crds_entry_t * incumbent = lookup_map_ele_query( crds->lookup_map, &candidate->key, NULL, crds->pool );
  uchar is_replacing = incumbent!=NULL;
  if( FD_LIKELY( is_replacing ) ) {
    insert_purged( crds, incumbent->value_hash, now );

    if( FD_UNLIKELY( incumbent->key.tag==FD_GOSSIP_VALUE_CONTACT_INFO ) ) {
      if( FD_LIKELY( !!incumbent->contact_info.fresh_dlist.in_list ) ) crds_contact_info_fresh_list_ele_remove( crds->contact_info.fresh_dlist, incumbent, crds->pool );
      crds_contact_info_evict_dlist_ele_remove( crds->contact_info.evict_dlist, incumbent, crds->pool );
      candidate->contact_info.ci = incumbent->contact_info.ci;

      /* is_active is user controlled (specifically by ping_tracker),
         and is used in sampler score calculations. So we inherit the
         incumbent's setting. */
      candidate->contact_info.is_active = incumbent->contact_info.is_active;
      if( FD_LIKELY( !is_from_me ) ) {
        if( FD_UNLIKELY( candidate->stake!=incumbent->stake ) ) {
          /* Perform a rescore here (expensive) */
          crds_samplers_upd_peer_at_idx( crds->samplers, candidate, incumbent->contact_info.sampler_idx, now );
        } else {
          crds_samplers_swap_peer_at_idx( crds->samplers, candidate, incumbent->contact_info.sampler_idx );
        }
      }

      if( FD_LIKELY( incumbent->stake ) ) crds->metrics->peer_staked_cnt--;
      else                                crds->metrics->peer_unstaked_cnt--;
      crds->metrics->peer_visible_stake -= incumbent->stake;
    }

    if( FD_LIKELY( incumbent->stake ) ) {
      staked_expire_dlist_ele_remove( crds->staked_expire_dlist, incumbent, crds->pool );
    } else {
      unstaked_expire_dlist_ele_remove( crds->unstaked_expire_dlist, incumbent, crds->pool );
    }
    evict_treap_ele_remove( crds->evict_treap, incumbent, crds->pool );
    hash_treap_ele_remove( crds->hash_treap, incumbent, crds->pool );
    lookup_map_ele_remove( crds->lookup_map, &incumbent->key, NULL, crds->pool );
    fd_crds_release( crds, incumbent );
  } else if( candidate->key.tag==FD_GOSSIP_VALUE_CONTACT_INFO ) {
    if( FD_UNLIKELY( !crds_contact_info_pool_free( crds->contact_info.pool ) ) ) {
      fd_crds_entry_t * evict = crds_contact_info_evict_dlist_ele_peek_head( crds->contact_info.evict_dlist, crds->pool );
      remove_contact_info( crds, evict, now, stem );
      if( FD_LIKELY( evict->stake ) ) {
        staked_expire_dlist_ele_remove( crds->staked_expire_dlist, evict, crds->pool );
      } else {
        unstaked_expire_dlist_ele_remove( crds->unstaked_expire_dlist, evict, crds->pool );
      }
      evict_treap_ele_remove( crds->evict_treap, evict, crds->pool );
      hash_treap_ele_remove( crds->hash_treap, evict, crds->pool );
      lookup_map_ele_remove( crds->lookup_map, &evict->key, NULL, crds->pool );
      fd_crds_release( crds, evict );
      crds->metrics->peer_evicted_cnt++;
      crds->metrics->evicted_cnt++;
    }

    candidate->contact_info.ci = crds_contact_info_pool_ele_acquire( crds->contact_info.pool );
  }

  candidate->num_duplicates         = 0UL;
  candidate->expire.wallclock_nanos = now;
  candidate->value_sz               = candidate_view->length;
  fd_memcpy( candidate->value_bytes, payload+candidate_view->value_off, candidate_view->length );

  crds->has_staked_node |= candidate->stake ? 1 : 0;

  evict_treap_ele_insert( crds->evict_treap, candidate, crds->pool );
  if( FD_LIKELY( candidate->stake ) ) {
    staked_expire_dlist_ele_push_tail( crds->staked_expire_dlist, candidate, crds->pool );
  } else {
    unstaked_expire_dlist_ele_push_tail( crds->unstaked_expire_dlist, candidate, crds->pool );
  }
  hash_treap_ele_insert( crds->hash_treap, candidate, crds->pool );
  lookup_map_ele_insert( crds->lookup_map, candidate, crds->pool );

  if( FD_UNLIKELY( candidate->key.tag==FD_GOSSIP_VALUE_CONTACT_INFO ) ) {
    fd_memcpy( candidate->contact_info.ci->contact_info, candidate_view->ci_view->contact_info, sizeof(fd_contact_info_t) );
    /* Default to active, since we filter inactive entries prior to insertion */
    candidate->contact_info.is_active = 1;

    crds_contact_info_evict_dlist_ele_push_tail( crds->contact_info.evict_dlist, candidate, crds->pool );

    if( FD_LIKELY( !is_from_me ) ){
      crds_contact_info_fresh_list_ele_push_tail( crds->contact_info.fresh_dlist, candidate, crds->pool );
      candidate->contact_info.fresh_dlist.in_list = 1;
    } else {
      candidate->contact_info.fresh_dlist.in_list = 0;
    }

    if( FD_UNLIKELY( !is_replacing && !is_from_me ) ) {
      crds_samplers_add_peer( crds->samplers, candidate, now);
    }

    if( FD_LIKELY( candidate->stake ) ) crds->metrics->peer_staked_cnt++;
    else                                crds->metrics->peer_unstaked_cnt++;
    crds->metrics->peer_visible_stake += candidate->stake;
  }

  publish_update_msg( crds, candidate, candidate_view, payload, now, stem );
  return candidate;
}

void
fd_crds_entry_value( fd_crds_entry_t const *  entry,
                     uchar const **           value_bytes,
                     ulong *                  value_sz ) {
  *value_bytes = entry->value_bytes;
  *value_sz    = entry->value_sz;
}

uchar const *
fd_crds_entry_hash( fd_crds_entry_t const * entry ) {
  return entry->value_hash;
}

inline static void
make_contact_info_key( uchar const * pubkey,
                       fd_crds_key_t * key_out ) {
  key_out->tag = FD_GOSSIP_VALUE_CONTACT_INFO;
  fd_memcpy( key_out->pubkey, pubkey, 32UL );
}

int
fd_crds_entry_is_contact_info( fd_crds_entry_t const * entry ) {
  return entry->key.tag==FD_GOSSIP_VALUE_CONTACT_INFO;
}

fd_contact_info_t *
fd_crds_entry_contact_info( fd_crds_entry_t const * entry ) {
  return entry->contact_info.ci->contact_info;
}


fd_contact_info_t const *
fd_crds_contact_info_lookup( fd_crds_t const * crds,
                              uchar const *     pubkey ) {

  fd_crds_key_t key[1];
  make_contact_info_key( pubkey, key );
  fd_crds_entry_t * peer_ci = lookup_map_ele_query( crds->lookup_map, key, NULL, crds->pool );
  if( FD_UNLIKELY( !peer_ci ) ) {
    return NULL;
  }

  return peer_ci->contact_info.ci->contact_info;
}

ulong
fd_crds_peer_count( fd_crds_t const * crds ){
  return crds_contact_info_pool_used( crds->contact_info.pool );
}

static inline void
set_peer_active_status( fd_crds_t *   crds,
                        uchar const * peer_pubkey,
                        uchar         status,
                        long          now ) {

  fd_crds_key_t key[1];
  make_contact_info_key( peer_pubkey, key );

  fd_crds_entry_t * peer_ci = lookup_map_ele_query( crds->lookup_map, key, NULL, crds->pool );
  /* TODO: error handling? This technically should never hit */
  if( FD_UNLIKELY( !peer_ci ) ) return;
  uchar old_status = peer_ci->contact_info.is_active;
  peer_ci->contact_info.is_active = status;

  if( FD_UNLIKELY( old_status!=status ) ) {
    /* Trigger sampler update */
    crds_samplers_upd_peer_at_idx( crds->samplers,
                                   peer_ci,
                                   peer_ci->contact_info.sampler_idx,
                                   now );
  }
}
void
fd_crds_peer_active( fd_crds_t *   crds,
                     uchar const * peer_pubkey,
                     long          now ) {
  set_peer_active_status( crds, peer_pubkey, 1 /* active */, now );
}

void
fd_crds_peer_inactive( fd_crds_t *   crds,
                       uchar const * peer_pubkey,
                       long          now ) {
  set_peer_active_status( crds, peer_pubkey, 0 /* inactive */, now );
}

fd_contact_info_t const *
fd_crds_peer_sample( fd_crds_t const * crds,
                     fd_rng_t *         rng ) {
  ulong idx = wpeer_sampler_sample( crds->samplers->pr_sampler,
                                    rng,
                                    crds->samplers->ele_cnt );
  if( FD_UNLIKELY( idx==SAMPLE_IDX_SENTINEL ) ) return NULL;
  return fd_crds_entry_contact_info( crds->samplers->ele[idx] );
}

fd_contact_info_t const *
fd_crds_bucket_sample_and_remove( fd_crds_t * crds,
                                  fd_rng_t *  rng,
                                  ulong       bucket ) {
  ulong idx = wpeer_sampler_sample( &crds->samplers->bucket_samplers[bucket],
                                    rng,
                                    crds->samplers->ele_cnt );
  if( FD_UNLIKELY( idx==SAMPLE_IDX_SENTINEL ) ) return NULL;
  /* Disable peer to prevent future sampling until added back with
     fd_crds_bucket_add */
  wpeer_sampler_disable( &crds->samplers->bucket_samplers[bucket],
                         idx,
                         crds->samplers->ele_cnt );

  return fd_crds_entry_contact_info( crds->samplers->ele[idx] );
}

void
fd_crds_bucket_add( fd_crds_t *   crds,
                    ulong         bucket,
                    uchar const * pubkey ) {
  fd_crds_key_t key[1];
  make_contact_info_key( pubkey, key );
  fd_crds_entry_t * peer_ci = lookup_map_ele_query( crds->lookup_map, key, NULL, crds->pool );
  if( FD_UNLIKELY( !peer_ci ) ) {
    FD_LOG_DEBUG(( "Sample peer not found in CRDS. Likely dropped." ));
    return;
  }
  wpeer_sampler_t * bucket_sampler = &crds->samplers->bucket_samplers[bucket];
  wpeer_sampler_enable( bucket_sampler,
                        peer_ci->contact_info.sampler_idx,
                        crds->samplers->ele_cnt );

  ulong score = wpeer_sampler_bucket_score( peer_ci,  bucket );
  wpeer_sampler_upd( bucket_sampler,
                     score,
                     peer_ci->contact_info.sampler_idx,
                     crds->samplers->ele_cnt );
}

struct fd_crds_mask_iter_private {
  ulong idx;
  ulong end_hash;
};

fd_crds_mask_iter_t *
fd_crds_mask_iter_init( fd_crds_t const * crds,
                        ulong             mask,
                        uint              mask_bits,
                        uchar             iter_mem[ static 16UL ] ) {
  fd_crds_mask_iter_t * it = (fd_crds_mask_iter_t *)iter_mem;
  ulong start_hash         = 0 ;
  if( FD_LIKELY( mask_bits > 0) ) start_hash = (mask&(~0UL<<(64UL-mask_bits)));

  it->end_hash             = mask;

  it->idx                  = hash_treap_idx_ge( crds->hash_treap, start_hash, crds->pool );
  return it;
}

fd_crds_mask_iter_t *
fd_crds_mask_iter_next( fd_crds_mask_iter_t * it, fd_crds_t const * crds ) {
  fd_crds_entry_t const * val = hash_treap_ele_fast_const( it->idx, crds->pool );
  it->idx                     = val->hash.next;
  return it;
}

int
fd_crds_mask_iter_done( fd_crds_mask_iter_t * it, fd_crds_t const * crds ) {
  fd_crds_entry_t const * val = hash_treap_ele_fast_const( it->idx, crds->pool );
  return hash_treap_idx_is_null( it->idx ) ||
         (it->end_hash < val->hash.hash);
}

fd_crds_entry_t const *
fd_crds_mask_iter_entry( fd_crds_mask_iter_t * it, fd_crds_t const * crds ){
  return hash_treap_ele_fast_const( it->idx, crds->pool );
}

fd_crds_mask_iter_t *
fd_crds_purged_mask_iter_init( fd_crds_t const * crds,
                               ulong             mask,
                               uint              mask_bits,
                               uchar             iter_mem[ static 16UL ] ){
  fd_crds_mask_iter_t * it = (fd_crds_mask_iter_t *)iter_mem;
  ulong start_hash         = 0;
  if( FD_LIKELY( mask_bits > 0 ) ) start_hash = (mask&(~0UL<<(64UL-mask_bits)));
  it->end_hash             = mask;

  it->idx                  = purged_treap_idx_ge( crds->purged.treap, start_hash, crds->purged.pool );
  return it;
}

fd_crds_mask_iter_t *
fd_crds_purged_mask_iter_next( fd_crds_mask_iter_t * it,
                               fd_crds_t const *     crds ){
  fd_crds_purged_t const * val = purged_treap_ele_fast_const( it->idx, crds->purged.pool );
  it->idx                      = val->treap.next;
  return it;
}

int
fd_crds_purged_mask_iter_done( fd_crds_mask_iter_t * it,
                               fd_crds_t const *     crds ){
  fd_crds_purged_t const * val = purged_treap_ele_fast_const( it->idx, crds->purged.pool );
  return purged_treap_idx_is_null( it->idx ) ||
         (it->end_hash < fd_ulong_load_8( val->hash ));
}

/* fd_crds_purged_mask_iter_hash returns the hash of the current
   entry in the purged mask iterator. */
uchar const *
fd_crds_purged_mask_iter_hash( fd_crds_mask_iter_t * it,
                               fd_crds_t const *     crds ){
  fd_crds_purged_t const * val = purged_treap_ele_fast_const( it->idx, crds->purged.pool );
  return val->hash;
}
