#include "fd_crds.h"

#include "../../../ballet/sha256/fd_sha256.h"
#include "../../../funk/fd_funk_base.h" /* no link dependency, only using hash */

#include <string.h>

struct fd_crds_contact_info_entry {
  fd_gossip_contact_info_t contact_info[1];
  long                     received_wallclock_nanos;

  fd_crds_entry_t *        crds_entry; /* Back-pointer to CRDS pool entry */

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

  /* Similar to fresh_dlist, but with a 15s timeout instead.
     Additionally, fresh_dlist explicilty excludes our own contact info
     while fresh_15s_dlist includes it. */
  struct {
    ulong prev;
    ulong next;
    uchar in_list; /* 1 if in the fresh list, 0 otherwise */
  } fresh_15s_dlist;

  /* The contact info side table has a separate size limit, so
     we maintain a separate evict list to make space for new
     entries */
  struct {
    ulong prev;
    ulong next;
  } evict_dlist;

  struct {
    ulong next;
  } pool;
};

typedef struct fd_crds_contact_info_entry fd_crds_contact_info_entry_t;

#define POOL_NAME  crds_contact_info_pool
#define POOL_T     fd_crds_contact_info_entry_t
#define POOL_NEXT  pool.next
#include "../../../util/tmpl/fd_pool.c"

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
    fd_crds_contact_info_entry_t * ci;
    ulong node_instance_token;
  };

  /* When an originator creates a CRDS message, they attach their local
     wallclock time to it.  This time is used to determine when a
     message should be upserted.  If messages have the same key, the
     newer one (as created by the originator) is used. */
  ulong wallclock;

  ushort value_sz;
  uchar  value_bytes[ FD_GOSSIP_VALUE_MAX_SZ ];
  uchar  value_hash[ 32UL ];

  ulong num_duplicates;
  ulong stake;

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
     nodes, which expire after 15 seconds (or also 48hours if the node
     is configured as unstaked). */
  struct {
    long  wallclock_nanos;
    ulong prev;
    ulong next;
  } expire;

  /* In order to load balance pull request messages across peers, each
     message has a mask value that is mask_bits long.  The pull request
     is only concerned with CRDS entires with a hash where the first
     mask_bits of the hash match the mask value.

     We need to be able to quickly iterate over all CRDS table entries
     matching a given mask.  To do this, we store the first 8 bytes of
     the value_hash in a sorted treap. */
  struct {
    ulong hash_prefix; /* TODO: Remove .. just use hash_value */
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

/* staked_expire_dlist tracks contact info crds entries inserted in the
   last 432000L*SLOT_DURATION_NANOS nanoseconds with nonzero active
   stake according to their epoch stake at the time they are inserted. */
#define DLIST_NAME      staked_expire_dlist
#define DLIST_ELE_T     fd_crds_entry_t
#define DLIST_PREV      expire.prev
#define DLIST_NEXT      expire.next

#include "../../../util/tmpl/fd_dlist.c"

/* unstaked_expire_dlist tracks contact info crds entries from the last
   432000L*SLOT_DURATION_NANOS nanoseconds (or from the last 15 seconds,
   if this node is itself running as unstaked) with zero active stake
   according to their epoch stake at the time they are inserted. */
#define DLIST_NAME      unstaked_expire_dlist
#define DLIST_ELE_T     fd_crds_entry_t
#define DLIST_PREV      expire.prev
#define DLIST_NEXT      expire.next

#include "../../../util/tmpl/fd_dlist.c"

/* fresh_15s_dlist tracks all contact info crds entries from the last
   15 seconds. */
#define DLIST_NAME      ci_fresh_15s_dlist
#define DLIST_ELE_T     fd_crds_contact_info_entry_t
#define DLIST_PREV      fresh_15s_dlist.prev
#define DLIST_NEXT      fresh_15s_dlist.next
#include "../../../util/tmpl/fd_dlist.c"

/* crds_contact_info_fresh_list tracks all contact info crds entries
   from the last 60 seconds. */
#define DLIST_NAME  crds_contact_info_fresh_list
#define DLIST_ELE_T fd_crds_contact_info_entry_t
#define DLIST_PREV  fresh_dlist.prev
#define DLIST_NEXT  fresh_dlist.next
#include "../../../util/tmpl/fd_dlist.c"

#define DLIST_NAME  crds_contact_info_evict_dlist
#define DLIST_ELE_T fd_crds_contact_info_entry_t
#define DLIST_PREV  evict_dlist.prev
#define DLIST_NEXT  evict_dlist.next
#include "../../../util/tmpl/fd_dlist.c"

#define TREAP_NAME      hash_treap
#define TREAP_T         fd_crds_entry_t
#define TREAP_QUERY_T   ulong
#define TREAP_CMP(q,e)  ((q>e->hash.hash_prefix)-(q<e->hash.hash_prefix))
#define TREAP_IDX_T     ulong
#define TREAP_OPTIMIZE_ITERATION 1
#define TREAP_NEXT      hash.next
#define TREAP_PREV      hash.prev
#define TREAP_LT(e0,e1) ((e0)->hash.hash_prefix<(e1)->hash.hash_prefix)
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

#include "../fd_gossip_wsample.h"

struct fd_crds_private {
  fd_gossip_out_ctx_t * gossip_update;

  fd_gossip_activity_update_fn activity_update_fn;
  void *                       activity_update_fn_ctx;

  fd_sha256_t sha256[1];

  int has_staked_node;

  fd_crds_entry_t * pool;
  fd_crds_contact_info_entry_t * ci_pool;

  evict_treap_t *           evict_treap;
  staked_expire_dlist_t *   staked_expire_dlist;
  unstaked_expire_dlist_t * unstaked_expire_dlist;
  ci_fresh_15s_dlist_t *    ci_fresh_15s_dlist;
  hash_treap_t *            hash_treap;
  lookup_map_t *            lookup_map;

  fd_gossip_purged_t *      purged;

  crds_contact_info_fresh_list_t *  ci_fresh_dlist;
  crds_contact_info_evict_dlist_t * ci_evict_dlist;

  fd_gossip_wsample_t *    wsample;

  fd_crds_metrics_t metrics[1];

  ulong magic;
};

FD_FN_CONST ulong
fd_crds_align( void ) {
  return FD_CRDS_ALIGN;
}

FD_FN_CONST ulong
fd_crds_footprint( ulong ele_max ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_CRDS_ALIGN,                         sizeof(fd_crds_t) );
  l = FD_LAYOUT_APPEND( l, crds_pool_align(),                     crds_pool_footprint( ele_max )                                 );
  l = FD_LAYOUT_APPEND( l, evict_treap_align(),                   evict_treap_footprint( ele_max )                               );
  l = FD_LAYOUT_APPEND( l, staked_expire_dlist_align(),           staked_expire_dlist_footprint()                                );
  l = FD_LAYOUT_APPEND( l, unstaked_expire_dlist_align(),         unstaked_expire_dlist_footprint()                              );
  l = FD_LAYOUT_APPEND( l, ci_fresh_15s_dlist_align(),            ci_fresh_15s_dlist_footprint()                                 );
  l = FD_LAYOUT_APPEND( l, hash_treap_align(),                    hash_treap_footprint( ele_max )                                );
  l = FD_LAYOUT_APPEND( l, lookup_map_align(),                    lookup_map_footprint( ele_max )                                );
  l = FD_LAYOUT_APPEND( l, crds_contact_info_pool_align(),        crds_contact_info_pool_footprint( FD_CONTACT_INFO_TABLE_SIZE ) );
  l = FD_LAYOUT_APPEND( l, crds_contact_info_fresh_list_align(),  crds_contact_info_fresh_list_footprint()                       );
  l = FD_LAYOUT_APPEND( l, crds_contact_info_evict_dlist_align(), crds_contact_info_evict_dlist_footprint()                      );
  l = FD_LAYOUT_APPEND( l, fd_gossip_wsample_align(),             fd_gossip_wsample_footprint( FD_CONTACT_INFO_TABLE_SIZE )      );
  return FD_LAYOUT_FINI( l, FD_CRDS_ALIGN );
}

void *
fd_crds_new( void *                       shmem,
             fd_rng_t *                   rng,
             ulong                        ele_max,
             fd_gossip_purged_t *         purged,
             fd_gossip_activity_update_fn activity_update_fn,
             void *                       activity_update_fn_ctx,
             fd_gossip_out_ctx_t *        gossip_update_out ) {
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

  if( FD_UNLIKELY( !rng ) ) {
    FD_LOG_WARNING(( "NULL rng" ));
    return NULL;
  }

  if( FD_UNLIKELY( !purged ) ) {
    FD_LOG_WARNING(( "NULL purged" ));
    return NULL;
  }

  if( FD_UNLIKELY( !gossip_update_out ) ) {
    FD_LOG_WARNING(( "NULL gossip_out" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_crds_t * crds              = FD_SCRATCH_ALLOC_APPEND( l, FD_CRDS_ALIGN,                         sizeof(fd_crds_t) );
  void * _pool                  = FD_SCRATCH_ALLOC_APPEND( l, crds_pool_align(),                     crds_pool_footprint( ele_max )                                 );
  void * _evict_treap           = FD_SCRATCH_ALLOC_APPEND( l, evict_treap_align(),                   evict_treap_footprint( ele_max )                               );
  void * _staked_expire_dlist   = FD_SCRATCH_ALLOC_APPEND( l, staked_expire_dlist_align(),           staked_expire_dlist_footprint()                                );
  void * _unstaked_expire_dlist = FD_SCRATCH_ALLOC_APPEND( l, unstaked_expire_dlist_align(),         unstaked_expire_dlist_footprint()                              );
  void * _ci_fresh_15s_dlist    = FD_SCRATCH_ALLOC_APPEND( l, ci_fresh_15s_dlist_align(),            ci_fresh_15s_dlist_footprint()                                 );
  void * _hash_treap            = FD_SCRATCH_ALLOC_APPEND( l, hash_treap_align(),                    hash_treap_footprint( ele_max )                                );
  void * _lookup_map            = FD_SCRATCH_ALLOC_APPEND( l, lookup_map_align(),                    lookup_map_footprint( ele_max )                                );
  void * _ci_pool               = FD_SCRATCH_ALLOC_APPEND( l, crds_contact_info_pool_align(),        crds_contact_info_pool_footprint( FD_CONTACT_INFO_TABLE_SIZE ) );
  void * _ci_dlist              = FD_SCRATCH_ALLOC_APPEND( l, crds_contact_info_fresh_list_align(),  crds_contact_info_fresh_list_footprint()                       );
  void * _ci_evict_dlist        = FD_SCRATCH_ALLOC_APPEND( l, crds_contact_info_evict_dlist_align(), crds_contact_info_evict_dlist_footprint()                      );
  void * _wsample               = FD_SCRATCH_ALLOC_APPEND( l, fd_gossip_wsample_align(),             fd_gossip_wsample_footprint( FD_CONTACT_INFO_TABLE_SIZE )      );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, FD_CRDS_ALIGN ) == (ulong)shmem + fd_crds_footprint( ele_max ) );

  crds->activity_update_fn = activity_update_fn;
  FD_TEST( crds->activity_update_fn );

  crds->activity_update_fn_ctx = activity_update_fn_ctx;

  crds->pool = crds_pool_join( crds_pool_new( _pool, ele_max ) );
  FD_TEST( crds->pool );

  crds->evict_treap = evict_treap_join( evict_treap_new( _evict_treap, ele_max ) );
  FD_TEST( crds->evict_treap );
  evict_treap_seed( crds->pool, ele_max, fd_rng_ulong( rng ) );

  crds->staked_expire_dlist = staked_expire_dlist_join( staked_expire_dlist_new( _staked_expire_dlist ) );
  FD_TEST( crds->staked_expire_dlist );

  crds->unstaked_expire_dlist = unstaked_expire_dlist_join( unstaked_expire_dlist_new( _unstaked_expire_dlist ) );
  FD_TEST( crds->unstaked_expire_dlist );

  crds->ci_fresh_15s_dlist = ci_fresh_15s_dlist_join( ci_fresh_15s_dlist_new( _ci_fresh_15s_dlist ) );
  FD_TEST( crds->ci_fresh_15s_dlist );

  crds->hash_treap = hash_treap_join( hash_treap_new( _hash_treap, ele_max ) );
  FD_TEST( crds->hash_treap );
  hash_treap_seed( crds->pool, ele_max, fd_rng_ulong( rng ) );

  crds->lookup_map = lookup_map_join( lookup_map_new( _lookup_map, ele_max, fd_rng_ulong( rng ) ) );
  FD_TEST( crds->lookup_map );

  crds->purged = purged;

  crds->ci_pool = crds_contact_info_pool_join( crds_contact_info_pool_new( _ci_pool, FD_CONTACT_INFO_TABLE_SIZE ) );
  FD_TEST( crds->ci_pool );

  crds->ci_fresh_dlist = crds_contact_info_fresh_list_join( crds_contact_info_fresh_list_new( _ci_dlist ) );
  FD_TEST( crds->ci_fresh_dlist );

  crds->ci_evict_dlist = crds_contact_info_evict_dlist_join( crds_contact_info_evict_dlist_new( _ci_evict_dlist ) );
  FD_TEST( crds->ci_evict_dlist );

  FD_TEST( fd_sha256_join( fd_sha256_new( crds->sha256 ) ) );

  crds->wsample = fd_gossip_wsample_join( fd_gossip_wsample_new( _wsample, rng, FD_CONTACT_INFO_TABLE_SIZE ) );
  FD_TEST( crds->wsample );

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

ulong
fd_crds_len( fd_crds_t const * crds ) {
  return crds_pool_used( crds->pool );
}

static inline void
crds_unindex( fd_crds_t *       crds,
              fd_crds_entry_t * entry ) {
  if( FD_LIKELY( entry->stake ) ) staked_expire_dlist_ele_remove( crds->staked_expire_dlist, entry, crds->pool );
  else                            unstaked_expire_dlist_ele_remove( crds->unstaked_expire_dlist, entry, crds->pool );

  evict_treap_ele_remove( crds->evict_treap, entry, crds->pool );
  hash_treap_ele_remove( crds->hash_treap, entry, crds->pool );
  lookup_map_ele_remove( crds->lookup_map, &entry->key, NULL, crds->pool );

  if( FD_UNLIKELY( entry->key.tag==FD_GOSSIP_VALUE_CONTACT_INFO ) ) {
    if( FD_LIKELY( entry->stake ) ) crds->metrics->peer_staked_cnt--;
    else                            crds->metrics->peer_unstaked_cnt--;
    crds->metrics->peer_visible_stake -= entry->stake;

    if( FD_LIKELY( entry->ci->fresh_dlist.in_list ) ) crds_contact_info_fresh_list_ele_remove( crds->ci_fresh_dlist, entry->ci, crds->ci_pool );
    if( FD_LIKELY( entry->ci->fresh_15s_dlist.in_list ) ) {
      ci_fresh_15s_dlist_ele_remove( crds->ci_fresh_15s_dlist, entry->ci, crds->ci_pool );
      crds->activity_update_fn( crds->activity_update_fn_ctx, (fd_pubkey_t const *)entry->key.pubkey, entry->ci->contact_info, FD_GOSSIP_ACTIVITY_CHANGE_TYPE_INACTIVE );
    }
    crds_contact_info_evict_dlist_ele_remove( crds->ci_evict_dlist, entry->ci, crds->ci_pool );
  }

  crds->metrics->count[ entry->key.tag ]--;
}

static inline void
crds_index( fd_crds_t *       crds,
            fd_crds_entry_t * entry ) {
  if( FD_LIKELY( entry->stake ) ) staked_expire_dlist_ele_push_tail( crds->staked_expire_dlist, entry, crds->pool );
  else                            unstaked_expire_dlist_ele_push_tail( crds->unstaked_expire_dlist, entry, crds->pool );

  evict_treap_ele_insert( crds->evict_treap, entry, crds->pool );
  hash_treap_ele_insert( crds->hash_treap, entry, crds->pool );
  lookup_map_ele_insert( crds->lookup_map, entry, crds->pool );

  if( FD_UNLIKELY( entry->key.tag==FD_GOSSIP_VALUE_CONTACT_INFO ) ) {
    if( FD_LIKELY( entry->stake ) ) crds->metrics->peer_staked_cnt++;
    else                            crds->metrics->peer_unstaked_cnt++;
    crds->metrics->peer_visible_stake += entry->stake;

    crds_contact_info_evict_dlist_ele_push_tail( crds->ci_evict_dlist, entry->ci, crds->ci_pool );
    crds_contact_info_fresh_list_ele_push_tail( crds->ci_fresh_dlist, entry->ci, crds->ci_pool );
    ci_fresh_15s_dlist_ele_push_tail( crds->ci_fresh_15s_dlist, entry->ci, crds->ci_pool );
    entry->ci->fresh_dlist.in_list = 1;
    entry->ci->fresh_15s_dlist.in_list = 1;
    crds->activity_update_fn( crds->activity_update_fn_ctx, (fd_pubkey_t const *)entry->key.pubkey, entry->ci->contact_info, FD_GOSSIP_ACTIVITY_CHANGE_TYPE_ACTIVE );
  }

  crds->metrics->count[ entry->key.tag ]++;
}

static inline void
crds_release( fd_crds_t *         crds,
              fd_crds_entry_t *   entry,
              long                now,
              int                 evicting,
              fd_stem_context_t * stem ) {
  crds_unindex( crds, entry );
  fd_gossip_purged_insert_replaced( crds->purged, entry->value_hash, now );

  if( FD_UNLIKELY( entry->key.tag==FD_GOSSIP_VALUE_CONTACT_INFO ) ) {
    if( FD_UNLIKELY( evicting ) ) crds->metrics->peer_evicted_cnt++;

    fd_gossip_update_message_t * msg = fd_gossip_out_get_chunk( crds->gossip_update );
    msg->tag = FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE;
    msg->wallclock = (ulong)FD_NANOSEC_TO_MILLI( now );
    msg->contact_info_remove->idx = crds_contact_info_pool_idx( crds->ci_pool, entry->ci );
    fd_memcpy( msg->origin, entry->key.pubkey, 32UL );
    fd_gossip_tx_publish_chunk( crds->gossip_update, stem, (ulong)msg->tag, FD_GOSSIP_UPDATE_SZ_CONTACT_INFO_REMOVE, now );

    /* FIXME: If the peer is in any active set bucket, it is NOT removed
       here. If the peer is re-inserted into the CRDS table in the
       future, it is added back into the bucket's sampler. This means a
       peer can be sampled in a bucket (at least) twice during
       fd_active_set_rotate. */
    fd_gossip_wsample_remove( crds->wsample, crds_contact_info_pool_idx( crds->ci_pool, entry->ci ) );

    crds_contact_info_pool_ele_release( crds->ci_pool, entry->ci );
  }

  if( FD_UNLIKELY( evicting ) ) crds->metrics->evicted_cnt++;
  else                          crds->metrics->expired_cnt++;

  crds_pool_ele_release( crds->pool, entry );
}

static inline fd_crds_entry_t *
crds_acquire( fd_crds_t *         crds,
              int                 is_contact_info,
              long                now,
              fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( is_contact_info ) ) {
    /* TODO: Should evict lowest stake CI first, or oldest if equally
       low stake. */
    if( FD_UNLIKELY( !crds_contact_info_pool_free( crds->ci_pool ) ) ) {
      fd_crds_contact_info_entry_t * ci_evict = crds_contact_info_evict_dlist_ele_peek_head( crds->ci_evict_dlist, crds->ci_pool );
      crds_release( crds, ci_evict->crds_entry, now, 1, stem );
    } else if( FD_UNLIKELY( !crds_pool_free( crds->pool ) ) ) {
      evict_treap_fwd_iter_t it = evict_treap_fwd_iter_init( crds->evict_treap, crds->pool );
      FD_TEST( !evict_treap_fwd_iter_done( it ) );
      crds_release( crds, evict_treap_fwd_iter_ele( it, crds->pool ), now, 1, stem );
    }
    fd_crds_contact_info_entry_t * ci = crds_contact_info_pool_ele_acquire( crds->ci_pool );
    fd_crds_entry_t * entry = crds_pool_ele_acquire( crds->pool );
    entry->ci = ci;
    entry->ci->crds_entry = entry;
    return entry;
  } else {
    if( FD_UNLIKELY( !crds_pool_free( crds->pool ) ) ) {
      evict_treap_fwd_iter_t it = evict_treap_fwd_iter_init( crds->evict_treap, crds->pool );
      FD_TEST( !evict_treap_fwd_iter_done( it ) );
      crds_release( crds, evict_treap_fwd_iter_ele( it, crds->pool ), now, 1, stem );
    }
    return crds_pool_ele_acquire( crds->pool );
  }
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
    crds_release( crds, head, now, 0, stem );
  }

  long unstaked_expire_duration_nanos = fd_long_if( crds->has_staked_node,
                                                    UNSTAKED_EXPIRE_DURATION_NANOS,
                                                    STAKED_EXPIRE_DURATION_NANOS );

  while( !unstaked_expire_dlist_is_empty( crds->unstaked_expire_dlist, crds->pool ) ) {
    fd_crds_entry_t * head = unstaked_expire_dlist_ele_peek_head( crds->unstaked_expire_dlist, crds->pool );

    if( FD_LIKELY( head->expire.wallclock_nanos>now-unstaked_expire_duration_nanos ) ) break;
    crds_release( crds, head, now, 0, stem );
  }
}

static void
unfresh( fd_crds_t * crds,
         long        now ) {
  while( !crds_contact_info_fresh_list_is_empty( crds->ci_fresh_dlist, crds->ci_pool ) ) {
    fd_crds_contact_info_entry_t * head = crds_contact_info_fresh_list_ele_peek_head( crds->ci_fresh_dlist, crds->ci_pool );

    if( FD_LIKELY( head->received_wallclock_nanos>now-60L*1000L*1000L*1000L ) ) break;
    head = crds_contact_info_fresh_list_ele_pop_head( crds->ci_fresh_dlist, crds->ci_pool );
    FD_TEST( head->fresh_dlist.in_list );
    head->fresh_dlist.in_list = 0;

    fd_gossip_wsample_fresh( crds->wsample, crds_contact_info_pool_idx( crds->ci_pool, head ), 0 );
  }

  while( !ci_fresh_15s_dlist_is_empty( crds->ci_fresh_15s_dlist, crds->ci_pool ) ) {
    fd_crds_contact_info_entry_t * head = ci_fresh_15s_dlist_ele_peek_head( crds->ci_fresh_15s_dlist, crds->ci_pool );

    if( FD_LIKELY( head->received_wallclock_nanos>now-15L*1000L*1000L*1000L ) ) break;

    head = ci_fresh_15s_dlist_ele_pop_head( crds->ci_fresh_15s_dlist, crds->ci_pool );

    FD_TEST( head->fresh_15s_dlist.in_list );
    head->fresh_15s_dlist.in_list = 0U;
    crds->activity_update_fn( crds->activity_update_fn_ctx, (fd_pubkey_t const *)head->crds_entry->key.pubkey, head->contact_info, FD_GOSSIP_ACTIVITY_CHANGE_TYPE_INACTIVE );
  }
}

void
fd_crds_advance( fd_crds_t *         crds,
                 long                now,
                 fd_stem_context_t * stem ) {
  expire( crds, now, stem );
  unfresh( crds, now );
}

int
fd_crds_has_staked_node( fd_crds_t const * crds ) {
  return crds->has_staked_node;
}

static inline void
publish_update_msg( fd_crds_t *               crds,
                    fd_crds_entry_t *         entry,
                    fd_gossip_value_t const * entry_view,
                    long                      now,
                    fd_stem_context_t *       stem ) {
  FD_TEST( stem );
  if( FD_LIKELY( entry->key.tag!=FD_GOSSIP_VALUE_CONTACT_INFO    &&
                 entry->key.tag!=FD_GOSSIP_VALUE_VOTE            &&
                 entry->key.tag!=FD_GOSSIP_VALUE_DUPLICATE_SHRED &&
                 entry->key.tag!=FD_GOSSIP_VALUE_SNAPSHOT_HASHES ) ) {
    return;
  }

  fd_gossip_update_message_t * msg = fd_gossip_out_get_chunk( crds->gossip_update );
  msg->wallclock = entry->wallclock;
  fd_memcpy( msg->origin, entry->key.pubkey, 32UL );

  ulong sz;
  switch( entry->key.tag ) {
    case FD_GOSSIP_VALUE_CONTACT_INFO:
      msg->tag = FD_GOSSIP_UPDATE_TAG_CONTACT_INFO;
      *msg->contact_info->value = *entry->ci->contact_info;
      msg->contact_info->idx = crds_contact_info_pool_idx( crds->ci_pool, entry->ci );
      sz = FD_GOSSIP_UPDATE_SZ_CONTACT_INFO;
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
        msg->vote->socket->is_ipv6 = ci->ci->contact_info->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].is_ipv6;
        if( msg->vote->socket->is_ipv6 ) {
          fd_memcpy( msg->vote->socket->ip6, ci->ci->contact_info->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].ip6, 16UL );
        } else {
          msg->vote->socket->ip4 = ci->ci->contact_info->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].ip4;
        }
        msg->vote->socket->port = ci->ci->contact_info->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].port;
      } else {
        msg->vote->socket->is_ipv6 = 0;
        msg->vote->socket->ip4 = 0;
        msg->vote->socket->port = 0;
      }

      msg->vote->value->index = entry->key.vote_index;
      msg->vote->value->transaction_len = entry_view->vote->transaction_len;
      fd_memcpy( msg->vote->value->transaction, entry_view->vote->transaction, entry_view->vote->transaction_len );
      break;
    case FD_GOSSIP_VALUE_DUPLICATE_SHRED:
      msg->tag = FD_GOSSIP_UPDATE_TAG_DUPLICATE_SHRED;
      /* TODO: dynamic sizing */
      sz = FD_GOSSIP_UPDATE_SZ_DUPLICATE_SHRED;
      {
        fd_gossip_duplicate_shred_t const * ds     = entry_view->duplicate_shred;
        fd_gossip_duplicate_shred_t *            ds_msg = msg->duplicate_shred;

        ds_msg->index       = ds->index;
        ds_msg->slot        = ds->slot;
        ds_msg->num_chunks  = ds->num_chunks;
        ds_msg->chunk_index = ds->chunk_index;
        ds_msg->chunk_len   = ds->chunk_len;
        fd_memcpy( ds_msg->chunk, ds->chunk, ds->chunk_len );
      }
      break;
    case FD_GOSSIP_VALUE_SNAPSHOT_HASHES:
      msg->tag = FD_GOSSIP_UPDATE_TAG_SNAPSHOT_HASHES;
      /* TODO: dynamic sizing */
      sz = FD_GOSSIP_UPDATE_SZ_SNAPSHOT_HASHES;
      {
        fd_gossip_snapshot_hashes_t const * sh     = entry_view->snapshot_hashes;
        fd_gossip_snapshot_hashes_t *            sh_msg = msg->snapshot_hashes;

        sh_msg->full_slot = sh->full_slot;
        fd_memcpy( sh_msg->full_hash, sh->full_hash, 32UL );
        sh_msg->incremental_len = sh->incremental_len;
        for( ulong i=0; i<sh->incremental_len; i++ ) {
          sh_msg->incremental[ i ].slot = sh->incremental[ i ].slot;
          fd_memcpy( sh_msg->incremental[ i ].hash, sh->incremental[ i ].hash, 32UL );
        }
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

static int
crds_compare( fd_crds_entry_t const *   incumbent,
              fd_gossip_value_t const * candidate ){
  int compare = 0;
  switch( candidate->tag ) {
    case FD_GOSSIP_VALUE_CONTACT_INFO:
      if( FD_UNLIKELY( candidate->contact_info->outset<incumbent->ci->contact_info->outset ) ) compare = 1;
      else if( FD_UNLIKELY( candidate->contact_info->outset>incumbent->ci->contact_info->outset ) ) compare = -1;
      break;
    /* NodeInstance has no special override logic in Agave — it uses
       the default wallclock + hash tiebreaker like all other types. */
    default:
      break;
  }

  if( FD_UNLIKELY( compare ) ) return compare;

  if( FD_UNLIKELY( candidate->wallclock<incumbent->wallclock ) ) return 1;
  else if( FD_UNLIKELY( candidate->wallclock>incumbent->wallclock ) ) return -1;
  else return 0;
}

long
fd_crds_insert( fd_crds_t *               crds,
                fd_gossip_value_t const * value,
                uchar const *             value_bytes,
                ulong                     value_bytes_len,
                ulong                     origin_stake,
                int                       origin_active,
                int                       is_me,
                long                      now ,
                fd_stem_context_t *       stem ) {
  fd_crds_key_t candidate_key = {
    .tag = (uchar)value->tag,
  };
  switch( candidate_key.tag ) {
    case FD_GOSSIP_VALUE_VOTE: candidate_key.vote_index = value->vote->index; break;
    case FD_GOSSIP_VALUE_EPOCH_SLOTS: candidate_key.epoch_slots_index = value->epoch_slots->index; break;
    case FD_GOSSIP_VALUE_DUPLICATE_SHRED: candidate_key.duplicate_shred_index = value->duplicate_shred->index; break;
    default: break;
  }
  fd_memcpy( candidate_key.pubkey, value->origin, 32UL );

  fd_crds_entry_t * incumbent = lookup_map_ele_query( crds->lookup_map, &candidate_key, NULL, crds->pool );
  int replacing = !!incumbent;

  uchar value_hash[ 32UL ];
  if( FD_UNLIKELY( !replacing ) ) {
    fd_sha256_hash( value_bytes, value_bytes_len, value_hash );

    incumbent = crds_acquire( crds, value->tag==FD_GOSSIP_VALUE_CONTACT_INFO, now, stem );
    incumbent->key = candidate_key;
    if( FD_UNLIKELY( value->tag==FD_GOSSIP_VALUE_CONTACT_INFO ) ) {
      fd_gossip_wsample_add( crds->wsample, crds_contact_info_pool_idx( crds->ci_pool, incumbent->ci ), origin_stake, origin_active && !is_me );
    }
  } else {
    /* Fast duplicate check by signature before computing expensive
       sha256 hash. */
    if( FD_UNLIKELY( fd_ulong_load_8( incumbent->value_bytes )==fd_ulong_load_8( value->signature ) ) ) return (long)(++incumbent->num_duplicates);

    fd_sha256_hash( value_bytes, value_bytes_len, value_hash );
    switch( crds_compare( incumbent, value ) ) {
      case -1: break; /* upserting */
      case 0: {
        int result = memcmp( value_hash, incumbent->value_hash, 32UL );
        if( FD_UNLIKELY( !result ) ) return (long)(++incumbent->num_duplicates);
        else if( FD_UNLIKELY( result<0 ) ) {
          fd_gossip_purged_insert_failed_insert( crds->purged, value_hash, now );
          return -1L; /* stale */
        }
        else break; /* upserting */
      }
      case 1: {
        fd_gossip_purged_insert_failed_insert( crds->purged, value_hash, now );
        return -1L; /* stale */
      }
    }

    fd_gossip_purged_insert_replaced( crds->purged, incumbent->value_hash, now );
    crds_unindex( crds, incumbent );

    if( FD_UNLIKELY( value->tag==FD_GOSSIP_VALUE_CONTACT_INFO ) ) {
      fd_gossip_wsample_fresh( crds->wsample, crds_contact_info_pool_idx( crds->ci_pool, incumbent->ci ), 1 );
      if( FD_UNLIKELY( incumbent->stake!=origin_stake ) ) fd_gossip_wsample_stake( crds->wsample, crds_contact_info_pool_idx( crds->ci_pool, incumbent->ci ), origin_stake );
    }
  }

  incumbent->wallclock              = value->wallclock;
  incumbent->stake                  = origin_stake;
  incumbent->num_duplicates         = 0UL;
  incumbent->expire.wallclock_nanos = now;
  incumbent->value_sz               = (ushort)value_bytes_len;
  fd_memcpy( incumbent->value_bytes, value_bytes, value_bytes_len );
  fd_memcpy( incumbent->value_hash, value_hash, 32UL );
  incumbent->hash.hash_prefix = fd_ulong_load_8( incumbent->value_hash );

  if( FD_UNLIKELY( value->tag==FD_GOSSIP_VALUE_NODE_INSTANCE ) ) {
    incumbent->node_instance_token = value->node_instance->token;
  } else if( FD_UNLIKELY( value->tag==FD_GOSSIP_VALUE_CONTACT_INFO ) ) {
    *incumbent->ci->contact_info            = *value->contact_info;
    incumbent->ci->received_wallclock_nanos = now;
  }

  crds_index( crds, incumbent );

  crds->has_staked_node |= incumbent->stake ? 1 : 0;

  publish_update_msg( crds, incumbent, value, now, stem );

  return 0L;
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

fd_gossip_contact_info_t *
fd_crds_entry_contact_info( fd_crds_entry_t const * entry ) {
  return entry->ci->contact_info;
}

fd_gossip_contact_info_t const *
fd_crds_contact_info_lookup( fd_crds_t const * crds,
                             uchar const *     pubkey ) {

  fd_crds_key_t key[1];
  make_contact_info_key( pubkey, key );
  fd_crds_entry_t * peer_ci = lookup_map_ele_query( crds->lookup_map, key, NULL, crds->pool );
  if( FD_UNLIKELY( !peer_ci ) ) {
    return NULL;
  }

  return peer_ci->ci->contact_info;
}

ulong
fd_crds_peer_count( fd_crds_t const * crds ){
  return crds_contact_info_pool_used( crds->ci_pool );
}

void
fd_crds_peer_active( fd_crds_t *   crds,
                     uchar const * peer_pubkey,
                     int           active ) {
  fd_crds_key_t key[1];
  make_contact_info_key( peer_pubkey, key );

  fd_crds_entry_t * peer_ci = lookup_map_ele_query( crds->lookup_map, key, NULL, crds->pool );
  if( FD_UNLIKELY( !peer_ci ) ) return;
  fd_gossip_wsample_active( crds->wsample, crds_contact_info_pool_idx( crds->ci_pool, peer_ci->ci ), active );
}

void
fd_crds_self_stake( fd_crds_t * crds,
                    ulong       self_stake ) {
  fd_gossip_wsample_self_stake( crds->wsample, self_stake );
}

fd_gossip_contact_info_t const *
fd_crds_peer_sample( fd_crds_t const * crds ) {
  ulong idx = fd_gossip_wsample_sample_pull_request( crds->wsample );
  if( FD_UNLIKELY( idx==ULONG_MAX ) ) return NULL;
  return crds->ci_pool[ idx ].contact_info;
}

uchar const *
fd_crds_bucket_sample_and_remove( fd_crds_t * crds,
                                  ulong       bucket ) {
  ulong idx = fd_gossip_wsample_sample_remove_bucket( crds->wsample, bucket );
  if( FD_UNLIKELY( idx==ULONG_MAX ) ) return NULL;
  return crds->ci_pool[ idx ].crds_entry->key.pubkey;
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

  ulong ci_idx = crds_contact_info_pool_idx( crds->ci_pool, peer_ci->ci );
  fd_gossip_wsample_add_bucket( crds->wsample, bucket, ci_idx );
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
  ulong start_hash, end_hash;
  fd_gossip_purged_generate_masks( mask, mask_bits, &start_hash, &end_hash );

  fd_crds_mask_iter_t * it = (fd_crds_mask_iter_t *)iter_mem;
  it->end_hash             = end_hash;
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
  if( FD_UNLIKELY( hash_treap_idx_is_null( it->idx ) ) ) return 1;
  fd_crds_entry_t const * val = hash_treap_ele_fast_const( it->idx, crds->pool );
  return it->end_hash < val->hash.hash_prefix;
}

fd_crds_entry_t const *
fd_crds_mask_iter_entry( fd_crds_mask_iter_t * it, fd_crds_t const * crds ){
  return hash_treap_ele_fast_const( it->idx, crds->pool );
}
