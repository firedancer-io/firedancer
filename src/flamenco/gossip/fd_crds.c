#include "fd_crds.h"
#include "fd_crds_value.h"

#define FD_CRDS_ALIGN 8UL
#define FD_CRDS_MAGIC (0xf17eda2c37c7d50UL) /* firedancer crds version 0*/

#define FD_CRDS_TAG_LEGACY_CONTACT_INFO           ( 0)
#define FD_CRDS_TAG_VOTE                          ( 1)
#define FD_CRDS_TAG_LOWEST_SLOT                   ( 2)
#define FD_CRDS_TAG_SNAPSHOT_HASHES               ( 3)
#define FD_CRDS_TAG_ACCOUNT_HASHES                ( 4)
#define FD_CRDS_TAG_EPOCH_SLOTS                   ( 5)
#define FD_CRDS_TAG_LEGACY_VERSION_V1             ( 6)
#define FD_CRDS_TAG_LEGACY_VERSION_V2             ( 7)
#define FD_CRDS_TAG_NODE_INSTANCE                 ( 8)
#define FD_CRDS_TAG_DUPLICATE_SHRED               ( 9)
#define FD_CRDS_TAG_INC_SNAPSHOT_HASHES           (10)
#define FD_CRDS_TAG_CONTACT_INFO                  (11)
#define FD_CRDS_TAG_RESTART_LAST_VOTED_FORK_SLOTS (12)
#define FD_CRDS_TAG_RESTART_HEAVIEST_FORK         (13)

struct fd_crds_purged {
  uchar hash[ 32UL ];
  long wallclock_nanos;
};

typedef struct fd_crds_purged fd_crds_purged_t;

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

    So we have a ContactInfo message for example.  If a validator sends
    us a new ContactInfo message, we want to replace the old one.  This
    lookup is serviced by a hash table, keyed by the public key of the
    originator, and in a few special cases an additional field.  For
    example, votes are (originator_key, vote_index), since we need to
    know about more than one vote from a given originator.

    This key field is the key for the hash table. */
  fd_crds_key_t key[1];

  union{
    struct {
      long instance_creation_wallclock_nanos;
    } contact_info;

    struct {
      /* offsets into data[] */
      ushort token_offset;
      ushort from_offset; /* TODO: Is this different from key->pubkey */
    } node_instance;
  };

  /* When an originator creates a CRDS message, they attach their local
    wallclock time to it.  This time is used to determine when a
    message should be upserted.  If messages have the same key, the
    newer one (as created by the originator) is used.

    Messages encode wallclock in millis, firedancer converts
    them into nanos internally. */
  long   wallclock_nanos;

  uchar  data[ 1232UL ];
  ushort data_sz;

  ulong num_duplicates;

  /* Pool fields. Not in use when pool element is acquired */
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
    ulong stake;
    ulong next; /* next in the treap iteration order */
    ulong prev; /* previous in the treap iteration order */
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
    ulong prev;
    ulong next;
    long  wallclock_nanos;
  } expire;

  /* Finally, a core operation on the CRDS is to to query for values by
     hash, to respond to pull requests.  This is done with a treap
     sorted by the hash of the encoded value. */
  struct {
    ulong parent;
    ulong left;
    ulong right;
    ulong next;
    ulong prev;
    ulong prio;
    ulong hash;
  } hash;
};

long
fd_crds_entry_wallclock( fd_crds_entry_t const * entry ){
  return entry->expire.wallclock_nanos;
}

#define POOL_NAME   crds_pool
#define POOL_T      fd_crds_entry_t
#define POOL_NEXT   pool.next

#include "../../util/tmpl/fd_pool.c"

#define TREAP_NAME      evict_treap
#define TREAP_T         fd_crds_entry_t
#define TREAP_QUERY_T   void *                                         /* We don't use query ... */
#define TREAP_CMP(q,e)  (__extension__({ (void)(q); (void)(e); -1; })) /* which means we don't need to give a real
                                                                          implementation to cmp either */
#define TREAP_IDX_T     ulong
#define TREAP_LT(e0,e1) ((e0)->evict.stake<(e1)->evict.stake)

#define TREAP_PARENT    evict.parent
#define TREAP_LEFT      evict.left
#define TREAP_RIGHT     evict.right
#define TREAP_PRIO      evict.prio

#define TREAP_OPTIMIZE_ITERATION 1
#define TREAP_NEXT      evict.next
#define TREAP_PREV      evict.prev

#include "../../util/tmpl/fd_treap.c"

#define DLIST_NAME      staked_expire_dlist
#define DLIST_ELE_T     fd_crds_entry_t
#define DLIST_PREV      expire.prev
#define DLIST_NEXT      expire.next

#include "../../util/tmpl/fd_dlist.c"

#define DLIST_NAME      unstaked_expire_dlist
#define DLIST_ELE_T     fd_crds_entry_t
#define DLIST_PREV      expire.prev
#define DLIST_NEXT      expire.next

#include "../../util/tmpl/fd_dlist.c"

#define TREAP_NAME      hash_treap
#define TREAP_T         fd_crds_entry_t
#define TREAP_QUERY_T   void *                                         /* We don't use query ... */
#define TREAP_CMP(q,e)  (__extension__({ (void)(q); (void)(e); -1; })) /* which means we don't need to give a real
                                                                          implementation to cmp either */
#define TREAP_IDX_T     ulong
#define TREAP_OPTIMIZE_ITERATION 1
#define TREAP_NEXT      hash.next
#define TREAP_PREV      hash.prev
#define TREAP_LT(e0,e1) ((e0)->hash.hash<(e1)->hash.hash)

#define TREAP_PARENT    hash.parent
#define TREAP_LEFT      hash.left
#define TREAP_RIGHT     hash.right
#define TREAP_PRIO      hash.prio

#include "../../util/tmpl/fd_treap.c"

static inline ulong
lookup_hash( fd_crds_key_t const * key,
             ulong                 seed ) {
  ulong hash = fd_hash( seed, &key->tag, 1UL );
  hash = fd_hash( hash, key->pubkey, 32UL );
  switch( key->tag ) {
    case FD_CRDS_TAG_VOTE:
      hash = fd_hash( hash, &key->vote_index, 1UL );
      break;
    case FD_CRDS_TAG_EPOCH_SLOTS:
      hash = fd_hash( hash, &key->epoch_slots_index, 1UL );
      break;
    case FD_CRDS_TAG_DUPLICATE_SHRED:
      hash = fd_hash( hash, &key->duplicate_shred_index, 2UL );
      break;
    default:
      break;
  }
  return hash;
}

static inline int
lookup_eq( fd_crds_key_t const * key0,
           fd_crds_key_t const * key1 ) {
  if( FD_UNLIKELY( key0->tag!=key1->tag ) ) return 0;
  if( FD_UNLIKELY( !memcmp( key0->pubkey, key1->pubkey, 32UL ) ) ) return 0;
  switch( key0->tag ) {
    case FD_CRDS_TAG_VOTE:
      return key0->vote_index==key1->vote_index;
    case FD_CRDS_TAG_EPOCH_SLOTS:
      return key0->epoch_slots_index==key1->epoch_slots_index;
    case FD_CRDS_TAG_DUPLICATE_SHRED:
      return key0->duplicate_shred_index==key1->duplicate_shred_index;
    default:
      break;
  }
  return 1;
}

#define MAP_NAME  lookup_map
#define MAP_ELE_T fd_crds_entry_t
#define MAP_KEY_T fd_crds_key_t
#define MAP_KEY   key
#define MAP_IDX_T ulong
#define MAP_NEXT  lookup.next
#define MAP_PREV  lookup.prev
#define MAP_KEY_HASH(k,s) (lookup_hash( k, s ))
#define MAP_KEY_EQ(k0,k1) (lookup_eq( k0, k1 ))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1

#include "../../util/tmpl/fd_map_chain.c"

struct fd_crds_private {
  fd_crds_entry_t *         pool;

  evict_treap_t *           evict_treap;
  staked_expire_dlist_t *   staked_expire_dlist;
  unstaked_expire_dlist_t * unstaked_expire_dlist;
  hash_treap_t *            hash_treap;
  lookup_map_t *            lookup_map;

  ulong                     purged_len;
  ulong                     purged_idx;
  ulong                     purged_cap;
  fd_crds_purged_t *        purged_list;

  int has_staked_node;
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
  l = FD_LAYOUT_APPEND( l, FD_CRDS_ALIGN,                 sizeof(fd_crds_t) );
  l = FD_LAYOUT_APPEND( l, crds_pool_align(),             crds_pool_footprint( ele_max )      );
  l = FD_LAYOUT_APPEND( l, evict_treap_align(),           evict_treap_footprint( ele_max )    );
  l = FD_LAYOUT_APPEND( l, staked_expire_dlist_align(),   staked_expire_dlist_footprint()     );
  l = FD_LAYOUT_APPEND( l, unstaked_expire_dlist_align(), unstaked_expire_dlist_footprint()   );
  l = FD_LAYOUT_APPEND( l, hash_treap_align(),            hash_treap_footprint( ele_max )     );
  l = FD_LAYOUT_APPEND( l, lookup_map_align(),            lookup_map_footprint( ele_max )     );
  l = FD_LAYOUT_APPEND( l, alignof(fd_crds_purged_t),     purged_max*sizeof(fd_crds_purged_t) );
  return FD_LAYOUT_FINI( l, FD_CRDS_ALIGN );
}

void *
fd_crds_new( void *     shmem,
             fd_rng_t * rng,
             ulong      ele_max,
             ulong      purged_max ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_crds_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !ele_max || !fd_ulong_is_pow2( ele_max ) ) ) {
    FD_LOG_WARNING(( "ele_max must be a power of 2" ));
    return NULL;
  }

  if( FD_UNLIKELY( !purged_max || !fd_ulong_is_pow2( purged_max ) ) ) {
    FD_LOG_WARNING(( "purged_max must be a power of 2" ));
    return NULL;
  }

  if( FD_UNLIKELY( !rng ) ) {
    FD_LOG_WARNING(( "NULL rng" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_crds_t * crds              = FD_SCRATCH_ALLOC_APPEND( l, FD_CRDS_ALIGN,                 sizeof(fd_crds_t) );
  void * _pool                  = FD_SCRATCH_ALLOC_APPEND( l, crds_pool_align(),             crds_pool_footprint( ele_max ) );
  void * _evict_treap           = FD_SCRATCH_ALLOC_APPEND( l, evict_treap_align(),           evict_treap_footprint( ele_max ) );
  void * _staked_expire_dlist   = FD_SCRATCH_ALLOC_APPEND( l, staked_expire_dlist_align(),   staked_expire_dlist_footprint() );
  void * _unstaked_expire_dlist = FD_SCRATCH_ALLOC_APPEND( l, unstaked_expire_dlist_align(), unstaked_expire_dlist_footprint() );
  void * _hash_treap            = FD_SCRATCH_ALLOC_APPEND( l, hash_treap_align(),            hash_treap_footprint( ele_max ) );
  void * _lookup_map            = FD_SCRATCH_ALLOC_APPEND( l, lookup_map_align(),            lookup_map_footprint( ele_max ) );
  void * _purged_list           = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_crds_purged_t),     purged_max*sizeof(fd_crds_purged_t) );

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

  crds->purged_len = 0UL;
  crds->purged_idx = 0UL;
  crds->purged_cap = purged_max;
  crds->purged_list = (fd_crds_purged_t *)_purged_list;

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

void
fd_crds_expire( fd_crds_t * crds,
                long        now ) {
  static const long SLOT_DURATION_NANOS            = 400L*1000L*1000L;
  static const long STAKED_EXPIRE_DURATION_NANOS   = 432000L*SLOT_DURATION_NANOS;
  static const long UNSTAKED_EXPIRE_DURATION_NANOS = 15L*1000L*1000L*1000L;

  while( !staked_expire_dlist_is_empty( crds->staked_expire_dlist, crds->pool ) ) {
    fd_crds_entry_t * head = staked_expire_dlist_ele_peek_head( crds->staked_expire_dlist, crds->pool );

    if( FD_LIKELY( head->expire.wallclock_nanos<now-STAKED_EXPIRE_DURATION_NANOS ) ) break;

    staked_expire_dlist_ele_pop_head( crds->staked_expire_dlist, crds->pool );
    hash_treap_ele_remove( crds->hash_treap, head, crds->pool );
    lookup_map_ele_remove( crds->lookup_map, head->key, NULL, crds->pool );
    evict_treap_ele_remove( crds->evict_treap, head, crds->pool );
    crds_pool_ele_release( crds->pool, head );
  }

  long unstaked_expire_duration_nanos = fd_long_if( crds->has_staked_node,
                                                    UNSTAKED_EXPIRE_DURATION_NANOS,
                                                    STAKED_EXPIRE_DURATION_NANOS );

  while( !unstaked_expire_dlist_is_empty( crds->unstaked_expire_dlist, crds->pool ) ) {
    fd_crds_entry_t * head = unstaked_expire_dlist_ele_peek_head( crds->unstaked_expire_dlist, crds->pool );

    if( FD_LIKELY( head->expire.wallclock_nanos<now-unstaked_expire_duration_nanos ) ) break;

    unstaked_expire_dlist_ele_pop_head( crds->unstaked_expire_dlist, crds->pool );
    hash_treap_ele_remove( crds->hash_treap, head, crds->pool );
    lookup_map_ele_remove( crds->lookup_map, head->key, NULL, crds->pool );
    evict_treap_ele_remove( crds->evict_treap, head, crds->pool );
    crds_pool_ele_release( crds->pool, head );
  }

  while( crds->purged_len ) {
    fd_crds_purged_t * purged = &crds->purged_list[ crds->purged_idx ];

    if( FD_LIKELY( purged->wallclock_nanos<now-60L*1000L*1000L*1000L ) ) break;
    crds->purged_idx = (crds->purged_idx+1UL)%crds->purged_cap;
    crds->purged_len--;
  }
}

fd_crds_entry_t *
fd_crds_acquire( fd_crds_t * crds ) {
  if( FD_UNLIKELY( crds_pool_free( crds->pool )==0UL ) ) {
    evict_treap_fwd_iter_t head = evict_treap_fwd_iter_init( crds->evict_treap, crds->pool );
    FD_TEST( !evict_treap_fwd_iter_done( head ) );
    fd_crds_entry_t * evict = evict_treap_fwd_iter_ele( head, crds->pool );

    if( FD_LIKELY( !evict->evict.stake ) ) {
      unstaked_expire_dlist_ele_remove( crds->unstaked_expire_dlist, evict, crds->pool );
    } else {
      staked_expire_dlist_ele_remove( crds->staked_expire_dlist, evict, crds->pool );
    }

    hash_treap_ele_remove( crds->hash_treap, evict, crds->pool );
    lookup_map_ele_remove( crds->lookup_map, evict->key, NULL, crds->pool );

    return evict;
  } else {
    return crds_pool_ele_acquire( crds->pool );
  }
}

void
fd_crds_release( fd_crds_t *       crds,
                 fd_crds_entry_t * value ) {
  crds_pool_ele_release( crds->pool, value );
}

static inline int
overrides( fd_crds_entry_t const * value,
           fd_crds_entry_t const * candidate ) {
  long val_wc         = value->wallclock_nanos;
  long cand_wc        = candidate->wallclock_nanos;
  long val_ci_onset   = value->contact_info.instance_creation_wallclock_nanos;
  long cand_ci_onset  = candidate->contact_info.instance_creation_wallclock_nanos;

  switch( value->key->tag ) {
    case FD_CRDS_TAG_CONTACT_INFO:
      if( FD_UNLIKELY( cand_ci_onset>val_ci_onset ) ) return 1;
      else if( FD_UNLIKELY( cand_ci_onset<val_ci_onset ) ) return 0;
      else if( FD_UNLIKELY( cand_wc>val_wc ) ) return 1;
      else if( FD_UNLIKELY( cand_wc<val_wc ) ) return 0;
      break;
    case FD_CRDS_TAG_NODE_INSTANCE:
      if( FD_LIKELY( !memcmp( candidate->data + candidate->node_instance.token_offset, value->data + value->node_instance.token_offset, 32UL ) ) ) break;
      else if( FD_LIKELY( memcmp( candidate->data + candidate->node_instance.from_offset, value->data + value->node_instance.from_offset, 32UL ) ) ) break;
      else if( FD_UNLIKELY( cand_wc>val_wc ) ) return 1;
      else if( FD_UNLIKELY( cand_wc<val_wc ) ) return 0;
      else return memcmp(candidate->data + candidate->node_instance.token_offset, value->data + value->node_instance.token_offset, 32UL) < 0;
    default:
      break;
  }

  if( FD_UNLIKELY( cand_wc>val_wc ) ) return 1;
  else if( FD_UNLIKELY( cand_wc<val_wc ) ) return 0;
  else return !!candidate->hash.hash<value->hash.hash;
}

int
fd_crds_upserts( fd_crds_t *       crds,
                 fd_crds_entry_t * candidate ) {
  fd_crds_entry_t const * value = lookup_map_ele_query_const( crds->lookup_map, candidate->key, NULL, crds->pool );
  if( FD_UNLIKELY( !value ) ) return 1;

  return overrides( value, candidate );
}

static inline void
insert_purged( fd_crds_t *   crds,
               uchar const * hash,
               long          wallclock_nanos ) {
  fd_memcpy( &crds->purged_list[ crds->purged_idx ].hash, hash, 32UL );
  crds->purged_list[ crds->purged_idx ].wallclock_nanos = wallclock_nanos;
  crds->purged_idx = (crds->purged_idx+1UL)%crds->purged_cap;
  crds->purged_len = fd_ulong_max( crds->purged_len+1UL, crds->purged_cap );
}

int
fd_crds_insert( fd_crds_t *       crds,
                fd_crds_entry_t * value,
                int               from_push_message ) {
  /* TODO: Why Agave tracks route? PushRespose etc ... */
  fd_crds_entry_t * replace = lookup_map_ele_query( crds->lookup_map, value->key, NULL, crds->pool );
  if( FD_LIKELY( replace ) ) {
    if( FD_UNLIKELY( !overrides( replace, value ) ) ) {
      if( FD_UNLIKELY( replace->hash.hash!=value->hash.hash ) ) {
        insert_purged( crds, fd_crds_value_hash( replace->data ), replace->wallclock_nanos );
        return -1;
      }

      /* We tried to insert a duplicate.  If it's from a push message,
         update the book-keeping to reflect the number of duplicates
         so we can send out proper prune messages. */
      if( FD_UNLIKELY( !from_push_message ) ) return -1;

      return (int)(replace->num_duplicates++);
    }
    replace->num_duplicates = 0;

    insert_purged( crds, fd_crds_value_hash( replace->data ), replace->wallclock_nanos );

    evict_treap_ele_remove( crds->evict_treap, replace, crds->pool );
    if( FD_LIKELY( replace->evict.stake ) ) {
      staked_expire_dlist_ele_remove( crds->staked_expire_dlist, replace, crds->pool );
    } else {
      unstaked_expire_dlist_ele_remove( crds->unstaked_expire_dlist, replace, crds->pool );
    }
    hash_treap_ele_remove( crds->hash_treap, replace, crds->pool );
    lookup_map_ele_remove( crds->lookup_map, replace->key, NULL, crds->pool );
    crds_pool_ele_release( crds->pool, replace );
  }

  crds->has_staked_node |= value->evict.stake ? 1 : 0;

  evict_treap_ele_insert( crds->evict_treap, value, crds->pool );
  if( FD_LIKELY( value->evict.stake ) ) {
    staked_expire_dlist_ele_push_tail( crds->staked_expire_dlist, value, crds->pool );
  } else {
    unstaked_expire_dlist_ele_push_tail( crds->unstaked_expire_dlist, value, crds->pool );
  }
  hash_treap_ele_insert( crds->hash_treap, value, crds->pool );
  lookup_map_ele_insert( crds->lookup_map, value, crds->pool );
  return 0;
}

struct fd_crds_mask_iter_private {
  ulong mask;
  ulong mask_bits;
  ulong iter;
};

fd_crds_mask_iter_t
fd_crds_mask_iter_init( fd_crds_t const * crds,
                        ulong             mask,
                        ulong             mask_bits ) {
  fd_crds_mask_iter_t it = {
    .mask       = mask,
    .mask_bits  = mask_bits,
    .iter       = hash_treap_fwd_iter_init( crds->hash_treap, crds->pool ),
  };
  return it;
}

fd_crds_mask_iter_t
fd_crds_mask_iter_next( fd_crds_mask_iter_t it );

int
fd_crds_mask_iter_done( fd_crds_mask_iter_t it );

fd_crds_entry_t const *
fd_crds_mask_iter_value( fd_crds_mask_iter_t it );
