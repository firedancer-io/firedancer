#include "fd_sshashes.h"

#include <stdio.h>

struct fd_sshashes_map;
typedef struct fd_sshashes_map fd_sshashes_map_t;

/* KnownSnapshotHashes set represented as
   HashMap<ulong, HashMap<ulong, hash>>.

   Stores up to 32 full snapshot hashes and each full SnapshotHash
   maps to up to 32 incremental SnapshotHashes.  The map can never
   overflow because the number of known validators is bounded to 16.
   See FD_SSHASHES_KNOWN_VALIDATORS_MAX in fd_sshashes.h */
struct fd_sshashes_incremental_map {
  ulong               slot;                        /* slot of incremental snapshot */
  uint                hash;                        /* for internal map use */
  uchar               sshash[ FD_HASH_FOOTPRINT ]; /* base58 decoded hash of incremental snapshot */
  ulong               ref_cnt;                     /* ref count of the snapshothashes entry */
};
typedef struct fd_sshashes_incremental_map fd_sshashes_incremental_map_t;

struct fd_sshashes_map {
  ulong                           slot;                        /* slot of full snapshot */
  uint                            hash;                        /* for internal map use */
  uchar                           sshash[ FD_HASH_FOOTPRINT ]; /* base58 decoded hash of full snapshot */
  ulong                           inc_cnt;                     /* number of incremental snapshothashes for this full snapshothash */
  fd_sshashes_incremental_map_t * inc_sshashes_map;            /* map containing known incremental SnapshotHashes */
};
typedef struct fd_sshashes_map fd_sshashes_map_t;

#define MAP_NAME        fd_sshashes_incremental_map
#define MAP_T           fd_sshashes_incremental_map_t
#define MAP_KEY         slot
#define MAP_KEY_NULL    ULONG_MAX
#define MAP_KEY_INVAL(k) (k==ULONG_MAX)
#define MAP_LG_SLOT_CNT 5
#include "../../../util/tmpl/fd_map.c"

#define MAP_NAME         fd_sshashes_map
#define MAP_T            fd_sshashes_map_t
#define MAP_KEY          slot
#define MAP_KEY_NULL     ULONG_MAX
#define MAP_KEY_INVAL(k) (k==ULONG_MAX)
#define MAP_LG_SLOT_CNT 5
#include "../../../util/tmpl/fd_map.c"

/* Stores the latest SnapshotHashes message for each known validator.
   There can be up to 16 different known validators. */
struct fd_sshashes_latest_msg_map {
  fd_pubkey_t                     key;  /* known validator pubkey */
  ulong                           hash; /* for internal map use */
  fd_gossip_upd_snapshot_hashes_t msg;  /* latest SnapshotHash message */
};
typedef struct fd_sshashes_latest_msg_map fd_sshashes_latest_msg_map_t;

#define MAP_NAME             fd_sshashes_latest_msg_map
#define MAP_T                fd_sshashes_latest_msg_map_t
#define MAP_KEY_T            fd_pubkey_t
#define MAP_KEY_NULL         (fd_pubkey_t){0}
#define MAP_KEY_EQUAL(k0,k1) (memcmp(k0.hash,k1.hash,FD_HASH_FOOTPRINT)==0)
#define MAP_KEY_INVAL(k)     (MAP_KEY_EQUAL((k),MAP_KEY_NULL))
#define MAP_HASH_T           ulong
#define MAP_KEY_HASH(key)    (fd_hash( (key).ui[3], key.hash, sizeof(fd_pubkey_t) ))
#define MAP_KEY_EQUAL_IS_SLOW  1
#define MAP_LG_SLOT_CNT        5
#include "../../../util/tmpl/fd_map.c"

/* */
struct fd_sshashes_known_validator {
  fd_pubkey_t key;
  ulong       hash;
};

typedef struct fd_sshashes_known_validator fd_sshashes_known_validator_t;

#define MAP_NAME             fd_sshashes_known_validators_set
#define MAP_T                fd_sshashes_known_validator_t
#define MAP_KEY_T            fd_pubkey_t
#define MAP_KEY_NULL         (fd_pubkey_t){0}
#define MAP_KEY_EQUAL(k0,k1) (!(memcmp((k0).key,(k1).key,sizeof(fd_pubkey_t))))
#define MAP_KEY_INVAL(k)     (MAP_KEY_EQUAL((k),MAP_KEY_NULL))
#define MAP_HASH_T           ulong
#define MAP_KEY_HASH(key)    (fd_hash( (key).ui[3], key.hash, sizeof(fd_pubkey_t) ))
#define MAP_KEY_EQUAL_IS_SLOW  1
#define MAP_LG_SLOT_CNT        5
#include "../../../util/tmpl/fd_map.c"

struct fd_sshashes_private {
  fd_sshashes_map_t *             known_map;
  ulong                           known_full_cnt;
  ulong                           latest_msg_cnt;
  fd_sshashes_latest_msg_map_t *  latest_msg_map;
  fd_sshashes_known_validator_t * known_validators_set;
  fd_sshashes_cluster_slot_pair_t highest_slots;
  ulong                           magic;          /* ==FD_SSHASHES_MAGIC */
};
typedef struct fd_sshashes_private fd_sshashes_private_t;

#define FD_SSHASHES_ERROR_INVAL (-1)

ulong
fd_sshashes_align( void ) {
  return alignof(fd_sshashes_map_t);
}

ulong
fd_sshashes_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_sshashes_latest_msg_map_align(), fd_sshashes_latest_msg_map_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_sshashes_map_align(), fd_sshashes_map_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_sshashes_incremental_map_align(), fd_sshashes_incremental_map_footprint() * fd_sshashes_map_slot_cnt() );
  l = FD_LAYOUT_APPEND( l, fd_sshashes_known_validators_set_align(), fd_sshashes_known_validators_set_footprint() );
  return FD_LAYOUT_FINI( l, fd_sshashes_map_align() );
}

void *
fd_sshashes_new( void * shmem,
                 char known_validators[ FD_SSHASHES_KNOWN_VALIDATORS_MAX ][ FD_BASE58_ENCODED_32_SZ ],
                 ulong known_validators_cnt ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_sshashes_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned shmem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_sshashes_t * sshashes     = FD_SCRATCH_ALLOC_APPEND( l, fd_sshashes_align(), fd_sshashes_footprint() );
  void * _latest_msg_map       = FD_SCRATCH_ALLOC_APPEND( l, fd_sshashes_latest_msg_map_align(), fd_sshashes_latest_msg_map_footprint() );
  void * _sshashes_map         = FD_SCRATCH_ALLOC_APPEND( l, fd_sshashes_map_align(), fd_sshashes_map_footprint() );
  void * _known_validators_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_sshashes_known_validators_set_align(), fd_sshashes_known_validators_set_footprint() );

  sshashes->latest_msg_map       = fd_sshashes_latest_msg_map_join( fd_sshashes_latest_msg_map_new( _latest_msg_map ) );
  sshashes->known_map            = fd_sshashes_map_join( fd_sshashes_map_new( _sshashes_map ) );
  sshashes->known_validators_set = fd_sshashes_known_validators_set_join( fd_sshashes_known_validators_set_new( _known_validators_mem ) );

  for( ulong i=0UL; i<fd_sshashes_map_slot_cnt(); i++ ) {
    fd_sshashes_map_t * entry = &sshashes->known_map[ i ];
    void * _inc_map = FD_SCRATCH_ALLOC_APPEND( l, fd_sshashes_map_align(), fd_sshashes_map_footprint() );
    entry->inc_sshashes_map = fd_sshashes_incremental_map_join( fd_sshashes_incremental_map_new( _inc_map ) );
    FD_TEST( entry->inc_sshashes_map );
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( sshashes->magic ) = FD_SSHASHES_MAGIC;
  FD_COMPILER_MFENCE();

  fd_sshashes_init( sshashes, known_validators, known_validators_cnt );

  return sshashes;
}

fd_sshashes_t *
fd_sshashes_join( void * shhashes ) {
  if( FD_UNLIKELY( !shhashes ) ) {
    FD_LOG_WARNING(( "NULL shhashes" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shhashes, fd_sshashes_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shhashes" ));
    return NULL;
  }

  fd_sshashes_t * sshashes = (fd_sshashes_t *)shhashes;

  if( FD_UNLIKELY( sshashes->magic!=FD_SSHASHES_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return sshashes;
}

void
fd_sshashes_init( fd_sshashes_t * sshashes,
                  char            known_validators[ FD_SSHASHES_KNOWN_VALIDATORS_MAX ][ FD_BASE58_ENCODED_32_SZ ],
                  ulong           known_validators_cnt ) {
  if( FD_UNLIKELY( sshashes->magic!=FD_SSHASHES_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return;
  }

  sshashes->known_full_cnt            = 0UL;
  sshashes->latest_msg_cnt            = 0UL;
  sshashes->highest_slots.full        = ULONG_MAX;
  sshashes->highest_slots.incremental = ULONG_MAX;

  for( ulong i=0UL; i<known_validators_cnt; i++ ) {
    fd_pubkey_t known_validator_pubkey;
    uchar * decoded = fd_base58_decode_32( known_validators[ i ], known_validator_pubkey.hash );
    fd_sshashes_known_validators_set_insert( sshashes->known_validators_set, known_validator_pubkey );

    if( FD_UNLIKELY( !decoded ) ) {
      FD_LOG_ERR(( "failed to decode known validator pubkey %s", known_validators[ i ] ));
    } else {
      FD_LOG_INFO(("got validator pubkey %s", FD_BASE58_ENC_32_ALLOCA( known_validator_pubkey.hash ) ));
    }
  }
}

void *
fd_sshashes_leave( fd_sshashes_t * sshashes ) {
  if( FD_UNLIKELY( !sshashes ) ) {
    FD_LOG_WARNING(( "NULL sshashes" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)sshashes, fd_sshashes_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned sshashes" ));
    return NULL;
  }

  if( FD_UNLIKELY( sshashes->magic!=FD_SSHASHES_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return (void *)sshashes;
}

void *
fd_sshashes_delete( fd_sshashes_t * shmhashes ) {
  if( FD_UNLIKELY( !shmhashes ) ) {
    FD_LOG_WARNING(( "NULL sshashes" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmhashes, fd_sshashes_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned sshashes" ));
    return NULL;
  }

  if( FD_UNLIKELY( shmhashes->magic!=FD_SSHASHES_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  fd_sshashes_reset( shmhashes );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( shmhashes->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return shmhashes;
}

/* fd_sshashes_insert_incremental inserts an incremental
   SnapshotHash message into the set of known SnapshotHashes.
   full_entry points to the associated full SnapshotHash that the
   incremental SnapshotHash builds off of.  incremental_slot and sshash
   are the contents of the incremental SnapshotHash to be inserted.
   This function is not expected to fail. */
static inline void
fd_sshashes_insert_incremental( fd_sshashes_map_t * full_entry,
                                    ulong               incremental_slot,
                                    uchar const         sshash[ static FD_HASH_FOOTPRINT ] ) {
  fd_sshashes_incremental_map_t * new_entry = fd_sshashes_incremental_map_insert( full_entry->inc_sshashes_map, incremental_slot );

  FD_TEST( new_entry );

  fd_memcpy( new_entry->sshash, sshash, FD_HASH_FOOTPRINT );
  new_entry->ref_cnt = 1UL;
  full_entry->inc_cnt++;
}

/* fd_sshashes_insert_full inserts a full
   SnapshotHash message into the set of known SnapshotHashes.
   sshashes_map points to the map of known SnapshotHashes and
   snapshot_hashes points to the received SnapshotHash message from
   gossip.  This function is not expected to fail. */
static inline void
fd_sshashes_insert_full( fd_sshashes_map_t *                     sshashes_map,
                         fd_gossip_upd_snapshot_hashes_t const * snapshot_hashes ) {
  fd_sshashes_map_t * new_full_entry = fd_sshashes_map_insert( sshashes_map, snapshot_hashes->full->slot );

  FD_TEST( new_full_entry );

  fd_memcpy( new_full_entry->sshash, snapshot_hashes->full->hash, FD_HASH_FOOTPRINT );
  fd_sshashes_insert_incremental( new_full_entry, snapshot_hashes->inc[ 0UL ].slot, snapshot_hashes->inc[ 0UL ].hash );
  new_full_entry->inc_cnt = 1UL;
}

/* fd_sshashes_remove removes a previously existing SnapshotHashes
   message.  Removal of an existing SnapshotHashes message requires
   removing the SnapshotHashes message from the latest_msg_map and from
   the known_map.  The SnapshotHashes are ref-counted in the known_map,
   so it can only be removed once its ref count is 0.  This function is
   not expected to fail and holds the invariant that the SnapshotHashes
   message must be present in both maps before removal. */
static inline void
fd_sshashes_remove( fd_sshashes_t *                         sshashes,
                    fd_sshashes_latest_msg_map_t *          latest_msg ) {
  fd_sshashes_latest_msg_map_remove( sshashes->latest_msg_map, latest_msg );

  fd_sshashes_map_t * full_entry = fd_sshashes_map_query( sshashes->known_map, latest_msg->msg.full->slot, NULL );

  if( FD_UNLIKELY( !full_entry ) ) {
    FD_LOG_ERR(( "invariant violation: full entry does not exist" ));
  }

  fd_sshashes_incremental_map_t * inc_entry = fd_sshashes_incremental_map_query( full_entry->inc_sshashes_map, latest_msg->msg.inc[ 0UL ].slot, NULL );
  if( FD_UNLIKELY( !inc_entry ) ) {
    FD_LOG_ERR(( "invariant violation: incremental entry does not exist" ));
  }

  inc_entry->ref_cnt--;

  if( FD_UNLIKELY( inc_entry->ref_cnt==0UL ) ) {
   fd_sshashes_incremental_map_remove( full_entry->inc_sshashes_map, inc_entry );
   full_entry->inc_cnt--;
  }

  if( FD_UNLIKELY( full_entry->inc_cnt==0UL ) ) {
    fd_sshashes_incremental_map_clear( full_entry->inc_sshashes_map );
    fd_sshashes_map_remove( sshashes->known_map, full_entry );
    FD_TEST( sshashes->known_full_cnt>0UL );
    sshashes->known_full_cnt--;
  }
}

/* fd_sshashes_insert_latest_msg inserts a SnapshotHashes message
   received from gossip into the latest_msg_map in sshashes.  Whenever
   a new SnapshotHashes message is updated for a known validator, the
   highest cluster slot pair is recalcualted.  This function is not
   expected to fail. */
static inline void
fd_sshashes_insert_latest_msg( fd_sshashes_t *                         sshashes,
                               uchar const                             pubkey[ static FD_HASH_FOOTPRINT ],
                               fd_gossip_upd_snapshot_hashes_t const * snapshot_hashes ) {

  fd_pubkey_t known_validator_key;
  fd_memcpy( known_validator_key.hash, pubkey, FD_HASH_FOOTPRINT );
  fd_sshashes_latest_msg_map_t * new_latest_msg = fd_sshashes_latest_msg_map_insert( sshashes->latest_msg_map, known_validator_key );

  FD_TEST( new_latest_msg );

  new_latest_msg->msg = *snapshot_hashes;
  sshashes->latest_msg_cnt++;

  /* Recalculate the highest cluster slot pair */
  if( sshashes->highest_slots.full==ULONG_MAX ||
      snapshot_hashes->full->slot>sshashes->highest_slots.full ) {
    sshashes->highest_slots.full = snapshot_hashes->full->slot;
  }

  if( sshashes->highest_slots.incremental==ULONG_MAX ||
      snapshot_hashes->inc[ 0UL ].slot>sshashes->highest_slots.incremental ) {
    sshashes->highest_slots.incremental = snapshot_hashes->inc[ 0UL ].slot;
  }
}

static void
fd_sshashes_insert( fd_sshashes_t *                         sshashes,
                    uchar const                             pubkey[ static FD_HASH_FOOTPRINT ],
                    fd_gossip_upd_snapshot_hashes_t const * snapshot_hashes ) {
  fd_sshashes_map_t * entry = fd_sshashes_map_query( sshashes->known_map, snapshot_hashes->full->slot, NULL );

  /* if the entry exists, check that the full and incremental hashes
     match */
  if( FD_LIKELY( entry ) ) {
    fd_sshashes_incremental_map_t * inc_entry = fd_sshashes_incremental_map_query( entry->inc_sshashes_map, snapshot_hashes->inc[ 0UL ].slot, NULL );

    if( FD_LIKELY( inc_entry ) ) {
      /* if the incremental snapshot hashes messae already exists and
         the new snapshot hashes message is valid, increment the ref cnt
         */
      inc_entry->ref_cnt++;
    } else {
      /* We can add the incremental SnapshotHashes message */
      fd_sshashes_insert_incremental( entry, snapshot_hashes->inc[ 0UL ].slot, snapshot_hashes->inc[ 0UL ].hash );
    }

  } else {
    /* we can add the full and incremental SnapshotHashes message */
    fd_sshashes_insert_full( sshashes->known_map, snapshot_hashes );
    sshashes->known_full_cnt++;
  }

  fd_sshashes_insert_latest_msg( sshashes, pubkey, snapshot_hashes );
}

static int
fd_sshashes_validate( fd_sshashes_t const *                   sshashes,
                      fd_gossip_upd_snapshot_hashes_t const * snapshot_hashes ) {
  fd_sshashes_map_t * entry = fd_sshashes_map_query( sshashes->known_map, snapshot_hashes->full->slot, NULL );

  if( FD_LIKELY( entry ) ) {
    if( memcmp( entry->sshash, snapshot_hashes->full->hash, FD_HASH_FOOTPRINT )!=0 ) {
      /* Don't accept a snapshot hashes message if its full hash does
         not match an existing full hash for the same full slot */
      return FD_SSHASHES_ERROR_INVAL;
    }

    fd_sshashes_incremental_map_t * inc_entry = fd_sshashes_incremental_map_query( entry->inc_sshashes_map, snapshot_hashes->inc[ 0UL ].slot, NULL );

    if( FD_LIKELY( inc_entry ) ) {
      if( memcmp( inc_entry->sshash, snapshot_hashes->inc[ 0UL ].hash, FD_HASH_FOOTPRINT )!=0 ) {
        /* Don't accept a snapshot hashes message if its incremental
           hash does not match an existing incremental hash for the
           same incremental slot */
        return FD_SSHASHES_ERROR_INVAL;
      }
    }
  }

  return FD_SSHASHES_SUCCESS;
}

int
fd_sshashes_query( fd_sshashes_t const *       sshashes,
                   fd_sshashes_entry_t const * full_entry,
                   fd_sshashes_entry_t const * incremental_entry ) {
  fd_sshashes_map_t * entry = fd_sshashes_map_query( sshashes->known_map, full_entry->slot, NULL );

  if( FD_UNLIKELY( !entry ) ) {
    return 0;
  }

  if( memcmp( entry->sshash, full_entry->hash, FD_HASH_FOOTPRINT )!=0 ) {
    return 0;
  }

  if( FD_UNLIKELY( !incremental_entry ) ) {
    return 1;
  }

  fd_sshashes_incremental_map_t * incremental = fd_sshashes_incremental_map_query( entry->inc_sshashes_map, incremental_entry->slot, NULL );

  if( FD_UNLIKELY( !incremental ) ) {
    return 0;
  }

  if( memcmp( incremental->sshash, incremental_entry->hash, FD_HASH_FOOTPRINT )!=0 ) {
    return 0;
  }

  return 1;
}

int
fd_sshashes_update( fd_sshashes_t *                         sshashes,
                    uchar const                             pubkey[ static FD_HASH_FOOTPRINT ],
                    fd_gossip_upd_snapshot_hashes_t const * snapshot_hashes ) {
  fd_pubkey_t known_validator_pubkey;
  fd_memcpy( known_validator_pubkey.hash, pubkey, FD_HASH_FOOTPRINT );

  fd_sshashes_known_validator_t * known_validator = fd_sshashes_known_validators_set_query( sshashes->known_validators_set, known_validator_pubkey, NULL );
  if( FD_LIKELY( !known_validator ) ) {
    return FD_SSHASHES_REJECT;
  }

  /* if snapshot hashes already exists in latest msgs, update it */
  fd_pubkey_t known_validator_key;
  fd_memcpy( known_validator_key.hash, pubkey, FD_HASH_FOOTPRINT );
  fd_sshashes_latest_msg_map_t * latest_msg = fd_sshashes_latest_msg_map_query( sshashes->latest_msg_map, known_validator_key, NULL );

  FD_TEST( snapshot_hashes->inc_len==1UL );
  FD_TEST( snapshot_hashes->inc[ 0UL ].slot>snapshot_hashes->full->slot );

  int res = FD_SSHASHES_SUCCESS;
  if( FD_LIKELY( latest_msg ) ) {
    FD_TEST( latest_msg->msg.inc_len==1UL );
    ulong highest_new_incremental_slot = snapshot_hashes->inc[ 0UL ].slot;
    ulong highest_existing_incremental_slot = latest_msg->msg.inc[ 0UL ].slot;

    if( FD_UNLIKELY( snapshot_hashes->full->slot>latest_msg->msg.full->slot ||
        (snapshot_hashes->full->slot==latest_msg->msg.full->slot &&
        highest_new_incremental_slot>highest_existing_incremental_slot ) ) ) {

      res = fd_sshashes_validate( sshashes, snapshot_hashes );
      if( FD_LIKELY( res==FD_SSHASHES_SUCCESS ) ) {
        /* replace the existing entry */
        fd_sshashes_remove( sshashes, latest_msg );
        fd_sshashes_insert( sshashes, pubkey, snapshot_hashes );
      }
    }
  } else {
    res = fd_sshashes_validate( sshashes, snapshot_hashes );
    if( FD_LIKELY( res==FD_SSHASHES_SUCCESS ) ) {
      fd_sshashes_insert( sshashes, pubkey, snapshot_hashes );
    }
  }

  if( FD_LIKELY( res==FD_SSHASHES_ERROR_INVAL ) ) {
    /* If validation failed due to an invalid SnapshotHash, remove any
       existing entry for that known validator. */
    if( FD_LIKELY( latest_msg ) ) {
      fd_sshashes_remove( sshashes, latest_msg );
    }

    /* Blacklist the known validator by removing it from the set of
       known validators.  */
    fd_sshashes_known_validators_set_remove( sshashes->known_validators_set, known_validator );
  }

  return FD_SSHASHES_REJECT;
}

fd_sshashes_cluster_slot_pair_t
fd_sshashes_get_highest_slots( fd_sshashes_t const * sshashes ) {
  return sshashes->highest_slots;
}

void
fd_sshashes_reset( fd_sshashes_t * sshashes ) {
  fd_sshashes_latest_msg_map_clear( sshashes->latest_msg_map );

  for( ulong i=0UL; i<fd_sshashes_map_slot_cnt(); i++ ) {
    fd_sshashes_map_t * entry = &sshashes->known_map[ i ];
    if( !fd_sshashes_map_key_inval( entry->slot ) ) {
      fd_sshashes_incremental_map_clear( entry->inc_sshashes_map );
    }
  }

  fd_sshashes_map_clear( sshashes->known_map );
  fd_sshashes_known_validators_set_clear( sshashes->known_validators_set );

  sshashes->known_full_cnt            = 0UL;
  sshashes->latest_msg_cnt            = 0UL;
  sshashes->highest_slots.full        = ULONG_MAX;
  sshashes->highest_slots.incremental = ULONG_MAX;
}

void
fd_sshashes_print( fd_sshashes_t const * sshashes ) {
  for( ulong i=0UL; i<fd_sshashes_map_slot_cnt(); i++ ) {
    fd_sshashes_map_t const * full_entry = &sshashes->known_map[ i ];
    if( fd_sshashes_map_key_inval( full_entry->slot ) ) continue;

    printf("Full entry slot: %lu hash %s inc_cnt: %lu\n",
           full_entry->slot,
           FD_BASE58_ENC_32_ALLOCA( full_entry->sshash ),
           full_entry->inc_cnt );

    for( ulong j=0UL; j<fd_sshashes_incremental_map_slot_cnt(); j++ ) {
      fd_sshashes_incremental_map_t const * inc_entry = &full_entry->inc_sshashes_map[ j ];
      if( fd_sshashes_incremental_map_key_inval( inc_entry->slot ) ) continue;

      printf("  Incremental entry slot: %lu hash %s ref_cnt: %lu\n",
             inc_entry->slot,
             FD_BASE58_ENC_32_ALLOCA( inc_entry->sshash ),
             inc_entry->ref_cnt );
    }
  }
}
