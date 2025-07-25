#include "fd_sshashes.h"

struct fd_sshashes_key {
  ulong slot;
};

typedef struct fd_sshashes_key fd_sshashes_key_t;

FD_FN_PURE static uint
fd_sshashes_key_hash( fd_sshashes_key_t key ) {
  return (uint)fd_hash( 0x39c49607bf16463aUL, &key, sizeof(fd_sshashes_key_t) );
}

struct fd_sshashes_map;
typedef struct fd_sshashes_map fd_sshashes_map_t;

/* KnownSnapshotHashes Map represented as
   HashMap<ulong, HashMap<ulong, hash>> */
struct fd_sshashes_map {
  fd_sshashes_key_t key;
  uint              hash;

  uchar               sshash[ FD_HASH_FOOTPRINT ];
  ulong               inc_sshashes_cnt;
  fd_sshashes_map_t * inc_sshashes_map; /* up to 8 entries */
};

typedef struct fd_sshashes_map fd_sshashes_map_t;

#define MAP_NAME             fd_sshashes_map
#define MAP_T                fd_sshashes_map_t
#define MAP_KEY_T            fd_sshashes_key_t
#define MAP_KEY_NULL         (fd_sshashes_key_t){0}
#define MAP_KEY_EQUAL(k0,k1) (k0.slot==k1.slot)
#define MAP_KEY_INVAL(k)     (MAP_KEY_EQUAL((k),MAP_KEY_NULL))
#define MAP_KEY_HASH(key)    (fd_sshashes_key_hash(key))
#define MAP_KEY_EQUAL_IS_SLOW  1
#define MAP_LG_SLOT_CNT        6
#include "../../../util/tmpl/fd_map.c"

struct fd_sshashes_latest_msg_key {
  uchar pubkey[ FD_HASH_FOOTPRINT ];
};

typedef struct fd_sshashes_latest_msg_key fd_sshashes_latest_msg_key_t;

struct fd_sshashes_latest_msg_map {
  fd_sshashes_latest_msg_key_t    key;
  uint                            hash;
  fd_gossip_upd_snapshot_hashes_t msg;
};

typedef struct fd_sshashes_latest_msg_map fd_sshashes_latest_msg_map_t;

FD_FN_PURE static uint
fd_sshashes_latest_msg_key_hash( fd_sshashes_latest_msg_key_t key ) {
  return (uint)fd_hash( 0x39c49607bf16463aUL, &key, sizeof(fd_sshashes_latest_msg_key_t) );
}

#define MAP_NAME             fd_sshashes_latest_msg_map
#define MAP_T                fd_sshashes_latest_msg_map_t
#define MAP_KEY_T            fd_sshashes_latest_msg_key_t
#define MAP_KEY_NULL         (fd_sshashes_latest_msg_key_t){0}
#define MAP_KEY_EQUAL(k0,k1) (memcmp(k0.pubkey,k1.pubkey,FD_HASH_FOOTPRINT)==0)
#define MAP_KEY_INVAL(k)     (MAP_KEY_EQUAL((k),MAP_KEY_NULL))
#define MAP_KEY_HASH(key)    (fd_sshashes_latest_msg_key_hash(key))
#define MAP_KEY_EQUAL_IS_SLOW  1
#define MAP_LG_SLOT_CNT        6
#include "../../../util/tmpl/fd_map.c"

#define FD_SSHASHES_MAX (1<<6)

struct fd_sshashes_private {
  fd_sshashes_map_t *            map;
  fd_sshashes_latest_msg_map_t * latest_msg_map;

  ulong                          magic; /* ==FD_SSHASHES_MAGIC */
};

typedef struct fd_sshashes_private fd_sshashes_private_t;

ulong
fd_sshashes_align( void ) {
  return alignof(fd_sshashes_map_t);
}

ulong
fd_sshashes_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_sshashes_latest_msg_map_align(), fd_sshashes_latest_msg_map_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_sshashes_map_align(), fd_sshashes_map_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_sshashes_map_align(), fd_sshashes_map_footprint() * fd_sshashes_map_slot_cnt() );
  return FD_LAYOUT_FINI( l, fd_sshashes_map_align() );
}

void *
fd_sshashes_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_sshashes_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned shmem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_sshashes_t * sshashes = FD_SCRATCH_ALLOC_APPEND( l, fd_sshashes_align(), fd_sshashes_footprint() );
  void * _latest_msg_map   = FD_SCRATCH_ALLOC_APPEND( l, fd_sshashes_latest_msg_map_align(), fd_sshashes_latest_msg_map_footprint() );
  void * _sshashes_map     = FD_SCRATCH_ALLOC_APPEND( l, fd_sshashes_map_align(), fd_sshashes_map_footprint() );

  sshashes->latest_msg_map = fd_sshashes_latest_msg_map_join( fd_sshashes_latest_msg_map_new( _latest_msg_map ) );
  sshashes->map            = fd_sshashes_map_join( fd_sshashes_map_new( _sshashes_map ) );

  for( ulong i=0UL; i<fd_sshashes_map_slot_cnt(); i++ ) {
    fd_sshashes_map_t * entry = &sshashes->map[ i ];
    void * _inc_map = FD_SCRATCH_ALLOC_APPEND( l, fd_sshashes_map_align(), fd_sshashes_map_footprint() );
    entry->inc_sshashes_map = fd_sshashes_map_join( fd_sshashes_map_new( _inc_map ) );
    FD_TEST( entry->inc_sshashes_map );
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( sshashes->magic ) = FD_SSHASHES_MAGIC;
  FD_COMPILER_MFENCE();

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

static int
fd_sshashes_try_insert_incremental( fd_sshashes_map_t * full_entry,
                                    fd_sshashes_key_t   key,
                                    uchar const         sshash[ static FD_HASH_FOOTPRINT ] ) {
  /* TODO: not sure if we need this check or not.
     Also: how to check if we run out of slots in outer map? */
  if( FD_UNLIKELY( full_entry->inc_sshashes_cnt>=FD_SSHASHES_MAX ) ) {
    FD_LOG_ERR(("fd_sshashes_map_t full_entry->inc_sshashes_cnt >= FD_SSHASHES_MAX"));
  }

  fd_sshashes_map_t * new_entry = fd_sshashes_map_insert( full_entry, key );

  if( FD_UNLIKELY( !new_entry ) ) {
    return FD_SSHASHES_ERROR;
  }

  fd_memcpy( new_entry->sshash, sshash, FD_HASH_FOOTPRINT );
  full_entry->inc_sshashes_cnt++;

  return FD_SSHASHES_SUCCESS;
}

static int
fd_sshashes_try_insert_full( fd_sshashes_map_t *                     sshashes_map,
                             fd_gossip_upd_snapshot_hashes_t const * snapshot_hashes ) {
  fd_sshashes_key_t key = { .slot = snapshot_hashes->full->slot };
  fd_sshashes_map_t * new_full_entry = fd_sshashes_map_insert( sshashes_map, key );

  if( !FD_UNLIKELY( new_full_entry ) ) {
    return FD_SSHASHES_ERROR;
  }

  fd_memcpy( new_full_entry->sshash, snapshot_hashes->full->hash, FD_HASH_FOOTPRINT );
  new_full_entry->inc_sshashes_cnt = 0UL;

  for( ulong i=0UL; i<snapshot_hashes->inc_len; i++ ) {
    fd_sshashes_key_t inc_key = { .slot = snapshot_hashes->inc[ i ].slot };
    int err = fd_sshashes_try_insert_incremental( new_full_entry, inc_key, snapshot_hashes->inc[ i ].hash );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_SSHASHES_SUCCESS;
}

static void
fd_sshashes_remove( fd_sshashes_t *                         sshashes,
                    fd_sshashes_latest_msg_map_t *          latest_msg ) {
  fd_sshashes_latest_msg_map_remove( sshashes->latest_msg_map, latest_msg );

  fd_sshashes_key_t key          = { .slot = latest_msg->msg.full->slot };
  fd_sshashes_map_t * full_entry = fd_sshashes_map_query( sshashes->map, key, NULL );

  if( FD_UNLIKELY( !full_entry ) ) {
    FD_LOG_ERR(( "ok something went wrong, how does the full entry not exist??" ));
  }

  fd_sshashes_map_clear( full_entry->inc_sshashes_map );
  fd_sshashes_map_remove( sshashes->map, full_entry );
}

static int
fd_sshashes_try_insert_latest_msg( fd_sshashes_t *                         sshashes,
                                   uchar const                             pubkey[ static FD_HASH_FOOTPRINT ],
                                   fd_gossip_upd_snapshot_hashes_t const * snapshot_hashes ) {
  fd_sshashes_latest_msg_key_t latest_msg_key;
  fd_memcpy( latest_msg_key.pubkey, pubkey, FD_HASH_FOOTPRINT );
  fd_sshashes_latest_msg_map_t * new_latest_msg = fd_sshashes_latest_msg_map_insert( sshashes->latest_msg_map, latest_msg_key );

  if( FD_UNLIKELY( !new_latest_msg ) ) {
    return FD_SSHASHES_ERROR;
  }

  new_latest_msg->msg = *snapshot_hashes;
  return FD_SSHASHES_SUCCESS;
}

static int
fd_sshashes_try_insert( fd_sshashes_t *                         sshashes,
                        uchar const                             pubkey[ static FD_HASH_FOOTPRINT ],
                        fd_gossip_upd_snapshot_hashes_t const * snapshot_hashes ) {
  fd_sshashes_key_t key     = { .slot = snapshot_hashes->full->slot };
  fd_sshashes_map_t * entry = fd_sshashes_map_query( sshashes->map, key, NULL );

  /* if the entry exists, check that the full and incremental hashes
     match */
  if( FD_LIKELY( entry ) ) {
    if( memcmp( entry->sshash, snapshot_hashes->full->hash, FD_HASH_FOOTPRINT )!=0 ) {
        /* Don't accept a snapshot hashes message if its full hash does
           not match an existing full hash for the same full slot */
      return FD_SSHASHES_ERROR;
    }

    FD_TEST( snapshot_hashes->inc_len==1UL );
    /* loop through incremental hashes for protocol compliance */
    for( ulong i=0UL; i<snapshot_hashes->inc_len; i++ ) {
      fd_sshashes_key_t inc_key     = { .slot = snapshot_hashes->inc[ 0 ].slot };
      fd_sshashes_map_t * inc_entry = fd_sshashes_map_query( entry->inc_sshashes_map, inc_key, NULL );

      if( FD_LIKELY( inc_entry ) ) {
        if( memcmp( inc_entry->sshash, snapshot_hashes->inc[ i ].hash, FD_HASH_FOOTPRINT )!=0 ) {
          /* Don't accept a snapshot hashes message if its incremental
             hash does not match an existing incremental hash for the
             same incremental slot */
          return FD_SSHASHES_ERROR;
        }
      } else {
        /* We can add the incremental SnapshotHashes message */
        int err = fd_sshashes_try_insert_incremental( entry, inc_key, snapshot_hashes->inc[ i ].hash );
        if( FD_UNLIKELY( err ) ) return err;
      }
    }
  } else {
    /* we can add the full and incremental SnapshotHashes message */
    int err = fd_sshashes_try_insert_full( sshashes->map, snapshot_hashes );
    if ( FD_UNLIKELY( err ) ) return err;
  }

  return fd_sshashes_try_insert_latest_msg( sshashes, pubkey, snapshot_hashes );
}

int
fd_sshashes_update( fd_sshashes_t *                         sshashes,
                    uchar const                             pubkey[ static FD_HASH_FOOTPRINT ],
                    fd_gossip_upd_snapshot_hashes_t const * snapshot_hashes ) {
  /* if snapshot hashes already exists in latest msgs, update it */
  fd_sshashes_latest_msg_key_t latest_msg_key;
  fd_memcpy( latest_msg_key.pubkey, pubkey, FD_HASH_FOOTPRINT );
  fd_sshashes_latest_msg_map_t * latest_msg = fd_sshashes_latest_msg_map_query( sshashes->latest_msg_map, latest_msg_key, NULL );

  FD_TEST( snapshot_hashes->inc_len==1UL );

  if( FD_LIKELY( latest_msg ) ) {
    ulong highest_new_incremental_slot = ULONG_MAX;
    for( ulong i=0UL; i<snapshot_hashes->inc_len; i++ ) {
      if( highest_new_incremental_slot==ULONG_MAX || snapshot_hashes->inc[ i ].slot>highest_new_incremental_slot ) {
        highest_new_incremental_slot = snapshot_hashes->inc[ i ].slot;
      }
    }

    ulong highest_existing_incremental_slot = ULONG_MAX;
    for( ulong i=0UL; i<latest_msg->msg.inc_len; i++ ) {
      if( highest_existing_incremental_slot==ULONG_MAX || latest_msg->msg.inc[ i ].slot>highest_existing_incremental_slot ) {
        highest_existing_incremental_slot = latest_msg->msg.inc[ i ].slot;
      }
    }

    if( FD_UNLIKELY( snapshot_hashes->full->slot>latest_msg->msg.full->slot ||
        (snapshot_hashes->full->slot==latest_msg->msg.full->slot &&
        highest_new_incremental_slot>highest_existing_incremental_slot ) ) ) {
      /* replace the existing entry */
      fd_sshashes_remove( sshashes, latest_msg );
      return fd_sshashes_try_insert( sshashes, pubkey, snapshot_hashes );
    }
  } else {
    return fd_sshashes_try_insert( sshashes, pubkey, snapshot_hashes );
  }

  return FD_SSHASHES_SUCCESS;
}
