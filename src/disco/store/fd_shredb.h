#ifndef HEADER_fd_src_disco_store_fd_shredb_h
#define HEADER_fd_src_disco_store_fd_shredb_h

#include "../../ballet/shred/fd_shred.h"

/* An on-disk shred store for serving repair requests.

   Unlike fd_store, fd_shredb stores individual raw shreds keyed
   by (slot, shred_index) and is optimized for random lookups.

   To speedup the HighestShred query, we have two hashmaps.
      - A per-slot map, which tracks what the highest known index for a slot is.
      - A per-shred map, keyed by (slot, shred_index) and
        contains the ring buffer position for a shred.

   The ring buffer is file-backend, and maps to a fixed-size circular array
   of shred entries. FIFO evicition by advancing the write head allows us
   to retain only the newest entries.

   NOTE: For now, this design does not have any WAL or crash recovery.

   NOTE: In the current design, the Rserve tile subscribes to the
   shred_out link for getting the shreds, but we may have the shred tile
   write directly into the store in the future. */


FD_FN_CONST static inline ulong
fd_shredb_key_pack( ulong slot, uint shred_idx ) {
  return (slot << 16) | (ulong)(ushort)shred_idx;
}

FD_FN_CONST static inline ulong
fd_shredb_key_slot( ulong key ) {
  return fd_ulong_extract( key, 16, 63 );
}

FD_FN_CONST static inline uint
fd_shredb_key_shred_idx( ulong key ) {
  return (uint)fd_ulong_extract( key, 0, 15 );
}

/* per-shred entry, (slot, shred_index) -> ring_idx */
struct fd_shredb_shred_entry {
  ulong key;
  ulong ring_idx;
};
typedef struct fd_shredb_shred_entry fd_shredb_shred_entry_t;

#define MAP_NAME              fd_shredb_shred_map
#define MAP_T                 fd_shredb_shred_entry_t
#define MAP_KEY_T             ulong
#define MAP_KEY_NULL          ULONG_MAX
#define MAP_KEY_INVAL(k)      ((k)==ULONG_MAX)
#define MAP_KEY_EQUAL(k0,k1)  ((k0)==(k1))
#define MAP_KEY_HASH(k,seed)  ((uint)fd_ulong_hash( (k) ^ (seed) ))
#define MAP_MEMOIZE           0
#define MAP_KEY_EQUAL_IS_SLOW 0
#include "../../util/tmpl/fd_map_dynamic.c"

/* per-slot entry, slot -> (highest_shred_idx, cnt) */
struct fd_shredb_slot_entry {
  ulong key;
  uint  highest_shred_idx; /* highest shred_idx we have for this slot */
  ulong cnt;               /* number of shreds we have for this slot */
};
typedef struct fd_shredb_slot_entry fd_shredb_slot_entry_t;

#define MAP_NAME              fd_shredb_slot_map
#define MAP_T                 fd_shredb_slot_entry_t
#define MAP_KEY_T             ulong
#define MAP_KEY_NULL          ULONG_MAX
#define MAP_KEY_INVAL(k)      ((k)==ULONG_MAX)
#define MAP_KEY_EQUAL(k0,k1)  ((k0)==(k1))
#define MAP_KEY_HASH(k,seed)  ((uint)fd_ulong_hash( (k) ^ (seed) ))
#define MAP_MEMOIZE           0
#define MAP_KEY_EQUAL_IS_SLOW 0
#include "../../util/tmpl/fd_map_dynamic.c"

/* On-disk ring buffer entry. */
struct __attribute__((aligned(64))) fd_shredb_entry {
  ulong  key;                      /* for reverse lookups on eviction */
  ushort shred_sz;                /* actual shred byte count */
  uchar  occupied;                /* 1 if this slot holds valid data */
  uchar  shred[FD_SHRED_MAX_SZ];
};
typedef struct fd_shredb_entry fd_shredb_entry_t;

struct fd_shredb {
  ulong  max_shreds;                  /* ring buffer capacity */
  ulong  write_head;                  /* next ring position to write */
  ulong  cnt;                         /* current number of entries */
  void * mapped;
  ulong  mapped_sz;                   /* the size of `mapped` in bytes */
  int    fd;                          /* file descriptor for the backing file */
  ulong  file_shreds;                 /* current file capacity in shred entries */
  fd_shredb_shred_entry_t * shred_map;
  fd_shredb_slot_entry_t  * slot_map;
};
typedef struct fd_shredb fd_shredb_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_shredb_align( void ) {
  return alignof(fd_shredb_t);
}

FD_FN_CONST ulong
fd_shredb_footprint( ulong max_size_gib );

void *
fd_shredb_new( void       * shmem,
               ulong        max_size_gib,
               char const * file_path,
               ulong        seed );

fd_shredb_t *
fd_shredb_join( void * shstore );

void *
fd_shredb_leave( fd_shredb_t const * store );

void *
fd_shredb_delete( void * shstore );

/* Inserts a FD_SHRED_DATA_HEADER_SZ sized header into a shred's entry.
   Leaves the payload part of the entry untouched.
   Will derive the (slot, shred_idx) from the header itself. */
void
fd_shredb_insert_header( fd_shredb_t  * store,
                             fd_shred_t const * shred );


/* Inserts the payload of a shred. Asserts that the corresponding header
   has already been inserted into the store beforehand. */
void
fd_shredb_insert_payload( fd_shredb_t * store,
                              uchar const     * payload,
                              ulong             payload_sz,
                              ulong             slot,
                              uint              shred_idx );

/* Given a (slot, shred_index), returns the corresponding entry.
   If no entry was found, returns -1, otherwise returns the amount
   of bytes written to out. */
int
fd_shredb_query( fd_shredb_t * store,
                     ulong             slot,
                     uint              shred_idx,
                     uchar             out[ FD_SHRED_MAX_SZ ] );

/* Given a (slot, min_shred_idx), returns the highest shred the store
   knows of for that slot.

   If the store has no shreds for the given slot, or does not have a shred
   with a high enough index, returns -1, otherwise returns the amount of
   bytes written to out. */
int
fd_shredb_query_highest( fd_shredb_t * store,
                             ulong             slot,
                             uint              min_shred_idx,
                             uchar             out[ FD_SHRED_MAX_SZ ] );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_store_fd_shredb_h */
