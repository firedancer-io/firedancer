#ifndef HEADER_fd_src_disco_store_fd_ledger_h
#define HEADER_fd_src_disco_store_fd_ledger_h

#include "../../util/fd_util.h"
#include "../../ballet/shred/fd_shred.h"

/* An on-disk shred store for serving repair requests.

   Unlike fd_store, fd_ledger stores individual raw shreds keyed
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
   write directly into the ledger in the future. */


FD_FN_CONST static inline ulong
fd_ledger_key_pack( ulong slot, uint shred_idx ) {
  return (slot << 16) | (ulong)(ushort)shred_idx;
}

FD_FN_CONST static inline ulong
fd_ledger_key_slot( ulong key ) {
  return key >> 16;
}

FD_FN_CONST static inline uint
fd_ledger_key_shred_idx( ulong key ) {
  return (uint)(key & 0xFFFFUL);
}

/* per-shred entry, (slot, shred_index) -> ring_idx */
struct fd_ledger_shred_entry {
  ulong key;
  uint  hash;
  ulong ring_idx;
};
typedef struct fd_ledger_shred_entry fd_ledger_shred_entry_t;

#define MAP_NAME             fd_ledger_shred_map
#define MAP_T                fd_ledger_shred_entry_t
#define MAP_KEY_T            ulong
#define MAP_KEY_NULL         ULONG_MAX
#define MAP_KEY_INVAL(k)     ((k)==ULONG_MAX)
#define MAP_KEY_EQUAL(k0,k1) ((k0)==(k1))
#define MAP_KEY_EQUAL_IS_SLOW 0
#define MAP_KEY_HASH(k,seed) ((uint)fd_ulong_hash( (k) ^ (seed) ))
#define MAP_MEMOIZE          1
#include "../../util/tmpl/fd_map_dynamic.c"

/* per-slot entry, slot -> (highest_shred_idx, cnt) */
struct fd_ledger_slot_entry {
  ulong key;
  uint  hash;
  uint  highest_shred_idx; /* highest shred_idx we have for this slot */
  ulong cnt;               /* number of shreds we have for this slot */
};
typedef struct fd_ledger_slot_entry fd_ledger_slot_entry_t;

#define MAP_NAME             fd_ledger_slot_map
#define MAP_T                fd_ledger_slot_entry_t
#define MAP_KEY_T            ulong
#define MAP_KEY_NULL         ULONG_MAX
#define MAP_KEY_INVAL(k)     ((k)==ULONG_MAX)
#define MAP_KEY_EQUAL(k0,k1) ((k0)==(k1))
#define MAP_KEY_EQUAL_IS_SLOW 0
#define MAP_KEY_HASH(k,seed) ((uint)fd_ulong_hash( (k) ^ (seed) ))
#define MAP_MEMOIZE          1
#include "../../util/tmpl/fd_map_dynamic.c"

/* On-disk ring buffer entry. */
struct __attribute__((aligned(64))) fd_ledger_entry {
  ulong  key;                      /* for reverse lookups on eviction */
  ushort shred_sz;                /* actual shred byte count */
  uchar  occupied;                /* 1 if this slot holds valid data */
  uchar  shred[FD_SHRED_MAX_SZ];
};
typedef struct fd_ledger_entry fd_ledger_entry_t;

struct fd_ledger {
  ulong  max_shreds;                  /* ring buffer capacity */
  ulong  write_head;                  /* next ring position to write */
  ulong  cnt;                         /* current number of entries */
  int    fd;
  void * mapped;
  ulong  mapped_sz;
  fd_ledger_shred_entry_t * shred_map;
  fd_ledger_slot_entry_t  * slot_map;
};
typedef struct fd_ledger fd_ledger_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_ledger_align( void ) {
  return alignof(fd_ledger_t);
}

FD_FN_CONST ulong
fd_ledger_footprint( ulong max_shreds );

void *
fd_ledger_new( void       * shmem,
               ulong        max_shreds,
               char const * file_path,
               ulong        seed );

fd_ledger_t *
fd_ledger_join( void * shledger );

void *
fd_ledger_leave( fd_ledger_t const * ledger );

void *
fd_ledger_delete( void * shledger );

/* Inserts a shred. Overwrites oldest entry if at capacity.
   TODO: May need to return whether an existing (slot, shred_idx) entry
   already existed before fd_ledger_insert was called. */
void
fd_ledger_insert( fd_ledger_t * ledger,
                  uchar const * shred,
                  ulong         shred_sz,
                  ulong         slot,
                  uint          shred_idx );

/* Given a (slot, shred_index), returns the corresponding entry.
   If no entry was found, returns -1, otherwise returns the amount
   of bytes written to out. */
int
fd_ledger_query( fd_ledger_t * ledger,
                 uchar         out[ FD_SHRED_MAX_SZ ],
                 ulong         slot,
                 uint          shred_idx );

/* Given a (slot, min_shred_idx), returns the highest shred the ledger
   knows of for that slot.

   If the ledger has no shreds for the given slot, or does not have a shred
   with a high enough index, returns -1, otherwise returns the amount of
   bytes written to out. */
int
fd_ledger_query_highest( fd_ledger_t * ledger,
                         uchar         out[ FD_SHRED_MAX_SZ ],
                         ulong         slot,
                         uint          min_shred_idx );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_store_fd_ledger_h */
