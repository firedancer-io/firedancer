#ifndef HEADER_fd_src_discof_fec_repair_fd_fec_repair_h
#define HEADER_fd_src_discof_fec_repair_fd_fec_repair_h

/* This provides APIs for orchestrating repair of FEC sets as they are
   received from the cluster.

   Concepts:

   - Blocks are aggregations of entries aka. microblocks which are
     groupings of txns and are constructed by the block producer (see
     fd_pack).

   - Entries are grouped into entry batches by the block producer (see
     fd_pack / fd_shredder).

   - Entry batches are divided into chunks known as shreds by the block
     producer (see fd_shredder).

   - Shreds are grouped into forward-error-correction sets (FEC sets) by
     the block producer (see fd_shredder).

   - Shreds are transmitted to the rest of the cluster via the Turbine
     protocol (see fd_shredder / fd_shred).

   - Once enough shreds within a FEC set are received to recover the
     entirety of the shred data encoded by that FEC set, the receiver
     can "complete" the FEC set (see fd_fec_resolver).

   - If shreds in the FEC set are missing such that it can't complete,
     the receiver can use the Repair protocol to request missing shreds
     in FEC set (see fd_fec_repair).

  -  The current Repair protocol does not support requesting coding
     shreds.  As a result, some FEC sets might be actually complete
     (contain all data shreds).  Repair currently hacks around this by
     forcing completion but the long-term solution is to add support for
     fec_repairing coding shreds via Repair. */

#include "../../disco/fd_disco_base.h"
#include "../../ballet/reedsol/fd_reedsol.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../tango/fseq/fd_fseq.h"


/* FD_REPAIR_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_REPAIR_USE_HANDHOLDING
#define FD_REPAIR_USE_HANDHOLDING 1
#endif

/* fd_fec_intra_idxs is a bit vec that tracks the received data shred
   idxs in the FEC set. */

#define SET_NAME     fd_fec_intra_idxs
#define SET_MAX      FD_REEDSOL_DATA_SHREDS_MAX
#include "../../util/tmpl/fd_set.c"

/* fd_fec_intra_t tracks in-progress FEC sets to repair "intra"-FEC set
   ie. repairing shreds that are missing within a given FEC set. This
   should roughly track the same set of in-progress FEC sets as
   fec_set_resolver. */

struct fd_fec_intra {
  ulong key;  /* map key. 32 msb = slot, 32 lsb = fec_set_idx */
  ulong prev; /* internal use by dlist */
  ulong next; /* internal use by map_chain */

  ulong slot;        /* slot of the block this fec set is part of  */
  ulong parent_slot; /* parent slot of `slot` */
  uint  fec_set_idx; /* index of the first data shred */
  long  ts;          /* timestamp upon receiving the first shred */
  ulong recv_cnt;    /* count of shreds received so far data + coding */
  ulong data_cnt;    /* count of total data shreds in the FEC set */

  fd_fec_intra_idxs_t idxs[fd_fec_intra_idxs_word_cnt]; /* bit vec of rx'd data shred idxs */
 };
 typedef struct fd_fec_intra fd_fec_intra_t;

#define POOL_NAME fd_fec_intra_pool
#define POOL_T    fd_fec_intra_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_fec_intra_map
#define MAP_ELE_T fd_fec_intra_t
#include "../../util/tmpl/fd_map_chain.c"

/* fd_fec_repair_t is the top-level structure that maintains an LRU cache
   (pool, dlist, map) of the outstanding block slices that need fec_repair.

   The fec_repair order is FIFO so the first slice to go into the LRU will
   also be the first to attempt fec_repair. */

struct __attribute__((aligned(128UL))) fd_fec_repair {
  fd_fec_intra_t *     intra_pool;
  fd_fec_intra_map_t * intra_map;
};
typedef struct fd_fec_repair fd_fec_repair_t;

FD_PROTOTYPES_BEGIN

/* Constructors */

/* fd_fec_repair_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as fec_repair with up to
   slice_max slices and block_max blocks. */

FD_FN_CONST static inline ulong
fd_fec_repair_align( void ) {
  return alignof(fd_fec_repair_t);
}

FD_FN_CONST static inline ulong
fd_fec_repair_footprint( ulong intra_max ) {
  return FD_LAYOUT_FINI(
      FD_LAYOUT_APPEND(
      FD_LAYOUT_APPEND(
      FD_LAYOUT_APPEND(
      FD_LAYOUT_INIT,
        alignof(fd_fec_repair_t),  sizeof(fd_fec_repair_t) ),
        fd_fec_intra_pool_align(), fd_fec_intra_pool_footprint( intra_max ) ),
        fd_fec_intra_map_align(),  fd_fec_intra_map_footprint( intra_max ) ),
    fd_fec_repair_align() );
}

/* fd_fec_repair_new formats an unused memory region for use as a fec_repair.
   mem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment. */

void *
fd_fec_repair_new( void * shmem, ulong intra_max, ulong seed );

/* fd_fec_repair_join joins the caller to the fec_repair.  fec_repair points to the
   first byte of the memory region backing the fec_repair in the caller's
   address space.

   Returns a pointer in the local address space to fec_repair on success. */

fd_fec_repair_t *
fd_fec_repair_join( void * fec_repair );

/* fd_fec_repair_leave leaves a current local join.  Returns a pointer to the
   underlying shared memory region on success and NULL on failure (logs
   details).  Reasons for failure include fec_repair is NULL. */

void *
fd_fec_repair_leave( fd_fec_repair_t const * fec_repair );

/* fd_fec_repair_delete unformats a memory region used as a fec_repair.
   Assumes only the nobody is joined to the region.  Returns a
   pointer to the underlying shared memory region or NULL if used
   obviously in error (e.g. fec_repair is obviously not a fec_repair ... logs
   details).  The ownership of the memory region is transferred to the
   caller. */

void *
fd_fec_repair_delete( void * fec_repair );

// /* fd_fec_repair_ele_query returns a pointer to the in-progress FEC keyed
//    by slot and fec_set_idx.  Returns NULL if not found. */

// FD_FN_PURE static inline fd_fec_intra_t *
// fd_fec_repair_ele_query( fd_fec_repair_t * fec_repair, ulong slot, uint fec_set_idx ) {
//   ulong key = slot << 32 | (ulong)fec_set_idx;
//   return fd_fec_repair_ele_map_query( fec_repair->map, key, NULL );
// }

// /* fd_fec_repair_ele_insert inserts and returns a new in-progress FEC set
//    keyed by slot and fec_set_idx into the map.  Returns NULL if the map
//    is full. */

// static inline fd_fec_intra_t *
// fd_fec_repair_ele_insert( fd_fec_repair_t * fec_repair, ulong slot, uint fec_set_idx ) {
//   if( FD_UNLIKELY( fd_fec_repair_ele_map_key_cnt( fec_repair->map ) == fd_fec_repair_ele_map_key_max( fec_repair->map ) ) ) return NULL;
//   ulong             key = slot << 32 | (ulong)fec_set_idx;
//   fd_fec_intra_t * fec = fd_fec_repair_ele_map_insert( fec_repair->map, key ); /* cannot fail */
//   fec->slot             = slot;
//   fec->fec_set_idx      = fec_set_idx;
//   fec->ts               = fd_log_wallclock();
//   fec->recv_cnt         = 0;
//   fec->data_cnt         = 0;
//   fd_fec_repair_ele_idxs_null( fec->idxs );
//   return fec;
// }

// /* fd_fec_repair_ele_query removes an in-progress FEC set from the map.
//    Returns NULL if no fec set keyed by slot and fec_set_idx is found. */

// static inline void
// fd_fec_repair_ele_remove( fd_fec_repair_t * fec_repair, ulong slot, uint fec_set_idx ) {
//   ulong             key = slot << 32 | (ulong)fec_set_idx;
//   fd_fec_intra_t * fec = fd_fec_repair_ele_map_query( fec_repair->map, key, NULL );
//   FD_TEST( fec );
//   fd_fec_repair_ele_map_remove( fec_repair->map, fec ); /* cannot fail */
// }

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_fec_repair_fd_fec_repair_h */
