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
  fd_ed25519_sig_t sig; /* Ed25519 sig identifier of the FEC. */

  uint  buffered_idx;  /* wmk of shreds buffered contiguously, inclusive. Starts at 0 */
  uint  completes_idx; /* UINT_MAX unless this FEC contains a shred with a batch_complete or slot_complete flag. shred_idx - fec_set_idx */

  fd_fec_intra_idxs_t idxs[fd_fec_intra_idxs_word_cnt]; /* bit vec of rx'd data shred idxs */
 };
 typedef struct fd_fec_intra fd_fec_intra_t;

#define POOL_NAME fd_fec_intra_pool
#define POOL_T    fd_fec_intra_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_fec_intra_map
#define MAP_ELE_T fd_fec_intra_t
#include "../../util/tmpl/fd_map_chain.c"

struct fd_fec_chainer {
  ulong key; /* 32 msb slot, 32 lsb fec_set*/
};
typedef struct fd_fec_chainer fd_fec_chainer_t;

#define MAP_NAME    fd_fec_chainer_map
#define MAP_T       fd_fec_chainer_t
#define MAP_MEMOIZE 0
#include "../../util/tmpl/fd_map_dynamic.c"

/* fd_fec_repair_t is the top-level structure that maintains an LRU cache
   (pool, dlist, map) of the outstanding block slices that need fec_repair.

   The fec_repair order is FIFO so the first slice to go into the LRU will
   also be the first to attempt fec_repair. */

struct __attribute__((aligned(128UL))) fd_fec_repair {
  fd_fec_intra_t *     intra_pool;
  fd_fec_intra_map_t * intra_map;

  fd_fec_chainer_t *   fec_chainer_map; /* FIXME: drop in replacement for the fec chainer */
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
  int lg_intra_max = fd_ulong_find_msb( fd_ulong_pow2_up( intra_max ) );
  return FD_LAYOUT_FINI(
      FD_LAYOUT_APPEND(
      FD_LAYOUT_APPEND(
      FD_LAYOUT_APPEND(
      FD_LAYOUT_APPEND(
      FD_LAYOUT_INIT,
        alignof(fd_fec_repair_t),  sizeof(fd_fec_repair_t) ),
        fd_fec_intra_pool_align(), fd_fec_intra_pool_footprint( intra_max ) ),
        fd_fec_intra_map_align(),  fd_fec_intra_map_footprint( intra_max ) ),
        fd_fec_chainer_map_align(),  fd_fec_chainer_map_footprint( lg_intra_max ) ),
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

static inline fd_fec_intra_t *
fd_fec_repair_ele_insert( fd_fec_repair_t * fec_repair,
                          ulong             slot,
                          uint              fec_set_idx,
                          uint              shred_idx_or_data_cnt,
                          int               completes,
                          int               is_code   ) {

  ulong key = slot << 32 | (ulong)fec_set_idx;
  fd_fec_intra_t * fec = fd_fec_intra_map_ele_query( fec_repair->intra_map, &key, NULL, fec_repair->intra_pool );
  if( FD_UNLIKELY( !fec ) ) {
    if( FD_UNLIKELY( !fd_fec_intra_pool_free( fec_repair->intra_pool ) ) ) {
      FD_LOG_WARNING(( "fec_repair pool full" ));
      return NULL;
    }
    fec = fd_fec_intra_pool_ele_acquire( fec_repair->intra_pool );
    //FD_LOG_INFO(("Inserting shred into fec repair map, slot %lu, fec %u", slot, fec_set_idx ));
    fec->key              = key;
    fec->slot             = slot;
    fec->fec_set_idx      = fec_set_idx;
    fec->ts               = fd_log_wallclock();
    fec->recv_cnt         = 0;
    fec->data_cnt         = 0;
    fec->completes_idx    = UINT_MAX;
    fec->buffered_idx     = UINT_MAX;
    memset( fec->sig, 0, sizeof(fd_ed25519_sig_t));
    fd_fec_intra_idxs_null( fec->idxs );
    fd_fec_intra_map_ele_insert( fec_repair->intra_map, fec, fec_repair->intra_pool ); /* cannot fail */
  }

  if( FD_UNLIKELY( is_code ) ) {
    fec->data_cnt = shred_idx_or_data_cnt;
    fec->completes_idx = (uint)fec->data_cnt - 1;
  } else {
    uint shred_idx = shred_idx_or_data_cnt;
    fd_fec_intra_idxs_insert( fec->idxs, shred_idx - fec_set_idx );
  }

  if( FD_UNLIKELY( completes ) ) {
    uint shred_idx = shred_idx_or_data_cnt;
    fec->completes_idx = shred_idx - fec_set_idx;
  }

  fec->recv_cnt++;
  /* advanced buffered if possible */
  for( uint i = fec->buffered_idx + 1; i <= fec->completes_idx; i++ ) {
    if( fd_fec_intra_idxs_test( fec->idxs, i ) ) {
      fec->buffered_idx = i;
    } else {
      break;
    }
  }

  return fec;
}

static inline int
check_blind_fec_completed( fd_fec_repair_t * fec_repair,
                           ulong             slot,
                           uint              fec_set_idx ) {

  ulong fec_key = ( slot << 32 ) | ( fec_set_idx );
  fd_fec_intra_t * fec_intra = fd_fec_intra_map_ele_query( fec_repair->intra_map, &fec_key, NULL, fec_repair->intra_pool );

  ulong next_fec_key = ( slot << 32 ) | ( fec_set_idx + fec_intra->buffered_idx + 1 );

  /* speculate - is the next shred after this the next FEC set? */

  if( FD_LIKELY( fec_intra->data_cnt != 0 ) ) return 0; /* We have a coding shred for this FEC. Do not force complete. */
  if( fec_intra->buffered_idx == UINT_MAX ) return 0;
  if( fec_intra->buffered_idx == fec_intra->completes_idx ) return 1; /* This happens when completes is populated by batch_complete flag or by the below */

  fd_fec_intra_t * next_fec = fd_fec_intra_map_ele_query( fec_repair->intra_map, &next_fec_key, NULL, fec_repair->intra_pool );
  if( !next_fec ) {
    fd_fec_chainer_t * next_fec_c = fd_fec_chainer_map_query( fec_repair->fec_chainer_map, next_fec_key, NULL );
    if( !next_fec_c ) {
      return 0; /* no next fec set */
    }
  }

  /* we have discovered the end of a fec_set. Now check if we've actually buffered that much */

  if( fec_intra->completes_idx == UINT_MAX ) {
    fec_intra->completes_idx = fec_intra->buffered_idx;
  }

  return ( fec_intra->buffered_idx != UINT_MAX && fec_intra->buffered_idx == fec_intra->completes_idx );
}

// /* fd_fec_repair_ele_query removes an in-progress FEC set from the map.
//    Returns NULL if no fec set keyed by slot and fec_set_idx is found. */

// static inline void
// fd_fec_repair_ele_remove( fd_fec_repair_t * fec_repair, ulong slot, uint fec_set_idx ) {
//   ulong             key = slot << 32 | (ulong)fec_set_idx;
//   fd_fec_intra_t * fec = fd_fec_repair_ele_map_query( fec_repair->map, key, NULL );
//   FD_TEST( fec );
//   fd_fec_repair_ele_map_remove( fec_repair->map, fec ); /* cannot fail */
// }

static inline void
fd_fec_repair_ele_remove( fd_fec_repair_t * fec_repair,
                          ulong             key ) {
  fd_fec_intra_t * fec = fd_fec_intra_map_ele_query( fec_repair->intra_map, &key, NULL, fec_repair->intra_pool );
  FD_TEST( fec );
  fd_fec_intra_t * ele = fd_fec_intra_map_ele_remove( fec_repair->intra_map, &key, NULL, fec_repair->intra_pool ); /* cannot fail */
  fd_fec_intra_pool_ele_release( fec_repair->intra_pool, ele ); /* cannot fail, hopefully */
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_fec_repair_fd_fec_repair_h */
