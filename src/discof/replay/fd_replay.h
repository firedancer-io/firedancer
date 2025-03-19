#ifndef HEADER_fd_src_discof_replay_fd_replay_h
#define HEADER_fd_src_discof_replay_fd_replay_h

#include "../../ballet/reedsol/fd_reedsol.h"

/* This provides APIs for orchestrating replay of blocks as they are
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
     in FEC set (see fd_repair).

   - Once all the FEC sets complete within an entry batch is now
     replayable (see fd_replay).

   - Replay describes a grouping of completed entry batches as a block
     slice.  Because shreds are received over the network and multiple
     entry batches may be completed at once, an entire slice is queued
     for replay (vs. individual entry batches)

   - Replay uses the frontier to determine which of the fork heads aka.
     banks the slice should be replayed from.  This is required because
     each fork head has an independent state ie. different set of txns
     that have been executed (see fd_replay / fd_forks).

   - This process is repeated for every slice in the block at which
     point the block is executed (see fd_replay).

   - Replay of all the slices in a block must happen in order, as well
     as the entry batches within the slice and the entries within the
     entry batch.  However, replay of the txns within an entry can
     happen out-of-order (see fd_replay). */

#include "../../disco/fd_disco_base.h"
#include "../../ballet/reedsol/fd_reedsol.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../tango/fseq/fd_fseq.h"


/* FD_REPLAY_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_REPLAY_USE_HANDHOLDING
#define FD_REPLAY_USE_HANDHOLDING 1
#endif

/* fd_replay_fec_idxs is a bit vec that tracks the received data shred
   idxs in the FEC set. */

#define SET_NAME     fd_replay_fec_idxs
#define SET_MAX      FD_REEDSOL_DATA_SHREDS_MAX
#define SET_WORD_CNT (SET_MAX / sizeof(ulong) + 1)
FD_STATIC_ASSERT( FD_REEDSOL_DATA_SHREDS_MAX % sizeof(ulong) != 0, fd_replay_fec_idxs );
#include "../../util/tmpl/fd_set.c"

/* fd_replay_fec_t tracks in-progress FEC sets.  It's synchronized with
   fd_fec_resolver, so the FEC sets fd_replay tracks should roughly
   match fd_fec_resolver's in-progress FEC sets.  This state might be
   slightly delayed, because the replay tile is a downstream consumer of
   the shred tile, and therefore fd_replay_fec lags fd_fec_resolver. */

struct fd_replay_fec {
  ulong key;  /* map key. 32 msb = slot, 32 lsb = fec_set_idx */
  ulong prev; /* internal use by dlist */
  uint  hash; /* internal use by map */

  ulong slot;        /* slot of the block this fec set is part of  */
  ulong parent_slot; /* parent slot of `slot` */
  uint  fec_set_idx; /* index of the first data shred */
  long  ts;          /* timestamp upon receiving the first shred */
  ulong recv_cnt;    /* count of shreds received so far data + coding */
  ulong data_cnt;    /* count of total data shreds in the FEC set */

  /* This set is used to track which data shred indices to request if
     needing repairs. */

  fd_replay_fec_idxs_t idxs[FD_REEDSOL_DATA_SHREDS_MAX / sizeof(ulong) + 1];
 };
 typedef struct fd_replay_fec fd_replay_fec_t;

#define DEQUE_NAME  fd_replay_fec_deque
#define DEQUE_T     fd_replay_fec_t
#include "../../util/tmpl/fd_deque_dynamic.c"

#define MAP_NAME  fd_replay_fec_map
#define MAP_T     fd_replay_fec_t
#include "../../util/tmpl/fd_map_dynamic.c"

/* fd_replay_slice_t describes a replayable slice of a block which is
   a group of one or more completed entry batches. */

static inline FD_FN_CONST
uint fd_replay_slice_start_idx( ulong key ){
  return (uint)fd_ulong_extract( key, 32, 63 );
}

static inline FD_FN_CONST
uint fd_replay_slice_end_idx( ulong key ){
  return (uint)fd_ulong_extract( key, 0, 31 );
}

static inline
ulong fd_replay_slice_key( uint start_idx, uint end_idx ) {
  return (ulong)start_idx << 32 | (ulong)end_idx;
}

struct fd_replay_slice {
  ulong   slot;
  ulong * deque;
};
typedef struct fd_replay_slice fd_replay_slice_t;

#define DEQUE_NAME fd_replay_slice_deque
#define DEQUE_T    ulong
#include "../../util/tmpl/fd_deque_dynamic.c"

#define MAP_NAME         fd_replay_slice_map
#define MAP_T            fd_replay_slice_t
#define MAP_KEY          slot
#define MAP_KEY_NULL     ULONG_MAX
#define MAP_KEY_INVAL(k) ((k)==ULONG_MAX)
#define MAP_MEMOIZE      0
#include "../../util/tmpl/fd_map_dynamic.c"

#define FD_REPLAY_MAGIC (0xf17eda2ce77e91a7UL) /* firedancer replay version 0 */

/* fd_replay_t is the top-level structure that maintains an LRU cache
   (pool, dlist, map) of the outstanding block slices that need replay.

   The replay order is FIFO so the first slice to go into the LRU will
   also be the first to attempt replay. */

struct __attribute__((aligned(128UL))) fd_replay {
  ulong fec_max;
  ulong slice_max;
  ulong block_max;

  /* Track in-progress FEC sets to repair if they don't complete in a
     timely way. */

  fd_replay_fec_t *   fec_map;
  fd_replay_fec_t *   fec_deque; /* FIFO */

  /* Track block slices to be replayed. */

  fd_replay_slice_t * slice_map;

  /* Buffer to hold the block slice. */

  uchar *             slice_buf;

  /* Magic number to verify the replay structure. */

  ulong               magic;
};
typedef struct fd_replay fd_replay_t;

FD_PROTOTYPES_BEGIN

/* Constructors */

/* fd_replay_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as replay with up to
   slice_max slices and block_max blocks. */

FD_FN_CONST static inline ulong
fd_replay_align( void ) {
  return alignof(fd_replay_t);
}

FD_FN_CONST static inline ulong
fd_replay_footprint( ulong fec_max, ulong slice_max, ulong block_max ) {
  int lg_fec_max   = fd_ulong_find_msb( fd_ulong_pow2_up( fec_max ) );
  int lg_block_max = fd_ulong_find_msb( fd_ulong_pow2_up( block_max ) );
  ulong footprint =
      FD_LAYOUT_APPEND(
      FD_LAYOUT_APPEND(
      FD_LAYOUT_APPEND(
      FD_LAYOUT_APPEND(
      FD_LAYOUT_APPEND(
      FD_LAYOUT_INIT,
        alignof(fd_replay_t),          sizeof(fd_replay_t) ),
        fd_replay_fec_map_align(),     fd_replay_fec_map_footprint( lg_fec_max ) ),
        fd_replay_fec_deque_align(),   fd_replay_fec_deque_footprint( fec_max ) ),
        128UL,                         FD_SLICE_MAX ),
        fd_replay_slice_map_align(),   fd_replay_slice_map_footprint( lg_block_max) );

    for( ulong i = 0UL; i < block_max; i++ ) {
      footprint = FD_LAYOUT_APPEND( footprint, fd_replay_slice_deque_align(), fd_replay_slice_deque_footprint( slice_max ) );
    }
    return FD_LAYOUT_FINI(footprint, fd_replay_align());
}

/* fd_replay_new formats an unused memory region for use as a replay.
   mem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment. */

void *
fd_replay_new( void * shmem, ulong fec_max, ulong slice_max, ulong block_max );

/* fd_replay_join joins the caller to the replay.  replay points to the
   first byte of the memory region backing the replay in the caller's
   address space.

   Returns a pointer in the local address space to replay on success. */

fd_replay_t *
fd_replay_join( void * replay );

/* fd_replay_leave leaves a current local join.  Returns a pointer to the
   underlying shared memory region on success and NULL on failure (logs
   details).  Reasons for failure include replay is NULL. */

void *
fd_replay_leave( fd_replay_t const * replay );

/* fd_replay_delete unformats a memory region used as a replay.
   Assumes only the nobody is joined to the region.  Returns a
   pointer to the underlying shared memory region or NULL if used
   obviously in error (e.g. replay is obviously not a replay ... logs
   details).  The ownership of the memory region is transferred to the
   caller. */

void *
fd_replay_delete( void * replay );

/* fd_replay_fec_query returns a pointer to the in-progress FEC keyed
   by slot and fec_set_idx.  Returns NULL if not found. */

FD_FN_PURE static inline fd_replay_fec_t *
fd_replay_fec_query( fd_replay_t * replay, ulong slot, uint fec_set_idx ) {
  ulong key = slot << 32 | (ulong)fec_set_idx;
  return fd_replay_fec_map_query( replay->fec_map, key, NULL );
}

/* fd_replay_fec_insert inserts and returns a new in-progress FEC set
   keyed by slot and fec_set_idx into the map.  Returns NULL if the map
   is full. */

static inline fd_replay_fec_t *
fd_replay_fec_insert( fd_replay_t * replay, ulong slot, uint fec_set_idx ) {
  if( FD_UNLIKELY( fd_replay_fec_map_key_cnt( replay->fec_map ) == fd_replay_fec_map_key_max( replay->fec_map ) ) ) return NULL;
  ulong             key = slot << 32 | (ulong)fec_set_idx;
  fd_replay_fec_t * fec = fd_replay_fec_map_insert( replay->fec_map, key ); /* cannot fail */
  fec->slot             = slot;
  fec->fec_set_idx      = fec_set_idx;
  fec->ts               = fd_log_wallclock();
  fec->recv_cnt         = 0;
  fec->data_cnt         = 0;
  fd_replay_fec_idxs_null( fec->idxs );
  return fec;
}

/* fd_replay_fec_query removes an in-progress FEC set from the map.
   Returns NULL if no fec set keyed by slot and fec_set_idx is found. */

static inline void
fd_replay_fec_remove( fd_replay_t * replay, ulong slot, uint fec_set_idx ) {
  ulong             key = slot << 32 | (ulong)fec_set_idx;
  fd_replay_fec_t * fec = fd_replay_fec_map_query( replay->fec_map, key, NULL );
  FD_TEST( fec );
  fd_replay_fec_map_remove( replay->fec_map, fec ); /* cannot fail */
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_replay_fd_replay_h */
