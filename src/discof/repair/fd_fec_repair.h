#ifndef HEADER_fd_src_discof_repair_fd_fec_repair_h
#define HEADER_fd_src_discof_repair_fd_fec_repair_h

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
#include "../../tango/fseq/fd_fseq.h"
#include "fd_fec_chainer.h"


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

  ulong  slot;        /* slot of the block this fec set is part of  */
  ushort parent_off;  /* parent slot's offset from slot */
  uint   fec_set_idx; /* index of the first data shred */
  long   ts;          /* timestamp upon receiving the first shred */
  ulong  recv_cnt;    /* count of shreds received so far data + coding */
  uint   data_cnt;    /* count of total data shreds in the FEC set */

  fd_ed25519_sig_t sig; /* Ed25519 sig identifier of the FEC. */

  uint  buffered_idx;  /* wmk of shreds buffered contiguously, inclusive. Starts at 0 */
  uint  completes_idx; /* UINT_MAX unless this FEC contains a shred with a batch_complete or slot_complete flag. shred_idx - fec_set_idx */

  uint  shred_tile_idx; /* index of the shred tile this FEC set is part of */
  ulong deque_ele_idx;  /* index of the element in the corresponding dlist */

  fd_fec_intra_idxs_t idxs[fd_fec_intra_idxs_word_cnt]; /* bit vec of rx'd data shred idxs */
 };
 typedef struct fd_fec_intra fd_fec_intra_t;

#define POOL_NAME fd_fec_intra_pool
#define POOL_T    fd_fec_intra_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_fec_intra_map
#define MAP_ELE_T fd_fec_intra_t
#include "../../util/tmpl/fd_map_chain.c"

struct fd_fec_order {
  ulong key;  /* 32 msb slot, 32 lsb fec_set_idx */
  ulong prev; /* internal use by dlist */
  ulong next; /* internal use by dlist */
};
typedef struct fd_fec_order fd_fec_order_t;

#define POOL_NAME fd_fec_order_pool
#define POOL_T    fd_fec_order_t
#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME  fd_fec_order_dlist
#define DLIST_ELE_T fd_fec_order_t
#include "../../util/tmpl/fd_dlist.c"

/* fd_fec_repair_t is the top-level structure that maintains an LRU cache
   (pool, dlist, map) of the outstanding block slices that need fec_repair.

   The fec_repair order is FIFO so the first slice to go into the LRU will
   also be the first to attempt fec_repair. */

struct __attribute__((aligned(128UL))) fd_fec_repair {
  /* These two parameters are tightly coupled with fd_fec_resolver,
     because fec_intra aims to exactly mirror the in-progress FEC sets
     across all the fec_resolver tiles. fec_max should be the number of
     in progress FEC sets each of the fec_resolvers can hold, which is
     max_pending_shred_sets + 1. fec_repair will size its intra pool to
     be able to hold all FECs across all fec_resolvers, so
     fec_max * ( max_pending_shred_sets + 1 ), although may be rounded
     up to the nearest power of 2. The dlist is sized to only hold
     max_pending_shred_sets + 1, and we create a dlist for every
     fec_resolver in order to maintain queue order. */

  ulong                fec_max;
  ulong                shred_tile_cnt;

  fd_fec_intra_t     * intra_pool;
  fd_fec_intra_map_t * intra_map;

  fd_fec_order_t       * * order_pool_lst;  /* List[shred_tile_cnt] of pointers to dlist pool */
  fd_fec_order_dlist_t * * order_dlist_lst; /* Maintains insertion order of FEC sets in FEC resolver */

  /* fd_fec_order_t       * order_pool;
     fd_fec_order_dlist_t * order_dlist; */ /* Maintains insertion order of FEC sets in FEC resolver */
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
fd_fec_repair_footprint( ulong fec_max, uint shred_tile_cnt ) {
  ulong total_fecs_pow2 = fd_ulong_pow2_up( fec_max * shred_tile_cnt );

  FD_TEST( fd_fec_intra_map_footprint( total_fecs_pow2 ) > 0 );
  FD_TEST( fd_fec_intra_pool_footprint( total_fecs_pow2 ) > 0 );

  ulong footprint =
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_fec_repair_t),   sizeof(fd_fec_repair_t) ),
      fd_fec_intra_pool_align (), fd_fec_intra_pool_footprint ( total_fecs_pow2 ) ),
      fd_fec_intra_map_align  (), fd_fec_intra_map_footprint  ( total_fecs_pow2 ) ),
      alignof(ulong),             sizeof(fd_fec_order_t*) * shred_tile_cnt ),
      alignof(ulong),             sizeof(fd_fec_order_dlist_t*) * shred_tile_cnt );

  for( ulong i = 0UL; i < shred_tile_cnt; i++ ) {
    footprint = FD_LAYOUT_APPEND( footprint, fd_fec_order_pool_align(), fd_fec_order_pool_footprint( fec_max ) );
    footprint = FD_LAYOUT_APPEND( footprint, fd_fec_order_dlist_align(), fd_fec_order_dlist_footprint() );
  }

  return FD_LAYOUT_FINI(footprint, fd_fec_repair_align());
}

/* fd_fec_repair_new formats an unused memory region for use as a
   fec_repair. mem is a non-NULL pointer to this region in the local
   address space with the required footprint and alignment. fec_max is a
   very specific number. fec_max should be the maximum number of pending
   FECs each fec_resolver can hold (usually max_pending_shred_sets + 2)
   We then size the fec_intra map to hold shred_tile_cnt * fec_max. Note
   that since fec_max will almost never be a power of 2, but the map
   chain cnt must be a power of 2, we size the intra pool to be the next
   largest power of 2 > shred_tile_cnt * fec_max, but we can limit the
   number of fec_intras to match the fec_resolvers using the fec
   ordering dlist.  */

void *
fd_fec_repair_new( void * shmem, ulong fec_max, uint shred_tile_cnt, ulong seed );

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

FD_FN_PURE static inline fd_fec_intra_t *
fd_fec_repair_query( fd_fec_repair_t * fec_repair, ulong slot, uint fec_set_idx ) {
  ulong key = slot << 32 | (ulong)fec_set_idx;
  return fd_fec_intra_map_ele_query( fec_repair->intra_map, &key, NULL, fec_repair->intra_pool );
}

// /* fd_fec_repair_ele_insert inserts and returns a new in-progress FEC set
//    keyed by slot and fec_set_idx into the map.  Returns NULL if the map
//    is full. */

static inline void
fd_fec_repair_remove( fd_fec_repair_t * fec_repair, ulong key ) {
  FD_LOG_NOTICE(( "remove %lu %u", key >> 32, (uint)key ));
  fd_fec_intra_t * fec = fd_fec_intra_map_ele_query( fec_repair->intra_map, &key, NULL, fec_repair->intra_pool );
  FD_TEST( fec );

  uint  shred_tile_idx = fec->shred_tile_idx;
  ulong deque_ele_idx  = fec->deque_ele_idx;

  fd_fec_intra_t * ele = fd_fec_intra_map_ele_remove( fec_repair->intra_map, &key, NULL, fec_repair->intra_pool ); /* cannot fail */
  fd_fec_intra_pool_ele_release( fec_repair->intra_pool, ele ); /* cannot fail, hopefully */

  /* Queue removal */

  fd_fec_order_dlist_t * fec_order_dlist = fec_repair->order_dlist_lst[shred_tile_idx];
  fd_fec_order_t * fec_order_pool = fec_repair->order_pool_lst[shred_tile_idx];

  fd_fec_order_dlist_idx_remove( fec_order_dlist, deque_ele_idx, fec_order_pool );
  fd_fec_order_pool_idx_release( fec_order_pool, deque_ele_idx );
}

static inline fd_fec_intra_t *
fd_fec_repair_insert( fd_fec_repair_t * fec_repair,
                          ulong             slot,
                          uint              fec_set_idx,
                          uint              shred_idx_or_data_cnt,
                          int               completes,
                          int               is_code,
                          uint              shred_tile_idx ) {
  FD_TEST( shred_tile_idx < fec_repair->shred_tile_cnt );
  FD_LOG_NOTICE(( "insert %lu %u", slot, fec_set_idx ));

  ulong key = slot << 32 | (ulong)fec_set_idx;
  fd_fec_intra_t * fec = fd_fec_intra_map_ele_query( fec_repair->intra_map, &key, NULL, fec_repair->intra_pool );
  if( FD_UNLIKELY( !fec ) ) {

    /* Check if the fec_resolver of shred_tile_idx has evicted any
       incomplete FECs. Deque ordering insertion */

    fd_fec_order_dlist_t * fec_order_dlist = fec_repair->order_dlist_lst[shred_tile_idx];
    fd_fec_order_t * fec_order_pool = fec_repair->order_pool_lst[shred_tile_idx];

    if( !fd_fec_order_pool_free( fec_order_pool ) ) {
      /* fec_resolver must have evicted something from their free list. */
      fd_fec_order_t * pop_ele = fd_fec_order_dlist_ele_pop_head( fec_order_dlist, fec_order_pool );
      fd_fec_order_pool_ele_release( fec_order_pool, pop_ele );

      fd_fec_intra_t * ele = fd_fec_intra_map_ele_remove( fec_repair->intra_map, &pop_ele->key, NULL, fec_repair->intra_pool ); /* cannot fail */
      fd_fec_intra_pool_ele_release( fec_repair->intra_pool, ele ); /* cannot fail, hopefully */
      //FD_LOG_WARNING(( "shred_tile:%u overflowing, popping from queue, slot %lu, fec %u", shred_tile_idx, pop_ele->key >> 32, (uint)pop_ele->key ));
    }
    fd_fec_order_t * fec_order = fd_fec_order_pool_ele_acquire( fec_order_pool );
    fec_order->key = key;
    fd_fec_order_dlist_ele_push_tail( fec_order_dlist, fec_order, fec_order_pool ); /* cannot fail */

    /* Map insertion */

    if( FD_UNLIKELY( !fd_fec_intra_pool_free( fec_repair->intra_pool ) ) ) { /* we definitely should have a free element */
      FD_LOG_ERR(( "fec_repair pool full. Almost certainly signifies fec_repair corruption, as the size of fec_order_pool <= fec_intra_pool." ));
    }

    fec = fd_fec_intra_pool_ele_acquire( fec_repair->intra_pool );
    //FD_LOG_INFO(("Inserting shred into fec repair map, slot %lu, fec %u. %lu/%lu eles used. On tile %u, queue usage %lu/%lu", slot, fec_set_idx,
                       //fd_fec_intra_pool_used( fec_repair->intra_pool ), fd_fec_intra_pool_max( fec_repair->intra_pool ),
                       //shred_tile_idx, fd_fec_order_pool_used( fec_order_pool ), fd_fec_order_pool_max( fec_order_pool ) ));

    fec->key            = key;
    fec->slot           = slot;
    fec->fec_set_idx    = fec_set_idx;
    fec->ts             = fd_log_wallclock();
    fec->recv_cnt       = 0;
    fec->data_cnt       = 0;
    fec->completes_idx  = UINT_MAX;
    fec->buffered_idx   = UINT_MAX;
    fec->shred_tile_idx = shred_tile_idx;
    fec->deque_ele_idx  = fd_fec_order_pool_idx( fec_order_pool, fec_order );
    memset( fec->sig, 0, sizeof(fd_ed25519_sig_t));
    fd_fec_intra_idxs_null( fec->idxs );
    fd_fec_intra_map_ele_insert( fec_repair->intra_map, fec, fec_repair->intra_pool ); /* cannot fail */
  }

  if( FD_UNLIKELY( is_code ) ) {
    fec->data_cnt = shred_idx_or_data_cnt;
    fec->completes_idx = fec->data_cnt - 1;
  } else {
    uint shred_idx = shred_idx_or_data_cnt;
    fd_fec_intra_idxs_insert( fec->idxs, shred_idx - fec_set_idx );
    if( FD_UNLIKELY( completes ) ) fec->completes_idx = shred_idx - fec_set_idx;
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

int
check_blind_fec_completed( fd_fec_repair_t  const * fec_repair,
                           fd_fec_chainer_t       * fec_chainer,
                           ulong                    slot,
                           uint                     fec_set_idx );
int
check_set_blind_fec_completed( fd_fec_repair_t * fec_repair,
                               fd_fec_chainer_t * fec_chainer,
                               ulong             slot,
                               uint              fec_set_idx );


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

#endif /* HEADER_fd_src_discof_repair_fd_fec_repair_h */
