#ifndef HEADER_fd_src_flamenco_runtime_fd_store_h
#define HEADER_fd_src_flamenco_runtime_fd_store_h

#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../flamenco/runtime/fd_runtime.h"

#include "util.h"
#include "fd_pending_slots.h"

#define FD_STORE_SLOT_PREPARE_CONTINUE            (0)
#define FD_STORE_SLOT_PREPARE_NEED_ORPHAN         (1)
#define FD_STORE_SLOT_PREPARE_NEED_REPAIR         (2)

/* The standard amount of time that we wait before repeating a slot */
#define FD_REPAIR_BACKOFF_TIME ( (long)150e6 )

struct __attribute__((aligned(128UL))) fd_store {
  long now;            /* Current time */

  /* metadata */
  ulong smr;           /* super-majority root */
  ulong snapshot_slot; /* the snapshot slot */
  ulong turbine_slot;  /* the first turbine slot we received on startup */

  /* external joins */
  fd_blockstore_t *     blockstore;
  fd_valloc_t           valloc;

  /* internal joins */
  fd_pending_slots_t * pending_slots;
};
typedef struct fd_store fd_store_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_store_align( void ) {
  return alignof( fd_store_t );
}

FD_FN_CONST static inline ulong
fd_store_footprint( void ) {
  return sizeof( fd_store_t ) + fd_pending_slots_footprint();
}

void *
fd_store_new( void * mem, ulong lo_wmark_slot );

fd_store_t * 
fd_store_join( void * store );

void *
fd_store_leave( fd_store_t const * store );

void *
fd_store_delete( void * store );

int
fd_store_slot_prepare( fd_store_t *   store,
                       ulong          slot,
                       ulong *        repair_slot_out,
                       uchar const ** block_out,
                       ulong *        block_sz_out );

int
fd_store_shred_insert( fd_store_t * store,
                       fd_shred_t const * shred );

void
fd_store_add_pending( fd_store_t * store,
                      ulong slot,
                      ulong delay );

ulong
fd_store_slot_repair( fd_store_t * store,
                      ulong slot,
                      fd_repair_request_t * out_repair_reqs,
                      ulong out_repair_reqs_sz );

FD_PROTOTYPES_END

#endif
