#ifndef HEADER_fd_src_choreo_eqvoc_fd_eqvoc_h
#define HEADER_fd_src_choreo_eqvoc_fd_eqvoc_h

#include "../../ballet/shred/fd_shred.h"
#include "../fd_choreo_base.h"

/* FD_EQVOC_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_EQVOC_USE_HANDHOLDING
#define FD_EQVOC_USE_HANDHOLDING 1
#endif

#define FD_EQVOC_MAX     ( 1UL << 10 )
#define FD_EQVOC_FEC_MAX ( 67UL )

struct fd_eqvoc_key {
  ulong slot;
  uint  fec_set_idx;
};
typedef struct fd_eqvoc_key fd_eqvoc_key_t;

/* clang-format off */
static const fd_eqvoc_key_t     fd_eqvoc_key_null = { 0 };
#define FD_EQVOC_KEY_NULL       fd_eqvoc_key_null
#define FD_EQVOC_KEY_INVAL(key) (!((key).slot) & !((key).fec_set_idx))
#define FD_EQVOC_KEY_EQ(k0,k1)  (!(((k0).slot) ^ ((k1).slot))) & !(((k0).fec_set_idx) ^ (((k1).fec_set_idx)))
#define FD_EQVOC_KEY_HASH(key)  ((uint)(((key).slot)<<15UL) | (((key).fec_set_idx)))
/* clang-format on */

struct fd_eqvoc_entry {
  fd_eqvoc_key_t   key;
  ulong            next;
  fd_ed25519_sig_t sig;
  ulong            code_cnt;
  ulong            data_cnt;
};
typedef struct fd_eqvoc_entry fd_eqvoc_entry_t;

#define POOL_NAME fd_eqvoc_pool
#define POOL_T    fd_eqvoc_entry_t
#include "../../util/tmpl/fd_pool.c"

/* clang-format off */
#define MAP_NAME               fd_eqvoc_map
#define MAP_ELE_T              fd_eqvoc_entry_t
#define MAP_KEY_T              fd_eqvoc_key_t
#define MAP_KEY_EQ(k0,k1)      (FD_EQVOC_KEY_EQ(*k0,*k1))
#define MAP_KEY_HASH(key,seed) (FD_EQVOC_KEY_HASH(*key)^seed)
#include "../../util/tmpl/fd_map_chain.c"

struct fd_eqvoc {
  fd_eqvoc_map_t *   map;
  fd_eqvoc_entry_t * pool;
};
typedef struct fd_eqvoc fd_eqvoc_t;

/* fd_eqvoc_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as eqvoc with up to
   node_max nodes and vote_max votes. */

FD_FN_CONST static inline ulong
fd_eqvoc_align( void ) {
  return alignof(fd_eqvoc_t);
}

FD_FN_CONST static inline ulong
fd_eqvoc_footprint( ulong key_max ) {
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof( fd_eqvoc_t ), sizeof( fd_eqvoc_t ) ),
      fd_eqvoc_pool_align(), fd_eqvoc_pool_footprint( key_max ) ),
      fd_eqvoc_map_align(), fd_eqvoc_map_footprint( FD_EQVOC_MAX ) ),
   fd_eqvoc_align() );
}
/* clang-format on */

/* fd_eqvoc_new formats an unused memory region for use as a eqvoc.
   mem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment. */

void *
fd_eqvoc_new( void * shmem, ulong key_max, ulong seed );

/* fd_eqvoc_join joins the caller to the eqvoc.  eqvoc points to the
   first byte of the memory region backing the eqvoc in the caller's
   address space.

   Returns a pointer in the local address space to eqvoc on success. */

fd_eqvoc_t *
fd_eqvoc_join( void * sheqvoc );

/* fd_eqvoc_leave leaves a current local join.  Returns a pointer to the
   underlying shared memory region on success and NULL on failure (logs
   details).  Reasons for failure include eqvoc is NULL. */

void *
fd_eqvoc_leave( fd_eqvoc_t const * eqvoc );

/* fd_eqvoc_delete unformats a memory region used as a eqvoc.
   Assumes only the nobody is joined to the region.  Returns a
   pointer to the underlying shared memory region or NULL if used
   obviously in error (e.g. eqvoc is obviously not a eqvoc ... logs
   details).  The ownership of the memory region is transferred to the
   caller. */

void *
fd_eqvoc_delete( void * sheqvoc );

/* fd_eqvoc_insert inserts shred's signature into eqvoc keyed by (slot,
   fec_set_idx).  Every FEC set must have the same signature for every
   shred in the set, so a different signature would indicate
   equivocation. */

void
fd_eqvoc_insert( fd_eqvoc_t * eqvoc, fd_shred_t const * shred );

/* fd_eqvoc_test tests for equivocation given a new shred.  Equivocation
   is when there are two or more shreds for the same (slot, idx) pair.

   A FEC set overlaps with another one if they both contain a data shred
   at idx.  For example, say we have a FEC set containing data shred the
   idxs in the interval [13, 15] and another set containing idxs [15,
   20].  The first FEC set has fec_set_idx 13 and data_cnt 3.  The
   second FEC set has fec_set_idx 15 and data_cnt
   6.  The overlapping data shred idx is 15.

   We can detect this arithmetically by adding the data_cnt to the
   fec_set_idx that starts earlier.  If the result is greater than
   fec_set_idx that starts later, we know at least one data shred idx
   must overlap.  In this example, 13 + 3 > 15, which indicates
   equivocation.

   We can check for this overlap both backwards and forwards.  We know
   the max number of data shred idxs in a valid FEC set is 67.  So we
   need to look back at most 67 FEC set idxs to find the previous FEC
   set.  Similarly, we look forward at most data_cnt idxs to find the
   next FEC set.
 */

int
fd_eqvoc_test( fd_eqvoc_t const * eqvoc, fd_shred_t const * shred );

#endif /* HEADER_fd_src_choreo_eqvoc_fd_eqvoc_h */
