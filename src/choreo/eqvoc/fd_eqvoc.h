#ifndef HEADER_fd_src_choreo_eqvoc_fd_eqvoc_h
#define HEADER_fd_src_choreo_eqvoc_fd_eqvoc_h

#include "../../ballet/shred/fd_shred.h"
#include "../../flamenco/leaders/fd_leaders.h"
#include "../fd_choreo_base.h"

/* fd_eqvoc presents an API for detecting and sending / receiving
   "proofs" of equivocation.

   Equivocation is when the shred producer produces two or more versions
   of a shred for the same (slot, idx). An equivocation proof comprises
   a sample of two shreds that conflict in a way that imply the shreds'
   producer equivocated.

   The proof can be both direct and indirect (implied). A direct proof
   is simpler: the proof is generated when you observe two versions of
   the same shred, ie. two shreds that have the same slot and shred_idx
   but a different data payload. Indirect

   The following lists the equivocation cases:

   1. Two shreds with the same slot and idx but different data payloads.
   2. Two shreds in the same FEC set have different merkle roots.
   3. Two shreds in the same FEC set with different metadata ie.
      code_cnt, data_cnt, last_idx.
   4. Two shreds in the same FEC set that are both data shreds, where
      one is marked as the last data shred in the slot, but the other
      shred has a higher data shred index than that.
   3. Two shreds in different FEC sets and the FEC sets are overlapping
      ie. the same shred idx appears in both FEC sets.

   Every FEC set must have the same signature for every shred in the
   set, so a different signature would indicate equivocation.  Note in
   the case of merkle shreds, the shred signature is signed on the FEC
   set's merkle root, so every shred in the same FEC set must have the
   same signature. */

/* FD_EQVOC_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_EQVOC_USE_HANDHOLDING
#define FD_EQVOC_USE_HANDHOLDING 1
#endif

#define FD_EQVOC_MAX     ( 1UL << 10 )
#define FD_EQVOC_FEC_MAX ( 67UL )

/* This is the standard IPv6 MTU - IP / UDP headers - DuplicateShred application headers
   https://github.com/anza-xyz/agave/blob/v2.0.3/gossip/src/cluster_info.rs#L113 */
#define FD_EQVOC_CHUNK_MAX ( 1232UL - 115UL )

/* The chunk_cnt is encoded in a UCHAR_MAX, so you can have at most UCHAR_MAX chunkskj */
#define FD_EQVOC_CHUNK_MIN ( FD_SHRED_MAX_SZ * 2 / UCHAR_MAX + 1 )

struct fd_eqvoc_chunk {
  fd_slot_pubkey_t            key;
  ulong                       next;
  fd_gossip_duplicate_shred_t duplicate_shred;
};
typedef struct fd_eqvoc_chunk fd_eqvoc_chunk_t;

#define POOL_NAME fd_eqvoc_chunk_pool
#define POOL_T    fd_eqvoc_chunk_t
#include "../../util/tmpl/fd_pool.c"

/* clang-format off */
#define MAP_NAME               fd_eqvoc_chunk_map
#define MAP_ELE_T              fd_eqvoc_chunk_t
#define MAP_KEY_T              fd_slot_pubkey_t
#define MAP_KEY_EQ(k0,k1)      (FD_SLOT_PUBKEY_EQ(k0,k1))
#define MAP_KEY_HASH(key,seed) (FD_SLOT_PUBKEY_HASH(key,seed))
#include "../../util/tmpl/fd_map_chain.c"


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
  ulong            code_cnt;
  ulong            data_cnt;
  uint             last_idx;
  fd_ed25519_sig_t sig;
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
/* clang-format on */

typedef int (*fd_eqvoc_sig_verify_fn)( void * arg, fd_shred_t * shred ); 

struct fd_eqvoc {

  /* primitives */

  ulong min_slot;      /* min slot we're currently indexing. */
  ulong key_max;       /* max # of FEC sets we can index. */
  ulong shred_version; /* shred version we expect in all shreds in eqvoc-related msgs. */

  /* owned */

  fd_eqvoc_map_t *   map;
  fd_eqvoc_entry_t * pool;
  fd_sha512_t *      sha512;
  void *             bmtree_mem;

  /* borrowed  */
  fd_epoch_leaders_t const * leaders;

  fd_eqvoc_sig_verify_fn sig_verify_fn; 
};
typedef struct fd_eqvoc fd_eqvoc_t;

/* clang-format off */

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
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_eqvoc_t),      sizeof(fd_eqvoc_t) ),
      fd_eqvoc_pool_align(),    fd_eqvoc_pool_footprint( key_max ) ),
      fd_eqvoc_map_align(),     fd_eqvoc_map_footprint( FD_EQVOC_MAX ) ),
      fd_sha512_align(),        fd_sha512_footprint() ),
      fd_bmtree_commit_align(), fd_bmtree_commit_footprint( FD_SHRED_MERKLE_LAYER_CNT ) ),
      fd_eqvoc_map_align(),     fd_eqvoc_map_footprint( FD_EQVOC_MAX ) ),
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

/* fd_eqvoc_insert inserts `shred` into eqvoc, indexing it by (slot,
   fec_set_idx).  If `shred` is a coding shred, it populates entry's
   metadata fields. */

void
fd_eqvoc_insert( fd_eqvoc_t * eqvoc, fd_shred_t const * shred );

/* fd_eqvoc_query queries for FEC set metadata on (slot, fec_set_idx).
   At least one coding shred most be inserted to populate code_cnt,
   data_cnt, and the last data shred in the slot to populate last_idx.
   Otherwise fields are defaulted to 0, 0, FD_SHRED_IDX_NULL
   respectively.  Callers should check whether fields are the default
   values before using them. */

FD_FN_CONST static inline fd_eqvoc_entry_t const *
fd_eqvoc_query( fd_eqvoc_t const * eqvoc, ulong slot, uint fec_set_idx ) {
  fd_eqvoc_key_t key = { slot, fec_set_idx };
  return fd_eqvoc_map_ele_query_const( eqvoc->map, &key, NULL, eqvoc->pool );
}

/* fd_eqvoc_search searches for whether `shred` implies equivocation by
   checking for a conflict in the currently indexed FEC sets. Returns
   the conflicting entry if there is one, NULL otherwise.

   A FEC set "overlaps" with another if they both contain a data shred
   at the samed idx.  For example, say we have a FEC set containing data
   shreds in the idx interval [13, 15] and another containing idxs [15,
   20].  The first FEC set has fec_set_idx 13 and data_cnt 3. The second
   FEC set has fec_set_idx 15 and data_cnt 6.  They overlap because they
   both contain a data shred at idx 15.  Therefore, these two FEC sets
   imply equivocation.

   This overlap can be detected arithmetically by adding the data_cnt to
   the fec_set_idx that starts earlier.  If the result is greater than
   the fec_set_idx that starts later, we know at least one data shred
   idx must overlap.  In this example, 13 + 3 > 15, which indicates
   equivocation.

   We can check for this overlap both backwards and forwards.  We know
   the max number of data shred idxs in a valid FEC set is 67.  So we
   need to look back at most 67 FEC set idxs to find the previous FEC
   set.  Similarly, we look forward at most data_cnt idxs to find the
   next FEC set. */

fd_eqvoc_entry_t const *
fd_eqvoc_search( fd_eqvoc_t const * eqvoc, fd_shred_t const * shred );

/* fd_eqvoc_test tests whether shred1 and shred2 present a valid
   equivocation proof.  See the header at the top of the file for an
   explanation and enumeration of the equivocation cases.

   To prevent false positives, this function checks equivocation proofs
   contain the following:

   1. shred1 and shred2 are for the same slot
   2. shred1 and shred2 are the expected shred_version
   3. shred1 and shred2 contain valid signatures by the current leader
   4. shred1 and shred2 are the same shred type
 */

int
fd_eqvoc_test( fd_eqvoc_t const * eqvoc, fd_shred_t * shred1, fd_shred_t * shred2 );

/* fd_eqvoc_from_chunks reconstructs shred1_out and shred2_out from
   `chunks` which is an array of "duplicate shred" gossip msgs. Shred1
   and shred2 comprise a "duplicate shred proof", ie. proof of two
   shreds that conflict and therefore demonstrate the shreds' producer
   has equivocated.

   Assumes `chunks` is non-NULL and contains at least one valid array
   member chunks[0] to extract header information.  Caller's
   responsibility to guarantee this.  Also assumes the `chunk` field in
   `fd_gossip_duplicate_shred_t` is a pointer to valid memory and
   consistent with the metadata presented in the header of the first
   array member, eg. if the header says there are 4 chunks then this
   implementation assumes this is true.  These assumptions should be
   already upheld by caller if using deserializers in `fd_types.h`.
   Behavior is undefined otherwise.

   Does additional sanity-check validation eg. checking chunk_len <=
   FD_EQVOC_CHUNK_MAX. */

void
fd_eqvoc_from_chunks( fd_eqvoc_t const *            eqvoc,
                      fd_gossip_duplicate_shred_t * chunks,
                      fd_shred_t *                  shred1_out,
                      fd_shred_t *                  shred2_out );

/* fd_eqvoc_to_chunks constructs an array of DuplicateShred gossip msgs
   (`chunks_out`) from shred1 and shred2.

   Shred1 and shred2 are concatenated (this concatenation is virtual in
   the implementation) and then spliced into chunks of `chunk_len` size.
   These chunks are embedded in the body of each DuplicateShred msg,
   along with a common header across all msgs.

   Caller supplies `chunks_out`, which is an array that MUST contain
   `ceil(shred1_payload_sz + shred2_payload_sz / chunk_len)` elements.
   Each chunk in `chunks_out` MUST have a buffer of at least `chunk_len`
   size available in its `chunk` pointer field.  Behavior is undefined
   otherwise.

   IMPORTANT SAFETY TIP!  The lifetime of each chunk in `chunks_out`
   must be at least as long as the lifetime of the array of
   duplicate_shreds.  Caller is responsible for ensuring this memory
   safety guarantee. */

void
fd_eqvoc_to_chunks( fd_eqvoc_t const *            eqvoc,
                    fd_shred_t const *            shred1,
                    fd_shred_t const *            shred2,
                    ulong                         chunk_len,
                    fd_gossip_duplicate_shred_t * chunks_out );

#endif /* HEADER_fd_src_choreo_eqvoc_fd_eqvoc_h */
