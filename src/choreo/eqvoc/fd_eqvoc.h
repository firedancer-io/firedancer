#ifndef HEADER_fd_src_choreo_eqvoc_fd_eqvoc_h
#define HEADER_fd_src_choreo_eqvoc_fd_eqvoc_h

#include "../../ballet/shred/fd_shred.h"
#include "../../flamenco/leaders/fd_leaders.h"
#include "../fd_choreo_base.h"
#include "../../flamenco/runtime/fd_blockstore.h"

/* fd_eqvoc presents an API for detecting and sending / receiving
   "proofs" of equivocation.

   Equivocation is when the shred producer produces two or more versions
   of a shred for the same (slot, idx).  An equivocation proof comprises
   a sample of two shreds that conflict in a way that imply the shreds'
   producer equivocated.

   The proof can be both direct and indirect (implied).  A direct proof
   contains two shreds with the same slot and shred_idx but different
   data payloads.  An indirect proof contains two shreds with the same
   slot but different shred_idxs, and the metadata on the shreds implies
   there must be two or more versions of a block for that slot.  See
   fd_eqvoc_test for a detailed list of equivocation cases.


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

#define FD_EQVOC_TEST_FALSE       0
#define FD_EQVOC_TEST_PAYLOAD     1
#define FD_EQVOC_TEST_MERKLE_ROOT 2
#define FD_EQVOC_TEST_CODE_META   3
#define FD_EQVOC_TEST_LAST_IDX    4
#define FD_EQVOC_TEST_OVERLAP     5
#define FD_EQVOC_TEST_CHAINED     6

struct fd_eqvoc_proof {
  fd_slot_pubkey_t key;
  ulong            next;
  uchar            bit_vec;

  union {
    struct __attribute__((packed)) {
      uchar chunks[FD_EQVOC_CHUNK_MAX][3];
    };
    struct __attribute__((packed)) {
      fd_shred_t shred1;
      fd_shred_t shred2;
    };
  };
};
typedef struct fd_eqvoc_proof fd_eqvoc_proof_t;

#define POOL_NAME fd_eqvoc_proof_pool
#define POOL_T    fd_eqvoc_proof_t
#include "../../util/tmpl/fd_pool.c"

/* clang-format off */
#define MAP_NAME               fd_eqvoc_proof_map
#define MAP_ELE_T              fd_eqvoc_proof_t
#define MAP_KEY_T              fd_slot_pubkey_t
#define MAP_KEY_EQ(k0,k1)      (FD_SLOT_PUBKEY_EQ(k0,k1))
#define MAP_KEY_HASH(key,seed) (FD_SLOT_PUBKEY_HASH(key,seed))
#include "../../util/tmpl/fd_map_chain.c"
/* clang-format on */

struct fd_slot_fec {
  ulong slot;
  uint  fec_set_idx;
};
typedef struct fd_slot_fec fd_slot_fec_t;

/* clang-format off */
static const fd_slot_fec_t     fd_slot_fec_null = { 0 };
#define FD_SLOT_FEC_NULL       fd_slot_fec_null
#define FD_SLOT_FEC_INVAL(key) (!((key).slot) & !((key).fec_set_idx))
#define FD_SLOT_FEC_EQ(k0,k1)  (!(((k0).slot) ^ ((k1).slot))) & !(((k0).fec_set_idx) ^ (((k1).fec_set_idx)))
#define FD_SLOT_FEC_HASH(key)  ((uint)(((key).slot)<<15UL) | (((key).fec_set_idx)))
/* clang-format on */

struct fd_eqvoc_fec {
  fd_slot_fec_t    key;
  ulong            next;
  ulong            code_cnt;
  ulong            data_cnt;
  uint             last_idx;
  fd_ed25519_sig_t sig;
};
typedef struct fd_eqvoc_fec fd_eqvoc_fec_t;

#define POOL_NAME fd_eqvoc_fec_pool
#define POOL_T    fd_eqvoc_fec_t
#include "../../util/tmpl/fd_pool.c"

/* clang-format off */
#define MAP_NAME               fd_eqvoc_fec_map
#define MAP_ELE_T              fd_eqvoc_fec_t
#define MAP_KEY_T              fd_slot_fec_t
#define MAP_KEY_EQ(k0,k1)      (FD_SLOT_FEC_EQ(*k0,*k1))
#define MAP_KEY_HASH(key,seed) (FD_SLOT_FEC_HASH(*key)^seed)
#include "../../util/tmpl/fd_map_chain.c"
/* clang-format on */

struct fd_eqvoc {

  /* primitives */

  ulong fec_min;       /* min slot we're currently tracking fec meta for (will be evicted first). */
  ulong key_max;       /* max # of FEC sets we can index. */
  ulong shred_version; /* shred version we expect in all shreds in eqvoc-related msgs. */

  /* owned */

  fd_eqvoc_fec_t *       fec_pool;
  fd_eqvoc_fec_map_t *   fec_map;
  fd_eqvoc_proof_t *     proof_pool;
  fd_eqvoc_proof_map_t * proof_map;
  fd_sha512_t *          sha512;
  void *                 bmtree_mem;

  /* borrowed  */

  fd_epoch_leaders_t const * leaders;
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
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_eqvoc_t),         sizeof(fd_eqvoc_t) ),
      fd_eqvoc_fec_pool_align(),   fd_eqvoc_fec_pool_footprint( key_max ) ),
      fd_eqvoc_fec_map_align(),    fd_eqvoc_fec_map_footprint( key_max ) ),
      fd_eqvoc_proof_pool_align(), fd_eqvoc_proof_pool_footprint( key_max ) ),
      fd_eqvoc_proof_map_align(),  fd_eqvoc_proof_map_footprint( key_max ) ),
      fd_sha512_align(),           fd_sha512_footprint() ),
      fd_bmtree_commit_align(),    fd_bmtree_commit_footprint( FD_SHRED_MERKLE_LAYER_CNT ) ),
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

/* fd_eqvoc_proof_insert inserts a fd_gossip_duplicate_shred_t `chunk`
   into eqvoc, indexed by (slot, pubkey).  Each chunk is buffered until
   all chunks for the given (slot, pubkey) are received (max 3).   */

fd_eqvoc_proof_t *
fd_eqvoc_proof_insert( fd_eqvoc_t * eqvoc, fd_gossip_duplicate_shred_t const * chunk );

/* fd_eqvoc_fec_insert inserts `shred` into eqvoc, indexed by (slot,
   fec_set_idx). */

void
fd_eqvoc_fec_insert( fd_eqvoc_t * eqvoc, fd_shred_t const * shred );


/* fd_eqvoc_proof_query queries for the proof that two shreds are
   equivocating at (slot, from). */

FD_FN_CONST static inline fd_eqvoc_proof_t const *
fd_eqvoc_proof_query( fd_eqvoc_t const * eqvoc, ulong slot, fd_hash_t from ) {
  fd_slot_pubkey_t key = { slot, from };
  return fd_eqvoc_proof_map_ele_query_const( eqvoc->proof_map, &key, NULL, eqvoc->proof_pool );
}

/* fd_eqvoc_fec_query queries for FEC set metadata on (slot,
   fec_set_idx).  At least one coding shred most be inserted to populate
   code_cnt, data_cnt, and the last data shred in the slot to populate
   last_idx.  Otherwise fields are defaulted to 0, 0, FD_SHRED_IDX_NULL
   respectively.  Callers should check whether fields are the default
   values before using them. */

FD_FN_CONST static inline fd_eqvoc_fec_t const *
fd_eqvoc_fec_query( fd_eqvoc_t const * eqvoc, ulong slot, uint fec_set_idx ) {
  fd_slot_fec_t key = { slot, fec_set_idx };
  return fd_eqvoc_fec_map_ele_query_const( eqvoc->fec_map, &key, NULL, eqvoc->fec_pool );
}

/* fd_eqvoc_fec_search searches for whether `shred` implies equivocation
   by checking for a conflict in the currently indexed FEC sets. Returns
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

fd_eqvoc_fec_t const *
fd_eqvoc_fec_search( fd_eqvoc_t const * eqvoc, fd_shred_t const * shred );

/* fd_eqvoc_test tests whether shred1 and shred2 are equivocating.
   Returns a positive integer they are equivocating, 0 if they are not,
   and -1 if they could not be compared for equivocation.  See
   FD_EQVOC_TEST_* constants defined at top of header for the list of
   return values.

   Two shreds are equivocating if they satisfy any of the following:

   1. Two shreds in the same FEC set but have different merkle roots.
   2. Two coding shreds in the same FEC set but with different coding
      metadata ie. code_cnt, data_cnt, first_code_idx.
   3. Two data shreds in the same FEC set where one is marked as the
      last data shred in the slot (FD_SHRED_DATA_FLAG_SLOT_COMPLETE is
      set), but the other shred has a higher data shred index.
   4. Two shreds in different FEC sets, where the shred with the lower
      FEC set index is a coding shred (the shred with the higher FEC set
      index can be either be a coding or data shred), and the FEC sets
      are overlapping based on the lower coding shred's `data_cnt` ie.
      the same data shred index would appear in both FEC sets.
   5. Two shreds in different FEC sets, where the FEC sets are adjacent
      (ie. the last data shred index in the lower FEC set is one less
      than the first data shred index in the higher FEC set), and the
      merkle root of the lower FEC set is different from the chained
      merkle root of the higher FEC set.

   To prevent false positives, this function also performs the following
   input validation on the shreds:

   1. shred1 and shred2 are both the expected shred_version.
   2. shred1 and shred2 are for the same slot.
   3. shred1 and shred2 contain valid signatures by the assigned leader
      for that slot.
   4. shred1 and shred2 are the same shred type.

   If any of the above input validation fail, this function returns -1
   ie. these two shreds cannot be compared for equivocation.

 */

int
fd_eqvoc_test( fd_eqvoc_t const * eqvoc, fd_shred_t * shred1, fd_shred_t * shred2 );

/* fd_eqvoc_verify verifies `slot` has FEC sets with merkle roots that
   correctly chain, including that the first FEC set in slot's merkle
   hash chains from the last FEC set in parent slot's merkle hash. */

int
fd_eqvoc_slot_verify( fd_eqvoc_t const * eqvoc, fd_blockstore_t * blockstore, ulong slot );

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
   FD_eqvoc_proof_MAX.

   This function is expected to be deprecated once chunks are specified
   to be fixed-length in the gossip protocol. */

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
   safety guarantee.

   This function is expected to be deprecated once chunks are specified
   to be fixed-length in the gossip protocol. */

void
fd_eqvoc_to_chunks( fd_eqvoc_t const *            eqvoc,
                    fd_shred_t const *            shred1,
                    fd_shred_t const *            shred2,
                    ulong                         chunk_len,
                    fd_gossip_duplicate_shred_t * chunks_out );

#endif /* HEADER_fd_src_choreo_eqvoc_fd_eqvoc_h */
