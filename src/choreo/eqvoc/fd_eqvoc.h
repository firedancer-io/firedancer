#ifndef HEADER_fd_src_choreo_eqvoc_fd_eqvoc_h
#define HEADER_fd_src_choreo_eqvoc_fd_eqvoc_h

#include "../../ballet/shred/fd_shred.h"
#include "../../flamenco/leaders/fd_leaders.h"
#include "../../flamenco/gossip/fd_gossip_types.h"
#include "../fd_choreo_base.h"

/* fd_eqvoc presents an API for detecting and sending / receiving proofs
   of equivocation.

   APIs prefixed with `fd_eqvoc_proof` relate to constructing and
   verifying equivocation proofs from shreds.

   APIs prefixed with `fd_eqvoc_fec` relate to shred and FEC set
   metadata indexing to detect equivocating shreds.

   Equivocation is when a shred producer produces two or more versions
   of a shred for the same (slot, idx).  An equivocation proof comprises
   two shreds that conflict in a way that imply the shreds' producer
   equivocated.

   The proof can be both direct and indirect (implied).  A direct proof,
   for example, contains two shreds with the same shred index but
   different data payloads.  An indirect proof contains two shreds with
   different shred indices, and the metadata on the shreds implies there
   must be two or more versions of a block for that slot.  See
   `fd_eqvoc_proof_verify` for more details.

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

#define FD_EQVOC_FEC_MAX ( 67UL )

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

/* This is the standard MTU

   IPv6 MTU - IP / UDP headers = 1232
   DuplicateShredMaxPayloadSize = 1232 - 115
   DuplicateShred headers = 63

   https://github.com/anza-xyz/agave/blob/v2.0.3/gossip/src/cluster_info.rs#L113 */

#define FD_EQVOC_PROOF_CHUNK_SZ  (1232UL - 115UL - 63UL)
#define FD_EQVOC_PROOF_CHUNK_CNT (( FD_EQVOC_PROOF_SZ / FD_EQVOC_PROOF_CHUNK_SZ ) + 1) /* 3 */
#define FD_EQVOC_PROOF_SZ (2*FD_SHRED_MAX_SZ + 2*sizeof(ulong)) /* 2 shreds prefixed with sz, encoded in 3 chunks */

FD_STATIC_ASSERT( FD_EQVOC_PROOF_CHUNK_SZ==FD_GOSSIP_DUPLICATE_SHRED_MAX_CHUNKS, "Update duplicate shred max chunks size" );

/* The chunk_cnt is encoded in a UCHAR_MAX, so you can have at most
   UCHAR_MAX chunks */

#define FD_EQVOC_PROOF_CHUNK_MIN ( ( FD_EQVOC_PROOF_SZ / UCHAR_MAX ) + 1 ) /* 20 */

#define FD_EQVOC_PROOF_VERIFY_FAILURE           (0)
#define FD_EQVOC_PROOF_VERIFY_SUCCESS_SIGNATURE (1)
#define FD_EQVOC_PROOF_VERIFY_SUCCESS_META      (2)
#define FD_EQVOC_PROOF_VERIFY_SUCCESS_LAST      (3)
#define FD_EQVOC_PROOF_VERIFY_SUCCESS_OVERLAP   (4)
#define FD_EQVOC_PROOF_VERIFY_SUCCESS_CHAINED   (5)

#define FD_EQVOC_PROOF_VERIFY_ERR_SLOT      (-1) /* different slot */
#define FD_EQVOC_PROOF_VERIFY_ERR_VERSION   (-2) /* different shred version */
#define FD_EQVOC_PROOF_VERIFY_ERR_TYPE      (-3) /* wrong shred type (must be chained {resigned} merkle) */
#define FD_EQVOC_PROOF_VERIFY_ERR_MERKLE    (-4) /* merkle root failed */
#define FD_EQVOC_PROOF_VERIFY_ERR_SIGNATURE (-5) /* sig verify of shred producer failed */

#define SET_NAME fd_eqvoc_proof_set
#define SET_MAX  256
#include "../../util/tmpl/fd_set.c"

struct fd_eqvoc_proof {
  fd_slot_pubkey_t     key;
  ulong                prev; /* reserved for data structure use */
  ulong                next; /* reserved for data structure use*/

  fd_pubkey_t         producer;   /* producer of shreds' pubkey */
  void *              bmtree_mem; /* scratch space for reconstructing
                                     the merkle root */
  long                wallclock;  /* `wallclock` (nanos) */
  ulong               chunk_cnt;  /* `num_chunks` */
  ulong               chunk_sz;   /* `chunk_len` */

  /* static declaration of an fd_set that occupies 4 words ie. 256 bits
     that tracks which proof chunks have been received. */

  fd_eqvoc_proof_set_t set[ fd_eqvoc_proof_set_word_cnt ];

  /* DuplicateShred messages are serialized in the following format:

     ---------
     shred1_sz
     ---------
     shred1
     ---------
     shred2_sz
     ---------
     shred2
     ---------

     Each shred is prepended with its size in bytes, before being
     chunked.
  */

   uchar shreds[2 * FD_SHRED_MAX_SZ + 2 * sizeof(ulong)];
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

struct fd_eqvoc {

  /* primitives */

  fd_pubkey_t me; /* our pubkey */
  ulong fec_max;
  ulong proof_max;
  ulong shred_version; /* shred version we expect in all shreds in eqvoc-related msgs. */

  /* owned */

  fd_eqvoc_fec_t *       fec_pool;
  fd_eqvoc_fec_map_t *   fec_map;
  // fd_eqvoc_fec_dlist_t * fec_dlist;
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
fd_eqvoc_footprint( ulong fec_max, ulong proof_max ) {
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
      fd_eqvoc_fec_pool_align(),   fd_eqvoc_fec_pool_footprint( fec_max ) ),
      fd_eqvoc_fec_map_align(),    fd_eqvoc_fec_map_footprint( fec_max ) ),
      fd_eqvoc_proof_pool_align(), fd_eqvoc_proof_pool_footprint( proof_max ) ),
      fd_eqvoc_proof_map_align(),  fd_eqvoc_proof_map_footprint( proof_max ) ),
      fd_sha512_align(),           fd_sha512_footprint() ),
      fd_bmtree_commit_align(),    fd_bmtree_commit_footprint( FD_SHRED_MERKLE_LAYER_CNT ) ),
   fd_eqvoc_align() );
}
/* clang-format on */

/* fd_eqvoc_new formats an unused memory region for use as a eqvoc.
   mem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment. */

void *
fd_eqvoc_new( void * shmem, ulong fec_max, ulong proof_max, ulong seed );

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

/* fd_eqvoc_init initializes eqvoc with the expected shred version. */

void
fd_eqvoc_init( fd_eqvoc_t * eqvoc, ulong shred_version );

/* fd_eqvoc_fec_query queries for FEC set metadata on (slot,
   fec_set_idx).  At least one coding shred most be inserted to populate
   code_cnt, data_cnt, and the last data shred in the slot to populate
   last_idx.  Otherwise fields are defaulted to 0, 0, FD_SHRED_IDX_NULL
   respectively.  Callers should check whether fields are the default
   values before using them. */

FD_FN_PURE static inline fd_eqvoc_fec_t const *
fd_eqvoc_fec_query( fd_eqvoc_t const * eqvoc, ulong slot, uint fec_set_idx ) {
  fd_slot_fec_t key = { slot, fec_set_idx };
  return fd_eqvoc_fec_map_ele_query_const( eqvoc->fec_map, &key, NULL, eqvoc->fec_pool );
}

/* fd_eqvoc_fec_insert inserts a new FEC entry into eqvoc, indexed by
   (slot, fec_set_idx). */

fd_eqvoc_fec_t *
fd_eqvoc_fec_insert( fd_eqvoc_t * eqvoc, ulong slot, uint fec_set_idx );

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

/* fd_eqvoc_proof_query queries for the proof at (slot, from). */

FD_FN_PURE static inline fd_eqvoc_proof_t *
fd_eqvoc_proof_query( fd_eqvoc_t * eqvoc, ulong slot, fd_pubkey_t const * from ) {
  fd_slot_pubkey_t key = { slot, *from };
  return fd_eqvoc_proof_map_ele_query( eqvoc->proof_map, &key, NULL, eqvoc->proof_pool );
}

/* fd_eqvoc_proof_query_const is the const version of the above. */

FD_FN_PURE static inline fd_eqvoc_proof_t const *
fd_eqvoc_proof_query_const( fd_eqvoc_t const * eqvoc, ulong slot, fd_pubkey_t const * from ) {
  fd_slot_pubkey_t key = { slot, *from };
  return fd_eqvoc_proof_map_ele_query_const( eqvoc->proof_map, &key, NULL, eqvoc->proof_pool );
}

/* fd_eqvoc_proof_insert inserts a proof entry into eqvoc, keyed by
   (slot, from) where from is the pubkey that generated the proof. */

fd_eqvoc_proof_t *
fd_eqvoc_proof_insert( fd_eqvoc_t * eqvoc, ulong slot, fd_pubkey_t const * from );

void
fd_eqvoc_proof_init( fd_eqvoc_proof_t * proof, fd_pubkey_t const * producer, long wallclock, ulong chunk_cnt, ulong chunk_sz, void * bmtree_mem );

/* fd_eqvoc_proof_chunk_insert inserts a proof chunk into the proof.
   Proofs are divided into chunks before they are transmitted via
   gossip, so this function is necessary for reconstruction. */

void
fd_eqvoc_proof_chunk_insert( fd_eqvoc_proof_t * proof, fd_gossip_duplicate_shred_t const * chunk );

/* fd_eqvoc_shreds_chunk_insert is a lower-level API for the above. */

void
fd_eqvoc_shreds_chunk_insert( fd_shred_t * shred1, fd_shred_t * shred2, fd_gossip_duplicate_shred_t const * chunk );

/* fd_eqvoc_proof_remove removes the proof entry associated with key. */

void
fd_eqvoc_proof_remove( fd_eqvoc_t * eqvoc, fd_slot_pubkey_t const * key );

/* fd_eqvoc_proof_complete checks whether the proof has received all
   chunks ie. is complete.  Returns 1 if so, 0 otherwise. */

static inline int
fd_eqvoc_proof_complete( fd_eqvoc_proof_t const * proof ) {
  for( uchar i = 0; i < proof->chunk_cnt; i++ ) {
    if( !fd_eqvoc_proof_set_test( proof->set, i ) ) return 0;
  }
  return 1;
}

/* fd_eqvoc_proof_verify verifies that the two shreds contained in
   `proof` do in fact equivocate.

   Returns: FD_EQVOC_VERIFY_FAILURE if they do not
     FD_EQVOC_VERIFY_SUCCESS_{REASON} if they do
     FD_EQVOC_VERIFY_ERR_{REASON} if the shreds were not valid inputs

   Two shreds equivocate if they satisfy any of the following:

   1. They are in the same FEC set but have different signatures.
   2. They are in the same FEC set and are both coding shreds, but have
      different coding metadata ie. code_cnt, data_cnt, first_code_idx.
   3. They are in the same FEC set and are both data shreds.  One shred
      is marked as the last data shred in the slot
      (FD_SHRED_DATA_FLAG_SLOT_COMPLETE), but the other shred has a
      higher data shred index.
   4. They are in different FEC sets and the shred with a lower FEC set
      index is a coding shred, whereas the shred with the higher FEC set
      index is either a coding or data shred.  The lower coding shred's
      `data_cnt` implies the lower FEC set intersects with the higher
      FEC set ie. the FEC sets are overlapping.
   5. They are in different FEC sets and the shred with a lower FEC set
      index is a coding shred, and the FEC sets are adjacent ie. the
      last data shred index in the lower FEC set is one less than the
      first data shred index in the higher FEC set.  The merkle root of
      the lower FEC set is different from the chained merkle root of the
      higher FEC set.

   Note: two shreds are in the same FEC set if they have the same slot
   and same FEC set index.

   To prevent false positives, this function also performs the following
   input validation on the shreds:

   1. shred1 and shred2 are both the expected shred_version.
   2. shred1 and shred2 are for the same slot.
   3. shred1 and shred2 are either chained merkle or chained resigned
      merkle variants.
   4. shred1 and shred2 contain valid signatures signed by the same
      producer pubkey.

   If any of the above input validation fail, this function returns
   FD_EQVOC_VERIFY_ERR_{REASON} for the appropriate reason. */

int
fd_eqvoc_proof_verify( fd_eqvoc_proof_t const * proof );

/* fd_eqvoc_proof_shreds_verify is a lower-level API for
   fd_eqvoc_proof_verify.  Refer above for documentation.  */

int
fd_eqvoc_shreds_verify( fd_shred_t const * shred1, fd_shred_t const * shred2, fd_pubkey_t const * producer, void * bmtree_mem );

/* fd_eqvoc_proof_shred1 returns a pointer to shred1 in `proof`. */

static inline fd_shred_t *
fd_eqvoc_proof_shred1( fd_eqvoc_proof_t * proof ) {
  return (fd_shred_t *)fd_type_pun_const( proof->shreds + sizeof(ulong) );
}

/* fd_eqvoc_proof_shred1_const returns a const pointer to shred1 in
   `proof`. */

static inline fd_shred_t const *
fd_eqvoc_proof_shred1_const( fd_eqvoc_proof_t const * proof ) {
  return (fd_shred_t const *)fd_type_pun_const( proof->shreds + sizeof(ulong) );
}

/* fd_eqvoc_proof_shred2 returns a pointer to shred2 in `proof`. */

static inline fd_shred_t *
fd_eqvoc_proof_shred2( fd_eqvoc_proof_t * proof ) {
  ulong shred1_sz = *(ulong *)fd_type_pun( proof->shreds );
  return (fd_shred_t *)fd_type_pun( proof->shreds + shred1_sz + 2*sizeof(ulong) );
}

/* fd_eqvoc_proof_shred2_const returns a const pointer to shred2 in `proof`. */

static inline fd_shred_t const *
fd_eqvoc_proof_shred2_const( fd_eqvoc_proof_t const * proof ) {
  ulong shred1_sz = *(ulong const *)fd_type_pun_const( proof->shreds );
  return (fd_shred_t const *)fd_type_pun_const( proof->shreds + shred1_sz + 2*sizeof(ulong) );
}

/* fd_eqvoc_verify verifies `slot` has FEC sets with merkle roots that
   correctly chain, including that the first FEC set in slot's merkle
   hash chains from the last FEC set in parent slot's merkle hash. */

int
fd_eqvoc_slot_verify( fd_eqvoc_t const * eqvoc, ulong slot );

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
   FD_EQVOC_PROOF_SZ.

   This function is expected to be deprecated once chunks are specified
   to be fixed-length in the gossip protocol. */

void
fd_eqvoc_proof_from_chunks( fd_gossip_duplicate_shred_t const * chunks,
                            fd_eqvoc_proof_t * proof_out );

/* fd_eqvoc_to_chunks constructs an array of DuplicateShred gossip msgs
   (`chunks_out`) from shred1 and shred2.

   Shred1 and shred2 are concatenated (the concatenation is implemented
   virtually) and then spliced into chunks of FD_EQVOC_PROOF_CHUNK_SZ
   size. These chunks are embedded in the body of each DuplicateShred
   msg, along with a common header across all msgs.

   Caller supplies `chunks_out`, which is an array that MUST contain
   `ceil(shred1_payload_sz + shred2_payload_sz /
   FD_EQVOC_PROOF_CHUNK_SZ)` elements.  Each chunk in `chunks_out` MUST
   have a buffer of at least `chunk_len` size available in its `chunk`
   pointer field.  Behavior is undefined otherwise.

   IMPORTANT SAFETY TIP!  The lifetime of each chunk in `chunks_out`
   must be at least as long as the lifetime of the array of
   duplicate_shreds.  Caller is responsible for ensuring this memory
   safety guarantee. */

void
fd_eqvoc_proof_to_chunks( fd_eqvoc_proof_t * proof, fd_gossip_duplicate_shred_t * chunks_out );

#endif /* HEADER_fd_src_choreo_eqvoc_fd_eqvoc_h */
