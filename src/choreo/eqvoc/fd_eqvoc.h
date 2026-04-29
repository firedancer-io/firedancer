#ifndef HEADER_fd_src_choreo_eqvoc_fd_eqvoc_h
#define HEADER_fd_src_choreo_eqvoc_fd_eqvoc_h

#include "../fd_choreo_base.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../flamenco/leaders/fd_leaders.h"
#include "../../flamenco/gossip/fd_gossip_message.h"

/* fd_eqvoc presents an API for detecting and sending & receiving proofs
   of equivocation.  Agave calls "equivocation" duplicates, including in
   their type names, so these terms will be used interchangeably for the
   sake of conformity.

   Equivocation is when a leader produces two or more blocks for the
   same slot.  Proving equivocation does not require the complete blocks
   however; in fact, only two shreds are required.  The idea is these
   shreds conflict in a way that implies equivocating blocks for a slot.
   See `verify_proof` in fd_eqvoc.c for details. */

#define FD_EQVOC_SUCCESS (0) /* shreds do not equivocate */

/* proof successfully reassembled from chunked and verified */

#define FD_EQVOC_SUCCESS_MERKLE  (1)
#define FD_EQVOC_SUCCESS_META    (2)
#define FD_EQVOC_SUCCESS_LAST    (3)
#define FD_EQVOC_SUCCESS_OVERLAP (4)
#define FD_EQVOC_SUCCESS_CHAINED (5)

/* proof successfully reassembled from chunked but not verified */

#define FD_EQVOC_ERR_SERDE   (-1) /* invalid serialization */
#define FD_EQVOC_ERR_SLOT    (-2) /* shreds were for different slots */
#define FD_EQVOC_ERR_VERSION (-3) /* either shred had wrong shred version */
#define FD_EQVOC_ERR_TYPE    (-4) /* wrong shred type (must be chained merkle) */
#define FD_EQVOC_ERR_MERKLE  (-5) /* failed to derive merkle root */
#define FD_EQVOC_ERR_SIG     (-6) /* failed to sigverify */

/* chunk was invalid */

#define FD_EQVOC_ERR_CHUNK_CNT (-7) /* num_chunks != FD_EQVOC_CHUNK_CNT */
#define FD_EQVOC_ERR_CHUNK_IDX (-8) /* chunk_index >= FD_EQVOC_CHUNK_CNT */
#define FD_EQVOC_ERR_CHUNK_LEN (-9) /* chunk_len does not match expected length for chunk_index */

/* chunk was ignored */

#define FD_EQVOC_ERR_IGNORED_FROM (-10) /* unrecognized from address */
#define FD_EQVOC_ERR_IGNORED_SLOT (-11) /* slot older than root or unable to derive leader schedule */

/* FD_EQVOC_CHUNK_CNT: the count of chunks is hardcoded because Agave
   discards any chunks where count != 3 (even though technically the
   schema supports it).

   See: https://github.com/anza-xyz/agave/blob/v3.1/gossip/src/duplicate_shred_handler.rs#L21 */

#define FD_EQVOC_CHUNK_CNT (3)

/* FD_EQVOC_CHUNK_SZ: the size of data in each chunk Firedancer produces
   in a DuplicateShred message is derived below.

   IPv6 MTU - IP / UDP headers = 1232
   DuplicateShredMaxPayloadSize = 1232 - 115
   DuplicateShred headers = 63

   See: https://github.com/anza-xyz/agave/blob/v2.0.3/gossip/src/cluster_info.rs#L113 */

#define FD_EQVOC_CHUNK_SZ (1232UL - 115UL - 63UL)
FD_STATIC_ASSERT( FD_EQVOC_CHUNK_SZ<=sizeof(((fd_gossip_duplicate_shred_t*)0)->chunk), "DuplicateShred chunk max mismatch" );

/* FD_EQVOC_CHUNK{0,1,2}_LEN: the chunk lengths for each of the 3 chunks
   in a DuplicateShred proof.  The memory layout is:

   [ shred1_sz (8 bytes) | shred1 | shred2_sz (8 bytes) | shred2 ]

   Chunks 0 and 1 are always FD_EQVOC_CHUNK_SZ bytes.  Chunk 2 gets
   whatever bytes remain, which depends on the shred types:

   CC = code  + code  (both FD_SHRED_MAX_SZ)
   DD = data  + data  (both FD_SHRED_MIN_SZ)
   DC = data  + code  (FD_SHRED_MIN_SZ + FD_SHRED_MAX_SZ)
   CD = same as above, reversed

   Firedancer is particularly strict with the validation of duplicate
   shred chunks.  Even though the schema supports both a variable-length
   and a variable-number of chunks, Agave restricts duplicate shred msgs
   to have 3 chunks (as mentioned above).  Firedancer chooses to further
   restrict chunks to exactly how vanilla Agave implements serialization
   (there is no reason for an honest sender to "mod" the code nor reason
   to even support variable-length in the schema in the first place).

   Firedancer might miss a valid modded duplicate shred proof, but their
   proof would propagate from other validators too (and gossip tx is
   unreliable and not strictly required for the protocol to work).

   Agave validation: https://github.com/anza-xyz/agave/blob/v3.1/gossip/src/duplicate_shred.rs#L262-L268 */

#define FD_EQVOC_CHUNK0_LEN     FD_EQVOC_CHUNK_SZ
#define FD_EQVOC_CHUNK1_LEN     FD_EQVOC_CHUNK_SZ
#define FD_EQVOC_CHUNK2_LEN_CC  (2UL * sizeof(ulong) + 2UL * FD_SHRED_MAX_SZ - 2UL * FD_EQVOC_CHUNK_SZ)
#define FD_EQVOC_CHUNK2_LEN_DD  (2UL * sizeof(ulong) + 2UL * FD_SHRED_MIN_SZ - 2UL * FD_EQVOC_CHUNK_SZ)
#define FD_EQVOC_CHUNK2_LEN_DC  (2UL * sizeof(ulong) + FD_SHRED_MIN_SZ + FD_SHRED_MAX_SZ - 2UL * FD_EQVOC_CHUNK_SZ)
#define FD_EQVOC_CHUNK2_LEN_CD  (FD_EQVOC_CHUNK2_LEN_DC)

typedef struct fd_eqvoc fd_eqvoc_t;

/* fd_eqvoc_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as eqvoc with up to
   shred_max shreds and chunk_max chunks. */

FD_FN_CONST ulong
fd_eqvoc_align( void );

FD_FN_CONST ulong
fd_eqvoc_footprint( ulong dup_max,
                    ulong fec_max,
                    ulong per_vtr_max,
                    ulong vtr_max );

/* fd_eqvoc_new formats an unused memory region for use as a eqvoc.
   mem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment. */

void *
fd_eqvoc_new( void * shmem,
              ulong  dup_max,
              ulong  fec_max,
              ulong  per_vtr_max,
              ulong  vtr_max,
              ulong  seed );

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

/* fd_eqvoc_delete unformats a memory region used as a eqvoc.  Assumes
   nobody is joined to the region.  Returns a pointer to the underlying
   shared memory region or NULL if used obviously in error (e.g. eqvoc
   is obviously not a eqvoc ... logs details).  The ownership of the
   memory region is transferred to the caller. */

void *
fd_eqvoc_delete( void * sheqvoc );

/* fd_eqvoc_shred_insert inserts the shred into eqvoc.  Assumes that
   shreds are already sig-verified.  Returns FD_EQVOC_SUCCESS if no
   equivocation was detected, FD_EQVOC_SUCCESS_{...} (positive) if the
   shred conflicts with a previously inserted shred (chunks_out will be
   populated with a DuplicateShred proof that can be sent over gossip),
   or FD_EQVOC_ERR_IGNORED_SLOT if shred->slot < root. */

int
fd_eqvoc_shred_insert( fd_eqvoc_t *                eqvoc,
                       ushort                      shred_version,
                       ulong                       root,
                       fd_shred_t const *          shred,
                       fd_gossip_duplicate_shred_t chunks_out[static FD_EQVOC_CHUNK_CNT] );

/* fd_eqvoc_chunk_insert inserts a DuplicateShred chunk from gossip into
   eqvoc.  Returns FD_EQVOC_SUCCESS if no proof was completed or
   verified yet, FD_EQVOC_SUCCESS_{...} (positive) if a complete proof
   was assembled and verified (chunks_out will be populated with the
   proof), or FD_EQVOC_ERR_{...} (negative) if the chunk or reassembled
   shreds failed validation.

   Chunks arrive from untrusted gossip peers and are validated (chunk
   count, index, length, shred deserialization, shred version, merkle
   root, signature, etc.).

   Returns FD_EQVOC_ERR_IGNORED_SLOT if leader_schedule is NULL or
   chunk->slot < root.  Returns FD_EQVOC_ERR_IGNORED_FROM if from is not
   in the voter set.  Each voter is limited to dup_max in-progress
   proofs; if exceeded, the LRU-proof is evicted.  Once all chunks for a
   proof arrive, the proof is reassembled, verified, and released
   regardless of the outcome. */

int
fd_eqvoc_chunk_insert( fd_eqvoc_t                        * eqvoc,
                       ushort                              shred_version,
                       ulong                               root,
                       fd_epoch_leaders_t const          * leader_schedule,
                       fd_pubkey_t const                 * from,
                       fd_gossip_duplicate_shred_t const * chunk,
                       fd_gossip_duplicate_shred_t         chunks_out[static FD_EQVOC_CHUNK_CNT] );

/* fd_eqvoc_query returns 1 if equivocation has been detected for the
   given slot (ie. a verified duplicate proof exists), 0 otherwise. */

int
fd_eqvoc_query( fd_eqvoc_t * eqvoc,
                ulong        slot );

/* fd_eqvoc_update_voters updates the vtr_map to match the given voter
   set.  Removes entries not in id_keys[0..cnt) (and evicts their proofs),
   adds entries in id_keys not yet in vtr_map.  Preserves existing
   entries that are still voters (keeping in-progress proofs intact).
   id_keys is an array of identity pubkeys of length cnt. */

void
fd_eqvoc_update_voters( fd_eqvoc_t *        eqvoc,
                        fd_pubkey_t const * id_keys,
                        ulong               cnt );

#endif /* HEADER_fd_src_choreo_eqvoc_fd_eqvoc_h */
