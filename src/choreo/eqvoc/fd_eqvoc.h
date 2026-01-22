#ifndef HEADER_fd_src_choreo_eqvoc_fd_eqvoc_h
#define HEADER_fd_src_choreo_eqvoc_fd_eqvoc_h

#include "../fd_choreo_base.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../flamenco/leaders/fd_leaders.h"
#include "../../flamenco/gossip/fd_gossip_types.h"

/* fd_eqvoc presents an API for detecting and sending & receiving proofs
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
   for example, contains two shreds with the same slot and shred index
   but different data payloads.  An indirect proof contains two shreds
   with different shred indices, and the metadata on the shreds implies
   there must be two or more versions of a block for that slot.  See
   `construct_proof` or `verify_proof` in fd_eqvoc.c for more details.

   Every shred in a FEC set must have the same signature, so a different
   value in the signature field would indicate equivocation.  Note in
   the case of merkle shreds, the shred signature is signed on the FEC
   set's merkle root, so every shred in the same FEC set must have the
   same signature. */

/* FD_EQVOC_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_EQVOC_USE_HANDHOLDING
#define FD_EQVOC_USE_HANDHOLDING 1
#endif

/* zero means nothing to do (no proof has been verified) */

#define FD_EQVOC_SUCCESS       (0) /* shreds do not equivocate */

/* positive error codes means there is a proof of equivocation */

#define FD_EQVOC_PROOF_MERKLE  (1)
#define FD_EQVOC_PROOF_META    (2)
#define FD_EQVOC_PROOF_LAST    (3)
#define FD_EQVOC_PROOF_OVERLAP (4)
#define FD_EQVOC_PROOF_CHAINED (5)

/* negative error codes mean the shreds in the proof were not valid inputs */

#define FD_EQVOC_ERR_SLOT      (-1) /* different slot */
#define FD_EQVOC_ERR_VERSION   (-2) /* different shred version */
#define FD_EQVOC_ERR_TYPE      (-3) /* wrong shred type (must be chained {resigned} merkle) */
#define FD_EQVOC_ERR_MERKLE    (-4) /* merkle root failed */
#define FD_EQVOC_ERR_SIGNATURE (-5) /* sigverify of leader failed */

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

   This is not enforce on receive (Firedancer will accept smaller chunk
   payloads).

   See: https://github.com/anza-xyz/agave/blob/v2.0.3/gossip/src/cluster_info.rs#L113 */

#define FD_EQVOC_CHUNK_SZ  (1232UL - 115UL - 63UL)
FD_STATIC_ASSERT( FD_EQVOC_CHUNK_SZ==FD_GOSSIP_DUPLICATE_SHRED_MAX_CHUNKS, "DuplicateShred chunk max mismatch" );

typedef struct fd_eqvoc       fd_eqvoc_t;
typedef struct fd_eqvoc_proof fd_eqvoc_proof_t;

/* fd_eqvoc_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as eqvoc with up to
   shred_max shreds and chunk_max chunks. */

FD_FN_CONST ulong
fd_eqvoc_align( void );

FD_FN_CONST ulong
fd_eqvoc_footprint( ulong shred_max,
                    ulong slot_max,
                    ulong from_max );

/* fd_eqvoc_new formats an unused memory region for use as a eqvoc.
   mem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment. */

void *
fd_eqvoc_new( void * shmem,
              ulong  shred_max,
              ulong  cache_max,
              ulong  proof_max,
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
   only the nobody is joined to the region.  Returns a pointer to the
   underlying shared memory region or NULL if used obviously in error
   (e.g. eqvoc is obviously not a eqvoc ... logs details).  The
   ownership of the memory region is transferred to the caller. */

void *
fd_eqvoc_delete( void * sheqvoc );

fd_eqvoc_t *
fd_eqvoc_init( fd_eqvoc_t               * eqvoc,
               ushort                     shred_version,
               fd_epoch_leaders_t const * leaders );

fd_eqvoc_t *
fd_eqvoc_fini( fd_eqvoc_t * eqvoc );

/* fd_eqvoc_shred_insert inserts the shred into eqvoc.  Returns an error
   code (FD_EQVOC_{SUCCESS,PROOF_{...},ERR_{...}}) indicating whether
   eqvoc found a shred that conflicts with another shred, indicating
   equivocation.  If the error code is positive, chunks_out will be
   populated with a DuplicateShred proof that can be sent over gossip.
   Assumes shred has already been validated by the shred tile. */

int
fd_eqvoc_shred_insert( fd_eqvoc_t *                eqvoc,
                       fd_shred_t const *          shred,
                       fd_gossip_duplicate_shred_t chunks_out[static FD_EQVOC_CHUNK_CNT] );

/* fd_eqvoc_chunk_insert inserts the DuplicateShred chunk from gossip
   into eqvoc.  Returns one of FD_EQVOC_{SUCCESS,PROOF_{...},ERR_{...}},
   an error code indicating whether eqvoc was able to verify the proof.
   If eqvoc hasn't received all the chunks, returns FD_EQVOC_SUCCESS. */

int
fd_eqvoc_chunk_insert( fd_eqvoc_t                        * eqvoc,
                       fd_pubkey_t const                 * from,
                       fd_gossip_duplicate_shred_t const * chunk );

#endif /* HEADER_fd_src_choreo_eqvoc_fd_eqvoc_h */
