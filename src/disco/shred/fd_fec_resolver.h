#ifndef HEADER_fd_src_disco_shred_fd_fec_resolver_h
#define HEADER_fd_src_disco_shred_fd_fec_resolver_h
#include "../../ballet/shred/fd_fec_set.h"
#include "../../ballet/bmtree/fd_bmtree.h"
#include "../../ballet/ed25519/fd_ed25519.h"

/* This header defines several methods for building and validating FEC
   sets from received shreds.  It's designed just for use by the shred
   tile, which is why it's in disco/shred.

   The primary complication in the interface comes from lifetimes.
   Buffers returned by the networking layer are typically ephemeral and
   we need to hold onto the data until we've finished the FEC set, so we
   need at least one memcpy.  Once we complete the FEC set, the result
   needs to go out on an mcache/dcache pair and on the network, which
   also have different lifetime requirements.  The FEC resolver goes out
   of its way to use memory in a way that doesn't require a second
   memcpy once the FEC set is complete.  To that end, the FEC resolver
   makes two promises:
   1. Once memory has been used for a specific FEC set, it will not be
      reused for a different FEC set until at least partial_depth other
      distinct FEC sets have been returned in the out_fec_set field of
      fd_fec_resolver_add_shred or fd_fec_resolver_force_complete.
   2. Once a FEC set is complete (specified with COMPLETES), the
      associated memory will not be reused for a different FEC set until
      at least complete_depth other distinct FEC sets have been returned
      from calls to fd_fec_resolver_add_shred or
      fd_fec_resolver_force_complete that return SHRED_COMPLETES.

   This is implemented using a freelist with an insertion point in the
   middle (which can also be seen as two chained freelists):
                 ------------------------
                 |   In progress FEC    |--------- if completed -
                 |    sets (<=depth)    |                       |
                 |                      |--- if spilled ----    |
                 ------------------------                  |    |
                       ^                                   |    |
                       |                                   V    |
                   --------                                |    |
                   |      |   -                            |    V
                   | Free |    \                           |    |
                   |      |     >=partial_depth            |    |
                   | FEC  |     /                          |    |
                   | sets |    |                           |    |
                   |      |   _                            |    |
                   --------                                V    |
                      ^  ^                                 |    |
                      |  |------<---------------<----------|    |
                      |                                         |
                   --------                                     |
                   |      | -                                   |
                   | Comp |  \                                  |
                   |leted |   complete_depth                    |
                   |      |  /                                  V
                   | FEC  |  |                                  |
                   | sets |  |                                  |
                   |      |  -                                  |
                   --------                                     |
                      ^                                         |
                      |-------------------<----------------------

   When a shred arrives for a new FEC set, we pull an entry from the
   head of the free FEC set queue.  If that would result in more than
   depth sets in progress, we spill the oldest in progress set, and
   insert it at the tail of the free set queue.  When we complete a set,
   we remove it from the in progress set, add it to the tail of the
   completed FEC set queue, and move one element from the head of the
   completed queue to the tail of the free queue.

   Since the completed queue only advances when an FEC set is completed,
   any complete FEC set stays in that queue for at least complete_depth
   completions.

   It might seems like this system is overkill and one combined longer
   freelist would suffice, but that's incorrect. Consider the following
   scenario: Suppose we've just completed FEC set A, so we return it
   with COMPLETES and then we put it at the end of the free list.  Now
   we receive a shred for a new FEC set, so we take memory from the head
   of the free list.  That happens many times, but we never receive
   enough shreds for any FEC set to complete one.  Eventually, we churn
   through the whole singular freelist with spilling until the memory we
   used for A gets to the head of the freelist.  Finally we receive
   enough shreds to complete the FEC set, so we return A with COMPLETES.
   Thus, from the perspective of a consumer that only cares about
   completed FEC sets, we've returned the same piece of memory twice in
   a row. */

/* Forward declare opaque handle.  It has a lot of types we don't
   necessarily want to bring into the includer */
#define FD_FEC_RESOLVER_ALIGN (128UL)
struct fd_fec_resolver;
typedef struct fd_fec_resolver fd_fec_resolver_t;

#define SHRED_CNT_NOT_SET      (UINT_MAX/2U)

/* fd_fec_resolver_sign_fn: used to sign shreds that require a
   retransmitter signature. */
typedef void (fd_fec_resolver_sign_fn)( void * ctx, uchar * sig, uchar const * merkle_root );

FD_PROTOTYPES_BEGIN
/* fd_fec_resolver_footprint returns the required footprint (in bytes as
   always) required to create an FEC set resolver that can keep track of
   `depth` in progress FEC sets, will not reuse FEC sets for at least
   partial_depth shreds or for at least complete_depth complete FEC sets
   (see above for more information).  Additionally, the FEC resolver
   remembers done_depth FEC sets to recognize duplicates vs. new FEC
   sets.  All depths must positive.

   fd_fec_resolver_alignment returns the required alignment of a region
   of memory for it to be used as a FEC resolver. */
FD_FN_PURE ulong fd_fec_resolver_footprint( ulong depth, ulong partial_depth, ulong complete_depth, ulong done_depth );
FD_FN_CONST ulong fd_fec_resolver_align    ( void );

/* fd_fec_resolver_new formats a region of memory as a FEC resolver.
   shmem must have the required alignment and footprint.  signer is a
   function pointer used to sign any shreds that require a retransmitter
   signature, and sign_ctx is an opaque pointer passed as the first
   argument to the function.  It is okay to pass NULL for signer, in
   which case, retransmission signatures will just be zeroed and
   sign_ctx will be ignored. depth, partial_depth, complete_depth, and
   done_depth are as defined above and must be positive.  sets is a
   pointer to the first of depth+partial_depth+complete_depth FEC sets
   that this resolver will take ownership of.  The FEC resolver retains
   a write interest in these FEC sets and the shreds they point to until
   the resolver is deleted.  These FEC sets and the memory for the
   shreds they point to are the only values that will be returned in the
   output parameters of _{add_shred, force_completes}.  The FEC resolver
   will reject any shreds with a shred version that does not match the
   value provided for expected_shred_version.  Shred versions are always
   non-zero, so expected_shred_version must be non-zero.  The FEC
   resolver will also reject any shred that seems to be part of a block
   containing more than max_shred_idx data or parity shreds.  Since
   shred_idx is a uint, it doesn't really make sense to have
   max_shred_idx > UINT_MAX, and max_shred_idx==0 rejects all shreds.
   Returns shmem on success and NULL on failure (logs details). */
void *
fd_fec_resolver_new( void                    * shmem,
                     fd_fec_resolver_sign_fn * signer,
                     void                    * sign_ctx,
                     ulong                     depth,
                     ulong                     partial_depth,
                     ulong                     complete_depth,
                     ulong                     done_depth,
                     fd_fec_set_t            * sets,
                     ulong                     max_shred_idx );

fd_fec_resolver_t * fd_fec_resolver_join( void * shmem );

void
fd_fec_resolver_set_shred_version( fd_fec_resolver_t * resolver,
                                   ushort              expected_shred_version );


#define FD_FEC_RESOLVER_SHRED_REJECTED  (-2)
#define FD_FEC_RESOLVER_SHRED_IGNORED   (-1)
#define FD_FEC_RESOLVER_SHRED_OKAY      ( 0)
#define FD_FEC_RESOLVER_SHRED_COMPLETES ( 1)

/* Return values + RETVAL_OFF are in [0, RETVAL_CNT) */
#define FD_FEC_RESOLVER_ADD_SHRED_RETVAL_CNT 4
#define FD_FEC_RESOLVER_ADD_SHRED_RETVAL_OFF 2

struct fd_fec_resolver_spilled {
  ulong slot;
  uint  fec_set_idx;
  uint  max_dshred_idx; /* position in FEC set, in [0, FD_REEDSOL_DATA_SHREDS_MAX) */
};
typedef struct fd_fec_resolver_spilled fd_fec_resolver_spilled_t;

/* fd_fec_resolver_add_shred notifies the FEC resolver of a newly
   received shred.  The FEC resolver validates the shred and copies it
   into its own storage.  resolver is a local join of an FEC resolver.
   shred is a pointer to the new shred that should be added.  shred_sz
   is the size of the shred in bytes.

   On success ie. SHRED_{OKAY,COMPLETES}, a pointer to the fd_fec_set_t
   structure representing the FEC set of which the shred is a part will
   be written to out_fec_set.  Additionally, on success a pointer to a
   copy of shred will be written to the location pointed to by
   out_shred.  See the long explanation above about the lifetimes of
   these pointers.  Finally, on success the merkle root of the shred
   (reconstructed from the merkle proof) will be written to
   out_merkle_root.  Unlike out_{fec_set,shred}, caller owns and
   provides the memory for out_merkle_root.  If the out_merkle_root
   pointer is NULL, the argument will be ignored and merkle root will
   not be written.

   If the shred fails validation for any reason, returns SHRED_REJECTED
   and does not write to out_{fec_set,shred,merkle_root}.  If the shred
   is a duplicate of a shred that has already been received (ie. a shred
   with the same index but a different payload), returns SHRED_IGNORED
   does not write to out_{fec_set,shred,merkle_root}.

   Note that only light validation is performed on a duplicate shred, so
   a shred that is actually invalid but looks like a duplicate of a
   previously received valid shred may be considered SHRED_IGNORED
   instead of SHRED_REJECTED.

   This function returns SHRED_COMPLETES when the received shred is the
   last one and completes the FEC set.  In this case, the function
   populates any missing shreds in the FEC set stored in out_fec_set.

   Regardless of success/failure, if an incomplete FEC set was evicted
   from the current map during this add_shred call, the metadata of the
   evicted FEC set will be written to out_spilled_fec_set.  The FEC set
   metadata includes slot, fec_set_idx, and also highest data shred
   index received thus far in this FEC set, in the range
   [0, FD_REEDSOL_DATA_SHREDS_MAX).  If no data shreds have been
   received yet (i.e., only parity shreds have been received),
   max_dshred_idx will be FD_SHRED_BLK_MAX.  If no FEC set was evicted,
   out_spilled_fec_set will remain unmodified.  Similar to
   out_merkle_root, the caller owns and provides the memory for
   out_spilled_fec_set.  If the out_spilled_fec_set pointer is NULL, the
   argument will be ignored and the evicted FEC set metadata will not be
   written. */

int
fd_fec_resolver_add_shred( fd_fec_resolver_t         * resolver,
                           fd_shred_t const          * shred,
                           ulong                       shred_sz,
                           uchar const               * leader_pubkey,
                           fd_fec_set_t const      * * out_fec_set,
                           fd_shred_t const        * * out_shred,
                           fd_bmtree_node_t          * out_merkle_root,
                           fd_fec_resolver_spilled_t * out_spilled_fec_set );


void * fd_fec_resolver_leave( fd_fec_resolver_t * resolver );
void * fd_fec_resolver_delete( void * shmem );

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_disco_shred_fd_fec_resolver_h */
