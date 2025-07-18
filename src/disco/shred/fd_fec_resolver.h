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
                     ushort                    expected_shred_version,
                     ulong                     max_shred_idx );

fd_fec_resolver_t * fd_fec_resolver_join( void * shmem );

#define FD_FEC_RESOLVER_SHRED_REJECTED  (-2)
#define FD_FEC_RESOLVER_SHRED_IGNORED   (-1)
#define FD_FEC_RESOLVER_SHRED_OKAY      ( 0)
#define FD_FEC_RESOLVER_SHRED_COMPLETES ( 1)

/* Return values + RETVAL_OFF are in [0, RETVAL_CNT) */
#define FD_FEC_RESOLVER_ADD_SHRED_RETVAL_CNT 4
#define FD_FEC_RESOLVER_ADD_SHRED_RETVAL_OFF 2



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
   populates any missing shreds in the FEC set stored in out_fec_set. */
int fd_fec_resolver_add_shred( fd_fec_resolver_t    * resolver,
                               fd_shred_t const     * shred,
                               ulong                  shred_sz,
                               uchar const          * leader_pubkey,
                               fd_fec_set_t const * * out_fec_set,
                               fd_shred_t const   * * out_shred,
                               fd_bmtree_node_t     * out_merkle_root );


/* fd_fec_resolver_done_contains returns 1 if the FEC with signature
   lives in the done_map, and thus means it has been completed. Returns
   0 otherwise. */
int
fd_fec_resolver_done_contains( fd_fec_resolver_t      * resolver,
                               fd_ed25519_sig_t const * signature );

/* fd_fec_resolver_shred_query returns the data shred in the FEC set
   with signature at shred_idx. The return shred is copied to the region
   of memory pointed to by out_shred, and will copy only up to
   FD_SHRED_MIN_SZ bytes.  Returns FD_FEC_RESOLVER_SHRED_REJECTED if the
   FEC set does not live in the curr_map, and in this case, the user
   should ignore the out_shred. If the FEC set with signature lives in
   the curr_map (i.e., is an in-progress FEC set), then the data shred
   at shred_idx is copied to out_shred and FD_FEC_RESOLVER_SHRED_OKAY is
   returned. Note: no validation on shred idx bounds is performed, so it
   is up to the user to ensure that provided shred_idx is between [0,
   data_cnt).  No validation that the shred at shred_idx has been
   received is performed either.  If either of these are not satisfied,
   upon return the value of out_shred[i] for i in [0, FD_SHRED_MIN_SZ)
   is undefined.

   The use case for this function is solely for the force completion
   API, which requires the last shred in a FEC set. This function should
   be removed at the time when force completion is removed. */
int
fd_fec_resolver_shred_query( fd_fec_resolver_t      * resolver,
                             fd_ed25519_sig_t const * signature,
                             uint                     shred_idx,
                             uchar                  * out_shred );

/* fd_fec_resolver_force_complete forces completion of a partial FEC set
   in the FEC resolver.

   API is similar to add_shred.  last_shred is what the caller has
   determined to be the last shred in the FEC set.  out_fec_set is set
   to a pointer to the complete FEC set on SHRED_COMPLETES.  Similar to
   add_shred, see the long explanation at the top of this file for
   details on the lifetime of out_fec_set.  out_merkle_root if non-NULL
   will contain a copy of the Merkle root of the FEC set on success.

   Returns SHRED_COMPLETES when last_shred validates successfully with
   the in-progress FEC set, SHRED_IGNORED if the FEC set containing
   last_shred has already been completed (done) and SHRED_REJECTED when
   the last_shred provided is obviously invalid or the in-progress FEC
   does not validate.

   This function is a temporary measure to address a current limitation
   in the Repair protocol where it does not support requesting coding
   shreds.  FEC resolver requires at least one coding shred to complete,
   so this function is intended to be called when the caller knows FEC
   set resolver has already received all the data shreds, but hasn't
   gotten any coding shreds, but the caller has no way to recover the
   coding shreds and make forward progress using the data shreds it does
   already have available.

   Note that forcing completion greatly reduces the amount of validation
   performed on the FEC set.  It only checks that the data shreds are
   consistent with one another.  If validation of the FEC set fails when
   completing (other than issues with the last shred that are obviously
   wrong eg. shred_idx > FD_REEDSOL_DATA_SHREDS_MAX), then the function,
   similar to add_shred, will dump the in-progress FEC and add it to the
   free list.  Caller should account for this ensure they only
   force_complete when they are certain last shred is the in fact the
   last shred, or the consequence is the entire FEC might be incorrectly
   discarded too early.

   The last_shred is used to derive the data_shred_cnt which is
   otherwise only available after receiving a coding shred.  It is an
   error to force completion of a FEC set that has already received at
   least one parity shred. */

int
fd_fec_resolver_force_complete( fd_fec_resolver_t  *  resolver,
                                fd_shred_t const   *  last_shred,
                                fd_fec_set_t const ** out_fec_set,
                                fd_bmtree_node_t   *  out_merkle_root );

void * fd_fec_resolver_leave( fd_fec_resolver_t * resolver );
void * fd_fec_resolver_delete( void * shmem );

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_disco_shred_fd_fec_resolver_h */
