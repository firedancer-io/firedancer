#ifndef HEADER_fd_src_disco_shred_fd_fec_resolver_h
#define HEADER_fd_src_disco_shred_fd_fec_resolver_h
#include "../../ballet/shred/fd_fec_set.h"

/* This header defines several methods for building and validating FEC
   sets from received shreds.  It's designed just for use by the shred
   tile, which is why it's in disco/shred.

   The primary complication in the interface comes from lifetimes.
   Buffers returned by the networking layer are typically ephemeral, we
   need to hold onto the data until we've finished the FEC set, so we
   need at least one memcpy.  Once we complete the FEC set, the result
   needs to go out on an mcache/dcache pair and on the network, which
   also have different lifetime requirements.  The FEC resolver goes out
   of its way to use memory in a way that doesn't require a second
   memcpy once the FEC set is complete.  To that end, the FEC resolver
   makes two promises:
   1. Once memory has been used for a specific FEC set, it will not be
      reused for a different FEC set until at least partial_depth other
      distinct FEC sets have been returned in the out_fec_set field of
      fd_fec_resolver_add_shred.
   2. Once a FEC set is complete (specified with COMPLETES), the
      associated memory will not be reused for a different FEC set until
      at least complete_depth other distinct FEC sets have been returned
      from calls to fd_fec_resolver_add_shred that return
      SHRED_COMPLETES.

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

FD_PROTOTYPES_BEGIN
/* fd_fec_resolver_footprint returns the required footprint (in bytes as
   always) required to create an FEC set resolver that can keep track of
   `depth` in progress FEC sets, will not reuse FEC sets for at least
   partial_depth shreds or for at least complete_depth complete FEC sets
   (see above for more information).  Aditionally, the FEC resolver
   remembers done_depth FEC sets to recognize duplicates vs. new FEC
   sets.  All depths must positive.

   fd_fec_resolver_alignment returns the required alignment of a region
   of memory for it to be used as a FEC resolver. */
ulong fd_fec_resolver_footprint( ulong depth, ulong partial_depth, ulong complete_depth, ulong done_depth );
ulong fd_fec_resolver_align    ( void );

/* fd_fec_resolver_new formats a region of memory as a FEC resolver.
   shmem must have the required alignment and footprint.  depth,
   partial_depth, complete_depth, and done_depth are as defined above
   and must be positive.  sets is a pointer to the first of
   depth+partial_depth+complete_depth FEC sets that this resolver will
   take ownership of.  The FEC resolver retains a write interest in
   these FEC sets and the shreds they point to until the resolver is
   deleted.  These FEC sets and the memory for the shreds they point to
   are the only values that will be returned in the output parameters of
   _add_shred.  Returns shmem on success and NULL on failure (logs
   details). */
void *
fd_fec_resolver_new( void         * shmem,
                     ulong          depth,
                     ulong          partial_depth,
                     ulong          complete_depth,
                     ulong          done_depth,
                     fd_fec_set_t * sets );

fd_fec_resolver_t * fd_fec_resolver_join( void * shmem );

#define FD_FEC_RESOLVER_SHRED_REJECTED  (-2)
#define FD_FEC_RESOLVER_SHRED_IGNORED   (-1)
#define FD_FEC_RESOLVER_SHRED_OKAY      ( 0)
#define FD_FEC_RESOLVER_SHRED_COMPLETES ( 1)

/* fd_fec_resolver_add_shred notifies the FEC resolver of a newly
   received shred.  The FEC resolver validates the shred and copies it
   into its own storage.  resolver is a local join of an FEC resolver.
   shred is a pointer to the new shred that should be added.  shred_sz
   is the size of the shred in bytes.

   On success (SHRED_OKAY or SHRED_COMPLETES), a pointer to the
   fd_fec_set_t structure representing the FEC set of which the shred is
   a part will be written to out_fec_set.  Additionally, on success a
   pointer to a copy of shred will be written to the location pointed to
   by out_shred.  See the long explanation above about the lifetimes of
   these pointers.

   If the shred fails validation for any reason, SHRED_REJECTED will be
   returned and nothing will be written to out_fec_set or out_shred.
   If the shred is a duplicate of a shred that has already been
   received, SHRED_IGNORED will be returned, and nothing will be written
   to out_fec_set or out_shred.  Note that only light validation is
   performed on a duplicate shred, so a shred that is actually invalid
   but looks like a duplicate of a previously received valid shred may
   be considered SHRED_IGNORED instead of SHRED_REJECTED.

   This function returns SHRED_COMPLETES when the received shred is the
   last one and completes the FEC set.  In this case, the function
   populates any missing shreds in the FEC set stored in out_fec_set. */
int fd_fec_resolver_add_shred( fd_fec_resolver_t    * resolver,
                               fd_shred_t   const   *  shred,
                               ulong                  shred_sz,
                               uchar  const   * leader_pubkey,
                               fd_fec_set_t const * * out_fec_set,
                               fd_shred_t   const * * out_shred );

void * fd_fec_resolver_leave( fd_fec_resolver_t * resolver );
void * fd_fec_resolver_delete( void * shmem );

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_disco_shred_fd_fec_resolver_h */
