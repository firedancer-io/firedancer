#ifndef HEADER_fd_src_flamenco_gossip_fd_crds_h
#define HEADER_fd_src_flamenco_gossip_fd_crds_h

#include "../../util/fd_util.h"

struct fd_crds_value_private;
typedef struct fd_crds_value_private fd_crds_value_t;

struct fd_crds_private;
typedef struct fd_crds_private fd_crds_t;

struct fd_crds_mask_iter_private;
typedef struct fd_crds_mask_iter_private fd_crds_mask_iter_t;

FD_PROTOTYPES_BEGIN

long
fd_crds_value_wallclock( fd_crds_value_t const * value );

uchar const *
fd_crds_value_pubkey( fd_crds_value_t const * value );

uchar const *
fd_crds_value_hash( fd_crds_value_t const * value );

FD_FN_CONST ulong
fd_crds_align( void );

FD_FN_CONST ulong
fd_crds_footprint( ulong ele_max );

void *
fd_crds_new( void *     shmem,
             fd_rng_t * rng,
             ulong      ele_max );

fd_crds_t *
fd_crds_join( void * shcrds );

/* fd_crds_expire removes stale entries from the replicated data
   store.  CRDS values from staked nodes expire roughly an epoch after
   they are created, and values from non-staked nodes expire after 15
   seconds.
   
   There is one exception, when the node is first bootstrapping, and
   has not yet seen any staked nodes, values do not expire at all. */

void
fd_crds_expire( fd_crds_t * crds,
                long        now );

/* fd_crds_sample_peer randomly selects a peer node from the CRDS based
   weighted by stake.  Peers with a ContactInfo that hasn't been
   refreshed in more than 60 seconds are considered offline, and are
   downweighted in the selection by a factor of 100.  They are still
   included to mitigate eclipse attacks.  Peers with no ContactInfo in
   the CRDS are not included in the selection.  The current node is
   also excluded from the selection.  Low stake peers which are not
   active in the ping tracker, because they aren't responding to pings
   are also excluded from the sampling.  Peers with a different shred
   version than us, or with an invalid gossip socket address are also
   excluded from the sampling.
   
   If no valid peer can be found, the returned fd_ip4_port_t will be
   zeroed out.  The caller should check for this case and handle it
   appropriately.  On success, the returned fd_ip4_port_t is a socket
   address suitable for sending a gossip pull request. */

fd_ip4_port_t
fd_crds_sample_peer( fd_crds_t const * crds );

/* fd_crds_acquire acquires a CRDS value from the storage pool in the
   CRDS so that it can be written to by the caller.  The value will
   _not_ be present in the underlying data structures and indexes of
   the CRDS (and will not, for example, be returned  by queries) until
   it is inserted into the CRDS with fd_crds_insert.  The caller is
   responsible for completely filling in the value before calling
   insert or it will not be indexed correctly.

   A value acquired with acquire does not strictly have to be inserted
   into the CRDS, and can be released back to the pool with
   fd_crds_release.

   fd_crds_acquire cannot fail and will always return a valid CRDS.  It
   does this by evicting an existing value from the pool and structures
   if there is no free space. */

fd_crds_value_t *
fd_crds_acquire( fd_crds_t * crds );

/* fd_crds_release releases a CRDS value back to the storage pool.  The
   value must have been acquired with fd_crds_acquire, and must not
   have been inserted into the CRDS.  The caller releases the ownership
   interest in the value and should not modify or use the value
   afterwards. */

void
fd_crds_release( fd_crds_t *       crds,
                 fd_crds_value_t * value );

/* fd_crds_upserts checks if inserting the value into the CRDS would
   succeed.  An insert will fail if the value is already present in the
   CRDS with a newer timestamp, or if the value is not present. */

fd_crds_upserts( fd_crds_t *       crds,
                 fd_crds_value_t * value );

/* fd_crds_insert inserts and indexes a previously acquired CRDS value
   into the data store, so that it can be returned by future queries.

   Once inserted, the value is owned by the CRDS and should not be
   modified or released by the caller.  The CRDS will automatically
   release the value when it expires, or when it must be evicted to
   make room for a new value. */

void
fd_crds_insert( fd_crds_t *       crds,
                fd_crds_value_t * value );

ulong
fd_crds_purged_len( fd_crds_t * crds );

uchar const *
fd_crds_purged( fd_crds_t * crds,
                ulong       idx );

fd_crds_mask_iter_t
fd_crds_mask_iter_init( fd_crds_t const * crds,
                        ulong             mask,
                        ulong             mask_bits );

fd_crds_mask_iter_t
fd_crds_mask_iter_next( fd_crds_mask_iter_t it );

int
fd_crds_mask_iter_done( fd_crds_mask_iter_t it );

fd_crds_value_t const *
fd_crds_mask_iter_value( fd_crds_mask_iter_t it );

ulong
fd_crds_len( void );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_gossip_fd_crds_h */
