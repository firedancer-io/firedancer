#ifndef HEADER_fd_src_flamenco_gossip_fd_crds_h
#define HEADER_fd_src_flamenco_gossip_fd_crds_h

#include "../fd_gossip_private.h"
#include "../fd_gossip_out.h"
#include "../fd_gossip_metrics.h"

struct fd_crds_entry_private;
typedef struct fd_crds_entry_private fd_crds_entry_t;

struct fd_crds_private;
typedef struct fd_crds_private fd_crds_t;

struct fd_crds_mask_iter_private;
typedef struct fd_crds_mask_iter_private fd_crds_mask_iter_t;

#define FD_CRDS_UPSERT_CHECK_UPSERTS      ( 0)
#define FD_CRDS_UPSERT_CHECK_FAILS        (-1)

#define CRDS_MAX_CONTACT_INFO_LG (15)
#define CRDS_MAX_CONTACT_INFO    (1<<CRDS_MAX_CONTACT_INFO_LG) /* 32768 */


FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_crds_align( void );

FD_FN_CONST ulong
fd_crds_footprint( ulong ele_max,
                   ulong purged_max );

/* metrics is a pointer to a fd_crds_table_metrics_t structure that will be
   updated with the current CRDS table metrics.
   gossip_update_out holds the info to the gossip out link used to publish
   gossip message updates */
void *
fd_crds_new( void *                    shmem,
             fd_rng_t *                rng,
             ulong                     ele_max,
             ulong                     purged_max,
             fd_crds_table_metrics_t * metrics,
             fd_gossip_out_ctx_t *     gossip_update_out  );

fd_crds_t *
fd_crds_join( void * shcrds );

/* fd_crds_advance performs housekeeping operations and should be run
   as a part of a gossip advance loop. The following operations are
   performed:
   - expire: removes stale entries from the replicated data store.
     CRDS values from staked nodes expire roughly an epoch after they
     are created, and values from non-staked nodes expire after 15
     seconds. Removed contact info entries are also published as gossip
     updates via stem.
   - re-weigh: peers are downsampled in the peer sampler if they have
     not been refreshed in <60s.

   There is one exception, when the node is first bootstrapping, and
   has not yet seen any staked nodes, values do not expire at all. */

void
fd_crds_advance( fd_crds_t *         crds,
                 long                now,
                 fd_stem_context_t * stem );

/* fd_crds_len returns the number of entries in the CRDS table. This does not
   include purged entries, which have a separate queue tracking them.
   See fd_crds_purged_* APIs below. */
ulong
fd_crds_len( fd_crds_t const * crds );

/* fd_crds maintains a table of purged CRDS entries. A CRDS entry is
   purged when it is overriden by a newer form of the entry. Such entries
   are no longer propagated by the node, but are still tracked in order
   to avoid re-receiving them via pull responses by including them in
   the pull request filters we generate. This means we only need to hold
   the hash of the entry and the wallclock time when it was purged.

   Agave's Gossip client maintains two such tables: one labeled "purged"
   and another "failed_inserts". They function the same, the only difference
   lies in the conditions that trigger the insertion and the expiry windows.

   "purged"
      A CRDS value is inserted into "purged" when
       - it is from an incoming push message and does NOT upsert in the CRDS
         table and is not a duplicate of an existing entry in the CRDS table
       - it is an existing entry in the CRDS table and will be overriden by
         an incoming CRDS value in a push/pull response message
      "purged" entries expire after 60s

  "failed_inserts"
      A CRDS value is inserted into "failed_inserts" when it is from an
      incoming pull response and either
        - does NOT upsert in the CRDS table and is not a duplicate of an
           existing entry in the CRDS table
        - satisfies upsert conditions, but is too old to be inserted
      "failed_inserts" entries expire after 20s */

ulong
fd_crds_purged_len( fd_crds_t const * crds );

void
fd_crds_genrate_hash( uchar const *     crds_value_buf,
                      ulong             crds_value_sz,
                      uchar             out_hash[ static 32UL ] );


void
fd_crds_insert_failed_insert( fd_crds_t *   crds,
                              uchar const * hash,
                              long          now );

/* fd_crds_checks_fast checks if inserting a CRDS value would fail on
   specific conditions. Updates the CRDS purged table depending on the checks
   that failed.

   This isn't an exhaustive check, but that does not matter since
   fd_crds_insert will perform the full check. This avoids expensive operations
   like sigverify and hashing* if a CRDS value fails these fast checks.

   Returns FD_CRDS_UPSERT_CHECK_UPSERTS if the value passes the fast checks.
   Returns >0 if the value is a duplicate, with the return value denoting the
   number of duplicates seen at this point (including current). Returns
   FD_CRDS_UPSERT_CHECK_UNDETERMINED if further checks are needed
   (e.g. hash comparison). Returns FD_CRDS_UPSERT_CHECK_FAILS for other
   failures (e.g. too old). This will result in the candidate being purged.

   Note that this function is not idempotent as duplicate counts are tracked by
   the CRDS table.

   *Hashing is performed if a failure condition warrants a purge insert. */

int
fd_crds_checks_fast( fd_crds_t *                         crds,
                     fd_gossip_view_crds_value_t const * candidate,
                     uchar const *                       payload,
                     uchar                               from_push_msg );

/* fd_crds_insert inserts and indexes a CRDS value into the data store
   as a CRDS entry, so that it can be returned by future queries. This
   function should not be called if the result of fd_crds_checks_fast is
   not FD_CRDS_UPSERT_CHECK_UPSERTS.

   On top of inserting the CRDS entry, this function also updates the sidetable
   of ContactInfo entries and the peer samplers if the entry is a ContactInfo.
   is_from_me indicates the CRDS entry originates from this node. We exclude our
   own entries from peer samplers. origin_stake is used to weigh the peer in the
   samplers.

   stem is used to publish updates to {ContactInfo, Vote, LowestSlot} entries.

   Returns a pointer to the newly created CRDS entry. Lifetime is guaranteed
   until the next call to the following functions:
     - fd_crds_insert
     - fd_crds_expire
   Returns NULL if the insertion fails for any reason. */

fd_crds_entry_t const *
fd_crds_insert( fd_crds_t *                         crds,
                fd_gossip_view_crds_value_t const * candidate_view,
                uchar const *                       payload,
                ulong                               origin_stake,
                uchar                               is_from_me,
                long                                now,
                fd_stem_context_t *                 stem );

void
fd_crds_entry_value( fd_crds_entry_t const * entry,
                     uchar const **          value_bytes,
                     ulong *                 value_sz );

uchar const *
fd_crds_entry_pubkey( fd_crds_entry_t const * entry );

/* fd_crds_entry_hash returns a pointer to the 32b sha256 hash of the
   entry's value hash. This is used for constructing a bloom filter. */
uchar const *
fd_crds_entry_hash( fd_crds_entry_t const * entry );

/* fd_crds_entry_is_contact_info returns 1 if entry holds a Contact
    Info CRDS value. Assumes entry was populated with either
   fd_crds_populate_{preflight,full} */
int
fd_crds_entry_is_contact_info( fd_crds_entry_t const * entry );

/* fd_crds_contact_info returns a pointer to the contact info
   structure in the entry.  This is used to access the contact info
   fields in the entry, such as the pubkey, shred version, and
   socket address.

   Assumes crds entry is a contact info (check with
   fd_crds_entry_is_contact_info) */
fd_contact_info_t *
fd_crds_entry_contact_info( fd_crds_entry_t const * entry );

/* fd_crds tracks Contact Info entries with a sidetable that holds the
   fully decoded contact info of a */

/* fd_crds_contact_info_lookup returns a pointer to the contact info
   structure corresponding to pubkey. returns NULL if there is no such
   entry. */

fd_contact_info_t const *
fd_crds_contact_info_lookup( fd_crds_t const * crds,
                             uchar const *     pubkey );

/* fd_crds_peer_count returns the number of Contact Info entries
   present in the sidetable. The lifetime of a Contact Info entry
   tracks the lifetime of the corresponding CRDS entry. */
ulong
fd_crds_peer_count( fd_crds_t const * crds );

/* The CRDS table tracks whether a peer is active or not to determine
   whether it should be sampled (see sample APIs).
   fd_crds_peer_{active,inactive} provide a way to manage this state
   for a given peer.

   A peer's active state is typicallly determined by its ping/pong status. */
void
fd_crds_peer_active( fd_crds_t *   crds,
                     uchar const * peer_pubkey,
                     long          now );

void
fd_crds_peer_inactive( fd_crds_t *   crds,
                       uchar const * peer_pubkey,
                       long          now );


/* The CRDS Table also maintains a set of peer samplers for use in various
   Gossip tx cases. Namely
   - Rotating the active push set (bucket_samplers)
   - Selecting a pull request target (pr_sampler) */


/* fd_crds_bucket_* sample APIs are meant to be used by fd_active_set.
   Each bucket has a unique sampler. */
fd_contact_info_t const *
fd_crds_bucket_sample_and_remove( fd_crds_t * crds,
                                  fd_rng_t *  rng,
                                  ulong       bucket );

/* fd_crds_bucket adds back in a peer that was previously
   sampled with fd_crds_bucket_sample_and_remove.  */
void
fd_crds_bucket_add( fd_crds_t *   crds,
                    ulong         bucket,
                    uchar const * pubkey );


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

   If no valid peer can be found, the returned fd_contact_info_t will be
   NULL.  The caller should check for this case and handle it
   appropriately.  On success, the returned fd_contact_info_t is a
   contact info suitable for sending a gossip pull request. */

fd_contact_info_t const *
fd_crds_peer_sample( fd_crds_t const * crds,
                     fd_rng_t *        rng );


/* fd_crds_mask_iter_{init,next,done,entry} provide an API to
   iterate over the CRDS values in the table that whose hashes match
   a given mask. In the Gossip CRDS filter, the mask is applied on
   the most significant 8 bytes of the CRDS value's hash.

   The Gossip CRDS filter encodes the mask in two values: `mask` and
   `mask_bits`. For example, if we set `mask_bits` to 5 and 0b01010 as
   `mask`, we get the following 64-bit bitmask:
                        01010 11111111111.....

   Therefore, we can frame a mask match as a CRDS value's hash whose
   most significant `mask_bits` is `mask`. We can trivially define
   the range of matching hash values by setting the non-mask bits to
   all 0s or 1s to get the start and end values respectively. */

fd_crds_mask_iter_t *
fd_crds_mask_iter_init( fd_crds_t const * crds,
                        ulong             mask,
                        uint              mask_bits,
                        uchar             iter_mem[ static 16UL ] );

fd_crds_mask_iter_t *
fd_crds_mask_iter_next( fd_crds_mask_iter_t * it,
                        fd_crds_t const * crds );

int
fd_crds_mask_iter_done( fd_crds_mask_iter_t * it,
                        fd_crds_t const * crds );

fd_crds_entry_t const *
fd_crds_mask_iter_entry( fd_crds_mask_iter_t * it,
                         fd_crds_t const * crds );

/* fd_crds_purged_mask_iter_{init,next,done} mirrors the fd_crds_mask_*
   APIs for the purged table. This includes purged and failed_inserts
   entries for the specified mask range.

   Mixing APIs (e.g., using crds init and purged next/done/hash) is UB.*/

fd_crds_mask_iter_t *
fd_crds_purged_mask_iter_init( fd_crds_t const * crds,
                               ulong             mask,
                               uint              mask_bits,
                               uchar             iter_mem[ static 16UL ] );

fd_crds_mask_iter_t *
fd_crds_purged_mask_iter_next( fd_crds_mask_iter_t * it,
                               fd_crds_t const * crds );

int
fd_crds_purged_mask_iter_done( fd_crds_mask_iter_t * it,
                               fd_crds_t const * crds );

/* fd_crds_purged_mask_iter_hash returns the hash of the current
   entry in the purged mask iterator. */
uchar const *
fd_crds_purged_mask_iter_hash( fd_crds_mask_iter_t * it,
                               fd_crds_t const * crds );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_gossip_fd_crds_h */
