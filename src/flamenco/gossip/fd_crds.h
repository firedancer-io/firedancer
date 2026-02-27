#ifndef HEADER_fd_src_flamenco_gossip_crds_fd_crds_h
#define HEADER_fd_src_flamenco_gossip_crds_fd_crds_h

#include "fd_gossip_wsample.h"
#include "fd_gossip_message.h"
#include "fd_gossip_out.h"
#include "fd_gossip_purged.h"

#include "../../disco/metrics/generated/fd_metrics_enums.h"

struct fd_crds_entry_private;
typedef struct fd_crds_entry_private fd_crds_entry_t;

struct fd_crds_private;
typedef struct fd_crds_private fd_crds_t;

struct fd_crds_mask_iter_private;
typedef struct fd_crds_mask_iter_private fd_crds_mask_iter_t;

#define FD_CRDS_ALIGN 128UL

#define FD_CRDS_MAGIC (0xf17eda2c37c7d50UL) /* firedancer crds version 0*/

struct fd_crds_metrics {
  ulong count[ FD_METRICS_ENUM_CRDS_VALUE_CNT ];
  ulong expired_cnt;
  ulong evicted_cnt;

  ulong peer_staked_cnt;
  ulong peer_unstaked_cnt;
  ulong peer_visible_stake;
  ulong peer_evicted_cnt;
};

typedef struct fd_crds_metrics fd_crds_metrics_t;

#define FD_GOSSIP_ACTIVITY_CHANGE_TYPE_ACTIVE   (1)
#define FD_GOSSIP_ACTIVITY_CHANGE_TYPE_INACTIVE (2)

typedef void (*fd_gossip_activity_update_fn)( void *                           ctx,
                                              fd_pubkey_t const *              identity,
                                              fd_gossip_contact_info_t const * ci,
                                              int                              change_type );

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_crds_align( void );

FD_FN_CONST ulong
fd_crds_footprint( ulong ele_max );

typedef struct fd_active_set_private fd_active_set_t;

void *
fd_crds_new( void *                       shmem,
             fd_gossip_wsample_t *        wsample,
             fd_active_set_t *            active_set, /* TODO: Remove .. circular dep */
             fd_rng_t *                   rng,
             ulong                        ele_max,
             fd_gossip_purged_t *         purged,
             fd_gossip_activity_update_fn activity_update_fn,
             void *                       activity_update_fn_ctx,
             fd_gossip_out_ctx_t *        gossip_update_out  );

fd_crds_t *
fd_crds_join( void * shcrds );

fd_crds_metrics_t const *
fd_crds_metrics( fd_crds_t const * crds );

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

/* fd_crds_len returns the number of entries in the CRDS table. This
   does not include purged entries, which have a separate queue tracking
   them. See fd_crds_purged_* APIs below. */

ulong
fd_crds_len( fd_crds_t const * crds );

/* fd_crds_insert upserts a CRDS value into the data store.  If the
   value's key is not yet present, a new entry is acquired and indexed.
   If a matching key already exists, the candidate is compared against
   the incumbent using wallclock (and outset for ContactInfo); the
   winner is kept and the loser is purged.

   On top of inserting the CRDS entry, this function also updates the
   sidetable of ContactInfo entries and the peer samplers if the entry
   is a ContactInfo.  is_from_me indicates the CRDS entry originates
   from this node.  We exclude our own entries from peer samplers.
   origin_stake is used to weigh the peer in the samplers.

   stem is used to publish updates to {ContactInfo, Vote, DuplicateShred,
   SnapshotHashes} entries.

   Returns 0L on successful upsert, -1L if the candidate was stale
   (not inserted), or >0 if the candidate was a duplicate (the return
   value is the running duplicate count). */

long
fd_crds_insert( fd_crds_t *               crds,
                fd_gossip_value_t const * value,
                uchar const *             value_bytes,
                ulong                     value_bytes_len,
                ulong                     origin_stake,
                int                       origin_active,
                int                       is_me,
                long                      now,
                fd_stem_context_t *       stem );

void
fd_crds_entry_value( fd_crds_entry_t const * entry,
                     uchar const **          value_bytes,
                     ulong *                 value_sz );

/* fd_crds_entry_wallclock returns the originator's wallclock timestamp
   for this entry, in milliseconds.  This is the wallclock the
   originator attached when they created the CRDS value. */

ulong
fd_crds_entry_wallclock( fd_crds_entry_t const * entry );

/* fd_crds_entry_hash returns a pointer to the 32b sha256 hash of the
   entry's value hash. This is used for constructing a bloom filter. */

uchar const *
fd_crds_entry_hash( fd_crds_entry_t const * entry );

/* fd_crds_peer_count returns the number of Contact Info entries
   present in the sidetable. The lifetime of a Contact Info entry
   tracks the lifetime of the corresponding CRDS entry. */

ulong
fd_crds_peer_count( fd_crds_t const * crds );

fd_gossip_contact_info_t const *
fd_crds_ci( fd_crds_t const * crds,
            ulong             ci_idx );

uchar const *
fd_crds_ci_pubkey( fd_crds_t const * crds,
                   ulong             ci_idx );

ulong
fd_crds_ci_idx( fd_crds_t const * crds,
                uchar const *     pubkey );

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

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_gossip_crds_fd_crds_h */
