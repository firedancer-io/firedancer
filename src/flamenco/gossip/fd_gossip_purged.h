#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_purged_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_purged_h

#include "../fd_flamenco_base.h"
#include "../../util/fd_hash32.h"

/* fd_gossip_purged implements the "purged" side-table of the CRDS.
   When a CRDS entry is overridden by a newer value, fails to insert
   (stale), or is dropped because the origin has no known contact info,
   its hash is recorded here so it can appear in bloom filters and
   prevent peers from re-sending it.

   There are three mutually exclusive lists:

     - replaced_dlist:        Entries replaced by a newer value.  Expire in 60s.
     - failed_inserts_dlist:  Entries that failed to upsert.     Expire in 60s.
     - no_contact_info_dlist: Entries dropped for missing CI.    Expire in ~2 days.

   All three lists share a single pool and treap (keyed by the first
   8 bytes of the value hash) so they can be iterated together when
   building pull-request bloom filters. */

struct fd_gossip_purged_metrics {
  ulong purged_cnt;
  ulong purged_expired_cnt;
  ulong purged_evicted_cnt;
};

typedef struct fd_gossip_purged_metrics fd_gossip_purged_metrics_t;

struct fd_crds_purged {
  uchar hash[ 32UL ];

  struct {
    uint next;
  } pool;

  struct {
    ulong hash_prefix;
    uint  parent;
    uint  left;
    uint  right;
    uint  next;
    uint  prev;
    uint  prio;
  } treap;

  /* We keep a linked list of purged values sorted by insertion time.
     The time used here is our node's wallclock.

     There are actually three (mutually exclusive) lists that reuse the
     same pointers here: one for "replaced" entries that expire in 60s,
     one for "failed_inserts" that expire after 60s, and one for
     "no_contact_info" entries that expire after 2 days. */
  struct {
    long  wallclock_nanos;
    uint  next;
    uint  prev;
  } expire;

  /* For no_contact_info entries, we also track the origin pubkey and
     chain entries by origin so they can all be drained when we learn
     the contact info for that pubkey. */
  fd_pubkey_t origin;
  struct {
    uint next;
    uint prev;
  } nci_map;
};

typedef struct fd_crds_purged fd_crds_purged_t;

FD_STATIC_ASSERT( sizeof(fd_crds_purged_t)==128UL, purged_entry_footprint );

struct fd_gossip_purged_private;
typedef struct fd_gossip_purged_private fd_gossip_purged_t;

#define FD_GOSSIP_PURGED_ALIGN 128UL
#define FD_GOSSIP_PURGED_MAGIC (0xf17eda2c39070ed0UL) /* firedancer purged v0 */

struct fd_gossip_purged_mask_iter_private {
  ulong idx;
  ulong end_hash;
};

typedef struct fd_gossip_purged_mask_iter_private fd_gossip_purged_mask_iter_t;

static inline void
fd_gossip_purged_generate_masks( ulong   mask,
                                 uint    mask_bits,
                                 ulong * start_mask,
                                 ulong * end_mask ) {
  /* Agave defines the mask as a ulong with the top mask_bits bits set
     to the desired prefix and all other bits set to 1. */
  FD_TEST( mask_bits<64U );
  ulong range = fd_ulong_mask( 0U, (int)(63U-mask_bits) );
  *start_mask = mask & ~range;
  *end_mask   = mask | range;
}

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_gossip_purged_align( void );

FD_FN_CONST ulong
fd_gossip_purged_footprint( ulong purged_max );

void *
fd_gossip_purged_new( void *     shmem,
                      fd_rng_t * rng,
                      ulong      purged_max );

fd_gossip_purged_t *
fd_gossip_purged_join( void * shpurged );

fd_gossip_purged_metrics_t const *
fd_gossip_purged_metrics( fd_gossip_purged_t const * purged );

/* fd_gossip_purged_len returns the number of entries currently tracked
   in the purged pool (across all three dlists). */

ulong
fd_gossip_purged_len( fd_gossip_purged_t const * purged );

/* fd_gossip_purged_insert_replaced records a hash that was purged
   because a newer CRDS value replaced it. */

void
fd_gossip_purged_insert_replaced( fd_gossip_purged_t * purged,
                                  uchar const *        hash,
                                  long                 now );

/* fd_gossip_purged_insert_failed_insert records a hash that failed to
   upsert the CRDS table (e.g. stale or lost a tiebreaker). */

void
fd_gossip_purged_insert_failed_insert( fd_gossip_purged_t * purged,
                                       uchar const *        hash,
                                       long                 now );

/* fd_gossip_purged_insert_no_contact_info records a hash that was
   dropped because the origin pubkey has no known contact info.  The
   hash is inserted into the shared purged treap (so it appears in
   bloom filters) and into a per-pubkey chain so all entries for a
   given origin can be drained when we learn their contact info. */

void
fd_gossip_purged_insert_no_contact_info( fd_gossip_purged_t * purged,
                                         uchar const *        origin,
                                         uchar const *        hash,
                                         long                 now );

/* fd_gossip_purged_drain_no_contact_info removes all no_contact_info
   entries associated with the given origin pubkey from the purged
   treap, no_contact_info dlist, and per-pubkey chain.  This causes
   those hashes to disappear from bloom filters, so peers will re-send
   the corresponding CRDS values in future pull responses. */

void
fd_gossip_purged_drain_no_contact_info( fd_gossip_purged_t * purged,
                                        uchar const *        origin );

/* fd_gossip_purged_expire removes entries that have exceeded their
   expiry window from each of the three dlists. */

void
fd_gossip_purged_expire( fd_gossip_purged_t * purged,
                         long                 now );

/* fd_gossip_purged_mask_iter_{init,next,done,hash} iterate over purged
   entries whose hash prefix falls within the range defined by mask and
   mask_bits.  This is used when building bloom filters for pull
   requests. */

fd_gossip_purged_mask_iter_t *
fd_gossip_purged_mask_iter_init( fd_gossip_purged_t const * purged,
                                 ulong                      mask,
                                 uint                       mask_bits,
                                 uchar                      iter_mem[ static 16UL ] );

fd_gossip_purged_mask_iter_t *
fd_gossip_purged_mask_iter_next( fd_gossip_purged_mask_iter_t * it,
                                 fd_gossip_purged_t const *     purged );

int
fd_gossip_purged_mask_iter_done( fd_gossip_purged_mask_iter_t * it,
                                 fd_gossip_purged_t const *     purged );

uchar const *
fd_gossip_purged_mask_iter_hash( fd_gossip_purged_mask_iter_t * it,
                                 fd_gossip_purged_t const *     purged );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_gossip_fd_gossip_purged_h */
