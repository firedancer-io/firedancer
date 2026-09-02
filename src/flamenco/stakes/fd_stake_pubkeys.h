#ifndef HEADER_fd_src_flamenco_stakes_fd_stake_pubkeys_h
#define HEADER_fd_src_flamenco_stakes_fd_stake_pubkeys_h

#include "../fd_flamenco_base.h"

#define FD_STAKE_PUBKEYS_ALIGN (128UL)
#define FD_STAKE_PUBKEYS_MAGIC (0xF17EDA2CE757A5E0) /* FIREDANCER STAKE V0 */

/* fd_stake_pubkeys stores stake-account pubkeys into stable uint
   indices shared by stake delegations and partitioned rewards.  Every
   live index is reference counted.

   All mutating operations below, except lock and unlock themselves,
   require the caller to hold the write lock.  Query operations require
   either that lock or a live reference which prevents index reuse.
   The lock also serializes every mutation to linked stake
   delegations. */

struct fd_stake_pubkeys;
typedef struct fd_stake_pubkeys fd_stake_pubkeys_t;

FD_PROTOTYPES_BEGIN

/* fd_stake_pubkeys_align is used to get the alignment for the stake
   pubkey structure. */

ulong
fd_stake_pubkeys_align( void );

/* fd_stake_pubkeys_footprint is used to get the footprint for the stake
   pubkey structure.  max_pubkeys is the capacity of the structure and
   expected_pubkeys sizes the internal map. */

ulong
fd_stake_pubkeys_footprint( ulong max_pubkeys,
                            ulong expected_pubkeys );

/* fd_stake_pubkeys_new creates a new stake pubkey structure. */

void *
fd_stake_pubkeys_new( void * mem,
                      ulong  seed,
                      ulong  max_pubkeys,
                      ulong  expected_pubkeys );

/* fd_stake_pubkeys_join joins the caller to the stake pubkey
   structure. */

fd_stake_pubkeys_t *
fd_stake_pubkeys_join( void * mem );

/* fd_stake_pubkeys_lock and fd_stake_pubkeys_unlock acquire and release
   the shared stake pubkeys and delegations write lock. */

void
fd_stake_pubkeys_lock( fd_stake_pubkeys_t * pubkeys );

void
fd_stake_pubkeys_unlock( fd_stake_pubkeys_t * pubkeys );

/* fd_stake_pubkeys_acquire finds or inserts pubkey, increments its
   reference count, and returns its stable index. */

uint
fd_stake_pubkeys_acquire( fd_stake_pubkeys_t * pubkeys,
                          fd_pubkey_t const *  pubkey );

/* fd_stake_pubkeys_release decrements the reference count for
   pubkey_idx.  In fallback mode, it validates the live index but leaves
   the reference count unchanged because all entries remain pinned until
   refresh or reset. */

void
fd_stake_pubkeys_release( fd_stake_pubkeys_t * pubkeys,
                          uint                 pubkey_idx );

/* fd_stake_pubkeys_retain increments the reference count for an
   existing pubkey_idx. */

void
fd_stake_pubkeys_retain( fd_stake_pubkeys_t * pubkeys,
                         uint                 pubkey_idx );

/* fd_stake_pubkeys_query returns the pubkey stored at a live index. */

fd_pubkey_t const *
fd_stake_pubkeys_query( fd_stake_pubkeys_t const * pubkeys,
                        uint                       pubkey_idx );

ulong
fd_stake_pubkeys_cnt( fd_stake_pubkeys_t const * pubkeys );

uint
fd_stake_pubkeys_iter_next( fd_stake_pubkeys_t const * pubkeys,
                            ulong *                    cursor );

int
fd_stake_pubkeys_fallback( fd_stake_pubkeys_t const * pubkeys );

void
fd_stake_pubkeys_fallback_enter( fd_stake_pubkeys_t * pubkeys,
                                 fd_pubkey_t const *  pubkey );

/* Refresh runs at boot with no live fork or rewards references.  These
   helpers remove stale entries despite fallback mode, normalize each
   surviving reference count to the root's single reference, and leave
   fallback mode when every surviving pubkey fits in the root. */

void
fd_stake_pubkeys_refresh_remove( fd_stake_pubkeys_t * pubkeys,
                                 uint                 pubkey_idx );

void
fd_stake_pubkeys_refresh_fini( fd_stake_pubkeys_t * pubkeys,
                               ulong                root_cnt );

/* Reset invalidates every outstanding index. */

void
fd_stake_pubkeys_reset( fd_stake_pubkeys_t * pubkeys );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_stake_pubkeys_h */
