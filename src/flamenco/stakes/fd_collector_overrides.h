#ifndef HEADER_fd_src_flamenco_stakes_fd_collector_overrides_h
#define HEADER_fd_src_flamenco_stakes_fd_collector_overrides_h

#include "../fd_flamenco_base.h"

/* fd_collector_overrides_t tracks SIMD-0232 commission collectors
   that differ from their defaults (inflation: the vote account,
   block revenue: the node identity).  A query miss means "use the
   default".

   Entries are captured once per epoch boundary from the vote account
   state at the start of the new epoch E, and tagged with E:
   inflation rewards distribution (at the boundary of E) queries tag
   E; block revenue collection during E queries tag E-1, the state
   its leader schedule was derived from.

   Vote account state can differ across forks crossing the boundary,
   so entries carry a fork membership bitmask.  Fork ids rotate at
   every boundary.  Entry content is immutable after creation: forks
   capturing identical state share an entry via their fork bit;
   divergent state gets a distinct entry.

   Concurrent queries are allowed; mutating operations take an
   exclusive lock internally.  The structure is only modified during
   boot and at epoch boundaries. */

#define FD_COLLECTOR_OVERRIDES_ALIGN (128UL)

/* Fork ids must fit in the 128-bit membership mask. */
#define FD_COLLECTOR_OVERRIDES_MAX_FORK_WIDTH (127UL)

/* Query result flags */
#define FD_COLLECTOR_OVERRIDE_INFLATION (1)
#define FD_COLLECTOR_OVERRIDE_BLOCK     (2)

struct fd_collector_overrides;
typedef struct fd_collector_overrides fd_collector_overrides_t;

FD_PROTOTYPES_BEGIN

ulong
fd_collector_overrides_align( void );

/* fd_collector_overrides_footprint returns the footprint for at most
   max_overrides entries.  Entries per epoch tag are bounded by the
   VAT-admitted vote account set (FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS):
   the admitted-set capture path enforces the bound directly, and the
   pre-VAT capture path creates no entries because non-default
   collectors require the custom_commission_collector feature, which
   is assumed inactive before the validator admission ticket.  Up to
   three tags can be live at once across the fork tree: forks that
   have not crossed the epoch boundary still query tags E-2/E-1 while
   forks past it hold E-1/E.  Boundary forks that captured divergent
   state add one entry per distinct content, at most one per
   boundary-crossing fork (max_fork_width).  Size for the product of
   the three; exhaustion is a fail-stop (FD_LOG_CRIT in
   fd_collector_overrides_upsert) rather than a silent fallback to
   default collectors. */

ulong
fd_collector_overrides_footprint( ulong max_overrides );

void *
fd_collector_overrides_new( void * shmem,
                            ulong  max_overrides,
                            ulong  seed );

fd_collector_overrides_t *
fd_collector_overrides_join( void * shmem );

/* fd_collector_overrides_new_child allocates a fork id for a fork
   crossing the epoch boundary.  The new fork starts with no visible
   entries; call fd_collector_overrides_inherit to make the parent's
   entries visible. */

ushort
fd_collector_overrides_new_child( fd_collector_overrides_t * co );

/* fd_collector_overrides_inherit makes the parent fork's entries with
   epoch >= min_epoch visible on the child fork.  Entries older than
   min_epoch can no longer be queried by the child and are dropped
   from it. */

void
fd_collector_overrides_inherit( fd_collector_overrides_t * co,
                                ushort                     parent_idx,
                                ushort                     child_idx,
                                ulong                      min_epoch );

/* fd_collector_overrides_advance_root moves the root to root_idx.
   All other forks are released and entries only visible on them are
   freed.  A no-op if root_idx is already the root. */

void
fd_collector_overrides_advance_root( fd_collector_overrides_t * co,
                                     ushort                     root_idx );

/* fd_collector_overrides_purge_child releases a non-root fork.  A
   no-op if fork_idx is the root. */

void
fd_collector_overrides_purge_child( fd_collector_overrides_t * co,
                                    ushort                     fork_idx );

/* fd_collector_overrides_reset returns the structure to its initial
   state (used when loading a new snapshot manifest). */

void
fd_collector_overrides_reset( fd_collector_overrides_t * co );

ushort
fd_collector_overrides_get_root_idx( fd_collector_overrides_t * co );

/* fd_collector_overrides_upsert records the non-default collectors
   for (pubkey, epoch) on the given fork.  Pass has_inflation /
   has_block=0 for a collector that is default (at least one must be
   set).  A fork joins an existing identical entry, else a new entry
   is created. */

void
fd_collector_overrides_upsert( fd_collector_overrides_t * co,
                               ushort                     fork_idx,
                               ulong                      epoch,
                               fd_pubkey_t const *        pubkey,
                               int                        has_inflation,
                               fd_pubkey_t const *        inflation,
                               int                        has_block,
                               fd_pubkey_t const *        block );

/* fd_collector_overrides_query returns which collectors of
   (pubkey, epoch) are overridden on the given fork, as a bitwise OR
   of FD_COLLECTOR_OVERRIDE_{INFLATION,BLOCK} (0 if none: use the
   defaults).  NULL out params are skipped; out params are only
   written for overridden collectors. */

int
fd_collector_overrides_query( fd_collector_overrides_t * co,
                              ushort                     fork_idx,
                              ulong                      epoch,
                              fd_pubkey_t const *        pubkey,
                              fd_pubkey_t *              inflation_out_opt,
                              fd_pubkey_t *              block_out_opt );

/* fd_collector_overrides_ele_cnt returns the number of live entries
   (across all forks and epochs).  Intended for tests and metrics. */

ulong
fd_collector_overrides_ele_cnt( fd_collector_overrides_t * co );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_collector_overrides_h */
