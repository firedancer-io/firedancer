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

   Each fork owns a compact set of entries.  Two sets are cached in
   shared memory; additional sets spill to a boot-created, unlinked
   file.  Inheritance copies the retained epochs into the child set.
   Fork ids rotate at every boundary.

   All operations lock internally.  Queries may load a spilled set
   and evict a dirty set, so readers also require the spill descriptor
   and write access to shared memory. */

#define FD_COLLECTOR_OVERRIDES_FD        (123454)
#define FD_COLLECTOR_OVERRIDES_CACHE_CNT (2UL)

#define FD_COLLECTOR_OVERRIDES_ALIGN (128UL)

/* Maximum number of child forks represented alongside the root. */
#define FD_COLLECTOR_OVERRIDES_MAX_FORK_WIDTH (4096UL)

/* Query result flags */
#define FD_COLLECTOR_OVERRIDE_INFLATION (1)
#define FD_COLLECTOR_OVERRIDE_BLOCK     (2)

struct fd_collector_overrides;
typedef struct fd_collector_overrides fd_collector_overrides_t;

FD_PROTOTYPES_BEGIN

ulong
fd_collector_overrides_align( void );

/* max_overrides bounds entries in each fork set.  Reserve room for
   three epoch tags times FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS, independent
   of fork width.  Only two full sets are resident; per-fork counts and
   disk-valid bits remain in memory.  Exhaustion fails closed rather
   than silently falling back to default collectors. */

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
   set).  Repeating an identical capture within a fork is a no-op. */

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
   (summed across all forks and epochs, including inherited copies
   and spilled sets).  Intended for tests and metrics. */

ulong
fd_collector_overrides_ele_cnt( fd_collector_overrides_t * co );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_collector_overrides_h */
