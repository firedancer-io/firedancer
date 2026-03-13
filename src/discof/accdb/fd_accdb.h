#ifndef HEADER_fd_src_accdb_fd_accdb_h
#define HEADER_fd_src_accdb_fd_accdb_h

/* An accounts database is a key-value store for account information,
   supporting fast queries and updates.  At the core it's kind of
   like,

    HashMap<Pubkey, AccountInfo>

   But with some special properties.  First, it's fork aware, we
   need to ask for AccountInfo as-of a specific fork.  In Agave,
   this is implemented like

    HashMap<Pubkey, BTreeMap<Slot, AccountInfo>>

   Then the query proceeds by getting the BTreeMap for a Pubkey, and
   iterating through it from highest to lowest slot, until we find
   one that's an ancestor of the requested slot.

   For this implementation, we use chained hash tables to store the
   index.  Each pubkey+fork combination has at most one entry.
   Lookups walk the hash chain, filtering by ancestry using a
   per-fork bitset of ancestors (descends_set).  The hash table
   capacity is fixed at initialization time.

   There's another special property, which is persistence.  We don't
   want to consume much memory for the accounts database, as it can
   grow very large.  We actually want to be able to operate the
   accounts database with nothing in memory except the index.
   Currently, the chain is small enough that we can keep the entire
   index in memory, although in future this could also be stored on
   disk.

   Reads and writes are equally likely in the accounts database, and
   we expect the storage medium to be an NVMe SSD, which benefits
   from sequential writes.  This leads to the following design:

    - The account data is stored in a single large file.  The file
      is divided into partitions of configurable size.  Accounts may
      not span partitions.

    - Each partition contains as many tightly packed accounts as
      possible, with no padding.

    - Account writes are append only and sequential, to the end of
      the last partition.

    - When a fork is rooted, any prior version of an account
      (written on an ancestor fork) that was updated on the rooted
      fork is tombstoned.

    - When a fork is rooted, any versions of accounts on a
      competing fork which is now dead are tombstoned.

    - If the freed bytes in a partition reach 30% of partition_sz,
      that partition is queued for compaction.  Compaction copies
      live accounts to the end of the last partition, then frees
      the old partition.  This happens incrementally, one account
      per call to fd_accdb_compact.

    - The accounts database is single threaded, and accessed by a
      single control plane tile which is responsible for receiving
      requests from other tiles, and returning responses.

    - The accounts database is not fault tolerant and does not
      support recovery.  It is expected the database will be
      rebuilt from a snapshot on every restart. */

#include "../../util/fd_util_base.h"

/* FD_ACCDB_ALIGN describes the alignment needed for an accdb.
   ALIGN is a positive integer power of 2. */

#define FD_ACCDB_ALIGN (4096UL)

#define FD_ACCDB_MAGIC (0xf17eda2ce7accdb0UL) /* firedancer accdb version 0 */

typedef struct { ushort val; } fd_accdb_fork_id_t;

struct fd_accdb_private;
typedef struct fd_accdb_private fd_accdb_t;

struct fd_accdb_metrics {
   ulong accounts_total;
   ulong accounts_capacity;
   ulong bytes_read;
   ulong bytes_written;
   ulong accounts_read;
   ulong accounts_written;
   ulong disk_allocated_bytes;
   ulong disk_used_bytes;
   int   in_compaction;
   ulong compactions_requested;
   ulong compactions_completed;
   ulong accounts_relocated;
   ulong accounts_relocated_bytes;
   ulong partitions_freed;
};

typedef struct fd_accdb_metrics fd_accdb_metrics_t;

FD_PROTOTYPES_BEGIN

/* fd_accdb_{align,footprint} give the needed alignment and footprint
   of a memory region suitable to hold an accounts database.
   fd_accdb_align returns the same value as FD_ACCDB_ALIGN.

   max_accounts is the maximum number of unique (pubkey, fork)
   entries the index can hold.  Must be less than UINT_MAX.
   max_live_slots is the maximum number of forks that can be alive
   (attached but not yet rooted or purged) at any time.  Must be
   less than USHORT_MAX.  max_account_writes_per_slot is the maximum
   number of distinct account writes per fork.  partition_cnt is the
   maximum number of partitions the underlying file can hold.

   fd_accdb_new formats a memory region with suitable alignment and
   footprint for holding an accounts database.  Assumes shmem points
   to the first byte of the memory region owned by the caller.
   Returns shmem on success and NULL on failure (logs details).  The
   memory region will be owned by the accounts database on
   successful return.  The caller is not joined on return.

   partition_cnt is the maximum number of partitions in the accounts
   file.  partition_sz is the size of each partition in bytes.

   fd_accdb_join joins the caller to an accounts database.  Assumes
   shaccdb points to the first byte of the memory region holding
   the accounts database.  fd should be the open file descriptor of
   the underlying accounts database file.  The accounts database
   will resize, write to, and read from this file as needed.  The
   accounts database takes an interest in the file descriptor, and
   it should not be closed until the caller leaves the join.
   Returns a local handle to the join on success (this is not
   necessarily a simple cast of the address) and NULL on failure
   (logs details). */

FD_FN_CONST ulong
fd_accdb_align( void );

FD_FN_CONST ulong
fd_accdb_footprint( ulong max_accounts,
                    ulong max_live_slots,
                    ulong max_account_writes_per_slot,
                    ulong partition_cnt );

void *
fd_accdb_new( void * shmem,
              ulong  max_accounts,
              ulong  max_live_slots,
              ulong  max_account_writes_per_slot,
              ulong  partition_cnt,
              ulong  partition_sz,
              ulong  seed );

fd_accdb_t *
fd_accdb_join( void * shaccdb,
               int    fd );

/* fd_accdb_attach_child allocates a new fork as a child of
   parent_fork_id and returns the new fork's id.  This must be done
   any time a new fork is being inserted into the accounts database,
   so that the accounts database can maintain ancestry information
   in order to support queries correctly.

   To create the initial root fork, pass a sentinel value with
   val==USHORT_MAX as parent_fork_id.  This must be done exactly
   once, before any other fork operations.

   For non-root forks, parent_fork_id must refer to a fork that has
   already been attached.  The ancestry must form a tree and it is
   undefined behavior to create cycles. */

fd_accdb_fork_id_t
fd_accdb_attach_child( fd_accdb_t *       accdb,
                       fd_accdb_fork_id_t parent_fork_id );

/* fd_accdb_advance_root advances the root of the accounts database
   to the given fork_id.  fork_id must be a direct child of the
   current root (i.e. fork->parent_id equals the current
   root_fork_id).

   Any competing sibling forks (and their entire subtrees) are
   removed.  For accounts updated on the newly rooted fork, any
   older versions on ancestor forks are tombstoned for later
   compaction.  After this call the old root fork slot is freed
   and fork_id becomes the new root. */

void
fd_accdb_advance_root( fd_accdb_t *       accdb,
                       fd_accdb_fork_id_t fork_id );

/* fd_accdb_read retrieves the account information for a given
   pubkey as-of the provided fork.  Returns 1 on success and fills
   all non-NULL out parameters.  Returns 0 if the account does not
   exist on the given fork or any of its ancestors back to the
   current root, and out parameter values are undefined.

   Query is fork-aware, based on the tree parentage information
   established in fd_accdb_attach_child, so the account could have
   been written on any ancestor fork of the provided fork.  Queries
   for forks prior to the current root are not supported, as that
   data may have been discarded.  fork_id must refer to a fork that
   has been attached into the tree.

   The caller must guarantee that at least one fork has been
   attached via fd_accdb_attach_child before calling read (i.e.
   root_fork_id is valid). */

int
fd_accdb_read( fd_accdb_t *       accdb,
               fd_accdb_fork_id_t fork_id,
               uchar const *      pubkey,
               ulong *            out_lamports,
               uchar *            out_data,
               ulong *            out_data_len,
               uchar              out_owner[ static 32UL ] );

/* fd_accdb_write writes the account information for a given pubkey
   on the given fork.  It is valid to write the same account on the
   same fork multiple times; if an entry already exists for this
   (pubkey, fork) pair, the old data is replaced and the freed disk
   space is tracked for compaction.

   The write function assumes the caller respects certain rules
   about how the chain progresses.  In particular, once a fork is
   rooted, no further writes to that fork or any fork before it
   should be made.

   data may be NULL if the account has no data, in which case
   data_len must be 0.  If data is not NULL, data_len must be less
   than or equal to 10 MiB.  owner must point to a valid 32-byte
   pubkey. */

void
fd_accdb_write( fd_accdb_t *       accdb,
                fd_accdb_fork_id_t fork_id,
                uchar const *      pubkey,
                ulong              lamports,
                uchar const *      data,
                ulong              data_len,
                uchar const *      owner );

/* fd_accdb_compact compacts the accounts database, removing any
   tombstoned accounts, and freeing up space in the underlying file.

   This function is idempotent and can be called as often as
   possible without any adverse effect.  If there is no compaction
   needing to be done it returns quickly.

   *charge_busy is set to 1 if any compaction work actually
   happened.

   Each call moves at most one account before returning.  It is
   suggested to call compact in the background when there is no
   other activity on the accounts database. */

void
fd_accdb_compact( fd_accdb_t * accdb,
                  int *        charge_busy );

/* fd_accdb_purge removes the provided fork and all of its
   descendants from the accounts database.  This is an extremely
   rare operation, used to handle cases where a leader equivocated
   and produced two competing blocks for the same slot.

   All accounts written on the purged fork and any child or
   grandchild forks are removed from the index, and their disk
   space is freed for compaction.  The ancestry information for all
   purged forks is also removed. */

void
fd_accdb_purge( fd_accdb_t *       accdb,
                fd_accdb_fork_id_t fork_id );

/* fd_accdb_metrics returns a pointer to the metrics structure for
   the accounts database.  The metrics structure is updated by the
   accounts database as it's used.  The returned pointer remains
   valid for the lifetime of the join. */

fd_accdb_metrics_t const *
fd_accdb_metrics( fd_accdb_t const * accdb );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_accdb_fd_accdb_h */
