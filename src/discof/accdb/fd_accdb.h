#ifndef HEADER_fd_src_accdb_fd_accdb_h
#define HEADER_fd_src_accdb_fd_accdb_h

/* An accounts database is a key-value store for account information,
   supporting fast queries and updates.  At the core it's kind of like,

    HashMap<Pubkey, AccountInfo>

   But with some special properties.  First, it's fork aware, we need to
   ask for AccountInfo as-of a specific slot.  In Agave, this is
   implemented like

    HashMap<Pubkey, BTreeMap<Slot, AccountInfo>>

   Then the query proceeds by getting the BTreeMap for a Pubkey, and
   iterating through it from highest to lowest slot, until we find one
   that's an ancestor of the requested slot.

   For this implementation, we use a single bplus tree to store the map
   instead.  The bplus tree size is fixed at initialization time, and it
   looks basically like

    BTree<(Pubkey, Slot), AccountInfo>

   There's another special property, which is persistence.  We don't
   want to consume much memory for the accounts database, as it can grow
   very large.  We actually want to be able to operate the accounts
   database with nothing in memory except the index.  Currently, the
   chain is small enough that we can keep the entire index in memory,
   although in future this could also be stored on disk.

   Reads and writes are equally likely in the accounts database, and we
   expect the storage medium to be an NVMe SSD, which benefits from
   sequential writes.  This leads to the following design:

    - The account data is stored in a single large file.  The file is
      divided into 1GiB partitions.  Accounts may not span partitions.

    - Each partition contains as many tightly packed accounts as
      possible, with no padding.

    - Account writes are append only and sequential, to the end of the
      last partition.

    - When a slot is rooted, any prior version of some account (written
      in an older slot) updated in the slot are tombstoned.

    - When a slot is rooted, any versions of accounts on a competing
      fork which is now dead are tombstoned.

    - If a partition drops below 70% of accounts in it being alive (non-
      tombstoned), it is compacted, by copying the live accounts to the
      end of the last partition, and then freeing the old partition.
      This compaction happens in the background, account by account, as
      the tile is free.

    - The accounts database is single threaded, and accessed by a single
      control plane tile which is responsible for receiving requests
      from other tiles, and returning responses.

    - The accounts database is not fault tolerant and does not support
      recovery.  It is expected the database will be rebuilt from a
      snapshot on every restart.

   Finally, some accounts are accessed more frequently than others, the
   "hot" accounts.  These are kept in memory up to a certain limit.
   These accounts do not get written out to disk, except if the cache
   fills up, in which case the least recently used accounts are
   evicted to disk. */

#include "../../util/fd_util.h"

/* FD_ACCDB_ALIGN describe the alignment needed for an accdb.  ALIGN
   should be a positive integer power of 2.  The footprint is dynamic
   depending on the cache size. */

#define FD_ACCDB_ALIGN (4096UL)

#define FD_ACCDB_MAGIC (0xf17eda2ce7accdb0UL) /* firedancer accdb version 0 */

struct fd_ancestors;
typedef struct fd_ancestors fd_ancestors_t;

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
   cache_footprint is the footprint of the in-memory account cache in
   bytes.  max_unrooted_slots is the maximum number of live
   unrooted slots that the validator can have active at any one time.
   max_accounts is the maximum number of accounts that the accounts
   database will hold.

   fd_accdb_new formats memory region with suitable alignment and
   footprint suitable for holding an accounts database.  Assumes shmem
   points on the caller to the first byte of the memory region
   owned by the caller to use.  Returns shmem on success and NULL on
   failure (logs details).  The memory region will be owned by the
   accounts database on successful return.  The caller is not joined on
   return.  cache_footprint is the footprint of the in-memory account
   cache in bytes.  max_unrooted_slots is the maximum number of live
   unrooted slots that the validator can have active at any one time.

   fd_accdb_join joins the caller to an accounts database.  Assumes
   shaccdb points to the first byte of the memory region holding
   the accounts database.  fd should be the open file descriptor of the
   underlying accounts database file.  The accounts database will resize
   write to, and read from this file as needed.  The accounts database
   takes an interest in the file descriptor, and it should not be closed
   until the caller leaves the join.  Returns a local handle to the join
   on success (this is not necessarily a simple cast of the address) and
   NULL on failure (logs details). */

FD_FN_CONST ulong
fd_accdb_align( void );

FD_FN_CONST ulong
fd_accdb_footprint( ulong max_accounts,
                    ulong max_unrooted_slots,
                    ulong cache_footprint );

void *
fd_accdb_new( void * shmem,
              ulong  max_accounts,
              ulong  max_unrooted_slots,
              ulong  cache_footprint,
              ulong  seed );

fd_accdb_t *
fd_accdb_join( void * shaccdb,
               int    fd );

/* fd_accdb_initialize initializes the accounts database, setting the
   root slot to the provided slot.  This is the first call that should
   be made to the accounts database, and it must be called before any
   other operations are performed on the accounts database. */

void
fd_accdb_initialize( fd_accdb_t * accdb,
                     ulong        root_slot );

/* fd_accdb_attach_child marks the provided slot as being a child of the
   parent slot.  This must be done any time a new slot is being inserted
   into the accounts database, so that the accounts database can
   maintain ancestry information in order to support queries correctly.

   A child cannot be attached to a parent slot if the parent slot itself
   has not been attached to a parent slot.  The ancestry must form a
   tree and it is undefined behavior to attach a child to a slot
   without a parent, or to attach a child to a slot that is not the
   parent of the child.
   
   In some rare cases, it is valid to attach the same child to a new
   parent slot, if the original child slot is first purged.  See
   fd_accdb_purge for more details. */

void
fd_accdb_attach_child( fd_accdb_t * accdb,
                       ulong        slot,
                       ulong        parent_slot );

/* fd_accdb_root marks the provided slot as the root of the accounts
   database.  This means that all accounts in this slot and all slots
   before it are now considered "frozen" and cannot be updated anymore.
   
   Any accounts updated in the provided slot are considered canonical,
   and earlier versions of those accounts are tombstoned for later
   compaction.  In addition, any accounts that were updated in a
   competing fork that is now dead are also tombstoned. */

void
fd_accdb_root( fd_accdb_t * accdb,
               ulong        slot );

/* fd_accdb_read retrieves the account information for a given pubkey
   as-of the provided slot.  Returns 1 on success, if the account
   exists, and all out parameters will be filled, and out_lamports will
   be non-zero (an account with no lamports is considered non-existent).
   
   Query is fork-aware, based on the tree parentage information
   established in fd_accdb_attach_child, so the account could have been
   updated on any ancestor slot of the provided slot.  Query is not an
   exact AS-OF query, though.  You cannot ask for data AS-OF a slot
   prior to the current root slot, as it has been discarded.  Slot must
   be equal to or greater than the current root slot, and it must be a
   slot which has been attached into the tree with attach_child.

   Querying never results in an error or corrupt data, it will either
   return an account or it will report that the account does not exist.

   On failure, returns 0, and out parameter values are undefined. */

int
fd_accdb_read( fd_accdb_t *  accdb,
               ulong         slot,
               uchar const * pubkey,
               ulong *       out_lamports,
               uchar *       out_data,
               ulong *       out_data_len,
               uchar         out_owner[ static 32UL ] );

/* fd_accdb_write writes the account information for a given pubkey in
   the accounts database.  The slot is the slot at which the update is
   being made.  It is valid to update an account at the same slot
   multiple times, if the account exists, it will be updated with the
   provided values, and any previous data will be replaced.

   The update function assumes the caller is respecting certain rules
   about how the chain progresses.  In particular, that once a slot is
   rooted, no updates to accounts in that slot, or slots before it will
   be made.

   If the account does not exist, it will be created with the provided
   lamports, executable, data, owner and rent epoch.  Lamports must be
   non-zero, and executable must be either 0 or 1.  Data may be NULL if
   the account has no data, and data_len must be 0 in that case.  If
   data is not NULL, it must be a pointer to a valid memory region of
   size data_len, and data_len must be less than or equal to the maximum
   data size for the account (currently 10MiB).  Owner must be a valid
   pubkey of size 32 bytes, and rent_epoch must be a valid epoch number. */

void
fd_accdb_write( fd_accdb_t *  accdb,
                ulong         slot,
                uchar const * pubkey,
                ulong         lamports,
                uchar const * data,
                ulong         data_len,
                uchar const * owner );

/* fd_accdb_compact compacts the accounts database, removing any
   tombstoned accounts, and freeing up space in the underlying file.
   
   This function is idempotent and can be called as often as possible
   without any adverse effect.  If there is no compaction needing to be
   done it return quickly.

   charge_busy should be set to 1 if any compaction work actually
   happened.
   
   Calling compact is always a fast operation, as it only moves at most
   one account at a time before returning.  It is suggested to call
   compact in the background when there is no other activity on the
   accounts database. */

void
fd_accdb_compact( fd_accdb_t * accdb,
                  int *        charge_busy );

/* fd_accdb_purge removes the provided slot from the accounts database.
   This is an extremely rare operation that is only used to handle cases
   where a leader equivocated and produced two blocks at the same slot.

   The slot must be a child of the current root slot, although it may
   have children of its own, which will also be purged.

   In this case, the slot is purged from the accounts database, and any
   children of the slot are also purged.  Then replay can start anew
   from the heaviest fork.

   When a slot is purged, the ancestor information of the slot and all
   child slots (as established by fd_accdb_attach_child) is also
   removed, and the caller will need to re-attach any children. */

void
fd_accdb_purge( fd_accdb_t * accdb,
                ulong        slot );

/* fd_accdb_metrics returns a pointer to the metrics structure for the
   accounts database.  The metrics structure is updated by the accounts
   database as it's used. */

fd_accdb_metrics_t const *
fd_accdb_metrics( fd_accdb_t const * accdb );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_accdb_fd_accdb_h */
