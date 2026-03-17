#ifndef HEADER_fd_src_discof_accdb_fd_accdb_h
#define HEADER_fd_src_discof_accdb_fd_accdb_h

#include "fd_accdb_shmem.h"
#include "../../tango/fd_tango_base.h"

/* The accdb is a fork aware database that can be queried to get the
   current state of any accounts as-of a given fork, and update them. */

#define FD_ACCDB_ALIGN     (128UL)
#define FD_ACCDB_FOOTPRINT (128UL)

struct fd_accdb_private;
typedef struct fd_accdb_private fd_accdb_t;

struct fd_accdb_fork_id { ushort val; };
typedef struct fd_accdb_fork_id fd_accdb_fork_id_t;

struct fd_accdb_entry {
  uchar   owner[ 32UL ];
  ulong   lamports;
  ulong   data_len;

  uchar * data;
  uchar * sidecar;

  int     dirty;

  ulong   _cache_idx;
};

typedef struct fd_accdb_entry fd_accdb_entry_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_accdb_align( void );

FD_FN_CONST ulong
fd_accdb_footprint( ulong max_live_slots );

void *
fd_accdb_new( void *             ljoin,
              fd_accdb_shmem_t * shmem,
              fd_frag_meta_t *   request_mcache,
              uchar *            request_dcache,
              fd_frag_meta_t *   response_mcache,
              uchar *            response_dcache );

fd_accdb_t *
fd_accdb_join( void * shaccdb );

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

/* fd_accdb_advance_root advances the root of the accounts database to
   the given fork_id.  fork_id must be a direct child of the current
   root (i.e. fork->parent_id equals the current root_fork_id).

   Any competing sibling forks (and their entire subtrees) are
   removed.  For accounts updated on the newly rooted fork, any
   older versions on ancestor forks are tombstoned for later
   compaction.  After this call the old root fork slot is freed
   and fork_id becomes the new root. */

void
fd_accdb_advance_root( fd_accdb_t *       accdb,
                       fd_accdb_fork_id_t fork_id );

/* fd_accdb_purge removes the provided fork and all of its descendants
   from the accounts database.  This is an extremely rare operation,
   used to handle cases where a leader equivocated and produced two
   competing blocks for the same slot.

   All accounts written on the purged fork and any child or
   grandchild forks are removed from the index, and their disk
   space is freed for compaction.  The ancestry information for all
   purged forks is also removed. */

void
fd_accdb_purge( fd_accdb_t *       accdb,
                fd_accdb_fork_id_t fork_id );

/* fd_accdb_acquire brings all of the requested accounts as-of the given
   fork_idx into the cache, and refcnts them in the cache so they cannot
   be evicted until later released.  If any of the requested accounts is
   not found, or has a balance of zero, then the function returns -1 and
   no accounts are acquired, otherwise returns 0.

   fork_idx is the fork index from replay to query as-of, and must exist
   for the entire duration of the acquire call, meaning, whoever is
   acquiring must have a refcnt on the bank corresponding to fork_idx,
   and not release it until after the accounts are acquired.  It is safe
   to release the bank after the acquire call returns, and this will not
   cause the acquired accounts to be evicted from the cache.

   pubkeys_cnt is the number of accounts to acquire, and pubkeys is an
   array of pointers to the 32-byte pubkeys of the accounts to acquire.
   writable is an array of flags indicating whether each corresponding
   account in pubkeys is being acquired for read (0), inplace write (1),
   or full write (2).  Acquiring for in-place is a rare optimization
   that allows modification of the metadata, or non-resizing
   modification of the data, directly in the cache's data buffer.  Full
   writes provide a temporary sidecar buffer of 10MiB in all cases,
   which the caller can use for staging changes to the data, and this
   allows account resizing, or cancelling of any data written (for
   example if a transaction fails) without needing to restore it.  If an
   account is acquired for write or in-place write, and the underlying
   data is changed, the caller must set the dirty bit on the
   corresponding entry to 1 before releasing it, so the cache can write
   the changes back through to the database.  The dirty bit should not
   be set if only metadata has changed.

   The data pointer provided is an in-place buffer maintained by the
   cache, not a copy, and cannot be freely mutated.  If you write any
   modifications at all to the data buffer, you must acquire the account
   for write, and set the dirty bit before releasing, which will commit
   the changes back to the database.  If you make modifications to the
   data buffer, and then the transaction doing the modifications fails,
   the buffer must be restored and the dirty bit cleared before
   releasing.  For full writes, you must not modify the data pointer,
   and can only write to the sidecar buffer, and then set the dirty bit
   to have the cache write the sidecar buffer back to the database on
   release.  If the dirty bit is not set for a full write, the sidecar
   buffer is discarded and not written back to the database.

   out_entries is an array of pubkeys_cnt cache entries to be filled in
   with the acquired accounts.  The cache will fill the owner, lamports,
   data_len, and data fields of each entry if the acquire is successful. */

int
fd_accdb_acquire( fd_accdb_t *          accdb,
                  fd_accdb_fork_id_t    fork_id,
                  ulong                 pubkeys_cnt,
                  uchar const * const * pubkeys,
                  int *                 writable,
                  fd_accdb_entry_t *    out_entries );

/* fd_accdb_release releases previously acquired accounts back to the
   cache, and if any of the released accounts have their dirty bit set,
   the cache will write the changes back to the database.  The caller
   must guarantee that the entries being released were previously
   acquired and not yet released, and that the pubkeys in the entries
   match the pubkeys of the acquired accounts.  The entries need not be
   a specific set that was acquired together, although this is
   recommended.  The bank that each entry refers to does not still need
   to exist, and it is OK to release accounts for banks that have been
   released.

   If the dirty bit has been set on any writable entries, the changes
   are persisted back into the database, in accordance with the rules
   described above for acquire. */

void
fd_accdb_release( fd_accdb_t *       accdb,
                  ulong              entries_cnt,
                  fd_accdb_entry_t * entries );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_accdb_fd_accdb_h */
