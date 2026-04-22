#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_h

#include "fd_accdb_shmem.h"
#include "../../util/bits/fd_bits.h"

/* The accdb is a fork aware database that can be queried to get the
   current state of any accounts as-of a given fork, and update them. */

#define FD_ACCDB_ALIGN     (128UL)
#define FD_ACCDB_FOOTPRINT (128UL)

struct fd_accdb_private;
typedef struct fd_accdb_private fd_accdb_t;

struct fd_accdb_fork_id { ushort val; };
typedef struct fd_accdb_fork_id fd_accdb_fork_id_t;

struct fd_accdb_entry {
  uchar   pubkey[ 32UL ];
  uchar   owner[ 32UL ];
  ulong   lamports;
  int     executable;

  ulong   data_len;
  uchar * data;

  uchar   prior_owner[ 32UL ];
  ulong   prior_lamports;
  int     prior_executable;
  ulong   prior_data_len;
  uchar * prior_data;

  int     commit;

  int     _writable;
  int     _overwrite;

  ushort  _fork_id;
  uint    _generation;
  ulong   _acc_map_idx;

  ulong   _original_size_class;
  ulong   _original_cache_idx;

  struct {
    ulong destination_cache_idx[ 8UL ];
  } _write;
};

typedef struct fd_accdb_entry fd_accdb_entry_t;

FD_PROTOTYPES_BEGIN

static inline ulong
fd_xxh3_mul128_fold64( ulong lhs, ulong rhs ) {
  uint128 product = (uint128)lhs * (uint128)rhs;
  return (ulong)product ^ (ulong)( product>>64 );
}

static inline ulong
fd_xxh3_mix16b( ulong i0, ulong i1,
                ulong s0, ulong s1,
                ulong seed ) {
  return fd_xxh3_mul128_fold64( i0 ^ (s0 + seed), i1 ^ (s1 - seed) );
}

FD_FN_PURE static inline ulong
fd_accdb_hash( uchar const key[ 32 ],
               ulong       seed ) {
  ulong k0 = FD_LOAD( ulong, key+ 0 );
  ulong k1 = FD_LOAD( ulong, key+ 8 );
  ulong k2 = FD_LOAD( ulong, key+16 );
  ulong k3 = FD_LOAD( ulong, key+24 );
  ulong acc = 32 * 0x9E3779B185EBCA87ULL;
  acc += fd_xxh3_mix16b( k0, k1, 0xbe4ba423396cfeb8UL, 0x1cad21f72c81017cUL, seed );
  acc += fd_xxh3_mix16b( k2, k3, 0xdb979083e96dd4deUL, 0x1f67b3b7a4a44072UL, seed );
  acc = acc ^ (acc >> 37);
  acc *= 0x165667919E3779F9ULL;
  acc = acc ^ (acc >> 32);
  return acc;
}

FD_FN_CONST ulong
fd_accdb_align( void );

FD_FN_CONST ulong
fd_accdb_footprint( ulong max_live_slots );

void *
fd_accdb_new( void *             ljoin,
              fd_accdb_shmem_t * shmem,
              int                fd );

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

   Any competing sibling forks (and their entire subtrees) are removed.
   For accounts updated on the newly rooted fork, any older versions on
   ancestor forks are tombstoned for later compaction.  After this call
   the old root fork slot is freed and fork_id becomes the new root.

   IMPORTANT: The caller must guarantee that all outstanding
   acquire/release pairs on every sibling of fork_id (and their entire
   subtrees) have completed before calling advance_root.  advance_root
   implicitly purges those sibling subtrees, which frees their fork pool
   slots for recycling.

   Once a fork is rooted, its generation becomes the new
   root_generation.  Concurrent acquires that observe the new root will
   use the generation fast path (generation <= root_generation) for all
   accounts from that fork and its ancestors, bypassing descends_set
   entirely.  This is what makes fork pool slot recycling safe: by the
   time a slot is freed and reusable, no reader will ever consult
   descends_set for the old fork_id. */

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
   purged forks is also removed.

   IMPORTANT: The caller must guarantee that all outstanding
   acquire/release pairs on the purged fork and every descendant
   have completed before calling purge.  The same fork pool slot
   recycling hazard described for advance_root applies here. */

void
fd_accdb_purge( fd_accdb_t *       accdb,
                fd_accdb_fork_id_t fork_id );

/* fd_accdb_acquire brings all of the requested accounts as-of the given
   fork_idx into the cache, and refcnts them in the cache so they cannot
   be evicted until later released.

   fork_idx is the fork index from replay to query as-of, and must exist
   for the entire duration of the acquire call, meaning, whoever is
   acquiring must have a refcnt on the bank corresponding to fork_idx,
   and not release it until after the accounts are acquired.  It is safe
   to release the bank after the acquire call returns, and this will not
   cause the acquired accounts to be evicted from the cache.

   pubkeys_cnt is the number of accounts to acquire, and pubkeys is an
   array of pointers to the 32-byte pubkeys of the accounts to acquire.
   writable is an array of flags indicating whether each corresponding
   account in pubkeys is being acquired for read (0) or write (1).
   Writes provide a temporary buffer of 10MiB in all cases, which the
   caller can use for staging changes to the data, and this allows
   account resizing, or cancelling of any data written (for example if a
   transaction fails) without needing to restore it.  If an account is
   acquired for write, the caller must set the commit bit on the entry
   to non-zero to have the changes written back to the database on
   release, or leave it at zero to discard the changes.  The commit bit
   must be set even if only the metadata has changed.

   IMPORTANT: The caller must guarantee that for any given (pubkey,
   fork) pair, there is no concurrent acquire that holds a writable
   entry while another acquire for the same account on the same fork is
   outstanding (whether readable or writable).  Specifically:

     - Multiple concurrent read-only acquires of the same account on the
       same fork are permitted.
     - A writable acquire of an account on a given fork must not overlap
       with any other acquire (read or write) of that same account on
       that same fork.
     - Acquires of the same account on _different_ forks are always safe
       and may overlap freely, provided that all releases on an ancestor
       fork have completed before any acquire on a descendant fork
       begins.  In particular, a fork must finish all of its transaction
       execution (including committing or cancelling every writable
       account) before a child fork is attached and begins acquiring.
       This is naturally guaranteed by the replay scheduler, which does
       not activate a child block until the parent block is fully done.
       Concurrent acquires across unrelated sibling forks have no
       ordering requirement.

   Violating this contract is undefined behavior and will likely crash
   with an assertion failure inside the cache refcount logic.  In
   practice, these constraints are naturally satisfied by the Solana
   execution model: each transaction has exclusive write locks on its
   writable accounts within a slot, the scheduler ensures no two
   concurrent transactions write to the same account on the same fork,
   and the replay scheduler serializes parent block completion before
   child block activation on the same fork chain.

   When a writable account is committed as an "overwrite" (same
   fork), the acc pool element's metadata fields (size, lamports,
   offset) are mutated in place, and the cache line's owner field is
   updated.  This is safe because these mutations
   only happen on the acc element whose generation matches the
   committing fork.  A concurrent acquire on a different fork cannot
   observe an in-place mutation of the same acc element for a child fork
   to even exist, the parent must be frozen and no longer undergoing
   modifications.  All acc pool fields are effectively immutable from
   the perspective of any concurrent cross-fork reader.

   out_entries is an array of pubkeys_cnt cache entries to be filled in
   with the acquired accounts.  The cache will fill the owner, lamports,
   data_len, and data fields of each entry if the acquire is successful,
   and the account exists.  If the account does not exist, the lamports
   field will be set to zero and other fields are undefined. */

void
fd_accdb_acquire( fd_accdb_t *          accdb,
                  fd_accdb_fork_id_t    fork_id,
                  ulong                 pubkeys_cnt,
                  uchar const * const * pubkeys,
                  int *                 writable,
                  fd_accdb_entry_t *    out_entries );

void
fd_accdb_acquire_a( fd_accdb_t *          accdb,
                    fd_accdb_fork_id_t    fork_id,
                    ulong                 pubkeys_cnt,
                    uchar const * const * pubkeys,
                    int *                 writable,
                    fd_accdb_entry_t *    out_entries );

void
fd_accdb_acquire_b( fd_accdb_t *          accdb,
                    fd_accdb_fork_id_t    fork_id,
                    ulong                 reserved_cnt,
                    ulong                 pubkeys_cnt,
                    uchar const * const * pubkeys,
                    int *                 writable,
                    fd_accdb_entry_t *    out_entries );

/* fd_accdb_release releases previously acquired accounts back to the
   cache, and if any of the released writable accounts have their commit
   bit set, the cache will write the changes back to the database.  The
   caller must guarantee that the entries being released were previously
   acquired and not yet released, and that the pubkeys in the entries
   match the pubkeys of the acquired accounts.  The entries need not be
   a specific set that was acquired together, although this is
   recommended.  The fork that each entry refers to must still exist
   (not yet purged or advanced past) at the time of release.  This
   includes forks that would be implicitly purged by a concurrent
   advance_root on a sibling — the caller must ensure advance_root
   is not called until all releases on affected forks have completed.
   Releasing accounts for a fork that has been purged or recycled is
   undefined behavior. */

void
fd_accdb_release( fd_accdb_t *       accdb,
                  ulong              entries_cnt,
                  fd_accdb_entry_t * entries );

fd_accdb_entry_t
fd_accdb_read_one( fd_accdb_t *       accdb,
                   fd_accdb_fork_id_t fork_id,
                   uchar const *      pubkey );

fd_accdb_entry_t
fd_accdb_write_one( fd_accdb_t *       accdb,
                    fd_accdb_fork_id_t fork_id,
                    uchar const *      pubkey );

/* TODO: Set commit, and add a version that doesn't? */
void
fd_accdb_unwrite_one( fd_accdb_t *       accdb,
                      fd_accdb_entry_t * entry );

void
fd_accdb_unread_one( fd_accdb_t *       accdb,
                     fd_accdb_entry_t * entry );

int
fd_accdb_exists( fd_accdb_t *       accdb,
                 fd_accdb_fork_id_t fork_id,
                 uchar const *      pubkey );

ulong
fd_accdb_lamports( fd_accdb_t *       accdb,
                   fd_accdb_fork_id_t fork_id,
                   uchar const *      pubkey );

int
fd_accdb_snapshot_write_one( fd_accdb_t *  accdb,
                             uchar const * pubkey,
                             ulong         slot,
                             ulong         lamports,
                             ulong         data_len,
                             int           executable );

/* fd_accdb_snapshot_write_four processes 4 accounts at once, using
   software prefetching to overlap hash chain memory latency with
   useful work.  Each pubkey[i] points to a 32-byte public key.
   Returns 0 on success. */

int
fd_accdb_snapshot_write_batch( fd_accdb_t *        accdb,
                               ulong               cnt,
                               uchar const * const pubkeys[],
                               ulong  const        slots[],
                               ulong  const        lamports[],
                               ulong  const        data_lens[],
                               int    const        executables[],
                               ulong *             accounts_ignored,
                               ulong *             accounts_replaced,
                               ulong *             accounts_loaded );

/* fd_accdb_background performs one unit of background work.

   THREADING MODEL

   The accdb API is split across three thread roles:

     T1 (replay): calls attach_child, advance_root, purge, acquire, and
         release.  attach_child runs inline on T1. advance_root and
         purge submit a command into a shared- memory slot and return
         immediately; the heavy work is deferred to T2.

     T2 (accdb tile / background): calls fd_accdb_background repeatedly.
         This is the only function T2 should call.

     T3 (executor tiles, 1..N): call acquire and release.

   acquire and release may be called concurrently from T1 and any number
   of T3 threads.  They must never be called concurrently with
   advance_root or purge on the same fork.

   fd_accdb_background must be called from exactly one thread (T2). It
   must not be called concurrently with itself.

   BEHAVIOR

   First checks for a pending advance_root or purge command from T1; if
   one is present it executes the command, sets *charge_busy to 1, and
   returns immediately without doing compaction. Otherwise, attempts one
   step of compaction at each layer, setting *charge_busy if work was
   done. */

void
fd_accdb_background( fd_accdb_t * accdb,
                     int *        charge_busy );

/* fd_accdb_metrics returns a pointer to the shared metrics counters
   for the given accdb instance.  The returned pointer remains valid
   for the lifetime of the underlying shmem. */

fd_accdb_shmem_metrics_t const *
fd_accdb_metrics( fd_accdb_t * accdb );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_h */
