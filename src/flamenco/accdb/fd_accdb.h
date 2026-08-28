#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_h

#include "fd_accdb_base.h"
#include "fd_accdb_shmem.h"

/* The accdb is a fork aware database that can be queried to get the
   current state of any accounts as-of a given fork, and update them. */

#define FD_ACCDB_ALIGN (128UL)

/* Well-known file descriptor numbers for the accounts database backing
   file.  Tiles inherit these from the parent process which dups the
   accounts file to these fds before fork+exec, so seccomp filters can
   pin syscalls to a fixed fd.  fd 123462 is reserved by XDP. */

#define FD_ACCDB_FD_RW (123461)
#define FD_ACCDB_FD_RO (123460)

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
  int     pd_write;

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

typedef struct fd_accdb_entry fd_acc_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_accdb_align( void );

FD_FN_CONST ulong
fd_accdb_footprint( ulong max_live_slots );

/* fd_accdb_new constructs the local joiner state for an accdb writer
   (or compaction tile).  fd is an O_RDWR fd of the on-disk file.

   external_epoch_cnt and external_epoch_slots provide a list of
   additional epoch publish slots to scan during compaction's
   deferred-free reclamation.  These point at memory owned by other
   processes (typically the per-tile fseq of read-only consumers like
   the rpc tile), mapped read-only into this joiner's address space.
   Each *external_epoch_slots[i] is updated by the owning RO joiner
   on each epoch-protected operation (and reset to ULONG_MAX when
   idle), and is used by this joiner's compaction scan to determine
   when on-disk partitions can be safely reclaimed.

   For joiners that do not need to track external RO consumers (i.e.
   any joiner that is not the compaction tile, or a writer-only
   topology), pass external_epoch_cnt=0 and external_epoch_slots=NULL.
   The pointer array is borrowed and must remain valid for the
   lifetime of the join. */

void *
fd_accdb_new( void *              ljoin,
              fd_accdb_shmem_t *  shmem,
              int                 fd,
              ulong               external_epoch_cnt,
              ulong const **      external_epoch_slots );

fd_accdb_t *
fd_accdb_join( void * shaccdb );

/* fd_accdb_join_readonly is the read-only counterpart of fd_accdb_new +
   fd_accdb_join.  shmem_ro may point into a read-only mapping of the
   shmem region; the function will not write to it.  my_epoch_slot_rw
   must point at a ulong owned by this joiner that it can write to
   (typically a private per-tile fseq that the accdb tile maps read-only
   and passes through external_epoch_slots[] in fd_accdb_new).  fd_ro
   must be opened O_RDONLY on the same file the writer joiner opened RW.

   The joiner publishes its current epoch into *my_epoch_slot_rw on
   entry to each epoch-protected operation (and resets to ULONG_MAX on
   exit).  The accdb tile's compaction scan observes this slot via its
   external_epoch_slots[] pointer and defers partition reclamation
   accordingly, the same way it does for in-shmem joiner_epochs[].

   Only fd_accdb_read_one_nocache, fd_accdb_exists, and
   fd_accdb_lamports are supported on a readonly join; any other API is
   undefined behavior. */

fd_accdb_t *
fd_accdb_join_readonly( void *             ljoin,
                        fd_accdb_shmem_t * shmem_ro,
                        ulong *            my_epoch_slot_rw,
                        int                fd_ro );

/* fd_accdb_snapshot_load_{begin,end} toggle a mode on this writer
   joiner that causes layer-0 partition handoffs to backfill tiering
   for older snapshot-loaded partitions.  Specifically, when a new
   partition P is opened at layer 0, the partition at P-2 is retiered
   to Warm (layer 1) and the partition at P-3 is retiered to Cold
   (layer 2).  This compensates for the fact that snapshot-loaded
   accounts never get a second write and therefore never get promoted
   by normal compaction-driven tiering.

   A single-writer snapshot loader has exclusive write access to
   acc_pool.  Multi-writer loaders serialize hash-chain access with the
   striped locks of fd_accdb_snapshot_write_batch_worker.

   fd_accdb_snapshot_load_begin is the single-writer entry point.
   fd_accdb_snapshot_load_begin_with_writers declares the number of
   joiners that may concurrently mutate the snapshot index.  The
   coordinator calls it before any writer starts and calls load_end
   after every writer stops.  With more than one writer the on-disk
   layout is no longer stream-ordered: each writer appends into its own
   partitions from a private write head, and every writer must use
   fd_accdb_snapshot_write_batch_worker (the only entry point that
   serializes chain access and allocates from a private write head). */

void
fd_accdb_snapshot_load_begin( fd_accdb_t * accdb );

void
fd_accdb_snapshot_load_begin_with_writers( fd_accdb_t * accdb,
                                           ulong        writer_cnt );

/* Each parallel snapshot index writer brackets its job stream with
   writer_begin/writer_end.  This lets it amortize shared acc_pool
   allocation over local blocks while returning any unused tail before
   the coordinator ends or resets the load.  Single-writer callers may
   also use this pair to opt into the same block allocator. */

void
fd_accdb_snapshot_writer_begin( fd_accdb_t * accdb );

void
fd_accdb_snapshot_writer_end( fd_accdb_t * accdb );

void
fd_accdb_snapshot_load_end( fd_accdb_t * accdb );

/* fd_accdb_snapshot_recover_delta appends into the accdb delta set the
   accounts modified at fork_id.

   This is intended to be used after booting off an incremental snapshot
   and allows the validator to create additional incremental snaps.

   Not thread safe: assumes no one but the calling thread is accessing
   accdb deltas.  Returns 0 on success, -1 if the delta map is too small. */

int
fd_accdb_snapshot_recover_delta( fd_accdb_t *       accdb,
                                 fd_accdb_fork_id_t fork_id );

/* fd_accdb_snapshot_recovery_t captures layer-0 write head metadata.
   Used by fd_accdb_snapshot_{save,revert}_whead to save and restore
   accdb state across an incremental snapshot attempt. */

struct fd_accdb_snapshot_recovery {
  ulong whead_val;             /* whead[0].val */
  int   has_partition;         /* has_partition[0] */
  ulong partition_max;         /* partition_max */
  ulong disk_current_bytes;    /* disk_current_bytes metric */
  ulong savepoint_bytes_freed; /* bytes_freed of the save-point partition */
};

typedef struct fd_accdb_snapshot_recovery fd_accdb_snapshot_recovery_t;

/* fd_accdb_snapshot_save_whead captures the current layer-0 write head,
   partition state, and disk_current_bytes metric into the provided
   recovery struct.  Also captures the save-point partition's
   bytes_freed. */

void
fd_accdb_snapshot_save_whead( fd_accdb_t *                   accdb,
                              fd_accdb_snapshot_recovery_t * out );

/* fd_accdb_snapshot_revert_whead restores the layer-0 write head to a
   previously saved position.

   It internally waits for the pending background purge command to
   complete on T2 before releasing partitions, so the caller does not
   need to insert a separate wait_cmd barrier.

   Previously allocated partitions (with indices in the range
   [saved_partition_max, current partition_max)) are released back
   to the partition pool.  disk_current_bytes is restored to the saved
   value rather than computed per-partition, and the save-point
   partition's bytes_freed and write_offset are reset. */

void
fd_accdb_snapshot_revert_whead( fd_accdb_t *                         accdb,
                                fd_accdb_snapshot_recovery_t const * recover );

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
   undefined behavior to create cycles.

   If the fork pool is full but contains deferred forks, this call
   blocks until reader epochs drain and a deferred slot can be reused.
   The caller should never call this function unless there are either
   free fork ids or deferred ones. */

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

   The refcnt does not have to be on the bank of fork_idx itself: a
   refcnt on a live child bank of fork_idx also suffices.  This is the
   executor's pattern, it holds a refcnt on the executing child bank
   and read-only acquires implicit programdata on that bank's (frozen)
   parent fork.  It works because a fork with a live (refcnt>0) child
   bank can be neither advanced-past nor purged, so fork_idx cannot be
   recycled out from under the acquire.  advance_root(fork_idx) itself
   (rooting the queried fork) IS permitted concurrently with a read-only
   acquire on fork_idx (see the THREADING MODEL section); what remains
   forbidden is advancing PAST fork_idx or purging it while any acquire
   on it is outstanding.

   pubkeys_cnt is the number of accounts to acquire, and pubkeys is an
   array of pointers to the 32-byte pubkeys of the accounts to acquire.
   writable is an array of flags indicating whether each corresponding
   account in pubkeys is being acquired for read (0) or write (1).
   Writes provide a temporary buffer of 10MiB in all cases, which the
   caller can use for staging changes to the data, and this allows
   account resizing, or cancelling of any data written (for example if a
   transaction fails) without needing to restore it.  If an account is
   acquired for write, the caller must set the commit bit on the acc
   to non-zero to have the changes written back to the database on
   release, or leave it at zero to discard the changes.  The commit bit
   must be set even if only the metadata has changed.

   IMPORTANT: The caller must guarantee that for any given (pubkey,
   fork) pair, there is no concurrent acquire that holds a writable
   acc while another acquire for the same account on the same fork is
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
     - A read-only acquire on a frozen ancestor fork may begin after
       descendant-fork acquires (read or write) have already begun.  The
       executor relies on this: while a child bank executes (writably
       acquiring its own-fork accounts), it also read-only acquires the
       program's implicit programdata on the frozen parent fork.  This
       is safe because the parent is frozen, no writer ever commits to
       it so the read-only acquire cannot overlap any same-fork write,
       and read-only acquires never mutate acc pool or fork state.

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

   out_accs is an array of pubkeys_cnt cache accs to be filled in
   with the acquired accounts.  The cache will fill the owner, lamports,
   data_len, and data fields of each acc if the acquire is successful,
   and the account exists.  If the account does not exist, the lamports
   field will be set to zero and other fields are undefined. */

void
fd_accdb_acquire( fd_accdb_t *          accdb,
                  fd_accdb_fork_id_t    fork_id,
                  ulong                 pubkeys_cnt,
                  uchar const * const * pubkeys,
                  int *                 writable,
                  fd_acc_t *            out_accs );

void
fd_accdb_acquire_a( fd_accdb_t *          accdb,
                    fd_accdb_fork_id_t    fork_id,
                    ulong                 pubkeys_cnt,
                    uchar const * const * pubkeys,
                    int *                 writable,
                    fd_acc_t *            out_accs );

void
fd_accdb_acquire_b( fd_accdb_t *          accdb,
                    fd_accdb_fork_id_t    fork_id,
                    ulong                 reserved_cnt,
                    ulong                 pubkeys_cnt,
                    uchar const * const * pubkeys,
                    int *                 writable,
                    fd_acc_t *            out_accs );

/* fd_accdb_release releases previously acquired accounts back to the
   cache, and if any of the released writable accounts have their commit
   bit set, the cache will write the changes back to the database.  The
   caller must guarantee that the accs being released were previously
   acquired and not yet released, and that the pubkeys in the accs
   match the pubkeys of the acquired accounts.  The accs need not be
   a specific set that was acquired together, although this is
   recommended.  The fork that each acc refers to must still exist
   (not yet purged or advanced past) at the time of release.  This
   includes forks that would be implicitly purged by a concurrent
   advance_root on a sibling — the caller must ensure advance_root
   is not called until all releases on affected forks have completed.
   Releasing accounts for a fork that has been purged or recycled is
   undefined behavior. */

void
fd_accdb_release( fd_accdb_t * accdb,
                  ulong        accs_cnt,
                  fd_acc_t *   accs );

void
fd_accdb_release_ab( fd_accdb_t * accdb,
                     ulong        accs_cnt,
                     fd_acc_t *   accs,
                     ulong        execs_cnt,
                     fd_acc_t *   execs );

fd_acc_t
fd_accdb_read_one( fd_accdb_t *       accdb,
                   fd_accdb_fork_id_t fork_id,
                   uchar const *      pubkey );

fd_acc_t
fd_accdb_write_one( fd_accdb_t *       accdb,
                    fd_accdb_fork_id_t fork_id,
                    uchar const *      pubkey );

void
fd_accdb_unwrite_one( fd_accdb_t * accdb,
                      fd_acc_t *   acc );

void
fd_accdb_unread_one( fd_accdb_t * accdb,
                     fd_acc_t *   acc );

int
fd_accdb_exists( fd_accdb_t *       accdb,
                 fd_accdb_fork_id_t fork_id,
                 uchar const *      pubkey );

/* fd_accdb_probe_pd_this_fork checks whether the newest version of
   pubkey visible on fork_id was committed on fork_id itself.  If so,
   returns 1 and sets *out_pd_write to that version's pd_write flag,
   *out_data_len to its data length, and *out_lamports to its lamport
   balance.  Otherwise returns 0, sets *out_pd_write to 0, and leaves
   *out_data_len and *out_lamports untouched.

   Reads only metadata, not account data.  out_pd_write deliberately
   ignores lamports: a programdata closed this slot is a lamports==0
   tombstone that must still report pd_write=1 so the loader's
   DelayVisibility gate fires.  out_lamports is reported separately so
   that callers doing account deadness checks have the current fork's
   deadness.

   Note that out_lamports and out_data_len are not read atomically.
   Caller is responsible for ensuring ordering if racing is not
   acceptable.

   Full join only. */

int
fd_accdb_probe_pd_this_fork( fd_accdb_t *       accdb,
                             fd_accdb_fork_id_t fork_id,
                             uchar const *      pubkey,
                             int *              out_pd_write,
                             ulong *            out_data_len,
                             ulong *            out_lamports );

/* fd_accdb_read_one_nocache reads one account at fork_id into
   caller-provided output buffers.  Suitable for processes that mmap the
   accdb data region read-only: it never mutates any cache line, index
   entry, or record.  The only write it makes into accdb shmem is
   publishing this joiner's epoch (to hold off compaction for the
   duration of the read), and that is done through a separately-mmap'd
   writable page aliasing the joiner's own epoch slot, not the read-only
   region.

   out_owner must point at a 32-byte buffer.  out_data must point at a
   buffer of at least FD_RUNTIME_ACC_SZ_MAX (10 MiB) bytes, the maximum
   account data size; the function does not bound-check against the
   account's actual length.  On a cache hit the bytes are memcpy'd from
   the cache slot using a try-read-test (ABA) loop; on a miss the owner
   and data are preadv2'd from the disk fd passed at join time, scattered
   into out_owner and out_data via iovec (looping on short reads).

   If the account does not exist, *out_lamports is set to zero and the
   other outputs are undefined; otherwise *out_lamports is non-zero and
   out_executable, out_owner, out_data, and out_data_len are all filled
   in.

   Returns FD_ACCDB_READ_ONE_NOCACHE_MISS when the account does not
   exist, FD_ACCDB_READ_ONE_NOCACHE_CACHE when read from cache, or
   FD_ACCDB_READ_ONE_NOCACHE_DISK when read from disk.

   The function takes no reference; nothing needs to be released. */

#define FD_ACCDB_READ_ONE_NOCACHE_MISS  (0)
#define FD_ACCDB_READ_ONE_NOCACHE_CACHE (1)
#define FD_ACCDB_READ_ONE_NOCACHE_DISK  (2)

int
fd_accdb_read_one_nocache( fd_accdb_t *       accdb,
                           fd_accdb_fork_id_t fork_id,
                           uchar const *      pubkey,
                           ulong *            out_lamports,
                           int *              out_executable,
                           uchar *            out_owner,
                           uchar *            out_data,
                           ulong *            out_data_len );

/* fd_accdb_lamports returns the lamports of the account at fork_id, or
   zero if the account does not exist. */

ulong
fd_accdb_lamports( fd_accdb_t *       accdb,
                   fd_accdb_fork_id_t fork_id,
                   uchar const *      pubkey );

/* fd_accdb_reset reinitializes the accdb to the state immediately after
   fd_accdb_new.  All in-memory index state is cleared and all pool
   joins are re-established.  The caller is responsible for truncating
   the on-disk file separately (e.g. via the snapin tiles).

   The caller must guarantee that no other thread is concurrently
   accessing the accdb (no outstanding acquires, no background work). */

void
fd_accdb_reset( fd_accdb_t * accdb );

/* fd_accdb_snapshot_write_one inserts or replaces an account during
   snapshot loading.  Returns -1 if the write was ignored (an existing
   acc has a higher slot), 1 if a new acc was inserted, 2 if an
   existing acc was replaced.  When 2 is returned, *out_replaced_lamports
   is set to the lamports of the replaced acc.  Otherwise it is set to
   0.  out_replaced_lamports must be non-NULL.

   slot must be <= UINT_MAX.  The slot is held in a 32-bit scratch field
   during snapshot loading; the accdb format must be widened before
   Solana reaches slot 2^32.  Passing a larger slot crashes the
   process.

   fork_id controls recovery behavior:

     USHORT_MAX, full-snapshot mode.  Existing entries with the same
                 pubkey are replaced in-place.  No txn entries are
                 created.

     other,      incremental-snapshot mode.  Cross-snapshot overrides
                 (existing entry from a different fork) insert a NEW
                 acc_pool entry alongside the old one and create a txn
                 record on fork_id, so fd_accdb_purge can revert the
                 incremental writes on failure.  Intra-fork duplicates
                 (same pubkey from the same fork) are still replaced
                 in-place. */

int
fd_accdb_snapshot_write_one( fd_accdb_t *       accdb,
                             fd_accdb_fork_id_t fork_id,
                             uchar const *      pubkey,
                             ulong              slot,
                             ulong              lamports,
                             ulong              data_len,
                             int                executable,
                             ulong *            out_replaced_lamports );

/* fd_accdb_snapshot_whead_t is a snapshot writer's private layer-0
   write head.  Each parallel snapshot writer appends into its own
   exclusive set of partitions: allocation is lock-free except when
   rotating to a fresh partition (which takes the shared partition
   lock).  val is an opaque packed (partition idx, offset) pair;
   zero-initialize the whole struct before the first allocation.

   attempt_partitions optionally tracks every partition this write head
   acquires: when non-NULL, each rotation appends the fresh partition's
   pool index (crashing if attempt_partition_cnt would exceed
   attempt_partition_max, so size it to the partition pool).  The
   caller resets attempt_partition_cnt at the start of an attempt and,
   if the attempt fails, hands the list to
   fd_accdb_snapshot_worker_release_partitions once no index entry
   references the partitions anymore.  NULL disables tracking. */

struct fd_accdb_snapshot_whead {
  ulong  val;
  int    has_partition;
  uint * attempt_partitions;
  ulong  attempt_partition_cnt;
  ulong  attempt_partition_max;
};

typedef struct fd_accdb_snapshot_whead fd_accdb_snapshot_whead_t;

/* fd_accdb_snapshot_worker_metrics_t buffers shared-metrics deltas and
   duplicate diagnostics for one parallel snapshot writer, so the hot
   insert path does not touch shared counters.  Fold into the shared
   metrics with fd_accdb_snapshot_flush_worker_metrics. */

struct fd_accdb_snapshot_worker_metrics {
  ulong disk_used_added;
  ulong disk_used_removed;
  ulong accounts_total_added;
  ulong eq_slot_dups;          /* equal-slot cross-appendvec duplicate encounters */
  ulong eq_slot_lamports_diff; /* subset of eq_slot_dups where the two versions' lamports differ */
};

typedef struct fd_accdb_snapshot_worker_metrics fd_accdb_snapshot_worker_metrics_t;

/* fd_accdb_snapshot_snoop_fn_t is a caller-supplied callback that
   fd_accdb_snapshot_write_batch_worker invokes for a winning,
   snoop_candidate-flagged account (see below).  batch_idx is the
   index into that call's cnt-sized input arrays (pubkeys[batch_idx],
   lamports[batch_idx], ...) identifying which account won. */

typedef void (*fd_accdb_snapshot_snoop_fn_t)( void * cb_ctx, ulong batch_idx );

/* fd_accdb_snapshot_write_batch_worker has the same duplicate handling
   and output semantics as fd_accdb_snapshot_write_batch, but multiple
   joiners may call it concurrently, including for pubkeys that collide
   on the same hash chain: each per-account chain walk + commit is
   serialized by a striped spin lock (stripe = chain_idx & stripe_msk
   over the caller provided stripe_locks array, which must be shared by
   all writers and zero-initialized).  Only one stripe is ever held at a
   time, so the locks cannot deadlock.

   Each writer allocates its own disk offsets from whead, and the
   insert/replace/ignore decision is made BEFORE allocation, so ignored
   duplicates burn no disk space.  Partition rotation is hoisted outside
   the stripe lock so a partition fallocate never runs under a contended
   lock.  Equal-slot cross-appendvec duplicates cannot be tiebroken
   (worker-local offsets are not stream ordered): they are counted in
   metrics->eq_slot_dups and treated as ignored; the caller must fail
   the load if the count is nonzero.

   fork_id has the same semantics as in fd_accdb_snapshot_write_batch:
   USHORT_MAX selects full-snapshot mode, otherwise incremental mode
   with cross-fork override tracking (undo records CAS-prepended to the
   fork's shared txn list under the stripe lock, fork bits packed into
   the entry offsets, key.generation stamped with the fork's
   generation).

   file_offsets[i] receives the allocated offset of entry i, or
   ULONG_MAX if the entry was ignored (the caller must then not write
   the account's bytes).  Shared metrics deltas are accumulated in
   metrics instead of the shared counters.  cnt must be in [1,8].

   snoop_candidates[i] flags entry i as interesting to the caller (set
   only for the rare accounts the caller wants to inspect, e.g. those
   owned by the stake program, a tracked feature id, or the
   SlotHistory sysvar pubkey).  For every i whose outcome is
   insert-or-replace AND snoop_candidates[i], snoop_fn(snoop_ctx, i) is
   invoked while entry i's stripe lock is STILL HELD; ignored/losing
   entries never fire.  snoop_fn==NULL disables all callbacks, in
   which case snoop_candidates may also be NULL.

   Returns 0 on success, -1 if the batch contained two entries with the
   same pubkey (corrupt snapshot). */

int
fd_accdb_snapshot_write_batch_worker( fd_accdb_t *                         accdb,
                                      fd_accdb_fork_id_t                   fork_id,
                                      ulong                                cnt,
                                      uchar const * const                  pubkeys[],
                                      ulong                                slot,
                                      ulong const                          lamports[],
                                      ulong const                          data_lens[],
                                      int const                            executables[],
                                      int const                            snoop_candidates[],
                                      fd_accdb_snapshot_whead_t *          whead,
                                      int *                                stripe_locks,
                                      ulong                                stripe_msk,
                                      fd_accdb_snapshot_worker_metrics_t * metrics,
                                      ulong                                file_offsets[],
                                      ulong *                              accounts_ignored,
                                      ulong *                              accounts_replaced,
                                      ulong *                              accounts_loaded,
                                      ulong *                              out_replaced_lamports,
                                      ulong *                              out_ignored_lamports,
                                      fd_accdb_snapshot_snoop_fn_t         snoop_fn,
                                      void *                               snoop_ctx );

/* fd_accdb_snapshot_flush_worker_metrics atomically folds the shared
   metrics deltas accumulated in m (disk_used_added/removed,
   accounts_total_added) into the shared metrics counters and zeroes
   them.  The eq_slot_* diagnostics are left untouched. */

void
fd_accdb_snapshot_flush_worker_metrics( fd_accdb_t *                         accdb,
                                        fd_accdb_snapshot_worker_metrics_t * m );

/* fd_accdb_snapshot_worker_close hands off this writer's final
   partition at the end of a load: materializes the partition's
   write_offset from the private whead and books the dead tail slack
   (mirroring what change_partition does on rotation).  Compaction
   enqueue is deliberately skipped; fd_accdb_snapshot_load_end's sweep
   re-checks every partition.  Idempotent (no-op without an open
   partition); resets whead so a later load starts fresh. */

void
fd_accdb_snapshot_worker_close( fd_accdb_t *                accdb,
                                fd_accdb_snapshot_whead_t * whead );

/* fd_accdb_snapshot_worker_release_partitions returns the given
   partitions (a failed attempt's per-writer allocations, collected via
   the whead attempt tracker) to the partition pool, undoing their
   disk_current_bytes contribution.  The caller must guarantee that no
   index entry references the partitions anymore (i.e. the failed
   attempt's purge has completed) and that no writer is appending to
   them; the function additionally waits for any pending background
   command before touching the pool.  partition_max/disk_allocated are
   deliberately left alone: they are a file-size high-water mark, and
   the released partitions are simply re-acquired (without a new
   fallocate) by later loads. */

void
fd_accdb_snapshot_worker_release_partitions( fd_accdb_t * accdb,
                                             uint const * partition_idxs,
                                             ulong        cnt );

/* fd_accdb_snapshot_verify_readback samples up to sample_max live
   accounts from the index and preads each one's on-disk record header
   at fd_accdb_acc_offset, verifying that the stored pubkey and data
   size match the index entry.  FD_LOG_ERR on any mismatch.  Intended as
   a post-load gate for multi-writer snapshot loading, where the on-disk
   layout is no longer stream-ordered. */

void
fd_accdb_snapshot_verify_readback( fd_accdb_t * accdb,
                                   ulong        sample_max );

/* fd_accdb_snapshot_write_batch processes up to 8 accounts at once,
   using software prefetching to overlap hash chain memory latency with
   useful work.  This function is not thread safe and must not be called
   concurrently.  Each pubkey[i] points to a 32-byte public key.
   *out_replaced_lamports is set to the sum of the lamports of all
   accounts replaced by this batch (i.e. the previous lamports value of
   each account whose acc was overwritten).  *out_ignored_lamports is
   set to the sum of the lamports of all accounts ignored by this batch
   (i.e. the lamports of each input account whose write was dropped
   because an acc with a higher slot already exists).  Returns 0 on
   success, -1 if the batch contained two entries with the same pubkey
   (a corrupt-snapshot signal — the caller should flag the snapshot
   malformed).  Output counters are not meaningful when -1 is returned.

   slot must be <= UINT_MAX (see fd_accdb_snapshot_write_one
   for the rationale).  Passing a larger slot crashes the process.

   fork_id has the same semantics as in fd_accdb_snapshot_write_one:
   USHORT_MAX for full-snapshot mode, otherwise incremental mode with
   txn tracking on the specified fork. */

int
fd_accdb_snapshot_write_batch( fd_accdb_t *        accdb,
                               fd_accdb_fork_id_t  fork_id,
                               ulong               cnt,
                               uchar const * const pubkeys[],
                               ulong               slot,
                               ulong  const        lamports[],
                               ulong  const        data_lens[],
                               int    const        executables[],
                               ulong *             accounts_ignored,
                               ulong *             accounts_replaced,
                               ulong *             accounts_loaded,
                               ulong *             out_replaced_lamports,
                               ulong *             out_ignored_lamports );

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
   of T3 threads.

   Read-only acquire/release on a fork F may run concurrently with
   advance_root(F) (rooting F itself).

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

/* fd_accdb_shmetrics returns a pointer to the shared metrics counters
   for the given accdb instance.  The returned pointer remains valid
   for the lifetime of the underlying shmem. */

fd_accdb_shmem_metrics_t const *
fd_accdb_shmetrics( fd_accdb_t * accdb );

/* fd_accdb_metrics returns a pointer to the per-thread metrics counters
   for the given accdb instance.  The returned pointer remains valid
   for the lifetime of the underlying shmem. */

fd_accdb_metrics_t const *
fd_accdb_metrics( fd_accdb_t * accdb );

/* fd_accdb_flush_metrics publishes this joiner's pending layer-0 write
   metrics.  Normal layer-0 writes defer these metrics by default.

   NOTE: A flush delayed past partition reuse can credit old counters
   to the new partition.  The impact on metrics accuracy is expected
   to be rare and small because partitions are rarely reused and
   metrics flush often. */

void
fd_accdb_flush_metrics( fd_accdb_t * accdb );

/* fd_accdb_cache_class_occupancy snapshots the current per-size-class
   cache occupancy and capacity into the caller-provided arrays, each
   of which must have FD_ACCDB_CACHE_CLASS_CNT entries.  used[c] is the
   number of slots in class c that currently hold a cache acc (i.e.
   slots that have been allocated lazily and are not sitting in the
   free list).  max[c] is the total slot capacity of class c.  Reads
   are done with relaxed (volatile) loads and may be momentarily
   inconsistent with each other under contention. */

void
fd_accdb_cache_class_occupancy( fd_accdb_t * accdb,
                                ulong *      used,
                                ulong *      max,
                                ulong *      reserved );

/* fd_accdb_cache_class_thresholds returns the per-size-class preeviction
   thresholds, expressed as used-slot counts (so they're directly
   comparable to occupancy.used and occupancy.max).  Each output array
   must have FD_ACCDB_CACHE_CLASS_CNT entries.  target_used[c] is the
   used count the background preevict pass tries to drive towards (max -
   cache_free_target).  low_water_used[c] is the used count at which the
   preevict pass starts firing (max - cache_free_low_water).  Both are
   set once at init and are stable for the lifetime of the cache. */

void
fd_accdb_cache_class_thresholds( fd_accdb_t * accdb,
                                 ulong *      target_used,
                                 ulong *      low_water_used );

/* FD_ACCDB_METRICS_WRITE publishes the per-joiner accdb runtime metrics
   for tile prefix TILE.  TILE must be a tile that declares the
   AccdbAccountAcquired/... counters in metrics.xml (e.g. EXECLE,
   EXECRP, REPLAY, TOWER, ACCDB).  m must be a fd_accdb_metrics_t const *
   for the joiner whose counters should be published. */

#define FD_ACCDB_METRICS_WRITE( TILE, m ) do {                                              \
    fd_accdb_metrics_t const * _m = (m);                                                    \
    FD_MCNT_ENUM_COPY( TILE, ACCDB_ACCOUNT_ACQUIRED,          _m->accounts_acquired_per_class          ); \
    FD_MCNT_ENUM_COPY( TILE, ACCDB_ACCOUNT_WRITABLE_ACQUIRED, _m->writable_accounts_acquired_per_class ); \
    FD_MCNT_ENUM_COPY( TILE, ACCDB_ACCOUNT_EVICTED,        _m->accounts_evicted_per_class        ); \
    FD_MCNT_ENUM_COPY( TILE, ACCDB_ACCOUNT_COMMITTED_NEW,       _m->accounts_committed_new_per_class       ); \
    FD_MCNT_ENUM_COPY( TILE, ACCDB_ACCOUNT_COMMITTED_OVERWRITE, _m->accounts_committed_overwrite_per_class ); \
    FD_MCNT_ENUM_COPY( TILE, ACCDB_ACCOUNT_NOT_FOUND,   _m->accounts_not_found_per_class ); \
    FD_MCNT_SET( TILE, ACCDB_ACCOUNT_WAITED,             _m->accounts_waited            ); \
    FD_MCNT_SET( TILE, ACCDB_BATCH_ACQUIRED,             _m->acquire_calls              ); \
    FD_MCNT_SET( TILE, ACCDB_ACQUIRE_FAILED,             _m->acquire_failed             ); \
    FD_MCNT_SET( TILE, ACCDB_BYTES_READ,                 _m->bytes_read                 ); \
    FD_MCNT_SET( TILE, ACCDB_READ_OPERATION,             _m->read_ops                   ); \
    FD_MCNT_SET( TILE, ACCDB_BYTES_WRITTEN,              _m->bytes_written              ); \
    FD_MCNT_SET( TILE, ACCDB_WRITE_OPERATION,            _m->write_ops                  ); \
    FD_MCNT_SET( TILE, ACCDB_BYTES_COPIED,               _m->bytes_copied               ); \
  } while(0)

/* FD_ACCDB_METRICS_WRITE_RO is the read-only joiner subset of
   FD_ACCDB_METRICS_WRITE.  It only emits the counters that
   fd_accdb_read_one_nocache touches; tiles that join readonly
   (e.g. RPC) declare only this subset of counters in metrics.xml. */

#define FD_ACCDB_METRICS_WRITE_RO( TILE, m ) do {                                           \
    fd_accdb_metrics_t const * _m = (m);                                                    \
    FD_MCNT_ENUM_COPY( TILE, ACCDB_ACCOUNT_ACQUIRED,  _m->accounts_acquired_per_class  ); \
    FD_MCNT_ENUM_COPY( TILE, ACCDB_ACCOUNT_NOT_FOUND, _m->accounts_not_found_per_class ); \
    FD_MCNT_SET( TILE, ACCDB_ACCOUNT_WAITED,    _m->accounts_waited   ); \
    FD_MCNT_SET( TILE, ACCDB_BATCH_ACQUIRED,    _m->acquire_calls     ); \
    FD_MCNT_SET( TILE, ACCDB_BYTES_READ,        _m->bytes_read        ); \
    FD_MCNT_SET( TILE, ACCDB_READ_OPERATION,    _m->read_ops          ); \
    FD_MCNT_SET( TILE, ACCDB_BYTES_COPIED,      _m->bytes_copied      ); \
  } while(0)

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_h */
