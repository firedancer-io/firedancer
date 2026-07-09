#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_cache_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_cache_h

#include "../../util/fd_util_base.h"

/* fd_accdb_cache.h provides a static algorithm for determining, given a
   fixed size cache_footprint specified by an operator, how to allocate
   that footprint into various account size classes to maximize expected
   cache hit while executing.

   The cache has 8 size classes (to fit in a single cache line) with a
   x4 geometric progression:

     Class 0: 0-128 B      (slot: 216 B)
     Class 1: 129-512 B    (slot: 600 B)
     Class 2: 513-2 KiB    (slot: 2,136 B)
     Class 3: 2K-8 KiB     (slot: 8,280 B)
     Class 4: 8K-32 KiB    (slot: 32,856 B)
     Class 5: 32K-128 KiB  (slot: 131,160 B)
     Class 6: 128K-1 MiB   (slot: 1,048,664 B)
     Class 7: 1M-10 MiB    (slot: 10,485,848 B)

   Each slot has 88 bytes of fixed metadata overhead
   (sizeof(fd_accdb_cache_line_t)) on top of the max data capacity
   for its class.  Slot sizes are 8-byte aligned.

   The allocation algorithm maximizes expected cache hit rate by
   distributing budget proportional to access density (observed accesses
   per byte of cache consumed), derived from empirical mainnet replay.
   Classes are capped at estimated population maximums to avoid
   over-provisioning. */

#define FD_ACCDB_CACHE_CLASS_CNT    (8UL)
#define FD_ACCDB_CACHE_META_SZ     (88UL)

/* Per-class line count ceiling.  The acc cache index packs (class, line)
   into 32 bits as 3 bits of class and FD_ACCDB_CACHE_LINE_BITS bits of
   line index (see FD_ACCDB_ACC_CIDX_* in fd_accdb_private.h).  A class
   may not be sized larger than FD_ACCDB_CACHE_LINE_MAX slots, or two
   distinct lines would pack to the same cidx and reads would alias. */

#define FD_ACCDB_CACHE_LINE_BITS    (29)
#define FD_ACCDB_CACHE_LINE_MAX     (1UL<<FD_ACCDB_CACHE_LINE_BITS)

/* min_reserved is supplied at runtime by the caller (see
   fd_accdb_cache_class_cnt and fd_accdb_shmem_new).  It is the minimum
   number of slots reserved per class so a worst-case batch of
   transactions can always execute fully in-memory.

   The floor is driven by the per-class peak that
   fd_accdb_acquire_a can atomically increment for the simultaneously-
   live transactions (a bundle of up to 5).  Per pubkey, per class, the
   acquire reservation can add up to:
     +1 for the existing account's own size class (cache read line)
     +1 for the writable staging buffer (added to EVERY class)
     +1 for the unknown-programdata placeholder (added to EVERY class,
         unconditionally per pubkey under MAYBE_PROGRAMDATA)
   = 3 slots in the worst-case-matching class for a writable account
   that already exists there.  Solana requires at least one read-only
   pubkey per txn (the invoked program), which can contribute at most
   2 (no writable +1 every class), so the per-txn worst case is:
     63 * 3 + 1 * 2 = 191 slots per class per txn.

   Bundles enabled:  5 * 191 = 955  (worst case 5-transaction bundle)
   Bundles disabled:     191       (worst case single transaction)

   See src/app/firedancer/topology.c for the canonical derivation. */

static const ulong fd_accdb_cache_slot_sz[ FD_ACCDB_CACHE_CLASS_CNT ] = {
  128UL+FD_ACCDB_CACHE_META_SZ,      /* class 0: 0-128 B     */
  512UL+FD_ACCDB_CACHE_META_SZ,      /* class 1: 129-512 B   */
  2048UL+FD_ACCDB_CACHE_META_SZ,     /* class 2: 513-2 KiB   */
  8192UL+FD_ACCDB_CACHE_META_SZ,     /* class 3: 2K-8 KiB    */
  32768UL+FD_ACCDB_CACHE_META_SZ,    /* class 4: 8K-32 KiB   */
  131072UL+FD_ACCDB_CACHE_META_SZ,   /* class 5: 32K-128 KiB */
  1048576UL+FD_ACCDB_CACHE_META_SZ,  /* class 6: 128K-1 MiB  */
  10485760UL+FD_ACCDB_CACHE_META_SZ, /* class 7: 1M-10 MiB   */
};

/* fd_accdb_cache_class_cnt computes the number of slots to allocate for
   each of the 8 size classes, given a total cache memory budget.

   The cache and staging pools are unified: class 7 slots serve double
   duty as both cache entries for large accounts and as 10 MiB staging
   buffers for writable accounts.  On commit, data is copied from the
   staging slot into a right-sized cache slot and the class 7 slot is
   released.

   cache_footprint is the total memory budget in bytes.

   class_cnt is populated with the slot count for each class on return.
   The sum of class_cnt[c]*slot_sz[c] will not exceed cache_footprint.

   Every class gets at least min_reserved entries, guaranteeing a
   worst-case batch can execute fully in memory regardless of account
   size mix.  See the min_reserved comment block above for the
   derivation (currently 192 per concurrently-live transaction).
   Returns 0 if the budget is too small for these minimums, or 1 on
   success.

   The algorithm:
   1) Reserves min_reserved of each class off the top.
   2) Reserves additional per-class minimums (at most 1% of remaining
      budget per class, clamped to [1, 1024] slots).
   3) Iteratively allocates remaining budget proportional to access
      density weights derived from mainnet replay data.
   4) Caps classes at estimated population maximums and redistributes
      surplus to uncapped classes. */

int
fd_accdb_cache_class_cnt( ulong   cache_footprint,
                          ulong   min_reserved,
                          ulong * class_cnt );

ulong
fd_accdb_cache_class( ulong data_sz );

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_cache_h */
