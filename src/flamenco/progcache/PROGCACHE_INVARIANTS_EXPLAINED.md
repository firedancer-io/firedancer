# Program Cache Invariant Checks - Detailed Explanation

This document explains each invariant check in the comprehensive progcache verification function, with references to the source code showing why each check is necessary.

## 1. Fork Management Invariants

### 1.1 Fork Depth Limit Check
**Check:** `fork_depth <= FD_PROGCACHE_DEPTH_MAX (128)`

**Why it's needed:**
- The fork array is statically allocated in `fd_progcache_user.h:82`:
```c
struct fd_progcache {
  fd_funk_txn_xid_t fork[ FD_PROGCACHE_DEPTH_MAX ];  // Static array of 128
  ulong             fork_depth;
```
- Without this check, `fd_progcache_load_fork_slow` in `fd_progcache_user.c:77` could overflow:
```c
for( i=0UL; i<FD_PROGCACHE_DEPTH_MAX; i++ ) {
  cache->fork[ i ] = next_xid;  // Would overflow if i >= 128
```

### 1.2 XID Existence in Transaction Map
**Check:** Non-root XIDs must exist as transactions in funk

**Why it's needed:**
- The fork array is used in `fd_progcache_fork_has_xid` (fd_progcache_user.c:165) to determine visibility:
```c
static int
fd_progcache_fork_has_xid( fd_progcache_t const *    cache,
                           fd_funk_txn_xid_t const * rec_xid ) {
  for( ulong i=0UL; i<fork_depth; i++ ) {
    if( fd_funk_txn_xid_eq( &cache->fork[i], rec_xid ) ) return 1;
  }
```
- If a fork XID doesn't exist in funk, queries would be checking against invalid/deleted transactions

### 1.3 Epoch Boundary Check
**Check:** Fork entries (except last) must have `slot >= epoch_slot0`

**Why it's needed:**
- In `fd_progcache_load_fork_slow` (fd_progcache_user.c:67-69):
```c
if( FD_UNLIKELY( next_xid.ul[0]<epoch_slot0 ) ) {
  FD_LOG_CRIT(( "attempted to load xid=%lu:%lu, which predates first slot of bank's epoch" ));
}
```
- In `fd_progcache_search_chain` (fd_progcache_user.c:214), records from old epochs are filtered:
```c
if( FD_UNLIKELY( found_slot<epoch_slot0 ) ) continue;
```

### 1.4 Parent-Child Relationship Verification
**Check:** Each fork entry's parent must match the next entry in the array

**Why it's needed:**
- The fork array represents a path from child to root, used in visibility checks
- `fd_progcache_load_fork_slow` (fd_progcache_user.c:100-114) walks parent pointers:
```c
parent_idx = fd_funk_txn_idx( FD_VOLATILE_CONST( candidate->parent_cidx ) );
if( parent_idx<txn_max ) {
  fd_funk_txn_t const * parent = &cache->funk->txn_pool->ele[ parent_idx ];
  parent_xid = FD_VOLATILE_CONST( parent->xid );
}
```

## 2. Record Structure Invariants

### 2.1 Executable Record Size Check
**Check:** Executable records must be larger than header size

**Why it's needed:**
- `fd_progcache_rec_footprint` (fd_progcache_rec.h:64) calculates required size:
```c
FD_FN_PURE FD_FN_UNUSED static ulong
fd_progcache_rec_footprint( fd_sbpf_elf_info_t const * elf_info ) {
  if( !elf_info ) return sizeof(fd_progcache_rec_t); /* non-executable */
  // ... executable records need more space for text, rodata, calldests
```
- Executable records contain additional data beyond the header

### 2.2 Text Segment Bounds Check
**Check:** `text_off + text_sz <= record_size`

**Why it's needed:**
- Text segment is accessed directly in VM execution
- Buffer overflow would occur if bounds aren't respected
- The text segment is copied in during `fd_progcache_rec_new` (implementation uses these offsets)

### 2.3 Rodata Segment Bounds Check
**Check:** `rodata_off + rodata_sz <= record_size`

**Why it's needed:**
- `fd_progcache_rec_rodata` (fd_progcache_rec.h:43) accesses rodata directly:
```c
static inline uchar const *
fd_progcache_rec_rodata( fd_progcache_rec_t const * rec ) {
  return (uchar const *)rec + rec->rodata_off;
}
```
- Out-of-bounds access would read invalid memory

### 2.4 Entry Point Validation
**Check:** `entry_pc < text_cnt`

**Why it's needed:**
- Entry PC is used as the starting instruction in VM execution
- In `fd_vm_interp.c`, the entry_pc is used as initial program counter
- Invalid entry point would cause immediate execution failure

### 2.5 Calldests Validation (for older SBPF)
**Check:** Calldests offset and size must be valid

**Why it's needed:**
- `fd_progcache_rec_calldests` (fd_progcache_rec.h:48) accesses calldests:
```c
static inline fd_sbpf_calldests_t const *
fd_progcache_rec_calldests( fd_progcache_rec_t const * rec ) {
  return fd_sbpf_calldests_join( (void *)( (ulong)rec + rec->calldests_off ) );
}
```
- Used for validating call instructions in older SBPF versions
- Check in fd_progcache_rec.h:67: `!fd_sbpf_enable_stricter_elf_headers_enabled`

## 3. Deduplication Invariants

### 3.1 No Duplicate (XID, prog_addr) Pairs
**Check:** Each (XID, program address) combination must be unique

**Why it's needed:**
- Recent fix in `fd_progcache_push` (fd_progcache_user.c:393-399) explicitly checks:
```c
/* Phase 3: Check if record exists */
fd_funk_rec_map_query_t query[1];
int query_err = fd_funk_rec_map_txn_query( funk->rec_map, &rec->pair, NULL, query, 0 );
if( FD_UNLIKELY( query_err==FD_MAP_SUCCESS ) ) {
  *dup_rec = query->ele;
  return 0; /* another thread was faster */
}
```
- Without this, multiple records for same program could exist, causing:
  - Memory waste
  - Inconsistent query results
  - Race conditions in concurrent access

### 3.2 Atomic Insert with Duplicate Detection
**Check:** Insert operation must atomically check and insert

**Why it's needed:**
- The fix addresses a race where two threads could both check, find no record, then both insert
- Uses funk transaction locks to ensure atomicity (fd_progcache_user.c:378-388)

## 4. Visibility and Invalidation Rules

### 4.1 Invalidated Records Must Not Be Executable
**Check:** `invalidate == 1` implies `executable == 0`

**Why it's needed:**
- Invalidated entries mark programs that have been modified
- In `fd_progcache_rec.h:33`: `uint invalidate : 1;  /* limits visibility of this entry to this slot */`
- An executable invalidated record would be a contradiction

### 4.2 Invalidated Records Cannot Be at Root
**Check:** Invalidated records must have non-root XID

**Why it's needed:**
- `fd_progcache_invalidate` (fd_progcache_user.c:668-670) explicitly prevents this:
```c
if( fd_funk_txn_xid_eq( xid, cache->funk->shmem->last_publish ) ) {
  FD_LOG_WARNING(( "fd_progcache_invalidate(xid=%lu,...) failed: xid is last_publish" ));
  return NULL;
}
```
- Root/published records are permanent and visible to all forks

### 4.3 Slot Consistency
**Check:** Record slot must match XID slot (for non-root)

**Why it's needed:**
- Slot is used for visibility filtering in `fd_progcache_search_chain` (fd_progcache_user.c:211-213):
```c
ulong found_slot = rec->pair.xid->ul[0];
if( found_slot==ULONG_MAX ) found_slot = root_slot;
if( FD_UNLIKELY( found_slot<epoch_slot0 ) ) continue;
```
- Inconsistent slots would break visibility rules

## 5. Memory Safety Invariants

### 5.1 Segment Non-Overlap
**Check:** Text and rodata segments must not overlap

**Why it's needed:**
- Overlapping segments could cause data corruption
- VM execution expects distinct memory regions for code and read-only data
- Memory layout is determined in `fd_progcache_rec_footprint`

### 5.2 Scratch Buffer Alignment
**Check:** Scratch buffer must be 64-byte aligned

**Why it's needed:**
- Defined in `fd_progcache_user.h:130`: `FD_PROGCACHE_SCRATCH_ALIGN (64UL)`
- Used for ELF loading and verification which may require aligned access
- Check in `fd_progcache_join` (fd_progcache_user.c:25-27):
```c
if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)scratch, FD_PROGCACHE_SCRATCH_ALIGN ) ) ) {
  FD_LOG_WARNING(( "misaligned scratch" ));
  return NULL;
}
```

## 6. Transaction Consistency

### 6.1 Transaction Lock Ordering
**Check:** Proper lock acquisition and release

**Why it's needed:**
- `fd_progcache_user.c:377-388` shows critical section management:
```c
/* Phase 2: Lock rec_map chain, entering critical section */
fd_funk_rec_map_txn_t * map_txn = fd_funk_rec_map_txn_init(...);
fd_funk_rec_map_txn_add( map_txn, &rec->pair, 1 );
int txn_err = fd_funk_rec_map_txn_try( map_txn, FD_MAP_FLAG_BLOCKING );
```
- Prevents data races in concurrent environment

### 6.2 Record-to-Transaction Linkage
**Check:** Records must be properly linked to their transactions

**Why it's needed:**
- `fd_progcache_push` (fd_progcache_user.c:406-410) maintains transaction record lists:
```c
if( txn ) {
  fd_funk_rec_push_tail( funk->rec_pool->ele,
                        rec,
                        &txn->rec_head_idx,
                        &txn->rec_tail_idx );
}
```
- Needed for transaction cancellation and cleanup

## 7. Fork Visibility Rules

### 7.1 Published Records Visibility
**Check:** Published records from current epoch visible to all forks

**Why it's needed:**
- `fd_progcache_load_fork_slow` (fd_progcache_user.c:144-148):
```c
/* Only include published/rooted records if they include at least one
   cache entry from the current epoch. */
if( fd_funk_last_publish( cache->funk )->ul[0] >= epoch_slot0 &&
    cache->fork_depth < FD_PROGCACHE_DEPTH_MAX ) {
  fd_funk_txn_xid_set_root( &cache->fork[ cache->fork_depth++ ] );
}
```

### 7.2 Fork Isolation
**Check:** Records not visible to unrelated forks

**Why it's needed:**
- `fd_progcache_search_chain` (fd_progcache_user.c:221) enforces fork isolation:
```c
/* Confirm that record is part of the current fork */
if( FD_UNLIKELY( !fd_progcache_fork_has_xid( cache, rec->pair.xid ) ) ) continue;
```
- Prevents cross-fork contamination of program state

## Summary

Each invariant check protects against specific failure modes:
- **Memory corruption**: Bounds checks prevent buffer overflows
- **Data races**: Atomic operations and proper locking prevent concurrent modification issues
- **Logic errors**: Consistency checks ensure the cache behaves correctly
- **Performance**: Proper indexing and deduplication prevent resource waste
- **Correctness**: Visibility rules ensure programs see the correct version for their fork

The recent deduplication fix (commit 0612d8eea) addressed a critical race condition where duplicate records could be created, demonstrating the importance of these invariant checks.