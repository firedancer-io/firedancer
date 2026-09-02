#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_rec_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_rec_h

#include "fd_progcache_base.h"
#include "../../ballet/sbpf/fd_sbpf_loader.h"
#include "../fd_flamenco_base.h"
#include "../fd_rwlock.h"

#include <stdatomic.h>

struct fd_progcache_rec_key {
  fd_progcache_fork_id_t xid;
  fd_pubkey_t            prog;
};

typedef struct fd_progcache_rec_key fd_progcache_rec_key_t;

static inline int
fd_progcache_rec_key_eq( fd_progcache_rec_key_t const * k0,
                         fd_progcache_rec_key_t const * k1 ) {
  return ( (k0->xid == k1->xid) & fd_pubkey_eq( &k0->prog, &k1->prog ) );
}

/* fd_progcache_rec_t is a program cache entry.  Entries are either
   executable or non-executable (e.g. programs that failed verification).
   An executable entry's program data (rodata/ROM segment, control flow
   metadata, ...) lives in its size class's arena slot, addressed by
   data_gaddr; a non-executable entry has data_gaddr==0. */

/* The first 64 bytes hold everything a lookup touches -- key, revision, chain
   link, lock and CLOCK state -- so walking a chain and locking the winner costs
   one cache line.  The rest is only read once the record is in hand. */

struct __attribute__((aligned(64))) fd_progcache_rec {
  fd_progcache_rec_key_t pair;  /* Transaction id and record key pair */

  ulong feature_slot;
  ulong deploy_slot;

  uint        map_next;  /* Internal use by map */
  fd_rwlock_t lock;

  /* CLOCK/liveness bits, atomically accessed (see fd_progcache_clock.h).  Its own
     byte: an atomic RMW cannot target a bitfield, and widening one to the bitfield
     below would race with the plain writes to those fields. */
  uchar       state;

  atomic_uint txn_idx;
  uint        next_idx;  /* Record map index of next record in its transaction */
  uint        prev_idx;  /* Record map index of previous record in its transaction */
  uint        data_max;  /* size of allocation */

  ulong data_gaddr;  /* wksp-base relative pointer to data */

  uint entry_pc;
  uint text_cnt;
  uint text_off;
  uint text_sz;

  uint rodata_sz;

  uint calldests_off;  /* offset to sbpf_calldests map */
  uint rodata_off;     /* offset to rodata segment */

  uint free_next; /* next record in the class's free list */

  ushort      sbpf_version : 8; /* SBPF version, SIMD-0161 */
  ushort      exists       : 1; /* if ==0, record is dead, no longer in map, and awaiting cleanup */
  ushort      size_class   : 3; /* the class the record's slot belongs to, set at acquire */
};

FD_STATIC_ASSERT( sizeof(fd_progcache_rec_t)==128, layout );

/* rec_init_inflight resets the record in two spans, skipping the gap between
   map_next and txn_idx: lock and state must be the only fields in it. */
FD_STATIC_ASSERT( offsetof(fd_progcache_rec_t,txn_idx)-offsetof(fd_progcache_rec_t,lock)==4UL, layout );

FD_PROTOTYPES_BEGIN

/* Accessors */

static inline uchar const *
fd_progcache_rec_rodata( fd_progcache_rec_t const * rec,
                         fd_wksp_t *                wksp ) {
  return fd_wksp_laddr_fast( wksp, rec->data_gaddr + rec->rodata_off );
}

static inline fd_sbpf_calldests_t const *
fd_progcache_rec_calldests( fd_progcache_rec_t const * rec,
                            fd_wksp_t *                wksp ) {
  if( rec->calldests_off==UINT_MAX ) return NULL;
  return fd_sbpf_calldests_join( fd_wksp_laddr_fast( wksp, rec->data_gaddr + rec->calldests_off ) );
}

/* Record + value slot management.  Records are partitioned by size class
   (see fd_progcache.h): acquiring a record from a class IS acquiring its
   value slot. */

/* fd_progcache_val_{align,footprint} give the alignment and size the program
   data of an executable cache entry needs, which is what picks its size class.
   elf_info must describe a successfully peeked ELF.  A non-executable entry
   leaves its slot unused; fd_progcache_rec_nx marks the record with
   data_gaddr==0. */

FD_FN_CONST static inline ulong
fd_progcache_val_align( void ) {
  return fd_sbpf_calldests_align();
}

FD_FN_PURE ulong
fd_progcache_val_footprint( fd_sbpf_elf_info_t const * elf_info );

/* fd_progcache_rec_acquire pops a free record from the class fitting
   val_footprint and initializes it as an in-flight record: read-locked by
   the caller, not in the map, its arena slot attached.  Returns NULL if the class
   is full, leaving the caller to evict within the class (fd_prog_evict hands
   back a record of that class) or spill.  No cross-class borrowing. */

fd_progcache_rec_t *
fd_progcache_rec_acquire( fd_progcache_join_t * join,
                          ulong                 val_footprint );

/* fd_progcache_rec_reinit turns a record the caller holds write-locked and
   out of the map into an in-flight record, exactly as acquire does, without
   passing through the class free list.  The eviction sweep uses it to hand a
   slot it just claimed straight to the requester, so the slot cannot be taken
   in between. */

fd_progcache_rec_t *
fd_progcache_rec_reinit( fd_progcache_join_t * join,
                         fd_progcache_rec_t *  rec );

/* fd_progcache_rec_release returns a record to its class free list and
   releases its value storage.  The caller must hold the record's WRITE
   lock (guaranteeing no other user) and the record must not be in the
   map.  The record stays write-locked on the free list, so a stale
   speculative reader can never lock a free record. */

void
fd_progcache_rec_release( fd_progcache_join_t * join,
                          fd_progcache_rec_t *  rec );

/* fd_progcache_rec_abandon releases an in-flight record that was never
   published to the map: a peer owns the key, at this revision or another.  The
   caller holds the read lock from fd_progcache_rec_acquire; abandon
   upgrades it to a write lock (draining transient speculative readers of
   a previous incarnation of this record) and releases. */

void
fd_progcache_rec_abandon( fd_progcache_join_t * join,
                          fd_progcache_rec_t *  rec );

fd_progcache_rec_t *
fd_progcache_rec_load( fd_progcache_rec_t *            rec,
                       fd_wksp_t *                     wksp,
                       fd_sbpf_elf_info_t const *      elf_info,
                       fd_sbpf_loader_config_t const * config,
                       ulong                           load_slot,
                       fd_features_t const *           features,
                       void const *                    progdata,
                       ulong                           progdata_sz,
                       void *                          scratch,
                       ulong                           scratch_sz );

fd_progcache_rec_t *
fd_progcache_rec_nx( fd_progcache_rec_t * rec );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_rec_h */
