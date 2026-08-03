#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_class_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_class_h

/* fd_progcache_class.h defines the program cache size classes.  Cache
   memory is split into classes, each with a fixed number of slots sized for
   programs of one size range (fd_progcache_slot_sz below).  The last class
   holds non-executable entries, programs that failed verification, which
   have no data. */

#include "../../util/fd_util_base.h"
#include "../runtime/fd_runtime_const.h" /* FD_RUNTIME_ACC_SZ_MAX */
#include "../../ballet/sbpf/fd_sbpf_loader.h" /* FD_SBPF_CALLDESTS_PRIVATE_WORD_CNT */

#define FD_PROGCACHE_DATA_CLASS_CNT (6UL)
#define FD_PROGCACHE_NX_CLASS           (FD_PROGCACHE_DATA_CLASS_CNT) /* == 6 */
#define FD_PROGCACHE_CLASS_CNT      (FD_PROGCACHE_NX_CLASS + 1UL)     /* == 7 */
#define FD_PROGCACHE_NX_SLOTS           (512UL)

/* A value holds the loaded image plus, for pre-strict ELFs, a calldests
   bitmap of one bit per instruction slot. */
#define FD_PROGCACHE_CALLDESTS_SZ_MAX (FD_SBPF_CALLDESTS_PRIVATE_WORD_CNT*8UL)

/* FD_PROGCACHE_SLOT_TOP_SZ is the slot size of the largest class.
   It must fit an account of the maximum size plus its calldests bitmap
   and alignment padding.  1 MiB of margin over the 10 MiB account is a
   comfortable fit for the 160 KiB bitmap. */
#define FD_PROGCACHE_SLOT_TOP_SZ (FD_RUNTIME_ACC_SZ_MAX + (1UL<<20))

FD_STATIC_ASSERT( FD_PROGCACHE_SLOT_TOP_SZ >= FD_RUNTIME_ACC_SZ_MAX + FD_PROGCACHE_CALLDESTS_SZ_MAX,
                  progcache_top_class_too_small );

/* fd_progcache_slot_sz[c] is the maximum value footprint that class
   c can store (and, since values are stored raw, the byte size of one
   slot in that class). */
static const ulong fd_progcache_slot_sz[ FD_PROGCACHE_CLASS_CNT ] = {
  128UL << 10,                    /* class 0: <= 128 KiB */
  512UL << 10,                    /* class 1: <= 512 KiB */
    1UL << 20,                    /* class 2: <=   1 MiB */
    2UL << 20,                    /* class 3: <=   2 MiB */
    4UL << 20,                    /* class 4: <=   4 MiB */
  FD_PROGCACHE_SLOT_TOP_SZ, /* class 5: <= 11 MiB */
    0UL,                          /* nx class:  non-executable, no program data */
};

/* fd_progcache_class maps a program_sz to its class. */
FD_FN_CONST static inline ulong
fd_progcache_class( ulong program_sz ) {
  if( FD_UNLIKELY( program_sz==0UL ) ) return FD_PROGCACHE_NX_CLASS; /* non-executable */
  for( ulong c=0UL; c<FD_PROGCACHE_NX_CLASS; c++ ) { /* data classes only */
    if( program_sz<=fd_progcache_slot_sz[c] ) return c;
  }
  return FD_PROGCACHE_CLASS_CNT;
}

/* fd_progcache_class_min returns the guaranteed minimum slot count
   of class c: 20 for data classes up to 2 MiB, 1 for the larger ones, and
   FD_PROGCACHE_NX_SLOTS for the nx class.  Sets the floor on progcache's
   memory requirements.  A class needs more slots than there are concurrent
   readers of it, otherwise every acquisition contends and replay cannot
   keep up. */
FD_FN_CONST static inline ulong
fd_progcache_class_min( ulong c ) {
  if( c==FD_PROGCACHE_NX_CLASS ) return FD_PROGCACHE_NX_SLOTS;
  return fd_progcache_slot_sz[ c ]<=(2UL<<20) ? 20UL : 1UL;
}

FD_PROTOTYPES_BEGIN

/* fd_progcache_class_cnt computes the number of slots to allocate
   for each class, given a total cache memory budget (bytes).
   class_cnt is populated with the slot count for each class.
   the sum of class_cnt[c]*slot_sz[c] will not exceed cache_footprint.
   Every data class gets at least their minimum slots (the nx class gets
   its fixed count).
   Returns 1 on success, 0 if the budget is too small for these minimums. */
int
fd_progcache_class_cnt( ulong   cache_footprint,
                        ulong * class_cnt );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_class_h */
