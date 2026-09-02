#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_cache_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_cache_h

/* fd_progcache_cache.h defines the program cache.
   value memory is split in classes, each dedicated to programs of
   a certain size, and each class has a fixed number of slots.

   The classes cover the mainnet program size distribution:

     class 0:  <= 128 KiB
     class 1:  <= 512 KiB
     class 2:  <=   1 MiB
     class 3:  <=   2 MiB
     class 4:  <=   4 MiB
     class 5:  <= ~10 MiB (FD_RUNTIME_ACC_SZ_MAX + a margin) */

#include "../../util/fd_util_base.h"
#include "../runtime/fd_runtime_const.h" /* FD_RUNTIME_ACC_SZ_MAX */
#include "../../ballet/sbpf/fd_sbpf_loader.h" /* FD_SBPF_PROGRAM_FOOTPRINT */

#define FD_PROGCACHE_CACHE_DATA_CLASS_CNT (6UL)
#define FD_PROGCACHE_CACHE_CLASS_CNT      (FD_PROGCACHE_CACHE_DATA_CLASS_CNT)

/* FD_PROGCACHE_CACHE_SLOT_TOP_SZ is the slot size of the largest class.
   It must be >= FD_RUNTIME_ACC_SZ_MAX (10 MiB) + ~160 KiB calldests + alignment.
   11 MiB gives comfortable margin. */
#define FD_PROGCACHE_CACHE_SLOT_TOP_SZ (FD_RUNTIME_ACC_SZ_MAX + (1UL<<20))

/* The worst case value is a max-size account that is all text, so it carries a
   full calldests bitmap; FD_SBPF_PROGRAM_FOOTPRINT bounds that bitmap, and 8 covers
   the alignment between the two regions.  Asserting the load buffer alone would
   leave the bitmap unaccounted. */

FD_STATIC_ASSERT( FD_SBPF_PROGRAM_FOOTPRINT + FD_RUNTIME_ACC_SZ_MAX + 8UL
                  <= FD_PROGCACHE_CACHE_SLOT_TOP_SZ, progcache_top_class_too_small );

/* fd_progcache_cache_slot_sz[c] is the maximum value footprint that class
   c can store (and, since values are stored raw, the byte size of one
   slot in that class). */
static const ulong fd_progcache_cache_slot_sz[ FD_PROGCACHE_CACHE_CLASS_CNT ] = {
  128UL << 10,                    /* class 0: <= 128 KiB */
  512UL << 10,                    /* class 1: <= 512 KiB */
    1UL << 20,                    /* class 2: <=   1 MiB */
    2UL << 20,                    /* class 3: <=   2 MiB */
    4UL << 20,                    /* class 4: <=   4 MiB */
  FD_PROGCACHE_CACHE_SLOT_TOP_SZ, /* class 5: <= ~10 MiB */
};

/* fd_progcache_cache_class maps a program_sz to its class.  Returns
   FD_PROGCACHE_CACHE_CLASS_CNT if no class can hold it. */
FD_FN_CONST static inline ulong
fd_progcache_cache_class( ulong program_sz ) {
  for( ulong c=0UL; c<FD_PROGCACHE_CACHE_CLASS_CNT; c++ ) {
    if( program_sz<=fd_progcache_cache_slot_sz[c] ) return c;
  }
  return FD_PROGCACHE_CACHE_CLASS_CNT;
}

/* fd_progcache_cache_class_min returns the guaranteed minimum slot count
   of class c: 30 for classes up to 2 MiB, 3 for the larger ones.  This is
   used to derive the minimum memory requirements for progcache. */
FD_FN_CONST static inline ulong
fd_progcache_cache_class_min( ulong c ) {
  return fd_progcache_cache_slot_sz[ c ]<=(2UL<<20) ? 30UL : 3UL;
}


FD_PROTOTYPES_BEGIN

/* fd_progcache_setup_slots provisions progcache_sz across the classes, populating
   slot_cnt with each class's slot count.  Every data class gets at least
   fd_progcache_cache_class_min slots.
   Returns the record capacity (== sum(slot_cnt)), or 0 if progcache_sz is below
   fd_progcache_shmem_min_sz( txn_max ). */
ulong
fd_progcache_setup_slots( ulong   txn_max,
                          ulong   progcache_sz,
                          ulong * slot_cnt );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_cache_h */
