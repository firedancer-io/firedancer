#ifndef HEADER_fd_src_groove_fd_groove_volume_h
#define HEADER_fd_src_groove_fd_groove_volume_h

#include "fd_groove_base.h" /* includes ../util/fd_util.h */

/* Groove data objects are stored in groove volumes.  A volume has a
   uniform size of FD_GROOVE_VOLUME_FOOTPRINT and a unique index.  A
   volume is mapped into the caller's address space starting at
   (ulong)volume0+idx*FD_GROOVE_VOLUME_FOOTPRINT where volume0 is the
   start of a region in the user's address space with enough room to
   accommodate mapping current and future volumes.  To support
   persistent and IPC usage across different applications, concurrent
   users can use different values for volume0.

   Volume indexing does not need to be contiguous or start at zero.
   Further, there is no theoretical limit on the number of volumes.
   Practically, the above implies that the address region footprint in
   the caller's address space is

     (max_idx_in_use+1)*FD_GROOVE_VOLUME_FOOTPRINT.

   As the FD machine model targets 64-bit address spaces, this implies a
   groove instance practically can hold at most < 2^64 B (16 EiB).
   (Note that 50 billion data objects at a worst case 10 MiB per object
   requires less than 0.5 EiB so this is not a limitation in practice.)

   To support commodity hardware and operating systems efficiently,
   volume0 should have at least normal page alignment and
   FD_GROOVE_VOLUME_FOOTPRINT should be a normal page multiple.  For
   highest performance on such systems, 1 GiB aligned volume0 with
   gigantic page DRAM backed volumes are recommended but this is not
   required.  E.g. it is fine for volumes to be a memory mapped file
   backed by a NVMe/SSD/RAID array.  This implementation uses a
   FD_GROOVE_VOLUME_FOOTPRINT of 1 GiB.

   Volumes can be backed by different technologies.  Note that while
   heterogeneous volumes are supported, this implementation does not
   treat a volume backed by fast DRAM differently from a volume backed
   by a tape drive.

   Empty groove volumes are stored on a lockfree stack to support adding
   / removing volumes from a groove instance dynamically without
   impacting on-going groove operations.  E.g. to increase the groove's
   capacity, create a volume at an unused index and lockfree push it
   onto the groove's empty volume stack.  To decrease capacity, pop the
   stack and reclaim the returned volume. */

/* FIXME: consider allowing larger volume headers (or adding a
   volume footer) to not waste ~15KiB space with pading */

#define FD_GROOVE_VOLUME_ALIGN     (4096UL)
#define FD_GROOVE_VOLUME_FOOTPRINT (1UL<<30)
#define FD_GROOVE_VOLUME_MAGIC     (0xfd67007e701c3300) /* fd groove volume version 0 */
#define FD_GROOVE_VOLUME_INFO_MAX  (FD_GROOVE_BLOCK_FOOTPRINT-32UL)
#define FD_GROOVE_VOLUME_DATA_MAX  (FD_GROOVE_VOLUME_FOOTPRINT-FD_GROOVE_BLOCK_FOOTPRINT)

struct __attribute__((aligned(FD_GROOVE_VOLUME_ALIGN))) fd_groove_volume {

  /* This point is aligned FD_GROOVE_VOLUME_ALIGN >= FD_GROOVE_BLOCK_ALIGN */

  ulong magic;   /* == FD_GROOVE_VOLUME_MAGIC if volume potentially contains groove data allocations,
                    ==~FD_GROOVE_VOLUME_MAGIC if volume contains no groove data allocations,
                    other values -> not a volume */
  ulong idx;     /* Volume index (this is mapped into the user's address space at groove->volume0 + idx) */
  ulong next;    /* Managed by the groove volume pool */
  ulong info_sz; /* in [0,INFO_MAX] */

  /* This point is aligned 32 */

  uchar info[ FD_GROOVE_VOLUME_INFO_MAX ]; /* info_sz bytes of user info, bytes [info_sz,INFO_MAX) are arbitrary */

  /* This point is aligned FD_GROOVE_BLOCK_ALIGN */

  uchar data[ FD_GROOVE_VOLUME_DATA_MAX ];
};

typedef struct fd_groove_volume fd_groove_volume_t;

/* Note: given a 2^30 volume footprint, a POOL_IDX_WIDTH of 34
   supports up ~2^34 volumes for up to a ~2^64 groove data storage.
   (For the default pool index width, this could go as high as
   fd_groove_pool_max_max ~ 2^43 but it would not be possible to memory
   map such a set of volumes on 64-bit architectures.) */

#define POOL_NAME       fd_groove_volume_pool
#define POOL_ELE_T      fd_groove_volume_t
#define POOL_IDX_WIDTH  (34)
#define POOL_MAGIC      (0xfd67007e70190010UL) /* fd groove vol pool version 0 */
#define POOL_IMPL_STYLE 1
#include "../util/tmpl/fd_pool_para.c"

FD_PROTOTYPES_BEGIN

/* fd_groove_volume_pool_add adds the footprint sized memory region
   whose first byte is at shmem in the caller's local address space to
   the pool.  Assumes pool is a current local join, the storage to add
   is mapped into a memory region that starts and stops at a
   FD_GROOVE_VOLUME_FOOTPRINT multiple offset in the pool's address
   space, and this memory region does not conflict with any current
   groove volumes.

   The volume info for these will be initialized to the info_sz bytes
   pointed in the caller's local address space by info.  info_sz will
   treated as zero if info is NULL.  info_sz>FD_GROOVE_VOLUME_INFO_MAX
   will be treated as FD_GROOVE_VOLUME_INFO_MAX.  If
   info_sz<FD_GROOVE_VOLUME_INFO_MAX, any uninitialized bytes info will
   be initialized to zero.  Retains no interest in info.

   It is the caller's responsibility to zero / initialize any volume
   data region bytes (usually not necessary).

   On success, returns FD_GROOVE_SUCCESS (zero), the volumes were added
   to the pool as empty and the pool has ownership of the volumes.

   On failure, returns a FD_GROOVE_ERR code (negative, logs details).
   Reasons for failure include INVAL (pool is obviously not a local
   join, shmem/footprint obviously not a valid mapping ... no volumes
   added) and CORRUPT (memory corruption was detected ... if this was
   adding multiple volumes, some volumes might have been added before
   the corruption was encountered).

   This is safe to use concurrently, will not block the caller
   (reasonably fast O(volume_cnt) worst case) and will not block
   concurrent pool users. */

int
fd_groove_volume_pool_add( fd_groove_volume_pool_t * pool,
                           void *                    shmem,
                           ulong                     footprint,
                           void const *              info,
                           ulong                     info_sz );

/* fd_groove_volume_pool_remove removes an empty volume from the pool.
   On success, returns the location in the caller's address space of the
   removed volume (the volume will no longer be in the pool and the
   caller has ownership).  On failure, returns NULL (e.g. no volumes in
   pool were empty at some point during the call).  Logs details if
   anything wonky was detected.

   This is safe to use concurrently, will not block the caller
   (reasonably fast O(1) worst case) and will not block concurrent pool
   users. */

void *
fd_groove_volume_pool_remove( fd_groove_volume_pool_t * pool );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_groove_fd_groove_volume_h */
