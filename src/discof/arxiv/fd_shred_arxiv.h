#ifndef HEADER_fd_src_flamenco_runtime_fd_shred_archive_h
#define HEADER_fd_src_flamenco_runtime_fd_shred_archive_h

#include "../../flamenco/runtime/fd_blockstore.h"

struct fd_shred_idx {
    ulong     key;   /* 32 msb slot, 32 lsb idx */
    ulong     next;
    uint      hash;
    ulong     off;
    ulong     sz;
};
typedef struct fd_shred_idx fd_shred_idx_t;

#define MAP_NAME          fd_shred_idx
#define MAP_T             fd_shred_idx_t
#define MAP_KEY           key
#define MAP_KEY_HASH(key) ((uint)(key)) /* finalized slots are guaranteed to be unique so perfect hashing */
#include "../../util/tmpl/fd_map_dynamic.c"

struct fd_shred_off { /* truly cannot think of a better way rn... */
  ulong key;
};
typedef struct fd_shred_off fd_shred_off_t;

struct __attribute__((aligned(128UL))) fd_shred_arxiver {
    ulong fd_size_max;      /* maximum size of the archival file */
    ulong shred_max;       /* maximum # of shreds that can be held in file (fd_size_max / FD_SHRED_MAX_SZ) */

    fd_shred_idx_t * shred_idx; /* pointer to shred_idx map */
    fd_shred_off_t * shred_off; /* pointer to shred_off map */
    int   fd;                /* file descriptor for the archive file */
    ulong tail;             /* location after most recently written block */
};
typedef struct fd_shred_arxiver fd_shred_arxiver_t;

#define FD_SHRED_ARXIV_UNIT_SZ  FD_SHRED_MAX_SZ /* max size of each element in the arxiv file */ /* will want to switch this to the payload ... actually ... */
#define FD_SHRED_ARXIV_MIN_SIZE (FD_SHRED_ARXIV_UNIT_SZ * 1024UL) /* minimum size of the archive file */

FD_FN_CONST static inline ulong
fd_shred_arxiv_align( void ) {
    return alignof(fd_shred_arxiver_t);
}

/* fd_shred_arxiv_footprint returns the footprint of the entire
   fd_shred_arxiver_t including data structures. */
FD_FN_CONST static inline ulong
fd_shred_arxiv_footprint( ulong fd_size_max ) {
  ulong shred_max  = fd_size_max / FD_SHRED_ARXIV_UNIT_SZ;
  int lg_shred_max = fd_ulong_find_msb( fd_ulong_pow2_up( shred_max ) ) + 1;
  return FD_LAYOUT_FINI(
      FD_LAYOUT_APPEND(
      FD_LAYOUT_APPEND(
      FD_LAYOUT_APPEND(
      FD_LAYOUT_INIT,
          alignof(fd_shred_arxiver_t), sizeof(fd_shred_arxiver_t) ),
          fd_shred_idx_align(),       fd_shred_idx_footprint( lg_shred_max ) ),
          alignof(fd_shred_off_t),    sizeof(fd_shred_off_t) * shred_max ),
      fd_shred_arxiv_align() );
}

/* fd_shred_arxiv_new formats an unused memory region for use as a
   arxiver.  mem is a non-NULL pointer to this region in the local
   address space with the required footprint and alignment. */

void *
fd_shred_arxiv_new( void * mem, ulong fd_size_max );

fd_shred_arxiver_t *
fd_shred_arxiv_join( void * shmem );

void *
fd_shred_arxiv_leave( fd_shred_arxiver_t * shred_arxiv );

void *
fd_shred_arxiv_delete( void * shred_arxiv );


/* Archives a block and block map entry to fd at shred->off, and does
   any necessary bookkeeping.
   If fd is -1, no write is attempted. Returns written size */
void
fd_shreds_checkpt( fd_shred_arxiver_t * arxiv,
                   fd_blockstore_t    * blockstore,
                   ulong slot,
                   uint  start_idx,
                   uint  end_idx /* inclusive */ );

/* Restores a block and block map entry from fd at given offset. As this used by
   rpcserver, it must return an error code instead of throwing an error on failure. */
int
fd_shred_restore( fd_shred_arxiver_t * arxiv,
                  fd_shred_idx_t * block_idx_entry,
                  uchar * buf_out,
                  ulong buf_max );

/* Returns 0 if the archive metadata is valid */
int
fd_shred_arxiv_verify( fd_shred_arxiver_t * archiver );

#endif /* HEADER_fd_src_flamenco_runtime_fd_shred_archive_h */
