#include "../util/fd_util.h"
#include "fd_funk.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "fd_cache.h"
#include "fd_funk_root.h"
#include "fd_funk_xaction.h"

struct fd_funk {
    // Workspace for allocation
    fd_wksp_t* wksp;
    // Generic allocator
    ulong alloc_offset;
    fd_alloc_t* alloc;
    // Backing file descriptor
    int backing_fd;
    char backing_name[128];
    // Length of backing file
    ulong backing_sz;
    // File offset of last control block in chain
    ulong lastcontrol;
    // Master index of finalized data
    ulong index_offset;
    fd_funk_index_t* index;
    // Table of transactions
    ulong xactions_offset;
    fd_funk_xactions_t* xactions;
    // Entry cache manager
    ulong cache_offset;
    fd_cache_t* cache;
    // Root transaction id
    fd_funk_xactionid_t root;
    // Transaction id of last successful commit
    fd_funk_xactionid_t last_commit;
    // Vector of free control entry locations
    fd_vec_ulong_t free_ctrl;
    // Dead entries indexed by allocation size
    fd_funk_vec_dead_entry_t deads[FD_FUNK_NUM_DISK_SIZES];
};

fd_funk_t* fd_funk_new(char const* backingfile,
                            fd_wksp_t* wksp,    // Workspace to allocate out of
                            ulong alloc_tag,    // Tag for workspace allocations
                            ulong index_max,    // Maximum size (count) of master index
                            ulong xactions_max, // Maximum size (count) of transaction index
                            ulong cache_max) {  // Maximum number of cache entries

  // Compute offsets and sizes of internal data structures
  ulong alloc_offset = fd_ulong_align_up(sizeof(struct fd_funk), fd_alloc_align());
  ulong alloc_footprint = fd_alloc_footprint();

  ulong index_offset = fd_ulong_align_up(alloc_offset + alloc_footprint, fd_funk_index_align());
  ulong index_footprint = fd_funk_index_footprint(index_max);
  
  ulong xactions_offset = fd_ulong_align_up(index_offset + index_footprint, fd_funk_xactions_align());
  ulong xactions_footprint = fd_funk_xactions_footprint(xactions_max);
  
  ulong cache_offset = fd_ulong_align_up(xactions_offset + xactions_footprint, fd_cache_align());
  ulong cache_footprint = fd_cache_footprint(cache_max);
  
  ulong footprint = cache_offset + cache_footprint;

  // Allocate space for the funk
  void* shmem = fd_wksp_alloc_laddr(wksp, fd_funk_align(), footprint, alloc_tag);
  if (NULL == shmem) {
    FD_LOG_ERR(("fd_wksp_alloc_laddr unable to allocate %ld bytes in the supplied workspace", footprint));
  }
  fd_funk_t* store = (fd_funk_t*)shmem;

  store->wksp = wksp;
  store->lastcontrol = 0;
  
  // Initialize the internal data structures
  store->alloc_offset = alloc_offset;
  store->alloc = fd_alloc_join(fd_alloc_new((char*)shmem + alloc_offset, alloc_tag), 0UL);

  char hostname[64];
  gethostname(hostname, sizeof(hostname));
  ulong hashseed = fd_hash(0, hostname, strnlen(hostname, sizeof(hostname)));
  store->index_offset = index_offset;
  store->index = fd_funk_index_new((char*)shmem + index_offset, index_max, hashseed);
  
  store->xactions_offset = xactions_offset;
  store->xactions = fd_funk_xactions_new((char*)shmem + xactions_offset, xactions_max, hashseed);
  
  store->cache_offset = cache_offset;
  store->cache = fd_cache_new((char*)shmem + cache_offset, cache_max);

  fd_vec_ulong_new(&store->free_ctrl);
  for (uint i = 0; i < FD_FUNK_NUM_DISK_SIZES; ++i)
    fd_funk_vec_dead_entry_new(&store->deads[i]);

  // Root transaction id is all zeros
  fd_memset(&store->root, 0, sizeof(store->root));
  fd_funk_xactionid_t_copy(&store->last_commit, &store->root);

  // Open the backing file
  strncpy(store->backing_name, backingfile, sizeof(store->backing_name)-1);
  store->backing_fd = open(backingfile, O_CREAT | O_RDWR, 0600);
  if (store->backing_fd == -1) {
    FD_LOG_ERR(("failed to open %s: %s", backingfile, strerror(errno)));
  }
  struct stat statbuf;
  if (fstat(store->backing_fd, &statbuf) == -1) {
    FD_LOG_ERR(("failed to open %s: %s", backingfile, strerror(errno)));
  }
  store->backing_sz = (ulong)statbuf.st_size;

  // Recover all state from control blocks
  fd_funk_replay_root(store);
  
  return store;
}

FD_FN_CONST ulong fd_funk_align(void) {
  return 64; // Cache aligned
}

void* fd_funk_delete(fd_funk_t* store) {
  fd_funk_index_destroy(store->index);
  fd_funk_xactions_cleanup(store);
  fd_funk_xactions_destroy(store->xactions);
  fd_cache_destroy(store->cache, store->alloc);
  fd_vec_ulong_destroy(&store->free_ctrl);
  for (uint i = 0; i < FD_FUNK_NUM_DISK_SIZES; ++i)
    fd_funk_vec_dead_entry_destroy(&store->deads[i]);
  if (!fd_alloc_is_empty(store->alloc))
    FD_LOG_ERR(("alloc leak detected!"));
  fd_alloc_delete(fd_alloc_leave(store->alloc));
  close(store->backing_fd);
  fd_wksp_free_laddr(store);
  return store;
}

fd_funk_xactionid_t const* fd_funk_root(fd_funk_t* store) {
  return &store->root;
}

long fd_funk_write(fd_funk_t* store,
                   fd_funk_xactionid_t const* xid,
                   fd_funk_recordid_t const* recordid,
                   const void* data,
                   ulong offset,
                   ulong data_sz) {
  struct iovec iov;
  iov.iov_base = (void*)data;
  iov.iov_len = data_sz;
  return fd_funk_writev(store, xid, recordid, &iov, 1, offset);
}

void fd_funk_truncate(fd_funk_t* store,
                      fd_funk_xactionid_t const* xid,
                      fd_funk_recordid_t const* recordid,
                      ulong record_sz);

int fd_funk_cache_query(fd_funk_t* store,
                        fd_funk_xactionid_t const* xid,
                        fd_funk_recordid_t const* recordid,
                        ulong offset,
                        ulong data_sz);

void fd_funk_cache_hint(fd_funk_t* store,
                        fd_funk_xactionid_t const* xid,
                        fd_funk_recordid_t const* recordid,
                        ulong offset,
                        ulong data_sz) {
  // Try to read but ignore failures
  const void* data;
  (void)fd_funk_read(store, xid, recordid, &data, offset, data_sz);
}

void fd_funk_validate(fd_funk_t* store) {
  fd_funk_validate_root(store);
  fd_funk_validate_xaction(store);
}

#include "fd_funk_root.c"
#include "fd_funk_xaction.c"
