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

#define FD_FUNK_NUM_DISK_SIZES 44U
#define FD_FUNK_MAX_ENTRY_SIZE (10U<<20) /* 10 MB */

struct fd_funk {
    // Backing file descriptor
    int backingfd;
    // Length of backing file
    ulong backinglen;
    // File offset of last control block in chain
    ulong lastcontrol; 
    // Master index of finalized data
    struct fd_funk_index* index;
    // Table of live transactions
    struct fd_funk_xactions* xactions;
    // Entry cache manager
    struct fd_cache* cache;
    // Root transaction id
    struct fd_funk_xactionid root;
    // Vector of free control entry locations
    struct fd_vec_ulong free_ctrl;
    // Dead entries indexed by allocation size
    struct fd_funk_vec_dead_entry deads[FD_FUNK_NUM_DISK_SIZES];
};

void* fd_funk_new(void* mem,
                  ulong footprint,
                  char const* backingfile) {
  if (footprint < fd_funk_footprint_min())
    FD_LOG_ERR(("footprint too small for fd_funk"));
  struct fd_funk* store = (struct fd_funk*)mem;
  
  store->backingfd = open(backingfile, O_CREAT | O_RDWR, 0600);
  if (store->backingfd == -1) {
    FD_LOG_ERR(("failed to open %s: %s", backingfile, strerror(errno)));
  }
  struct stat statbuf;
  if (fstat(store->backingfd, &statbuf) == -1) {
    FD_LOG_ERR(("failed to open %s: %s", backingfile, strerror(errno)));
  }
  store->backinglen = (ulong)statbuf.st_size;

  // Reserve 1/3 of the footprint for the master index
  FD_STATIC_ASSERT(sizeof(struct fd_funk_index_entry) == 128,fd_funk);
  void* mem2 = store+1;
  store->index = (struct fd_funk_index*)mem2;
  char hostname[64];
  gethostname(hostname, sizeof(hostname));
  ulong hashseed = fd_hash(0, hostname, strnlen(hostname, sizeof(hostname)));
  ulong fp2 = fd_funk_index_new(store->index, footprint/3, hashseed);

  // Allocate 1/2 of the footprint for the cache
  void* mem3 = (char*)mem2 + fp2;
  ulong fp3 = footprint/2;
  store->cache = fd_cache_new(store->index->capacity/16, fp3, mem3);

  // Allocate a chunk for the transaction table
  void* mem4 = (char*)mem3 + fp3;
  store->xactions = (struct fd_funk_xactions*)mem4;
  ulong fp4 = fd_funk_xactions_new(store->xactions, footprint/32, hashseed);

  if ((char*)mem4 + fp4 > (char*)mem + footprint)
    FD_LOG_ERR(("confused allocation math"));

  fd_vec_ulong_new(&store->free_ctrl);
  for (uint i = 0; i < FD_FUNK_NUM_DISK_SIZES; ++i)
    fd_funk_vec_dead_entry_new(&store->deads[i]);

  // Recover all state from control blocks
  fd_funk_replay_root(store);

  // Root transaction id is all zeros
  fd_memset(&store->root, 0, sizeof(store->root));
  
  return store;
}

FD_FN_CONST ulong fd_funk_footprint_min(void) {
  return 64UL << 20; // 64MB just to be safe
}

FD_FN_CONST ulong fd_funk_align(void) {
  return 64; // Cache aligned
}

struct fd_funk* fd_funk_join(void* mem) {
  struct fd_funk* store = (struct fd_funk*)mem;
  return store;
}

void* fd_funk_leave(struct fd_funk* store) {
  return store;
}

void* fd_funk_delete(void* mem) {
  struct fd_funk* store = (struct fd_funk*)mem;
  fd_funk_index_destroy(store->index);
  fd_funk_xactions_destroy(store->xactions);
  fd_cache_destroy(store->cache);
  fd_vec_ulong_destroy(&store->free_ctrl);
  for (uint i = 0; i < FD_FUNK_NUM_DISK_SIZES; ++i)
    fd_funk_vec_dead_entry_destroy(&store->deads[i]);
  close(store->backingfd);
  return mem;
}

struct fd_funk_xactionid const* fd_funk_root(struct fd_funk* store) {
  return &store->root;
}

void fd_funk_truncate(struct fd_funk* store,
                      struct fd_funk_xactionid const* xid,
                      struct fd_funk_recordid const* recordid,
                      ulong recordlen);

int fd_funk_cache_query(struct fd_funk* store,
                        struct fd_funk_xactionid const* xid,
                        struct fd_funk_recordid const* recordid,
                        ulong offset,
                        ulong datalen);

void fd_funk_cache_hint(struct fd_funk* store,
                        struct fd_funk_xactionid const* xid,
                        struct fd_funk_recordid const* recordid,
                        ulong offset,
                        ulong datalen) {
  // Try to read but ignore failures
  const void* data;
  (void)fd_funk_read(store, xid, recordid, &data, offset, datalen);
}

void fd_funk_validate(struct fd_funk* store) {
  fd_funk_validate_root(store);
}

#include "fd_funk_root.c"
#include "fd_funk_xaction.c"
