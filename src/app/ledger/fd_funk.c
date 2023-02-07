#include "../../util/fd_util.h"
#include "fd_funk.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

struct fd_funk {
    // Backing file descriptor
    int backingfd;
    // Length of backing file
    long backinglen;
};

struct fd_funk_control_entry {
    union {
        struct {
            int dummy;
        } empty;
        struct {
            // Record identifier
            struct fd_funk_recordid id;
            // Offset into file
            ulong start; 
            // Length of content
            ulong len;
        } normal;
    } u;
    uchar type;
#define FD_FUNK_CONTROL_EMPTY 0 // Unused control entry
#define FD_FUNK_CONTROL_NORMAL 1 // Control entry for a normal record
};

void* fd_funk_new(void* mem,
                  ulong footprint,
                  char const* backingfile) {
  if (footprint < fd_funk_footprint_min())
    FD_LOG_ERR(("footprint too small for fd_funk"));
  struct fd_funk* store = (struct fd_funk*)mem;
  
  store->backingfd = open(backingfile, O_CREAT, 0600);
  if (store->backingfd == -1) {
    FD_LOG_ERR(("failed to open %s: %s", backingfile, strerror(errno)));
  }
  struct stat statbuf;
  if (fstat(store->backingfd, &statbuf) == -1) {
    FD_LOG_ERR(("failed to open %s: %s", backingfile, strerror(errno)));
  }
  store->backinglen = statbuf.st_size;
  
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
  close(store->backingfd);
  return mem;
}

struct fd_funk_xactionid const* fd_funk_root(struct fd_funk* store);

void fd_funk_fork(struct fd_funk* store,
                  struct fd_funk_xactionid const* parent,
                  struct fd_funk_xactionid const* child);

void fd_funk_commit(struct fd_funk* store,
                    struct fd_funk_xactionid const* id);

void fd_funk_cancel(struct fd_funk* store,
                    struct fd_funk_xactionid const* id);

void fd_funk_merge(struct fd_funk* store,
                   struct fd_funk_xactionid const* destid,
                   ulong source_cnt,
                   struct fd_funk_xactionid const* const* source_ids);

int fd_funk_isopen(struct fd_funk* store,
                   struct fd_funk_xactionid const* id);

void fd_funk_write(struct fd_funk* store,
                   struct fd_funk_xactionid const* xid,
                   struct fd_funk_recordid const* recordid,
                   const void* data,
                   ulong offset,
                   ulong datalen);

long fd_funk_read(struct fd_funk* store,
                  struct fd_funk_xactionid const* xid,
                  struct fd_funk_recordid const* recordid,
                  void* data,
                  ulong offset,
                  ulong datalen);

void fd_funk_truncate(struct fd_funk* store,
                      struct fd_funk_xactionid const* xid,
                      struct fd_funk_recordid const* recordid,
                      ulong recordlen);

void fd_funk_delete_record(struct fd_funk* store,
                           struct fd_funk_xactionid const* xid,
                           struct fd_funk_recordid const* recordid);

int fd_funk_cache_query(struct fd_funk* store,
                        struct fd_funk_xactionid const* xid,
                        struct fd_funk_recordid const* recordid);

void fd_funk_cache_hint(struct fd_funk* store,
                        struct fd_funk_xactionid const* xid,
                        struct fd_funk_recordid const* recordid);
