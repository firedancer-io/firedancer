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

// Control block size
#define FD_FUNK_CONTROL_SIZE (64UL<<10)

// Hash a record id
ulong fd_funk_recordid_t_hash(struct fd_funk_recordid const* id, ulong hashseed) {
  return fd_hash(hashseed, id, sizeof(struct fd_funk_recordid));
}

// Test record id equality
int fd_funk_recordid_t_equal(struct fd_funk_recordid const* id1, struct fd_funk_recordid const* id2) {
  const ulong* const id1hack = (const ulong* const)id1;
  const ulong* const id2hack = (const ulong* const)id2;
  return ((id1hack[0] ^ id2hack[0]) |
          (id1hack[1] ^ id2hack[1]) |
          (id1hack[2] ^ id2hack[2]) |
          (id1hack[3] ^ id2hack[3]) |
          (id1hack[4] ^ id2hack[4]) |
          (id1hack[5] ^ id2hack[5]) |
          (id1hack[6] ^ id2hack[6]) |
          (id1hack[7] ^ id2hack[7])) == 0;
}

// Copy a record id
void fd_funk_recordid_t_copy(struct fd_funk_recordid* dest, struct fd_funk_recordid const* src) {
  ulong* const id1hack = (ulong* const)dest;
  const ulong* const id2hack = (const ulong* const)src;
  id1hack[0] = id2hack[0];
  id1hack[1] = id2hack[1];
  id1hack[2] = id2hack[2];
  id1hack[3] = id2hack[3];
  id1hack[4] = id2hack[4];
  id1hack[5] = id2hack[5];
  id1hack[6] = id2hack[6];
  id1hack[7] = id2hack[7];
}

struct fd_funk_index_entry {
    // Record identifier
    struct fd_funk_recordid key;
    // Position of control entry
    ulong control;
    // Offset into file for content.
    ulong start;
    // Length of content
    uint len;
    // Length of disk allocation
    uint alloc;
    // Version of this record
    uint version;
    // Next entry in hash chain
    uint next;
    // Cached data
    char* cache;
    // Length of cached data. May be less than len if we are just caching a prefix
    uint cachelen;
    // sizeof(fd_funk_index_entry) must be 128
    uint unused1;
    ulong unused2[2];
};

#define MAP_NAME fd_funk_index
#define MAP_ELEMENT struct fd_funk_index_entry
#define MAP_KEY fd_funk_recordid_t
#include "fd_map_giant.h"
#undef MAP_NAME
#undef MAP_ELEMENT
#undef MAP_KEY

// Round up a size to a valid disk allocation size
#define FD_FUNK_NUM_DISK_SIZES 44U
#define FD_FUNK_MAX_ENTRY_SIZE (10U<<20) /* 10 MB */
uint fd_funk_disk_size(ulong rawsize, uint* index) {
  static const uint ALLSIZES[FD_FUNK_NUM_DISK_SIZES] = {
    128, 256, 384, 512, 640, 768, 896, 1024, 1152, 1280, 1664, 2176, 2944, 3840,
    4992, 6528, 8576, 11264, 14720, 19200, 24960, 32512, 42368, 55168, 71808, 93440,
    121472, 157952, 205440, 267136, 347392, 451712, 587264, 763520, 992640, 1290496,
    1677696, 2181120, 2835456, 3686144, 4792064, 6229760, 8098688, FD_FUNK_MAX_ENTRY_SIZE
  };
  uint i = 0;
  while (i+4 < FD_FUNK_NUM_DISK_SIZES && rawsize >= ALLSIZES[i+4])
    i += 4;
  while (i+1 < FD_FUNK_NUM_DISK_SIZES && rawsize > ALLSIZES[i])
    i += 1;
  *index = i;
  return ALLSIZES[i];
}

struct fd_funk_control_entry {
    union {
        struct {
            int dummy;
        } empty;
        struct {
            // Record identifier
            struct fd_funk_recordid id;
            // Offset into file for content.
            ulong start;
            // Length of content
            uint len;
            // Length of disk allocation
            uint alloc;
            // Version of this record
            uint version;
        } normal;
        struct {
            // Offset into file for content.
            ulong start;
            // Length of disk allocation
            uint alloc;
        } dead;
    } u;
    uint type;
#define FD_FUNK_CONTROL_EMPTY 0 // Unused control entry
#define FD_FUNK_CONTROL_NORMAL 1 // Control entry for a normal record
#define FD_FUNK_CONTROL_DEAD 2 // Control entry for a dead record
};

#define FD_FUNK_ENTRIES_IN_CONTROL (FD_FUNK_CONTROL_SIZE/128)
struct fd_funk_control {
    // Make sure control entries don't cross block boundaries
    struct {
        struct fd_funk_control_entry entry;
        union {
            char pad[128 - sizeof(struct fd_funk_control_entry)];
            ulong next_control;
        } u;
    } entries[FD_FUNK_ENTRIES_IN_CONTROL];
};
#define FD_FUNK_CONTROL_NEXT(_ctrl_) (_ctrl_.entries[0].u.next_control)

#define VECT_NAME fd_vec_ulong
#define VECT_ELEMENT ulong
#include "fd_vector.h"
#undef VECT_NAME
#undef VECT_ELEMENT

struct fd_funk_dead_entry {
    // Position of control entry
    ulong control;
    // Offset into file for allocation
    ulong start;
};
#define VECT_NAME fd_funk_vec_dead_entry
#define VECT_ELEMENT struct fd_funk_dead_entry
#include "fd_vector.h"
#undef VECT_NAME
#undef VECT_ELEMENT

struct fd_funk {
    // Backing file descriptor
    int backingfd;
    // Length of backing file
    ulong backinglen;
    // File offset of last control block in chain
    ulong lastcontrol; 
    // Master index of finalized data
    struct fd_funk_index* index;
    // Root transaction id
    struct fd_funk_xactionid root;
    // Vector of free control entry locations
    struct fd_vec_ulong free_ctrl;
    // Dead entries indexed by allocation size
    struct fd_funk_vec_dead_entry deads[FD_FUNK_NUM_DISK_SIZES];
};

void fd_funk_make_dead(struct fd_funk* store, ulong control, ulong start, uint alloc) {
  uint k;
  ulong rsize = fd_funk_disk_size(alloc, &k);
  if (rsize != alloc) {
    FD_LOG_WARNING(("invalid record allocation in store"));
    return;
  }
  // Update deads lists
  struct fd_funk_dead_entry de;
  de.control = control;
  de.start = start;
  fd_funk_vec_dead_entry_push(&store->deads[k], de);
  // Update control on disk
  struct fd_funk_control_entry de2;
  fd_memset(&de2, 0, sizeof(de2));
  de2.type = FD_FUNK_CONTROL_DEAD;
  de2.u.dead.alloc = alloc;
  de2.u.dead.start = start;
  if (pwrite(store->backingfd, &de2, sizeof(de2), (long)control) < (long)sizeof(de2)) {
    FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
  }
}

void fd_funk_replay_control(struct fd_funk* store) {
  FD_STATIC_ASSERT(sizeof(struct fd_funk_control_entry) <= 120,fd_funk);
  FD_STATIC_ASSERT(sizeof(struct fd_funk_control) == FD_FUNK_CONTROL_SIZE,fd_funk);

  struct fd_funk_control ctrl;
  FD_STATIC_ASSERT(sizeof(ctrl.entries[0]) == 128,fd_funk);
  if (store->backinglen < sizeof(ctrl)) {
    // Initialize with an empty control block
    fd_memset(&ctrl, 0, sizeof(ctrl));
    if (pwrite(store->backingfd, &ctrl, sizeof(ctrl), 0) < (long)sizeof(ctrl)) {
      FD_LOG_ERR(("failed to initialize store: %s", strerror(errno)));
    }
  }

  // First control block is always at zero
  store->lastcontrol = 0;
  for (;;) {
    if (pread(store->backingfd, &ctrl, sizeof(ctrl), (long)store->lastcontrol) < (long)sizeof(ctrl)) {
      FD_LOG_WARNING(("failed to read backing file: %s", strerror(errno)));
      break;
    }
    if (store->lastcontrol + sizeof(ctrl) > store->backinglen)
      store->backinglen = store->lastcontrol + sizeof(ctrl);

    for (ulong i = 0; i < FD_FUNK_ENTRIES_IN_CONTROL; ++i) {
      struct fd_funk_control_entry* ent = &ctrl.entries[i].entry;
      // Compute file position of control entry
      ulong entpos = store->lastcontrol + (ulong)((char*)ent - (char*)&ctrl);
        
      if (ent->type == FD_FUNK_CONTROL_NORMAL) {
        // Account for gaps at the end
        if (ent->u.normal.start + ent->u.normal.alloc > store->backinglen)
          store->backinglen = ent->u.normal.start + ent->u.normal.alloc;
        int exists;
        struct fd_funk_index_entry* ent2 = fd_funk_index_insert(store->index, &ent->u.normal.id, &exists);
        if (exists) {
          FD_LOG_WARNING(("duplicate record id in store"));
          // Keep the later version. Delete the older one.
          if (ent2->version > ent->u.normal.version) {
            fd_funk_make_dead(store, entpos, ent->u.normal.start, ent->u.normal.alloc);
            // Leave ent2 alone
            continue;
          } else {
            fd_funk_make_dead(store, ent2->control, ent2->start, ent2->alloc);
            // Update ent2 below
          }
        }
          
        ent2->start = ent->u.normal.start;
        ent2->len = ent->u.normal.len;
        ent2->alloc = ent->u.normal.alloc;
        ent2->version = ent->u.normal.version;
        ent2->control = entpos;
        ent2->cache = NULL;
        ent2->cachelen = 0;

      } else if (ent->type == FD_FUNK_CONTROL_DEAD) {
        // Account for gaps at the end
        if (ent->u.dead.start + ent->u.dead.alloc > store->backinglen)
          store->backinglen = ent->u.dead.start + ent->u.dead.alloc;
        uint k;
        ulong rsize = fd_funk_disk_size(ent->u.dead.alloc, &k);
        if (rsize != ent->u.dead.alloc) {
          FD_LOG_WARNING(("invalid record allocation in store"));
          continue;
        }
        struct fd_funk_dead_entry de;
        de.control = entpos;
        de.start = ent->u.dead.start;
        fd_funk_vec_dead_entry_push(&store->deads[k], de);

      } else if (ent->type == FD_FUNK_CONTROL_EMPTY) {
        fd_vec_ulong_push(&store->free_ctrl, entpos);
      }
    }

    ulong next = FD_FUNK_CONTROL_NEXT(ctrl);
    if (!next)
      break;
    store->lastcontrol = next;
  }
}

int fd_funk_allocate_disk(struct fd_funk* store, ulong datalen, ulong* control, ulong* start, uint* alloc) {
  uint k;
  *alloc = fd_funk_disk_size(datalen, &k);
  if (datalen > *alloc) {
    FD_LOG_WARNING(("entry too large"));
    return 0;
  }
  
  // Look for a dead control which owns a chunk of disk of the right size
  struct fd_funk_vec_dead_entry* vec = &store->deads[k];
  if (!fd_funk_vec_dead_entry_empty(vec)) {
    struct fd_funk_dead_entry de = fd_funk_vec_dead_entry_pop_unsafe(vec);
    *control = de.control;
    *start = de.start;
    return 1;
  }
  
  if (fd_vec_ulong_empty(&store->free_ctrl)) {
    // Make a batch of empty controls
    const ulong ctrlpos = store->backinglen;
    struct fd_funk_control ctrl;
    fd_memset(&ctrl, 0, sizeof(ctrl));
    if (pwrite(store->backingfd, &ctrl, sizeof(ctrl), (long)ctrlpos) < (long)sizeof(ctrl)) {
      FD_LOG_WARNING(("failed to write store: %s", strerror(errno)));
      return 0;
    }
    store->backinglen = ctrlpos + sizeof(ctrl);
    for (ulong i = 0; i < FD_FUNK_ENTRIES_IN_CONTROL; ++i) {
      struct fd_funk_control_entry* ent = &ctrl.entries[i].entry;
      // Compute file position of control entry
      ulong entpos = ctrlpos + (ulong)((char*)ent - (char*)&ctrl);
      fd_vec_ulong_push(&store->free_ctrl, entpos);
    }
    // Chain together control blocks
    long offset = (char*)(&FD_FUNK_CONTROL_NEXT(ctrl)) - (char*)&ctrl;
    if (pwrite(store->backingfd, &ctrlpos, sizeof(ctrlpos), (long)store->lastcontrol + offset) < (long)sizeof(ctrlpos)) {
      FD_LOG_WARNING(("failed to write store: %s", strerror(errno)));
      return 0;
    }
    store->lastcontrol = ctrlpos;
  }

  // Grow the file
  *control = fd_vec_ulong_pop_unsafe(&store->free_ctrl);
  *start = store->backinglen;
  store->backinglen += *alloc;
  return 1;
}

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
  fd_funk_index_new(store->index, footprint/3, hashseed);

  fd_vec_ulong_new(&store->free_ctrl);
  for (uint i = 0; i < FD_FUNK_NUM_DISK_SIZES; ++i)
    fd_funk_vec_dead_entry_new(&store->deads[i]);

  // Recover all state from control blocks
  fd_funk_replay_control(store);

  // Root is all zeros
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
  close(store->backingfd);
  return mem;
}

struct fd_funk_xactionid const* fd_funk_root(struct fd_funk* store) {
  return &store->root;
}

int fd_funk_is_root(struct fd_funk_xactionid const* xid) {
  // A xactionid is 4 ulongs long
  FD_STATIC_ASSERT(sizeof(struct fd_funk_xactionid)/sizeof(ulong) == 4,fd_funk);

  const ulong* const idhack = (const ulong* const)xid;
  return (idhack[0] | idhack[1] | idhack[2] | idhack[3]) == 0;
}

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

void fd_funk_update_control_from_index(struct fd_funk* store,
                                       struct fd_funk_index_entry* ent) {
  struct fd_funk_control_entry ctrl;
  fd_memset(&ctrl, 0, sizeof(ctrl));
  ctrl.type = FD_FUNK_CONTROL_NORMAL;
  fd_funk_recordid_t_copy(&ctrl.u.normal.id, &ent->key);
  ctrl.u.normal.start = ent->start;
  ctrl.u.normal.len = ent->len;
  ctrl.u.normal.alloc = ent->alloc;
  ctrl.u.normal.version = ent->version;
  if (pwrite(store->backingfd, &ctrl, sizeof(ctrl), (long)ent->control) < (long)sizeof(ctrl)) {
    FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
  }
}

long fd_funk_write_root(struct fd_funk* store,
                        struct fd_funk_recordid const* recordid,
                        const void* data,
                        ulong offset,
                        ulong datalen) {
  const ulong newlen = offset + datalen;
  // See if this is a new record
  int exists;
  struct fd_funk_index_entry* ent = fd_funk_index_insert(store->index, recordid, &exists);
  if (ent == NULL) {
    FD_LOG_WARNING(("index is full, cannot create a new record"));
    return -1;
  }
  
  if (exists) {
    // Patch the cache
    if (ent->cache && offset < ent->cachelen)
      fd_memcpy(ent->cache + offset, data,
                (datalen <= ent->cachelen - offset ? datalen : ent->cachelen - offset));
    
    if (newlen <= ent->alloc) {
      // Can update in place. Just patch the disk storage
      if (offset > ent->len) {
        // Zero fill gap in disk space
        ulong zeroslen = offset - ent->len;
        char* zeros = fd_alloca(1, zeroslen);
        fd_memset(zeros, 0, zeroslen);
        if (pwrite(store->backingfd, zeros, zeroslen, (long)(ent->start + ent->len)) < (long)zeroslen) {
          FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
          return -1;
        }
      }
      if (pwrite(store->backingfd, data, datalen, (long)(ent->start + offset)) < (long)datalen) {
        FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
        return -1;
      }
      if (ent->len < newlen) {
        // Update the control with the new length
        ent->len = (uint)newlen;
        fd_funk_update_control_from_index(store, ent);
      }
      return (long)datalen;
      
    } else {
      // Hard case where we must move and grow the entry at the same
      // time. Create a new record with a new version number first
      uint oldlen = ent->len;
      ulong oldcontrol = ent->control;
      ulong oldstart = ent->start;
      uint oldalloc = ent->alloc;
      if (!fd_funk_allocate_disk(store, newlen, &ent->control, &ent->start, &ent->alloc))
        // Allocation failure
        return -1;
      ulong newstart = ent->start;
      ent->len = (uint)newlen;
      ent->version ++;
      // Track how much we have written so far
      uint done = 0;
      if (ent->cache) {
        // Start by writing out what we cached because this is easy
        if (pwrite(store->backingfd, ent->cache, ent->cachelen, (long)newstart) < (long)ent->cachelen) {
          FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
          return -1;
        }
        done = ent->cachelen;
      }
      char* tmpbuf = NULL;
      int tmpbuflen = 0;
      // Copy old data that came before the update
      int beforelen = (int)((offset < oldlen ? offset : oldlen) - done);
      if (beforelen > 0) {
        if (tmpbuf == NULL || beforelen > tmpbuflen) {
          tmpbuf = fd_alloca(1, (uint)beforelen);
          tmpbuflen = beforelen;
        }
        if (pread(store->backingfd, tmpbuf, (ulong)beforelen, (long)(oldstart + done)) < (long)beforelen) {
          FD_LOG_WARNING(("failed to read backing file: %s", strerror(errno)));
          return -1;
        }
        if (pwrite(store->backingfd, tmpbuf, (ulong)beforelen, (long)(newstart + done)) < (long)beforelen) {
          FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
          return -1;
        }
        done += (uint)beforelen;
      }
      // Fill gap with zeros
      int zeroslen = (int)(offset - done);
      if (zeroslen > 0) {
        if (tmpbuf == NULL || zeroslen > tmpbuflen) {
          tmpbuf = fd_alloca(1, (uint)zeroslen);
          tmpbuflen = zeroslen;
        }
        fd_memset(tmpbuf, 0, (ulong)zeroslen);
        if (pwrite(store->backingfd, tmpbuf, (ulong)zeroslen, (long)(newstart + done)) < (long)zeroslen) {
          FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
          return -1;
        }
        done += (uint)zeroslen;
      }
      // Write out whatever is left of the original update
      int updatelen = (int)(newlen - done);
      if (updatelen > 0) {
        if (pwrite(store->backingfd, (const char*)data + (datalen - (uint)updatelen),
                   (ulong)updatelen, (long)(newstart + done)) < (long)updatelen) {
          FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
          return -1;
        }
      }
      // Data is ready. Finally update the control.
      // Write out the new version first in case we crash in the
      // middle. If duplicate keys are found during recovery, the newer
      // version wins.
      fd_funk_update_control_from_index(store, ent);
      // Collect old control and disk space
      fd_funk_make_dead(store, oldcontrol, oldstart, oldalloc);
      return (long)datalen;
    }
    
  } else {
    // Create a new record
    if (!fd_funk_allocate_disk(store, newlen, &ent->control, &ent->start, &ent->alloc))
      // Allocation failure
      return -1;
    ent->len = (uint)newlen;
    ent->version = 1;
    ent->cache = NULL;
    ent->cachelen = 0;
    if (offset > 0) {
      // Zero fill gap in disk space
      char* zeros = fd_alloca(1, offset);
      fd_memset(zeros, 0, offset);
      if (pwrite(store->backingfd, zeros, offset, (long)ent->start) < (long)offset) {
        FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
        return -1;
      }
    }
    if (pwrite(store->backingfd, data, datalen, (long)(ent->start + offset)) < (long)datalen) {
      FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
      return -1;
    }
    // Data is in place. Update the control.
    fd_funk_update_control_from_index(store, ent);
    return (long)datalen;
  }
}

long fd_funk_write(struct fd_funk* store,
                   struct fd_funk_xactionid const* xid,
                   struct fd_funk_recordid const* recordid,
                   const void* data,
                   ulong offset,
                   ulong datalen) {
  if (fd_funk_is_root(xid))
    return fd_funk_write_root(store, recordid, data, offset, datalen);
  FD_LOG_ERR(("transactions not supported yet"));
  return -1;
}

long fd_funk_read_root(struct fd_funk* store,
                       struct fd_funk_recordid const* recordid,
                       const void** data,
                       ulong offset,
                       ulong datalen) {
  *data = NULL; // defensive
  struct fd_funk_index_entry* ent = fd_funk_index_query(store->index, recordid);
  // See if we got a hit
  if (ent == NULL)
    return -1;
  // See if we are reading past the end of the record
  if (offset >= ent->len)
    return 0;
  if (offset + datalen > ent->len)
    datalen = ent->len - offset;
  ulong neededlen = offset + datalen;
  if (ent->cache == NULL || neededlen > ent->cachelen) {
    // Load the cache. We can cache a prefix rather than the entire
    // record. This is useful if metadata is in front of the real data.
    ent->cachelen = (uint)neededlen;
    if (ent->cache)
      free(ent->cache);
    ent->cache = malloc(neededlen);
    if (pread(store->backingfd, ent->cache, neededlen, (long)ent->start) < (long)neededlen) {
      FD_LOG_WARNING(("failed to read backing file: %s", strerror(errno)));
      free(ent->cache);
      ent->cache = NULL;
      return -1;
    }
  }
  *data = ent->cache + offset;
  return (long)datalen;
}

long fd_funk_read(struct fd_funk* store,
                  struct fd_funk_xactionid const* xid,
                  struct fd_funk_recordid const* recordid,
                  const void** data,
                  ulong offset,
                  ulong datalen) {
  if (fd_funk_is_root(xid))
    return fd_funk_read_root(store, recordid, data, offset, datalen);
  FD_LOG_ERR(("transactions not supported yet"));
  return -1;
}

void fd_funk_truncate(struct fd_funk* store,
                      struct fd_funk_xactionid const* xid,
                      struct fd_funk_recordid const* recordid,
                      ulong recordlen);

void fd_funk_delete_record_root(struct fd_funk* store,
                                struct fd_funk_recordid const* recordid) {
  
  struct fd_funk_index_entry* ent = fd_funk_index_remove(store->index, recordid);
  if (ent == NULL) {
    // Doesn't exist
    return;
  }
  if (ent->cache != NULL)
    free(ent->cache);
  fd_funk_make_dead(store, ent->control, ent->start, ent->alloc);
}

void fd_funk_delete_record(struct fd_funk* store,
                           struct fd_funk_xactionid const* xid,
                           struct fd_funk_recordid const* recordid) {
  if (fd_funk_is_root(xid)) {
    fd_funk_delete_record_root(store, recordid);
    return;
  }
  FD_LOG_ERR(("transactions not supported yet"));
}

uint fd_funk_num_records(struct fd_funk* store) {
  return store->index->used;
}

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
  if (!fd_funk_index_validate(store->index))
    FD_LOG_ERR(("index is corrupt"));

  char* scratch = malloc(FD_FUNK_MAX_ENTRY_SIZE);

  ulong normalcnt = 0;
  ulong emptycnt = 0;
  ulong deadcnt[FD_FUNK_NUM_DISK_SIZES];
  fd_memset(deadcnt, 0, sizeof(deadcnt));
  
  struct fd_funk_control ctrl;
  ulong ctrlpos = 0;
  ulong allocpos = 0;
  for (;;) {
    if (pread(store->backingfd, &ctrl, sizeof(ctrl), (long)ctrlpos) < (long)sizeof(ctrl))
      FD_LOG_ERR(("failed to read backing file: %s", strerror(errno)));
    if (ctrlpos + sizeof(ctrl) > store->backinglen)
      FD_LOG_ERR(("backinglen is wrong"));
    if (ctrlpos < allocpos)
      FD_LOG_ERR(("overlapping allocations"));
    allocpos = ctrlpos + sizeof(ctrl);

    // It is an artifact of the way disk is allocated that reversed
    // control order gets all allocations in ascending positional order
    for (int i=FD_FUNK_ENTRIES_IN_CONTROL-1; i >= 0; --i) {
      struct fd_funk_control_entry* ent = &ctrl.entries[i].entry;
      // Compute file position of control entry
      ulong entpos = ctrlpos + (ulong)((char*)ent - (char*)&ctrl);
        
      if (ent->type == FD_FUNK_CONTROL_NORMAL) {
        if (ent->u.normal.start + ent->u.normal.alloc > store->backinglen)
          FD_LOG_ERR(("backinglen is wrong"));
        struct fd_funk_index_entry* ent2 = fd_funk_index_query(store->index, &ent->u.normal.id);
        if (ent2 == NULL)
          FD_LOG_ERR(("index missing entry"));
        if (!(ent2->start == ent->u.normal.start ||
              ent2->len == ent->u.normal.len ||
              ent2->alloc == ent->u.normal.alloc ||
              ent2->version == ent->u.normal.version ||
              ent2->control == entpos))
          FD_LOG_ERR(("index is wrong"));
        if (ent->u.normal.len > FD_FUNK_MAX_ENTRY_SIZE ||
            ent->u.normal.len > ent->u.normal.alloc)
          FD_LOG_ERR(("lengths make no sense"));
        uint k;
        ulong rsize = fd_funk_disk_size(ent->u.normal.alloc, &k);
        if (rsize != ent->u.normal.alloc || k >= FD_FUNK_NUM_DISK_SIZES)
          FD_LOG_ERR(("invalid record allocation in store"));
        if (ent2->cache != NULL) {
          if (ent2->cachelen > ent->u.normal.len)
            FD_LOG_ERR(("cache too large"));
          if (pread(store->backingfd, scratch, ent2->cachelen, (long)ent->u.normal.start) < (long)ent2->cachelen)
            FD_LOG_ERR(("failed to read backing file: %s", strerror(errno)));
          if (memcmp(scratch, ent2->cache, ent2->cachelen) != 0)
            FD_LOG_ERR(("cache is wrong"));
        }
        if (ent->u.normal.start < allocpos)
          FD_LOG_ERR(("overlapping allocations"));
        allocpos = ent->u.normal.start + ent->u.normal.alloc;
        normalcnt++;

      } else if (ent->type == FD_FUNK_CONTROL_DEAD) {
        if (ent->u.dead.start + ent->u.dead.alloc > store->backinglen)
          FD_LOG_ERR(("backinglen is wrong"));
        uint k;
        ulong rsize = fd_funk_disk_size(ent->u.dead.alloc, &k);
        if (rsize != ent->u.dead.alloc || k >= FD_FUNK_NUM_DISK_SIZES)
          FD_LOG_ERR(("invalid record allocation in store"));
        if (ent->u.dead.start < allocpos)
          FD_LOG_ERR(("overlapping allocations"));
        allocpos = ent->u.dead.start + ent->u.dead.alloc;
        deadcnt[k]++;

      } else if (ent->type == FD_FUNK_CONTROL_EMPTY) {
        emptycnt++;
      }
    }

    ulong next = FD_FUNK_CONTROL_NEXT(ctrl);
    if (!next)
      break;
    ctrlpos = next;
  }

  if (normalcnt != store->index->used)
    FD_LOG_ERR(("wrong count for normal entries"));
  for (uint i = 0; i < FD_FUNK_NUM_DISK_SIZES; ++i) {
    if (deadcnt[i] != store->deads[i].cnt)
      FD_LOG_ERR(("wrong count for dead entries"));
  }
  if (emptycnt != store->free_ctrl.cnt)
    FD_LOG_ERR(("wrong count for free entries"));

  free(scratch);
}
