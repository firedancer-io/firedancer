#include "../../util/fd_util.h"
#include "fd_funk.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

// Smallest unit of disk allocation
#define FD_FUNK_MINIBLOCK_SIZE 512

// Starting size of master index
#define FD_FUNK_INDEX_START_SIZE (1UL<<13)

// Hash a record id
ulong fd_funk_recordid_hash(struct fd_funk_recordid* id) {
  // A recordid is 8 ulongs long
  FD_STATIC_ASSERT(sizeof(struct fd_funk_recordid)/sizeof(ulong) == 8,fd_funk);

  // Multiply parts by random primes
  const ulong* const idhack = (const ulong* const)id;
#define ROTATE_LEFT(x,r) (((x)<<(r)) | ((x)>>(64-(r))))
  return ((idhack[0]*544625467UL + ROTATE_LEFT(idhack[1],31)*921290941UL) ^
          (idhack[1]*499335469UL + ROTATE_LEFT(idhack[2],31)*406155949UL) ^
          (idhack[2]*550225019UL + ROTATE_LEFT(idhack[3],31)*920227961UL) ^
          (idhack[3]*872766749UL + ROTATE_LEFT(idhack[4],31)*711342493UL) ^
          (idhack[4]*324462059UL + ROTATE_LEFT(idhack[5],31)*165217477UL) ^
          (idhack[5]*573508609UL + ROTATE_LEFT(idhack[6],31)*817180781UL) ^
          (idhack[6]*896075273UL + ROTATE_LEFT(idhack[7],31)*507836809UL) ^
          (idhack[7]*800558767UL + ROTATE_LEFT(idhack[0],31)*927185099UL));
}

// Test record id equality
int fd_funk_recordid_equal(struct fd_funk_recordid* id1, struct fd_funk_recordid* id2) {
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
void fd_funk_recordid_copy(struct fd_funk_recordid* dest, struct fd_funk_recordid const* src) {
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
    struct fd_funk_recordid id __attribute__ ((aligned(FD_FUNK_RECORDID_ALIGN)));
    // Hash of identifier
    ulong idhash;
    // Offset into file for content. Must be a multiple of
    // FD_FUNK_MINIBLOCK_SIZE. Zero means the entry is unused.
    ulong start; 
    // Length of content
    ulong len;
    // Position of control entry
    ulong control;
    ulong unused[4];
};

int fd_funk_index_entry_valid(struct fd_funk_index_entry* entry) {
  return entry->start != 0;
}

// Gigantic flat hash table which serves as the master record index for finalized data.
struct fd_funk_index {
    // Number of entries allocated. Must be a power of 2.
    ulong allocsize;
    // Number of entries in use.
    ulong numinuse;
    ulong unused[6];
};

// Allocate an empty index with the given number of slots
struct fd_funk_index* fd_funk_index_new(const ulong allocsize) {
  FD_STATIC_ASSERT(sizeof(struct fd_funk_index)==64,fd_funk);
  FD_STATIC_ASSERT(sizeof(struct fd_funk_index_entry)==128,fd_funk);
  if ((allocsize&(allocsize-1)) != 0) // Power of 2
    FD_LOG_ERR(("fd_funk_index size must be a power of 2"));
  
  // !!! Replace malloc with zone allocator
  struct fd_funk_index* index = (struct fd_funk_index*)
    malloc(sizeof(struct fd_funk_index) + sizeof(struct fd_funk_index_entry)*allocsize);
  index->allocsize = allocsize;
  index->numinuse = 0;
  struct fd_funk_index_entry* entries = (struct fd_funk_index_entry*)(index + 1);
  for (struct fd_funk_index_entry* i = entries; i < entries + allocsize; ++i) {
    i->start = 0; // Mark as invalid
  }
  
  return index;
}

// Move an entry to the right location
struct fd_funk_index_entry* fd_funk_index_relocate(struct fd_funk_index* index,
                                                   struct fd_funk_index_entry* ent) {
  const ulong size = index->allocsize;
  struct fd_funk_index_entry* const entries = (struct fd_funk_index_entry*)(index + 1);
  struct fd_funk_index_entry* i = entries + (ent->idhash & (size-1));
  while (fd_funk_index_entry_valid(i)) {
    if (ent->idhash == i->idhash && fd_funk_recordid_equal(&(ent->id), &(i->id))) {
      if (ent != i) {
        fd_memcpy(i, ent, sizeof(struct fd_funk_index_entry));
        ent->start = 0; // Invalidate old location
      }
      return i;
    }
    if (++i == entries + size)
      i = entries;
  }
  fd_memcpy(i, ent, sizeof(struct fd_funk_index_entry));
  ent->start = 0; // Invalidate old location
  return i;
}

// Insert/lookup an entry in the index. The index pointer might get
// updated if the index is grown. The returned entry will already be
// valid if the key already exists.
struct fd_funk_index_entry* fd_funk_index_insert(struct fd_funk_index** indexp,
                                                 struct fd_funk_recordid* id) {
  struct fd_funk_index* index = *indexp;
  if (index->numinuse * 3 > index->allocsize) {
    // !!! Replace malloc with zone allocator
    struct fd_funk_index* newindex = fd_funk_index_new(index->allocsize << 1);

    // Copy over entries
    struct fd_funk_index_entry* const oldentries = (struct fd_funk_index_entry*)(index + 1);
    const ulong oldsize = index->allocsize;
    for (struct fd_funk_index_entry* i = oldentries; i < oldentries + oldsize; ++i) {
      if (fd_funk_index_entry_valid(i))
        fd_funk_index_relocate(newindex, i);
    }
    newindex->numinuse = index->numinuse;

    // !!! Replace free with zone allocator
    free(index);
    index = *indexp = newindex;
  }

  // We have space. Do a fast insert.
  const ulong size = index->allocsize;
  const ulong idhash = fd_funk_recordid_hash(id);
  struct fd_funk_index_entry* const entries = (struct fd_funk_index_entry*)(index + 1);
  struct fd_funk_index_entry* i = entries + (idhash & (size-1));
  while (fd_funk_index_entry_valid(i)) {
    if (idhash == i->idhash && fd_funk_recordid_equal(id, &(i->id)))
      // Return existing valid entry
      return i;
    if (++i == entries + size)
      i = entries;
  }
  // Make new entry
  fd_funk_recordid_copy(&(i->id), id);
  i->idhash = idhash;
  index->numinuse ++;
  return i;
}

// Query an entry in the index. NULL is returned on a miss;
struct fd_funk_index_entry* fd_funk_index_query(struct fd_funk_index* index,
                                                struct fd_funk_recordid* id) {
  const ulong idhash = fd_funk_recordid_hash(id);
  const ulong size = index->allocsize;
  struct fd_funk_index_entry* const entries = (struct fd_funk_index_entry*)(index + 1);
  struct fd_funk_index_entry* i = entries + (idhash & (size-1));
  while (fd_funk_index_entry_valid(i)) {
    if (idhash == i->idhash && fd_funk_recordid_equal(id, &(i->id)))
      return i;
    if (++i == entries + size)
      i = entries;
  }
  return NULL;
}

// Delete an entry
void fd_funk_index_delete(struct fd_funk_index* index,
                          struct fd_funk_index_entry* ent) {
  if (fd_funk_index_entry_valid(ent)) {
    ent->start = 0; // Mark invalid
    index->numinuse --;
  }
  // Readjust entries that may have been nudged out of position
  const ulong size = index->allocsize;
  struct fd_funk_index_entry* const entries = (struct fd_funk_index_entry*)(index + 1);
  for (;;) {
    if (++ent == entries + size)
      ent = entries;
    if (!fd_funk_index_entry_valid(ent))
      break;
    fd_funk_index_relocate(index, ent);
  }
}

struct fd_funk_control_entry {
    union {
        struct {
            int dummy;
        } empty;
        struct {
            // Record identifier
            struct fd_funk_recordid id;
            // Offset into file. Must be a multiple of FD_FUNK_MINIBLOCK_SIZE.
            ulong start; 
            // Length of content
            ulong len;
        } normal;
    } u;
    uchar type;
#define FD_FUNK_CONTROL_EMPTY 0 // Unused control entry
#define FD_FUNK_CONTROL_NORMAL 1 // Control entry for a normal record
};

struct fd_funk {
    // Backing file descriptor
    int backingfd;
    // Length of backing file
    long backinglen;
    // Master index of finalized data
    struct fd_funk_index* index;
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

  store->index = fd_funk_index_new(FD_FUNK_INDEX_START_SIZE);
  
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
  // !!! Replace free with zone allocator
  free(store->index);
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
