// Hash a xaction id
ulong fd_funk_xactionid_t_hash(fd_funk_xactionid_t const* id, ulong hashseed) {
  return fd_hash(hashseed, id, sizeof(fd_funk_xactionid_t));
}

// Test xaction id equality
int fd_funk_xactionid_t_equal(fd_funk_xactionid_t const* id1, fd_funk_xactionid_t const* id2) {
  const ulong* const id1hack = (const ulong* const)id1;
  const ulong* const id2hack = (const ulong* const)id2;
  return ((id1hack[0] ^ id2hack[0]) |
          (id1hack[1] ^ id2hack[1]) |
          (id1hack[2] ^ id2hack[2]) |
          (id1hack[3] ^ id2hack[3])) == 0;
}

// Copy a xaction id
void fd_funk_xactionid_t_copy(fd_funk_xactionid_t* dest, fd_funk_xactionid_t const* src) {
  ulong* const id1hack = (ulong* const)dest;
  const ulong* const id2hack = (const ulong* const)src;
  id1hack[0] = id2hack[0];
  id1hack[1] = id2hack[1];
  id1hack[2] = id2hack[2];
  id1hack[3] = id2hack[3];
}

struct fd_funk_xaction_cache_entry {
    // Record identifier
    fd_funk_recordid_t record;
    // Actual length of record. The cache might just be a prefix. !!! consider ulong
    uint record_sz;
    // Cached data
    fd_cache_handle cachehandle;
};
#define VECT_NAME fd_funk_xaction_cache
#define VECT_ELEMENT struct fd_funk_xaction_cache_entry
#include "fd_vector.h"
#undef VECT_NAME
#undef VECT_ELEMENT

struct fd_funk_xaction_entry {
    // Transaction identifier
    fd_funk_xactionid_t key;
    // Parent transaction identifier
    fd_funk_xactionid_t parent;
    // Transaction update transcript. This is exactly the same as the
    // on-disk representation.
    char* script;
    uint scriptlen;
    uint scriptmax;
    // Cached record data. Reflects the updates in this transaction.
    struct fd_funk_xaction_cache cache;
    // Next entry in hash chain
    uint next;
    // State of entry used for garbage collection
    int gc_state;
#define FD_FUNK_GC_UNKNOWN -1
#define FD_FUNK_GC_GOOD 0
#define FD_FUNK_GC_ORPHAN 1
    // Write-ahead log control and file position info
    ulong wa_control;
    ulong wa_start;
    uint wa_alloc;
};

#define MAP_NAME fd_funk_xactions
#define MAP_ELEMENT struct fd_funk_xaction_entry
#define MAP_KEY fd_funk_xactionid_t
#include "fd_map_giant.h"
#undef MAP_NAME
#undef MAP_ELEMENT
#undef MAP_KEY

int fd_funk_is_root(fd_funk_xactionid_t const* xid);
void fd_funk_xactions_cleanup(fd_funk_t* store);
void fd_funk_validate_xaction(fd_funk_t* store);
void fd_funk_writeahead_load(fd_funk_t* store,
                             fd_funk_xactionid_t* id,
                             fd_funk_xactionid_t* parent,
                             ulong start,
                             uint size,
                             uint alloc,
                             ulong ctrlpos,
                             char* script);
void fd_funk_writeahead_recommits(fd_funk_t* store);
