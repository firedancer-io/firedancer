// Hash a xaction id
ulong fd_funk_xactionid_t_hash(struct fd_funk_xactionid const* id, ulong hashseed) {
  return fd_hash(hashseed, id, sizeof(struct fd_funk_xactionid));
}

// Test xaction id equality
int fd_funk_xactionid_t_equal(struct fd_funk_xactionid const* id1, struct fd_funk_xactionid const* id2) {
  const ulong* const id1hack = (const ulong* const)id1;
  const ulong* const id2hack = (const ulong* const)id2;
  return ((id1hack[0] ^ id2hack[0]) |
          (id1hack[1] ^ id2hack[1]) |
          (id1hack[2] ^ id2hack[2]) |
          (id1hack[3] ^ id2hack[3])) == 0;
}

// Copy a xaction id
void fd_funk_xactionid_t_copy(struct fd_funk_xactionid* dest, struct fd_funk_xactionid const* src) {
  ulong* const id1hack = (ulong* const)dest;
  const ulong* const id2hack = (const ulong* const)src;
  id1hack[0] = id2hack[0];
  id1hack[1] = id2hack[1];
  id1hack[2] = id2hack[2];
  id1hack[3] = id2hack[3];
}

struct fd_funk_xaction_cache_entry {
    // Record identifier
    struct fd_funk_recordid record;
    // Actual length of record. The cache might just be a prefix
    uint recordlen;
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
    struct fd_funk_xactionid key;
    // Parent transaction identifier
    struct fd_funk_xactionid parent;
    // Transaction update transcript. This is exactly the same as the
    // on-disk representation.
    char* script;
    uint scriptlen;
    uint scriptmax;
    // Cached record data. Reflects the updates in this transaction.
    struct fd_funk_xaction_cache cache;
    // Next entry in hash chain
    uint next;
};

#define MAP_NAME fd_funk_xactions
#define MAP_ELEMENT struct fd_funk_xaction_entry
#define MAP_KEY fd_funk_xactionid_t
#include "fd_map_giant.h"
#undef MAP_NAME
#undef MAP_ELEMENT
#undef MAP_KEY

int fd_funk_is_root(struct fd_funk_xactionid const* xid);
