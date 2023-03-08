#define FD_FUNK_NUM_DISK_SIZES 52U

// Hash a record id
ulong fd_funk_recordid_t_hash(fd_funk_recordid_t const* id, ulong hashseed) {
  return fd_hash(hashseed, id, sizeof(fd_funk_recordid_t));
}

// Test record id equality
int fd_funk_recordid_t_equal(fd_funk_recordid_t const* id1, fd_funk_recordid_t const* id2) {
  const ulong* id1hack = (const ulong*)id1;
  const ulong* id2hack = (const ulong*)id2;
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
void fd_funk_recordid_t_copy(fd_funk_recordid_t* dest, fd_funk_recordid_t const* src) {
  ulong* id1hack = (ulong*)dest;
  const ulong* id2hack = (const ulong*)src;
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
    fd_funk_recordid_t key;
    // Position of control entry
    ulong control;
    // Offset into file for content.
    ulong start;
    // Length of content. Must be <= FD_FUNK_MAX_ENTRY_SIZE.
    uint size;
    // Length of disk allocation. Must be <= FD_FUNK_MAX_ENTRY_SIZE.
    uint alloc;
    // Version of this record
    uint version;
    // Next entry in hash chain
    uint next;
    // Cached data
    fd_cache_handle cachehandle;
    // sizeof(fd_funk_index_entry) must be 128
    ulong unused[3];
};

#define MAP_NAME fd_funk_index
#define MAP_ELEMENT struct fd_funk_index_entry
#define MAP_KEY fd_funk_recordid_t
#include "fd_map_giant.h"
#undef MAP_NAME
#undef MAP_ELEMENT
#undef MAP_KEY

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

uint fd_funk_disk_size(ulong rawsize, ulong* index);

void fd_funk_replay_root(fd_funk_t* store);

long fd_funk_writev_root(fd_funk_t* store,
                         fd_funk_recordid_t const* recordid,
                         struct iovec const * const iov,
                         ulong iovcnt,
                         ulong offset);

int fd_funk_delete_record_root(fd_funk_t* store,
                               fd_funk_recordid_t const* recordid);

void fd_funk_validate_root(fd_funk_t* store);

fd_cache_handle fd_funk_get_cache_root(fd_funk_t* store,
                                       fd_funk_recordid_t const* recordid,
                                       uint needed_sz,
                                       void** cache_data,
                                       uint* cache_sz,
                                       uint* record_sz);

int fd_funk_writeahead(fd_funk_t* store,
                       fd_funk_xactionid_t const* id,
                       fd_funk_xactionid_t const* parent,
                       char const* script,
                       uint scriptlen,
                       ulong* control,
                       ulong* start,
                       uint* alloc);

void fd_funk_writeahead_delete(fd_funk_t* store,
                               ulong control,
                               ulong start,
                               uint alloc);
