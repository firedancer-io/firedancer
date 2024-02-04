#ifndef HEADER_fd_src_ballet_ebpf_fd_ebpf_h
#define HEADER_fd_src_ballet_ebpf_fd_ebpf_h

#include "../../util/fd_util_base.h"

struct fd_ebpf_sym {
  char const * name;
  ulong        value;
};
typedef struct fd_ebpf_sym fd_ebpf_sym_t;

struct fd_ebpf_link_opts {
  /* In params */

  char const *    section;
  fd_ebpf_sym_t * sym;
  ulong           sym_cnt;

  /* Out params */

  ulong * bpf;
  ulong   bpf_sz;
};
typedef struct fd_ebpf_link_opts fd_ebpf_link_opts_t;

fd_ebpf_link_opts_t *
fd_ebpf_static_link( fd_ebpf_link_opts_t * opts,
                     void *                elf,
                     ulong                 elf_sz );

#if defined(__linux__) && defined(_DEFAULT_SOURCE) || defined(_BSD_SOURCE)

#include <sys/syscall.h>
#include <unistd.h>
#include <linux/bpf.h>

/* bpf Linux syscall */

static inline long
bpf( int              cmd,
     union bpf_attr * attr,
     ulong            attr_sz ) {
  return syscall( SYS_bpf, cmd, attr, attr_sz );
}

/* fd_bpf_map_get_next_key wraps bpf(2) op BPF_MAP_GET_NEXT_KEY.

   Given a BPF map file descriptor and a const ptr to the current key,
   finds and stores the next key into `next_key`.  key and next_key must
   match the key size of the map object.  If key does not exist, yields
   the first key of the map.  When mutating a map while iterating, get
   the next key before deleting the current key to avoid iterator from
   restarting.  Returns 0 on success and -1 on failure (sets errno).
   Sets errno to ENOENT if given key is last in map. */

static inline int
fd_bpf_map_get_next_key( int          map_fd,
                         void const * key,
                         void       * next_key ) {
  union bpf_attr attr = {
    .map_fd   = (uint)map_fd,
    .key      = (ulong)key,
    .next_key = (ulong)next_key
  };
  return (int)bpf( BPF_MAP_GET_NEXT_KEY, &attr, sizeof(union bpf_attr) );
}

/* fd_bpf_map_update_elem wraps bpf(2) op BPF_MAP_UPDATE_ELEM.

   Creates or updates an entry in a BPF map.  key and value point to
   the tuple to be inserted and must match the key/value size of the map
   object.  flags is one of BPF_ANY (create or update), BPF_NOEXIST
   (create only), BPF_EXIST (update only).  Returns 0 on success and -1
   on failure (sets errno).  Reasons for failure include: E2BIG (max
   entry limit reached), EEXIST (BPF_NOEXIST requested but key exists),
   ENOENT (BPF_EXIST requested but key not found). */

static inline int
fd_bpf_map_update_elem( int          map_fd,
                        void const * key,
                        void const * value,
                        ulong        flags ) {
  union bpf_attr attr = {
    .map_fd   = (uint)map_fd,
    .key      = (ulong)key,
    .value    = (ulong)value,
    .flags    = flags
  };
  return (int)bpf( BPF_MAP_UPDATE_ELEM, &attr, sizeof(union bpf_attr) );
}

/* fd_bpf_map_delete_elem wraps bpf(2) op BPF_MAP_DELETE_ELEM.

   Deletes an entry in a BPF map.  key points to the key to be deleted
   and must match the key size of the map object.  Returns 0 on success
   and -1 on failure (sets errno).  Reasons for failure include: ENOENT
   (no such key). */

static inline int
fd_bpf_map_delete_elem( int          map_fd,
                        void const * key ) {
  union bpf_attr attr = {
    .map_fd   = (uint)map_fd,
    .key      = (ulong)key
  };
  return (int)bpf( BPF_MAP_DELETE_ELEM, &attr, sizeof(union bpf_attr) );
}

/* fd_bpf_obj_get wraps bpf(2) op BPF_OBJ_GET.

   Opens a BPF map at given filesystem path.  Path must be within a
   valid bpffs mount and point to a BPF map pinned via BPF_OBJ_PIN.
   Returns fd number on success and negative integer on failure. */

static inline int
fd_bpf_obj_get( char const * pathname ) {
  union bpf_attr attr = {
    .pathname = (ulong)pathname
  };
  return (int)bpf( BPF_OBJ_GET, &attr, sizeof(union bpf_attr) );
}

/* fd_bpf_obj_pin wraps bpf(2) op BPF_OBJ_PIN.

   Pins a bpf syscall API object at given filesystem path.  Types of
   objects include: BPF map (BPF_MAP_CREATE), links (BPF_LINK_CREATE),
   programs (BPF_PROG_LOAD).  Returns 0 on success and -1 on failure. */

static inline int
fd_bpf_obj_pin( int          bpf_fd,
                char const * pathname ) {
  union bpf_attr attr = {
    .bpf_fd   = (uint)bpf_fd,
    .pathname = (ulong)pathname
  };
  return (int)bpf( BPF_OBJ_PIN, &attr, sizeof(union bpf_attr) );
}

#endif /* defined (__linux__) */

#endif /* HEADER_fd_src_ballet_ebpf_fd_ebpf_h */
