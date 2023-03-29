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
                     void * elf,
                     ulong  elf_sz );

#if defined(__linux__)

#include <sys/syscall.h>
#include <unistd.h>
#include <linux/bpf.h>

static inline long
bpf( int              cmd,
     union bpf_attr * attr,
     ulong            attr_sz ) {
  return syscall( SYS_bpf, cmd, attr, attr_sz );
}

static inline int
fd_bpf_map_get_next_key( int    map_fd,
                         void * key,
                         void * next_key ) {
  union bpf_attr attr = {
    .map_fd   = (uint)map_fd,
    .key      = (ulong)key,
    .next_key = (ulong)next_key
  };
  return (int)bpf( BPF_MAP_GET_NEXT_KEY, &attr, sizeof(union bpf_attr) );
}

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

static inline int
fd_bpf_map_delete_elem( int          map_fd,
                        void const * key ) {
  union bpf_attr attr = {
    .map_fd   = (uint)map_fd,
    .key      = (ulong)key
  };
  return (int)bpf( BPF_MAP_DELETE_ELEM, &attr, sizeof(union bpf_attr) );
}

static inline int
fd_bpf_obj_get( char const * pathname ) {
  union bpf_attr attr = {
    .pathname = (ulong)pathname
  };
  return (int)bpf( BPF_OBJ_GET, &attr, sizeof(union bpf_attr) );
}

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
