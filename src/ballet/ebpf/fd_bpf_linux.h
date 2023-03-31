#ifndef HEADER_fd_src_ballet_ebpf_fd_bpf_linux_h
#define HEADER_fd_src_ballet_ebpf_fd_bpf_linux_h

/* Wrappers for bpf(2) syscall API.  Only available on Linux. */

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
#endif /* HEADER_fd_src_ballet_ebpf_fd_bpf_linux_h */

