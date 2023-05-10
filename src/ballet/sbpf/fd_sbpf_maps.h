#ifndef HEADER_fd_src_ballet_sbpf_fd_sbpf_maps_h
#define HEADER_fd_src_ballet_sbpf_fd_sbpf_maps_h

/* fd_sbpf_maps defines map types that the loader and VM depend on. */

/* fd_sbpf_calldests_t is a map type used to resolve sBPF call targets.
   This is required because loaded sBPF bytecode does not directly call
   relative addresses, but instead calls the Murmur3 hash of the
   destination program counter.  This hash is not trivially reversible
   thus we store all Murmur3(PC) => PC mappings in this map. */

struct __attribute__((aligned(16UL))) fd_sbpf_calldests {
  ulong key;  /* hash of PC */
  /* FIXME salt map key with an add-rotate-xor */
  ulong pc;
};
typedef struct fd_sbpf_calldests fd_sbpf_calldests_t;

#define MAP_NAME         fd_sbpf_calldests
#define MAP_T            fd_sbpf_calldests_t
#define MAP_KEY_NULL     ULONG_MAX
#define MAP_KEY_INVAL(k) ((k)==ULONG_MAX)
#define MAP_MEMOIZE      0
#define MAP_LG_SLOT_CNT  12
/* FIXME use dynamic maps */
#include "../../util/tmpl/fd_map.c"

static FD_FN_UNUSED int
fd_sbpf_calldests_upsert( fd_sbpf_calldests_t * calldests,
                          uint                  hash,
                          ulong                 pc ) {

  /* Check if entry already exists */
  fd_sbpf_calldests_t * entry = fd_sbpf_calldests_query( calldests, hash, NULL );
  if( entry )
    return entry->pc == pc;  /* check for Murmur3 collision */

  /* Insert new */
  entry = fd_sbpf_calldests_insert( calldests, hash );
  if( FD_UNLIKELY( !entry ) ) return 0;  /* check for internal map collision */
  entry->pc = pc;

  return 1;
}


/* fd_sbpf_syscalls_t maps syscall IDs => local function pointers. */

/* FIXME */
typedef void * fd_sbpf_syscall_func_t;

struct __attribute__((aligned(16UL))) fd_sbpf_syscalls {
  uint                   key;  /* Murmur3-32 hash of function name */
  fd_sbpf_syscall_func_t func;
};
typedef struct fd_sbpf_syscalls fd_sbpf_syscalls_t;

#define MAP_NAME              fd_sbpf_syscalls
#define MAP_T                 fd_sbpf_syscalls_t
#define MAP_KEY_T             uint
#define MAP_KEY_NULL          0U
#define MAP_KEY_INVAL(k)      !(k)
#define MAP_KEY_EQUAL(k0,k1)  (k0)==(k1)
#define MAP_KEY_EQUAL_IS_SLOW 0
#define MAP_KEY_HASH(k)       (k)
#define MAP_MEMOIZE           0
#define MAP_LG_SLOT_CNT       12
#include "../../util/tmpl/fd_map.c"

#endif /* HEADER_fd_src_ballet_sbpf_fd_sbpf_maps_h */

