#ifndef HEADER_fd_src_ballet_ebpf_fd_ebpf_h
#define HEADER_fd_src_ballet_ebpf_fd_ebpf_h

/* fd_ebpf.h provides APIs for loading Linux eBPF programs.  Currently,
   only XDP programs are supported.

   The scope of this API is *trusted*:  It is assumed that only hardcoded
   eBPF programs and symbols are provided.

   ### What are eBPF programs?

   Linux eBPF programs are pieces of bytecode that userland programs can
   deploy into the kernel virtual machine.  The kernel can interact with
   these programs with very low overhead, which makes them particularly
   useful for fast packet filtering.

   Userland applications can deploy and interact with eBPF programs via
   the bpf(2) syscall.  When deploying, the user provides a bytecode blob
   (see fd_ebpf_base.h) which is produced by the userland on the fly.
   Typically, userland also shares file descriptors while deploying the
   program.

   To avoid hardcoding file descriptor numbers into the eBPF programs, eBPF
   programs are typically stored as ELF static objects.  These are
   "relocated" just-in-time to actual bytecode.  (The term relocation in
   this context has not much to do with offsets.  It refers to filling in
   symbolic names (such as "xsk_fileno") with an actual value (like 3)).

   This relocation step is provided by fd_ebpf_static_link.  Various
   wrappers for bpf(2) operations are also provided. */

#include "../../util/fd_util_base.h"

/* fd_ebpf_sym_t a key-value pair.  name matches the name of an imported
   symbol in the ELF object.  value is the 'absolute address' to fill in.
   (The 'absolute address' is abused as a generic 64-bit value and can
   also refer to file descriptors, config parameters, etc.) */

struct fd_ebpf_sym {
  char const * name;   /* null-terminated cstr */
  ulong        value;  /* arbitrary 64-bit value */
};
typedef struct fd_ebpf_sym fd_ebpf_sym_t;

/* fd_ebpf_link_opts_t describe parameters to load an eBPF ELF object into
   a bytecode blob that can be loaded into a kernel.  section is the name
   of the ELF section carrying the bytecode (not necessarily ".text"),
   and sym is an array of sym_cnt symbols containing values to fill in.
   fd_ebpf_static_link will look for a relocation table for this section,
   which identifies where and how to fill in symbol values in the given
   section. */

struct fd_ebpf_link_opts {
  /* In params */

  char const *          section;
  fd_ebpf_sym_t const * sym;
  ulong                 sym_cnt;

  /* Out params */

  ulong * bpf;
  ulong   bpf_sz;
};
typedef struct fd_ebpf_link_opts fd_ebpf_link_opts_t;

/* fd_ebpf_static_link relocates an eBPF ELF object as mentioned above.
   elf points to a memory region of elf_sz bytes containing the ELF static
   object.  This memory region will be clobbered during the relocation
   process.  Returns opts on success, with bpf pointing to the first eBPF
   instruction (a subrange of the memory region at elf).  bpf_sz is the
   size of the eBPF bytecode blob (multiple of 8).  On failure, returns
   NULL.

   ### Caveats

   The static linking process is fairly slow and quite complex.  This
   function only implements a small subset of the linking logic needed to
   load simple programs.  Users of this function should expect bugs and
   therefore independently test whether their programs load.  See
   test_xdp_ebpf on how to do unit testing of the relocated program with
   the bpf(2) syscall. */

fd_ebpf_link_opts_t *
fd_ebpf_static_link( fd_ebpf_link_opts_t * opts,
                     void *                elf,
                     ulong                 elf_sz );

/* bpf syscall wrappers **************************************************/

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

/* fd_bpf_map_lookup_elem wraps bpf(2) op BPF_MAP_LOOKUP_ELEM.

   Gets an entry in a BPF map.  key points to the key to be retrieved
   and must match the key size of the map object.  Returns 0 on success
   and stores element value into value.
*/
static inline int
fd_bpf_map_lookup_elem( int          map_fd,
                        void const * key,
                        void *       value ) {
  union bpf_attr attr = {
    .map_fd   = (uint)map_fd,
    .key      = (ulong)key,
    .value    = (ulong)value
  };
  return (int)bpf( BPF_MAP_LOOKUP_ELEM, &attr, sizeof(union bpf_attr) );
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
