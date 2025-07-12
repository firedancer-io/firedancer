#ifndef HEADER_fd_src_waltz_route_fd_fib4_private_h
#define HEADER_fd_src_waltz_route_fd_fib4_private_h

#include "fd_fib4.h"

struct __attribute__((aligned(FD_FIB4_ALIGN))) fd_fib4_key {
  /* FIXME optimize this to 8 bytes? */
  uint addr; /* prefix bits, little endian (low bits outside of mask are undefined) */
  uint mask; /* bit pattern */
  uint prio; /* lower is higher */
};

typedef struct fd_fib4_key fd_fib4_key_t;

struct __attribute__((aligned(FD_FIB4_ALIGN))) fd_fib4 {
  ulong hmap_offset;
  ulong hmap_elem_offset;
  ulong hmap_lock_cnt;
  ulong hmap_seed;
  ulong hmap_cnt;
  ulong hmap_max;
  ulong generation;
  ulong cnt;
  ulong max;
  ulong hop_off;
  /* fd_fib4_key_t[] follows */
  /* fd_fib4_hop_t[] follows */
  /* hmap_mem        follows */
  /* hmap_elem_mem   follows */
};

FD_FN_CONST static inline ulong
fd_fib4_key_tbl_laddr( fd_fib4_t const * fib ) {
  return (ulong)fib + sizeof(fd_fib4_t);
}

FD_FN_PURE static inline ulong
fd_fib4_hop_tbl_laddr( fd_fib4_t const * fib ) {
  return (ulong)fib + fib->hop_off;
}

FD_FN_CONST static inline fd_fib4_key_t const * fd_fib4_key_tbl_const( fd_fib4_t const * fib ) { return (fd_fib4_key_t const *)fd_fib4_key_tbl_laddr( fib ); }
FD_FN_CONST static inline fd_fib4_key_t *       fd_fib4_key_tbl      ( fd_fib4_t *       fib ) { return (fd_fib4_key_t *)      fd_fib4_key_tbl_laddr( fib ); }
FD_FN_CONST static inline fd_fib4_hop_t const * fd_fib4_hop_tbl_const( fd_fib4_t const * fib ) { return (fd_fib4_hop_t const *)fd_fib4_hop_tbl_laddr( fib ); }
FD_FN_CONST static inline fd_fib4_hop_t *       fd_fib4_hop_tbl      ( fd_fib4_t *       fib ) { return (fd_fib4_hop_t *)      fd_fib4_hop_tbl_laddr( fib ); }


/* Hashmap private APIs */

#define MAP_NAME fd_fib4_hmap
#define MAP_ELE_T fd_fib4_hmap_entry_t
#define MAP_KEY_T uint
#define MAP_KEY dst_addr
#define MAP_KEY_HASH(key,seed) fd_uint_hash( (*(key)) ^ ((uint)seed) )

struct __attribute__((aligned(16))) fd_fib4_hmap_entry {
  uint dst_addr; /* Little endian. All 32-bits defined */
  fd_fib4_hop_t next_hop;
};

typedef struct fd_fib4_hmap_entry fd_fib4_hmap_entry_t;

#define MAP_IMPL_STYLE 0
#include "../../util/tmpl/fd_map_slot_para.c"

/* fd_fib4_hmap_insert adds a new entry (key=ip4_dst, value=hop) to the fib4
   hmap. Assume the netmask for the ip4_dst entry is 32, and ip4_dst is not 0.
   The insertion to fib->hmap is blocking. Return FD_MAP_SUCCESS on success,
   FD_MAP_ERR_FULL if the hmap is full.
*/

static int
fd_fib4_hmap_insert( fd_fib4_t *     fib,
                     uint            ip4_dst,
                     fd_fib4_hop_t * hop );

static inline void *  fd_fib4_hmap_mem      ( fd_fib4_t * fib ) { return (void *)( (ulong)fib + fib->hmap_offset      ); }
static inline void *  fd_fib4_hmap_ele_mem  ( fd_fib4_t * fib ) { return (void *)( (ulong)fib + fib->hmap_elem_offset ); }

/* Get the hashmap's total capacity (50% extra capacity beyond the requested size to optimize performance) */
static inline ulong   fd_fib4_hmap_get_ele_max   ( ulong max_cnt  ) { return fd_ulong_pow2_up( max_cnt + ( max_cnt>>1 ) ); }
/* Get the hashmap's probe limit (75% of total capacity). Higher than requested size to avoid probe failure */
static inline ulong   fd_fib4_hmap_get_probe_max ( ulong elem_max ) { return elem_max - ( elem_max>>2 );                      }

#endif /* HEADER_fd_src_waltz_route_fd_fib4_private_h */
