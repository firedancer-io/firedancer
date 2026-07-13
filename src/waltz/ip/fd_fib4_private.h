#ifndef HEADER_fd_src_waltz_ip_fd_fib4_private_h
#define HEADER_fd_src_waltz_ip_fd_fib4_private_h

#include "fd_fib4.h"
#include "../../util/fd_util.h"

struct __attribute__((aligned(16))) fd_fib4_key {
  /* FIXME optimize this to 8 bytes? */
  uint addr;       /* prefix bits, little endian (low bits outside of mask are undefined) */
  uint mask;       /* bit pattern */
  uint prio;       /* lower is higher */
  int  mask_bits;  /* precompute mask bits for comparison */
};

typedef struct fd_fib4_key fd_fib4_key_t;

struct fd_fib4_hmap_key {
  uint dst_addr;
  uint prio; /* lower is higher */
};

typedef struct fd_fib4_hmap_key fd_fib4_hmap_key_t;

struct __attribute__((aligned(16))) fd_fib4_hmap_entry {
  fd_fib4_hmap_key_t key;
  fd_fib4_hop_t      next_hop; /* 16 bytes */
};

typedef struct fd_fib4_hmap_entry fd_fib4_hmap_entry_t;

static inline uint
fd_fib4_hmap_entry_hash( uint dst_addr, ulong seed ) {
  return fd_uint_hash( dst_addr ^ ((uint)seed) );
}

#define MAP_NAME  fd_fib4_hmap
#define MAP_ELE_T fd_fib4_hmap_entry_t
#define MAP_KEY_T fd_fib4_hmap_key_t
#define MAP_KEY   key
#define MAP_KEY_EQ(k0,k1) (((k0)->dst_addr==(k1)->dst_addr) & ((k0)->prio==(k1)->prio))
#define MAP_KEY_HASH(k,s) fd_fib4_hmap_entry_hash( (k)->dst_addr, (s) )
#define MAP_ELE_IS_FREE(ele) ((ele)->next_hop.rtype==FD_FIB4_RTYPE_UNSPEC)
#define MAP_ELE_FREE(ctx,ele) do { (void)(ctx); (ele)->next_hop.rtype = FD_FIB4_RTYPE_UNSPEC; } while(0)
#define MAP_ELE_MOVE(ctx,dst,src) do { (void)(ctx); *(dst) = *(src); (src)->next_hop.rtype = FD_FIB4_RTYPE_UNSPEC; } while(0)
#include "../../util/tmpl/fd_map_slot.c"

FD_STATIC_ASSERT( sizeof(fd_fib4_hmap_entry_t)==32UL, hmap_entry_size );

FD_STATIC_ASSERT( sizeof( fd_fib4_hmap_t)<=sizeof(( (fd_fib4_t){0}).hmap_join), "hmap_join is too small" );

struct __attribute__((aligned(FD_FIB4_ALIGN))) fd_fib4_priv {
  ulong hmap_offset;
  ulong hmap_cnt;
  ulong hmap_max;
  ulong cnt;
  ulong max;
  ulong hop_off;
  ulong seed;
  /* fd_fib4_key_t[] follows */
  /* fd_fib4_hop_t[] follows */
  /* hmap_mem        follows */
};
typedef struct fd_fib4_priv fd_fib4_priv_t;

FD_FN_CONST static inline ulong
fd_fib4_key_tbl_laddr( fd_fib4_priv_t const * fib ) {
  return (ulong)fib + sizeof(fd_fib4_priv_t);
}

FD_FN_PURE static inline ulong
fd_fib4_hop_tbl_laddr( fd_fib4_priv_t const * fib ) {
  return (ulong)fib + fib->hop_off;
}

FD_FN_CONST static inline fd_fib4_key_t const * fd_fib4_key_tbl_const( fd_fib4_priv_t const * fib ) { return (fd_fib4_key_t const *)fd_fib4_key_tbl_laddr( fib ); }
FD_FN_CONST static inline fd_fib4_key_t *       fd_fib4_key_tbl      ( fd_fib4_priv_t *       fib ) { return (fd_fib4_key_t *)      fd_fib4_key_tbl_laddr( fib ); }
FD_FN_CONST static inline fd_fib4_hop_t const * fd_fib4_hop_tbl_const( fd_fib4_priv_t const * fib ) { return (fd_fib4_hop_t const *)fd_fib4_hop_tbl_laddr( fib ); }
FD_FN_CONST static inline fd_fib4_hop_t *       fd_fib4_hop_tbl      ( fd_fib4_priv_t *       fib ) { return (fd_fib4_hop_t *)      fd_fib4_hop_tbl_laddr( fib ); }

static inline void *  fd_fib4_hmap_mem( fd_fib4_priv_t * priv ) {
  return (void *)( (ulong)priv + priv->hmap_offset);
}

/* Get the hashmap's total capacity (50% extra capacity beyond the requested size to optimize performance) */
static inline ulong   fd_fib4_hmap_get_ele_max   ( ulong max_cnt  ) { return fd_ulong_pow2_up( max_cnt + ( max_cnt>>1 ) ); }
/* Get the hashmap's probe limit (75% of total capacity). Higher than requested size to avoid probe failure */
static inline ulong   fd_fib4_hmap_get_probe_max ( ulong elem_max ) { return elem_max - ( elem_max>>2 );                   }

#endif /* HEADER_fd_src_waltz_ip_fd_fib4_private_h */
