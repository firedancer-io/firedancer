#ifndef HEADER_fd_src_waltz_ip_fd_fib4_private_h
#define HEADER_fd_src_waltz_ip_fd_fib4_private_h

#include "fd_fib4.h"

#if FD_HAS_X86
#include <immintrin.h>
#endif

#include "../../util/fd_util.h"

struct __attribute__((aligned(16))) fd_fib4_key {
  /* FIXME optimize this to 8 bytes? */
  uint addr;       /* prefix bits, little endian (low bits outside of mask are undefined) */
  uint mask;       /* bit pattern */
  uint prio;       /* lower is higher */
  int  mask_bits;  /* precompute mask bits for comparison */
};

typedef struct fd_fib4_key fd_fib4_key_t;

struct __attribute__((aligned(FD_FIB4_ALIGN))) fd_fib4 {
  ulong  hmap_join_offset; /* compute join by adding offset to fib4 base */
  ulong  hmap_cnt;
  ulong  hmap_max;
  ulong  generation;
  ulong  cnt;
  ulong  max;
  ulong  hop_off;
  /* fd_fib4_key_t[] follows */
  /* fd_fib4_hop_t[] follows */
  /* hmap_mem        follows */
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
union __attribute__((aligned(16))) fd_fib4_hmap_entry {
  struct {
    uint dst_addr; /* Little endian. All 32-bits defined */
    uint hash;
    fd_fib4_hop_t next_hop; /* 16 bytes */
  };
#if FD_HAS_INT128
  uint128 uf[2];
#endif
#if FD_HAS_X86
  __m128i xmm[2];
#endif
#if FD_HAS_AVX
  __m256i avx[1];
#endif
};

typedef union fd_fib4_hmap_entry fd_fib4_hmap_entry_t;

/* fd_fib4_hmap_entry_st stores from src into dst. Assumes no other writers,
   and that src is non-volatile. Best effort for atomicity, but only guaranteed
   when FD_HAS_AVX. */
static inline void
fd_fib4_hmap_entry_st( fd_fib4_hmap_entry_t       * dst,
                       fd_fib4_hmap_entry_t const * src ) {
# if FD_HAS_X86
  FD_VOLATILE( dst->xmm[0] ) = src->xmm[0];
  FD_VOLATILE( dst->xmm[1] ) = src->xmm[1];
# elif FD_HAS_INT128
  FD_VOLATILE( dst->uf[0] )  = src->uf[0];
  FD_VOLATILE( dst->uf[1] )  = src->uf[1];
# elif FD_HAS_AVX
  FD_VOLATILE( dst->avx[0] ) = src->avx[0];
# else
  dst->dst_addr = src->dst_addr;
  dst->hash     = src->hash;
  dst->next_hop = src->next_hop;
#endif
}

/* fd_fib4_hmap_entry_ld loads from src into dst.
   Best effort for atomicity, but only guaranteed when FD_HAS_AVX.
   Assumes that dst is non-volatile. */
static inline void
fd_fib4_hmap_entry_ld( fd_fib4_hmap_entry_t       * dst,
                       fd_fib4_hmap_entry_t const * src ) {
#if FD_HAS_X86
  dst->xmm[0] = FD_VOLATILE_CONST( src->xmm[0] );
  dst->xmm[1] = FD_VOLATILE_CONST( src->xmm[1] );
#elif FD_HAS_INT128
  dst->uf[0] = FD_VOLATILE_CONST( src->uf[0] );
  dst->uf[1] = FD_VOLATILE_CONST( src->uf[1] );
# elif FD_HAS_AVX
  dst->avx[0] = FD_VOLATILE_CONST( src->avx[0] );
# else
  dst->dst_addr = src->dst_addr;
  dst->hash     = src->hash;
  dst->next_hop = src->next_hop;
#endif
}

#define MAP_NAME               fd_fib4_hmap
#define MAP_T                  fd_fib4_hmap_entry_t
#define MAP_KEY_T              uint
#define MAP_KEY                dst_addr
#define MAP_KEY_HASH(key,seed) fd_uint_hash( key ) ^ ((uint)seed)
#define MAP_KEY_NULL           ((uint)0U)
#define MAP_KEY_INVAL(k)       !(k)
#define MAP_KEY_EQUAL(a,b)     ((a)==(b))
#define MAP_KEY_EQUAL_IS_SLOW  0

#define MAP_MOVE(d,s) fd_fib4_hmap_entry_st(&d,&s)
#define MAP_QUERY_OPT 2 /* low fill ratio, rare query success */

#include "../../util/tmpl/fd_map_dynamic.c"

/* fd_fib4_hmap_query_hop queries the routing table for the next hop
   for the given destination address. Attemps (but does not guarantee) atomicity.
   If the destination address is not found, returns a route with rtype
   set to UNSPEC. The result is not guaranteed to be valid - the caller
   is responsible for validating the result. */

static inline fd_fib4_hop_t
fd_fib4_hmap_query_hop( fd_fib4_hmap_entry_t * map,
                        uint                   dst_addr ) {
  static fd_fib4_hop_t null = {0};
  fd_fib4_hmap_entry_t const * entry = fd_fib4_hmap_query( map, dst_addr, NULL );
  if( !entry ) return null;

  fd_fib4_hmap_entry_t hmap_entry;
  fd_fib4_hmap_entry_ld( &hmap_entry, entry );

  return hmap_entry.next_hop;
}

/* access the fib4 hmap */

static inline fd_fib4_hmap_entry_t const *
fd_fib4_hmap_const( fd_fib4_t const * fib ) {
  return (fd_fib4_hmap_entry_t const *)( (ulong)fib + fib->hmap_join_offset );
}

static inline fd_fib4_hmap_entry_t *
fd_fib4_hmap( fd_fib4_t * fib ) {
  return (fd_fib4_hmap_entry_t*)( (ulong)fib + fib->hmap_join_offset );
}

static inline int
fd_fib4_hmap_est_lg_slot_cnt( ulong route_peer_max ) {
  if( FD_UNLIKELY( !route_peer_max )) return -1;

  #define FD_FIB4_DEFAULT_SPARSITY (2.5)
  ulong slot_cnt_bound = (ulong)( FD_FIB4_DEFAULT_SPARSITY * (double)route_peer_max );
  int   lg_slot_cnt    = fd_ulong_find_msb( slot_cnt_bound - 1 ) + 1;
  #undef FD_FIB4_DEFAULT_SPARSITY

  return lg_slot_cnt;
}

#endif /* HEADER_fd_src_waltz_ip_fd_fib4_private_h */
