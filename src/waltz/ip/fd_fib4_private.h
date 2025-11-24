#ifndef HEADER_fd_src_waltz_ip_fd_fib4_private_h
#define HEADER_fd_src_waltz_ip_fd_fib4_private_h

#include "fd_fib4.h"
#include "../../util/fd_util.h"

#if FD_HAS_X86
#include <immintrin.h>
#endif

struct __attribute__((aligned(16))) fd_fib4_key {
  /* FIXME optimize this to 8 bytes? */
  uint addr;       /* prefix bits, little endian (low bits outside of mask are undefined) */
  uint mask;       /* bit pattern */
  uint prio;       /* lower is higher */
  int  mask_bits;  /* precompute mask bits for comparison */
};

typedef struct fd_fib4_key fd_fib4_key_t;

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
# if FD_HAS_AVX
  FD_VOLATILE( dst->avx[0] ) = src->avx[0];
# elif FD_HAS_X86
  FD_VOLATILE( dst->xmm[0] ) = src->xmm[0];
  FD_VOLATILE( dst->xmm[1] ) = src->xmm[1];
# elif FD_HAS_INT128
  FD_VOLATILE( dst->uf[0] )  = src->uf[0];
  FD_VOLATILE( dst->uf[1] )  = src->uf[1];
# else
  FD_VOLATILE( dst->dst_addr ) = src->dst_addr;
  FD_VOLATILE( dst->hash     ) = src->hash;
  FD_VOLATILE( dst->next_hop ) = src->next_hop;
#endif
}

/* fd_fib4_hmap_entry_ld loads from src into dst.
   Best effort for atomicity, but only guaranteed when FD_HAS_AVX.
   Assumes that dst is non-volatile. */
static inline void
fd_fib4_hmap_entry_ld( fd_fib4_hmap_entry_t       * dst,
                       fd_fib4_hmap_entry_t const * src ) {

# if FD_HAS_AVX
  dst->avx[0] = FD_VOLATILE_CONST( src->avx[0] );
# elif FD_HAS_X86
  dst->xmm[0] = FD_VOLATILE_CONST( src->xmm[0] );
  dst->xmm[1] = FD_VOLATILE_CONST( src->xmm[1] );
# elif FD_HAS_INT128
  dst->uf[0] = FD_VOLATILE_CONST( src->uf[0] );
  dst->uf[1] = FD_VOLATILE_CONST( src->uf[1] );
# else
  dst->dst_addr = FD_VOLATILE_CONST( src->dst_addr );
  dst->hash     = FD_VOLATILE_CONST( src->hash );
  dst->next_hop = FD_VOLATILE_CONST( src->next_hop );
#endif
}

static inline uint
fd_fib4_hmap_entry_hash( uint dst_addr, ulong seed ) {
  return fd_uint_hash( dst_addr ^ ((uint)seed) );
}

#define MAP_NAME            fd_fib4_hmap
#define MAP_ELE_T           fd_fib4_hmap_entry_t
#define MAP_KEY_T           uint
#define MAP_KEY             dst_addr
#define MAP_KEY_HASH(k,s)   fd_fib4_hmap_entry_hash( (*(k)), (s) )
#define MAP_ELE_MOVE(c,d,s) do { fd_fib4_hmap_entry_t * _src = (s); fd_fib4_hmap_entry_st( (d), _src ); _src->dst_addr = 0; } while(0)

#include "../../util/tmpl/fd_map_slot.c"

FD_STATIC_ASSERT( sizeof(fd_fib4_hmap_t)<=sizeof(((fd_fib4_t){0}).hmap_join), "hmap_join is too small" );

/* fd_fib4_hmap_query_hop queries the /32 routing table for the next hop
   for the given destination address. Attempts (but does not guarantee) atomicity.
   If the destination address is not found, returns a route with rtype
   set to UNSPEC. The result is not guaranteed to be valid - the caller
   is responsible for validating the result. */

static inline fd_fib4_hop_t
fd_fib4_hmap_query_hop( fd_fib4_hmap_t const * map,
                        uint                   dst_addr ) {
  static fd_fib4_hop_t null = {0};
  fd_fib4_hmap_entry_t const * entry = fd_fib4_hmap_query( map, &dst_addr );
  if( !entry ) return null;

  fd_fib4_hmap_entry_t hmap_entry;
  fd_fib4_hmap_entry_ld( &hmap_entry, entry );

  return hmap_entry.next_hop;
}

struct __attribute__((aligned(FD_FIB4_ALIGN))) fd_fib4_priv {
  ulong hmap_offset;
  ulong hmap_cnt;
  ulong hmap_max;
  ulong generation;
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
