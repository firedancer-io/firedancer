#ifndef HEADER_fd_src_waltz_ip_fd_fib4_private_h
#define HEADER_fd_src_waltz_ip_fd_fib4_private_h

#include "fd_fib4.h"
#include "../../util/simd/fd_sse.h"
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
struct __attribute__((aligned(16))) fd_fib4_hmap_entry {
  uint dst_addr; /* Little endian. All 32-bits defined */
  fd_fib4_hop_t next_hop;
  uint hash;
};

typedef struct fd_fib4_hmap_entry fd_fib4_hmap_entry_t;

/* fd_fib4_hop_st_atomic stores from src into dst. Assumes no other writers,
   and that src is non-volatile. Write to dst is atomic  */
FD_STATIC_ASSERT( sizeof(fd_fib4_hop_t) == 16, "atomic st assumes 16 bytes" );
static inline void
fd_fib4_hop_st_atomic( fd_fib4_hop_t       * dst,
                       fd_fib4_hop_t const * src ) {
  # if FD_HAS_X86
   FD_VOLATILE( *(__m128i *)( dst ) ) = *(__m128i const *)( src );
  # elif FD_HAS_INT128
    FD_VOLATILE( *(uint128 *)( dst ) ) = *(uint128 const *)( src );
  # else
    FD_VOLATILE( *dst ) = *src;
  #endif
}

/* fd_fib4_hop_ld_atomic loads atomically from src into dst.
   Assumes that dst is non-volatile. */
FD_STATIC_ASSERT( sizeof(fd_fib4_hop_t) == 16, "atomic st assumes 16 bytes" );
static inline void
fd_fib4_hop_ld_atomic( fd_fib4_hop_t       * dst,
                       fd_fib4_hop_t const * src ) {
  #if FD_HAS_X86
    *(__m128i *)( dst ) = FD_VOLATILE_CONST( *(__m128i const *)( src ) );
  #elif FD_HAS_INT128
    *(uint128 *)( dst ) = FD_VOLATILE_CONST( *(uint128 const *)( src ) );
  # else
    *dst = *src;
  #endif
}

/* Atomically write hop, then write hash and key. Assumes no other writers */
static void
fd_fib4_hmap_entry_move( fd_fib4_hmap_entry_t * dst,
                         fd_fib4_hmap_entry_t const * src) {
  fd_fib4_hop_st_atomic( &dst->next_hop, &src->next_hop );
  dst->hash     = src->hash;
  dst->dst_addr = src->dst_addr; /* write key last, so query hits valid data */
}

#define MAP_NAME fd_fib4_hmap
#define MAP_T fd_fib4_hmap_entry_t
#define MAP_KEY_T uint
#define MAP_KEY dst_addr
#define MAP_KEY_HASH(key) fd_uint_hash( key )
#define MAP_KEY_NULL ((uint)0U)
#define MAP_KEY_INVAL(k) !(k)
#define MAP_KEY_EQUAL(a,b) ((a)==(b))
#define MAP_KEY_EQUAL_IS_SLOW 0

#define MAP_MOVE(d,s) fd_fib4_hmap_entry_move(&d,&s)
#define MAP_QUERY_OPT 2 /* low fill ratio, rare query success */

#include "../../util/tmpl/fd_map_dynamic.c"

static inline fd_fib4_hop_t
fd_fib4_hmap_query_atomic( fd_fib4_hmap_entry_t * map,
                           uint dst_addr ) {
  static fd_fib4_hop_t null = {0};
  fd_fib4_hmap_entry_t const * entry = fd_fib4_hmap_query( map, dst_addr, NULL );
  if( !entry ) return null;

  fd_fib4_hop_t next_hop;
  fd_fib4_hop_ld_atomic( &next_hop, &entry->next_hop );

  /* confirm it's still the same IP we expected */
  int torn_read = FD_VOLATILE_CONST( entry->dst_addr )!=dst_addr;
  if( FD_UNLIKELY( torn_read ) ) return null;

  return next_hop;
}

/* access the fib4 hmap */

static inline fd_fib4_hmap_entry_t const *
fd_fib4_hmap_const( fd_fib4_t const * fib ) {
  return (fd_fib4_hmap_entry_t const *)( (ulong)fib + fib->hmap_join_offset );
}

static inline fd_fib4_hmap_entry_t *
fd_fib4_hmap( fd_fib4_t * fib ) {
  return (fd_fib4_hmap_entry_t*)fd_fib4_hmap_const( fib );
}

static inline int
_fd_fib4_hmap_lg_slot_cnt( ulong route_peer_max ) {
  if( FD_UNLIKELY( !route_peer_max )) return -1;

  #define FD_FIB4_DEFAULT_SPARSITY (2.5)
  ulong slot_cnt_bound = (ulong)( FD_FIB4_DEFAULT_SPARSITY * (double)route_peer_max );
  int   lg_slot_cnt    = fd_ulong_find_msb( slot_cnt_bound - 1 ) + 1;
  #undef FD_FIB4_DEFAULT_SPARSITY

  return lg_slot_cnt;
}

static inline ulong
_fd_fib4_hmap_footprint( ulong route_peer_max) {
  if( FD_UNLIKELY( !route_peer_max )) return 0UL;

  int lg_slot_cnt = _fd_fib4_hmap_lg_slot_cnt( route_peer_max );
  return fd_fib4_hmap_footprint( lg_slot_cnt );
}

#endif /* HEADER_fd_src_waltz_ip_fd_fib4_private_h */
