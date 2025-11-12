#ifndef HEADER_fd_src_waltz_ip_fd_fib4_private_h
#define HEADER_fd_src_waltz_ip_fd_fib4_private_h

#include "fd_fib4.h"
#include "../../util/simd/fd_sse.h"
#include "../../util/fd_util.h"

struct __attribute__((aligned(FD_FIB4_ALIGN))) fd_fib4_key {
  /* FIXME optimize this to 8 bytes? */
  uint addr; /* prefix bits, little endian (low bits outside of mask are undefined) */
  uint mask; /* bit pattern */
  uint prio; /* lower is higher */
};

typedef struct fd_fib4_key fd_fib4_key_t;

struct __attribute__((aligned(FD_FIB4_ALIGN))) fd_fib4 {
  ulong hmap_offset;
  ulong hmap_cnt;
  ulong hmap_max;
  ulong generation;
  ulong cnt;
  ulong max;
  ulong hop_off;
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

/* Atomically move hop, then hash and key */
static void
fd_fib4_hmap_entry_move( fd_fib4_hmap_entry_t * dst,
                         fd_fib4_hmap_entry_t const * src) {
  # if FD_HAS_X86
    __m128i const * src_tmp = (__m128i *)fd_type_pun_const( &src->next_hop );
    __m128i       * dst_tmp = (__m128i *)fd_type_pun      ( &dst->next_hop );
  # elif FD_HAS_INT128
    uint128 const * src_tmp = (uint128 *)fd_type_pun_const( &src->next_hop );
    uint128       * dst_tmp = (uint128 *)fd_type_pun      ( &dst->next_hop );
  # else
    fd_fib4_hop_t const * src_tmp = &src->next_hop;
    fd_fib4_hop_t       * dst_tmp = &dst->next_hop;
  #endif

  FD_VOLATILE( *dst_tmp ) = FD_VOLATILE_CONST( *src_tmp );
  dst->hash     = src->hash;
  dst->dst_addr = src->dst_addr; /* write key last, so query hits valid data */
}

#define MAP_NAME fd_fib4_hmap
#define MAP_T fd_fib4_hmap_entry_t
#define MAP_LG_SLOT_CNT 17 /* sized for 100k entries */
#define MAP_KEY_T uint
#define MAP_KEY dst_addr
#define MAP_KEY_HASH(key) fd_uint_hash( key )
#define MAP_KEY_NULL ((uint)0U)
#define MAP_KEY_INVAL(k) !(k)
#define MAP_KEY_EQUAL(a,b) ((a)==(b))
#define MAP_KEY_EQUAL_IS_SLOW 0

#define MAP_MOVE(d,s) fd_fib4_hmap_entry_move(&d,&s)
#define MAP_QUERY_OPT 2 /* low fill ratio, rare query success */

#define MAP_IMPL_STYLE 0
#include "../../util/tmpl/fd_map.c"

static inline fd_fib4_hop_t
fd_fib4_hmap_query_atomic( fd_fib4_hmap_entry_t const * map,
                           uint dst_addr ) {
  static const fd_fib4_hop_t null = {0};
  fd_fib4_hmap_entry_t const * entry = fd_fib4_hmap_query_const( map, dst_addr, fd_type_pun_const( &null ));
  if( !entry ) return null;

  #if FD_HAS_X86
    __m128i tmp = FD_VOLATILE_CONST( *(__m128i const *)fd_type_pun_const( entry ) );
  #elif FD_HAS_INT128
    uint128 tmp = FD_VOLATILE_CONST( *(uint128 const *)fd_type_pun_const( entry ) );
  # else
    fd_fib4_hop_t tmp = entry->next_hop;
  #endif
  return FD_LOAD( fd_fib4_hop_t, &tmp );
}

/* access the fib4 hmap */
static inline fd_fib4_hmap_entry_t       * fd_fib4_hmap(       fd_fib4_t       * fib )
  { return (fd_fib4_hmap_entry_t       *)( (ulong)fib + fib->hmap_offset ); }
static inline fd_fib4_hmap_entry_t const * fd_fib4_hmap_const( fd_fib4_t const * fib )
  { return (fd_fib4_hmap_entry_t const *)( (ulong)fib + fib->hmap_offset ); }
#endif /* HEADER_fd_src_waltz_ip_fd_fib4_private_h */
