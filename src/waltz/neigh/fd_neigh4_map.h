#ifndef HEADER_fd_src_waltz_neigh_fd_neigh4_map_h
#define HEADER_fd_src_waltz_neigh_fd_neigh4_map_h

/* fd_neigh4.h provides APIs for IPv4 neighbor discovery using ARP. */

#include "../../util/log/fd_log.h" /* fd_log_wallclock */

#if FD_HAS_X86
#include <immintrin.h>
#endif

union __attribute__((aligned(16))) fd_neigh4_entry {
  struct {
    uint  ip4_addr;
    uchar mac_addr[6]; /* MAC address */
    uchar state;
    ulong probe_suppress_until : 40; /* Holds deadline>>24, so minimum delay
                                        is ~16.7M ticks (2**24) */
    #define FD_NEIGH4_PROBE_SUPPRESS_SHIFT ( sizeof(ulong)*8 - 40 )
    #define FD_NEIGH4_PROBE_SUPPRESS_MASK ( (1UL<<40) - 1 )

    #define FD_NEIGH4_PROBE_SUPPRESS_UNTIL_SET(entry, deadline) \
      ulong udead = ((ulong)(deadline))>>FD_NEIGH4_PROBE_SUPPRESS_SHIFT; \
      udead >>= FD_NEIGH4_PROBE_SUPPRESS_SHIFT; \
      (entry)->probe_suppress_until = udead & FD_NEIGH4_PROBE_SUPPRESS_MASK;
    #define FD_NEIGH4_PROBE_SUPPRESS_UNTIL_GET(entry) \
      (long)(((entry)->probe_suppress_until)<<FD_NEIGH4_PROBE_SUPPRESS_SHIFT)
  };
#if FD_HAS_INT128
  uint128 uf[1];
#endif
#if FD_HAS_X86
  __m128i xmm[1];
#endif
};

typedef union fd_neigh4_entry fd_neigh4_entry_t;
typedef fd_neigh4_entry_t fd_neigh4_hmap_t;


/* fd_neigh4_entry_atomic_st atomically stores from src into dst.
   Assumes no other writers, and that src is non-volatile. */
static inline void
fd_neigh4_entry_atomic_st( fd_neigh4_entry_t       * dst,
                           fd_neigh4_entry_t const * src ) {
# if FD_HAS_X86
  FD_VOLATILE( dst->xmm[0] ) = src->xmm[0];
# elif FD_HAS_INT128
  FD_VOLATILE( dst->uf[0] )  = src->uf[0];
# endif
  memcpy( dst->mac_addr, src->mac_addr, 6 );
  dst->probe_suppress_until = src->probe_suppress_until;
  dst->ip4_addr             = src->ip4_addr;
  dst->state                = src->state;
}

/* fd_neigh4_entry_atomic_ld atomically loads from src into dst.
   Assumes no other writers, and that dst is non-volatile. */
static inline void
fd_neigh4_entry_atomic_ld( fd_neigh4_entry_t       * dst,
                           fd_neigh4_entry_t const * src ) {
# if FD_HAS_X86
  dst->xmm[0] = FD_VOLATILE_CONST( src->xmm[0] );
# elif FD_HAS_INT128
  dst->uf[0] = FD_VOLATILE_CONST( src->uf[0] );
# endif
  memcpy( dst->mac_addr, src->mac_addr, 6 );
  dst->probe_suppress_until = src->probe_suppress_until;
  dst->ip4_addr             = src->ip4_addr;
  dst->state                = src->state;
}


#define FD_NEIGH4_STATE_INCOMPLETE (0)
#define FD_NEIGH4_STATE_ACTIVE     (1)

#include "fd_neigh4_map_defines.h"
#include "../../util/tmpl/fd_map_dynamic.c"

/* fd_neigh4_hmap_query_entry queries a neighbor table entry by IP address.
   Returns 1 if out was successfully populated, and 0 otherwise.
   Out is a pointer to the entry to be filled in. Must have 16 byte alignment.
   map is a join to the neighbor table, and ip4_addr is the IP address to query.
   Reasons for failure include:
   - The entry was not found
   - Entry changed between query and copying out (out will be clobbered)
   */
static inline int
fd_neigh4_hmap_query_entry( fd_neigh4_hmap_t   *  map,
                            uint                  ip4_addr,
                            fd_neigh4_entry_t  *  out ) {
  fd_neigh4_entry_t const * e = fd_neigh4_hmap_query( map, ip4_addr, NULL );
  if( FD_UNLIKELY( !e ) ) return 0;
  fd_neigh4_entry_atomic_ld( out, e );
  /* Confirm key we read matches what we expect */
  if( FD_UNLIKELY( out->ip4_addr !=ip4_addr ) ) return 0;
  return 1;
}

/* _fd_neigh4_hmap_slot_lg_slot_cnt computes the log2 of the number of slots
   needed to store 'ele_max' entries. Uses a sparsity factor of 3. */
static inline int
fd_neigh4_hmap_est_lg_slot_cnt( ulong ele_max ) {
  ulong slot_cnt_bound = 3 * ele_max;
  return fd_ulong_find_msb( slot_cnt_bound - 1UL ) + 1;
}

FD_PROTOTYPES_BEGIN

#if FD_HAS_HOSTED

/* fd_neigh4_hmap_fprintf prints the routing table to the given FILE *
   pointer (or target equivalent).  Order of routes is undefined but
   guaranteed to be stable between calls.  Outputs ASCII encoding with LF
   newlines.  Returns errno on failure and 0 on success.  Only works on
   ACTIVE tables. */

int
fd_neigh4_hmap_fprintf( fd_neigh4_hmap_t const * map,
                        void *                       file );

#endif /* FD_HAS_HOSTED */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_neigh_fd_neigh4_map_h */
