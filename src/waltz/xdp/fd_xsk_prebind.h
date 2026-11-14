#ifndef HEADER_fd_src_waltz_xdp_fd_xsk_prebind_h
#define HEADER_fd_src_waltz_xdp_fd_xsk_prebind_h

/* Pure layout and fresh-ring publication primitives. The experimental
   opt-in initializer transfers the published physical span before bind. */
#include <limits.h>

struct fd_xsk_prebind_layout {
  unsigned long tx_off, cache_off, phys_off, loop_off, end_off;
  unsigned long tx_cnt, cache_cnt, phys_cnt, loop_cnt;
};
typedef struct fd_xsk_prebind_layout fd_xsk_prebind_layout_t;

static inline int
fd_xsk_prebind_layout( fd_xsk_prebind_layout_t * out,
                      unsigned long umem_sz, unsigned long frame_sz,
                      unsigned long tx_cnt, unsigned long cache_cnt,
                      unsigned long phys_cnt, unsigned long loop_cnt ) {
  if( !out || frame_sz!=2048UL || umem_sz%frame_sz || !phys_cnt ) return -1;
  unsigned long counts[4]={tx_cnt,cache_cnt,phys_cnt,loop_cnt};
  unsigned long offsets[5]={0UL,0UL,0UL,0UL,0UL};
  for( unsigned i=0U; i<4U; i++ ) {
    if( counts[i]>(umem_sz-offsets[i])/frame_sz ) return -1;
    offsets[i+1U]=offsets[i]+counts[i]*frame_sz;
  }
  fd_xsk_prebind_layout_t result={ offsets[0],offsets[1],offsets[2],offsets[3],offsets[4],
                                 tx_cnt,cache_cnt,phys_cnt,loop_cnt };
  *out=result;
  return 0;
}

/* Fresh, unbound FILL ring only. Caller supplies one validated disjoint
   physical span.  Reject reuse rather than resetting a potentially live
   ring. Zero counters alone do not prove the socket is unbound; the caller
   must establish that and nonaliasing ring/control storage. No writes on error; release publication follows all descriptors. */
static inline int
fd_xsk_prebind_publish( unsigned long * descriptors,
                       unsigned int * producer, unsigned int const * consumer,
                       unsigned int * cached_prod, unsigned int const * cached_cons,
                       unsigned long depth, unsigned long offset,
                       unsigned long count, unsigned long umem_sz ) {
  if( !descriptors || !producer || !consumer || !cached_prod || !cached_cons ||
      !depth || (depth&(depth-1UL)) || depth>UINT_MAX || !count || count>depth ||
      umem_sz%2048UL || offset%2048UL || offset>umem_sz ||
      count>(umem_sz-offset)/2048UL ) return -1;
  if( *cached_prod || *cached_cons ||
      __atomic_load_n( producer, __ATOMIC_ACQUIRE ) ||
      __atomic_load_n( consumer, __ATOMIC_ACQUIRE ) ) return -1;
  for( unsigned long i=0UL; i<count; i++ ) descriptors[i]=offset+i*2048UL;
  *cached_prod=(unsigned int)count;
  __atomic_store_n( producer, (unsigned int)count, __ATOMIC_RELEASE );
  return 0;
}
#endif
