/* fd_rollset.h provides a rolling bitset for 64 entries.

     ..11111111 01010101..01010101 00000000..
       ^        ^                  ^
       left     active set         right

   The bitset tracks a 64 wide range of indices.  All indices left to
   the bitset are 1.  All indices right to the bitset are 0. */

#include "../../util/bits/fd_bits.h"

struct fd_rollset {
  ulong min;
  ulong set;
};

typedef struct fd_rollset fd_rollset_t;

static inline fd_rollset_t *
fd_rollset_init( fd_rollset_t * rs ) {
  rs->min = 0UL;
  rs->set = 0UL;
  return rs;
}

static inline void
fd_rollset_insert( fd_rollset_t * rs,
                   ulong          idx ) {
  ulong min  = rs->min;
  ulong set  = rs->set;
  ulong dist = idx - min;
        min  = dist<=0x3fUL ?  min : idx -0x3fUL;
  ulong roll = dist<=0x3fUL ?  0UL : dist-0x3fUL;
  ulong pos  = dist<=0x3fUL ? dist :      0x3fUL;
        set  = dist>=0x80UL ?  0UL : set>>roll;
        set |= 1UL<<pos;
  rs->set    = set;
  rs->min    = min;
}

FD_FN_PURE static inline int
fd_rollset_query( fd_rollset_t const * rs,
                  ulong                idx ) {
  ulong min  = rs->min;
  ulong set  = rs->set;
  ulong dist = idx - min;
  ulong mask = (1UL<<(dist&63));
  int   res  = !!(set & mask);
  return idx<min ? 1 : dist>=64 ? 0 : res;
}
