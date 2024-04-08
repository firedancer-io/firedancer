#ifndef HEADER_fd_src_tango_tcache_fd_tcache_h
#define HEADER_fd_src_tango_tcache_fd_tcache_h

/* A fd_tcache_t is a cache of the most recently observed unique 64-bit
   tags.  It is useful for, among other things, deduplication of traffic
   based on a thumbprint / hash / signature.  Makes no demands on the
   application on tagging scheme except that there be a "null" tag (a
   tag value that will never occur).

   The amount of history ("depth") of a tcache is theoretically
   unlimited but the implementation below was optimized for large-ish
   depths (e.g. millions) on platforms where memory footprint is
   reasonable cheap.  The implementation was also optimized for
   situations where heavily duplication is common and temporally
   localized.  Lastly, the implementation is optimized for the case that
   tags behave like IID random values (e.g. a tag is a hash of a packet
   payload).

   It is strongly recommend that the tcache be backed by a single NUMA
   page (e.g. in a gigantic page backed workspace) to avoid TLB
   thrashing if used in performance critical contexts. */

#include "../fd_tango_base.h"

/* FD_TCACHE_{ALIGN,FOOTPRINT} specify the alignment and footprint
   needed for a tcache with depth history and a tag key-only map with
   map_cnt slots.  ALIGN is at least double cache line to mitigate
   various kinds of false sharing.  depth and map_cnt are assumed to be
   valid (i.e. depth is positive, map_cnt is an integer power of 2 of at
   least depth+2 and the combination will not require a footprint larger
   than ULONG_MAX).  These are provided to facilitate compile time
   declarations. */

#define FD_TCACHE_ALIGN (128UL)
#define FD_TCACHE_FOOTPRINT( depth, map_cnt )                     \
  FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,               \
    FD_TCACHE_ALIGN, (4UL + (depth) + (map_cnt))*sizeof(ulong) ), \
    FD_TCACHE_ALIGN )

/* FD_TCACHE_TAG_NULL is a tag value that will never be inserted. */

#define FD_TCACHE_TAG_NULL (0UL)

/* FD_TCACHE_SPARSE_DEFAULT specifies how sparse a default map_cnt
   tcache map should be.  Must be a positive and << 64.  After startup, a
   tcache with a large depth with a default map size will have fixed
   fill ratio somewhere between ~2^-SPARSE_DEFAULT and
   ~2^-(SPARSE_DEFAULT-1) (i.e. for SPARSE_DEFAULT=2, the fill ratio
   will be in the range 25% to 50%).  This trades off between tcache
   memory footprint efficiency and tcache computational efficiency.
   Larger values are more computationally efficient but with an
   exponentially rapidly diminishing return and an exponentially
   increasing memory footprint.  SPARSE_DEFAULT of 1 is usually a bad
   idea as operational costs can spike exponentially if the worst fill
   ratio for the depth ends up close to 1. */

#define FD_TCACHE_SPARSE_DEFAULT (2)

/* fd_tcache_t is an opaque handle of a tcache object.  Details are
   exposed here to facilitate usage of tcache in performance critical
   contexts. */

#define FD_TCACHE_MAGIC (0xf17eda2c377ca540UL) /* firedancer tcash ver 0 */

struct __attribute((aligned(FD_TCACHE_ALIGN))) fd_tcache_private {
  ulong magic;   /* ==FD_TCACHE_MAGIC */
  ulong depth;   /* The tcache will maintain a history of the most recent depth tags */
  ulong map_cnt;
  ulong oldest;  /* oldest is in [0,depth) */

  /* depth ulong (ring):

     After the tcache has started up (i.e. at least depth unique tags
     have been inserted), ring[oldest] will be contain the oldest tag in
     the tcache.  As strongly hinted by the name, ring is cyclic: the
     ring entry before oldest (cyclic) is the newest tag in the tcache
     and the ring entry after oldest (cyclic) is the 2nd oldest tag in
     the tcache.  During startup (the first depth-1 unique tags
     inserted), ring[oldest] will be FD_TCACHE_NULL.  In high
     performance operation, only the slots around oldest will be in
     active use / occupy local cache and the access pattern will be
     highly sequential. */

  /* map_cnt ulong (map):

     This is a sparse linear probed key-only map of tags currently in
     the tcache.  Since it is sparse, probe collisions are rare (and thus
     the branches involved in various cache operations are highly
     predictable.  While the sparsity makes the map reasonably
     inefficient from a memory footprint point of view, memory footprint
     is quite cheap in practice and the actual cache utilization is
     quite mild.  Specifically, if tag duplication is rare, only the
     slots around the newest and oldest tags will be in use typically.
     Further, if any tag duplication is temporally clustered (as is
     commonly the case), duplicate tags will be a cache hit against the
     (still cached because of recent use) original insertion.

     In the typical case of randomized tags, this randomly accesses the
     map aggressively.  The NUMA and TLB thrashing impacts of that can
     be reduced / eliminated by backing the tcache with a huge /
     gigantic page shared workspace on a NUMA node nearby the tcache
     using threads. */

  /* Padding to FD_TCACHE align */
};

typedef struct fd_tcache_private fd_tcache_t;

FD_PROTOTYPES_BEGIN

/* fd_tcache_map_cnt_default returns the default map_cnt to use for the
   given depth.  Returns 0 if the depth is invalid / results in a
   map_cnt larger than ULONG_MAX. */

FD_FN_CONST static inline ulong
fd_tcache_map_cnt_default( ulong depth ) {

  if( FD_UNLIKELY( !depth ) ) return 0UL; /* depth must be positive */

  if( FD_UNLIKELY( depth==ULONG_MAX ) ) return 0UL; /* overflow */
  int lg_map_cnt = fd_ulong_find_msb( depth + 1UL ) + FD_TCACHE_SPARSE_DEFAULT; /* no overflow */
  if( FD_UNLIKELY( lg_map_cnt>63 ) ) return 0UL; /* depth too large */

  /* At this point:

       2^(lg_map_cnt-s) <= depth+n < 2^(lg_map_cnt-s+1)

     where s is SPARSE_DEFAULT > 0 and n is 1.

       map_cnt/2^s - n <= depth < map_cnt/2^(s-1) - n
       1/2^s - n/map_cnt <= depth/map_cnt < 1/2^(s-1) - n/map_cnt

     For asymptotically large depth / map_cnt, the worst case map fill
     ratio will asymptote to something in ~( 1/2^s, 1/2^(s-1) ).
     Flipping this around, we also have:

       -> 2^(s-1) (depth+n) < map_cnt <= 2^s (depth+n)

     In the worst case, s==1, depth+1 < map_cnt -> map_cnt>=depth+2. */

  return 1UL << lg_map_cnt;
}

/* fd_tcache_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as a tcache.
   fd_tcache_align returns FD_TCACHE_ALIGN.  For fd_tcache_footprint, a
   map_cnt of 0 indicates to use fd_tcache_map_cnt_default above.  If
   depth is not positive, map_cnt is not a power of 2 of at least
   depth+2 and/or the required footprint would be larger than ULONG_MAX,
   footprint will silently return 0 (and thus can be used by the caller
   to validate the tcache configuration parameters).  Otherwise, it
   returns FD_TCACHE_FOOTPRINT for actual value of map_cnt used. */

FD_FN_CONST ulong
fd_tcache_align( void );

FD_FN_CONST ulong
fd_tcache_footprint( ulong depth,
                     ulong map_cnt );

/* fd_tcache_new formats an unused memory region for use as a tcache.
   shmem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment.  depth is the number of
   unique tags that can be stored in the tcache and should be positive
   (positive integer powers of 2 minus 2 have good memory footprint Feng
   Shui and positive integer powers of 2 minus 1 have good computational
   efficiency Feng Shui).  map_cnt is the number of slots to use for the
   map.  A map_cnt of 0 indicates to fd_tcache_map_cnt_default above.

   Returns shmem (and the memory region it points to will be formatted
   as a tcache, caller is not joined, tcache will be empty) on success
   and NULL on failure (logs details).  Reasons for failure include
   obviously bad shmem, bad depth or bad map_cnt. */

void *
fd_tcache_new( void * shmem,
               ulong  depth,
               ulong  map_cnt );

/* fd_tcache_join joins the caller to the tcache.  _tcache points to the
   first byte of the memory region backing the tcache in the caller's
   address space.

   Returns a pointer in the local address space to the tcache's entries
   on success (this is not necessarily just a cast of _tcache) and NULL
   on failure (logs details).  Reasons for failure are that _tcache is
   obviously not a pointer to memory region holding a tcache.  Every
   successful join should have a matching leave.  The lifetime of the
   join is until the matching leave or thread group is terminated. */

fd_tcache_t *
fd_tcache_join( void * _tcache );

/* fd_tcache_leave leaves a current local join.  Returns a pointer to
   the underlying shared memory region on success (this is not
   necessarily just a cast of _tcache) and NULL on failure (logs
   details).  Reasons for failure include tcache is NULL. */

void *
fd_tcache_leave( fd_tcache_t * tcache );

/* fd_tcache_delete unformats a memory region used as a tcache.  Assumes
   nobody is joined to the region.  Returns a pointer to the underlying
   shared memory region or NULL if used obviously in error (e.g.
   _tcache is obviously not a tcache ... logs details).  The ownership
   of the memory region is transferred to the caller. */

void *
fd_tcache_delete( void * _tcache );

/* fd_tcache_{depth,map_cnt,oldest_laddr,ring_laddr,map_laddr} return
   various properties of the tcache.  These assume tcache is a valid
   local join.  Since tcache is used in performance critical code paths,
   typical usage will unpack tcache ring and map pointers into registers
   and the current value for oldest will be tracked in a register as
   well.  It is the responsibility of users to update the value at
   oldest_laddr at termination to do clean restarts on an in progress
   tcache. */

FD_FN_PURE  static inline ulong   fd_tcache_depth       ( fd_tcache_t const * tcache ) { return tcache->depth; }
FD_FN_PURE  static inline ulong   fd_tcache_map_cnt     ( fd_tcache_t const * tcache ) { return tcache->map_cnt; }

FD_FN_CONST static inline ulong * fd_tcache_oldest_laddr( fd_tcache_t * tcache ) { return &tcache->oldest; }
FD_FN_CONST static inline ulong * fd_tcache_ring_laddr  ( fd_tcache_t * tcache ) { return ((ulong *)tcache)+4UL; }
FD_FN_PURE  static inline ulong * fd_tcache_map_laddr   ( fd_tcache_t * tcache ) { return ((ulong *)tcache)+4UL+tcache->depth; }

/* fd_tcache_tag_is_null returns non-zero if tag is FD_TCACHE_TAG_NULL
   and zero otherwise. */

FD_FN_CONST static inline int fd_tcache_tag_is_null( ulong tag ) { return tag==FD_TCACHE_TAG_NULL; }

/* fd_tcache_reset resets a tcache to empty, the same state the tcache
   was in at creation.  For performance critical usage, does no input
   argument checking, uses the unpacked tcache fields and returns the
   value to use for oldest. */

static inline ulong
fd_tcache_reset( ulong * ring,
                 ulong   depth,
                 ulong * map,
                 ulong   map_cnt ) {
  for( ulong ring_idx=0UL; ring_idx<depth;   ring_idx++ ) ring[ ring_idx ] = FD_TCACHE_TAG_NULL;
  for( ulong map_idx =0UL; map_idx <map_cnt; map_idx++  ) map [ map_idx  ] = FD_TCACHE_TAG_NULL;
  return 0UL; /* ring_oldest */
}

/* fd_tcache_map_start returns the location in a tcache map to start
   probing for tag.  Assumes tag is not null and map_cnt is a positive
   integer power of 2.  Implementation here is optimized for the case
   where tags are randomized.

   fd_tcache_map_next returns the next location to probe given the
   current location.  idx is assumed in [0,map_cnt) and map_cnt is
   assumed to be a positive integer power of 2. */

FD_FN_CONST static inline ulong fd_tcache_map_start( ulong tag, ulong map_cnt ) { return  tag      & (map_cnt-1UL); }
FD_FN_CONST static inline ulong fd_tcache_map_next ( ulong idx, ulong map_cnt ) { return (idx+1UL) & (map_cnt-1UL); }

/* FD_TCACHE_QUERY searches for tag in a map with map_cnt slots.  On
   return, map_idx will be in [0,map_cnt) and found will be in [0,1].
   If found is 0, map_idx is a suitable location where tag can be
   inserted into the map, assuming the map has at most map_cnt-2 entries
   currently in it.  If found is is 1, map_idx is the index into the map
   where tag is currently located (this index will be valid until the
   next map remove or map destruction).

   For sparse fill ratios and properly randomized map_starts, this is a
   fast O(1).

   This is implemented as a macro to support multiple return values
   (found and map_idx), especially as this is used in performance
   critical contexts.  Similarly, does no input argument checking and
   uses the unpacked fields of a tcache.  Assumes map is non-NULL, map
   is indexed [0,map_cnt), map_cnt is a positive integer power-of-two
   and tag is not null.

   This macro is robust (e.g. evaluates its arguments a minimal number
   of times) and pure (i.e. found / map_idx will not change between
   calls given the same map / map[*] / tag). */

#define FD_TCACHE_QUERY( found, map_idx, map, map_cnt, tag ) do {                  \
    ulong const * _ftq_map     = (map);                                            \
    ulong         _ftq_map_cnt = (map_cnt);                                        \
    ulong         _ftq_tag     = (tag);                                            \
    int           _ftq_found;                                                      \
    ulong         _ftq_map_idx = fd_tcache_map_start( _ftq_tag, _ftq_map_cnt );    \
    for(;;) {                                                                      \
      ulong _ftq_map_tag = _ftq_map[ _ftq_map_idx ];                               \
      _ftq_found = (_ftq_tag==_ftq_map_tag);                                       \
      if( FD_LIKELY( _ftq_found | fd_tcache_tag_is_null( _ftq_map_tag ) ) ) break; \
      _ftq_map_idx = fd_tcache_map_next( _ftq_map_idx, _ftq_map_cnt );             \
    }                                                                              \
    (found)   = _ftq_found;                                                        \
    (map_idx) = _ftq_map_idx;                                                      \
  } while(0)

/* fd_tcache_remove removes tag in a map with map_cnt slots.  For
   sparsely populated maps and properly randomized tags, this is a fast
   O(1).  This does not remove tag from the ring, so oldest may still
   take a value that was removed.  As this is used in performance
   critical contexts, does no input argument checking and uses the
   unpacked fields of a tcache.  Assumes map is non-NULL, map is indexed
   [0,map_cnt) and map_cnt is a positive integer power-of-two.  Does
   nothing if tag is null or if tag is not currently in the map. */

FD_FN_UNUSED static void /* Work around -Winline */
fd_tcache_remove( ulong * map,
                  ulong   map_cnt,
                  ulong   tag ) {

  /* If tag is a null tag (e.g. less than depth unique tags have been
     inserted into the tcache), nothing to do. */

  if( FD_LIKELY( !fd_tcache_tag_is_null( tag ) ) ) {

    /* Look up tag in the tcache.  If not found, nothing to do.  (This
       should always succeed at this point in typical tcache usage but we
       keep the check for paranoia / minimize risk of silent corruption.) */

    int   found;
    ulong slot;
    FD_TCACHE_QUERY( found, slot, map, map_cnt, tag );
    if( FD_LIKELY( found ) ) {

      /* slot contains the tag to remove.  Remove it.  See util/fd_map*
         for details how this works. */

      for(;;) {
        map[ slot ] = FD_TCACHE_TAG_NULL;
        ulong hole = slot;
        for(;;) {
          slot = fd_tcache_map_next( slot, map_cnt );
          tag  = map[ slot ];
          if( FD_LIKELY( fd_tcache_tag_is_null( tag ) ) ) return;
          ulong start = fd_tcache_map_start( tag, map_cnt );
          if( !(((hole<start) & (start<=slot)) | ((hole>slot) & ((hole<start) | (start<=slot)))) ) break;
        }
        map[ hole ] = tag;
      }
    }
  }
}

/* FD_TCACHE_INSERT inserts tag into the tcache in fast O(1) operations.
   On return, if dup is non-zero, tag is already in the tcache and the
   tcache in unchanged.  If dup is zero, tag was inserted and, if the
   tcache was full (e.g. has had depth values previously inserted), the
   oldest tag in the tcache will have been evicted.

   This is implemented as a macro to support multiple return values (dup
   and oldest in particular), especially as this is used in performance
   critical contexts.  Similarly, does no input argument checking.
   Assumes oldest is in [0,depth), ring is non-NULL and indexed
   [0,depth), depth is positive, map is non-NULL, map is indexed
   [0,map_cnt), map_cnt is an integer power-of-two of at least depth+2,
   and tag is not null.

   Note that, given a duplicate tag, insertion is _not_ LRU-like (i.e.
   does not make the duplicate tag the most recently used tag in the
   tcache).  This is usually the desired behavior in deduplication and
   it is cheaper as well.  LRU-like behavior is still possible with
   fast-ish O(1) and more memory footprint.  Specifically, the map
   entries would store the location in the ring structure and ring
   structure would need to be made a doubly linked list.  On a duplicate
   tag, insert would move the duplicate tag from its current location in
   the ring (given from the query itself) to one immediately before the
   oldest tag in the ring and update the map entry (and similar for
   unique tag insert).

   This macro is robust (e.g. evaluates its arguments a minimal number
   of times). */

#define FD_TCACHE_INSERT( dup, oldest, ring, depth, map, map_cnt, tag ) do {     \
    ulong   _fti_oldest   = (oldest);                                            \
    ulong * _fti_ring     = (ring);                                              \
    ulong   _fti_depth    = (depth);                                             \
    ulong * _fti_map      = (map);                                               \
    ulong   _fti_map_cnt  = (map_cnt);                                           \
    ulong   _fti_tag      = (tag);                                               \
                                                                                 \
    int   _fti_dup;                                                              \
    ulong _fti_map_idx;                                                          \
    FD_TCACHE_QUERY( _fti_dup, _fti_map_idx, _fti_map, _fti_map_cnt, _fti_tag ); \
    if( !_fti_dup ) { /* application dependent branch probability */             \
                                                                                 \
      /* Insert tag into the map (assumes depth <= map_cnt-2) */                 \
      /* map has at most map_cnt-2 entries here */                               \
      _fti_map[ _fti_map_idx ] = _fti_tag;                                       \
      /* map has at most map_cnt-1 entries here */                               \
                                                                                 \
      /* Evict oldest tag / insert tag into ring */                              \
      ulong _fti_tag_oldest = _fti_ring[ _fti_oldest ];                          \
      _fti_ring[ _fti_oldest ] = _fti_tag;                                       \
      _fti_oldest++;                                                             \
      if( _fti_oldest >= _fti_depth ) _fti_oldest = 0UL; /* cmov */              \
                                                                                 \
      /* Remove oldest tag from map */                                           \
      /* _fti_tag_oldest will be null at startup but remove handles that case */ \
      fd_tcache_remove( _fti_map, _fti_map_cnt, _fti_tag_oldest );               \
      /* Map has at most map_cnt-2 entries here */                               \
    }                                                                            \
    (dup)    = _fti_dup;                                                         \
    (oldest) = _fti_oldest;                                                      \
  } while(0)

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_tango_tcache_fd_tcache_h */

