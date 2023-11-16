#ifndef HEADER_fd_src_tango_lru_fd_lru_h
#define HEADER_fd_src_tango_lru_fd_lru_h

/* fd_lru_t is very similar to fd_tcache_t. The main differences are:
      1. instead of a ring, it uses a doubly linked list.
      2. instead of a map of tag -> index, it uses a map of tag -> node.

   Keeping in mind these differences, the API and documentation is otherwise
   based on `fd_tcache.h`.

   A fd_lru_t is a cache of the most recently observed unique 64-bit
   tags.  It is useful for, among other things, deduplication of traffic
   based on a thumbprint / hash / signature.  Makes no demands on the
   application on tagging scheme except that there be a "null" tag (a
   tag value that will never occur).

   The amount of history ("depth") of a lru is theoretically
   unlimited but the implementation below was optimized for large-ish
   depths (e.g. millions) on platforms where memory footprint is
   reasonable cheap.  The implementation was also optimized for
   situations where heavily duplication is common and temporally
   localized.  Lastly, the implementation is optimized for the case that
   tags behave like IID random values (e.g. a tag is a hash of a packet
   payload).

   It is strongly recommend that the lru be backed by a single NUMA
   page (e.g. in a gigantic page backed workspace) to avoid TLB
   thrashing if used in performance critical contexts. */

#include "../fd_tango_base.h"
#include "fd_list.h"

/* FD_TCACHE_{ALIGN,FOOTPRINT} specify the alignment and footprint
   needed for a tcache with depth history and a tag key-only map with
   map_cnt slots.  ALIGN is at least double cache line to mitigate
   various kinds of false sharing.  depth and map_cnt are assumed to be
   valid (i.e. depth is positive, map_cnt is an integer power of 2 of at
   least depth+2 and the combination will not require a footprint larger
   than ULONG_MAX). */
#define FD_LRU_ALIGN ( 128UL )

#define FD_LRU_TAG_NULL ( 0UL )

#define FD_LRU_SPARSE_DEFAULT ( 2 )

#define FD_LRU_MAGIC ( 0xf17eda2c3712C0UL ) /* firedancer lru ver 0 */

struct __attribute( ( aligned( FD_LRU_ALIGN ) ) ) fd_lru_private {
  ulong magic; /* ==FD_LRU_MAGIC */
  ulong depth; /* The lru will maintain a history of the most recent depth tags */
  ulong free_top;
  ulong map_cnt;

  /* depth ulong (doubly linked list):

     After the tcache has started up (i.e. at least depth unique tags
     have been inserted), list[oldest] will be contain the oldest tag in
     the tcache.  This is a circular doubly linked list with a sentinel:
     the entry before sentinel (cyclic) is the newest tag in the tcache and
     the list entry after oldest (cyclic) is the 2nd oldest tag in the
     tcache. During startup (the first depth-1 unique tags inserted),
     list[oldest] will be FD_TCACHE_NULL.  In high performance operation,
     only the slots around oldest will be in active use / occupy local
     cache and the access pattern will be highly sequential. */

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

typedef struct fd_lru_private fd_lru_t;

FD_PROTOTYPES_BEGIN

/* fd_lru_map_cnt_default returns the default map_cnt to use for the
   given depth.  Returns 0 if the depth is invalid / results in a
   map_cnt larger than ULONG_MAX. */

FD_FN_CONST static inline ulong
fd_lru_map_cnt_default( ulong depth ) {

  if ( FD_UNLIKELY( !depth ) ) return 0UL; /* depth must be positive */

  if ( FD_UNLIKELY( depth == ULONG_MAX ) ) return 0UL;                       /* overflow */
  int lg_map_cnt = fd_ulong_find_msb( depth + 1UL ) + FD_LRU_SPARSE_DEFAULT; /* no overflow */
  if ( FD_UNLIKELY( lg_map_cnt > 63 ) ) return 0UL;                          /* depth too large */

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

/* fd_lru_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as a lru.
   fd_lru_align returns FD_LRU_ALIGN.  For fd_lru_footprint, a
   map_cnt of 0 indicates to use fd_lru_map_cnt_default above.  If
   depth is not positive, map_cnt is not a power of 2 of at least
   depth+2 and/or the required footprint would be larger than ULONG_MAX,
   footprint will silently return 0 (and thus can be used by the caller
   to validate the lru configuration parameters).  Otherwise, it
   returns FD_LRU_FOOTPRINT for actual value of map_cnt used. */

FD_FN_CONST ulong
fd_lru_align( void );

FD_FN_CONST ulong
fd_lru_footprint( ulong depth, ulong map_cnt );

/* fd_lru_new formats an unused memory region for use as a lru.
   shmem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment.  depth is the number of
   unique tags that can be stored in the lru and should be positive
   (positive integer powers of 2 minus 2 have good memory footprint Feng
   Shui and positive integer powers of 2 minus 1 have good computational
   efficiency Feng Shui).  map_cnt is the number of slots to use for the
   map.  A map_cnt of 0 indicates to fd_lru_map_cnt_default above.

   Returns shmem (and the memory region it points to will be formatted
   as a lru, caller is not joined, lru will be empty) on success
   and NULL on failure (logs details).  Reasons for failure include
   obviously bad shmem, bad depth or bad map_cnt. */

void *
fd_lru_new( void * shmem, ulong depth, ulong map_cnt );

/* fd_lru_join joins the caller to the lru.  _lru points to the
   first byte of the memory region backing the lru in the caller's
   address space.

   Returns a pointer in the local address space to the lru's entries
   on success (this is not necessarily just a cast of _lru) and NULL
   on failure (logs details).  Reasons for failure are that _lru is
   obviously not a pointer to memory region holding a lru.  Every
   successful join should have a matching leave.  The lifetime of the
   join is until the matching leave or thread group is terminated. */

fd_lru_t *
fd_lru_join( void * _lru );

/* fd_lru_leave leaves a current local join.  Returns a pointer to
   the underlying shared memory region on success (this is not
   necessarily just a cast of _lru) and NULL on failure (logs
   details).  Reasons for failure include lru is NULL. */

void *
fd_lru_leave( fd_lru_t * lru );

/* fd_lru_delete unformats a memory region used as a lru.  Assumes
   nobody is joined to the region.  Returns a pointer to the underlying
   shared memory region or NULL if used obviously in error (e.g.
   _lru is obviously not a lru ... logs details).  The ownership
   of the memory region is transferred to the caller. */

void *
fd_lru_delete( void * _lru );

/* fd_lru_{depth,map_cnt,oldest_laddr,list_laddr,map_laddr} return
   various properties of the lru.  These assume lru is a valid
   local join.  Since lru is used in performance critical code paths,
   typical usage will unpack lru list and map pointers into registers
   and the current value for oldest will be tracked in a register as
   well.  It is the responsibility of users to update the value at
   oldest_laddr at termination to do clean restarts on an in progress
   lru. */

FD_FN_PURE static inline ulong
fd_lru_depth( fd_lru_t const * lru ) {
  return lru->depth;
}
FD_FN_PURE static inline ulong
fd_lru_free_top( fd_lru_t const * lru ) {
  return lru->free_top;
}
FD_FN_PURE static inline ulong
fd_lru_map_cnt( fd_lru_t const * lru ) {
  return lru->map_cnt;
}

FD_FN_CONST static inline fd_list_t *
fd_lru_list_laddr( fd_lru_t * lru ) {
  return ( (fd_list_t *)fd_type_pun( lru ) ) + 1UL;
} /* both metadata and fd_list_t are 32-byte */

FD_FN_PURE static inline fd_list_t **
fd_lru_map_laddr( fd_lru_t * lru ) {
  return (fd_list_t **)fd_type_pun( ( (fd_list_t *)lru ) + 1UL /*metadata*/ + 1UL /*sentinel*/ +
                                    lru->depth );
}

/* fd_lru_tag_is_null returns non-zero if tag is FD_LRU_TAG_NULL
   and zero otherwise. */

FD_FN_CONST static inline int
fd_lru_tag_is_null( ulong tag ) {
  return tag == FD_LRU_TAG_NULL;
}

/* fd_lru_reset resets a lru to empty, the same state the lru
   was in at creation.  For performance critical usage, does no input
   argument checking, uses the unpacked lru fields and returns the
   value to use for oldest. */

static inline ulong
fd_lru_reset( ulong * list, ulong depth, ulong * map, ulong map_cnt ) {
  for ( ulong list_idx = 0UL; list_idx < depth; list_idx++ )
    list[list_idx] = FD_LRU_TAG_NULL;
  for ( ulong map_idx = 0UL; map_idx < map_cnt; map_idx++ )
    map[map_idx] = FD_LRU_TAG_NULL;
  return 0UL; /* list_oldest */
}

/* fd_lru_map_start returns the location in a lru map to start
   probing for tag.  Assumes tag is not null and map_cnt is a positive
   integer power of 2.  Implementation here is optimized for the case
   where tags are randomized.

   fd_lru_map_next returns the next location to probe given the
   current location.  idx is assumed in [0,map_cnt) and map_cnt is
   assumed to be a positive integer power of 2. */

FD_FN_CONST static inline ulong
fd_lru_map_start( ulong tag, ulong map_cnt ) {
  return tag & ( map_cnt - 1UL );
}
FD_FN_CONST static inline ulong
fd_lru_map_next( ulong idx, ulong map_cnt ) {
  return ( idx + 1UL ) & ( map_cnt - 1UL );
}

/* FD_LRU_QUERY searches for tag in a map with map_cnt slots.  On
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
   uses the unpacked fields of a lru.  Assumes map is non-NULL, map
   is indexed [0,map_cnt), map_cnt is a positive integer power-of-two
   and tag is not null.

   This macro is robust (e.g. evaluates its arguments a minimal number
   of times) and pure (i.e. found / map_idx will not change between
   calls given the same map / map[*] / tag). */

#define FD_LRU_QUERY( found, map_idx, map, map_cnt, tag )                                          \
  do {                                                                                             \
    fd_list_t * const * _flq_map     = ( map );                                                    \
    ulong               _flq_map_cnt = ( map_cnt );                                                \
    ulong               _flq_tag     = ( tag );                                                    \
    int                 _flq_found   = 0;                                                          \
    ulong               _flq_map_idx = fd_lru_map_start( _flq_tag, _flq_map_cnt );                 \
    for ( ;; ) {                                                                                   \
      fd_list_t * _flq_map_slot = _flq_map[_flq_map_idx];                                          \
      if ( _flq_map_slot == NULL ) break;                                                          \
      _flq_found = ( _flq_tag == _flq_map_slot->tag );                                             \
      if ( FD_LIKELY( _flq_found | fd_lru_tag_is_null( _flq_map_slot->tag ) ) ) break;             \
      _flq_map_idx = fd_lru_map_next( _flq_map_idx, _flq_map_cnt );                                \
    }                                                                                              \
    ( found )   = _flq_found;                                                                      \
    ( map_idx ) = _flq_map_idx;                                                                    \
  } while ( 0 )

/* fd_lru_remove removes tag in a map with map_cnt slots.  For
   sparsely populated maps and properly randomized tags, this is a fast
   O(1).  This does not remove tag from the list, so the user is responsible
   for the removing the value from the list.  As this is used in performance
   critical contexts, does no input argument checking and uses the
   unpacked fields of a lru.  Assumes map is non-NULL, map is indexed
   [0,map_cnt) and map_cnt is a positive integer power-of-two.  Does
   nothing if tag is null or if tag is not currently in the map. */

FD_FN_UNUSED static void /* Work around -Winline */
fd_lru_remove( fd_lru_t * lru, ulong tag ) {

  /* Look up tag in the lru.  If not found, nothing to do.  (This
     should always succeed at this point in typical lru usage but we
     keep the check for paranoia / minimize risk of silent corruption.) */

  int          found;
  ulong        slot;
  fd_list_t ** map = fd_lru_map_laddr( lru );
  FD_LRU_QUERY( found, slot, map, lru->map_cnt, tag );
  if ( FD_LIKELY( found ) ) {

    /* slot contains the tag to remove.  Remove it.  See util/fd_map*
       for details how this works. */

    for ( ;; ) {
      map[slot]        = FD_LRU_TAG_NULL;
      ulong       hole = slot;
      fd_list_t * next;
      for ( ;; ) {
        slot = fd_lru_map_next( slot, lru->map_cnt );
        next = map[slot];
        if ( FD_LIKELY( next == NULL || fd_lru_tag_is_null( next->tag ) ) ) return;
        ulong start = fd_lru_map_start( tag, lru->map_cnt );
        if ( !( ( ( hole < start ) & ( start <= slot ) ) |
                ( ( hole > slot ) & ( ( hole < start ) | ( start <= slot ) ) ) ) )
          break;
      }
      map[hole] = next;
    }
  }
}

static inline fd_list_t *
fd_lru_list_acquire( fd_lru_t * lru ) {
  fd_list_t * sentinel = fd_lru_list_laddr( lru );
  fd_list_t * free_top = sentinel + lru->free_top;
  lru->free_top        = free_top->next;
  return fd_list_remove( free_top );
}

/* user is responsible for ensuring curr is removed */
static inline void
fd_lru_list_release( fd_lru_t * lru, fd_list_t * curr ) {
  fd_list_t * sentinel = fd_lru_list_laddr( lru );
  fd_list_t * free_top = sentinel + lru->free_top;
  fd_list_insert( fd_list_prev( free_top ), curr );
  lru->free_top = curr->curr;
}

static inline fd_list_t *
fd_lru_list_head( fd_lru_t * lru ) {
  return fd_list_next( fd_lru_list_laddr( lru ) );
}

static inline fd_list_t *
fd_lru_list_tail( fd_lru_t * lru ) {
  return fd_list_prev( fd_lru_list_laddr( lru ) + lru->free_top );
}

/* fd_lru_upsert upserts tag into the lru in fast O(1) operations.
   On return, if tag is already in the lru, the tag will be moved to
   most recent position (back). If tag is not in the lru, tag was inserted,
   and if the lru was full (i.e. had already contained depth values), the
   oldest tag in the lru will have been evicted.

   Returns the evicted element (if any) or NULL if no element was evicted.

   Assumes oldest is in [0,depth), list is non-NULL and indexed
   [0,depth), depth is positive, map is non-NULL, map is indexed
   [0,map_cnt), map_cnt is an integer power-of-two of at least depth+2,
   and tag is not null.

   Map entries store the location in the list structure. On a duplicate
   tag, insert will move the duplicate tag from its current location in
   the list (given from the query itself) to one immediately before the
   oldest tag in the list and update the map entry (and similar for
   unique tag insert). */

static inline fd_list_t *
fd_lru_upsert( fd_lru_t * lru, ulong tag, int * dup ) {
  ulong        map_idx;
  fd_list_t ** map = fd_lru_map_laddr( lru );
  int          found;
  FD_LRU_QUERY( found, map_idx, map, lru->map_cnt, tag );
  *dup                = found;
  fd_list_t * evicted = NULL;

  /* LRU insert*/
  if ( !*dup ) { /* application dependent branch probability */
    /* Evict oldest tag / insert tag into list */
    if ( FD_LIKELY( lru->free_top == 0 ) ) {
      fd_list_t * remove = fd_list_remove( fd_lru_list_head( lru ) );
      fd_lru_list_release( lru, remove );
      fd_lru_remove( lru, remove->tag );
      evicted = remove;
    }
    fd_list_t * insert = fd_lru_list_acquire( lru );
    insert->tag        = tag;
    fd_list_insert( fd_lru_list_tail( lru ), insert );

    /* Insert tag into the map (assumes depth <= map_cnt-2) */
    /* map has at most map_cnt-2 entries here */
    map[map_idx] = insert;
    /* map has at most map_cnt-1 entries here */

    /* LRU update */
  } else {
    fd_list_insert( fd_lru_list_tail( lru ), fd_list_remove( map[map_idx] ) );
  }
  return evicted;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_tango_lru_fd_lru_h */
