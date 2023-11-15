#ifndef HEADER_fd_src_tango_dcache_fd_dcache_h
#define HEADER_fd_src_tango_dcache_fd_dcache_h

#include "../fd_tango_base.h"

/* FD_DCACHE_{ALIGN,FOOTPRINT} specify the alignment and footprint
   needed for a dcache with a data region of data_sz bytes and an
   application region of app_sz bytes.  ALIGN is at least FD_CHUNK_ALIGN
   and recommended to be at least double cache line to mitigate various
   kinds of false sharing.  data_sz and app_sz are assumed to be valid
   (e.g. will not require a footprint larger than ULONG_MAX).  These are
   provided to facilitate compile time dcache declarations. */

#define FD_DCACHE_ALIGN (128UL)
#define FD_DCACHE_FOOTPRINT( data_sz, app_sz )                                                            \
  FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT, \
    FD_DCACHE_ALIGN, 128UL                     ), /* hdr   */                                             \
    FD_DCACHE_ALIGN, FD_DCACHE_GUARD_FOOTPRINT ), /* guard */                                             \
    FD_DCACHE_ALIGN, (data_sz)                 ), /* data  */                                             \
    FD_DCACHE_ALIGN, (app_sz)                  ), /* app   */                                             \
    FD_DCACHE_ALIGN )

/* FD_DCACHE_GUARD_FOOTPRINT specify the footprint of the guard region
   immediately before the dcache data region.  The guard region
   footprint is FD_DCACHE_ALIGN aligned and a FD_DCACHE_ALIGN multiple.
   It provides flexibility (up to the magnitude of the footprint) to
   align how a producer might write directly into a dcache such that the
   frag payload alignment a consumer sees is consistent regardless of
   the details of the underlying producer. */

#define FD_DCACHE_GUARD_FOOTPRINT (128UL)

/* FD_DCACHE_SLOT_FOOTPRINT returns the footprint of a FD_DCACHE_ALIGN
   aligned slot sufficient to hold a frag payload of up to mtu bytes.
   Returns 0 if mtu is not valid (i.e. so large that the required slot
   size is larger than ULONG_MAX). */

#define FD_DCACHE_SLOT_FOOTPRINT( mtu ) FD_ULONG_ALIGN_UP( (mtu), FD_DCACHE_ALIGN )

/* FD_DCACHE_REQ_DATA_SZ returns the size of a data region in bytes
   sufficient for a dcache whose producer writes frag payloads up to mtu
   (should be positive) bytes in size, that can have up to depth (should
   be positive) frag payloads visible to consumers while the producer
   can be concurrently preparing up to burst (should be positive) frag
   payloads.  Assumes mtu, depth, burst and compact are valid and
   payload footprints are rounded up to at most a FD_DCACHE_ALIGN
   multiple when written by a producer.  Note that payloads written by a
   producer will generally be at least FD_DCACHE_ALIGN aligned to
   facilitate interoperability with fd_frag_meta_t chunk indexing.  Also
   note that for a compactly stored ring, it is usually not useful to
   use a burst larger than 1 (but not particularly harmful outside
   resulting a data region larger than necessary ... might use it to
   quasi-batch publish frags). */

#define FD_DCACHE_REQ_DATA_SZ( mtu, depth, burst, compact ) (FD_DCACHE_SLOT_FOOTPRINT( mtu )*((depth)+(burst)+(ulong)!!(compact)))

FD_PROTOTYPES_BEGIN

/* Construction API */

/* fd_dcache_req_data_sz is the same as FD_DCACHE_REQ_DATA_SZ but does
   not assume valid arguments.  Returns sz on success or 0 on failure.
   Reasons for failure include zero mtu, too large mtu, zero depth, zero
   burst or the required data_sz would be larger than ULONG_MAX. */

FD_FN_CONST ulong
fd_dcache_req_data_sz( ulong mtu,
                       ulong depth,
                       ulong burst,
                       int   compact );

/* fd_dcache_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as dcache with a data
   region of data_sz bytes and an application region of app_sz bytes.
   align returns FD_DCACHE_ALIGN.  If data_sz or app_sz are invalid
   (e.g. the required footprint is larger than a ULONG_MAX), footprint
   will silently return 0 (and thus can be used by the caller to
   validate dcache configuration parameters).  Zero is valid for data_sz
   and/or app_sz. */

FD_FN_CONST ulong
fd_dcache_align( void );

FD_FN_CONST ulong
fd_dcache_footprint( ulong data_sz,
                     ulong app_sz );

/* fd_dcache_new formats an unused memory region for use as a dcache.
   shmem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment.  The size of the dcache
   data size region is data_sz bytes and the size of the application
   region is app_sz bytes.  Zero is valid for data_sz and/or app_sz.

   Returns shmem (and the memory region it points to will be formatted
   as a dcache with the data and application regions initialized to
   zero, caller is not joined) on success and NULL on failure (logs
   details).  Reasons for failure include obviously bad shmem, bad
   data_sz or bad app_sz. */

void *
fd_dcache_new( void * shmem,
               ulong  data_sz,
               ulong  app_sz );

/* fd_dcache_join joins the caller to the dcache.  shdcache points to
   the first byte of the memory region backing the dcache in the
   caller's address space.

   Returns a pointer in the local address space to the dcache's data
   region on success (IMPORTANT! THIS IS NOT JUST A CAST OF SHDCACHE)
   and NULL on failure (logs details).  Reasons for failure are that
   shdcache is obviously not a pointer to memory region holding a
   dcache.  Every successful join should have a matching leave.  The
   lifetime of the join is until the matching leave or the thread group
   is terminated.

   This region will have a guard region of FD_DCACHE_GUARD_FOOTPRINT
   just before it and data_sz bytes available after it. */

uchar *
fd_dcache_join( void * shdcache );

/* fd_dcache_leave leaves a current local join.  Returns a pointer to
   the underlying shared memory region on success (IMPORTANT!  THIS IS
   NOT JUST A CAST OF DCACHE) and NULL on failure (logs details).
   Reasons for failure include dcache is NULL. */

void *
fd_dcache_leave( uchar const * dcache );

/* fd_dcache_delete unformats a memory region used as a dcache.  Assumes
   nobody is joined to the region.  Returns a pointer to the underlying
   shared memory region or NULL if used obviously in error (e.g.
   shdcache is obviously not a dcache ...  logs details).  The ownership
   of the memory region is transferred to the caller. */

void *
fd_dcache_delete( void * shdcache );

/* Accessor API */

/* fd_dcache_{data_sz,app_sz} return the sizes of the {data,app}
   regions.  Assumes dcache is a current local join. */

FD_FN_PURE ulong fd_dcache_data_sz( uchar const * dcache );
FD_FN_PURE ulong fd_dcache_app_sz ( uchar const * dcache );

/* fd_dcache_app_laddr returns location in the caller's local address
   space of memory set aside for application specific usage.  Assumes
   dcache is a current local join.  The lifetime of the returned pointer
   is the same as the underlying join.  This region has FD_DCACHE_ALIGN
   alignment (double cache line) and is fd_cache_app_sz( dcache ) in
   size.  laddr_const is a const-correct version. */

FD_FN_PURE uchar const * fd_dcache_app_laddr_const( uchar const * dcache );
FD_FN_PURE uchar *       fd_dcache_app_laddr      ( uchar *       dcache );

/* fd_dcache_compact_is_safe return whether the dcache can safely store
   frags in compactly quasi ring like as described in
   fd_dcache_chunk_next below.

   Chunks are indexed relative to base (e.g. the wksp containing the
   dcache to facilitate multiple dcaches written by multiple producers
   concurrently in the same wksp using a common chunk indexing scheme at
   consumers ... base==dcache is fine and implies chunks in this dcache
   region will be indexed starting from zero).

   base and dcache should be double chunk aligned, dcache should be
   current local join, base and dcache should be relatively spaced
   identically between different thread groups that might use the chunk
   indices and sufficiently close in the local address space that the
   all data region chunk addresses can be losslessly compressed and
   shared via a 32-bit fd_frag_meta_t chunk field.

   mtu is the maximum frag that a producer might write into this dcache.
   It is assumed that the producer will round up the footprint of frags
   into the dcache into double chunk aligned boundaries.

   depth is the maximum number of frags that might be concurrently
   accessing frags in this dcache.

   Returns 1 if the dcache is safe and 0 if not (with details logged). */

int
fd_dcache_compact_is_safe( void const * base,
                           void const * dcache,
                           ulong        mtu,
                           ulong        depth );

/* fd_dcache_compact_{chunk0,chunk1,wmark} returns the range of chunk indices
   [chunk0,chunk1) that relative to the base address covered by the
   dcache's data region and watermark chunk index for use by
   fd_dcache_compact_chunk_next below.
   0<=chunk0<=wmark<=chunk1<=UINT_MAX.  These assume dcache is current
   local join and the base / dcache pass fd_dcache_is_compact_safe
   above. */

FD_FN_CONST static inline ulong
fd_dcache_compact_chunk0( void const * base,
                          void const * dcache ) {
  return ((ulong)dcache - (ulong)base) >> FD_CHUNK_LG_SZ;
}

FD_FN_PURE static inline ulong
fd_dcache_compact_chunk1( void const * base,
                          void const * dcache ) {
  return ((ulong)dcache + fd_dcache_data_sz( (uchar const *)dcache ) - (ulong)base) >> FD_CHUNK_LG_SZ;
}

FD_FN_PURE static inline ulong
fd_dcache_compact_wmark( void const * base,
                         void const * dcache,
                         ulong        mtu ) {
  ulong chunk_mtu = ((mtu + 2UL*FD_CHUNK_SZ-1UL) >> (1+FD_CHUNK_LG_SZ)) << 1;
  return fd_dcache_compact_chunk1( base, dcache ) - chunk_mtu;
}

/* fd_dcache_compact_chunk_next:

   Let a dcache have space for at least chunk_mtu*(depth+2)-1 chunks
   where chunks are indexed [chunk0,chunk1) and chunk_mtu is a
   sufficient number of chunks to hold the worst case frag size.
   Further, let the dcache's producer write frags into the dcache at
   chunk aligned positions with a footprint of at most chunk_mtu chunks
   (with one exception noted below).  Lastly, let the producer write
   frags contiguously into the dcache such that consumers do not need to
   do any special handling for frags that wrap around the end of the
   dcache.

   Since the producer does not necessarily know the size of a frag as it
   is producing it but does know a priori the maximum size of a frag it
   might produce, the producer can achieve this by making the first
   chunk of any frag it writes in:

     [chunk0,wmark]

   where:

     wmark = chunk1 - chunk_mtu

   This is equivalent to saying that, if there are at least chunk_mtu
   chunks until the end of a dcache after a frag, that frag's footprint
   will be enough contiguous chunks to cover the frag (up to chunk_mtu).
   But if there there are less than chunk_mtu chunks, that frag's
   footprint will be until the end of the dcache.

   This implies, in the worst case, there at least depth+1 chunk_mtu
   footprint frags (those not near the end) and 1 frag with a
   2*chunk_mtu-1 footprint (the one frag nearest the dcache end) in the
   dcache.  depth of these are exposed to consumers and 1 in preparation
   by the producer.  It also implies that the set of chunks in the
   dcache in use is cyclically contiguous starting from the oldest
   consumer exposed frag until the currently exposed frag.

   Noting that the act of publishing in the in preparation frag also
   unpublishes the oldest exposed frag.  Given the above, this
   guarantees that there is at least chunk_mtu contiguous space
   available for use by the next frag so long as chunk_mtu is large
   enough to cover the worst case frag and the dcache has room at least
   for chunk_mtu*(depth+2)-1 chunks. */

FD_FN_CONST static inline ulong         /* Will be in [chunk0,wmark] */
fd_dcache_compact_next( ulong chunk,    /* Assumed in [chunk0,wmark] */
                        ulong sz,       /* Assumed in [0,mtu] */
                        ulong chunk0,   /* From fd_dcache_compact_chunk0 */
                        ulong wmark ) { /* From fd_dcache_compact_wmark */
  chunk += ((sz+(2UL*FD_CHUNK_SZ-1UL)) >> (1+FD_CHUNK_LG_SZ)) << 1; /* Advance to next chunk pair, no overflow if init passed */
  return fd_ulong_if( chunk>wmark, chunk0, chunk );                 /* If that goes over the high water mark, wrap to zero */
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_tango_dcache_fd_dcache_h */

