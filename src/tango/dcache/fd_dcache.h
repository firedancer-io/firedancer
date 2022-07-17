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
#define FD_DCACHE_FOOTPRINT( data_sz, app_sz )                                 \
  ( 128UL                                                        /* hdr   */ + \
    128UL                                                        /* guard */ + \
    (((data_sz)+FD_DCACHE_ALIGN-1UL) & (~(FD_DCACHE_ALIGN-1UL))) /* data  */ + \
    (((app_sz) +FD_DCACHE_ALIGN-1UL) & (~(FD_DCACHE_ALIGN-1UL))) /* app   */ )

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

#define FD_DCACHE_SLOT_FOOTPRINT( mtu ) (((mtu)+FD_DCACHE_ALIGN-1UL) & (~(FD_DCACHE_ALIGN-1UL)))

/* FD_DCACHE_REQ_DATA_SZ returns the size of a data region in bytes
   sufficient for a dcache whose producer writes frag payloads up to mtu
   (should be positive) bytes in size, that can have up to depth (should
   be positive) frag payloads visible to consumers while the producer
   can be concurrently preparing up to burst (should be positive) frag
   payloads.  Assumes mtu, depth, burst and compact are valid and
   payload footprints are rounded up to at most a FD_DCACHE_ALIGN
   multiple when written by a producer.  (Note that payloads written by
   a producer will generally be at least FD_DCACHE_ALIGN aligned to
   facilitate interoperability with fd_frag_meta_t chunk indexing.) */

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
   zero) on success and NULL on failure (logs details).  Reasons for
   failure include obviously bad shmem, bad data_sz or bad app_sz. */

void *
fd_dcache_new( void * shmem,
               ulong  data_sz,
               ulong  app_sz );

/* fd_dcache_join joins the caller to the dcache.  shdcache points to
   the first byte of the memory region backing the dcache in the
   caller's addresss space.

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

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_tango_dcache_fd_dcache_h */

