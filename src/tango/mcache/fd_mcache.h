#ifndef HEADER_fd_src_tango_mcache_fd_mcache_h
#define HEADER_fd_src_tango_mcache_fd_mcache_h

#include "../fd_tango_base.h"

/* FD_MCACHE_{ALIGN,FOOTPRINT} specify the alignment and footprint
   needed for a mcache with depth entries and an application region of
   size app_sz.  ALIGN is at least FD_FRAG_META_ALIGN and recommended to
   be at least double cache line to mitigate various kinds of false
   sharing.  depth and app_sz are assumed to be valid (i.e. depth is an
   integer power of 2 of at least FD_MCACHE_BLOCK and the combination
   will not require a footprint larger than ULONG_MAX).  These are
   provided to facilitate compile time mcache declarations. */

#define FD_MCACHE_ALIGN (128UL)
#define FD_MCACHE_FOOTPRINT( depth, app_sz )                                                              \
  FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT, \
    FD_MCACHE_ALIGN, 128UL                           ), /* hdr  */                                        \
    FD_MCACHE_ALIGN, FD_MCACHE_SEQ_CNT*sizeof(ulong) ), /* seq  */                                        \
    FD_MCACHE_ALIGN, (depth)*sizeof(fd_frag_meta_t)  ), /* meta */                                        \
    FD_MCACHE_ALIGN, (app_sz)                        ), /* app  */                                        \
    FD_MCACHE_ALIGN )

/* FD_MCACHE_SEQ_CNT specifies the number of entries in the mcache's seq
   storage region.  It is aligned FD_MCACHE_ALIGN.  Multiples of 16 have
   good Feng Shui.  seq[0] has special meaning; see below for details. */

#define FD_MCACHE_SEQ_CNT (16UL)

/* FD_MCACHE_{LG_BLOCK,LG_INTERLEAVE,BLOCK} specifies how recent
   fragment meta data should be packed into mcaches.  LG_BLOCK should be
   in [1,64).  LG_INTERLEAVE should be in [0,FD_MCACHE_BLOCK).  BLOCK ==
   2^LG_BLOCK.  See below for more details. */

#define FD_MCACHE_LG_BLOCK      (7)
#define FD_MCACHE_LG_INTERLEAVE (0)
#define FD_MCACHE_BLOCK         (128UL) /* == 2^FD_MCACHE_LG_BLOCK, explicit to workaround compiler limitations */

FD_PROTOTYPES_BEGIN

/* Construction API */

/* fd_mcache_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as mcache with depth
   entries.  align returns FD_MCACHE_ALIGN.  If depth is invalid (e.g.
   not an integer power-of-2 >= FD_MCACHE_BLOCK or the footprint is
   larger than ULONG_MAX), footprint will silently return 0 (and thus
   can be used by the caller to validate mcache configuration
   parameters). */

FD_FN_CONST ulong
fd_mcache_align( void );

FD_FN_CONST ulong
fd_mcache_footprint( ulong depth,
                     ulong app_sz );

/* fd_mcache_new formats an unused memory region for use as a mcache.
   shmem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment.  depth is the number of
   cache entries (should be an integer power of 2 >= FD_MCACHE_BLOCK).
   The mcache will also have an app_sz byte application region for
   application specific usage.  seq0 is the initial fragment sequence
   number a producer should use for this mcache.

   The cache entries will be initialized such all queries for any
   sequence number will fail immediately after creation.  They will
   further be initialized such that for any consumer initialized to
   start receiving a sequence number at or after seq0 will think it is
   ahead of the producer (such that it will wait for its sequence number
   cleanly instead of immediately trying to recover a gap).  Conversely,
   consumers initialized to start receiving a sequence number before
   seq0 will think they are behind the producer (thus realize it is been
   incorrectly initialized and can recover appropriately).  Anybody who
   looks at the mcache entries directly will also see the entries are
   initialized to have zero sz (such that they shouldn't try deference
   any fragment payloads), have the SOM and EOM bits set (so they
   shouldn't try to interpret the entry as part of some message spread
   over multiple fragments) and have the ERR bit set (so they don't
   think there is any validity to the meta data or payload).

   The application region will be initialized to zero.

   Returns shmem (and the memory region it points to will be formatted
   as a mcache, caller is not joined) on success and NULL on failure
   (logs details).  Reasons for failure include obviously bad shmem or
   bad depth. */

void *
fd_mcache_new( void * shmem,
               ulong  depth,
               ulong  app_sz,
               ulong  seq0 );

/* fd_mcache_join joins the caller to the mcache.  shmcache points to
   the first byte of the memory region backing the mcache in the
   caller's address space.

   Returns a pointer in the local address space to the mcache's entries
   on success (IMPORTANT! THIS IS NOT JUST A CAST OF SHMCACHE) and NULL
   on failure (logs details).  Reasons for failure are that shmcache is
   obviously not a pointer to memory region holding a mcache.  Every
   successful join should have a matching leave.  The lifetime of the
   join is until the matching leave or thread group is terminated.

   Entries are indexed [0,depth) and the mapping from sequence number to
   depth is nontrivial (see below for accessors and mapping functions).
   There is no restrictions on the number of joins overall and a single
   thread can join multiple times (all joins to the same shmcache laddr
   will return same mcache laddr). */

fd_frag_meta_t *
fd_mcache_join( void * shmcache );

/* fd_mcache_leave leaves a current local join.  Returns a pointer to
   the underlying shared memory region on success (IMPORTANT!  THIS IS
   NOT JUST A CAST OF MCACHE) and NULL on failure (logs details).
   Reasons for failure include mcache is NULL. */

void *
fd_mcache_leave( fd_frag_meta_t const * mcache );

/* fd_mcache_delete unformats a memory region used as a mcache.  Assumes
   nobody is joined to the region.  Returns a pointer to the underlying
   shared memory region or NULL if used obviously in error (e.g.
   shmcache is obviously not a mcache ...  logs details).  The ownership
   of the memory region is transferred to the caller. */

void *
fd_mcache_delete( void * shmcache );

/* Accessor API */

/* fd_mcache_{depth,seq0} return the values corresponding to those use
   at the mcache's construction.  Assume mcache is a current local join. */

FD_FN_PURE ulong fd_mcache_depth ( fd_frag_meta_t const * mcache );
FD_FN_PURE ulong fd_mcache_app_sz( fd_frag_meta_t const * mcache );
FD_FN_PURE ulong fd_mcache_seq0  ( fd_frag_meta_t const * mcache );

/* fd_mcache_seq_laddr returns location in the caller's local address
   space of mcache's sequence array.  This array is indexed
   [0,FD_MCACHE_SEQ_CNT) with FD_MCACHE_ALIGN alignment (double cache
   line).  laddr_const is a const correct version.  Assumes mcache is a
   current local join.  The lifetime of the returned pointer is the same
   as the underlying join.

   seq[0] has special meaning.  Specifically, sequence numbers in
   [seq0,seq[0]) cyclic are guaranteed to have been published.  seq[0]
   is not strictly atomically updated by the producer when it publishes
   so seq[0] can lag the most recently published sequence number
   somewhat.  As seq[0] is moderately to aggressively frequently updated
   by the mcache's producer (depending on the application), this is on
   its own cache line pair to avoid false sharing.  seq[0] is mostly
   used for monitoring, initialization and support for some methods for
   unreliable consumer overrun handling.

   The meaning of the remaining sequence numbers is application
   dependent.  Application should try to restrict any use of these to
   ones that are seq[0] cache-friendly (e.g. use for producer write
   oriented cases or use for rarely used cases). */

FD_FN_CONST ulong const * fd_mcache_seq_laddr_const( fd_frag_meta_t const * mcache );
FD_FN_CONST ulong *       fd_mcache_seq_laddr      ( fd_frag_meta_t *       mcache );

/* fd_mcache_app_laddr returns location in the caller's local address
   space of memory set aside for application specific usage.  Assumes
   mcache is a current local join.  The lifetime of the returned pointer
   is the same as the underlying join.  This region has FD_MCACHE_ALIGN
   alignment (double cache line) and is fd_mcache_app_sz( mcache ) in
   size.  laddr_const is a const-correct version. */

FD_FN_PURE uchar const * fd_mcache_app_laddr_const( fd_frag_meta_t const * mcache );
FD_FN_PURE uchar *       fd_mcache_app_laddr      ( fd_frag_meta_t *       mcache );

/* fd_mcache_seq_query atomically reads the mcache's seq[0] (e.g. from
   fd_mcache_seq_laddr_const) to get a lower bound of where the producer
   is at in sequence space (in the sense that the producer guarantees it
   has produced all sequence numbers strictly before the return value
   cyclic).  This is usually done at consumer startup and, for some
   unreliable consumer overrun handling, during consumer overrun
   recovery.  It is strongly recommended for consumers to avoid using
   this as much as possible to limit cache line ping-ponging with the
   producer. */

static inline ulong
fd_mcache_seq_query( ulong const * _seq ) {
  FD_COMPILER_MFENCE();
  ulong seq = FD_VOLATILE_CONST( *_seq );
  FD_COMPILER_MFENCE();
  return seq;
}

/* fd_mcache_seq_update updates the mcache's seq[0] (e.g. from
   fd_mcache_seq_laddr) above where the producer a lower bound of where
   the producer is currently at (in the sense that the producer has
   produced all sequence numbers strictly before seq cyclic).  This
   should be monotonically non-decreasing.  This should be done
   moderately frequently (e.g. in background housekeeping) after the
   producer has moved forward in sequence space since the last update.
   Even more aggressively is usually fine.  This should also be done
   when the producer is shutdown to facilitate cleanly restarting a
   producer and what not.  This also serves as a compiler memory fence
   to ensure the sequence number is updated at a well defined point in
   the instruction stream (e.g. so that compiler doesn't move any stores
   from before the update to after the above). */

static inline void
fd_mcache_seq_update( ulong * _seq,
                      ulong   seq ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *_seq ) = seq;
  FD_COMPILER_MFENCE();
}

/* fd_mcache_line_idx returns the index of the cache line in a depth
   entry mcache (depth is assumed to be a power of 2) where the
   metadata for the frag with sequence number seq will be stored when it
   is in cache.  Outside of startup transients, a mcache is guaranteed
   to exactly hold the depth most recently sequence numbers (the act of
   publishing a new sequence number atomically unpublishes the oldest
   sequence number implicitly).

   FD_MCACHE_LG_INTERLEAVE is in [0,FD_MCACHE_LG_BLOCK) and controls the
   details of this mapping.  LG_INTERLEAVE 0 indicates no interleaving.
   Values from 1 to LG_BLOCK space out sequential frag meta data in
   memory to avoid false sharing between producers and fast consumers to
   keep fast consumers low latency while keeping frag meta data storage
   compact in memory to help throughput of slow consumers.

   Specifically, at a LG_INTERLEAVE of i with s byte frag meta data,
   meta data storage for sequential frags is typically s*2^i bytes
   apart.  To avoid wasting memory and bandwidth, the interleaving is
   implemented by doing a rotation of the least LG_BLOCK bits of the lg
   depth bits of the sequence number (NOTE: this imposes a requirement
   that mcaches have at least a depth of 2^LG_BLOCK fragments).  This
   yields a frag sequence number to line idx mapping that avoids false
   sharing for fast consumers and maintains compactness, avoids TLB
   thrashing (even if meta data is backed by normal pages) and exploits
   CPU data and TLB prefetching behavior for slow consumers.

   How useful block interleaving is somewhat application dependent.
   Different values have different trade offs between optimizing for
   fast and slow consumers and for different sizes of meta data and
   different page size backing memory.

   Using 0 / B for FD_MCACHE_LG_INTERLEAVE / LG_BLOCK will disable meta
   data interleaving while still requiring mcaches be at least 2^B in
   size.  This implicitly optimizes for slow consumers.  Something like
   2 / 7 (with a 32-byte size 32-byte aligned fd_frag_meta_t and a
   mcache that is at least normal page aligned) will access cached meta
   data in sequential blocks of 128 message fragments that are normal
   page size and aligned while meta data within those blocks will
   typically be strided at double DRAM cache line granularity.  As such,
   fast consumers (e.g. those within 32 of the producers) will rarely
   have false sharing with the producers as nearby sequence numbers are
   on different DRAM cache line pairs.  And slow consumers (e.g. ones
   that fall more than 128 fragments behind) will access meta data in a
   very DRAM cache friendly / data prefetcher / TLB friendly / bandwidth
   efficient manner (and without needing to load any prefilterable
   payload data while completely avoiding memory being written by the
   producer).  That is, it typically has good balance of performance for
   both fast and slow consumers simultaneously. */

#if FD_MCACHE_LG_INTERLEAVE==0

FD_FN_CONST static inline ulong /* Will be in [0,depth) */
fd_mcache_line_idx( ulong seq,
                    ulong depth ) { /* Assumed power of 2 >= BLOCK */
  return seq & (depth-1UL);
}

#else

FD_FN_CONST static inline ulong /* Will be in [0,depth) */
fd_mcache_line_idx( ulong seq,
                    ulong depth ) { /* Assumed power of 2 >= BLOCK */
  ulong block_mask = FD_MCACHE_BLOCK - 1UL; /* Compile time */
  ulong page_mask  = (depth-1UL) & (~block_mask);    /* Typically compile time or loop invariant */
  ulong page = seq & page_mask;
  ulong bank = (seq << FD_MCACHE_LG_INTERLEAVE) & block_mask;
  ulong idx  = (seq & block_mask) >> (FD_MCACHE_LG_BLOCK-FD_MCACHE_LG_INTERLEAVE);
  return page | bank | idx;
}

#endif

/* fd_mcache_publish inserts the metadata for frag seq into the given
   depth entry mcache in a way compatible with FD_MCACHE_WAIT and
   FD_MCACHE_WAIT_SSE (but not FD_MCACHE_WAIT_AVX ... see FD_MCACHE_WAIT
   for more details).  This implicitly evicts the metadata for the
   sequence number currently stored at fd_mcache_line_idx( seq, depth ).
   In the typical case where sequence numbers are published into the
   mcache sequentially, the evicted metadata is typically for frag
   seq-depth (cyclic).  This does no error checking or the like as it is
   frequently used in ultra high performance contexts.  This operation
   implies a compiler mfence to the caller. */

static inline void
fd_mcache_publish( fd_frag_meta_t * mcache,   /* Assumed a current local join */
                   ulong            depth,    /* Assumed an integer power-of-2 >= BLOCK */
                   ulong            seq,
                   ulong            sig,
                   ulong            chunk,    /* Assumed in [0,UINT_MAX] */
                   ulong            sz,       /* Assumed in [0,USHORT_MAX] */
                   ulong            ctl,      /* Assumed in [0,USHORT_MAX] */
                   ulong            tsorig,   /* Assumed in [0,UINT_MAX] */
                   ulong            tspub ) { /* Assumed in [0,UINT_MAX] */
  fd_frag_meta_t * meta = mcache + fd_mcache_line_idx( seq, depth );
  FD_COMPILER_MFENCE();
  meta->seq    = fd_seq_dec( seq, 1UL );
  FD_COMPILER_MFENCE();
  meta->sig    =         sig;
  meta->chunk  = (uint  )chunk;
  meta->sz     = (ushort)sz;
  meta->ctl    = (ushort)ctl;
  meta->tsorig = (uint  )tsorig;
  meta->tspub  = (uint  )tspub;
  FD_COMPILER_MFENCE();
  meta->seq    = seq;
  FD_COMPILER_MFENCE();
}

#if FD_HAS_SSE

/* fd_mcache_publish_sse is a SSE implementation of fd_mcache_publish.
   It is compatible with FD_MCACHE_WAIT and FD_MCACHE_WAIT_SSE. */

static inline void
fd_mcache_publish_sse( fd_frag_meta_t * mcache,   /* Assumed a current local join */
                       ulong            depth,    /* Assumed an integer power-of-2 >= BLOCK */
                       ulong            seq,
                       ulong            sig,
                       ulong            chunk,    /* Assumed in [0,UINT_MAX] */
                       ulong            sz,       /* Assumed in [0,USHORT_MAX] */
                       ulong            ctl,      /* Assumed in [0,USHORT_MAX] */
                       ulong            tsorig,   /* Assumed in [0,UINT_MAX] */
                       ulong            tspub ) { /* Assumed in [0,UINT_MAX] */
  fd_frag_meta_t * meta = mcache + fd_mcache_line_idx( seq, depth );
  __m128i meta_sse0 = fd_frag_meta_sse0( fd_seq_dec( seq, 1UL ), sig );
  __m128i meta_sse1 = fd_frag_meta_sse1( chunk, sz, ctl, tsorig, tspub );
  FD_COMPILER_MFENCE();
  _mm_store_si128( &meta->sse0, meta_sse0 );
  FD_COMPILER_MFENCE();
  _mm_store_si128( &meta->sse1, meta_sse1 );
  FD_COMPILER_MFENCE();
  meta->seq = seq;
  FD_COMPILER_MFENCE();
}

#endif

#if FD_HAS_AVX

/* fd_mcache_publish_avx is an AVX implementation of fd_mcache_publish.
   It is compatible with FD_MCACHE_WAIT, FD_MCACHE_WAIT_SSE and
   FD_MCACHE_WAIT_AVX.  It requires a target for which aligned AVX
   stores are guaranteed atomic under the hood (see below for more
   details). */

static inline void
fd_mcache_publish_avx( fd_frag_meta_t * mcache,   /* Assumed a current local join */
                       ulong            depth,    /* Assumed an integer power-of-2 >= BLOCK */
                       ulong            seq,
                       ulong            sig,
                       ulong            chunk,    /* Assumed in [0,UINT_MAX] */
                       ulong            sz,       /* Assumed in [0,USHORT_MAX] */
                       ulong            ctl,      /* Assumed in [0,USHORT_MAX] */
                       ulong            tsorig,   /* Assumed in [0,UINT_MAX] */
                       ulong            tspub ) { /* Assumed in [0,UINT_MAX] */
  fd_frag_meta_t * meta = mcache + fd_mcache_line_idx( seq, depth );
  __m256i meta_avx = fd_frag_meta_avx( seq, sig, chunk, sz, ctl, tsorig, tspub );
  FD_COMPILER_MFENCE();
  _mm256_store_si256( &meta->avx, meta_avx );
  FD_COMPILER_MFENCE();
}

#endif

/* FD_MCACHE_WAIT does a bounded wait for a producer to transmit a
   particular frag.

   meta (fd_frag_meta_t * compatible) is the location on the caller
   where the wait should save the found metadata.  This typically
   points to a stack temporary.

   mline (fd_frag_meta_t const * compatible) will be
     mcache + fd_mcache_line_idx( seq_expected, depth )
   when the wait does not time out.  This is the location where the
   caller can verify (after any speculative processing of seq_expected)
   the producer did not clobber the consumer during the processing.

   seq_found (ulong compatible) will be the sequence number found at
   mline when the wait does not time out.  This will be seq_expected
   on a successful wait.

   seq_diff (long compatible) will be how many sequence numbers ahead
   of seq_expected when the wait does not time out
     fd_seq_diff( seq_found, seq_expected )
   This will be zero on a successful wait.  This will be positive
   otherwise and a lower bound of how far behind the consumer is from
   the producer (and seq_found will typically be a reasonably recently
   produced sequence number).

   poll_max (ulong compatible) is the number of times FD_MCACHE_WAIT
   will poll the mcache of the given depth for seq_expected before
   timing out.  poll_max should be positive on input.  (Note: using
   ULONG_MAX for poll_max practically turns this into a blocking wait as
   this take hundreds of years to complete on realistic platforms.)
   If poll max is zero on completion of the, the wait timed out.

   mcache (fd_frag_meta_t const * compatible) is a current local join to
   the mcache the producer uses to cache metadata for the frags it is
   producing.

   depth (a ulong compatible power of two of at least FD_MCACHE_BLOCK)
   is the number of entries in mcache.

   seq_expected (ulong compatible) is the sequence number to wait to be
   produced.

   On completion of the WAIT, if poll_max is zero, the WAIT timed out
   and none of the other outputs (meta, mline, seq_found, seq_diff)
   should be trusted.  If poll_max is non-zero, it will be the original
   poll_max value decremented by the number of polls it took for the
   WAIT to complete and the WAIT did not timeout.

   When the WAIT did not timeout, mline, seq_found and seq_diff can be
   trusted.  If seq_diff is positive, the caller has fallen more than
   depth behind the producer such that metadata for frag seq_expected is
   no longer available via the mcache.  IMPORTANT!  *META MIGHT NOT BE
   VALID FOR SEQ_FOUND WHEN CONSUMER HAS FALLEN BEHIND (e.g. if the
   producer is paused after it starts writing metadata but before it has
   completed writing it ... an unreliable overrun consumer that reads
   the metadata while the producer is paused will observe metadata that
   is a mix of the new metadata and old metadata with a bogus sequence
   number on it).  seq_diff is a lower bound of how far the caller has
   fallen behind the producer and seq_found is a lower bound of where
   producer is currently at.

   Otherwise, the caller is within depth of the producer and *meta will
   be a local copy of the desired metadata.

   TL;DR  Typical usage:

     ... Example HPC receiver run loop setup

     ulong                  poll_max = ... number of polls until next housekeeping (positive)
     fd_frag_meta_t const * mcache   = ... local join to producer's mcache
     ulong                  depth    = ... producer's mcache depth
     ulong                  rx_seq   = ... next sequence number to receive from producer

     ... Example HPC receiver run loop structure

     for(;;) {

       fd_frag_meta_t         meta[1];
       fd_frag_meta_t const * mline;
       ulong                  tx_seq;
       long                   seq_diff;
       FD_MCACHE_WAIT( meta, mline, tx_seq, seq_diff, poll_max, mcache, depth, rx_seq );

       ... At this point, poll_max can be trusted and has been
       ... decremented the number of polls that were done by the wait
       ... from its value at the start of the wait.  We either timed
       ... out waiting, detected we've been overrun or received the
       ... desired meta data.

       if( FD_UNLIKELY( !poll_max ) ) {

         ... We timed out.  Do background housekeeping.

         poll_max = ... Reload for the next housekeeping (positive and
                    ... ideally somewhat randomized each time).  Value
                    ... depends on how aggressively the run loop needs
                    ... to do background tasks such as
                    ... command-and-control interactions, monitoring
                    ... diagnostics, maintenance, etc).

         continue;
       }

       ... At this point, poll_max, mline, tx_seq and seq_diff can be
       ... trusted.  We either have been overrun or received the desired
       ... metadata.  poll_max>0 and seq_diff==fd_seq_diff(tx_seq,rx_seq).

       if( FD_UNLIKELY( seq_diff ) ) {

         ... We got overrun by the producer.  tx_seq is an estimate
         ... (typically within depth and often much closer) of where the
         ... producer currently is at.  Technically, this branch should
         ... never be exercised on reliable consumers but is a generally
         ... good idea regardless to detect / protect against flow
         ... control misconfigurations, bugs in the consumer, etc.
         ... Overrun handling could be as simple as "rx_seq = tx_seq;"
         ... here (but applications will typically do more elaborate
         ... application specific handling)

         continue;
       }

       ... We received meta data for frag rx_seq.  At this point, meta,
       ... tx_seq, seq_diff and poll_max can be trusted.  poll_max>=0UL,
       ... tx_seq==rx_seq and seq_diff==0L.

       ... Process meta->* at the run loop's leisure and speculatively
       ... process actual frag data as necessary here.

       tx_seq = fd_frag_meta_seq_query( mline );
       if( FD_UNLIKELY( fd_seq_ne( tx_seq, rx_seq ) ) ) {

         ... We got overrun by the producer while speculatively
         ... processing data pointed to by meta.  Same considerations
         ... as above for overrun handling.

         continue;
       }

       ... Advance to the producer's next sequence number.

       rx_seq = fd_seq_inc( rx_seq, 1UL );
     }

   This assumes the producer either writes the entire metadata cache
   line atomically (on targets where aligned AVX writes are in fact
   atomic) or writes the metadata cache line in a particular order:

     FD_COMPILER_MFENCE();
     mcache_line->seq = fd_seq_dec( seq, 1UL ); // atomically marks cache line as in the process of writing seq
                                                // This implicitly atomically evicts frag metadata for cache line
                                                // seq-depth cycle
     FD_COMPILER_MFENCE();
     ... update the actual cache line body without changing mcache_line->seq ...
     FD_COMPILER_MFENCE();
     mcache_line->seq = seq; // atomically marks metadata for frag seq as available for consumers
     FD_COMPILER_MFENCE();

   Note that above writes can be SSE accelerated on AVX platforms (where
   aligned SSE writes are guaranteed to be atomic) as:

     FD_COMPILER_MFENCE();
     _mm_store_si128( &mcache_line->sse0, fd_frag_meta_sse0( fd_seq_dec( seq, 1UL ), sig );
     FD_COMPILER_MFENCE();
     _mm_store_si128( &mcache_line->sse1, fd_frag_meta_sse1( chunk, sz, ctl, tsorig, tspub );
     FD_COMPILER_MFENCE();
     mcache_line->seq = seq;
     FD_COMPILER_MFENCE();

   Note that the above uses no expensive atomic operations or hardware
   memory fences under the hood as these are not required for x86-style
   cache coherency.  Specifically, Intel Architecture Software Developer
   Manual 3A-8-9:

     "Reads are not reordered with other reads."

   and 3A-8-10:

     "Writes by a single processor are observed in the same order by all
     processors."

   This makes heavy use of compiler memory fences though to insure that
   compiler optimizations do not reorder how the operations are issued
   to CPUs (and thus also imply the operation acts as a compiler memory
   fence overall).

   Non-x86 platforms that use different cache coherency models may
   require modification of the below to use more explicit fencing or
   what not.

   The below is implemented as a macro to facilitate use in ultra high
   performance run loops and support multiple return values.  This macro
   is robust (e.g. it evaluates its argument a minimal number of times). */

#define FD_MCACHE_WAIT( meta, mline, seq_found, seq_diff, poll_max, mcache, depth, seq_expected ) do {                    \
    ulong                  _fd_mcache_wait_seq_expected = (seq_expected);                                                 \
    fd_frag_meta_t const * _fd_mcache_wait_mline        = (mcache)                                                        \
                                                        + fd_mcache_line_idx( _fd_mcache_wait_seq_expected, (depth) );    \
    fd_frag_meta_t *       _fd_mcache_wait_meta         = (meta);                                                         \
    ulong                  _fd_mcache_wait_seq_found;                                                                     \
    long                   _fd_mcache_wait_seq_diff;                                                                      \
    ulong                  _fd_mcache_wait_poll_max     = (poll_max);                                                     \
    for(;;) {                                                                                                             \
      FD_COMPILER_MFENCE();                                                                                               \
      _fd_mcache_wait_seq_found = _fd_mcache_wait_mline->seq; /* atomic */                                                \
      FD_COMPILER_MFENCE();                                                                                               \
      *_fd_mcache_wait_meta = *_fd_mcache_wait_mline; /* probably non-atomic, typically fast L1 cache hit */              \
      FD_COMPILER_MFENCE();                                                                                               \
      ulong _fd_mcache_wait_seq_test = _fd_mcache_wait_mline->seq; /* atomic, typically fast L1 cache hit */              \
      FD_COMPILER_MFENCE();                                                                                               \
      _fd_mcache_wait_seq_diff = fd_seq_diff( _fd_mcache_wait_seq_found, _fd_mcache_wait_seq_expected );                  \
      int _fd_mcache_wait_done = ((_fd_mcache_wait_seq_found==_fd_mcache_wait_seq_test) & (_fd_mcache_wait_seq_diff>=0L)) \
                               | (!--_fd_mcache_wait_poll_max);                                                           \
      FD_COMPILER_FORGET( _fd_mcache_wait_done ); /* inhibit compiler from turning this into branch nest */               \
      if( FD_LIKELY( _fd_mcache_wait_done ) ) break; /* opt for exit, single exit to help spin_pause cpu hinting */       \
      FD_SPIN_PAUSE();                                                                                                    \
    }                                                                                                                     \
    (mline)     = _fd_mcache_wait_mline;                                                                                  \
    (seq_found) = _fd_mcache_wait_seq_found;                                                                              \
    (seq_diff)  = _fd_mcache_wait_seq_diff;                                                                               \
    (poll_max)  = _fd_mcache_wait_poll_max;                                                                               \
  } while(0)

/* FD_MCACHE_WAIT_REG: similar to FD_MCACHE_WAIT but uses (nominally)
   registers to hold the metadata instead of a local buffer. */

#define FD_MCACHE_WAIT_REG( sig, chunk, sz, ctl, tsorig, tspub, mline, seq_found, seq_diff, poll_max,                     \
                            mcache, depth, seq_expected ) do {                                                            \
    ulong                  _fd_mcache_wait_seq_expected = (seq_expected);                                                 \
    fd_frag_meta_t const * _fd_mcache_wait_mline        = (mcache)                                                        \
                                                        + fd_mcache_line_idx( _fd_mcache_wait_seq_expected, (depth) );    \
    ulong                  _fd_mcache_wait_poll_max     = (poll_max);                                                     \
    ulong                  _fd_mcache_wait_sig;                                                                           \
    ulong                  _fd_mcache_wait_chunk;                                                                         \
    ulong                  _fd_mcache_wait_sz;                                                                            \
    ulong                  _fd_mcache_wait_ctl;                                                                           \
    ulong                  _fd_mcache_wait_tsorig;                                                                        \
    ulong                  _fd_mcache_wait_tspub;                                                                         \
    ulong                  _fd_mcache_wait_seq_found;                                                                     \
    long                   _fd_mcache_wait_seq_diff;                                                                      \
    for(;;) {                                                                                                             \
      FD_COMPILER_MFENCE();                                                                                               \
      _fd_mcache_wait_seq_found = _fd_mcache_wait_mline->seq; /* atomic */                                                \
      FD_COMPILER_MFENCE();                                                                                               \
      _fd_mcache_wait_sig       =        _fd_mcache_wait_mline->sig;                                                      \
      _fd_mcache_wait_chunk     = (ulong)_fd_mcache_wait_mline->chunk;                                                    \
      _fd_mcache_wait_sz        = (ulong)_fd_mcache_wait_mline->sz;                                                       \
      _fd_mcache_wait_ctl       = (ulong)_fd_mcache_wait_mline->ctl;                                                      \
      _fd_mcache_wait_tsorig    = (ulong)_fd_mcache_wait_mline->tsorig;                                                   \
      _fd_mcache_wait_tspub     = (ulong)_fd_mcache_wait_mline->tspub;                                                    \
      FD_COMPILER_MFENCE();                                                                                               \
      ulong _fd_mcache_wait_seq_test = _fd_mcache_wait_mline->seq; /* atomic, typically fast L1 cache hit */              \
      FD_COMPILER_MFENCE();                                                                                               \
      _fd_mcache_wait_seq_diff = fd_seq_diff( _fd_mcache_wait_seq_found, _fd_mcache_wait_seq_expected );                  \
      int _fd_mcache_wait_done = ((_fd_mcache_wait_seq_found==_fd_mcache_wait_seq_test) & (_fd_mcache_wait_seq_diff>=0L)) \
                               | (!--_fd_mcache_wait_poll_max);                                                           \
      FD_COMPILER_FORGET( _fd_mcache_wait_done ); /* inhibit compiler from turning this into branch nest */               \
      if( FD_LIKELY( _fd_mcache_wait_done ) ) break; /* opt for exit, single exit to help spin_pause cpu hinting */       \
      FD_SPIN_PAUSE();                                                                                                    \
    }                                                                                                                     \
    (sig)       = _fd_mcache_wait_sig;                                                                                    \
    (chunk)     = _fd_mcache_wait_chunk;                                                                                  \
    (sz)        = _fd_mcache_wait_sz;                                                                                     \
    (ctl)       = _fd_mcache_wait_ctl;                                                                                    \
    (tsorig)    = _fd_mcache_wait_tsorig;                                                                                 \
    (tspub)     = _fd_mcache_wait_tspub;                                                                                  \
    (mline)     = _fd_mcache_wait_mline;                                                                                  \
    (seq_found) = _fd_mcache_wait_seq_found;                                                                              \
    (seq_diff)  = _fd_mcache_wait_seq_diff;                                                                               \
    (poll_max)  = _fd_mcache_wait_poll_max;                                                                               \
  } while(0)

#if FD_HAS_AVX

/* FD_MCACHE_WAIT_SSE: similar to FD_MCACHE_WAIT but uses a pair of SSE
   registers to hold the metadata instead of a local buffer.  This is
   only valid on targets with the FD_HAS_AVX capability (see
   fd_tango_base.h for details on Intel's atomicity guarantees). */

#define FD_MCACHE_WAIT_SSE( meta_sse0, meta_sse1, mline, seq_found, seq_diff, poll_max, mcache, depth, seq_expected ) do { \
    ulong                  _fd_mcache_wait_seq_expected = (seq_expected);                                                  \
    fd_frag_meta_t const * _fd_mcache_wait_mline        = (mcache)                                                         \
                                                        + fd_mcache_line_idx( _fd_mcache_wait_seq_expected, (depth) );     \
    __m128i                _fd_mcache_wait_meta_sse0;                                                                      \
    __m128i                _fd_mcache_wait_meta_sse1;                                                                      \
    ulong                  _fd_mcache_wait_seq_found;                                                                      \
    long                   _fd_mcache_wait_seq_diff;                                                                       \
    ulong                  _fd_mcache_wait_poll_max     = (poll_max);                                                      \
    for(;;) {                                                                                                              \
      FD_COMPILER_MFENCE();                                                                                                \
      _fd_mcache_wait_meta_sse0 = _mm_load_si128( &_fd_mcache_wait_mline->sse0 ); /* atomic */                             \
      FD_COMPILER_MFENCE();                                                                                                \
      _fd_mcache_wait_meta_sse1 = _mm_load_si128( &_fd_mcache_wait_mline->sse1 ); /* atomic, typ fast L1 hit */            \
      FD_COMPILER_MFENCE();                                                                                                \
      ulong _fd_mcache_wait_seq_test = _fd_mcache_wait_mline->seq; /* atomic, typically fast L1 cache hit */               \
      FD_COMPILER_MFENCE();                                                                                                \
      _fd_mcache_wait_seq_found = fd_frag_meta_sse0_seq( _fd_mcache_wait_meta_sse0 );                                      \
      _fd_mcache_wait_seq_diff  = fd_seq_diff( _fd_mcache_wait_seq_found, _fd_mcache_wait_seq_expected );                  \
      int _fd_mcache_wait_done  = ((_fd_mcache_wait_seq_found==_fd_mcache_wait_seq_test) & (_fd_mcache_wait_seq_diff>=0L)) \
                                | (!--_fd_mcache_wait_poll_max);                                                           \
      FD_COMPILER_FORGET( _fd_mcache_wait_done ); /* inhibit compiler from turning this into branch nest */                \
      if( FD_LIKELY( _fd_mcache_wait_done ) ) break; /* opt for exit, single exit to help spin_pause cpu hinting */        \
      FD_SPIN_PAUSE();                                                                                                     \
    }                                                                                                                      \
    (meta_sse0) = _fd_mcache_wait_meta_sse0;                                                                               \
    (meta_sse1) = _fd_mcache_wait_meta_sse1;                                                                               \
    (mline)     = _fd_mcache_wait_mline;                                                                                   \
    (seq_found) = _fd_mcache_wait_seq_found;                                                                               \
    (seq_diff)  = _fd_mcache_wait_seq_diff;                                                                                \
    (poll_max)  = _fd_mcache_wait_poll_max;                                                                                \
  } while(0)

/* FD_MCACHE_WAIT_AVX: similar to FD_MCACHE_WAIT_SSE but uses a single
   AVX register to hold the found metadata instead of a local buffer.
   This is only valid for targets that have atomic AVX load / stores
   (not guaranteed across all AVX supporting CPUs and Intel is
   deliberately vague about which ones do have it) and a producer that
   similarly uses atomic AVX writes for metadata publication.  On the
   overrun case here, meta_avx will in fact be the metadata for the
   overrun sequence number. */

#define FD_MCACHE_WAIT_AVX( meta_avx, mline, seq_found, seq_diff, poll_max, mcache, depth, seq_expected ) do {         \
    ulong                  _fd_mcache_wait_seq_expected = (seq_expected);                                              \
    fd_frag_meta_t const * _fd_mcache_wait_mline        = (mcache)                                                     \
                                                        + fd_mcache_line_idx( _fd_mcache_wait_seq_expected, (depth) ); \
    __m256i                _fd_mcache_wait_meta_avx;                                                                   \
    ulong                  _fd_mcache_wait_seq_found;                                                                  \
    long                   _fd_mcache_wait_seq_diff;                                                                   \
    ulong                  _fd_mcache_wait_poll_max     = (poll_max);                                                  \
    for(;;) {                                                                                                          \
      FD_COMPILER_MFENCE();                                                                                            \
      _fd_mcache_wait_meta_avx  = _mm256_load_si256( &_fd_mcache_wait_mline->avx ); /* atomic */                       \
      FD_COMPILER_MFENCE();                                                                                            \
      _fd_mcache_wait_seq_found = fd_frag_meta_avx_seq( _fd_mcache_wait_meta_avx );                                    \
      _fd_mcache_wait_seq_diff  = fd_seq_diff( _fd_mcache_wait_seq_found, _fd_mcache_wait_seq_expected );              \
      int _fd_mcache_wait_done  = (_fd_mcache_wait_seq_diff>=0L) | (!--_fd_mcache_wait_poll_max);                      \
      FD_COMPILER_FORGET( _fd_mcache_wait_done ); /* inhibit compiler from turning this into branch nest */            \
      if( FD_LIKELY( _fd_mcache_wait_done ) ) break; /* opt for exit, single exit to help spin_pause cpu hinting */    \
      FD_SPIN_PAUSE();                                                                                                 \
    }                                                                                                                  \
    (meta_avx)  = _fd_mcache_wait_meta_avx;                                                                            \
    (mline)     = _fd_mcache_wait_mline;                                                                               \
    (seq_found) = _fd_mcache_wait_seq_found;                                                                           \
    (seq_diff)  = _fd_mcache_wait_seq_diff;                                                                            \
    (poll_max)  = _fd_mcache_wait_poll_max;                                                                            \
  } while(0)

#endif

/* fd_mcache_query returns seq_query if seq_query is still in the mcache
   (assumed to be a current local mcache join) with depth entries (depth
   is assumed to be an integer power of two of at least
   FD_MCACHE_BLOCK).  It will return a sequence number before seq_query
   if the seq_query has not yet been published.  It will return a
   sequence after seq_query if seq_query is no longer available in the
   mcache.  In this last case, seq_query will be typically be within
   depth of the most recently published sequence number as of some point
   in time between when the call was made and the call returned (in many
   common uses, this is typically very very close to most recently
   published sequence number).  This acts as a compiler memory fence. */

static inline ulong
fd_mcache_query( fd_frag_meta_t const * mcache,
                 ulong                  depth,
                 ulong                  seq_query ) {
  return fd_frag_meta_seq_query( mcache + fd_mcache_line_idx( seq_query, depth ) );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_tango_mcache_fd_mcache_h */

