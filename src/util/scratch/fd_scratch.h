#ifndef HEADER_fd_src_util_scratch_fd_scratch_h
#define HEADER_fd_src_util_scratch_fd_scratch_h

/* APIs for high performance scratch pad memory allocation.  There
   are two allocators provided.  One is fd_alloca, which is an alignment
   aware equivalent of alloca.  It is meant for use anywhere alloca
   would normally be used.  This is only available if the built target
   has the FD_HAS_ALLOCA capability.  The second as fd_scratch_alloc.
   It is meant for use in situations that have very complex and large
   temporary memory usage. */

#include "../sanitize/fd_sanitize.h"
#include "../tile/fd_tile.h"
#include "../valloc/fd_valloc.h"

/* FD_SCRATCH_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional run-time checks. */

#ifndef FD_SCRATCH_USE_HANDHOLDING
#define FD_SCRATCH_USE_HANDHOLDING 0
#endif

/* FD_SCRATCH_ALLOC_ALIGN_DEFAULT is the default alignment to use for
   allocations.

   Default should be at least 16 for consistent cross platform behavior
   that is language conformant across a wide range of targets (i.e. the
   largest primitive type across all possible build ... practically
   sizeof(int128)).  This also naturally covers SSE natural alignment on
   x86.  8 could be used if features like int128 and so forth and still
   be linguistically conformant (sizeof(ulong) here is the limit).
   Likewise, 32, 64, 128 could be used to guarantee all allocations will
   have natural AVX/AVX2, natural AVX-512 / cache-line,
   adjacent-cache-line-prefetch false sharing avoidance / natural GPU
   alignment properties.

   128 for default was picked as double x86 cache line for ACLPF false
   sharing avoidance and for consistency with GPU warp sizes ... i.e.
   the default allocation behaviors are naturally interthread
   communication false sharing resistant and GPU friendly.  This also
   naturally covers cases like SSE, AVX, AVX2 and AVX-512. */

#define FD_SCRATCH_ALIGN_DEFAULT (128UL) /* integer power-of-2 >=16 */

/* FD_SCRATCH_{SMEM,FMEM}_ALIGN give the alignment requirements for
   the memory regions used to a scratch pad memory.  There are not many
   restrictions on the SMEM alignment practically other than it be a
   reasonable integer power of two.  128 was picked to harmonize with
   FD_SCRATCH_ALIGN_DEFAULT (which does have more technical motivations
   behind its choice) but this is not strictly required.
   FD_SCRATCH_FMEM_ALIGN is required to be sizeof(ulong). */

#define FD_SCRATCH_SMEM_ALIGN (128UL) /* integer power-of-2, harmonized with ALIGN_DEFAULT */
#define FD_SCRATCH_FMEM_ALIGN   (8UL) /* ==sizeof(ulong) but avoids bugs with some compilers */

FD_PROTOTYPES_BEGIN

/* Private APIs *******************************************************/

#if FD_SCRATCH_USE_HANDHOLDING
extern FD_TL int     fd_scratch_in_prepare;
#endif

extern FD_TL ulong   fd_scratch_private_start;
extern FD_TL ulong   fd_scratch_private_free;
extern FD_TL ulong   fd_scratch_private_stop;

extern FD_TL ulong * fd_scratch_private_frame;
extern FD_TL ulong   fd_scratch_private_frame_cnt;
extern FD_TL ulong   fd_scratch_private_frame_max;

FD_FN_CONST static inline int
fd_scratch_private_align_is_valid( ulong align ) {
  return !(align & (align-1UL)); /* returns true if power or 2 or zero, compile time typically */
}

FD_FN_CONST static inline ulong
fd_scratch_private_true_align( ulong align ) {
  return fd_ulong_if( !align, FD_SCRATCH_ALIGN_DEFAULT, align ); /* compile time typically */
}

/* Public APIs ********************************************************/

/* Constructor APIs */

/* fd_scratch_smem_{align,footprint} return the alignment and footprint
   of a memory region suitable for use as a scratch pad memory that can
   hold up to smax bytes.  There are very few restrictions on the nature
   of this memory.  It could even be just a flat address space that is
   not backed by an actual physical memory as far as scratch is
   concerned.  In typical use cases though, the scratch pad memory
   should point to a region of huge or gigantic page backed memory on
   the caller's numa node.

   A shared memory region for smem is fine for smem.  This could be used
   for example to allow other threads / processes to access a scratch
   allocation from this thread for the lifetime of a scratch allocation.

   Even more generally, a shared memory region for both smem and fmem
   could make it is theoretically possible to have a scratch pad memory
   that is shared across multiple threads / processes.  The API is not
   well designed for such though (the main reason to use fmem in shared
   memory would be convenience and/or adding hot swapping
   functionality).  In the common scratch scenario, every thread would
   attach to their local join of the shared smem and shared fmem.  But
   since the operations below are not designed to be thread safe, the
   threads would have to protect against concurrent use of push and pop
   (and attach would probably need to be tweaked to make it easier to
   attach to an already in use scratch pad).

   Compile time allocation is possible via the FD_SCRATCH_SMEM_ALIGN
   define.  E.g.:

     uchar my_smem[ MY_SMAX ] __attribute__((aligned(FD_SCRATCH_SMEM_ALIGN)));

   will be valid to use as a scratch smem with space for up to MY_SMAX
   bytes. */

FD_FN_CONST static inline ulong fd_scratch_smem_align( void ) { return FD_SCRATCH_SMEM_ALIGN; }

FD_FN_CONST static inline ulong
fd_scratch_smem_footprint( ulong smax ) {
  return fd_ulong_align_up( smax, FD_SCRATCH_SMEM_ALIGN );
}

/* fd_scratch_fmem_{align,footprint} return the alignment and footprint
   of a memory region suitable for holding the scratch pad memory
   metadata (typically very small).  The scratch pad memory will be
   capable of holding up to depth scratch frames.

   Compile time allocation is possible via the FD_SCRATCH_FMEM_ALIGN
   define.  E.g.

     ulong my_fmem[ MY_DEPTH ] __attribute((aligned(FD_SCRATCH_FMEM_ALIGN)));

   or, even simpler:

     ulong my_fmem[ MY_DEPTH ];

   will be valid to use as a scratch fmem with space for up to depth
   frames.  The attribute variant is not strictly necessary, just for
   consistency with the smem above (where it is required). */

FD_FN_CONST static inline ulong fd_scratch_fmem_align    ( void        ) { return sizeof(ulong);       }
FD_FN_CONST static inline ulong fd_scratch_fmem_footprint( ulong depth ) { return sizeof(ulong)*depth; }

/* fd_scratch_attach attaches the calling thread to memory regions
   sufficient to hold up to smax (positive) bytes and with up to depth
   (positive) frames.  smem/fmem should have the required alignment and
   footprint specified for smax/depth from the above and be non-NULL).
   The caller has a read/write interest in these regions while attached
   (and thus the local lifetime of these regions must cover the lifetime
   of the attachment).  Only one scratch pad memory may be attached to a
   caller at a time.  This cannot fail from the caller's point of view
   (if handholding is enabled, it will abort the caller with a
   descriptive error message if used obviously in error). */

static inline void
fd_scratch_attach( void * smem,
                   void * fmem,
                   ulong  smax,
                   ulong  depth ) {

# if FD_SCRATCH_USE_HANDHOLDING
  if( FD_UNLIKELY( fd_scratch_private_frame_max ) ) FD_LOG_ERR(( "already attached" ));
  if( FD_UNLIKELY( !smem                        ) ) FD_LOG_ERR(( "bad smem"  ));
  if( FD_UNLIKELY( !fmem                        ) ) FD_LOG_ERR(( "bad fmem"  ));
  if( FD_UNLIKELY( !smax                        ) ) FD_LOG_ERR(( "bad smax"  ));
  if( FD_UNLIKELY( !depth                       ) ) FD_LOG_ERR(( "bad depth" ));
  fd_scratch_in_prepare = 0;
# endif

  fd_scratch_private_start     = (ulong)smem;
  fd_scratch_private_free      = fd_scratch_private_start;
  fd_scratch_private_stop      = fd_scratch_private_start + smax;

  fd_scratch_private_frame     = (ulong *)fmem;
  fd_scratch_private_frame_cnt = 0UL;
  fd_scratch_private_frame_max = depth;

# if FD_HAS_DEEPASAN
  /* Poison the entire smem region and populate with junk bytes for debugging.
     Alignment should be hanmdled by the caller */
  fd_memset( smem, 'A', smax );
  fd_asan_poison( smem, smax );
# endif
}

/* fd_scratch_detach detaches the calling thread from its current
   attachment.  Returns smem used on attach and, if opt_fmem is
   non-NULL, opt_fmem[0] will contain the fmem used on attach on return.

   This relinquishes the calling threads read/write interest on these
   memory regions.  All the caller's scratch frames are popped, any
   prepare in progress is canceled and all the caller's scratch
   allocations are freed implicitly by this.

   This cannot fail from the caller's point of view (if handholding is
   enabled, it will abort the caller with a descriptive error message if
   used obviously in error). */

static inline void *
fd_scratch_detach( void ** _opt_fmem ) {

# if FD_SCRATCH_USE_HANDHOLDING
  if( FD_UNLIKELY( !fd_scratch_private_frame_max ) ) FD_LOG_ERR(( "not attached" ));
  fd_scratch_in_prepare = 0;
# endif

# if FD_HAS_DEEPASAN
  /* Unpoison the entire scratch space and fill with junk bytes. We have a guarantee
     about the alignment region already. */
  fd_asan_unpoison( (void *)fd_scratch_private_start, fd_scratch_private_stop - fd_scratch_private_start );
  fd_memset( (void *)fd_scratch_private_start, 'B', fd_scratch_private_stop - fd_scratch_private_start );
# endif

  void * smem = (void *)fd_scratch_private_start;
  void * fmem = (void *)fd_scratch_private_frame;

  fd_scratch_private_start     = 0UL;
  fd_scratch_private_free      = 0UL;
  fd_scratch_private_stop      = 0UL;

  fd_scratch_private_frame     = NULL;
  fd_scratch_private_frame_cnt = 0UL;
  fd_scratch_private_frame_max = 0UL;

  if( _opt_fmem ) _opt_fmem[0] = fmem;
  return smem;
}

/* User APIs */

/* fd_scratch_{used,free} returns the number of bytes used/free in the
   caller's scratch.  Returns 0 if not attached.  Because of alignment
   overheads, an allocation is guaranteed to succeed if free>=sz+align-1
   where align is the actual alignment required for the allocation (e.g.
   align==0 -> default, align<min -> min).  It is guaranteed to fail if
   free<sz.  It might succeed or fail in between depending on the
   alignments of previously allocations.  These are freaky fast (O(3)
   fast asm operations under the hood). */

static inline ulong fd_scratch_used( void ) { return fd_scratch_private_free - fd_scratch_private_start; }
static inline ulong fd_scratch_free( void ) { return fd_scratch_private_stop - fd_scratch_private_free;  }

/* fd_scratch_frame_{used,free} returns the number of scratch frames
   used/free in the caller's scratch.  Returns 0 if not attached.  push
   is guaranteed to succeed if free is non-zero and guaranteed to fail
   otherwise.  pop is guaranteed to succeed if used is non-zero and
   guaranteed to fail otherwise.  These are freaky fast (O(1-3) fast asm
   operations under the hood). */

static inline ulong fd_scratch_frame_used( void ) { return fd_scratch_private_frame_cnt; }
static inline ulong fd_scratch_frame_free( void ) { return fd_scratch_private_frame_max - fd_scratch_private_frame_cnt; }

/* fd_scratch_reset frees all allocations (if any) and pops all scratch
   frames (if any) such that the caller's scratch will be in the same
   state it was immediately after attach.  The caller must be attached
   to a scratch memory to use.  This cannot fail from the caller's point
   of view (if handholding is enabled, it will abort the caller with a
   descriptive error message if used obviously in error).  This is
   freaky fast (O(3) fast asm operations under the hood). */

static inline void
fd_scratch_reset( void ) {
# if FD_SCRATCH_USE_HANDHOLDING
  if( FD_UNLIKELY( !fd_scratch_private_frame_max ) ) FD_LOG_ERR(( "not attached" ));
  fd_scratch_in_prepare = 0;
# endif
  fd_scratch_private_free      = fd_scratch_private_start;
  fd_scratch_private_frame_cnt = 0UL;

# if FD_HAS_DEEPASAN
  /* Poison entire scratch space again. */
  fd_asan_poison( (void *)fd_scratch_private_start, fd_scratch_private_stop - fd_scratch_private_start );
# endif
}

/* fd_scratch_push creates a new scratch frame and makes it the current
   frame.  Assumes caller is attached to a scratch with space for a new
   frame.  This cannot fail from the caller's point of view (if
   handholding is enabled, it will abort the caller with a descriptive
   error message if used obviously in error).  This is freaky fast (O(5)
   fast asm operations under the hood). */

FD_FN_UNUSED static void /* Work around -Winline */
fd_scratch_push( void ) {
# if FD_SCRATCH_USE_HANDHOLDING
  if( FD_UNLIKELY( !fd_scratch_private_frame_max                              ) ) {
    FD_LOG_ERR(( "not attached" ));
  }
  if( FD_UNLIKELY( fd_scratch_private_frame_cnt>=fd_scratch_private_frame_max ) ) FD_LOG_ERR(( "too many frames" ));
  fd_scratch_in_prepare = 0;
# endif
  fd_scratch_private_frame[ fd_scratch_private_frame_cnt++ ] = fd_scratch_private_free;
}

/* fd_scratch_pop frees all allocations in the current scratch frame,
   destroys the current scratch frame and makes the previous frame (if
   there is one) the current stack frame (and leaves the caller without
   a current frame if there is not one).  Assumes the caller is attached
   to a scratch memory with at least one frame in use.  This cannot fail
   from the caller's point of view (if handholding is enabled, it will
   abort the caller with a descriptive error message if used obviously
   in error).  This is freaky fast (O(5) fast asm operations under the
   hood). */

FD_FN_UNUSED static void /* Work around -Winline */
fd_scratch_pop( void ) {
# if FD_SCRATCH_USE_HANDHOLDING
  if( FD_UNLIKELY( !fd_scratch_private_frame_max ) ) FD_LOG_ERR(( "not attached" ));
  if( FD_UNLIKELY( !fd_scratch_private_frame_cnt ) ) FD_LOG_ERR(( "unmatched pop" ));
  fd_scratch_in_prepare = 0;
# endif
  fd_scratch_private_free = fd_scratch_private_frame[ --fd_scratch_private_frame_cnt ];

# if FD_HAS_DEEPASAN
  /* On a pop() operation, the entire range from fd_scratch_private_free to the
     end of the scratch space can be safely poisoned. The region must be aligned
     to accomodate asan manual poisoning requirements. The region from the new
     fd_scratch_private_free to the poisoned region is populated with junk bytes
     for debugging. If the junk bytes are accessed before a frame is pushed and
     is populated with allocations, then it is a bad memory access.*/
  ulong aligned_free = fd_ulong_align_up( fd_scratch_private_free, FD_ASAN_ALIGN );
  ulong poison_range = fd_scratch_private_stop - aligned_free;
  fd_asan_poison( (void *)aligned_free, poison_range );
  fd_memset( (void *)fd_scratch_private_free, 'C', aligned_free - fd_scratch_private_free );
# endif
}

/* fd_scratch_prepare starts an allocation of unknown size and known
   alignment align (0 means use default alignment) in the caller's
   current scratch frame.  Returns a pointer in the caller's address
   space with alignment align to the first byte of a region with
   fd_scratch_free() (as observed after this function returns) bytes
   available.  The caller is free to clobber any bytes in this region.

   fd_scratch_publish finishes an in-progress allocation.  end points at
   the first byte after the final allocation.  Assumes there is a
   matching prepare.  A published allocation can be subsequently
   trimmed.

   fd_scratch_cancel cancels an in-progress allocation.  This is a no-op
   if there is no matching prepare.  If the prepare had alignment other
   than 1, it is possible that some alignment padding needed for the
   allocation will still be used in the caller's current scratch frame.
   If this is not acceptable, the prepare should use an alignment of 1
   and manually align the return.

   This allows idioms like:

     uchar * p = (uchar *)fd_scratch_prepare( align );

     if( FD_UNLIKELY( fd_scratch_free() < app_max_sz ) ) {

       fd_scratch_cancel();

       ... handle too little scratch space to handle application
       ... worst case needs here

     } else {

       ... populate sz bytes to p where sz is in [0,app_max_sz]
       p += sz;

       fd_scratch_publish( p );

       ... at this point, scratch is as though
       ... fd_scratch_alloc( align, sz ) was called above

     }

   Ideally every prepare should be matched with a publish or a cancel,
   only one prepare can be in-progress at a time on a thread and prepares
   cannot be nested.  As such virtually all other scratch operations
   will implicitly cancel any in-progress prepare, including attach /
   detach / push / pop / prepare / alloc / trim. */

FD_FN_UNUSED static void * /* Work around -Winline */
fd_scratch_prepare( ulong align ) {

# if FD_SCRATCH_USE_HANDHOLDING
  if( FD_UNLIKELY( !fd_scratch_private_frame_cnt               ) ) FD_LOG_ERR(( "unmatched push" ));
  if( FD_UNLIKELY( !fd_scratch_private_align_is_valid( align ) ) ) FD_LOG_ERR(( "bad align (%lu)", align ));
# endif

  ulong true_align = fd_scratch_private_true_align( align );
# if FD_HAS_DEEPASAN
  /* Need 8 byte alignment */
  align            = fd_ulong_if( align < FD_ASAN_ALIGN, FD_ASAN_ALIGN, align );
# endif
  ulong smem       = fd_ulong_align_up( fd_scratch_private_free, true_align );

# if FD_SCRATCH_USE_HANDHOLDING
  if( FD_UNLIKELY( smem < fd_scratch_private_free ) ) FD_LOG_ERR(( "prepare align (%lu) overflow", true_align ));
  if( FD_UNLIKELY( smem > fd_scratch_private_stop ) ) FD_LOG_ERR(( "prepare align (%lu) needs %lu additional scratch",
                                                                   align, smem - fd_scratch_private_stop ));
  fd_scratch_in_prepare = 1;
# endif

  fd_scratch_private_free = smem;
  return (void *)smem;
}

static inline void
fd_scratch_publish( void * _end ) {
  ulong end = (ulong)_end;

# if FD_SCRATCH_USE_HANDHOLDING
  if( FD_UNLIKELY( !fd_scratch_in_prepare        ) ) FD_LOG_ERR(( "unmatched prepare" ));
  if( FD_UNLIKELY( end < fd_scratch_private_free ) ) FD_LOG_ERR(( "publish underflow" ));
  if( FD_UNLIKELY( end > fd_scratch_private_stop ) )
    FD_LOG_ERR(( "publish needs %lu additional scratch", end-fd_scratch_private_stop ));
  fd_scratch_in_prepare   = 0;
# endif

# if FD_HAS_DEEPASAN
  /* Unpoison the range from the previous fd_scratch_private_free to the end
     address specified by the caller. The start address is aligned down because
     the start of the scratch space is aligned and any prior bytes should be
     unpoisoned already. The size is aligned up to accomodate 8 byte alignment
     for asan manual poisoning. This is also acceptable because future allocations
     will be aligned up. For debugging purposes the range from end_ to the end of
     the unpoisoned region will be filled with junk bytes because these bytes
     should not ever be accessed (until the frame is popped, pushed, and the
     region is allocated again).  */
  ulong aligned_addr = fd_ulong_align_dn( fd_scratch_private_free, FD_ASAN_ALIGN );
  ulong aligned_sz = fd_ulong_align_up( end - aligned_addr, FD_ASAN_ALIGN );
  fd_asan_unpoison( (void *) aligned_addr, aligned_sz );
  fd_memset( _end, 'D', aligned_addr + aligned_sz - end );
# endif

  fd_scratch_private_free = end;
}

static inline void
fd_scratch_cancel( void ) {

# if FD_SCRATCH_USE_HANDHOLDING
  if( FD_UNLIKELY( !fd_scratch_in_prepare ) ) FD_LOG_ERR(( "unmatched prepare" ));
  fd_scratch_in_prepare = 0;
# endif

}

/* fd_scratch_alloc allocates sz bytes with alignment align in the
   caller's current scratch frame.  There should be no prepare in
   progress.  Note that this has same function signature as
   aligned_alloc (and not by accident).  It does have some less
   restrictive behaviors though.

   align must be 0 or an integer power of 2.  0 will be treated as
   FD_SCRATCH_ALIGN_DEFAULT.

   sz need not be a multiple of align.  Further, the underlying
   allocator does not implicitly round up sz to an align multiple (as
   such, scratch can allocate additional items in any tail padding that
   might have been implicitly reserved had it rounded up).  That is, if
   you really want to round up allocations to a multiple of align, then
   manually align up sz ... e.g. pass fd_ulong_align_up(sz,align) when
   align is non-zero to this call (this could be implemented as a
   compile time mode with some small extra overhead if desirable).

   sz 0 is fine.  This will currently return a properly aligned non-NULL
   pointer (the allocator might do some allocation under the hood to get
   the desired alignment and it is possible this might fail ... there is
   a case for returning NULL or an arbitrary but appropriately aligned
   non-NULL and this could be implemented as a compile time mode with
   some small extra overhead if desirable).

   This cannot fail from the caller's point of view (if handholding is
   enabled, it will abort the caller with a descriptive error message if
   used obviously in error).

   This is freaky fast (O(5) fast asm operations under the hood). */

FD_FN_UNUSED static void * /* Work around -Winline */
fd_scratch_alloc( ulong align,
                  ulong sz ) {
  ulong smem = (ulong)fd_scratch_prepare( align );
  ulong end  = smem + sz;

# if FD_SCRATCH_USE_HANDHOLDING
  if( FD_UNLIKELY( (end < smem) | (end > fd_scratch_private_stop) ) ) FD_LOG_ERR(( "sz (%lu) overflow", sz ));
# endif

  fd_scratch_publish( (void *)end );
  return (void *)smem;
}

/* fd_scratch_trim trims the size of the most recent scratch allocation
   in the current scratch frame (technically it can be used to trim the
   size of the entire current scratch frame but doing more than the most
   recent scratch allocation is strongly discouraged).  Assumes there is
   a current scratch frame and the caller is not in a prepare.  end
   points at the first byte to free in the most recent scratch
   allocation (or the first byte after the most recent scratch
   allocation).  This allows idioms like:

     uchar * p = (uchar *)fd_scratch_alloc( align, max_sz );

     ... populate sz bytes of p where sz is in [0,max_sz]
     p += sz;

     fd_scratch_trim( p );

     ... now the thread's scratch is as though original call was
     ... p = fd_scratch_alloc( align, sz );

   This cannot fail from the caller's point of view (if handholding is
   enabled, this will abort the caller with a descriptive error message
   if used obviously in error).

   Note that an allocation be repeatedly trimmed.

   Note also that trim can nest.  E.g. a thread can call a function that
   uses scratch with its own properly matched scratch pushes and pops.
   On function return, trim will still work on the most recent scratch
   alloc in that frame by the caller.

   This is freaky fast (O(1) fast asm operations under the hood). */

static inline void
fd_scratch_trim( void * _end ) {
  ulong end = (ulong)_end;

# if FD_SCRATCH_USE_HANDHOLDING
  if( FD_UNLIKELY( !fd_scratch_private_frame_cnt                                      ) ) FD_LOG_ERR(( "unmatched push" ));
  if( FD_UNLIKELY( end < fd_scratch_private_frame[ fd_scratch_private_frame_cnt-1UL ] ) ) FD_LOG_ERR(( "trim underflow" ));
  if( FD_UNLIKELY( end > fd_scratch_private_free                                      ) ) FD_LOG_ERR(( "trim overflow" ));
  fd_scratch_in_prepare = 0;
# endif

# if FD_HAS_DEEPASAN
  /* The region to poison should be from _end to the end of the scratch's region.
     The same alignment considerations need to be taken into account. The region
     that is trimmed but not poisoned will be populated with junk bytes. */
  ulong aligned_free = fd_ulong_align_up( end, FD_ASAN_ALIGN );
  ulong poison_range = fd_scratch_private_stop - aligned_free;
  fd_asan_poison( (void*)aligned_free, poison_range );
  fd_memset( (void*)end, 'E', aligned_free - end );
# endif

  fd_scratch_private_free = end;
}

/* fd_scratch_*_is_safe returns false (0) if the operation is obviously
   unsafe to do at the time of the call or true otherwise.
   Specifically:

   fd_scratch_attach_is_safe() returns 1 if the calling thread is not
   already attached to scratch.

   fd_scratch_detach_is_safe() returns 1 if the calling thread is
   already attached to scratch.

   fd_scratch_reset_is_safe() returns 1 if the calling thread is already
   attached to scratch.

   fd_scratch_push_is_safe() returns 1 if there is at least one frame
   available and 0 otherwise.

   fd_scratch_pop_is_safe() returns 1 if there is at least one frame
   in use and 0 otherwise.

   fd_scratch_prepare_is_safe( align ) returns 1 if there is a current
   frame for the allocation and enough scratch pad memory to start
   preparing an allocation with alignment align.

   fd_scratch_publish_is_safe( end ) returns 1 if end is a valid
   location to complete an allocation in preparation.  If handholding is
   enabled, will additionally check that there is a prepare already in
   progress.

   fd_scratch_cancel_is_safe() returns 1.

   fd_scratch_alloc_is_safe( align, sz ) returns 1 if there is a current
   frame for the allocation and enough scratch pad memory for an
   allocation with alignment align and size sz.

   fd_scratch_trim_is_safe( end ) returns 1 if there is a current frame
   and that current frame can be trimmed to end safely.

   These are safe to call at any time and also freak fast handful of
   assembly operations. */

FD_FN_PURE static inline int fd_scratch_attach_is_safe( void ) { return  !fd_scratch_private_frame_max; }
FD_FN_PURE static inline int fd_scratch_detach_is_safe( void ) { return !!fd_scratch_private_frame_max; }
FD_FN_PURE static inline int fd_scratch_reset_is_safe ( void ) { return !!fd_scratch_private_frame_max; }
FD_FN_PURE static inline int fd_scratch_push_is_safe  ( void ) { return fd_scratch_private_frame_cnt<fd_scratch_private_frame_max; }
FD_FN_PURE static inline int fd_scratch_pop_is_safe   ( void ) { return !!fd_scratch_private_frame_cnt; }

FD_FN_PURE static inline int
fd_scratch_prepare_is_safe( ulong align ) {
  if( FD_UNLIKELY( !fd_scratch_private_frame_cnt               ) ) return 0; /* No current frame */
  if( FD_UNLIKELY( !fd_scratch_private_align_is_valid( align ) ) ) return 0; /* Bad alignment, compile time typically */
  ulong true_align = fd_scratch_private_true_align( align ); /* compile time typically */
  ulong smem       = fd_ulong_align_up( fd_scratch_private_free, true_align );
  if( FD_UNLIKELY( smem < fd_scratch_private_free              ) ) return 0; /* alignment overflow */
  if( FD_UNLIKELY( smem > fd_scratch_private_stop              ) ) return 0; /* insufficient scratch */
  return 1;
}

FD_FN_PURE static inline int
fd_scratch_publish_is_safe( void * _end ) {
  ulong end = (ulong)_end;
# if FD_SCRATCH_USE_HANDHOLDING
  if( FD_UNLIKELY( !fd_scratch_in_prepare        ) ) return 0; /* Not in prepare */
# endif
  if( FD_UNLIKELY( end < fd_scratch_private_free ) ) return 0; /* Backward */
  if( FD_UNLIKELY( end > fd_scratch_private_stop ) ) return 0; /* Out of bounds */
  return 1;
}

FD_FN_CONST static inline int
fd_scratch_cancel_is_safe( void ) {
  return 1;
}

FD_FN_PURE static inline int
fd_scratch_alloc_is_safe( ulong align,
                          ulong sz ) {
  if( FD_UNLIKELY( !fd_scratch_private_frame_cnt               ) ) return 0; /* No current frame */
  if( FD_UNLIKELY( !fd_scratch_private_align_is_valid( align ) ) ) return 0; /* Bad align, compile time typically */
  ulong true_align = fd_scratch_private_true_align( align ); /* compile time typically */
  ulong smem       = fd_ulong_align_up( fd_scratch_private_free, true_align );
  if( FD_UNLIKELY( smem < fd_scratch_private_free              ) ) return 0; /* align overflow */
  ulong free       = smem + sz;
  if( FD_UNLIKELY( free < smem                                 ) ) return 0; /* sz overflow */
  if( FD_UNLIKELY( free > fd_scratch_private_stop              ) ) return 0; /* too little space */
  return 1;
}

FD_FN_PURE static inline int
fd_scratch_trim_is_safe( void * _end ) {
  ulong end = (ulong)_end;
  if( FD_UNLIKELY( !fd_scratch_private_frame_cnt                                      ) ) return 0; /* No current frame */
  if( FD_UNLIKELY( end < fd_scratch_private_frame[ fd_scratch_private_frame_cnt-1UL ] ) ) return 0; /* Trim underflow */
  if( FD_UNLIKELY( end > fd_scratch_private_free                                      ) ) return 0; /* Trim overflow */
  return 1;
}

/* fd_scratch_vtable is the virtual function table implementing
   fd_valloc for fd_scratch. */

extern const fd_valloc_vtable_t fd_scratch_vtable;

/* fd_scratch_virtual returns an abstract handle to the fd_scratch join.
   Valid for lifetime of scratch frame.  fd_valloc_t must be dropped
   before scratch frame changes or scratch detaches. */

FD_FN_CONST static inline fd_valloc_t
fd_scratch_virtual( void ) {
  fd_valloc_t valloc = { NULL, &fd_scratch_vtable };
  return valloc;
}

/* FD_SCRATCH_SCOPE_{BEGIN,END} create a `do { ... } while(0);` scope in
   which a temporary scratch frame is available.  Nested scopes are
   permitted.  This scratch frame is automatically destroyed when
   exiting the scope normally (e.g. by 'break', 'return', or reaching
   the end).  Uses a dummy variable with a cleanup attribute under the
   hood.  U.B. if scope is left abnormally (e.g. longjmp(), exception,
   abort(), etc.).  Use as follows:

   FD_SCRATCH_SCOPE_BEGIN {
     ...
     fd_scratch_alloc( ... );
     ...
   }
   FD_SCRATCH_SCOPE_END; */

FD_FN_UNUSED static inline void
fd_scratch_scoped_pop_private( void * _unused ) {
  (void)_unused;
  fd_scratch_pop();
}

#define FD_SCRATCH_SCOPE_BEGIN do {                         \
  fd_scratch_push();                                        \
  int __fd_scratch_guard_ ## __LINE__                       \
    __attribute__((cleanup(fd_scratch_scoped_pop_private))) \
    __attribute__((unused)) = 0;                            \
  do

#define FD_SCRATCH_SCOPE_END while(0); } while(0)

/* fd_alloca is variant of alloca that works like aligned_alloc.  That
   is, it returns an allocation of sz bytes with an alignment of at
   least align.  Like alloca, this allocation will be in the stack frame
   of the calling function with a lifetime of until the calling function
   returns.  Stack overflow handling is likewise identical to alloca
   (stack overflows will overlap the top stack guard, typically
   triggering a seg fault when the overflow region is touched that will
   be caught and handled by the logger to terminate the calling thread
   group).  As such, like alloca, these really should only be used for
   smallish (<< few KiB) quick allocations in bounded recursion depth
   circumstances.

   Like fd_scratch_alloc, align must be an 0 or a non-negative integer
   power of 2.  0 will be treated as align_default.  align smaller than
   align_min will be bumped up to align_min.

   The caller promises request will not overflow the stack.  This has to
   be implemented as a macro for linguistic reasons and align should be
   safe against multiple evaluation and, due to compiler limitations,
   must be a compile time constant.  Returns non-NULL on success and
   NULL on failure (in most situations, can never fail from the caller's
   POV).  sz==0 is okay (and will return non-NULL). */

#if FD_HAS_ALLOCA

/* Work around compiler limitations */
#define FD_SCRATCH_PRIVATE_TRUE_ALIGN( align ) ((align) ? (align) : FD_SCRATCH_ALIGN_DEFAULT)

#define fd_alloca(align,sz) __builtin_alloca_with_align( fd_ulong_max( (sz), 1UL ), \
                                                         8UL*FD_SCRATCH_PRIVATE_TRUE_ALIGN( (align) ) /*bits*/ )

/* fd_alloca_check does fd_alloca but it will FD_LOG_CRIT with a
   detailed message if the request would cause a stack overflow or leave
   so little available free stack that subsequent normal thread
   operations would be at risk.

   Note that returning NULL on failure is not an option as this would no
   longer be a drop-in instrumented replacement for fd_alloca (this
   would also require even more linguistic hacks to keep the fd_alloca
   at the appropriate scope).  Likewise, testing the allocated region is
   within the stack post allocation is not an option as the FD_LOG_CRIT
   invocation would then try to use stack with the already overflowed
   allocation in it (there is no easy portable way to guarantee an
   alloca has been freed short of returning from the function in which
   the alloca was performed).  Using FD_LOG_ERR instead of FD_LOG_CRIT
   is a potentially viable alternative error handling behavior though.

   This has to be implemented as a macro for linguistic reasons.  It is
   recommended this only be used for development / debugging / testing
   purposes (e.g. if you are doing alloca in production that are large
   enough you are worried about stack overflow, you probably should be
   using fd_scratch, fd_alloc or fd_wksp depending on performance and
   persistence needs or, better still, architecting to not need any
   temporary memory allocations at all).  If the caller's stack
   diagnostics could not be successfully initialized (this is logged),
   this will always FD_LOG_CRIT. */

#if !FD_HAS_ASAN

extern FD_TL ulong fd_alloca_check_private_sz;

#define fd_alloca_check( align, sz )                                                                             \
   ( fd_alloca_check_private_sz = (sz),                                                                          \
     (__extension__({                                                                                            \
       ulong _fd_alloca_check_private_pad_max   = FD_SCRATCH_PRIVATE_TRUE_ALIGN( (align) ) - 1UL;                \
       ulong _fd_alloca_check_private_footprint = fd_alloca_check_private_sz + _fd_alloca_check_private_pad_max; \
       if( FD_UNLIKELY( (_fd_alloca_check_private_footprint < _fd_alloca_check_private_pad_max      ) |          \
                        (_fd_alloca_check_private_footprint > (31UL*(fd_tile_stack_est_free() >> 5))) ) )        \
         FD_LOG_CRIT(( "fd_alloca_check( " #align ", " #sz " ) stack overflow" ));                               \
     })),                                                                                                        \
     fd_alloca( (align), fd_alloca_check_private_sz ) )

#else /* FD_HAS_ASAN */

/* AddressSanitizer provides its own alloca safety instrumentation
   which are more powerful than the above fd_alloca_check heuristics. */

#define fd_alloca_check fd_alloca

#endif /* FD_HAS_ASAN */
#endif /* FD_HAS_ALLOCA */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_scratch_fd_scratch_h */
