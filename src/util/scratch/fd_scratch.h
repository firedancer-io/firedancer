#ifndef HEADER_src_util_spad_fd_spad_h
#define HEADER_src_util_scratch_fd_scratch_h

/* APIs for high performance scratch pad memory allocation */

#include "../log/fd_log.h"

/* FD_SCRATCH_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional debugging checks. */

#ifndef FD_SCRATCH_USE_HANDHOLDING
#define FD_SCRATCH_USE_HANDHOLDING 0
#endif

/* FD_SCRATCH_ALLOC_ALIGN_{MIN,DEFAULT} are the minimum/default
   alignment to use for allocations.

   16 for min is for consistent cross platform behavior that is language
   conformant across a wide range of targets (i.e. the largest primitive
   type across all possible build ... practically sizeof(int128)).  This
   also naturally covers SSE natural alignment on x86.  8 could be used
   if features like int128 and so forth and still be linguistically
   conformant (sizeof(ulong) here is the limit).  Likewise, 32, 64, 128
   could be used to guarantee all allocations will have natural
   AVX/AVX2, natural AVX-512, adjacent-cache-line-prefetch false sharing
   avoidance / natural GPU alignment properties.

   128 for default was picked as double x86 cache line for ACLPF false
   sharing avoidance and for consistency with GPU warp sizes ... i.e.
   the default allocation behaviors are naturally interthread
   communication false sharing resistant and GPU friendly.  This also
   naturally covers cases like SSE, AVX, AVX2 and AVX-512. */

#define FD_SCRATCH_ALIGN_MIN      (16UL) /* integer power-of-2 of at least the largest primitive type */
#define FD_SCRATCH_ALIGN_DEFAULT (128UL) /* integer power-of-2 >=min */

/* FD_SCRATCH_{SMEM,FMEM}_ALIGN give the alignment requirements for
   regions used as scratch pad memories.  They are discussed in more
   detail below. */

#define FD_SCRATCH_SMEM_ALIGN (128UL) /* integer power-of-2, harmonized with ALIGN_DEFAULT */
#define FD_SCRATCH_FMEM_ALIGN   (8UL) /* ==sizeof(ulong) but avoids bugs with some compilers */

FD_PROTOTYPES_BEGIN

/* Private APIs *******************************************************/

extern FD_TLS ulong   fd_scratch_private_start;
extern FD_TLS ulong   fd_scratch_private_free;
extern FD_TLS ulong   fd_scratch_private_stop;

extern FD_TLS ulong * fd_scratch_private_frame;
extern FD_TLS ulong   fd_scratch_private_frame_cnt;
extern FD_TLS ulong   fd_scratch_private_frame_max;

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
   
   Compile time allocation is possible via the FD_SCRATCH_SMEM_ALIGN
   define.  E.g.:

     uchar my_smem[ MY_SMAX ] __attribute__((aligned(FD_SCRATCH_SMEM_ALIGN)));
   
   will be valid to use as a scratch smem with space for up to MY_SMAX
   bytes.

   There are not many restrictions on the alignment practically other
   than it be a reasonable integer power of two.  128 was picked to
   harmonize with FD_SCRATCH_ALIGN_DEFAULT (which does have more
   technical motivations behind its choice) but this is not strictly
   required. */

FD_FN_CONST static inline ulong fd_scratch_smem_align( void ) { return (ulong)FD_SCRATCH_SMEM_ALIGN; }

FD_FN_CONST static inline ulong
fd_scratch_smem_footprint( ulong smax ) {
  return fd_ulong_align_up( smax, (ulong)FD_SCRATCH_SMEM_ALIGN ); 
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

  if( FD_UNLIKELY( !smem  ) ) FD_LOG_ERR(( "bad smem"  ));
  if( FD_UNLIKELY( !fmem  ) ) FD_LOG_ERR(( "bad fmem"  ));
  if( FD_UNLIKELY( !smax  ) ) FD_LOG_ERR(( "bad smax"  ));
  if( FD_UNLIKELY( !depth ) ) FD_LOG_ERR(( "bad depth" ));
# endif

  fd_scratch_private_start     = (ulong)smem;
  fd_scratch_private_free      = fd_scratch_private_start;
  fd_scratch_private_stop      = fd_scratch_private_start + smax;

  fd_scratch_private_frame     = (ulong *)fmem;
  fd_scratch_private_frame_cnt = 0UL;
  fd_scratch_private_frame_max = depth;
}

/* fd_scratch_detach detaches the calling thread from its current
   attachment.  Returns smem used on attach and, if opt_fmem is
   non-NULL, opt_fmem[0] will contain the fmem used on attach on return.

   This reliquishes the calling threads read/write interest on these
   memory regions.  All the caller's scratch frames are popped and all
   the caller's scratch allocations are freed implicitly by this.

   This cannot fail from the caller's point of view (if handholding is
   enabled, it will abort the caller with a descriptive error message if
   used obviously in error). */

static inline void *
fd_scratch_detach( void ** _opt_fmem ) {

# if FD_SCRATCH_USE_HANDHOLDING
  if( FD_UNLIKELY( !fd_scratch_private_frame_max ) ) FD_LOG_ERR(( "not attached" ));
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
# endif
  fd_scratch_private_free      = fd_scratch_private_start;
  fd_scratch_private_frame_cnt = 0UL;
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
  if( FD_UNLIKELY( !fd_scratch_private_frame_max ) ) FD_LOG_ERR(( "not attached" ));
  if( FD_UNLIKELY( fd_scratch_private_frame_cnt>=fd_scratch_private_frame_max ) ) FD_LOG_ERR(( "too many frames" ));
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
# endif
  fd_scratch_private_free = fd_scratch_private_frame[ --fd_scratch_private_frame_cnt ];
}

/* fd_scratch_alloc allocates sz bytes with alignment align in the
   caller's current scratch frame.  Note that this has same function
   signature as aligned_alloc (and not by accident).  It does has some
   less restrictive behaviors though.
   
   align must be an 0 or a non-negative integer power of 2.  0 will be
   treated as align_default.  align smaller than align_min will be
   bumped up to align_min.
   
   sz need not be a multiple of align.  Further, the underlying
   allocator does not implicitly round up sz to an align multiple (as
   such, it is free to allocate additional stuff in any tail padding
   that might have been implicitly reserved had it rounded up).  That
   is, if you really want to round up allocations to a multiple of
   align, then manually align up sz ... e.g. pass
   fd_ulong_align_up(sz,align) when align is non-zero to this call (this
   could be implemented as a compile time mode with some small extra
   overhead if desirable).
   
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

FD_FN_CONST static inline int
fd_scratch_private_align_is_valid( ulong align ) {
  return !(align & (align-1UL)); /* returns true if power or 2 or zero, compile time typically */
}

FD_FN_CONST static inline ulong
fd_scratch_private_true_align( ulong align ) {
  return fd_ulong_max( fd_ulong_if( !align, FD_SCRATCH_ALIGN_DEFAULT, align ), FD_SCRATCH_ALIGN_MIN ); /* compile time typically */
}

__attribute__((malloc,alloc_align(1),alloc_size(2),nonnull)) static inline void *
fd_scratch_private_alloc( ulong true_align,
                          ulong sz ) {
  ulong smem = fd_ulong_align_up( fd_scratch_private_free, true_align );
  ulong free = smem + sz;
# if FD_SCRATCH_USE_HANDHOLDING
  if( FD_UNLIKELY( smem < fd_scratch_private_free ) ) FD_LOG_ERR(( "alloc(align=%lu,sz=%lu) align overflow", true_align, sz ));
  if( FD_UNLIKELY( free < smem                    ) ) FD_LOG_ERR(( "alloc(align=%lu,sz=%lu) size overflow",  true_align, sz ));
  if( FD_UNLIKELY( free > fd_scratch_private_stop ) ) FD_LOG_ERR(( "alloc(align=%lu,sz=%lu) needs %lu additional scratch",
                                                                   true_align, sz, free-fd_scratch_private_stop ));
# endif
  fd_scratch_private_free = free;
  return (void *)smem;
}

FD_FN_UNUSED static void * /* Work around -Winline */
fd_scratch_alloc( ulong align,
                  ulong sz ) {
# if FD_SCRATCH_USE_HANDHOLDING
  if( FD_UNLIKELY( !fd_scratch_private_frame_max               ) ) FD_LOG_ERR(( "not attached" ));
  if( FD_UNLIKELY( !fd_scratch_private_frame_cnt               ) ) FD_LOG_ERR(( "unmatched push" ));
  if( FD_UNLIKELY( !fd_scratch_private_align_is_valid( align ) ) ) /* compile time typically */
    FD_LOG_ERR(( "bad align (%lu)", align ));
# endif
  return fd_scratch_private_alloc( fd_scratch_private_true_align( align ), sz );
}

/* fd_scratch_{push,pop,alloc}_is_safe returns true (1) if the operation
   is safe to to at the present time and false (0) otherwise.
   Specifically:

   fd_scratch_push_is_safe() returns 1 if there is at least one frame
   available and 0 otherwise.

   fd_scratch_pop_is_safe() returns 1 if there is at least one frame
   in use and 0 otherwise.

   fd_scratch_alloc_is_safe( align, sz ) returns 1 if there is a current
   frame for the allocation and enough scratch pad memory for an
   allocation with alignment align and size sz and .

   These are safe to call at any time and also freak fast handful of
   assembly operations. */

FD_FN_PURE static inline int fd_scratch_push_is_safe( void ) { return fd_scratch_private_frame_cnt<fd_scratch_private_frame_max; }
FD_FN_PURE static inline int fd_scratch_pop_is_safe ( void ) { return !!fd_scratch_private_frame_cnt; }

FD_FN_PURE static inline int
fd_scratch_alloc_is_safe( ulong align,
                          ulong sz ) {
  if( FD_UNLIKELY( !fd_scratch_private_frame_cnt               ) ) return 0; /* No current frame */
  if( FD_UNLIKELY( !fd_scratch_private_align_is_valid( align ) ) ) return 0; /* Bad alignment, compile time typically */
  ulong true_align = fd_scratch_private_true_align( align ); /* compile time typically */
  ulong smem = fd_ulong_align_up( fd_scratch_private_free, true_align );
  if( FD_UNLIKELY( smem < fd_scratch_private_free ) ) return 0; /* alignment overflow */
  ulong free = smem + sz;
  if( FD_UNLIKELY( free < smem ) ) return 0; /* sz overflow */
  return free <= fd_scratch_private_stop;
}

FD_PROTOTYPES_END

#endif /* HEADER_src_util_scratch_fd_scratch_h */
