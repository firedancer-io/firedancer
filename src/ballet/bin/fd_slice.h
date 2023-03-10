#ifndef HEADER_fd_src_ballet_bin_fd_slice_h
#define HEADER_fd_src_ballet_bin_fd_slice_h

/* fd_slice provides APIs for traversing binary memory regions. */

#include "../../util/fd_util.h"

#define FD_SLICE_ALIGN     (32UL)
#define FD_SLICE_FOOTPRINT (32UL)

/* fd_slice_t points to a contiguous memory region at [ptr;end) in the
   local address space.  The same memory region may be aliased by
   multiple slices concurrently if all accesses to this region are
   read-only.  Slice reads or writes from a memory region that was
   written to from another thread are undefined without the appropriate
   data barriers.  The size of the memory region is `end-ptr` which may
   be zero, in which case the value of ptr and end is undefined. */

struct __attribute__((aligned(FD_SLICE_ALIGN))) fd_slice {
  void * ptr;
  void * end; /* invariant: end>=ptr */
  uint   flags;

  /* Reserved */
  uint   _unk_0x14;
  ulong  _unk_0x18;
};

typedef struct fd_slice fd_slice_t;

/* FD_SLICE_FLAG_OOB indicates that a previous slice API call could not
   be served as it would have attempted an out-of-bounds memory access. */

#define FD_SLICE_FLAG_OOB 0

FD_PROTOTYPES_BEGIN

/* fd_slice_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as a slice.
   fd_slice_align returns FD_SLICE_ALIGN.  fd_slice_footprint returns
   FD_SLICE_FOOTPRINT. */

FD_FN_CONST ulong
fd_slice_align( void );

FD_FN_CONST ulong
fd_slice_footprint( void );

/* fd_slice_new formats an unused memory region at `slice` for use as an
   fd_slice_t.  Assumes slice is a non-NULL pointer to this region in the
   local address space with the required footprint and alignment.
   Returns a pointer to the slice on success or NULL on failure (logs
   details).  On success, initializes the slice to point to an undefined
   memory region of zero sz.  Reasons for failure include that `slice` is
   NULL or misaligned. */

fd_slice_t *
fd_slice_new( void * slice );

/* FIXME ambiguous join semantic: is a zero sz slice joined to anything?
   fd_slice_join(slice,NULL,0UL) returns non-NULL by design */

/* fd_slice_join joins slice to a memory region and leaves the previously
   joined memory region. The range [mem;mem+sz) must be an addressable
   memory region in the local address space. Returns slice on success or
   NULL on failure (logs details). Reasons for failure include that mem
   is obviously not a local pointer or that sz is too large.  On
   successful return, fd_slice_t->ptr is set to `mem`, fd_slice_t->ptr
   points to the first unaddressable byte after the end
   of the target memory region, fd_slice_t->flags is zero.  The
   lifetime of this memory region and the join to slice is until the
   matching delete or caller's thread group is terminated. */

fd_slice_t *
fd_slice_join( fd_slice_t * slice,
               void *       mem,
               ulong        sz );

/* fd_slice_clone replicates the join of src onto dst and leaves the
   previous join in dst.  Returns dst. */

fd_slice_t *
fd_slice_clone( fd_slice_t * dst,
                fd_slice_t * src );

/* fd_slice_leave leaves a current local join to the slice memory region.
   On return, slice points to an undefined memory region of zero sz. */

fd_slice_t *
fd_slice_leave( fd_slice_t * slice );

/* fd_slice_delete leaves a current local join to `slice`.  Returns a
   pointer to the memory region that stored the `fd_slice_t`. */

void *
fd_slice_delete( fd_slice_t * slice );

/* fd_slice_sz returns the size of the slice memory region. */

FD_FN_PURE static inline ulong
fd_slice_sz( fd_slice_t const * slice ) {
  return (ulong)slice->end - (ulong)slice->ptr;
}

/* fd_slice_isoob returns non-zero if FD_SLICE_FLAG_OOB is set. */

FD_FN_PURE static inline uint
fd_slice_isoob( fd_slice_t const * slice ) {
  return slice->flags & (1U<<FD_SLICE_FLAG_OOB);
}

/* fd_slice_clearerr clears all errors (such as FD_SLICE_FLAG_OOB). */

static inline fd_slice_t *
fd_slice_clearerr( fd_slice_t * slice ) {
  slice->flags = 0UL;
  return slice;
}

/* fd_slice_peek returns a pointer of the subrange of the slice memory
   region at [slice->mem+off;slice->mem+off+sz).  Returns pointer to
   first byte of subrange on success or NULL on failure. Reasons for
   failure include that subslice is out-of-bounds for the given {off,sz}
   params.  Return value is undefined if sz is zero. */

static inline void *
fd_slice_peek( fd_slice_t * slice,
               ulong        off,
               ulong        sz ) {

  ulong const ptr     = (ulong)slice->ptr;
  ulong const end     = (ulong)slice->end;

  ulong const ptr_new = ptr     + off;
  ulong const end_new = ptr_new + sz;

  if( FD_UNLIKELY( off+sz<off || end_new<ptr || end_new>end ) )
    return NULL;

  return (void *)ptr_new;
}

/* fd_slice_subslice joins slice to a subrange of its memory region of at
   [slice->mem+off;slice->mem+off+sz) and leaves previous join.  Reset
   flags. Returns slice on success or NULL on failure.  On success,
   fd_slice_sz(sz)==sz. Reasons for failure include that the slice is
   NULL (logs warning) or that new subslice is out-of-bounds for the
   given {off,sz} params (sets FD_SLICE_FLAG_OOB on slice). */

fd_slice_t *
fd_slice_subslice( fd_slice_t * slice,
                   ulong        off,
                   ulong        sz );

/* fd_slice_advance advances the start of slice by sz bytes.
   Returns the previous slice ptr on success or returns NULL and sets
   FD_SLICE_FLAG_OOB if sz exceeds fd_slice_sz(slice). */

void *
fd_slice_advance( fd_slice_t * slice,
                  ulong        sz );

/* fd_slice_read_{uchar,ushort,uint,ulong} read a little-endian
   unaligned integer value from the start of slice and advance slice
   to next byte beyond.  Returns the integer value on success or sets
   FD_SLICE_FLAG_OOB and returns zero on failure. */

static inline uchar
fd_slice_read_uchar( fd_slice_t * slice ) {
  void * p = fd_slice_advance( slice, sizeof(uchar) );
  if( FD_UNLIKELY( !p ) ) return 0U;

  return fd_uchar_load_1( p );
}

static inline ushort
fd_slice_read_ushort( fd_slice_t * slice ) {
  void * p = fd_slice_advance( slice, sizeof(ushort) );
  if( FD_UNLIKELY( !p ) ) return 0U;

  return fd_ushort_load_2( p );
}

static inline uint
fd_slice_read_uint( fd_slice_t * slice ) {
  void * p = fd_slice_advance( slice, sizeof(uint) );
  if( FD_UNLIKELY( !p ) ) return 0U;

  return fd_uint_load_4( p );
}

static inline ulong
fd_slice_read_ulong( fd_slice_t * slice ) {
  void * p = fd_slice_advance( slice, sizeof(ulong) );
  if( FD_UNLIKELY( !p ) ) return 0U;

  return fd_ulong_load_8( p );
}

/* fd_slice_read_{ushort,uint,ulong}_be are the big-endian
   variants of fd_slice_read_{ushort,uint,ulong}. */

static inline ushort fd_slice_read_ushort_be( fd_slice_t * s ) { return fd_ushort_bswap( fd_slice_read_ushort( s ) ); }
static inline uint   fd_slice_read_uint_be  ( fd_slice_t * s ) { return fd_uint_bswap  ( fd_slice_read_uint  ( s ) ); }
static inline ulong  fd_slice_read_ulong_be ( fd_slice_t * s ) { return fd_ulong_bswap ( fd_slice_read_ulong ( s ) ); }

FD_PROTOTYPES_END

#endif
