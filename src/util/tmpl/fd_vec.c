/* Declare vectors of bounded run-time maximum size suitable for
   persistent and IPC usage.  Designed for POD types that have a trivial
   copy operator. Typical usage:

     #define VEC_NAME myvec
     #define VEC_T    myvec_t
     #include "util/tmpl/fd_vec.c"

   will declare the following static inline APIs as a header only style
   library in the compilation unit: 

     // align/footprint - Return the alignment/footprint required for a
     // memory region to be used as vector that can hold up to max
     // events.  footprint returns 0 if max is so large that the
     // footprint would overflow ULONG_MAX.
     //
     // new - Format a memory region pointed to by shmem into a myvec
     // vector.  Assumes shmem points to a region with the required
     // alignment and footprint not in use by anything else.  Caller is
     // not joined on return.  Returns shmem on success or NULL on
     // failure (e.g. shmem or max are obviously bad).
     //
     // join - Join a myvec vector.  Assumes shvec points at a region
     // formatted as an vector.  Returns a pointer in the caller's
     // address space to a memory region indexed [0,max) where elements
     // [0,cnt) are currently in use on success and NULL on failure
     // (e.g.  shmem is obviously bad).  THIS IS NOT JUST A SIMPLE CAST
     // OF SHVEC.
     //
     // leave - Leave a myvec vector.  Assumes join points to a current
     // local join.  Returns a pointer to the shared memory region the
     // join on success and NULL on failure.  THIS IS NOT JUST A SIMPLE
     // CAST OF JOIN.
     //
     // delete - Unformat a memory region used as myvec vector.  Assumes
     // myvec vector points to a formatted region with no current joins.
     // Returns a pointer to the unformatted memory region.

     ulong     myvec_align    ( void      );
     ulong     myvec_footprint( ulong max );
     void *    myvec_new      ( void *    shmem, ulong max );
     myvec_t * myvec_join     ( void *    shvec );
     void *    myvec_leave    ( myvec_t * join  );
     void *    myvec_delete   ( void *    shvec );

     // All the below APIs assume join is a current local join.

     // myvec_max returns the maximum number of elements in a myvec vector.
     // myvec_cnt returns the current number of elements, in [0,max]
     // myvec_free     = max - cnt
     // myvec_is_empty = (cnt==0)
     // myvec_is_full  = (cnt==max)

     ulong myvec_max( myvec_t const * join );
     ulong myvec_cnt     ( myvec_t const * join );
     ulong myvec_free    ( myvec_t const * join );
     int   myvec_is_empty( myvec_t const * join );
     int   myvec_is_full ( myvec_t const * join );

     // myvec_expand increases the number of elements in a vector by
     // delta.  The new elements will be indexed [cnt,cnt+delta) Returns
     // a pointer to the delta (uninitialized) new elements.  IMPORTANT!
     // AS THIS IS USED IN HPC CONTEXTS, ASSUMES CALLER KNOWS THERE ARE
     // DELTA AT LEAST DELTA ELEMENTS FREE (I.E. DELTA IS IN [0,FREE].
     //
     // myvec_contract decreases the number of elements in a vector by
     // delta.  The elements removed are indexed [cnt-delta,cnt).
     // Returns a pointer to delta removed elements.  IMPORTANT!  AS
     // THIS IS USED IN HPC CONTEXTS, ASSUMES CALLER KNOWS THERE ARE
     // DELTA AT LEAST DELTA ELEMENTS PRESENT (I.E.  DELTA IS IN
     // [0,CNT].

     myvec_t * myvec_expand  ( myvec_t * join, ulong delta );
     myvec_t * myvec_contract( myvec_t * join, ulong delta );

     // myvec_remove removes the element at index by backfilling the
     // last element into element idx.  This is an O(1) operation.
     // Returns join.  IMPORTANT!  AS THIS IS USED IN HPC CONTEXTS,
     // ASSUMES CALLER KNOWS IDX IS A CURRENT ELEMENT.  THAT IS, IDX IS
     // IN [0,CNT).

     myvec_t * myvec_remove( myvec_t * join, ulong idx );
     
     // myvec_remove_compact remove element at idx by compaction.  While
     // this is preserves operating, this is an O(cnt-idx-1) operation
     // and it is very easily to accidentally create O(N^2)
     // if using compaction.  IMPORTANT!  AS THIS IS USED IN HPC
     // CONTEXTS, ASSUMES CALLER KNOWS IDX IS A CURRENT ELEMENT.  THAT
     // IS, IDX IS IN [0,CNT).

     myvec_t * myvec_remove_compact( myvec_t * join, ulong idx );

     // TODO: CONSIDER ADDING OTHER APIS LIKE SHUFFLE AND WHAT NOT?

     You can do this as often as you like in a compilation unit to get
     different types of vectors.  Since it is all static inline, it is
     fine to do this in a header too.  Additional options to fine tune
     this are detailed below. */

#ifndef VEC_NAME
#define "Define VEC_NAME"
#endif

#ifndef VEC_T
#define "Define VEC_T"
#endif

// TODO: CONSIDER LETTING USER SPECIFY COPY AND MOVE?

#define VEC_(n) FD_EXPAND_THEN_CONCAT3(VEC_NAME,_,n)

struct VEC_(private) {
  ulong max; /* Arbitrary */
  ulong cnt; /* In [0,max) */
};

typedef struct VEC_(private) VEC_(private_t);

FD_FN_CONST static inline VEC_(private_t) *
VEC_(private)( VEC_T * join ) {
  return (VEC_(private_t) *)(((ulong)join) - sizeof(VEC_(private_t)));
}

FD_FN_CONST static inline VEC_(private_t) const *
VEC_(private_const)( VEC_T const * join ) {
  return (VEC_(private_t) const *)(((ulong)join) - sizeof(VEC_(private_t)));
}

FD_FN_CONST static inline ulong
VEC_(align)( void ) {
  return fd_ulong_max( alignof(VEC_T), 128UL );
}

FD_FN_CONST static inline ulong
VEC_(private_meta_footprint)( void ) {
  return fd_ulong_align_up( sizeof(VEC_(private_t)), VEC_(align)() );
}

FD_FN_CONST static inline ulong
VEC_(footprint)( ulong max ) {
  ulong align          = VEC_(align)();
  ulong meta_footprint = VEC_(private_meta_footprint)(); /* Multiple of align */
  ulong data_footprint = fd_ulong_align_up( sizeof(VEC_T)*max, align );
  ulong thresh         = (ULONG_MAX - align - meta_footprint + 1UL) / sizeof(VEC_T);
  return fd_ulong_if( max > thresh, 0UL, meta_footprint + data_footprint );
}

static inline void *
VEC_(new)( void * shmem,
           ulong  max ) {

  if( FD_UNLIKELY( !shmem ) ) return NULL;

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, VEC_(align)() ) ) ) return NULL;

  if( FD_UNLIKELY( !VEC_(footprint)( max ) ) ) return NULL;

  VEC_(private_t) * join = VEC_(private)( (VEC_T *)(((ulong)shmem) + VEC_(private_meta_footprint)()) );
  join->max = max;
  join->cnt = 0UL;
  return shmem;
}

FD_FN_CONST static inline VEC_T *
VEC_(join)( void * shvec ) {

  if( FD_UNLIKELY( !shvec ) ) return NULL;

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shvec, VEC_(align)() ) ) ) return NULL;

  return (VEC_T *)(((ulong)shvec) + VEC_(private_meta_footprint)());
}

FD_FN_CONST static inline void *
VEC_(leave)( VEC_T * join ) {

  if( FD_UNLIKELY( !join ) ) return NULL;

  return (void *)(((ulong)join) - VEC_(private_meta_footprint)());
}

FD_FN_CONST static inline void *
VEC_(delete)( void * shvec ) {

  if( FD_UNLIKELY( !shvec ) ) return NULL;

  return shvec;
}

FD_FN_PURE static inline ulong VEC_(max)( VEC_T const * join ) { return  VEC_(private_const)( join )->max; }
FD_FN_PURE static inline ulong VEC_(cnt)( VEC_T const * join ) { return  VEC_(private_const)( join )->cnt; }

FD_FN_PURE static inline ulong
VEC_(free)( VEC_T const * join ) {
  VEC_(private_t) const * vec = VEC_(private_const)( join );
  return vec->max - vec->cnt;
}

FD_FN_PURE static inline int VEC_(is_empty)( VEC_T const * join ) { return !VEC_(private_const)( join )->cnt; }

FD_FN_PURE static inline int
VEC_(is_full) ( VEC_T const * join ) {
  VEC_(private_t) const * vec = VEC_(private_const)( join );
  return vec->cnt==vec->max;
}

static inline VEC_T *
VEC_(expand)( VEC_T * join,
              ulong   delta ) {
  VEC_(private_t) * vec = VEC_(private)( join );
  ulong cnt = vec->cnt;
  vec->cnt = cnt + delta;
  return join + cnt;
}

static inline VEC_T *
VEC_(contract)( VEC_T * join,
                ulong   delta ) {
  VEC_(private_t) * vec = VEC_(private)( join );
  ulong cnt = vec->cnt - delta;
  vec->cnt = cnt;
  return join + cnt;
}

static inline VEC_T *
VEC_(remove)( VEC_T * join,
              ulong   idx ) {
  VEC_(private_t) * vec = VEC_(private)( join );
  ulong cnt = vec->cnt - 1UL;
  join[idx] = join[cnt]; /* TODO: Consider letting user decide if self copy is cheaper than testing */
  vec->cnt = cnt;
  return join;
}

static inline VEC_T *
VEC_(remove_compact)( VEC_T * join,
                      ulong   idx ) {
  VEC_(private_t) * vec = VEC_(private)( join );
  ulong cnt = vec->cnt - 1UL;
  for( ; idx<cnt; idx++ ) join[idx] = join[idx+1UL];
  vec->cnt = cnt;
  return join;
}

#undef VEC_

#undef VEC_T
#undef VEC_NAME

