/* Generate prototypes, inlines and/or implementations for concurrent
   persistent shared element pools.  A pool can hold a practically
   unbounded number of elements.  Acquiring an element from and
   releasing an element to a pool are typically fast O(1) time.
   Requires small O(1) space per element.

   The current implementation is based on a lockfree stack.  Acquire and
   release are done via atomic compare-and-swap of the stack top.  As
   such, concurrent usage requires FD_HAS_ATOMIC support (this can still
   be used on platforms without FD_HAS_ATOMIC but it will not be safe
   for concurrent usage).  Stack top versioning is used to handle ABA.
   Versioning has been tweaked to support locked pool operations like
   initialization (and thus this can also be used without changes as a
   more conventional spin lock based concurrent stack).  Unsurprisingly,
   the current implementation is equally usable as a concurrent element
   stack (though the implementation may be changed in the future to
   better support ultra high contention ultra high concurrency ala
   fd_alloc).

   The current implementation is optimized for pools with a moderate
   number of reasonably localized users (e.g. a handful of cores and
   memory on the same NUMA node).  Various operations are slightly more
   optimal when the size of a pool element is an integer power of 2.
   Operations do much internal integrity checking / bounds checking for
   use in high reliability / high security environments.

   This API is designed for tight and flexible composition with treaps,
   heaps, lists, maps, etc.  Further, a pool can be persisted beyond the
   lifetime of the creating process, be used inter-process, be relocated
   in memory, be naively serialized/deserialized, be moved between
   hosts, use index compression for cache and memory bandwidth
   efficiency, etc.

   Typical usage:

     struct myele {
       ulong next; // Technically "POOL_IDX_T POOL_NEXT" (default is ulong next), managed by the mypool when in the mypool

       ... next can be located arbitrarily in the element and can be
       ... reused for other purposes when the element is not in a
       ... mypool.  elements are all located in a linear array element
       ... store whose lifetime is at least that of the mypool.

     };

     typedef struct myele myele_t;

     #define POOL_NAME  mypool
     #define POOL_ELE_T myele_t
     #include "tmpl/fd_pool_para.c"

   will declare the following APIs as a header only style library in the
   compilation unit:

     // A mypool_t is a stack declaration friendly quasi-opaque handle
     // used to describe a join to a mypool.  E.g. it is fine to do
     // "mypool_t join[1];" to allocate a mypool_t but the contents
     // should be used directly.

     typedef struct mypool_private mypool_t;

     // Constructors

     // mypool_ele_max_max returns the maximum element store capacity
     // compatible with a mypool.

     ulong mypool_ele_max_max( void );

     // mypool_{align,footprint} returns the alignment and footprint
     // needed for a memory region to be used as a mypool.  align will
     // be an integer power-of-two and footprint will be a multiple of
     // align.
     //
     // mypool_new formats a memory region with the appropriate
     // alignment and footprint into a mypool.  shmem points in the
     // caller's address space of the memory region to format.  Returns
     // shmem on success (mypool has ownership of the memory region) and
     // NULL on failure (no changes, logs details).  Caller is not
     // joined on return.  The mypool will be empty and unlocked.
     //
     // mypool_join joins a mypool.  ljoin points to a mypool_t
     // compatible memory region in the caller's address space used to
     // hold info about the local join, shpool points in the caller's
     // address space to the memory region containing the mypool, shele
     // points in the caller's address space to mypool's element store,
     // and ele_max is the element store's capacity.  Returns a handle
     // to the caller's local join on success (join has ownership of the
     // ljoin region) and NULL on failure (no changes, logs details).
     //
     // mypool_leave leaves a mypool.  join points to a current local
     // join.  Returns the memory used for the local join (caller has
     // ownership on return and caller is no longer joined) on success
     // and NULL on failure (no changes, logs details).  Use the join
     // accessors before leaving to get shpool, shele and ele_max used
     // by the join if needed.
     //
     // mypool_delete unformats a memory region used as a mypool.
     // Assumes shpool points in the caller's address space to the
     // memory region containing the mypool and that there are no
     // current joins globally.  Returns shpool on success (caller has
     // ownership of the memory region and any elements still in the
     // mypool are acquired by the caller) and NULL on failure (no
     // changes, logs details).

     ulong      mypool_align    ( void );
     ulong      mypool_footprint( void );
     void *     mypool_new      ( void *     shmem );
     mypool_t * mypool_join     ( void *     ljoin, void * shpool, void * shele, ulong ele_max );
     void *     mypool_leave    ( mypool_t * join );
     void *     mypool_delete   ( void *     shpool );

     // mypool_{shpool,shele,ele_max} return join details.  Assumes join
     // is a current local join.  mypool_{shpool_const,shele_const} are
     // const correct versions.  The lifetime of the returned pointers
     // is the lifetime of the join.

     void const * mypool_shpool_const( mypool_t const * join );
     void const * mypool_shele_const ( mypool_t const * join );
     ulong        mypool_ele_max     ( mypool_t const * join );

     void * mypool_shpool( mypool_t * join );
     void * mypool_shele ( mypool_t * join );

     // mypool_idx_null returns the element store index used to
     // represent null for a mypool.
     //
     // mypool_idx_is_null returns 1 if an element store index is the
     // null index value and 0 otherwise.
     //
     // mypool_idx returns the element store index for the element
     // pointed to by ele in the caller's address space.  Assumes join
     // is a current local join.  If ele is NULL or not into the element
     // store, returns the element store null index.
     //
     // mypool_ele returns a pointer in the caller's address space to
     // the element whose element store index is ele_idx.  If ele_idx is
     // the null value or invalid, returns NULL.  mypool_ele_const is a
     // const correct version.
     //
     // These are usually not needed but allow translating pointers to
     // element store elements from one address space to another.

     ulong mypool_idx_null   ( void );
     int   mypool_idx_is_null( ulong idx );
     ulong mypool_idx        ( mypool_t const * join, myele_t const * ele );

     myele_t const * mypool_ele_const( mypool_t const * join, ulong ele_idx );
     myele_t *       mypool_ele      ( mypool_t *       join, ulong ele_idx );

     // mypool_peek returns a pointer in the local address space to the
     // next element to acquire from the mypool or NULL if the mypool
     // was empty at some point during the call.  mypool_peek_const is a
     // const correct version.  Because of concurrent operations, unless
     // the caller is holding a lock on the mypool, this may not be the
     // actual element the caller will acquire next from the mypool.

     myele_t const * mypool_peek_const( mypool_t const * join );
     myele_t *       mypool_peek      ( mypool_t       * join );

     // mypool_acquire acquires an element from a mypool.  Assumes join
     // is a current local join.  If the mypool is empty or an error
     // occurs, returns sentinel (arbitrary).  A non-zero / zero value
     // for blocking indicates locked operations on the mypool are / are
     // not allowed to block the caller.  If opt_err is not NULL, on
     // return, *_opt_err will indicate FD_POOL_SUCCESS (zero) or an
     // FD_POOL_ERR code (negative).  On success, the returned value
     // will be a pointer in the caller's address space to the element
     // store element acquired from the mypool.  On failure for any
     // reason, the value returned will be sentinel and the mypool will
     // be unchanged.  Reasons for failure:
     //
     // FD_POOL_ERR_EMPTY: the mypool contained no elements at some
     // point during the call.
     //
     // FD_POOL_ERR_AGAIN: the mypool was locked at some point during
     // the call.  Never returned for a blocking call (but then locking
     // operations can then potentially block the caller indefinitely).
     //
     // FD_POOL_ERR_CORRUPT: memory corruption was detected during the
     // call.

     myele_t * mypool_acquire( mypool_t * join, myele_t * sentinel, int blocking, int * _opt_err );

     // mypool_release releases an element to a mypoool.  Assumes join
     // is a current local join, ele is a pointer in the caller's
     // address space to the element, and the element is currently not
     // in the mypool.  Returns FD_POOL_SUCCESS (zero) on success (the
     // element will be in the mypool on return) and an FD_POOL_ERR code
     // (negative) on failure (the element will not be in the mypool on
     // return).  Reasons for failure:
     //
     // FD_POOL_ERR_INVAL: ele does not point to an element in mypool's
     // element store.
     //
     // FD_POOL_ERR_AGAIN: the mypool was locked at some point during
     // the call.  Never returned for a blocking call (but locking
     // operations can then potentially block the caller indefinitely).
     //
     // FD_POOL_ERR_CORRUPT: memory corruption was detected during the
     // call.

     int mypool_release( mypool_t * join, myele_t * ele, int blocking );

     // mypool_is_locked returns whether or not a mypool is locked.
     // Assumes join is a current local join.

     int mypool_is_locked( mypool_t const * join );

     // mypool_lock will lock a mypool (e.g. pausing concurrent acquire
     // / release operations).  A non-zero / zero value for blocking
     // indicates the call should / should not wait to lock the mypool
     // if it is currently locked.  Returns FD_POOL_SUCCESS on success
     // (caller has the lock on return) and FD_POOL_ERR_AGAIN on failure
     // (pool was already locked at some point during the call).  AGAIN
     // is never returned if blocking is requested.  Assumes join is a
     // current local join.

     int mypool_lock( mypool_t * join, int blocking );

     // mypool_unlock will unlock a mypool (e.g. resuming concurrent
     // acquire / release operations).  Assumes join is a current local
     // join and the caller has a lock on mypool.  Guaranteed to
     // succeed.

     void mypool_unlock( mypool_t * join );

     // mypool_reset resets the mypool.  On return, it will hold all but
     // the leading sentinel_cnt elements in the element store (e.g.
     // initialization after creation) in ascending order.  If
     // sentinel_cnt is greater than or equal to the element store
     // capacity, the mypool will be empty on return.  Thus, on return,
     // if sentinel_cnt is zero, every element in the element store will
     // be in the mypool and, if sentinel_cnt is ele_max or greater
     // (e.g. ULONG_MAX), every element will be removed from the mypool.
     // Assumes join is a current local join and the mypool is locked or
     // otherwise idle.

     void mypool_reset( mypool_t * join, ulong sentinel_cnt );

     // mypool_verify returns FD_POOL_SUCCESS if join appears to be
     // current local join to a valid mypool and FD_POOL_ERR_CORRUPT
     // otherwise (logs details).  Assumes join is a current local join
     // and the mypool is locked or otherwise idle.

     int mypool_verify( mypool_t const * join );

     // mypool_strerror converts an FD_POOL_SUCCESS / FD_POOL_ERR code
     // into a human readable cstr.  The lifetime of the returned
     // pointer is infinite.  The returned pointer is always to a
     // non-NULL cstr.

     char const * mypool_strerror( int err );

   Do this as often as desired in a compilation unit to get different
   types of concurrent pools.  Options exist for generating library
   header prototypes and/or library implementations for concurrent pools
   usable across multiple compilation units.  Additional options exist
   to use index compression, configuring versioning, etc. */

/* POOL_NAME gives the API prefix to use for pool */

#ifndef POOL_NAME
#error "Define POOL_NAME"
#endif

/* POOL_ELE_T is the pool element type. */

#ifndef POOL_ELE_T
#error "Define POOL_ELE_T"
#endif

/* POOL_IDX_T is the type used for the next field in the POOL_ELE_T.
   Should be a primitive unsigned integer type.  Defaults to ulong.  A
   pool can't use element stores with a capacity that can't be
   represented by a POOL_IDX_T.  (E.g. if ushort, the maximum capacity
   pool compatible element store is 65535 elements.) */

#ifndef POOL_IDX_T
#define POOL_IDX_T ulong
#endif

/* POOL_NEXT is the POOL_ELE_T next field */

#ifndef POOL_NEXT
#define POOL_NEXT next
#endif

/* POOL_ALIGN gives the alignment required for the pool shared memory.
   Default is 128 for double cache line alignment.  Should be at least
   ulong alignment. */

#ifndef POOL_ALIGN
#define POOL_ALIGN (128UL)
#endif

/* POOL_IDX_WIDTH gives the number of bits in a ulong to reserve for
   encoding the element store index in a versioned index.  Element store
   capacity should be representable in this width.  Default is 43 bits
   (e.g. enough to support a ~1 PiB element store of 128 byte elements).
   The versioning width will be 64-POOL_IDX_WIDTH.  Since the least
   significant bit of the version is used to indicate global locking,
   versioning width should be at least 2 and ideally as large as
   possible.  With the 43 default, version numbers will not be reused
   until 2^20 individual operations have been done. */

#ifndef POOL_IDX_WIDTH
#define POOL_IDX_WIDTH (43)
#endif

/* POOL_MAGIC is the magic number to use for the structure to aid in
   persistent and or IPC usage. */

#ifndef POOL_MAGIC
#define POOL_MAGIC (0xf17eda2c37c90010UL) /* firedancer cpool version 0 */
#endif

/* POOL_IMPL_STYLE controls what to generate:
     0 - local use only
     1 - library header declaration
     2 - library implementation */

#ifndef POOL_IMPL_STYLE
#define POOL_IMPL_STYLE 0
#endif

/* POOL_LAZY enables lazy initialization for faster startup if defined
   to non-zero.  Decreases pool_reset cost from O(ele_max) to O(1), at
   the cost of more complex allocation logic. */

#ifndef POOL_LAZY
#define POOL_LAZY 0
#endif

/* Common pool error codes (FIXME: probably should get around to making
   unified error codes and string handling across all util at least so
   we don't have to do this in the generator itself) */

#define FD_POOL_SUCCESS     ( 0)
#define FD_POOL_ERR_INVAL   (-1)
#define FD_POOL_ERR_AGAIN   (-2)
#define FD_POOL_ERR_CORRUPT (-3)
#define FD_POOL_ERR_EMPTY   (-4)
//#define FD_POOL_ERR_FULL    (-5)
//#define FD_POOL_ERR_KEY     (-6)

/* Implementation *****************************************************/

#define POOL_VER_WIDTH (64-POOL_IDX_WIDTH)

#if POOL_IMPL_STYLE==0 /* local use only */
#define POOL_STATIC FD_FN_UNUSED static
#else /* library header and/or implementation */
#define POOL_STATIC
#endif

#define POOL_(n) FD_EXPAND_THEN_CONCAT3(POOL_NAME,_,n)

#if POOL_IMPL_STYLE!=2 /* need header */

#include "../bits/fd_bits.h"

struct __attribute__((aligned(POOL_ALIGN))) POOL_(shmem_private) {

  /* Note: there is no free count because that that isn't precisely
     knowable in a portable concurrent data structure.  (Not enough bits
     to squeeze into ver_top for large pools, requiring 128-bit wide
     ver_top would limit supported targets, etc). */

  ulong magic;   /* == POOL_MAGIC */
  ulong ver_top; /* Versioned index of the free stack top, top is in [0,ele_max) (not-empty) or is idx_null (empty) */

# if POOL_LAZY
  ulong ver_lazy; /* Versioned index of the lazy init, lazy is in [0,ele_max] (not-empty) or is idx_null (empty) */
# endif

};

typedef struct POOL_(shmem_private) POOL_(shmem_t);

struct POOL_(private) {
  POOL_(shmem_t) * pool;    /* Pool location in the local address space */
  POOL_ELE_T *     ele;     /* Element store location in the local address space, NULL okay if ele_max==0 */
  ulong            ele_max; /* Element store capacity, in [0,ele_max_max] */
};

typedef struct POOL_(private) POOL_(t);

FD_PROTOTYPES_BEGIN

/* pool_private_vidx pack ver and idx into a versioned idx.  ver is
   masked to fit into POOL_VER_WIDTH bits.  idx is assumed in
   [0,ele_max_max].

   pool_private_vidx_{ver,idx} extract the {version,index} from a
   versioned index and will fit into {POOL_VER_WIDTH,POOL_IDX_WIDTH}
   bits. */

FD_FN_CONST static inline ulong POOL_(private_vidx)( ulong ver, ulong idx ) { return (ver<<POOL_IDX_WIDTH) | idx; }

FD_FN_CONST static inline ulong POOL_(private_vidx_ver)( ulong ver_idx ) { return ver_idx >> POOL_IDX_WIDTH;  }
FD_FN_CONST static inline ulong POOL_(private_vidx_idx)( ulong ver_idx ) { return (ver_idx << POOL_VER_WIDTH) >> POOL_VER_WIDTH; }

/* pool_private_{cidx,idx} compress/decompress a 64-bit in-register
   index to/from its in-memory representation. */

FD_FN_CONST static inline POOL_IDX_T POOL_(private_cidx)( ulong  idx ) { return (POOL_IDX_T) idx; }
FD_FN_CONST static inline ulong      POOL_(private_idx) ( ulong cidx ) { return (ulong)     cidx; }

/* pool_private_cas does a ulong FD_ATOMIC_CAS when FD_HAS_ATOMIC
   support is available and emulates it when not.  Similarly for
   pool_private_fetch_and_or.  When emulated, the pool will not be safe
   to use concurrently (but will still work). */

static inline ulong
POOL_(private_cas)( ulong volatile * p,
                    ulong            c,
                    ulong            s ) {
  ulong o;
  FD_COMPILER_MFENCE();
# if FD_HAS_ATOMIC
  o = FD_ATOMIC_CAS( p, c, s );
# else
  o = *p;
  *p = fd_ulong_if( o==c, s, o );
# endif
  FD_COMPILER_MFENCE();
  return o;
}

static inline ulong
POOL_(private_fetch_and_or)( ulong volatile * p,
                             ulong            b ) {
  ulong x;
  FD_COMPILER_MFENCE();
# if FD_HAS_ATOMIC
  x = FD_ATOMIC_FETCH_AND_OR( p, b );
# else
  x = *p;
  *p = x | b;
# endif
  FD_COMPILER_MFENCE();
  return x;
}

FD_FN_CONST static inline ulong POOL_(ele_max_max)( void ) { return (ulong)(POOL_IDX_T)(ULONG_MAX >> POOL_VER_WIDTH); }

FD_FN_CONST static inline ulong POOL_(align)    ( void ) { return alignof(POOL_(shmem_t)); }
FD_FN_CONST static inline ulong POOL_(footprint)( void ) { return sizeof (POOL_(shmem_t)); }

FD_FN_PURE  static inline void const * POOL_(shpool_const)( POOL_(t) const * join ) { return join->pool;    }
FD_FN_PURE  static inline void const * POOL_(shele_const) ( POOL_(t) const * join ) { return join->ele;     }
FD_FN_PURE  static inline ulong        POOL_(ele_max)     ( POOL_(t) const * join ) { return join->ele_max; }

FD_FN_PURE  static inline void * POOL_(shpool)( POOL_(t) * join ) { return join->pool; }
FD_FN_PURE  static inline void * POOL_(shele) ( POOL_(t) * join ) { return join->ele;  }

FD_FN_CONST static inline ulong POOL_(idx_null)( void ) { return (ulong)(POOL_IDX_T)(ULONG_MAX >> POOL_VER_WIDTH); }
FD_FN_CONST static inline int   POOL_(idx_is_null)( ulong idx ) { return idx==POOL_(idx_null)(); }

FD_FN_PURE static inline ulong
POOL_(idx)( POOL_(t)   const * join,
            POOL_ELE_T const * ele ) {
  ulong  ele_idx = (ulong)(ele - join->ele);
  return ele_idx<join->ele_max ? ele_idx : POOL_(idx_null)();
}

FD_FN_PURE static inline POOL_ELE_T const *
POOL_(ele_const)( POOL_(t) const * join,
                  ulong            ele_idx ) {
  POOL_ELE_T const * ele = join->ele;
  return (ele_idx < join->ele_max) ? (ele + ele_idx) : NULL;
}

FD_FN_PURE static inline POOL_ELE_T *
POOL_(ele)( POOL_(t) * join,
            ulong      ele_idx ) {
  POOL_ELE_T * ele = join->ele;
  return (ele_idx < join->ele_max) ? (ele + ele_idx) : NULL;
}

static inline POOL_ELE_T const *
POOL_(peek_const)( POOL_(t) const * join ) {
  POOL_(shmem_t) const * pool    = join->pool;
  POOL_ELE_T     const * ele     = join->ele;
  ulong                  ele_max = join->ele_max;
  FD_COMPILER_MFENCE();
  ulong ver_top  = pool->ver_top;
# if POOL_LAZY
  ulong ver_lazy = pool->ver_lazy;
# endif
  FD_COMPILER_MFENCE();
  ulong ele_idx = POOL_(private_vidx_idx)( ver_top );
# if POOL_LAZY
  if( ele_idx<ele_max ) {
    return ele + ele_idx;
  } else {
    ulong lazy_idx = POOL_(private_vidx_idx)( ver_lazy );
    return (lazy_idx<ele_max) ? ele + lazy_idx : NULL;
  }
# else
  return (ele_idx<ele_max) ? ele + ele_idx : NULL;
# endif
}

static inline POOL_ELE_T * POOL_(peek)( POOL_(t) * join ) { return (POOL_ELE_T *)POOL_(peek_const)( join ); }

static inline int
POOL_(is_locked)( POOL_(t) const * join ) {
  POOL_(shmem_t) const * pool = join->pool;
  FD_COMPILER_MFENCE();
  ulong ver_top  = pool->ver_top;
# if POOL_LAZY
  ulong ver_lazy = pool->ver_lazy;
# endif
  FD_COMPILER_MFENCE();
  return
      (int)(POOL_(private_vidx_ver)( ver_top  ) & 1UL)
# if POOL_LAZY
    | (int)(POOL_(private_vidx_ver)( ver_lazy ) & 1UL)
# endif
  ;
}

static inline void
POOL_(unlock)( POOL_(t) * join ) {
  POOL_(shmem_t) * pool = join->pool;
  FD_COMPILER_MFENCE();
  pool->ver_top  += 1UL<<POOL_IDX_WIDTH;
# if POOL_LAZY
  pool->ver_lazy += 1UL<<POOL_IDX_WIDTH;
# endif
  FD_COMPILER_MFENCE();
}

POOL_STATIC void *     POOL_(new)   ( void *     shmem );
POOL_STATIC POOL_(t) * POOL_(join)  ( void *     ljoin, void * shpool, void * shele, ulong  ele_max );
POOL_STATIC void *     POOL_(leave) ( POOL_(t) * join );
POOL_STATIC void *     POOL_(delete)( void *     shpool );

POOL_STATIC POOL_ELE_T * POOL_(acquire)( POOL_(t) * join, POOL_ELE_T * sentinel, int blocking, int * _opt_err );

POOL_STATIC int POOL_(release)( POOL_(t) * join, POOL_ELE_T * ele, int blocking );

POOL_STATIC int POOL_(is_empty)( POOL_(t) * join );

POOL_STATIC int POOL_(lock)( POOL_(t) * join, int blocking );

POOL_STATIC void POOL_(reset)( POOL_(t) * join, ulong sentinel_cnt );

POOL_STATIC int POOL_(verify)( POOL_(t) const * join );

POOL_STATIC FD_FN_CONST char const * POOL_(strerror)( int err );

FD_PROTOTYPES_END

#endif

#if POOL_IMPL_STYLE!=1 /* need implementations (assumes header already included) */

#include "../log/fd_log.h" /* used by constructors and verify (FIXME: Consider making a compile time option) */

POOL_STATIC void *
POOL_(new)( void * shmem ) {
  POOL_(shmem_t) * pool = (POOL_(shmem_t) *)shmem;

  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)pool, POOL_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  pool->ver_top  = POOL_(private_vidx)( 0UL, POOL_(idx_null)() );
# if POOL_LAZY
  pool->ver_lazy = POOL_(private_vidx)( 0UL, POOL_(idx_null)() );
# endif

  FD_COMPILER_MFENCE();
  pool->magic = POOL_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)pool;
}

POOL_STATIC POOL_(t) *
POOL_(join)( void * ljoin,
             void * shpool,
             void * shele,
             ulong  ele_max ) {
  POOL_(t)       * join = (POOL_(t)       *)ljoin;
  POOL_(shmem_t) * pool = (POOL_(shmem_t) *)shpool;
  POOL_ELE_T     * ele  = (POOL_ELE_T     *)shele;

  if( FD_UNLIKELY( !join ) ) {
    FD_LOG_WARNING(( "NULL ljoin" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)join, alignof(POOL_(t)) ) ) ) {
    FD_LOG_WARNING(( "misaligned ljoin" ));
    return NULL;
  }

  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_WARNING(( "NULL shpool" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)pool, POOL_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shpool" ));
    return NULL;
  }

  if( FD_UNLIKELY( pool->magic!=POOL_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  if( FD_UNLIKELY( (!ele) & (!!ele_max) ) ) {
    FD_LOG_WARNING(( "NULL shele" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ele, alignof(POOL_ELE_T) ) ) ) {
    FD_LOG_WARNING(( "misaligned shele" ));
    return NULL;
  }

  if( FD_UNLIKELY( ele_max>POOL_(ele_max_max)() ) ) {
    FD_LOG_WARNING(( "bad ele_max" ));
    return NULL;
  }

  join->pool    = pool;
  join->ele     = ele;
  join->ele_max = ele_max;

  return join;
}

POOL_STATIC void *
POOL_(leave)( POOL_(t) * join ) {

  if( FD_UNLIKELY( !join ) ) {
    FD_LOG_WARNING(( "NULL join" ));
    return NULL;
  }

  return (void *)join;
}

POOL_STATIC void *
POOL_(delete)( void * shpool ) {
  POOL_(shmem_t) * pool = (POOL_(shmem_t) *)shpool;

  if( FD_UNLIKELY( !pool) ) {
    FD_LOG_WARNING(( "NULL shpool" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)pool, POOL_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shpool" ));
    return NULL;
  }

  if( FD_UNLIKELY( pool->magic!=POOL_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  pool->magic = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)pool;
}

#if POOL_LAZY

static inline POOL_ELE_T *
POOL_(acquire_lazy)( POOL_(t) *   join,
                     POOL_ELE_T * sentinel,
                     int          blocking,
                     int *        _opt_err ) {
  POOL_ELE_T *     ele0    = join->ele;
  ulong            ele_max = join->ele_max;
  ulong volatile * _l      = (ulong volatile *)&join->pool->ver_lazy;

  POOL_ELE_T * ele = sentinel;
  int          err = FD_POOL_SUCCESS;

  FD_COMPILER_MFENCE();

  for(;;) {
    ulong ver_lazy = *_l;

    ulong ver     = POOL_(private_vidx_ver)( ver_lazy );
    ulong ele_idx = POOL_(private_vidx_idx)( ver_lazy );

    if( FD_LIKELY( !(ver & 1UL) ) ) { /* opt for unlocked */

      if( FD_UNLIKELY( POOL_(idx_is_null)( ele_idx ) ) ) { /* opt for not empty */
        err = FD_POOL_ERR_EMPTY;
        break;
      }

      if( FD_UNLIKELY( ele_idx>=ele_max ) ) { /* opt for not corrupt */
        err = FD_POOL_ERR_CORRUPT;
        break;
      }

      ulong ele_nxt = ele_idx+1UL;
      if( FD_UNLIKELY( ele_nxt>=ele_max ) ) ele_nxt = POOL_(idx_null)();

      ulong new_ver_lazy = POOL_(private_vidx)( ver+2UL, ele_nxt );
      if( FD_LIKELY( POOL_(private_cas)( _l, ver_lazy, new_ver_lazy )==ver_lazy ) ) { /* opt for low contention */
        ele = ele0 + ele_idx;
        break;
      }
    } else if( FD_UNLIKELY( !blocking ) ) { /* opt for blocking */

      err = FD_POOL_ERR_AGAIN;
      break; /* opt for blocking */

    }

    FD_SPIN_PAUSE();
  }

  FD_COMPILER_MFENCE();

  fd_int_store_if( !!_opt_err, _opt_err, err );
  return ele;
}

#endif /* POOL_LAZY */

POOL_STATIC POOL_ELE_T *
POOL_(acquire)( POOL_(t) *   join,
                POOL_ELE_T * sentinel,
                int          blocking,
                int *        _opt_err ) {
  POOL_ELE_T *     ele0    = join->ele;
  ulong            ele_max = join->ele_max;
  ulong volatile * _v      = (ulong volatile *)&join->pool->ver_top;

  POOL_ELE_T * ele = sentinel;
  int          err = FD_POOL_SUCCESS;

  FD_COMPILER_MFENCE();

  for(;;) {
    ulong ver_top = *_v;

    ulong ver     = POOL_(private_vidx_ver)( ver_top );
    ulong ele_idx = POOL_(private_vidx_idx)( ver_top );

    if( FD_LIKELY( !(ver & 1UL) ) ) { /* opt for unlocked */

      if( FD_UNLIKELY( POOL_(idx_is_null)( ele_idx ) ) ) { /* opt for not empty */
#       if POOL_LAZY
        return POOL_(acquire_lazy)( join, sentinel, blocking, _opt_err );
#       endif
        err = FD_POOL_ERR_EMPTY;
        break;
      }

      if( FD_UNLIKELY( ele_idx>=ele_max ) ) { /* opt for not corrupt */
        err = FD_POOL_ERR_CORRUPT;
        break;
      }

      ulong ele_nxt = POOL_(private_idx)( ele0[ ele_idx ].POOL_NEXT );

      if( FD_UNLIKELY( (ele_nxt>=ele_max) & (!POOL_(idx_is_null)( ele_nxt )) ) ) { /* ele_nxt is invalid, opt for valid */
        /* It is possible that another thread acquired ele_idx and
           repurposed ele_idx's POOL_NEXT (storing something in it that
           isn't a valid pool value) between when we read ver_top and
           when we read ele_idx's POOL_NEXT above.  If so, the pool
           version would be changed from what we read above.  We thus
           only signal ERR_CORRUPT if the version number hasn't changed
           since we read it. */

        if( FD_UNLIKELY( POOL_(private_vidx_ver)( *_v )==ver ) ) {
          err = FD_POOL_ERR_CORRUPT;
          break;
        }
      } else { /* ele_nxt is valid */
        ulong new_ver_top = POOL_(private_vidx)( ver+2UL, ele_nxt );

        if( FD_LIKELY( POOL_(private_cas)( _v, ver_top, new_ver_top )==ver_top ) ) { /* opt for low contention */
          ele = ele0 + ele_idx;
          break;
        }
      }
    } else if( FD_UNLIKELY( !blocking ) ) { /* opt for blocking */

      err = FD_POOL_ERR_AGAIN;
      break; /* opt for blocking */

    }

    FD_SPIN_PAUSE();
  }

  FD_COMPILER_MFENCE();

  fd_int_store_if( !!_opt_err, _opt_err, err );
  return ele;
}

POOL_STATIC int
POOL_(release)( POOL_(t) *   join,
                POOL_ELE_T * ele,
                int          blocking ) {
  ulong            ele_max = join->ele_max;
  ulong volatile * _v      = (ulong volatile *)&join->pool->ver_top;

  ulong ele_idx = (ulong)(ele - join->ele);
  if( FD_UNLIKELY( ele_idx>=ele_max ) ) return FD_POOL_ERR_INVAL; /* opt for valid call */

  int err = FD_POOL_SUCCESS;

  FD_COMPILER_MFENCE();

  for(;;) {
    ulong ver_top = *_v;

    ulong ver     = POOL_(private_vidx_ver)( ver_top );
    ulong ele_nxt = POOL_(private_vidx_idx)( ver_top );

    if( FD_LIKELY( !(ver & 1UL) ) ) { /* opt for unlocked */

      if( FD_UNLIKELY( (ele_nxt>=ele_max) & (!POOL_(idx_is_null)( ele_nxt )) ) ) { /* opt for not corrupt */
        err = FD_POOL_ERR_CORRUPT;
        break;
      }

      ele->POOL_NEXT = POOL_(private_cidx)( ele_nxt );

      ulong new_ver_top = POOL_(private_vidx)( ver+2UL, ele_idx );

      if( FD_LIKELY( POOL_(private_cas)( _v, ver_top, new_ver_top )==ver_top ) ) break; /* opt for low contention */

    } else if( FD_UNLIKELY( !blocking ) ) { /* opt for blocking */

      err = FD_POOL_ERR_AGAIN;
      break;

    }

    FD_SPIN_PAUSE();
  }

  FD_COMPILER_MFENCE();

  return err;
}

POOL_STATIC int
POOL_(is_empty)( POOL_(t) * join ) {
  ulong ver_top = join->pool->ver_top;
  ulong ele_idx = POOL_(private_vidx_idx)( ver_top );
  return POOL_(idx_is_null)( ele_idx );
}

POOL_STATIC int
POOL_(lock)( POOL_(t) * join,
             int        blocking ) {
  ulong volatile * _v = (ulong volatile *)&join->pool->ver_top;
# if POOL_LAZY
  ulong volatile * _l = (ulong volatile *)&join->pool->ver_lazy;
# endif

  int err = FD_POOL_SUCCESS;

  FD_COMPILER_MFENCE();

  ulong ver_top;
  for(;;) {

    /* use a test-and-test-and-set style for reduced contention */

    ver_top = *_v;
    if( FD_LIKELY( !(ver_top & (1UL<<POOL_IDX_WIDTH)) ) ) { /* opt for low contention */
      ver_top = POOL_(private_fetch_and_or)( _v, 1UL<<POOL_IDX_WIDTH );
      if( FD_LIKELY( !(ver_top & (1UL<<POOL_IDX_WIDTH)) ) ) break; /* opt for low contention */
    }

    if( FD_UNLIKELY( !blocking ) ) { /* opt for blocking */
      err = FD_POOL_ERR_AGAIN;
      goto fail;
    }

    FD_SPIN_PAUSE();
  }

  FD_COMPILER_MFENCE();

# if POOL_LAZY

  for(;;) {

    /* use a test-and-test-and-set style for reduced contention */

    ulong ver_lazy = *_l;
    if( FD_LIKELY( !(ver_lazy & (1UL<<POOL_IDX_WIDTH)) ) ) { /* opt for low contention */
      ver_lazy = POOL_(private_fetch_and_or)( _l, 1UL<<POOL_IDX_WIDTH );
      if( FD_LIKELY( !(ver_lazy & (1UL<<POOL_IDX_WIDTH)) ) ) break; /* opt for low contention */
    }

    if( FD_UNLIKELY( !blocking ) ) { /* opt for blocking */
      *_v = POOL_(private_vidx)( POOL_(private_vidx_ver)( ver_top )+2UL, POOL_(private_vidx_idx)( ver_top ) ); /* unlock */
      err = FD_POOL_ERR_AGAIN;
      goto fail;
    }

    FD_SPIN_PAUSE();
  }

  FD_COMPILER_MFENCE();

# endif

fail:
  return err;
}

#if !POOL_LAZY

POOL_STATIC void
POOL_(reset)( POOL_(t) * join,
              ulong      sentinel_cnt ) {
  POOL_(shmem_t) * pool    = join->pool;
  POOL_ELE_T *     ele     = join->ele;
  ulong            ele_max = join->ele_max;

  /* Insert all but the leading sentinel_cnt elements in increasing
     order */

  ulong ele_top;

  if( FD_UNLIKELY( sentinel_cnt>=ele_max ) ) ele_top = POOL_(idx_null)(); /* All items are sentinels */
  else { /* Note: ele_max at least 1 here */
    ele_top = sentinel_cnt;
    for( ulong ele_idx=ele_top; ele_idx<(ele_max-1UL); ele_idx++ ) {
      ele[ ele_idx ].POOL_NEXT = POOL_(private_cidx)( ele_idx+1UL );
    }
    ele[ ele_max-1UL ].POOL_NEXT = POOL_(private_cidx)( POOL_(idx_null)() );
  }

  ulong ver_top = pool->ver_top;
  ulong ver     = POOL_(private_vidx_ver)( ver_top );
  pool->ver_top = POOL_(private_vidx)( ver, ele_top );
}

#else

POOL_STATIC void
POOL_(reset)( POOL_(t) * join,
              ulong      sentinel_cnt ) {
  POOL_(shmem_t) * pool    = join->pool;
  ulong            ele_max = join->ele_max;

  /* Assign all but the leading sentinel_cnt elements to the bump
     allocator */

  ulong ele_top  = POOL_(idx_null)();
  ulong ele_lazy = sentinel_cnt<ele_max ? sentinel_cnt : POOL_(idx_null)();

  ulong ver_top  = pool->ver_top;
  ulong ver_lazy = pool->ver_lazy;
  pool->ver_top  = POOL_(private_vidx)( POOL_(private_vidx_ver)( ver_top  ), ele_top  );
  pool->ver_lazy = POOL_(private_vidx)( POOL_(private_vidx_ver)( ver_lazy ), ele_lazy );
}

#endif

POOL_STATIC int
POOL_(verify)( POOL_(t) const * join ) {

# define POOL_TEST(c) do {                                                                        \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return FD_POOL_ERR_CORRUPT; } \
  } while(0)

  /* Validate join */

  POOL_TEST( join );
  POOL_TEST( fd_ulong_is_aligned( (ulong)join, alignof(POOL_(t)) ) );

  POOL_(shmem_t) const * pool    = join->pool;
  POOL_ELE_T const *     ele     = join->ele;
  ulong                  ele_max = join->ele_max;

  POOL_TEST( pool );
  POOL_TEST( fd_ulong_is_aligned( (ulong)pool, POOL_(align)() ) );

  POOL_TEST( (!!ele)| (!ele_max) );
  POOL_TEST( fd_ulong_is_aligned( (ulong)ele, alignof(POOL_ELE_T) ) );

  POOL_TEST( ele_max<=POOL_(ele_max_max)() );

  /* Validate pool metadata */

  ulong magic   = pool->magic;
  ulong ver_top = pool->ver_top;

  /* version arbitrary as far as verify is concerned */
  ulong ele_idx = POOL_(private_vidx_idx)( ver_top );

  POOL_TEST( magic==POOL_MAGIC );

  /* Validate pool elements */

  ulong ele_rem = ele_max;
  while( ele_idx<ele_max ) {
    POOL_TEST( ele_rem ); ele_rem--; /* no cycles */
    ele_idx = POOL_(private_idx)( ele[ ele_idx ].POOL_NEXT );
  }

  POOL_TEST( POOL_(idx_is_null)( ele_idx ) );

# if POOL_LAZY
  ulong lazy_idx  = POOL_(private_vidx_idx)( pool->ver_lazy );
  ulong lazy_free = POOL_(idx_is_null)( lazy_idx ) ? 0UL : (ele_max-lazy_idx);
  POOL_TEST( lazy_free<=ele_rem );
# endif

# undef POOL_TEST

  return FD_POOL_SUCCESS;
}

POOL_STATIC char const *
POOL_(strerror)( int err ) {
  switch( err ) {
  case FD_POOL_SUCCESS:     return "success";
  case FD_POOL_ERR_INVAL:   return "bad input";
  case FD_POOL_ERR_AGAIN:   return "try again";
  case FD_POOL_ERR_CORRUPT: return "corruption detected";
  case FD_POOL_ERR_EMPTY:   return "pool empty";
  default: break;
  }
  return "unknown";
}

#endif

#undef POOL_
#undef POOL_STATIC
#undef POOL_VER_WIDTH

#undef POOL_LAZY
#undef POOL_IMPL_STYLE
#undef POOL_MAGIC
#undef POOL_IDX_WIDTH
#undef POOL_ALIGN
#undef POOL_NEXT
#undef POOL_IDX_T
#undef POOL_ELE_T
#undef POOL_NAME
