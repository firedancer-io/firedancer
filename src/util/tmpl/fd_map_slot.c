/* Generate prototypes, inlines and/or implementations for
   _non_-concurrent persistent shared key-val maps based on linear
   probing.  Roughly speaking, this provides the advanced features of
   fd_map_slot_para with an API more like fd_map_dynamic.  Namely, like
   fd_map_slot_para and beyond fd_map_dynamic, this has:

   - First class support for seeded hashing (this has also been
     backported to fd_map_dynamic).

   - First class support for upserting.

   - First class support for prefetching (including efficient handling
     of expensive key hashing between prefetch and use).

   - No requirement for a sentinel key.  (Maps that do use sentinel
     keys are still supported.)

   - Improved support for key-val pairs that are not plain-old-data.

   - Bounded and configurable worst case algorithmic bounds (and, as a
     side effect, no requirement for the user to guarantee there is
     always at least one free element in the element store).

   - Iteration over all keys with a common hash (e.g. for maps that
     use structured hashing to group keys together).

   - A run-time data integrity verification function.

   All operations have been factored into a strict O(1) inline fast path
   and a compact bounded worst case non-inlined slow path.  The shared
   part of the map is just a plain-old flat array of elements.

   In typical usage, doing:

     struct myele {

       ulong key;  // Technically "MAP_KEY_T MAP_KEY;"  (default is ulong key)
       ulong memo; // Technically "ulong     MAP_MEMO;" (default is ulong memo), ==mymap_key_hash(key,seed)

       ... key and memo can be located arbitrarily in struct and are
       ... managed by the mymap.  memo is not required if MAP_MEMOIZE is
       ... zero or not specified.  The rest of the struct holds the vals
       ... associated with key.  The mapping of a key to a location in
       ... the element store is arbitrary and might change whenever any
       ... key is removed from the map.

     };

     typedef struct myele myele_t;

     #define MAP_NAME  mymap
     #define MAP_ELE_T myele_t
     #include "util/tmpl/fd_map_slot.c"

   will declare the following APIs as a header only style library in the
   current translation unit:

     // A mymap_t is a stack declaration friendly quasi-opaque local
     // object used to hold the state of a local join to a mymap.
     // Similarly, a mymap_iter_t holds the local state of an ongoing
     // iteration.  E.g. it is fine to do mymap_t join[1];" to allocate
     // a mymap_t but the contents should not be used directly.

     typedef struct mymap_private      mymap_t;
     typedef struct mymap_iter_private mymap_iter_t;

     // mymap_{ele_is_free,key_eq,key_hash} expose the user provided
     // MAP_{ELE_IS_FREE,KEY_EQ,KEY_HASH} implementations as functions
     // with strict semantics.  They assume that the provided pointers
     // are in the caller's address space and will not be changed during
     // the call.  They retain no interest after the call.
     //
     // mymap_ele_is_free returns 1 if *ele is not in use and 0 otherwise.
     //
     // mymap_key_eq returns 1 if *k0 and *k1 are equal and 0 otherwise.
     //
     // mymap_key_hash returns the hash of *key using the hash function
     // seed.  This should ideally be a random mapping from a MAP_KEY_T
     // to a ulong but this depends on what the user actually provided
     // for MAP_KEY_HASH.  The seed used by a particular mymap instance
     // can be obtained from the mymap accessors.

     int   mymap_ele_is_free( myele_t * ele );
     int   mymap_key_eq     ( ulong * k0,  ulong * k1 );
     ulong mymap_key_hash   ( ulong * key, ulong seed );

     // mymap_probe_max_est returns a reasonable value to use for
     // probe_max with an ele_max myele_t store.  Assumes a valid
     // ele_max.  Return will be in [1,ele_max].

     ulong mymap_probe_max_est( ulong ele_max );

     // mymap_{align,footprint} return the {alignment,footprint}
     // required for a memory region to be used as myele_t store with
     // ele_max elements.  footprint returns 0 if ele_max is not an
     // integer power of 2 where ele_max*sizeof(myele_t) does not
     // overflow.
     //
     // mymap_new formats the memory region pointed to by shmem into a
     // myele_t element store sufficient for ele_max elements.  If reset
     // is non-zero, this will also clear the memory region.  If reset
     // is zero or clearing the region does not mark all the elements in
     // the store as free, it is the caller's responsibility to mark all
     // elements as free.  Assumes shmem is not in use on entry.
     // Returns shmem on success (shmem will be a suitable store for the
     // mymap) or NULL on failure (bad ele_max, NULL shmem, misaligned
     // shmem ... no changes, log details).  Caller is not joined on
     // return.
     //
     // mymap_join joins the caller to an existing mymap.  lmem points
     // to a mymap_t compatible memory region in the caller's address
     // space, ele0 points to the mymap's element store, ele_max is the
     // store's element capacity, probe_max is a bound for worst case
     // time complexity for most operations (in [1,ele_max]) and seed is
     // the hash seed to use.  All joiners must use the same ele_max,
     // probe_max and seed (as this is not a concurrent structure, there
     // typically is only a single join in practice).  Returns a handle
     // to the caller's local join on success (join has ownership of the
     // lmem region) and NULL on failure (no changes, logs details).
     //
     // mymap_leave leaves a mymap.  join points to a current local
     // join.  Returns the memory region used for the join on success
     // (caller has ownership on return and the caller is no longer
     // joined) and NULL on failure (no changes, logs details).  Use the
     // mymap accessors before leaving to get the underlying element
     // store if needed.
     //
     // mymap_delete unformats a memory region used as a mymap element
     // store.  Assumes ele0 points in the caller's address space to the
     // memory region used as the element store and that there are no
     // current joins.  Returns shmem on success (caller has ownership
     // of the memory region, any remaining elements still in the mymap
     // are released to the caller implicitly, any resources used by
     // theses are the caller's responsibility to clean up) and NULL on
     // failure (no changes, logs details).

     ulong     mymap_align    ( void );
     ulong     mymap_footprint( ulong ele_max );
     myele_t * mymap_new      ( void * shmem, ulong ele_max, int reset );
     mymap_t * mymap_join     ( void * lmem, myele_t * ele0, ulong ele_max, ulong probe_max, ulong seed );
     void *    mymap_leave    ( mymap_t * join );
     void *    mymap_delete   ( myele_t * ele0 );

     // mymap_{ele0,ele_max,probe_max,seed} return the corresponding
     // join value.  Assumes join is a current local join.
     // mymap_ele0_const is a const correct version.

     myele_t * mymap_ele0      ( mymap_t *       join );
     ulong     mymap_ele_max   ( mymap_t const * join );
     ulong     mymap_probe_max ( mymap_t const * join );
     ulong     mymap_seed      ( mymap_t const * join );

     myele_t const * mymap_ele0_const( mymap_t const * join );

     // mymap_{ctx,ctx_max} return {a pointer in the caller's address
     // space to,the byte size of} the join's user context.  The
     // lifetime of the returned pointer is the join's lifetime.
     // Assumes join is a current local join.  mymap_ctx_const is a
     // const correct version.

     void * mymap_ctx    ( mymap_t *       join );
     ulong  mymap_ctx_max( mymap_t const * join );

     void const * mymap_ctx_const( mymap_t const * join );

     // Basic operations

     // mymap_query:
     //
     //   ... join is a current local join and key points to the key of
     //   ... interest (for maps that use key sentinels, *key should not
     //   ... be a sentinel key), retains no interest in join or key.
     //
     //   ele = mymap_query( join, key );
     //
     //   if( FD_UNLIKELY( !ele ) ) {
     //
     //     ... no element *key in map
     //
     //   } else {
     //
     //     ... ele points in the caller's address space into the
     //     ... element store where element *key is currently held.  The
     //     ... caller is free to read any field of ele.  ele's lifetime
     //     ... is until the next remove or leave.
     //
     //   }

     myele_t const * mymap_query ( mymap_t const * join, ulong const * key );

     // mymap_update:
     //
     //   ... join is a current local join and key points to the key of
     //   ... interest (for maps that use key sentinels, *key should not
     //   ... be a sentinel key), retains no interest in join or key.
     //
     //   ele = mymap_update( join, key );
     //
     //   if( FD_UNLIKELY( !ele ) ) {
     //
     //     ... no element *key in map
     //
     //   } else {
     //
     //     ... ele points in the caller's address space into the
     //     ... element store where element *key is currently held.  The
     //     ... caller is free to update ele's val fields.  Caller
     //     ... should not update ele's key, update ele's memo (if
     //     ... applicable) or mark ele as free (if applicable).  ele's
     //     ... lifetime is until the next remove or leave.
     //
     //   }

     myele_t * mymap_update( mymap_t * join, ulong const * key );

     // mymap_insert:
     //
     //   ... join is a current local join and key points to the key of
     //   ... interest (for maps that use key sentinels, *key should not
     //   ... be a sentinel key), retains no interest in join or key.
     //
     //   ele = mymap_insert( join, key );
     //
     //   if( FD_UNLIKELY( !ele ) ) {
     //
     //     ... element *key is already in the map or the map was too
     //     ... full to insert element *key
     //
     //   } else {
     //
     //     ... we are starting to insert element *key.  ele's key and
     //     ... (if applicable) ele's memo will already be initialized
     //     ... to *key and mymap_key_hash( key, seed ) respectively.
     //     ... Further, if the map uses key sentinels, the ele will be
     //     ... implicitly marked as not free.
     //
     //     ... caller should initalize ele's val fields here and, if
     //     ... map does not use key sentinels, mark ele as not free (at
     //     ... which point, ele's lifetime is until the next remove or
     //     ... leave).
     //
     //     ... If ele is not marked as in use, the insert is implicitly
     //     ... canceled (at which point, ele's lifetime is until the
     //     ... next insert, remove or leave).
     //
     //   }

     myele_t * mymap_insert( mymap_t * join, ulong const * key );

     // mymap_upsert:
     //
     //   ... join is a current local join and key points to the key of
     //   ... interest (for maps that use key sentinels, *key should not
     //   ... be a sentinel key), retains no interest in join or key.
     //
     //   ele = mymap_upsert( join, key );
     //
     //   if( FD_UNLIKELY( !ele ) ) {
     //
     //     ... element *key is not in map and the map is too full to
     //     ... insert it
     //
     //   } else if( FD_UNLIKELY( mymap_ele_is_free( ele ) ) ) {
     //
     //     ... element *key was not in map and should be inserted at
     //     ... ele.  See insert for details how to complete inserting
     //     ... ele.
     //
     //     ... Note that if mymap uses key sentinels to indicate when
     //     ... an element is free, this code path will never be taken.
     //     ... That is, the caller will not be able to tell via
     //     ... mymap_ele_is_free if an upsert is inserting or updating
     //     ... as the upsert initialized ele's key field (implicitly
     //     ... marking the element as not free such).
     //
     //   } else {
     //
     //     ... element *key is stored in the map at ele.  See update
     //     ... for details how to complete updating ele.
     //
     //     ... Note that if mymap uses key sentinels to indicate when
     //     ... an element is free, we might actually be inserting ele
     //     ... here (see note above).
     //
     //   }

     myele_t * mymap_upsert( mymap_t * join, ulong const * key );

     // mymap_remove:
     //
     //   ... join is a current local join and ele points to the
     //   ... location in the element store holding element key to
     //   ... remove.  (As such this location is marked as not free.)
     //
     //   mymap_remove( join, ele );
     //
     //   ... at this point, element key is no longer in the map and all
     //   ... pointers into the element store are potentially pointing
     //   ... at different and/or free elements.

     void mymap_remove( mymap_t * join, myele_t * ele );

     // Advanced operations

     // mymap_hint tries to prefetch the location currently holding
     // element *key from the map according to the user hint and returns
     // the memo==mymap_key_hash( key, seed ) for use with the below
     // APIs.
     //
     // mymap_{query,update,insert,upsert}_fast are the same as the
     // basic operations but require the user to pass in the memo
     // corresponding to key (e.g. computed earlier by hint) and allow
     // the user to give an element sentinel location to return on
     // failure.
     //
     // All these assume join is a current local join and key points to
     // the key of interest (for maps that use key sentinels, *key
     // should not be a sentinel key).  These retain no interest in
     // join, key or the element sentinel (use NULL for error handling
     // like the basic API).
     //
     // Advanced example (prefetching query with branchless error
     // handling):
     //
     //   memo = mymap_hint( map, key, hint )
     //
     //   ... do other stuff while memory subsystem is prefetching in
     //   ... the background here
     //
     //   ele = mymap_query_fast( join, key, memo, fallback );
     //
     //   ... at this point, ele is guaranteed non-NULL (if element *key
     //   ... is not in the map, ele will point to fallback which could
     //   ... hold, for example, fallback vals to use when *key specific
     //   ... vals are not available).

     ulong mymap_hint( mymap_t * join, ulong const * key, int hint );

     myele_t const * mymap_query_fast ( mymap_t const * join, ulong const * key, ulong memo, myele_t const * sentinel );
     myele_t *       mymap_update_fast( mymap_t *       join, ulong const * key, ulong memo, myele_t *       sentinel );
     myele_t *       mymap_insert_fast( mymap_t *       join, ulong const * key, ulong memo, myele_t *       sentinel );
     myele_t *       mymap_upsert_fast( mymap_t *       join, ulong const * key, ulong memo, myele_t *       sentinel );

     // mymap_iter_{init,done,next,ele,ele_const} allow for iteration
     // over all mymap elements with the same memo.  Basic usage:
     //
     //   ulong memo = ... memo of keys of interest;
     //
     //   for( mymap_iter_t iter = mymap_iter_init( join, memo );
     //        !mymap_iter_done( join, memo, iter );
     //        iter = mymap_iter_next( join, memo, iter ) ) {
     //
     //     myele_t * ele = mymap_iter_ele( join, memo, iter );
     //
     //     ... process ele here (do not modify key or memo, do
     //     ... not insert or remove any elements)
     //
     //   }

     mymap_iter_t    mymap_iter_init     ( mymap_t const * join, ulong memo );
     int             mymap_iter_done     ( mymap_t const * join, ulong memo, mymap_iter_t iter );
     mymap_iter_t    mymap_iter_next     ( mymap_t const * join, ulong memo, mymap_iter_t iter );
     myele_t const * mymap_iter_ele_const( mymap_t const * join, ulong memo, mymap_iter_t iter );
     myele_t *       mymap_iter_ele      ( mymap_t *       join, ulong memo, mymap_iter_t iter );

     // mymap_verify returns 0 if the join and underlying element store
     // give a mapping of unique keys to unique elements in the element
     // store with properly bounded maximum probe length and -1
     // otherwise (no changes, logs details).

     int mymap_verify( mymap_t const * join );

   Do this as often as desired in a compilation unit to get different
   types of maps.  Options exist for generating library header
   prototypes and/or library implementations for maps usable across
   multiple translation units.  Additional options exist to use
   different hashing functions, key comparison functions, etc as
   detailed below. */

/* MAP_NAME gives the API prefix to use */

#ifndef MAP_NAME
#error "Define MAP_NAME"
#endif

/* MAP_ELE_T is the map element type */

#ifndef MAP_ELE_T
#error "Define MAP_ELE_T"
#endif

/* MAP_KEY_T is the map key type */

#ifndef MAP_KEY_T
#define MAP_KEY_T ulong
#endif

/* MAP_KEY is the MAP_KEY_T key field.  When a slot is in use, this
   field is managed by the map.  For maps that use key sentinels, this
   element may also designate whether or not an element is in use. */

#ifndef MAP_KEY
#define MAP_KEY key
#endif

/* MAP_KEY_EQ returns 0/1 if *k0 is the same/different as *k1 */

#ifndef MAP_KEY_EQ
#define MAP_KEY_EQ(k0,k1) ((*(k0))==(*(k1)))
#endif

/* MAP_KEY_HASH returns a random mapping of *key into ulong.  The
   mapping is parameterized by the 64-bit ulong seed. */

#ifndef MAP_KEY_HASH
#define MAP_KEY_HASH(key,seed) fd_ulong_hash( (*(key)) ^ (seed) )
#endif

/* If MAP_MEMOIZE is non-zero, elements have a field that can be used
   while in the map to hold the MAP_KEY_HASH for an element's key.  This
   is useful for accelerating user code that might need a hash and
   various map operations. */

#ifndef MAP_MEMOIZE
#define MAP_MEMOIZE 0
#endif

/* If MAP_MEMOIZE is non-zero, MAP_MEMO is the memo element field.
   Should be a ulong.  Like MAP_KEY, when a slot is in use, this field
   is managed by the map and will contain the MAP_KEY_HASH of the
   element's key and the map's seed. */

#ifndef MAP_MEMO
#define MAP_MEMO memo
#endif

/* If MAP_MEMOIZE and MAP_KEY_EQ_IS_SLOW are both non-zero, the MAP_MEMO
   field should be used to accelerate MAP_KEY_EQ operations.  This is
   useful when MAP_KEY_EQ is non-trivial (e.g. variable length string
   compare, large buffer compares, etc). */

#ifndef MAP_KEY_EQ_IS_SLOW
#define MAP_KEY_EQ_IS_SLOW 0
#endif

/* MAP_ELE_IS_FREE returns 0/1 if the slot pointed to by ele in the
   caller's address space contains/does not contain a key-val pair.  The
   implementation can assume ele points to a slot in the element store.
   The default implementation tests if key is not 0 (i.e. "0" is a key
   sentinel).  If using a different key sentinel or not using a key
   sentinel, update this appropriately. */

#ifndef MAP_ELE_IS_FREE
#define MAP_ELE_IS_FREE(ele) (!((ele)->MAP_KEY))
#endif

/* MAP_ELE_FREE frees the key-val pair in the slot pointed to by ele in
   the caller's address space.  The implementation can assume ele is
   valid, ele contains a key-value pair on entry and there will be no
   concurrent operations on ele during the free.  The default
   implementation sets key to 0.  If using a different key sentinel or
   not using a key sentinel, update this appropriately.  Likewise, if
   not using plain-old-data keys and vals, this should do the
   appropriate application specific resource management.  The join ctx
   is provided to facilitate this. */

#ifndef MAP_ELE_FREE
#define MAP_ELE_FREE(ctx,ele) do (ele)->MAP_KEY = (MAP_KEY_T)0; while(0)
#endif

/* MAP_ELE_MOVE moves the key-val pair in slot src to slot dst.  src and
   dst are in the caller's address space.  The implementation can assume
   src and dst are valid and src/dst does/does not contain a key-val
   pair on entry.  The default implementation shallow copies src to dst
   and sets src key to 0.  If using a different key sentinel or not
   using a key sentinel, update this appropriately.  Likewise, if
   elements do not use plain-old-data keys and/or vals, this should do
   the appropriate key and/or val resource management.  The join ctx is
   provided to facilitate this. */

#ifndef MAP_ELE_MOVE
#define MAP_ELE_MOVE(ctx,dst,src) do { MAP_ELE_T * _src = (src); (*(dst)) = *_src; _src->MAP_KEY = (MAP_KEY_T)0; } while(0)
#endif

/* MAP_CTX_MAX specifies the maximum number of bytes of user context for
   use in MAP_ELE_FREE / MAP_ELE_MOVE above (e.g. custom allocators /
   workspaces / local pointers to additional value arrays / etc).  This
   context will be ulong aligned.  Default is up to 32 bytes. */

#ifndef MAP_CTX_MAX
#define MAP_CTX_MAX (32UL)
#endif

/* MAP_PREFETCH specifies how the hint API should prefetch a slot.  The
   default is to call __builtin_prefetch on the address of the slot's
   leading byte using the default rw and locality hints of 0 (read) / 3
   (high temporal locality).  Note that a user hint value is provided to
   support for more sophisticated and application specific forms of
   prefetching.

   Also note that instrincs like __builtin_prefetch often require their
   hints to be _compile_ _time_ _constants_ (because they map to
   assembly instructions that encode these hints into the raw
   instruction stream).  Ideally, we would plumb in the appropriate
   instrinic hint from a _compile_ _time _constant_ user hint directly
   via something like:

     __builtin_prefetch( (src), (hint) & 1, (hint) >> 1 )

   But ... sigh ... the compiler frequently does not recognize the above
   values are in fact compile time constants (it will try to compile the
   enclosing static inline to an intermediate representation and fail
   because it doesn't know the values above will simplify into compile
   time constants at the inline call sites ... yet another area where
   macros actually are faster than inlines in real world code).

   Working around this typically requires using constructs like:

     if(      (hint)==0 ) __builtin_prefetch( (src), 0, 3 );
     else if( (hint)==1 ) __builtin_prefetch( (src), 1, 3 );
     ...

   and keeping our fingers crossed the compiler will prune the
   unnecessary branches at compile time.  Which it often won't because
   it will view the construct as too large and complex to inline and
   thus never get around to pruning the dead branches at the call sites
   ... more sighs ... YMMV. */

#ifndef MAP_PREFETCH
#define MAP_PREFETCH(src,hint) __builtin_prefetch( (src), 0, 3 )
#endif

/* MAP_IMPL_STYLE controls what to generate:
     0 - header only library
     1 - library header declaration
     2 - library implementation */

#ifndef MAP_IMPL_STYLE
#define MAP_IMPL_STYLE 0
#endif

/* Implementation *****************************************************/

#if MAP_IMPL_STYLE==0 /* local use only */
#define MAP_STATIC FD_FN_UNUSED static
#else /* library header and/or implementation */
#define MAP_STATIC
#endif

#define MAP_(n) FD_EXPAND_THEN_CONCAT3(MAP_NAME,_,n)

#if MAP_IMPL_STYLE!=2 /* need header */

#include "../bits/fd_bits.h"

struct MAP_(private) {
  MAP_ELE_T * ele0;               /* Points to the element store in caller's address space, indexed [0,ele_max) */
  ulong       ele_mask;           /* ==ele_max-1UL where ele_max is a power of 2 */
  ulong       probe_rem;          /* ==probe_max-1UL where probe_max is in [1,ele_max], probe_max bounds worst case ops count. */
  ulong       seed;               /* Key hash seed */
  uchar       ctx[ MAP_CTX_MAX ]; /* User context (for non-POD datatypes) */
};

typedef struct MAP_(private) MAP_(t);

typedef ulong MAP_(iter_t); /* Element store index cursor for current iteration */

FD_PROTOTYPES_BEGIN

/* Private APIs *******************************************************/

static inline void
MAP_(private_ele_free)( void *      ctx,
                        MAP_ELE_T * ele ) {
  (void)ctx;
  MAP_ELE_FREE( (ctx), (ele) );
}

static inline void
MAP_(private_ele_move)( void *      ctx,
                        MAP_ELE_T * dst,
                        MAP_ELE_T * src ) {
  (void)ctx;
  MAP_ELE_MOVE( (ctx), (dst), (src) );
}

FD_FN_PURE MAP_STATIC MAP_ELE_T *
MAP_(private_update)( MAP_(t) *         join,
                      MAP_KEY_T const * key,
                      ulong             memo,
                      MAP_ELE_T *       sentinel );

MAP_STATIC MAP_ELE_T *
MAP_(private_insert)( MAP_(t) *         join,
                      MAP_KEY_T const * key,
                      ulong             memo,
                      MAP_ELE_T *       sentinel );

MAP_STATIC MAP_ELE_T *
MAP_(private_upsert)( MAP_(t) *         join,
                      MAP_KEY_T const * key,
                      ulong             memo,
                      MAP_ELE_T *       sentinel );

MAP_STATIC void
MAP_(private_remove)( MAP_(t) * join,
                      ulong     hole_idx );

/* Public APIs ********************************************************/

FD_FN_PURE static inline int
MAP_(ele_is_free)( MAP_ELE_T const * ele ) {
  return !!(MAP_ELE_IS_FREE( (ele) ));
}

FD_FN_PURE static inline int
MAP_(key_eq)( MAP_KEY_T const * k0,
              MAP_KEY_T const * k1 ) {
  return !!(MAP_KEY_EQ( (k0), (k1) ));
}

FD_FN_PURE static inline ulong
MAP_(key_hash)( MAP_KEY_T const * key,
                ulong             seed ) {
  return (MAP_KEY_HASH( (key), (seed) ));
}

FD_FN_CONST static inline ulong MAP_(probe_max_est)( ulong ele_max ) { return ele_max; }

FD_FN_CONST static inline ulong MAP_(align)( void ) { return alignof(MAP_ELE_T); }

FD_FN_CONST static inline ulong
MAP_(footprint)( ulong ele_max ) {
  if( !((ele_max<=(ULONG_MAX / sizeof(MAP_ELE_T))) & fd_ulong_is_pow2( ele_max )) ) return 0UL;
  return ele_max*sizeof(MAP_ELE_T); /* no overflow */
}

MAP_STATIC MAP_ELE_T * MAP_(new)   ( void * shmem, ulong ele_max, int reset );
MAP_STATIC MAP_(t) *   MAP_(join)  ( void * lmem, MAP_ELE_T * ele0, ulong ele_max, ulong probe_max, ulong seed );
MAP_STATIC void *      MAP_(leave) ( MAP_(t) * join );
MAP_STATIC void *      MAP_(delete)( MAP_ELE_T * ele0 );

FD_FN_PURE  static inline MAP_ELE_T *       MAP_(ele0)      ( MAP_(t) *       join ) { return join->ele0;              }
FD_FN_PURE  static inline MAP_ELE_T const * MAP_(ele0_const)( MAP_(t) const * join ) { return join->ele0;              }
FD_FN_PURE  static inline ulong             MAP_(ele_max)   ( MAP_(t) const * join ) { return join->ele_mask + 1UL;    }
FD_FN_PURE  static inline ulong             MAP_(probe_max) ( MAP_(t) const * join ) { return join->probe_rem + 1UL;   }
FD_FN_PURE  static inline ulong             MAP_(seed)      ( MAP_(t) const * join ) { return join->seed;              }
FD_FN_CONST static inline void *            MAP_(ctx)       ( MAP_(t) *       join ) { return join->ctx;               }
FD_FN_CONST static inline void const *      MAP_(ctx_const) ( MAP_(t) const * join ) { return join->ctx;               }
FD_FN_CONST static inline ulong             MAP_(ctx_max)   ( MAP_(t) const * join ) { (void)join; return MAP_CTX_MAX; }

FD_FN_PURE static inline ulong
MAP_(hint)( MAP_(t) const *   join,
            MAP_KEY_T const * key,
            int               hint ) {
  ulong memo = MAP_(key_hash)( key, join->seed );
  MAP_PREFETCH( join->ele0 + (memo & join->ele_mask), hint ); (void)hint;
  return memo;
}

FD_FN_PURE static inline MAP_ELE_T *
MAP_(update_fast)( MAP_(t) *         join,
                   MAP_KEY_T const * key,
                   ulong             memo,
                   MAP_ELE_T *       sentinel ) {
# if FD_TMPL_USE_HANDHOLDING
  FD_TEST( memo==MAP_(key_hash)( key, join->seed ) );
# endif

  ulong ele_idx = memo & join->ele_mask;

  MAP_ELE_T * ele = join->ele0 + ele_idx;

  if( FD_UNLIKELY( MAP_(ele_is_free)( ele ) ) ) return sentinel;

# if MAP_MEMOIZE && MAP_KEY_EQ_IS_SLOW
  if( FD_LIKELY( ele->MAP_MEMO==memo ) && FD_LIKELY( MAP_(key_eq)( &ele->MAP_KEY, key ) ) ) return ele;
# else
  if( FD_LIKELY( MAP_(key_eq)( &ele->MAP_KEY, key ) ) ) return ele;
# endif

  return MAP_(private_update)( join, key, memo, sentinel );
}

static inline MAP_ELE_T *
MAP_(insert_fast)( MAP_(t) *         join,
                   MAP_KEY_T const * key,
                   ulong             memo,
                   MAP_ELE_T *       sentinel ) {
# if FD_TMPL_USE_HANDHOLDING
  FD_TEST( memo==MAP_(key_hash)( key, join->seed ) );
# endif

  ulong ele_idx = memo & join->ele_mask;

  MAP_ELE_T * ele = join->ele0 + ele_idx;

  if( FD_LIKELY( MAP_(ele_is_free)( ele ) ) ) {
#   if MAP_MEMOIZE
    ele->MAP_MEMO = memo;
#   endif
    ele->MAP_KEY  = *key;
    return ele;
  }

# if MAP_MEMOIZE && MAP_KEY_EQ_IS_SLOW
  if( FD_UNLIKELY( ele->MAP_MEMO==memo ) && FD_UNLIKELY( MAP_(key_eq)( &ele->MAP_KEY, key ) ) ) return sentinel;
# else
  if( FD_UNLIKELY( MAP_(key_eq)( &ele->MAP_KEY, key ) ) ) return sentinel;
# endif

  return MAP_(private_insert)( join, key, memo, sentinel );
}

static inline MAP_ELE_T *
MAP_(upsert_fast)( MAP_(t) *         join,
                   MAP_KEY_T const * key,
                   ulong             memo,
                   MAP_ELE_T *       sentinel ) {
# if FD_TMPL_USE_HANDHOLDING
  FD_TEST( memo==MAP_(key_hash)( key, join->seed ) );
# endif

  ulong ele_idx = memo & join->ele_mask;

  MAP_ELE_T * ele = join->ele0 + ele_idx;

  if( FD_UNLIKELY( MAP_(ele_is_free)( ele ) ) ) {
#   if MAP_MEMOIZE
    ele->MAP_MEMO = memo;
#   endif
    ele->MAP_KEY  = *key;
    return ele;
  }

# if MAP_MEMOIZE && MAP_KEY_EQ_IS_SLOW
  if( FD_LIKELY( ele->MAP_MEMO==memo ) && FD_LIKELY( MAP_(key_eq)( &ele->MAP_KEY, key ) ) ) return ele;
# else
  if( FD_LIKELY( MAP_(key_eq)( &ele->MAP_KEY, key ) ) ) return ele;
# endif

  return MAP_(private_upsert)( join, key, memo, sentinel );
}

/* Note that this is just a const correct version of update */

FD_FN_PURE static inline MAP_ELE_T const *
MAP_(query_fast)( MAP_(t) const *   join,
                  MAP_KEY_T const * key,
                  ulong             memo,
                  MAP_ELE_T const * sentinel ) {
  return MAP_(update_fast)( (MAP_(t) *)join, key, memo, (MAP_ELE_T *)sentinel );
}

/* Basic APIs *********************************************************/

FD_FN_PURE static inline MAP_ELE_T const *
MAP_(query)( MAP_(t) const *   join,
             MAP_KEY_T const * key ) {
  return MAP_(update_fast)( (MAP_(t) *)join, key, MAP_(key_hash)( key, join->seed ), NULL );
}

FD_FN_PURE static inline MAP_ELE_T *
MAP_(update)( MAP_(t) *         join,
              MAP_KEY_T const * key ) {
  return MAP_(update_fast)( join, key, MAP_(key_hash)( key, join->seed ), NULL );
}

static inline MAP_ELE_T *
MAP_(insert)( MAP_(t) *         join,
              MAP_KEY_T const * key ) {
  return MAP_(insert_fast)( join, key, MAP_(key_hash)( key, join->seed ), NULL );
}

static inline MAP_ELE_T *
MAP_(upsert)( MAP_(t) *         join,
              MAP_KEY_T const * key ) {
  return MAP_(upsert_fast)( join, key, MAP_(key_hash)( key, join->seed ), NULL );
}

static inline void
MAP_(remove)( MAP_(t) *   join,
              MAP_ELE_T * ele ) {
  MAP_ELE_T * ele0     = join->ele0;
  ulong       ele_mask = join->ele_mask;
  ulong       hole_idx = (ulong)(ele - ele0);

# if FD_TMPL_USE_HANDHOLDING
  FD_TEST( fd_ulong_is_aligned( (ulong)ele0, alignof(MAP_ELE_T) ) );
  FD_TEST( ele0<=ele );
  FD_TEST( ele<=(ele0+ele_mask) );
  FD_TEST( !MAP_(ele_is_free( ele ) ) );
# endif

  MAP_(private_ele_free)( join->ctx, ele );

  if( FD_UNLIKELY( !MAP_(ele_is_free)( &ele0[ (hole_idx+1UL) & ele_mask ] ) ) ) MAP_(private_remove)( join, hole_idx );
}

FD_FN_PURE static inline int
MAP_(iter_done)( MAP_(t) const * join,
                 ulong           memo,
                 MAP_(iter_t)    iter ) {
  (void)memo;
  return iter > join->probe_rem;
}

__attribute__((warn_unused_result)) FD_FN_PURE static inline MAP_(iter_t)
MAP_(iter_next)( MAP_(t) const * join,
                 ulong           memo,
                 MAP_(iter_t)    iter ) {
  MAP_ELE_T const * ele0      = join->ele0;
  ulong             ele_mask  = join->ele_mask;
  ulong             probe_rem = join->probe_rem;
  ulong             seed      = join->seed;     (void)seed;

  for(;;) {
    iter++;
    if( FD_UNLIKELY( iter>probe_rem ) ) break;
    MAP_ELE_T const * ele = ele0 + ((memo + iter) & ele_mask);
    if( FD_LIKELY( MAP_(ele_is_free)( ele ) ) ) {
      iter = probe_rem + 1UL;
      break;
    }
#   if MAP_MEMOIZE
    if( FD_LIKELY( ele->MAP_MEMO==memo ) ) break;
#   else
    if( FD_LIKELY( MAP_(key_hash)( &ele->MAP_KEY, seed )==memo ) ) break;
#   endif
  }

  return iter;
}

FD_FN_PURE static inline MAP_(iter_t)
MAP_(iter_init)( MAP_(t) const * join,
                 ulong           memo ) {
  return MAP_(iter_next)( join, memo, -1UL );
}

FD_FN_PURE static inline MAP_ELE_T const *
MAP_(iter_ele_const)( MAP_(t) const * join,
                      ulong           memo,
                      MAP_(iter_t)    iter ) {
  (void)memo;
  return join->ele0 + ((memo + iter) & join->ele_mask);
}

FD_FN_PURE static inline MAP_ELE_T *
MAP_(iter_ele)( MAP_(t) *    join,
                ulong        memo,
                MAP_(iter_t) iter ) {
  (void)memo;
  return join->ele0 + ((memo + iter) & join->ele_mask);
}

MAP_STATIC int MAP_(verify)( MAP_(t) const * join );

FD_PROTOTYPES_END

#endif

#if MAP_IMPL_STYLE!=1 /* need implementations (assumes header already included) */

#include "../log/fd_log.h" /* Used by constructors and verify (FIXME: Consider making a compile time option) */

MAP_ELE_T *
MAP_(new)( void * shmem,
           ulong  ele_max,
           int    reset ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, MAP_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = MAP_(footprint)( ele_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad ele_max" ));
    return NULL;
  }

  MAP_ELE_T * ele0 = (MAP_ELE_T *)shmem;

  if( reset ) memset( ele0, 0, footprint );

  return ele0;
}

MAP_(t) *
MAP_(join)( void *      lmem,
            MAP_ELE_T * ele0,
            ulong       ele_max,
            ulong       probe_max,
            ulong       seed ) {

  if( FD_UNLIKELY( !lmem ) ) {
    FD_LOG_WARNING(( "NULL lmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)lmem, alignof(MAP_(t)) ) ) ) {
    FD_LOG_WARNING(( "misaligned lmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !ele0 ) ) {
    FD_LOG_WARNING(( "NULL ele0" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ele0, MAP_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned ele0" ));
    return NULL;
  }

  ulong footprint = MAP_(footprint)( ele_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad ele_max" ));
    return NULL;
  }

  if( FD_UNLIKELY( !((1UL<=probe_max) & (probe_max<=ele_max)) ) ) {
    FD_LOG_WARNING(( "bad probe_max" ));
    return NULL;
  }

  /* seed is arbitrary */

  MAP_(t) * join = (MAP_(t) *)lmem;

  memset( join, 0, sizeof(MAP_(t)) ); /* note: clears user context */

  join->ele0      = ele0;
  join->ele_mask  = ele_max - 1UL;
  join->probe_rem = probe_max - 1UL;
  join->seed      = seed;

  return join;
}

void *
MAP_(leave)( MAP_(t) * join ) {

  if( FD_UNLIKELY( !join ) ) {
    FD_LOG_WARNING(( "NULL join" ));
    return NULL;
  }

  return (void *)join;
}

void *
MAP_(delete)( MAP_ELE_T * ele0 ) {

  if( FD_UNLIKELY( !ele0 ) ) {
    FD_LOG_WARNING(( "NULL ele0" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ele0, alignof(MAP_ELE_T) ) ) ) {
    FD_LOG_WARNING(( "misaligned ele0" ));
    return NULL;
  }

  return ele0;
}

MAP_ELE_T *
MAP_(private_update)( MAP_(t) *         join,
                      MAP_KEY_T const * key,
                      ulong             memo,
                      MAP_ELE_T *       sentinel ) {

  MAP_ELE_T * ele0     = join->ele0;
  ulong       ele_mask = join->ele_mask;

  /* Note that the fast path did the first probe (and it collided) */

  ulong ele_idx = (memo+1UL) & ele_mask;
  for( ulong rem=join->probe_rem; rem; rem-- ) {
    MAP_ELE_T * ele = ele0 + ele_idx;

    if( FD_UNLIKELY( MAP_(ele_is_free)( ele ) ) ) break;

#   if MAP_MEMOIZE && MAP_KEY_EQ_IS_SLOW
    if( FD_LIKELY( ele->MAP_MEMO==memo ) && FD_LIKELY( MAP_(key_eq)( &ele->MAP_KEY, key ) ) ) return ele;
#   else
    if( FD_LIKELY( MAP_(key_eq)( &ele->MAP_KEY, key ) ) ) return ele;
#   endif

    ele_idx = (ele_idx+1UL) & ele_mask;
  }

  return sentinel;
}

MAP_ELE_T *
MAP_(private_insert)( MAP_(t) *         join,
                      MAP_KEY_T const * key,
                      ulong             memo,
                      MAP_ELE_T *       sentinel ) {

  MAP_ELE_T * ele0      = join->ele0;
  ulong       ele_mask  = join->ele_mask;

  /* Note that the fast path did the first probe (and it collided) */

  ulong ele_idx = (memo+1UL) & ele_mask;
  for( ulong rem=join->probe_rem; rem; rem-- ) {
    MAP_ELE_T * ele = ele0 + ele_idx;

    if( FD_LIKELY( MAP_(ele_is_free)( ele ) ) ) {
#     if MAP_MEMOIZE
      ele->MAP_MEMO = memo;
#     endif
      ele->MAP_KEY  = *key;
      return ele;
    }

#   if MAP_MEMOIZE && MAP_KEY_EQ_IS_SLOW
    if( FD_UNLIKELY( ele->MAP_MEMO==memo ) && FD_UNLIKELY( MAP_(key_eq)( &ele->MAP_KEY, key ) ) ) return sentinel;
#   else
    if( FD_UNLIKELY( MAP_(key_eq)( &ele->MAP_KEY, key ) ) ) return sentinel;
#   endif

    ele_idx = (ele_idx+1UL) & ele_mask;
  }

  return sentinel;
}

MAP_ELE_T *
MAP_(private_upsert)( MAP_(t) *         join,
                      MAP_KEY_T const * key,
                      ulong             memo,
                      MAP_ELE_T *       sentinel ) {

  MAP_ELE_T * ele0      = join->ele0;
  ulong       ele_mask  = join->ele_mask;

  /* Note that the fast path did the first probe */

  ulong ele_idx = (memo+1UL) & ele_mask;
  for( ulong rem=join->probe_rem; rem; rem-- ) {
    MAP_ELE_T * ele = ele0 + ele_idx;

    if( FD_UNLIKELY( MAP_(ele_is_free)( ele ) ) ) {
#     if MAP_MEMOIZE
      ele->MAP_MEMO = memo;
#     endif
      ele->MAP_KEY  = *key;
      return ele;
    }

#   if MAP_MEMOIZE && MAP_KEY_EQ_IS_SLOW
    if( FD_LIKELY( ele->MAP_MEMO==memo ) && FD_LIKELY( MAP_(key_eq)( &ele->MAP_KEY, key ) ) ) return ele;
#   else
    if( FD_LIKELY( MAP_(key_eq)( &ele->MAP_KEY, key ) ) ) return ele;
#   endif

    ele_idx = (ele_idx+1UL) & ele_mask;
  }

  return sentinel;
}

void
MAP_(private_remove)( MAP_(t) * join,
                      ulong     hole_idx ) {

  MAP_ELE_T * ele0     = join->ele0;
  ulong       ele_mask = join->ele_mask;
  ulong       seed     = join->seed; (void)seed;
  void *      ctx      = join->ctx;  (void)ctx;

  /* At this point, element hole is free, we need to repair any broken
     probe sequences for all contiguously occupied slots following
     element hole and the first element following hole is occupied. */

  ulong ele_idx = (hole_idx+1UL) & ele_mask;

  do {

#   if MAP_MEMOIZE
    ulong start_idx = ele0[ ele_idx ].MAP_MEMO & ele_mask;
#   else
    ulong start_idx = MAP_(key_hash)( &ele0[ ele_idx ].MAP_KEY, seed ) & ele_mask;
#   endif

    if( !( ((hole_idx<start_idx) & (start_idx<=ele_idx)                       ) |
           ((hole_idx>ele_idx) & ((hole_idx<start_idx) | (start_idx<=ele_idx))) ) ) {

      MAP_(private_ele_move)( ctx, ele0 + hole_idx, ele0 + ele_idx );

      hole_idx = ele_idx;

    }

    ele_idx = (ele_idx+1UL) & ele_mask;

  } while( !MAP_(ele_is_free)( &ele0[ ele_idx ] ) );
}

int
MAP_(verify)( MAP_(t) const * join ) {

# define MAP_TEST(c) do {                                                        \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return -1; } \
  } while(0)

  /* Validate join */

  MAP_TEST( join );
  MAP_TEST( fd_ulong_is_aligned( (ulong)join, alignof(MAP_(t)) ) );

  MAP_ELE_T const * ele0      = join->ele0;
  ulong             ele_mask  = join->ele_mask;
  ulong             probe_rem = join->probe_rem;
  ulong             seed      = join->seed;

  ulong             ele_max   = ele_mask  + 1UL;
  ulong             probe_max = probe_rem + 1UL;

  MAP_TEST( ele0                                                   );
  MAP_TEST( fd_ulong_is_aligned( (ulong)ele0, alignof(MAP_ELE_T) ) );
  MAP_TEST( ele_max <= (ULONG_MAX / sizeof(MAP_ELE_T))             );
  MAP_TEST( fd_ulong_is_pow2( ele_max )                            );
  MAP_TEST( (1UL<=probe_max) & (probe_max<=ele_max)                );
  /* seed is arbitrary */

  /* Validate map elements */

  for( ulong ele_idx=0UL; ele_idx<ele_max; ele_idx++ ) {
    MAP_ELE_T const * ele = ele0 + ele_idx;
    if( FD_LIKELY( MAP_(ele_is_free)( ele ) ) ) continue; /* opt for sparse */

    ulong memo = MAP_(key_hash)( &ele->MAP_KEY, seed );

#   if MAP_MEMOIZE
    MAP_TEST( ele->MAP_MEMO==memo );
#   endif

    ulong probe_idx = memo & ele_mask;
    ulong probe_cnt = fd_ulong_if( ele_idx>=probe_idx, ele_idx - probe_idx, ele_max + ele_idx - probe_idx ) + 1UL;
    MAP_TEST( probe_cnt<=probe_max );

    for( ulong probe_rem=probe_cnt; probe_rem; probe_rem-- ) {
      MAP_ELE_T const * probe = ele0 + probe_idx;
      MAP_TEST( !MAP_(ele_is_free)( probe ) );

      int found =
#       if MAP_MEMOIZE && MAP_KEY_EQ_IS_SLOW
        FD_LIKELY( probe->MAP_MEMO == ele->MAP_MEMO ) &&
#       endif
        MAP_(key_eq)( &probe->MAP_KEY, &ele->MAP_KEY );

      MAP_TEST( (probe_rem==1UL) ? found : !found );

      probe_idx = (probe_idx+1UL) & ele_mask;
    }
  }

  /* At this point, every key in the map is reachable via it's probe
     sequence and every probe sequence is at most probe_max probes long.
     By extension, if a key is in the map, it will be found in at most
     probe_max probes. */

# undef MAP_TEST

  return 0;
}

#endif

#undef MAP_
#undef MAP_STATIC

#undef MAP_IMPL_STYLE
#undef MAP_PREFETCH
#undef MAP_CTX_MAX
#undef MAP_ELE_MOVE
#undef MAP_ELE_FREE
#undef MAP_ELE_IS_FREE
#undef MAP_KEY_EQ_IS_SLOW
#undef MAP_MEMO
#undef MAP_MEMOIZE
#undef MAP_KEY_HASH
#undef MAP_KEY_EQ
#undef MAP_KEY
#undef MAP_KEY_T
#undef MAP_ELE_T
#undef MAP_NAME
