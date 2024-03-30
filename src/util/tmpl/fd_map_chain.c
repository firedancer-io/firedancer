/* Generate prototypes, inlines and/or implementations for ultra high
   performance maps based on hash chains.  A map can store a practically
   unbounded number of elements but, if sized on creation for the
   maximum number of mapped elements, typical map operations are a fast
   O(1) time and map element overhead is a small O(1) space.

   This API is designed for ultra tight coupling with pools, treaps,
   heaps, lists, other maps, etc.  Likewise, a map can be persisted
   beyond the lifetime of the creating process, used concurrently in
   many common operations, used inter-process, relocated in memory,
   naively serialized/deserialized, moved between hosts, supports index
   compression for cache and memory bandwidth efficiency, etc.

   Memory efficiency and flexible footprint are prioritized.  Elements
   that are recently queried can be optionally moved to the front of
   hash chains to adaptively optimize the maps for recent queries in
   non-concurrent use cases.

   Typical usage:

     struct myele {
       ulong key;  // Technically "MAP_KEY_T MAP_KEY"  (default is ulong key),  do not modify while the element is in the map
       ulong next; // Technically "MAP_IDX_T MAP_NEXT" (default is ulong next), do not modify while the element is in the map
       ... key and next can be located arbitrarily in the element and
       ... can be reused for other purposes when the element is not in a
       ... map.  The mapping of a key to an element storage index is
       ... arbitrary but an element should not be moved / released while
       ... an element is in a map.
     };

     typedef struct myele myele_t;

     #define MAP_NAME  mymap
     #define MAP_ELE_T myele_t
     #include "tmpl/fd_map_chain.c"

   will declare the following APIs as a header only style library in the
   compilation unit:

     // mymap_ele_max returns the theoretical maximum number of elements
     // that can be mapped by a mymap.

     ulong mymap_ele_max( void );

     // mymap_chain_max returns the theoretical maximum number possible
     // chains in a mymap.  Will be an integer power-of-two.

     ulong mymap_chain_max( void );

     // mymap_chain_cnt_est returns a reasonable number of chains to use
     // for a map that is expected to hold up to ele_max_est elements.
     // ele_max_est will be clamped to be in [1,mymap_ele_max()] and the
     // return value will be a integer power-of-two in
     // [1,mymap_chain_max()].

     ulong mymap_chain_cnt_est( ulong ele_max_est );

     // mymap_{align,footprint} returns the alignment and footprint
     // needed for a memory region to be used as a mymap.  align will be
     // an integer power-of-two and footprint will be a multiple of
     // align.  footprint returns 0 if chain_cnt is not an integer
     // power-of-two in [1,mymap_chain_max()].
     //
     // mymap_new formats a memory region with the appropriate alignment
     // and footprint whose first byte in the caller's address space is
     // pointed by shmem for use as a mymap.  Returns shmem on success
     // and NULL on failure (logs details).  Caller is not joined on
     // return.  The map will be empty.
     //
     // mymap_join joins a mymap.  Assumes shmap points at a memory
     // region formatted as a mymap in the caller's address space.
     // Returns a handle to the caller's local join on success and NULL
     // on failure (logs details).  Do not assume this is a simple cast
     // of shmap!
     //
     // mymap_leave leaves a mymap.  Assumes join points to a current
     // local join.  Returns shmap used on join.  Do not assume this is
     // a simple cast of join!
     //
     // mymap_delete unformats a memory region used as a mymap.  Assumes
     // shmap points to a memory region in the caller's local address
     // space formatted as a mymap, that there are no joins to the mymap
     // and that any application cleanup of the entries has already been
     // done.  Returns shmap on success and NULL on failure.

     ulong     mymap_align    ( void );
     ulong     mymap_footprint( ulong chain_cnt );
     void *    mymap_new      ( void * shmem, ulong chain_cnt, ulong seed );
     mymap_t * mymap_join     ( void * shmap );
     void *    mymap_leave    ( mymap_t * join  );
     void *    mymap_delete   ( void * shmap );

     // mymap_{chain_cnt,seed} return the values used to construct the
     // map.  They assume join is a current local join.  The values will
     // be constant for the map lifetime.

     ulong mymap_chain_cnt( mymap_t const * join );
     ulong mymap_seed     ( mymap_t const * join );

     // mymap_key_{eq,hash} expose the provided MAP_KEY_{EQ,HASH} macros
     // as inline functions with strict semantics.  They assume that the
     // provided pointers are in the caller's address space to keys that
     // will not be changed concurrently.  They retain no interest in
     // any keys on return.
     //
     // mymap_key_eq returns 1 if *k0 and *k1 are equal and 0 otherwise.
     //
     // mymap_key_hash returns the hash of *key using the hash function
     // seed.  Should ideally be a random mapping from MAP_KEY_T to
     // ulong but this depends on what the user actually passed in for
     // MAP_KEY_HASH.  The seed used by a particular instance of a map
     // can be obtained above.

     int   mymap_key_eq  ( ulong * k0,  ulong * k1 );
     ulong mymap_key_hash( ulong * key, ulong seed );

     // mymap_idx_insert inserts an element into the map.  The caller
     // promises the element is not currently in the map and that
     // element key is not equal to the key of any other element
     // currently in the map.  Assumes there are no concurrent
     // operations on the map.  This always succeeds.

     mymap_t *                            // Returns join
     mymap_idx_insert( mymap_t * join,    // Current local join to element map
                       ulong     ele_idx, // Index of element to insert
                       myele_t * pool );  // Current local join to element storage

     // mymap_idx_remove removes the mapping of a key to an element.
     // Assumes there are no concurrent operations on the map and that
     // *key will not be modified during the remove.  The map retains no
     // interest in key.  On success, the map will no longer have an
     // interest in the returned element.  On failure, the returned
     // index lifetime will be that of the sentinel.

     ulong                                     // Index of removed element on success, sentinel on failure
     mymap_idx_remove( mymap_t *     join,     // Current local join to element map
                       ulong const * key,      // Points to the key to remove in the caller's address space
                       ulong         sentinel, // Value to return if key not in map
                       myele_t *     pool );   // Current local join to element storage

     // mymap_idx_query finds the element corresponding to key.  Assumes
     // there are no concurrent operations on the map and that *key will
     // not be modified during the query.  The map retains no interest
     // in key.  On success, the returned index lifetime will be at
     // least as long as the corresponding element is still in the map.
     // On failure, the returned index lifetime will be that of the
     // sentinel.

     ulong                                    // Index of found element on success, sentinel on failure
     mymap_idx_query( mymap_t *     join,     // Current local join to the element map
                      ulong const * key,      // Points to the key to find in the caller's address space
                      ulong         sentinel, // Value to return on failure
                      myele_t *     pool );   // Current local join to element storage

     // mymap_idx_query_const is the same as mymap_idx_query but
     // supports concurrent queries so long as there no concurrently
     // running insert/remove/query operations.  The value fields of the
     // element returned by this function can be changed by the
     // application but it is up to the application to manage
     // concurrency between different users modifying the same element.

     ulong                                            // Index of found element on success, sentinel on failure
     mymap_idx_query_const( mymap_t const * join,     // Current local join to element map
                            ulong const *   key,      // Points to the key to find in the caller's address space
                            ulong           sentinel, // Value to return on failure
                            myele_t const * pool );   // Current local join to element storage

     // The mymap_ele_{insert,remove,query,query_const} variants are the
     // same as the above but use pointers in the caller's address
     // instead of pool element storage indices.

     mymap_t *                           // Returns join
     mymap_ele_insert( mymap_t * join,   // Current local join to element map
                       myele_t * ele,    // Element to insert (assumed to be in pool)
                       myele_t * pool ); // Current local join to element storage

     myele_t *                                 // Removed element on success (will be from pool), sentinel on failure
     mymap_ele_remove( mymap_t *     join,     // Current local join to element map
                       ulong const * key,      // Points to the key to remove in the caller's address space
                       myele_t *     sentinel, // Value to return if key not in map
                       myele_t *     pool );   // Current local join to element storage

     myele_t *                                // Found element on success (will be from pool), sentinel on failure
     mymap_ele_query( mymap_t *     join,     // Current local join to element map
                      ulong const * key,      // Points to the key to find in the caller's address space
                      myele_t *     sentinel, // Value to return if key not in map
                      myele_t *     pool );   // Current local join to element storage

     myele_t const *                                  // Found element on success (will be from pool), sentinel on failure
     mymap_ele_query_const( mymap_t const * join,     // Current local join to element map
                            ulong const *   key,      // Points to the key to find in the caller's address space
                            myele_t const * sentinel, // Value to return if key not in map
                            myele_t const * pool );   // Current local join to element storage

     // mymap_iter_* support fast iteration over all the elements in a
     // map.  The iteration will be in a random order but the order will
     // be identical if repeated with no insert/remove/query operations
     // done in between.  Assumes no concurrent insert/remove/query
     // operations (query_const is fine).  Example usage:
     //
     //   for( mymap_iter_t iter = mymap_iter_init( join, pool );
     //        !mymap_iter_done( iter, join, pool );
     //        iter = mymap_iter_next( iter, join, pool ) ) {
     //     ulong ele_idx = mymap_iter_idx( iter, join, pool );
     //
     //     ... process element here
     //
     //     ... IMPORTANT!  It is _not_ _safe_ to insert, remove
     //     ... or query here (query_const is fine).
     //   }

     struct mymap_iter_private { ... internal use only ... };
     typedef struct mymap_iter_private mymap_iter_t;

     mymap_iter_t    mymap_iter_init     (                    mymap_t const * join, myele_t const * pool );
     int             mymap_iter_done     ( mymap_iter_t iter, mymap_t const * join, myele_t const * pool );
     mymap_iter_t    mymap_iter_next     ( mymap_iter_t iter, mymap_t const * join, myele_t const * pool ); // assumes not done
     ulong           mymap_iter_idx      ( mymap_iter_t iter, mymap_t const * join, myele_t const * pool ); // assumes not done
     myele_t *       mymap_iter_ele      ( mymap_iter_t iter, mymap_t const * join, myele_t *       pool ); // assumes not done
     myele_t const * mymap_iter_ele_const( mymap_iter_t iter, mymap_t const * join, myele_t const * pool ); // assumes not done

     // mymap_verify returns 0 if the mymap is not obviously corrupt or
     // -1 (i.e. ERR_INVAL) otherwise (logs details).

     int
     mymap_verify( mymap_t const * join,    // Current local join to a mymap.
                   ulong           ele_cnt, // Element storage size, in [0,mymap_ele_max()]
                   myele_t const * pool );  // Current local join to element storage, indexed [0,ele_cnt)

   You can do this as often as you like in a compilation unit to get
   different types of maps.  Variants exist for making header prototypes
   only and/or implementations if doing a library with multiple
   compilation units.  Further, options exist to use index compression,
   different hashing functions, comparison functions, etc as detailed
   below. */

/* MAP_NAME gives the API prefix to use for map */

#ifndef MAP_NAME
#error "Define MAP_NAME"
#endif

/* MAP_ELE_T is the map element type. */

#ifndef MAP_ELE_T
#error "Define MAP_ELE_T"
#endif

/* MAP_KEY_T is the map key type */

#ifndef MAP_KEY_T
#define MAP_KEY_T ulong
#endif

/* MAP_KEY is the MAP_ELE_T key field */

#ifndef MAP_KEY
#define MAP_KEY key
#endif

/* MAP_IDX_T is the type used for the next field in the MAP_ELE_T.
   Should be a primitive unsigned integer type.  Defaults to ulong.  A
   map can't use element stores with more elements than the maximum
   value that can be represented by a MAP_IDX_T.  (E.g. if ushort, the
   maximum size element store usable by the map is 65535 elements.) */

#ifndef MAP_IDX_T
#define MAP_IDX_T ulong
#endif

/* MAP_NEXT is the MAP_ELE_T next field */

#ifndef MAP_NEXT
#define MAP_NEXT next
#endif

/* MAP_KEY_EQ returns 0/1 if *k0 is the same/different as *k1 */

#ifndef MAP_KEY_EQ
#define MAP_KEY_EQ(k0,k1) ((*(k0))==(*(k1)))
#endif

/* MAP_KEY_HASH maps *key into ulong uniform pseudo randomly. */

#ifndef MAP_KEY_HASH
#define MAP_KEY_HASH(key,seed) fd_ulong_hash( (*(key)) ^ (seed) )
#endif

/* MAP_MAGIC is the magic number to use for the structure to aid in
   persistent and or IPC usage. */

#ifndef MAP_MAGIC
#define MAP_MAGIC (0xf17eda2c37c3a900UL) /* firedancer cmap version 0 */
#endif

/* 0 - local use only
   1 - library header declaration
   2 - library implementation */

#ifndef MAP_IMPL_STYLE
#define MAP_IMPL_STYLE 0
#endif

/* Implementation *****************************************************/

/* Constructors and verification log details on failure (rest only needs
   fd_bits.h, consider making logging a compile time option). */

#include "../log/fd_log.h"

#define MAP_(n) FD_EXPAND_THEN_CONCAT3(MAP_NAME,_,n)

#if MAP_IMPL_STYLE==0 || MAP_IMPL_STYLE==1 /* need structures and inlines */

struct MAP_(private) {

  /* join points here */

  /* FIXME: consider having an ele_cnt for number of elements in the
     underlying storage? (probably not) consider having a memo of the
     chain in which an element is stored and/or using doubly linked
     chains?  We could do a faster remove by index then. */

  ulong magic;     /* == MAP_MAGIC */
  ulong seed;      /* Hash seed, arbitrary */
  ulong chain_cnt; /* Number of chains, positive integer power-of-two */

  /* MAP_IDX_T chain[ chain_cnt ] here */

};

typedef struct MAP_(private) MAP_(private_t);

typedef MAP_(private_t) MAP_(t);

struct MAP_(iter) {
  ulong chain_rem;
  ulong ele_idx;
};

typedef struct MAP_(iter) MAP_(iter_t);

FD_PROTOTYPES_BEGIN

/* map_private returns the location of the map private for a current
   local join.  Assumes join is a current local join.  map_private_const
   is a const correct version. */

FD_FN_CONST static inline MAP_(private_t) *       MAP_(private)      ( MAP_(t) *       join ) { return join; }
FD_FN_CONST static inline MAP_(private_t) const * MAP_(private_const)( MAP_(t) const * join ) { return join; }

/* map_private_chain returns the location in the caller's address space
   of the map chains.  Assumes map is valid.  map_private_chain_const is
   a const correct version. */

FD_FN_CONST static inline MAP_IDX_T *
MAP_(private_chain)( MAP_(private_t) * map ) {
  return (MAP_IDX_T *)(map+1);
}

FD_FN_CONST static inline MAP_IDX_T const *
MAP_(private_chain_const)( MAP_(private_t) const * map ) {
  return (MAP_IDX_T const *)(map+1);
}

/* map_private_chain_idx returns the index of the chain (in
   [0,chain_cnt) that will contain the element corresponding to key (if
   present at all) for a map with chain_cnt elements and seed.  Assumes
   chain_cnt is an integer power-of-two.  Assumes key points to a key is
   in the caller's address space that will not be changed concurrently.
   Retains no interest in key on return. */

FD_FN_PURE static inline ulong
MAP_(private_chain_idx)( MAP_KEY_T const * key,
                         ulong             seed,
                         ulong             chain_cnt ) {
  return (MAP_KEY_HASH( (key), (seed) )) & (chain_cnt-1UL);
}

/* map_private_{box,unbox} compress / decompress 64-bit in-register
   indices to/from their in-memory representations. */

FD_FN_CONST static inline MAP_IDX_T MAP_(private_box)  ( ulong     idx  ) { return (MAP_IDX_T)idx;  }
FD_FN_CONST static inline ulong     MAP_(private_unbox)( MAP_IDX_T cidx ) { return (ulong)    cidx; }

/* map_private_idx_null returns the element storage index that
   represents NULL. */

FD_FN_CONST static inline ulong MAP_(private_idx_null)( void ) { return (ulong)(MAP_IDX_T)(~0UL); }

/* map_private_idx_is_null returns 1 if idx is the NULL map index
   and 0 otherwise. */

FD_FN_CONST static inline int MAP_(private_idx_is_null)( ulong idx ) { return idx==(ulong)(MAP_IDX_T)(~0UL); }

FD_FN_CONST static inline ulong MAP_(ele_max)( void ) { return (ulong)(MAP_IDX_T)(~0UL); }

FD_FN_CONST static inline ulong
MAP_(chain_max)( void ) {
  return fd_ulong_pow2_dn( (ULONG_MAX + 1UL - alignof(MAP_(t)) - sizeof(MAP_(t))) / sizeof(MAP_IDX_T) );
}

FD_FN_CONST static inline ulong
MAP_(chain_cnt_est)( ulong ele_max_est ) {

  /* Clamp to be in [1,ele_max] (as ele_max_est 0 is degenerate and as
     the map is guaranteed to hold at most ele_max keys). */

  ele_max_est = fd_ulong_min( fd_ulong_max( ele_max_est, 1UL ), MAP_(ele_max)() );

  /* Compute the number of chains as the power of 2 that makes the
     average chain length between ~1 and ~2 when ele_max_est are stored
     in the map and then clamp to the chain max. */

  ulong chain_min = (ele_max_est>>1) + (ele_max_est&1UL); /* chain_min = ceil(ele_max_est/2), in [1,2^63], computed w/o overflow */
  ulong chain_cnt = fd_ulong_pow2_up( chain_min );        /* Power of 2 in [1,2^63] */

  return fd_ulong_min( chain_cnt, MAP_(chain_max)() );
}

FD_FN_PURE static inline ulong MAP_(chain_cnt)( MAP_(t) const * join ) { return MAP_(private_const)( join )->chain_cnt; }
FD_FN_PURE static inline ulong MAP_(seed)     ( MAP_(t) const * join ) { return MAP_(private_const)( join )->seed;      }

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

FD_FN_PURE static inline MAP_(iter_t)
MAP_(iter_init)( MAP_(t) const *   join,
                 MAP_ELE_T const * pool ) {
  (void)pool;

  MAP_(private_t) const * map   = MAP_(private_const)( join );
  MAP_IDX_T const *       chain = MAP_(private_chain_const)( map );

  /* Find first element.  If the map is empty, chain_rem will be 0 and
     ele_idx will be idx_null. */

  ulong chain_rem = map->chain_cnt; /* At least 1 */
  ulong ele_idx;
  do {
    ele_idx = MAP_(private_unbox)( chain[ chain_rem-1UL ] );
    if( !MAP_(private_idx_is_null)( ele_idx ) ) break;
  } while( --chain_rem );

  MAP_(iter_t) iter;
  iter.chain_rem = chain_rem;
  iter.ele_idx   = ele_idx;
  return iter;
}

FD_FN_CONST static inline int
MAP_(iter_done)( MAP_(iter_t)      iter,
                 MAP_(t) const *   join,
                 MAP_ELE_T const * pool ) {
  (void)join; (void)pool;
  return !iter.chain_rem;
}

FD_FN_PURE static inline MAP_(iter_t)
MAP_(iter_next)( MAP_(iter_t)      iter,
                 MAP_(t) const *   join,
                 MAP_ELE_T const * pool ) {
  ulong chain_rem = iter.chain_rem;
  ulong ele_idx   = iter.ele_idx;

  /* At this point, we are just finished iterating over element ele_idx
     on chain chain_rem-1 and we already iterated over all elements in
     chains (chain_rem,chain_cnt] and all elements in chain chain_rem-1
     before this element.  As such, ele_idx is in [0,ele_cnt) and
     chain_rem is in (0,chain_cnt].  Get the next element in the chain
     chain_rem-1. */

  ele_idx = MAP_(private_unbox)( pool[ ele_idx ].MAP_NEXT );
  if( MAP_(private_idx_is_null)( ele_idx ) ) {

    /* There were no more elements in chain chain_rem-1.  Find the next
       chain to start processing.  If all unprocessed chains are empty,
       then we are done. */

    MAP_IDX_T const * chain = MAP_(private_chain_const)( MAP_(private_const)( join ) );
    while( --chain_rem ) {
      ele_idx = MAP_(private_unbox)( chain[ chain_rem-1UL ] );
      if( !MAP_(private_idx_is_null)( ele_idx ) ) break;
    }

  }

  iter.chain_rem = chain_rem;
  iter.ele_idx   = ele_idx;
  return iter;
}

FD_FN_CONST static inline ulong
MAP_(iter_idx)( MAP_(iter_t)    iter,
                MAP_(t) const * join,
                MAP_ELE_T *     pool ) {
  (void)join; (void)pool;
  return iter.ele_idx;
}

FD_FN_CONST static inline MAP_ELE_T *
MAP_(iter_ele)( MAP_(iter_t)    iter,
                MAP_(t) const * join,
                MAP_ELE_T *     pool ) {
  (void)join; (void)pool;
  return pool + iter.ele_idx;
}

FD_FN_CONST static inline MAP_ELE_T const *
MAP_(iter_ele_const) ( MAP_(iter_t)      iter,
                       MAP_(t) const *   join,
                       MAP_ELE_T const * pool ) {
  (void)join; (void)pool;
  return pool + iter.ele_idx;
}

FD_PROTOTYPES_END

#endif

#if MAP_IMPL_STYLE==1 /* need prototypes */

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong MAP_(align)    ( void );
FD_FN_CONST ulong MAP_(footprint)( ulong chain_cnt );
void *            MAP_(new)      ( void * shmem, ulong chain_cnt, ulong seed );
MAP_(t) *         MAP_(join)     ( void * shmap );
void *            MAP_(leave)    ( MAP_(t) * join );
void *            MAP_(delete)   ( void * shmap );

MAP_(t) *
MAP_(idx_insert)( MAP_(t) *   join,
                  ulong       ele_idx,
                  MAP_ELE_T * pool );

ulong
MAP_(idx_remove)( MAP_(t) *         join,
                  MAP_KEY_T const * key,
                  ulong             sentinel,
                  MAP_ELE_T *       pool );

FD_FN_PURE ulong
MAP_(idx_query)( MAP_(t) *         join,
                 MAP_KEY_T const * key,
                 ulong             sentinel,
                 MAP_ELE_T *       pool );

FD_FN_PURE ulong
MAP_(idx_query_const)( MAP_(t) const *   join,
                       MAP_KEY_T const * key,
                       ulong             sentinel,
                       MAP_ELE_T const * pool );

FD_FN_PURE int
MAP_(verify)( MAP_(t) const *   join,
              ulong             ele_cnt,
              MAP_ELE_T const * pool );

FD_PROTOTYPES_END

#else /* need implementations */

#if MAP_IMPL_STYLE==0 /* local only */
#define MAP_IMPL_STATIC FD_FN_UNUSED static
#else
#define MAP_IMPL_STATIC
#endif

FD_FN_CONST MAP_IMPL_STATIC ulong MAP_(align)( void ) { return alignof(MAP_(t)); }

FD_FN_CONST MAP_IMPL_STATIC ulong
MAP_(footprint)( ulong chain_cnt ) {
  if( !(fd_ulong_is_pow2( chain_cnt ) & (chain_cnt<=MAP_(chain_max)())) ) return 0UL;
  return fd_ulong_align_up( sizeof(MAP_(t)) + chain_cnt*sizeof(MAP_IDX_T), alignof(MAP_(t)) ); /* no overflow */
}

MAP_IMPL_STATIC void *
MAP_(new)( void * shmap,
           ulong  chain_cnt,
           ulong  seed ) {

  if( FD_UNLIKELY( !shmap ) ) {
    FD_LOG_WARNING(( "NULL shmap" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmap, MAP_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmap" ));
    return NULL;
  }

  ulong footprint = MAP_(footprint)( chain_cnt );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad footprint" ));
    return NULL;
  }

  /* seed is arbitrary */

  /* Init the metadata */

  MAP_(private_t) * map = (MAP_(private_t) *)shmap;

  map->seed      = seed;
  map->chain_cnt = chain_cnt;

  /* Set all the chains to NULL */

  MAP_IDX_T * chain = MAP_(private_chain)( map );
  for( ulong chain_idx=0UL; chain_idx<chain_cnt; chain_idx++ ) chain[ chain_idx ] = MAP_(private_box)( MAP_(private_idx_null)() );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( map->magic ) = MAP_MAGIC;
  FD_COMPILER_MFENCE();

  return shmap;
}

MAP_IMPL_STATIC MAP_(t) *
MAP_(join)( void * shmap ) {
  MAP_(private_t) * map = (MAP_(private_t) *)shmap;

  if( FD_UNLIKELY( !map ) ) {
    FD_LOG_WARNING(( "NULL shmap" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)map, MAP_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmap" ));
    return NULL;
  }

  if( FD_UNLIKELY( map->magic!=MAP_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return (MAP_(t) *)map;
}

MAP_IMPL_STATIC void *
MAP_(leave)( MAP_(t) * join ) {

  if( FD_UNLIKELY( !join ) ) {
    FD_LOG_WARNING(( "NULL join" ));
    return NULL;
  }

  return (void *)join;
}

MAP_IMPL_STATIC void *
MAP_(delete)( void * shmap ) {
  MAP_(private_t) * map = (MAP_(private_t) *)shmap;

  if( FD_UNLIKELY( !map ) ) {
    FD_LOG_WARNING(( "NULL shmap" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)map, MAP_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmap" ));
    return NULL;
  }

  if( FD_UNLIKELY( map->magic!=MAP_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( map->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return shmap;
}

MAP_IMPL_STATIC MAP_(t) *
MAP_(idx_insert)( MAP_(t) *   join,
                  ulong       ele_idx,
                  MAP_ELE_T * pool ) {
  MAP_(private_t) * map = MAP_(private)( join );

  MAP_IDX_T * head = MAP_(private_chain)( map ) + MAP_(private_chain_idx)( &pool[ ele_idx ].MAP_KEY, map->seed, map->chain_cnt );

  pool[ ele_idx ].MAP_NEXT = *head;
  *head = MAP_(private_box)( ele_idx );

  return join;
}

MAP_IMPL_STATIC ulong
MAP_(idx_remove)( MAP_(t) *         join,
                  MAP_KEY_T const * key,
                  ulong             sentinel,
                  MAP_ELE_T *       pool ) {
  MAP_(private_t) * map = MAP_(private)( join );

  /* Find the key */

  MAP_IDX_T * cur = MAP_(private_chain)( map ) + MAP_(private_chain_idx)( key, map->seed, map->chain_cnt );
  for(;;) {
    ulong ele_idx = MAP_(private_unbox)( *cur );
    if( FD_UNLIKELY( MAP_(private_idx_is_null)( ele_idx ) ) ) break; /* optimize for found (it is remove after all) */
    if( FD_LIKELY( MAP_(key_eq)( key, &pool[ ele_idx ].MAP_KEY ) ) ) { /* " */
      *cur = pool[ ele_idx ].MAP_NEXT;
      return ele_idx;
    }
    cur = &pool[ ele_idx ].MAP_NEXT; /* Retain the pointer to next so we can rewrite it later. */
  }

  /* Not found */

  return sentinel;
}

FD_FN_PURE MAP_IMPL_STATIC ulong
MAP_(idx_query)( MAP_(t) *         join,
                 MAP_KEY_T const * key,
                 ulong             sentinel,
                 MAP_ELE_T *       pool ) {
  MAP_(private_t) * map = MAP_(private)( join );

  /* Find the key */

  MAP_IDX_T * head = MAP_(private_chain)( map ) + MAP_(private_chain_idx)( key, map->seed, map->chain_cnt );
  MAP_IDX_T * cur  = head;
  for(;;) {
    ulong ele_idx = MAP_(private_unbox)( *cur );
    if( FD_UNLIKELY( MAP_(private_idx_is_null)( ele_idx ) ) ) break; /* optimize for found */
    if( FD_LIKELY( MAP_(key_eq)( key, &pool[ ele_idx ].MAP_KEY ) ) ) { /* optimize for found */
      /* Found, move it to the front of the chain */
      if( FD_UNLIKELY( cur!=head ) ) { /* Assume already at head from previous query */
        *cur = pool[ ele_idx ].MAP_NEXT;
        pool[ ele_idx ].MAP_NEXT = *head;
        *head = MAP_(private_box)( ele_idx );
      }
      return ele_idx;
    }
    cur = &pool[ ele_idx ].MAP_NEXT; /* Retain the pointer to next so we can rewrite it later. */
  }

  /* Not found */

  return sentinel;
}

FD_FN_PURE MAP_IMPL_STATIC ulong
MAP_(idx_query_const)( MAP_(t) const *   join,
                       MAP_KEY_T const * key,
                       ulong             sentinel,
                       MAP_ELE_T const * pool ) {
  MAP_(private_t) const * map = MAP_(private_const)( join );

  /* Find the key */

  MAP_IDX_T const * cur = MAP_(private_chain_const)( map ) + MAP_(private_chain_idx)( key, map->seed, map->chain_cnt );
  for(;;) {
    ulong ele_idx = MAP_(private_unbox)( *cur );
    if( FD_UNLIKELY( MAP_(private_idx_is_null)( ele_idx ) ) ) break; /* optimize for found */
    if( FD_LIKELY( MAP_(key_eq)( key, &pool[ ele_idx ].MAP_KEY ) ) ) return ele_idx; /* optimize for found */
    cur = &pool[ ele_idx ].MAP_NEXT;
  }

  /* Not found */

  return sentinel;
}

FD_FN_PURE MAP_IMPL_STATIC int
MAP_(verify)( MAP_(t) const *   join,
              ulong             ele_cnt,
              MAP_ELE_T const * pool ) {

# define MAP_TEST(c) do {                                                        \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return -1; } \
  } while(0)

  /* Validate input arguments */

  MAP_TEST( join );
  MAP_TEST( ele_cnt<=MAP_(ele_max)() );
  MAP_TEST( (!!pool) | (!ele_cnt) );

  /* Validate metadata */

  MAP_(private_t) const * map = MAP_(private_const)( join );

  MAP_TEST( map->magic==MAP_MAGIC );

  ulong seed = map->seed;
  /* seed is arbitrary */

  ulong chain_cnt = map->chain_cnt;
  MAP_TEST( fd_ulong_is_pow2( chain_cnt ) );
  MAP_TEST( chain_cnt<=MAP_(chain_max)()  );

  /* Visit each map entry, doing simple chain integrity checks */

  MAP_IDX_T const * chain = MAP_(private_chain_const)( map );

  ulong rem = ele_cnt; /* We can visit at most ele_cnt elements */
  for( ulong chain_idx=0UL; chain_idx<chain_cnt; chain_idx++ )
    for( ulong ele_idx = MAP_(private_unbox)( chain[ chain_idx ] );
         !MAP_(private_idx_is_null)( ele_idx );
         ele_idx = MAP_(private_unbox)( pool[ ele_idx ].MAP_NEXT ) ) {
      MAP_TEST( rem ); rem--;                                                                      /* Check for cycles */
      MAP_TEST( ele_idx<ele_cnt );                                                                 /* Check valid element index */
      MAP_TEST( MAP_(private_chain_idx)( &pool[ ele_idx ].MAP_KEY, seed, chain_cnt )==chain_idx ); /* Check in correct chain */
    }

  /* At this point, we know that there are no cycles in the map chains,
     all indices are inbounds and elements are in the correct chains for
     probes.  It is possible for there to be keys that have been
     inserted more than once though.  We visit all the nodes a second
     time and make sure each probe resolves to itself to prove the key
     of every element in the map is unique.  (We could do this faster if
     we could tag the elements but this verify is written to not modify
     any memory.) */

  for( ulong chain_idx=0UL; chain_idx<chain_cnt; chain_idx++ )
    for( ulong ele_idx = MAP_(private_unbox)( chain[ chain_idx ] );
         !MAP_(private_idx_is_null)( ele_idx );
         ele_idx = MAP_(private_unbox)( pool[ ele_idx ].MAP_NEXT ) )
      MAP_TEST( MAP_(idx_query_const)( join, &pool[ ele_idx ].MAP_KEY, ULONG_MAX, pool )==ele_idx );

# undef MAP_TEST

  return 0;
}

#undef MAP_IMPL_STATIC

#endif

#if MAP_IMPL_STYLE==0 || MAP_IMPL_STYLE==1 /* need inlines */

FD_PROTOTYPES_BEGIN

static inline MAP_(t) *
MAP_(ele_insert)( MAP_(t) *   join,
                  MAP_ELE_T * ele,
                  MAP_ELE_T * pool ) {
  return MAP_(idx_insert)( join, (ulong)(ele-pool), pool );
}

static inline MAP_ELE_T *
MAP_(ele_remove)( MAP_(t) *         join,
                  MAP_KEY_T const * key,
                  MAP_ELE_T *       sentinel,
                  MAP_ELE_T *       pool ) {
  ulong ele_idx = MAP_(idx_remove)( join, key, MAP_(private_idx_null)(), pool );
  return fd_ptr_if( !MAP_(private_idx_is_null)( ele_idx ), (MAP_ELE_T       *)( (ulong)pool + (ele_idx * sizeof(MAP_ELE_T)) ), sentinel );
}

FD_FN_PURE static inline MAP_ELE_T *
MAP_(ele_query)( MAP_(t) *         join,
                 MAP_KEY_T const * key,
                 MAP_ELE_T *       sentinel,
                 MAP_ELE_T *       pool ) {
  ulong ele_idx = MAP_(idx_query)( join, key, MAP_(private_idx_null)(), pool );
  return fd_ptr_if( !MAP_(private_idx_is_null)( ele_idx ), (MAP_ELE_T       *)( (ulong)pool + (ele_idx * sizeof(MAP_ELE_T)) ), sentinel );
}

FD_FN_PURE static inline MAP_ELE_T const *
MAP_(ele_query_const)( MAP_(t) const *   join,
                       MAP_KEY_T const * key,
                       MAP_ELE_T const * sentinel,
                       MAP_ELE_T const * pool ) {
  ulong ele_idx = MAP_(idx_query_const)( join, key, MAP_(private_idx_null)(), pool );
  return fd_ptr_if( !MAP_(private_idx_is_null)( ele_idx ), (MAP_ELE_T const *)( (ulong)pool + (ele_idx * sizeof(MAP_ELE_T)) ), sentinel );
}

FD_PROTOTYPES_END

#endif

#undef MAP_

#undef MAP_IMPL_STYLE
#undef MAP_MAGIC
#undef MAP_KEY_HASH
#undef MAP_KEY_EQ
#undef MAP_NEXT
#undef MAP_IDX_T
#undef MAP_KEY
#undef MAP_KEY_T
#undef MAP_ELE_T
#undef MAP_NAME
