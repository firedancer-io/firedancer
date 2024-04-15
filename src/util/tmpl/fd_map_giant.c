/* Generate prototypes, inlines and/or implementations for ultra high
   performance dynamic key-val maps of gigantic size.  A giant map can
   be persisting beyond the lifetime of creating process, used
   concurrently, used IPC, relocated in memory, naively
   serialized/deserialized and/or moved between hosts.  Memory
   efficiency and flexible footprint are prioritized.  Elements that are
   recently used can be optionally moved to the front of the chains to
   adaptively optimize the maps for recent queries.  Typical usage:

     struct mymap {
       ulong key;  // Technically "MAP_KEY_T MAP_KEY;" (default is ulong key), should not be touched by user
       ulong next; // Technically "ulong     MAP_NEXT;", should not be touched by user
       ... key and next can be located arbitrarily in struct
       ... the mapping of a key to an array index is arbitrary but is
       ... fixed over the lifetime of the key in the map
     };

     typedef struct mymap mymap_t;

     #define MAP_NAME  mymap
     #define MAP_T     mymap_t
     #include "tmpl/fd_map_giant.c"

  will declare the following APIs as a header only style library in the
  compilation unit:

    // mymap_{align,footprint} returns alignment and footprint needed
    // for a memory region to be used as a mymap.  align will be an
    // integer power-of-two and footprint will be a multiple of align.
    // footprint will returns 0 if key_max requires a footprint that
    // would overflow 64-bit.  key_max is the maximum number of keys
    // (elements) the map can hold.
    //
    // mymap_new formats a memory region with the appropriate alignment
    // and footprint whose first byte in the caller's address space is
    // pointed by shmem.  Returns shmem on success and NULL on failure
    // (logs details).  Caller is not joined on return.  The map will be
    // empty.
    //
    // mymap_join joins a mymap.  Assumes shmap points at a memory
    // region formatted as a mymap in the caller's address space.
    // Returns a handle to the caller's local join on success and NULL
    // on failure (logs details).  THIS IS NOT A SIMPLE CAST OF SHMAP!
    // The join can be indexed as a flat array with key_max elements in
    // the caller's address space.
    //
    // mymap_leave leaves a mymap.  Assumes join points to a current
    // local join.  Returns shmap used on join.  THIS IS NOT A SIMPLE
    // CASE OF JOIN!
    //
    // mymap_delete unformats a memory region used as a mymap.  Assumes
    // shmap points to a memory region in the caller's local address
    // space formatted as a mymap, that there are no joins to the mymap
    // and that any application cleanup of the entries has already been
    // done.  Returns shmap on success and NULL on failure.

    ulong     mymap_align    ( void );
    ulong     mymap_footprint( ulong     key_max );
    void *    mymap_new      ( void *    shmem, ulong key_max, ulong seed );
    mymap_t * mymap_join     ( void *    shmap   ); // Indexed [0,key_max)
    void *    mymap_leave    ( mymap_t * join    );
    void *    mymap_delete   ( void *    shmap   );

    // mymap_key_max and mymap_seed return the values used to construct
    // the map.  They assume join is a current local join.  The values
    // will be constant for the map lifetime.

    ulong mymap_key_max( mymap_t const * join );
    ulong mymap_seed   ( mymap_t const * join );

    // mymap_key_cnt returns the current number of keys in the map.
    // Will be in [0,key_max].  mymap_is_full returns 1 if
    // key_cnt==key_max.  Assumes join is a current local join.  The
    // values will be constant until the next map insert / remove.

    ulong mymap_key_cnt( mymap_t const * join );
    int   mymap_is_full( mymap_t const * join );

    // mymap_key_{eq,hash,copy} expose the provided
    // MAP_KEY_{EQ,HASH,COPY} macros as inline functions with strict
    // semantics.  They assume that the provided pointers are in the
    // caller's address space to keys that will not be changed
    // concurrently.  They retains no interest in key on return.
    //
    // mymap_key_eq returns 1 if the *k0 and *k1 are equal and 0
    // otherwise.
    //
    // mymap_key_hash returns the hash *key using the hash function
    // seed.  Should ideally be a random mapping from MAP_KEY_T -> ulong
    // but this depends on what the user actually passed in for
    // MAP_HASH.  The seed used by a particular instance of a giant map
    // can be obtained above.
    //
    // mymap_key_copy deep copies *ks into *kd and returns kd.

    int     mymap_key_eq  ( ulong * k0, ulong * k1       );
    ulong   mymap_key_hash( ulong * key, ulong seed      );
    ulong * mymap_key_copy( ulong * kd, ulong const * ks );

    // mymap_insert inserts the key pointed to by key into the map.
    // Returns the location in the caller's address space of the element
    // for key in the map or NULL if there was no space in the map.
    //
    // Assumes map is a current local join, key points to a valid key in
    // the caller's address space, there are no concurrent operations on
    // the map or key.  The map retains no interest in key.  The
    // returned element will be valid for the lesser of the lifetime of
    // the join and until key is removed from the map.
    //
    // Critically, as this is used in high performance contexts where
    // the application already knows this, THE CALLER PROMISES THE KEY
    // IS NOT IN THE MAP AND THAT THE MAP HAS SPACE FOR KEY.
    //
    // This always succeeds (with the above requirements) and returns
    // non NULL.

    mymap_t * mymap_insert( mymap_t * join, ulong const * key );

    // mymap_remove removes the key pointed to by key from the map.  A
    // pointer in the caller's address space to the former element is
    // returned to allow additional cleanup of the application fields.
    // Returns NULL if key is not in the map.
    //
    // Assumes map is a current local join, key points to a valid key in
    // the caller's address space and there are no concurrent operations
    // on the map or key.  The map retains no interest in key.  Any
    // returned pointer will be valid for the lesser of the lifetime of
    // the join and until the next insert.

    mymap_t * mymap_remove( mymap_t * join, ulong const * key );

    // mymap_query finds the element for the key pointed to by key in
    // the map and returns a pointer to it in the caller's address
    // space.  If key is not found, returns sentinel (usually pass
    // NULL).
    //
    // Assumes map is a current local join, key points to a valid key in
    // the caller's address space and there are no concurrent operations
    // on the map or key.  The map retains no interest in key.  On
    // success, the returned pointer will be valid for the lesser of the
    // lifetime of join or until key is removed.  On failure, the
    // returned pointer lifetime will be that of the sentinel.

    mymap_t * mymap_query( mymap_t * join, ulong const * key, mymap_t * sentinel );

    // mymap_query_const is the same as mymap_query but supports
    // concurrent queries so long as there no concurrently running
    // insert/remove/query operations.  The value fields of the mymap_t
    // returned by this function can be changed by the application (but
    // it is up to the application to manage concurrency between
    // different users modifying the same key).

    mymap_t const * mymap_query_const( mymap_t const * join, ulong const * key, mymap_t const * sentinel );

    // mymap_iter_* allow for iteration over all the keys inserted into
    // a mymap.  The iteration will be in a random order but the order
    // will be identical if repeated with no insert/remove/query
    // operations done in between.  Assumes no concurrent
    // insert/remove/query operations.  Example usage:
    //
    //   for( mymap_t iter = mymap_iter_init( join ); !mymap_iter_done( join, iter ); iter = mymap_iter_next( join, iter ) ) {
    //     mymap_t * ele = mymap_iter_ele( join, iter );
    //
    //     ... process ele here
    //
    //     ... IMPORTANT!  It is _okay_ to insert, remove, query or
    //     ... query_const here.  In particular, if an element is
    //     ... inserted, it may or may not be covered by this iteration.
    //     ... If an element is removed that has not already been
    //     ... iterated over, it will not be iterated over in this
    //     ... iteration.  It is fine to remove the current item being
    //     ... iterated over.
    //
    //     ... WARNING! While this looks like an O(key_cnt) operation,
    //     ... technically, this is an O(key_max) operation under the
    //     ... hood.  As such, use outside critical paths (e.g.
    //     ... checkpointing), on dense maps (e.g. key_cnt/key_max ~
    //     ... O(1)) and/or on maps where key_max is small enough not to
    //     ... matter practically.
    //   }

    struct mymap_iter_private { ... internal use only ... };
    typedef struct mymap_iter_private mymap_iter_t;

    mymap_iter_t    mymap_iter_init     ( mymap_t const * join, mymap_iter_t iter ); // returns iter, NULL join fine
    int             mymap_iter_done     ( mymap_t const * join, mymap_iter_t iter ); // returns 1 if no more iterations, 0 o.w.
    mymap_iter_t    mymap_iter_next     ( mymap_t const * join, mymap_iter_t iter ); // returns next iter value iter
    mymap_t *       mymap_iter_ele      ( mymap_t *       join, mymap_iter_t iter ); // assumes not done, return non-NULL ele
    mymap_t const * mymap_iter_ele_const( mymap_t const * join, mymap_iter_t iter ); // assumes not done, return non-NULL ele

    // mymap_verify returns 0 if the mymap is not obviously corrupt or a
    // -1 (i.e. ERR_INVAL) if it is obviously corrupt (logs details).
    // join is the handle of a current local join to mymap.

    int mymap_verify( mymap_t const * join );

  You can do this as often as you like in a compilation unit to get
  different types of gigantic maps.  Variants exist for making header
  protoypes only and/or implementations if doing a library with multiple
  compilation units.  Further, options exist to use different hashing
  functions, comparison functions, etc as detailed below. */

/* MAP_NAME gives the API prefix to use for map */

#ifndef MAP_NAME
#error "Define MAP_NAME"
#endif

/* MAP_T is the map element type. */

#ifndef MAP_T
#error "Define MAP_T"
#endif

/* MAP_KEY_T is the map key type */

#ifndef MAP_KEY_T
#define MAP_KEY_T ulong
#endif

/* MAP_KEY is the MAP_T key field */

#ifndef MAP_KEY
#define MAP_KEY key
#endif

/* MAP_NEXT is the MAP_T next field */

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

/* MAP_KEY_COPY copys the contents from *ks to *kd.  Non-POD key types
   might need to customize this accordingly.  Defaults to the copy
   operator.  */

#ifndef MAP_KEY_COPY
#define MAP_KEY_COPY(kd,ks) (*(kd))=(*(ks))
#endif

/* MAP_MAGIC is the magic number to use for the structure to aid in
   persistent and or IPC usage. */

#ifndef MAP_MAGIC
#define MAP_MAGIC (0xf17eda2c3763a900UL) /* firedancer gmap version 0 */
#endif

/* 0 - local use only
   1 - library header declaration
   2 - library implementation */

#ifndef MAP_IMPL_STYLE
#define MAP_IMPL_STYLE 0
#endif

/* Implementation *****************************************************/

/* Constructors and verification logs detail on failure (rest only needs
   fd_bits.h, consider making logging a compile time option). */

#include "../log/fd_log.h"

#define MAP_IDX_NULL (~(1UL<<63)) /* 2^63-1 */
#define MAP_(n)      FD_EXPAND_THEN_CONCAT3(MAP_NAME,_,n)

#if MAP_IMPL_STYLE==0 || MAP_IMPL_STYLE==1 /* need structures and inlines */

struct MAP_(private) {

  /* This point is max(128,alignof(MAP_T)) aligned */

  /* 2 ulong here, index 0 is MAP_MAGIC, index 1 is offset from shmem
     region to key_max map array below. */

  /* alignment padding here */

  /* list_cnt ulong here, indexed [0,list_cnt)
     list[ list_idx ], idx is in [0,key_max) or MAP_IDX_NULL, tag is used */

  ulong key_max;    /* yields non-zero footprint, <2^63 */
  ulong seed;       /* hash seed, arbitrary */
  ulong list_cnt;   /* == MAP_(private_list_cnt)( key_max  ) */
  ulong key_cnt;    /* in [0,key_max] */
  ulong free_stack; /* idx is in [0,key_max) or MAP_IDX_NULL, tag is free */

  /* Elements on the free_stack will have bit 63 of their next field set
     to facilitate iteration and validation.  Elements in lists will
     have their bit 63 of their next field clear.  key_max<2^63 ensures
     no confusion possible with MAP_IDX_NULL though this is more
     theoretical as ~2^63 keys is impractical physically. */

  /* This point is max(128,alignof(MAP_T)) aligned */

  /* key_max MAP_T here, hdr[1] above points here */

};

typedef struct MAP_(private) MAP_(private_t);

typedef ulong MAP_(iter_t);

FD_PROTOTYPES_BEGIN

/* map_private_list_cnt returns the number of lists a map with the given
   key_max should use. */

FD_FN_CONST static inline ulong
MAP_(private_list_cnt)( ulong key_max ) {
  /* Compute the number of lists as the power of 2 that makes the
     average chain length between ~1 and ~2 */
  ulong list_min = (key_max>>1) + (key_max&1UL); /* list_min = ceil(key_max/2), at most 2^63, computed without overflow */
  ulong list_cnt = fd_ulong_pow2_up( list_min ); /* at most 2^63 */
  return list_cnt;
}

FD_FN_CONST static inline ulong
MAP_(private_meta_footprint)( ulong list_cnt ) {
  return fd_ulong_align_up( (2UL + list_cnt)*sizeof(ulong) + sizeof(MAP_(private_t)), fd_ulong_max( 128UL, alignof(MAP_T) ) );
}

/* map_private returns the location of the map private for a current
   local join.  Assumes join is a current local join.  map_private_const
   is a const correct version. */

FD_FN_CONST static inline MAP_(private_t) *
MAP_(private)( MAP_T * join ) {
  return (MAP_(private_t) *)(((ulong)join) - sizeof(MAP_(private_t)));
}

FD_FN_CONST static inline MAP_(private_t) const *
MAP_(private_const)( MAP_T const * join ) {
  return (MAP_(private_t) const *)(((ulong)join) - sizeof(MAP_(private_t)));
}

/* map_private_{list,ele}[_const] returns the location in the caller's
   address space of the map lists and elements.  The _const variants are
   for const correctness.  Assumes map is valid. */

FD_FN_PURE static inline ulong *
MAP_(private_list)( MAP_(private_t) * map ) {
  return ((ulong *)map) - map->list_cnt;
}

FD_FN_PURE static inline ulong const *
MAP_(private_list_const)( MAP_(private_t) const * map ) {
  return ((ulong const *)map) - map->list_cnt;
}

/* map_private_list_idx returns the index of the list (in [0,list_cnt)
   that will contain the element corresponding to key (if present at
   all) for a map with list_cnt elements and seed.  Assumes list_cnt is
   an integer power-of 2.  Assumes key points to a key is in the
   caller's address space that will not be changed concurrently.
   Retains no interest in key on return. */

FD_FN_PURE static inline ulong
MAP_(private_list_idx)( MAP_KEY_T const * key,
                        ulong             seed,
                        ulong             list_cnt ) {
  return (MAP_KEY_HASH( (key), (seed) )) & (list_cnt-1UL);
}

/* map_private_box_next boxes idx and tag into a map next field value.
   Assumes idx is in [0,2^63-1==MAP_IDX_NULL] and tag is in [0,1].

   map_private_unbox_idx unboxes the idx from a map next field value.
   Return will be in [0,2^63-1==MAP_IDX_NULL].

   map_private_unbox_tag unboxes the tag from a map next field value.
   Return will be in [0,1] */

FD_FN_CONST static inline ulong MAP_(private_box_next)   ( ulong idx, int tag ) { return idx | (((ulong)tag)<<63); }
FD_FN_CONST static inline ulong MAP_(private_unbox_idx)  ( ulong next )         { return next & MAP_IDX_NULL;      }
FD_FN_CONST static inline int   MAP_(private_unbox_tag)  ( ulong next )         { return (int)(next>>63);          }

/* map_private_is_null returns 1 if idx is the NULL map idx value
   and 0 otherwise. */

FD_FN_CONST static inline int   MAP_(private_is_null)( ulong idx ) { return idx==MAP_IDX_NULL; }

FD_FN_PURE static inline ulong
MAP_(key_max)( MAP_T const * join ) {
  if( FD_UNLIKELY( !join ) ) return 0UL;
  return MAP_(private_const)( join )->key_max;
}

FD_FN_PURE static inline ulong
MAP_(seed)( MAP_T const * join ) {
  if( FD_UNLIKELY( !join ) ) return 0UL;
  return MAP_(private_const)( join )->seed;
}

FD_FN_PURE static inline ulong
MAP_(key_cnt)( MAP_T const * join ) {
  if( FD_UNLIKELY( !join ) ) return 0UL;
  return MAP_(private_const)( join )->key_cnt;
}

FD_FN_PURE static inline int
MAP_(is_full)( MAP_T const * join ) {
  if( FD_UNLIKELY( !join ) ) return 0UL;
  MAP_(private_t) const * map = MAP_(private_const)( join );
  return MAP_(private_is_null)( MAP_(private_unbox_idx)( map->free_stack ) );
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

static inline MAP_KEY_T *
MAP_(key_copy)( MAP_KEY_T *       kd,
                MAP_KEY_T const * ks ) {
  (MAP_KEY_COPY( (kd), (ks) ));
  return kd;
}

FD_FN_PURE static inline MAP_(iter_t)
MAP_(iter_init)( MAP_T const * join ) {
  if( FD_UNLIKELY( !join ) ) return 0UL; /* Debatable */
  MAP_(private_t) const * map = MAP_(private_const)( join );
  ulong ele_rem = map->key_max;
  for( ; ele_rem; ele_rem-- ) if( !MAP_(private_unbox_tag)( join[ ele_rem-1UL ].MAP_NEXT ) ) break;
  return ele_rem;
}

FD_FN_CONST static inline int
MAP_(iter_done)( MAP_T const * join,
                 MAP_(iter_t)  ele_rem ) {
  (void)join;
  return !ele_rem;
}

FD_FN_PURE static inline MAP_(iter_t)
MAP_(iter_next)( MAP_T const * join,
                 MAP_(iter_t)  ele_rem ) {
  for( ele_rem--; ele_rem; ele_rem-- ) if( !MAP_(private_unbox_tag)( join[ ele_rem-1UL ].MAP_NEXT ) ) break;
  return ele_rem;
}

FD_FN_CONST static inline MAP_T *
MAP_(iter_ele)( MAP_T *      join,
                MAP_(iter_t) ele_rem ) {
  return join + ele_rem - 1UL;
}

FD_FN_CONST static inline MAP_T const *
MAP_(iter_ele_const)( MAP_T const * join,
                      MAP_(iter_t)  ele_rem ) {
  return join + ele_rem - 1UL;
}

FD_PROTOTYPES_END

#endif

#if MAP_IMPL_STYLE==1 /* need prototypes */

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong MAP_(align)    ( void );
FD_FN_CONST ulong MAP_(footprint)( ulong   key_max );
void *            MAP_(new)      ( void *  shmem, ulong key_max, ulong seed );
MAP_T *           MAP_(join)     ( void *  shmap );
void *            MAP_(leave)    ( MAP_T * join  );
void *            MAP_(delete)   ( void *  shmap );

MAP_T *
MAP_(insert)( MAP_T *           join,
              MAP_KEY_T const * key );

MAP_T *
MAP_(remove)( MAP_T *           join,
              MAP_KEY_T const * key );

FD_FN_PURE MAP_T *
MAP_(query)( MAP_T *           join,
             MAP_KEY_T const * key,
             MAP_T *           null );

FD_FN_PURE MAP_T *
MAP_(query2)( MAP_T *           join,
             MAP_KEY_T const * key,
             MAP_T *           null );

FD_FN_PURE MAP_T const *
MAP_(query_const)( MAP_T const *     join,
                   MAP_KEY_T const * key,
                   MAP_T const *     null );

FD_FN_PURE int
MAP_(verify)( MAP_T const * join );

MAP_T *
MAP_(pop_free_ele)( MAP_T * join );

MAP_T *
MAP_(push_free_ele)( MAP_T * join,
                     MAP_T * ele );

FD_PROTOTYPES_END

#else /* need implementations */

#if MAP_IMPL_STYLE==0 /* local only */
#define MAP_IMPL_STATIC FD_FN_UNUSED static
#else
#define MAP_IMPL_STATIC
#endif

FD_FN_CONST MAP_IMPL_STATIC ulong
MAP_(align)( void ) {
  return fd_ulong_max( 128UL, alignof(MAP_T) );
}

FD_FN_CONST MAP_IMPL_STATIC ulong
MAP_(footprint)( ulong key_max ) {
  ulong align = MAP_(align)();

  /* memory layout is:

       2 ulong | pad | list_cnt ulong | map_private_t | key_max map_t | pad
       <------ meta_footprint, align multiple ------>
       <------------------ footprint, align multiple -------------------->

     Noting that list_cnt is in [key_max/2,key_max], footprint is
     (conservatively) at most:

       2*sizeof(ulong) + align-1 + key_max*sizeof(ulong) + sizeof(map_private_t) + key_max*sizeof(map_t) + align-1

     Requiring this to be at most ULONG_MAX (such that no calculations
     will overflow) yields the below.  We also must have
     key_max<=2^63-1==MAP_IDX_NULL given how elements are marked. */

  ulong key_thresh = fd_ulong_min( (ULONG_MAX - 2UL*(align-1UL) - 2UL*sizeof(ulong) - sizeof(MAP_(private_t))) /
                                   (sizeof(MAP_T) + sizeof(ulong)), MAP_IDX_NULL );
  if( FD_UNLIKELY( key_max>key_thresh ) ) return 0UL;
  ulong list_cnt       = MAP_(private_list_cnt)      ( key_max  );
  ulong meta_footprint = MAP_(private_meta_footprint)( list_cnt );
  return meta_footprint + fd_ulong_align_up( key_max*sizeof(MAP_T), align );
}

MAP_IMPL_STATIC void *
MAP_(new)( void * shmem,
           ulong  key_max,
           ulong  seed ) {
  ulong * hdr = (ulong *)shmem;

  if( FD_UNLIKELY( !hdr ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)hdr, MAP_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = MAP_(footprint)( key_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad key_max" ));
    return NULL;
  }

  /* Init the metadata */

  ulong list_cnt       = MAP_(private_list_cnt)( key_max );
  ulong meta_footprint = MAP_(private_meta_footprint)( list_cnt );

  MAP_T *           join = (MAP_T *)( ((ulong)shmem) + meta_footprint );
  MAP_(private_t) * map  = MAP_(private)( join );

  map->key_max  = key_max;
  map->seed     = seed;
  map->list_cnt = list_cnt;
  map->key_cnt  = 0UL;

  /* Init the free stack */

  if( FD_UNLIKELY( !key_max ) ) map->free_stack = MAP_(private_box_next)( MAP_IDX_NULL, 1 );
  else {
    map->free_stack = MAP_(private_box_next)( 0UL, 1 );
    for( ulong ele_idx=1UL; ele_idx<key_max; ele_idx++ ) join[ ele_idx-1UL ].MAP_NEXT = MAP_(private_box_next)( ele_idx, 1 );
    join[ key_max-1UL ].MAP_NEXT = MAP_(private_box_next)( MAP_IDX_NULL, 1 );
  }

  /* Set all the lists to null */

  ulong * list = MAP_(private_list)( map );
  for( ulong list_idx=0UL; list_idx<list_cnt; list_idx++ ) list[ list_idx ] = MAP_(private_box_next)( MAP_IDX_NULL, 0 );

  hdr[1] = meta_footprint;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr[0] ) = MAP_MAGIC;
  FD_COMPILER_MFENCE();

  return hdr;
}

MAP_IMPL_STATIC MAP_T *
MAP_(join)( void * shmap ) {
  ulong * hdr = (ulong *)shmap;

  if( FD_UNLIKELY( !hdr ) ) {
    FD_LOG_WARNING(( "NULL shmap" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)hdr, MAP_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmap" ));
    return NULL;
  }

  if( FD_UNLIKELY( hdr[0]!=MAP_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return (MAP_T *)(((ulong)shmap) + hdr[1]);
}

MAP_IMPL_STATIC void *
MAP_(leave)( MAP_T * join ) {

  if( FD_UNLIKELY( !join ) ) {
    FD_LOG_WARNING(( "NULL join" ));
    return NULL;
  }

  return (void *)(((ulong)join) - MAP_(private_meta_footprint)( MAP_(private)( join )->list_cnt ));
}

MAP_IMPL_STATIC void *
MAP_(delete)( void * shmap ) {
  ulong * hdr = (ulong *)shmap;

  if( FD_UNLIKELY( !hdr ) ) {
    FD_LOG_WARNING(( "NULL shmap" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)hdr, MAP_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmap" ));
    return NULL;
  }

  if( FD_UNLIKELY( hdr[0]!=MAP_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr[0] ) = 0UL;
  FD_COMPILER_MFENCE();

  return shmap;
}

static inline long
MAP_(verify_key)( MAP_T *           join,
                  MAP_KEY_T const * key,
                  ulong             cnt ) {
# define MAP_TEST(c) do {                                                        \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); __asm("int $3"); return -1; } \
  } while(0)

  MAP_(private_t) * map = MAP_(private)( join );
  ulong list_idx = MAP_(private_list_idx)( key, map->seed, map->list_cnt );
  ulong key_max  = map->key_max;
  ulong key_cnt  = map->key_cnt;
  ulong ele_idx  = MAP_(private_list)( map )[ MAP_(private_list_idx)( key, map->seed, map->list_cnt ) ];
  while( !MAP_(private_is_null)( ele_idx ) ) {
    MAP_TEST( cnt<key_cnt );
    MAP_TEST( ele_idx<key_max );
    MAP_T const * ele = join + ele_idx;
    MAP_TEST( MAP_(private_list_idx)( &ele->MAP_KEY, map->seed, map->list_cnt )==list_idx );
    cnt++;
    ele_idx  = MAP_(private_unbox_idx)( ele->MAP_NEXT );
    MAP_TEST( !MAP_(private_unbox_tag)( ele->MAP_NEXT ) ); /* Element marked as used */
  }

# undef MAP_TEST
  return (long)cnt;;
}

MAP_IMPL_STATIC MAP_T *
MAP_(insert)( MAP_T *           join,
              MAP_KEY_T const * key ) {
  MAP_(private_t) * map = MAP_(private)( join );

  /* Pop the free stack to allocate an element (this is guaranteed to
     succeed as per contract) */

  ulong ele_idx = MAP_(private_unbox_idx)( map->free_stack );
  MAP_T * ele = join + ele_idx;
  map->free_stack = ele->MAP_NEXT; /* already tagged free */
  map->key_cnt++; /* Consider eliminating this to help make completely concurrent lockfree? */

  /* ... and map the newly allocated element to key (this is also
     guaranteed to not have collisions as per contract). */

  ulong * head = MAP_(private_list)( map ) + MAP_(private_list_idx)( key, map->seed, map->list_cnt );
  MAP_(key_copy)( &ele->MAP_KEY, key );
  ele->MAP_NEXT = MAP_(private_box_next)( MAP_(private_unbox_idx)( *head ), 0 );
  *head = MAP_(private_box_next)( ele_idx, 0 );

  return ele;
}

MAP_IMPL_STATIC MAP_T *
MAP_(pop_free_ele)( MAP_T * join ) {
  MAP_(private_t) * map = MAP_(private)( join );

  /* Pop the free stack to allocate an element (this is guaranteed to
     succeed as per contract) */

  ulong ele_idx = MAP_(private_unbox_idx)( map->free_stack );
  FD_TEST(ele_idx != MAP_IDX_NULL);
  MAP_T * ele = join + ele_idx;
  map->free_stack = ele->MAP_NEXT; /* already tagged free */

  return ele;
}

MAP_IMPL_STATIC MAP_T *
MAP_(push_free_ele)( MAP_T * join,
                     MAP_T * ele ) {
  MAP_(private_t) * map = MAP_(private)( join );

  ulong ele_idx = (ulong)(ele - join);

  ele->MAP_NEXT = map->free_stack; /* already tagged free */
  map->free_stack = MAP_(private_box_next)( ele_idx, 1 );

  return ele;
}

MAP_IMPL_STATIC MAP_T *
MAP_(insert_free_ele)( MAP_T *           join,
                       MAP_T *           ele,
                       MAP_KEY_T const * key ) {
  MAP_(private_t) * map = MAP_(private)( join );
  /* Map the allocated element to key (this is also
     guaranteed to not have collisions as per contract). */

  ulong ele_idx = (ulong)(ele - join);

  ulong * head = MAP_(private_list)( map ) + MAP_(private_list_idx)( key, map->seed, map->list_cnt );
  MAP_(key_copy)( &ele->MAP_KEY, key );
  ele->MAP_NEXT = MAP_(private_box_next)( MAP_(private_unbox_idx)( *head ), 0 );
  *head = MAP_(private_box_next)( ele_idx, 0 );

  return ele;
}

MAP_IMPL_STATIC MAP_T *
MAP_(remove)( MAP_T *           join,
              MAP_KEY_T const * key ) {
  MAP_(private_t) * map = MAP_(private)( join );

  ulong   list_cnt = map->list_cnt;
  ulong * list     = MAP_(private_list)( map );

  /* Find the key */

  ulong * head = list + MAP_(private_list_idx)( key, map->seed, list_cnt );
  ulong * cur  = head;
  for(;;) {
    ulong ele_idx = MAP_(private_unbox_idx)( *cur );
    if( FD_UNLIKELY( MAP_(private_is_null)( ele_idx ) ) ) break;
    MAP_T * ele = join + ele_idx;
    if( FD_LIKELY( MAP_(key_eq)( key, &ele->MAP_KEY ) ) ) { /* Optimize for found (it is remove after all) */
      /* Found, remove the mapping and push it to free stack. */
      *cur = ele->MAP_NEXT; /* already tagged empty */
      ele->MAP_NEXT = map->free_stack; /* already tagged free */
      map->free_stack = MAP_(private_box_next)( ele_idx, 1 );
      map->key_cnt--;
      return ele;
    }
    cur = &ele->MAP_NEXT; /* Retain the pointer to next so we can rewrite it later. */
  }

  /* Not found */

  return NULL;
}

FD_FN_PURE MAP_IMPL_STATIC MAP_T *
MAP_(query)( MAP_T *           join,
             MAP_KEY_T const * key,
             MAP_T *           sentinel ) {
  MAP_(private_t) * map = MAP_(private)( join );

  ulong   list_cnt = map->list_cnt;
  ulong * list     = MAP_(private_list)( map );

  /* Find the key */

  ulong * head = list + MAP_(private_list_idx)( key, map->seed, list_cnt );
  ulong * cur  = head;
  for(;;) {
    ulong ele_idx = MAP_(private_unbox_idx)( *cur );
    if( FD_UNLIKELY( MAP_(private_is_null)( ele_idx ) ) ) break; /* optimize for found */
    MAP_T * ele = join + ele_idx;
    if( FD_LIKELY( MAP_(key_eq)( key, &ele->MAP_KEY ) ) ) { /* optimize for found */
      /* Found, move it to the front of the chain. (FIXME: BRANCH PROB? DO BRANCHLESS?) */
      if( FD_UNLIKELY( cur!=head ) ) { /* Assume already at head from previous query */
        *cur = ele->MAP_NEXT;  /* Already tagged free */
        ele->MAP_NEXT = *head; /* Already tagged free */
        *head = MAP_(private_box_next)( ele_idx, 0 );
      }
      return ele;
    }
    cur = &ele->MAP_NEXT; /* Retain the pointer to next so we can rewrite it later. */
  }

  /* Not found */

  return sentinel;
}

FD_FN_PURE MAP_IMPL_STATIC MAP_T *
MAP_(query2)( MAP_T *           join,
             MAP_KEY_T const * key,
             MAP_T *           sentinel ) {
  MAP_(private_t) * map = MAP_(private)( join );

  ulong   list_cnt = map->list_cnt;
  ulong * list     = MAP_(private_list)( map );

  /* Find the key */

  ulong * head = list + MAP_(private_list_idx)( key, map->seed, list_cnt );
  ulong * cur  = head;
  for(;;) {
    ulong ele_idx = MAP_(private_unbox_idx)( *cur );
    if( FD_UNLIKELY( MAP_(private_is_null)( ele_idx ) ) ) break; /* optimize for found */
    MAP_T * ele = join + ele_idx;
    if( FD_LIKELY( MAP_(key_eq)( key, &ele->MAP_KEY ) ) ) return ele; /* optimize for found */
    cur = &ele->MAP_NEXT;
  }

  /* Not found */

  return sentinel;
}

FD_FN_PURE MAP_IMPL_STATIC MAP_T const *
MAP_(query_const)( MAP_T const *     join,
                   MAP_KEY_T const * key,
                   MAP_T const *     sentinel ) {
  MAP_(private_t) const * map = MAP_(private_const)( join );

  ulong         list_cnt = map->list_cnt;
  ulong const * list     = MAP_(private_list_const)( map );

  /* Find the key */

  ulong const * head = list + MAP_(private_list_idx)( key, map->seed, list_cnt );
  ulong const * cur  = head;
  for(;;) {
    ulong ele_idx = MAP_(private_unbox_idx)( *cur );
    if( FD_UNLIKELY( MAP_(private_is_null)( ele_idx ) ) ) break; /* optimize for found */
    MAP_T const * ele = join + ele_idx;
    if( FD_LIKELY( MAP_(key_eq)( key, &ele->MAP_KEY ) ) ) return ele; /* optimize for found */
    cur = &ele->MAP_NEXT;
  }

  /* Not found */

  return sentinel;
}

FD_FN_PURE MAP_IMPL_STATIC int
MAP_(verify)( MAP_T const * join ) {

# define MAP_TEST(c) do {                                                        \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); __asm("int $3"); return -1; } \
  } while(0)

  MAP_TEST( join );

  MAP_(private_t) const * map = MAP_(private_const)( join ); MAP_TEST( map!=NULL );

  MAP_TEST( MAP_(footprint)( map->key_max ) );

  /* seed can be anything as far as map is concerned */

  MAP_TEST( map->list_cnt==MAP_(private_list_cnt)( map->key_max ) );
  MAP_TEST( map->key_cnt <=map->key_max                           );

  ulong         key_max  = map->key_max;
  ulong         key_cnt  = map->key_cnt;
  ulong         seed     = map->seed;
  ulong         list_cnt = map->list_cnt;
  ulong const * list     = MAP_(private_list_const)( map ); MAP_TEST( list!=NULL );

  ulong free_cnt = key_max - key_cnt;

  ulong ele_idx;
  ulong cnt;

  cnt = 0UL;
  for( ulong list_idx=0UL; list_idx<list_cnt; list_idx++ ) {
    ele_idx =  MAP_(private_unbox_idx)( list[ list_idx ] );
    MAP_TEST( !MAP_(private_unbox_tag)( list[ list_idx ] ) ); /* Head marked as used */
    while( !MAP_(private_is_null)( ele_idx ) ) {
      MAP_TEST( cnt<key_cnt );
      MAP_TEST( ele_idx<key_max );
      MAP_T const * ele = join + ele_idx;
      MAP_TEST( MAP_(private_list_idx)( &ele->MAP_KEY, seed, list_cnt )==list_idx );
      cnt++;
      ele_idx  = MAP_(private_unbox_idx)( ele->MAP_NEXT );
      MAP_TEST( !MAP_(private_unbox_tag)( ele->MAP_NEXT ) ); /* Element marked as used */
    }
  }

  MAP_TEST( cnt==key_cnt );

  cnt = 0UL;

  ele_idx = MAP_(private_unbox_idx)( map->free_stack );
  MAP_TEST( MAP_(private_unbox_tag)( map->free_stack ) ); /* Head marked as free */
  while( !MAP_(private_is_null)( ele_idx ) ) {
    MAP_TEST( cnt<free_cnt );
    MAP_TEST( ele_idx<key_max );
    MAP_T const * ele = join + ele_idx;
    cnt++;
    ele_idx = MAP_(private_unbox_idx)( ele->MAP_NEXT );
    MAP_TEST( MAP_(private_unbox_tag)( ele->MAP_NEXT ) ); /* Element marked as free */
  }

  MAP_TEST( cnt==free_cnt );

  for( ulong ele_idx=0UL; ele_idx<key_cnt; ele_idx++ ) {
    if( MAP_(private_unbox_tag)( join[ele_idx].MAP_NEXT ) ) continue;
    MAP_TEST( MAP_(query_const)( join, &join[ele_idx].MAP_KEY, NULL )==&join[ele_idx] );
  }

# undef MAP_TEST

  return 0;
}

#undef MAP_IMPL_STATIC

#endif

#undef MAP_
#undef MAP_IDX_NULL

#undef MAP_IMPL_STYLE
#undef MAP_MAGIC
#undef MAP_KEY_COPY
#undef MAP_KEY_HASH
#undef MAP_KEY_EQ
#undef MAP_NEXT
#undef MAP_KEY
#undef MAP_KEY_T
#undef MAP_T
#undef MAP_NAME
