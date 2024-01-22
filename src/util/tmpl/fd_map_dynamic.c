/* Declare ultra high performance dynamic key-val maps of bounded
   run time size.  Typical usage:

     struct mymap {
       ulong key;  // Technically "MAP_KEY_T  MAP_KEY;"  (default is ulong key)
       uint  hash; // Technically "MAP_HASH_T MAP_HASH;" (default is uint  hash), ==mymap_hash(key)
       ... key and hash can be located arbitrarily in struct
       ... hash is not required if MAP_MEMOIZE is zero
       ... the rest of the struct is POD state/values associated with key
       ... the mapping of a key to a map slot is arbitrary and might
       ... change over the lifetime of the key
     };

     typedef struct mymap mymap_t;

     #define MAP_NAME mymap
     #define MAP_T    mymap_t
     #include "util/tmpl/fd_map_dynamic.c"

  will declare the following static inline APIs as a header only style
  library in the compilation unit:

    // align/footprint - Return the alignment/footprint required for a
    // memory region to be used as mymap sufficient to hold up to
    // (2^lg_slot_cnt)-1 keys.  Assumes non-negative lg_slot_cnt.
    //
    // new - Format a memory region pointed to by shmem into a mymap.
    // Assumes shmem points to a region with the required alignment and
    // footprint not in use by anything else.  Caller is not joined on
    // return.  Returns shmem.
    //
    // join - Join a mymap.  Assumes shmap points at a region formatted
    // as a mymap.  Returns a handle of the callers join (will be
    // pointer to an array indexed [0,2^lg_slot_cnt) of mymap_t slots).
    // THIS IS NOT JUST A SIMPLE CAST OF SHMAP.
    //
    // leave - Leave a mymap.  Assumes mymap points to a current join.
    // Returns a pointer to the shared memory region the join.  THIS IS
    // NOT JUST A SIMPLE CAST OF MAP.
    //
    // delete - Unformat a memory region used as a mymap.  Assumes
    // shmymap points to a formatted region with no current joins.
    // Returns a pointer to the unformatted memory region.

    ulong     mymap_align    ( void                             );
    ulong     mymap_footprint( int lg_slot_cnt                  );
    void *    mymap_new      ( void *    shmem, int lg_slot_cnt );
    mymap_t * mymap_join     ( void *    shmap                  ); // Indexed [0,2^lg_slot_cnt)
    void *    mymap_leave    ( mymap_t * map                    );
    void *    mymap_delete   ( void *    shmap                  );

    // Return the current/maximum number of keys that can be inserted
    // into a mymap.  The mymap will become increasingly inefficient the
    // more keys there are.  Recommend not using more than around half
    // this value.

    ulong mymap_key_cnt( mymap_t const * map ); // In [0,key_max]
    ulong mymap_key_max( mymap_t const * map ); // == 2^lg_slot_cnt - 1

    // Return the log2 number of slots / number of slots in a mymap.
    // This is to facilitate iterating / listing all contents of a mymap
    // (this process is not algorithmically ideal for a sparse mymap).
    // E.g.  mymap[slot_idx].key for slot_idx in [0,mymap_slot_cnt()]
    // when key!=0 is the set of all current key-vals in the mymap.

    int   mymap_lg_slot_cnt( mymap_t const * map ); // Non-negative
    ulong mymap_slot_cnt   ( mymap_t const * map ); // == 2^lg_slot_cnt

    // Returns the index of the slot (allows communicating locations of
    // map entries between users of mymap in different address spaces).
    // Might imply a division (probably via magic multiply) if
    // sizeof(mymap_t) is not a power of two (as such, power-of-2
    // sizeof(mymap_t) have good Feng Shui).  Assumes that mymap is a
    // current join and slot points to a slot in that join.

    ulong mymap_slot_idx( mymap_t const * map, mymap_t const * slot );

    // Returns the "null" key, which is the canonical key that will
    // never be inserted (typically zero).

    ulong mymap_key_null( void ); // == MAP_KEY_NULL

    // Return the 1/0 if key is a key that will never/might be inserted.

    int mymap_key_inval( ulong key );

    // Return the 1/0 if k0 and k1 are keys that are the same

    int mymap_key_equal( ulong k0, ulong k1 );

    // Return the hash of key used by the map.  Should ideally be a
    // random mapping from MAP_KEY_T -> MAP_HASH_T.

    uint mymap_key_hash( ulong key );

    // Insert key into the map, fast O(1).  Returns a pointer to the map
    // entry with key on success and NULL on failure (i.e. key is
    // already in the map or there are too many keys in the map to
    // insert this key).  The returned pointer lifetime is until _any_
    // map remove or map leave.  The caller should not change the values
    // in map_key or map_hash but is free to modify other fields in the
    // entry on return.  Assumes map is a current join and key is value
    // that can be inserted.

    mymap_t * mymap_insert( mymap_t * map, ulong key );

    // Remove entry from map, fast O(1).  Assumes map is a current join
    // and that entry points to a full entry currently in the map.
    // Removal performance very slightly more optimal if sizeof(mymap_t)
    // is a power of two.

    void mymap_remove( mymap_t * map, mymap_t * entry );

    // Remove all entries from the map. O(map size).

    void mymap_clear( mymap_t * map );

    // Query map for key, fast O(1).  Returns a pointer to the map slot
    // holding key or null if key not in map.  The returned pointer
    // lifetime is until the next map remove or map leave.  The caller
    // should not change key or hash but is free to modify other fields
    // in the entry.  Assumes map is a current join and that key is
    // non-zero.

    mymap_t * mymap_query( mymap_t * map, ulong key, mymap_t * null );

  You can do this as often as you like in a compilation unit to get
  different types of maps.  Since it is all static inline, it is fine
  to do this in a header too.  Further, options exist to use different
  hashing functions, variable length keys, etc as detailed below.

  For use with non-POD C++ structs, map_new assumes that a slot can be
  initialized to empty by assigning its key to MAP_KEY_NULL.  Map insert
  will use MAP_KEY_MOVE to move the user provided key into the slot key
  value.  Map remove will MAP_MOVE slots as necessary to preserve their
  probe sequences and assumes the user has already cleaned up the entry
  to remove enough so that all that needs to be done to eliminate the
  entry from the map is assign the entry's key to MAP_KEY_NULL.

    mymap_t * slot = mymap_insert( map, cxx_key );
    if( FD_UNLIKELY( !slot ) ) ... handle failure (cxx_key was not moved)
    else {
      ... mymap_insert did a MAP_KEY_MOVE of cxx_key into slot->key
      ... clean cxx_key's shell here as necessary here
      ... initialize other slot fields as necessary
    }

  and on removal:

    ... clean up other slot fields as necessary
    ... clean up slot->key as necessary
    mymap_remove( map, slot );
    ... the mapping of keys to map slots might have been changed by the
    ... mymap_remove.  Any motion of slots was done via:
    ... MAP_MOVE( dst_slot, src_slot ) */

#include "../bits/fd_bits.h"
#include <stddef.h>

#ifndef offsetof
#  define offsetof(TYPE,MEMB) ((ulong)((TYPE*)0)->MEMB)
#endif

#ifndef MAP_NAME
#error "Define MAP_NAME"
#endif

/* A MAP_T should be something something reasonable to shallow copy with
   the fields described above. */

#ifndef MAP_T
#error "Define MAP_T struct"
#endif

/* MAP_HASH_T should be an unsigned integral type. */

#ifndef MAP_HASH_T
#define MAP_HASH_T uint
#endif

/* MAP_HASH is the MAP_T hash field name.  Defaults to hash. */

#ifndef MAP_HASH
#define MAP_HASH hash
#endif

/* MAP_KEY_T should be something reasonable to pass to a static inline
   by value, assign to MAP_KEY_NULL, compare for equality and copy.
   E.g. a uint, ulong, __m128i, etc. */

#ifndef MAP_KEY_T
#define MAP_KEY_T ulong
#else
#if !defined(MAP_KEY_NULL) || !defined(MAP_KEY_INVAL) || !defined(MAP_KEY_EQUAL) || !defined(MAP_KEY_EQUAL_IS_SLOW) || !defined(MAP_KEY_HASH)
#error "Define MAP_KEY_NULL, MAP_KEY_INVAL, MAP_KEY_EQUAL, MAP_KEY_EQUAL_IS_SLOW, and MAP_KEY_HASH if using a custom MAP_KEY_T"
#endif
#endif

/* MAP_KEY is the MAP_T key field name.  Defaults to key. */

#ifndef MAP_KEY
#define MAP_KEY key
#endif

/* MAP_KEY_NULL is a key that will never be inserted. */

#ifndef MAP_KEY_NULL
#define MAP_KEY_NULL 0UL
#endif

/* MAP_KEY_INVAL returns 1 if k0 is key that will never be inserted
   and zero otherwise.  Note that MAP_KEY_INVAL( MAP_KEY_NULL ) should
   be true.  This should be generally fast. */

#ifndef MAP_KEY_INVAL
#define MAP_KEY_INVAL(k) !(k)
#endif

/* MAP_KEY_EQUAL returns 0/1 if k0 is the same/different */

#ifndef MAP_KEY_EQUAL
#define MAP_KEY_EQUAL(k0,k1) (k0)==(k1)
#endif

/* If MAP_KEY_EQUAL_IS_SLOW is slow (e.g. variable length string
   compare, large buffer compares, etc), set MAP_KEY_EQUAL_IS_SLOW to
   non-zero.  Then, if MAP_MEMOIZE (below) is set, precomputed key hashes
   will be used accelerate key insert and key query. */

#ifndef MAP_KEY_EQUAL_IS_SLOW
#define MAP_KEY_EQUAL_IS_SLOW 0
#endif

/* MAP_KEY_HASH takes a key and maps it into MAP_HASH_T uniform pseudo
   randomly. */

#ifndef MAP_KEY_HASH
#define MAP_KEY_HASH(key) ((MAP_HASH_T)fd_ulong_hash( key ))
#endif

/* MAP_KEY_MOVE moves the contents from src to dst.  Non-POD key types
   need to customize this accordingly (and handle the case of
   ks==MAP_KEY_NULL).  Defaults to shallow copy. */

#ifndef MAP_KEY_MOVE
#define MAP_KEY_MOVE(kd,ks) (kd)=(ks)
#endif

/* MAP_MOVE moves the contents of a MAP_T from src to dst.  Non-POD key
   types need to customize this accordingly.  Defaults to shallow copy. */

#ifndef MAP_MOVE
#define MAP_MOVE(d,s) (d)=(s)
#endif

/* If MAP_MEMOIZE is defined to non-zero, the MAP_T requires a
   "map_hash" field that will hold the value of the MAP_KEY_HASH of the
   MAP_T's MAP_KEY when the map slot is not empty (undefined otherwise).
   This is useful for accelerating user operations that might need a
   hash of the key and for accelerating remove operations.  It is also
   potentially useful as a way to accelerate slow key comparison
   operations (see MAP_KEY_EQUAL_IS_SLOW). */

#ifndef MAP_MEMOIZE
#define MAP_MEMOIZE 1
#endif

/* MAP_QUERY_OPT allows the user to specify how the map query function
   should be optimized.
     0 -> optimize for low fill ratio
     1 -> optimize for low fill ratio and extremely rare query failure
     2 -> optimize for low fill ratio and extremely rare query success */

#ifndef MAP_QUERY_OPT
#define MAP_QUERY_OPT 0
#endif

/* Implementation *****************************************************/

#define MAP_(n) FD_EXPAND_THEN_CONCAT3(MAP_NAME,_,n)

struct MAP_(private) {
  ulong key_cnt;     /* == number of keys currently in map */
  ulong slot_mask;   /* == key_max == 2^lg_slot_cnt - 1 */
  int   lg_slot_cnt; /* non-negative */
  MAP_T slot[1];     /* Actually 2^lg_slot_cnt in size */
};

typedef struct MAP_(private) MAP_(private_t);

FD_PROTOTYPES_BEGIN

/* Private APIs *******************************************************/

/* private_from_slot return a pointer to the map_private given a pointer
   to the map's slot.  private_from_map_const also provided for
   const-correctness purposes. */

FD_FN_CONST static inline MAP_(private_t) *
MAP_(private_from_slot)( MAP_T * slot ) {
  ulong slot_ofs = offsetof( MAP_(private_t), slot );
  return (MAP_(private_t) *)( (ulong)slot - (ulong)slot_ofs );
}

FD_FN_CONST static inline MAP_(private_t) const *
MAP_(private_from_slot_const)( MAP_T const * slot ) {
  ulong slot_ofs = offsetof( MAP_(private_t), slot );
  return (MAP_(private_t) const *)( (ulong)slot - (ulong)slot_ofs );
}

/* Get the linear probing starting slot for a key and the slot to probe
   after a given slot */

FD_FN_CONST static inline ulong MAP_(private_start)( MAP_HASH_T hash, ulong slot_mask ) { return (ulong)(hash & (MAP_HASH_T)slot_mask); }
FD_FN_CONST static inline ulong MAP_(private_next) ( ulong      slot, ulong slot_mask ) { return (++slot) & slot_mask; }

/* Public APIS ********************************************************/

FD_FN_CONST static inline ulong MAP_(align)( void ) { return alignof(MAP_(private_t)); }

FD_FN_CONST static inline ulong
MAP_(footprint)( int lg_slot_cnt ) {
  ulong slot_cnt = 1UL << lg_slot_cnt;
  return fd_ulong_align_up( fd_ulong_align_up( 24UL, alignof(MAP_T) ) + sizeof(MAP_T)*slot_cnt, alignof(MAP_(private_t)) );
}

static inline void *
MAP_(new)( void *  shmem,
           int     lg_slot_cnt ) {
  ulong slot_cnt  = 1UL<<lg_slot_cnt;
  ulong slot_mask = slot_cnt - 1UL;
  MAP_(private_t) * map = (MAP_(private_t) *)shmem;

  map->key_cnt     = 0UL;
  map->slot_mask   = slot_mask;
  map->lg_slot_cnt = lg_slot_cnt;

  MAP_T * slot = map->slot; FD_COMPILER_FORGET( slot );

  for( ulong slot_idx=0UL; slot_idx<slot_cnt; slot_idx++ )
    slot[ slot_idx ].MAP_KEY = (MAP_KEY_NULL);

  return map;
}

static inline MAP_T *
MAP_(join)( void * shmap ) {
  MAP_(private_t) * map = (MAP_(private_t) *)shmap;
  MAP_T * slot = map->slot; FD_COMPILER_FORGET( slot );
  return slot;
}

static inline void * MAP_(leave) ( MAP_T * slot  ) { return (void *)MAP_(private_from_slot)( slot ); }
static inline void * MAP_(delete)( void *  shmap ) { return shmap; }

FD_FN_PURE static inline ulong MAP_(key_cnt)    ( MAP_T const * slot ) { return MAP_(private_from_slot_const)( slot )->key_cnt;       }
FD_FN_PURE static inline ulong MAP_(key_max)    ( MAP_T const * slot ) { return MAP_(private_from_slot_const)( slot )->slot_mask;     }
FD_FN_PURE static inline int   MAP_(lg_slot_cnt)( MAP_T const * slot ) { return MAP_(private_from_slot_const)( slot )->lg_slot_cnt;   }
FD_FN_PURE static inline ulong MAP_(slot_cnt)   ( MAP_T const * slot ) { return MAP_(private_from_slot_const)( slot )->slot_mask+1UL; }

FD_FN_CONST static inline ulong MAP_(slot_idx)( MAP_T const * map, MAP_T const * entry ) { return (ulong)(entry - map); }

FD_FN_CONST static inline MAP_KEY_T MAP_(key_null)( void ) { return (MAP_KEY_NULL); }

/* These are FD_FN_PURE instead of FD_FN_CONST in case a non-POD
   MAP_KEY_T.  FIXME: CONSIDER LETTING THE COMPILER SORT THIS OUT? */

FD_FN_PURE static inline int MAP_(key_inval)( MAP_KEY_T k0               ) { return (MAP_KEY_INVAL(k0)); }
FD_FN_PURE static inline int MAP_(key_equal)( MAP_KEY_T k0, MAP_KEY_T k1 ) { return (MAP_KEY_EQUAL(k0,k1)); }

FD_FN_PURE static inline MAP_HASH_T MAP_(key_hash)( MAP_KEY_T key ) { return (MAP_KEY_HASH(key)); }

FD_FN_UNUSED static MAP_T * /* Work around -Winline */
MAP_(insert)( MAP_T *   map,
              MAP_KEY_T key ) {
  MAP_(private_t) * hdr = MAP_(private_from_slot)( map );

  ulong key_cnt   = hdr->key_cnt;
  ulong slot_mask = hdr->slot_mask; /* == key_max (FIXME: MAKE KEY_MAX DISTINCT FROM SLOT_MASK?) */
  if( FD_UNLIKELY( key_cnt >= slot_mask ) ) return NULL;

  MAP_HASH_T hash = MAP_(key_hash)( key );
  ulong      slot = MAP_(private_start)( hash, slot_mask );
  MAP_T * m;
  for(;;) {
    m = map + slot;
    MAP_KEY_T map_key = m->MAP_KEY;
    if( FD_LIKELY( MAP_(key_inval)( map_key ) ) ) break; /* Optimize for not found */
#   if MAP_MEMOIZE && MAP_KEY_EQUAL_IS_SLOW              /* ... and then for searching */
    if( FD_UNLIKELY( m->MAP_HASH==hash && MAP_(key_equal)( map_key, key ) ) ) return NULL;
#   else
    if( FD_UNLIKELY( MAP_(key_equal)( map_key, key ) ) ) return NULL;
#   endif
    slot = MAP_(private_next)( slot, slot_mask );
  }
  MAP_KEY_MOVE( m->MAP_KEY, key );
# if MAP_MEMOIZE
  m->MAP_HASH = hash;
# endif
  hdr->key_cnt = key_cnt + 1UL;
  return m;
}

static inline void
MAP_(remove)( MAP_T * map,
              MAP_T * entry ) {
  MAP_(private_t) * hdr = MAP_(private_from_slot)( map );

  /* FIXME: CONSIDER VALIDATING KEY_CNT AND/OR ENTRY ISN'T VALID */
  hdr->key_cnt--;

  ulong slot_mask = hdr->slot_mask;
  ulong slot      = MAP_(slot_idx)( map, entry );
  for(;;) {

    /* Make a hole at slot */

    map[slot].MAP_KEY = (MAP_KEY_NULL);
    ulong hole = slot;

    /* The creation of a hole at slot might have disrupted the probe
       sequence involving the keys in any contiguously occupied map
       entry after slot. */

    for(;;) {
      slot = MAP_(private_next)( slot, slot_mask );

      /* At this point, map entries (hole,slot) (cyclic) are occupied
         and the probe sequence for these has been confirmed to be
         intact.  If slot is empty, then all probe sequences are intact. */

      MAP_KEY_T key = map[slot].MAP_KEY;
      if( MAP_(key_inval)(key) ) return;

      /* slot is occupied.  If a probe looking for the key at slot does
         not start its scan in (hole,slot] (cyclic), its scan will fail
         erroneously due to the hole just made.  In this case, we move
         slot to hole to restore the probe sequence for the key at slot
         and then make a new hole at slot.  As the new hole could break
         the other probe sequences, we start over on the new hole. */

#     if MAP_MEMOIZE
      MAP_HASH_T hash = map[slot].MAP_HASH;
#     else
      MAP_HASH_T hash = MAP_(key_hash)( key );
#     endif
      ulong start = MAP_(private_start)( hash, slot_mask );
      if( !(((hole<start) & (start<=slot)) | ((hole>slot) & ((hole<start) | (start<=slot)))) ) break;
    }

    MAP_MOVE( map[hole], map[slot] );
  }
  /* never get here */
}

static inline void
MAP_(clear)( MAP_T * map ) {
  MAP_(private_t) * hdr = MAP_(private_from_slot)( map );
  hdr->key_cnt = 0UL;
  ulong slot_cnt  = 1UL<<hdr->lg_slot_cnt;
  MAP_T * slot = hdr->slot;
  for( ulong slot_idx=0UL; slot_idx<slot_cnt; slot_idx++ )
    slot[ slot_idx ].MAP_KEY = (MAP_KEY_NULL);
}

FD_FN_PURE FD_FN_UNUSED static MAP_T * /* Work around -Winline */
MAP_(query)( MAP_T *   map,
             MAP_KEY_T key,
             MAP_T *   null ) {
  ulong      slot_mask = MAP_(private_from_slot)( map )->slot_mask;
  MAP_HASH_T hash      = MAP_(key_hash)( key );
  ulong      slot      = MAP_(private_start)( hash, slot_mask );
  MAP_T * m;
  for(;;) {
    m = map + slot;
    MAP_KEY_T map_key = m->MAP_KEY;

#   if MAP_MEMOIZE && MAP_KEY_EQUAL_IS_SLOW
#   define MAP_IMPL_QUERY_FOUND (hash==m->MAP_HASH && MAP_(key_equal)( map_key, key ))
#   else
#   define MAP_IMPL_QUERY_FOUND MAP_(key_equal)( map_key, key )
#   endif

#   if MAP_QUERY_OPT==0
    int found = MAP_IMPL_QUERY_FOUND;
    int empty = MAP_(key_inval)( map_key );
    int done  = found | empty;
    if( empty ) m = null; /* cmov */
    FD_COMPILER_FORGET( done );
    if( FD_LIKELY( done ) ) break;
#   elif MAP_QUERY_OPT==1
    if( FD_LIKELY( MAP_IMPL_QUERY_FOUND       ) ) break;
    if( FD_LIKELY( MAP_(key_inval)( map_key ) ) ) return null;
#   else
    if( FD_LIKELY( MAP_(key_inval)( map_key ) ) ) return null;
    if( FD_LIKELY( MAP_IMPL_QUERY_FOUND       ) ) break;
#   endif

#   undef MAP_IMPL_QUERY_FOUND

    slot = MAP_(private_next)( slot, slot_mask );
  }
  return m;
}

FD_PROTOTYPES_END

#undef MAP_SLOT_MASK
#undef MAP_SLOT_CNT
#undef MAP_

/* End implementation *************************************************/

#undef MAP_QUERY_OPT
#undef MAP_MEMOIZE
#undef MAP_MOVE
#undef MAP_KEY_MOVE
#undef MAP_KEY_HASH
#undef MAP_KEY_EQUAL_IS_SLOW
#undef MAP_KEY_EQUAL
#undef MAP_KEY_INVAL
#undef MAP_KEY_NULL
#undef MAP_KEY
#undef MAP_KEY_T
#undef MAP_HASH
#undef MAP_HASH_T
#undef MAP_T
#undef MAP_NAME
