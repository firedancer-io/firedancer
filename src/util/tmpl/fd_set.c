/* Declare a bunch of functions for fast manipulation of index sets that
   can contain a large compile time bounded number of elements and that
   can be shared between processes.  The implementation is optimized for
   dense-ish sets with a largish maximum element contains (thousands+).
   Example:

     #define SET_NAME my_set
     #define SET_MAX  65536   ... Should be in [1,2^31-64]
     #include "util/tmpl/fd_set.c"

   Will implement and expose the following header only library in the
   local compilation unit:

     my_set_t // opaque handle type for the set

     // interprocess shared memory constructors / destructors
     // these obey the usual conventions

     ulong      my_set_align    ( void             ); // required byte alignment of a my_set_t
     ulong      my_set_footprint( void             ); // required byte footprint of a my_set_t
     void *     my_set_new      ( void     * shmem ); // format memory region into a my_set, my_set will be empty
                                                      // (caller not joined on return, mem has required align/footprint, etc)
     my_set_t * my_set_join     ( void     * shset ); // join a my_set_t (unlimited joins, etc)
     void *     my_set_leave    ( my_set_t *   set ); // leave a my_set_t (matched with join, etc)
     void *     my_set_delete   ( void     * shset ); // unformat memory (no active joins, etc)

     // it is also possible to do declaration based allocation via

     my_set_t set[ my_set_word_cnt ];

     // Returns 1 if set appears to be point to a valid set, 0 otherwise
     // (e.g. set is NULL, there's corruption in the set zero padding,
     // etc). 

     int my_set_valid( my_set_t const * set )

     // Returns 1 if idx is a valid set element index (i.e. in [0,max)
     // (It is okay to pass NULL for set here as it is technically
     // ignored).

     int my_set_valid_idx( my_set_t const * set, ulong idx )

     // Return the maximum number of elements this set can contain.  Set
     // elements are indexed [0,max).  (It is okay to pass NULL for set
     // here as it is technically ignored.)

     ulong my_set_max( my_set_t const * set ); // Return positive

     // Return the current number of elements this set contains

     ulong my_set_cnt( my_set_t const * set ); // Return in [0,max]

     // Return 1 if set contains no elements and 0 if not

     int my_set_is_null( my_set_t const * set );

     // Return 1 if set contains all elements and 0 if not

     int my_set_is_full( my_set_t const * set );

     // Return the lowest indexed element in the set

     ulong my_set_first( my_set_t const * set ); // Return in [0,max) on success, >=max if empty set

     // Two pair of functions for writing efficient iterators over all
     // members of sparse sets.  The first pair is a destructive
     // iterator:
     //
     //   for( ulong idx=my_set_iter_init( set ); !my_set_iter_done( idx ); idx=my_set_iter_next( set, idx ) ) {
     //     ... idx is the next element of the set, will be in [0,max)
     //     ... set elements will be iterated over in increasing order
     //     ... do not modify set, modify idx; there are no elements
     //     ... in set before idx at this point
     //   }
     //   ... set will be empty at this point
     //
     // The second pair is a non-destructive iterator:
     //
     //   for( ulong idx=my_set_const_iter_init( set ); !my_set_const_iter_done( idx ); idx=my_set_const_iter_next( set, idx ) ) {
     //     ... idx is the next element of the set, will be in [0,max)
     //     ... set elements will be iterated over in increasing order
     //     ... do not modify set or modify idx; set is unchanged
     //     ... at this point
     //   }
     //   ... set is unchanged at this point
     //
     // The performance difference between the two styles are situation
     // dependent (depends on the sizes of the set, cache conditions,
     // distribution of elements in the set, etc) but not expected to be
     // large.  In general though, the above iterators are best for very
     // sparse sets.  For dense sets, the idiom:
     //
     //   ulong max = my_set_max( set );
     //   for( ulong idx=0UL; idx<max; idx++ ) {
     //     if( !my_set_test( set, idx ) ) continue;
     //     ... idx is the next element of the set, will be in [0,max)
     //     ... set elements will be iterated over in increasing order
     //     ... do not modify set or modify idx; set is unchanged
     //     ... at this point
     //   }
     //   ... set is unchanged at this point
     //
     // or is more predictable branchless speculative variant:
     //
     //   ulong max = my_set_max( set );
     //   for( ulong idx=0UL; idx<max; idx++ ) {
     //     ... speculate idx is in the set, will be in [0,max)
     //     ... set elements will be iterated over in increasing order
     //     ... do not modify set or modify idx; set is unchanged
     //     ... at this point
     //     ... commit speculation when my_set_test( set, idx ) is true
     //   }
     //   ... set is unchanged at this point
     //
     // might be preferable.

     ulong my_set_iter_init( my_set_t * set );
     int   my_set_iter_done( ulong idx );
     ulong my_set_iter_next( my_set_t * set, ulong idx );

     ulong my_set_const_iter_init( my_set_t const * set );
     int   my_set_const_iter_done( ulong idx );
     ulong my_set_const_iter_next( my_set_t const * set, ulong idx );

     // Insert/remove element idx to a set if not already present (no-op
     // otherwise).  Returns set.

     my_set_t * my_set_insert( my_set_t * set, ulong idx ); // in [0,max).
     my_set_t * my_set_remove( my_set_t * set, ulong idx ); // in [0,max).

     // Fast version of "c ? my_set_{insert,remove}( set, idx ) : set".

     my_set_t * my_set_insert_if( my_set_t * set, int c, ulong idx ); // in [0,max).
     my_set_t * my_set_remove_if( my_set_t * set, int c, ulong idx ); // in [0,max).

     // Return 1 if idx is in set and 0 otherwise

     int my_set_test( my_set_t const * set, ulong idx ); // in [0,max).

     // Returns 1 if x and y contain the same elements, 0 otherwise.  In
     // place is fine.

     int my_set_eq( my_set_t const * x, my_set_t const * y );

     // Returns 1 if x is a subset of y (including x==y), 0 otherwise.
     // In place is fine.

     int my_set_subset( my_set_t const * x, my_set_t const * y );

     // Operations that populate an output set.  All of these return z
     // and inplace operation is fine.

     my_set_t * my_set_null      ( my_set_t * z );                                                // z =  {}
     my_set_t * my_set_full      ( my_set_t * z );                                                // z = ~{}
     my_set_t * my_set_full_if   ( my_set_t * z, int c );                                         // z = c ? {idx} : {}
     my_set_t * my_set_ele       ( my_set_t * z, ulong idx );                                     // z = {idx}
     my_set_t * my_set_ele_if    ( my_set_t * z, int c, ulong idx );                              // z = c ? {idx} : {}
     my_set_t * my_set_copy      ( my_set_t * z, my_set_t const * x );                            // z = x
     my_set_t * my_set_complement( my_set_t * z, my_set_t const * x );                            // z = ~x
     my_set_t * my_set_union     ( my_set_t * z, my_set_t const * x, my_set_t const * y );        // z = x u y
     my_set_t * my_set_intersect ( my_set_t * z, my_set_t const * x, my_set_t const * y );        // z = x n y
     my_set_t * my_set_subtract  ( my_set_t * z, my_set_t const * x, my_set_t const * y );        // z = x - y
     my_set_t * my_set_xor       ( my_set_t * z, my_set_t const * x, my_set_t const * y );        // z = (x u y) - (x n y)
     my_set_t * my_set_if        ( my_set_t * z, int c, my_set_t const * x, my_set_t const * y ); // z = c ? x : y

   With the exception of my_set_valid_idx and my_set_valid, all of these
   assume the inputs are value and will produce strictly valid outputs
   unless otherwise explicitly noted. */

#include "../bits/fd_bits.h"

#ifndef SET_NAME
#error "Define SET_NAME"
#endif

#ifndef SET_MAX
#error "Define SET_MAX"
#endif

FD_STATIC_ASSERT( 1<=SET_MAX && SET_MAX<=2147483584 /* 2^31-64 */, invalid_set_max );

/* Implementation *****************************************************/

#define SET_(x) FD_EXPAND_THEN_CONCAT3(SET_NAME,_,x)

typedef ulong SET_(t);

enum { SET_(word_cnt) = (((int)(SET_MAX))+63)>>6 };

FD_PROTOTYPES_BEGIN

/* Private APIs *******************************************************/

FD_FN_CONST static inline ulong
SET_(private_full_last_word)( void ) {
  return fd_ulong_mask_lsb( SET_MAX - ((SET_(word_cnt)-1)<<6) );
}

/* Public APIs ********************************************************/

FD_FN_CONST static inline ulong SET_(align)    ( void ) { return alignof(ulong); }
FD_FN_CONST static inline ulong SET_(footprint)( void ) { return 8UL*(ulong)SET_(word_cnt); }

static inline void    * SET_(new)   ( void *    shmem ) { return fd_memset( shmem, 0, SET_(footprint)() ); }
static inline SET_(t) * SET_(join)  ( void *    shset ) { return (SET_(t) *)shset; }
static inline void    * SET_(leave) ( SET_(t) * set   ) { return (void *)set; }
static inline void    * SET_(delete)( void *    shset ) { return shset; }

FD_FN_CONST static inline ulong SET_(max)( SET_(t) const * set ) { (void)set; return (ulong)SET_MAX; }

FD_FN_PURE static inline int
SET_(valid)( SET_(t) const * set ) {
  if( FD_UNLIKELY( !set ) ) return 0; /* FIXME: TEST ALIGNMENT TOO? */
  return !(set[ SET_(word_cnt)-1 ] & ~SET_(private_full_last_word()));
}

FD_FN_CONST static inline int
SET_(valid_idx)( SET_(t) const * set,
                 ulong           idx ) {
  (void)set;
  return idx<(ulong)SET_MAX;
}

FD_FN_PURE static inline ulong
SET_(cnt)( SET_(t) const * set ) {
  ulong word_cnt = (ulong)SET_(word_cnt);
  ulong cnt = 0UL;
  for( ulong i=0UL; i<word_cnt; i++ ) cnt += (ulong)fd_ulong_popcnt( set[i] );
  return cnt;
}

FD_FN_PURE static inline int
SET_(is_null)( SET_(t) const * set ) {
  ulong word_cnt = (ulong)SET_(word_cnt);
  for( ulong i=0UL; i<word_cnt; i++ ) if( set[i] ) return 0;
  return 1;
}

FD_FN_PURE static inline int
SET_(is_full)( SET_(t) const * set ) {
  ulong word_cnt = ((ulong)SET_(word_cnt))-1UL;
  for( ulong i=0UL; i<word_cnt; i++ ) if( ~set[i] ) return 0;
  return set[word_cnt]==SET_(private_full_last_word());
}

FD_FN_PURE static inline ulong
SET_(first)( SET_(t) const * set ) {
  ulong word_cnt = (ulong)SET_(word_cnt);
  for( ulong i=0UL; i<word_cnt; i++ ) {
    ulong w = set[i];
    if( w ) return (i<<6) + (ulong)fd_ulong_find_lsb( w );
  }
  return ~0UL;
}

FD_FN_UNUSED static ulong /* Work around -Winline */
SET_(iter_next)( SET_(t) * set,
                 ulong     j ) {                     /* We've considered all bits up to and including j */
  j++;                                               /* Lowest bit we haven't considered */
  ulong word_cnt = (ulong)SET_(word_cnt);
  for( ulong i=(j>>6); i<word_cnt; i++ ) {           /* For all words with bits we haven't considered */
    ulong w = set[i];                                /* Get the bits we haven't considered for the current word */
    if( w ) {                                        /* If any bits are set in this word */
      set[i] = fd_ulong_pop_lsb( w );                /* Clear the lsb */
      return (i<<6) + (ulong)fd_ulong_find_lsb( w ); /* And return the index */
    }
  }
  return ~0UL;                                       /* No more bits to consider */
}
static inline ulong SET_(iter_init)( SET_(t) * set ) { return SET_(iter_next)( set, ~0UL ); }
FD_FN_CONST static inline ulong SET_(iter_done)( ulong j ) { return !~j; }

FD_FN_PURE FD_FN_UNUSED static ulong /* Work around -Winline */
SET_(const_iter_next)( SET_(t) const * set,
                       ulong           j ) {               /* We've considered all bits up to and including j */
  j++;                                                     /* Lowest bit we haven't considered */
  ulong m = (1UL<<(j&63UL))-1UL;                           /* Bits in first word that have been considered */
  ulong word_cnt = (ulong)SET_(word_cnt);
  for( ulong i=(j>>6); i<word_cnt; i++ ) {                 /* For all words with bits we haven't considered */
    ulong w = set[i] & ~m;                                 /* Get the bits we haven't considered for the current word */
    if( w ) return (i<<6) + (ulong)fd_ulong_find_lsb( w ); /* If any bit is set in this word, return its index */
    m = 0UL;                                               /* Otherwise, continue to next word (haven't considered any bits) */
  }
  return ~0UL;                                             /* No more bits to consider */
}
FD_FN_PURE  static inline ulong SET_(const_iter_init)( SET_(t) const * set ) { return SET_(const_iter_next)( set, ~0UL ); }
FD_FN_CONST static inline ulong SET_(const_iter_done)( ulong j             ) { return !~j; }

static inline SET_(t) *
SET_(insert)( SET_(t) * set,
              ulong     idx ) {
  set[ idx >> 6 ] |= 1UL << (idx & 63UL);
  return set;
}

static inline SET_(t) *
SET_(remove)( SET_(t) * set,
              ulong     idx ) {
  set[ idx >> 6 ] &= ~(1UL << (idx & 63UL));
  return set;
}

static inline SET_(t) *
SET_(insert_if)( SET_(t) * set,
                 int       c,
                 ulong     idx ) {
  set[ idx >> 6 ] |= ((ulong)!!c) << (idx & 63UL);
  return set;
}

static inline SET_(t) *
SET_(remove_if)( SET_(t) * set,
                 int       c,
                 ulong     idx ) {
  set[ idx >> 6 ] &= ~(((ulong)!!c) << (idx & 63UL));
  return set;
}

FD_FN_PURE static inline int
SET_(test)( SET_(t) const * set,
            ulong           idx ) {
  return (int)((set[ idx >> 6 ] >> (idx & 63UL)) & 1UL);
}

FD_FN_PURE static inline int
SET_(eq)( SET_(t) const * x,
          SET_(t) const * y ) {
  ulong word_cnt = (ulong)SET_(word_cnt);
  for( ulong i=0UL; i<word_cnt; i++ ) if( x[i]!=y[i] ) return 0;
  return 1;
}

FD_FN_PURE static inline int
SET_(subset)( SET_(t) const * x,
              SET_(t) const * y ) {
  ulong word_cnt = (ulong)SET_(word_cnt);
  for( ulong i=0UL; i<word_cnt; i++ ) if( x[i]!=(y[i] & x[i]) ) return 0;
  return 1;
}

static inline SET_(t) *
SET_(null)( SET_(t) * z ) {
  ulong word_cnt = (ulong)SET_(word_cnt);
  for( ulong i=0UL; i<word_cnt; i++ ) z[i] = 0UL;
  return z;
}

static inline SET_(t) *
SET_(full)( SET_(t) * z ) {
  ulong word_cnt = ((ulong)SET_(word_cnt))-1UL;
  for( ulong i=0UL; i<word_cnt; i++ ) z[i] = ~0UL;
  z[word_cnt] = SET_(private_full_last_word)();
  return z;
}

static inline SET_(t) *
SET_(full_if)( SET_(t) * z,
               int       c ) {
  ulong word_cnt = ((ulong)SET_(word_cnt))-1UL;
  ulong word     = ((ulong)!c)-1UL;
  for( ulong i=0UL; i<word_cnt; i++ ) z[i] = word;
  z[word_cnt] = word & SET_(private_full_last_word)();
  return z;
}

static inline SET_(t) *
SET_(ele)( SET_(t) * z,
           ulong     idx ) {
  return SET_(insert)( SET_(null)( z ), idx );
}

static inline SET_(t) *
SET_(ele_if)( SET_(t) * z,
              int       c,
              ulong     idx ) {
  return SET_(insert_if)( SET_(null)( z ), c, idx );
}

static inline SET_(t) *
SET_(copy)( SET_(t) *       z,
            SET_(t) const * x ) {
  ulong word_cnt = (ulong)SET_(word_cnt);
  for( ulong i=0UL; i<word_cnt; i++ ) z[i] = x[i];
  return z;
}

static inline SET_(t) *
SET_(complement)( SET_(t) *       z,
                  SET_(t) const * x ) {
  ulong word_cnt = ((ulong)SET_(word_cnt))-1UL;
  for( ulong i=0UL; i<word_cnt; i++ ) z[i] = ~x[i];
  z[word_cnt] = (~x[word_cnt]) & SET_(private_full_last_word)();
  return z;
}

static inline SET_(t) *
SET_(union)( SET_(t) *       z,
             SET_(t) const * x,
             SET_(t) const * y ) {
  ulong word_cnt = (ulong)SET_(word_cnt);
  for( ulong i=0UL; i<word_cnt; i++ ) z[i] = x[i] | y[i];
  return z;
}

static inline SET_(t) *
SET_(intersect)( SET_(t) *       z,
                 SET_(t) const * x,
                 SET_(t) const * y ) {
  ulong word_cnt = (ulong)SET_(word_cnt);
  for( ulong i=0UL; i<word_cnt; i++ ) z[i] = x[i] & y[i];
  return z;
}

static inline SET_(t) *
SET_(subtract)( SET_(t) *       z,
                SET_(t) const * x,
                SET_(t) const * y ) {
  ulong word_cnt = (ulong)SET_(word_cnt);
  for( ulong i=0UL; i<word_cnt; i++ ) z[i] = x[i] & ~y[i];
  return z;
}

static inline SET_(t) *
SET_(xor)( SET_(t) *       z,
           SET_(t) const * x,
           SET_(t) const * y ) {
  ulong word_cnt = (ulong)SET_(word_cnt);
  for( ulong i=0UL; i<word_cnt; i++ ) z[i] = x[i] ^ y[i];
  return z;
}

static inline SET_(t) *
SET_(if)( SET_(t) *       z,
          int             c,
          SET_(t) const * x,
          SET_(t) const * y ) {
  return SET_(copy)( z, c ? x : y );
}

FD_PROTOTYPES_END

#undef SET_

#undef SET_MAX
#undef SET_NAME

