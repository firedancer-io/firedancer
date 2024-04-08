/* Declare a header-only API for fast manipulation of index sets where
   the set itself is represented in a primitive unsigned integer type.
   Example:

     #define SET_NAME myset
     #include "util/tmpl/fd_smallset.c"

   will declare the following in the compile unit:

     enum { myset_MAX = 64 }; // maximum number of elements in set (for use in compile time constructors)

     // Set constructors
     myset_t myset_null   ( void           ); // return {}
     myset_t myset_full   ( void           ); // return ~{}
     myset_t myset_full_if( int c          ); // return c ? ~{} : {}
     myset_t myset_ele    ( ulong i        ); // return { i }
     myset_t myset_ele_if ( int c, ulong i ); // return c ? { i } : {}
     
     // Index operations
     ulong myset_max  ( void      ); // return the maximum number of elements that can be held by the set,
                                     // will be in (0,8*sizeof(myset_t)]
     ulong myset_cnt  ( myset_t x ); // return the current number of elements in the set, will be in [0,myset_max()]
     ulong myset_first( myset_t x ); // return the index of the first element in the set, will be in [0,myset_max()),
                                     // U.B. if set is null
     
     // Boolean operations
     int myset_valid_idx( ulong i              ); // returns 1 if i is a valid set index (i.e. idx < myset_max())
     int myset_valid    ( myset_t x            ); // returns 1 if x a valid set (i.e. no bits idx >= myset_max() are set)
     int myset_is_null  ( myset_t x            ); // returns 1 if x is the null set
     int myset_is_full  ( myset_t x            ); // returns 1 if x is the full set
     int myset_test     ( myset_t x, ulong i   ); // returns 1 if element i is in set x
     int myset_eq       ( myset_t x, myset_t y ); // returns 1 if x and y are the same sets
     int myset_subset   ( myset_t x, myset_t y ); // returns 1 if x is a subset of y
     
     // Unary operations
     myset_t myset_copy      ( myset_t x ); // returns x
     myset_t myset_complement( myset_t x ); // returns ~x
     
     // Binary operations
     myset_t myset_union    ( myset_t x, myset_t y ); // returns x u y
     myset_t myset_intersect( myset_t x, myset_t y ); // returns x n y 
     myset_t myset_subtract ( myset_t x, myset_t y ); // returns x - y
     myset_t myset_xor      ( myset_t x, myset_t y ); // returns (x u y) - (x n y)
     
     // Trinary operations
     myset_t myset_if( int c, myset_t t, myset_t f ); // returns c ? t : f

     // Iteration
     //
     // for( myset_iter_t iter=myset_iter_init(set); !myset_iter_done(iter); iter=myset_iter_next(iter) ) {
     //   ulong idx = myset_iter_idx(iter);
     //   ... process element idx of set here
     //   ... do not touch iter
     // }
     //
     // will efficiently iterate over the elements of set in ascending
     // order.

     myset_iter_t myset_iter_init( myset_t      set  );
     myset_iter_t myset_iter_done( myset_iter_t iter );
     myset_iter_t myset_iter_next( myset_iter_t iter );
     ulong        myset_iter_idx ( myset_iter_t iter );
     
     // Misc
     myset_t myset_insert( myset_t x, ulong i ); // short for myset_union   ( x, myset_ele( i ) )
     myset_t myset_remove( myset_t x, ulong i ); // short for myset_subtract( x, myset_ele( i ) )

     myset_t myset_insert_if( int c, myset_t x, ulong i ); // Fast implementation of "c ? myset_insert( x, i ) : x;"
     myset_t myset_remove_if( int c, myset_t x, ulong i ); // Fast implementation of "c ? myset_remove( x, i ) : y;"

     // With the exceptions of myidx_valid_idx and myset_valid, all
     // these assume their inputs are valid and produce valid well
     // defined outputs unless explicitly noted otherwise

   This is safe for multiple inclusion and other options exist for fine
   tuning described below. */

#include "../bits/fd_bits.h"

#ifndef SET_NAME
#error "Define SET_NAME"
#endif

/* SET_TYPE is a type that behaves like a primitive integral type and
   is efficient to pass around by value.  Defaults to ulong. */

#ifndef SET_TYPE
#define SET_TYPE ulong
#endif

/* SET_MAX is an integer expression that gives the maximum number of
   elements this set can hold.  Should be [1,WIDTH_SET_TYPE].  Defaults
   to the number of bits in SET_TYPE. */

#ifndef SET_MAX
#define SET_MAX (8*(int)sizeof(SET_TYPE))
#endif

/* SET_IDX_T is the integral type used to index set elements.  Defaults
   to ulong. */

#ifndef SET_IDX_T
#define SET_IDX_T ulong
#endif

/* Define SET_POPCNT, SET_FIND_LSB AND SET_POP_LSB to the most efficient
   way to compute the population count of a small set.  Defaults to
   corresponding APIs for the SET_TYPE in fd_bits. */

#ifndef SET_POPCNT
#define SET_POPCNT FD_EXPAND_THEN_CONCAT3(fd_,SET_TYPE,_popcnt)
#endif

#ifndef SET_FIND_LSB
#define SET_FIND_LSB FD_EXPAND_THEN_CONCAT3(fd_,SET_TYPE,_find_lsb)
#endif

#ifndef SET_POP_LSB
#define SET_POP_LSB FD_EXPAND_THEN_CONCAT3(fd_,SET_TYPE,_pop_lsb)
#endif

/* Implementation *****************************************************/

#define SET_(x)FD_EXPAND_THEN_CONCAT3(SET_NAME,_,x)

enum {
  SET_(MAX)             = (SET_MAX),
  SET_(PRIVATE_BIT_CNT) = 8*(int)sizeof(SET_TYPE),
  SET_(PRIVATE_ZP_CNT)  = SET_(PRIVATE_BIT_CNT) - SET_(MAX)
}; 

FD_STATIC_ASSERT( 0<SET_(MAX) && SET_(MAX)<=SET_(PRIVATE_BIT_CNT),              range );
FD_STATIC_ASSERT( (ulong)SET_(PRIVATE_BIT_CNT)<=(1UL<<(8*sizeof(SET_IDX_T)-1)), range );

typedef SET_TYPE SET_(t);
typedef SET_TYPE SET_(iter_t);

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline SET_(t) SET_(null)( void ) { return (SET_(t))0; }

FD_FN_CONST static inline SET_(t) SET_(full)( void ) { return (SET_(t))((((SET_(t))~((SET_(t))0))) >> SET_(PRIVATE_ZP_CNT)); }

FD_FN_CONST static inline SET_(t)
SET_(full_if)( int c ) {
  return (SET_(t))(((SET_(t))(((SET_(t))!c)-((SET_(t))1))) & SET_(full)());
}

FD_FN_CONST static inline SET_(t) SET_(ele)   (        SET_IDX_T i ) { return (SET_(t))(((SET_(t))  1) << i);   }
FD_FN_CONST static inline SET_(t) SET_(ele_if)( int c, SET_IDX_T i ) { return (SET_(t))(((SET_(t))!!c) << i);   }

FD_FN_CONST static inline SET_IDX_T SET_(max)  ( void      ) { return (SET_IDX_T)SET_(MAX);       }
FD_FN_CONST static inline SET_IDX_T SET_(cnt)  ( SET_(t) x ) { return (SET_IDX_T)SET_POPCNT(x);   }
FD_FN_CONST static inline SET_IDX_T SET_(first)( SET_(t) x ) { return (SET_IDX_T)SET_FIND_LSB(x); }

/* Handles >=0 for negative types too */
FD_FN_CONST static inline int SET_(valid_idx)( SET_IDX_T i              ) { return ((ulong)(long)i)<((ulong)SET_(MAX)); }

FD_FN_CONST static inline int SET_(valid)    ( SET_(t)   x              ) { return !(x & ~SET_(full)());                }
FD_FN_CONST static inline int SET_(is_null)  ( SET_(t)   x              ) { return !x;                                  }
FD_FN_CONST static inline int SET_(is_full)  ( SET_(t)   x              ) { return x==SET_(full)();                     }
FD_FN_CONST static inline int SET_(test)     ( SET_(t)   x, SET_IDX_T i ) { return (int)((x>>i) & ((SET_(t))1));        }
FD_FN_CONST static inline int SET_(eq)       ( SET_(t)   x, SET_(t)   y ) { return x==y;                                }
FD_FN_CONST static inline int SET_(subset)   ( SET_(t)   x, SET_(t)   y ) { return x==(x & y);                          }

FD_FN_CONST static inline SET_(t) SET_(copy)      ( SET_(t) x ) { return x;                }
FD_FN_CONST static inline SET_(t) SET_(complement)( SET_(t) x ) { return x ^ SET_(full)(); }

FD_FN_CONST static inline SET_(t) SET_(union)    ( SET_(t) x, SET_(t) y ) { return x | y;  }
FD_FN_CONST static inline SET_(t) SET_(intersect)( SET_(t) x, SET_(t) y ) { return x & y;  }
FD_FN_CONST static inline SET_(t) SET_(subtract) ( SET_(t) x, SET_(t) y ) { return (SET_(t))(x & ~y); }
FD_FN_CONST static inline SET_(t) SET_(xor)      ( SET_(t) x, SET_(t) y ) { return x ^  y;  }

FD_FN_CONST static inline SET_(t) SET_(if)( int c, SET_(t) t, SET_(t) f ) { return c ? t : f; }

FD_FN_CONST static inline SET_(iter_t) SET_(iter_init)( SET_(t)      set  ) { return set;                             }
FD_FN_CONST static inline SET_(iter_t) SET_(iter_done)( SET_(iter_t) iter ) { return !iter;                           }
FD_FN_CONST static inline SET_(iter_t) SET_(iter_next)( SET_(iter_t) iter ) { return SET_POP_LSB(  iter );            }
FD_FN_CONST static inline SET_IDX_T    SET_(iter_idx) ( SET_(iter_t) iter ) { return (SET_IDX_T)SET_FIND_LSB( iter ); }

FD_FN_CONST static inline SET_(t) SET_(insert)( SET_(t) x, SET_IDX_T i ) { return x | SET_(ele)(i); }
FD_FN_CONST static inline SET_(t) SET_(remove)( SET_(t) x, SET_IDX_T i ) { return (SET_(t))(x & ~SET_(ele)(i)); }

FD_FN_CONST static inline SET_(t) SET_(insert_if)( int c, SET_(t) x, SET_IDX_T i ) { return x | SET_(ele_if)(c,i); }
FD_FN_CONST static inline SET_(t) SET_(remove_if)( int c, SET_(t) x, SET_IDX_T i ) { return (SET_(t))(x & ~SET_(ele_if)(c,i)); }

FD_PROTOTYPES_END

#undef SET_

#undef SET_POP_LSB
#undef SET_FIND_LSB
#undef SET_POPCNT
#undef SET_MAX
#undef SET_TYPE
#undef SET_NAME

