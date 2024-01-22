/* fd_map_perfect defines a few macros and functions for building
   ultra high performance compile-time perfect hash tables.

   If C's preprocessor were more powerful, it might be possible to do
   this all automatically and fully generically, but it's not.  The good
   thing this does provide is that it will fail to compile (with errors
   about override-init in GCC and initializer-overrides in Clang) if
   your hash function doesn't result in a perfect hash table.  It takes
   abusing the preprocessor a little and jumping through some hoops in
   order to get that property.

   This file also supports tables with no value, in which case it is
   essentially a set (quickly answering containment queries). */

/*
   Example usage:

   struct __attribute__((aligned(32))) key_prio {
     ulong key;
     ulong prio;
   };
   typedef struct key_prio key_prio_t;

#define MAP_PERFECT_NAME      key_prio_tbl // Name of the table and function prefix
#define MAP_PERFECT_LG_TBL_SZ 3            // Table can fit at most 8 elements
#define MAP_PERFECT_T         key_prio_t   // The type of each element
#define MAP_PERFECT_HASH_C    650148382U   // A random uint, see below for details
#define MAP_PERFECT_KEY       key          // Name of the key field
#define MAP_PERFECT_KEY_T     ulong        // Type of the query (typically key type)
#define MAP_PERFECT_ZERO_KEY  0UL          // Must be the key that's all zero bytes

To add elements, just define MAP_PERFECT_i to be key, value (or values).
This will eventually expand to something like
          { MAP_PERFECT_KEY = key, values }
so using the .fieldname=value syntax is supported.  Otherwise
the fields will be initialized in the order they are declared in the
struct.

The ordering of these declarations does not matter, but you
must declare at least MAP_PERFECT_0.  This implies that there must be at
least one element in the map, but if you know at compile time that the
map is empty, why use a map in the first place?  The other limitations
are that the number of elements cannot exceed 1000, and the number of
values in each definition line cannot exceed 100.  If you're getting
close to either of these limits, this file is probably not the right
solution to your problem.

#define MAP_PERFECT_0  44, 12
#define MAP_PERFECT_1  45, .prio = 19
#define MAP_PERFECT_2  17, 0

#include "fd_map_perfect.c"

will declare the following static inline functions in the compilation unit:

// Returns 1 if the key is contained in the table, or 0 if not.

static inline int key_prio_tbl_contains( ulong key );

// Returns a pointer to the element in the table that has key `key` if
// one exists, or the value provided as null if one doesn't.

static inline key_prio_t const * key_prio_tbl_query( ulong key, key_prio_t const * null );

// Returns the hash of key (using the provided perfect hash) if key is
// in the table.  If key is not in the table, returns UINT_MAX.
static inline uint key_prio_tbl_hash_or_default( ulong key );


You can do this multiple times within a compilation unit as long as
MAP_PERFECT_NAME differs for the different instantiations.  It's also
fine to use it in a header.  There are many options (detailed below) to
customize the behavior.

It's also totally fine to make the element type a struct containing just
the key if you only need a set (containment queries).  To do so, just
then append a comma to the elements in the normal way, e.g.
              #define MAP_PERFECT_0 44,
adds 44 to the set.

One advanced usage is with multi-element keys (e.g. arrays).  They are
fully supported, but require #define MAP_PERFECT_COMPLEX_KEY 1.  See
below for more details. */

#ifndef MAP_PERFECT_NAME
#error "Define MAP_PERFECT_NAME"
#endif

/* MAP_PERFECT_LG_TBL_SZ is the base-2 log of the table size.  See the
   note about MAP_PERFECT_HASH_C below for guidance on how to choose
   this value.  It must be at least 1. */

#ifndef MAP_PERFECT_LG_TBL_SZ
#error "Define MAP_PERFECT_LG_TBL_SZ"
#endif

/* MAP_PERFECT_T is the type of each element in the perfect hash table.
   There are no requirements on it other than that it must contain the
   key.  Large structs are okay, since they never get copied, but they
   might be a pain to const initialize. */

#ifndef MAP_PERFECT_T
#error "Define MAP_PERFECT_T"
#endif

/* MAP_PERFECT_KEY is the name of the key field in the struct.  It
   defaults to key. */
#ifndef MAP_PERFECT_KEY
#define MAP_PERFECT_KEY key
#endif

/* MAP_PERFECT_KEY_T is the type of the query, which should typically be
   the key type.  When using an array as a key, you may want to make
   this a const pointer instead of an array though.  For example, if
   the key is uchar key[32], #define MAP_PERFECT_KEY_T uchar const * is
   pretty reasonable. */

#ifndef MAP_PERFECT_KEY_T
#error "Define MAP_PERFECT_KEY_T"
#endif

/* MAP_PERFECT_COMPLEX_KEY controls whether the key type is a scalar
   (COMPLEX_KEY==0) or an array (COMPLEX_KEY==1).  If a complex key, the
   key should be surrounded by parenthesis, e.g.
     #define MAP_PERFECT_0 (1,1,1), .value=7, .other_value=8

   In this case, when HASH_PP is invoked, each value in the key will be
   a different argument to the macro.  The hash of the above example
   will be calculated by expanding MAP_PERFECT_HASH_PP( 1, 1, 1 ), not
   MAP_PERFECT_HASH_PP( (1,1,1) ). */

#ifndef MAP_PERFECT_COMPLEX_KEY
#  define MAP_PERFECT_COMPLEX_KEY 0
#endif

/* MAP_PERFECT_ZERO_KEY must be set to the key of all 0s.  In the
   non-complex case, the code below probably does the right thing.  The
   reason for this is a little strange: keys in the table that don't
   have a value get default initialized, which means set to all 0 bytes.
   We have to be able to distinguish that case from the case in which
   the zero key was actually inserted into the table, and we need to be
   able to do that at preprocessor time.  Especially in the complex key
   case, this is not easy, so we just require specifying it manually. */

#ifndef MAP_PERFECT_ZERO_KEY
#  if !MAP_PERFECT_COMPLEX_KEY
#    define MAP_PERFECT_ZERO_KEY 0
#  else
#     error "Define MAP_PERFECT_ZERO_KEY to be the key of all zero bytes"
#  endif
#endif

/* MAP_PERFECT_KEYS_EQUAL takes two key arguments, where the second has
   type MAP_PERFECT_KEY_T, and returns 1 if they are equal and 0 if they
   are not. */

#ifndef MAP_PERFECT_KEYS_EQUAL
#  if !MAP_PERFECT_COMPLEX_KEY
#    define MAP_PERFECT_KEYS_EQUAL(k1,k2) ((k1)==(k2))
#  else
#    error "Define MAP_PERFECT_KEYS_EQUAL"
#  endif
#endif


/* By default, this file uses a family of hash functions of the form

     ((uint)k * (uint)MAP_PERFECT_HASH_C)>>(32-MAP_PERFECT_LG_TBL_SZ)

   where k is the key. I'm not too sure about the theory of this
   function, but it seems to work decently well in practice, and it's
   extremely cheap (2 instructions, 4 cycles of latency, 1 cycle inverse
   throughput).
   Of course, this is customizable, but you need to provide the hash
   function in two forms: One that is executed by the preprocessor, and
   one that is executed at runtime.

   IMPORTANT GOTCHA: the preprocessor only kind of understands types.
   It seems like it can differentiate between signed and unsigned, but
   everything is either a long or a ulong.  It's probably easiest to
   treat everything as a ulong.

   The other difference is only apparent with complex keys:
   MAP_PERFECT_HASH_PP takes as many arguments as the array length,
   while MAP_PERFECT_HASH_R takes one argument of type
   MAP_PERFECT_KEY_T.  They must return identical hashes for equivalent
   values.  One good way to do that is to make them identical or to have
   them both invoke a common macro with the core hash logic.

   The hash must be simple enough that the preprocessor can execute it.
   */

#ifdef MAP_PERFECT_HASH_PP
#  ifndef MAP_PERFECT_HASH_R
#     error "If you're using a custom hash function, you must define both MAP_PERFECT_HASH_PP and MAP_PERFECT_HASH_R"
#  endif
#else
#  ifndef MAP_PERFECT_HASH_C
#    error "Define MAP_PERFECT_HASH_C"
#  endif
#  define MAP_PERFECT_HASH_PP( u ) ((( MAP_PERFECT_HASH_C * (u))&UINT_MAX)>>(32-(MAP_PERFECT_LG_TBL_SZ)))
#  define MAP_PERFECT_HASH_R(  u ) ((  MAP_PERFECT_HASH_C * (uint)(u)    )>>(32-(MAP_PERFECT_LG_TBL_SZ)))
#endif

/* A note on picking MAP_PERFECT_HASH_C: I don't know a better way to
   find the constant other than brute force.  If we model the hash
   function as a random map, then the probability any given constant
   results in no collisions is:
                             N!/((N-m)!*N^m)
   where N is 2^MAP_PERFECT_LG_TBL_SZ and m is the number of elements in the
   table.  The simple estimate of the number of constants you need to
   try is then ((N-m)! N^m)/N!.  This function grows faster than
   exponential as a function of m.  The only real downside to a larger
   table is increased cache utilization and cache misses.

   Here is some example Python code for finding a hash for prime numbers
   under 100:

   import numpy as np
   import random
   import math

   arr = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
   PMP_LG_TBL_SZ = 5
   nn = np.array(arr)
   best = 0

   estimated_cnt = int(math.factorial( (1<<PMP_LG_TBL_SZ)-len(arr) ) * ((1<<PMP_LG_TBL_SZ)**len(arr)) / math.factorial((1<<PMP_LG_TBL_SZ)))
   if estimated_cnt > 2**32:
       print(f"Warning: the table is likely too full. Estimated {estimated_cnt} random values needed")
   print(f"Trying {2*estimated_cnt} random constants")

   for k in range(2*estimated_cnt):
       r = random.randint(0,2**32-1)
       cur = len(set( ((nn*r)>>(32-PMP_LG_TBL_SZ))&((1<<PMP_LG_TBL_SZ) - 1) ))
       if cur == len(arr):
           print(f"Success! Use {r} as the hash constant")
           break
       if cur>best:
           best = cur
           print(f"Progress: found projection onto {best} entries.") */

#if defined(MAP_PERFECT_1000)
#  error "fd_map_perfect only supports up to 1000 elements."
#endif

/* Implementation: */
#include "../bits/fd_bits.h"

#define MAP_PERFECT_(n)       FD_EXPAND_THEN_CONCAT3(MAP_PERFECT_NAME,_,n)

/* Step 1: Define macros that can kinda distinguish between whether
   something has been defined or not.  The actual preprocessor function
   "defined" only works in #if expressions, so it's no good.  Instead we
   determine whether the token in question expands to something with a
   comma in it (this is why even in the no-value case, the elements need
   a comma).  This is mostly taken from the Internet. */

#define FD_MP_EXPAND(x) x

#define FD_MP_ARG_100(_,\
   _100,_99,_98,_97,_96,_95,_94,_93,_92,_91,_90,_89,_88,_87,_86,_85,_84,_83,_82,_81, \
   _80,_79,_78,_77,_76,_75,_74,_73,_72,_71,_70,_69,_68,_67,_66,_65,_64,_63,_62,_61, \
   _60,_59,_58,_57,_56,_55,_54,_53,_52,_51,_50,_49,_48,_47,_46,_45,_44,_43,_42,_41, \
   _40,_39,_38,_37,_36,_35,_34,_33,_32,_31,_30,_29,_28,_27,_26,_25,_24,_23,_22,_21, \
   _20,_19,_18,_17,_16,_15,_14,_13,_12,_11,_10,_9,_8,_7,_6,_5,_4,_3,_2,X_,...) X_

/* Returns whether __VA_ARGS__ has a comma (up to 100 arguments). */
#define FD_MP_HAS_COMMA(...) FD_MP_EXPAND(FD_MP_ARG_100(__VA_ARGS__, \
   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, \
   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, \
   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, \
   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 ,1, \
   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, -1))



/* Step 2: Define macros that will generate the sequence of integers
   0, 1, ... 999. */

/* This set of recursive macros expands f with argument p0 concatenated
   with successive sequential integers from 0 to 999 (inclusive).  The
   invocations are joined with j.  z1 and z2 are helper arguments that
   must start with z1 as empty and z2 as 0. When the leading digit is
   not zero, they will be flipped.

   Solving something close to this is not hard: you just concat a digit
   onto the prefix (p) and then recurse.  The tricky part comes from
   leading 0s.  To solve that, we use z1 which is empty when it's a
   leading zero and a literal zero when not.  That almost solves it, but
   then the very first call to FD_MP_RECURSE1 has p="" instead of p="0" (not
   actually strings), since it's entirely leading zeros.  z2 solves
   that. */
#define FD_MP_RECURSE4(p0, p, j, z1, z2, f) FD_MP_RECURSE3( p0, FD_EXPAND_THEN_CONCAT2(p,z1), j, z1, z2, f ) j() \
                                            FD_MP_RECURSE3( p0, FD_EXPAND_THEN_CONCAT2(p,1),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE3( p0, FD_EXPAND_THEN_CONCAT2(p,2),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE3( p0, FD_EXPAND_THEN_CONCAT2(p,3),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE3( p0, FD_EXPAND_THEN_CONCAT2(p,4),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE3( p0, FD_EXPAND_THEN_CONCAT2(p,5),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE3( p0, FD_EXPAND_THEN_CONCAT2(p,6),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE3( p0, FD_EXPAND_THEN_CONCAT2(p,7),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE3( p0, FD_EXPAND_THEN_CONCAT2(p,8),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE3( p0, FD_EXPAND_THEN_CONCAT2(p,9),  j, 0,    , f )
#define FD_MP_RECURSE3(p0, p, j, z1, z2, f) FD_MP_RECURSE2( p0, FD_EXPAND_THEN_CONCAT2(p,z1), j, z1, z2, f ) j() \
                                            FD_MP_RECURSE2( p0, FD_EXPAND_THEN_CONCAT2(p,1),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE2( p0, FD_EXPAND_THEN_CONCAT2(p,2),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE2( p0, FD_EXPAND_THEN_CONCAT2(p,3),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE2( p0, FD_EXPAND_THEN_CONCAT2(p,4),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE2( p0, FD_EXPAND_THEN_CONCAT2(p,5),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE2( p0, FD_EXPAND_THEN_CONCAT2(p,6),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE2( p0, FD_EXPAND_THEN_CONCAT2(p,7),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE2( p0, FD_EXPAND_THEN_CONCAT2(p,8),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE2( p0, FD_EXPAND_THEN_CONCAT2(p,9),  j, 0,    , f )
#define FD_MP_RECURSE2(p0, p, j, z1, z2, f) FD_MP_RECURSE1( p0, FD_EXPAND_THEN_CONCAT2(p,z1), j, z1, z2, f ) j() \
                                            FD_MP_RECURSE1( p0, FD_EXPAND_THEN_CONCAT2(p,1),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE1( p0, FD_EXPAND_THEN_CONCAT2(p,2),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE1( p0, FD_EXPAND_THEN_CONCAT2(p,3),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE1( p0, FD_EXPAND_THEN_CONCAT2(p,4),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE1( p0, FD_EXPAND_THEN_CONCAT2(p,5),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE1( p0, FD_EXPAND_THEN_CONCAT2(p,6),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE1( p0, FD_EXPAND_THEN_CONCAT2(p,7),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE1( p0, FD_EXPAND_THEN_CONCAT2(p,8),  j, 0,    , f ) j() \
                                            FD_MP_RECURSE1( p0, FD_EXPAND_THEN_CONCAT2(p,9),  j, 0,    , f )

#define FD_MP_RECURSE1(p0, p, j, z1, z2, f) f( FD_EXPAND_THEN_CONCAT3(p0, p, z2) )
#define FD_MP_EMPTY()
#define FD_MP_AND() &&

/* Step 3: Define macros for turning a table element into an array
   declaration, and also whether it has a key that hashes to something
   other than what the zero key hashes to. */

#if MAP_PERFECT_COMPLEX_KEY
/* Consume the first and last parenthesis */
#  define FD_MP_EAT_PARENS( ... ) __VA_ARGS__
#  define FD_MP_FORMAT_KEY( K ) { FD_MP_EAT_PARENS K }
/* Various macro expansion tricks */
#  define FD_MP_HASH_PP_1( KEY ) FD_MP_HASH_PP_2( KEY )
#  define FD_MP_HASH_PP_2( KEY ) MAP_PERFECT_HASH_PP KEY
#else
#  define FD_MP_FORMAT_KEY( K ) K
#  define FD_MP_HASH_PP_1( KEY ) MAP_PERFECT_HASH_PP( KEY )
#endif

#define FD_MP_VAL( K, ... ) __VA_ARGS__
#define FD_MP_KEY( K, ... ) K

#define FD_MP_ADD_ELE( ... ) \
  [ FD_MP_HASH_PP_1( FD_MP_KEY( __VA_ARGS__ ) ) ] =   \
  {  . MAP_PERFECT_KEY = FD_MP_FORMAT_KEY( FD_MP_KEY(__VA_ARGS__) ), FD_MP_VAL(__VA_ARGS__)  },

#define FD_MP_MAKE_ELE_0(...)
#define FD_MP_MAKE_ELE_1(K, ...) FD_MP_ADD_ELE(K, __VA_ARGS__)

#define FD_MP_CHOOSE_MAKE(...) FD_EXPAND_THEN_CONCAT2( FD_MP_MAKE_ELE_, FD_MP_HAS_COMMA(__VA_ARGS__) )(__VA_ARGS__)



#define FD_MP_HASH_PP_3( ... ) FD_MP_HASH_PP_1( FD_MP_KEY( __VA_ARGS__ ) )

/* If nothing maps to the same entry as the zero key, then we need to
   insert a dummy element.  We insert MAP_PERFECT_0 at the index that
   the zero key would map to.  In this case, nothing maps to the same
   entry as the zero key, which means MAP_PERFECT_0 certainly doesn't,
   which means the zero key's index is the wrong index for it.  Thus it
   won't match any queries that hit the zero key's index, as desired. */

#define FD_MP_NONZERO_ELE_0(...) 1
#define FD_MP_NONZERO_ELE_1(K, ...) (FD_MP_HASH_PP_1(MAP_PERFECT_ZERO_KEY) != FD_MP_HASH_PP_1(K))

#define FD_MP_CHOOSE_NONZERO(...) FD_EXPAND_THEN_CONCAT2( FD_MP_NONZERO_ELE_, FD_MP_HAS_COMMA(__VA_ARGS__) )(__VA_ARGS__)

#if FD_MP_RECURSE4( MAP_PERFECT_, , FD_MP_AND, FD_MP_EMPTY(), 0, FD_MP_CHOOSE_NONZERO)
#define FD_MP_ZERO_KEY_VAL_1( ... ) \
  {  . MAP_PERFECT_KEY = FD_MP_FORMAT_KEY( FD_MP_KEY(__VA_ARGS__) ), \
    FD_MP_VAL(__VA_ARGS__)  }
#define FD_MP_ZERO_KEY_ELE [ FD_MP_HASH_PP_1(MAP_PERFECT_ZERO_KEY) ] = \
                                           FD_MP_ZERO_KEY_VAL_1(MAP_PERFECT_0),
#else
#define FD_MP_ZERO_KEY_ELE
#endif

static const MAP_PERFECT_T MAP_PERFECT_(tbl)[ 1<<MAP_PERFECT_LG_TBL_SZ ] = {
  FD_MP_RECURSE4( MAP_PERFECT_, , FD_MP_EMPTY, FD_MP_EMPTY(), 0, FD_MP_CHOOSE_MAKE )
  FD_MP_ZERO_KEY_ELE
};


static inline int
MAP_PERFECT_(contains)( MAP_PERFECT_KEY_T key ) {
  uint hash = MAP_PERFECT_HASH_R( key );
  return MAP_PERFECT_KEYS_EQUAL( MAP_PERFECT_(tbl)[ hash ].MAP_PERFECT_KEY, key );
}

static inline MAP_PERFECT_T const *
MAP_PERFECT_(query)( MAP_PERFECT_KEY_T key, MAP_PERFECT_T const * null ) {
  uint hash = MAP_PERFECT_HASH_R( key );
  int contained = MAP_PERFECT_KEYS_EQUAL( MAP_PERFECT_(tbl)[ hash ].MAP_PERFECT_KEY, key );
  return fd_ptr_if( contained, MAP_PERFECT_(tbl)+hash, null );
}

static inline uint
MAP_PERFECT_(hash_or_default)( MAP_PERFECT_KEY_T key ) {
  uint hash = MAP_PERFECT_HASH_R( key );
  int contained = MAP_PERFECT_KEYS_EQUAL( MAP_PERFECT_(tbl)[ hash ].MAP_PERFECT_KEY, key );
  return fd_uint_if( contained, hash, UINT_MAX );
}

#undef FD_MP_ZERO_KEY_ELE
#undef FD_MP_ZERO_KEY_VAL_1
#undef FD_MP_CHOOSE_NONZERO
#undef FD_MP_NONZERO_ELE_1
#undef FD_MP_NONZERO_ELE_0
#undef FD_MP_CHOOSE_MAKE
#undef FD_MP_MAKE_ELE_0
#undef FD_MP_MAKE_ELE_1
#undef FD_MP_ADD_ELE
#undef FD_MP_VAL
#undef FD_MP_KEY
#undef FD_MP_HASH_PP_3
#undef FD_MP_HASH_PP_2
#undef FD_MP_HASH_PP_1
#undef FD_MP_FORMAT_KEY
#undef FD_MP_EAT_PARENS
#undef FD_MP_AND
#undef FD_MP_EMPTY
#undef FD_MP_RECURSE_1
#undef FD_MP_RECURSE_2
#undef FD_MP_RECURSE_3
#undef FD_MP_RECURSE_4
#undef FD_MP_HAS_COMMA
#undef FD_MP_ARG_100
#undef FD_MP_EXPAND
#undef MAP_PERFECT_
#undef MAP_PERFECT_HASH_R
#undef MAP_PERFECT_HASH_PP
#undef MAP_PERFECT_HASH_C
#undef MAP_PERFECT_KEYS_EQUAL
#undef MAP_PERFECT_ZERO_KEY
#undef MAP_PERFECT_COMPLEX_KEY
#undef MAP_PERFECT_KEY_T
#undef MAP_PERFECT_KEY
#undef MAP_PERFECT_T
#undef MAP_PERFECT_LG_TBL_SZ
#undef MAP_PERFECT_NAME

/* Finally, undefine all the 1000 possible entries... It's not possible to
   make a macro emit an undef command. Nothing else follows this section. */
#undef MAP_PERFECT_999
#undef MAP_PERFECT_998
#undef MAP_PERFECT_997
#undef MAP_PERFECT_996
#undef MAP_PERFECT_995
#undef MAP_PERFECT_994
#undef MAP_PERFECT_993
#undef MAP_PERFECT_992
#undef MAP_PERFECT_991
#undef MAP_PERFECT_990
#undef MAP_PERFECT_989
#undef MAP_PERFECT_988
#undef MAP_PERFECT_987
#undef MAP_PERFECT_986
#undef MAP_PERFECT_985
#undef MAP_PERFECT_984
#undef MAP_PERFECT_983
#undef MAP_PERFECT_982
#undef MAP_PERFECT_981
#undef MAP_PERFECT_980
#undef MAP_PERFECT_979
#undef MAP_PERFECT_978
#undef MAP_PERFECT_977
#undef MAP_PERFECT_976
#undef MAP_PERFECT_975
#undef MAP_PERFECT_974
#undef MAP_PERFECT_973
#undef MAP_PERFECT_972
#undef MAP_PERFECT_971
#undef MAP_PERFECT_970
#undef MAP_PERFECT_969
#undef MAP_PERFECT_968
#undef MAP_PERFECT_967
#undef MAP_PERFECT_966
#undef MAP_PERFECT_965
#undef MAP_PERFECT_964
#undef MAP_PERFECT_963
#undef MAP_PERFECT_962
#undef MAP_PERFECT_961
#undef MAP_PERFECT_960
#undef MAP_PERFECT_959
#undef MAP_PERFECT_958
#undef MAP_PERFECT_957
#undef MAP_PERFECT_956
#undef MAP_PERFECT_955
#undef MAP_PERFECT_954
#undef MAP_PERFECT_953
#undef MAP_PERFECT_952
#undef MAP_PERFECT_951
#undef MAP_PERFECT_950
#undef MAP_PERFECT_949
#undef MAP_PERFECT_948
#undef MAP_PERFECT_947
#undef MAP_PERFECT_946
#undef MAP_PERFECT_945
#undef MAP_PERFECT_944
#undef MAP_PERFECT_943
#undef MAP_PERFECT_942
#undef MAP_PERFECT_941
#undef MAP_PERFECT_940
#undef MAP_PERFECT_939
#undef MAP_PERFECT_938
#undef MAP_PERFECT_937
#undef MAP_PERFECT_936
#undef MAP_PERFECT_935
#undef MAP_PERFECT_934
#undef MAP_PERFECT_933
#undef MAP_PERFECT_932
#undef MAP_PERFECT_931
#undef MAP_PERFECT_930
#undef MAP_PERFECT_929
#undef MAP_PERFECT_928
#undef MAP_PERFECT_927
#undef MAP_PERFECT_926
#undef MAP_PERFECT_925
#undef MAP_PERFECT_924
#undef MAP_PERFECT_923
#undef MAP_PERFECT_922
#undef MAP_PERFECT_921
#undef MAP_PERFECT_920
#undef MAP_PERFECT_919
#undef MAP_PERFECT_918
#undef MAP_PERFECT_917
#undef MAP_PERFECT_916
#undef MAP_PERFECT_915
#undef MAP_PERFECT_914
#undef MAP_PERFECT_913
#undef MAP_PERFECT_912
#undef MAP_PERFECT_911
#undef MAP_PERFECT_910
#undef MAP_PERFECT_909
#undef MAP_PERFECT_908
#undef MAP_PERFECT_907
#undef MAP_PERFECT_906
#undef MAP_PERFECT_905
#undef MAP_PERFECT_904
#undef MAP_PERFECT_903
#undef MAP_PERFECT_902
#undef MAP_PERFECT_901
#undef MAP_PERFECT_900
#undef MAP_PERFECT_899
#undef MAP_PERFECT_898
#undef MAP_PERFECT_897
#undef MAP_PERFECT_896
#undef MAP_PERFECT_895
#undef MAP_PERFECT_894
#undef MAP_PERFECT_893
#undef MAP_PERFECT_892
#undef MAP_PERFECT_891
#undef MAP_PERFECT_890
#undef MAP_PERFECT_889
#undef MAP_PERFECT_888
#undef MAP_PERFECT_887
#undef MAP_PERFECT_886
#undef MAP_PERFECT_885
#undef MAP_PERFECT_884
#undef MAP_PERFECT_883
#undef MAP_PERFECT_882
#undef MAP_PERFECT_881
#undef MAP_PERFECT_880
#undef MAP_PERFECT_879
#undef MAP_PERFECT_878
#undef MAP_PERFECT_877
#undef MAP_PERFECT_876
#undef MAP_PERFECT_875
#undef MAP_PERFECT_874
#undef MAP_PERFECT_873
#undef MAP_PERFECT_872
#undef MAP_PERFECT_871
#undef MAP_PERFECT_870
#undef MAP_PERFECT_869
#undef MAP_PERFECT_868
#undef MAP_PERFECT_867
#undef MAP_PERFECT_866
#undef MAP_PERFECT_865
#undef MAP_PERFECT_864
#undef MAP_PERFECT_863
#undef MAP_PERFECT_862
#undef MAP_PERFECT_861
#undef MAP_PERFECT_860
#undef MAP_PERFECT_859
#undef MAP_PERFECT_858
#undef MAP_PERFECT_857
#undef MAP_PERFECT_856
#undef MAP_PERFECT_855
#undef MAP_PERFECT_854
#undef MAP_PERFECT_853
#undef MAP_PERFECT_852
#undef MAP_PERFECT_851
#undef MAP_PERFECT_850
#undef MAP_PERFECT_849
#undef MAP_PERFECT_848
#undef MAP_PERFECT_847
#undef MAP_PERFECT_846
#undef MAP_PERFECT_845
#undef MAP_PERFECT_844
#undef MAP_PERFECT_843
#undef MAP_PERFECT_842
#undef MAP_PERFECT_841
#undef MAP_PERFECT_840
#undef MAP_PERFECT_839
#undef MAP_PERFECT_838
#undef MAP_PERFECT_837
#undef MAP_PERFECT_836
#undef MAP_PERFECT_835
#undef MAP_PERFECT_834
#undef MAP_PERFECT_833
#undef MAP_PERFECT_832
#undef MAP_PERFECT_831
#undef MAP_PERFECT_830
#undef MAP_PERFECT_829
#undef MAP_PERFECT_828
#undef MAP_PERFECT_827
#undef MAP_PERFECT_826
#undef MAP_PERFECT_825
#undef MAP_PERFECT_824
#undef MAP_PERFECT_823
#undef MAP_PERFECT_822
#undef MAP_PERFECT_821
#undef MAP_PERFECT_820
#undef MAP_PERFECT_819
#undef MAP_PERFECT_818
#undef MAP_PERFECT_817
#undef MAP_PERFECT_816
#undef MAP_PERFECT_815
#undef MAP_PERFECT_814
#undef MAP_PERFECT_813
#undef MAP_PERFECT_812
#undef MAP_PERFECT_811
#undef MAP_PERFECT_810
#undef MAP_PERFECT_809
#undef MAP_PERFECT_808
#undef MAP_PERFECT_807
#undef MAP_PERFECT_806
#undef MAP_PERFECT_805
#undef MAP_PERFECT_804
#undef MAP_PERFECT_803
#undef MAP_PERFECT_802
#undef MAP_PERFECT_801
#undef MAP_PERFECT_800
#undef MAP_PERFECT_799
#undef MAP_PERFECT_798
#undef MAP_PERFECT_797
#undef MAP_PERFECT_796
#undef MAP_PERFECT_795
#undef MAP_PERFECT_794
#undef MAP_PERFECT_793
#undef MAP_PERFECT_792
#undef MAP_PERFECT_791
#undef MAP_PERFECT_790
#undef MAP_PERFECT_789
#undef MAP_PERFECT_788
#undef MAP_PERFECT_787
#undef MAP_PERFECT_786
#undef MAP_PERFECT_785
#undef MAP_PERFECT_784
#undef MAP_PERFECT_783
#undef MAP_PERFECT_782
#undef MAP_PERFECT_781
#undef MAP_PERFECT_780
#undef MAP_PERFECT_779
#undef MAP_PERFECT_778
#undef MAP_PERFECT_777
#undef MAP_PERFECT_776
#undef MAP_PERFECT_775
#undef MAP_PERFECT_774
#undef MAP_PERFECT_773
#undef MAP_PERFECT_772
#undef MAP_PERFECT_771
#undef MAP_PERFECT_770
#undef MAP_PERFECT_769
#undef MAP_PERFECT_768
#undef MAP_PERFECT_767
#undef MAP_PERFECT_766
#undef MAP_PERFECT_765
#undef MAP_PERFECT_764
#undef MAP_PERFECT_763
#undef MAP_PERFECT_762
#undef MAP_PERFECT_761
#undef MAP_PERFECT_760
#undef MAP_PERFECT_759
#undef MAP_PERFECT_758
#undef MAP_PERFECT_757
#undef MAP_PERFECT_756
#undef MAP_PERFECT_755
#undef MAP_PERFECT_754
#undef MAP_PERFECT_753
#undef MAP_PERFECT_752
#undef MAP_PERFECT_751
#undef MAP_PERFECT_750
#undef MAP_PERFECT_749
#undef MAP_PERFECT_748
#undef MAP_PERFECT_747
#undef MAP_PERFECT_746
#undef MAP_PERFECT_745
#undef MAP_PERFECT_744
#undef MAP_PERFECT_743
#undef MAP_PERFECT_742
#undef MAP_PERFECT_741
#undef MAP_PERFECT_740
#undef MAP_PERFECT_739
#undef MAP_PERFECT_738
#undef MAP_PERFECT_737
#undef MAP_PERFECT_736
#undef MAP_PERFECT_735
#undef MAP_PERFECT_734
#undef MAP_PERFECT_733
#undef MAP_PERFECT_732
#undef MAP_PERFECT_731
#undef MAP_PERFECT_730
#undef MAP_PERFECT_729
#undef MAP_PERFECT_728
#undef MAP_PERFECT_727
#undef MAP_PERFECT_726
#undef MAP_PERFECT_725
#undef MAP_PERFECT_724
#undef MAP_PERFECT_723
#undef MAP_PERFECT_722
#undef MAP_PERFECT_721
#undef MAP_PERFECT_720
#undef MAP_PERFECT_719
#undef MAP_PERFECT_718
#undef MAP_PERFECT_717
#undef MAP_PERFECT_716
#undef MAP_PERFECT_715
#undef MAP_PERFECT_714
#undef MAP_PERFECT_713
#undef MAP_PERFECT_712
#undef MAP_PERFECT_711
#undef MAP_PERFECT_710
#undef MAP_PERFECT_709
#undef MAP_PERFECT_708
#undef MAP_PERFECT_707
#undef MAP_PERFECT_706
#undef MAP_PERFECT_705
#undef MAP_PERFECT_704
#undef MAP_PERFECT_703
#undef MAP_PERFECT_702
#undef MAP_PERFECT_701
#undef MAP_PERFECT_700
#undef MAP_PERFECT_699
#undef MAP_PERFECT_698
#undef MAP_PERFECT_697
#undef MAP_PERFECT_696
#undef MAP_PERFECT_695
#undef MAP_PERFECT_694
#undef MAP_PERFECT_693
#undef MAP_PERFECT_692
#undef MAP_PERFECT_691
#undef MAP_PERFECT_690
#undef MAP_PERFECT_689
#undef MAP_PERFECT_688
#undef MAP_PERFECT_687
#undef MAP_PERFECT_686
#undef MAP_PERFECT_685
#undef MAP_PERFECT_684
#undef MAP_PERFECT_683
#undef MAP_PERFECT_682
#undef MAP_PERFECT_681
#undef MAP_PERFECT_680
#undef MAP_PERFECT_679
#undef MAP_PERFECT_678
#undef MAP_PERFECT_677
#undef MAP_PERFECT_676
#undef MAP_PERFECT_675
#undef MAP_PERFECT_674
#undef MAP_PERFECT_673
#undef MAP_PERFECT_672
#undef MAP_PERFECT_671
#undef MAP_PERFECT_670
#undef MAP_PERFECT_669
#undef MAP_PERFECT_668
#undef MAP_PERFECT_667
#undef MAP_PERFECT_666
#undef MAP_PERFECT_665
#undef MAP_PERFECT_664
#undef MAP_PERFECT_663
#undef MAP_PERFECT_662
#undef MAP_PERFECT_661
#undef MAP_PERFECT_660
#undef MAP_PERFECT_659
#undef MAP_PERFECT_658
#undef MAP_PERFECT_657
#undef MAP_PERFECT_656
#undef MAP_PERFECT_655
#undef MAP_PERFECT_654
#undef MAP_PERFECT_653
#undef MAP_PERFECT_652
#undef MAP_PERFECT_651
#undef MAP_PERFECT_650
#undef MAP_PERFECT_649
#undef MAP_PERFECT_648
#undef MAP_PERFECT_647
#undef MAP_PERFECT_646
#undef MAP_PERFECT_645
#undef MAP_PERFECT_644
#undef MAP_PERFECT_643
#undef MAP_PERFECT_642
#undef MAP_PERFECT_641
#undef MAP_PERFECT_640
#undef MAP_PERFECT_639
#undef MAP_PERFECT_638
#undef MAP_PERFECT_637
#undef MAP_PERFECT_636
#undef MAP_PERFECT_635
#undef MAP_PERFECT_634
#undef MAP_PERFECT_633
#undef MAP_PERFECT_632
#undef MAP_PERFECT_631
#undef MAP_PERFECT_630
#undef MAP_PERFECT_629
#undef MAP_PERFECT_628
#undef MAP_PERFECT_627
#undef MAP_PERFECT_626
#undef MAP_PERFECT_625
#undef MAP_PERFECT_624
#undef MAP_PERFECT_623
#undef MAP_PERFECT_622
#undef MAP_PERFECT_621
#undef MAP_PERFECT_620
#undef MAP_PERFECT_619
#undef MAP_PERFECT_618
#undef MAP_PERFECT_617
#undef MAP_PERFECT_616
#undef MAP_PERFECT_615
#undef MAP_PERFECT_614
#undef MAP_PERFECT_613
#undef MAP_PERFECT_612
#undef MAP_PERFECT_611
#undef MAP_PERFECT_610
#undef MAP_PERFECT_609
#undef MAP_PERFECT_608
#undef MAP_PERFECT_607
#undef MAP_PERFECT_606
#undef MAP_PERFECT_605
#undef MAP_PERFECT_604
#undef MAP_PERFECT_603
#undef MAP_PERFECT_602
#undef MAP_PERFECT_601
#undef MAP_PERFECT_600
#undef MAP_PERFECT_599
#undef MAP_PERFECT_598
#undef MAP_PERFECT_597
#undef MAP_PERFECT_596
#undef MAP_PERFECT_595
#undef MAP_PERFECT_594
#undef MAP_PERFECT_593
#undef MAP_PERFECT_592
#undef MAP_PERFECT_591
#undef MAP_PERFECT_590
#undef MAP_PERFECT_589
#undef MAP_PERFECT_588
#undef MAP_PERFECT_587
#undef MAP_PERFECT_586
#undef MAP_PERFECT_585
#undef MAP_PERFECT_584
#undef MAP_PERFECT_583
#undef MAP_PERFECT_582
#undef MAP_PERFECT_581
#undef MAP_PERFECT_580
#undef MAP_PERFECT_579
#undef MAP_PERFECT_578
#undef MAP_PERFECT_577
#undef MAP_PERFECT_576
#undef MAP_PERFECT_575
#undef MAP_PERFECT_574
#undef MAP_PERFECT_573
#undef MAP_PERFECT_572
#undef MAP_PERFECT_571
#undef MAP_PERFECT_570
#undef MAP_PERFECT_569
#undef MAP_PERFECT_568
#undef MAP_PERFECT_567
#undef MAP_PERFECT_566
#undef MAP_PERFECT_565
#undef MAP_PERFECT_564
#undef MAP_PERFECT_563
#undef MAP_PERFECT_562
#undef MAP_PERFECT_561
#undef MAP_PERFECT_560
#undef MAP_PERFECT_559
#undef MAP_PERFECT_558
#undef MAP_PERFECT_557
#undef MAP_PERFECT_556
#undef MAP_PERFECT_555
#undef MAP_PERFECT_554
#undef MAP_PERFECT_553
#undef MAP_PERFECT_552
#undef MAP_PERFECT_551
#undef MAP_PERFECT_550
#undef MAP_PERFECT_549
#undef MAP_PERFECT_548
#undef MAP_PERFECT_547
#undef MAP_PERFECT_546
#undef MAP_PERFECT_545
#undef MAP_PERFECT_544
#undef MAP_PERFECT_543
#undef MAP_PERFECT_542
#undef MAP_PERFECT_541
#undef MAP_PERFECT_540
#undef MAP_PERFECT_539
#undef MAP_PERFECT_538
#undef MAP_PERFECT_537
#undef MAP_PERFECT_536
#undef MAP_PERFECT_535
#undef MAP_PERFECT_534
#undef MAP_PERFECT_533
#undef MAP_PERFECT_532
#undef MAP_PERFECT_531
#undef MAP_PERFECT_530
#undef MAP_PERFECT_529
#undef MAP_PERFECT_528
#undef MAP_PERFECT_527
#undef MAP_PERFECT_526
#undef MAP_PERFECT_525
#undef MAP_PERFECT_524
#undef MAP_PERFECT_523
#undef MAP_PERFECT_522
#undef MAP_PERFECT_521
#undef MAP_PERFECT_520
#undef MAP_PERFECT_519
#undef MAP_PERFECT_518
#undef MAP_PERFECT_517
#undef MAP_PERFECT_516
#undef MAP_PERFECT_515
#undef MAP_PERFECT_514
#undef MAP_PERFECT_513
#undef MAP_PERFECT_512
#undef MAP_PERFECT_511
#undef MAP_PERFECT_510
#undef MAP_PERFECT_509
#undef MAP_PERFECT_508
#undef MAP_PERFECT_507
#undef MAP_PERFECT_506
#undef MAP_PERFECT_505
#undef MAP_PERFECT_504
#undef MAP_PERFECT_503
#undef MAP_PERFECT_502
#undef MAP_PERFECT_501
#undef MAP_PERFECT_500
#undef MAP_PERFECT_499
#undef MAP_PERFECT_498
#undef MAP_PERFECT_497
#undef MAP_PERFECT_496
#undef MAP_PERFECT_495
#undef MAP_PERFECT_494
#undef MAP_PERFECT_493
#undef MAP_PERFECT_492
#undef MAP_PERFECT_491
#undef MAP_PERFECT_490
#undef MAP_PERFECT_489
#undef MAP_PERFECT_488
#undef MAP_PERFECT_487
#undef MAP_PERFECT_486
#undef MAP_PERFECT_485
#undef MAP_PERFECT_484
#undef MAP_PERFECT_483
#undef MAP_PERFECT_482
#undef MAP_PERFECT_481
#undef MAP_PERFECT_480
#undef MAP_PERFECT_479
#undef MAP_PERFECT_478
#undef MAP_PERFECT_477
#undef MAP_PERFECT_476
#undef MAP_PERFECT_475
#undef MAP_PERFECT_474
#undef MAP_PERFECT_473
#undef MAP_PERFECT_472
#undef MAP_PERFECT_471
#undef MAP_PERFECT_470
#undef MAP_PERFECT_469
#undef MAP_PERFECT_468
#undef MAP_PERFECT_467
#undef MAP_PERFECT_466
#undef MAP_PERFECT_465
#undef MAP_PERFECT_464
#undef MAP_PERFECT_463
#undef MAP_PERFECT_462
#undef MAP_PERFECT_461
#undef MAP_PERFECT_460
#undef MAP_PERFECT_459
#undef MAP_PERFECT_458
#undef MAP_PERFECT_457
#undef MAP_PERFECT_456
#undef MAP_PERFECT_455
#undef MAP_PERFECT_454
#undef MAP_PERFECT_453
#undef MAP_PERFECT_452
#undef MAP_PERFECT_451
#undef MAP_PERFECT_450
#undef MAP_PERFECT_449
#undef MAP_PERFECT_448
#undef MAP_PERFECT_447
#undef MAP_PERFECT_446
#undef MAP_PERFECT_445
#undef MAP_PERFECT_444
#undef MAP_PERFECT_443
#undef MAP_PERFECT_442
#undef MAP_PERFECT_441
#undef MAP_PERFECT_440
#undef MAP_PERFECT_439
#undef MAP_PERFECT_438
#undef MAP_PERFECT_437
#undef MAP_PERFECT_436
#undef MAP_PERFECT_435
#undef MAP_PERFECT_434
#undef MAP_PERFECT_433
#undef MAP_PERFECT_432
#undef MAP_PERFECT_431
#undef MAP_PERFECT_430
#undef MAP_PERFECT_429
#undef MAP_PERFECT_428
#undef MAP_PERFECT_427
#undef MAP_PERFECT_426
#undef MAP_PERFECT_425
#undef MAP_PERFECT_424
#undef MAP_PERFECT_423
#undef MAP_PERFECT_422
#undef MAP_PERFECT_421
#undef MAP_PERFECT_420
#undef MAP_PERFECT_419
#undef MAP_PERFECT_418
#undef MAP_PERFECT_417
#undef MAP_PERFECT_416
#undef MAP_PERFECT_415
#undef MAP_PERFECT_414
#undef MAP_PERFECT_413
#undef MAP_PERFECT_412
#undef MAP_PERFECT_411
#undef MAP_PERFECT_410
#undef MAP_PERFECT_409
#undef MAP_PERFECT_408
#undef MAP_PERFECT_407
#undef MAP_PERFECT_406
#undef MAP_PERFECT_405
#undef MAP_PERFECT_404
#undef MAP_PERFECT_403
#undef MAP_PERFECT_402
#undef MAP_PERFECT_401
#undef MAP_PERFECT_400
#undef MAP_PERFECT_399
#undef MAP_PERFECT_398
#undef MAP_PERFECT_397
#undef MAP_PERFECT_396
#undef MAP_PERFECT_395
#undef MAP_PERFECT_394
#undef MAP_PERFECT_393
#undef MAP_PERFECT_392
#undef MAP_PERFECT_391
#undef MAP_PERFECT_390
#undef MAP_PERFECT_389
#undef MAP_PERFECT_388
#undef MAP_PERFECT_387
#undef MAP_PERFECT_386
#undef MAP_PERFECT_385
#undef MAP_PERFECT_384
#undef MAP_PERFECT_383
#undef MAP_PERFECT_382
#undef MAP_PERFECT_381
#undef MAP_PERFECT_380
#undef MAP_PERFECT_379
#undef MAP_PERFECT_378
#undef MAP_PERFECT_377
#undef MAP_PERFECT_376
#undef MAP_PERFECT_375
#undef MAP_PERFECT_374
#undef MAP_PERFECT_373
#undef MAP_PERFECT_372
#undef MAP_PERFECT_371
#undef MAP_PERFECT_370
#undef MAP_PERFECT_369
#undef MAP_PERFECT_368
#undef MAP_PERFECT_367
#undef MAP_PERFECT_366
#undef MAP_PERFECT_365
#undef MAP_PERFECT_364
#undef MAP_PERFECT_363
#undef MAP_PERFECT_362
#undef MAP_PERFECT_361
#undef MAP_PERFECT_360
#undef MAP_PERFECT_359
#undef MAP_PERFECT_358
#undef MAP_PERFECT_357
#undef MAP_PERFECT_356
#undef MAP_PERFECT_355
#undef MAP_PERFECT_354
#undef MAP_PERFECT_353
#undef MAP_PERFECT_352
#undef MAP_PERFECT_351
#undef MAP_PERFECT_350
#undef MAP_PERFECT_349
#undef MAP_PERFECT_348
#undef MAP_PERFECT_347
#undef MAP_PERFECT_346
#undef MAP_PERFECT_345
#undef MAP_PERFECT_344
#undef MAP_PERFECT_343
#undef MAP_PERFECT_342
#undef MAP_PERFECT_341
#undef MAP_PERFECT_340
#undef MAP_PERFECT_339
#undef MAP_PERFECT_338
#undef MAP_PERFECT_337
#undef MAP_PERFECT_336
#undef MAP_PERFECT_335
#undef MAP_PERFECT_334
#undef MAP_PERFECT_333
#undef MAP_PERFECT_332
#undef MAP_PERFECT_331
#undef MAP_PERFECT_330
#undef MAP_PERFECT_329
#undef MAP_PERFECT_328
#undef MAP_PERFECT_327
#undef MAP_PERFECT_326
#undef MAP_PERFECT_325
#undef MAP_PERFECT_324
#undef MAP_PERFECT_323
#undef MAP_PERFECT_322
#undef MAP_PERFECT_321
#undef MAP_PERFECT_320
#undef MAP_PERFECT_319
#undef MAP_PERFECT_318
#undef MAP_PERFECT_317
#undef MAP_PERFECT_316
#undef MAP_PERFECT_315
#undef MAP_PERFECT_314
#undef MAP_PERFECT_313
#undef MAP_PERFECT_312
#undef MAP_PERFECT_311
#undef MAP_PERFECT_310
#undef MAP_PERFECT_309
#undef MAP_PERFECT_308
#undef MAP_PERFECT_307
#undef MAP_PERFECT_306
#undef MAP_PERFECT_305
#undef MAP_PERFECT_304
#undef MAP_PERFECT_303
#undef MAP_PERFECT_302
#undef MAP_PERFECT_301
#undef MAP_PERFECT_300
#undef MAP_PERFECT_299
#undef MAP_PERFECT_298
#undef MAP_PERFECT_297
#undef MAP_PERFECT_296
#undef MAP_PERFECT_295
#undef MAP_PERFECT_294
#undef MAP_PERFECT_293
#undef MAP_PERFECT_292
#undef MAP_PERFECT_291
#undef MAP_PERFECT_290
#undef MAP_PERFECT_289
#undef MAP_PERFECT_288
#undef MAP_PERFECT_287
#undef MAP_PERFECT_286
#undef MAP_PERFECT_285
#undef MAP_PERFECT_284
#undef MAP_PERFECT_283
#undef MAP_PERFECT_282
#undef MAP_PERFECT_281
#undef MAP_PERFECT_280
#undef MAP_PERFECT_279
#undef MAP_PERFECT_278
#undef MAP_PERFECT_277
#undef MAP_PERFECT_276
#undef MAP_PERFECT_275
#undef MAP_PERFECT_274
#undef MAP_PERFECT_273
#undef MAP_PERFECT_272
#undef MAP_PERFECT_271
#undef MAP_PERFECT_270
#undef MAP_PERFECT_269
#undef MAP_PERFECT_268
#undef MAP_PERFECT_267
#undef MAP_PERFECT_266
#undef MAP_PERFECT_265
#undef MAP_PERFECT_264
#undef MAP_PERFECT_263
#undef MAP_PERFECT_262
#undef MAP_PERFECT_261
#undef MAP_PERFECT_260
#undef MAP_PERFECT_259
#undef MAP_PERFECT_258
#undef MAP_PERFECT_257
#undef MAP_PERFECT_256
#undef MAP_PERFECT_255
#undef MAP_PERFECT_254
#undef MAP_PERFECT_253
#undef MAP_PERFECT_252
#undef MAP_PERFECT_251
#undef MAP_PERFECT_250
#undef MAP_PERFECT_249
#undef MAP_PERFECT_248
#undef MAP_PERFECT_247
#undef MAP_PERFECT_246
#undef MAP_PERFECT_245
#undef MAP_PERFECT_244
#undef MAP_PERFECT_243
#undef MAP_PERFECT_242
#undef MAP_PERFECT_241
#undef MAP_PERFECT_240
#undef MAP_PERFECT_239
#undef MAP_PERFECT_238
#undef MAP_PERFECT_237
#undef MAP_PERFECT_236
#undef MAP_PERFECT_235
#undef MAP_PERFECT_234
#undef MAP_PERFECT_233
#undef MAP_PERFECT_232
#undef MAP_PERFECT_231
#undef MAP_PERFECT_230
#undef MAP_PERFECT_229
#undef MAP_PERFECT_228
#undef MAP_PERFECT_227
#undef MAP_PERFECT_226
#undef MAP_PERFECT_225
#undef MAP_PERFECT_224
#undef MAP_PERFECT_223
#undef MAP_PERFECT_222
#undef MAP_PERFECT_221
#undef MAP_PERFECT_220
#undef MAP_PERFECT_219
#undef MAP_PERFECT_218
#undef MAP_PERFECT_217
#undef MAP_PERFECT_216
#undef MAP_PERFECT_215
#undef MAP_PERFECT_214
#undef MAP_PERFECT_213
#undef MAP_PERFECT_212
#undef MAP_PERFECT_211
#undef MAP_PERFECT_210
#undef MAP_PERFECT_209
#undef MAP_PERFECT_208
#undef MAP_PERFECT_207
#undef MAP_PERFECT_206
#undef MAP_PERFECT_205
#undef MAP_PERFECT_204
#undef MAP_PERFECT_203
#undef MAP_PERFECT_202
#undef MAP_PERFECT_201
#undef MAP_PERFECT_200
#undef MAP_PERFECT_199
#undef MAP_PERFECT_198
#undef MAP_PERFECT_197
#undef MAP_PERFECT_196
#undef MAP_PERFECT_195
#undef MAP_PERFECT_194
#undef MAP_PERFECT_193
#undef MAP_PERFECT_192
#undef MAP_PERFECT_191
#undef MAP_PERFECT_190
#undef MAP_PERFECT_189
#undef MAP_PERFECT_188
#undef MAP_PERFECT_187
#undef MAP_PERFECT_186
#undef MAP_PERFECT_185
#undef MAP_PERFECT_184
#undef MAP_PERFECT_183
#undef MAP_PERFECT_182
#undef MAP_PERFECT_181
#undef MAP_PERFECT_180
#undef MAP_PERFECT_179
#undef MAP_PERFECT_178
#undef MAP_PERFECT_177
#undef MAP_PERFECT_176
#undef MAP_PERFECT_175
#undef MAP_PERFECT_174
#undef MAP_PERFECT_173
#undef MAP_PERFECT_172
#undef MAP_PERFECT_171
#undef MAP_PERFECT_170
#undef MAP_PERFECT_169
#undef MAP_PERFECT_168
#undef MAP_PERFECT_167
#undef MAP_PERFECT_166
#undef MAP_PERFECT_165
#undef MAP_PERFECT_164
#undef MAP_PERFECT_163
#undef MAP_PERFECT_162
#undef MAP_PERFECT_161
#undef MAP_PERFECT_160
#undef MAP_PERFECT_159
#undef MAP_PERFECT_158
#undef MAP_PERFECT_157
#undef MAP_PERFECT_156
#undef MAP_PERFECT_155
#undef MAP_PERFECT_154
#undef MAP_PERFECT_153
#undef MAP_PERFECT_152
#undef MAP_PERFECT_151
#undef MAP_PERFECT_150
#undef MAP_PERFECT_149
#undef MAP_PERFECT_148
#undef MAP_PERFECT_147
#undef MAP_PERFECT_146
#undef MAP_PERFECT_145
#undef MAP_PERFECT_144
#undef MAP_PERFECT_143
#undef MAP_PERFECT_142
#undef MAP_PERFECT_141
#undef MAP_PERFECT_140
#undef MAP_PERFECT_139
#undef MAP_PERFECT_138
#undef MAP_PERFECT_137
#undef MAP_PERFECT_136
#undef MAP_PERFECT_135
#undef MAP_PERFECT_134
#undef MAP_PERFECT_133
#undef MAP_PERFECT_132
#undef MAP_PERFECT_131
#undef MAP_PERFECT_130
#undef MAP_PERFECT_129
#undef MAP_PERFECT_128
#undef MAP_PERFECT_127
#undef MAP_PERFECT_126
#undef MAP_PERFECT_125
#undef MAP_PERFECT_124
#undef MAP_PERFECT_123
#undef MAP_PERFECT_122
#undef MAP_PERFECT_121
#undef MAP_PERFECT_120
#undef MAP_PERFECT_119
#undef MAP_PERFECT_118
#undef MAP_PERFECT_117
#undef MAP_PERFECT_116
#undef MAP_PERFECT_115
#undef MAP_PERFECT_114
#undef MAP_PERFECT_113
#undef MAP_PERFECT_112
#undef MAP_PERFECT_111
#undef MAP_PERFECT_110
#undef MAP_PERFECT_109
#undef MAP_PERFECT_108
#undef MAP_PERFECT_107
#undef MAP_PERFECT_106
#undef MAP_PERFECT_105
#undef MAP_PERFECT_104
#undef MAP_PERFECT_103
#undef MAP_PERFECT_102
#undef MAP_PERFECT_101
#undef MAP_PERFECT_100
#undef MAP_PERFECT_99
#undef MAP_PERFECT_98
#undef MAP_PERFECT_97
#undef MAP_PERFECT_96
#undef MAP_PERFECT_95
#undef MAP_PERFECT_94
#undef MAP_PERFECT_93
#undef MAP_PERFECT_92
#undef MAP_PERFECT_91
#undef MAP_PERFECT_90
#undef MAP_PERFECT_89
#undef MAP_PERFECT_88
#undef MAP_PERFECT_87
#undef MAP_PERFECT_86
#undef MAP_PERFECT_85
#undef MAP_PERFECT_84
#undef MAP_PERFECT_83
#undef MAP_PERFECT_82
#undef MAP_PERFECT_81
#undef MAP_PERFECT_80
#undef MAP_PERFECT_79
#undef MAP_PERFECT_78
#undef MAP_PERFECT_77
#undef MAP_PERFECT_76
#undef MAP_PERFECT_75
#undef MAP_PERFECT_74
#undef MAP_PERFECT_73
#undef MAP_PERFECT_72
#undef MAP_PERFECT_71
#undef MAP_PERFECT_70
#undef MAP_PERFECT_69
#undef MAP_PERFECT_68
#undef MAP_PERFECT_67
#undef MAP_PERFECT_66
#undef MAP_PERFECT_65
#undef MAP_PERFECT_64
#undef MAP_PERFECT_63
#undef MAP_PERFECT_62
#undef MAP_PERFECT_61
#undef MAP_PERFECT_60
#undef MAP_PERFECT_59
#undef MAP_PERFECT_58
#undef MAP_PERFECT_57
#undef MAP_PERFECT_56
#undef MAP_PERFECT_55
#undef MAP_PERFECT_54
#undef MAP_PERFECT_53
#undef MAP_PERFECT_52
#undef MAP_PERFECT_51
#undef MAP_PERFECT_50
#undef MAP_PERFECT_49
#undef MAP_PERFECT_48
#undef MAP_PERFECT_47
#undef MAP_PERFECT_46
#undef MAP_PERFECT_45
#undef MAP_PERFECT_44
#undef MAP_PERFECT_43
#undef MAP_PERFECT_42
#undef MAP_PERFECT_41
#undef MAP_PERFECT_40
#undef MAP_PERFECT_39
#undef MAP_PERFECT_38
#undef MAP_PERFECT_37
#undef MAP_PERFECT_36
#undef MAP_PERFECT_35
#undef MAP_PERFECT_34
#undef MAP_PERFECT_33
#undef MAP_PERFECT_32
#undef MAP_PERFECT_31
#undef MAP_PERFECT_30
#undef MAP_PERFECT_29
#undef MAP_PERFECT_28
#undef MAP_PERFECT_27
#undef MAP_PERFECT_26
#undef MAP_PERFECT_25
#undef MAP_PERFECT_24
#undef MAP_PERFECT_23
#undef MAP_PERFECT_22
#undef MAP_PERFECT_21
#undef MAP_PERFECT_20
#undef MAP_PERFECT_19
#undef MAP_PERFECT_18
#undef MAP_PERFECT_17
#undef MAP_PERFECT_16
#undef MAP_PERFECT_15
#undef MAP_PERFECT_14
#undef MAP_PERFECT_13
#undef MAP_PERFECT_12
#undef MAP_PERFECT_11
#undef MAP_PERFECT_10
#undef MAP_PERFECT_9
#undef MAP_PERFECT_8
#undef MAP_PERFECT_7
#undef MAP_PERFECT_6
#undef MAP_PERFECT_5
#undef MAP_PERFECT_4
#undef MAP_PERFECT_3
#undef MAP_PERFECT_2
#undef MAP_PERFECT_1
#undef MAP_PERFECT_0
