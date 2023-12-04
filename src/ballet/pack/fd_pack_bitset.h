#ifndef HEADER_fd_src_ballet_pack_fd_pack_bitset_h
#define HEADER_fd_src_ballet_pack_fd_pack_bitset_h

/* One of the main computational tasks of fd_pack is determining whether
   a given transaction conflicts with a different transaction or a group
   of transactions.  This is just a set intersection problem, and there
   are many ways to represent sets.  Here, we have the additional
   hypothesis that accounts referenced in a transaction exhibit some
   kind of power law probability distribution, i.e. certain accounts are
   referenced much more frequently than other accounts.  This means if
   two transactions conflict, the account that causes them to conflict
   is not a uniform random choice.

   This non-uniformity motivates the use of a hybrid bitset/hashset
   representation.  In an ideal world, we'd represent the N most common
   accounts with a bit in fixed-size a bitset and the rest in a hashset.
   To produce the bitset, we'd have some kind of mapping off on the side
   of which accounts correspond to which bits, and the intersection
   could be computed just looking at the bitset in the common case.

   However, the N most common accounts can change, and the complexity of
   tracking down every bitset that needs to be adjusted when the N most
   common accounts changes seems like it would eliminate any of the
   gains from this approach.

   Instead, we implement a simpler version of this idea.  We reserve a
   bit for an account when we have two transactions that reference that
   account.  Note that an account which appears in a single transaction
   can't cause a conflict, and this means that we only have one bitset
   to update.

   On the flip side, we'd like to free the bit when the reference count
   drops from 2 to 1, but again we face the difficult problem of
   tracking down that single transaction.  Threading some kind of
   per-account linked list through the transactions would work but seems
   like a nightmare, so we just defer freeing the bit until the
   reference count drops to 0.

   Since our bitset is fixed size, it's possible that we may try to
   reserve a bit but find all our bits are already mapped.  Rather than
   spilling the account to some kind of overflow hashset like in the
   motivating sketch solution, we just don't store it.  That means that
   this compressed set representation can sometimes answer incorrectly,
   but only in one direction: it may suggest a transaction doesn't
   conflict when it actually does.  This may seem like the opposite type
   of error compared to what we want, but for each transaction we might
   accept into the microblock, we need to iterate over at least the
   writable accounts it contains to check if they would exceed the
   per-account max write lock cost, so we already have a case of needing
   to reject a transaction it seemed like we might accept, so now we
   just have a second reason for that.

   It is easy to modify the code slightly to flip the direction of the
   error (i.e. it might say two sets intersect when they actually
   don't) by permanently reserving one of the bits as an "overflow bit"
   indicating that the transaction has some accounts other than those
   represented in the bitset.  This naturally causes any transaction
   with the overflow bit to conflict with any other transaction with the
   overflow bit.

   All of this can be done with AVX or with fd_set. */

#ifndef FD_PACK_BITSET_MODE
#  if FD_HAS_AVX512
#    define FD_PACK_BITSET_MODE 2
#  elif FD_HAS_AVX
#    define FD_PACK_BITSET_MODE 1
#  else
#    define FD_PACK_BITSET_MODE 0
#  endif
#endif

#define FD_PACK_BITSET_SLOWPATH       ((ushort)0xFFFF)
#define FD_PACK_BITSET_FIRST_INSTANCE ((ushort)0xFFFE)
/* Define a little interface for the different bitset implementations.

   FD_PACK_BITSET_T is never used in the code, but is the type of the
   arguments to the other functions.

   FD_PACK_BITSET_MAX is the number of elements that can be stored in
   the bitset.

   FD_PACK_BITSET_DECLARE declares a variable called `name` of type T (or
   something that decays to T).  The set has indeterminate value at this
   point.

   FD_PACK_BITSET_CLEAR takes a set of type T and clears it, setting
   `set` to the empty set.

   FD_PACK_BITSET_SETN sets bit n in the set.  `set` must be type T.  If
   n is not in [0, FD_PACK_BITSET_MAX) or n is already in `set`, this is
   a no-op.

   FD_PACK_BITSET_CLEARN clears bit n in the set. `set` must be type T.
   If n is not in [0, FD_PACK_BITSET_MAX) or n is not in `set`, this is
   a no-op.

   FD_PACK_BITSET_OR updates srcdest with the union of srcdest and x.
   This is a statement and so does not return anything, not a value.
   Think of it like srcdest |= x.

   FD_PACK_BITSET_INTERSECT4_EMPTY returns whether (x1 & y1) and
   (x2 & y2) are both empty.  It is done this way because fd_set
   temporaries are a bit of a pain.  All 4 sets should be of type T.
   Does not modify any of the input sets.

   FD_PACK_BITSET_ISNULL takes a set of type T and returns 1 if the set
   is empty/the null set and 0 if it has at least one element.

   FD_PACK_BITSET_COPY takes two sets of type T and resets the contents
   of dest to be equal to the contents of src. */
#if FD_PACK_BITSET_MODE==0


#  define SET_NAME addr_bitset
/* We actually have some flexibility in this case, but for the few
   blocks that I looked it, 256 seemed like a good number for 1024
   transactions. */
#  define SET_MAX  256
#  include "../../util/tmpl/fd_set.c"

#  define FD_PACK_BITSET_T   addr_bitset_t * /* == ulong *   */
#  define FD_PACK_BITSET_MAX 256UL

#  define FD_PACK_BITSET_DECLARE(name)  addr_bitset_t name [ addr_bitset_word_cnt ]
#  define FD_PACK_BITSET_CLEAR(set)     addr_bitset_new( set )
#  define FD_PACK_BITSET_SETN(set, n)   do {                                                       \
                                          if( n<FD_PACK_BITSET_MAX ) addr_bitset_insert( set, n ); \
                                        } while( 0 )
#  define FD_PACK_BITSET_CLEARN(set, n) do {                                                       \
                                          if( n<FD_PACK_BITSET_MAX ) addr_bitset_remove( set, n ); \
                                        } while( 0 )
#  define FD_PACK_BITSET_OR(srcdest, x) do {                                              \
                                          addr_bitset_t * __srcdest = (srcdest);          \
                                          addr_bitset_union( __srcdest, __srcdest, (x) ); \
                                        } while( 0 )
#  define FD_PACK_BITSET_INTERSECT4_EMPTY(x1, x2, y1, y2) (__extension__({                                                    \
                                                            addr_bitset_t __temp1[ addr_bitset_word_cnt ];                    \
                                                            addr_bitset_t __temp2[ addr_bitset_word_cnt ];                    \
                                                            addr_bitset_intersect( __temp1, (x1), (y1) );                     \
                                                            addr_bitset_intersect( __temp2, (x2), (y2) );                     \
                                                            addr_bitset_is_null( __temp1 ) && addr_bitset_is_null( __temp2 ); \
                                                          }))
#  define FD_PACK_BITSET_ISNULL(set)    addr_bitset_is_null( set )

#  define FD_PACK_BITSET_COPY(dest, src) addr_bitset_copy( dest, src )


#elif FD_PACK_BITSET_MODE==1

#  include "../../util/simd/fd_avx.h"

#  define FD_PACK_BITSET_T   wv_t
#  define FD_PACK_BITSET_MAX 256UL

#  define FD_PACK_BITSET_DECLARE(name) wv_t name
#  define FD_PACK_BITSET_CLEAR(set)    (set) = wv_zero()
#  define FD_PACK_BITSET_SETN(set, n)    do {                                                                    \
                                           wv_t _n           = wv_bcast( n );                                    \
                                           wv_t shift_offset = wv( 0UL, 64UL, 128UL, 192UL );                    \
                                           wv_t one          = wv_bcast( 1UL );                                  \
                                           set = wv_or( set, wv_shl_vector( one, wv_sub( _n, shift_offset ) ) ); \
                                         } while( 0 )
#  define FD_PACK_BITSET_CLEARN(set, n)  do {                                                                      \
                                         wv_t _n           = wv_bcast( n );                                        \
                                         wv_t shift_offset = wv( 0UL, 64UL, 128UL, 192UL );                        \
                                         wv_t one          = wv_bcast( 1UL );                                      \
                                         set = wv_andnot( wv_shl_vector( one, wv_sub( _n, shift_offset ) ), set ); \
                                       } while( 0 )
#  define FD_PACK_BITSET_OR(srcdest, x) srcdest = wv_or( srcdest, x );
#  define FD_PACK_BITSET_INTERSECT4_EMPTY(x1, x2, y1, y2) (__extension__({                                             \
                                                             wv_t _temp = wv_or( wv_and( x1, y1 ), wv_and( x2, y2 ) ); \
                                                             _mm256_testz_si256( _temp, _temp );                       \
                                                          }))
#  define FD_PACK_BITSET_ISNULL(set)      _mm256_testz_si256( set, set )
#  define FD_PACK_BITSET_COPY(dest, src) dest=src

#elif FD_PACK_BITSET_MODE==2
#  include "../../util/simd/fd_avx512.h"

#  define FD_PACK_BITSET_T   wwv_t
#  define FD_PACK_BITSET_MAX 512UL

#  define FD_PACK_BITSET_DECLARE(name) wwv_t name
#  define FD_PACK_BITSET_CLEAR(set)    (set) = wwv_zero()
#  define FD_PACK_BITSET_SETN(set, n)    do {                                                                               \
                                           wwv_t _n           = wwv_bcast( n );                                             \
                                           wwv_t shift_offset = wwv( 0UL, 64UL, 128UL, 192UL, 256UL, 320UL, 384UL, 448UL ); \
                                           wwv_t one          = wwv_bcast( 1UL );                                           \
                                           set = wwv_or( set, wwv_shl_vector( one, wwv_sub( _n, shift_offset ) ) );         \
                                         } while( 0 )
#  define FD_PACK_BITSET_CLEARN(set, n)  do {                                                                               \
                                           wwv_t _n           = wwv_bcast( n );                                             \
                                           wwv_t shift_offset = wwv( 0UL, 64UL, 128UL, 192UL, 256UL, 320UL, 384UL, 448UL ); \
                                           wwv_t one          = wwv_bcast( 1UL );                                           \
                                           set = wwv_andnot( wwv_shl_vector( one, wwv_sub( _n, shift_offset ) ), set );     \
                                         } while( 0 )
#  define FD_PACK_BITSET_OR(srcdest, x) srcdest = wwv_or( srcdest, x );
#  define FD_PACK_BITSET_INTERSECT4_EMPTY(x1, x2, y1, y2) (__extension__({                                                 \
                                                             wwv_t _temp = wwv_or( wwv_and( x1, y1 ), wwv_and( x2, y2 ) ); \
                                                             _mm512_test_epi64_mask( _temp, _temp )==0;                    \
                                                          }))
#  define FD_PACK_BITSET_ISNULL(set) (0==_mm512_test_epi64_mask( set, set ))
#  define FD_PACK_BITSET_COPY(dest, src) dest=src

#else
#  error "FD_PACK_BITSET_MODE not recognized"
#endif

#endif /* HEADER_fd_src_ballet_pack_fd_pack_bitset_h */
