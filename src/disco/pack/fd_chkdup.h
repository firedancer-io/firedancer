#ifndef HEADER_fd_src_disco_pack_fd_chkdup_h
#define HEADER_fd_src_disco_pack_fd_chkdup_h

#include "../../ballet/fd_ballet_base.h"
#include "../../ballet/txn/fd_txn.h"

/* fd_chkdup declares a set of functions for ultra-HPC checking if a
   list of account addresses contains any duplicates.  It's important
   that this be fast, because a transaction containing duplicate account
   addresses fails to sanitize and is not charged a fee.  Although this
   check can (and really ought) to be done in parallel, perhaps in the
   verify tiles, right now, it's done in pack, which means it's serial
   and on the critical path.

   On platforms with AVX, the current implementation uses a fast initial
   check which may have false positives (thinking there are duplicates
   when there aren't).  Any transaction that fails the initial check is
   then subjected to the full, precise check.  Without AVX, all
   transactions use the slow path. */

/* The functions are defined in the header to facilitate inlining since
   they take 10s of cycles in the good case, but should probably be
   treated as if they were defined in a .c file. */

#ifndef FD_CHKDUP_IMPL
# if FD_HAS_AVX512
#   include "../../util/simd/fd_avx.h"
#   define FD_CHKDUP_IMPL 2
# elif FD_HAS_AVX
#   define FD_CHKDUP_IMPL 1
# else
#   define FD_CHKDUP_IMPL 0
# endif
#endif


#if FD_CHKDUP_IMPL==2
# define FD_CHKDUP_ALIGN ( 64UL)
#elif FD_CHKDUP_IMPL==1
# define FD_CHKDUP_ALIGN ( 32UL)
#elif FD_CHKDUP_IMPL==0
# define FD_CHKDUP_ALIGN ( 32UL)
#else
# error "Unrecognized value of FD_CHKDUP_IMPL"
#endif


# define FD_CHKDUP_FOOTPRINT  FD_LAYOUT_FINI( FD_LAYOUT_APPEND(                                         \
                                                             FD_LAYOUT_APPEND( FD_LAYOUT_INIT,               \
                                                             FD_CHKDUP_ALIGN, 32*FD_CHKDUP_IMPL ), \
                                                             32UL,                 (1UL<<8)*32UL    ),       \
                                                   FD_CHKDUP_ALIGN )

FD_STATIC_ASSERT( (1UL<<8)==2*FD_TXN_ACCT_ADDR_MAX, "hash table size" );

/* Fixed size (just over 8kB) and safe for declaration on the stack or
   inclusion in a struct. */
struct fd_chkdup_private;
typedef struct fd_chkdup_private fd_chkdup_t;

FD_PROTOTYPES_BEGIN
/* fd_chkdup_{footprint, align} return the footprint and alignment of
   the scratch memory that duplicate detection requires. */
static inline ulong fd_chkdup_footprint( void ) { return FD_CHKDUP_FOOTPRINT; }
static inline ulong fd_chkdup_align    ( void ) { return FD_CHKDUP_ALIGN;     }

/* fd_chkdup_new formats an appropriately sized region of memory for use
   in duplicate address detection.  shmem must point to the first byte
   of a region of memory with the appropriate alignment and footprint.
   rng must be a pointer to a local join of an RNG.  Some slots of the
   RNG will be consumed, but no interest in the RNG will be retained
   after the function returns.  Returns shmem on success and NULL on
   failure (logs details).  The only failure cases are if shmem is NULL
   or not aligned.

   fd_chkdup_join joins the caller to the formatted region of memory.
   Returns shmem.

   fd_chkdup_leave unjoins the caller to chkdup.  Returns chkdup.
   fd_chkdup_delete unformats the region of memory.  Returns a pointer
   to the unformatted memory region. */
static inline void *        fd_chkdup_new   ( void * shmem, fd_rng_t * rng );
static inline fd_chkdup_t * fd_chkdup_join  ( void * shmem                 );
static inline void *        fd_chkdup_leave ( fd_chkdup_t * chkdup         );
static inline void *        fd_chkdup_delete( void * shmem                 );


/* fd_chkdup_check{,_slow,_fast} check a list of account addresses for
   any duplicate addresses, i.e. an account address that appears twice
   in the list.  The list does not need to be sorted or have any
   particular order.  The list may be decomposed into two sublists
   (list0 and list1) to facilitate 0-copy usage with address lookup
   tables, but list0 and list1 are logically concatenated prior to
   checking for duplicates.

   chkdup is a pointer to a valid local join of a chkdup object.

   list0 and list1 point to the first account address of the respective
   sublists.  The memory they point to need not have any particular
   alignment.  list0==NULL is okay only if list0_cnt==0, and similarly
   for list1.  list0 is accessed with indices [0, list0_cnt) and list1
   is accessed with indices [0, list1_cnt).  list0 and list1 must not
   overlap.  Requires list0_cnt+list1_cnt<=128, and the function is
   somewhat tuned for smaller values.

   fd_chkdup_check and the _slow version return 1 if the list of
   transactions contains at least one duplicated account address and 0
   otherwise (implying each account address in the provided list is
   unique).

   fd_chkdup_check_fast returns 1 if the list of transactions contains
   at least one duplicated account address and typically returns 0 if
   each account address in the provided list is unique, but may
   sometimes spuriiously return 1 even without duplicates.

   WARNING: the _fast version MAY HAVE FALSE POSITIVES.  You probably
   want the un-suffixed version, which is precise.  It uses the fast
   version as a fast-path and then does a slower full check if the
   fast-path suggests there may be a duplicate.

   However, it's also worth calling out again that the _fast version
   only makes errors in one direction.  If the list contains duplicates,
   it will definitely return 1.  If it returns 0, the list definitely
   does not contain duplicates. (Those two statements are equivalent).
   */
static inline int
fd_chkdup_check     ( fd_chkdup_t          * chkdup,
                      fd_acct_addr_t const * list0,     ulong list0_cnt,
                      fd_acct_addr_t const * list1,     ulong list1_cnt );
static inline int
fd_chkdup_check_slow( fd_chkdup_t          * chkdup,
                      fd_acct_addr_t const * list0,     ulong list0_cnt,
                      fd_acct_addr_t const * list1,     ulong list1_cnt );
static inline int
fd_chkdup_check_fast( fd_chkdup_t          * chkdup,
                      fd_acct_addr_t const * list0,     ulong list0_cnt,
                      fd_acct_addr_t const * list1,     ulong list1_cnt );


/*   -----  Implementation details and discussion follow------

   The fast path implementation is somewhat interesting.  The normal way
   to do this is with a Bloom filter, but Bloom filters do lots of
   unpredictable reads and the pack tile is somewhat cache sensitive.
   Instead, this implements a variant on a Bloom filter that lives
   entirely in AVX registers.

   Basically, we use C W-bit words stored in (C*W)/256 AVX2 registers or
   (C*W)/512 AVX512 registers.  Each word is a modified Bloom filter
   with one associated hash function.  For each account address, we
   compute C hashes, giving (up to) C positions across the AVX
   registers.  If any of those positions have an unset bit, then we know
   we have not seen the account address before.  Finally, we then set
   all the positions.

   The only difference between this idea and a normal Bloom filter is
   that sometimes the hash function may not select a bit.  There's a
   tradeoff to be made here: suppose you insert R account addresses, and
   R is at least almost as large as W.  Then each word fills up, and
   false positives become increasingly likely.  Only testing and
   inserting a bit, say, half the time, effectively halves C, but
   prevents each word from getting saturated as quickly, and makes the
   algorithm effective for larger values of R.  We use Intel's quirky
   behavior to get this for free.

   (Note: The R and C notation is supposed to suggest a tabular layout
   in which the account addresses are rows and the words are columns.)

   The key insight into making this work quickly is that the vpsllv{d,q}
   variable left shift instructions are cheap (1 cycle, can execute on
   port 0 or 1 for AVX2, still 1 cycle on port 0 for AVX512).  If we can
   compute the hashes in parallel with SIMD, then we can variably shift
   bcast(0x1) quickly, and select several bits at a time.  The rest is
   just bitwise logic, which is extremely cheap with AVX.  This approach
   constrains W to be either 32 or 64, and C to be a multiple of the
   number of words in a vector, but those are both pretty acceptable
   constraints.

   The final ingredient is a cheap hash function that places the hashes
   in the appropriate position for vpsllv.  We just xor the account
   address with some validator-specific entropy and use a mask to select
   certain bits.

   The slow-path implementation uses a hash table to check for
   duplicates.  This is slower than sorting for transactions with only a
   few account addresses, but substantially faster than sorting for
   transactions with large numbers of account addresses, which is when
   the slow-path matters more anyway.


   You can see from above there are a variety of knobs to tune.  Should
   W be 32 or 64?  How big should C be?  How many bits should we mask
   off for the hash, which controls the frequency with which we skip a
   word, neither checking nor inserting a bit?  It would be good to have
   a rigorous understanding of the false positive rate as a function of
   these parameters so we can make a decision that minimizes the
   expected compute required.

   Unfortunately, the false positive computation is tricky.  The key
   difficulty is that whether processing account address r results in a
   false positive is not independent from whether processing account
   address r+1 results in a false positive.  This leads to an obnoxious
   inclusion-exclusion formula which quickly becomes more unwieldy than
   I (or Sage) can handle.

   A dynamic-programming-ish algorithm can compute the false positive
   rate in approximately O(R*2^R) time.  To start, we just want to
   understand a single word/column.  Suppose k bits in the word have
   been set.  Then there are (W-k) hash values that set a new bit, and
   (V+k) hash values that don't set a new, where V is the number of hash
   values that don't select a bit.  The hash values that set a bit are
   also exactly the ones that provide information that the account
   address is not a false positive.  I think about this as "spending a
   bit" to know it's not a false positive.

   Denoting the rows at which we spend a bit by a 1 and the rows at
   which we don't spend a bit by 0, we might get a column like:

                                1
                                0
                                1
                                1
                                0.
   The number of ways this column can occur is x1 =
   W*(V+1)*(W-1)*(W-2)*(V+3), which means that the probability the
   column occurs is x1/(W+V)^5.  Expanding to multiple columns is easy,
   since the number of ways that two specific columns can occur is just
   the product of the number of ways each can occur.  For example,
                              1 0
                              0 1
                              1 1
                              1 0
                              0 0
   can occur x1 * x2 ways, where x2 = V*W*(W-1)*(V+2)*(V+2).
   A false positive happens when there's a row of all 0s, as in the last
   row of the example.

   It's cleaner to count the number of ways not to get a false positive.
   This gives us the inclusion-exclusion formula:
   (all ways)
        - (all ways where row 0 is all 0s)
        - (all ways where row 1 is all 0s)
        - ...
        + (all ways where rows 0 and 1 are both all 0s)
        + (all ways where rows 0 and 2 are both all 0s)
        + ...
        - (all ways where rows 0, 1, and 2 are all 0s)
        - (all ways where rows 0, 1, and 3 are all 0s)
        +, - ...
        + (-1)^R (all ways in which all rows are all 0s).

   There's a nice way to understand each of these terms.  For example,
   in the R=2, C=3 case, the term in which row 0 is all 0s has the
   following elements:
    0 0 0   0 0 0   0 0 0   0 0 0   0 0 0   0 0 0   0 0 0   0 0 0
    0 0 0   0 0 1   0 1 0   0 1 1   1 0 0   1 0 1   1 1 0   1 1 1
   Rather than enumerating all 2^( (R-1)*C ) elements, we'll represent
   it as
                      ( 0  + 0 )^3
                      ( 0    1 )

   Skipping some steps, the task boils down to counting the number of
   ways to get columns that match a mask, then raising that to the Cth
   power.

   Now, with all this behind us, our goal is to pick the optimal value
   of W,V, and C given a supposed distribution of transactions, and a
   performance model.  Based on some back of the envelope calculations
   based on instruction throughput and latency measurements and
   confirmed by some experiments, the fast path code takes about 3.5*R
   cycles if using one AVX2 vector (W*C==256) and
   2.5*R+2*ceil(W*C/256)*R cycles otherwise.  The slow path takes about
   133*J cycles.  Then the expected value of the number of cycles it
   takes to process a transaction with R accounts is
     R*(2.5+2*ceil(W*C/256) - [W*C<=256]) + FP_{W,V,R,C}*133*R

   Based on a sample of 100,000 slots containing about 100M
   transactions, the CDF looks like

     Fraction of transactions containing <=  3 account addresses     71%
                                         <= 13 account addresses     80%
                                         <= 24 account addresses     91%
                                         <= 31 account addresses     95%
                                         <= 44 account addresses     98%
                                         <= 50 account addresses     99%

   Basically, there's a peak at 3 (votes), and then a very long, very
   fat tail.  When using AVX2, it basically boils down into 2 regimes:
          0 <= R <  28            W=32, C=8,  V=0  (one AVX vector)
         28 <= R <= 64            W=32, C=32, V=32 (four AVX vectors)

   This combination has an expected value of about 54 cycles over all
   transactions.  For a typical transaction with 3 account addresses,
   this takes about 10 cycles and the false positive probability is
   about 2e-10.

   When using AVX512, the regimes are similar:
          0 <= R <  36            W=32, C=16, V=0  (one AVX vector)
         36 <= R <= 64            W=32, C=32, V=32 (two AVX vectors)
  This combination has an expected value of about 33 cycles over all
  transactions.  Again, the typical 3 account address account takes
  about 9 cycles and has a negligible false positive probability. */


struct fd_chkdup_waddr {
  fd_acct_addr_t key; /* account address */
};
typedef struct fd_chkdup_waddr fd_chkdup_waddr_t;
static const fd_acct_addr_t chkdup_null_addr = {{ 0 }};

#define MAP_NAME              fd_chkdup_pmap
#define MAP_T                 fd_chkdup_waddr_t
#define MAP_KEY_T             fd_acct_addr_t
#define MAP_KEY_NULL          chkdup_null_addr
#define MAP_KEY_INVAL(k)      MAP_KEY_EQUAL(k, chkdup_null_addr)
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp((k0).b,(k1).b, FD_TXN_ACCT_ADDR_SZ))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_MEMOIZE           0
#define MAP_KEY_HASH(key)     ((uint)fd_ulong_hash( fd_ulong_load_8( (key).b ) ))
#define MAP_LG_SLOT_CNT 8
#include "../../util/tmpl/fd_map.c"


struct __attribute__((aligned(FD_CHKDUP_ALIGN))) fd_chkdup_private {
#if FD_CHKDUP_IMPL >= 1
  uchar  entropy[ 32*FD_CHKDUP_IMPL ];
#endif

  fd_chkdup_waddr_t hashmap[ 1UL<<8 ];
};

static inline void *
fd_chkdup_new( void     * shmem,
               fd_rng_t * rng   ) {
  fd_chkdup_t * chkdup = (fd_chkdup_t *)shmem;
#if FD_CHKDUP_IMPL >= 1
  for( ulong i=0UL; i<32*FD_CHKDUP_IMPL; i++ ) chkdup->entropy[ i ] = fd_rng_uchar( rng );
#else
  (void)rng;
#endif
  FD_TEST( fd_chkdup_pmap_footprint()==sizeof(chkdup->hashmap) ); /* Known at compile time */

  fd_chkdup_pmap_new( chkdup->hashmap );
  return chkdup;
}

static inline fd_chkdup_t * fd_chkdup_join  ( void * shmem ) { return (fd_chkdup_t *)shmem; }

static inline void * fd_chkdup_leave ( fd_chkdup_t * chkdup ) { return (void *)chkdup; }
static inline void * fd_chkdup_delete( void        * shmem  ) { return         shmem;  }


static inline int
fd_chkdup_check     ( fd_chkdup_t          * chkdup,
                      fd_acct_addr_t const * list0,     ulong list0_cnt,
                      fd_acct_addr_t const * list1,     ulong list1_cnt ) {
  if( FD_LIKELY( 0==fd_chkdup_check_fast( chkdup, list0, list0_cnt, list1, list1_cnt ) ) ) return 0;
  return fd_chkdup_check_slow( chkdup, list0, list0_cnt, list1, list1_cnt );
}

static inline int
fd_chkdup_check_slow( fd_chkdup_t          * chkdup,
                      fd_acct_addr_t const * list0,     ulong list0_cnt,
                      fd_acct_addr_t const * list1,     ulong list1_cnt ) {
  fd_chkdup_waddr_t * map = fd_chkdup_pmap_join( chkdup->hashmap );
  fd_chkdup_waddr_t * inserted[ FD_TXN_ACCT_ADDR_MAX ];
  ulong inserted_cnt = 0UL;

  int any_duplicates = 0;
  int skipped_inval = 0;
  for( ulong i0=0UL; (i0<list0_cnt) & !any_duplicates; i0++ ) {
    if( FD_UNLIKELY( fd_chkdup_pmap_key_inval( list0[ i0 ] ) ) ) {
      /* Okay if this is the 1st, but not if the 2nd */
      any_duplicates |= skipped_inval;
      skipped_inval   = 1;
      continue;
    }
    fd_chkdup_waddr_t * ins = fd_chkdup_pmap_insert( map, list0[ i0 ] );
    inserted[ inserted_cnt++ ] = ins;
    any_duplicates |=        (NULL==ins);
    inserted_cnt   -= (ulong)(NULL==ins); /* Correct inserted_cnt if we just stored a NULL */
  }
  for( ulong i1=0UL; (i1<list1_cnt) & !any_duplicates; i1++ ) {
    if( FD_UNLIKELY( fd_chkdup_pmap_key_inval( list1[ i1 ] ) ) ) {
      any_duplicates |= skipped_inval;
      skipped_inval   = 1;
      continue;
    }
    fd_chkdup_waddr_t * ins = fd_chkdup_pmap_insert( map, list1[ i1 ] );
    inserted[ inserted_cnt++ ] = ins;
    any_duplicates |=        (NULL==ins);
    inserted_cnt   -= (ulong)(NULL==ins);
  }

  /* FIXME: This depends on undocumented map behavior for correctness.
     Deleting in the opposite order of insertion preserves previously
     inserted pointers. That behavior should be documented. */
  for( ulong i=0UL; i<inserted_cnt; i++ ) fd_chkdup_pmap_remove( map, inserted[ inserted_cnt-1UL-i ] );

  fd_chkdup_pmap_leave( map );

  return any_duplicates;
}


#if FD_CHKDUP_IMPL==1

/* AVX2 implementation */
#include "../../util/simd/fd_avx.h"
static inline int
fd_chkdup_check_fast( fd_chkdup_t          * chkdup,
                      fd_acct_addr_t const * list0,     ulong list0_cnt,
                      fd_acct_addr_t const * list1,     ulong list1_cnt ) {
  if( FD_UNLIKELY( list0_cnt+list1_cnt<=1UL ) ) return 0UL;

  int any_duplicates = 0;

  const wu_t entropy = wb_ld( chkdup->entropy );
  const wu_t one     = wu_bcast( 1U );


  if( FD_LIKELY( list0_cnt+list1_cnt<28UL ) ) {
    /* Single vector implementation */
    const wu_t mask = wu_bcast( 0x1FU );

    wu_t bloom = wu_zero();
    for( ulong i0=0UL; i0<list0_cnt; i0++ ) {
      wu_t addr    = wb_ldu( list0+i0 );
      wu_t masked  = wu_and( wu_xor( addr, entropy ), mask );
      wu_t select  = wu_shl_vector( one, masked );
      /* testc: "Compute the bitwise NOT of a and then AND with b, and
         [return] 1 if the result is zero." */
      any_duplicates |= _mm256_testc_si256( bloom, select );
      bloom = wu_or( bloom, select );
    }
    for( ulong i1=0UL; i1<list1_cnt; i1++ ) {
      wu_t addr    = wb_ldu( list1+i1 );
      wu_t masked  = wu_and( wu_xor( addr, entropy ), mask );
      wu_t select  = wu_shl_vector( one, masked );
      any_duplicates |= _mm256_testc_si256( bloom, select );
      bloom = wu_or( bloom, select );
    }
    return any_duplicates;

  } else {
    /* 4-vector implementation: slower but much better false positive
       rate so that we don't have to fall back to the slow path as
       frequently. */
    const wu_t mask = wu_bcast( 0x3FU );

    wu_t bloom0 = wu_zero();                                wu_t bloom1 = wu_zero();
    wu_t bloom2 = wu_zero();                                wu_t bloom3 = wu_zero();
    for( ulong i0=0UL; i0<list0_cnt; i0++ ) {
      wu_t addr    = wb_ldu( list0+i0 );
      wu_t blinded = wu_xor( addr, entropy );
      wu_t masked0 = wu_and( mask, blinded );               wu_t masked1 = wu_and( mask, wu_shr( blinded,  6 ) );
      wu_t masked2 = wu_and( mask, wu_shr( blinded, 12 ) ); wu_t masked3 = wu_and( mask, wu_shr( blinded, 18 ) );
      wu_t select0 = wu_shl_vector( one, masked0 );         wu_t select1 = wu_shl_vector( one, masked1 );
      wu_t select2 = wu_shl_vector( one, masked2 );         wu_t select3 = wu_shl_vector( one, masked3 );

      wu_t any_differences = wu_or(
           wu_or( wu_andnot( bloom0, select0 ),             wu_andnot( bloom1, select1 ) ),
           wu_or( wu_andnot( bloom2, select2 ),             wu_andnot( bloom3, select3 ) ) );

      bloom0  = wu_or( bloom0, select0 );                   bloom1  = wu_or( bloom1, select1 );
      bloom2  = wu_or( bloom2, select2 );                   bloom3  = wu_or( bloom3, select3 );

      any_duplicates |= _mm256_testz_si256( any_differences, any_differences );
      FD_COMPILER_FORGET( any_duplicates );
    }
    for( ulong i1=0UL; i1<list1_cnt; i1++ ) {
      wu_t addr    = wb_ldu( list1+i1 );
      wu_t blinded = wu_xor( addr, entropy );
      wu_t masked0 = wu_and( mask, blinded );               wu_t masked1 = wu_and( mask, wu_shr( blinded,  6 ) );
      wu_t masked2 = wu_and( mask, wu_shr( blinded, 12 ) ); wu_t masked3 = wu_and( mask, wu_shr( blinded, 18 ) );
      wu_t select0 = wu_shl_vector( one, masked0 );         wu_t select1 = wu_shl_vector( one, masked1 );
      wu_t select2 = wu_shl_vector( one, masked2 );         wu_t select3 = wu_shl_vector( one, masked3 );

      wu_t any_differences = wu_or(
           wu_or( wu_andnot( bloom0, select0 ),             wu_andnot( bloom1, select1 ) ),
           wu_or( wu_andnot( bloom2, select2 ),             wu_andnot( bloom3, select3 ) ) );

      bloom0  = wu_or( bloom0, select0 );                   bloom1  = wu_or( bloom1, select1 );
      bloom2  = wu_or( bloom2, select2 );                   bloom3  = wu_or( bloom3, select3 );

      any_duplicates |= _mm256_testz_si256( any_differences, any_differences );
      FD_COMPILER_FORGET( any_duplicates );
    }
    return any_duplicates;
  }
}

#elif FD_CHKDUP_IMPL==2

/* AVX512 implementation */
#include "../../util/simd/fd_avx512.h"
static inline int
fd_chkdup_check_fast( fd_chkdup_t              * chkdup,
                      fd_acct_addr_t const     * list0,     ulong list0_cnt,
                      fd_acct_addr_t const     * list1,     ulong list1_cnt ) {
  if( FD_UNLIKELY( list0_cnt+list1_cnt<=1UL ) ) return 0UL;

  int any_duplicates = 0;

  const wwu_t entropy = wwu_ld( (uint const *)chkdup->entropy );
  const wwu_t one     = wwu_bcast( 1U );

  if( FD_LIKELY( list0_cnt+list1_cnt<36UL ) ) {
    /* One vector version */
    /* Our analysis assumed the 64 bytes of hash were all independent,
       but if we just xor and then use the low 5 bits of both parts of
       the vector, we get a lot more false positives than the math
       predicts. */
    const wwu_t mask = wwu_bcast( 0x1FU );
    wwu_t bloom = wwu_zero();
    for( ulong i0=0UL; i0<list0_cnt; i0++ ) {
      wwu_t addr    = _mm512_broadcast_i64x4( wu_ldu( list0+i0 ) );
      wwu_t blinded = wwu_xor( addr, entropy );
      wwu_t masked  = wwu_and( mask, _mm512_mask_srli_epi32( blinded, 0xFF00, blinded, 6 ) );
      wwu_t select  = _mm512_rolv_epi32( one, masked );
      wwu_t next    = wwu_or( bloom, select );
      __mmask8 any_differences = _mm512_cmp_epi64_mask( bloom, next, _MM_CMPINT_NE ); /* if non-zero, not a duplicate */
      bloom = next;
      /* kortestz_mask8_u8: "Compute the bitwise OR of 8-bit masks a and
         b. If the result is all zeroes, [return] 1" */
      any_duplicates |= _kortestz_mask8_u8( any_differences, any_differences );
      FD_COMPILER_FORGET( any_duplicates );
    }
    for( ulong i1=0UL; i1<list1_cnt; i1++ ) {
      wwu_t addr    = _mm512_broadcast_i64x4( wu_ldu( list1+i1 ) );
      wwu_t blinded = wwu_xor( addr, entropy );
      wwu_t masked  = wwu_and( mask, _mm512_mask_srli_epi32( blinded, 0xFF00, blinded, 6 ) );
      wwu_t select  = _mm512_rolv_epi32( one, masked );
      wwu_t next    = wwu_or( bloom, select );
      __mmask8 any_differences = _mm512_cmp_epi64_mask( bloom, next, _MM_CMPINT_NE );
      bloom = next;
      any_duplicates |= _kortestz_mask8_u8( any_differences, any_differences );
      FD_COMPILER_FORGET( any_duplicates );
    }
    return any_duplicates;
  } else {
    /* Two vector version */
    const wwu_t mask = wwu_bcast( 0x3FU );
    const wwu_t shift0 = wwu( 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
                              6U, 6U, 6U, 6U, 6U, 6U, 6U, 6U );
    const wwu_t shift1 = wwu( 12U, 12U, 12U, 12U, 12U, 12U, 12U, 12U,
                              18U, 18U, 18U, 18U, 18U, 18U, 18U, 18U );
    wwu_t bloom0 = wwu_zero();            wwu_t bloom1 = wwu_zero();
    for( ulong i0=0UL; i0<list0_cnt; i0++ ) {
      wwu_t addr    = _mm512_broadcast_i64x4( wu_ldu( list0+i0 ) );
      wwu_t blinded = wwu_xor( addr, entropy );
      wwu_t masked0 = wwu_and( mask, wwu_shr_vector( blinded, shift0 ) );  wwu_t masked1 = wwu_and( mask, wwu_shr_vector( blinded, shift1 ) );
      wwu_t select0 = wwu_shl_vector( one, masked0 );                      wwu_t select1 = wwu_shl_vector( one, masked1 );
      wwu_t next0   = wwu_or( bloom0, select0 );                           wwu_t next1   = wwu_or( bloom1, select1 );
      __mmask8 any_differences = _kor_mask8(
          _mm512_cmp_epi64_mask( bloom0, next0, _MM_CMPINT_NE ),           _mm512_cmp_epi64_mask( bloom1, next1, _MM_CMPINT_NE ) );

      bloom0 = next0;                                                      bloom1 = next1;

      any_duplicates |= _kortestz_mask8_u8( any_differences, any_differences );
      FD_COMPILER_FORGET( any_duplicates );
    }
    for( ulong i1=0UL; i1<list1_cnt; i1++ ) {
      wwu_t addr    = _mm512_broadcast_i64x4( wu_ldu( list1+i1 ) );
      wwu_t blinded = wwu_xor( addr, entropy );
      wwu_t masked0 = wwu_and( mask, wwu_shr_vector( blinded, shift0 ) );  wwu_t masked1 = wwu_and( mask, wwu_shr_vector( blinded, shift1 ) );
      wwu_t select0 = wwu_shl_vector( one, masked0 );                      wwu_t select1 = wwu_shl_vector( one, masked1 );
      wwu_t next0   = wwu_or( bloom0, select0 );                           wwu_t next1   = wwu_or( bloom1, select1 );
      __mmask8 any_differences = _kor_mask8(
          _mm512_cmp_epi64_mask( bloom0, next0, _MM_CMPINT_NE ),           _mm512_cmp_epi64_mask( bloom1, next1, _MM_CMPINT_NE ) );

      bloom0 = next0;                                                      bloom1 = next1;

      any_duplicates |= _kortestz_mask8_u8( any_differences, any_differences );
      FD_COMPILER_FORGET( any_duplicates );
    }
    return any_duplicates;
  }
}

#else

static inline int
fd_chkdup_check_fast( fd_chkdup_t          * chkdup,
                      fd_acct_addr_t const * list0,     ulong list0_cnt,
                      fd_acct_addr_t const * list1,     ulong list1_cnt ) {
  (void)chkdup;
  (void)list0;
  (void)list1;
  (void)list0_cnt;
  (void)list1_cnt;
  return 1;
}

#endif


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_pack_fd_chkdup_h */
