#ifndef HEADER_fd_src_rng_fd_rng_h
#define HEADER_fd_src_rng_fd_rng_h

/* Simple fast high quality non-cryptographic pseudo random number
   generator.  Supports parallel generation, interprocess shared memory
   usage, checkpointing, random access, reversible, atomic, etc.  Passes
   extremely strict tests of randomness.
   
   Assumes fd_bits provides a high quality 64<>64-bit integer hash
   functions (i.e. full avalanche) with the property
   fd_ulong_hash(0)==0, fd_ulong_hash(i) for i in [0,2^64) yields a
   permutation of [0,2^64) and also provides reasonably efficient
   inverse of this. */

#include "../bits/fd_bits.h"

/* FD_RNG_{ALIGN,FOOTPRINT} describe the alignment and footprint needed
   for a rng.  ALIGN should be a positive integer power of 2.  FOOTPRINT
   is multiple of ALIGN.  These are provided to facilitate compile time
   declarations.  */

#define FD_RNG_ALIGN     (16UL)
#define FD_RNG_FOOTPRINT (16UL)

/* fd_rng_t should be treated as an opaque handle of a pseudo random
   number generator.  (It technically isn't here to facilitate inlining
   of fd_rng operations.) */

struct __attribute__((aligned(FD_RNG_ALIGN))) fd_rng_private {
  ulong seq;
  ulong idx;
};

typedef struct fd_rng_private fd_rng_t;

FD_PROTOTYPES_BEGIN

/* Private: fd_rng_private_expand(seq) randomly expands an arbitrary
   32-bit value into a unique 64-bit non-sparse value such that the
   original 32-bit value can be recovered and that 0 expands to
   something non-zero (the non-sparse expansion helps reduce
   correlations between different sequences, the zero to non-zero
   expansion means the common initialization of seq=0, idx=0 doesn't
   yield 0 for the first random value as would happen for hash functions
   that have the property fd_ulong_hash(0)==0, the XOR 64-bit const here
   is zero in the lower 32-bits and an arbitrary non-zero in the upper
   32-bits).  For the current fd_ulong_hash implementation and XOR
   64-bit constant, the pop count of the expanded seq is ~32.000 +/-
   ~4.000 and in [8,56] for all possible values of seq (i.e. the
   expanded seq popcount is well approximated as a normal with mean 32
   and rms 4 and the extremes are in line with the expected extremes for
   2^32 samples). */

FD_FN_CONST static inline ulong
fd_rng_private_expand( uint seq ) {
  return fd_ulong_hash( 0x900df00d00000000UL ^ (ulong)seq );
}

/* Private: fd_rng_private_contract(seq) extract the original 32-bit seq
   from its expanded value */

FD_FN_CONST static inline uint
fd_rng_private_contract( ulong eseq ) {
  return (uint)fd_ulong_hash_inverse( eseq );
}

/* fd_rng_{align,footprint} give the needed alignment and footprint
   for a memory region suitable to hold a fd_rng's state.  Declaration /
   aligned_alloc / fd_alloca friendly (e.g. a memory region declared as
   "fd_rng_t _rng[1];", or created by
   "aligned_alloc(alignof(fd_rng_t),sizeof(fd_rng_t))" or created by
   "fd_alloca(alignof(fd_rng_t),sizeof(fd_rng_t))" will all
   automatically have the needed alignment and footprint).
   fd_rng_{align,footprint} return the same value as
   FD_RNG_{ALIGN,FOOTPRINT}.

   fd_rng_new takes ownership of the memory region pointed to by mem
   (which is assumed to be non-NULL with the appropriate alignment and
   footprint) and formats it as a fd_rng.  The random number generator
   stream will initialized to use pseudo random sequence "seq" and will
   start at slot "idx".  Returns mem (which will be formatted for use).
   The caller will not be joined to the region on return.

   fd_rng_join joins the caller to a memory region holding the state of
   a fd_rng.  _rng points to a memory region in the local address space
   that holds a fd_rng.  Returns an opaque handle of the local join in
   the local address space to the fd_rng (which might not be the same
   thing as _rng ... the separation of new and join is to facilitate
   interprocess shared memory usage patterns while supporting
   transparent upgrades users of this to more elaborate algorithms where
   address translations under the hood may not be trivial).

   fd_rng_leave leaves the current rng join.  Returns a pointer in the
   local address space to the memory region holding the state of the
   fd_rng.  The join should not be used afterward.

   fd_rng_delete unformats the memory region currently used to hold the
   state of a _rng and returns ownership of the underlying memory region
   to the caller.  There should be no joins in the system on the fd_rng.
   Returns a pointer to the underlying memory region. */

FD_FN_CONST static inline ulong fd_rng_align    ( void ) { return alignof( fd_rng_t ); }
FD_FN_CONST static inline ulong fd_rng_footprint( void ) { return sizeof ( fd_rng_t ); }

static inline void *
fd_rng_new( void * mem,
            uint   seq,
            ulong  idx ) {
  fd_rng_t * rng = (fd_rng_t *)mem;
  rng->seq = fd_rng_private_expand( seq );
  rng->idx = idx;
  return (void *)rng;
}

static inline fd_rng_t * fd_rng_join  ( void     * _rng ) { return (fd_rng_t *)_rng; }
static inline void     * fd_rng_leave ( fd_rng_t *  rng ) { return (void     *) rng; }
static inline void     * fd_rng_delete( void     * _rng ) { return (void     *)_rng; }

/* fd_rng_seq returns the sequence used by the rng.  fd_rng_idx returns
   the next slot that will be consumed by the rng. */

static inline uint  fd_rng_seq( fd_rng_t * rng ) { return fd_rng_private_contract( rng->seq ); }
static inline ulong fd_rng_idx( fd_rng_t * rng ) { return rng->idx;                            }

/* fd_rng_seq_set sets the sequence to be used by rng and returns
   the replaced value.  fd_rng_idx_set sets the next slot that will be
   consumed next by rng and returns the replaced value. */

static inline uint
fd_rng_seq_set( fd_rng_t * rng,
                uint       seq ) {
  uint old = fd_rng_seq( rng );
  rng->seq = fd_rng_private_expand( seq );
  return old;
}

static inline ulong
fd_rng_idx_set( fd_rng_t * rng,
                ulong      idx ) {
  ulong old = fd_rng_idx( rng );
  rng->idx = idx;
  return old;
}

/* fd_rng_{uchar,ushort,uint,ulong} returns the next integer in the PRNG
   sequence in [0,2^N) for N in {8,16,32,64} respectively with uniform
   probability with a period of 2^64 (fd_rng_ulong has a period of 2^63
   as it consumes two slots).  Passes various strict PRNG tests (e.g.
   diehard, dieharder, testu01, etc).  Assumes rng is a current join.
   fd_rng_{schar,short,int,long} are the same but return a value in
   [0,2^(N-1)).  (A signed generator that can assume all possible values
   of a signed int uniform IID can be obtained by casting the output of
   the unsigned generator of the same, assuming a typical twos
   complement arithmetic platform.)
   
   The theory for this that fd_ulong_hash(i) for i in [0,2^64) specifies
   a random looking permutation of the integers in [0,2^64).  Returning
   the low order bits of this random permutation then yields a high
   quality non-cryptographic random number stream automatically as it:

   - Has a long period (2^64).  This is implied by the permutation
     property.

   - Has the expected random properties (as theoretically best possible
     for a finite period generator) of a true uniform IID bit source.
     For example, the probability of next random number is uniform and
     independent of previous N random numbers for N<<2^64).  This is
     also implied by the full avalanche and permutation property.

   - Is "unpredictable".  That is, the internal state of the generator
     is difficult to recover from its outputs, e.g. a return from
     fd_rng_uint could be have been generated from 2^32 internal states
     (if the sequence is known), up to 2^32 sequences (if the state is
     known) and up to 2^64 (state,seq) pairs neither is known (the state
     / sequence is potentially recoverable given a long enough stream of
     values though).  This is implied by the truncation of hash values.

   To turn this into parameterizable family of generators, note that
   fd_ulong_hash( perm_j( i ) ) where j is some parameterized family of
   random permutations is still a permutation and would have all the
   above properties for free so long as no perm_j is similar to the hash
   permutation inverse.  Practically, xoring i by a non-sparse 64-bit
   number will ultra cheaply generate a wide family of "good enough"
   permutations to do a parameterized shuffling of the original
   fd_ulong_hash permutation, creating a large number of parallel
   sequences.  Since users are empirically notoriously bad at seeding
   though, we only let the user specify a 32-bit sequence id and then
   generate a unique non-sparse 64-bit random looking seed from it. */

static inline uchar  fd_rng_uchar ( fd_rng_t * rng ) { return (uchar )fd_ulong_hash( rng->seq ^ (rng->idx++) ); }
static inline ushort fd_rng_ushort( fd_rng_t * rng ) { return (ushort)fd_ulong_hash( rng->seq ^ (rng->idx++) ); }
static inline uint   fd_rng_uint  ( fd_rng_t * rng ) { return (uint  )fd_ulong_hash( rng->seq ^ (rng->idx++) ); }

FD_FN_UNUSED static ulong /* Work around -Winline */
fd_rng_ulong( fd_rng_t * rng ) {
  ulong hi = (ulong)fd_rng_uint( rng );
  return (hi<<32) | (ulong)fd_rng_uint( rng );
}

static inline schar fd_rng_schar( fd_rng_t * rng ) { return (schar)( fd_rng_uchar ( rng ) >> 1 ); }
static inline short fd_rng_short( fd_rng_t * rng ) { return (short)( fd_rng_ushort( rng ) >> 1 ); }
static inline int   fd_rng_int  ( fd_rng_t * rng ) { return (int  )( fd_rng_uint  ( rng ) >> 1 ); }
static inline long  fd_rng_long ( fd_rng_t * rng ) { return (long )( fd_rng_ulong ( rng ) >> 1 ); }

#if FD_HAS_INT128
FD_FN_UNUSED static uint128 /* Work around -Winline */
fd_rng_uint128( fd_rng_t * rng ) {
  return (((uint128)fd_rng_ulong( rng ))<<64) | ((uint128)fd_rng_ulong( rng ));
}

/* FIXME: MIGHT BE BETTER TO MASK OR (hi<<63) ^ lo */
static inline int128 fd_rng_int128( fd_rng_t * rng ) { return (int128)( fd_rng_uint128( rng ) >> 1 ); }
#endif

/* fd_rng_{uint_to_float,ulong_to_double}_{c0,c1,c,o}( u ):  These
   quickly and robustly convert uniform random integers into uniform
   random floating point with appropriate rounding.  Intervals are:

     c0 -> [0,1)
     c1 -> (0,1]
     c  -> [0,1]
     o  -> (0,1)

   To provide more specifics, let the real numbers from [0,1) be
   partitioned into N uniform disjoint intervals such that interval i
   goes from [i/N,(i+1)/N) where i is in [0,N).  For single (double)
   precision, "float" ("double"), the largest N for which the range of
   each interval is _exactly_ representable is N = 2^24 (2^53).

   Given then a uniform IID uint random input, the
   fd_rng_uint_to_float_c0 converter output is as though a continuous
   IID uniform random in [0,1) was generated and then rounded down to
   the start of the containing interval (2^24 intervals).  As such, this
   generator can never return exactly 1 but it can exactly return +0.
   Since floats have higher resolution near 0 than 1, this will not
   return all float possible representations in [0,1) but it can return
   all possible float representations in [1/2,1).  In particular, this
   will never return a denorm or -0.

   Similarly for fd_rng_uint_to_float_c1 converter rounds up to the end
   of the containing interval / start of the next interval (2^24
   intervals).  As such, this converter can never return exactly +0 but
   it can exactly return 1.  It will not return all possible float
   representations in (0,1] but it can return all possible float
   representations in [1/2,1].  This will never return a denorm or -0.

   The fd_rng_uint_to_float_c converter rounds toward nearest even
   toward the start containing interval or start of the next interval
   (2^24 intervals).  As such, this can return both exactly +0 and
   exactly 1 (and the probability of returning exactly +0 == probability
   of exactly 1 == (1/2) probability all other possible return values).
   It will not return all possible float representations in [0,1] but it
   can return all float possible representations in [1/2,1].  This will
   never return a denorm or -0.

   The fd_rng_uint_to_float_o converter rounds toward the middle of
   containing internal (2^23 intervals ... note that then in a sense
   this converter is 1-bit less accurate than the above).  As such, this
   can neither return +0 nor 1 and will not return all possible float
   representations in (0,1).  This will never return a denorm or -0.

   Similarly for the double variants (*_{c0,c1,c} uses 2^53 intervals
   and o uses 2^52 intervals). */

FD_FN_CONST static inline float  fd_rng_uint_to_float_c0  ( uint  u ) { return (1.f/(float )(1 <<24))*(float )(int )( u>>(32-24)         ); }
FD_FN_CONST static inline float  fd_rng_uint_to_float_c1  ( uint  u ) { return (1.f/(float )(1 <<24))*(float )(int )((u>>(32-24))+   1U  ); }
FD_FN_CONST static inline float  fd_rng_uint_to_float_c   ( uint  u ) { return (1.f/(float )(1 <<24))*(float )(int )((u>>(32-24))+(u&1U )); }
FD_FN_CONST static inline float  fd_rng_uint_to_float_o   ( uint  u ) { return (1.f/(float )(1 <<24))*(float )(int )((u>>(32-24))|   1U  ); }

#if FD_HAS_DOUBLE
FD_FN_CONST static inline double fd_rng_ulong_to_double_c0( ulong u ) { return (1. /(double)(1L<<53))*(double)(long)( u>>(64-53)         ); }
FD_FN_CONST static inline double fd_rng_ulong_to_double_c1( ulong u ) { return (1. /(double)(1L<<53))*(double)(long)((u>>(64-53))+   1UL ); }
FD_FN_CONST static inline double fd_rng_ulong_to_double_c ( ulong u ) { return (1. /(double)(1L<<53))*(double)(long)((u>>(64-53))+(u&1UL)); }
FD_FN_CONST static inline double fd_rng_ulong_to_double_o ( ulong u ) { return (1. /(double)(1L<<53))*(double)(long)((u>>(64-53))|   1UL ); }
#endif

/* fd_rng_{float,double}_{c0,c1,c,o} are basic uniform generators on the
   appropriate interval of 0 to 1 based on the above converters.  The
   float variant consumes 1 slot, the double variant consumes 2 slots. */

static inline float  fd_rng_float_c0 ( fd_rng_t * rng ) { return fd_rng_uint_to_float_c0  ( fd_rng_uint ( rng ) ); }
static inline float  fd_rng_float_c1 ( fd_rng_t * rng ) { return fd_rng_uint_to_float_c1  ( fd_rng_uint ( rng ) ); }
static inline float  fd_rng_float_c  ( fd_rng_t * rng ) { return fd_rng_uint_to_float_c   ( fd_rng_uint ( rng ) ); }
static inline float  fd_rng_float_o  ( fd_rng_t * rng ) { return fd_rng_uint_to_float_o   ( fd_rng_uint ( rng ) ); }

#if FD_HAS_DOUBLE
static inline double fd_rng_double_c0( fd_rng_t * rng ) { return fd_rng_ulong_to_double_c0( fd_rng_ulong( rng ) ); }
static inline double fd_rng_double_c1( fd_rng_t * rng ) { return fd_rng_ulong_to_double_c1( fd_rng_ulong( rng ) ); }
static inline double fd_rng_double_c ( fd_rng_t * rng ) { return fd_rng_ulong_to_double_c ( fd_rng_ulong( rng ) ); }
static inline double fd_rng_double_o ( fd_rng_t * rng ) { return fd_rng_ulong_to_double_o ( fd_rng_ulong( rng ) ); }
#endif

/* fd_rng_int_roll uses the given rng to roll an n-sided die where n is
   the number of sides (assumed to be positive).  That is returns
   uniform IID rand in [0,n) even if n is not an exact power of two.
   Similarly for the other types.

   Rejection method based.  Specifically, the number of rng slots
   consumed is typically 1 but theoretically might be higher
   occasionally (64-bit wide types consume rng slots twice as fast).

   Deterministic_rng slot consumption possible with a slightly more
   approximate implementation (bound the number of iterations such that
   this always consumes a fixed number of slot and accept the
   practically infinitesimal bias when n is not a power of 2). */

static inline uint
fd_rng_private_roll32( fd_rng_t * rng,
                       uint       n ) {
  uint r = (-n) % n; /* Compute 2^32 mod n = (2^32 - n) mod n = (-n) mod n, compile time for compile time n */
  uint u; do u = fd_rng_uint( rng ); while( FD_UNLIKELY( u<r ) ); /* Rejection unlikely (highly unlikely for n<<<2^32) */
  /* At this point, u is uniform in [r,2^32) which has an integer
     multiple of n elements (thus u % n is in [0,n) uniform) */
  return u % n;
}

static inline ulong
fd_rng_private_roll64( fd_rng_t * rng,
                       ulong      n ) {
  ulong r = (-n) % n; /* Compute 2^64 mod n = (2^64 - n) mod n = (-n) mod n, compile time for compile time n */
  ulong u; do u = fd_rng_ulong( rng ); while( FD_UNLIKELY( u<r ) ); /* Rejection unlikely (highly unlikely for n<<<2^64) */
  /* At this point, u is uniform in [r,2^64) which has an integer
     multiple of n elements (thus u % n is in [0,n) uniform) */
  return u % n;
}

static inline uchar  fd_rng_uchar_roll ( fd_rng_t * rng, uchar  n ) { return (uchar )fd_rng_private_roll32( rng, (uint )n ); }
static inline ushort fd_rng_ushort_roll( fd_rng_t * rng, ushort n ) { return (ushort)fd_rng_private_roll32( rng, (uint )n ); }
static inline uint   fd_rng_uint_roll  ( fd_rng_t * rng, uint   n ) { return (uint  )fd_rng_private_roll32( rng, (uint )n ); }
static inline ulong  fd_rng_ulong_roll ( fd_rng_t * rng, ulong  n ) { return (ulong )fd_rng_private_roll64( rng, (ulong)n ); }

static inline schar  fd_rng_schar_roll ( fd_rng_t * rng, schar  n ) { return (schar )fd_rng_private_roll32( rng, (uint )n ); }
static inline short  fd_rng_short_roll ( fd_rng_t * rng, short  n ) { return (short )fd_rng_private_roll32( rng, (uint )n ); }
static inline int    fd_rng_int_roll   ( fd_rng_t * rng, int    n ) { return (int   )fd_rng_private_roll32( rng, (uint )n ); }
static inline long   fd_rng_long_roll  ( fd_rng_t * rng, long   n ) { return (long  )fd_rng_private_roll64( rng, (ulong)n ); }

/* fd_rng_coin_tosses tosses a fair coin until it comes up tails and
   returns the number of tosses taken (including the final toss that
   came up tails).  That is, the PDF of coin tosses is:

     Pr(cnt) = 2^-cnt, cnt>0
               0,      otherwise

   Typically consumes 1 slot but can consume more with exceedingly low
   probability (~2^-32).  Deterministic slot consumption is possible by
   truncating the maximum number of tosses.  Practically a fast O(1). */

FD_FN_UNUSED static ulong /* Work around -Winline */
fd_rng_coin_tosses( fd_rng_t * rng ) {
  ulong cnt = 1UL;
  ulong u;
  for(;;) {
    u = (ulong)fd_rng_uint( rng );
    if( FD_LIKELY( u ) ) break;
    cnt += 32UL;
  }
  cnt += (ulong)fd_ulong_find_lsb( u );
  return cnt;
}

/* fd_rng_float_robust generates a uniform random number in [0,1) and
   rounds this infinite precision result to the closest exactly
   representable float in [0,1].  As such, this can theoretically
   generate any exactly representable floating point number in [0,1],
   including 0 (with an exceedingly small probability), denorms (also
   with an exceedingly small probability) and exact 1 (with a
   probability of ~2^-25).  This will never produce a value larger than
   1, a negative value or -0.  This is slower than the above uniform
   floating point generators above but still a reasonably fast O(1).
   Typically consumes 2 slots but can consume more with exceedingly low
   probability.

   Similarly for the double precision variant.  Typically consumes 3
   slots.  Reasonably fast O(1).

   fd_rng_float_exp generates a random number with an exponential
   distribution.

   PDF:
     f(x) ~ exp(-x), x>=0
            0,       otherwise
   CDF:
     F(x) ~ 1-exp(-x), x>=0
            0,         otherwise

   Based on transformation method applied to a 63-bit uniform rand.  As
   such, some quantization due to the floating point limitations and
   generator precision is present around zero and in the extreme tails
   but these rarely affect typical use cases (variants that can generate
   every non-negative float possible are possible in principle but these
   are more expensive under the hood).  Extreme values are:

     output                      | prob
     0        ~ -ln( 1         ) | ~2^-25 (limited by floating rep)
     ~5.96e-8 ~ -ln( 1-  2^-24 ) | ~2^-24 (limited by floating rep)
     ~1.19e-7 ~ -ln( 1-2*2^-24 ) | ~2^-24 (limited by floating rep)
     ...
     ~42.975  ~ -ln(   2*2^-63 ) | ~2^-63 (limited by generator)
     ~43.668  ~ -ln(     2^-63 ) | ~2^-63 (limited by generator)

   The current implementation will only generate bit level identical
   results between machine targets that have a libm with correctly
   rounded exp and log functions.  It is possible to do this reasonably
   fast without use of libm if necessary though.  Consumes 2 slots.
   Reasonably fast O(1).

   For the double precision generator, similar considerations apply:

     output                       | prob
     0         ~ -ln( 1         ) | ~2^-54 (limited by floating rep)
     ~1.11e-16 ~ -ln( 1-  2^-53 ) | ~2^-53 (limited by floating rep)
     ~2.22e-16 ~ -ln( 1-2*2^-53 ) | ~2^-53 (limited by floating rep)
     ...
     ~42.975   ~ -ln(   2*2^-63 ) | ~2^-63 (limited by generator)
     ~43.668   ~ -ln(     2^-63 ) | ~2^-63 (limited by generator)

   Consumes 2 slots.  Reasonably fast O(1).

   fd_rng_float_norm generates a random number with a normal
   distribution.

   PDF:
     f(x) ~ exp(-x^2/2) / sqrt(2 pi)

   Based on the Ziggurat method.  User should assume any finite value is
   possible (including denorms and -0 though note that denorms will
   likely be flushed to zero if the processor is configured to do so for
   performance, as is typical and that values larger in magnitude than
   sqrt( 2 log N ) where N is the number of invocations of this will be
   exceedingly rare).  Typically consumes 1 slot but can consume more
   with moderately low probability.  Reasonably fast O(1).
   Deterministic slot consumption can be obtained by using the
   Box-Muller method (will consume more slots on average though).

   Similarly for the double precision variant.  Typically consumes 2
   slots.  Reasonably fast O(1). */

float fd_rng_float_robust( fd_rng_t * rng );
float fd_rng_float_exp   ( fd_rng_t * rng );
float fd_rng_float_norm  ( fd_rng_t * rng );

#if FD_HAS_DOUBLE
double fd_rng_double_robust( fd_rng_t * rng );
double fd_rng_double_exp   ( fd_rng_t * rng );
double fd_rng_double_norm  ( fd_rng_t * rng );
#endif

/* FIXME: IMPORT ATOMIC VARIANTS FOR REENTRANT USAGE (E.G. ATOMIC_XCHG
   FOR SET, ATOMIC_INC OF INDEX FOR THE RETURN TYPES, CAS STATE UPDATES,
   ETC) */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_rng_fd_rng_h */
