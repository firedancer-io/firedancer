#ifndef HEADER_fd_src_ballet_chacha20_fd_chacha20rng_h
#define HEADER_fd_src_ballet_chacha20_fd_chacha20rng_h

/* fd_chacha20rng provides APIs for ChaCha20-based RNG, as used in the
   Solana protocol.  This API should only be used where necessary.
   fd_rng is a better choice in all other cases. */

#include "fd_chacha20.h"
#if !FD_HAS_INT128
#include "../../util/bits/fd_uwide.h"
#endif

/* FD_CHACHA20RNG_DEBUG controls debug logging.  0 is off; 1 is on. */

#ifndef FD_CHACHA20RNG_DEBUG
#define FD_CHACHA20RNG_DEBUG 0
#endif

/* Solana uses different mechanisms of mapping a ulong to an unbiased
   integer in [0, n) in different parts of the code.  In particular,
   leader schedule generation uses MODE_MOD and Turbine uses MODE_SHIFT.
   See the note in fd_chacha20rng_ulong_roll for more details. */
#define FD_CHACHA20RNG_MODE_MOD   1
#define FD_CHACHA20RNG_MODE_SHIFT 2

/* FD_CHACHA20RNG_BUFSZ is the internal buffer size of pre-generated
   ChaCha20 blocks.  Multiple of block size (64 bytes) and a power of 2. */

#define FD_CHACHA20RNG_BUFSZ (256UL)

struct __attribute__((aligned(64UL))) fd_chacha20rng_private {
  /* ChaCha20 encryption key */
  uchar key[ 32UL ] __attribute__((aligned(32UL)));

  /* Ring buffer of pre-generated ChaCha20 RNG data. */
  uchar buf[ FD_CHACHA20RNG_BUFSZ ] __attribute__((aligned(FD_CHACHA20_BLOCK_SZ)));
  uint  buf_off;   /* Total number of bytes consumed */
  uint  buf_fill;  /* Total number of bytes produced
                      Always aligned by FD_CHACHA20_BLOCK_SZ */

  int mode;

  /* ChaCha20 block index */
  uint idx;
};
typedef struct fd_chacha20rng_private fd_chacha20rng_t;

FD_PROTOTYPES_BEGIN

/* fd_chacha20rng_{align,footprint} give the needed alignment and
   footprint of a memory region suitable to hold a ChaCha20-based RNG.

   fd_chacha20rng_new formats a memory region with suitable alignment
   and footprint for holding a chacha20rng object.  Assumes shmem
   points on the caller to the first byte of the memory region owned by
   the caller to use.  `mode` must be one of the FD_CHACHA20RNG_MODE_*
   constants defined above and dictates what mode this object will use
   to generate random numbers. Returns shmem on success and NULL on
   failure (logs details).  The memory region will be owned by the
   object on successful return.  The caller is not joined on return.

   fd_chacha20rng_join joins the caller to a chacha20rng object.
   Assumes shrng points to the first byte of the memory region holding
   the object.  Returns a local handle to the join on success (this is
   not necessarily a simple cast of the address) and NULL on failure
   (logs details).

   fd_chacha20rng_leave leaves the caller's current local join to a
   ChaCha20 RNG object.  Returns a pointer to the memory region holding
   the object on success this is not necessarily a simple cast of the
   address) and NULL on failure (logs details).  The caller is not
   joined on successful return.

   fd_chacha20rng_delete unformats a memory region that holds a ChaCha20
   RNG object.  Assumes shrng points on the caller to the first byte of
   the memory region holding the state and that nobody is joined.
   Returns a pointer to the memory region on success and NULL on failure
   (logs details).  The caller has ownership of the memory region on
   successful return. */

FD_FN_CONST ulong
fd_chacha20rng_align( void );

FD_FN_CONST ulong
fd_chacha20rng_footprint( void );

void *
fd_chacha20rng_new( void * shmem, int mode );

fd_chacha20rng_t *
fd_chacha20rng_join( void * shrng );

void *
fd_chacha20rng_leave( fd_chacha20rng_t * );

void *
fd_chacha20rng_delete( void * shrng );

/* fd_chacha20rng_init starts a ChaCha20 RNG stream.  rng is assumed to
   be a current local join to a chacha20rng object with no other
   concurrent operation that would modify the state while this is
   executing.  seed points to the first byte of the RNG seed byte vector
   with 32 byte size.  Any preexisting state for an in-progress or
   recently completed calculation will be discarded.  Returns rng (on
   return, rng will have the state of a new in-progress calculation).

   Compatible with Rust fn rand_chacha::ChaCha20Rng::from_seed
   https://docs.rs/rand_chacha/latest/rand_chacha/struct.ChaCha20Rng.html#method.from_seed */

fd_chacha20rng_t *
fd_chacha20rng_init( fd_chacha20rng_t * rng,
                     void const *       key );

/* fd_chacha20rng_private_refill refills the buffer with random bytes.

   On return, guarantees fd_chacha20rng_avail( rng )>=FD_CHACHA20RNG_BLOCK_SZ */

void
fd_chacha20rng_private_refill( fd_chacha20rng_t * rng );

/* fd_chacha20rng_avail returns the number of buffered bytes. */

FD_FN_PURE static inline ulong
fd_chacha20rng_avail( fd_chacha20rng_t const * rng ) {
  return rng->buf_fill - rng->buf_off;
}

/* fd_chacha20rng_ulong reads a 64-bit integer in [0,2^64) from the RNG
   stream. */

static ulong
fd_chacha20rng_ulong( fd_chacha20rng_t * rng ) {
  if( FD_UNLIKELY( fd_chacha20rng_avail( rng ) < sizeof(ulong) ) )
    fd_chacha20rng_private_refill( rng );
  ulong x = FD_LOAD( ulong, rng->buf + (rng->buf_off % FD_CHACHA20RNG_BUFSZ) );
  rng->buf_off += 8U;
  return x;
}

/* fd_chacha20rng_ulong_roll returns an uniform IID rand in [0,n)
   analogous to fd_rng_ulong_roll.  Rejection method based using
   fd_chacha20rng_ulong.

   Compatible with Rust type
   <rand_chacha::ChaCha20Rng as rand::Rng>::gen<rand::distributions::Uniform<u64>>()
   as of version 0.7.0 of the crate
   https://docs.rs/rand/latest/rand/distributions/struct.Uniform.html */

static inline ulong
fd_chacha20rng_ulong_roll( fd_chacha20rng_t * rng,
                           ulong              n ) {
  /* We use a pretty standard rejection-sampling based approach here,
     but for future reference, here's an explanation:

     We know that v can take 2^64 values, and so any method that maps
     each of the 2^64 values to the range directly [0, n) will not be
     uniform distribution when 2^64 is not divisible by n.  This
     motivates using rejection sampling.

     The most basic approach is to map v from [0, n*floor(2^64/n) ) to
     [0, n) using v%n, but that puts a modulus on the critical path.  To
     avoid that, the Rust rand crate uses a different approach: compute
     v*n/2^64, which is also in [0, n).

     Now the question to answer is which values to throw out.  We pick a
     large integer k such that k*n<=2^64 and map [0, k*n) -> 0, [2^64,
     2^64+k*n) -> 1, etc.  Since k*n might be 2^64 and then not fit in a
     long, we define zone=k*n-1 <= ULONG_MAX, and make the intervals
     closed instead of half-open.

     Here's where the mode comes in.  Depending on what method you call
     and what datatype you use, the Rust crate uses different values of
     k.  When MODE_MOD is set, we use largest possible value of k,
     namely floor(2^64/n).  You can compute zone directly as follows:
               zone  = k*n-1
                     = floor(2^64/n)*n - 1
                     = 2^64 - (2^64%n) - 1
                     = 2^64-1 - (2^64-n)%n, since n<2^64
                     = 2^64-1 - ((2^64-1)-n+1)%n
     Which is back to having a mod... But at least if n is a
     compile-time constant than the whole zone computation becomes a
     compile-time constant.

     When MODE_SHIFT is set, we use uses almost the largest possible
     power of two for k.  Precisely, it uses the smallest power of two
     such that k*n >= 2^63, which is the largest power of two such that
     k*n<=2^64 unless n is a power of two.  This approach eliminates the
     mod calculation but increases the expected number of samples
     required. */
  ulong const zone = fd_ulong_if( rng->mode==FD_CHACHA20RNG_MODE_MOD,
                                  ULONG_MAX - (ULONG_MAX-n+1UL)%n,
                                  (n << (63 - fd_ulong_find_msb( n ) )) - 1UL );

  for( int i=0; 1; i++ ) {
    ulong   v   = fd_chacha20rng_ulong( rng );
#if FD_HAS_INT128
    /* Compiles to one mulx instruction */
    uint128 res = (uint128)v * (uint128)n;
    ulong   hi  = (ulong)(res>>64);
    ulong   lo  = (ulong) res;
#else
    ulong hi, lo;
    fd_uwide_mul( &hi, &lo, v, n );
#endif

#   if FD_CHACHA20RNG_DEBUG
    FD_LOG_DEBUG(( "roll (attempt %d): n=%016lx zone: %016lx v=%016lx lo=%016lx hi=%016lx", i, n, zone, v, lo, hi ));
#   else
    (void)i;
#   endif /* FD_CHACHA20RNG_DEBUG */

    if( FD_LIKELY( lo<=zone ) ) return hi;
  }
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_chacha20_fd_chacha20rng_h */
