#ifndef HEADER_fd_src_ballet_lthash2_fd_lthash2_h
#define HEADER_fd_src_ballet_lthash2_fd_lthash2_h

/* fd_lthash2: lattice-based incremental hash built on Keccak-p[1600,12].
 *
 * Same lattice add/sub semantics as fd_lthash (1024 16-bit elements,
 * group operation in (Z/65536)^1024) but the hash function is Keccak
 * instead of Blake3.  Output bytes are NOT compatible with fd_lthash;
 * fd_lthash2 is a separate construction.
 *
 * Hash construction:
 *   state    = Keccak-256-style absorb of input (rate 136 B, padding 0x07/0x80)
 *   for ctr in 0..15:
 *     state_ctr = state with ctr XORed into capacity lane 17
 *     state_ctr = Keccak-p[1600,12]( state_ctr )       (12-round permutation)
 *     out[ctr*136 : ctr*136 + 136] = lanes 0..16 of state_ctr (as bytes)
 *   truncate out to 2048 bytes
 *
 * The 16 squeeze permutations are independent (counter mode), so they
 * map naturally onto AVX-512 keccak8 as 2 batches of 8.
 *
 * Two entry points:
 *   fd_lthash2_compute     : 1 lthash, lane=counter (variant b)
 *   fd_lthash2_batch8      : up to 8 lthashes in parallel, lane=account
 *                            (variant a, best amortized cost)
 */

#include "../fd_ballet_base.h"

#define FD_LTHASH2_ALIGN       (64UL)
#define FD_LTHASH2_LEN_BYTES (2048UL)
#define FD_LTHASH2_LEN_ELEMS (1024UL)

union __attribute__((aligned(FD_LTHASH2_ALIGN))) fd_lthash2_value {
  uchar  bytes[FD_LTHASH2_LEN_BYTES];
  ushort words[FD_LTHASH2_LEN_ELEMS];
};
typedef union fd_lthash2_value fd_lthash2_value_t;

FD_PROTOTYPES_BEGIN

/* Compute one lthash2 from input data. */
void
fd_lthash2_compute( void const *         input,
                    ulong                input_sz,
                    fd_lthash2_value_t * out );

#if FD_HAS_AVX512

/* Compute `n` (1..8) lthash2 values in parallel, lane=account.  Lanes
   >= n are masked off (no output written, no wasted absorb). */
void
fd_lthash2_batch8( void const *               inputs[8],
                   uint const                 sizes[8],
                   fd_lthash2_value_t * const outputs[8],
                   ulong                      n );

#endif

/* Group operations: same semantics as fd_lthash (16-bit element add/sub
   in (Z/65536)^1024). */

static inline fd_lthash2_value_t *
fd_lthash2_zero( fd_lthash2_value_t * r ) {
  return fd_memset( r->bytes, 0, FD_LTHASH2_LEN_BYTES );
}

static inline int
fd_lthash2_eq( fd_lthash2_value_t const * a, fd_lthash2_value_t const * b ) {
  return fd_memeq( a->bytes, b->bytes, FD_LTHASH2_LEN_BYTES );
}

static inline fd_lthash2_value_t *
fd_lthash2_add( fd_lthash2_value_t * restrict       r,
                fd_lthash2_value_t const * restrict a ) {
  for( ulong i=0; i<FD_LTHASH2_LEN_ELEMS; i++ ) {
    r->words[i] = (ushort)( r->words[i] + a->words[i] );
  }
  return r;
}

static inline fd_lthash2_value_t *
fd_lthash2_sub( fd_lthash2_value_t * restrict       r,
                fd_lthash2_value_t const * restrict a ) {
  for( ulong i=0; i<FD_LTHASH2_LEN_ELEMS; i++ ) {
    r->words[i] = (ushort)( r->words[i] - a->words[i] );
  }
  return r;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_lthash2_fd_lthash2_h */
