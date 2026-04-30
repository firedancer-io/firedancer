#ifndef HEADER_fd_src_ballet_keccak256_fd_keccak256_h
#define HEADER_fd_src_ballet_keccak256_fd_keccak256_h

/* fd_keccak256 provides APIs for Keccak256 hashing of messages. */

#include "../fd_ballet_base.h"

/* FD_KECCAK256_{ALIGN,FOOTPRINT} describe the alignment and footprint needed
   for a memory region to hold a fd_keccak256_t.  ALIGN is a positive
   integer power of 2.  FOOTPRINT is a multiple of align.  ALIGN is
   recommended to be at least double cache line to mitigate various
   kinds of false sharing.  These are provided to facilitate compile
   time declarations. */

#define FD_KECCAK256_ALIGN     (128UL)
#define FD_KECCAK256_FOOTPRINT (256UL)

/* FD_KECCAK256_HASH_SZ describe the size of a KECCAK256 hash in bytes. */

#define FD_KECCAK256_HASH_SZ    (32UL) /* == 2^FD_KECCAK256_LG_HASH_SZ, explicit to workaround compiler limitations */

/* A fd_keccak256_t should be treated as an opaque handle of a keccak256
   calculation state.  (It technically isn't here facilitate compile
   time declarations of fd_keccak256_t memory.) */

#define FD_KECCAK256_MAGIC (0xF17EDA2CE7EC2560) /* FIREDANCE KEC256 V0 */

#define FD_KECCAK256_STATE_SZ (25UL)
#define FD_KECCAK256_OUT_SZ (32UL)
#define FD_KECCAK256_RATE ((sizeof(ulong)*FD_KECCAK256_STATE_SZ) - (2*FD_KECCAK256_OUT_SZ))

struct __attribute__((aligned(FD_KECCAK256_ALIGN))) fd_keccak256_private {

  /* This point is 128-byte aligned */

  /* This point is 64-byte aligned */

  ulong state[ 25 ];

  /* This point is 32-byte aligned */

  ulong magic;    /* ==FD_KECCAK256_MAGIC */
  ulong padding_start; /* Number of buffered bytes, in [0,FD_KECCAK256_BUF_MAX) */

  /* Padding to 128-byte here */
};

typedef struct fd_keccak256_private fd_keccak256_t;

FD_PROTOTYPES_BEGIN

/* fd_keccak256_{align,footprint,new,join,leave,delete} usage is identical to
   that of fd_sha256.  See ../sha256/fd_sha256.h */

FD_FN_CONST ulong
fd_keccak256_align( void );

FD_FN_CONST ulong
fd_keccak256_footprint( void );

void *
fd_keccak256_new( void * shmem );

fd_keccak256_t *
fd_keccak256_join( void * shsha );

void *
fd_keccak256_leave( fd_keccak256_t * sha );

void *
fd_keccak256_delete( void * shsha );

/* fd_keccak256_init starts a keccak256 calculation.  sha is assumed to be a
   current local join to a keccak256 calculation state with no other
   concurrent operation that would modify the state while this is
   executing.  Any preexisting state for an in-progress or recently
   completed calculation will be discarded.  Returns sha (on return, sha
   will have the state of a new in-progress calculation). */

fd_keccak256_t *
fd_keccak256_init( fd_keccak256_t * sha );

/* fd_keccak256_append adds sz bytes locally pointed to by data an
   in-progress keccak256 calculation.  sha, data and sz are assumed to be
   valid (i.e. sha is a current local join to a keccak256 calculation state
   with no other concurrent operations that would modify the state while
   this is executing, data points to the first of the sz bytes and will
   be unmodified while this is running with no interest retained after
   return ... data==NULL is fine if sz==0).  Returns sha (on return, sha
   will have the updated state of the in-progress calculation).

   It does not matter how the user group data bytes for a keccak256
   calculation; the final hash will be identical.  It is preferable for
   performance to try to append as many bytes as possible as a time
   though.  It is also preferable for performance if sz is a multiple of
   64. */

fd_keccak256_t *
fd_keccak256_append( fd_keccak256_t * sha,
                     void const *     data,
                     ulong            sz );

/* fd_keccak256_fini finishes a a keccak256 calculation.  sha and hash are
   assumed to be valid (i.e. sha is a local join to a keccak256 calculation
   state that has an in-progress calculation with no other concurrent
   operations that would modify the state while this is executing and
   hash points to the first byte of a 32-byte memory region where the
   result of the calculation should be stored).  Returns hash (on
   return, there will be no calculation in-progress on sha and 32-byte
   buffer pointed to by hash will be populated with the calculation
   result). */

void *
fd_keccak256_fini( fd_keccak256_t * sha,
                   void *           hash );

/* fd_keccak256_hash is a convenience implementation of:

     fd_keccak256_t keccak[1];
     return fd_keccak256_fini( fd_keccak256_append( fd_keccak256_init( keccak ), data, sz ), hash )

  It may eventually be streamlined. */

void *
fd_keccak256_hash( void const * data,
                   ulong        sz,
                   void *       hash );

#if FD_HAS_AVX
/* fd_keccak256_avx2_keccak8_f1600 runs eight interleaved-limb Keccak-f[1600]
   permutations in one call (AVX2).  state must hold 200 ulongs:
   lane0 state[0..24], …, lane7 state[175..199].  rc is fd_keccak256_rc. */

void
fd_keccak256_avx2_keccak8_f1600( ulong state[ static 200 ], ulong const * rc );

/* Even/odd bit-interleaved variant: each 64-bit lane split as
   E = bits w[0,2,...,62], O = bits w[1,3,...,63].  Same external state layout
   (200 ulongs, lane-major); pack/unpack happens internally. */
void
fd_keccak256_avx2_keccak8_eo_f1600( ulong state[ static 200 ], ulong const * rc );

/* Raw permutation: state already in (E,O) SoA form (50 ymm = 1600 bytes,
   alpha=ae[0..24]+ao[0..24]).  rc_eo = 48 uint32 of pre-deinterleaved RCs
   (e0,o0,e1,o1,...).  Skips boundary bit-interleave so the round loop's
   actual cost is measurable, and supports keeping state packed across blocks. */
void
fd_keccak256_avx2_keccak8_eo_f1600_raw( void * state_eo, uint const * rc_eo );

/* Pre-deinterleave the 24 round constants once into 48 u32 (e,o pairs).
   rc_eo must point to 48 uint32 (32-byte aligned recommended). */
void
fd_keccak256_avx2_keccak8_eo_rc_pack( ulong const * rc, uint * rc_eo );

/* Absorb one Keccak-256 block (1088 bits = 17 u64) for each of 8 instances.
   blocks = 8 instances of 17 contiguous ulongs (lane-major). XORs deinterleaved
   bits into the rate of state_eo.  Pair with f1600_raw for full sponge step. */
void
fd_keccak256_avx2_keccak8_eo_absorb_block( void const * blocks, void * state_eo );

#endif /* FD_HAS_AVX */

#if FD_HAS_S2NBIGNUM
/* fd_s2n_sha3_keccak4_f1600 runs s2n-bignum's batched Keccak-f[1600] on four
   lanes in one call (SHA3 round constants).  state must hold 100 ulongs:
   lane0 state[0..24], lane1 [25..49], lane2 [50..74], lane3 [75..99]. */

void
fd_s2n_sha3_keccak4_f1600( ulong state[ static 100 ] );

#endif /* FD_HAS_S2NBIGNUM */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_keccak256_fd_keccak256_h */
