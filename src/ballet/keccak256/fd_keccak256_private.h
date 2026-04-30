#ifndef HEADER_fd_src_ballet_keccak256_fd_keccak256_private_h
#define HEADER_fd_src_ballet_keccak256_fd_keccak256_private_h

#include "../fd_ballet_base.h"

FD_PROTOTYPES_BEGIN

/* SHA3 Keccak-f[1600] round constants (shared by reference core, s2n-bignum,
   and optional fd_s2n_sha3_keccak4_f1600).  Defined in fd_keccak256.c. */
extern ulong const fd_keccak256_rc[24];

#if defined(FD_KECCAK256_USE_X86_64_LIMB_ASM) && defined(__x86_64__)
/* x86_64 BMI andn + BMI2 rorx permutation (fd_keccak256_x86_64_limb_f1600.S).
   LE u64 lanes match uint32 lo|hi limb layout.  Enable with
   FD_KECCAK256_X86_64_LIMB_ASM=1 on make (keccak256/Local.mk). */
void
fd_keccak256_x86_64_limb_f1600( ulong * state, ulong const * rc );

static inline void
fd_keccak256_core( ulong * state ) {
  fd_keccak256_x86_64_limb_f1600( state, fd_keccak256_rc );
}

#elif defined(FD_KECCAK256_USE_INTERLEAVED32)
/* u64 lanes as two uint32 limbs (LE), same model as plonky2-crypto Keccak; see
   fd_keccak256_interleaved.c.  Enable with FD_KECCAK256_INTERLEAVED32=1 on make
   (keccak256/Local.mk). */
#include "fd_keccak256_interleaved.c"
#elif FD_HAS_S2NBIGNUM
#include "fd_keccak256_s2n.c"
#else

/* The implementation below was derived from the original Keccak spec.
   See in particular:

   https://keccak.team/keccak_specs_summary.html

   It is straightforward to replace these implementations with HPC
   implementations that target specific machine capabilities without
   requiring any changes to caller code. */

static inline void
fd_keccak256_core( ulong * state ) {
  static uchar const rho_consts[24] = {
    1,  3,   6, 10,
    15, 21, 28, 36,
    45, 55,  2, 14,
    27, 41, 56,  8,
    25, 43, 62, 18,
    39, 61, 20, 44
  };

  static uchar const pi_consts[24] = {
    10,  7, 11, 17,
    18,  3,  5, 16,
     8, 21, 24,  4,
    15, 23, 19, 13,
    12,  2, 20, 14,
    22,  9,  6,  1
  };

# define NUM_ROUNDS (24)
# define ROTATE     fd_ulong_rotate_left

  ulong b[5];
  ulong t;

  for( ulong round = 0; round < NUM_ROUNDS; round++ ) {
    /* Theta step */
    for( ulong i = 0; i < 5; i++ ) {
      b[i] = (state[i] ^ state[i+5] ^ state[i+10] ^ state[i+15] ^ state[i+20]);
    }

    for( ulong i = 0; i < 5; i++ ) {
      t = b[(i+4) % 5] ^ ROTATE(b[(i+1) % 5], 1);

      for( ulong j = 0; j < 25; j += 5 ) {
        state[i+j] ^= t;
      }
    }

    /* Rho and pi steps */
    t = state[1];
    for( ulong i = 0; i < 24; i++ ) {
      ulong pi_val = pi_consts[i];
      int rho_val = rho_consts[i];
      b[0] = state[pi_val];
      state[pi_val] = ROTATE(t, rho_val);
      t = b[0];
    }

    /* Chi step */
    for( ulong i = 0; i < 25; i += 5 ) {
      for( ulong j = 0; j < 5; j++ ) {
        b[j] = state[i+j];
      }
      for( ulong j = 0; j < 5; j++ ) {
        state[i+j] ^= (~b[(j+1) % 5]) & (b[(j+2) % 5]);
      }
    }

    /* Iota step */
    state[0] ^= fd_keccak256_rc[round];
  }

# undef NUM_ROUNDS
# undef ROTATE
}

#endif /* interleaved32 / s2n / reference */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_keccak256_fd_keccak256_private_h */
