#ifndef HEADER_fd_src_ballet_keccak256_fd_keccak256_private_h
#define HEADER_fd_src_ballet_keccak256_fd_keccak256_private_h

#include "../fd_ballet_base.h"

FD_PROTOTYPES_BEGIN

/* The implementation below was derived from the original Keccak spec.
   See in particular:

   https://keccak.team/keccak_specs_summary.html

   It is straightforward to replace these implementations with HPC
   implementations that target specific machine capabilities without
   requiring any changes to caller code. */

static inline void
fd_keccak256_core( ulong * state ) {
 ulong const round_consts[24] = {
    0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808AUL, 0x8000000080008000UL,
    0x000000000000808BUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008AUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000AUL,
    0x000000008000808BUL, 0x800000000000008BUL, 0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800AUL, 0x800000008000000AUL,
    0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
  };

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
    // Theta step
    for( ulong i = 0; i < 5; i++ ) {
      b[i] = (state[i] ^ state[i+5] ^ state[i+10] ^ state[i+15] ^ state[i+20]);
    }

    for( ulong i = 0; i < 5; i++ ) {
      t = b[(i+4) % 5] ^ ROTATE(b[(i+1) % 5], 1);

      for( ulong j = 0; j < 25; j += 5 ) {
        state[i+j] ^= t;
      }
    }

    // Rho and pi steps
    t = state[1];
    for( ulong i = 0; i < 24; i++ ) {
      ulong pi_val = pi_consts[i];
      int rho_val = rho_consts[i];
      b[0] = state[pi_val];
      state[pi_val] = ROTATE(t, rho_val);
      t = b[0];
    }

    // Chi step
    for( ulong i = 0; i < 25; i += 5 ) {
      for( ulong j = 0; j < 5; j++ ) {
        b[j] = state[i+j];
      }
      for( ulong j = 0; j < 5; j++ ) {
        state[i+j] ^= (~b[(j+1) % 5]) & (b[(j+2) % 5]);
      }
    }

    // Iota step
    state[0] ^= round_consts[round];
  }

# undef NUM_ROUNDS
# undef ROTATE
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_keccak256_fd_keccak256_private_h */
