#include "fd_keccak256.h"

ulong
fd_keccak256_align( void ) {
  return FD_KECCAK256_ALIGN;
}

ulong
fd_keccak256_footprint( void ) {
  return FD_KECCAK256_FOOTPRINT;
}

void *
fd_keccak256_new( void * shmem ) {
  fd_keccak256_t * sha = (fd_keccak256_t *)shmem;

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_keccak256_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = fd_keccak256_footprint();

  fd_memset( sha, 0, footprint );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( sha->magic ) = FD_KECCAK256_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)sha;
}

fd_keccak256_t *
fd_keccak256_join( void * shsha ) {

  if( FD_UNLIKELY( !shsha ) ) {
    FD_LOG_WARNING(( "NULL shsha" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shsha, fd_keccak256_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shsha" ));
    return NULL;
  }

  fd_keccak256_t * sha = (fd_keccak256_t *)shsha;

  if( FD_UNLIKELY( sha->magic!=FD_KECCAK256_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return sha;
}

void *
fd_keccak256_leave( fd_keccak256_t * sha ) {

  if( FD_UNLIKELY( !sha ) ) {
    FD_LOG_WARNING(( "NULL sha" ));
    return NULL;
  }

  return (void *)sha;
}

void *
fd_keccak256_delete( void * shsha ) {

  if( FD_UNLIKELY( !shsha ) ) {
    FD_LOG_WARNING(( "NULL shsha" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shsha, fd_keccak256_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shsha" ));
    return NULL;
  }

  fd_keccak256_t * sha = (fd_keccak256_t *)shsha;

  if( FD_UNLIKELY( sha->magic!=FD_KECCAK256_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( sha->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)sha;
}

/* The implementation below was derived from the original Keccak spec.
   See in particular:

   https://keccak.team/keccak_specs_summary.html

   It is straightforward to replace these implementations with HPC
   implementations that target specific machine capabilities without
   requiring any changes to caller code. */

static void
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

fd_keccak256_t *
fd_keccak256_init( fd_keccak256_t * sha ) {
  fd_memset( sha->state, 0, sizeof( sha->state ) );
  
  sha->padding_start = 0;

  return sha;
}

fd_keccak256_t *
fd_keccak256_append( fd_keccak256_t * sha,
                     void const *     _data,
                     ulong            sz ) {

  /* If no data to append, we are done */

  if( FD_UNLIKELY( !sz ) ) return sha; /* optimize for non-trivial append */

  /* Unpack inputs */

  ulong * state         = sha->state;
  uchar * state_bytes   = (uchar*) sha->state;
  ulong   padding_start = sha->padding_start;

  uchar const * data = (uchar const *)_data;

  ulong state_idx = padding_start;
  for( ulong i = 0; i < sz; i++ ) {
    state_bytes[state_idx] ^= data[i];
    state_idx++;
    if( state_idx >= FD_KECCAK256_RATE ) {
      fd_keccak256_core(state);
      state_idx = 0;
    }
  }

  sha->padding_start = state_idx;

  return sha;
}

void *
fd_keccak256_fini( fd_keccak256_t * sha,
                   void *           hash ) {

  /* Unpack inputs */

  ulong * state         = sha->state;
  uchar * state_bytes   = (uchar*) sha->state;
  ulong   padding_start = sha->padding_start;


  /* Append the terminating message byte */

  state_bytes[padding_start] ^= (uchar)0x01;
  state_bytes[FD_KECCAK256_RATE-1] ^= (uchar)0x80;
  fd_keccak256_core(state);

  /* Copy the result into hash */

  fd_memcpy(hash, state, FD_KECCAK256_OUT_SZ); 
  return hash;
}

void *
fd_keccak256_hash( void const * _data,
                ulong        sz,
                void *       _hash ) {
  fd_keccak256_t sha;
  fd_keccak256_init( &sha );
  fd_keccak256_append( &sha, _data, sz );
  fd_keccak256_fini( &sha, _hash );


  return _hash;
}

#undef fd_keccak256_core
