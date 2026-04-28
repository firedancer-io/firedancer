
#ifndef HEADER_fd_src_ballet_keccak256_fd_shake256_h
#define HEADER_fd_src_ballet_keccak256_fd_shake256_h

#include "../fd_ballet_base.h"

#define FD_SHAKE256_RATE 136

typedef struct {
  union {
    ulong state[25];
    uchar bytes[200];
  };
  ulong offset;
} fd_shake256_t;

FD_PROTOTYPES_BEGIN

/* fd_shake256_init initializes a shake256 state.
   Any existing state in sha will be zeroed out. */
void
fd_shake256_init( fd_shake256_t * sha );

/* fd_shake256_absorb absorbs len bytes pointed to by data
   into the shake256 state.  May not be called after fd_shake256_fini. */
void
fd_shake256_absorb( fd_shake256_t * sha,
                    uchar const   * data,
                    ulong           len );

/* fd_shake256_fini finishes the absorb stage.  This must be called
   before fd_shake256_squeeze is called. */
void
fd_shake256_fini( fd_shake256_t * sha );

/* fd_shake256_squeeze extracts len bytes into out from the shake256
   state.  May only be called after fd_shake256_fini has been called.*/
void
fd_shake256_squeeze( fd_shake256_t * sha,
                     uchar         * out,
                     ulong           len );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_keccak256_fd_shake256_h */
