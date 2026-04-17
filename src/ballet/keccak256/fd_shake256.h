
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
  int   finalized;
} fd_shake256_t;

FD_PROTOTYPES_BEGIN

void
fd_shake256_init( fd_shake256_t * sha );

void
fd_shake256_absorb( fd_shake256_t * sha,
                    uchar const   * data,
                    ulong           len );

void
fd_shake256_squeeze( fd_shake256_t * sha,
                     uchar         * out,
                     ulong           len );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_keccak256_fd_shake256_h */
