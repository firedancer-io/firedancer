#ifndef HEADER_fd_src_ballet_chacha20_fd_chacha20_h
#define HEADER_fd_src_ballet_chacha20_fd_chacha20_h

#include "../fd_ballet_base.h"

typedef uint32_t fd_chacha20_rng_t;

#define FD_CHACHA20_KEY_SIZE 32 // 32 bytes, 256 bits

/*
  This method generates a cryptographically secure random number.
  It expects a key (32 bytes) param, as well as a buffer
  to store the generated number, passed as 'random_number' param (fd_chacha20_rng_t)
*/
int fd_chacha20_generate_random_number(const uchar *key, fd_chacha20_rng_t *random_number);

/*
  This method implements a FFI that generates a cryptographically secure random number using the target rust crate.
  it also expects a key (32 bytes) param, as well as a buffer to store the generated number, passed as 'random_number' param (fd_chacha20_rng_t)
*/
void fd_chacha20_ffi_random_number(const uchar *key, fd_chacha20_rng_t *random_number);

#endif /* HEADER_fd_src_ballet_chacha20_fd_chacha20_h */