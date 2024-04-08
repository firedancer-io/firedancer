#ifndef HEADER_fd_src_ballet_bn254_fd_poseidon_h
#define HEADER_fd_src_ballet_bn254_fd_poseidon_h

#include "../fd_ballet_base.h"

FD_PROTOTYPES_BEGIN

#define FD_POSEIDON_HASH_SIZE (32UL)

/* Hash result. Actually a value in the bn254 field */
struct fd_poseidon_hash_result {
  uchar v[ FD_POSEIDON_HASH_SIZE ];
};
typedef struct fd_poseidon_hash_result fd_poseidon_hash_result_t;

/* Hash a series of bytes. Generally speaking, the input should be a
   sequence of bn254 field values in 32 byte chunks.  If the input
   doesn't exactly conform, we zero-fill and modulo to make it
   work. Non-zero is returned on failure. */
int fd_poseidon_hash( const uchar * bytes, ulong bytes_len,
                      int big_endian, fd_poseidon_hash_result_t * result );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_bn254_fd_poseidon_h */
