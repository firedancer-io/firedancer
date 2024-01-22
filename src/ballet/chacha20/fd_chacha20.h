#ifndef HEADER_fd_src_ballet_chacha20_fd_chacha20_h
#define HEADER_fd_src_ballet_chacha20_fd_chacha20_h

#include "../fd_ballet_base.h"

/* FD_CHACHA20_BLOCK_SZ is the output size of the ChaCha20 block function. */

#define FD_CHACHA20_BLOCK_SZ (64UL)

/* FD_CHACHA20_KEY_SZ is the size of the ChaCha20 encryption key */

#define FD_CHACHA20_KEY_SZ (32UL)

FD_PROTOTYPES_BEGIN

/* fd_chacha20_block is the ChaCha20 block function.

   - block points to the first byte of the output block of 64 bytes size
     and 64 bytes alignment
   - key points to the first byte of the encryption key of 32 bytes size
   - idx is the block index
   - nonce points to the first byte of the block nonce of 24 bytes size
     and 4 bytes alignment

   FIXME this should probably do multiple blocks */

void *
fd_chacha20_block( void *       block,
                   void const * key,
                   uint         idx,
                   void const * nonce );

/* Encryption/decryption functions not implemented for now
   as they are not yet required. */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_chacha20_fd_chacha20_h */
