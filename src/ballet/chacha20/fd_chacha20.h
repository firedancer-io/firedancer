#ifndef HEADER_fd_src_ballet_chacha20_fd_chacha20_h
#define HEADER_fd_src_ballet_chacha20_fd_chacha20_h

#include "../fd_ballet_base.h"

/* FD_CHACHA20_BLOCK_SZ is the output size of the ChaCha20 block function. */

#define FD_CHACHA20_BLOCK_SZ (64UL)

/* FD_CHACHA20_KEY_SZ is the size of the ChaCha20 encryption key */

#define FD_CHACHA20_KEY_SZ (32UL)

FD_PROTOTYPES_BEGIN

/* fd_chacha20_block is the ChaCha20 block function.

   - block points to the output block (64 byte size, 32 byte align)
   - key points to the encryption key (32 byte size, 32 byte align)
   - idx_nonce points to the block index and block nonce
     (first byte is 32-bit index, rest is 96-bit nonce)
     (16 byte size, 16 byte align)

   FIXME this should probably do multiple blocks */

void *
fd_chacha20_block( void *       block,
                   void const * key,
                   void const * idx_nonce );

/* Encryption/decryption functions not implemented for now
   as they are not yet required. */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_chacha20_fd_chacha20_h */
