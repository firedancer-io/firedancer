#ifndef HEADER_fd_src_ballet_aes_fd_aes_h
#define HEADER_fd_src_ballet_aes_fd_aes_h

#include "fd_aes_private.h"

FD_PROTOTYPES_BEGIN

static inline void
fd_aes_encrypt_init_128( fd_aes_t *  aes,
                         uchar const key[ static 16 ] ) {
  fd_aes_encrypt_init_private( aes, key, 16UL );
}

static inline void
fd_aes_encrypt_init_192( fd_aes_t *  aes,
                         uchar const key[ static 24 ] ) {
  fd_aes_encrypt_init_private( aes, key, 24UL );
}

static inline void
fd_aes_encrypt_init_256( fd_aes_t *  aes,
                         uchar const key[ static 32 ] ) {
  fd_aes_encrypt_init_private( aes, key, 32UL );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_aes_fd_aes_h */
