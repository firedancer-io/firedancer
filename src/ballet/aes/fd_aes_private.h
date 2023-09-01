#ifndef HEADER_fd_src_ballet_aes_fd_aes_private_h
#define HEADER_fd_src_ballet_aes_fd_aes_private_h

#include "../fd_ballet_base.h"

/* fd_aes_key_t is an expanded AES key. */

struct fd_aes_key {
  uint rd_key[ 60 ];
  int  rounds;
};

typedef struct fd_aes_key fd_aes_key_t;

struct fd_aes {
  int x;
};

typedef struct fd_aes fd_aes_t;

FD_PROTOTYPES_BEGIN

void
fd_aes_encrypt_init_private( fd_aes_t *    aes,
                             uchar const * key,
                             ulong         key_len );

/* AES key: Reference implementation **********************************/

int
fd_aes_ref_set_encrypt_key( uchar const *  user_key,
                            ulong          bits,
                            fd_aes_key_t * key );

int
fd_aes_ref_set_decrypt_key( uchar const *  user_key,
                            ulong          bits,
                            fd_aes_key_t * key );

void
fd_aes_ref_encrypt_core( uchar const *        in,
                         uchar *              out,
                         fd_aes_key_t const * key );

void
fd_aes_ref_decrypt_core( uchar const *        in,
                         uchar *              out,
                         fd_aes_key_t const * key );

/* AES key: x86_64 AES-NI (128-bit) and AVX (256-bit) accelerated *****/

#if FD_HAS_AESNI

__attribute__((sysv_abi))
void
fd_aesni_set_encrypt_key( uchar const *  user_key,
                          ulong          bits,
                          fd_aes_key_t * key );

__attribute__((sysv_abi))
void
fd_aesni_set_decrypt_key( uchar const *  user_key,
                          ulong          bits,
                          fd_aes_key_t * key );

__attribute__((sysv_abi))
void
fd_aesni_encrypt( uchar const *  in,
                  uchar *        out,
                  fd_aes_key_t * key );

__attribute__((sysv_abi))
void
fd_aesni_decrypt( uchar const *  in,
                  uchar *        out,
                  fd_aes_key_t * key );

#endif /* FD_HAS_AESNI */

#endif /* HEADER_fd_src_ballet_aes_fd_aes_private_h */
