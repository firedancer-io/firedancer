#ifndef HEADER_fd_src_ballet_aes_fd_aes_h
#define HEADER_fd_src_ballet_aes_fd_aes_h

#include "../fd_ballet_base.h"
#include "../../util/sanitize/fd_msan.h"

#define FD_AES_128_KEY_SZ (16UL)

/* Reference backend internals ****************************************/

struct fd_aes_key_ref {
  uint rd_key[ 60 ];
  int  rounds;
};

typedef struct fd_aes_key_ref fd_aes_key_ref_t;

FD_PROTOTYPES_BEGIN

int
fd_aes_ref_set_encrypt_key( uchar const *      user_key,
                            ulong              bits,
                            fd_aes_key_ref_t * key );

int
fd_aes_ref_set_decrypt_key( uchar const *      user_key,
                            ulong              bits,
                            fd_aes_key_ref_t * key );

void
fd_aes_ref_encrypt_core( uchar const *            in,
                         uchar *                  out,
                         fd_aes_key_ref_t const * key );

void
fd_aes_ref_decrypt_core( uchar const *        in,
                         uchar *              out,
                         fd_aes_key_ref_t const * key );

FD_PROTOTYPES_END

/* AES-NI backend internals *******************************************/

#if FD_HAS_AESNI

FD_PROTOTYPES_BEGIN

__attribute__((sysv_abi)) void
fd_aesni_set_encrypt_key( uchar const *      user_key,
                          ulong              bits,
                          fd_aes_key_ref_t * key );

__attribute__((sysv_abi)) void
fd_aesni_set_decrypt_key( uchar const *      user_key,
                          ulong              bits,
                          fd_aes_key_ref_t * key );

__attribute__((sysv_abi)) void
fd_aesni_encrypt( uchar const *      in,
                  uchar *            out,
                  fd_aes_key_ref_t * key );

__attribute__((sysv_abi)) void
fd_aesni_decrypt( uchar const *      in,
                  uchar *            out,
                  fd_aes_key_ref_t * key );

FD_PROTOTYPES_END

#endif /* FD_HAS_AESNI */

/* Backend selection **************************************************/

#if FD_HAS_AESNI
#define FD_AES_IMPL 1 /* AESNI */
#else
#define FD_AES_IMPL 0 /* Portable */
#endif

#if FD_AES_IMPL == 0

  typedef fd_aes_key_ref_t               fd_aes_key_t;
  #define fd_aes_private_encrypt         fd_aes_ref_encrypt_core
  #define fd_aes_private_decrypt         fd_aes_ref_encrypt_core
  #define fd_aes_private_set_encrypt_key fd_aes_ref_set_encrypt_key
  #define fd_aes_private_set_decrypt_key fd_aes_ref_set_decrypt_key

#elif FD_AES_IMPL == 1

  typedef fd_aes_key_ref_t               fd_aes_key_t;
  #define fd_aes_private_encrypt         fd_aesni_encrypt
  #define fd_aes_private_decrypt         fd_aesni_decrypt
  #define fd_aes_private_set_encrypt_key fd_aesni_set_encrypt_key
  #define fd_aes_private_set_decrypt_key fd_aesni_set_decrypt_key

#endif

static inline void
fd_aes_set_encrypt_key( uchar const *  user_key,
                        ulong          bits,
                        fd_aes_key_t * key ) {
  fd_msan_check   ( user_key, bits/8               );
  fd_msan_unpoison( key,      sizeof(fd_aes_key_t) );
  fd_aes_private_set_encrypt_key( user_key, bits, key );
}

static inline void
fd_aes_set_decrypt_key( uchar const *  user_key,
                        ulong          bits,
                        fd_aes_key_t * key ) {
  fd_msan_check   ( user_key, bits/8               );
  fd_msan_unpoison( key,      sizeof(fd_aes_key_t) );
  fd_aes_private_set_decrypt_key( user_key, bits, key );
}

static inline void
fd_aes_encrypt( uchar const *  in,
                uchar *        out,
                fd_aes_key_t * key ) {
  fd_msan_check   ( key, sizeof(fd_aes_key_t) );
  fd_msan_check   ( in,  16UL );
  fd_msan_unpoison( out, 16UL );
  fd_aes_private_encrypt( in, out, key );
}

static inline void
fd_aes_decrypt( uchar const *  in,
                uchar *        out,
                fd_aes_key_t * key ) {
  fd_msan_check   ( key, sizeof(fd_aes_key_t) );
  fd_msan_check   ( in,  16UL );
  fd_msan_unpoison( out, 16UL );
  fd_aes_private_decrypt( in, out, key );
}

#endif /* HEADER_fd_src_ballet_aes_fd_aes_h */
