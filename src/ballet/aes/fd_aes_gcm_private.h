#ifndef HEADER_fd_src_ballet_aes_fd_aes_gcm_private_h
#define HEADER_fd_src_ballet_aes_fd_aes_gcm_private_h

#include "fd_aes_private.h"

/* AVX accelerated GCM ************************************************/

#if FD_HAS_AVX && FD_HAS_INT128

struct __attribute__((aligned(64UL))) fd_aes_gcm {
  /* Offset of Yi, EKi, EK0, len, Xi, H, and Htable is hardcoded in
     asm modules -- Do not change offsets */

  /* Following 6 names follow names in GCM specification */
  union {
    ulong u[ 2];
    uint  d[ 4];
    uchar c[16];
    ulong t[ 2];
  } Yi, EKi, EK0, len, Xi, H;
  uint128 Htable[16];

  uint    mres, ares;
  uchar   Xn[48];

  fd_aes_key_t key;
};

typedef struct fd_aes_gcm fd_aes_gcm_t;

FD_PROTOTYPES_BEGIN

__attribute__((sysv_abi))
void
fd_gcm_init_avx( uint128     Htable[16],
                 ulong const Xi[2] );

__attribute__((sysv_abi))
void
fd_gcm_gmult_avx( ulong         Xi[2],
                  uint128 const Htable[16] );

__attribute__((sysv_abi))
void
fd_gcm_ghash_avx( ulong         Xi[2],
                  uint128 const Htable[16],
                  uchar const * in,
                  ulong         len);

FD_PROTOTYPES_END

#endif /* FD_HAS_AVX */

/* AES-GCM: x86_64 AES-NI (128-bit) and AVX (256-bit) accelerated *****/

#if FD_HAS_AESNI

ulong
fd_aesni_gcm_encrypt_private(
    uchar const * in,
    uchar *       out,
    ulong         len,
    void const *  key,
    uchar         ivec[ 16 ],
    ulong *       Xi );

ulong
fd_aesni_gcm_decrypt_private(
    uchar const * in,
    uchar *       out,
    ulong         len,
    void const *  key,
    uchar         ivec[ 16 ],
    ulong *       Xi );

#endif /* FD_HAS_AESNI */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_aes_fd_aes_gcm_private_h */
