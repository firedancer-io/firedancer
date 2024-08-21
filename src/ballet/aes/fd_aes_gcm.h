#ifndef HEADER_fd_src_ballet_aes_fd_aes_gcm_h
#define HEADER_fd_src_ballet_aes_fd_aes_gcm_h

#include "../fd_ballet_base.h"

/* AES-GCM ************************************************************/

/* fd_aes_gcm are APIs for authenticated AES-GCM encryption of messages.
   Compatible with TLS 1.3 and QUIC.

   AES-GCM is an extension of the AES-CTR stream cipher, adding the
   ability to detect malicious tampering of the ciphertext.  (Henceforth
   referred to as 'authentication'.)   Additionally, can protect a
   variable-sz unencrypted 'additional data' blob.

   ### Optimization Notes

   Currently supports 'all-in-one' API only, wherein the entire plain-
   text is encrypted/decrypted in a single blocking call.  API may
   change in the future to support a batched 'multi block' API or
   streaming mode of operation.

   AES-GCM offers opportunity for processing of multiple AES blocks in
   parallel.  However, the computation of the auth tag is a sequential
   chain with depth of block count of message.  In QUIC, the max
   AES-GCM msg sz is limited by the packet MTU.  Thus, auth tag
   processing can still be vectorized by processing independent packets
   in parallel. */

/* Reference backend internals ****************************************/

#include "fd_aes_gcm_ref.h"

/* AES-NI backend internals *******************************************/

struct fd_aes_gcm_aesni_key {
  uchar key_enc[ 240 ];
  uchar key_dec[ 240 ];
  uint  key_sz; /* 16 */
};
typedef struct fd_aes_gcm_aesni_key fd_aes_gcm_aesni_key_t;

/* Do not change. These offsets are hardcoded in fd_aes_gcm_aesni.S. */
struct fd_aes_gcm_aesni_state {
  fd_aes_gcm_aesni_key_t key;
  uchar pad1[  12 ];
  uchar gcm [ 208 ];
  uchar iv  [  12 ];
  uchar pad2[  52 ];
};
typedef struct fd_aes_gcm_aesni_state fd_aes_gcm_aesni_t;

/* AVX10 backend internals ********************************************/

/* Do not change. These offsets are hardcoded in fd_aes_gcm_avx10.S. */
struct fd_aes_gcm_avx10_state {
  fd_aes_gcm_aesni_key_t key;
  uchar pad1[  28 ];
  uchar gcm [ 320 ];
  uchar iv  [  12 ];
  uchar pad2[  52 ];
};
typedef struct fd_aes_gcm_avx10_state fd_aes_gcm_avx10_t;

/* Backend selection **************************************************/

#if FD_HAS_AVX512 && FD_HAS_GFNI && FD_HAS_AESNI
#define FD_AES_GCM_IMPL 3 /* AVX10.1/512, VAES, VPCLMUL */
#elif FD_HAS_AVX && FD_HAS_AESNI
#define FD_AES_GCM_IMPL 2 /* AVX2, VAES */
#elif FD_HAS_AESNI
#define FD_AES_GCM_IMPL 1 /* AESNI */
#else
#define FD_AES_GCM_IMPL 0 /* Portable */
#endif

#if FD_AES_GCM_IMPL == 0

  typedef fd_aes_gcm_ref_t    fd_aes_gcm_t;
  #define fd_aes_128_gcm_init fd_aes_128_gcm_init_ref
  #define fd_aes_gcm_encrypt  fd_aes_gcm_encrypt_ref
  #define fd_aes_gcm_decrypt  fd_aes_gcm_decrypt_ref

#elif FD_AES_GCM_IMPL == 1

  typedef fd_aes_gcm_aesni_t  fd_aes_gcm_t;
  #define fd_aes_128_gcm_init fd_aes_128_gcm_init_aesni
  #define fd_aes_gcm_encrypt  fd_aes_gcm_encrypt_aesni
  #define fd_aes_gcm_decrypt  fd_aes_gcm_decrypt_aesni

#elif FD_AES_GCM_IMPL == 2

  typedef fd_aes_gcm_aesni_t  fd_aes_gcm_t;
  #define fd_aes_128_gcm_init fd_aes_128_gcm_init_avx2
  #define fd_aes_gcm_encrypt  fd_aes_gcm_encrypt_avx2
  #define fd_aes_gcm_decrypt  fd_aes_gcm_decrypt_avx2

#elif FD_AES_GCM_IMPL == 3

  typedef fd_aes_gcm_avx10_t  fd_aes_gcm_t;
  #define fd_aes_128_gcm_init fd_aes_128_gcm_init_avx10_512
  #define fd_aes_gcm_encrypt  fd_aes_gcm_encrypt_avx10_512
  #define fd_aes_gcm_decrypt  fd_aes_gcm_decrypt_avx10_512

#endif

/* Public API *********************************************************/

/* FD_AES_GCM_ALIGN: minimum alignment of fd_aes_gcm_t.
   Large enough to satisfy alignment requirements on all architectures. */
#define FD_AES_GCM_ALIGN (64UL)

#define FD_AES_GCM_TAG_SZ (16UL)
#define FD_AES_GCM_IV_SZ  (12UL)

FD_PROTOTYPES_BEGIN

/* fd_aes_128_gcm_init initializes an fd_aes_gcm_t object for
   encrypt or decrypt use.  aes_gcm points to unused and uninitialized
   memory aligned to FD_AES_GCM_STATE_ALIGN with sizeof(fd_aes_gcm_t)
   bytes available. */

void
fd_aes_128_gcm_init( fd_aes_gcm_t * aes_gcm,
                     uchar const    key[ 16 ],
                     uchar const    iv [ 12 ] );

/* fd_aes_gcm_aead_{encrypt,decrypt} implements the AES-GCM AEAD cipher
   c points to the ciphertext buffer.  p points to the plaintext buffer.
   sz is the length of the p and c buffers.  p,c,sz do not have align-
   ment requirements.  iv points to the 12 byte initialization vector.
   aad points to the 'associated data' buffer (with size aad_sz).  tag
   points to the 16 byte authentication tag (written by both decrypt and
   encrypt).

   (AAD serves to mix in arbitrary additional data into the auth tag,
   such that tampering with the AAD results in a decryption failure)

   fd_aes_gcm_encrypt reads plaintext from p, writes ciphertext to
   c, and writes the auth tag to 'tag'.  encrypt cannot fail.

   fd_aes_gcm_decrypt reads the expected auth tag and ciphertext,
   and writes the decrypted plaintext to p.  Ciphertext and auth tag are
   usually transmitted as-is over a network packet.  Returns 1 on
   success, or 0 on failure.  Reasons for failure include:  Corrupt
   ciphertext, corrupt sz, corrupt AAD, or corrupt tag (could be due to
   network corruption or malicious tampering). */

void
fd_aes_gcm_encrypt( fd_aes_gcm_t * aes_gcm,
                    uchar *        c,
                    uchar const *  p,
                    ulong          sz,
                    uchar const *  aad,
                    ulong          aad_sz,
                    uchar          tag[ 16 ] );

int
fd_aes_gcm_decrypt( fd_aes_gcm_t * aes_gcm,
                    uchar const *  c,
                    uchar *        p,
                    ulong          sz,
                    uchar const *  aad,
                    ulong          aad_sz,
                    uchar const    tag[ 16 ] );

#define FD_AES_GCM_DECRYPT_FAIL (0)
#define FD_AES_GCM_DECRYPT_OK   (1)

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_aes_fd_aes_gcm_h */
