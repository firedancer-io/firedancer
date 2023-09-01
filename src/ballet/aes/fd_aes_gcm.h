#ifndef HEADER_fd_src_ballet_aes_fd_aes_gcm_h
#define HEADER_fd_src_ballet_aes_fd_aes_gcm_h

#include "fd_aes_gcm_private.h"


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


FD_PROTOTYPES_BEGIN

/* fd_aes_{128,192,256}_gcm_init initialize an fd_aes_gcm_t object for
   encrypt or decrypt use.  fd_aes_gcm_init is the generic variant (may
   only be used for key_len in {128,192,256}).  Zero-initialization of
   aes not required.  key contains the AES-GCM decryption key.  Security
   of AES-GCM operation is dependent on key length. */

void
fd_aes_gcm_init( fd_aes_gcm_t * aes_gcm,
                 uchar const *  key,
                 ulong          key_len,
                 uchar const    iv[ static 12 ] );

static inline void
fd_aes_128_gcm_init( fd_aes_gcm_t * aes_gcm,
                     uchar const    key[ static 16 ],
                     uchar const    iv [ static 12 ] ) {
  fd_aes_gcm_init( aes_gcm, key, 16UL, iv );
}

static inline void
fd_aes_192_gcm_init( fd_aes_gcm_t * aes_gcm,
                     uchar const    key[ static 24 ],
                     uchar const    iv [ static 12 ] ) {
  fd_aes_gcm_init( aes_gcm, key, 24UL, iv );
}

static inline void
fd_aes_256_gcm_init( fd_aes_gcm_t * aes_gcm,
                     uchar const    key[ static 32 ],
                     uchar const    iv [ static 12 ] ) {
  fd_aes_gcm_init( aes_gcm, key, 32UL, iv );
}

/* fd_aes_gcm_aead_{encrypt,decrypt} implements the AES-GCM AEAD cipher
   c points to the ciphertext buffer.  p points to the plaintext buffer.
   sz is the length of the p and c buffers.  p,c,sz do not have align-
   ment requirements.  iv points to the 12 byte initialization vector.
   aad points to the 'associated data' buffer (with size aad_sz).  tag
   points to the 16 byte authentication tag (written by both decrypt and
   encrypt).

   (AAD serves to mix in arbitrary additional data into the auth tag,
   such that tampering with the AAD results in a decryption failure)

   fd_aes_gcm_aead_encrypt reads plaintext from p, writes ciphertext to
   c, and writes the auth tag to 'tag'.  encrypt cannot fail.

   fd_aes_gcm_aead_decrypt reads the expected auth tag and ciphertext,
   and writes the decrypted plaintext to p.  Ciphertext and auth tag are
   usually transmitted as-is over a network packet.  Returns 1 on
   success, or 0 on failure.  Reasons for failure include:  Corrupt
   ciphertext, corrupt sz, corrupt AAD, or corrupt tag (could be due to
   network corruption or malicious tampering). */

void
fd_aes_gcm_aead_encrypt( fd_aes_gcm_t * aes_gcm, /* rdi */
                         uchar *        c,       /* rsi */
                         uchar const *  p,       /* rdx */
                         ulong          sz,      /* rcx */
                         uchar const *  aad,     /* r8  */
                         ulong          aad_sz,  /* r9  */
                         uchar          tag[ static 16 ] );

int
fd_aes_gcm_aead_decrypt( fd_aes_gcm_t * aes_gcm,
                         uchar const *  c,
                         uchar *        p,
                         ulong          sz,
                         uchar const *  aad,
                         ulong          aad_sz,
                         uchar const    tag[ static 16 ] );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_aes_fd_aes_gcm_h */
