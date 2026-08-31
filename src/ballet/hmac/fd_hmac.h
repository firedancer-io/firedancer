#ifndef HEADER_fd_src_ballet_hmac_fd_hmac_h
#define HEADER_fd_src_ballet_hmac_fd_hmac_h

/* fd_hmac.h provides APIs for HMAC (RFC 2104) and HKDF (RFC 5869).

   HMAC is a keyed hash construction used for message authentication.
   HKDF is a key derivation function built on HMAC, used by TLS 1.3
   and QUIC for deriving encryption keys from shared secrets. */

#include "../fd_ballet_base.h"

/* fd_hmac_fn_t is the generic HMAC function pointer type.
   Computes HMAC(key, data) and stores the result in hash.
   Returns hash. */

typedef void *
(* fd_hmac_fn_t)( void const * data,
                  ulong        data_sz,
                  void const * key,
                  ulong        key_sz,
                  void *       hash );

FD_PROTOTYPES_BEGIN


/* fd_hmac_{sha256,sha384,sha512} computes the HMAC digest for the
   given hash function.  data/data_sz is the message.  key/key_sz is
   the HMAC key.  Stores the digest into hash and returns hash.

   hash must point to a buffer of at least {32,48,64} bytes. */

void * fd_hmac_sha256( void const * data, ulong data_sz,
                       void const * key,  ulong key_sz,
                       void *       hash );

void * fd_hmac_sha384( void const * data, ulong data_sz,
                       void const * key,  ulong key_sz,
                       void *       hash );

void * fd_hmac_sha512( void const * data, ulong data_sz,
                       void const * key,  ulong key_sz,
                       void *       hash );

/* fd_hkdf_extract computes HKDF-Extract.
   RFC 5869 Section 2.2,
   "The output PRK is calculated as follows:
    PRK = HMAC-Hash(salt, IKM)"

   hash_sz is the digest size (32 for SHA-256, etc) and must be in
   [1,64].  prk must point to a buffer of hash_sz bytes.  Returns prk on
   success and NULL if hash_sz is invalid.

   If salt is NULL or salt_sz==0, a zero-filled key of hash_sz bytes
   is used. RFC 5869 Section 2.2,
   "salt     optional salt value (a non-secret random value);
             if not provided, it is set to a string of HashLen zeros." */

static inline void *
fd_hkdf_extract( void *       prk,
                 ulong        hash_sz,
                 void const * salt,    ulong salt_sz,
                 void const * ikm,     ulong ikm_sz,
                 fd_hmac_fn_t hmac_fn ) {
  uchar zeros[64] = {0};
  if( FD_UNLIKELY( !hash_sz || hash_sz>sizeof(zeros) ) ) return NULL;
  if( !salt || !salt_sz ) {
    salt    = zeros;
    salt_sz = hash_sz;
  }
  return hmac_fn( ikm, ikm_sz, salt, salt_sz, prk );
}

/* fd_hkdf_expand_label computes HKDF-Expand-Label.
   Described in RFC 5869 Section 7.1, this is the standard key derivation
   primitive used throughout TLS 1.3 and QUIC and replaces PRFs from older
   protocols.

   secret_sz is the HMAC digest size and must be at most 64.
   out_sz must be within [1, secret_sz].
   label_sz and context_sz must each be at most 64.

   Returns out on success.  Returns NULL if any of these size bounds is
   violated.  On failure, neither hmac_fn nor out is accessed.

   Constructs the HkdfLabel struct:
     struct { uint16 length; opaque label<7..255>; opaque context<0..255>; }
   with "tls13 " prepended to the label, then computes
     HMAC(secret, HkdfLabel || 0x01)

   Only single-expand (counter=1) is supported, as it is sufficient for
   TLS 1.3 where all derived values fit in one hash output. */

void *
fd_hkdf_expand_label( uchar *       out,
                      ulong         out_sz,
                      uchar const * secret,
                      ulong         secret_sz,
                      char const *  label,
                      ulong         label_sz,
                      uchar const * context,
                      ulong         context_sz,
                      fd_hmac_fn_t  hmac_fn );

/* fd_hkdf_expand_label_sha256 is a convenience wrapper that uses
   HMAC-SHA-256 and assumes a 32-byte secret. */

static inline void *
fd_hkdf_expand_label_sha256( uchar *       out,
                             ulong         out_sz,
                             uchar const   secret[ 32 ],
                             char const *  label,
                             ulong         label_sz,
                             uchar const * context,
                             ulong         context_sz ) {
  return fd_hkdf_expand_label( out, out_sz, secret, 32UL,
                               label, label_sz, context, context_sz,
                               fd_hmac_sha256 );
}

/* fd_hkdf_expand_label_sha384 is a convenience wrapper that uses
   HMAC-SHA-384 and assumes a 48-byte secret. */

static inline void *
fd_hkdf_expand_label_sha384( uchar *       out,
                             ulong         out_sz,
                             uchar const   secret[ 48 ],
                             char const *  label,
                             ulong         label_sz,
                             uchar const * context,
                             ulong         context_sz ) {
  return fd_hkdf_expand_label( out, out_sz, secret, 48UL,
                               label, label_sz, context, context_sz,
                               fd_hmac_sha384 );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_hmac_fd_hmac_h */
