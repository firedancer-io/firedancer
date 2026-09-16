#ifndef HEADER_fd_src_ballet_rsa_fd_rsa_h
#define HEADER_fd_src_ballet_rsa_fd_rsa_h

/* fd_rsa.h provides RSA signature verification (RFC 8017) for
   RSASSA-PKCS1-v1_5 and RSASSA-PSS with SHA-{256,384,512}.
   Accepts moduli of 2048 to 4096 bits and public exponents of at most
   64 bits.  */

#include "../fd_ballet_base.h"

#define FD_RSA_SUCCESS (1)
#define FD_RSA_FAILURE (0)

/* Accepted modulus size range, in bits */

#define FD_RSA_MOD_BITS_MIN (2048UL)
#define FD_RSA_MOD_BITS_MAX (4096UL)

/* FD_RSA_MOD_SZ_MAX is the max modulus (and thus signature) size in
   bytes.  FD_RSA_LIMB_CNT_MAX is the corresponding limb count. */

#define FD_RSA_MOD_SZ_MAX   (FD_RSA_MOD_BITS_MAX/8UL)
#define FD_RSA_LIMB_CNT_MAX (FD_RSA_MOD_SZ_MAX/8UL)

/* Hash functions used with RSA signatures */

#define FD_RSA_HASH_SHA256 (0)
#define FD_RSA_HASH_SHA384 (1)
#define FD_RSA_HASH_SHA512 (2)

/* fd_rsa_pubkey_t is a parsed RSA public key.  Limbs are little endian
   64-bit words. */

struct fd_rsa_pubkey {
  ulong n[ FD_RSA_LIMB_CNT_MAX ];
  ulong e;
  ulong limb_cnt;  /* limbs in n */
  ulong n_sz;      /* modulus size in bytes, ceil(mod_bits/8) */
  ulong mod_bits;  /* modulus size in bits */
};

typedef struct fd_rsa_pubkey fd_rsa_pubkey_t;

FD_PROTOTYPES_BEGIN

/* fd_rsa_pubkey_init loads a public key from big endian modulus
   [n,n+n_sz) and public exponent [e,e+e_sz).  Leading zero bytes are
   permitted.  Returns key on success and NULL if the key is rejected:
   modulus even or outside [FD_RSA_MOD_BITS_MIN,FD_RSA_MOD_BITS_MAX]
   bits, or exponent even, smaller than 3, or larger than 64 bits. */

fd_rsa_pubkey_t *
fd_rsa_pubkey_init( fd_rsa_pubkey_t * key,
                    uchar const *     n,
                    ulong             n_sz,
                    uchar const *     e,
                    ulong             e_sz );

/* fd_rsa_verify_pkcs1_v15 verifies an RSASSA-PKCS1-v1_5 signature
   (RFC 8017 Section 8.2.2) over msg.  hash is FD_RSA_HASH_{...}.
   sig_sz must equal key->n_sz.  Returns FD_RSA_SUCCESS if the
   signature is valid and FD_RSA_FAILURE otherwise. */

int
fd_rsa_verify_pkcs1_v15( fd_rsa_pubkey_t const * key,
                         uchar const *           sig,
                         ulong                   sig_sz,
                         uchar const *           msg,
                         ulong                   msg_sz,
                         int                     hash );

/* fd_rsa_verify_pss verifies an RSASSA-PSS signature (RFC 8017 Section
   8.1.2) over msg with MGF1 over the same hash and a salt length equal
   to the hash length, as TLS 1.3 requires (RFC 8446 Section 4.2.3).
   Returns FD_RSA_SUCCESS if the signature is valid and FD_RSA_FAILURE
   otherwise. */

int
fd_rsa_verify_pss( fd_rsa_pubkey_t const * key,
                   uchar const *           sig,
                   ulong                   sig_sz,
                   uchar const *           msg,
                   ulong                   msg_sz,
                   int                     hash );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_rsa_fd_rsa_h */
