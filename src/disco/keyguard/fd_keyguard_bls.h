#ifndef HEADER_fd_src_disco_keyguard_fd_keyguard_bls_h
#define HEADER_fd_src_disco_keyguard_fd_keyguard_bls_h

#include "fd_keyguard.h"
#include "../../ballet/bls/fd_bls.h"
#include "../../ballet/ed25519/fd_ed25519.h"

#define FD_KEYGUARD_BLS_KEY_MAX (17UL) /* identity plus 16 authorized voters */

FD_STATIC_ASSERT( FD_KEYGUARD_BLS_PUBKEY_SZ==FD_BLS_PUB_COMPRESSED_SZ, bls_public_key_size );
FD_STATIC_ASSERT( FD_KEYGUARD_BLS_SIG_SZ   ==FD_BLS_SIG_SZ,            bls_signature_size  );

struct fd_keyguard_bls_key {
  fd_bls_sec_t secret_key;
  uchar        public_key[ FD_KEYGUARD_BLS_PUBKEY_SZ ]; /* canonical compressed encoding */
};
typedef struct fd_keyguard_bls_key fd_keyguard_bls_key_t;

FD_STATIC_ASSERT( sizeof(fd_keyguard_bls_key_t)*FD_KEYGUARD_BLS_KEY_MAX<=4096UL, bls_keys_fit_protected_page );

FD_PROTOTYPES_BEGIN

void FD_FN_SENSITIVE
fd_keyguard_bls_key_derive( fd_keyguard_bls_key_t * key,
                            uchar const              ed25519_public_key[ static 32 ],
                            uchar const              ed25519_private_key[ static 32 ],
                            fd_sha512_t *            sha );

FD_FN_PURE fd_keyguard_bls_key_t const *
fd_keyguard_bls_key_query( fd_keyguard_bls_key_t const * keys,
                           ulong                         key_cnt,
                           uchar const                   public_key[ static FD_KEYGUARD_BLS_PUBKEY_SZ ] );

ulong
fd_keyguard_bls_request_encode( uchar *       request,
                                uchar const   public_key[ static FD_KEYGUARD_BLS_PUBKEY_SZ ],
                                uchar const * payload,
                                ulong         payload_sz );

int FD_FN_SENSITIVE
fd_keyguard_bls_sign_request( fd_keyguard_bls_key_t const * keys,
                              ulong                         key_cnt,
                              uchar const *                 request,
                              ulong                         request_sz,
                              fd_bls_sig_t *                signature );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_keyguard_fd_keyguard_bls_h */
