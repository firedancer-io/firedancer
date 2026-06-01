#ifndef HEADER_fd_src_disco_events_fd_event_auth_h
#define HEADER_fd_src_disco_events_fd_event_auth_h

/* fd_event_auth.h provides OpenSSL glue code to authenticate the
   event client with the validator's identity key.

   This is done securely via 'remote' (IPC) signing via the sign tile.
   The identity key is only used to sign TLS 1.3 CertificateVerify
   messages. */

#include "../keyguard/fd_keyguard_client.h"
#include <openssl/ssl.h>

FD_PROTOTYPES_BEGIN

/* fd_event_auth_set_identity configures an SSL connection to use RFC
   7250 RawPublicKey client authentication using the validator
   identity Ed25519 public key.

   Signing is delegated to the sign tile via the provided keyguard
   client object.  (Retains mutable borrow on keyguard_client until the
   SSL object is destroyed.) */

int
fd_event_auth_set_identity( SSL *                  ssl,
                            uchar const *          identity_pubkey,
                            fd_keyguard_client_t * keyguard_client );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_events_fd_event_auth_h */
