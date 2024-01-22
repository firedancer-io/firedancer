#ifndef HEADER_fd_src_ballet_ed25519_fd_x25519_h
#define HEADER_fd_src_ballet_ed25519_fd_x25519_h

/* fd_x25519 provides an API for the X25519 ECDH key exchange.
   X25519 is defined in RFC 7748 Section 5.

   ### Key Derivation

   Given two arbitrary 32 byte secrets (a, b) owned by different peers
   (A, B), X25519 computes a shared secret K without revealing the
   contents of (a, b) to either party.

   Each party derives a curve point (Ga, Gb) using their secret (a, b).
   This derivation is irreversible, thus does not reveal information
   about the original secret.  (provided by fd_x25519_public).

   Both parties exchange curve points, such that

     Peer A knows (a, Gb)
     Peer B knows (b, Ga)

   ### Shared Secret Derivation

   Using fd_x25519_exchange, both parties then derive the same shared
   secret using inputs (a, Gb) and (b, Ga). */

#include "../fd_ballet_base.h"

#define FD_X25519_SECRET_SZ (32UL)

FD_PROTOTYPES_BEGIN

/* fd_x25519_public generates an X25519 public key (curve point) given
   an arbitrary 32 byte secret at self_private_key.  self_public_key
   points to the first byte of a memory region of at least 32 bytes.
   Returns self_public_key.  On return, self_public_key holds the
   serialized public key suitable for sharing over the network.

   The remote peer in the key exchange process would typically use the
   public key generated locally using this function as the
   peer_public_key input to fd_x25519_exchange. */

void *
fd_x25519_public( void *       self_public_key,
                  void const * self_private_key );

/* fd_x25519_exchange computes a shared secret given an arbitrary 32
   byte secret at self_private_key and an X25519 public key at
   peer_public_key.  On success, writes 32 bytes to shared_secret and
   returns shared_secret.  On failure, returns NULL and leaves the
   contents of shared_secret undefined. Reasons for failure include that
   peer_public_key is a low order curve point.  (This is never the case
   when using fd_x25519_public.  However, peer_public_key typically is
   received from an untrusted network transport, such as the beginning
   of a TLS handshake, and thus may have been tampered with by an
   attacker) */

void *
fd_x25519_exchange( void *       shared_secret,
                    void const * self_private_key,
                    void const * peer_public_key );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_ed25519_fd_x25519_h */
