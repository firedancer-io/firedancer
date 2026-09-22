#ifndef HEADER_fd_src_discof_failover_fd_failover_tls_h
#define HEADER_fd_src_discof_failover_fd_failover_tls_h

/* TLS 1.3 over TCP for one failover candidate, built on fd_tls and
   fd_tlsrec.  Both ends present a self-signed Ed25519 cert for their
   junk identity and pin the peer's junk pubkey.  The caller owns the
   socket. */

#include "../../waltz/tlsrec/fd_tlsrec_sock.h"
#include "../../ballet/chacha/fd_chacha_rng.h"
#include "../../ballet/sha512/fd_sha512.h"

/* Max ciphertext accepted from a candidate before it pairs */
#define FD_FAILOVER_TLS_PREPAIR_MAX (32768UL)

/* Per-channel TLS config: the fd_tls template, its RNG, and the junk
   private key used to sign CertificateVerify.  The private key sits on
   a protected page (mlocked, no core dump, wiped on fork), not in the
   channel object. */

struct fd_failover_tls_ctx {
  fd_tls_t        tls;
  fd_chacha_rng_t rng[ 1 ];
  fd_sha512_t     sha[ 1 ];
  uchar *         private_key; /* 32 byte seed on a protected page */
  uchar           public_key [ 32 ];
  uchar           peer_pubkey[ 32 ];
  int             ready;
};
typedef struct fd_failover_tls_ctx fd_failover_tls_ctx_t;

/* One candidate connection.  conn is ~100 KiB and sock ~80 KiB, both
   wiped by fini. */

struct fd_failover_tls {
  fd_tlsrec_conn_t              conn;
  fd_tlsrec_sock_t              sock;
  fd_failover_tls_ctx_t const * ctx;
  int   fd;
  int   dial_peer;
  int   verified;     /* handshake done, peer key matches the expected junk key */
  int   paired;       /* set by the channel after HELLO */
  int   read_budget;  /* socket reads left this turn */
  int   write_budget; /* record writes left this turn */
  ulong received;     /* ciphertext bytes read before pairing */
};
typedef struct fd_failover_tls fd_failover_tls_t;

FD_PROTOTYPES_BEGIN

/* fd_failover_tls_ctx_init installs a 64 byte Ed25519 junk keypair
   (seed then pubkey) and the peer's junk pubkey.  Call before
   sandboxing: it allocates the protected key page and seeds the RNG.
   Every connection then reads its own key share from getrandom, which
   the sandbox allows.  Returns 0 on success, -1 if the keypair is
   inconsistent, matches the peer's key, or entropy fails. */

int
fd_failover_tls_ctx_init( fd_failover_tls_ctx_t * ctx,
                          uchar const *           keypair,
                          uchar const *           peer_pubkey );

/* fd_failover_tls_ctx_fini wipes the key material.  The protected page
   stays mapped for the next init. */

void
fd_failover_tls_ctx_fini( fd_failover_tls_ctx_t * ctx );

/* fd_failover_tls_new binds a fresh connection to fd.  The dialer pins
   the peer key before sending ClientHello, the listener requires a
   client cert and checks its key after the handshake.  Returns 0 on
   success, -1 if ctx is not initialized. */

int
fd_failover_tls_new( fd_failover_tls_t *     tls,
                     fd_failover_tls_ctx_t * ctx,
                     int                     fd,
                     int                     dial_peer );

/* fd_failover_tls_fini sends close_notify if the connection is up and
   wipes the connection state.  The caller closes fd. */

void
fd_failover_tls_fini( fd_failover_tls_t * tls );

/* fd_failover_tls_budget allows one socket read and one record write
   per service turn. */

void
fd_failover_tls_budget( fd_failover_tls_t * tls );

/* fd_failover_tls_handshake returns 1 once the handshake is done and
   the peer key matches the expected junk key, 0 while pending, -1 on failure.
   fd_failover_tls_read and fd_failover_tls_write return bytes moved,
   0 when pending or out of budget, -1 on error or peer close.  A write
   may take fewer bytes than offered (at most one record), the caller
   retries the rest. */

int
fd_failover_tls_handshake( fd_failover_tls_t * tls );

long
fd_failover_tls_read( fd_failover_tls_t * tls,
                      void *              buf,
                      ulong               sz );

long
fd_failover_tls_write( fd_failover_tls_t * tls,
                       void const *        buf,
                       ulong               sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_failover_fd_failover_tls_h */
