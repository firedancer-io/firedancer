#ifndef HEADER_fd_src_discof_failover_fd_failover_tls_h
#define HEADER_fd_src_discof_failover_fd_failover_tls_h

/* TLS 1.3 over TCP for one failover candidate, built on fd_tls and
   fd_tlsrec.  Both ends present a self-signed Ed25519 cert for their
   junk identity.  Nobody pins a key, the channel checks the peer key TLS
   authenticated against HELLO and its member certificate.  The caller
   owns the socket. */

#include "../../waltz/tlsrec/fd_tlsrec_sock.h"
#include "../../ballet/chacha/fd_chacha_rng.h"

/* Max ciphertext accepted from a candidate before it pairs */
#define FD_FAILOVER_TLS_PREPAIR_MAX (32768UL)

/* Per-channel TLS config, the fd_tls template and its RNG.  The sign
   tile signs our CertificateVerify, no private key is kept here. */

struct fd_failover_tls_ctx {
  fd_tls_t        tls;
  fd_chacha_rng_t rng[ 1 ];
  int             ready;
};
typedef struct fd_failover_tls_ctx fd_failover_tls_ctx_t;

/* One candidate connection.  conn is ~100 KiB and sock ~80 KiB, both
   wiped by fini. */

struct fd_failover_tls {
  fd_tlsrec_conn_t conn;
  fd_tlsrec_sock_t sock;
  int              fd;
  int              verified;          /* handshake done, peer_pubkey is set */
  int              paired;            /* set by the channel after HELLO */
  int              peer_closed;       /* orderly EOF or close_notify, never a TLS error */
  uchar            peer_pubkey[ 32 ]; /* junk key the peer signed the handshake with */
  int              read_budget;       /* socket reads left this turn */
  int              write_budget;      /* record writes left this turn */
  ulong            received;          /* ciphertext bytes read before pairing */
};
typedef struct fd_failover_tls fd_failover_tls_t;

FD_PROTOTYPES_BEGIN

/* fd_failover_tls_ctx_init sets our junk pubkey and the signer for
   CertificateVerify.  Call before sandboxing, it seeds the RNG.  Every
   connection then reads its own key share from getrandom, which the
   sandbox allows.  Returns 0 on success, -1 if entropy fails. */

int
fd_failover_tls_ctx_init( fd_failover_tls_ctx_t * ctx,
                          uchar const             public_key[ 32 ],
                          fd_tls_sign_t           signer );

/* fd_failover_tls_ctx_fini wipes the context. */

void
fd_failover_tls_ctx_fini( fd_failover_tls_ctx_t * ctx );

/* fd_failover_tls_new binds a fresh connection to fd.  The listener
   requires a client cert.  Returns 0 on success, -1 if ctx is not
   initialized or entropy fails. */

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
   the peer signed it with an Ed25519 key, which is then in peer_pubkey,
   0 while pending, -1 on failure.  fd_failover_tls_read and
   fd_failover_tls_write return bytes moved, 0 when pending or out of
   budget, -1 on error or peer close.  A write may take fewer bytes than
   offered (at most one record), the caller retries the rest. */

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
