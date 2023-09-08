#ifndef HEADER_fd_src_tango_tls_fd_tls_estate_h
#define HEADER_fd_src_tango_tls_fd_tls_estate_h

#include "fd_tls_base.h"

/* Base ***************************************************************/

/* fd_tls_estate_base_t is the shared header of the
   fd_tls_estate_{srv,cli} objects. */

struct fd_tls_estate_base {
  uchar  state;
  uchar  server : 1;  /* 1 if server, 0 if client */
  uchar  quic   : 1;  /* 1 if QUIC, 0 otherwise ... TODO this is redundant */
  ushort reason;      /* FD_TLS_REASON_{...} */

  /* Sadly required for SSLKEYLOGFILE */
  uchar client_random[ 32 ];
};

typedef struct fd_tls_estate_base fd_tls_estate_base_t;


/* Server *************************************************************/

/* fd_tls_estate_srv contains compressed TLS server handshake state
   while waiting for the client to send a message.  estate is optimized
   for small memory use for incoming conns (128 byte per handshake).

   *** Security ********************************************************

   fd_tls servers must handle handshake requests from untrusted clients,
   and thus require hardening.  A typical lifetime of an estate object
   is in the order of ~3 seconds (conn timeout).  This requires some
   care to avoid memory exhaustion attacks.

   For example, a default OpenSSL app uses a handshake state size of
   about 10 KB (via multiple allocations on global heap).  Assuming 3
   second conn timeout, and flood rate of 1 million ClientHello msg/s,
   an attacker could indefinitely occupy ~30 GB of raw heap allocations!
   More concerning -- Global heap pressure will cause latent allocation
   failures in unrelated code, which might escalate to OOM kills.

   fd_tls_estate would only require 0.38 GB of memory for the same spam
   rate.  The memory of estate_srv objects is provided by the transport
   layer (e.g. QUIC or TLS record layer).  Each estate_srv object has
   static footprint.  This allows dense packing in custom memory arenas.

   This allows for robust handling of packet floods:  Even in the event
   the estate_srv arena is exhausted, the impact is limited to temporary
   inability to accept new connections.  Processing of established conns
   and unrelated code is unaffected.

   *** State Machine ***************************************************

   Each estate_srv object corresponds to an instance of a server-side
   TLS handshake state machine.  It is first instantiated when the
   client sent its ClientHello, the first message of a TLS handshake.

   Currently, only one external state exists:

     FD_TLS_HS_WAIT_FINISHED:  Processed ClientHello.

       At this point, the server has responded with all messages up to
       server Finished and is waiting for the client to respond with
       with client Finished (and optionally, a certificate).

   State data contains:

   - The transcript hash state, which commits both sides to the entire
     sequence of handshake messages (such that they cannot be tampered
     with).

   - The client handshake secret, which is used to derive the "client
     Finished" verify data. */

struct fd_tls_estate_srv {
  fd_tls_estate_base_t base;

  uchar  server_cert_rpk : 1;  /* 0: X.509  1: raw public key */
  uchar  client_cert     : 1;  /* 0: no client auth  1: client cert */
  uchar  client_cert_rpk : 1;  /* 0: X.509  1: raw public key */

  fd_tls_transcript_t transcript;
  uchar               client_hs_secret[32];
  uchar               client_pubkey[32];
};

typedef struct fd_tls_estate_srv fd_tls_estate_srv_t;


/* Note:  When requesting a cert, the server should consider stopping
   after CertificateVerify to save compute resources (at the expense of
   more memory required to save state carried over from
   CertificateRequest...server Finished). */

FD_PROTOTYPES_BEGIN

/* fd_tls_estate_srv_new initializes a estate object for an incoming
   conn.  mem points to a memory region suitable for storing an
   fd_tls_estate_srv_t.  Returns cast of mem, which will be initialized
   to state FD_TLS_HS_START. */

fd_tls_estate_srv_t *
fd_tls_estate_srv_new( void * mem );

/* fd_tls_estate_srv_delete is currently a no-op. */

static inline void *
fd_tls_estate_srv_delete( fd_tls_estate_srv_t * estate ) {
  return (void *)estate;
}

FD_PROTOTYPES_END


/* Client *************************************************************/

/* fd_tls_estate_cli contains TLS client handshake state while waiting
   for the server to send a message.

   TLS client side handshake state is considerably more complex than
   the server-side state.  Thus, estate_cli memory requirements are
   larger than for estate_srv.

   However, clients are not vulnerable to handshake packet floods:
   - The packet count per handshake is limited
   - Peers cannot initiate connections to clients (clients will simply
     drop unsolicited packets)

   Thus, estate_cli is not optimized for memory use. */

struct fd_tls_estate_cli {
  fd_tls_estate_base_t base;

  uchar server_pubkey   [ 32 ];
  uchar server_hs_secret[ 32 ];
  uchar client_hs_secret[ 32 ];
  uchar master_secret   [ 32 ];

  uchar client_cert        : 1;  /* 0=anon  1=client auth */
  uchar server_cert_rpk    : 1;
  uchar client_cert_nox509 : 1;
  uchar client_cert_rpk    : 1;
  uchar server_pubkey_pin  : 1;  /* if 1, require cert to match server_pubkey */

  fd_sha256_t transcript;
};

typedef struct fd_tls_estate_cli fd_tls_estate_cli_t;

FD_PROTOTYPES_BEGIN

fd_tls_estate_cli_t *
fd_tls_estate_cli_new( void * mem );

static inline void *
fd_tls_estate_cli_delete( fd_tls_estate_cli_t * estate ) {
  return (void *)estate;
}

FD_PROTOTYPES_END


/* Common *************************************************************/

union fd_tls_estate {
  fd_tls_estate_base_t base;
  fd_tls_estate_srv_t  srv;
  fd_tls_estate_cli_t  cli;
};

typedef union fd_tls_estate fd_tls_estate_t;

#endif /* HEADER_fd_src_tango_tls_fd_tls_estate_h */
