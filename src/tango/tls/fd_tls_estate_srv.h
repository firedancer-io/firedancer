#ifndef HEADER_fd_src_tango_tls_fd_tls_estate_srv_h
#define HEADER_fd_src_tango_tls_fd_tls_estate_srv_h

#include "fd_tls_base.h"

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
  char  state;  /* FD_TLS_HS_{...} */
  uchar server_cert_rpk : 1;  /* 0: X.509  1: raw public key */
  uchar client_cert     : 1;  /* 0: no client auth  1: client cert */
  uchar client_cert_rpk : 1;  /* 0: X.509  1: raw public key */

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

#endif /* HEADER_fd_src_tango_tls_fd_tls_estate_srv_h */
