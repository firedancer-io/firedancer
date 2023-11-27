#ifndef HEADER_fd_src_tango_tls_fd_tls_estate_h
#define HEADER_fd_src_tango_tls_fd_tls_estate_h

#include "../fd_tango_base.h"
#include "../../ballet/sha256/fd_sha256.h"

/* Base ***************************************************************/

/* fd_tls_estate_base_t is the shared header of the
   fd_tls_estate_{srv,cli} objects. */

struct fd_tls_estate_base {
  uchar  state;
  uchar  server : 1;  /* 1 if server, 0 if client */
  ushort reason;      /* FD_TLS_REASON_{...} */

  /* Sadly required for SSLKEYLOGFILE */
  uchar client_random[ 32 ];
};

typedef struct fd_tls_estate_base fd_tls_estate_base_t;

/* The transcript is a running hash over all handshake messages.  The
   hash state depends on the current handshake progression.  The hash
   order is as follows:

     client   ClientHello           always
     server   ServerHello           always
     server   EncryptedExtensions   always
     server   CertificateRequest    optional
     server   Certificate           always
     server   CertificateVerify     always
     server   Finished              always
     client   Certificate           optional
     client   CertificateVerify     optional
     client   Finished              always */

struct fd_tls_transcript {
  uchar buf[ 64 ];  /* Pending SHA block */
  uint  sha[ 8 ];   /* Current internal SHA state */
  uint  len;        /* Number of bytes so far compressed into SHA state
                       plus number of bytes in pending in buf */
};

typedef struct fd_tls_transcript fd_tls_transcript_t;

/* Note:  An experimental memory optimization that is not implemented
   here is alignment of SHA state.  It might be possible to craft a
   transcript preimage that is aligned to SHA block size.  This allows
   omitting the SHA block buffer, saving 64 bytes per transcript (and
   thus per in-flight handshake). */

FD_PROTOTYPES_BEGIN

static inline void
fd_tls_transcript_store( fd_tls_transcript_t * script,
                         fd_sha256_t const *   sha ) {
  memcpy( script->buf, sha->buf,   64UL );
  memcpy( script->sha, sha->state, 32UL );
  script->len = (uint)( sha->bit_cnt / 8UL );
}

static inline void
fd_tls_transcript_load( fd_tls_transcript_t const * script,
                        fd_sha256_t *               sha ) {
  memcpy( sha->buf,   script->buf, 64UL );
  memcpy( sha->state, script->sha, 32UL );
  sha->bit_cnt  = (ulong)( script->len * 8U  );
  sha->buf_used = (uint )( script->len % 64U );
}

FD_PROTOTYPES_END

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
