#ifndef HEADER_src_ballet_tls_fd_tls_h
#define HEADER_src_ballet_tls_fd_tls_h

#include "../fd_tango_base.h"
#include "../../ballet/sha256/fd_sha256.h"

/* fd_tls implements a subset of the TLS v1.3 (RFC 8446) handshake
   protocol.

   fd_tls is not a general purpose TLS library.  It only provides the
   TLS components required to secure peer-to-peer QUIC connections as
   they appear in Solana network protocol.  Specifics are listed below.

   Older TLS versions, such as TLS v1.2, are not supported.

   ### Peer Authentication

   Peers are authenticated via Ed25519 using the TLS v1.3 raw public key
   (RPK) extension.  Unlike usual deployments of TLS, this library does
   not support X.509 certificates or other signature schemes.

   ### Key Exchange

   Peers exchange symmetric keys using X25519, an Elliptic Curve Diffie-
   Hellman key exchange scheme using Curve25519.  Pre-shared keys and
   other key exchange schemes are currently not supported.

   ### Data Confidentiality and Integratity

   fd_tls provides an API for the TLS_AES_128_GCM_SHA256 cipher suite.
   Other cipher suites are currently not supported.

   ### References

   This library implements parts of protocols specified in the following
   IETF RFCs:

     RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
     https://datatracker.ietf.org/doc/html/rfc8446

     RFC 6066: Transport Layer Security (TLS) Extensions:
               Extension Definitions
     https://datatracker.ietf.org/doc/html/rfc6066

     RFC 9001: Using TLS to Secure QUIC
     https://datatracker.ietf.org/doc/html/rfc9001

     RFC 7919: Negotiated Finite Field Diffie-Hellman Ephemeral
               Parameters for Transport Layer Security (TLS)
     RFC 4492: Elliptic Curve Cryptography (ECC) Cipher Suites for
               Transport Layer Security (TLS)
     https://datatracker.ietf.org/doc/html/rfc7919
     https://datatracker.ietf.org/doc/html/rfc4492

     RFC 7250: Using Raw Public Keys in Transport Layer Security (TLS)
     https://datatracker.ietf.org/doc/html/rfc7250

     RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
     https://datatracker.ietf.org/doc/html/rfc8032
     Note: fd_ed25519 uses stricter signature malleability checks!

     RFC 7748: Elliptic Curves for Security
     https://datatracker.ietf.org/doc/html/rfc7748

     RFC 5288: AES Galois Counter Mode (GCM) Cipher Suites for TLS
     https://datatracker.ietf.org/doc/html/rfc5288 */

/* Callback functions */

typedef int
(* fd_tls_secrets_fn_t)( void const * handshake,
                         void const * recv_secret,
                         void const * send_secret,
                         int          encryption_level );

typedef int
(* fd_tls_sendmsg_fn_t)( void const * handshake,
                         void const * record,
                         ulong        record_sz,
                         int          encryption_level,
                         int          flush );

typedef void *
(* fd_tls_rand_fn_t)( void * buf,
                      ulong  bufsz );

/* Handshake state identifiers */

#define FD_TLS_HS_FAIL          (-1)
#define FD_TLS_HS_CONNECTED     (-2)
#define FD_TLS_HS_START         ( 0)
#define FD_TLS_HS_NEGOTIATED    ( 1)
#define FD_TLS_HS_WAIT_FLIGHT2  ( 2)
#define FD_TLS_HS_WAIT_CERT     ( 3)
#define FD_TLS_HS_WAIT_CV       ( 4)
#define FD_TLS_HS_WAIT_FINISHED ( 5)

/* TLS encryption levels */

#define FD_TLS_LEVEL_INITIAL     (0)
#define FD_TLS_LEVEL_EARLY       (1)
#define FD_TLS_LEVEL_HANDSHAKE   (2)
#define FD_TLS_LEVEL_APPLICATION (3)


/* The fd_tls_server_t object provides the server-side functionality
   of a TLS handshake. */

struct fd_tls_server {
  fd_tls_rand_fn_t    rand_fn;
  fd_tls_secrets_fn_t secrets_fn;
  fd_tls_sendmsg_fn_t sendmsg_fn;

  uchar kex_private_key[ 32 ];
  uchar kex_public_key [ 32 ];
};

typedef struct fd_tls_server fd_tls_server_t;

/* fd_tls_server_hs_t is an instance of the server-side TLS handshake
   state machine. */

struct fd_tls_server_hs {
  fd_sha256_t transcript;
  int         state;  /* FD_TLS_HS_{...} */
  uchar       master_secret[ 32 ];
};

typedef struct fd_tls_server_hs fd_tls_server_hs_t;

FD_PROTOTYPES_BEGIN

fd_tls_server_hs_t *
fd_tls_server_hs_new( void * mem );

/* fd_tls_server_recvmsg ingests a TLS record from the client.
   Progresses the TLS state machine. Synchronously dispatches callbacks.

   Returns 0L on success.  On failure, returns negated TLS alert code. */

long
fd_tls_server_handshake( fd_tls_server_t const * server,
                         fd_tls_server_hs_t *    handshake,
                         void const *            record,
                         ulong                   record_sz,
                         int                     encryption_level );

FD_PROTOTYPES_END

#endif /* HEADER_src_ballet_tls_fd_tls_h */
