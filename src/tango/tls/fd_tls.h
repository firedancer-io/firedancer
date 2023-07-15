#ifndef HEADER_src_ballet_tls_fd_tls_h
#define HEADER_src_ballet_tls_fd_tls_h

#include "../fd_tango_base.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "fd_tls_proto.h"

/* fd_tls implements a subset of the TLS v1.3 (RFC 8446) handshake
   protocol.

   fd_tls is not a general purpose TLS library.  It only provides the
   TLS components required to secure peer-to-peer QUIC connections as
   they appear in Solana network protocol.  Specifics are listed below.

   Older TLS versions, such as TLS v1.2, are not supported.

   ### Peer Authentication

   Peers are authenticated via Ed25519 using the TLS v1.3 raw public key
   (RPK) extension.  Minimal support for X.509 is included.

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

/* fd_tls_secrets_fn_t is called by fd_tls when new encryption secrets
   have been generated.  {recv/send}_secret are used for incoming/out-
   going data respectively and point to a 32-byte buffer valid for the
   lifetime of the function call.  This function is invoked for each
   new encryption_level, which is FD_TLS_LEVEL_{HANDSHAKE,APPLICATION}.
   It is safe to discard handshake-level decryption secrets after the
   handshake has been completed. */

typedef int
(* fd_tls_secrets_fn_t)( void const * handshake,
                         void const * recv_secret,
                         void const * send_secret,
                         int          encryption_level );

/* fd_tls_sendmsg_fn_t is called by fd_tls to request transmission of a
   TLS record to the peer.  record points to a buffer containing
   record_sz message bytes.  The smallest message size is 4 bytes (the
   size of a record header).  encryption_level indicates which key to
   use.  flush==0 when another message for the same conn will follow
   immediately on return.  flush==1 hints that no more sendmsg callbacks
   are issued until the next call to fd_tls_server_handshake.  It is
   safe to "flush" (i.e. transmit data out through the NIC) even when
   flush==0. */

typedef int
(* fd_tls_sendmsg_fn_t)( void const * handshake,
                         void const * record,
                         ulong        record_sz,
                         int          encryption_level,
                         int          flush );

/* fd_tls_rand_fn_t is called by fd_tls to request random bytes.
   TODO use thiscall convention */

typedef void *
(* fd_tls_rand_fn_t)( void * buf,
                      ulong  bufsz );

/* fd_tls_ext_fn_t allows the callee to add arbitrary TLS extensions.
   Return value is a NULL-terminated list.  Each list element points to
   a serialized extension (length is implied by the extension header).
   hs is the handshake object (fd_server_hs_t).  It is U.B. to return
   NULL or to provide an invalid serialization.
   TODO document length restrictions */

typedef void const * const *
(* fd_tls_ext_fn_t)( void * hs );

/* Handshake state identifiers */

#define FD_TLS_HS_FAIL          (-1)
#define FD_TLS_HS_CONNECTED     (-2)
#define FD_TLS_HS_START         ( 0)
#define FD_TLS_HS_WAIT_FLIGHT2  ( 2)
#define FD_TLS_HS_WAIT_CERT     ( 3)
#define FD_TLS_HS_WAIT_CV       ( 4)
#define FD_TLS_HS_WAIT_FINISHED ( 5)

/* TLS encryption levels */

#define FD_TLS_LEVEL_INITIAL     (0)
#define FD_TLS_LEVEL_EARLY       (1)
#define FD_TLS_LEVEL_HANDSHAKE   (2)
#define FD_TLS_LEVEL_APPLICATION (3)

/* FD_TLS_SERVER_CERT_SZ_MAX is the max permitted size of the DER-
   serialized X.509 server certificate. */

#define FD_TLS_SERVER_CERT_SZ_MAX (1011UL)

/* FD_TLS_SERVER_CERT_MSG_SZ_MAX is the max permitted size of the pre-
   buffered X.509 server certificate message. */

#define FD_TLS_SERVER_CERT_MSG_SZ_MAX (FD_TLS_SERVER_CERT_SZ_MAX+13UL)

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
     client   Finished              always

   TODO We can (and should) cheat and remove the pending SHA block
        buffer.  In the server case, we control the last few messages,
        so we can align the transcript preimage with a multiple of a
        SHA block size. */

struct fd_tls_transcript {
  uchar buf[ 64 ];  /* Pending SHA block */
  uint  sha[ 8 ];   /* Current internal SHA state */
  uint  len;        /* Number of bytes so far compressed into SHA state
                       plus number of bytes in pending in buf */
};

typedef struct fd_tls_transcript fd_tls_transcript_t;

/* The fd_tls_server_t object provides the server-side functionality
   of a TLS handshake. */

struct fd_tls_server {
  fd_tls_rand_fn_t    rand_fn;
  fd_tls_secrets_fn_t secrets_fn;
  fd_tls_sendmsg_fn_t sendmsg_fn;
  fd_tls_ext_fn_t     encrypted_exts_fn;

  uchar kex_private_key[ 32 ];
  uchar kex_public_key [ 32 ];

  uchar cert_private_key[ 32 ];
  uchar cert_public_key [ 32 ];

  /* Buffers storing the Certificate record.  This is not a simple copy
     of the cert but also contains TLS headers/footers.  Do not set
     directly. */
  uchar cert_x509[ FD_TLS_SERVER_CERT_MSG_SZ_MAX ];  /* set using fd_tls_server_set_x509 */
  ulong cert_x509_sz;
  /* TODO support raw public key */

  uchar alpn[ 32 ];
};

typedef struct fd_tls_server fd_tls_server_t;

/* fd_tls_server_hs_t is an instance of the server-side TLS handshake
   state machine.  This object is instantiated when the client sent its
   ClientHello, the first message of a TLS handshake.  Currently, only
   one in-flight state exists:

     FD_TLS_HS_WAIT_FINISHED:  Processed ClientHello.

       At this point, the server has responded with all messages up to
       server Finished and is waiting for the client to respond with
       with client Finished (and optionally, a certificate).

       FIXME When requesting a cert, the server should instead stop
             sending after CertificateVerify to save compute resources
             (at the expense of more memory required to save state
              carried over from CertificateRequest ... server Finished).

   A server might have to handle lots of concurrent connection attempts.
   To minimize memory usage, the handshake state only contains the info
   that a server needs to remember between function calls (i.e. when
   waiting for the client to respond).  Specifically, this is:

     The transcript hash state, which commits both sides to the entire
     sequence of handshake messages (such that they cannot be tampered
     with).

     The client handshake secret, which is used to derive the "client
     Finished" verify data. */

struct fd_tls_server_hs {
  char  state;  /* FD_TLS_HS_{...} */
  uchar server_cert_type : 2;
  uchar client_cert_type : 2;

  fd_tls_transcript_t transcript;
  uchar               client_hs_secret[32];
};

typedef struct fd_tls_server_hs fd_tls_server_hs_t;

FD_PROTOTYPES_BEGIN

ulong
fd_tls_server_align( void );

ulong
fd_tls_server_footprint( void );

void *
fd_tls_server_new( void * mem );

fd_tls_server_t *
fd_tls_server_join( void * );

void *
fd_tls_server_leave( fd_tls_server_t * );

void *
fd_tls_server_delete( void * );

/* fd_tls_server_hs_new initializes a handshake object.  mem points to a
   buffer suitable for storing an fd_tls_server_hs_t.  Returns cast of
   mem. */

fd_tls_server_hs_t *
fd_tls_server_hs_new( void * mem );

/* fd_tls_server_set_x509 sets the server certificate.  cert points to
   the first byte of the DER serialized X.509 certificate.  cert_sz is
   the serialized size.  Returns 1 on success and 0 on failure.  Reasons
   for failure include oversz cert. */

static inline int
fd_tls_server_set_x509( fd_tls_server_t * server,
                        void const *      cert,
                        ulong             cert_sz ) {

  long res = fd_tls_encode_server_cert_x509( cert, cert_sz, server->cert_x509, FD_TLS_SERVER_CERT_MSG_SZ_MAX );
  if( FD_UNLIKELY( res<0 ) ) return 0;
  server->cert_x509_sz = (ulong)res;
  return 1;
}

/* fd_tls_server_handshake ingests a TLS record from the client.
   Progresses the TLS state machine. Synchronously dispatches callbacks.

   Returns 0L on success.  On failure, returns negated TLS alert code. */

long
fd_tls_server_handshake( fd_tls_server_t const * server,
                         fd_tls_server_hs_t *    handshake,
                         void const *            record,
                         ulong                   record_sz,
                         int                     encryption_level );

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

#endif /* HEADER_src_ballet_tls_fd_tls_h */
