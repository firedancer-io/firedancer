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
   (RPK) extension.  Minimal support for X.509 is included.  Client
   cert authentication is optional for fd_tls_client_t and mandatory
   for fd_tls_server_t.

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

/* Callbacks **********************************************************/

/* fd_tls_secrets_fn_t is called by fd_tls when new encryption secrets
   have been generated.  {recv/send}_secret are used for incoming/out-
   going data respectively and point to a 32-byte buffer valid for the
   lifetime of the function call.  This function is invoked for each
   new encryption_level, which is FD_TLS_LEVEL_{HANDSHAKE,APPLICATION}.
   It is safe to discard handshake-level decryption secrets after the
   handshake has been completed. */

typedef void
(* fd_tls_secrets_fn_t)( void const * handshake,
                         void const * recv_secret,
                         void const * send_secret,
                         uint         encryption_level );

/* fd_tls_sendmsg_fn_t is called by fd_tls to request transmission of a
   TLS message to the peer.  msg points to a buffer containing msg_sz
   message bytes.  The smallest message size is 4 bytes (the size of a
   message header).  encryption_level indicates which key to use.
   flush==0 when another message for the same conn will follow
   immediately on return.  flush==1 hints that no more sendmsg callbacks
   are issued until the next call to fd_tls_server_handshake.  It is
   safe to "flush" (i.e. transmit data out through the NIC) even when
   flush==0.  Returns 1 on success and 0 on failure. */

typedef int
(* fd_tls_sendmsg_fn_t)( void const * handshake,
                         void const * msg,
                         ulong        msg_sz,
                         uint         encryption_level,
                         int          flush );

/* fd_tls_quic_tp_self_fn_t is called by fd_tls to request QUIC
   transport params to be sent to the peer.  quic_tp points to the
   buffer that may hold serialized QUIC transport parameters (RFC
   Section 18). quic_tp_bufsz is the size of the buffer at quic_tp.
   Return value is actual serialized (<=quic_tp_bufsz) on success.
   On failure, returns (>quic_tp_bufsz) to indicate insufficient bufsz.
   (Zero implies success, however!) */

typedef ulong __attribute__((warn_unused_result))
(* fd_tls_quic_tp_self_fn_t)( void *  handshake,
                              uchar * quic_tp,
                              ulong   quic_tp_bufsz );

/* fd_tls_quic_tp_peer_fn_t is called by fd_tls to inform the user of
   the peer's QUIC transport params RFC.  quic_tp points to the
   serialized QUIC transport parameters (RFC 9000 Section 18).
   quic_tp_sz is the serialized size.  Lifetime of quic_tp buffer ends
   at return. fd_tls does not do any validation on the peer's QUIC TP --
   Please ensure your deserializer is robust given arbitrary data. */

typedef void
(* fd_tls_quic_tp_peer_fn_t)( void  *       handshake,
                              uchar const * quic_tp,
                              ulong         quic_tp_sz );

/* fd_tls_rand_vt_t is an abstraction for retrieving secure pseudorandom
   values.  When fd_tls needs random values, it calls fd_tls_rand_fn_t.

   ctx is an arbitrary pointer that is provided as a callback argument.
   buf points to a buffer of bufsz bytes that is to be filled with
   cryptographically secure randomness.  bufsz is usually 32 bytes.
   Assume buf is unaligned.  Returns buf on success and NULL on failure.

   Function must not block, but may synchronously pre-calculate a
   reasonable amount of data ahead of time.  NULL return value implies
   inability to keep up with demand for random values.  In this case,
   function should return NULL.  Function should minimize side effects
   (notably, should not log).

   TODO API considerations:
   - read() style error codes?
   - Buffering to reduce amount of virtual function calls? */

typedef void *
(* fd_tls_rand_fn_t)( void * ctx,
                      void * buf,
                      ulong  bufsz );

struct fd_tls_rand_vt {
  void *           ctx;
  fd_tls_rand_fn_t rand_fn;
};

typedef struct fd_tls_rand_vt fd_tls_rand_t;

static inline void *
fd_tls_rand( fd_tls_rand_t const * rand,
             void *                buf,
             ulong                 bufsz ) {
  return rand->rand_fn( rand->ctx, buf, bufsz );
}

/* Handshake state identifiers */

/* Server */
#define FD_TLS_HS_FAIL          ( 0)
#define FD_TLS_HS_CONNECTED     ( 1)
#define FD_TLS_HS_START         ( 2)
#define FD_TLS_HS_WAIT_CERT     ( 3)
#define FD_TLS_HS_WAIT_CV       ( 4)
#define FD_TLS_HS_WAIT_FINISHED ( 5)
/* Client */
#define FD_TLS_HS_WAIT_SH       ( 6)
#define FD_TLS_HS_WAIT_EE       ( 7)
#define FD_TLS_HS_WAIT_CERT_CR  ( 8)

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

/* FD_TLS_EXT_QUIC_PARAMS_SZ is the max permitted byte size of encoded
   QUIC transport parameters */

# define FD_TLS_EXT_QUIC_PARAMS_SZ_MAX (510UL)

/* Extended Alert Reasons *********************************************/

/* fd_tls-specific error codes to identify reasons for alerts.  These
   can help with debugging when the error cause is not evident by the
   alert itself. */

#define FD_TLS_REASON_NULL            ( 0)

#define FD_TLS_REASON_ILLEGAL_STATE   ( 1)  /* illegal hs state */
#define FD_TLS_REASON_SENDMSG_FAIL    ( 2)  /* sendmsg callback failed */
#define FD_TLS_REASON_WRONG_ENC_LVL   ( 3)  /* wrong encryption level */
#define FD_TLS_REASON_RAND_FAIL       ( 4)  /* rand fn failed */

#define FD_TLS_REASON_X25519_FAIL     ( 9)  /* fd_x25519_exchange failed */
#define FD_TLS_REASON_NO_X509         (10)  /* no X.509 cert installed */
#define FD_TLS_REASON_WRONG_PUBKEY    (11)  /* peer cert has different pubkey than expected */
#define FD_TLS_REASON_ED25519_FAIL    (12)  /* Ed25519 signature validation failed */

#define FD_TLS_REASON_CH_EXPECTED    (101)  /* wanted ClientHello, got another msg type */
#define FD_TLS_REASON_CH_PARSE       (103)  /* failed to parse ClientHello */
#define FD_TLS_REASON_CH_ENCODE      (104)  /* failed to encode ClientHello */
#define FD_TLS_REASON_CH_CRYPTO_NEG  (105)  /* ClientHello crypto negotiation failed */
#define FD_TLS_REASON_CH_NO_QUIC     (106)  /* Missing QUIC transport params in ClientHello */

#define FD_TLS_REASON_SH_EXPECTED    (201)  /* wanted ServerHello, got another msg type */
#define FD_TLS_REASON_SH_PARSE       (203)  /* failed to parse ServerHello */
#define FD_TLS_REASON_SH_ENCODE      (204)  /* failed to encode ServerHello */

#define FD_TLS_REASON_EE_NO_QUIC     (301)  /* Missing QUIC transport params in EncryptedExtensions */
#define FD_TLS_REASON_EE_EXPECTED    (302)  /* wanted EncryptedExtensions, got another msg type */
#define FD_TLS_REASON_EE_PARSE       (304)  /* failed to parse EncryptedExtensions */
#define FD_TLS_REASON_EE_ENCODE      (305)  /* failed to encode EncryptedExtensions */
#define FD_TLS_REASON_QUIC_TP_OVERSZ (306)  /* Buffer overflow in QUIC transport params callback */

#define FD_TLS_REASON_CV_EXPECTED    (401)  /* wanted CertificateVerify, got another msg type */
#define FD_TLS_REASON_CV_SIGALG      (402)  /* CertificateVerify sig is not Ed25519 */
#define FD_TLS_REASON_CV_PARSE       (404)  /* failed to parse CertificateVerify */
#define FD_TLS_REASON_CV_ENCODE      (405)  /* failed to encode CertificateVerify */

#define FD_TLS_REASON_CERT_CR_EXPECTED (501)  /* wanted Certificate or CertificateRequest, got another msg type */
#define FD_TLS_REASON_CERT_CR_PARSE    (503)  /* failed to parse Certificate or CertificateRequest */

#define FD_TLS_REASON_CERT_TYPE      (601)  /* unsupported certificate type */
#define FD_TLS_REASON_CERT_EXPECTED  (602)  /* wanted Certificate, got another msg type */
#define FD_TLS_REASON_CERT_PARSE     (604)  /* failed to parse Certificate */
#define FD_TLS_REASON_X509_PARSE     (605)  /* X.509 DER parse failed */
#define FD_TLS_REASON_SPKI_PARSE     (606)  /* Subject public key info parse failed */

#define FD_TLS_REASON_CERT_CHAIN_EMPTY    (701)  /* cert chain contains no certs */
#define FD_TLS_REASON_CERT_CHAIN_PARSE    (702)  /* failed to parse cert chain */

#define FD_TLS_REASON_FINI_PARSE     (901)  /* invalid Finished message */
#define FD_TLS_REASON_FINI_EXPECTED  (902)  /* wanted Finished, got another msg type */
#define FD_TLS_REASON_FINI_FAIL      (904)  /* Finished data mismatch */

#define FD_TLS_REASON_ALPN_PARSE     (1001)  /* failed to parse ALPN */
#define FD_TLS_REASON_ALPN_NEG       (1002)  /* ALPN negotiation failed */
#define FD_TLS_REASON_NO_ALPN        (1003)  /* no ALPN extension */

FD_PROTOTYPES_BEGIN

FD_FN_PURE char const *
fd_tls_alert_cstr( uint alert );

FD_FN_PURE char const *
fd_tls_reason_cstr( uint reason );

FD_PROTOTYPES_END

/* Transcripts ********************************************************/

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

/* fd_tls_hkdf_expand_label implements the TLS 1.3 HKDF-Expand function
   with SHA-256.  Writes the resulting hash to out.  secret is a 32 byte
   secret value.  label points to the label string.  label_sz is the
   number of chars in label (not including terminating NUL).  context
   points to the context byte array.  context_sz is the number of bytes
   in context.

   Constraints:

     out   !=NULL
     secret!=NULL
     label_sz  ==0 || label  !=NULL
     context_sz==0 || context!=NULL
     1<=out_sz    <=32
     0<=label_sz  <=64
     0<=context_sz<=64

   TODO this function should probably be in src/ballet */

void *
fd_tls_hkdf_expand_label( uchar         out[ 32 ],
                          ulong         out_sz,
                          uchar const   secret[ static 32 ],
                          char const *  label,
                          ulong         label_sz,
                          uchar const * context,
                          ulong         context_sz );

FD_PROTOTYPES_END

#endif /* HEADER_src_ballet_tls_fd_tls_h */
