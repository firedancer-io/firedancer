#include "fd_tls_base.h"
#include "fd_tls.h"
#include "fd_tls_proto.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/ed25519/fd_x25519.h"
#include "../../ballet/hmac/fd_hmac.h"

#include <assert.h>

/* Pre-generated keys */

static char const fd_tls13_cli_sign_prefix[ 98 ] =
  "                                "  /* 32 spaces */
  "                                "  /* 32 spaces */
  "TLS 1.3, client CertificateVerify";

static char const fd_tls13_srv_sign_prefix[ 98 ] =
  "                                "  /* 32 spaces */
  "                                "  /* 32 spaces */
  "TLS 1.3, server CertificateVerify";

//uchar empty_hash[ 32 ];
//fd_sha256_hash( empty_hash, NULL, 0UL );
static uchar const empty_hash[ 32 ] =
  { 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55 };

//static uchar const psk[ 32 ] = {0};
//uchar early_secret[ 32 ];
//fd_hmac_sha256( /* data */ psk, 32UL,
//                /* salt */ NULL, 0UL,
//                early_secret );
//static uchar const early_secret[ 32 ] =
//  { 0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b,
//    0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68, 0x0c, 0xe2,
//    0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60,
//    0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a };

//uchar handshake_derived[ 32 ];
//fd_tls_hkdf_expand_label( handshake_derived,
//                          early_secret,
//                          "derived",   7UL,
//                          empty_hash, 32UL );
static uchar const handshake_derived[ 32 ] =
  { 0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5,
    0x67, 0x8f, 0x54, 0xfc, 0x9d, 0xba, 0xb6, 0x97,
    0x16, 0xc0, 0x76, 0x18, 0x9c, 0x48, 0x25, 0x0c,
    0xeb, 0xea, 0xc3, 0x57, 0x6c, 0x36, 0x11, 0xba };

/* fd_tls_t boilerplate */

ulong
fd_tls_align( void ) {
  return alignof(fd_tls_t);
}

ulong
fd_tls_footprint( void ) {
  return sizeof(fd_tls_t);
}

void *
fd_tls_new( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_tls_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }

  ulong fp = fd_tls_footprint();
  memset( mem, 0, fp );
  return mem;
}

fd_tls_t *
fd_tls_join( void * mem ) {
  return (fd_tls_t *)mem;
}

void *
fd_tls_leave( fd_tls_t * server ) {
  return (void *)server;
}

void *
fd_tls_delete( void * mem ) {
  return mem;
}

/* TODO create internal state machine and integrate Tango for
        accelerating cryptographic computations (e.g. FPGA sigverify) */

fd_tls_estate_srv_t *
fd_tls_estate_srv_new( void * mem ) {

  fd_tls_estate_srv_t * hs = mem;

  memset( hs, 0, sizeof(fd_tls_estate_srv_t) );
  hs->base.state  = FD_TLS_HS_START;
  hs->base.server = 1;

  return hs;
}

fd_tls_estate_cli_t *
fd_tls_estate_cli_new( void * mem ) {

  fd_tls_estate_cli_t * hs = mem;

  memset( hs, 0, sizeof(fd_tls_estate_cli_t) );
  hs->base.state = FD_TLS_HS_START;

  return hs;
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
     0<=label_sz  <=64
     0<=context_sz<=64 */

static void *
fd_tls_hkdf_expand_label( uchar         out[ static 32 ],
                          uchar const   secret[ static 32 ],
                          char const *  label,
                          ulong         label_sz,
                          uchar const * context,
                          ulong         context_sz ) {

# define LABEL_BUFSZ (64UL)
  FD_TEST( label_sz  <=LABEL_BUFSZ );
  FD_TEST( context_sz<=LABEL_BUFSZ );

  /* Create HKDF info */
  uchar info[ 2+1+6+LABEL_BUFSZ+1+LABEL_BUFSZ+1 ];
  ulong info_sz = 0UL;

  /* Length of hash output (hardcoded to be 32) */
  info[0]=0; info[1]=32;
  info_sz += 2UL;

  /* Length prefix of label */
  info[ info_sz ] = (uchar)( 6UL + label_sz );
  info_sz += 1UL;

  /* Label */
  memcpy( info+info_sz, "tls13 ", 6UL );
  info_sz += 6UL;
  memcpy( info+info_sz, label, label_sz );
  info_sz += label_sz;

  /* Length prefix of context */
  info[ info_sz ] = (uchar)( context_sz );
  info_sz += 1UL;

  /* Context */
  fd_memcpy( info+info_sz, context, context_sz );
  info_sz += context_sz;

  /* HKDF-Expand suffix */
  info[ info_sz ] = 0x01;
  info_sz += 1UL;

  /* Compute result of HKDF-Expand-Label */
  fd_hmac_sha256( info, info_sz, secret, 32UL, out );
  return out;
# undef LABEL_BUFSZ
}

/* fd_tls_alert is a convenience function for setting a handshake
   failure alert and reason code. */

static inline long __attribute__((warn_unused_result))
fd_tls_alert( fd_tls_estate_base_t * hs,
              uint                   alert,
              ushort                 reason ) {
  hs->reason = reason;
  return -(long)alert;
}

/* fd_tls_send_cert_verify generates and sends a CertificateVerify
   message.  Returns 0L on success and negated TLS alert number on
   failure.  this is the local client or server object.  hs is the
   local handshake object.  transcript is the SHA state of the
   transcript hasher immediately preceding the CertificateVerify (where
   last entry is Certificate).  is_client is 1 if the local role is a
   client, 0 otherwise. */

static long
fd_tls_send_cert_verify( fd_tls_t const *       this,
                         fd_tls_estate_base_t * hs,
                         fd_sha256_t *          transcript,
                         int                    is_client ) {

  /* Export current transcript hash
     And create message to be signed */

  uchar sign_msg[ 130 ];
  fd_memcpy( sign_msg,
             is_client ? fd_tls13_cli_sign_prefix : fd_tls13_srv_sign_prefix,
             98UL );

  fd_sha256_t transcript_clone = *transcript;
  fd_sha256_fini( &transcript_clone, sign_msg+98 );

  /* Sign certificate */

  fd_sha512_t sha512;
  uchar cert_verify_sig[ 64UL ];
  fd_ed25519_sign( cert_verify_sig,
                   sign_msg, 130UL,
                   this->cert_public_key,
                   this->cert_private_key,
                   &sha512 );

  /* Create CertificateVerify record */

# define MSG_BUFSZ (512UL)
  uchar msg_buf[ MSG_BUFSZ ];

  ulong cv_sz;

  do {
    uchar *       wire     = msg_buf;
    uchar * const wire_end = msg_buf + MSG_BUFSZ;

    /* Leave space for record header */

    void * hdr_ptr = wire;
    wire += sizeof(fd_tls_record_hdr_t);
    fd_tls_record_hdr_t hdr = { .type = FD_TLS_RECORD_CERT_VERIFY };

    /* Construct CertificateVerify */

    fd_tls_cert_verify_t cv = {
      .sig_alg = FD_TLS_SIGNATURE_ED25519
    };
    fd_memcpy( cv.sig, cert_verify_sig, 64UL );

    /* Encode CertificateVerify */

    long encode_res = fd_tls_encode_cert_verify( &cv, wire, (ulong)(wire_end-wire) );
    if( FD_UNLIKELY( encode_res<0L ) )
      return fd_tls_alert( hs, (uint)(-encode_res), FD_TLS_REASON_CV_ENCODE );
    wire += (ulong)encode_res;

    hdr.sz = fd_uint_to_tls_u24( (uint)encode_res );
    fd_tls_encode_record_hdr( &hdr, hdr_ptr, sizeof(fd_tls_record_hdr_t) );
    cv_sz = (ulong)(wire - msg_buf);
  } while(0);

  /* Send CertificateVerify record */

  if( FD_UNLIKELY( !this->sendmsg_fn(
        hs,
        msg_buf, cv_sz,
        FD_TLS_LEVEL_HANDSHAKE,
        /* flush */ 0 ) ) )
    return fd_tls_alert( hs, FD_TLS_ALERT_INTERNAL_ERROR, FD_TLS_REASON_SENDMSG_FAIL );

  /* Record CertificateVerify in transcript hash */

  fd_sha256_append( transcript, msg_buf, cv_sz );

# undef MSG_BUFSZ
  return 0L;
}

static long fd_tls_server_hs_start           ( fd_tls_t const *, fd_tls_estate_srv_t *, uchar const *, ulong, uint );
static long fd_tls_server_hs_wait_cert       ( fd_tls_t const *, fd_tls_estate_srv_t *, uchar const *, ulong, uint );
static long fd_tls_server_hs_wait_cert_verify( fd_tls_t const *, fd_tls_estate_srv_t *, uchar const *, ulong, uint );
static long fd_tls_server_hs_wait_finished   ( fd_tls_t const *, fd_tls_estate_srv_t *, uchar const *, ulong, uint );

long
fd_tls_server_handshake( fd_tls_t const *      server,
                         fd_tls_estate_srv_t * handshake,
                         void const *          record,
                         ulong                 record_sz,
                         uint                  encryption_level ) {
  switch( handshake->base.state ) {
  case FD_TLS_HS_START:
    return fd_tls_server_hs_start           ( server, handshake, record, record_sz, encryption_level );
  case FD_TLS_HS_WAIT_CERT:
    return fd_tls_server_hs_wait_cert       ( server, handshake, record, record_sz, encryption_level );
  case FD_TLS_HS_WAIT_CV:
    return fd_tls_server_hs_wait_cert_verify( server, handshake, record, record_sz, encryption_level );
  case FD_TLS_HS_WAIT_FINISHED:
    return fd_tls_server_hs_wait_finished   ( server, handshake, record, record_sz, encryption_level );
  default:
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_INTERNAL_ERROR, FD_TLS_REASON_ILLEGAL_STATE );
  }
}

/* fd_tls_server_hs_start is invoked in response to the initial
   ClientHello.  We send back several messages in response, including
   - the ServerHello, completing cryptographic negotiation
   - EncryptedExtensions, for further handshake data
   - Finished, completing the server's handshake message sequence */

static long
fd_tls_server_hs_start( fd_tls_t const *      const server,
                        fd_tls_estate_srv_t * const handshake,
                        uchar const *         const record,
                        ulong                       record_sz,
                        uint                        encryption_level ) {

  /* Request QUIC transport params */
  uchar quic_tp[ FD_TLS_EXT_QUIC_PARAMS_SZ_MAX ];
  long  quic_tp_sz = -1L;
  if( server->quic )
    quic_tp_sz = (long)server->quic_tp_self_fn( handshake, quic_tp, FD_TLS_EXT_QUIC_PARAMS_SZ_MAX );
  if( FD_UNLIKELY( quic_tp_sz > (long)FD_TLS_EXT_QUIC_PARAMS_SZ_MAX ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_QUIC_TP_OVERSZ );

  if( FD_UNLIKELY( encryption_level != FD_TLS_LEVEL_INITIAL ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_INTERNAL_ERROR, FD_TLS_REASON_WRONG_ENC_LVL );

  /* Message buffer */
# define MSG_BUFSZ 512UL
  uchar msg_buf[ MSG_BUFSZ ];

  /* Transcript hasher */
  fd_sha256_t transcript; fd_sha256_init( &transcript );

  /* Read client hello ************************************************/

  fd_tls_client_hello_t ch = {0};

  do {
    uchar const *       wire     = record;
    uchar const * const wire_end = record + record_sz;

    /* Decode record header */

    fd_tls_record_hdr_t record_hdr = {0};
    long decode_res = fd_tls_decode_record_hdr( &record_hdr, wire, (ulong)(wire_end-wire) );
    if( FD_UNLIKELY( decode_res<0L ) )
      return fd_tls_alert( &handshake->base, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_CH_PARSE );
    wire += (ulong)decode_res;

    if( FD_UNLIKELY( record_hdr.type != FD_TLS_RECORD_CLIENT_HELLO ) )
      return fd_tls_alert( &handshake->base, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_CH_EXPECTED );

    /* Decode Client Hello */

    decode_res = fd_tls_decode_client_hello( &ch, wire, (ulong)(wire_end-wire) );
    if( FD_UNLIKELY( decode_res<0L ) )
      return fd_tls_alert( &handshake->base, (uint)(-decode_res), FD_TLS_REASON_CH_PARSE );
    wire += (ulong)decode_res;

    /* Fail if trailing bytes detected */

    if( FD_UNLIKELY( wire!=wire_end ) )
      return fd_tls_alert( &handshake->base, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_CH_TRAILING );
  } while(0);

  /* Check for cryptographic compatibility */

  if( FD_UNLIKELY( ( !ch.supported_versions.tls13         )
                 | ( !ch.supported_groups.x25519          )
                 | ( !ch.signature_algorithms.ed25519     )
                 | ( !ch.cipher_suites.aes_128_gcm_sha256 ) ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_HANDSHAKE_FAILURE, FD_TLS_REASON_CH_CRYPTO_NEG );

  /* Remember client random for SSLKEYLOGFILE */
  fd_memcpy( handshake->base.client_random, ch.random, 32UL );

  /* Detect QUIC */

  if( server->quic ) {
    /* QUIC transport parameters are mandatory in QUIC mode */
    if( FD_UNLIKELY( !ch.quic_tp.buf ) )
      return fd_tls_alert( &handshake->base, FD_TLS_ALERT_MISSING_EXTENSION, FD_TLS_REASON_CH_NO_QUIC );

    /* Remember that this is a QUIC-TLS handshake */
    handshake->base.quic = 1;
    /* Inform user of peer's QUIC transport parameters */
    server->quic_tp_peer_fn( handshake, ch.quic_tp.buf, ch.quic_tp.bufsz );
  }

  /* TODO check whether ALPN string contains our requested protocol */

  /* Record client hello in transcript hash */

  fd_sha256_append( &transcript, record, record_sz );

  /* Respond with server hello ****************************************/

  /* Create server random */

  uchar server_random[ 32 ];
  if( FD_UNLIKELY( !fd_tls_rand( &server->rand, server_random, 32UL ) ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_HANDSHAKE_FAILURE, FD_TLS_REASON_RAND_FAIL );

  /* Create server hello record */

  ulong server_hello_sz;

  do {
    uchar *       wire     = msg_buf;
    uchar * const wire_end = msg_buf + MSG_BUFSZ;

    /* Leave space for record header */

    void * hdr_ptr = wire;
    wire += sizeof(fd_tls_record_hdr_t);
    fd_tls_record_hdr_t hdr = { .type = FD_TLS_RECORD_SERVER_HELLO };

    /* Construct server hello */

    fd_tls_server_hello_t sh = {
      .cipher_suite = FD_TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
      .key_share    = { .has_x25519 = 1 },
    };
    memcpy( sh.random,           server_random,          32UL );
    memcpy( sh.key_share.x25519, server->kex_public_key, 32UL );

    /* Encode server hello */

    long encode_res = fd_tls_encode_server_hello( &sh, wire, (ulong)(wire_end-wire) );
    if( FD_UNLIKELY( encode_res<0L ) )
      return fd_tls_alert( &handshake->base, (uint)(-encode_res), FD_TLS_REASON_SH_ENCODE );
    wire += (ulong)encode_res;

    hdr.sz = fd_uint_to_tls_u24( (uint)encode_res );
    fd_tls_encode_record_hdr( &hdr, hdr_ptr, sizeof(fd_tls_record_hdr_t) );
    server_hello_sz = (ulong)(wire - msg_buf);
  } while(0);

  /* Call back with server hello */

  if( FD_UNLIKELY( !server->sendmsg_fn(
        handshake,
        msg_buf, server_hello_sz,
        FD_TLS_LEVEL_INITIAL,
        /* flush */ 0 ) ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_INTERNAL_ERROR, FD_TLS_REASON_SENDMSG_FAIL );

  /* Derive handshake secrets *****************************************/

  /* Record server hello in transcript hash */

  fd_sha256_append( &transcript, msg_buf, server_hello_sz );

  /* Export handshake transcript hash */

  fd_sha256_t transcript_clone = transcript;
  uchar transcript_hash[ 32 ];
  fd_sha256_fini( &transcript_clone, transcript_hash );

  /* Derive ECDH input key material */

  uchar _ecdh_ikm[ 32 ];
  void * ecdh_ikm = fd_x25519_exchange( _ecdh_ikm,
                                        server->kex_private_key,
                                        ch.key_share.x25519 );
  if( FD_UNLIKELY( !ecdh_ikm ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_HANDSHAKE_FAILURE, FD_TLS_REASON_X25519_FAIL );

  /* Derive main handshake secret */

  uchar handshake_secret[ 32 ];
  fd_hmac_sha256( /* data */ ecdh_ikm,          32UL,
                  /* salt */ handshake_derived, 32UL,
                  /* out  */ handshake_secret );

  /* Derive client/server handshake secrets */

  uchar client_hs_secret[ 32UL ];
  fd_tls_hkdf_expand_label( client_hs_secret,
                            handshake_secret,
                            "c hs traffic",  12UL,
                            transcript_hash, 32UL );
  memcpy( handshake->client_hs_secret, client_hs_secret, 32UL );

  uchar server_hs_secret[ 32UL ];
  fd_tls_hkdf_expand_label( server_hs_secret,
                            handshake_secret,
                            "s hs traffic",  12UL,
                            transcript_hash, 32UL );

  /* Call back with handshake secrets */

  server->secrets_fn( handshake,
                      /* read secret  */ client_hs_secret,
                      /* write secret */ server_hs_secret,
                      FD_TLS_LEVEL_HANDSHAKE );

  /* Derive master secret */

  uchar master_derive[ 32 ];
  fd_tls_hkdf_expand_label( master_derive,
                            handshake_secret,
                            "derived",   7UL,
                            empty_hash, 32UL );

  static uchar const zeros[ 32 ] = {0};
  uchar master_secret[ 32 ];
  fd_hmac_sha256( /* data */ zeros,         32UL,
                  /* salt */ master_derive, 32UL,
                  /* out  */ master_secret );

  /* Send EncryptedExtensions (EE) record *****************************/

  ulong server_ee_sz;

  do {
    uchar *       wire     = msg_buf;
    uchar * const wire_end = msg_buf + MSG_BUFSZ;

    /* Leave space for record header */

    void * hdr_ptr = wire;
    wire += sizeof(fd_tls_record_hdr_t);
    fd_tls_record_hdr_t hdr = { .type = FD_TLS_RECORD_ENCRYPTED_EXT };

    ushort * ext_sz_ptr = (ushort *)wire;
    wire += sizeof(ushort);

    /* Construct encrypted extensions */

    fd_tls_enc_ext_t ee = {
      .quic_tp = {
        .buf   = (quic_tp_sz>=0L) ? quic_tp : NULL,
        .bufsz = (ushort)quic_tp_sz,
      }
    };

    if( server->alpn_sz > sizeof(ee.alpn) )
      return fd_tls_alert( &handshake->base, FD_TLS_ALERT_INTERNAL_ERROR, FD_TLS_REASON_ALPN_OVERSZ );
    fd_memcpy( ee.alpn, server->alpn, server->alpn_sz );
    ee.alpn_sz = (uchar)server->alpn_sz;

    /* Negotiate raw public keys if available */

    if( ch.server_cert_types.raw_pubkey ) {
      handshake->server_cert_rpk = 1;
      ee.server_cert.cert_type   = FD_TLS_CERTTYPE_RAW_PUBKEY;
    } else if( !server->cert_x509_sz ) {
      /* If server lacks an X.509 certificate and client does not support
        raw public keys, abort early. */
      return fd_tls_alert( &handshake->base, FD_TLS_ALERT_UNSUPPORTED_CERTIFICATE, FD_TLS_REASON_NO_X509 );
    }

    if( ch.client_cert_types.raw_pubkey ) {
      handshake->client_cert_rpk = 1;
      ee.client_cert.cert_type   = FD_TLS_CERTTYPE_RAW_PUBKEY;
    }

    /* Encode encrypted extensions */

    long encode_res = fd_tls_encode_enc_ext( &ee, wire, (ulong)(wire_end-wire) );
    if( FD_UNLIKELY( encode_res<0L ) )
      return fd_tls_alert( &handshake->base, (uint)(-encode_res), FD_TLS_REASON_EE_ENCODE );
    wire += (ulong)encode_res;

    *ext_sz_ptr = (ushort)fd_ushort_bswap( (ushort)encode_res );
    hdr.sz = fd_uint_to_tls_u24( (uint)encode_res + (uint)sizeof(ushort) );
    fd_tls_encode_record_hdr( &hdr, hdr_ptr, 4UL );
    server_ee_sz = (ulong)(wire - msg_buf);
  } while(0);

  /* Call back with EE */

  if( FD_UNLIKELY( !server->sendmsg_fn(
        handshake,
        msg_buf, server_ee_sz,
        FD_TLS_LEVEL_HANDSHAKE,
        /* flush */ 0 ) ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_INTERNAL_ERROR, FD_TLS_REASON_SENDMSG_FAIL );

  /* Record EE in transcript hash */

  fd_sha256_append( &transcript, msg_buf, server_ee_sz );

  /* Send CertificateRequest ******************************************/

  static uchar const cert_req[] = {
    FD_TLS_RECORD_CERT_REQ,  /* record_type */
    0x00, 0x00, 0x0b,        /* record_sz */
    0x00,                    /* certificate_request_context */
    0x00, 0x08,              /* extensions length prefix */
    0x00, FD_TLS_EXT_SIGNATURE_ALGORITHMS,
                             /* ext type */
    0x00, 0x04,              /* ext sz */
    0x00, 0x02,              /* sigalg sz */
    0x08, 0x07,              /* Ed25519 */
  };

  if( FD_UNLIKELY( !server->sendmsg_fn(
        handshake,
        cert_req, sizeof(cert_req),
        FD_TLS_LEVEL_HANDSHAKE,
        /* flush */ 0 ) ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_INTERNAL_ERROR, FD_TLS_REASON_SENDMSG_FAIL );

  /* Record CertificateRequest in transcript hash */

  fd_sha256_append( &transcript, cert_req, sizeof(cert_req) );

  /* Send Certificate *************************************************/

  void const * cert_msg;
  ulong        cert_msg_sz;

  if( ch.server_cert_types.raw_pubkey ) {
    long sz = fd_tls_encode_raw_public_key( server->cert_public_key, msg_buf, MSG_BUFSZ );
    FD_TEST( sz>=0L );
    cert_msg    = msg_buf;
    cert_msg_sz = (ulong)sz;
  } else {
    /* Send pre-prepared X.509 Certificate message */
    cert_msg    = server->cert_x509;
    cert_msg_sz = server->cert_x509_sz;
  }

  /* Send certificate message */

  if( FD_UNLIKELY( !server->sendmsg_fn(
        handshake,
        cert_msg, cert_msg_sz,
        FD_TLS_LEVEL_HANDSHAKE,
        /* flush */ 0 ) ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_INTERNAL_ERROR, FD_TLS_REASON_SENDMSG_FAIL );

  /* Record Certificate record in transcript hash */

  fd_sha256_append( &transcript, cert_msg, cert_msg_sz );

  /* Send CertificateVerify *******************************************/

  long cvfy_res = fd_tls_send_cert_verify( server, &handshake->base, &transcript, 0 );
  if( FD_UNLIKELY( !!cvfy_res ) ) return cvfy_res;
  /* CertificateVerify already included in transcript hash */

  /* Send Finished ****************************************************/

  /* Create static size message layout */

  struct __attribute__((packed)) {
    fd_tls_record_hdr_t hdr;
    fd_tls_finished_t   fin;
  } fin_rec;
  fin_rec.hdr = (fd_tls_record_hdr_t){
    .type = FD_TLS_RECORD_FINISHED,
    .sz   = fd_uint_to_tls_u24( 0x20 )
  };
  fd_tls_record_hdr_bswap( &fin_rec.hdr );
  fd_tls_finished_bswap( &fin_rec.fin );

  /* Export transcript hash ClientHello..CertificateVerify */

  transcript_clone = transcript;
  fd_sha256_fini( &transcript_clone, transcript_hash );

  /* Derive "Finished" key */

  uchar finished_key[ 32 ];
  fd_tls_hkdf_expand_label( finished_key,
                            server_hs_secret,
                            "finished", 8UL,
                            NULL,       0UL );

  /* Derive "Finished" verify data */

  fd_hmac_sha256( /* data */ transcript_hash, 32UL,
                  /* salt */ finished_key,    32UL,
                  /* out  */ fin_rec.fin.verify );

  /* Send Finished record */

  if( FD_UNLIKELY( !server->sendmsg_fn(
        handshake,
        &fin_rec, sizeof(fin_rec),
        FD_TLS_LEVEL_HANDSHAKE,
        /* flush */ 1 ) ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_INTERNAL_ERROR, FD_TLS_REASON_SENDMSG_FAIL );

  /* Record Finished in transcript hash */

  fd_sha256_append( &transcript,
                    &fin_rec, sizeof(fin_rec) );

  /* Derive application secrets ***************************************/

  /* Export transcript hash ClientHello..ServerFinished */

  transcript_clone = transcript;
  fd_sha256_fini( &transcript_clone, transcript_hash );

  /* Derive client/server application secrets */

  uchar client_app_secret[ 32UL ];
  fd_tls_hkdf_expand_label( client_app_secret,
                            master_secret,
                            "c ap traffic",  12UL,
                            transcript_hash, 32UL );

  uchar server_app_secret[ 32UL ];
  fd_tls_hkdf_expand_label( server_app_secret,
                            master_secret,
                            "s ap traffic",  12UL,
                            transcript_hash, 32UL );

  /* Call back with application secrets */

  server->secrets_fn( handshake,
                      /* read secret  */ client_app_secret,
                      /* write secret */ server_app_secret,
                      FD_TLS_LEVEL_APPLICATION );

  /* Finish up ********************************************************/

  /* Store transcript hash state */

  fd_tls_transcript_store( &handshake->transcript, &transcript );

  /* Done */

  handshake->base.state = FD_TLS_HS_WAIT_CERT;

# undef MSG_BUFSZ
  return 0L;
}

static long
fd_tls_handle_cert_chain( fd_tls_estate_base_t * const base,
                          uchar const *          const cert_chain,
                          ulong                  const cert_chain_sz,
                          uchar const *          const expected_pubkey,
                          uchar *                const out_pubkey,
                          int                    const is_rpk ) {

  fd_tls_extract_cert_pubkey_res_t extract =
  fd_tls_extract_cert_pubkey( cert_chain, cert_chain_sz, fd_uint_if( is_rpk, FD_TLS_CERTTYPE_RAW_PUBKEY, FD_TLS_CERTTYPE_X509 ) );

  if( FD_UNLIKELY( !extract.pubkey ) )
    return fd_tls_alert( base, extract.alert, extract.reason );

  if( expected_pubkey )
    if( FD_UNLIKELY( 0!=memcmp( extract.pubkey, expected_pubkey, 32UL ) ) )
      return fd_tls_alert( base, FD_TLS_ALERT_HANDSHAKE_FAILURE, FD_TLS_REASON_WRONG_PUBKEY );
  if( out_pubkey )
    fd_memcpy( out_pubkey, extract.pubkey, 32UL );

  /* Skip extensions */
  /* Skip remaining certificate chain */

  return (long)cert_chain_sz;
}

static long
fd_tls_handle_cert_verify( fd_tls_estate_base_t * hs,
                           fd_sha256_t const *    transcript,
                           uchar const *          record,
                           ulong                  record_sz,
                           uchar const            pubkey[ static 32 ],
                           int                    is_client ) {

  /* Read CertificateVerify *******************************************/

  fd_tls_cert_verify_t vfy[1] = {{0}};

  do {
    uchar const *       wire     = record;
    uchar const * const wire_end = record + record_sz;

    /* Decode record header */

    fd_tls_record_hdr_t record_hdr = {0};
    long decode_res = fd_tls_decode_record_hdr( &record_hdr, wire, (ulong)(wire_end-wire) );
    if( FD_UNLIKELY( ( decode_res<0L ) |
                     ( fd_tls_u24_to_uint( record_hdr.sz ) != 0x44UL ) ) )
      return fd_tls_alert( hs, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_CV_PARSE );
    wire += (ulong)decode_res;

    if( FD_UNLIKELY( record_hdr.type != FD_TLS_RECORD_CERT_VERIFY ) )
      return fd_tls_alert( hs, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_CV_EXPECTED );

    /* Decode CertificateVerify */

    decode_res = fd_tls_decode_cert_verify( vfy, wire, (ulong)(wire_end-wire) );
    if( FD_UNLIKELY( decode_res<0L ) )
      return fd_tls_alert( hs, (uint)(-decode_res), FD_TLS_REASON_CV_PARSE );
    wire += (ulong)decode_res;

    /* Fail if trailing bytes detected */

    if( FD_UNLIKELY( wire!=wire_end ) )
      return fd_tls_alert( hs, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_CV_TRAILING );
  } while(0);

  if( FD_UNLIKELY( vfy->sig_alg != FD_TLS_SIGNATURE_ED25519 ) )
    return fd_tls_alert( hs, FD_TLS_ALERT_HANDSHAKE_FAILURE, FD_TLS_REASON_CV_SIGALG );

  /* Verify signature *************************************************/

  /* Export transcript hash ClientHello..server Certificate
     And recover message that was signed */

  uchar sign_msg[ 130 ];
  fd_memcpy( sign_msg,
             is_client ? fd_tls13_cli_sign_prefix : fd_tls13_srv_sign_prefix,
             98UL );

  fd_sha256_t transcript_clone = *transcript;
  fd_sha256_fini( &transcript_clone, sign_msg+98 );

  /* Verify certificate signature
     > If the verification fails, the receiver MUST terminate the handshake
     > with a "decrypt_error" alert. */

  fd_sha512_t sha512[1];
  int sig_err = fd_ed25519_verify( sign_msg, 130UL, vfy->sig, pubkey, sha512 );
  if( FD_UNLIKELY( sig_err != FD_ED25519_SUCCESS ) )
    return fd_tls_alert( hs, FD_TLS_ALERT_DECRYPT_ERROR, FD_TLS_REASON_ED25519_FAIL );

  return 0L;
}

static long
fd_tls_server_hs_wait_cert( fd_tls_t const *      server,
                            fd_tls_estate_srv_t * handshake,
                            uchar const *   const record,
                            ulong           const record_sz,
                            uint                  encryption_level ) {

  (void)server;

  if( FD_UNLIKELY( encryption_level != FD_TLS_LEVEL_HANDSHAKE ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_INTERNAL_ERROR, FD_TLS_REASON_WRONG_ENC_LVL );

  fd_sha256_t transcript;
  fd_tls_transcript_load( &handshake->transcript, &transcript );
  fd_sha256_append( &transcript, record, record_sz );
  fd_tls_transcript_store( &handshake->transcript, &transcript );

  /* Decode incoming client Certificate *******************************/

  fd_tls_record_hdr_t hdr[1] = {{0}};
  if( FD_UNLIKELY( fd_tls_decode_record_hdr( hdr, record, record_sz )<0L ) )
    return -(long)FD_TLS_ALERT_DECODE_ERROR;
  if( FD_UNLIKELY( hdr->type != FD_TLS_RECORD_CERT ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_CERT_EXPECTED );

  long res = fd_tls_handle_cert_chain( &handshake->base, (uchar *)record+4, record_sz-4, NULL, handshake->client_pubkey, handshake->client_cert_rpk );
  if( FD_UNLIKELY( res<0L ) ) return res;

  /* Finish up ********************************************************/

  handshake->base.state = FD_TLS_HS_WAIT_CV;
  return 0L;
}

static long
fd_tls_server_hs_wait_cert_verify( fd_tls_t const *      server,
                                   fd_tls_estate_srv_t * hs,
                                   uchar const *   const record,
                                   ulong           const record_sz,
                                   uint                  encryption_level ) {

  (void)server;

  if( FD_UNLIKELY( encryption_level != FD_TLS_LEVEL_HANDSHAKE ) )
    return fd_tls_alert( &hs->base, FD_TLS_ALERT_INTERNAL_ERROR, FD_TLS_REASON_WRONG_ENC_LVL );

  fd_sha256_t transcript;
  fd_tls_transcript_load( &hs->transcript, &transcript );
  fd_sha256_t transcript_clone = transcript;
  fd_sha256_append( &transcript, record, record_sz );
  fd_tls_transcript_store( &hs->transcript, &transcript );

  /* Decode incoming client CertificateVerify *************************/

  long res = fd_tls_handle_cert_verify( &hs->base, &transcript_clone, record, record_sz, hs->client_pubkey, 1 );
  if( FD_UNLIKELY( res<0L ) ) return res;

  /* Finish up ********************************************************/

  hs->base.state = FD_TLS_HS_WAIT_FINISHED;
  return 0L;
}

static long
fd_tls_server_hs_wait_finished( fd_tls_t const *      server,
                                fd_tls_estate_srv_t * handshake,
                                uchar const *   const record,
                                ulong           const record_sz,
                                uint                  encryption_level )  {

  (void)server;

  if( FD_UNLIKELY( encryption_level != FD_TLS_LEVEL_HANDSHAKE ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_INTERNAL_ERROR, FD_TLS_REASON_WRONG_ENC_LVL );

  /* Restore state ****************************************************/

  fd_sha256_t transcript;
  fd_tls_transcript_load( &handshake->transcript, &transcript );

  /* Decode incoming client "Finished" message ************************/

  if( FD_UNLIKELY( record_sz!=0x24 ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_FINI_PARSE );

  fd_tls_record_hdr_t hdr[1] = {{0}};
  if( FD_UNLIKELY( fd_tls_decode_record_hdr( hdr, record, record_sz )<0L ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_FINI_PARSE );

  if( FD_UNLIKELY( ( hdr->type != FD_TLS_RECORD_FINISHED )
                 | ( fd_tls_u24_to_uint( hdr->sz )!=0x20 ) ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_FINI_PARSE );

  fd_tls_finished_t finished = {0};
  if( FD_UNLIKELY( fd_tls_decode_finished( &finished, (uchar const *)record+4, 0x20UL )<0L ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_FINI_PARSE );

  /* Check "Finished" verify data *************************************/

  /* Export transcript hash */

  uchar transcript_hash[ 32 ];
  fd_sha256_fini( &transcript, transcript_hash );

  /* Derive "Finished" key */

  uchar finished_key[ 32 ];
  fd_tls_hkdf_expand_label( finished_key,
                            handshake->client_hs_secret,
                            "finished", 8UL,
                            NULL,       0UL );

  /* Derive "Finished" verify data */

  uchar finished_expected[ 32 ];
  fd_hmac_sha256( /* data */ transcript_hash, 32UL,
                  /* salt */ finished_key,    32UL,
                  /* out  */ finished_expected );

  /* Verify that client and server's transcripts match */

  int match = 0;
  for( ulong i=0; i<32UL; i++ )
    match |= finished.verify[i] ^ finished_expected[i];
  if( FD_UNLIKELY( match!=0 ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_DECRYPT_ERROR, FD_TLS_REASON_FINI_FAIL );

  /* Done */

  handshake->base.state = FD_TLS_HS_CONNECTED;
  return 0L;
}

static long fd_tls_client_hs_start           ( fd_tls_t const *, fd_tls_estate_cli_t *                             );
static long fd_tls_client_hs_wait_sh         ( fd_tls_t const *, fd_tls_estate_cli_t *, uchar const *, ulong, uint );
static long fd_tls_client_hs_wait_ee         ( fd_tls_t const *, fd_tls_estate_cli_t *, uchar const *, ulong, uint );
static long fd_tls_client_hs_wait_cert_cr    ( fd_tls_t const *, fd_tls_estate_cli_t *, uchar const *, ulong, uint );
static long fd_tls_client_hs_wait_cert       ( fd_tls_t const *, fd_tls_estate_cli_t *, uchar const *, ulong, uint );
static long fd_tls_client_hs_wait_cert_verify( fd_tls_t const *, fd_tls_estate_cli_t *, uchar const *, ulong, uint );
static long fd_tls_client_hs_wait_finished   ( fd_tls_t const *, fd_tls_estate_cli_t *, uchar const *, ulong, uint );

long
fd_tls_client_handshake( fd_tls_t const *      client,
                         fd_tls_estate_cli_t * handshake,
                         void *                record,
                         ulong                 record_sz,
                         uint                  encryption_level ) {
  switch( handshake->base.state ) {
  case FD_TLS_HS_START:
    /* Record argument is ignored, since ClientHello is always the first record */
    (void)record; (void)record_sz; (void)encryption_level;
    return fd_tls_client_hs_start( client, handshake );
  case FD_TLS_HS_WAIT_SH:
    /* Incoming ServerHello */
    return fd_tls_client_hs_wait_sh( client, handshake, record, record_sz, encryption_level );
  case FD_TLS_HS_WAIT_EE:
    /* Incoming EncryptedExtensions */
    return fd_tls_client_hs_wait_ee( client, handshake, record, record_sz, encryption_level );
  case FD_TLS_HS_WAIT_CERT_CR:
    /* Incoming CertificateRequest or Certificate */
    return fd_tls_client_hs_wait_cert_cr( client, handshake, record, record_sz, encryption_level );
  case FD_TLS_HS_WAIT_CERT:
    /* Incoming Certificate */
    return fd_tls_client_hs_wait_cert( client, handshake, record, record_sz, encryption_level );
  case FD_TLS_HS_WAIT_CV:
    /* Incoming CertificateVerify */
    return fd_tls_client_hs_wait_cert_verify( client, handshake, record, record_sz, encryption_level );
  case FD_TLS_HS_WAIT_FINISHED:
    /* Incoming Server Finished */
    return fd_tls_client_hs_wait_finished( client, handshake, record, record_sz, encryption_level );
  default:
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_HANDSHAKE_FAILURE, FD_TLS_REASON_ILLEGAL_STATE );
  }
}

static long
fd_tls_client_hs_start( fd_tls_t const * const      client,
                        fd_tls_estate_cli_t * const handshake ) {

  /* Request QUIC transport params */
  uchar quic_tp[ FD_TLS_EXT_QUIC_PARAMS_SZ_MAX ];
  long  quic_tp_sz = -1L;
  if( client->quic )
    quic_tp_sz = (long)client->quic_tp_self_fn( handshake, quic_tp, FD_TLS_EXT_QUIC_PARAMS_SZ_MAX );
  if( FD_UNLIKELY( quic_tp_sz > (long)FD_TLS_EXT_QUIC_PARAMS_SZ_MAX ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_QUIC_TP_OVERSZ );

  /* Message buffer */
# define MSG_BUFSZ 512UL
  uchar msg_buf[ MSG_BUFSZ ];

  /* Transcript hasher */
  fd_sha256_init( &handshake->transcript );

  /* Send ClientHello *************************************************/

  /* Create client random */

  uchar client_random[ 32 ];
  if( FD_UNLIKELY( !fd_tls_rand( &client->rand, client_random, 32UL ) ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_INTERNAL_ERROR, FD_TLS_REASON_RAND_FAIL );

  /* Remember client random for SSLKEYLOGFILE */
  fd_memcpy( handshake->base.client_random, client_random, 32UL );

  /* Create client hello record */

  ulong client_hello_sz;

  do {
    uchar *       wire     = msg_buf;
    uchar * const wire_end = msg_buf + MSG_BUFSZ;

    /* Leave space for record header */

    void * hdr_ptr = wire;
    wire += sizeof(fd_tls_record_hdr_t);
    fd_tls_record_hdr_t hdr = { .type = FD_TLS_RECORD_CLIENT_HELLO };

    /* Construct client hello */

    fd_tls_client_hello_t ch = {
      .supported_versions   = { .tls13=1 },
      .supported_groups     = { .x25519=1 },
      .signature_algorithms = { .ed25519=1 },
      .cipher_suites        = { .aes_128_gcm_sha256=1 },
      .key_share            = { .has_x25519=1 },
      .server_cert_types    = { .x509=!!client->cert_x509_sz, .raw_pubkey=1 },
      .client_cert_types    = { .x509=!!client->cert_x509_sz, .raw_pubkey=1 },
      .quic_tp = {
        .buf   = (quic_tp_sz>=0L) ? quic_tp : NULL,
        .bufsz = (ushort)quic_tp_sz,
      }
    };
    memcpy( ch.random,           client_random,          32UL );
    memcpy( ch.key_share.x25519, client->kex_public_key, 32UL );

    /* Encode client hello */

    long encode_res = fd_tls_encode_client_hello( &ch, wire, (ulong)(wire_end-wire) );
    if( FD_UNLIKELY( encode_res<0L ) )
      return fd_tls_alert( &handshake->base, (uint)(-encode_res), FD_TLS_REASON_CH_ENCODE );
    wire += (ulong)encode_res;

    hdr.sz = fd_uint_to_tls_u24( (uint)encode_res );
    fd_tls_encode_record_hdr( &hdr, hdr_ptr, sizeof(fd_tls_record_hdr_t) );
    client_hello_sz = (ulong)(wire - msg_buf);
  } while(0);

  /* Call back with client hello */

  if( FD_UNLIKELY( !client->sendmsg_fn(
        handshake,
        msg_buf, client_hello_sz,
        FD_TLS_LEVEL_INITIAL,
        /* flush */ 1 ) ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_INTERNAL_ERROR, FD_TLS_REASON_SENDMSG_FAIL );

  /* Record client hello in transcript hash */

  fd_sha256_append( &handshake->transcript, msg_buf, client_hello_sz );

  /* Finish up ********************************************************/

  handshake->base.state = FD_TLS_HS_WAIT_SH;

# undef MSG_BUFSZ
  return 0L;
}

static long
fd_tls_client_hs_wait_sh( fd_tls_t const *      const client,
                          fd_tls_estate_cli_t * const handshake,
                          uchar const *         const record,
                          ulong                 const record_sz,
                          uint                  const encryption_level ) {

  if( FD_UNLIKELY( encryption_level != FD_TLS_LEVEL_INITIAL ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_INTERNAL_ERROR, FD_TLS_REASON_WRONG_ENC_LVL );

  /* Record server hello in transcript hash */

  fd_sha256_append( &handshake->transcript, record, record_sz );

  /* Read server hello ************************************************/

  fd_tls_server_hello_t sh[1] = {0};

  do {
    uchar const *       wire     = record;
    uchar const * const wire_end = record + record_sz;

    /* Decode record header */

    fd_tls_record_hdr_t record_hdr = {0};
    long decode_res = fd_tls_decode_record_hdr( &record_hdr, wire, (ulong)(wire_end-wire) );
    if( FD_UNLIKELY( decode_res<0L ) )
      return fd_tls_alert( &handshake->base, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_SH_PARSE );
    wire += (ulong)decode_res;

    if( FD_UNLIKELY( record_hdr.type != FD_TLS_RECORD_SERVER_HELLO ) )
      return fd_tls_alert( &handshake->base, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_SH_EXPECTED );

    /* Decode Server Hello */

    decode_res = fd_tls_decode_server_hello( sh, wire, (ulong)(wire_end-wire) );
    if( FD_UNLIKELY( decode_res<0L ) )
      return fd_tls_alert( &handshake->base, (uint)(-decode_res), FD_TLS_REASON_SH_PARSE );
    wire += (ulong)decode_res;

    /* Fail if trailing bytes detected */

    if( FD_UNLIKELY( wire!=wire_end ) )
      return fd_tls_alert( &handshake->base, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_CH_TRAILING );
  } while(0);

  /* TODO: For now, cryptographic parameters are hardcoded in the
           decoder.  Thus, we skip checks. */

  /* Derive handshake secrets *****************************************/

  /* TODO: This code is duplicated server-side */

  /* Export handshake transcript hash */

  fd_sha256_t transcript_clone = handshake->transcript;
  uchar transcript_hash[ 32 ];
  fd_sha256_fini( &transcript_clone, transcript_hash );

  /* Derive ECDH input key material */

  uchar _ecdh_ikm[ 32 ];
  void * ecdh_ikm = fd_x25519_exchange( _ecdh_ikm,
                                        client->kex_private_key,
                                        sh->key_share.x25519 );
  if( FD_UNLIKELY( !ecdh_ikm ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_HANDSHAKE_FAILURE, FD_TLS_REASON_X25519_FAIL );

  /* Derive main handshake secret */

  uchar handshake_secret[ 32 ];
  fd_hmac_sha256( /* data */ ecdh_ikm,          32UL,
                  /* salt */ handshake_derived, 32UL,
                  /* out  */ handshake_secret );

  /* Derive client/server handshake secrets */

  fd_tls_hkdf_expand_label( handshake->client_hs_secret,
                            handshake_secret,
                            "c hs traffic",  12UL,
                            transcript_hash, 32UL );

  fd_tls_hkdf_expand_label( handshake->server_hs_secret,
                            handshake_secret,
                            "s hs traffic",  12UL,
                            transcript_hash, 32UL );

  /* Call back with handshake secrets */

  client->secrets_fn( handshake,
                      /* read secret  */ handshake->server_hs_secret,
                      /* write secret */ handshake->client_hs_secret,
                      FD_TLS_LEVEL_HANDSHAKE );

  /* Derive master secret */

  uchar master_derive[ 32 ];
  fd_tls_hkdf_expand_label( master_derive,
                            handshake_secret,
                            "derived",   7UL,
                            empty_hash, 32UL );

  static uchar const zeros[ 32 ] = {0};
  fd_hmac_sha256( /* data */ zeros,         32UL,
                  /* salt */ master_derive, 32UL,
                  /* out  */ handshake->master_secret );

  /* Finish up ********************************************************/

  handshake->base.state = FD_TLS_HS_WAIT_EE;

  return 0L;
}

static long
fd_tls_client_hs_wait_ee( fd_tls_t const *      const client,
                          fd_tls_estate_cli_t * const handshake,
                          uchar const *         const record,
                          ulong                 const record_sz,
                          uint                  const encryption_level ) {

  (void)client;

  if( FD_UNLIKELY( encryption_level != FD_TLS_LEVEL_HANDSHAKE ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_INTERNAL_ERROR, FD_TLS_REASON_WRONG_ENC_LVL );

  /* Record EE in transcript hash */

  fd_sha256_append( &handshake->transcript, record, record_sz );

  /* Read EncryptedExtensions (EE) record *****************************/

  fd_tls_enc_ext_t ee[1] = {0};

  do {
    uchar const *       wire     = record;
    uchar const * const wire_end = record + record_sz;

    /* Decode record header */

    fd_tls_record_hdr_t record_hdr = {0};
    long decode_res = fd_tls_decode_record_hdr( &record_hdr, wire, (ulong)(wire_end-wire) );
    if( FD_UNLIKELY( decode_res<0L ) )
      return fd_tls_alert( &handshake->base, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_EE_PARSE );
    wire += (ulong)decode_res;

    if( FD_UNLIKELY( record_hdr.type != FD_TLS_RECORD_ENCRYPTED_EXT ) )
      return fd_tls_alert( &handshake->base, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_EE_EXPECTED );

    /* Decode EncryptedExtensions */

    decode_res = fd_tls_decode_enc_ext( ee, wire, (ulong)(wire_end-wire) );
    if( FD_UNLIKELY( decode_res<0L ) )
      return fd_tls_alert( &handshake->base, (uint)(-decode_res), FD_TLS_REASON_EE_PARSE );
    wire += (ulong)decode_res;

    if( client->quic ) {
      /* QUIC transport parameters are mandatory in QUIC mode */
      if( FD_UNLIKELY( !ee->quic_tp.buf ) )
        return fd_tls_alert( &handshake->base, FD_TLS_ALERT_MISSING_EXTENSION, FD_TLS_REASON_EE_NO_QUIC );

      /* Remember that this is a QUIC-TLS handshake */
      handshake->base.quic = 1;
      /* Inform user of peer's QUIC transport parameters */
      client->quic_tp_peer_fn( handshake, ee->quic_tp.buf, ee->quic_tp.bufsz );
    }

    /* Fail if trailing bytes detected */

    if( FD_UNLIKELY( wire!=wire_end ) )
      return fd_tls_alert( &handshake->base, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_CH_TRAILING );
  } while(0);

  switch( ee->server_cert.cert_type ) {
  case FD_TLS_CERTTYPE_X509:
    break;  /* ok */
  case FD_TLS_CERTTYPE_RAW_PUBKEY:
    handshake->server_cert_rpk = 1;
    break;
  default:
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_UNSUPPORTED_CERTIFICATE, FD_TLS_REASON_CERT_TYPE );
  }

  handshake->client_cert_nox509 = 1;
  switch( ee->client_cert.cert_type ) {
  case FD_TLS_CERTTYPE_X509:
    handshake->client_cert_nox509 = 0;
    break;
  case FD_TLS_CERTTYPE_RAW_PUBKEY:
    handshake->client_cert_rpk = 1;
    break;
  default:
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_UNSUPPORTED_CERTIFICATE, FD_TLS_REASON_CERT_TYPE );
  }

  /* Fail if server requested an X.509 client cert, but we can only
     serve a raw public key. */

  if( FD_UNLIKELY( ( !!handshake->client_cert            )
                 & (  !handshake->client_cert_rpk        )
                 & ( ( !client->cert_x509_sz           )
                   | ( !!handshake->client_cert_nox509 ) ) ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_UNSUPPORTED_CERTIFICATE, FD_TLS_REASON_NO_X509 );

  /* Finish up ********************************************************/

  handshake->base.state = FD_TLS_HS_WAIT_CERT_CR;

  return 0L;
}

static long
fd_tls_client_handle_cert_req( fd_tls_estate_cli_t * const handshake,
                               uchar const *         const req,
                               ulong                 const req_sz ) {

  /* For now, just ignore the content of the certificate request.
     TODO: This is obviously not compliant. */
  (void)req; (void)req_sz;

  handshake->client_cert = 1;
  handshake->base.state       = FD_TLS_HS_WAIT_CERT;

  return (long)req_sz;
}

static long
fd_tls_client_handle_cert_chain( fd_tls_estate_cli_t * const hs,
                                 uchar const *         const cert_chain,
                                 ulong                 const cert_chain_sz ) {
  /* pubkey pinning is ...
       ... enabled  => check that public key matches cert
       ... disabled => update the handshake's public key value based on cert */
  uchar const * expected_pubkey = ( hs->server_pubkey_pin) ? (hs->server_pubkey) : NULL;
  uchar *       out_pubkey      = (!hs->server_pubkey_pin) ? (hs->server_pubkey) : NULL;
  return fd_tls_handle_cert_chain( &hs->base, cert_chain, cert_chain_sz, expected_pubkey, out_pubkey, hs->server_cert_rpk );
}

static long
fd_tls_client_hs_wait_cert_cr( fd_tls_t const *      const client,
                               fd_tls_estate_cli_t * const handshake,
                               uchar const *         const record,
                               ulong                 const record_sz,
                               uint                  const encryption_level ) {

  (void)client;

  if( FD_UNLIKELY( encryption_level != FD_TLS_LEVEL_HANDSHAKE ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_INTERNAL_ERROR, FD_TLS_REASON_WRONG_ENC_LVL );

  fd_sha256_append( &handshake->transcript, record, record_sz );

  /* Read Certificate(Request) ****************************************/

  uchar next_state;

  do {
    uchar const *       wire     = record;
    uchar const * const wire_end = record + record_sz;

    /* Decode record header */

    fd_tls_record_hdr_t record_hdr = {0};
    long decode_res = fd_tls_decode_record_hdr( &record_hdr, wire, (ulong)(wire_end-wire) );
    if( FD_UNLIKELY( decode_res<0L ) )
      return fd_tls_alert( &handshake->base, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_CERT_CR_PARSE );
    wire += (ulong)decode_res;

    switch( record_hdr.type ) {
    case FD_TLS_RECORD_CERT_REQ:
      decode_res = fd_tls_client_handle_cert_req ( handshake, wire, (ulong)(wire_end-wire) );
      next_state = FD_TLS_HS_WAIT_CERT;
      break;
    case FD_TLS_RECORD_CERT:
      decode_res = fd_tls_client_handle_cert_chain( handshake, wire, (ulong)(wire_end-wire) );
      next_state = FD_TLS_HS_WAIT_CV;
      break;
    default:
      return fd_tls_alert( &handshake->base, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_CERT_CR_EXPECTED );
    }

    if( FD_UNLIKELY( decode_res<0L ) )
      return fd_tls_alert( &handshake->base, (uint)(-decode_res), FD_TLS_REASON_CERT_CR_PARSE );
    wire += (ulong)decode_res;

    /* Fail if trailing bytes detected */

    if( FD_UNLIKELY( wire!=wire_end ) )
      return fd_tls_alert( &handshake->base, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_CERT_CR_TRAILING );
  } while(0);

  /* Finish up ********************************************************/

  handshake->base.state = ((uchar)next_state);
  return 0L;
}

static long
fd_tls_client_hs_wait_cert( fd_tls_t const *      const client,
                            fd_tls_estate_cli_t * const handshake,
                            uchar const *         const record,
                            ulong                 const record_sz,
                            uint                  const encryption_level ) {

  (void)client;

  if( FD_UNLIKELY( encryption_level != FD_TLS_LEVEL_HANDSHAKE ) )
    return fd_tls_alert( &handshake->base, FD_TLS_ALERT_INTERNAL_ERROR, FD_TLS_REASON_WRONG_ENC_LVL );

  fd_sha256_append( &handshake->transcript, record, record_sz );

  /* Read Certificate *************************************************/

  do {
    uchar const *       wire     = record;
    uchar const * const wire_end = record + record_sz;

    /* Decode record header */

    fd_tls_record_hdr_t record_hdr = {0};
    long decode_res = fd_tls_decode_record_hdr( &record_hdr, wire, (ulong)(wire_end-wire) );
    if( FD_UNLIKELY( decode_res<0L ) )
      return fd_tls_alert( &handshake->base, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_CERT_PARSE );
    wire += (ulong)decode_res;

    if( FD_UNLIKELY( record_hdr.type != FD_TLS_RECORD_CERT ) )
      return fd_tls_alert( &handshake->base, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_CERT_EXPECTED );

    /* Decode Certificate */

    decode_res = fd_tls_client_handle_cert_chain( handshake, wire, (ulong)(wire_end-wire) );
    if( FD_UNLIKELY( decode_res<0L ) )
      return fd_tls_alert( &handshake->base, (uint)(-decode_res), FD_TLS_REASON_CERT_PARSE );
    wire += (ulong)decode_res;

    /* Fail if trailing bytes detected */

    if( FD_UNLIKELY( wire!=wire_end ) )
      return fd_tls_alert( &handshake->base, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_CH_TRAILING );
  } while(0);

  /* Finish up ********************************************************/

  handshake->base.state = (char)FD_TLS_HS_WAIT_CV;
  return 0L;
}

static long
fd_tls_client_hs_wait_cert_verify( fd_tls_t const *      const client,
                                   fd_tls_estate_cli_t * const hs,
                                   uchar const *         const record,
                                   ulong                 const record_sz,
                                   uint                  const encryption_level ) {

  (void)client;

  if( FD_UNLIKELY( encryption_level != FD_TLS_LEVEL_HANDSHAKE ) )
    return fd_tls_alert( &hs->base, FD_TLS_ALERT_INTERNAL_ERROR, FD_TLS_REASON_WRONG_ENC_LVL );

  long res = fd_tls_handle_cert_verify( &hs->base, &hs->transcript, record, record_sz, hs->server_pubkey, 0 );
  if( FD_UNLIKELY( res<0L ) ) return res;

  fd_sha256_append( &hs->transcript, record, record_sz );

  /* Finish up ********************************************************/

  hs->base.state = FD_TLS_HS_WAIT_FINISHED;
  return 0L;
}

static long
fd_tls_client_hs_wait_finished( fd_tls_t const *      const client,
                                fd_tls_estate_cli_t * const hs,
                                uchar const *         const record,
                                ulong                 const record_sz,
                                uint                  const encryption_level ) {

  if( FD_UNLIKELY( encryption_level != FD_TLS_LEVEL_HANDSHAKE ) )
    return fd_tls_alert( &hs->base, FD_TLS_ALERT_INTERNAL_ERROR, FD_TLS_REASON_WRONG_ENC_LVL );

  /* Export transcript hash ClientHello..CertificateVerify */

  fd_sha256_t transcript_clone = hs->transcript;
  uchar transcript_hash[ 32 ];
  fd_sha256_fini( &transcript_clone, transcript_hash );

  /* Derive "Finished" key */

  uchar server_finished_key[ 32 ];
  fd_tls_hkdf_expand_label( server_finished_key,
                            hs->server_hs_secret,
                            "finished", 8UL,
                            NULL,       0UL );

  /* Derive "Finished" verify data */

  uchar server_finished_expected[ 32 ];
  fd_hmac_sha256( /* data */ transcript_hash,     32UL,
                  /* salt */ server_finished_key, 32UL,
                  /* out  */ server_finished_expected );

  /* Record ServerFinished */

  fd_sha256_append( &hs->transcript, record, record_sz );

  /* Read ServerFinished **********************************************/

  fd_tls_finished_t server_fin = {0};

  do {
    uchar const *       wire     = record;
    uchar const * const wire_end = record + record_sz;

    /* Decode record header */

    fd_tls_record_hdr_t record_hdr = {0};
    long decode_res = fd_tls_decode_record_hdr( &record_hdr, wire, (ulong)(wire_end-wire) );
    if( FD_UNLIKELY( decode_res<0L ) )
      return fd_tls_alert( &hs->base, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_FINI_PARSE );
    wire += (ulong)decode_res;

    if( FD_UNLIKELY( record_hdr.type != FD_TLS_RECORD_FINISHED ) )
      return fd_tls_alert( &hs->base, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_FINI_EXPECTED );

    /* Decode server Finished */

    decode_res = fd_tls_decode_finished( &server_fin, wire, (ulong)(wire_end-wire) );
    if( FD_UNLIKELY( decode_res<0L ) )
      return fd_tls_alert( &hs->base, (uint)(-decode_res), FD_TLS_REASON_FINI_PARSE );
    wire += (ulong)decode_res;

    /* Fail if trailing bytes detected */

    if( FD_UNLIKELY( wire!=wire_end ) )
      return fd_tls_alert( &hs->base, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_FINI_TRAILING );
  } while(0);

  /* Verify that client and server's transcripts match */

  int match = 0;
  for( ulong i=0; i<32UL; i++ )
    match |= server_fin.verify[i] ^ server_finished_expected[i];
  if( FD_UNLIKELY( match!=0 ) )
    return fd_tls_alert( &hs->base, FD_TLS_ALERT_DECRYPT_ERROR, FD_TLS_REASON_FINI_FAIL );

  /* Derive application secrets ***************************************/

  /* Export transcript hash ClientHello..ServerFinished */

  transcript_clone = hs->transcript;
  fd_sha256_fini( &transcript_clone, transcript_hash );

  /* Derive client/server application secrets */

  uchar client_app_secret[ 32UL ];
  fd_tls_hkdf_expand_label( client_app_secret,
                            hs->master_secret,
                            "c ap traffic",  12UL,
                            transcript_hash, 32UL );

  uchar server_app_secret[ 32UL ];
  fd_tls_hkdf_expand_label( server_app_secret,
                            hs->master_secret,
                            "s ap traffic",  12UL,
                            transcript_hash, 32UL );

  /* Call back with application secrets */

  client->secrets_fn( hs,
                      /* read secret  */ server_app_secret,
                      /* write secret */ client_app_secret,
                      FD_TLS_LEVEL_APPLICATION );

  if( hs->client_cert ) {

    /* Send client Certificate ****************************************/

    /* TODO deduplicate this */

    /* Message buffer */
#   define MSG_BUFSZ 512UL
    uchar msg_buf[ MSG_BUFSZ ];

    /* TODO: fd_tls does not support certificate_request_context.
       It is an opaque string that the server may send in the cert
       request.  The client is supposed to echo it back in its cert
       message.  However, the server is not supposed to send it in the
       first place, unless post-handshake auth is used (which is not
       the case) */

    void const * cert_msg;
    ulong        cert_msg_sz;

    if( hs->client_cert_rpk ) {
      long sz = fd_tls_encode_raw_public_key( client->cert_public_key, msg_buf, MSG_BUFSZ );
      FD_TEST( sz>=0L );
      cert_msg    = msg_buf;
      cert_msg_sz = (ulong)sz;
    } else if( client->cert_x509_sz ) {
      /* TODO: Technically should check whether the server supports
         X.509.  There could be servers that support neither X.509 nor
         raw public keys. */

      /* Send pre-prepared X.509 Certificate message */
      cert_msg    = client->cert_x509;
      cert_msg_sz = client->cert_x509_sz;
    } else {
      /* TODO: Unreachable:  We should have verified whether we have
         an appropriate certificate in wait_cert_cr. */
      return fd_tls_alert( &hs->base, FD_TLS_ALERT_INTERNAL_ERROR, FD_TLS_REASON_CERT_TYPE );
    }

    /* Send certificate message */

    if( FD_UNLIKELY( !client->sendmsg_fn(
          hs,
          cert_msg, cert_msg_sz,
          FD_TLS_LEVEL_HANDSHAKE,
          /* flush */ 0 ) ) )
      return fd_tls_alert( &hs->base, FD_TLS_ALERT_INTERNAL_ERROR, FD_TLS_REASON_SENDMSG_FAIL );

    /* Record Certificate record in transcript hash */

    fd_sha256_append( &hs->transcript, cert_msg, cert_msg_sz );

    /* Send client CertificateVerify **********************************/

    long cvfy_res = fd_tls_send_cert_verify( client, &hs->base, &hs->transcript, 1 );
    if( FD_UNLIKELY( !!cvfy_res ) ) return cvfy_res;

#   undef MSG_BUFSZ

  }

  /* Send client Finished *********************************************/

  struct __attribute__((packed)) {
    fd_tls_record_hdr_t hdr;
    fd_tls_finished_t   fin;
  } fin_rec;
  fin_rec.hdr = (fd_tls_record_hdr_t){
    .type = FD_TLS_RECORD_FINISHED,
    .sz   = fd_uint_to_tls_u24( 0x20 )
  };

  fd_tls_record_hdr_bswap( &fin_rec.hdr );

  /* Export transcript hash up to this point */

  fd_sha256_fini( &hs->transcript, transcript_hash );

  /* Derive "Finished" key */

  uchar client_finished_key[ 32 ];
  fd_tls_hkdf_expand_label( client_finished_key,
                            hs->client_hs_secret,
                            "finished", 8UL,
                            NULL,       0UL );

  /* Derive "Finished" verify data */

  fd_hmac_sha256( /* data */ transcript_hash,     32UL,
                  /* salt */ client_finished_key, 32UL,
                  /* out  */ fin_rec.fin.verify );

  /* Send client Finished record */

  if( FD_UNLIKELY( !client->sendmsg_fn(
        hs,
        &fin_rec, sizeof(fin_rec),
        FD_TLS_LEVEL_HANDSHAKE,
        /* flush */ 1 ) ) )
    return fd_tls_alert( &hs->base, FD_TLS_ALERT_INTERNAL_ERROR, FD_TLS_REASON_SENDMSG_FAIL );

  hs->base.state = FD_TLS_HS_CONNECTED;
  return 0L;
}

FD_FN_PURE char const *
fd_tls_alert_cstr( uint alert ) {
  switch( alert ) {
  case FD_TLS_ALERT_UNEXPECTED_MESSAGE:
    return "unexpected message";
  case FD_TLS_ALERT_BAD_RECORD_MAC:
    return "bad record MAC";
  case FD_TLS_ALERT_RECORD_OVERFLOW:
    return "record overflow";
  case FD_TLS_ALERT_HANDSHAKE_FAILURE:
    return "handshake failure";
  case FD_TLS_ALERT_BAD_CERTIFICATE:
    return "bad certificate";
  case FD_TLS_ALERT_UNSUPPORTED_CERTIFICATE:
    return "unsupported certificate";
  case FD_TLS_ALERT_CERTIFICATE_REVOKED:
    return "certificate revoked";
  case FD_TLS_ALERT_CERTIFICATE_EXPIRED:
    return "certificate expired";
  case FD_TLS_ALERT_CERTIFICATE_UNKNOWN:
    return "certificate unknown";
  case FD_TLS_ALERT_ILLEGAL_PARAMETER:
    return "illegal parameter";
  case FD_TLS_ALERT_UNKNOWN_CA:
    return "unknown CA";
  case FD_TLS_ALERT_ACCESS_DENIED:
    return "access denied";
  case FD_TLS_ALERT_DECODE_ERROR:
    return "decode error";
  case FD_TLS_ALERT_DECRYPT_ERROR:
    return "decrypt error";
  case FD_TLS_ALERT_PROTOCOL_VERSION:
    return "unsupported protocol version";
  case FD_TLS_ALERT_INSUFFICIENT_SECURITY:
    return "insufficient security";
  case FD_TLS_ALERT_INTERNAL_ERROR:
    return "internal error";
  case FD_TLS_ALERT_INAPPROPRIATE_FALLBACK:
    return "inappropriate fallback";
  case FD_TLS_ALERT_USER_CANCELED:
    return "user canceled";
  case FD_TLS_ALERT_MISSING_EXTENSION:
    return "missing extension";
  case FD_TLS_ALERT_UNSUPPORTED_EXTENSION:
    return "unsupported extension";
  case FD_TLS_ALERT_UNRECOGNIZED_NAME:
    return "unrecognized name";
  case FD_TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE:
    return "bad certificate status response";
  case FD_TLS_ALERT_UNKNOWN_PSK_IDENTITY:
    return "unknown PSK identity";
  case FD_TLS_ALERT_CERTIFICATE_REQUIRED:
    return "certificate required";
  case FD_TLS_ALERT_NO_APPLICATION_PROTOCOL:
    return "no application protocol";
  default:
    FD_LOG_WARNING(( "Missing fd_tls_alert_cstr code for %u (memory corruption?)", alert ));
    return "unknown alert";
  /* TODO add the other alert codes */
  }
}

FD_FN_PURE char const *
fd_tls_reason_cstr( uint reason ) {
  switch( reason ) {
  case FD_TLS_REASON_ILLEGAL_STATE:
    return "illegal handshake state ID (memory corruption?)";
  case FD_TLS_REASON_SENDMSG_FAIL:
    return "sendmsg callback failed";
  case FD_TLS_REASON_WRONG_ENC_LVL:
    return "wrong encryption level (bug in user of fd_tls API)";
  case FD_TLS_REASON_RAND_FAIL:
    return "rand function failed";
  case FD_TLS_REASON_ALPN_OVERSZ:
    return "our ALPN list is too long";
  case FD_TLS_REASON_CH_EXPECTED:
    return "expected ClientHello, but got other message type";
  case FD_TLS_REASON_CH_TRAILING:
    return "trailing bytes after ClientHello";
  case FD_TLS_REASON_CH_PARSE:
    return "failed to decode ClientHello";
  case FD_TLS_REASON_CH_ENCODE:
    return "failed to encode ClientHello";
  case FD_TLS_REASON_CH_CRYPTO_NEG:
    return "unsupported cryptographic parameters (fd_tls only supports TLS 1.3, X25519, Ed25519, AES-128-GCM)";
  case FD_TLS_REASON_CH_NO_QUIC:
    return "client does not support QUIC (missing QUIC transport params)";
  case FD_TLS_REASON_X25519_FAIL:
    return "X25519 key exchange failed";
  case FD_TLS_REASON_NO_X509:
    return "peer requested X.509 cert, but we don't have one";
  case FD_TLS_REASON_WRONG_PUBKEY:
    return "peer identity does not match expected public key";
  case FD_TLS_REASON_ED25519_FAIL:
    return "Ed25519 signature verification failed";
  case FD_TLS_REASON_FINI_FAIL:
    return "unexpected 'Finished' data (transcript hash fail)";
  case FD_TLS_REASON_QUIC_TP_OVERSZ:
    return "buffer overflow in QUIC transport param handling (user bug)";
  case FD_TLS_REASON_EE_NO_QUIC:
    return "server does not support QUIC (missing QUIC transport params)";
  case FD_TLS_REASON_X509_PARSE:
    return "X.509 cert parse failed";
  case FD_TLS_REASON_SPKI_PARSE:
    return "Raw public key parse failed";
  case FD_TLS_REASON_CV_EXPECTED:
    return "expected CertificateVerify, but got other message type";
  case FD_TLS_REASON_CV_SIGALG:
    return "peer CertificateVerify contains uses incorrect signature algorithm";
  case FD_TLS_REASON_FINI_PARSE:
    return "failed to parse 'Finished' message";
  case FD_TLS_REASON_SH_EXPECTED:
    return "expected ServerHello, but got other message type";
  case FD_TLS_REASON_SH_TRAILING:
    return "trailing bytes after ServerHello";
  case FD_TLS_REASON_SH_PARSE:
    return "failed to decode ServerHello";
  case FD_TLS_REASON_SH_ENCODE:
    return "failed to encode ServerHello";
  case FD_TLS_REASON_EE_EXPECTED:
    return "expected EncryptedExtensions, but got other message type";
  case FD_TLS_REASON_EE_TRAILING:
    return "trailing bytes after EncryptedExtensions";
  case FD_TLS_REASON_EE_PARSE:
    return "failed to decode EncryptedExtensions";
  case FD_TLS_REASON_EE_ENCODE:
    return "failed to encode EncryptedExtensions";
  case FD_TLS_REASON_CERT_TYPE:
    return "unsupported certificate type";
  case FD_TLS_REASON_CERT_EXPECTED:
    return "expected Certificate, but got other message type";
  case FD_TLS_REASON_CERT_PARSE:
   return "failed to decode Certificate";
  case FD_TLS_REASON_FINI_EXPECTED:
    return "expected Finished, but got other message type";
  case FD_TLS_REASON_FINI_TRAILING:
    return "trailing bytes after Finished";
  case FD_TLS_REASON_CERT_CR_EXPECTED:
    return "expected Certificate or CertificateRequest, but got other message type";
  case FD_TLS_REASON_CERT_CR_TRAILING:
    return "trailing bytes after Certificate or CertificateRequest";
  case FD_TLS_REASON_CERT_CR_PARSE:
    return "failed to decode Certificate or CertificateRequest";
  case FD_TLS_REASON_CERT_CHAIN_EMPTY:
    return "peer did not provide a certificate";
  case FD_TLS_REASON_CERT_CHAIN_PARSE:
    return "invalid peer cert chain";
  case FD_TLS_REASON_CERT_CHAIN_TRAILING:
    return "trailing bytes after Certificate chain";
  case FD_TLS_REASON_CV_TRAILING:
    return "trailing bytes after CertificateVerify";
  case FD_TLS_REASON_CV_PARSE:
    return "failed to decode CertificateVerify";
  case FD_TLS_REASON_CV_ENCODE:
    return "failed to encode CertificateVerify";
  default:
    FD_LOG_WARNING(( "Missing fd_tls_reason_cstr code for %u (memory corruption?)", reason ));
    __attribute__((fallthrough));
  /* TODO need to add a lot more error reason codes */
  case FD_TLS_REASON_NULL:
    return "unknown reason";
  }
}
