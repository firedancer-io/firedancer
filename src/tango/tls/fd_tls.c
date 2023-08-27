#include "fd_tls.h"
#include "fd_tls_server.h"
#include "fd_tls_client.h"
#include "fd_tls_proto.h"
#include "fd_tls_serde.h"
#include "fd_tls_asn1.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/ed25519/fd_x25519.h"
#include "../../ballet/hmac/fd_hmac.h"

/* Pre-generated keys */

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

/* fd_tls_server_t boilerplate */

ulong
fd_tls_server_align( void ) {
  return alignof(fd_tls_server_t);
}

ulong
fd_tls_server_footprint( void ) {
  return sizeof(fd_tls_server_t);
}

void *
fd_tls_server_new( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_tls_server_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }

  ulong fp = fd_tls_server_footprint();
  memset( mem, 0, fp );
  return mem;
}

fd_tls_server_t *
fd_tls_server_join( void * mem ) {
  return (fd_tls_server_t *)mem;
}

void *
fd_tls_server_leave( fd_tls_server_t * server ) {
  return (void *)server;
}

void *
fd_tls_server_delete( void * mem ) {
  return mem;
}

/* TODO create internal state machine and integrate Tango for
        accelerating cryptographic computations (e.g. FPGA sigverify) */

fd_tls_estate_srv_t *
fd_tls_estate_srv_new( void * mem ) {

  fd_tls_estate_srv_t * hs = mem;

  memset( hs, 0, sizeof(fd_tls_estate_srv_t) );
  hs->state = FD_TLS_HS_START;

  /* Assume X.509 unless otherwise specified using CertificateType ext */
  hs->client_cert_type = FD_TLS_CERTTYPE_X509;
  hs->server_cert_type = FD_TLS_CERTTYPE_X509;

  return hs;
}

fd_tls_estate_cli_t *
fd_tls_estate_cli_new( void * mem ) {

  fd_tls_estate_cli_t * hs = mem;

  memset( hs, 0, sizeof(fd_tls_estate_cli_t) );
  hs->state = FD_TLS_HS_START;

  return hs;
}

static void *
fd_tls_hkdf_expand_label( void *        out,
                          uchar const * secret,
                          char const *  label,
                          ulong         label_sz,
                          uchar const * context,
                          ulong         context_sz ) {

  /* Create HKDF info */
  uchar info[ 2+1+256+1+256+1 ];
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
  memcpy( info+info_sz, context, context_sz );
  info_sz += context_sz;

  /* HKDF-Expand suffix */
  info[ info_sz ] = 0x01;
  info_sz += 1UL;

  /* Compute result of HKDF-Expand-Label */
  fd_hmac_sha256( info, info_sz, secret, 32UL, out );
  return out;
}

/* fd_tls_server_hs_start is invoked in response to the initial
   ClientHello.  We send back several messages in response, including
   - the ServerHello, completing cryptographic negotiation
   - EncryptedExtensions, for further handshake data
   - Finished, completing the server's handshake message sequence */

static long
fd_tls_server_hs_start( fd_tls_server_t const * const server,
                        fd_tls_estate_srv_t *   const handshake,
                        void const *            const record,
                        ulong                         record_sz,
                        int                           encryption_level ) {

  if( FD_UNLIKELY( encryption_level != FD_TLS_LEVEL_INITIAL ) )
    return -(long)FD_TLS_ALERT_INTERNAL_ERROR;

  /* Message buffer */
# define MSG_BUFSZ 512UL
  uchar msg_buf[ MSG_BUFSZ ];

  /* Transcript hasher */
  fd_sha256_t transcript; fd_sha256_init( &transcript );

  /* Read client hello ************************************************/

  fd_tls_client_hello_t ch;

  do {
    ulong wire_laddr = (ulong)record;
    ulong wire_sz    = record_sz;

    /* Decode record header */

    fd_tls_record_hdr_t record_hdr;
    FD_TLS_DECODE_SUB( fd_tls_decode_record_hdr, &record_hdr );

    if( FD_UNLIKELY( record_hdr.type != FD_TLS_RECORD_CLIENT_HELLO ) )
      return -(long)FD_TLS_ALERT_UNEXPECTED_MESSAGE;

    /* Decode Client Hello */

    FD_TLS_DECODE_SUB( fd_tls_decode_client_hello, &ch );

    /* Fail if trailing bytes detected */

    if( FD_UNLIKELY( wire_laddr != (ulong)record+record_sz ) )
      return -(long)FD_TLS_ALERT_DECODE_ERROR;
  } while(0);

  /* Check for cryptographic compatibility */

  if( FD_UNLIKELY( ( !ch.supported_versions.tls13         )
                 | ( !ch.supported_groups.x25519          )
                 | ( !ch.signature_algorithms.ed25519     )
                 | ( !ch.cipher_suites.aes_128_gcm_sha256 ) ) )
    return -(long)FD_TLS_ALERT_HANDSHAKE_FAILURE;

  /* Record client hello in transcript hash */

  fd_sha256_append( &transcript, record, record_sz );

  /* Respond with server hello ****************************************/

  /* Create server random */

  uchar server_random[ 32 ];
  if( FD_UNLIKELY( !fd_tls_rand( &server->rand, server_random, 32UL ) ) )
    return -(long)FD_TLS_ALERT_INTERNAL_ERROR;

  /* Create server hello record */

  ulong server_hello_sz;

  do {
    ulong wire_laddr = (ulong)msg_buf;
    ulong wire_sz    = MSG_BUFSZ;

    /* Leave space for record header */

    void * hdr_ptr = FD_TLS_SKIP_FIELD( fd_tls_record_hdr_t );
    fd_tls_record_hdr_t hdr = { .type = FD_TLS_RECORD_SERVER_HELLO };

    /* Construct server hello */

    fd_tls_server_hello_t sh = {
      .cipher_suite = FD_TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
      .key_share    = { .has_x25519 = 1 },
    };
    memcpy( sh.random,           server_random,          32UL );
    memcpy( sh.key_share.x25519, server->kex_public_key, 32UL );

    /* Encode server hello */

    ulong msg_sz = FD_TLS_ENCODE_SUB( fd_tls_encode_server_hello, &sh );
    hdr.sz = fd_uint_to_tls_u24( (uint)msg_sz );
    fd_tls_encode_record_hdr( &hdr, hdr_ptr, 4UL );
    server_hello_sz = wire_laddr - (ulong)msg_buf;
  } while(0);

  /* Call back with server hello */

  if( FD_UNLIKELY( !server->sendmsg_fn(
        handshake,
        msg_buf, server_hello_sz,
        FD_TLS_LEVEL_INITIAL,
        /* flush */ 1 ) ) )
    return -(long)FD_TLS_ALERT_INTERNAL_ERROR;

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
    return -(long)FD_TLS_ALERT_HANDSHAKE_FAILURE;

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

  if( FD_UNLIKELY( !server->secrets_fn(
      handshake,
      /* read secret  */ client_hs_secret,
      /* write secret */ server_hs_secret,
      FD_TLS_LEVEL_HANDSHAKE ) ) )
    return -(long)FD_TLS_ALERT_HANDSHAKE_FAILURE;

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

  /* TODO it is illegal to include extensions that the client didn't
          request in the ClientHello -- should add some mechanism to
          remember the requests of the client. */

  ulong server_ee_sz;

  do {
    ulong wire_laddr = (ulong)msg_buf;
    ulong wire_sz    = MSG_BUFSZ;

    /* Leave space for headers */

    fd_tls_record_hdr_t * rec_hdr = FD_TLS_SKIP_FIELD( fd_tls_record_hdr_t );
    ushort *              exts_sz = FD_TLS_SKIP_FIELD( ushort );

    /* Add ALPN if requested */

    ulong alpn_sz = FD_LOAD( ushort, server->alpn );
    if( alpn_sz ) {
      fd_tls_ext_hdr_t * alpn_hdr = FD_TLS_SKIP_FIELD( fd_tls_ext_hdr_t );
      uchar *            alpn     = FD_TLS_SKIP_FIELDS( uchar, alpn_sz );

      fd_memcpy( alpn, server->alpn, alpn_sz );
      *alpn_hdr = (fd_tls_ext_hdr_t) {
        .type = FD_TLS_EXT_TYPE_ALPN,
        .sz   = fd_ushort_bswap( (ushort)alpn_sz )
      };
      fd_tls_ext_hdr_bswap( alpn_hdr );
    }

    /* Update headers */

    server_ee_sz = wire_laddr - (ulong)msg_buf;

    *rec_hdr = (fd_tls_record_hdr_t){
      .type = FD_TLS_RECORD_ENCRYPTED_EXT,
      .sz   = fd_uint_to_tls_u24( (uint)( server_ee_sz - 4UL) )
    };
    fd_tls_record_hdr_bswap( rec_hdr );

    *exts_sz = fd_ushort_bswap( (ushort)( server_ee_sz - 6UL ) );
  } while(0);

  /* Call back with EE */

  if( FD_UNLIKELY( !server->sendmsg_fn(
        handshake,
        msg_buf, server_ee_sz,
        FD_TLS_LEVEL_HANDSHAKE,
        /* flush */ 1 ) ) )
    return -(long)FD_TLS_ALERT_INTERNAL_ERROR;

  /* Record EE in transcript hash */

  fd_sha256_append( &transcript, msg_buf, server_ee_sz );

  /* Send Certificate *************************************************/

  /* TODO check whether we negotiated X.509 or RPK */

  /* Send Certificate record with X.509 */

  if( FD_UNLIKELY( !server->cert_x509_sz ) ) {
    FD_LOG_WARNING(( "fd_tls: no server certificate configured" ));
    return -(long)FD_TLS_ALERT_INTERNAL_ERROR;
  }

  if( FD_UNLIKELY( !server->sendmsg_fn(
        handshake,
        server->cert_x509, server->cert_x509_sz,
        FD_TLS_LEVEL_HANDSHAKE,
        /* flush */ 1 ) ) )
    return -(long)FD_TLS_ALERT_INTERNAL_ERROR;

  /* Record Certificate record in transcript hash */

  fd_sha256_append( &transcript, server->cert_x509, server->cert_x509_sz );

  /* Send CertificateVerify *******************************************/

  /* Export transcript hash ClientHello..server Certificate
     And create message to be signed */

  uchar sign_msg[ 130 ];
  fd_memcpy( sign_msg, fd_tls13_srv_sign_prefix, 98UL );

  transcript_clone = transcript;
  fd_sha256_fini( &transcript_clone, sign_msg+98 );

  /* Create static size message layout */

  fd_tls_cert_verify_t cert_verify = {
    .hdr = {
      .type = FD_TLS_RECORD_CERT_VERIFY,
      .sz   = fd_uint_to_tls_u24( 0x44 )
    },
    .sig_alg = FD_TLS_SIGNATURE_ED25519,
    .sig_sz  = 0x40,
  };
  fd_tls_cert_verify_bswap( &cert_verify );

  /* Sign certificate */

  fd_sha512_t sha512;
  fd_ed25519_sign( cert_verify.sig,
                   sign_msg, 130UL,
                   server->cert_public_key,
                   server->cert_private_key,
                   &sha512 );

  /* Send CertificateVerify record */

  if( FD_UNLIKELY( !server->sendmsg_fn(
        handshake,
        &cert_verify, sizeof(fd_tls_cert_verify_t),
        FD_TLS_LEVEL_HANDSHAKE,
        /* flush */ 1 ) ) )
    return -(long)FD_TLS_ALERT_INTERNAL_ERROR;

  /* Record CertificateVerify in transcript hash */

  fd_sha256_append( &transcript,
                    &cert_verify, sizeof(fd_tls_cert_verify_t) );

  /* Send Finished ****************************************************/

  /* Create static size message layout */

  fd_tls_finished_t finished = {
    .hdr = {
      .type = FD_TLS_RECORD_FINISHED,
      .sz   = fd_uint_to_tls_u24( 0x20 )
    }
  };
  fd_tls_finished_bswap( &finished );

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
                  /* out  */ finished.verify );

  /* Send Finished record */

  if( FD_UNLIKELY( !server->sendmsg_fn(
        handshake,
        &finished, sizeof(finished),
        FD_TLS_LEVEL_HANDSHAKE,
        /* flush */ 1 ) ) )
    return -(long)FD_TLS_ALERT_INTERNAL_ERROR;

  /* Record Finished in transcript hash */

  fd_sha256_append( &transcript,
                    &finished, sizeof(fd_tls_finished_t) );

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

  /* Call back with handshake secrets */

  if( FD_UNLIKELY( !server->secrets_fn(
      handshake,
      /* read secret  */ client_app_secret,
      /* write secret */ server_app_secret,
      FD_TLS_LEVEL_APPLICATION ) ) )
    return -(long)FD_TLS_ALERT_HANDSHAKE_FAILURE;

  /* Finish up ********************************************************/

  /* Store transcript hash state */

  fd_tls_transcript_store( &handshake->transcript, &transcript );

  /* Done */

  handshake->state = FD_TLS_HS_WAIT_FINISHED;

# undef MSG_BUFSZ
  return 0L;
}

static long
fd_tls_server_hs_wait_finished( fd_tls_estate_srv_t * const handshake,
                                void const *          const record,
                                ulong                       record_sz,
                                int                         encryption_level ) {

  if( FD_UNLIKELY( encryption_level != FD_TLS_LEVEL_HANDSHAKE ) )
    return -(long)FD_TLS_ALERT_INTERNAL_ERROR;

  /* Restore state ****************************************************/

  fd_sha256_t transcript;
  fd_tls_transcript_load( &handshake->transcript, &transcript );

  /* TODO support client certificates */

  /* Decode incoming client "Finished" message ************************/

  fd_tls_finished_t finished;
  if( FD_UNLIKELY( fd_tls_decode_finished( &finished, record, record_sz )<0L ) )
    return -(long)FD_TLS_ALERT_DECODE_ERROR;

  if( FD_UNLIKELY( ( finished.hdr.type != FD_TLS_RECORD_FINISHED   )
                 | ( fd_tls_u24_to_uint( finished.hdr.sz ) != 0x20 ) ) )
    return -(long)FD_TLS_ALERT_DECODE_ERROR;

  /* Check "Finished" verify data *************************************/

  /* Export transcript hash */

  fd_sha256_t transcript_clone = transcript;
  uchar transcript_hash[ 32 ];
  fd_sha256_fini( &transcript_clone, transcript_hash );

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
    return -(long)FD_TLS_ALERT_DECRYPT_ERROR;

  /* Done */

  handshake->state = FD_TLS_HS_CONNECTED;

  return 0L;
}

long
fd_tls_server_handshake( fd_tls_server_t const * server,
                         fd_tls_estate_srv_t *    handshake,
                         void const *            record,
                         ulong                   record_sz,
                         int                     encryption_level ) {

  switch( handshake->state ) {
  case FD_TLS_HS_START:
    return fd_tls_server_hs_start( server, handshake, record, record_sz, encryption_level );
  case FD_TLS_HS_WAIT_FINISHED:
    return fd_tls_server_hs_wait_finished( handshake, record, record_sz, encryption_level );
  default:
    return -(long)FD_TLS_ALERT_HANDSHAKE_FAILURE;
  }
}

ulong
fd_tls_client_align( void ) {
  return alignof(fd_tls_client_t);
}

ulong
fd_tls_client_footprint( void ) {
  return sizeof(fd_tls_client_t);
}

void *
fd_tls_client_new( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_tls_client_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }

  ulong fp = fd_tls_client_footprint();
  memset( mem, 0, fp );
  return mem;
}

fd_tls_client_t *
fd_tls_client_join( void * mem ) {
  return (fd_tls_client_t *)mem;
}

void *
fd_tls_client_leave( fd_tls_client_t * client ) {
  return (void *)client;
}

void *
fd_tls_client_delete( void * mem ) {
  return mem;
}

static long fd_tls_client_hs_start           ( fd_tls_client_t const *, fd_tls_estate_cli_t *                     );
static long fd_tls_client_hs_wait_sh         ( fd_tls_client_t const *, fd_tls_estate_cli_t *, void *, ulong, int );
static long fd_tls_client_hs_wait_ee         ( fd_tls_client_t const *, fd_tls_estate_cli_t *, void *, ulong, int );
static long fd_tls_client_hs_wait_cert_cr    ( fd_tls_client_t const *, fd_tls_estate_cli_t *, void *, ulong, int );
static long fd_tls_client_hs_wait_cert       ( fd_tls_client_t const *, fd_tls_estate_cli_t *, void *, ulong, int );
static long fd_tls_client_hs_wait_cert_verify( fd_tls_client_t const *, fd_tls_estate_cli_t *, void *, ulong, int );
static long fd_tls_client_hs_wait_finished   ( fd_tls_client_t const *, fd_tls_estate_cli_t *, void *, ulong, int );

long
fd_tls_client_handshake( fd_tls_client_t const * client,
                         fd_tls_estate_cli_t *   handshake,
                         void *                  record,
                         ulong                   record_sz,
                         int                     encryption_level ) {
  FD_LOG_NOTICE(( "x" ));
  switch( handshake->state ) {
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
    return -(long)FD_TLS_ALERT_HANDSHAKE_FAILURE;
  }
}

static long
fd_tls_client_hs_start( fd_tls_client_t const * const client,
                        fd_tls_estate_cli_t *   const handshake ) {

  /* Message buffer */
# define MSG_BUFSZ 512UL
  uchar msg_buf[ MSG_BUFSZ ];

  /* Transcript hasher */
  fd_sha256_init( &handshake->transcript );

  /* Send ClientHello *************************************************/

  /* Create client random */

  uchar client_random[ 32 ];
  if( FD_UNLIKELY( !fd_tls_rand( &client->rand, client_random, 32UL ) ) )
    return -(long)FD_TLS_ALERT_INTERNAL_ERROR;

  /* Create client hello record */

  ulong client_hello_sz;

  do {
    ulong wire_laddr = (ulong)msg_buf;
    ulong wire_sz    = MSG_BUFSZ;

    /* Leave space for record header */

    void * hdr_ptr = FD_TLS_SKIP_FIELD( fd_tls_record_hdr_t );
    fd_tls_record_hdr_t hdr = { .type = FD_TLS_RECORD_CLIENT_HELLO };

    /* Construct client hello */

    fd_tls_client_hello_t ch = {
      .supported_versions   = { .tls13=1 },
      .supported_groups     = { .x25519=1 },
      .signature_algorithms = { .ed25519=1 },
      .cipher_suites        = { .aes_128_gcm_sha256=1 },
      .key_share            = { .has_x25519=1 },
      .cert_types           = { .x509=1, .raw_pubkey=1 }
    };
    memcpy( ch.random,           client_random,          32UL );
    memcpy( ch.key_share.x25519, client->kex_public_key, 32UL );

    /* Encode client hello */

    ulong msg_sz = FD_TLS_ENCODE_SUB( fd_tls_encode_client_hello, &ch );
    hdr.sz = fd_uint_to_tls_u24( (uint)msg_sz );
    fd_tls_encode_record_hdr( &hdr, hdr_ptr, 4UL );
    client_hello_sz = wire_laddr - (ulong)msg_buf;
  } while(0);

  /* Call back with client hello */

  if( FD_UNLIKELY( !client->sendmsg_fn(
        handshake,
        msg_buf, client_hello_sz,
        FD_TLS_LEVEL_INITIAL,
        /* flush */ 1 ) ) )
    return -(long)FD_TLS_ALERT_INTERNAL_ERROR;

  /* Record client hello in transcript hash */

  fd_sha256_append( &handshake->transcript, msg_buf, client_hello_sz );

  /* Finish up ********************************************************/

  handshake->state = FD_TLS_HS_WAIT_SH;

# undef MSG_BUFSZ
  return 0L;
}

static long
fd_tls_client_hs_wait_sh( fd_tls_client_t const * const client,
                          fd_tls_estate_cli_t *   const handshake,
                          void *                  const record,
                          ulong                   const record_sz,
                          int                     const encryption_level ) {

  if( FD_UNLIKELY( encryption_level != FD_TLS_LEVEL_INITIAL ) )
    return -(long)FD_TLS_ALERT_INTERNAL_ERROR;

  /* Read server hello ************************************************/

  fd_tls_server_hello_t sh[1];

  do {
    ulong wire_laddr = (ulong)record;
    ulong wire_sz    = record_sz;

    /* Decode record header */

    fd_tls_record_hdr_t record_hdr;
    FD_TLS_DECODE_SUB( fd_tls_decode_record_hdr, &record_hdr );

    if( FD_UNLIKELY( record_hdr.type != FD_TLS_RECORD_SERVER_HELLO ) )
      return -(long)FD_TLS_ALERT_UNEXPECTED_MESSAGE;

    /* Decode Server Hello */

    FD_TLS_DECODE_SUB( fd_tls_decode_server_hello, sh );

    /* Fail if trailing bytes detected */

    if( FD_UNLIKELY( wire_laddr != (ulong)record+record_sz ) )
      return -(long)FD_TLS_ALERT_DECODE_ERROR;
  } while(0);

  /* TODO: For now, cryptographic parameters are hardcoded in the
           decoder.  Thus, we skip checks. */

  /* Record server hello in transcript hash */

  fd_sha256_append( &handshake->transcript, record, record_sz );

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
    return -(long)FD_TLS_ALERT_HANDSHAKE_FAILURE;

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

  uchar server_hs_secret[ 32UL ];
  fd_tls_hkdf_expand_label( server_hs_secret,
                            handshake_secret,
                            "s hs traffic",  12UL,
                            transcript_hash, 32UL );

  /* Call back with handshake secrets */

  if( FD_UNLIKELY( !client->secrets_fn(
      handshake,
      /* read secret  */ server_hs_secret,
      /* write secret */ client_hs_secret,
      FD_TLS_LEVEL_HANDSHAKE ) ) )
    return -(long)FD_TLS_ALERT_HANDSHAKE_FAILURE;

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

  /* Finish up ********************************************************/

  handshake->state = FD_TLS_HS_WAIT_EE;

  return 0L;
}

static long
fd_tls_client_hs_wait_ee( fd_tls_client_t const * const client,
                          fd_tls_estate_cli_t *   const handshake,
                          void *                  const record,
                          ulong                   const record_sz,
                          int                     const encryption_level ) {

  (void)client;

  if( FD_UNLIKELY( encryption_level != FD_TLS_LEVEL_HANDSHAKE ) )
    return -(long)FD_TLS_ALERT_INTERNAL_ERROR;

  /* Read EncryptedExtensions (EE) record *****************************/

  do {
    ulong wire_laddr = (ulong)record;
    ulong wire_sz    = record_sz;

    /* Decode record header */

    fd_tls_record_hdr_t record_hdr;
    FD_TLS_DECODE_SUB( fd_tls_decode_record_hdr, &record_hdr );

    if( FD_UNLIKELY( record_hdr.type != FD_TLS_RECORD_ENCRYPTED_EXT ) )
      return -(long)FD_TLS_ALERT_UNEXPECTED_MESSAGE;

    /* Decode EncryptedExtensions */

    FD_TLS_DECODE_LIST_BEGIN( ushort, alignof(uchar) ) {
      ushort ext_type;
      ushort ext_sz;
#     define FIELDS( FIELD )             \
        FIELD( 0, &ext_type, ushort, 1 ) \
        FIELD( 1, &ext_sz,   ushort, 1 )
        FD_TLS_DECODE_STATIC_BATCH( FIELDS )
#     undef FIELDS

      /* Bounds check extension data
         (list_stop declared by DECODE_LIST macro) */
      if( FD_UNLIKELY( (list_stop - wire_laddr) < ext_sz ) )
        return -(long)FD_TLS_ALERT_DECODE_ERROR;

      FD_LOG_NOTICE(( "TODO: Extension" ));

      wire_laddr += ext_sz;
      wire_sz    -= ext_sz;
    }
    FD_TLS_DECODE_LIST_END

    /* Fail if trailing bytes detected */

    if( FD_UNLIKELY( wire_laddr != (ulong)record+record_sz ) )
      return -(long)FD_TLS_ALERT_DECODE_ERROR;
  } while(0);

  /* Record EE in transcript hash */

  fd_sha256_append( &handshake->transcript, record, record_sz );

  /* Finish up ********************************************************/

  handshake->state = FD_TLS_HS_WAIT_CERT_CR;

  return 0L;
}

static long
fd_tls_client_handle_cert( fd_tls_estate_cli_t *   handshake,
                           void *                  cert,
                           ulong                   cert_sz ) {

  if( FD_UNLIKELY( !handshake->server_cert_raw ) ) {
    FD_LOG_WARNING(( "Server sent us an X.509 cert, but we only support raw public keys for now" ));
    return -(long)FD_TLS_ALERT_INTERNAL_ERROR;
  }

  void const * public_key = fd_ed25519_public_key_from_asn1( cert, cert_sz );
  if( FD_UNLIKELY( !public_key ) )
    return -(long)FD_TLS_ALERT_BAD_CERTIFICATE;

  if( FD_UNLIKELY( 0!=memcmp( public_key, handshake->server_pubkey, 32UL ) ) )
    return -(long)FD_TLS_ALERT_HANDSHAKE_FAILURE;

  return 0L;
}

static long
fd_tls_client_hs_wait_cert_cr( fd_tls_client_t const * const client,
                               fd_tls_estate_cli_t *   const handshake,
                               void *                  const record,
                               ulong                   const record_sz,
                               int                     const encryption_level ) {

  (void)client;

  if( FD_UNLIKELY( encryption_level != FD_TLS_LEVEL_HANDSHAKE ) )
    return -(long)FD_TLS_ALERT_INTERNAL_ERROR;

  /* Read Certificate(Request) ****************************************/

  int next_state;

  do {
    ulong wire_laddr = (ulong)record;
    ulong wire_sz    = record_sz;

    /* Decode record header */

    fd_tls_record_hdr_t record_hdr;
    FD_TLS_DECODE_SUB( fd_tls_decode_record_hdr, &record_hdr );

    long res;
    switch( record_hdr.type ) {
    case FD_TLS_RECORD_CERT_REQ:
      /* Ignore content of certificate request */
      res        = 0L;
      next_state = FD_TLS_HS_WAIT_CERT;
      break;
    case FD_TLS_RECORD_CERT:
      res        = fd_tls_client_handle_cert( handshake, record, record_sz );
      next_state = FD_TLS_HS_WAIT_CV;
      break;
    default:
      res = -(long)FD_TLS_ALERT_UNEXPECTED_MESSAGE;
      break;
    }
    if( FD_UNLIKELY( res<0L ) )
      return res;
  } while(0);

  /* Finish up ********************************************************/

  fd_sha256_append( &handshake->transcript, record, record_sz );
  handshake->state = (char)next_state;
  return 0L;
}

static long
fd_tls_client_hs_wait_cert( fd_tls_client_t const * const client,
                            fd_tls_estate_cli_t *   const handshake,
                            void *                  const record,
                            ulong                   const record_sz,
                            int                     const encryption_level ) {

  (void)client;

  if( FD_UNLIKELY( encryption_level != FD_TLS_LEVEL_HANDSHAKE ) )
    return -(long)FD_TLS_ALERT_INTERNAL_ERROR;

  /* Read Certificate *************************************************/

  do {
    ulong wire_laddr = (ulong)record;
    ulong wire_sz    = record_sz;

    /* Decode record header */

    fd_tls_record_hdr_t record_hdr;
    FD_TLS_DECODE_SUB( fd_tls_decode_record_hdr, &record_hdr );

    if( FD_UNLIKELY( record_hdr.type != FD_TLS_RECORD_CERT ) )
      return -(long)FD_TLS_ALERT_UNEXPECTED_MESSAGE;

    long res = fd_tls_client_handle_cert( handshake, record, record_sz );
    if( FD_UNLIKELY( res<0L ) ) return res;
  } while(0);

  /* Finish up ********************************************************/

  fd_sha256_append( &handshake->transcript, record, record_sz );
  handshake->state = (char)FD_TLS_HS_WAIT_CV;
  return 0L;
}

static long
fd_tls_client_hs_wait_cert_verify( fd_tls_client_t const * const client,
                                   fd_tls_estate_cli_t *   const hs,
                                   void *                  const record,
                                   ulong                   const record_sz,
                                   int                     const encryption_level ) {

  (void)client;

  if( FD_UNLIKELY( encryption_level != FD_TLS_LEVEL_HANDSHAKE ) )
    return -(long)FD_TLS_ALERT_INTERNAL_ERROR;

  /* Read CertificateVerify *******************************************/

  fd_tls_cert_verify_t vfy[1];

  do {
    ulong wire_laddr = (ulong)record;
    ulong wire_sz    = record_sz;

    /* Decode record header */

    fd_tls_record_hdr_t record_hdr;
    FD_TLS_DECODE_SUB( fd_tls_decode_record_hdr, &record_hdr );

    if( FD_UNLIKELY( record_hdr.type != FD_TLS_RECORD_CERT_VERIFY ) )
      return -(long)FD_TLS_ALERT_UNEXPECTED_MESSAGE;

    /* Decode CertificateVerify */

    FD_TLS_DECODE_SUB( fd_tls_decode_cert_verify, vfy );

    /* Fail if trailing bytes detected */

    if( FD_UNLIKELY( wire_laddr != (ulong)record+record_sz ) )
      return -(long)FD_TLS_ALERT_DECODE_ERROR;
  } while(0);

  if( FD_UNLIKELY( ( vfy->sig_alg != FD_TLS_SIGNATURE_ED25519 )
                 | ( vfy->sig_sz  != 0x40                     ) ) )
    return -(long)FD_TLS_ALERT_HANDSHAKE_FAILURE;

  /* Verify signature *************************************************/

  /* Export transcript hash ClientHello..server Certificate
     And recover message that was signed */

  uchar sign_msg[ 130 ];
  fd_memcpy( sign_msg, fd_tls13_srv_sign_prefix, 98UL );

  fd_sha256_t transcript_clone = hs->transcript;
  fd_sha256_fini( &transcript_clone, sign_msg+98 );

  /* Verify certificate signature
     > If the verification fails, the receiver MUST terminate the handshake
     > with a "decrypt_error" alert. */

  fd_sha512_t sha512[1];
  int sig_err = fd_ed25519_verify( sign_msg, 130UL, vfy->sig, hs->server_pubkey, sha512 );
  if( FD_UNLIKELY( sig_err != FD_ED25519_SUCCESS ) )
    return -(long)FD_TLS_ALERT_DECRYPT_ERROR;

  /* Finish up ********************************************************/

  fd_sha256_append( &hs->transcript, record, record_sz );
  hs->state = FD_TLS_HS_WAIT_FINISHED;
  return 0L;
}

static long
fd_tls_client_hs_wait_finished( fd_tls_client_t const * const client,
                                fd_tls_estate_cli_t *   const handshake,
                                void *                  const record,
                                ulong                   const record_sz,
                                int                     const encryption_level ) {

  (void)client;
  (void)handshake;
  (void)record;
  (void)record_sz;
  (void)encryption_level;
  FD_LOG_ERR(( "TODO" ));
}
