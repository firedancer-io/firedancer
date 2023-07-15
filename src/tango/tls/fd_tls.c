#include "fd_tls.h"
#include "fd_tls_proto.h"
#include "fd_tls_serde.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/ed25519/fd_x25519.h"
#include "../../ballet/hmac/fd_hmac.h"

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

fd_tls_server_hs_t *
fd_tls_server_hs_new( void * mem ) {

  fd_tls_server_hs_t * hs = mem;

  memset( hs, 0, sizeof(*hs) );
  hs->state = FD_TLS_HS_START;

  /* Assume X.509 unless otherwise specified using CertificateType ext */
  hs->client_cert_type = FD_TLS_CERTTYPE_X509;
  hs->server_cert_type = FD_TLS_CERTTYPE_X509;

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
                        fd_tls_server_hs_t *    const handshake,
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
  if( FD_UNLIKELY( !server->rand_fn( server_random, 32UL ) ) )
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

  /* No early secret, derive dummy value */

  //static uchar const psk[ 32 ] = {0};
  //uchar early_secret[ 32 ];
  //fd_hmac_sha256( /* data */ psk, 32UL,
  //                /* salt */ NULL, 0UL,
  //                early_secret );
  static uchar const early_secret[ 32 ] =
    { 0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b,
      0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68, 0x0c, 0xe2,
      0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60,
      0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a };

  /* SHA-256 empty hash (TODO cache) */
  static uchar const empty_hash[ 32 ] =
    { 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
      0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
      0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55 };

  /* Derive root of handshake stage */
  /* TODO Cache this, since it's always the same */

  uchar handshake_derived[ 32 ];
  fd_tls_hkdf_expand_label( handshake_derived,
                            early_secret,
                            "derived",   7UL,
                            empty_hash, 32UL );

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

    /* Add custom extensions */

    void const * const * exts = server->encrypted_exts_fn( handshake );
    for( void const * ext = *exts; ext; ext = *++exts ) {
      /* Peek extension length */
      ulong ext_sz = 4UL + fd_ushort_bswap( FD_LOAD( ushort, (uchar const *)ext+2UL ) );
      /* Copy extension data */
      fd_memcpy( FD_TLS_SKIP_FIELDS( uchar, ext_sz ), ext, ext_sz );
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

  /* Create signing prefix */

  char verify_preimage[ 130 ] =
    "                                "  /* 32 spaces */
    "                                "  /* 32 spaces */
    "TLS 1.3, server CertificateVerify";

  /* Export transcript hash ClientHello..Certificate */

  transcript_clone = transcript;
  fd_sha256_fini( &transcript_clone, verify_preimage+98 );

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
                   verify_preimage, 130UL,
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
fd_tls_server_hs_wait_finished( fd_tls_server_hs_t *    const handshake,
                                void const *            const record,
                                ulong                         record_sz,
                                int                           encryption_level ) {

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
                         fd_tls_server_hs_t *    handshake,
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

