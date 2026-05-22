#include "fd_bundle_auth.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/pb/fd_pb_encode.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../disco/keyguard/fd_keyguard_client.h"

#define FD_BUNDLE_AUTH_REQUEST_TIMEOUT ((long)5e9) /* 5 seconds */

/* fd_bundle_auther_t generates auth tokens and keeps them refreshed. */

fd_bundle_auther_t *
fd_bundle_auther_init( fd_bundle_auther_t * auther ) {
  *auther = (fd_bundle_auther_t) {
    .state      = FD_BUNDLE_AUTH_STATE_REQ_CHALLENGE,
    .needs_poll = 1
  };
  return auther;
}

void
fd_bundle_auther_handle_request_fail( fd_bundle_auther_t * auther ) {
  switch( auther->state ) {
  case FD_BUNDLE_AUTH_STATE_WAIT_CHALLENGE:
    FD_LOG_DEBUG(( "Request for auth challenge failed, retrying" ));
    auther->state = FD_BUNDLE_AUTH_STATE_REQ_CHALLENGE;
    auther->needs_poll = 1;
    break;
  case FD_BUNDLE_AUTH_STATE_WAIT_TOKENS:
    FD_LOG_DEBUG(( "Request for auth tokens failed" ));
    auther->state = FD_BUNDLE_AUTH_STATE_REQ_CHALLENGE;
    auther->needs_poll = 1;
    break;
  }
}

static void
fd_bundle_auther_req_challenge( fd_bundle_auther_t *   auther,
                                fd_grpc_client_t *     client ) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( client ) ) ) return;

  uchar req[ 256 ];
  fd_pb_encoder_t enc; fd_pb_encoder_init( &enc, req, sizeof(req) );
  fd_pb_push_uint32( &enc, 1, 2 ); /* role = VALIDATOR */
  fd_pb_push_bytes( &enc, 2, auther->pubkey, 32 ); /* pubkey */

  static char const path[] = "/auth.AuthService/GenerateAuthChallenge";
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      client,
      path, sizeof(path)-1,
      FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthChallenge,
      req, fd_pb_encoder_out_sz( &enc ),
      NULL, 0,
      0 /* is_streaming */
  );
  if( FD_UNLIKELY( !request ) ) return;

  auther->state      = FD_BUNDLE_AUTH_STATE_WAIT_CHALLENGE;
  auther->needs_poll = 0;
  fd_grpc_client_deadline_set(
      request,
      FD_GRPC_DEADLINE_RX_END,
      fd_log_wallclock()+FD_BUNDLE_AUTH_REQUEST_TIMEOUT );

  char key_cstr[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( auther->pubkey, NULL, key_cstr );
  FD_LOG_INFO(( "Requesting bundle auth challenge (identity=%s)", key_cstr ));
}

int
fd_bundle_auther_handle_challenge_resp(
    fd_bundle_auther_t * auther,
    fd_pb_inbuf_t        in
) {
  auther->needs_poll = 1;

  int found_challenge = 0;
  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t tlv[1]; if( FD_UNLIKELY( !fd_pb_tlv_read( &in, tlv ) ) ) goto fail;
    if( tlv->field_id==1 ) { /* challenge */
      uchar const * chal = fd_pb_tlv_bytes( &in, tlv );
      if( FD_UNLIKELY( !chal || tlv->len != 9UL ) ) goto fail;
      memcpy( auther->challenge, chal, 9UL );
      found_challenge = 1;
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, tlv ) ) ) goto fail;
  }
  if( FD_UNLIKELY( !found_challenge ) ) goto fail;

  auther->state = FD_BUNDLE_AUTH_STATE_REQ_TOKENS;
  FD_LOG_DEBUG(( "Got auth challenge" ));
  return 1;

fail:
  FD_LOG_WARNING(( "Failed to decode auth challenge response" ));
  fd_bundle_auther_reset( auther );
  return 0;
}

static void
fd_bundle_auther_req_tokens( fd_bundle_auther_t *   auther,
                             fd_grpc_client_t *     client,
                             fd_keyguard_client_t * keyguard ) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( client ) ) ) return;

  /* Format challenge string as '{base58(pubkey)}-{challenge}' */
  ulong enc_len;
  char p_[ 128 ]; char * p = p_;
  fd_base58_encode_32( auther->pubkey, &enc_len, p );
  p += enc_len;
  p = fd_cstr_append_char( p, '-' );
  p = fd_cstr_append_text( p, auther->challenge, 9UL );
  ulong chal_len = (ulong)p - (ulong)p_;

  uchar req[ 256 ];
  fd_pb_encoder_t enc; fd_pb_encoder_init( &enc, req, sizeof(req) );
  fd_pb_push_bytes( &enc, 1, p, chal_len ); /* challenge */
  fd_pb_push_bytes( &enc, 2, auther->pubkey, 32 ); /* client_pubkey */
  uchar signed_chal[ 64 ];
  fd_keyguard_client_sign( keyguard, signed_chal, (uchar const *)auther->challenge, 9UL, FD_KEYGUARD_SIGN_TYPE_PUBKEY_CONCAT_ED25519 );
  fd_pb_push_bytes( &enc, 3, signed_chal, 64 ); /* signed_challenge */

  static char const path[] = "/auth.AuthService/GenerateAuthTokens";
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      client,
      path, sizeof(path)-1,
      FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthTokens,
      req, fd_pb_encoder_out_sz( &enc ),
      NULL, 0,
      0 /* is_streaming */
  );
  if( FD_UNLIKELY( !request ) ) return;

  auther->state      = FD_BUNDLE_AUTH_STATE_WAIT_TOKENS;
  auther->needs_poll = 0;
  fd_grpc_client_deadline_set(
      request,
      FD_GRPC_DEADLINE_RX_END,
      fd_log_wallclock()+FD_BUNDLE_AUTH_REQUEST_TIMEOUT );

  FD_LOG_DEBUG(( "Requesting bundle auth tokens" ));
}

static char const *
extract_token( char *        tok,
               ushort *      tok_sz,
               ushort        tok_max,
               fd_pb_inbuf_t in ) {
  int found_tok = 0;
  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t tlv[1]; if( FD_UNLIKELY( !fd_pb_tlv_read( &in, tlv ) ) ) return NULL;
    if( tlv->field_id==1 ) { /* access_token */
      uchar const * t = fd_pb_tlv_bytes( &in, tlv );
      if( FD_UNLIKELY( !t ) ) return NULL;
      if( FD_UNLIKELY( tlv->len > tok_max ) ) {
        FD_LOG_WARNING(( "Access token in auth.GenerateAuthTokensResponse is too long: %lu bytes", tlv->len ));
        return NULL;
      }
      fd_memcpy( tok, t, tlv->len );
      *tok_sz = (ushort)tlv->len;
      found_tok = 1;
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, tlv ) ) ) return NULL;
  }
  return found_tok ? tok : NULL;
}

int
fd_bundle_auther_handle_tokens_resp(
    fd_bundle_auther_t * auther,
    fd_pb_inbuf_t        in
) {
  auther->access_token_sz = 0UL;

  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t tlv[1]; if( FD_UNLIKELY( !fd_pb_tlv_read( &in, tlv ) ) ) goto fail;
    switch( tlv->field_id ) {
    case 1: { /* access_token */
      fd_pb_inbuf_t sub;
      if( FD_UNLIKELY( !fd_pb_tlv_submsg( &in, tlv, &sub ) ) ) goto fail;
      if( FD_UNLIKELY( !extract_token( auther->access_token, &auther->access_token_sz, sizeof(auther->access_token), sub ) ) ) goto fail;
      break;
    }
    default:
      break;
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, tlv ) ) ) goto fail;
  }

  if( FD_UNLIKELY( !auther->access_token_sz ) ) {
    FD_LOG_WARNING(( "Auth tokens response did not contain access token" ));
    goto fail;
  }

  auther->state = FD_BUNDLE_AUTH_STATE_DONE_WAIT;
  FD_LOG_DEBUG(( "Got auth tokens" ));
  return 1;

fail:
  FD_LOG_WARNING(( "Failed to decode auth tokens response" ));
  fd_bundle_auther_reset( auther );
  return 0;
}

void
fd_bundle_auther_poll( fd_bundle_auther_t *   auther,
                       fd_grpc_client_t *     client,
                       fd_keyguard_client_t * keyguard ) {
  switch( auther->state ) {
  case FD_BUNDLE_AUTH_STATE_REQ_CHALLENGE:
    fd_bundle_auther_req_challenge( auther, client );
    break;
  case FD_BUNDLE_AUTH_STATE_REQ_TOKENS:
    fd_bundle_auther_req_tokens( auther, client, keyguard );
    break;
  default:
    break;
  }
}

void
fd_bundle_auther_reset( fd_bundle_auther_t * auther ) {
  auther->state      = FD_BUNDLE_AUTH_STATE_REQ_CHALLENGE;
  auther->needs_poll = 1;
}
