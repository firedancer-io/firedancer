#include "fd_bundle_auth.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/pb/fd_pb_encode.h"
#include "../../ballet/pb/fd_pb_tokenize.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../disco/keyguard/fd_keyguard_client.h"

#define FD_BUNDLE_AUTH_REQUEST_TIMEOUT ((long)5e9) /* 5 seconds */

/* fd_bundle_auther_t generates auth tokens and keeps them refreshed. */

/* FIXME consider rewriting this with coroutines or light threads */

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

  uchar req[ 64 ];
  fd_pb_encoder_t enc[1]; fd_pb_encoder_init( enc, req, sizeof(req) );
  FD_TEST( fd_pb_push_uint32( enc, 1U, 2U ) ); /* role = VALIDATOR */
  FD_TEST( fd_pb_push_bytes( enc, 2U, auther->pubkey, 32UL ) ); /* pubkey */

  static char const path[] = "/auth.AuthService/GenerateAuthChallenge";
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      client,
      path, sizeof(path)-1,
      FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthChallenge,
      req, fd_pb_encoder_out_sz( enc ),
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
    void const *         data,
    ulong                data_sz
) {
  auther->needs_poll = 1;

  fd_pb_inbuf_t in[1]; fd_pb_inbuf_init( in, data, data_sz );
  int found_challenge = 0;
  while( fd_pb_inbuf_sz( in ) ) {
    fd_pb_tlv_t tlv[1];
    if( FD_UNLIKELY( !fd_pb_tlv_read( in, tlv ) ) ) {
      FD_LOG_WARNING(( "Protobuf decode of (auth.GenerateAuthChallengeResponse) failed" ));
      goto fail;
    }
    if( tlv->field_id==1U ) { /* challenge */
      uchar const * chal = fd_pb_tlv_bytes( in, tlv );
      if( FD_UNLIKELY( !chal ) ) {
        FD_LOG_WARNING(( "Protobuf decode of (auth.GenerateAuthChallengeResponse) failed" ));
        goto fail;
      }
      if( FD_UNLIKELY( tlv->len!=9UL ) ) {
        FD_LOG_WARNING(( "Unexpected auth.GenerateAuthChallengeResponse challenge size: %lu bytes", tlv->len ));
        goto fail;
      }
      memcpy( auther->challenge, chal, 9UL );
      found_challenge = 1;
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( in, tlv ) ) ) {
      FD_LOG_WARNING(( "Protobuf decode of (auth.GenerateAuthChallengeResponse) failed" ));
      goto fail;
    }
  }
  if( FD_UNLIKELY( !found_challenge ) ) {
    FD_LOG_WARNING(( "auth.GenerateAuthChallengeResponse: missing challenge" ));
    goto fail;
  }

  auther->state = FD_BUNDLE_AUTH_STATE_REQ_TOKENS;
  FD_LOG_DEBUG(( "Got auth challenge" ));
  return 1;

fail:
  auther->state = FD_BUNDLE_AUTH_STATE_REQ_CHALLENGE;
  return 0;
}

static void
fd_bundle_auther_req_tokens( fd_bundle_auther_t *   auther,
                             fd_grpc_client_t *     client,
                             fd_keyguard_client_t * keyguard ) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( client ) ) ) return;

  /* Format challenge string as '{base58(pubkey)}-{challenge}' */
  char  chal[ FD_BASE58_ENCODED_32_SZ+1UL+9UL ];
  ulong enc_len;
  char * p = chal;
  fd_base58_encode_32( auther->pubkey, &enc_len, p );
  p += enc_len;
  p = fd_cstr_append_char( p, '-' );
  p = fd_cstr_append_text( p, auther->challenge, 9UL );
  ulong chal_sz = (ulong)p - (ulong)chal;

  uchar signed_chal[ 64 ];
  fd_keyguard_client_sign( keyguard, signed_chal, (uchar const *)auther->challenge, 9UL, FD_KEYGUARD_SIGN_TYPE_PUBKEY_CONCAT_ED25519 );

  uchar req[ 256 ];
  fd_pb_encoder_t enc[1]; fd_pb_encoder_init( enc, req, sizeof(req) );
  FD_TEST( fd_pb_push_bytes( enc, 1U, chal,           chal_sz ) ); /* challenge */
  FD_TEST( fd_pb_push_bytes( enc, 2U, auther->pubkey, 32UL    ) ); /* client_pubkey */
  FD_TEST( fd_pb_push_bytes( enc, 3U, signed_chal,    64UL    ) ); /* signed_challenge */

  static char const path[] = "/auth.AuthService/GenerateAuthTokens";
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      client,
      path, sizeof(path)-1,
      FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthTokens,
      req, fd_pb_encoder_out_sz( enc ),
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

int
fd_bundle_auther_handle_tokens_resp(
    fd_bundle_auther_t * auther,
    void const *         data,
    ulong                data_sz
) {
  /* GenerateAuthTokensResponse.access_token (Token) .value (bytes) */
  uchar const * tok    = NULL;
  ulong         tok_sz = 0UL;
  fd_pb_inbuf_t in[1]; fd_pb_inbuf_init( in, data, data_sz );
  while( fd_pb_inbuf_sz( in ) ) {
    fd_pb_tlv_t tlv[1];
    if( FD_UNLIKELY( !fd_pb_tlv_read( in, tlv ) ) ) goto decode_fail;
    if( tlv->field_id==1U ) { /* access_token */
      fd_pb_inbuf_t sub[1];
      if( FD_UNLIKELY( !fd_pb_tlv_submsg( in, tlv, sub ) ) ) goto decode_fail;
      tok = NULL; tok_sz = 0UL;
      while( fd_pb_inbuf_sz( sub ) ) {
        fd_pb_tlv_t tlv2[1];
        if( FD_UNLIKELY( !fd_pb_tlv_read( sub, tlv2 ) ) ) goto decode_fail;
        if( tlv2->field_id==1U ) { /* value */
          tok = fd_pb_tlv_bytes( sub, tlv2 );
          if( FD_UNLIKELY( !tok ) ) goto decode_fail;
          tok_sz = tlv2->len;
        }
        if( FD_UNLIKELY( !fd_pb_tlv_skip( sub, tlv2 ) ) ) goto decode_fail;
      }
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( in, tlv ) ) ) goto decode_fail;
  }
  if( FD_UNLIKELY( !tok || !tok_sz ) ) {
    FD_LOG_WARNING(( "auth.GenerateAuthTokensResponse: missing access_token" ));
    goto fail;
  }
  if( FD_UNLIKELY( tok_sz > sizeof(auther->access_token) ) ) {
    FD_LOG_WARNING(( "auth.GenerateAuthTokensResponse: oversz access_token: %lu bytes", tok_sz ));
    goto fail;
  }

  fd_memcpy( auther->access_token, tok, tok_sz );
  auther->access_token_sz = (ushort)tok_sz;
  auther->state = FD_BUNDLE_AUTH_STATE_DONE_WAIT;
  FD_LOG_DEBUG(( "Got auth tokens" ));
  return 1;

decode_fail:
  FD_LOG_WARNING(( "Protobuf decode of (auth.GenerateAuthTokensResponse) failed" ));
fail:
  auther->state = FD_BUNDLE_AUTH_STATE_REQ_CHALLENGE;
  auther->needs_poll = 1;
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
