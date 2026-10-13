#include "fd_bundle_auth.h"
#include "proto/auth.pb.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../third_party/nanopb/pb_decode.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../disco/keyguard/fd_keyguard_client.h"

#define FD_BUNDLE_AUTH_REQUEST_TIMEOUT ((long)5e9) /* 5 seconds */

/* fd_bundle_auther_t generates auth tokens and keeps them refreshed. */

/* FIXME consider rewriting this with coroutines or light threads */

fd_bundle_auther_t *
fd_bundle_auther_init( fd_bundle_auther_t * auther ) {
  *auther = (fd_bundle_auther_t) {
    .state      = FD_BUNDLE_AUTH_STATE_REQ_CHALLENGE,
    .needs_poll = 1,
    .refresh_at = LONG_MAX,
    .reauth_at  = LONG_MAX
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
  case FD_BUNDLE_AUTH_STATE_WAIT_REFRESH:
    FD_LOG_DEBUG(( "Request to refresh access token failed, re-authenticating" ));
    auther->state = FD_BUNDLE_AUTH_STATE_REQ_CHALLENGE;
    auther->needs_poll = 1;
    break;
  }
}

static void
fd_bundle_auther_req_challenge( fd_bundle_auther_t *   auther,
                                fd_grpc_client_t *     client ) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( client ) ) ) return;

  auth_GenerateAuthChallengeRequest req = {0};
  req.role = auth_Role_VALIDATOR;
  memcpy( req.pubkey.bytes, auther->pubkey, 32 );
  req.pubkey.size = 32;

  static char const path[] = "/auth.AuthService/GenerateAuthChallenge";
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      client,
      path, sizeof(path)-1,
      FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthChallenge,
      &auth_GenerateAuthChallengeRequest_msg, &req,
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

  pb_istream_t istream = pb_istream_from_buffer( data, data_sz );
  auth_GenerateAuthChallengeResponse resp = auth_GenerateAuthChallengeResponse_init_default;
  int decode_ok = pb_decode( &istream, &auth_GenerateAuthChallengeResponse_msg, &resp );
  if( FD_UNLIKELY( !decode_ok ) ) {
    FD_LOG_WARNING(( "Protobuf decode of (auth.GenerateAuthChallengeResponse) failed" ));
    goto fail;
  }
  if( FD_UNLIKELY( resp.challenge.size!=9UL ) ) {
    FD_LOG_WARNING(( "Unexpected auth.GenerateAuthChallengeResponse challenge size: %u bytes", resp.challenge.size ));
    goto fail;
  }
  memcpy( auther->challenge, resp.challenge.bytes, 9UL );

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

  auth_GenerateAuthTokensRequest req = {0};

  /* Format challenge string as '{base58(pubkey)}-{challenge}' */
  ulong enc_len;
  char * p = (char *)req.challenge.bytes;
  fd_base58_encode_32( auther->pubkey, &enc_len, p );
  p += enc_len;
  p = fd_cstr_append_char( p, '-' );
  p = fd_cstr_append_text( p, auther->challenge, 9UL );
  req.challenge.size = (uint)( (ulong)p - (ulong)req.challenge.bytes );

  memcpy( req.client_pubkey.bytes, auther->pubkey, 32UL );
  req.client_pubkey.size = 32UL;

  fd_keyguard_client_sign( keyguard, req.signed_challenge.bytes, (uchar const *)auther->challenge, 9UL, FD_KEYGUARD_SIGN_TYPE_PUBKEY_CONCAT_ED25519 );
  req.signed_challenge.size = 64UL;

  static char const path[] = "/auth.AuthService/GenerateAuthTokens";
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      client,
      path, sizeof(path)-1,
      FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthTokens,
      &auth_GenerateAuthTokensRequest_msg, &req,
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

static long
fd_bundle_auther_half_life( auth_Token const * token,
                            long               now ) {
  if( FD_UNLIKELY( !token->has_expires_at_utc ) ) return LONG_MAX;
  long sec = token->expires_at_utc.seconds;
  if( FD_UNLIKELY( sec<=0L || sec>=LONG_MAX/(long)1e9-1L ) ) return LONG_MAX;
  long expires_at = sec*(long)1e9 + (long)token->expires_at_utc.nanos;
  if( FD_UNLIKELY( expires_at<=now ) ) return LONG_MAX;
  return now + (expires_at-now)/2L;
}

int
fd_bundle_auther_handle_tokens_resp(
    fd_bundle_auther_t * auther,
    void const *         data,
    ulong                data_sz,
    long                 now
) {
  pb_istream_t istream = pb_istream_from_buffer( data, data_sz );
  auth_GenerateAuthTokensResponse resp = auth_GenerateAuthTokensResponse_init_default;
  int decode_ok = pb_decode( &istream, &auth_GenerateAuthTokensResponse_msg, &resp );
  if( FD_UNLIKELY( !decode_ok ) ) {
    FD_LOG_WARNING(( "Protobuf decode of (auth.GenerateAuthTokensResponse) failed" ));
    goto fail;
  }
  if( FD_UNLIKELY( !resp.has_access_token || resp.access_token.value.size==0 ) ) {
    FD_LOG_WARNING(( "auth.GenerateAuthTokensResponse: missing access_token" ));
    goto fail;
  }
  if( FD_UNLIKELY( resp.access_token.value.size > sizeof(auther->access_token) ) ) {
    FD_LOG_WARNING(( "auth.GenerateAuthTokensResponse: oversz access_token: %u bytes", resp.access_token.value.size ));
    goto fail;
  }
  if( FD_UNLIKELY( !resp.has_refresh_token || resp.refresh_token.value.size==0 ) ) {
    FD_LOG_WARNING(( "auth.GenerateAuthTokensResponse: missing refresh_token" ));
    goto fail;
  }
  if( FD_UNLIKELY( resp.refresh_token.value.size > sizeof(auther->refresh_token) ) ) {
    FD_LOG_WARNING(( "auth.GenerateAuthTokensResponse: oversz refresh_token: %u bytes", resp.refresh_token.value.size ));
    goto fail;
  }

  fd_memcpy( auther->access_token, resp.access_token.value.bytes, resp.access_token.value.size );
  auther->access_token_sz = (ushort)resp.access_token.value.size;
  auther->refresh_at      = fd_bundle_auther_half_life( &resp.access_token, now );

  fd_memcpy( auther->refresh_token, resp.refresh_token.value.bytes, resp.refresh_token.value.size );
  auther->refresh_token_sz = (ushort)resp.refresh_token.value.size;
  auther->reauth_at        = fd_bundle_auther_half_life( &resp.refresh_token, now );

  auther->state = FD_BUNDLE_AUTH_STATE_DONE_WAIT;
  FD_LOG_DEBUG(( "Got auth tokens" ));
  return 1;

fail:
  auther->state = FD_BUNDLE_AUTH_STATE_REQ_CHALLENGE;
  auther->needs_poll = 1;
  return 0;
}

static void
fd_bundle_auther_req_refresh( fd_bundle_auther_t * auther,
                              fd_grpc_client_t *   client ) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( client ) ) ) return;

  auth_RefreshAccessTokenRequest req = {0};
  memcpy( req.refresh_token.bytes, auther->refresh_token, auther->refresh_token_sz );
  req.refresh_token.size = auther->refresh_token_sz;

  static char const path[] = "/auth.AuthService/RefreshAccessToken";
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      client,
      path, sizeof(path)-1,
      FD_BUNDLE_CLIENT_REQ_Auth_RefreshAccessToken,
      &auth_RefreshAccessTokenRequest_msg, &req,
      NULL, 0,
      0 /* is_streaming */
  );
  if( FD_UNLIKELY( !request ) ) return;

  auther->state      = FD_BUNDLE_AUTH_STATE_WAIT_REFRESH;
  auther->needs_poll = 0;
  fd_grpc_client_deadline_set(
      request,
      FD_GRPC_DEADLINE_RX_END,
      fd_log_wallclock()+FD_BUNDLE_AUTH_REQUEST_TIMEOUT );

  FD_LOG_DEBUG(( "Requesting bundle access token refresh" ));
}

int
fd_bundle_auther_handle_refresh_resp(
    fd_bundle_auther_t * auther,
    void const *         data,
    ulong                data_sz,
    long                 now
) {
  /* Auth restarted while the refresh was in flight */
  if( FD_UNLIKELY( auther->state!=FD_BUNDLE_AUTH_STATE_WAIT_REFRESH ) ) return 1;

  pb_istream_t istream = pb_istream_from_buffer( data, data_sz );
  auth_RefreshAccessTokenResponse resp = auth_RefreshAccessTokenResponse_init_default;
  int decode_ok = pb_decode( &istream, &auth_RefreshAccessTokenResponse_msg, &resp );
  if( FD_UNLIKELY( !decode_ok ) ) {
    FD_LOG_WARNING(( "Protobuf decode of (auth.RefreshAccessTokenResponse) failed" ));
    goto fail;
  }
  if( FD_UNLIKELY( !resp.has_access_token || resp.access_token.value.size==0 ) ) {
    FD_LOG_WARNING(( "auth.RefreshAccessTokenResponse: missing access_token" ));
    goto fail;
  }
  if( FD_UNLIKELY( resp.access_token.value.size > sizeof(auther->access_token) ) ) {
    FD_LOG_WARNING(( "auth.RefreshAccessTokenResponse: oversz access_token: %u bytes", resp.access_token.value.size ));
    goto fail;
  }

  fd_memcpy( auther->access_token, resp.access_token.value.bytes, resp.access_token.value.size );
  auther->access_token_sz = (ushort)resp.access_token.value.size;
  auther->refresh_at      = fd_bundle_auther_half_life( &resp.access_token, now );
  auther->state = FD_BUNDLE_AUTH_STATE_DONE_WAIT;
  FD_LOG_DEBUG(( "Refreshed access token" ));
  return 1;

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
  case FD_BUNDLE_AUTH_STATE_REQ_REFRESH:
    fd_bundle_auther_req_refresh( auther, client );
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

void
fd_bundle_auther_refresh( fd_bundle_auther_t * auther ) {
  auther->state      = FD_BUNDLE_AUTH_STATE_REQ_REFRESH;
  auther->needs_poll = 1;
}
