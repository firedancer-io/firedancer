#ifndef HEADER_fd_src_disco_bundle_fd_bundle_auth_h
#define HEADER_fd_src_disco_bundle_fd_bundle_auth_h

/* fd_bundle_auth.h acquires an auth token for a bundle server.

   The auth flow is as follows:
   - Client requests a challenge-response transaction
   - Server returns a 9 byte "challenge" to be signed using the client's
     identity key
   - Client sends back the signed challenge and requests an auth token
   - Server returns an auth token and a refresh token  */

#include "../../waltz/grpc/fd_grpc_client.h"
#include "../../disco/keyguard/fd_keyguard_client.h"

struct fd_bundle_auther {
  int   state;
  uint  needs_poll : 1;
  uchar pubkey[ 32 ];

  char   challenge[ 9 ];
  char   access_token[ 1024 ];
  ushort access_token_sz;
};

typedef struct fd_bundle_auther fd_bundle_auther_t;

#define FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthChallenge         1
#define FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthTokens            2
//#define FD_BUNDLE_CLIENT_REQ_Auth_RefreshAccessToken            3

#define FD_BUNDLE_AUTH_STATE_REQ_CHALLENGE  0
#define FD_BUNDLE_AUTH_STATE_WAIT_CHALLENGE 1
#define FD_BUNDLE_AUTH_STATE_REQ_TOKENS     2
#define FD_BUNDLE_AUTH_STATE_WAIT_TOKENS    3
#define FD_BUNDLE_AUTH_STATE_DONE_WAIT      4

FD_PROTOTYPES_BEGIN

fd_bundle_auther_t *
fd_bundle_auther_init( fd_bundle_auther_t * auther );

/* fd_bundle_auther_poll does request work.  Should be called as soon as
   possible if auther->needs_poll is set.  Otherwise, should be called
   at a low rate (once every ~100ms). */

void
fd_bundle_auther_poll( fd_bundle_auther_t *   auther,
                       fd_grpc_client_t *     client,
                       fd_keyguard_client_t * keyguard );

/* fd_bundle_auther_reset restarts authentication.  Intended to be
   called when a request fails with an auth failure. */

void
fd_bundle_auther_reset( fd_bundle_auther_t * auther );

/* Response handlers */

void
fd_bundle_auther_handle_request_fail( fd_bundle_auther_t * auther );

int
fd_bundle_auther_handle_challenge_resp(
    fd_bundle_auther_t * auther,
    void const *         data,
    ulong                data_sz
);

int
fd_bundle_auther_handle_tokens_resp(
    fd_bundle_auther_t * auther,
    void const *         data,
    ulong                data_sz
);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_bundle_fd_bundle_auth_h */
