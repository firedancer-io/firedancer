#ifndef HEADER_fd_src_disco_bundle_fd_bundle_auth_h
#define HEADER_fd_src_disco_bundle_fd_bundle_auth_h

#include "../../waltz/grpc/fd_grpc_client.h"
#include "../../disco/keyguard/fd_keyguard_client.h"

struct fd_bundle_auther {
  fd_grpc_client_t *     client;
  fd_keyguard_client_t * keyguard;

  int  state;
  uchar pubkey[ 32 ];

  uchar challenge[ 9 ];
  char  access_token [ 256 ];
  char  refresh_token[ 256 ];
  uchar access_token_sz;
  uchar refresh_token_sz;
};

typedef struct fd_bundle_auther fd_bundle_auther_t;

#define FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthChallenge         1
#define FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthTokens            2
#define FD_BUNDLE_CLIENT_REQ_Auth_RefreshAccessToken            3

#define STATE_START          0
#define STATE_WAIT_CHALLENGE 1
#define STATE_REQ_TOKENS     2
#define STATE_WAIT_TOKENS    3
#define STATE_DONE_WAIT      4
#define STATE_WAIT_REFRESH   5

FD_PROTOTYPES_BEGIN

fd_bundle_auther_t *
fd_bundle_auther_init( fd_bundle_auther_t * auther );

void
fd_bundle_auther_start( fd_bundle_auther_t * auther );

void
fd_bundle_auther_handle_challenge_resp(
    fd_bundle_auther_t * auther,
    void const *         data,
    ulong                data_sz
);

void
fd_bundle_auther_handle_tokens_resp(
    fd_bundle_auther_t * auther,
    void const *         data,
    ulong                data_sz
);

void
fd_bundle_auther_handle_refresh_resp(
    fd_bundle_auther_t * auther,
    void const *         data,
    ulong                data_sz
);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_bundle_fd_bundle_auth_h */
