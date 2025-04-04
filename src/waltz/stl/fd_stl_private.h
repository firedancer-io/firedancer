#ifndef HEADER_stl_private_h
#define HEADER_stl_private_h

/* stl_private.h contains reusable internal modules.  The APIs in this
   file may change without notice. */

#include "fd_stl_base.h"
#include "fd_stl_proto.h"
#include "fd_stl_sesh.h"
#include "fd_stl_sesh_map.h"
#include "fd_stl_s0_server.h"
#include "fd_stl_s0_client.h"

#include "../../util/rng/fd_rng.h"

/* OBJECT POOLS to go in internal state */
// #define POOL_NAME fd_stl_hs_pool
// #define POOL_T    fd_stl_hs_t
// #include "../../util/tmpl/fd_pool.c"

// #define POOL_NAME fd_stl_sesh_pool
// #define POOL_T    fd_stl_sesh_t
// #include "../../util/tmpl/fd_pool.c"

// #define POOL_NAME fd_stl_pkt_buf_pool
// #define POOL_T    fd_stl_pkt_buf_t
// #include "../../util/tmpl/fd_pool.c"



/* stl_cookie_claims_t contains the public data hashed into the
   cookie value. */

/* TODO - use FD utilities to deal with alignment and packing */
union __attribute__((aligned(8UL))) stl_cookie_claims {

  struct __attribute__((packed)) {
    stl_net_ctx_t net;
  };

# define STL_COOKIE_CLAIMS_B_SZ (8UL)
  uchar b[ STL_COOKIE_CLAIMS_B_SZ ];

};

typedef union stl_cookie_claims stl_cookie_claims_t;


_Static_assert( sizeof(stl_cookie_claims_t) == STL_COOKIE_CLAIMS_B_SZ,
                "stl_cookie_claims_t is not packed" );



/* TODO - 16 alignment copied from quic, does it make sense? */
struct __attribute__((aligned(16UL))) fd_stl_state_private {
//TODO    fd_stl_sesh_map_t *    sesh_map;       /* map session ids -> sessions */
  // TODO add a session pool
  fd_stl_sesh_t sessions[FD_STL_MAX_SESSION_TMP];
  uchar session_sz;

  // TODO add a handshake pool
  fd_stl_s0_server_hs_t server_hs[FD_STL_MAX_SESSION_TMP];
  uchar server_hs_sz;

  fd_stl_s0_client_hs_t client_hs[FD_STL_MAX_SESSION_TMP];
  uchar client_hs_sz;

  // TODO move buffering from hs to shared, use pool
  fd_rng_t                _rng[1];        /* random number generator */
};
typedef struct fd_stl_state_private fd_stl_state_private_t;

FD_PROTOTYPES_BEGIN

/* stl_cookie_create issues a cookie for the Server Continue
   packet.  hs contains the incoming Client Initial packet for which
   a cookie should be issued.  Writes the HMAC cookie to the given
   array and returns it. */

uchar *
stl_cookie_create( uchar                     cookie[ static STL_COOKIE_SZ ],
                   stl_cookie_claims_t const * ctx,
                   uchar const               cookie_secret[ static STL_COOKIE_KEY_SZ ] );

/* stl_cookie_verify verifies a cookie in a Client Accept
   packet.  Returns 1 if cookie is valid.  Otherwise, returns 0. */

__attribute__((pure,warn_unused_result))
int
stl_cookie_verify( uchar const               cookie[ static STL_COOKIE_SZ ],
                   stl_cookie_claims_t const * ctx,
                   uchar const               cookie_secret[ static STL_COOKIE_KEY_SZ ] );

/* stl_gen_session_id generates a new random session ID. */

void
stl_gen_session_id( uchar session_id[ static STL_SESSION_ID_SZ ] );

void
fd_stl_s0_crypto_key_share_generate( uchar private_key[32], uchar public_key[32] );

void
fd_stl_s0_crypto_enc_state_generate( uchar private_key_enc[48], uchar public_key[32], uchar const key[16] );

int
fd_stl_s0_crypto_enc_state_verify( uchar private_key[32], uchar const private_key_enc[48], uchar const public_key[32], uchar const key[16] );

FD_PROTOTYPES_END

#endif /* HEADER_stl_private_h */
