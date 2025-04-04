#ifndef HEADER_stl_s0_server_h
#define HEADER_stl_s0_server_h

/* fd_stl_s0.h provides APIs for STL. */

#include "fd_stl_base.h"
#include "fd_stl_proto.h"
#include "fd_stl_sesh.h"
struct fd_stl_s0_server_params {

  /* identity is a compound structure of the identity private and
     public key */
  uchar identity[ STL_ED25519_KEY_SZ ];

  /* random AES-128 key to encrypt state (to avoid storing state) */
  uchar state_enc_key[ STL_STATE_KEY_SZ ];

  /* cookie_secret is an ephemeral key used to create and verify
     handshake cookies. */
  uchar cookie_secret[ STL_COOKIE_KEY_SZ ];

  uchar token[16];
};

typedef struct fd_stl_s0_server_params fd_stl_s0_server_params_t;

struct fd_stl_s0_server_hs {
  uchar identity[ STL_ED25519_KEY_SZ ];
  uchar session_id[ STL_SESSION_ID_SZ ];
  uchar state;
  fd_stl_payload_t buffers[FD_STL_MAX_BUF];
};

typedef struct fd_stl_s0_server_hs fd_stl_s0_server_hs_t;

FD_PROTOTYPES_BEGIN

// TODO document
long
fd_stl_s0_server_handle_initial( fd_stl_s0_server_params_t const * server,
                                 stl_net_ctx_t const *             ctx,
                                 stl_s0_hs_pkt_t const *           pkt,
                                 uchar                             out[ STL_MTU ],
                                 fd_stl_s0_server_hs_t *           hs );

// TODO document
long
fd_stl_s0_server_handle_accept( fd_stl_s0_server_params_t const * server,
                                stl_net_ctx_t const *             ctx,
                                stl_s0_hs_pkt_t const *           pkt,
                                uchar                             out[ STL_MTU ],
                                uchar                             to_sign[32],
                                fd_stl_s0_server_hs_t *           hs,
                                fd_stl_sesh_t *                   sesh );

void
fd_stl_s0_server_handle_accept_add_signature( uchar out[ STL_MTU ], 
                                              uchar sig[ 64 ] );

/* fd_stl_s0_server_rotate_keys re-generates the ephemeral keys
   (cookie_secret and signature_seed).  This invalidates any active
   handshakes.  (Established session IDs are not affected) */

void
fd_stl_s0_server_rotate_keys( fd_stl_s0_server_params_t * server );


/* fd_stl_s0_decode_appdata is a temp function that
   unwraps the STL protocol from the payload. It
   takes encoded_buf off the wire and decodes it
   into pkt_out */
long
fd_stl_s0_decode_appdata( fd_stl_sesh_t* sesh,
                          const uchar* encoded_buf,
                          ushort encoded_sz,
                          uchar  pkt_out[STL_BASIC_PAYLOAD_MTU] );

FD_PROTOTYPES_END

#endif /* HEADER_stl_s0_server_h */
