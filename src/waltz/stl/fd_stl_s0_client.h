#ifndef HEADER_stl_s0_client_h
#define HEADER_stl_s0_client_h

#include "fd_stl_base.h"
#include "fd_stl_proto.h"
#include "fd_stl_sesh.h"
#include <stdbool.h>

struct fd_stl_s0_client_params {

  /* identity is a compound structure of the identity private and
     public key */
  uchar identity[ STL_ED25519_KEY_SZ ];

  /* cookie_secret is an ephemeral key used to create and verify
     handshake cookies. */
  uchar cookie_secret[ STL_COOKIE_KEY_SZ ];
};

typedef struct fd_stl_s0_client_params fd_stl_s0_client_params_t;

/* TODO: decouple handshake, connection, and client objects*/
struct fd_stl_s0_client_hs {
  uchar server_token[ STL_TOKEN_SZ ]; /* TODO: unnecessary? */
  uchar client_token[ STL_TOKEN_SZ ];
  // crypto_hash_sha256_state transcript;
  uchar state;
  ulong socket_addr;
  uchar session_id[ STL_SESSION_ID_SZ ];
  uchar _session_id_pad[1];
  uchar server_identity[ STL_ED25519_KEY_SZ ];
  fd_stl_payload_t buffers[FD_STL_MAX_BUF];
  uchar buffers_sz;
};

typedef struct fd_stl_s0_client_hs fd_stl_s0_client_hs_t;

FD_PROTOTYPES_BEGIN

fd_stl_s0_client_hs_t *
fd_stl_s0_client_hs_new( void * hs );

long
fd_stl_s0_client_initial( fd_stl_s0_client_params_t const * client,
                          fd_stl_s0_client_hs_t *           hs,
                          uchar                             pkt_out[ STL_MTU ] );

// TODO document
long
fd_stl_s0_client_handle_continue( fd_stl_s0_client_params_t const * client,
                                  stl_s0_hs_pkt_t const *           pkt,
                                  uchar                             out[ STL_MTU ],
                                  uchar                             to_sign[32],
                                  fd_stl_s0_client_hs_t *           hs );

void
fd_stl_s0_client_handle_continue_add_signature( uchar out[ STL_MTU ],
                                                uchar sig[ 64 ] );

// TODO document
long
fd_stl_s0_client_handle_accept( fd_stl_t*                         stl,
                                fd_stl_s0_client_params_t const * client,
                                stl_s0_hs_pkt_t const *           pkt,
                                fd_stl_s0_client_hs_t *           hs );

/*
  fd_stl_s0_encode_appdata is a temporary function that encodes the payload into
  pkt_out using STL 0x1. It takes session details from hs. It returns the total
  number of bytes encoded, or a negative value for err
*/
long
fd_stl_s0_encode_appdata( fd_stl_sesh_t * sesh,
                     const uchar *      payload, /* TODO: create a 0cp mode */
                     ushort             payload_sz,
                     uchar              pkt_out[ STL_MTU ] );

FD_PROTOTYPES_END

#endif /* HEADER_stl_s0_client_h */
