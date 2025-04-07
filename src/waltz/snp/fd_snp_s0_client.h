#ifndef HEADER_snp_s0_client_h
#define HEADER_snp_s0_client_h

#include "fd_snp_base.h"
#include "fd_snp_proto.h"
#include "fd_snp_sesh.h"
#include <stdbool.h>

struct fd_snp_s0_client_params {

  /* identity is a compound structure of the identity private and
     public key */
  uchar identity[ SNP_ED25519_KEY_SZ ];

  /* cookie_secret is an ephemeral key used to create and verify
     handshake cookies. */
  uchar cookie_secret[ SNP_COOKIE_KEY_SZ ];
};

typedef struct fd_snp_s0_client_params fd_snp_s0_client_params_t;

/* TODO: decouple handshake, connection, and client objects*/
struct fd_snp_s0_client_hs {
  uchar server_token[ SNP_TOKEN_SZ ]; /* TODO: unnecessary? */
  uchar client_token[ SNP_TOKEN_SZ ];
  // crypto_hash_sha256_state transcript;
  uchar state;
  ulong socket_addr;
  uchar session_id[ SNP_SESSION_ID_SZ ];
  uchar _session_id_pad[1];
  uchar server_identity[ SNP_ED25519_KEY_SZ ];
  fd_snp_payload_t buffers[FD_SNP_MAX_BUF];
  uchar buffers_sz;
};

typedef struct fd_snp_s0_client_hs fd_snp_s0_client_hs_t;

FD_PROTOTYPES_BEGIN

fd_snp_s0_client_hs_t *
fd_snp_s0_client_hs_new( void * hs );

long
fd_snp_s0_client_initial( fd_snp_s0_client_params_t const * client,
                          fd_snp_s0_client_hs_t *           hs,
                          uchar                             pkt_out[ SNP_MTU ] );

// TODO document
long
fd_snp_s0_client_handle_continue( fd_snp_s0_client_params_t const * client,
                                  snp_s0_hs_pkt_t const *           pkt,
                                  uchar                             out[ SNP_MTU ],
                                  uchar                             to_sign[32],
                                  fd_snp_s0_client_hs_t *           hs );

void
fd_snp_s0_client_handle_continue_add_signature( uchar out[ SNP_MTU ],
                                                uchar sig[ 64 ] );

// TODO document
long
fd_snp_s0_client_handle_accept( fd_snp_t*                         snp,
                                fd_snp_s0_client_params_t const * client,
                                snp_s0_hs_pkt_t const *           pkt,
                                fd_snp_s0_client_hs_t *           hs );

/*
  fd_snp_s0_encode_appdata is a temporary function that encodes the payload into
  pkt_out using SNP 0x1. It takes session details from hs. It returns the total
  number of bytes encoded, or a negative value for err
*/
long
fd_snp_s0_encode_appdata( fd_snp_sesh_t * sesh,
                     const uchar *      payload, /* TODO: create a 0cp mode */
                     ushort             payload_sz,
                     uchar              pkt_out[ SNP_MTU ] );

FD_PROTOTYPES_END

#endif /* HEADER_snp_s0_client_h */
