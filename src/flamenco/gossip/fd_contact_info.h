#ifndef HEADER_fd_src_flamenco_gossip_fd_contact_info_h
#define HEADER_fd_src_flamenco_gossip_fd_contact_info_h

/* APIs to interact with Gossip Contact Infos.
   Analagous to:

   https://github.com/anza-xyz/agave/blob/b11ca828cfc658b93cb86a6c5c70561875abe237/gossip/src/contact_info.rs# */

#include "../types/fd_types.h"
#include "../../disco/plugin/fd_plugin.h"

typedef union fd_ip4_port fd_gossip_peer_addr_t;

/* Contact info v2 socket tag constants */
#define FD_GOSSIP_SOCKET_TAG_GOSSIP             (0)
#define FD_GOSSIP_SOCKET_TAG_RPC                (2)
#define FD_GOSSIP_SOCKET_TAG_RPC_PUBSUB         (3)
#define FD_GOSSIP_SOCKET_TAG_SERVE_REPAIR       (4)
#define FD_GOSSIP_SOCKET_TAG_SERVE_REPAIR_QUIC  (1)
#define FD_GOSSIP_SOCKET_TAG_TPU                (5)
#define FD_GOSSIP_SOCKET_TAG_TPU_FORWARDS       (6)
#define FD_GOSSIP_SOCKET_TAG_TPU_FORWARDS_QUIC  (7)
#define FD_GOSSIP_SOCKET_TAG_TPU_QUIC           (8)
#define FD_GOSSIP_SOCKET_TAG_TPU_VOTE           (9)
#define FD_GOSSIP_SOCKET_TAG_TPU_VOTE_QUIC      (12)
#define FD_GOSSIP_SOCKET_TAG_TVU                (10)
#define FD_GOSSIP_SOCKET_TAG_TVU_QUIC           (11)

#define FD_GOSSIP_SOCKET_TAG_MAX                (13)

/* TODO: update fd_gossip_update_msg_t and change this assert to be ==
   instead of <= */
FD_STATIC_ASSERT( sizeof(((fd_gossip_update_msg_t*)0)->addrs) <= FD_GOSSIP_SOCKET_TAG_MAX*6,  fd_gossip_update_msg_addrs_sz );

typedef fd_gossip_contact_info_v1_t fd_gossip_legacy_contact_info_t;

/* Internal struct for maintaining a contact_info_v2 entry.

   Notable difference is we limit the number of
   socket entries and addrs. Duplicate entries of a
   socket tag will be dropped during the conversion. This
   is in-line with Agave's behavior when populating its
   contact_info_v2.

   https://github.com/anza-xyz/agave/blob/b11ca828cfc658b93cb86a6c5c70561875abe237/gossip/src/contact_info.rs#L342 */
typedef struct {
  fd_gossip_contact_info_v2_t   ci_crd;
  fd_gossip_ip_addr_t           addrs[FD_GOSSIP_SOCKET_TAG_MAX];
  fd_gossip_socket_entry_t      sockets[FD_GOSSIP_SOCKET_TAG_MAX];
  /* uint                       extentions[1]; // Unused, dropped during conversion  */

  /* Metadata */
  ushort                        socket_tag_idx[FD_GOSSIP_SOCKET_TAG_MAX]; /* Index of socket tag in sockets array */
  ushort                        ports[FD_GOSSIP_SOCKET_TAG_MAX]; /* Avoid scanning to get ports, maps to entry in sockets. HOST order. */
} fd_contact_info_t;

#define FD_CONTACT_INFO_SOCKET_TAG_NULL (USHORT_MAX) /* Denotes a missing socket in socket_tag_idx array */

void
fd_contact_info_init( fd_contact_info_t * contact_info );

ushort
fd_contact_info_get_shred_version( fd_contact_info_t const * contact_info );

void
fd_contact_info_set_shred_version( fd_contact_info_t * contact_info,
                                   ushort              shred_version );

int
fd_contact_info_get_socket_addr( fd_contact_info_t const *  ci_int,
                                 uchar                      socket_tag,
                                 fd_gossip_socket_addr_t *  out_addr );

int
fd_contact_info_insert_socket( fd_contact_info_t *            ci_int,
                               fd_gossip_peer_addr_t const *  peer,
                               uchar                          socket_tag );

/***** Conversion APIs *****/

/* Assumes ci_int is initialized properly */
void
fd_contact_info_from_ci_v2( fd_gossip_contact_info_v2_t const * ci_v2,
                            fd_contact_info_t *                 ci_int );

/* Invariant: ci_int lifetime >= ci_v2 lifetime */
void
fd_contact_info_to_ci_v2( fd_contact_info_t const *     ci_int,
                          fd_gossip_contact_info_v2_t * ci_v2 );

void
fd_contact_info_to_update_msg( fd_contact_info_t const * ci_int,
                               fd_gossip_update_msg_t *  update );


/* Misc. utility functions for fd_gossip_contact_info_v2_t */

int
fd_gossip_contact_info_v2_find_proto_ident( fd_gossip_contact_info_v2_t const * contact_info,
                                            uchar                               proto_ident,
                                            fd_gossip_socket_addr_t *           out_addr );

#endif
