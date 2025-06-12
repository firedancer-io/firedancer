#ifndef HEADER_fd_src_flamenco_gossip_fd_contact_info_h
#define HEADER_fd_src_flamenco_gossip_fd_contact_info_h

/* APIs to interact with Gossip Contact Infos.
   Analagous to:

   https://github.com/anza-xyz/agave/blob/b11ca828cfc658b93cb86a6c5c70561875abe237/gossip/src/contact_info.rs# */

#include "../types/fd_types.h"
#include "../../util/net/fd_net_headers.h" /* fd_ip4_port_t */

typedef union fd_ip4_port fd_gossip_peer_addr_t;

/* Contact info v2 socket tag constants */
#define FD_GOSSIP_SOCKET_TAG_GOSSIP             ( 0)
#define FD_GOSSIP_SOCKET_TAG_SERVE_REPAIR_QUIC  ( 1)
#define FD_GOSSIP_SOCKET_TAG_RPC                ( 2)
#define FD_GOSSIP_SOCKET_TAG_RPC_PUBSUB         ( 3)
#define FD_GOSSIP_SOCKET_TAG_SERVE_REPAIR       ( 4)
#define FD_GOSSIP_SOCKET_TAG_TPU                ( 5)
#define FD_GOSSIP_SOCKET_TAG_TPU_FORWARDS       ( 6)
#define FD_GOSSIP_SOCKET_TAG_TPU_FORWARDS_QUIC  ( 7)
#define FD_GOSSIP_SOCKET_TAG_TPU_QUIC           ( 8)
#define FD_GOSSIP_SOCKET_TAG_TPU_VOTE           ( 9)
#define FD_GOSSIP_SOCKET_TAG_TVU                (10)
#define FD_GOSSIP_SOCKET_TAG_TVU_QUIC           (11)
#define FD_GOSSIP_SOCKET_TAG_TPU_VOTE_QUIC      (12)

#define FD_GOSSIP_SOCKET_TAG_MAX                (13)

typedef fd_gossip_contact_info_v1_t fd_gossip_legacy_contact_info_t;

/* Internal struct for maintaining a Gossip ContactInfo entry.

   Notable difference is we limit the number of
   socket entries and addrs. Duplicate entries of a
   socket tag will be dropped during the conversion. This
   is in-line with Agave's behavior when populating its
   contact_info_v2.

   https://github.com/anza-xyz/agave/blob/b11ca828cfc658b93cb86a6c5c70561875abe237/gossip/src/contact_info.rs#L342 */
struct fd_contact_info_t {
  uchar         pubkey[ 32UL ];
  ushort        shred_version; /* Shred version for this contact info */

  long          wallclock_nanos; /* Wallclock when contact info was sent out */
  long          instance_creation_wallclock_nanos; /* Wallclock when node was initialized */
  fd_ip4_port_t sockets[ FD_GOSSIP_SOCKET_TAG_MAX ];

  struct {
    uchar client;

    ushort major;      /* Major version */
    ushort minor;      /* Minor version */
    ushort patch;      /* Patch version */

    int   has_commit;  /* 0 = no commit, 1 = commit present */
    uint  commit;      /* Commit hash */
    uint  feature_set; /* Feature set for this contact info */
  } version;
};

typedef struct fd_contact_info_t fd_contact_info_t;

#define FD_CONTACT_INFO_SOCKET_TAG_NULL (0UL) /* Denotes an invalid/empty socket entry  */

struct fd_gossip_contact_info_socket_entry {
  ushort port_offset; /* relative to sockets[i-1] port value */
  uchar  tag;
  uchar  addr_index;
};

typedef struct fd_gossip_contact_info_socket_entry fd_gossip_contact_info_socket_entry_t;

/* The Gossip encoding of a contact info splits the sockets into
   two vectors: socket entries (socket_entry_t) and addrs (uint).
   The sockets are ordered by port values, and the port values
   are encoded as "offsets" to the previous socket entry's value.
   addrs is a list of unique IP addresses, and a socket entry's
   addr_index indexes into this list. To illustrate the conversion:

   sockets = [
      { IP: 192.1.1.1, Port: 1000 },  # tag gossip
      {     192.1.2.1,       2000 },  # tag serve_repair_quic
      {     0,               0 },     # NULL socket entry for tag RPC
      {     192.1.1.1,       500 }    # tag rpc pubsub
  ]

  would be transformed to:

  addrs = [
    192.1.1.1,
    192.1.2.1
  ]

  socket_entries = [
    { port_offset: 500,  tag: 3, addr_index: 1 }, # first entry's port_offset is the actual port value
    {              500,       0,             0 }, # second entry is relative to the first entry's port value
    {              1000,      1,             0 }  # third entry is relative to the second entry's port value
                                                  # null socket entry is not included
  ]
*/

int
fd_contact_info_convert_sockets( fd_contact_info_t const *             contact_info,
                                 fd_gossip_contact_info_socket_entry_t sockets_entries[static FD_GOSSIP_SOCKET_TAG_MAX],
                                 uchar *                               socket_entries_cnt,
                                 uint                                  addrs[static FD_GOSSIP_SOCKET_TAG_MAX],
                                 uchar *                               addrs_cnt );


ushort
fd_contact_info_get_shred_version( fd_contact_info_t const * ci );

void
fd_contact_info_set_shred_version( fd_contact_info_t * ci,
                                   ushort              shred_version );

int
fd_contact_info_insert_socket( fd_contact_info_t *            ci,
                               fd_ip4_port_t const *          socket,
                               uchar                          socket_tag );



#endif
