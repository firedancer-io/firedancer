#ifndef HEADER_fd_src_flamenco_gossip_fd_contact_info_h
#define HEADER_fd_src_flamenco_gossip_fd_contact_info_h

/* APIs to interact with Gossip Contact Infos.
   Analagous to:

   https://github.com/anza-xyz/agave/blob/b11ca828cfc658b93cb86a6c5c70561875abe237/gossip/src/contact_info.rs# */

#include "../../util/net/fd_net_headers.h" /* fd_ip4_port_t */
#include "../types/fd_pubkey_type.h"

/* Contact info v2 socket tag constants */
#define FD_CONTACT_INFO_SOCKET_GOSSIP             ( 0)
#define FD_CONTACT_INFO_SOCKET_SERVE_REPAIR_QUIC  ( 1)
#define FD_CONTACT_INFO_SOCKET_RPC                ( 2)
#define FD_CONTACT_INFO_SOCKET_RPC_PUBSUB         ( 3)
#define FD_CONTACT_INFO_SOCKET_SERVE_REPAIR       ( 4)
#define FD_CONTACT_INFO_SOCKET_TPU                ( 5)
#define FD_CONTACT_INFO_SOCKET_TPU_FORWARDS       ( 6)
#define FD_CONTACT_INFO_SOCKET_TPU_FORWARDS_QUIC  ( 7)
#define FD_CONTACT_INFO_SOCKET_TPU_QUIC           ( 8)
#define FD_CONTACT_INFO_SOCKET_TPU_VOTE           ( 9)
#define FD_CONTACT_INFO_SOCKET_TVU                (10)
#define FD_CONTACT_INFO_SOCKET_TVU_QUIC           (11)
#define FD_CONTACT_INFO_SOCKET_TPU_VOTE_QUIC      (12)

#define FD_CONTACT_INFO_SOCKET_MAX                (13)

/* https://github.com/anza-xyz/agave/blob/540d5bc56cd44e3cc61b179bd52e9a782a2c99e4/version/src/lib.rs#L95-L105 */
#define FD_GOSSIP_VERSION_CLIENT_SOLANA_LABS      ( 0)
#define FD_GOSSIP_VERSION_CLIENT_JITO_LABS        ( 1)
#define FD_GOSSIP_VERSION_CLIENT_FIREDANCER       ( 2)
#define FD_GOSSIP_VERSION_CLIENT_AGAVE            ( 3)

/* Internal struct for maintaining a Gossip ContactInfo entry.

   Notable difference is we limit the number of
   socket entries and addrs. Duplicate entries of a
   socket tag will be dropped during the conversion. This
   is in-line with Agave's behavior when populating its
   contact_info_v2.

   https://github.com/anza-xyz/agave/blob/b11ca828cfc658b93cb86a6c5c70561875abe237/gossip/src/contact_info.rs#L342 */
struct fd_contact_info {
  fd_pubkey_t   pubkey;
  ushort        shred_version;

  long          instance_creation_wallclock_nanos;
  long          wallclock_nanos;
  fd_ip4_port_t sockets[ FD_CONTACT_INFO_SOCKET_MAX ];

  struct {
    uchar client;

    ushort major;
    ushort minor;
    ushort patch;

    uint  commit;
    uint  feature_set;
  } version;
};

typedef struct fd_contact_info fd_contact_info_t;

#define FD_CONTACT_INFO_NULL_SOCKET (0UL) /* Denotes an invalid/empty socket entry  */

fd_ip4_port_t
fd_contact_info_get_socket( fd_contact_info_t const * ci,
                            uchar                     socket_tag );

fd_ip4_port_t
fd_contact_info_gossip_socket( fd_contact_info_t const * ci );

ushort
fd_contact_info_get_shred_version( fd_contact_info_t const * ci );

void
fd_contact_info_set_shred_version( fd_contact_info_t * ci,
                                   ushort              shred_version );

int
fd_contact_info_insert_socket( fd_contact_info_t *   ci,
                               fd_ip4_port_t const * socket,
                               uchar                 socket_tag );

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
struct fd_gossip_contact_info_socket_entry {
  ushort port_offset;
  uchar  tag;
  uchar  addr_index;
};

typedef struct fd_gossip_contact_info_socket_entry fd_gossip_contact_info_socket_entry_t;

int
fd_contact_info_convert_sockets( fd_contact_info_t const *             contact_info,
                                 fd_gossip_contact_info_socket_entry_t sockets_entries[static FD_CONTACT_INFO_SOCKET_MAX],
                                 uchar *                               socket_entries_cnt,
                                 uint                                  addrs[static FD_CONTACT_INFO_SOCKET_MAX],
                                 uchar *                               addrs_cnt );



#endif
