#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_types_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_types_h

/* The gossip tile produces an output stream of update messages as it
   runs, which are published to a link for other tiles to consume.

   The formt and protocol of the update messages is defined here.

   Messages are published one by one incrementally, as they are
   received, although expirations or removals will not be published
   except for contact information which publishes a removal stream so
   that consumers of the updates can mirror the true gossip table.

   Not all gossip messages are published, and some are consumed just by
   the gossip tile itself. */

#include "../types/fd_types_custom.h"
#include "../../util/net/fd_net_headers.h"

/* The tag is the kind of gossip message that is being sent.  It will be
   put both in the fragment signature, and in the message itself. */

#define FD_GOSSIP_UPDATE_TAG_CONTACT_INFO        (0)
#define FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE (1)
#define FD_GOSSIP_UPDATE_TAG_LOWEST_SLOT         (2)
#define FD_GOSSIP_UPDATE_TAG_VOTE                (3)
#define FD_GOSSIP_UPDATE_TAG_DUPLICATE_SHRED     (4)
#define FD_GOSSIP_UPDATE_TAG_SNAPSHOT_HASHES     (5)

/* The maximum number of contact infos that may be present at any one
   time.  If new contact infos are added, a removal will be issued first
   to make space.  This is a hard limit, and the consumer of the contact
   info messages can assume it is always respected.

   The contact info messages are designed to be consumed in an
   incremental way.  In particular, CONTACT_INFO and CONTACT_INFO_REMOVE
   messages are both sent with an idx field, which is the index of the
   contact info in an imaginary array of contact infos.  Updates will
   always have the same idx for the same pubkey, and removes will
   likewise have the same idx for the pubkey being removed.  A consumer
   of contact info updates can therefore simply maintain a local array
   of contact infos, and update it with the idx field.  */

#define FD_CONTACT_INFO_TABLE_SIZE (32768UL)

#define FD_CONTACT_INFO_SOCKET_GOSSIP            ( 0)
#define FD_CONTACT_INFO_SOCKET_SERVE_REPAIR_QUIC ( 1)
#define FD_CONTACT_INFO_SOCKET_RPC               ( 2)
#define FD_CONTACT_INFO_SOCKET_RPC_PUBSUB        ( 3)
#define FD_CONTACT_INFO_SOCKET_SERVE_REPAIR      ( 4)
#define FD_CONTACT_INFO_SOCKET_TPU               ( 5)
#define FD_CONTACT_INFO_SOCKET_TPU_FORWARDS      ( 6)
#define FD_CONTACT_INFO_SOCKET_TPU_FORWARDS_QUIC ( 7)
#define FD_CONTACT_INFO_SOCKET_TPU_QUIC          ( 8)
#define FD_CONTACT_INFO_SOCKET_TPU_VOTE          ( 9)
#define FD_CONTACT_INFO_SOCKET_TVU               (10)
#define FD_CONTACT_INFO_SOCKET_TVU_QUIC          (11)
#define FD_CONTACT_INFO_SOCKET_TPU_VOTE_QUIC     (12)
#define FD_CONTACT_INFO_SOCKET_LAST              (12)

/* https://github.com/anza-xyz/agave/blob/540d5bc56cd44e3cc61b179bd52e9a782a2c99e4/version/src/lib.rs#L95-L105 */

#define FD_CONTACT_INFO_VERSION_CLIENT_SOLANA_LABS (0)
#define FD_CONTACT_INFO_VERSION_CLIENT_JITO_LABS   (1)
#define FD_CONTACT_INFO_VERSION_CLIENT_FIREDANCER  (2)
#define FD_CONTACT_INFO_VERSION_CLIENT_AGAVE       (3)

/* A contact info represents a peer node in the cluster that is
   publishing information about itself to the gossip network.  It it
   sent when the tag is FD_GOSSIP_UPDATE_TAG_CONTACT_INFO.

   Contact infos are already deduplicated, so the same pubkey will not
   appear twice, and the number of contact infos outstanding is limited
   to FD_CONTACT_INFO_TABLE_SIZE.  If more contact infos are received,
   the oldest ones are first removed with a
   FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE fragment.

   Contact infos are regularly updated, for example if a node changes
   its IP address or port.  More typically nodes just periodically
   republish their contact info with an updated wallclock.  When an
   existing contact info is updated, a FD_GOSSIP_UPDATE_TAG_CONTACT_INFO
   fragment is sent with the same pubkey.

   Contact information is not well-validated by the gossip network, and
   for example the wallclock may be old, or in the future, and the
   sockets may be unroutable or invalid (a private network), and the
   version fields are completely arbitrary.

   However, the pubkey is authenticated, as messages are signed.

   TODO: Remove the _upd suffixes once the types are removed from
   fd_types.h and fd_contact_info.h */

struct fd_contact_info {
  fd_pubkey_t pubkey;          /* The identity public key of the peer node */
  ushort      shred_version;   /* The shred version of the peer node, should be non-zero but not required */

  long        instance_creation_wallclock_nanos;
  long        wallclock_nanos; /* The timestamp on the producer side of when the contact info was signed */

  /* Peer nodes declare a list of ip:port pairs corresponding to
     standard Solana protocols that they support.  A value of 0:0
     indicates the node does not advertise that protocol.  For example,
     sockets[ FD_CONTACT_INFO_SOCKET_RPC ] is the IP address and port
     for the RPC service of the node. */
  fd_ip4_port_t sockets[ FD_CONTACT_INFO_SOCKET_LAST+1UL ];

  struct {
    uchar  client; /* Any uchar in [0, 255], although typically one of FD_CONTACT_INFO_VERSION_CLIENT_* indicating the self-reported client version */

    ushort major;  /* The self-reported major version of the client */
    ushort minor;  /* The self-reported minor version of the client */
    ushort patch;  /* The self-reported patch version of the client */

    uint   commit; /* The self-reported commit hash of the client, in little-endian order, or 0 if no commit hash was provided */
    uint   feature_set; /* The self-reported feature set of the client, in little-endian order */
  } version;
};

typedef struct fd_contact_info fd_contact_info_t;

/* A gossip vote represents a vote transaction that was sent to us by a
   peer node.  It is sent when the tag is FD_GOSSIP_UPDATE_TAG_VOTE.
   Votes are typically sent over the TPU, but also via. gossip for
   redundancy.

   The transaction is not validated or parsed in any way yet, and in
   particular the signatures have not been verified.   Transaction data
   is arbitrary and could be empty or corrupt or malicious. */

struct fd_gossip_vote_upd {
  uchar vote_tower_index;
  ulong txn_sz;
  uchar txn[ 1232UL ];
};

typedef struct fd_gossip_vote_upd fd_gossip_vote_upd_t;

#define FD_GOSSIP_DUPLICATE_SHRED_MAX_CHUNKS (1054UL)

/* An edge case in the network is "equivocation" when a node publishes
   conflicting shred data for its leader slot.  In future this may be
   a slashable offense, but for now it simply "proven" on the chain and
   communicated among peers. */

struct fd_gossip_duplicate_shred_upd {
  ushort index;
  ulong  slot;
  uchar  num_chunks;
  uchar  chunk_index;
  ulong  chunk_len;
  uchar  chunk[ FD_GOSSIP_DUPLICATE_SHRED_MAX_CHUNKS ];
};

typedef struct fd_gossip_duplicate_shred_upd fd_gossip_duplicate_shred_upd_t;

struct fd_gossip_snapshot_hash_pair {
  ulong slot;
  uchar hash[ 32UL ];
};

typedef struct fd_gossip_snapshot_hash_pair fd_gossip_snapshot_hash_pair_t;

#define FD_GOSSIP_SNAPSHOT_HASHES_MAX_INCREMENTAL (25UL)

/* Each peer node which is serving snapshots will periodically
   publish a snapshot hash update, which contains the hashes of the
   latest snapshots it has available.  This is sent when the tag is
   FD_GOSSIP_UPDATE_TAG_SNAPSHOT_HASHES.

   The full field indicates the full snapshot slot and hash, and then a
   list of recent incremental snapshots is provided which build on top
   of the full snapshot. */

struct fd_gossip_snapshot_hashes_upd {
  fd_gossip_snapshot_hash_pair_t full[ 1 ];

  ulong                          incremental_len;
  fd_gossip_snapshot_hash_pair_t incremental[ FD_GOSSIP_SNAPSHOT_HASHES_MAX_INCREMENTAL ];
};

typedef struct fd_gossip_snapshot_hashes_upd fd_gossip_snapshot_hashes_upd_t;

struct fd_gossip_update_message {
  uchar tag;
  uchar origin_pubkey[ 32UL ];
  ulong origin_stake;
  long  wallclock_nanos;

  union {
    struct {
      ulong                 idx; /* Index into flat array to place this contact info, see comments on FD_CONTACT_INFO_TABLE_SIZE */
      fd_contact_info_t contact_info[ 1 ];
    } contact_info;

    struct {
      ulong idx; /* Index into flat array of contact info to remove, see FD_CONTACT_INFO_TABLE_SIZE */
    } contact_info_remove;

    ulong                           lowest_slot;
    fd_gossip_vote_upd_t            vote;
    fd_gossip_duplicate_shred_upd_t duplicate_shred;
    fd_gossip_snapshot_hashes_upd_t snapshot_hashes;
  };
};

typedef struct fd_gossip_update_message fd_gossip_update_message_t;

#endif /* HEADER_fd_src_flamenco_gossip_fd_gossip_types_h */
