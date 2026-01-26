#ifndef HEADER_fd_src_discof_restore_utils_fd_snapct_test_topo
#define HEADER_fd_src_discof_restore_utils_fd_snapct_test_topo

#include "fd_restore_test_base.h"

#include "../../../util/fd_util_base.h"
#include "../../../disco/topo/fd_topo.h"

/* fd_snapct_test_topo is a unit-test test fixture for the snapct tile.
   It is meant to be used within a testing topology setup that includes
   the snapct tile and its associated input and output links.
   See test_snapct_tile.c for example usage. */
struct fd_snapct_test_topo {
  /* tile context */
  void * ctx;
  /* input links */
  fd_restore_link_in_t in_gossip; /* gossip_out (optional) */
  fd_restore_link_in_t in_ld;     /* snapld_dc ack */
  fd_restore_link_in_t in_ack;    /* snapin_ct or snapls_ct control ack */
  /* output links */
  fd_restore_link_out_t out_ld;   /* snapct_ld to snapld */
  fd_restore_link_out_t out_gui;  /* snapct_gui for GUI updates */
  fd_restore_link_out_t out_repr; /* snapct_repr to replay */

  /* Input link views on output links.  Used to verify snapct published
     expected messages in its output links in a single tile unit test
     topology. */
  fd_restore_link_in_t out_ld_in_view;
  fd_restore_link_in_t out_repr_in_view;

  fd_restore_stem_mock_t mock_stem; /* mock stem fields */

  ulong magic;
};

typedef struct fd_snapct_test_topo fd_snapct_test_topo_t;

#define FD_SNAPCT_TEST_TOPO_MAGIC (0xFD53A1C113510) /* FD SNAPCT TEST TOPO V0 */

/* Default full snapshot slot for test context */
#define FD_SNAPCT_TEST_TOPO_DEFAULT_FULL_SLOT (10000UL)

FD_FN_CONST ulong
fd_snapct_test_topo_align( void );

FD_FN_CONST ulong
fd_snapct_test_topo_footprint( void );

void *
fd_snapct_test_topo_new( void * shmem );

fd_snapct_test_topo_t *
fd_snapct_test_topo_join( void * shmem );

/* fd_snapct_test_topo_init initializes the test fixture context for the
   snapct tile.  It assumes a test topology already exists with the
   snapct tile and in/out links already created in the topology.

   topo points to an existing test topology.  wksp points to an existing
   wksp.  wksp_name is the name of the wksp.  allow_gossip controls
   whether the snapct tile is configured to download from gossip peers.
   server_cnt is the number of servers snapct can download from. servers
   is an array of server addresses.  server_names is an array of server
   hostnames.  server_names_len is an array of hostname lengths.
   in_ack_link_name is the name of the in_link for control messages
   looping back into snapct.  snapshots_path is the mock path to a
   snapshots archive path.  snapshots_path_len is the length of the
   snapshots path. */
void
fd_snapct_test_topo_init( fd_snapct_test_topo_t * snapct_topo,
                          fd_topo_t *             topo,
                          fd_wksp_t *             wksp,
                          char const *            wksp_name,
                          int                     allow_gossip_any,
                          ulong                   servers_cnt,
                          fd_ip4_port_t const *   servers,
                          char const **           server_names,
                          ulong *                 server_names_len,
                          char const *            in_ack_link_name,
                          char const *            snapshots_path,
                          ulong                   snapshots_path_len );

/* fd_snapct_test_topo_get_state returns the snapct tile's state. */
int
fd_snapct_test_topo_get_state( fd_snapct_test_topo_t * snapct_topo );

/* fd_snapct_test_topo_inject_server_response injects a mock server
   response into the snapct tile.  This is done to provide server
   responses to the http requests the snapct tile makes to each server.
   Snapct uses the slot information in the server response to determine
   the server's snapshot age and availability.

   addr is the address of the server.  full_slot is the advertised slot
   of the full snapshot on the server.  incr_slot is the advertised slot
   of the incremental snapshot on the server. */
void
fd_snapct_test_topo_inject_server_response( fd_snapct_test_topo_t * snapct_topo,
                                            fd_ip4_port_t           addr,
                                            ulong                   full_slot,
                                            ulong                   incr_slot );

/* fd_snapct_test_topo_inject_gossip_peer injects a mock gossip peer
   into the snapct tile's gossip contact info table.  origin_pubkey and
   contact info idx (idx) are mapped one-to-one and must be unique to
   insert a new gossip peer.  To override a previously injected gossip
   peer, the same contact info idx must be provided.  It is an error to
   attempt to inject a gossip peer with the same origin_pubkey as a
   previously injected gossip peer but with a different contact info
   idx.

   origin_pubkey is the pubkey of the gossip peer.  addr is the gossip
   peer's rpc address.  idx is the gossip peer's contact info idx.

   Typically, each gossip contact info update message contains a unique
   origin_pubkey and contact info idx that snapct uses to uniquely
   identify each peer.  The caller is responsible for providing a unique
   origin_pubkey and contact info idx for each new gossip peer. */
void
fd_snapct_test_topo_inject_gossip_peer( fd_snapct_test_topo_t * snapct_topo,
                                        uchar                   origin_pubkey[ static FD_HASH_FOOTPRINT ],
                                        fd_ip4_port_t           addr,
                                        ulong                   idx );

/* fd_snapct_test_topo_inject_snapshot_hash injects a mock snapshot hash
   gossip update message into the snapct tile.  Snapshot hashes messages
   contain advertised snapshot slot information from gossip peers and
   are used by the snapct tile to determine snapshot age and
   availability.  Snapshot hash injection also inserts the gossip peer
   into snapct's gossip contact info table.  Repeated calls
   with the same contact info idx will override the previoiusly injected
   gossip peer with the newly provided parameters in snapct's gossip
   contact info table.

   origin_pubkey is the origin_pubkey of the gossip peer. addr is the
   gossip peer's rpc address. idx is the gossip peer's contact info idx.
   full_slot is the gossip peer's advertised full snapshot slot.
   incr_slot is the gossip peer's advertised incremental snapshot slot.
   */
void
fd_snapct_test_topo_inject_snapshot_hash( fd_snapct_test_topo_t * snapct_topo,
                                          uchar                   origin_pubkey[ static FD_HASH_FOOTPRINT ],
                                          fd_ip4_port_t           addr,
                                          ulong                   idx,
                                          ulong                   full_slot,
                                          ulong                   incr_slot );

/* fd_snapct_test_topo_inject_ping injects a ping response from a gossip
   peer or from a snapshot server.  snapct uses ping responses to
   estimate the peer's download speed and distance from the validator.
   Ping responses with lower latencies indicate a peer is closer.

   A ping response consists of the server's ip address and its ping
   latency.  addr is the server's ip address and latency_nanos is the
   ping latency in nanoseconds. */
void
fd_snapct_test_topo_inject_ping( fd_snapct_test_topo_t * snapct_topo,
                                 fd_ip4_port_t           addr,
                                 ulong                   latency_nanos );

/* fd_snapct_test_topo_returnable_frag is a stub that calls the snapct
   tile's returnable_frag function. */
int
fd_snapct_test_topo_returnable_frag( fd_snapct_test_topo_t * snapct,
                                     ulong                   in_idx,
                                     ulong                   seq,
                                     ulong                   sig,
                                     ulong                   chunk,
                                     ulong                   sz,
                                     ulong                   ctl,
                                     ulong                   tsorig,
                                     ulong                   tspub );

/* fd_snapct_test_topo_after_credit is a stub that calls the snapct
   tile's after_credit function. */
void
fd_snapct_test_topo_after_credit( fd_snapct_test_topo_t * snapct,
                                  int *                   opt_poll_in,
                                  int *                   charge_busy );

/* fd_snapct_test_topo_fini deallocates any additional objects added to
   the existing test topology by fd_snapct_test_topo_init. */
void
fd_snapct_test_topo_fini( fd_snapct_test_topo_t * snapct );

#endif /* HEADER_fd_src_discof_restore_fd_snapct_test_topo */
