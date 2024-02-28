#ifndef HEADER_fd_src_disco_tiles_shred_fd_shred_tile_h
#define HEADER_fd_src_disco_tiles_shred_fd_shred_tile_h

/* The shred tile handles shreds from two data sources: shreds
   generated from microblocks from the banking tile, and shreds
   retransmitted from the network.

   They have rather different semantics, but at the end of the day, they
   both result in a bunch of shreds and FEC sets that need to be sent to
   the blockstore and on the network, which is why one tile handles
   both.

   We segment the memory for the two types of shreds into two halves of
   a dcache because they follow somewhat different flow control
   patterns. For flow control, the normal guarantee we want to provide
   is that the dcache entry is not overwritten unless the mcache entry
   has also been overwritten.  The normal way to do this when using both
   cyclically and with a 1-to-1 mapping is to make the dcache at least
   `burst` entries bigger than the mcache.

   In this tile, we use one output mcache with one output dcache (which
   is logically partitioned into two) for the two sources of data.  The
   worst case for flow control is when we're only sending with one of
   the dcache partitions at a time though, so we can consider them
   separately.

   From bank: Every FEC set triggers at least two mcache entries (one
   for parity and one for data), so at most, we have ceil(mcache
   depth/2) FEC sets exposed.  This means we need to decompose dcache
   into at least ceil(mcache depth/2)+1 FEC sets.

   From the network: The FEC resolver doesn't use a cyclic order, but it
   does promise that once it returns an FEC set, it will return at least
   complete_depth FEC sets before returning it again.  This means we
   want at most complete_depth-1 FEC sets exposed, so
   complete_depth=ceil(mcache depth/2)+1 FEC sets as above.  The FEC
   resolver has the ability to keep individual shreds for partial_depth
   calls, but because in this version of the shred tile, we send each
   shred to all its destinations as soon as we get it, we don't need
   that functionality, so we set partial_depth=1.

   Adding these up, we get 2*ceil(mcache_depth/2)+3+fec_resolver_depth
   FEC sets, which is no more than mcache_depth+4+fec_resolver_depth.
   Each FEC is paired with 4 fd_shred34_t structs, so that means we need
   to decompose the dcache into 4*mcache_depth + 4*fec_resolver_depth +
   16 fd_shred34_t structs. */

#include "../../fd_disco_base.h"
#include "../../mux/fd_mux.h"

#include "../../shred/fd_shredder.h"
#include "../../shred/fd_fec_resolver.h"
#include "../../shred/fd_stake_ci.h"

#include "../../../util/net/fd_ip4.h"
#include "../../../util/net/fd_udp.h"
#include "../../../util/net/fd_eth.h"

#define FD_SHRED_TILE_ALIGN (128UL)

struct fd_shred_tile_args {
  ulong  depth;
  uint   ip_addr;
  uchar  src_mac_addr[ 6 ];
  ulong  fec_resolver_depth;
  ushort shred_listen_port;
  ulong  expected_shred_version;

  char const * identity_key_path;
};

typedef struct fd_shred_tile_args fd_shred_tile_args_t;

struct fd_shred_tile_topo {
  ulong bank_cnt;

  ulong netmux_in_idx;
  ulong poh_in_idx;
  ulong sign_in_idx;
  ulong contact_in_idx;
  ulong stake_in_idx;

  fd_wksp_t * netmux_in_wksp;
  ulong       netmux_in_mtu;

  fd_wksp_t * poh_in_wksp;
  void *      poh_in_dcache;
  ulong       poh_in_mtu;

  fd_wksp_t * stake_in_wksp;
  void *      stake_in_dcache;
  ulong       stake_in_mtu;

  fd_wksp_t * contact_in_wksp;
  void *      contact_in_dcache;
  ulong       contact_in_mtu;

  fd_wksp_t *      netmux_out_wksp;
  fd_frag_meta_t * netmux_out_mcache;
  void *           netmux_out_dcache;
  ulong            netmux_out_mtu;

  fd_wksp_t * store_out_wksp;
  void *      store_out_dcache;
  ulong       store_out_mtu;

  fd_frag_meta_t * sign_out_mcache;
  void *           sign_out_dcache;
  fd_frag_meta_t * sign_in_mcache;
  void *           sign_in_dcache;
};

typedef struct fd_shred_tile_topo fd_shred_tile_topo_t;

typedef struct __attribute__((packed)) {
  fd_eth_hdr_t eth[1];
  fd_ip4_hdr_t ip4[1];
  fd_udp_hdr_t udp[1];
} eth_ip_udp_t;

struct __attribute__((aligned(FD_SHRED_TILE_ALIGN))) fd_shred_tile_private {
  fd_shredder_t      * shredder;
  fd_fec_resolver_t  * resolver;
  fd_pubkey_t          identity_key[1]; /* Just the public key */

  fd_keyguard_client_t keyguard_client[1];

  uint                 src_ip_addr;
  uchar                src_mac_addr[ 6 ];
  ushort               shred_listen_port;

  /* shred34 and fec_sets are very related: fec_sets[i] has pointers
     to the shreds in shred34[4*i + k] for k=0,1,2,3. */
  fd_shred34_t       * shred34;
  fd_fec_set_t       * fec_sets;

  fd_stake_ci_t      * stake_ci;
  /* These are used in between during_frag and after_frag */
  fd_shred_dest_weighted_t * new_dest_ptr;
  ulong                      new_dest_cnt;

  ushort net_id;

  eth_ip_udp_t data_shred_net_hdr  [1];
  eth_ip_udp_t parity_shred_net_hdr[1];

  fd_wksp_t * shred_store_wksp;

  ulong shredder_fec_set_idx;     /* In [0, shredder_max_fec_set_idx) */
  ulong shredder_max_fec_set_idx; /* exclusive */

  ulong send_fec_set_idx;
  ulong tsorig;  /* timestamp of the last packet in compressed form */

  /* Includes Ethernet, IP, UDP headers */
  ulong shred_buffer_sz;
  uchar shred_buffer[ FD_NET_MTU ];

  ulong netmux_in_idx;
  ulong poh_in_idx;
  ulong sign_in_idx;
  ulong contact_in_idx;
  ulong stake_in_idx;

  fd_wksp_t * netmux_in_mem;
  ulong       netmux_in_chunk0;
  ulong       netmux_in_wmark;

  fd_wksp_t * stake_in_mem;
  ulong       stake_in_chunk0;
  ulong       stake_in_wmark;

  fd_wksp_t * contact_in_mem;
  ulong       contact_in_chunk0;
  ulong       contact_in_wmark;

  fd_wksp_t * poh_in_mem;
  ulong       poh_in_chunk0;
  ulong       poh_in_wmark;

  fd_frag_meta_t * netmux_out_mcache;
  ulong *          netmux_out_sync;
  ulong            netmux_out_depth;
  ulong            netmux_out_seq;

  fd_wksp_t * netmux_out_mem;
  ulong       netmux_out_chunk0;
  ulong       netmux_out_wmark;
  ulong       netmux_out_chunk;

  fd_wksp_t * store_out_mem;
  ulong       store_out_chunk0;
  ulong       store_out_wmark;
  ulong       store_out_chunk;

  struct {
    ulong pos; /* in payload, so 0<=pos<63671 */
    ulong slot; /* set to 0 when pos==0 */
    union {
      struct {
        ulong microblock_cnt;
        uchar payload[ 63679UL - 8UL ];
      };
      uchar raw[ 63679UL ]; /* The largest that fits in 1 FEC set */
    };
  } pending_batch;
};

typedef struct fd_shred_tile_private fd_shred_tile_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_shred_tile_align( void );

FD_FN_PURE ulong
fd_shred_tile_footprint( fd_shred_tile_args_t const * args );

ulong
fd_shred_tile_seccomp_policy( void *               shshred,
                              struct sock_filter * out,
                              ulong                out_cnt );

ulong
fd_shred_tile_allowed_fds( void * shshred,
                           int *  out,
                           ulong  out_cnt );

void
fd_shred_tile_join_privileged( void *                       shshred,
                               fd_shred_tile_args_t const * args );

fd_shred_tile_t *
fd_shred_tile_join( void *                       shshred,
                    fd_shred_tile_args_t const * args,
                    fd_shred_tile_topo_t const * topo );

void
fd_shred_tile_run( fd_shred_tile_t *       verify,
                   fd_cnc_t *              cnc,
                   ulong                   in_cnt,
                   fd_frag_meta_t const ** in_mcache,
                   ulong **                in_fseq,
                   fd_frag_meta_t *        mcache,
                   ulong                   out_cnt,
                   ulong **                out_fseq );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_fd_disco_tiles_shred_fd_shred_tile_h */
