#ifndef HEADER_fd_src_disco_topo_fd_topo_h
#define HEADER_fd_src_disco_topo_fd_topo_h

#include "../stem/fd_stem.h"
#include "../../tango/fd_tango.h"
#include "../../waltz/xdp/fd_xdp1.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../util/net/fd_net_headers.h"

/* Maximum number of workspaces that may be present in a topology. */
#define FD_TOPO_MAX_WKSPS         (256UL)
/* Maximum number of links that may be present in a topology. */
#define FD_TOPO_MAX_LINKS         (256UL)
/* Maximum number of tiles that may be present in a topology. */
#define FD_TOPO_MAX_TILES         (256UL)
/* Maximum number of objects that may be present in a topology. */
#define FD_TOPO_MAX_OBJS          (4096UL)
/* Maximum number of links that may go into any one tile in the
   topology. */
#define FD_TOPO_MAX_TILE_IN_LINKS  ( 128UL)
/* Maximum number of links that a tile may write to. */
#define FD_TOPO_MAX_TILE_OUT_LINKS ( 32UL)
/* Maximum number of objects that a tile can use. */
#define FD_TOPO_MAX_TILE_OBJS      ( 256UL)

/* Maximum number of additional ip addresses */
#define FD_NET_MAX_SRC_ADDR 4

/* Maximum number of additional destinations for leader shreds and for retransmitted shreds */
#define FD_TOPO_ADTL_DESTS_MAX ( 32UL)


/* A workspace is a Firedancer specific memory management structure that
   sits on top of 1 or more memory mapped gigantic or huge pages mounted
   to the hugetlbfs. */
typedef struct {
  ulong id;           /* The ID of this workspace.  Indexed from [0, wksp_cnt).  When placed in a topology, the ID must be the index of the workspace in the workspaces list. */
  char  name[ 13UL ]; /* The name of this workspace, like "pack".  There can be at most one of each workspace name in a topology. */

  ulong numa_idx;     /* The index of the NUMA node on the system that this workspace should be allocated from. */

  /* Computed fields.  These are not supplied as configuration but calculated as needed. */
  struct {
    ulong page_sz;  /* The size of the pages that this workspace is backed by.  One of FD_PAGE_SIZE_*. */
    ulong page_cnt; /* The number of pages that must be mapped to this workspace to store all the data needed by consumers. */
    ulong part_max; /* The maximum number of partitions in the underlying workspace.  There can only be this many allocations made at any one time. */

    fd_wksp_t * wksp;            /* The workspace memory in the local process. */
    ulong       known_footprint; /* Total size in bytes of all data in Firedancer that will be stored in this workspace at startup. */
    ulong       total_footprint; /* Total size in bytes of all data in Firedancer that could be stored in this workspace, includes known data and loose data. */
  };
} fd_topo_wksp_t;

/* A link is an mcache in a workspace that has one producer and one or
   more consumers. A link may optionally also have a dcache, that holds
   fragments referred to by the mcache entries.

   A link belongs to exactly one workspace.  A link has exactly one
   producer, and 1 or more consumers.  Each consumer is either reliable
   or not reliable.  A link has a depth and a MTU, which correspond to
   the depth and MTU of the mcache and dcache respectively.  A MTU of
   zero means no dcache is needed, as there is no data. */
typedef struct {
  ulong id;           /* The ID of this link.  Indexed from [0, link_cnt).  When placed in a topology, the ID must be the index of the link in the links list. */
  char  name[ 13UL ]; /* The name of this link, like "pack_bank". There can be multiple of each link name in a topology. */
  ulong kind_id;      /* The ID of this link within its name.  If there are N links of a particular name, they have IDs [0, N).  The pair (name, kind_id) uniquely identifies a link, as does "id" on its own. */

  ulong depth;    /* The depth of the mcache representing the link. */
  ulong mtu;      /* The MTU of data fragments in the mcache.  A value of 0 means there is no dcache. */
  ulong burst;    /* The max amount of MTU sized data fragments that might be bursted to the dcache. */

  ulong mcache_obj_id;
  ulong dcache_obj_id;

  /* Computed fields.  These are not supplied as configuration but calculated as needed. */
  struct {
    fd_frag_meta_t * mcache; /* The mcache of this link. */
    void *           dcache; /* The dcache of this link, if it has one. */
  };

  uint permit_no_consumers : 1;  /* Permit a topology where this link has no consumers */
  uint permit_no_producers : 1;  /* Permit a topology where this link has no producers */
} fd_topo_link_t;

/* Be careful: ip and host are in different byte order */
typedef struct {
  uint   ip;   /* in network byte order */
  ushort port; /* in host byte order */
} fd_topo_ip_port_t;

struct fd_topo_net_tile {
  ulong umem_dcache_obj_id;  /* dcache for XDP UMEM frames */
  uint  bind_address;

  ushort shred_listen_port;
  ushort quic_transaction_listen_port;
  ushort legacy_transaction_listen_port;
  ushort gossip_listen_port;
  ushort repair_intake_listen_port;
  ushort repair_serve_listen_port;
  ushort send_src_port;
};
typedef struct fd_topo_net_tile fd_topo_net_tile_t;

/* A tile is a unique process that is spawned by Firedancer to represent
   one thread of execution.  Firedancer sandboxes all tiles to their own
   process for security reasons.

   A tile belongs to exactly one workspace.  A tile is a consumer of 0
   or more links, it's inputs.  A tile is a producer of 0 or more output
   links.

   All input links will be automatically polled by the tile
   infrastructure, and output links will automatically source and manage
   credits from consumers. */
struct fd_topo_tile {
  ulong id;                     /* The ID of this tile.  Indexed from [0, tile_cnt).  When placed in a topology, the ID must be the index of the tile in the tiles list. */
  char  name[ 7UL ];            /* The name of this tile.  There can be multiple of each tile name in a topology. */
  char  metrics_name[ 10UL ];   /* The name of this tile for looking up metrics.  This is used so tiles can share a name but report different metrics, for Frankendancer and Firedancer. */
  ulong kind_id;                /* The ID of this tile within its name.  If there are n tile of a particular name, they have IDs [0, N).  The pair (name, kind_id) uniquely identifies a tile, as does "id" on its own. */
  int   is_agave;               /* If the tile needs to run in the Agave (Anza) address space or not. */
  int   allow_shutdown;         /* If the tile is allowed to shutdown gracefully.  If false, when the tile exits it will tear down the entire application. */

  ulong cpu_idx;                /* The CPU index to pin the tile on.  A value of ULONG_MAX or more indicates the tile should be floating and not pinned to a core. */

  ulong in_cnt;                 /* The number of links that this tile reads from. */
  ulong in_link_id[ FD_TOPO_MAX_TILE_IN_LINKS ];       /* The link_id of each link that this tile reads from, indexed in [0, in_cnt). */
  int   in_link_reliable[ FD_TOPO_MAX_TILE_IN_LINKS ]; /* If each link that this tile reads from is a reliable or unreliable consumer, indexed in [0, in_cnt). */
  int   in_link_poll[ FD_TOPO_MAX_TILE_IN_LINKS ];     /* If each link that this tile reads from should be polled by the tile infrastructure, indexed in [0, in_cnt).
                                                          If the link is not polled, the tile will not receive frags for it and the tile writer is responsible for
                                                          reading from the link.  The link must be marked as unreliable as it is not flow controlled. */

  ulong out_cnt;                                   /* The number of links that this tile writes to. */
  ulong out_link_id[ FD_TOPO_MAX_TILE_OUT_LINKS ]; /* The link_id of each link that this tile writes to, indexed in [0, link_cnt). */

  ulong tile_obj_id;
  ulong metrics_obj_id;
  ulong keyswitch_obj_id;
  ulong in_link_fseq_obj_id[ FD_TOPO_MAX_TILE_IN_LINKS ];

  ulong uses_obj_cnt;
  ulong uses_obj_id[ FD_TOPO_MAX_TILE_OBJS ];
  int   uses_obj_mode[ FD_TOPO_MAX_TILE_OBJS ];

  /* Computed fields.  These are not supplied as configuration but calculated as needed. */
  struct {
    ulong *    metrics; /* The shared memory for metrics that this tile should write.  Consumer by monitoring and metrics writing tiles. */

    /* The fseq of each link that this tile reads from.  Multiple fseqs
       may point to the link, if there are multiple consumers.  An fseq
       can be uniquely identified via (link_id, tile_id), or (link_kind,
       link_kind_id, tile_kind, tile_kind_id) */
    ulong *    in_link_fseq[ FD_TOPO_MAX_TILE_IN_LINKS ];
  };

  /* Configuration fields.  These are required to be known by the topology so it can determine the
     total size of Firedancer in memory. */
  union {
    fd_topo_net_tile_t net;

    struct {
      fd_topo_net_tile_t net;
      char interface[ 16 ];

      /* xdp specific options */
      ulong  xdp_rx_queue_size;
      ulong  xdp_tx_queue_size;
      ulong  free_ring_depth;
      long   tx_flush_timeout_ns;
      char   xdp_mode[8];
      int    zero_copy;

      ulong netdev_dbl_buf_obj_id; /* dbl_buf containing netdev_tbl */
      ulong fib4_main_obj_id;      /* fib4 containing main route table */
      ulong fib4_local_obj_id;     /* fib4 containing local route table */
      ulong neigh4_obj_id;         /* neigh4 hash map header */
      ulong neigh4_ele_obj_id;     /* neigh4 hash map slots */
    } xdp;

    struct {
      fd_topo_net_tile_t net;
      /* sock specific options */
      int so_sndbuf;
      int so_rcvbuf;
    } sock;

    struct {
      ulong netdev_dbl_buf_obj_id; /* dbl_buf containing netdev_tbl */
      ulong fib4_main_obj_id;      /* fib4 containing main route table */
      ulong fib4_local_obj_id;     /* fib4 containing local route table */
      char  neigh_if[ 16 ];        /* neigh4 interface name */
      ulong neigh4_obj_id;         /* neigh4 hash map header */
      ulong neigh4_ele_obj_id;     /* neigh4 hash map slots */
    } netlink;

#define FD_TOPO_GOSSIP_ENTRYPOINTS_MAX 16UL

    struct {
      char identity_key_path[ PATH_MAX ];

      ulong         entrypoints_cnt;
      fd_ip4_port_t entrypoints[ FD_TOPO_GOSSIP_ENTRYPOINTS_MAX ];

      long boot_timestamp_nanos;

      ulong tcache_depth;

      ushort shred_version;
      int allow_private_address;
    } gossvf;

    struct {
      char identity_key_path[ PATH_MAX ];

      ulong         entrypoints_cnt;
      fd_ip4_port_t entrypoints[ FD_TOPO_GOSSIP_ENTRYPOINTS_MAX ];

      long boot_timestamp_nanos;

      uint   ip_addr;
      ushort shred_version;

      ulong  max_entries;
      ulong  max_purged;
      ulong  max_failed;

      struct {
        ushort gossip;
        ushort tvu;
        ushort tvu_quic;
        ushort tpu;
        ushort tpu_quic;
        ushort repair;
      } ports;
    } gossip;

    struct {
      uint   out_depth;
      uint   reasm_cnt;
      ulong  max_concurrent_connections;
      ulong  max_concurrent_handshakes;
      ushort quic_transaction_listen_port;
      long   idle_timeout_millis;
      uint   ack_delay_millis;
      int    retry;
      char   key_log_path[ PATH_MAX ];
    } quic;

    struct {
      ulong tcache_depth;
    } verify;

    struct {
      ulong tcache_depth;
    } dedup;

    struct {
      char  url[ 256 ];
      ulong url_len;
      char  sni[ 256 ];
      ulong sni_len;
      char  identity_key_path[ PATH_MAX ];
      char  key_log_path[ PATH_MAX ];
      ulong buf_sz;
      ulong ssl_heap_sz;
      ulong keepalive_interval_nanos;
      uchar tls_cert_verify : 1;
    } bundle;

    struct {
      ulong max_pending_transactions;
      ulong bank_tile_count;
      int   larger_max_cost_per_block;
      int   larger_shred_limits_per_block;
      int   use_consumed_cus;
      int   schedule_strategy;
      struct {
        int   enabled;
        uchar tip_distribution_program_addr[ 32 ];
        uchar tip_payment_program_addr[ 32 ];
        uchar tip_distribution_authority[ 32 ];
        ulong commission_bps;
        char  identity_key_path[ PATH_MAX ];
        char  vote_account_path[ PATH_MAX ]; /* or pubkey is okay */
      } bundle;
    } pack;

    struct {
      int   lagged_consecutive_leader_start;
      int   plugins_enabled;
      ulong bank_cnt;
      char  identity_key_path[ PATH_MAX ];
      struct {
        int   enabled;
        uchar tip_payment_program_addr[ 32 ];
        uchar tip_distribution_program_addr[ 32 ];
        char  vote_account_path[ PATH_MAX ];
      } bundle;
    } poh;

    struct {
      ulong             depth;
      ulong             fec_resolver_depth;
      char              identity_key_path[ PATH_MAX ];
      ushort            shred_listen_port;
      int               larger_shred_limits_per_block;
      ushort            expected_shred_version;
      ulong             adtl_dests_retransmit_cnt;
      fd_topo_ip_port_t adtl_dests_retransmit[ FD_TOPO_ADTL_DESTS_MAX ];
      ulong             adtl_dests_leader_cnt;
      fd_topo_ip_port_t adtl_dests_leader[ FD_TOPO_ADTL_DESTS_MAX ];
    } shred;

    struct {
      ulong disable_blockstore_from_slot;
    } store;

    struct {
      char   identity_key_path[ PATH_MAX ];
    } sign;

    struct {
      uint   listen_addr;
      ushort listen_port;

      int    is_voting;

      char   cluster[ 32 ];
      char   identity_key_path[ PATH_MAX ];
      char   vote_key_path[ PATH_MAX ];

      ulong  max_http_connections;
      ulong  max_websocket_connections;
      ulong  max_http_request_length;
      ulong  send_buffer_size_mb;
      int    schedule_strategy;

      int websocket_compression;
      int frontend_release_channel;
    } gui;

    struct {
      uint   listen_addr;
      ushort listen_port;

      ulong max_http_connections;
      ulong send_buffer_size_mb;
      ulong max_http_request_length;

      ulong max_live_slots;

      char identity_key_path[ PATH_MAX ];
    } rpc;

    struct {
      uint   prometheus_listen_addr;
      ushort prometheus_listen_port;
    } metric;

    struct {
      ulong fec_max;
      ulong max_vote_accounts;

      ulong funk_obj_id;
      ulong txncache_obj_id;
      ulong progcache_obj_id;

      char  shred_cap[ PATH_MAX ];
      char  cluster_version[ 32 ];

      char  identity_key_path[ PATH_MAX ];
      uint  ip_addr;
      char  vote_account_path[ PATH_MAX ];

      ushort expected_shred_version;

      ulong heap_size_gib;
      ulong max_live_slots;

      /* not specified in TOML */

      ulong enable_features_cnt;
      char  enable_features[ 16 ][ FD_BASE58_ENCODED_32_SZ ];

      ulong enable_bank_hash_cmp;

      int   larger_max_cost_per_block;

      ulong capture_start_slot;
      char  solcap_capture[ PATH_MAX ];
      char  dump_proto_dir[ PATH_MAX ];
      int   dump_block_to_pb;

      struct {
        int   enabled;
        uchar tip_payment_program_addr[ 32 ];
        uchar tip_distribution_program_addr[ 32 ];
        char  vote_account_path[ PATH_MAX ];
      } bundle;

    } replay;

    struct {
      ulong funk_obj_id;
      ulong txncache_obj_id;
      ulong progcache_obj_id;

      ulong max_live_slots;

      ulong capture_start_slot;
      char  solcap_capture[ PATH_MAX ];
      char  dump_proto_dir[ PATH_MAX ];
      int   dump_instr_to_pb;
      int   dump_txn_to_pb;
      int   dump_syscall_to_pb;
      int   dump_elf_to_pb;
    } exec;

    struct {
      ushort send_to_port;
      uint   send_to_ip_addr;
      ulong  conn_cnt;
      int    no_quic;
    } benchs;

    struct {
      ushort rpc_port;
      uint   rpc_ip_addr;
    } bencho;

    struct {
      ulong accounts_cnt;
      int   mode;
      float contending_fraction;
      float cu_price_spread;
    } benchg;

    struct {
      ushort  repair_intake_listen_port;
      ushort  repair_serve_listen_port;
      char    identity_key_path[ PATH_MAX ];
      ulong   max_pending_shred_sets;
      ulong   slot_max;

      /* non-config */

      ulong   repair_sign_depth;
      ulong   repair_sign_cnt;
    } repair;

    struct {
      char  slots_pending[PATH_MAX];

      ulong expected_shred_version;

      /* non-config */

      char  identity_key_path[ PATH_MAX ];
      char  shred_cap_archive[ PATH_MAX ];
      char  shred_cap_replay[ PATH_MAX ];
      ulong shred_cap_end_slot;

      char  blockstore_file[ PATH_MAX ];
      char  blockstore_restore[ PATH_MAX ];
    } store_int;

    struct {
      ushort  send_src_port;

      /* non-config */

      uint    ip_addr;
      char  identity_key_path[ PATH_MAX ];
    } send;

    struct {
      uint fake_dst_ip;
    } pktgen;

    struct {
      ulong end_slot;
      char  rocksdb_path[ PATH_MAX ];
      char  shredcap_path[ PATH_MAX ];
      char  bank_hash_path[ PATH_MAX ];
      char  ingest_mode[ 32 ];

      /* Set internally by the archiver tile */
      int archive_fd;
    } archiver;

    struct {
      ulong funk_obj_id;
      char  identity_key_path[ PATH_MAX ];
      char  vote_acc_path[ PATH_MAX ];
      char  ledger_path[PATH_MAX];
    } tower;
    struct {
      char   folder_path[ PATH_MAX ];
      ushort repair_intake_listen_port;
      ulong   write_buffer_size; /* Size of the write buffer for the capture tile */
      int    enable_publish_stake_weights;
      char   manifest_path[ PATH_MAX ];

      /* Set internally by the capture tile */
      int shreds_fd;
      int requests_fd;
      int fecs_fd;
      int peers_fd;
      int bank_hashes_fd;
      int slices_fd;
    } shredcap;

#define FD_TOPO_SNAPSHOTS_GOSSIP_LIST_MAX (32UL)
#define FD_TOPO_SNAPSHOTS_SERVERS_MAX     (16UL)

    struct fd_topo_tile_snapct {
      char snapshots_path[ PATH_MAX ];

      struct {
        uint max_local_full_effective_age;
        uint max_local_incremental_age;

        struct {
          int         allow_any;
          ulong       allow_list_cnt;
          fd_pubkey_t allow_list[ FD_TOPO_SNAPSHOTS_GOSSIP_LIST_MAX ];
          ulong       block_list_cnt;
          fd_pubkey_t block_list[ FD_TOPO_SNAPSHOTS_GOSSIP_LIST_MAX ];
        } gossip;

        ulong         servers_cnt;
        fd_ip4_port_t servers[ FD_TOPO_SNAPSHOTS_SERVERS_MAX ];
      } sources;

      int  incremental_snapshots;
      uint max_full_snapshots_to_keep;
      uint max_incremental_snapshots_to_keep;
      uint full_effective_age_cancel_threshold;
    } snapct;

    struct {
      char snapshots_path[ PATH_MAX ];
    } snapld;

    struct {
      ulong max_live_slots;
      ulong funk_obj_id;
      ulong txncache_obj_id;

      uint  use_vinyl : 1;
      ulong vinyl_meta_map_obj_id;
      ulong vinyl_meta_pool_obj_id;
      ulong snapwr_depth;
      char  vinyl_path[ PATH_MAX ];
    } snapin;

    struct {
      ulong dcache_obj_id;
      char  vinyl_path[ PATH_MAX ];
    } snapwr;

    struct {

      uint   bind_address;
      ushort bind_port;

      ushort expected_shred_version;
      ulong entrypoints_cnt;
      fd_ip4_port_t entrypoints[ FD_TOPO_GOSSIP_ENTRYPOINTS_MAX ];
    } ipecho;

    struct {
      ulong max_live_slots;

      ulong txncache_obj_id;
      ulong funk_obj_id;
      ulong progcache_obj_id;
    } bank;

    struct {
      ulong funk_obj_id;
    } resolv;

    struct {
      ulong funk_obj_id;

      int allow_download;

      ushort expected_shred_version;
      ulong entrypoints_cnt;
      fd_ip4_port_t entrypoints[ FD_TOPO_GOSSIP_ENTRYPOINTS_MAX ];

      int has_expected_genesis_hash;
      uchar expected_genesis_hash[ 32UL ];

      char genesis_path[ PATH_MAX ];

      uint target_gid;
      uint target_uid;
    } genesi;

    struct {
      ulong vinyl_meta_map_obj_id;
      ulong vinyl_meta_pool_obj_id;
      ulong vinyl_line_max;
      ulong vinyl_cnc_obj_id; /* optional */
      ulong vinyl_data_obj_id;
      char  vinyl_bstream_path[ PATH_MAX ];
    } vinyl;
  };
};

typedef struct fd_topo_tile fd_topo_tile_t;

typedef struct {
  ulong id;
  char  name[ 13UL ];
  ulong wksp_id;

  ulong offset;
  ulong footprint;
} fd_topo_obj_t;

/* An fd_topo_t represents the overall structure of a Firedancer
   configuration, describing all the workspaces, tiles, and links
   between them. */
struct fd_topo {
  char           app_name[ 256UL ];
  uchar          props[ 16384UL ];

  ulong          wksp_cnt;
  ulong          link_cnt;
  ulong          tile_cnt;
  ulong          obj_cnt;

  fd_topo_wksp_t workspaces[ FD_TOPO_MAX_WKSPS ];
  fd_topo_link_t links[ FD_TOPO_MAX_LINKS ];
  fd_topo_tile_t tiles[ FD_TOPO_MAX_TILES ];
  fd_topo_obj_t  objs[ FD_TOPO_MAX_OBJS ];

  ulong          agave_affinity_cnt;
  ulong          agave_affinity_cpu_idx[ FD_TILE_MAX ];

  ulong          max_page_size; /* 2^21 or 2^30 */
  ulong          gigantic_page_threshold; /* see [hugetlbfs.gigantic_page_threshold_mib]*/
};
typedef struct fd_topo fd_topo_t;

typedef struct {
  char const * name;

  int          keep_host_networking;
  int          allow_connect;
  int          allow_renameat;
  ulong        rlimit_file_cnt;
  ulong        rlimit_address_space;
  ulong        rlimit_data;
  int          for_tpool;

  ulong (*populate_allowed_seccomp)( fd_topo_t const * topo, fd_topo_tile_t const * tile, ulong out_cnt, struct sock_filter * out );
  ulong (*populate_allowed_fds    )( fd_topo_t const * topo, fd_topo_tile_t const * tile, ulong out_fds_sz, int * out_fds );
  ulong (*scratch_align           )( void );
  ulong (*scratch_footprint       )( fd_topo_tile_t const * tile );
  ulong (*loose_footprint         )( fd_topo_tile_t const * tile );
  void  (*privileged_init         )( fd_topo_t * topo, fd_topo_tile_t * tile );
  void  (*unprivileged_init       )( fd_topo_t * topo, fd_topo_tile_t * tile );
  void  (*run                     )( fd_topo_t * topo, fd_topo_tile_t * tile );
  ulong (*rlimit_file_cnt_fn      )( fd_topo_t const * topo, fd_topo_tile_t const * tile );
} fd_topo_run_tile_t;

struct fd_topo_obj_callbacks {
  char const * name;
  ulong (* footprint )( fd_topo_t const * topo, fd_topo_obj_t const * obj );
  ulong (* align     )( fd_topo_t const * topo, fd_topo_obj_t const * obj );
  ulong (* loose     )( fd_topo_t const * topo, fd_topo_obj_t const * obj );
  void  (* new       )( fd_topo_t const * topo, fd_topo_obj_t const * obj );
};

typedef struct fd_topo_obj_callbacks fd_topo_obj_callbacks_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_topo_workspace_align( void ) {
  /* This needs to be the max( align ) of all the child members that
     could be aligned into this workspace, otherwise our footprint
     calculation will not be correct.  For now just set to 4096 but this
     should probably be calculated dynamically, or we should reduce
     those child aligns if we can. */
  return 4096UL;
}

void *
fd_topo_obj_laddr( fd_topo_t const * topo,
                   ulong             obj_id );

/* Returns a pointer in the local address space to the base address of
   the workspace out of which the given object was allocated. */

static inline void *
fd_topo_obj_wksp_base( fd_topo_t const * topo,
                       ulong             obj_id ) {
  FD_TEST( obj_id<FD_TOPO_MAX_OBJS );
  fd_topo_obj_t const * obj = &topo->objs[ obj_id ];
  FD_TEST( obj->id == obj_id );
  ulong const wksp_id = obj->wksp_id;

  FD_TEST( wksp_id<FD_TOPO_MAX_WKSPS );
  fd_topo_wksp_t const * wksp = &topo->workspaces[ wksp_id ];
  FD_TEST( wksp->id == wksp_id );
  return wksp->wksp;
}

FD_FN_PURE static inline ulong
fd_topo_tile_name_cnt( fd_topo_t const * topo,
                       char const *      name ) {
  ulong cnt = 0;
  for( ulong i=0; i<topo->tile_cnt; i++ ) {
    if( FD_UNLIKELY( !strcmp( topo->tiles[ i ].name, name ) ) ) cnt++;
  }
  return cnt;
}

/* Finds the workspace of a given name in the topology.  Returns
   ULONG_MAX if there is no such workspace.  There can be at most one
   workspace of a given name. */

FD_FN_PURE static inline ulong
fd_topo_find_wksp( fd_topo_t const * topo,
                   char const *      name ) {
  for( ulong i=0; i<topo->wksp_cnt; i++ ) {
    if( FD_UNLIKELY( !strcmp( topo->workspaces[ i ].name, name ) ) ) return i;
  }
  return ULONG_MAX;
}

/* Find the tile of a given name and kind_id in the topology, there will
   be at most one such tile, since kind_id is unique among the name.
   Returns ULONG_MAX if there is no such tile. */

FD_FN_PURE static inline ulong
fd_topo_find_tile( fd_topo_t const * topo,
                   char const *      name,
                   ulong             kind_id ) {
  for( ulong i=0; i<topo->tile_cnt; i++ ) {
    if( FD_UNLIKELY( !strcmp( topo->tiles[ i ].name, name ) ) && topo->tiles[ i ].kind_id == kind_id ) return i;
  }
  return ULONG_MAX;
}

/* Find the link of a given name and kind_id in the topology, there will
   be at most one such link, since kind_id is unique among the name.
   Returns ULONG_MAX if there is no such link. */

FD_FN_PURE static inline ulong
fd_topo_find_link( fd_topo_t const * topo,
                   char const *      name,
                   ulong             kind_id ) {
  for( ulong i=0; i<topo->link_cnt; i++ ) {
    if( FD_UNLIKELY( !strcmp( topo->links[ i ].name, name ) ) && topo->links[ i ].kind_id == kind_id ) return i;
  }
  return ULONG_MAX;
}

FD_FN_PURE static inline ulong
fd_topo_find_tile_in_link( fd_topo_t const *      topo,
                           fd_topo_tile_t const * tile,
                           char const *           name,
                           ulong                  kind_id ) {
  for( ulong i=0; i<tile->in_cnt; i++ ) {
    if( FD_UNLIKELY( !strcmp( topo->links[ tile->in_link_id[ i ] ].name, name ) )
        && topo->links[ tile->in_link_id[ i ] ].kind_id == kind_id ) return i;
  }
  return ULONG_MAX;
}

FD_FN_PURE static inline ulong
fd_topo_find_tile_out_link( fd_topo_t const *      topo,
                            fd_topo_tile_t const * tile,
                            char const *           name,
                            ulong                  kind_id ) {
  for( ulong i=0; i<tile->out_cnt; i++ ) {
    if( FD_UNLIKELY( !strcmp( topo->links[ tile->out_link_id[ i ] ].name, name ) )
        && topo->links[ tile->out_link_id[ i ] ].kind_id == kind_id ) return i;
  }
  return ULONG_MAX;
}

/* Find the id of the tile which is a producer for the given link.  If
   no tile is a producer for the link, returns ULONG_MAX.  This should
   not be possible for a well formed and validated topology.  */
FD_FN_PURE static inline ulong
fd_topo_find_link_producer( fd_topo_t const *      topo,
                            fd_topo_link_t const * link ) {
  for( ulong i=0; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ i ];

    for( ulong j=0; j<tile->out_cnt; j++ ) {
      if( FD_UNLIKELY( tile->out_link_id[ j ] == link->id ) ) return i;
    }
  }
  return ULONG_MAX;
}

/* Given a link, count the number of consumers of that link among all
   the tiles in the topology. */
FD_FN_PURE static inline ulong
fd_topo_link_consumer_cnt( fd_topo_t const *      topo,
                           fd_topo_link_t const * link ) {
  ulong cnt = 0;
  for( ulong i=0; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ i ];
    for( ulong j=0; j<tile->in_cnt; j++ ) {
      if( FD_UNLIKELY( tile->in_link_id[ j ] == link->id ) ) cnt++;
    }
  }

  return cnt;
}

/* Given a link, count the number of reliable consumers of that link
   among all the tiles in the topology. */
FD_FN_PURE static inline ulong
fd_topo_link_reliable_consumer_cnt( fd_topo_t const *      topo,
                                    fd_topo_link_t const * link ) {
  ulong cnt = 0;
  for( ulong i=0; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ i ];
    for( ulong j=0; j<tile->in_cnt; j++ ) {
      if( FD_UNLIKELY( tile->in_link_id[ j ] == link->id && tile->in_link_reliable[ j ] ) ) cnt++;
    }
  }

  return cnt;
}

FD_FN_PURE static inline ulong
fd_topo_tile_consumer_cnt( fd_topo_t const *      topo,
                           fd_topo_tile_t const * tile ) {
  (void)topo;
  return tile->out_cnt;
}

FD_FN_PURE static inline ulong
fd_topo_tile_reliable_consumer_cnt( fd_topo_t const *      topo,
                                    fd_topo_tile_t const * tile ) {
  ulong reliable_cons_cnt = 0UL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * consumer_tile = &topo->tiles[ i ];
    for( ulong j=0UL; j<consumer_tile->in_cnt; j++ ) {
      for( ulong k=0UL; k<tile->out_cnt; k++ ) {
        if( FD_UNLIKELY( consumer_tile->in_link_id[ j ]==tile->out_link_id[ k ] && consumer_tile->in_link_reliable[ j ] ) ) {
          reliable_cons_cnt++;
        }
      }
    }
  }
  return reliable_cons_cnt;
}

FD_FN_PURE static inline ulong
fd_topo_tile_producer_cnt( fd_topo_t const *     topo,
                           fd_topo_tile_t const * tile ) {
  (void)topo;
  ulong in_cnt = 0UL;
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    if( FD_UNLIKELY( !tile->in_link_poll[ i ] ) ) continue;
    in_cnt++;
  }
  return in_cnt;
}

/* Join (map into the process) all shared memory (huge/gigantic pages)
   needed by the tile, in the given topology.  All memory associated
   with the tile (aka. used by links that the tile either produces to or
   consumes from, or used by the tile itself for its cnc) will be
   attached (mapped into the process).

   This is needed to play nicely with the sandbox.  Once a process is
   sandboxed we can no longer map any memory. */
void
fd_topo_join_tile_workspaces( fd_topo_t *      topo,
                              fd_topo_tile_t * tile );

/* Join (map into the process) the shared memory (huge/gigantic pages)
   for the given workspace.  Mode is one of
   FD_SHMEM_JOIN_MODE_READ_WRITE or FD_SHMEM_JOIN_MODE_READ_ONLY and
   determines the prot argument that will be passed to mmap when mapping
   the pages in (PROT_WRITE or PROT_READ respectively). */
void
fd_topo_join_workspace( fd_topo_t *      topo,
                        fd_topo_wksp_t * wksp,
                        int              mode );

/* Join (map into the process) all shared memory (huge/gigantic pages)
   needed by all tiles in the topology.  Mode is one of
   FD_SHMEM_JOIN_MODE_READ_WRITE or FD_SHMEM_JOIN_MODE_READ_ONLY and
   determines the prot argument that will be passed to mmap when
   mapping the pages in (PROT_WRITE or PROT_READ respectively). */
void
fd_topo_join_workspaces( fd_topo_t *  topo,
                         int          mode );

/* Leave (unmap from the process) the shared memory needed for the
   given workspace in the topology, if it was previously mapped.

   topo and wksp are assumed non-NULL.  It is OK if the workspace
   has not been previously joined, in which case this is a no-op. */

void
fd_topo_leave_workspace( fd_topo_t *      topo,
                         fd_topo_wksp_t * wksp );

/* Leave (unmap from the process) all shared memory needed by all
   tiles in the topology, if each of them was mapped.

   topo is assumed non-NULL.  Only workspaces which were previously
   joined are unmapped. */

void
fd_topo_leave_workspaces( fd_topo_t * topo );

/* Create the given workspace needed by the topology on the system.
   This does not "join" the workspaces (map their memory into the
   process), but only creates the .wksp file and formats it correctly
   as a workspace.

   Returns 0 on success and -1 on failure, with errno set to the error.
   The only reason for failure currently that will be returned is
   ENOMEM, as other unexpected errors will cause the program to exit.

   If update_existing is 1, the workspace will not be created from
   scratch but it will be assumed that it already exists from a prior
   run and needs to be maybe resized and then have the header
   structures reinitialized.  This can save a very expensive operation
   of zeroing all of the workspace pages.  This is dangerous in
   production because it can leave stray memory from prior runs around,
   and should only be used in development environments. */

int
fd_topo_create_workspace( fd_topo_t *      topo,
                          fd_topo_wksp_t * wksp,
                          int              update_existing );

/* Join the standard IPC objects needed by the topology of this particular
   tile */

void
fd_topo_fill_tile( fd_topo_t *      topo,
                   fd_topo_tile_t * tile );

/* Same as fd_topo_fill_tile but fills in all the objects for a
   particular workspace with the given mode. */
void
fd_topo_workspace_fill( fd_topo_t *      topo,
                        fd_topo_wksp_t * wksp );

/* Apply a new function to every object that is resident in the given
   workspace in the topology. */

void
fd_topo_wksp_new( fd_topo_t const *          topo,
                  fd_topo_wksp_t const *     wksp,
                  fd_topo_obj_callbacks_t ** callbacks );

/* Same as fd_topo_fill_tile but fills in all tiles in the topology. */

void
fd_topo_fill( fd_topo_t * topo );

/* fd_topo_tile_stack_join joins a huge page optimized stack for the
   provided tile.  The stack is assumed to already exist at a known
   path in the hugetlbfs mount. */

void *
fd_topo_tile_stack_join( char const * app_name,
                         char const * tile_name,
                         ulong        tile_kind_id );

/* Install the XDP program needed by the net tiles into the local device
   and return the xsk_map_fd.  bind_addr is an optional IPv4 address to
   used for filtering by dst IP. */

fd_xdp_fds_t
fd_topo_install_xdp( fd_topo_t const * topo,
                     uint              bind_addr );

/* fd_topo_run_single_process runs all the tiles in a single process
   (the calling process).  This spawns a thread for each tile, switches
   that thread to the given UID and GID and then runs the tile in it.
   Each thread will never exit, as tiles are expected to run forever.
   An error is logged and the application will exit if a tile exits.
   The function itself does return after spawning all the threads.

   The threads will not be sandboxed in any way, except switching to the
   provided UID and GID, so they will share the same address space, and
   not have any seccomp restrictions or use any Linux namespaces.  The
   calling thread will also switch to the provided UID and GID before
   it returns.

   In production, when running with an Agave child process this is
   used for spawning certain tiles inside the Agave address space.
   It's also useful for tooling and debugging, but is not how the main
   production Firedancer process runs.  For production, each tile is run
   in its own address space with a separate process and full security
   sandbox.

   The agave argument determines which tiles are started.  If the
   argument is 0 or 1, only non-agave (or only agave) tiles are started.
   If the argument is any other value, all tiles in the topology are
   started regardless of if they are Agave tiles or not. */

void
fd_topo_run_single_process( fd_topo_t *       topo,
                            int               agave,
                            uint              uid,
                            uint              gid,
                            fd_topo_run_tile_t (* tile_run )( fd_topo_tile_t const * tile ) );

/* fd_topo_run_tile runs the given tile directly within the current
   process (and thread).  The function will never return, as tiles are
   expected to run forever.  An error is logged and the application will
   exit if the tile exits.

   The sandbox argument determines if the current process will be
   sandboxed fully before starting the tile.  The thread will switch to
   the UID and GID provided before starting the tile, even if the thread
   is not being sandboxed.  Although POSIX specifies that all threads in
   a process must share a UID and GID, this is not the case on Linux.
   The thread will switch to the provided UID and GID without switching
   the other threads in the process.

   If keep_controlling_terminal is set to 0, and the sandbox is enabled
   the controlling terminal will be detached as an additional sandbox
   measure, but you will not be able to send Ctrl+C or other signals
   from the terminal.  See fd_sandbox.h for more information.

   The allow_fd argument is only used if sandbox is true, and is a file
   descriptor which will be allowed to exist in the process.  Normally
   the sandbox code rejects and aborts if there is an unexpected file
   descriptor present on boot.  This is helpful to allow a parent
   process to be notified on termination of the tile by waiting for a
   pipe file descriptor to get closed.

   wait and debugger are both used in debugging.  If wait is non-NULL,
   the runner will wait until the value pointed to by wait is non-zero
   before launching the tile.  Likewise, if debugger is non-NULL, the
   runner will wait until a debugger is attached before setting the
   value pointed to by debugger to non-zero.  These are intended to be
   used as a pair, where many tiles share a waiting reference, and then
   one of the tiles (a tile you want to attach the debugger to) has the
   same reference provided as the debugger, so all tiles will stop and
   wait for the debugger to attach to it before proceeding. */

void
fd_topo_run_tile( fd_topo_t *          topo,
                  fd_topo_tile_t *     tile,
                  int                  sandbox,
                  int                  keep_controlling_terminal,
                  int                  dumpable,
                  uint                 uid,
                  uint                 gid,
                  int                  allow_fd,
                  volatile int *       wait,
                  volatile int *       debugger,
                  fd_topo_run_tile_t * tile_run );

/* This is for determining the value of RLIMIT_MLOCK that we need to
   successfully run all tiles in separate processes.  The value returned
   is the maximum amount of memory that will be locked with mlock() by
   any individual process in the tree.  Specifically, if we have three
   tile processes, and they each need to lock 5, 9, and 2 MiB of memory
   respectively, RLIMIT_MLOCK needs to be 9 MiB to allow all three
   process mlock() calls to succeed.

   Tiles lock memory in three ways.  Any workspace they are using, they
   lock the entire workspace.  Then each tile uses huge pages for the
   stack which are also locked, and finally some tiles use private
   locked mmaps outside the workspace for storing key material.  The
   results here include all of this memory together.

   The result is not necessarily the amount of memory used by the tile
   process, although it will be quite close.  Tiles could potentially
   allocate memory (eg, with brk) without needing to lock it, which
   would not need to included, and some kernel memory that tiles cause
   to be allocated (for example XSK buffers) is also not included.  The
   actual amount of memory used will not be less than this value. */
FD_FN_PURE ulong
fd_topo_mlock_max_tile( fd_topo_t const * topo );

/* Same as fd_topo_mlock_max_tile, but for loading the entire topology
   into one process, rather than a separate process per tile.  This is
   used, for example, by the configuration code when it creates all the
   workspaces, or the monitor that maps the entire system into one
   address space. */
FD_FN_PURE ulong
fd_topo_mlock( fd_topo_t const * topo );

/* This returns the number of gigantic pages needed by the topology on
   the provided numa node.  It includes pages needed by the workspaces,
   as well as additional allocations like huge pages for process stacks
   and private key storage. */

FD_FN_PURE ulong
fd_topo_gigantic_page_cnt( fd_topo_t const * topo,
                           ulong             numa_idx );

/* This returns the number of huge pages in the application needed by
   the topology on the provided numa node.  It includes pages needed by
   things placed in the hugetlbfs (workspaces, process stacks).  If
   include_anonymous is true, it also includes anonymous hugepages which
   are needed but are not placed in the hugetlbfs. */

FD_FN_PURE ulong
fd_topo_huge_page_cnt( fd_topo_t const * topo,
                       ulong             numa_idx,
                       int               include_anonymous );

/* Prints a message describing the topology to an output stream.  If
   stdout is true, will be written to stdout, otherwise will be written
   as a NOTICE log message to the log file. */
void
fd_topo_print_log( int         stdout,
                   fd_topo_t * topo );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_topo_fd_topo_h */
