
#ifndef HEADER_fd_src_app_fdctl_topology_h
#define HEADER_fd_src_app_fdctl_topology_h

#include "../../tango/fd_tango.h"

/* Maximum number of workspaces that may be present in a topology. */
#define FD_TOPO_MAX_WKSPS         (256UL)
/* Maximum number of links that may be present in a topology. */
#define FD_TOPO_MAX_LINKS         (256UL)
/* Maximum number of tiles that may be present in a topology. */
#define FD_TOPO_MAX_TILES         (256UL)
/* Maximum number of links that may go into any one tile in the
   topology. */
#define FD_TOPO_MAX_TILE_IN_LINKS ( 16UL)

#define FD_CNC_APP_SZ (4032UL)

/* FD_TOPO_FILL_MODE_* are used with the fd_topo_fill functions to
   determine what they do.  See comments on those functions for more
   details. */
#define FD_TOPO_FILL_MODE_FOOTPRINT (0UL)
#define FD_TOPO_FILL_MODE_NEW       (1UL)
#define FD_TOPO_FILL_MODE_JOIN      (2UL)

/* A FD_TOPO_WKSP_KIND_* is an identifier for a particular "kind" of
   workspace.  Each workspace kind can exist at most once in the
   application topology, and the kind of a workspace uniquely
   identifies it. */
#define FD_TOPO_WKSP_KIND_NETMUX_INOUT ( 0UL)
#define FD_TOPO_WKSP_KIND_QUIC_VERIFY  ( 1UL)
#define FD_TOPO_WKSP_KIND_VERIFY_DEDUP ( 2UL)
#define FD_TOPO_WKSP_KIND_DEDUP_PACK   ( 3UL)
#define FD_TOPO_WKSP_KIND_PACK_BANK    ( 4UL)
#define FD_TOPO_WKSP_KIND_BANK_SHRED   ( 5UL)
#define FD_TOPO_WKSP_KIND_SHRED_STORE  ( 6UL)
#define FD_TOPO_WKSP_KIND_NET          ( 7UL)
#define FD_TOPO_WKSP_KIND_NETMUX       ( 8UL)
#define FD_TOPO_WKSP_KIND_QUIC         ( 9UL)
#define FD_TOPO_WKSP_KIND_VERIFY       (10UL)
#define FD_TOPO_WKSP_KIND_DEDUP        (11UL)
#define FD_TOPO_WKSP_KIND_PACK         (12UL)
#define FD_TOPO_WKSP_KIND_BANK         (13UL)
#define FD_TOPO_WKSP_KIND_SHRED        (14UL)
#define FD_TOPO_WKSP_KIND_STORE        (15UL)
#define FD_TOPO_WKSP_KIND_MAX          ( FD_TOPO_WKSP_KIND_STORE+1 ) /* Keep updated with maximum tile IDX */

/* FD_TOPO_LINK_KIND_* is an identifier for a particular kind of link. A
   link is a single producer multi consumer communication channel.  In
   Firedancer, this is represented by an mcache and potentially a
   dcache.

   A link kind does not uniquely identify a spmc channel, since there
   may be multiple of the same kind in the application.  For example,
   one link kind, QUIC_TO_VERIFY is for sending transactions from the
   QUIC engine to be verified, but we may have N of these links if there
   are N QUIC tiles. Instead, a link can be uniquely identified by the
   pair of (kind, kind_id) where kind_id is the 0 indexed counter of
   that kind of link. */
#define FD_TOPO_LINK_KIND_NET_TO_NETMUX   ( 0UL)
#define FD_TOPO_LINK_KIND_NETMUX_TO_OUT   ( 1UL)
#define FD_TOPO_LINK_KIND_QUIC_TO_NETMUX  ( 2UL)
#define FD_TOPO_LINK_KIND_QUIC_TO_VERIFY  ( 3UL)
#define FD_TOPO_LINK_KIND_VERIFY_TO_DEDUP ( 4UL)
#define FD_TOPO_LINK_KIND_DEDUP_TO_PACK   ( 5UL)
#define FD_TOPO_LINK_KIND_GOSSIP_TO_PACK  ( 6UL)
#define FD_TOPO_LINK_KIND_LSCHED_TO_PACK  ( 7UL)
#define FD_TOPO_LINK_KIND_PACK_TO_BANK    ( 8UL)
#define FD_TOPO_LINK_KIND_POH_TO_SHRED    ( 9UL)
#define FD_TOPO_LINK_KIND_SHRED_TO_NETMUX (10UL)
#define FD_TOPO_LINK_KIND_SHRED_TO_STORE  (11UL)

/* FD_TOPO_TILE_KIND_* is an identifier for a particular kind of tile.
   There may be multiple or in some cases zero of a particular tile
   kind in the application. */
#define FD_TOPO_TILE_KIND_NET    ( 0UL)
#define FD_TOPO_TILE_KIND_NETMUX ( 1UL)
#define FD_TOPO_TILE_KIND_QUIC   ( 2UL)
#define FD_TOPO_TILE_KIND_VERIFY ( 3UL)
#define FD_TOPO_TILE_KIND_DEDUP  ( 4UL)
#define FD_TOPO_TILE_KIND_PACK   ( 5UL)
#define FD_TOPO_TILE_KIND_BANK   ( 6UL)
#define FD_TOPO_TILE_KIND_SHRED  ( 7UL)
#define FD_TOPO_TILE_KIND_STORE  ( 8UL)
#define FD_TOPO_TILE_KIND_MAX    ( FD_TOPO_TILE_KIND_STORE+1 ) /* Keep updated with maximum tile IDX */

/* A workspace is a Firedance specific memory management structure that
   sits on top of 1 or more memory mapped gigantic or huge pages mounted
   to the hugetlbfs. */
typedef struct {
  ulong id;   /* The ID of this workspace.  Indexed from [0, wksp_cnt).  When placed in a topology, the ID must be the index of the workspace in the workspaces list. */
  ulong kind; /* The kind of this workspace, one of FD_TOPO_WKSP_KIND_*.  There can be at most one of each workspace kind in a topology. */

  /* Computed fields.  These are not supplied as configuration but calculated as needed. */
  struct {
    ulong page_sz;  /* The size of the pages that this workspace is backed by.  One of FD_PAGE_SIZE_*. */
    ulong page_cnt; /* The number of pages that must be mapped to this workspace to store all the data needed by consumers. */

    fd_wksp_t * wksp;      /* The workspace memory in the local process. */
    ulong       footprint; /* Total size in bytes of all data in Firedancer that will be stored in this workspace. */
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
  ulong id;      /* The ID of this link.  Indexed from [0, link_cnt).  When placed in a topology, the ID must be the index of the link in the links list. */
  ulong kind;    /* The kind of this link.  One of FD_TOPO_LINK_KIND_*.  There can be multiple of each link kind in a topology. */
  ulong kind_id; /* The ID of this link within its kind.  If there are N links of a particular kind, they have IDs [0, N).  The pair (kind, kind_id) uniquely identifies a link, as does "id" on its own. */
  ulong wksp_id; /* The workspace that this link belongs to.  Each link belongs to exactly one workspace. */

  ulong depth;   /* The depth of the mcache representing the link. */
  ulong mtu;     /* The MTU of data fragments in the mcache.  A value of 0 means there is no dache. */
  ulong burst;   /* The max amount of MTU sized data fragments that might be bursted to the dcache. */

  /* Computed fields.  These are not supplied as configuration but calculated as needed. */
  struct {
   fd_frag_meta_t * mcache; /* The mcache of this link. */
   void *           dcache; /* The dcache of this link, if it has one. */
  };
} fd_topo_link_t;

/* A tile is a unique process that is spawned by Firedancer to represent
   one thread of execution.  Firedancer sandboxes all tiles to their own
   process for security reasons.

   A tile belongs to exactly one workspace.  A tile is a consumer of 0
   or more links, it's inputs.  A tile is a producer of 0 or more output
   links.  Either zero or one of the output links is considered the
   primary output, which will be managed automatically by the tile
   infrastructure.

   All input links will be automatically polled by the tile
   infrastructure, but only the primary output will be written to. */
typedef struct {
  ulong id;                     /* The ID of this tile.  Indexed from [0, tile_cnt).  When placed in a topology, the ID must be the index of the tile in the tiles list. */
  ulong kind;                   /* The kind of this tile.  One of FD_TOPO_TILE_KIND_*.  There can be multiple of each tile kind in a topology. */
  ulong kind_id;                /* The ID of this tile within its kind.  If there are n tile of a particular kind, they have IDs [0, N).  The pair (kind, kind_id) uniquely identifies a tile, as does "id" on its own. */
  ulong wksp_id;                /* The workspace that this tile belongs to.  Each tile belongs to exactly one workspace. */

  ulong burst;                  /* The maximum number of fragments this tile can produce on its primary output link in response
                                   to a fragment being received from an input link.  This is used to do flow control, as we do
                                   not let the tile receive fragments (propagate the backpressure) while it could not potentially
                                   burst this amount to downstream consumers. */

  ulong in_cnt;                 /* The number of links that this tile reads from. */
  ulong in_link_id[ 16 ];       /* The link_id of each link that this tile reads from, indexed in [0, in_cnt). */
  int   in_link_reliable[ 16 ]; /* If each link that this tile reads from is a reliable or unreliable consumer, indeexed in [0, in_cnt). */

  ulong out_link_id_primary;    /* The link_id of the primary link that this tile writes to.  A value of ULONG_MAX means there is no primary output link. */

  ulong out_cnt;                /* The number of non-primary links that this tile writes to. */
  ulong out_link_id[ 16 ];      /* The link_id of each non-primary link that this tile writes to, indexed in [0, link_cnt). */

  /* Computed fields.  These are not supplied as configuration but calculated as needed. */
  struct {
    fd_cnc_t * cnc;
    ulong *    in_link_fseq[ 16 ]; /* The fseq of each link that this tile reads from.  Multiple fseqs may point to the link, if there are multiple consumers.
                                      An fseq can be uniquely identified via (link_id, tile_id), or (link_kind, link_kind_id, tile_kind, tile_kind_id) */

    ulong      user_mem_offset;    /* Offset in bytes from the workspace base for memory region that has been
                                      reserved for this tile. The footprint and alignment will match those
                                      provided by the workspace_footprint and workspace_align functions in the
                                      corresponding fd_tile_config_t */

    void *     extra[ 32 ];         /* Hack for stashing extra shared tango objects. */
  };

  /* Configuration fields.  These are required to be known by the topology so it can determine the
     total size of Firedancer in memory. */
  struct {
    char   app_name[ 256 ];
    char   interface[ 16 ];
    ulong  xdp_rx_queue_size;
    ulong  xdp_tx_queue_size;
    ulong  xdp_aio_depth;
    ushort allow_ports[ 3 ];
  } net;

  struct {
    ulong  depth;
    ulong  max_concurrent_connections;
    ulong  max_concurrent_handshakes;
    ulong  max_inflight_quic_packets;
    ulong  tx_buf_size;
    ulong  max_concurrent_streams_per_connection;
    uint   ip_addr;
    uchar  src_mac_addr[ 6 ];
    ushort quic_transaction_listen_port;
    ushort legacy_transaction_listen_port;
    ulong  idle_timeout_millis;
  } quic;

  struct {
    ulong tcache_depth;
  } dedup;

  struct {
    ulong max_pending_transactions;
    ulong bank_tile_count;
  } pack;

  struct {
    ulong  depth;
    uint   ip_addr;
    uchar  src_mac_addr[ 6 ];
    ulong  fec_resolver_depth;
    char   identity_key_path[ PATH_MAX ];
    ushort shred_listen_port;
    ulong  expected_shred_version;
  } shred;
} fd_topo_tile_t;

/* An fd_topo_t represents the overall structure of a Firedancer
   configuration, describing all the workspaces, tiles, and links
   between them. */
typedef struct fd_topo_t {
  ulong          wksp_cnt;
  ulong          link_cnt;
  ulong          tile_cnt;

  fd_topo_wksp_t workspaces[ FD_TOPO_MAX_WKSPS ];
  fd_topo_link_t links[ FD_TOPO_MAX_LINKS ];
  fd_topo_tile_t tiles[ FD_TOPO_MAX_TILES ];
} fd_topo_t;

FD_PROTOTYPES_BEGIN

FD_FN_PURE static inline ulong
fd_topo_tile_kind_cnt( fd_topo_t * topo,
                       ulong       kind ) {
  ulong cnt = 0;
  for( ulong i=0; i<topo->tile_cnt; i++ ) {
    if( topo->tiles[ i ].kind == kind ) cnt++;
  }
  return cnt;
}

/* Finds the workspace of a given kind in the topology.  Returns
   ULONG_MAX if there is no such workspace.  There can be at most one
   workspace of a given kind.  kind should be one of FD_TOPO_WKSP_KIND_* */
FD_FN_PURE static inline ulong
fd_topo_find_wksp( fd_topo_t * topo,
                   ulong       kind ) {
  for( ulong i=0; i<topo->wksp_cnt; i++ ) {
    if( topo->workspaces[i].kind == kind ) {
      return i;
    }
  }
  return ULONG_MAX;
}

/* Find the tile of a given kind and kind_id in the topology, there will
   be at most one such tile, since kind_id is unique among the kind.
   kind should be one of FD_TOPO_TILE_KIND_*.  Returns ULONG_MAX if
   there is no such tile. */
FD_FN_PURE static inline ulong
fd_topo_find_tile( fd_topo_t * topo,
                   ulong       kind,
                   ulong       kind_id ) {
  for( ulong i=0; i<topo->tile_cnt; i++ ) {
    if( topo->tiles[i].kind == kind && topo->tiles[i].kind_id == kind_id ) {
      return i;
    }
  }
  return ULONG_MAX;
}

/* Find the link of a given kind and kind_id in the topology, there will
   be at most one such link, since kind_id is unique among the kind.
   kind should be one of FD_TOPO_LINK_KIND_*.  Returns ULONG_MAX if
   there is no such link. */
FD_FN_PURE static inline ulong
fd_topo_find_link( fd_topo_t * topo,
                   ulong       kind,
                   ulong       kind_id ) {
  for( ulong i=0; i<topo->link_cnt; i++ ) {
    if( topo->links[i].kind == kind && topo->links[i].kind_id == kind_id ) {
      return i;
    }
  }
  return ULONG_MAX;
}

/* Find the id of the tile which is a producer for the given link.  If
   no tile is a producer for the link, returns ULONG_MAX.  This should
   not be possible for a well formed and validated topology.  */
FD_FN_PURE static inline ulong
fd_topo_find_link_producer( fd_topo_t *      topo,
                            fd_topo_link_t * link ) {
  for( ulong i=0; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];

    if( FD_UNLIKELY( tile->out_link_id_primary == link->id ) ) return i;
    for( ulong j=0; j<tile->out_cnt; j++ ) {
      if( FD_UNLIKELY( tile->out_link_id[ j ] == link->id ) ) return i;
    }
  }
  return ULONG_MAX;
}

/* Given a workspace kind, one of FD_TOPO_WKSP_KIND_*, produce a human
   readable string for what to name that workspace.  This string
   uniquely identifies the workspace, since a toplogy may only have one
   of each kind of workspace. */
FD_FN_CONST static inline char *
fd_topo_wksp_kind_str( ulong kind ) {
  switch( kind ) {
    case FD_TOPO_WKSP_KIND_NETMUX_INOUT: return "netmux_inout";
    case FD_TOPO_WKSP_KIND_QUIC_VERIFY:  return "quic_verify";
    case FD_TOPO_WKSP_KIND_VERIFY_DEDUP: return "verify_dedup";
    case FD_TOPO_WKSP_KIND_DEDUP_PACK:   return "dedup_pack";
    case FD_TOPO_WKSP_KIND_PACK_BANK:    return "pack_bank";
    case FD_TOPO_WKSP_KIND_BANK_SHRED:   return "bank_shred";
    case FD_TOPO_WKSP_KIND_SHRED_STORE:  return "shred_store";
    case FD_TOPO_WKSP_KIND_NET:          return "net";
    case FD_TOPO_WKSP_KIND_NETMUX:       return "netmux";
    case FD_TOPO_WKSP_KIND_QUIC:         return "quic";
    case FD_TOPO_WKSP_KIND_VERIFY:       return "verify";
    case FD_TOPO_WKSP_KIND_DEDUP:        return "dedup";
    case FD_TOPO_WKSP_KIND_PACK:         return "pack";
    case FD_TOPO_WKSP_KIND_BANK:         return "bank";
    case FD_TOPO_WKSP_KIND_SHRED:        return "shred";
    case FD_TOPO_WKSP_KIND_STORE:        return "store";
    default: FD_LOG_ERR(( "unknown workspace kind %lu", kind )); return NULL;
  }
}

/* Given a link kind, one of FD_TOPO_LINK_KIND_*, produce a human
   readable string describing it. This string does not uniquely
   identify a link, since there can be multiple of each link kind
   in the topology. */
FD_FN_CONST static inline char *
fd_topo_link_kind_str( ulong kind ) {
  switch( kind ) {
    case FD_TOPO_LINK_KIND_NET_TO_NETMUX:   return "net_netmux";
    case FD_TOPO_LINK_KIND_NETMUX_TO_OUT:   return "netmux_out";
    case FD_TOPO_LINK_KIND_QUIC_TO_NETMUX:  return "quic_netmux";
    case FD_TOPO_LINK_KIND_QUIC_TO_VERIFY:  return "quic_verify";
    case FD_TOPO_LINK_KIND_VERIFY_TO_DEDUP: return "verify_dedup";
    case FD_TOPO_LINK_KIND_DEDUP_TO_PACK:   return "dedup_pack";
    case FD_TOPO_LINK_KIND_GOSSIP_TO_PACK:  return "gossip_pack";
    case FD_TOPO_LINK_KIND_LSCHED_TO_PACK:  return "lsched_pack";
    case FD_TOPO_LINK_KIND_PACK_TO_BANK:    return "pack_bank";
    case FD_TOPO_LINK_KIND_POH_TO_SHRED:    return "poh_shred";
    case FD_TOPO_LINK_KIND_SHRED_TO_NETMUX: return "shred_netmux";
    case FD_TOPO_LINK_KIND_SHRED_TO_STORE:  return "shred_store";
    default: FD_LOG_ERR(( "unknown workspace kind %lu", kind )); return NULL;
  }
}

/* Given a tile kind, one of FD_TOPO_TILE_KIND_*, produce a human
   readable string describing it.  This string does not uniquely
   identify a tile, since there can be multiple of each tile kind
   in the topology.
   
   Tile names must be <= 7 chars, so that we can print them easily in
   diagnostic output and monitoring tools. */
FD_FN_CONST static inline char *
fd_topo_tile_kind_str( ulong kind ) {
  switch ( kind ) {
     case FD_TOPO_TILE_KIND_NET:    return "net";
     case FD_TOPO_TILE_KIND_NETMUX: return "netmux";
     case FD_TOPO_TILE_KIND_QUIC:   return "quic";
     case FD_TOPO_TILE_KIND_VERIFY: return "verify";
     case FD_TOPO_TILE_KIND_DEDUP:  return "dedup";
     case FD_TOPO_TILE_KIND_PACK:   return "pack";
     case FD_TOPO_TILE_KIND_BANK:   return "bank";
     case FD_TOPO_TILE_KIND_SHRED:  return "shred";
     case FD_TOPO_TILE_KIND_STORE:  return "store";
     default: FD_LOG_ERR(( "unknown tile kind %lu", kind )); return NULL;
  }
}

/* Given a link, count the number of consumers of that link among all
   the tiles in the topology. */
FD_FN_PURE static inline ulong
fd_topo_link_consumer_cnt( fd_topo_t *      topo,
                           fd_topo_link_t * link ) {
  ulong cnt = 0;
  for( ulong i=0; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    for( ulong j=0; j<tile->in_cnt; j++ ) {
      if( FD_UNLIKELY( tile->in_link_id[ j ] == link->id ) ) cnt++;
    }
  }

  return cnt;
}

/* Join (map into the process) all shared memory (huge/gigantic pages)
   needed by the tile, in the given topology.  All memory associated
   with the tile (aka. used by links that the tile either produces to or
   consumes from, or used by the tile itself for its cnc) will be
   attached (mapped into the process).

   This is needed to play nicely with the sandbox.  Once a process is
   sandboxed we can no longer map any memory. */
void
fd_topo_join_tile_workspaces( char * const     app_name,
                              fd_topo_t *      topo,
                              fd_topo_tile_t * tile );

/* Join (map into the process) all shared memory (huge/gigantic pages)
   needed by all tiles in the topology. */
void
fd_topo_join_workspaces( char * const app_name,
                         fd_topo_t *  topo );

/* Leave (unmap from the process) all shared memory needed by all
   tiles in the toplogy, if each of them was mapped. */
void
fd_topo_leave_workspaces( fd_topo_t *  topo );

/* Create all the workspaces needed by the topology on the system. This
   does not "join" the workspaces (map their memory into the process),
   but only creates the .wksp files and formats them correctly as
   workspaces. */
void
fd_topo_create_workspaces( char *      app_name,
                           fd_topo_t * topo );

/* Populate all IPC objects needed by the topology of this particular
   tile, or just calculate the footprint needed to store them depending
   on the argument.  This will populate all mcaches, dcaches, and fseqs
   into the topo object. This must be called after all of the tile
   workspaces have been joined, either by calling
   fd_topo_join_workspaces, or fd_topo_join_tile_workspaces.
   
   The mode should be one of FD_TOPO_FILL_MODE_* and determines
   what the function actually does. 

     FD_TOPO_FILL_MODE_FOOTPRINT
        The footprint of every workspace in the topology is calculated
        and stored in the toplogy, under wksp->footprint, along with
        other size and offset related fields.  No objects are actually
        created or joined.

     FD_TOPO_FILL_MODE_NEW
        This actually creates (calls new) on all of the objects
        (mcaches, dcaches, etc) in the toplogy.  It does not join them,
        and it is assumed to be running during some static
        initialization or configuration step.

     FD_TOPO_FILL_MODE_JOIN
        This joins the objects in the toplogy, assuming that they
        already exist (aka someone else has already called
        FD_TOPO_FILL_MODE_NEW during an initialization step.) */
void
fd_topo_fill_tile( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   ulong            mode );

/* Same as fd_topo_fill_tile but fills in all tiles in the topology with
   the given mode. */
void
fd_topo_fill( fd_topo_t * topo,
              ulong       mode );

/* This is for determining the value of RLIMIT_MLOCK that we need to
   sucessfully run all tiles in separate processes.  The value returned
   is the maximum amount of memory that will be locked with mlock() by
   any individual process in the tree.  Specifically, if we have three
   tile processes, and they each need to lock 5, 9, and 2 MiB of memory
   respectively, RLIMIT_MLOCK needs to be 9 MiB to allow all three
   process mlock() calls to succed.

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
ulong
fd_topo_mlock_max_tile( fd_topo_t * topo );

/* Same as fd_topo_mlock_max_tile, but for loading the entire topology
   topology into one process, rather than a separate process per tile.
   This is used, for example, by the configuration code when it creates
   all the workspaces, or the monitor that maps the entire system into
   one address space. */
ulong
fd_topo_mlock( fd_topo_t * topo );

/* Check all invariants of the given topology to make sure it is valid.
   An invalid topology will cause the program to abort with an error
   message. */
void
fd_topo_validate( fd_topo_t * topo );

/* Prints a NOTICE log message describing the topology to the log. */
void
fd_topo_print_log( fd_topo_t * topo );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_fdctl_topology_h */
