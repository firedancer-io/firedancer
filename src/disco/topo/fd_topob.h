#ifndef HEADER_fd_src_disco_topo_fd_topob_h
#define HEADER_fd_src_disco_topo_fd_topob_h

/* fd_topob is a builder for fd_topo, providing many convenience
   functions for creating a useful topology. */

#include "../../disco/topo/fd_topo.h"

/* A link in the topology is either unpolled or polled.  Almost all
   links are polled, which means a tile which has this link as an in
   will read fragments from it and pass them to the tile handling
   code.  An unpolled link will not read off the link by default and
   the user code will need to specifically read it as needed. */

#define FD_TOPOB_UNPOLLED 0
#define FD_TOPOB_POLLED 1

/* A reliable link is a flow controlled one, where the producer will
   not send fragments if any downstream consumer does not have enough
   capacity (credits) to handle it. */

#define FD_TOPOB_UNRELIABLE 0
#define FD_TOPOB_RELIABLE 1

FD_PROTOTYPES_BEGIN

/* Initialize a new fd_topo_t with the given app name, the topology will
   be empty with no tiles, objects, links. */

fd_topo_t
fd_topob_new( char const * app_name );

/* Add a workspace with the given name to the topology.  Workspace names
   must be unique and adding the same workspace twice will produce an
   error. */

void
fd_topob_wksp( fd_topo_t *  topo,
               char const * name );

/* Add an object with the given name to the toplogy.  An object is
   something that takes up space in memory, in a workspace.
   
   The workspace must exist and have been added to the topology.
   Adding an object will cause it to occupt space in memory, but not
   be mapped into any tiles.  If you wish the object to be readable or
   writable by a tile, you need to add a fd_topob_tile_uses relationship. */

fd_topo_obj_t *
fd_topob_obj( fd_topo_t *  topo,
              char const * obj_name,
              char const * wksp_name );

/* Add a relationship saying that a certain tile uses a given object.
   This has the effect that when memory mapping required workspaces
   for a tile, it will map the workspace required for this object in
   the appropriate mode.

   mode should be one of FD_SHMEM_MAP_MODE_READ_ONLY or
   FD_SHMEM_MAP_MODE_READ_WRITE. */

void
fd_topob_tile_uses( fd_topo_t *      topo,
                    fd_topo_tile_t * tile,
                    fd_topo_obj_t *  obj,
                    int              mode );

/* Add a link to the toplogy.  The link will not have any producer or
   consumer(s) by default, and those need to be added after.  The link
   can have no backing data buffer, a dcache, or a reassembly buffer
   behind it. */

void
fd_topob_link( fd_topo_t *  topo,
               char const * link_name,
               char const * wksp_name,
               int          is_reasm,
               ulong        depth,
               ulong        mtu,
               ulong        burst );

/* Add a tile to the topology.  This creates various objects needed for
   a standard tile, including a cnc object, tile scratch memory, metrics
   memory and so on.  These objects will be created and linked to the
   respective workspaces provided, and the tile will be specified to map
   those workspaces when it is attached.
   
   The out_link is optional, but if provided is the primary output link
   of the tile.  If the tile is created with the standard mux runner, it
   will automatically send frags and flow control the primary output
   link. */

void
fd_topob_tile( fd_topo_t *    topo,
               char const *   tile_name,
               char const *   tile_wksp,
               char const *   cnc_wksp,
               char const *   metrics_wksp,
               ushort         cpu_idx,
               int            is_solana_labs,
               char const *   out_link,
               ulong          out_link_kind_id );

/* Add an input link to the tile.  If the tile is created with the
   standard mux runner, it will automatically poll the in link and
   forward fragments to the user code (unless the link is specified
   as unpolled).

   An input link has an fseq which is a ulong used for returning the
   current reader position in sequence space, used for wiring flow
   control to the producer.  The producer will not produce fragments
   while any downstream consumer link is not ready to receive them,
   unless the link is marked as unreliable. */

void
fd_topob_tile_in( fd_topo_t *  topo,
                  char const * tile_name,
                  ulong        tile_kind_id,
                  char const * fseq_wksp,
                  char const * link_name,
                  ulong        link_kind_id,
                  int          reliable,
                  int          polled );

/* Add an output link to the tile.  This doesn't do much by itself,
   but will cause the link to get mapped in as writable for the tile,
   and the tile can later look up the link by name and write to it
   as it wants. */

void
fd_topob_tile_out( fd_topo_t *  topo,
                   char const * tile_name,
                   ulong        tile_kind_id,
                   char const * link_name,
                   ulong        link_kind_id );

/* Finish creating the topology.  Lays out all the objects in the
   given workspaces, and sizes everything correctly.  Also validates
   the topology before returning.
   
   This must be called to finish creating the topology. */

void
fd_topob_finish( fd_topo_t * topo,
                 ulong (* align    )( fd_topo_t const * topo, fd_topo_obj_t const * obj ),
                 ulong (* footprint)( fd_topo_t const * topo, fd_topo_obj_t const * obj ),
                 ulong (* loose    )( fd_topo_t const * topo, fd_topo_obj_t const * obj) );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_topo_fd_topob_h */
