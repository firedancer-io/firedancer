#ifndef HEADER_fd_src_app_firedancer_dev_commands_gossip_h
#define HEADER_fd_src_app_firedancer_dev_commands_gossip_h

#include "../../shared/fd_config.h"

/* Shared gossip topology setup functions */

/* Sets up the gossip subtopo. This includes gossip, gossvf, and ipecho.
   Assumes that net, metrics, and sign tiles have already been added to the
   topo.  Does not finalize any part of the topo, so calls to fd_gossip_subtopo
   must be eventually be followed by fd_topos_net_tile_finish and
   fd_topob_finish.  DOES NOT call fd_topo_tile_in("gossip", "sign_gossip" ),
   to avoid adding new in_links to gossip after the unpolled sign_gossip. */
void
fd_gossip_subtopo( config_t * config, ulong tile_to_cpu[ FD_TILE_MAX ] );

#endif /* HEADER_fd_src_app_firedancer_dev_commands_gossip_h */
