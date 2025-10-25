#ifndef HEADER_fd_src_app_firedancer_topology_h
#define HEADER_fd_src_app_firedancer_topology_h

/* topology.h contains APIs for constructing a Firedancer topology. */

#include "../shared/fd_config.h"

FD_PROTOTYPES_BEGIN

/* fd_topo_initialize constructs a full validator config according to
   the given topology.  Populates config->topo. */

void
fd_topo_initialize( fd_config_t * config );

fd_topo_obj_t *
setup_topo_bank_hash_cmp( fd_topo_t * topo, char const * wksp_name );

fd_topo_obj_t *
setup_topo_banks( fd_topo_t *  topo,
                  char const * wksp_name,
                  ulong        max_live_slots,
                  ulong        max_fork_width );

fd_topo_obj_t *
setup_topo_funk( fd_topo_t *  topo,
                 char const * wksp_name,
                 ulong        max_account_records,
                 ulong        max_database_transactions,
                 ulong        heap_size_gib );

fd_topo_obj_t *
setup_topo_progcache( fd_topo_t *  topo,
                      char const * wksp_name,
                      ulong        max_cache_entries,
                      ulong        max_database_transactions,
                      ulong        heap_size_gib );

fd_topo_obj_t *
setup_topo_store( fd_topo_t *  topo,
                  char const * wksp_name,
                  ulong        fec_max,
                  uint         part_cnt );

fd_topo_obj_t *
setup_topo_txncache( fd_topo_t *  topo,
                     char const * wksp_name,
                     ulong        max_live_slots,
                     ulong        max_txn_per_slot );
void
setup_topo_vinyl( fd_topo_t *    topo,
                  fd_configf_t * config );

void
fd_topo_configure_tile( fd_topo_tile_t * tile,
                        fd_config_t *    config );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_firedancer_topology_h */
