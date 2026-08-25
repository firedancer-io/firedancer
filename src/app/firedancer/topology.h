#ifndef HEADER_fd_src_app_firedancer_topology_h
#define HEADER_fd_src_app_firedancer_topology_h

/* topology.h contains APIs for constructing a Firedancer topology. */

#include "../shared/fd_config.h"

FD_PROTOTYPES_BEGIN

/* Accdb records runtime-generated account stores in addition to
   transaction writable accounts.  Keep the existing production
   capacity until those stores have an independently proven bound. */
#define FD_TOPO_ACCDB_MAX_ACCOUNT_WRITES_PER_SLOT (367535UL)

/* fd_topo_initialize constructs a full validator config according to
   the given topology.  Populates config->topo. */

void
fd_topo_initialize( fd_config_t * config );

fd_topo_obj_t *
setup_topo_banks( fd_topo_t *  topo,
                  char const * wksp_name,
                  ulong        max_live_slots,
                  ulong        max_fork_width,
                  int          larger_max_cost_per_block );

void
setup_topo_progcache( fd_topo_t *  topo,
                      char const * wksp_name,
                      ulong        max_cache_entries,
                      ulong        max_database_transactions,
                      ulong        heap_size_gib );

fd_topo_obj_t *
setup_topo_store( fd_topo_t *  topo,
                  char const * wksp_name,
                  ulong        fec_max,
                  uint         part_cnt,
                  ulong        fec_data_max );

fd_topo_obj_t *
setup_topo_fec_sets( fd_topo_t *  topo,
                     char const * wksp_name,
                     ulong        sz );

fd_topo_obj_t *
setup_topo_accdb( fd_topo_t *  topo,
                  char const * wksp_name,
                  ulong        max_accounts,
                  ulong        max_live_slots,
                  ulong        max_account_writes_per_slot,
                  ulong        partition_cnt,
                  ulong        partition_sz,
                  ulong        cache_footprint,
                  int          bundle_enabled,
                  ulong        joiner_cnt,
                  ulong        max_incremental_accounts );

fd_topo_obj_t *
setup_topo_txncache( fd_topo_t *  topo,
                     char const * wksp_name,
                     ulong        max_live_slots,
                     ulong        max_txn_per_slot,
                     int          larger_max_cost_per_block );

void
fd_topo_configure_tile( fd_topo_tile_t * tile,
                        fd_config_t *    config );

void
wire_event_links( fd_topo_t * topo );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_firedancer_topology_h */
