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
setup_topo_banks( fd_topo_t *  topo,
                  char const * wksp_name,
                  ulong        max_live_slots,
                  ulong        cache_cnt,
                  ulong        stake_delegation_cache_cnt,
                  ulong        bench_max_cost_per_block );

fd_topo_obj_t *
setup_topo_footer_cache( fd_topo_t *  topo,
                         char const * wksp_name );

fd_topo_obj_t *
setup_topo_execrp_result( fd_topo_t *  topo,
                          char const * wksp_name,
                          ulong        execrp_tile_cnt );

/* Smallest program_cache_size that setup_topo_progcache accepts: a huge-page
   multiple that is locked exactly.  0 if txn_max is invalid. */
ulong
setup_topo_progcache_min_sz( ulong txn_max );

void
setup_topo_progcache( fd_topo_t *  topo,
                      char const * wksp_name,
                      ulong        txn_max,
                      ulong        wksp_size );

/* setup_topo_jit adds the jit and jitmap tiles, the JIT code arena and
   the links between them and the exec tiles named by exec_name
   (exec_cnt instances, each already in the topology).  No-op unless
   [development.jit] is enabled. */

void
setup_topo_jit( fd_topo_t *    topo,
                fd_config_t *  config,
                char const *   exec_name,
                ulong          exec_cnt,
                char const *   exec_name2,
                ulong          exec_cnt2,
                ulong          cpu_idx_jit,
                ulong          cpu_idx_jitmap );

fd_topo_obj_t *
setup_topo_bpf_frames( fd_topo_t *  topo,
                       char const * wksp_name,
                       ulong        frame_cnt,
                       ulong        local_cnt,
                       ulong        join_cnt );

fd_topo_obj_t *
setup_topo_store( fd_topo_t *  topo,
                  char const * wksp_name,
                  ulong        fec_max,
                  ulong        fec_data_max,
                  ulong        shred_storage_gib,
                  ulong        shred_cache_mib,
                  ulong        fec_set_cnt,
                  ulong        max_shreds_per_block,
                  char const * db_path,
                  ulong        shred_tile_cnt );

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
                     ulong        cache_footprint );

void
fd_topo_configure_tile( fd_topo_tile_t * tile,
                        fd_config_t *    config );

void
wire_event_links( fd_topo_t * topo );

void
wire_replay_diff_link( fd_topo_t * topo );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_firedancer_topology_h */
