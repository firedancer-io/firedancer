#ifndef HEADER_fd_src_app_fdctl_run_tiles_h
#define HEADER_fd_src_app_fdctl_run_tiles_h

#include "../../fdctl.h"

#include "../../../../disco/mux/fd_mux.h"

#include <linux/filter.h>

typedef struct {
  ulong                         mux_flags;
  ulong                         burst;
  void * (*mux_ctx           )( void * scratch );

  fd_mux_during_housekeeping_fn * mux_during_housekeeping;
  fd_mux_before_credit_fn       * mux_before_credit;
  fd_mux_after_credit_fn        * mux_after_credit;
  fd_mux_before_frag_fn         * mux_before_frag;
  fd_mux_during_frag_fn         * mux_during_frag;
  fd_mux_after_frag_fn          * mux_after_frag;
  fd_mux_metrics_write_fn       * mux_metrics_write;

  ulong (*populate_allowed_seccomp)( void * scratch, ulong out_cnt, struct sock_filter * out );
  ulong (*populate_allowed_fds    )( void * scratch, ulong out_fds_sz, int * out_fds );
  ulong (*loose_footprint         )( fd_topo_tile_t * tile );
  ulong (*scratch_align           )( void );
  ulong (*scratch_footprint       )( fd_topo_tile_t * tile );
  void  (*privileged_init         )( fd_topo_t * topo, fd_topo_tile_t * tile, void * scratch );
  void  (*unprivileged_init       )( fd_topo_t * topo, fd_topo_tile_t * tile, void * scratch );
} fd_tile_config_t;

FD_FN_CONST ulong
fd_quic_dcache_app_footprint( ulong depth );

FD_FN_CONST fd_tile_config_t *
fd_topo_tile_to_config( fd_topo_tile_t * tile );

extern fd_tile_config_t fd_tile_net;
extern fd_tile_config_t fd_tile_netmux;
extern fd_tile_config_t fd_tile_quic;
extern fd_tile_config_t fd_tile_verify;
extern fd_tile_config_t fd_tile_dedup;
extern fd_tile_config_t fd_tile_pack;
extern fd_tile_config_t fd_tile_bank;
extern fd_tile_config_t fd_tile_shred;
extern fd_tile_config_t fd_tile_store;

void *
fd_wksp_pod_map1( uchar const * pod,
                  char const *  format,
                  ... );

#endif /* HEADER_fd_src_app_fdctl_run_tiles_h */
