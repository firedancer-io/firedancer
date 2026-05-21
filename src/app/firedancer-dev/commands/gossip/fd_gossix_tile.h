#ifndef HEADER_fd_src_app_firedancer_dev_commands_gossip_fd_gossix_tile_h
#define HEADER_fd_src_app_firedancer_dev_commands_gossip_fd_gossix_tile_h

#include "../../../../disco/topo/fd_topo.h"
#include "../../../../flamenco/gossip/fd_gossip_message.h"

/* fd_gossix_tile (gossip index tile) is a lightweight tile that
   reliably consumes the gossip_out link and accumulates contact info
   entries.  It monitors CRDS metrics from the gossip tile for threshold
   and timeout conditions.  When triggered, it writes the accumulated
   entries to a JSON file and signals completion by updating an
   fseq.

   Configuration is plumbed through config->props:
     gossix.out_path       — output file path (cstr)
     gossix.max_entries    — CRDS entry threshold (ulong)
     gossix.max_contact    — contact info threshold (ulong)
     gossix.timeout_nanos  — timeout in nanoseconds (long)
     gossix.exit_after_steady — enable steady-state exit (int)

   The tile's scratch memory is a single fd_gossix_tile_ctx_t. */

/* Sentinel value written to the done fseq on completion. */
#define FD_GOSSIX_FSEQ_DONE (1UL)

typedef struct {
  int                      valid;
  uchar                    pubkey[ 32UL ];
  fd_gossip_contact_info_t ci[ 1UL ];
  ulong                    wallclock;
} fd_gossix_ci_entry_t;

typedef struct {
  /* In-link state */
  fd_wksp_t * gossip_out_wksp;

  /* Gossip tile metrics (read-only) for CRDS counts */
  volatile ulong const * gossip_metrics;

  /* Thresholds / config */
  char  out_path[ PATH_MAX ];
  ulong max_entries;
  ulong max_contact;
  long  timeout_nanos;
  long  start_nanos;

  int   exit_after_steady;
  ulong steady_last_ci_cnt;
  long  steady_last_change_nanos;

  /* Shared fseq for signalling completion to the main thread */
  ulong * done_fseq;
  int     done;

  fd_gossix_ci_entry_t ci_table[ FD_CONTACT_INFO_TABLE_SIZE ];
} fd_gossix_tile_ctx_t;

extern fd_topo_run_tile_t fd_tile_gossix;

#endif /* HEADER_fd_src_app_firedancer_dev_commands_gossip_fd_gossix_tile_h */
