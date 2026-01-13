#ifndef HEADER_fd_src_discof_restore_utils_fd_snapct_test_topo
#define HEADER_fd_src_discof_restore_utils_fd_snapct_test_topo

#include "../../../util/fd_util_base.h"
#include "../../../disco/topo/fd_topo.h"
#include "fd_restore_test_base.h"

struct fd_snapct_test_topo {
  /* tile context */
  void * ctx;
  /* input links */
  fd_restore_link_in_t in_gossip; /* optional: gossip_out */
  fd_restore_link_in_t in_snapld; /* snapld_dc ack */
  fd_restore_link_in_t in_ack;    /* snapin_ct or snapls_ct control ack */
  /* output links */
  fd_restore_link_out_t out_ld;   /* snapct_ld to snapld */
  fd_restore_link_out_t out_gui;  /* snapct_gui for GUI updates */
  fd_restore_link_out_t out_repr; /* snapct_repr to replay */

  fd_restore_stem_mock_t mock_stem;

  ulong magic;
};

typedef struct fd_snapct_test_topo fd_snapct_test_topo_t;

#define FD_SNAPCT_TEST_TOPO_MAGIC (0xFD53A1C113510) /* FD SNAPCT TEST TOPO V0 */

FD_FN_CONST ulong
fd_snapct_test_topo_align( void );

FD_FN_CONST ulong
fd_snapct_test_topo_footprint( void );

void *
fd_snapct_test_topo_new( void * shmem );

fd_snapct_test_topo_t *
fd_snapct_test_topo_join( void * shmem );

void
fd_snapct_test_topo_init( fd_snapct_test_topo_t * snapct_topo,
                          fd_topo_t *             topo,
                          fd_wksp_t *             wksp );

void
fd_snapct_test_topo_returnable_frag( fd_snapct_test_topo_t * snapct,
                                     ulong                   in_idx,
                                     ulong                   seq,
                                     ulong                   sig,
                                     ulong                   chunk,
                                     ulong                   sz,
                                     ulong                   ctl,
                                     ulong                   tsorig,
                                     ulong                   tspub );

void
fd_snapct_test_topo_fini( fd_snapct_test_topo_t * snapct );

#endif /* HEADER_fd_src_discof_restore_fd_snapct_test_topo */