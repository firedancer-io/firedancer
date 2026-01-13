#ifndef HEADER_fd_src_discof_restore_utils_fd_snapwh_test_topo
#define HEADER_fd_src_discof_restore_utils_fd_snapwh_test_topo

#include "../../../util/fd_util_base.h"
#include "../../../disco/topo/fd_topo.h"
#include "fd_restore_test_base.h"

struct fd_snapwh_test_topo {
  /* tile context */
  void * ctx;
  /* input links */
  fd_restore_link_in_t in_snapin; /* snapin_wh from snapin */
  /* output links */
  fd_restore_link_out_t out_wr;   /* snapin_wr to snapwr */

  fd_restore_stem_mock_t mock_stem;

  ulong magic;
};

typedef struct fd_snapwh_test_topo fd_snapwh_test_topo_t;

#define FD_SNAPWH_TEST_TOPO_MAGIC (0xFD53A1E113510) /* FD SNAPWH TEST TOPO V0 */

FD_FN_CONST ulong
fd_snapwh_test_topo_align( void );

FD_FN_CONST ulong
fd_snapwh_test_topo_footprint( void );

void *
fd_snapwh_test_topo_new( void * shmem );

fd_snapwh_test_topo_t *
fd_snapwh_test_topo_join( void * shmem );

void
fd_snapwh_test_topo_init( fd_snapwh_test_topo_t * snapwh_topo,
                          fd_topo_t *             topo,
                          fd_wksp_t *             wksp );

void
fd_snapwh_test_topo_during_frag( fd_snapwh_test_topo_t * snapwh,
                                 ulong                   in_idx,
                                 ulong                   seq,
                                 ulong                   sig,
                                 ulong                   chunk,
                                 ulong                   sz,
                                 ulong                   ctl );

void
fd_snapwh_test_topo_fini( fd_snapwh_test_topo_t * snapwh );

#endif /* HEADER_fd_src_discof_restore_fd_snapwh_test_topo */
