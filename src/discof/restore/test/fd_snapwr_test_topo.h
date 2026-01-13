#ifndef HEADER_fd_src_discof_restore_utils_fd_snapwr_test_topo
#define HEADER_fd_src_discof_restore_utils_fd_snapwr_test_topo

#include "../../../util/fd_util_base.h"
#include "../../../disco/topo/fd_topo.h"
#include "fd_restore_test_base.h"

struct fd_snapwr_test_topo {
  /* tile context */
  void * ctx;
  /* input links */
  fd_restore_link_in_t in_wh; /* snapin_wr from snapwh */
  /* output links (none - writes to disk) */

  fd_restore_stem_mock_t mock_stem;

  ulong magic;
};

typedef struct fd_snapwr_test_topo fd_snapwr_test_topo_t;

#define FD_SNAPWR_TEST_TOPO_MAGIC (0xFD53A1E213510) /* FD SNAPWR TEST TOPO V0 */

FD_FN_CONST ulong
fd_snapwr_test_topo_align( void );

FD_FN_CONST ulong
fd_snapwr_test_topo_footprint( void );

void *
fd_snapwr_test_topo_new( void * shmem );

fd_snapwr_test_topo_t *
fd_snapwr_test_topo_join( void * shmem );

void
fd_snapwr_test_topo_init( fd_snapwr_test_topo_t * snapwr_topo,
                          fd_topo_t *             topo,
                          fd_wksp_t *             wksp );

void
fd_snapwr_test_topo_during_frag( fd_snapwr_test_topo_t * snapwr,
                                 ulong                   in_idx,
                                 ulong                   seq,
                                 ulong                   sig,
                                 ulong                   chunk,
                                 ulong                   sz,
                                 ulong                   ctl );

void
fd_snapwr_test_topo_fini( fd_snapwr_test_topo_t * snapwr );

#endif /* HEADER_fd_src_discof_restore_fd_snapwr_test_topo */
