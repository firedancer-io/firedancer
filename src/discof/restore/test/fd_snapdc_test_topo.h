#ifndef HEADER_fd_src_discof_restore_utils_fd_snapdc_test_topo
#define HEADER_fd_src_discof_restore_utils_fd_snapdc_test_topo

#include "../../../util/fd_util_base.h"
#include "../../../disco/topo/fd_topo.h"
#include "fd_restore_test_base.h"

struct fd_snapdc_test_topo {
  /* tile context */
  void * ctx;
  /* input links */
  fd_restore_link_in_t in_ld;   /* snapld_dc from snapld */
  /* output links */
  fd_restore_link_out_t out_in; /* snapdc_in to snapin */

  fd_restore_stem_mock_t mock_stem;

  ulong magic;
};

typedef struct fd_snapdc_test_topo fd_snapdc_test_topo_t;

#define FD_SNAPDC_TEST_TOPO_MAGIC (0xFD53A1DC13510) /* FD SNAPDC TEST TOPO V0 */

FD_FN_CONST ulong
fd_snapdc_test_topo_align( void );

FD_FN_CONST ulong
fd_snapdc_test_topo_footprint( void );

void *
fd_snapdc_test_topo_new( void * shmem );

fd_snapdc_test_topo_t *
fd_snapdc_test_topo_join( void * shmem );

void
fd_snapdc_test_topo_init( fd_snapdc_test_topo_t * snapdc_topo,
                          fd_topo_t *             topo,
                          fd_wksp_t *             wksp );

void
fd_snapdc_test_topo_returnable_frag( fd_snapdc_test_topo_t * snapdc,
                                     ulong                   in_idx,
                                     ulong                   seq,
                                     ulong                   sig,
                                     ulong                   chunk,
                                     ulong                   sz,
                                     ulong                   ctl,
                                     ulong                   tsorig,
                                     ulong                   tspub );

void
fd_snapdc_test_topo_fini( fd_snapdc_test_topo_t * snapdc );

#endif /* HEADER_fd_src_discof_restore_fd_snapdc_test_topo */
