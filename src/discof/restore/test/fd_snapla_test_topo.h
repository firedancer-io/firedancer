#ifndef HEADER_fd_src_discof_restore_utils_fd_snapla_test_topo
#define HEADER_fd_src_discof_restore_utils_fd_snapla_test_topo

#include "../../../util/fd_util_base.h"
#include "../../../disco/topo/fd_topo.h"
#include "fd_restore_test_base.h"

struct fd_snapla_test_topo {
  /* tile context */
  void * ctx;
  ulong num_snapla;             /* number of snapla tiles */
  /* input links */
  fd_restore_link_in_t in_dc;   /* snapdc_in from snapdc */
  /* output links */
  fd_restore_link_out_t out_ls; /* snapla_ls to snapls */

  fd_restore_stem_mock_t mock_stem;

  ulong magic;
};

typedef struct fd_snapla_test_topo fd_snapla_test_topo_t;

#define FD_SNAPLA_TEST_TOPO_MAGIC (0xFD53A11A13510) /* FD SNAPLA TEST TOPO V0 */

FD_FN_CONST ulong
fd_snapla_test_topo_align( void );

FD_FN_CONST ulong
fd_snapla_test_topo_footprint( void );

void *
fd_snapla_test_topo_new( void * shmem );

fd_snapla_test_topo_t *
fd_snapla_test_topo_join( void * shmem );

void
fd_snapla_test_topo_init( fd_snapla_test_topo_t * snapla_topo,
                          fd_topo_t *             topo,
                          fd_wksp_t *             wksp );

void
fd_snapla_test_topo_returnable_frag( fd_snapla_test_topo_t * snapla,
                                     ulong                   in_idx,
                                     ulong                   seq,
                                     ulong                   sig,
                                     ulong                   chunk,
                                     ulong                   sz,
                                     ulong                   ctl,
                                     ulong                   tsorig,
                                     ulong                   tspub );

void
fd_snapla_test_topo_fini( fd_snapla_test_topo_t * snapla );

#endif /* HEADER_fd_src_discof_restore_fd_snapla_test_topo */
