#ifndef HEADER_fd_src_discof_restore_utils_fd_snapls_test_topo
#define HEADER_fd_src_discof_restore_utils_fd_snapls_test_topo

#include "../../../util/fd_util_base.h"
#include "../../../disco/topo/fd_topo.h"
#include "fd_restore_test_base.h"

struct fd_snapls_test_topo {
  /* tile context */
  void * ctx;
  /* input links */
  fd_restore_link_in_t in_snapin; /* snapin_ls from snapin */
  fd_restore_link_in_t in_snapla; /* snapla_ls from snapla tiles */
  ulong num_snapla_in;            /* number of snapla input links */
  /* output links */
  fd_restore_link_out_t out_ct;   /* snapls_ct control back to snapct */

  fd_restore_stem_mock_t mock_stem;

  ulong magic;
};

typedef struct fd_snapls_test_topo fd_snapls_test_topo_t;

#define FD_SNAPLS_TEST_TOPO_MAGIC (0xFD53A11513510) /* FD SNAPLS TEST TOPO V0 */

FD_FN_CONST ulong
fd_snapls_test_topo_align( void );

FD_FN_CONST ulong
fd_snapls_test_topo_footprint( void );

void *
fd_snapls_test_topo_new( void * shmem );

fd_snapls_test_topo_t *
fd_snapls_test_topo_join( void * shmem );

void
fd_snapls_test_topo_init( fd_snapls_test_topo_t * snapls_topo,
                          fd_topo_t *             topo,
                          fd_wksp_t *             wksp );

void
fd_snapls_test_topo_returnable_frag( fd_snapls_test_topo_t * snapls,
                                     ulong                   in_idx,
                                     ulong                   seq,
                                     ulong                   sig,
                                     ulong                   chunk,
                                     ulong                   sz,
                                     ulong                   ctl,
                                     ulong                   tsorig,
                                     ulong                   tspub );

void
fd_snapls_test_topo_fini( fd_snapls_test_topo_t * snapls );

#endif /* HEADER_fd_src_discof_restore_fd_snapls_test_topo */
