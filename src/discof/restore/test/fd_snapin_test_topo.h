#ifndef HEADER_fd_src_discof_restore_utils_fd_snapin_test_topo
#define HEADER_fd_src_discof_restore_utils_fd_snapin_test_topo

#include "../../../util/fd_util_base.h"
#include "../../../disco/topo/fd_topo.h"
#include "fd_restore_test_base.h"

struct fd_snapin_test_topo {
  /* tile context */
  void * ctx;
  /* input links */
  fd_restore_link_in_t in_dc;      /* snapdc_in from snapdc */
  /* output links */
  fd_restore_link_out_t out_manif; /* snapin_manif manifest data */
  fd_restore_link_out_t out_gui;   /* snapin_gui for GUI updates (optional) */
  fd_restore_link_out_t out_ct;    /* snapin_ct control back to snapct */
  fd_restore_link_out_t out_ls;    /* snapin_ls to snapls (optional, for lthash) */
  fd_restore_link_out_t out_wh;    /* snapin_wh to snapwh (optional, for vinyl) */

  /* Shared memory objects */
  void * accdb_funk;
  void * txncache;

  fd_restore_stem_mock_t mock_stem;

  ulong magic;
};

typedef struct fd_snapin_test_topo fd_snapin_test_topo_t;

#define FD_SNAPIN_TEST_TOPO_MAGIC (0xFD53A11113510) /* FD SNAPIN TEST TOPO V0 */

FD_FN_CONST ulong
fd_snapin_test_topo_align( void );

FD_FN_CONST ulong
fd_snapin_test_topo_footprint( void );

void *
fd_snapin_test_topo_new( void * shmem );

fd_snapin_test_topo_t *
fd_snapin_test_topo_join( void * shmem );

void
fd_snapin_test_topo_init( fd_snapin_test_topo_t * snapin_topo,
                          fd_topo_t *             topo,
                          fd_wksp_t *             wksp );

void
fd_snapin_test_topo_returnable_frag( fd_snapin_test_topo_t * snapin,
                                     ulong                   in_idx,
                                     ulong                   seq,
                                     ulong                   sig,
                                     ulong                   chunk,
                                     ulong                   sz,
                                     ulong                   ctl,
                                     ulong                   tsorig,
                                     ulong                   tspub );

void
fd_snapin_test_topo_fini( fd_snapin_test_topo_t * snapin );

#endif /* HEADER_fd_src_discof_restore_fd_snapin_test_topo */
