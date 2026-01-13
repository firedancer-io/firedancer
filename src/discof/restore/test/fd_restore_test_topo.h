#ifndef HEADER_fd_src_discof_restore_utils_fd_restore_test_topo
#define HEADER_fd_src_discof_restore_utils_fd_restore_test_topo

#include "../../../util/fd_util_base.h"
#include "../../../disco/topo/fd_topo.h"
#include "fd_snapct_test_topo.h"
#include "fd_snapld_test_topo.h"
#include "fd_snapdc_test_topo.h"
#include "fd_snapin_test_topo.h"
#include "fd_snapla_test_topo.h"
#include "fd_snapls_test_topo.h"
#include "fd_snapwh_test_topo.h"
#include "fd_snapwr_test_topo.h"

struct fd_restore_test_topo {
  fd_topo_t * topo;

  fd_snapct_test_topo_t snapct;

  fd_snapld_test_topo_t snapld;

  fd_snapdc_test_topo_t snapdc;

  fd_snapin_test_topo_t snapin;

  fd_snapla_test_topo_t snapla;

  fd_snapls_test_topo_t snapls;

  fd_snapwh_test_topo_t snapwh;

  fd_snapwr_test_topo_t snapwr;

  ulong magic;
};

typedef struct fd_restore_test_topo fd_restore_test_topo_t;

#define FD_RESTORE_TEST_TOPO_MAGIC (0xFD5E5101E1E510) /* FD RESTORE TEST TOPO V0 */

FD_FN_CONST ulong
fd_restore_test_topo_align( void );

FD_FN_CONST ulong
fd_restore_test_topo_footprint( void );

void *
fd_restore_test_topo_new( void * shmem );

fd_restore_test_topo_t *
fd_restore_test_topo_join( void * shmem );

void
fd_restore_test_topo_init( fd_restore_test_topo_t * restore_topo,
                           fd_wksp_t *              wksp );

void
fd_restore_test_topo_fini( fd_restore_test_topo_t * restore_topo );

#endif /* HEADER_fd_src_discof_restore_utils_fd_restore_test_topo */