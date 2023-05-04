#include "fd_tilegroup.h"
#include "../log/fd_log.h"
#include "../pod/fd_pod.h"

ulong
fd_taskgroup_cnt_all_tiles( uchar const * all_grps_pod ) {
  ulong cnt = 0;

  /* for each task group */
  for( fd_pod_iter_t iter = fd_pod_iter_init( all_grps_pod ); !fd_pod_iter_done( iter ); iter = fd_pod_iter_next( iter ) ) {
    fd_pod_info_t info = fd_pod_iter_info( iter );
    if( FD_UNLIKELY( info.val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) {
      FD_LOG_ERR(( "expected for child of `.grp` to be a pod" ));
    }
    
    cnt += fd_taskgroup_cnt_grp_tiles( info.val );
  } /* for each task group */
  return cnt;
}
