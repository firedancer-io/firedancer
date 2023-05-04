#ifndef HEADER_fd_src_util_tilegroup_fd_tile_h
#define HEADER_fd_src_util_tilegroup_fd_tile_h

#include "../fd_util_base.h"
#include "../../tango/cnc/fd_cnc.h"

/* fd_tg_cnt_all_tiles counts all tiles in all groups.
   The input pod should be '$APP.grp'. */
ulong
fd_taskgroup_cnt_all_tiles( uchar const * all_grps_pod );


/* fd_tg_cnt_grp_tiles counts all of the tiles in a tile group. 
   The input pod could be '$APP.grp.verify'. */
ulong
fd_taskgroup_cnt_grp_tiles( uchar const * tg_pod );

#endif /* HEADER_fd_src_util_tilegroup_fd_tile_h */
