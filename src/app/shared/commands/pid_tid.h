#ifndef HEADER_fd_src_app_shared_commands_pid_tid_h
#define HEADER_fd_src_app_shared_commands_pid_tid_h

#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"

FD_PROTOTYPES_BEGIN

ulong
fd_topo_match_tiles( fd_topo_t const * topo,
                     ushort            tile_idxs[ static 128 ],
                     char const *      query,
                     _Bool *           whole_process );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_commands_pid_tid_h */
