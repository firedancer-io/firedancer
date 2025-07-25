#ifndef HEADER_fd_src_discof_restore_utils_fd_sshashes_h
#define HEADER_fd_src_discof_restore_utils_fd_sshashes_h

#include "../../../util/fd_util_base.h"
#include "../../../flamenco/types/fd_types_custom.h"
#include "../../../flamenco/gossip/fd_gossip_update_msg.h"

struct fd_sshashes_private;
typedef struct fd_sshashes_private fd_sshashes_t;

#define FD_SSHASHES_MAGIC (0xF17EDA2CE555710) /* FIREDANCER HTTP RESOLVE V0 */

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_sshashes_align( void );

FD_FN_CONST ulong
fd_sshashes_footprint( void );

void *
fd_sshashes_new( void * shmem );

fd_sshashes_t *
fd_sshashes_join( void * _sshashes_map );

#define FD_SSHASHES_ERROR   (-1)
#define FD_SSHASHES_SUCCESS ( 0)

/* fd_sshashes_update updates the internal snapshot hashes map with a new
   snapshot hashes message. */
int
fd_sshashes_update( fd_sshashes_t *                         map,
                    uchar const                             pubkey[ static FD_HASH_FOOTPRINT ],
                    fd_gossip_upd_snapshot_hashes_t const * snapshot_hashes );

FD_PROTOTYPES_END


#endif /* HEADER_fd_src_discof_restore_utils_fd_sshashes_h */
