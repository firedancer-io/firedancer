#ifndef HEADER_fd_src_discof_backup_fd_backup_disk_h
#define HEADER_fd_src_discof_backup_fd_backup_disk_h

/* fd_backup_disk.h finds rooted accounts from disk. */

#include "fd_backup.h"
#include "../../flamenco/accdb/fd_accdb.h"
#define FD_ACCDB_NO_FORK_ID
#include "../../flamenco/accdb/fd_accdb_private.h"

struct fd_backup_disk {
  uint const *               acc_map;
  fd_accdb_accmeta_t const * acc_pool;
  uint root_generation;
};

typedef struct fd_backup_disk fd_backup_disk_t;

FD_PROTOTYPES_BEGIN

fd_backup_disk_t *
fd_backup_disk_init( fd_backup_disk_t *         backup,
                     uchar const *              acc_map,
                     fd_accdb_accmeta_t const * acc_pool,
                     ulong                      acc_map_seed,
                     ulong                      chain_mask );

fd_backup_disk_t *
fd_backup_disk_join( fd_backup_disk_t * backup,
                     fd_accdb_shmem_t * accdb_shmem );

fd_backup_frag_t *
fd_backup_disk_scan( fd_backup_disk_t * backup,
                     fd_backup_frag_t * frag,
                     uchar const *      data,
                     ulong              data_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backup_fd_backup_disk_h */
