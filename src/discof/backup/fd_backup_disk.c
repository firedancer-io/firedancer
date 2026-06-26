#include "fd_backup_disk.h"

fd_backup_disk_t *
fd_backup_disk_init( fd_backup_disk_t *         backup,
                     uchar const *              acc_map,
                     fd_accdb_accmeta_t const * acc_pool,
                     ulong                      acc_map_seed,
                     ulong                      chain_mask ) {

}

fd_backup_disk_t *
fd_backup_disk_join( fd_backup_disk_t * backup,
                     fd_accdb_shmem_t * accdb_shmem ) {

}

fd_backup_frag_t *
fd_backup_disk_scan( fd_backup_disk_t * backup,
                     fd_backup_frag_t * frag,
                     uchar const *      data,
                     ulong              data_sz ) {

}
