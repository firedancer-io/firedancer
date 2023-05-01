typedef struct fd_funk_persist_free_entry fd_funk_persist_free_entry_t;

void *
fd_funk_persist_free_map_pool_leave( fd_funk_persist_free_entry_t * join );

void *
fd_funk_persist_free_map_pool_delete( void * shmem );

FD_FN_PURE static inline fd_funk_persist_free_entry_t *
fd_funk_free_map( fd_funk_t * funk,       /* Assumes current local join */
                  fd_wksp_t * wksp ) {    /* Assumes wksp == fd_funk_wksp( funk ) */
  return (fd_funk_persist_free_entry_t *)fd_wksp_laddr_fast( wksp, funk->persist_frees_gaddr );
}

int
fd_funk_rec_persist_unsafe( fd_funk_t *     funk,
                            fd_funk_rec_t * rec );

int
fd_funk_rec_persist_erase_unsafe( fd_funk_t *     funk,
                                  fd_funk_rec_t * rec );
