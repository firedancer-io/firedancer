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

/* fd_funk_persist_verify verifies the persistence layer. Returns
   FD_FUNK_SUCCESS if everything appears intact and FD_FUNK_ERR_INVAL if
   not (logs details).  Meant to be called as part of fd_funk_verify.
   As such, it assumes funk is non-NULL, fd_funk_{wksp,rec_map,wksp_tag}
   have been verified to work and the rec_map has been verified. */
int
fd_funk_persist_verify( fd_funk_t * funk );
