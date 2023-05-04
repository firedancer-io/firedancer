void
fd_funk_persist_leave( fd_funk_t * funk );

int
fd_funk_rec_persist_unsafe( fd_funk_t *     funk,
                            fd_funk_rec_t * rec );

int
fd_funk_rec_persist_erase_unsafe( fd_funk_t *     funk,
                                  fd_funk_rec_t * rec );

int
fd_funk_txn_persist_writeahead( fd_funk_t *     funk,
                                fd_funk_txn_t * map,
                                ulong           txn_idx,
                                ulong *         wa_pos,
                                ulong *         wa_alloc);

void
fd_funk_txn_persist_writeahead_erase( fd_funk_t * funk,
                                      ulong       wa_pos,
                                      ulong       wa_alloc);

/* fd_funk_persist_verify verifies the persistence layer. Returns
   FD_FUNK_SUCCESS if everything appears intact and FD_FUNK_ERR_INVAL if
   not (logs details).  Meant to be called as part of fd_funk_verify.
   As such, it assumes funk is non-NULL, fd_funk_{wksp,rec_map,wksp_tag}
   have been verified to work and the rec_map has been verified. */
int
fd_funk_persist_verify( fd_funk_t * funk );
