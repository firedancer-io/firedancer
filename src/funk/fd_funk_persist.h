/* Private API called from fd_funk_new */
void
fd_funk_persist_new( fd_funk_t * funk );

/* Private API called from fd_funk_join */
void
fd_funk_persist_join( fd_funk_t * funk );

/* Private API called from fd_funk_leave */
void
fd_funk_persist_leave( fd_funk_t * funk );

/* Private API called from fd_funk_delete */
void
fd_funk_persist_delete( fd_funk_t * funk );

/* Read a record from the persistence file into the given buffer */
int
fd_funk_persist_load( fd_funk_t *           funk,
                      fd_funk_rec_t const * rec,
                      ulong                 val_sz,
                      uchar *               val );

/* Private version of fd_funk_rec_persist that skips argument checks */
int
fd_funk_rec_persist_unsafe( fd_funk_t *     funk,
                            fd_funk_rec_t * rec );

/* Private version of fd_funk_rec_persist_erase that skips argument checks */
int
fd_funk_rec_persist_erase_unsafe( fd_funk_t *     funk,
                                  fd_funk_rec_t * rec );

/* Generate a write-ahead log entry for a transaction. Called by publish. */
int
fd_funk_txn_persist_writeahead( fd_funk_t *     funk,
                                fd_funk_txn_t * map,
                                ulong           txn_idx,
                                ulong *         wa_pos,
                                ulong *         wa_alloc);

/* Delete a write-ahead log entry because it is no longer needed. */
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
