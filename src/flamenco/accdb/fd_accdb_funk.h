#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_funk_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_funk_h

#include "fd_accdb_ref.h"
#include "../fd_flamenco_base.h"
#include "../../funk/fd_funk_rec.h"

FD_PROTOTYPES_BEGIN

void
fd_accdb_funk_copy_account( fd_account_meta_t *       out_meta,
                            void *                    out_data,
                            fd_account_meta_t const * src_meta,
                            void const *              src_data );

void
fd_accdb_funk_copy_truncated( fd_account_meta_t *       out_meta,
                              fd_account_meta_t const * src_meta );

fd_accdb_rw_t *
fd_accdb_funk_prep_create( fd_accdb_rw_t *       rw,
                           fd_funk_t *           funk,
                           fd_funk_txn_t const * txn,
                           void const *          address,
                           void *                val,
                           ulong                 val_sz,
                           ulong                 val_max ) ;

fd_accdb_rw_t *
fd_accdb_funk_prep_inplace( fd_accdb_rw_t * rw,
                            fd_funk_t *     funk,
                            fd_funk_rec_t * rec );

fd_accdb_rw_t *
fd_accdb_funk_create( fd_funk_t *           funk,
                      fd_accdb_rw_t *       rw,
                      fd_funk_txn_t const * txn,
                      void const *          address,
                      ulong                 data_max );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_funk_h */
