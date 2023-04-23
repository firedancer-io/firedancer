#ifndef HEADER_fd_src_funk_fd_funk_val_h
#define HEADER_fd_src_funk_fd_funk_val_h

/* This provides APIs for managing funk record values.  It is generally
   not meant to be included directly.  Use fd_funk.h instead. */

#include "fd_funk_rec.h" /* Includes fd_funk_txn.h, fd_funk_base.h */

/* FD_FUNK_REC_VAL_MAX is the maximum size of a record value.  The
   current value is aligned with Solana usages. */

#define FD_FUNK_REC_VAL_MAX (10UL<<20) /* 10 MiB */

FD_PROTOTYPES_BEGIN

static inline void
fd_funk_val_init( fd_funk_rec_t * rec ) { /* Assumed a mapped record */
  rec->val_sz    = 0U;
  rec->val_max   = 0U;
  rec->val_gaddr = 0UL;
}

static inline void
fd_funk_val_flush( fd_funk_rec_t * rec,     /* Assumed a mapped record */
                   fd_alloc_t *    alloc,   /* ==fd_funk_alloc( funk, wksp ) */
                   fd_wksp_t *     wksp ) { /* ==fd_funk_wksp( funk ) */
  ulong val_gaddr = rec->val_gaddr;
  fd_funk_val_init( rec );
  if( val_gaddr ) fd_alloc_free( alloc, fd_wksp_laddr_fast( wksp, val_gaddr ) );
}

/* Misc */

/* fd_funk_val_verify verifies the record values.  Returns
   FD_FUNK_SUCCESS if the values appear intact and FD_FUNK_ERR_INVAL if
   not (logs details).  Meant to be called as part of fd_funk_verify.
   As such, it assumes funk is non-NULL,
   fd_funk_{wksp,txn_map,rec_map,alloc} have been verified to work and
   the txn_map and rec_map have been verified. */

int
fd_funk_val_verify( fd_funk_t * funk );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_funk_fd_funk_val_h */
