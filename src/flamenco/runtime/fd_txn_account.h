#ifndef HEADER_fd_src_flamenco_runtime_fd_txn_account_h
#define HEADER_fd_src_flamenco_runtime_fd_txn_account_h

#include "../../ballet/txn/fd_txn.h"
#include "program/fd_program_util.h"
#include "fd_txn_account_private.h"
#include "fd_txn_account_vtable.h"

struct fd_acc_mgr;
typedef struct fd_acc_mgr fd_acc_mgr_t;

struct __attribute__((aligned(8UL))) fd_txn_account {
  ulong                           magic;

  fd_pubkey_t                     pubkey[1];

  fd_txn_account_private_state_t  private_state;

  ulong                           starting_dlen;
  ulong                           starting_lamports;

  /* only used when obtaining a mutable fd_txn_account_t from funk */
  fd_funk_rec_prepare_t           prepared_rec;

  fd_txn_account_vtable_t const * vt;
};
typedef struct fd_txn_account fd_txn_account_t;
#define FD_TXN_ACCOUNT_FOOTPRINT (sizeof(fd_txn_account_t))
#define FD_TXN_ACCOUNT_ALIGN     (8UL)
#define FD_TXN_ACCOUNT_MAGIC     (0xF15EDF1C51F51AA1UL)

#define FD_TXN_ACCOUNT_DECL(_x)  fd_txn_account_t _x[1]; fd_txn_account_init( _x );

FD_PROTOTYPES_BEGIN

/* Initializes an fd_txn_account_t from a pointer to a region of memory */
fd_txn_account_t *
fd_txn_account_init( void * ptr );

/* Assigns account meta and data for a readonly txn account */
void
fd_txn_account_init_from_meta_and_data_mutable( fd_txn_account_t *  acct,
                                                fd_account_meta_t * meta,
                                                uchar *             data );

/* Assigns account meta and data for a mutable txn account */
void
fd_txn_account_init_from_meta_and_data_readonly( fd_txn_account_t *       acct,
                                                fd_account_meta_t const * meta,
                                                uchar const *             data );

/* Sets up a readonly sentinel account meta for the txn object.
   Allocates from the given spad and uses the spad_wksp to set the
   meta gaddr field.

   Intended for use in the executor tile only, where txn accounts
   must be setup readonly. */
void
fd_txn_account_setup_sentinel_meta_readonly( fd_txn_account_t * acct,
                                             fd_spad_t *        spad,
                                             fd_wksp_t *        spad_wksp );

/* Sets up a mutable account meta for the txn_account.
   Allocates a mutable account meta object from the given spad with the given sz. */
void
fd_txn_account_setup_meta_mutable( fd_txn_account_t * acct,
                                   fd_spad_t *        spad,
                                   ulong              sz );

/* Operators */

/* buf is a handle to the account shared data. Sets the account shared
   data as mutable. Also, gaddr aware pointers for account metadata and
   data are stored in the txn account. */
fd_txn_account_t *
fd_txn_account_make_mutable( fd_txn_account_t * acct,
                             void *             buf,
                             fd_wksp_t *        wksp );

/* Factory constructors from funk (Accounts DB) */

/* Initializes a fd_txn_account_t object with a readonly handle into
   its funk record.

   IMPORTANT: When we access the account metadata and data pointer later on in the
     execution pipeline, we assume that nothing else will change these.

     This is safe because we assume that we hold a read lock on the account, since
     we are inside a Solana transaction. */
int
fd_txn_account_init_from_funk_readonly( fd_txn_account_t *    acct,
                                        fd_pubkey_t const *   pubkey,
                                        fd_funk_t const *     funk,
                                        fd_funk_txn_t const * funk_txn );

/* Initializes a fd_txn_account_t object with a mutable handle into
   its funk record. Cannot be called in the executor tile. */
int
fd_txn_account_init_from_funk_mutable( fd_txn_account_t *  acct,
                                       fd_pubkey_t const * pubkey,
                                       fd_funk_t *         funk,
                                       fd_funk_txn_t *     funk_txn,
                                       int                 do_create,
                                       ulong               min_data_sz );
/* Funk Save and Publish helpers */

/* Save helper into Funk (Accounts DB)
   Saves the contents of a fd_txn_account_t object obtained from
   fd_txn_account_init_from_funk_readonly back into funk */
int
fd_txn_account_save( fd_txn_account_t * acct,
                     fd_funk_t *        funk,
                     fd_funk_txn_t *    txn,
                     fd_wksp_t *        acc_data_wksp );

/* Publishes the record contents of a mutable fd_txn_account_t object
   obtained from fd_txn_account_init_from_funk_mutable into funk
   if the record does not yet exist in the current funk txn.
   ie. the record was created / cloned from an ancestor funk txn
   by fd_txn_account_init_from_funk_mutable */
void
fd_txn_account_mutable_fini( fd_txn_account_t * acct,
                             fd_funk_t *        funk,
                             fd_funk_txn_t *    txn );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_txn_account_h */
