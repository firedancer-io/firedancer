#ifndef HEADER_fd_src_flamenco_runtime_fd_txn_account_h
#define HEADER_fd_src_flamenco_runtime_fd_txn_account_h

#include "../accdb/fd_accdb_sync.h"
#include "../types/fd_types.h"
#include "../../funk/fd_funk_rec.h"

struct fd_acc_mgr;
typedef struct fd_acc_mgr fd_acc_mgr_t;

/* fd_txn_account_t is a wrapper around a database record. It is used to
   provide an interface for an account during transaction execution
   along with reference counting semantics. The fd_txn_account_t object
   is initialized with a pointer to the account's metadata and data, the
   wksp that the data belongs to, its pubkey, and if the transaction
   account is mutable.

   fd_txn_account_t is NOT thread-safe and only supports a single join
   at a given time.

   TODO: Consider changing the meta/data boundary to make it more
   explicit that the caller passes in a contigious region of memory
   which has to correspond to the meta/data layout.

   TODO: Consider making the fd_txn_account struct private */

struct __attribute__((aligned(8UL))) fd_txn_account {
  ulong                           magic;

  fd_pubkey_t                     pubkey[1];

  fd_account_meta_t *             meta;
  uchar *                         data;

  int                             is_mutable;
  long                            meta_soff;

  ulong                           starting_dlen;
  ulong                           starting_lamports;

  /* Provide borrowing semantics. Used for single-threaded logic only,
     thus not comparable to a data synchronization lock. */
  ushort                          refcnt_excl;

};
typedef struct fd_txn_account fd_txn_account_t;
#define FD_TXN_ACCOUNT_FOOTPRINT (sizeof(fd_txn_account_t))
#define FD_TXN_ACCOUNT_ALIGN     (8UL)
#define FD_TXN_ACCOUNT_MAGIC     (0xF15EDF1C51F51AA1UL)

FD_PROTOTYPES_BEGIN

/* fd_txn_account_new lays out the memory required for a
   fd_txn_account object. The caller should only use the struct
   after it has been joined. fd_txn_account_t makes the assumption
   that the account data is laid out directly after the account meta.
   After a successful call to fd_txn_account_new, the object will now
   own the account's metadata and data. */

void *
fd_txn_account_new( void *              mem,
                    fd_pubkey_t const * pubkey,
                    fd_account_meta_t * meta,
                    int                 is_mutable );

/* fd_txn_account_join joins a thread with an indepedent address space
   to the memory region allocated by fd_txn_account_new. There can be
   only ONE valid join per fd_txn_account_t object. If a _join is called
   from one thread, it is implied that the object is no longer valid
   on other threads.

   TODO: When the new db is introduced, the wksp argument should be
   removed in favor of using offsets into other data structures. */

fd_txn_account_t *
fd_txn_account_join( void * mem );

/* fd_txn_account_leave leaves a current local join and returns a
   pointer to the underlying shared memory region. The fd_txn_account_t
   will still own the account's metadata and data. */

void *
fd_txn_account_leave( fd_txn_account_t * acct );

/* fd_txn_account_delete removes the memory layout for the
   fd_txn_account_t object. It returns a pointer to the underlying
   shared struct. Any attempts to join after a call to
   fd_txn_account_delete will fail. The account's metadata and data
   will be owned by the caller after the delete is called.  */

void *
fd_txn_account_delete( void * mem );

/* Factory constructors from funk.
   TODO: These need to be removed when a new db is introduced and either
   replaced with a new factory constructor or removed entirely in favor
   of the generic constructors defined above. */

/* fd_txn_account_init_from_funk_readonly initializes a fd_txn_account_t
   object with a readonly handle into its funk record.

   IMPORTANT: When we access the account metadata and data pointer later
   on in the execution pipeline, we assume that nothing else will change
   these.

   This is safe because we assume that we hold a read lock on the
   account, since we are inside a Solana transaction. */

int
fd_txn_account_init_from_funk_readonly( fd_txn_account_t *        acct,
                                        fd_pubkey_t const *       pubkey,
                                        fd_funk_t const *         funk,
                                        fd_funk_txn_xid_t const * xid );

/* fd_txn_account_init_from_funk_mutable initializes a fd_txn_account_t
   object with a mutable handle into its funk record.

   IMPORTANT: Cannot be called in the executor tile. */

fd_account_meta_t *
fd_txn_account_init_from_funk_mutable( fd_txn_account_t *        acct,
                                       fd_pubkey_t const *       pubkey,
                                       fd_accdb_user_t *         accdb,
                                       fd_funk_txn_xid_t const * xid,
                                       int                       do_create,
                                       ulong                     min_data_sz,
                                       fd_funk_rec_prepare_t *   prepare_out );

/* Publishes the record contents of a mutable fd_txn_account_t object
   obtained from fd_txn_account_init_from_funk_mutable into funk
   if the record does not yet exist in the current funk txn.
   ie. the record was created / cloned from an ancestor funk txn
   by fd_txn_account_init_from_funk_mutable. */

void
fd_txn_account_mutable_fini( fd_txn_account_t *        acct,
                             fd_accdb_user_t *         funk,
                             fd_funk_rec_prepare_t *   prepare );

/* Simple accesssors and mutators. */

fd_pubkey_t const *
fd_txn_account_get_owner( fd_txn_account_t const * acct );

fd_account_meta_t const *
fd_txn_account_get_meta( fd_txn_account_t const * acct );

uchar const *
fd_txn_account_get_data( fd_txn_account_t const * acct );

uchar *
fd_txn_account_get_data_mut( fd_txn_account_t const * acct );

ulong
fd_txn_account_get_data_len( fd_txn_account_t const * acct );

int
fd_txn_account_is_executable( fd_txn_account_t const * acct );

ulong
fd_txn_account_get_lamports( fd_txn_account_t const * acct );

ulong
fd_txn_account_get_rent_epoch( fd_txn_account_t const * acct );

void
fd_txn_account_set_meta( fd_txn_account_t * acct, fd_account_meta_t * meta );

void
fd_txn_account_set_executable( fd_txn_account_t * acct, int is_executable );

void
fd_txn_account_set_owner( fd_txn_account_t * acct, fd_pubkey_t const * owner );

void
fd_txn_account_set_lamports( fd_txn_account_t * acct, ulong lamports );

int
fd_txn_account_checked_add_lamports( fd_txn_account_t * acct, ulong lamports );

int
fd_txn_account_checked_sub_lamports( fd_txn_account_t * acct, ulong lamports );

void
fd_txn_account_set_data( fd_txn_account_t * acct,
                         void const *       data,
                         ulong              data_sz );

void
fd_txn_account_set_data_len( fd_txn_account_t * acct, ulong data_len );

void
fd_txn_account_set_slot( fd_txn_account_t * acct,
                         ulong              slot );

void
fd_txn_account_clear_owner( fd_txn_account_t * acct );

void
fd_txn_account_resize( fd_txn_account_t * acct, ulong dlen );

ushort
fd_txn_account_is_borrowed( fd_txn_account_t const * acct );

int
fd_txn_account_is_mutable( fd_txn_account_t const * acct );

int
fd_txn_account_is_readonly( fd_txn_account_t const * acct );

int
fd_txn_account_try_borrow_mut( fd_txn_account_t * acct );

void
fd_txn_account_drop( fd_txn_account_t * acct );

void
fd_txn_account_set_readonly( fd_txn_account_t * acct );

void
fd_txn_account_set_mutable( fd_txn_account_t * acct );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_txn_account_h */
