#ifndef HEADER_fd_src_ballet_runtime_fd_acc_mgr_h
#define HEADER_fd_src_ballet_runtime_fd_acc_mgr_h

#include "../fd_ballet_base.h"
#include "../txn/fd_txn.h"
#include "../../funk/fd_funk.h"
#include "fd_banks_solana.h"

FD_PROTOTYPES_BEGIN

#define FD_ACC_MGR_SUCCESS             (0)
#define FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT (-1)
#define FD_ACC_MGR_ERR_WRITE_FAILED    (-2)
#define FD_ACC_MGR_ERR_READ_FAILED     (-3)
#define FD_ACC_MGR_ERR_WRONG_MAGIC     (-4)

struct fd_acc_mgr {
    fd_funk_t* funk;
    const struct fd_funk_xactionid* funk_xroot;
};
typedef struct fd_acc_mgr fd_acc_mgr_t;

#define FD_ACC_MGR_FOOTPRINT (sizeof( fd_acc_mgr_t ))
#define FD_ACC_MGR_ALIGN (8UL)

void* fd_acc_mgr_new( void* mem,
                      fd_funk_t* funk,
                      const fd_funk_xactionid_t* funk_xroot,
                      ulong footprint );

fd_acc_mgr_t* fd_acc_mgr_join( void* mem );

void* fd_acc_mgr_leave( fd_acc_mgr_t* acc_mgr );

void* fd_acc_mgr_delete( void* mem );

/* Represents the lamport balance associated with an account. */
typedef ulong fd_acc_lamports_t;

/* Writes an account to the database with the given data and public key.

   The account will be created if it doesn't already exist. */
int fd_acc_mgr_write_account( fd_acc_mgr_t* acc_mgr, struct fd_funk_xactionid const*, fd_pubkey_t* pubkey, uchar* data, ulong data_len );

/* Writes account data to the database, starting at the given offset.

   TODO: make this automatically update the metadata (hash, dlen etc)
 */
int fd_acc_mgr_write_account_data( fd_acc_mgr_t* acc_mgr, struct fd_funk_xactionid const*, fd_pubkey_t* pubkey, ulong offset, uchar* data, ulong data_len );

/* Fetches the account data for the account with the given public key.
   
   TODO: nicer API so users of this method don't have to make two db calls, one to determine the
         size of the buffer and the other to actually read the data.
    */
int fd_acc_mgr_get_account_data( fd_acc_mgr_t* acc_mgr, fd_pubkey_t* pubkey, uchar* result, ulong offset, ulong bytes );

/* Fetches the account metadata for the account with the given public key. */
int fd_acc_mgr_get_metadata( fd_acc_mgr_t* acc_mgr, fd_pubkey_t* pubkey, fd_account_meta_t *result );

/* Fetches the lamport balance for the account with the given public key. */
int fd_acc_mgr_get_lamports( fd_acc_mgr_t* acc_mgr, fd_pubkey_t* pubkey, fd_acc_lamports_t* result );

/* Sets the lamport balance for the account with the given public key. */
int fd_acc_mgr_set_lamports( fd_acc_mgr_t* acc_mgr, struct fd_funk_xactionid const*, fd_pubkey_t* pubkey, fd_acc_lamports_t lamports );

int fd_acc_mgr_write_structured_account( fd_acc_mgr_t* acc_mgr, ulong slot, fd_pubkey_t*, fd_solana_account_t *);

int fd_acc_mgr_write_append_vec_account( fd_acc_mgr_t* acc_mgr, ulong slot, fd_solana_account_hdr_t *);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_runtime_fd_acc_mgr_h */
