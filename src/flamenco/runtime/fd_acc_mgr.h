#ifndef HEADER_fd_src_flamenco_runtime_fd_acc_mgr_h
#define HEADER_fd_src_flamenco_runtime_fd_acc_mgr_h

#include "../fd_flamenco_base.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../funk/fd_funk.h"
#include "fd_banks_solana.h"
#include "fd_hashes.h"

FD_PROTOTYPES_BEGIN

#define FD_ACC_MGR_SUCCESS             (0)
#define FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT (-1)
#define FD_ACC_MGR_ERR_WRITE_FAILED    (-2)
#define FD_ACC_MGR_ERR_READ_FAILED     (-3)
#define FD_ACC_MGR_ERR_WRONG_MAGIC     (-4)


struct __attribute__((aligned(8UL))) fd_acc_mgr {
  fd_global_ctx_t*                             global;
  unsigned char  __attribute__((aligned(8UL))) data[];
};
typedef struct fd_acc_mgr fd_acc_mgr_t;

#define FD_ACC_MGR_FOOTPRINT ( sizeof( fd_acc_mgr_t ) )
#define FD_ACC_MGR_ALIGN (8UL)

typedef struct fd_global_ctx fd_global_ctx_t;

void* fd_acc_mgr_new( void*            mem,
                      fd_global_ctx_t* global,
                      ulong            footprint );


/* Represents the lamport balance associated with an account. */
typedef ulong fd_acc_lamports_t;

/* Writes account data to the database, starting at the given offset.
 */
int fd_acc_mgr_write_account_data( fd_acc_mgr_t* acc_mgr, fd_funk_txn_t* txn, fd_pubkey_t const * pubkey,
                                   const void* data, ulong sz, const void* data2, ulong sz2, int uncache );

/* Fetches the account data for the account with the given public key.

   TODO: nicer API so users of this method don't have to make two db calls, one to determine the
         size of the buffer and the other to actually read the data.
    */
int fd_acc_mgr_get_account_data( fd_acc_mgr_t* acc_mgr, fd_funk_txn_t* txn, fd_pubkey_t const * pubkey, uchar* result, ulong offset, ulong bytes );

/* Fetches the account metadata for the account with the given public key. */
int fd_acc_mgr_get_metadata( fd_acc_mgr_t* acc_mgr, fd_funk_txn_t* txn, fd_pubkey_t const * pubkey, fd_account_meta_t *result );

int fd_acc_mgr_set_metadata( fd_acc_mgr_t* acc_mgr, fd_funk_txn_t* txn, fd_pubkey_t const * pubkey, fd_account_meta_t *metadata);

/* Fetches the lamport balance for the account with the given public key. */
int fd_acc_mgr_get_lamports( fd_acc_mgr_t* acc_mgr, fd_funk_txn_t* txn, fd_pubkey_t const * pubkey, fd_acc_lamports_t* result );

/* Fetches the owner of the account with the given public key */
int fd_acc_mgr_get_owner( fd_acc_mgr_t* acc_mgr, fd_funk_txn_t* txn, fd_pubkey_t const * pubkey, fd_pubkey_t* result );

/* Sets the lamport balance for the account with the given public key. */
int fd_acc_mgr_set_lamports( fd_acc_mgr_t* acc_mgr, fd_funk_txn_t*, ulong slot, fd_pubkey_t const * pubkey, fd_acc_lamports_t lamports );
int fd_acc_mgr_set_owner( fd_acc_mgr_t* acc_mgr, fd_funk_txn_t* txn, ulong slot, fd_pubkey_t const * pubkey, fd_pubkey_t new_owner );

int fd_acc_mgr_write_structured_account( fd_acc_mgr_t* acc_mgr, fd_funk_txn_t* txn, ulong slot, fd_pubkey_t const *, fd_solana_account_t *);

int fd_acc_mgr_write_append_vec_account( fd_acc_mgr_t* acc_mgr, fd_funk_txn_t* txn, ulong slot, fd_solana_account_hdr_t *, int uncache);

int fd_acc_mgr_update_hash ( fd_acc_mgr_t* acc_mgr, fd_pubkey_hash_vector_t * dirty_keys, fd_account_meta_t * m, fd_funk_txn_t* txn, ulong slot, fd_pubkey_t const * pubkey, uchar const *data, ulong dlen );
int fd_acc_mgr_update_data( fd_acc_mgr_t* acc_mgr, fd_funk_txn_t* txn, ulong slot, fd_pubkey_t* pubkey, uchar *data, ulong dlen);

int fd_acc_mgr_is_key( fd_funk_rec_key_t const* id );

void const * fd_acc_mgr_view_data  ( fd_acc_mgr_t* acc_mgr, fd_funk_txn_t* txn, fd_pubkey_t const * pubkey,                           fd_funk_rec_t const **out_rec, int *opt_err );
void       * fd_acc_mgr_modify_data( fd_acc_mgr_t* acc_mgr, fd_funk_txn_t* txn, fd_pubkey_t const * pubkey, int do_create, ulong *sz, fd_funk_rec_t const *opt_con_rec, fd_funk_rec_t **opt_out_rec, int *opt_err );

int fd_acc_mgr_commit_data( fd_acc_mgr_t* acc_mgr, fd_funk_rec_t *rec, fd_pubkey_t const * pubkey, void *data, ulong slot, int uncache);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_acc_mgr_h */
