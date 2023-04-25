#ifndef HEADER_fd_src_ballet_runtime_fd_acc_mgr_h
#define HEADER_fd_src_ballet_runtime_fd_acc_mgr_h

#include "../fd_ballet_base.h"
#include "../txn/fd_txn.h"
#include "../../funk/fd_funk.h"
#include "fd_banks_solana.h"
#include "fd_hashes.h"

static fd_pubkey_t fd_dirty_map_empty = {0};

typedef struct fd_dirty_map_entry {
  fd_pubkey_t      key;
  uint             hash;
  ulong            index;
} fd_dirty_map_entry_t;

#define MAP_NAME              fd_dirty_dup
#define MAP_KEY_T             fd_pubkey_t
#define MAP_KEY_NULL          fd_dirty_map_empty
#define MAP_KEY_INVAL(k)      (memcmp( (k.key), fd_dirty_map_empty.key, sizeof(MAP_KEY_T) ) == 0)
#define MAP_KEY_EQUAL(k0,k1)  (memcmp( (k0.key), (k1.key), sizeof(MAP_KEY_T) ) == 0)
#define MAP_KEY_EQUAL_IS_SLOW (1)
#define MAP_KEY_HASH(k)       ((uint)fd_hash( 0UL, (k.key), sizeof(MAP_KEY_T) ))
#define MAP_T                 fd_dirty_map_entry_t
#include "../../util/tmpl/fd_map_dynamic.c"

#define LG_SLOT_CNT 15

FD_PROTOTYPES_BEGIN

#define FD_ACC_MGR_SUCCESS             (0)
#define FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT (-1)
#define FD_ACC_MGR_ERR_WRITE_FAILED    (-2)
#define FD_ACC_MGR_ERR_READ_FAILED     (-3)
#define FD_ACC_MGR_ERR_WRONG_MAGIC     (-4)

#define VECT_NAME fd_pubkey_hash_vector
#define VECT_ELEMENT fd_pubkey_hash_pair_t
#include "fd_vector.h"
#undef VECT_NAME
#undef VECT_ELEMENT

struct __attribute__((aligned(8UL))) fd_acc_mgr {
  fd_global_ctx_t*                             global;
  void *                                       shmap;
  fd_dirty_map_entry_t *                       dup;
  fd_pubkey_hash_vector_t                      keys;
  unsigned char  __attribute__((aligned(8UL))) data[];
};
typedef struct fd_acc_mgr fd_acc_mgr_t;

#define FD_ACC_MGR_FOOTPRINT (sizeof( fd_acc_mgr_t ) + fd_dirty_dup_footprint(LG_SLOT_CNT)  )
#define FD_ACC_MGR_ALIGN (8UL)

typedef struct fd_global_ctx fd_global_ctx_t;

void* fd_acc_mgr_new( void*            mem,
                      fd_global_ctx_t* global,
                      ulong            footprint );

fd_acc_mgr_t* fd_acc_mgr_join( void* mem );

void* fd_acc_mgr_leave( fd_acc_mgr_t* acc_mgr );

void* fd_acc_mgr_delete( void* mem );

/* Represents the lamport balance associated with an account. */
typedef ulong fd_acc_lamports_t;

/* Writes account data to the database, starting at the given offset.
 */
int fd_acc_mgr_write_account_data( fd_acc_mgr_t* acc_mgr, fd_funk_txn_t* txn, fd_pubkey_t* pubkey,
                                   const void* data, ulong sz, const void* data2, ulong sz2 );

/* Fetches the account data for the account with the given public key.

   TODO: nicer API so users of this method don't have to make two db calls, one to determine the
         size of the buffer and the other to actually read the data.
    */
int fd_acc_mgr_get_account_data( fd_acc_mgr_t* acc_mgr, fd_funk_txn_t* txn, fd_pubkey_t* pubkey, uchar* result, ulong offset, ulong bytes );

/* Fetches the account metadata for the account with the given public key. */
int fd_acc_mgr_get_metadata( fd_acc_mgr_t* acc_mgr, fd_funk_txn_t* txn, fd_pubkey_t* pubkey, fd_account_meta_t *result );

/* Fetches the lamport balance for the account with the given public key. */
int fd_acc_mgr_get_lamports( fd_acc_mgr_t* acc_mgr, fd_funk_txn_t* txn, fd_pubkey_t* pubkey, fd_acc_lamports_t* result );

/* Sets the lamport balance for the account with the given public key. */
int fd_acc_mgr_set_lamports( fd_acc_mgr_t* acc_mgr, fd_funk_txn_t*, ulong slot, fd_pubkey_t* pubkey, fd_acc_lamports_t lamports );

int fd_acc_mgr_write_structured_account( fd_acc_mgr_t* acc_mgr, fd_funk_txn_t* txn, ulong slot, fd_pubkey_t*, fd_solana_account_t *);

int fd_acc_mgr_write_append_vec_account( fd_acc_mgr_t* acc_mgr, fd_funk_txn_t* txn, ulong slot, fd_solana_account_hdr_t *);

void fd_acc_mgr_dirty_pubkey ( fd_acc_mgr_t* acc_mgr, fd_pubkey_t* pubkey, fd_hash_t *hash);

int fd_acc_mgr_update_hash ( fd_acc_mgr_t* acc_mgr, fd_account_meta_t * m, fd_funk_txn_t* txn, ulong slot, fd_pubkey_t * pubkey, uchar *data, ulong dlen );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_runtime_fd_acc_mgr_h */
