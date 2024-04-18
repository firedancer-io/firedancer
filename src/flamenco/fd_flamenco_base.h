#ifndef HEADER_fd_src_flamenco_fd_flamenco_base_h
#define HEADER_fd_src_flamenco_fd_flamenco_base_h

#include "../util/scratch/fd_scratch.h"
#include "../ballet/base58/fd_base58.h"
#include "../ballet/sha256/fd_sha256.h"
#include "types/fd_types_custom.h"

#define FD_DEFAULT_SLOTS_PER_EPOCH   ( 432000UL )
#define FD_DEFAULT_SHREDS_PER_EPOCH  ( ( 1 << 15UL ) * FD_DEFAULT_SLOTS_PER_EPOCH )
#define FD_SLOT_NULL                 ( ULONG_MAX )
#define FD_SHRED_IDX_NULL            ( UINT_MAX )

#define FD_FUNK_KEY_TYPE_ACC ((uchar)1)
#define FD_FUNK_KEY_TYPE_ELF_CACHE ((uchar)2)

/* Forward declarations */

struct fd_exec_epoch_ctx;
typedef struct fd_exec_epoch_ctx fd_exec_epoch_ctx_t;

struct fd_exec_slot_ctx;
typedef struct fd_exec_slot_ctx fd_exec_slot_ctx_t;

struct fd_exec_txn_ctx;
typedef struct fd_exec_txn_ctx fd_exec_txn_ctx_t;

struct fd_exec_instr_ctx;
typedef struct fd_exec_instr_ctx fd_exec_instr_ctx_t;

struct fd_acc_mgr;
typedef struct fd_acc_mgr fd_acc_mgr_t;

/* fd_rawtxn_b_t is a convenience type to store a pointer to a
   serialized transaction.  Should probably be removed in the future. */

struct fd_rawtxn_b {
  void * raw;
  ushort txn_sz;
};
typedef struct fd_rawtxn_b fd_rawtxn_b_t;

FD_PROTOTYPES_BEGIN

/* fd_acct_addr_cstr converts the given Solana address into a base58-
   encoded cstr.  Returns cstr.  On return cstr contains a string with
   length in [32,44] (excluding NULL terminator). */

static inline char *
fd_acct_addr_cstr( char        cstr[ static FD_BASE58_ENCODED_32_SZ ],
                   uchar const addr[ static 32 ] ) {
  return fd_base58_encode_32( addr, NULL, cstr );
}

/* fd_pod utils */

FD_FN_UNUSED static fd_pubkey_t *
fd_pod_query_pubkey( uchar const * pod,
                     char const *  path,
                     fd_pubkey_t * val ) {

  ulong        bufsz = 0UL;
  void const * buf   = fd_pod_query_buf( pod, path, &bufsz );

  if( FD_UNLIKELY( (!buf) | (bufsz!=sizeof(fd_pubkey_t)) ) )
    return NULL;

  memcpy( val->uc, buf, sizeof(fd_pubkey_t) );
  return val;
}

static inline ulong
fd_pod_insert_pubkey( uchar *             pod,
                      char const *        path,
                      fd_pubkey_t const * val ) {
  return fd_pod_insert_buf( pod, path, val->uc, sizeof(fd_pubkey_t) );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_fd_flamenco_base_h */
