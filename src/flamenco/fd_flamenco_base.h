#ifndef HEADER_fd_src_flamenco_fd_flamenco_base_h
#define HEADER_fd_src_flamenco_fd_flamenco_base_h

#include "../util/scratch/fd_scratch.h"
#include "../ballet/base58/fd_base58.h"
#include "../ballet/sha256/fd_sha256.h"
#include "types/fd_types_custom.h"

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

/* fd_addr_cstr converts the given Solana address into a base58-
   encoded cstr.  Returns cstr.  On return cstr contains a string with
   length in [32,44] (excluding NULL terminator). */

static inline char *
fd_addr_cstr( char        cstr[ static FD_BASE58_ENCODED_32_SZ ],
              uchar const addr[ static 32 ] ) {
  return fd_base58_encode_32( addr, NULL, cstr );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_fd_flamenco_base_h */
