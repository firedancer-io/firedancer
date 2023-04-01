#ifndef HEADER_fd_src_ballet_runtime_fd_runtime_h
#define HEADER_fd_src_ballet_runtime_fd_runtime_h

#include "fd_rocksdb.h"
#include "fd_acc_mgr.h"
#include "../poh/fd_poh.h"

#define FD_RUNTIME_EXECUTE_SUCCESS                               ( 0 )  /* Slot executed successfully */
#define FD_RUNTIME_EXECUTE_GENERIC_ERR                          ( -1 ) /* The Slot execute returned an error */

typedef struct fd_executor fd_executor_t;

struct fd_global_ctx {
  fd_alloc_fun_t             allocf;
  void *                     allocf_arg;
  fd_free_fun_t              freef;
  fd_acc_mgr_t*              acc_mgr;

  fd_genesis_solana_t        gen;
  uchar                      genesis_hash[FD_SHA256_HASH_SZ];

  fd_rng_t                   rnd_mem;

  fd_wksp_t *                wksp;
  fd_funk_t*                 funk;
  fd_alloc_t *               alloc;
  fd_executor_t*             executor;  // Amusingly, it is just a pointer to this...
  fd_rng_t*                  rng;

  // This state needs to be commited to funk so that we can roll it back?
  ulong                      current_slot;
  fd_poh_state_t             poh;
  struct fd_funk_xactionid   funk_txn;
  uchar                      block_hash[FD_SHA256_HASH_SZ];
  // TODO: should we instead remember which slot the poh is valid for?
  uchar                      poh_booted;
  fd_clock_timestamp_votes_t timestamp_votes;

};
typedef struct fd_global_ctx fd_global_ctx_t;

#define FD_GLOBAL_CTX_FOOTPRINT ( sizeof(fd_global_ctx_t) )
#define FD_GLOBAL_CTX_ALIGN (8UL)

FD_PROTOTYPES_BEGIN

// TODO: add a global_ctx_new/init..

void fd_runtime_boot_slot_zero( fd_global_ctx_t *global );
int  fd_runtime_block_execute ( fd_global_ctx_t *global, fd_slot_blocks_t *slot_data );
int  fd_runtime_block_verify  ( fd_global_ctx_t *global, fd_slot_blocks_t *slot_data );
int  fd_runtime_block_eval    ( fd_global_ctx_t *global, fd_slot_blocks_t *slot_data );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_runtime_fd_runtime_h */
