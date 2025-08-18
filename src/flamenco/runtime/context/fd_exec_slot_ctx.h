#ifndef HEADER_fd_src_flamenco_runtime_context_fd_exec_slot_ctx_h
#define HEADER_fd_src_flamenco_runtime_context_fd_exec_slot_ctx_h

#include "../../../funk/fd_funk.h"
#include "../../../util/rng/fd_rng.h"
#include "../../../util/wksp/fd_wksp.h"

#include "../../types/fd_types.h"
#include "../fd_txncache.h"
#include "../fd_bank.h"
#include "../../types/fd_types.h"
#include "../../../funk/fd_funk_txn.h"

/* fd_exec_slot_ctx_t is the context that stays constant during all
   transactions in a block. */

/* TODO: The slot ctx should be removed entirely. Pointers to
   funk, funk_txn, status_cache should be passed in
   seperately.*/

struct fd_exec_slot_ctx {
  ulong           magic; /* ==FD_EXEC_SLOT_CTX_MAGIC */

  fd_banks_t *    banks; /* TODO: Remove fd_banks_t when fd_ledger is removed*/
  fd_bank_t *     bank;

  fd_funk_t *     funk;
  fd_funk_txn_t * funk_txn;

  fd_txncache_t * status_cache;

  fd_capture_ctx_t * capture_ctx;

  uint silent : 1;
};

#define FD_EXEC_SLOT_CTX_ALIGN     (alignof(fd_exec_slot_ctx_t))
#define FD_EXEC_SLOT_CTX_FOOTPRINT (sizeof (fd_exec_slot_ctx_t))
#define FD_EXEC_SLOT_CTX_MAGIC     (0xC2287BA2A5E6FC3DUL) /* random */

FD_PROTOTYPES_BEGIN

void *
fd_exec_slot_ctx_new( void * mem );

fd_exec_slot_ctx_t *
fd_exec_slot_ctx_join( void * mem );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_context_fd_exec_slot_ctx_h */
