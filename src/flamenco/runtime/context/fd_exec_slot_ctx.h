#ifndef HEADER_fd_src_flamenco_runtime_context_fd_exec_slot_ctx_h
#define HEADER_fd_src_flamenco_runtime_context_fd_exec_slot_ctx_h

#include "../../../funk/fd_funk.h"
#include "../../../util/fd_util_base.h"
#include "../../../util/rng/fd_rng.h"
#include "../../../util/valloc/fd_valloc.h"
#include "../../../util/wksp/fd_wksp.h"

#include "../../capture/fd_solcap_writer.h"
#include "../../rewards/fd_rewards_types.h"
#include "../../types/fd_types.h"

#include "fd_exec_epoch_ctx.h"

struct fd_acc_mgr;
typedef struct fd_acc_mgr fd_acc_mgr_t;

FD_PROTOTYPES_BEGIN

#define FD_EXEC_SLOT_CTX_ALIGN (8UL)
struct __attribute__((aligned(FD_EXEC_SLOT_CTX_ALIGN))) fd_exec_slot_ctx {
  ulong magic; /* ==FD_EXEC_SLOT_CTX_MAGIC */

  fd_exec_epoch_ctx_t * epoch_ctx;
  
  // TODO: needs to move out
  fd_funk_txn_t * funk_txn_tower[32];
  ushort          funk_txn_index;
  fd_wksp_t *     funk_wksp; // Workspace dedicated to funk, KEEP YOUR GRUBBY MITS OFF!
  fd_wksp_t *     local_wksp; // Workspace for allocs local to this process

  fd_funk_txn_t *      funk_txn;
  fd_acc_mgr_t *       acc_mgr;
  fd_valloc_t          valloc;
  fd_solcap_writer_t * capture;
  int                  trace_dirfd;
  int                  trace_mode;
  fd_rng_t             rnd_mem;
  fd_rng_t *           rng;

  fd_epoch_reward_status_t epoch_reward_status;
  ulong                    signature_cnt;
  fd_hash_t                account_delta_hash;
  fd_hash_t                prev_banks_hash;
  
  fd_pubkey_t const * leader;   /* Current leader */
  fd_firedancer_banks_t bank;
};
typedef struct fd_exec_slot_ctx fd_exec_slot_ctx_t;
#define FD_EXEC_SLOT_CTX_FOOTPRINT ( sizeof(fd_exec_slot_ctx_t) )
#define FD_EXEC_SLOT_CTX_MAGIC (0xC2287BA2A5E6FC3DUL) /* random */

void *
fd_exec_slot_ctx_new( void * mem );

fd_exec_slot_ctx_t *
fd_exec_slot_ctx_join( void * mem );

void *
fd_exec_slot_ctx_leave( fd_exec_slot_ctx_t * ctx );

void *
fd_exec_slot_ctx_delete( void * mem );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_context_fd_exec_slot_ctx_h */
