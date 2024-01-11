#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_h

#include "../fd_flamenco_base.h"

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

/* FD_FEATURE_ACTIVE evalutes to 1 if the given feature is active, 0
   otherwise.  First arg is the fd_exec_slot_ctx_t.  Second arg is the
   name of the feature.

   Example usage:   if( FD_FEATURE_ACTIVE( slot_ctx, set_exempt_rent_epoch_max ) ) */

#define FD_FEATURE_ACTIVE(_slot_ctx, _feature_name)  (_slot_ctx->slot_bank.slot >= _slot_ctx->epoch_ctx->features. _feature_name)

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_h */
