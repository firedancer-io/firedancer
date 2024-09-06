#ifndef HEADER_fd_src_flamenco_harness_fd_harness_dump_h
#define HEADER_fd_src_flamenco_harness_fd_harness_dump_h

#include "../../funk/fd_funk.h"
#include "../fd_flamenco_base.h"

#include "../runtime/fd_account.h"

#include "../runtime/context/fd_exec_txn_ctx.h"
#include "../runtime/context/fd_exec_instr_ctx.h"

#include "../runtime/fd_system_ids.h"

#include "../nanopb/pb_encode.h"
#include "../nanopb/pb_decode.h"
#include "../runtime/sysvar/fd_sysvar_recent_hashes.h"

#include "../runtime/tests/generated/exec_v2.pb.h"

FD_PROTOTYPES_BEGIN

struct fd_harness_ctx {
   fd_wksp_t           * wksp;
   fd_funk_t           * funk;
   fd_exec_epoch_ctx_t * epoch_ctx;
   fd_exec_slot_ctx_t  * slot_ctx;
   fd_exec_txn_ctx_t   * txn_ctx;
   fd_acc_mgr_t        * acc_mgr;
};
typedef struct fd_harness_ctx fd_harness_ctx_t;

/* Dump execution state to protobuf format that capture the execution
   environment. */

int
fd_harness_dump_instr( fd_exec_instr_ctx_t * instr_ctx );

int
fd_harness_dump_txn( fd_exec_txn_ctx_t * txn_ctx );

int
fd_harness_dump_slot( fd_exec_slot_ctx_t * slot_ctx );

int 
fd_harness_dump_runtime( fd_exec_epoch_ctx_t * epoch_ctx );

/* Restore execution state from protobuf format. Outputs a protobuf
   that captures the execution environment effects. */

int
fd_harness_exec_instr( uchar const * filename, ulong file_sz );

int
fd_harness_exec_txn( uchar const * filename, ulong file_sz );

int
fd_harness_exec_slot( uchar const * filename, ulong file_sz );

int
fd_harness_exec_runtime( uchar const * filename, ulong file_sz );

/* TODO: converters from old format to new */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_harness_fd_harness_h */
