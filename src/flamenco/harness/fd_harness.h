#ifndef HEADER_fd_src_flamenco_harness_fd_harness_dump_h
#define HEADER_fd_src_flamenco_harness_fd_harness_dump_h

#include "../fd_flamenco.h"

#include "../nanopb/pb_firedancer.h"
#include "../nanopb/pb_encode.h"
#include "../nanopb/pb_decode.h"

#include "../runtime/fd_executor.h"
#include "../runtime/fd_account.h"
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

int
fd_harness_dump_instr( fd_exec_txn_ctx_t const * txn_ctx, 
                       fd_instr_info_t   const * instr_info, 
                       ushort                    instr_idx );

int
fd_harness_exec_instr( uchar const * file_buf, ulong file_sz );

int
fd_harness_convert_legacy_instr( uchar const * file_buf, ulong file_sz );

int
fd_harness_dump_txn( fd_exec_txn_ctx_t * txn_ctx );

int
fd_harness_dump_slot( fd_exec_slot_ctx_t * slot_ctx );

int 
fd_harness_dump_runtime( fd_exec_epoch_ctx_t * epoch_ctx );

int
fd_harness_exec_txn( uchar const * filename, ulong file_sz );

int
fd_harness_exec_slot( uchar const * filename, ulong file_sz );

int
fd_harness_exec_runtime( uchar const * filename, ulong file_sz );

/* TODO: converters from old format to new */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_harness_fd_harness_h */
