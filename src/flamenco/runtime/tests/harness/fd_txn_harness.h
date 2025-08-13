#ifndef HEADER_fd_src_flamenco_runtime_tests_harness_fd_txn_harness_h
#define HEADER_fd_src_flamenco_runtime_tests_harness_fd_txn_harness_h

#include <assert.h>

#include "../../fd_executor.h"
#include "../../program/fd_builtin_programs.h"
#include "../../program/fd_program_cache.h"
#include "../../sysvar/fd_sysvar_last_restart_slot.h"
#include "../../sysvar/fd_sysvar_slot_hashes.h"
#include "../../sysvar/fd_sysvar_recent_hashes.h"
#include "../../sysvar/fd_sysvar_stake_history.h"
#include "../../sysvar/fd_sysvar_epoch_rewards.h"
#include "../../sysvar/fd_sysvar_clock.h"
#include "../../sysvar/fd_sysvar_epoch_schedule.h"
#include "../../sysvar/fd_sysvar_rent.h"
#include "../../../fd_flamenco.h"
#include "../../../../disco/pack/fd_pack.h"

#include "fd_harness_common.h"
#include "generated/txn.pb.h"

/* Macros to append data to construct a serialized transaction
   without exceeding bounds */
#define FD_CHECKED_ADD_TO_TXN_DATA( _begin, _cur_data, _to_add, _sz ) __extension__({ \
   if( FD_UNLIKELY( (*_cur_data)+_sz>_begin+FD_TXN_MTU ) ) return ULONG_MAX;          \
   fd_memcpy( *_cur_data, _to_add, _sz );                                             \
   *_cur_data += _sz;                                                                 \
})

#define FD_CHECKED_ADD_CU16_TO_TXN_DATA( _begin, _cur_data, _to_add ) __extension__({ \
   do {                                                                               \
      uchar _buf[3];                                                                  \
      fd_bincode_encode_ctx_t _encode_ctx = { .data = _buf, .dataend = _buf+3 };      \
      fd_bincode_compact_u16_encode( &_to_add, &_encode_ctx );                        \
      ulong _sz = (ulong) ((uchar *)_encode_ctx.data - _buf );                        \
      FD_CHECKED_ADD_TO_TXN_DATA( _begin, _cur_data, _buf, _sz );                     \
   } while(0);                                                                        \
})

FD_PROTOTYPES_BEGIN

/* Serializes a Protobuf SanitizedTransaction that can be parsed into a
   txn descriptor and returns the number of bytes consumed. Returns
   ULONG_MAX if the number of bytes read exceeds 1232 (FD_TXN_MTU).
   _txn_raw_begin is assumed to be a pre-allocated buffer of at least
   1232 bytes. */
ulong
fd_runtime_fuzz_serialize_txn( uchar *                                      txn_raw_begin,
                               fd_exec_test_sanitized_transaction_t const * tx );

/* Takes in a parsed txn descriptor to be executed against the runtime.
   Returns the spad-allocated transaction context. Writes the execution
   result to the `exec_res` pointer (assumed to be pre-allocated). */
fd_exec_txn_ctx_t *
fd_runtime_fuzz_txn_ctx_exec( fd_runtime_fuzz_runner_t * runner,
                              fd_exec_slot_ctx_t *       slot_ctx,
                              fd_txn_p_t *               txn,
                              int *                      exec_res );

/*
   Similar to fd_runtime_fuzz_instr_run, but executes a txn given txn context (input)
*/
ulong
fd_runtime_fuzz_txn_run( fd_runtime_fuzz_runner_t * runner,
                         void const *               input_,
                         void **                    output_,
                         void *                     output_buf,
                         ulong                      output_bufsz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_harness_fd_txn_harness_h */
