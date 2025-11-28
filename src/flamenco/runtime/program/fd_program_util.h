#ifndef HEADER_fd_src_flamenco_runtime_program_fd_program_util_h
#define HEADER_fd_src_flamenco_runtime_program_fd_program_util_h

#include "../../fd_flamenco_base.h"
#include "../fd_executor_err.h"

FD_PROTOTYPES_BEGIN

/**********************************************************************/
/* mod instruction                                                    */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/instruction.rs#L519
static inline int
fd_ulong_checked_add( ulong a, ulong b, ulong * out ) {
  int cf = __builtin_uaddl_overflow( a, b, out );
  return fd_int_if( cf, FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS, FD_EXECUTOR_INSTR_SUCCESS );
}

// https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/instruction.rs#L519
static inline int FD_FN_UNUSED
fd_ulong_checked_sub( ulong a, ulong b, ulong * out ) {
  int cf = __builtin_usubl_overflow( a, b, out );
  return fd_int_if( cf, FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS, FD_EXECUTOR_INSTR_SUCCESS );
}

static inline ulong
fd_ulong_checked_add_expect( ulong a, ulong b, char const * expect ) {
  ulong out = ULONG_MAX;
  if( FD_UNLIKELY( fd_ulong_checked_add( a, b, &out ) ) ) { FD_LOG_ERR(( "%s", expect )); }
  return out;
}

static inline ulong
fd_ulong_checked_sub_expect( ulong a, ulong b, char const * expect ) {
  ulong out = ULONG_MAX;
  if( FD_UNLIKELY( fd_ulong_checked_sub( a, b, &out ) ) ) { FD_LOG_ERR(( "%s", expect )); }
  return out;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_program_util_h */
