#ifndef HEADER_fd_src_flamenco_runtime_native_program_util_h
#define HEADER_fd_src_flamenco_runtime_native_program_util_h

#include "../../fd_flamenco_base.h"
#include "../context/fd_exec_instr_ctx.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../context/fd_exec_txn_ctx.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"
#include "../fd_system_ids.h"

#include "../sysvar/fd_sysvar_clock.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../sysvar/fd_sysvar_stake_history.h"

#define FD_DEBUG_MODE 0

#ifndef FD_DEBUG_MODE
#define FD_DEBUG( ... ) __VA_ARGS__
#else
#define FD_DEBUG( ... )
#endif

#define FD_PROGRAM_OK FD_EXECUTOR_INSTR_SUCCESS

FD_PROTOTYPES_BEGIN

/**********************************************************************/
/* mod instruction                                                    */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/instruction.rs#L519
static inline int
fd_ulong_checked_add( ulong a, ulong b, ulong * out ) {
  bool cf = __builtin_uaddl_overflow( a, b, out );
  return fd_int_if( cf, FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS, FD_PROGRAM_OK );
}

// https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/instruction.rs#L519
static inline int FD_FN_UNUSED
fd_ulong_checked_sub( ulong a, ulong b, ulong * out ) {
  bool cf = __builtin_usubl_overflow( a, b, out );
  return fd_int_if( cf, FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS, FD_PROGRAM_OK );
}

static inline ulong
fd_ulong_checked_add_expect( ulong a, ulong b, char const * expect ) {
  ulong out = ULONG_MAX;
  if( FD_UNLIKELY( fd_ulong_checked_add( a, b, &out ) ) ) { FD_LOG_ERR( ( expect ) ); }
  return out;
}

static inline ulong
fd_ulong_checked_sub_expect( ulong a, ulong b, char const * expect ) {
  ulong out = ULONG_MAX;
  if( FD_UNLIKELY( fd_ulong_checked_sub( a, b, &out ) ) ) { FD_LOG_ERR( ( expect ) ); }
  return out;
}

/**********************************************************************/
/* impl BorrowedAccount                                               */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L841
static inline int
fd_borrowed_account_checked_add_lamports( fd_borrowed_account_t * self, ulong lamports ) {
  // FIXME suppress warning
  ulong temp;
  int   rc = fd_int_if( __builtin_uaddl_overflow( self->meta->info.lamports, lamports, &temp ),
                      FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW,
                      FD_PROGRAM_OK );
  self->meta->info.lamports = temp;
  return rc;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_native_program_util_h */
