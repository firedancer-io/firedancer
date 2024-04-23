#ifndef HEADER_fd_src_flamenco_runtime_native_program_util_h
#define HEADER_fd_src_flamenco_runtime_native_program_util_h

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"

#define FD_DEBUG_MODE 0

#ifndef FD_DEBUG_MODE
#define FD_DEBUG( ... ) __VA_ARGS__
#else
#define FD_DEBUG( ... )
#endif

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

/**********************************************************************/
/* impl BorrowedAccount                                               */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L841
static inline int
fd_borrowed_account_checked_add_lamports( fd_borrowed_account_t * self,
                                          ulong                   lamports ) {
  // FIXME suppress warning
  ulong temp;
  int   rc = fd_int_if( __builtin_uaddl_overflow( self->meta->info.lamports, lamports, &temp ),
                      FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW,
                      FD_EXECUTOR_INSTR_SUCCESS );
  self->meta->info.lamports = temp;
  return rc;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_native_program_util_h */
