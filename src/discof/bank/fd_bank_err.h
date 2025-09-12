#ifndef HEADER_fd_src_discof_bank_fd_bank_err_h
#define HEADER_fd_src_discof_bank_fd_bank_err_h

#include "../../util/log/fd_log.h"
#include "../../flamenco/runtime/fd_runtime_err.h"

#define FD_BANK_EXECUTE_SUCCESS                                     0

/* Preflight and execution errors.  This is just instruction error,
   which can occur both when loading the transaction, and when executing
   it.  When loading, it occurs when executing the compute budget
   program, or verifying precompiles. */
#define FD_BANK_TXN_ERR_INSTRUCTION_ERROR                          -1

/* Preflight errors.  These are errors in validation before we begin
   actually executing the transaction in the virtual machine. */
#define FD_BANK_TXN_ERR_ACCOUNT_NOT_FOUND                          -2 /* The transaction fee payer address was not found */
#define FD_BANK_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND                  -3 /* A program account referenced by the transaction was not found */
#define FD_BANK_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE                 -4 /* The transaction fee payer did not have balance to pay the fee */
#define FD_BANK_TXN_ERR_INVALID_ACCOUNT_FOR_FEE                    -5 /* The transaction fee payer account is not owned by the system program, or has data that is not a nonce */
#define FD_BANK_TXN_ERR_ALREADY_PROCESSED                          -6 /* The transaction has already been processed in a recent block */
#define FD_BANK_TXN_ERR_BLOCKHASH_NOT_FOUND                        -7 /* The transaction references a blockhash that is not recent, or advances a nonce with the wrong value */
#define FD_BANK_TXN_ERR_INVALID_PROGRAM_FOR_EXECUTION              -8 /* A program account referenced by the transaction was no executable. TODO: No longer needed with SIMD-0162 */
#define FD_BANK_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND             -9 /* The transaction references an ALUT account that does not exist or is inactive */
#define FD_BANK_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_OWNER        -10 /* The transaction references an ALUT account that is not owned by the ALUT program account */
#define FD_BANK_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA         -11 /* The transaction references an ALUT account that contains data which is not a valid ALUT */
#define FD_BANK_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX        -12 /* The transaction references an account offset from the ALUT which does not exist */
#define FD_BANK_TXN_ERR_MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED    -13 /* The total account data size of the loaded accounts exceeds the consensus limit */
#define FD_BANK_TXN_ERR_DUPLICATE_INSTRUCTION                     -14 /* A compute budget program instruction was invoked more than once */
#define FD_BANK_TXN_ERR_INVALID_LOADED_ACCOUNTS_DATA_SIZE_LIMIT   -15 /* The compute budget program was invoked and set the loaded accounts data size to zero */

/* Preflight errors during replay.  These are errors in validation
   before we begin executing the transaction, which can only occur
   during replay, as such transactions do not make it to execution when
   we are leader. */
#define FD_BANK_TXN_ERR_ACCOUNT_IN_USE                            -16 /* The transaction conflicts with another transaction in the microblock. TODO: No longer possible with smart dispatcher */
#define FD_BANK_TXN_ERR_ACCOUNT_LOADED_TWICE                      -17 /* The transaction references the same account twice */
#define FD_BANK_TXN_ERR_SIGNATURE_FAILURE                         -18 /* The transaction had an invalid signature */
#define FD_BANK_TXN_ERR_TOO_MANY_ACCOUNT_LOCKS                    -19 /* The transaction references too many accounts. TODO: No longer possible with smart dispatcher */

/* Execution errors.  These are errors which occur during actual
   execution of the transaction, after it has been validated. */
#define FD_BANK_TXN_ERR_INSUFFICIENT_FUNDS_FOR_RENT               -20 /* The transaction would leave an account with a lower balance than the rent-exempt minimum */
#define FD_BANK_TXN_ERR_UNBALANCED_TRANSACTION                    -21 /* The total referenced account lamports before and after the transaction was unbalanced */

/* Errors that aren't returned by the runtime execution itself, but are
   used by bank as an additional reason transactions might fail. */
#define FD_BANK_TXN_ERR_BUNDLE_PEER                               -22 /* The transaction was part of a bundle and an earlier transaction in the bundle failed */

/* Marker for the lowest error number, must be updated when new errors
   are added. */
#define FD_BANK_TXN_ERR_LAST                                      -22

static inline int
fd_bank_err_from_runtime_err( int err ) {
   switch( err ) {
      case FD_RUNTIME_EXECUTE_SUCCESS:                                 return FD_BANK_EXECUTE_SUCCESS;

      case FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR:                       return FD_BANK_TXN_ERR_INSTRUCTION_ERROR;

      case FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND:                       return FD_BANK_TXN_ERR_ACCOUNT_NOT_FOUND;
      case FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND:               return FD_BANK_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND;
      case FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE:              return FD_BANK_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE;
      case FD_RUNTIME_TXN_ERR_INVALID_ACCOUNT_FOR_FEE:                 return FD_BANK_TXN_ERR_INVALID_ACCOUNT_FOR_FEE;
      case FD_RUNTIME_TXN_ERR_ALREADY_PROCESSED:                       return FD_BANK_TXN_ERR_ALREADY_PROCESSED;
      case FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND:                     return FD_BANK_TXN_ERR_BLOCKHASH_NOT_FOUND;
      case FD_RUNTIME_TXN_ERR_INVALID_PROGRAM_FOR_EXECUTION:           return FD_BANK_TXN_ERR_INVALID_PROGRAM_FOR_EXECUTION;
      case FD_RUNTIME_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND:          return FD_BANK_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND;
      case FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_OWNER:      return FD_BANK_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_OWNER;
      case FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA:       return FD_BANK_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA;
      case FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX:      return FD_BANK_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX;
      case FD_RUNTIME_TXN_ERR_MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED:  return FD_BANK_TXN_ERR_MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED;
      case FD_RUNTIME_TXN_ERR_DUPLICATE_INSTRUCTION:                   return FD_BANK_TXN_ERR_DUPLICATE_INSTRUCTION;
      case FD_RUNTIME_TXN_ERR_INVALID_LOADED_ACCOUNTS_DATA_SIZE_LIMIT: return FD_BANK_TXN_ERR_INVALID_LOADED_ACCOUNTS_DATA_SIZE_LIMIT;

      case FD_RUNTIME_TXN_ERR_ACCOUNT_IN_USE:                          return FD_BANK_TXN_ERR_ACCOUNT_IN_USE;
      case FD_RUNTIME_TXN_ERR_ACCOUNT_LOADED_TWICE:                    return FD_BANK_TXN_ERR_ACCOUNT_LOADED_TWICE;
      case FD_RUNTIME_TXN_ERR_SIGNATURE_FAILURE:                       return FD_BANK_TXN_ERR_SIGNATURE_FAILURE;
      case FD_RUNTIME_TXN_ERR_TOO_MANY_ACCOUNT_LOCKS:                  return FD_BANK_TXN_ERR_TOO_MANY_ACCOUNT_LOCKS;

      case FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_RENT:             return FD_BANK_TXN_ERR_INSUFFICIENT_FUNDS_FOR_RENT;
      case FD_RUNTIME_TXN_ERR_UNBALANCED_TRANSACTION:                  return FD_BANK_TXN_ERR_UNBALANCED_TRANSACTION;

      case FD_RUNTIME_TXN_ERR_CALL_CHAIN_TOO_DEEP:
      case FD_RUNTIME_TXN_ERR_MISSING_SIGNATURE_FOR_FEE:
      case FD_RUNTIME_TXN_ERR_INVALID_ACCOUNT_INDEX:
      case FD_RUNTIME_TXN_ERR_SANITIZE_FAILURE:
      case FD_RUNTIME_TXN_ERR_CLUSTER_MAINTENANCE:
      case FD_RUNTIME_TXN_ERR_ACCOUNT_BORROW_OUTSTANDING:
      case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_BLOCK_COST_LIMIT:
      case FD_RUNTIME_TXN_ERR_UNSUPPORTED_VERSION:
      case FD_RUNTIME_TXN_ERR_INVALID_WRITABLE_ACCOUNT:
      case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_ACCOUNT_COST_LIMIT:
      case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_ACCOUNT_DATA_BLOCK_LIMIT:
      case FD_RUNTIME_TXN_ERR_INVALID_RENT_PAYING_ACCOUNT:
      case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_VOTE_COST_LIMIT:
      case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_ACCOUNT_DATA_TOTAL_LIMIT:
      case FD_RUNTIME_TXN_ERR_RESANITIZATION_NEEDED:
      case FD_RUNTIME_TXN_ERR_PROGRAM_EXECUTION_TEMPORARILY_RESTRICTED:
      case FD_RUNTIME_TXN_ERR_PROGRAM_CACHE_HIT_MAX_LIMIT:
      default: FD_LOG_ERR(( "Unknown runtime error %d", err ));
    }

    return 0;
}

#define FD_BANK_LUT_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND     (-1)
#define FD_BANK_LUT_ERR_INVALID_ADDRESS_LOOKUP_TABLE_OWNER (-2)
#define FD_BANK_LUT_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA  (-3)
#define FD_BANK_LUT_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX (-5)

#define FD_BANK_LUT_ERR_LAST                               (-5)

static inline int
fd_bank_lut_err_from_runtime_err( int err ) {
   switch( err ) {
      case FD_RUNTIME_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND: return FD_BANK_LUT_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND;
      case FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_OWNER: return FD_BANK_LUT_ERR_INVALID_ADDRESS_LOOKUP_TABLE_OWNER;
      case FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA: return FD_BANK_LUT_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA;
      case FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX: return FD_BANK_LUT_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX;
      default: FD_LOG_ERR(( "Unknown runtime LUT error %d", err ));
   }
}

#endif /* HEADER_fd_src_discof_bank_fd_bank_err_h */
