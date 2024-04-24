#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_err_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_err_h

#define FD_RUNTIME_EXECUTE_SUCCESS                               ( 0 )  /* Slot executed successfully */
#define FD_RUNTIME_EXECUTE_GENERIC_ERR                          ( -1 ) /* The Slot execute returned an error */

/* Transaction errors */
#define FD_RUNTIME_TXN_ERR_ACCOUNT_IN_USE                            -1
#define FD_RUNTIME_TXN_ERR_ACCOUNT_LOADED_TWICE                      -2
#define FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND                         -3
#define FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND                 -4
#define FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE                -5
#define FD_RUNTIME_TXN_ERR_INVALID_ACCOUNT_FOR_FEE                   -6
#define FD_RUNTIME_TXN_ERR_ALREADY_PROCESSED                         -7
#define FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND                       -8
#define FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR                         -9
#define FD_RUNTIME_TXN_ERR_CALL_CHAIN_TOO_DEEP                       -10
#define FD_RUNTIME_TXN_ERR_MISSING_SIGNATURE_FOR_FEE                 -11
#define FD_RUNTIME_TXN_ERR_INVALID_ACCOUNT_INDEX                     -12
#define FD_RUNTIME_TXN_ERR_SIGNATURE_FAILURE                         -13
#define FD_RUNTIME_TXN_ERR_INVALID_PROGRAM_FOR_EXECUTION             -14
#define FD_RUNTIME_TXN_ERR_SANITIZE_FAILURE                          -15
#define FD_RUNTIME_TXN_ERR_CLUSTER_MAINTENANCE                       -16
#define FD_RUNTIME_TXN_ERR_ACCOUNT_BORROW_OUTSTANDING                -17
#define FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_BLOCK_COST_LIMIT         -18
#define FD_RUNTIME_TXN_ERR_UNSUPPORTED_VERSION                       -19
#define FD_RUNTIME_TXN_ERR_INVALID_WRITABLE_ACCOUNT                  -20
#define FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_ACCOUNT_COST_LIMIT       -21
#define FD_RUNTIME_TXN_ERR_WOULD_EXCEED_ACCOUNT_DATA_BLOCK_LIMIT     -22
#define FD_RUNTIME_TXN_ERR_TOO_MANY_ACCOUNT_LOCKS                    -23
#define FD_RUNTIME_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND            -24
#define FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_OWNER        -25
#define FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA         -26
#define FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX        -27
#define FD_RUNTIME_TXN_ERR_INVALID_RENT_PAYING_ACCOUNT               -28
#define FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_VOTE_COST_LIMIT          -29
#define FD_RUNTIME_TXN_ERR_WOULD_EXCEED_ACCOUNT_DATA_TOTAL_LIMIT     -30
#define FD_RUNTIME_TXN_ERR_DUPLICATE_INSTRUCTION                     -31
#define FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_RENT               -32
#define FD_RUNTIME_TXN_ERR_MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED    -33
#define FD_RUNTIME_TXN_ERR_INVALID_LOADED_ACCOUNTS_DATA_SIZE_LIMIT   -34
#define FD_RUNTIME_TXN_ERR_RESANITIZATION_NEEDED                     -35
#define FD_RUNTIME_TXN_ERR_PROGRAM_EXECUTION_TEMPORARILY_RESTRICTED  -36
#define FD_RUNTIME_TXN_ERR_UNBALANCED_TRANSACTION                    -37

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_err_h */
