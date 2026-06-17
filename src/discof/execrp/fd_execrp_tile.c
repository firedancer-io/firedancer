#include "../execle/fd_execle_err.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../disco/metrics/fd_metrics.h"

#include "../../choreo/tower/fd_tower_serdes.h"
#include "../../discof/fd_startup.h"
#include "../../discof/replay/fd_execrp.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/fd_executor.h"
#include "../../flamenco/runtime/tests/fd_dump_pb.h"
#include "../../flamenco/progcache/fd_progcache_user.h"
#include "../../flamenco/log_collector/fd_log_collector_base.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/events/fd_event_report.h"
#include "../../disco/events/generated/fd_event_gen.h"
#include "../../flamenco/accdb/fd_accdb.h"

#include <time.h>
#include <limits.h>
#include "generated/fd_execrp_tile_seccomp.h"

/* The exec tile is responsible for executing single transactions.  The
   tile receives a parsed transaction (fd_txn_p_t) and an identifier to
   which bank to execute against (index into the bank pool).  With this,
   the exec tile is able to identify the correct bank and accounts
   database fork to execute the transaction against.  The exec tile then
   commits the results of the transaction to the accounts db and makes
   any necessary updates to the bank. */

typedef struct link_ctx {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk;
  ulong       chunk0;
  ulong       wmark;
} link_ctx_t;

struct fd_execrp_tile {
  ulong tile_idx;

  /* link-related data structures. */
  link_ctx_t            replay_in[ 1 ];
  link_ctx_t            execrp_replay_out[ 1 ]; /* TODO: Remove with solcap v2 */

  fd_sha512_t           sha_mem[ FD_TXN_ACTUAL_SIG_MAX ];
  fd_sha512_t *         sha_lj[ FD_TXN_ACTUAL_SIG_MAX ];

  /* Capture context for debugging runtime execution. */
  fd_capture_ctx_t *    capture_ctx;
  fd_capture_link_buf_t cap_execrp_out[1];

  /* Protobuf dumping context for debugging runtime execution and
     collecting seed corpora. */
  fd_dump_proto_ctx_t * dump_proto_ctx;
  fd_txn_dump_ctx_t *   txn_dump_ctx;

  fd_banks_t *    banks;
  fd_bank_t *     bank;
  fd_accdb_t *    accdb;
  fd_txncache_t * txncache;
  fd_progcache_t  progcache[1];

  ulong txn_idx;
  ulong slot;
  ulong dispatch_time_comp;

  fd_log_collector_t log_collector;

  fd_txn_in_t  txn_in;
  fd_txn_out_t txn_out;

  fd_runtime_t runtime[1];

  struct {
    ulong sigverify_cnt;
    ulong poh_hash_cnt;

    /* Ticks spent loading txn accounts */
    ulong txn_load_cum_ticks;

    /* Ticks spent validating txn invariants (e.g. status cache, fee payer) */
    ulong txn_check_cum_ticks;

    /* Ticks spent executing a txn (includes any VM time) */
    ulong txn_exec_cum_ticks;

    /* Ticks spent committing a txn (database writes) */
    ulong txn_commit_cum_ticks;

    ulong txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_CNT ];
  } metrics;

  /* If non-zero, emit one runtime_txn event per dispatched txn */
  int report_runtime_txn;

  /* FEC merkle root at txn dispatch time */
  uchar dispatch_fec_mr[ 32 ];
};

typedef struct fd_execrp_tile fd_execrp_tile_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND(   l, alignof(fd_execrp_tile_t),    sizeof(fd_execrp_tile_t)                             );
  l = FD_LAYOUT_APPEND(   l, fd_txncache_align(),          fd_txncache_footprint( tile->execrp.max_live_slots ) );
  l = FD_LAYOUT_APPEND(   l, fd_accdb_align(),             fd_accdb_footprint( tile->execrp.max_live_slots )    );
  l = FD_LAYOUT_APPEND(   l, FD_PROGCACHE_SCRATCH_ALIGN,   FD_PROGCACHE_SCRATCH_FOOTPRINT                       );

  if( FD_UNLIKELY( strlen( tile->execrp.solcap_capture ) ) ) {
    l = FD_LAYOUT_APPEND( l, fd_capture_ctx_align(),       fd_capture_ctx_footprint()                           );
  }

  if( FD_UNLIKELY( strlen( tile->execrp.dump_proto_dir ) ) ) {
    l = FD_LAYOUT_APPEND( l, alignof(fd_dump_proto_ctx_t), sizeof(fd_dump_proto_ctx_t)                          );
    l = FD_LAYOUT_APPEND( l, fd_txn_dump_context_align(),  fd_txn_dump_context_footprint()                      );
    if( FD_UNLIKELY( tile->execrp.dump_instr_to_pb || tile->execrp.dump_syscall_to_pb || tile->execrp.dump_txn_to_pb ) ) {
      l = FD_LAYOUT_APPEND( l, FD_SPAD_ALIGN,              FD_SPAD_FOOTPRINT( 1UL<<28UL )                       );
    }
  }

  return FD_LAYOUT_FINI(  l, scratch_align() );
}

static void
metrics_write( fd_execrp_tile_t * ctx ) {
  FD_MCNT_SET      ( EXECRP, SIGNATURE_VERIFIED,    ctx->metrics.sigverify_cnt );
  FD_MCNT_SET      ( EXECRP, POH_HASHED,     ctx->metrics.poh_hash_cnt  );
  FD_MCNT_ENUM_COPY( EXECRP, TXN_RESULT,   ctx->metrics.txn_result    );

  fd_progcache_metrics_t * pm = ctx->progcache->metrics;
  FD_MCNT_SET( EXECRP, PROGCACHE_LOOKUP,                 pm->lookup_cnt     );
  FD_MCNT_SET( EXECRP, PROGCACHE_HIT,                    pm->hit_cnt        );
  FD_MCNT_SET( EXECRP, PROGCACHE_MISS,                   pm->miss_cnt       );
  FD_MCNT_SET( EXECRP, PROGCACHE_OOM_HEAP,               pm->oom_heap_cnt   );
  FD_MCNT_SET( EXECRP, PROGCACHE_OOM_DESC,               pm->oom_desc_cnt   );
  FD_MCNT_SET( EXECRP, PROGCACHE_FILL,                   pm->fill_cnt       );
  FD_MCNT_SET( EXECRP, PROGCACHE_FILL_BYTES,             pm->fill_tot_sz    );
  FD_MCNT_SET( EXECRP, PROGCACHE_SPILL,                  pm->spill_cnt      );
  FD_MCNT_SET( EXECRP, PROGCACHE_SPILL_BYTES,            pm->spill_tot_sz   );
  FD_MCNT_SET( EXECRP, PROGCACHE_EVICTION,               pm->evict_cnt      );
  FD_MCNT_SET( EXECRP, PROGCACHE_EVICTION_BYTES,         pm->evict_tot_sz   );
  FD_MCNT_SET( EXECRP, PROGCACHE_DURATION_SECONDS,       pm->cum_pull_ticks );
  FD_MCNT_SET( EXECRP, PROGCACHE_LOAD_DURATION_SECONDS,  pm->cum_load_ticks );

  FD_MCNT_SET( EXECRP, TXN_REGIME_DURATION_NANOS_SETUP,  ctx->metrics.txn_load_cum_ticks+ctx->metrics.txn_check_cum_ticks );
  FD_MCNT_SET( EXECRP, TXN_REGIME_DURATION_NANOS_EXEC,   ctx->metrics.txn_exec_cum_ticks    );
  FD_MCNT_SET( EXECRP, TXN_REGIME_DURATION_NANOS_COMMIT, ctx->metrics.txn_commit_cum_ticks  );

  fd_runtime_t const * runtime = ctx->runtime;
  ulong cpi_ticks  = runtime->metrics.cpi_setup_cum_ticks +
                     runtime->metrics.cpi_commit_cum_ticks;
  ulong exec_ticks = fd_ulong_sat_sub( runtime->metrics.vm_exec_cum_ticks, cpi_ticks );
  FD_MCNT_SET( EXECRP, VM_REGIME_DURATION_NANOS_SETUP,       runtime->metrics.vm_setup_cum_ticks   );
  FD_MCNT_SET( EXECRP, VM_REGIME_DURATION_NANOS_COMMIT,      runtime->metrics.vm_commit_cum_ticks  );
  FD_MCNT_SET( EXECRP, VM_REGIME_DURATION_NANOS_SETUP_CPI,   runtime->metrics.cpi_setup_cum_ticks  );
  FD_MCNT_SET( EXECRP, VM_REGIME_DURATION_NANOS_COMMIT_CPI,  runtime->metrics.cpi_commit_cum_ticks );
  FD_MCNT_SET( EXECRP, VM_REGIME_DURATION_NANOS_INTERPRETER, exec_ticks                            );

  FD_MCNT_SET( EXECRP, CU_EXECUTED, runtime->metrics.cu_cum );

  FD_ACCDB_METRICS_WRITE( EXECRP, fd_accdb_metrics( ctx->accdb ) );
}

static inline int
fd_event_txn_err_from_txn_err( int err ) {
  switch( err ) {
    case FD_RUNTIME_EXECUTE_SUCCESS:                                  return FD_EVENT_RUNTIME_TXN_TXN_ERR_SUCCESS;
    case FD_RUNTIME_TXN_ERR_ACCOUNT_IN_USE:                           return FD_EVENT_RUNTIME_TXN_TXN_ERR_ACCOUNT_IN_USE;
    case FD_RUNTIME_TXN_ERR_ACCOUNT_LOADED_TWICE:                     return FD_EVENT_RUNTIME_TXN_TXN_ERR_ACCOUNT_LOADED_TWICE;
    case FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND:                        return FD_EVENT_RUNTIME_TXN_TXN_ERR_ACCOUNT_NOT_FOUND;
    case FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND:                return FD_EVENT_RUNTIME_TXN_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND;
    case FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE:               return FD_EVENT_RUNTIME_TXN_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE;
    case FD_RUNTIME_TXN_ERR_INVALID_ACCOUNT_FOR_FEE:                  return FD_EVENT_RUNTIME_TXN_TXN_ERR_INVALID_ACCOUNT_FOR_FEE;
    case FD_RUNTIME_TXN_ERR_ALREADY_PROCESSED:                        return FD_EVENT_RUNTIME_TXN_TXN_ERR_ALREADY_PROCESSED;
    case FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND:                      return FD_EVENT_RUNTIME_TXN_TXN_ERR_BLOCKHASH_NOT_FOUND;
    case FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR:                        return FD_EVENT_RUNTIME_TXN_TXN_ERR_INSTRUCTION_ERROR;
    case FD_RUNTIME_TXN_ERR_CALL_CHAIN_TOO_DEEP:                      return FD_EVENT_RUNTIME_TXN_TXN_ERR_CALL_CHAIN_TOO_DEEP;
    case FD_RUNTIME_TXN_ERR_MISSING_SIGNATURE_FOR_FEE:                return FD_EVENT_RUNTIME_TXN_TXN_ERR_MISSING_SIGNATURE_FOR_FEE;
    case FD_RUNTIME_TXN_ERR_INVALID_ACCOUNT_INDEX:                    return FD_EVENT_RUNTIME_TXN_TXN_ERR_INVALID_ACCOUNT_INDEX;
    case FD_RUNTIME_TXN_ERR_SIGNATURE_FAILURE:                        return FD_EVENT_RUNTIME_TXN_TXN_ERR_SIGNATURE_FAILURE;
    case FD_RUNTIME_TXN_ERR_INVALID_PROGRAM_FOR_EXECUTION:            return FD_EVENT_RUNTIME_TXN_TXN_ERR_INVALID_PROGRAM_FOR_EXECUTION;
    case FD_RUNTIME_TXN_ERR_SANITIZE_FAILURE:                         return FD_EVENT_RUNTIME_TXN_TXN_ERR_SANITIZE_FAILURE;
    case FD_RUNTIME_TXN_ERR_CLUSTER_MAINTENANCE:                      return FD_EVENT_RUNTIME_TXN_TXN_ERR_CLUSTER_MAINTENANCE;
    case FD_RUNTIME_TXN_ERR_ACCOUNT_BORROW_OUTSTANDING:               return FD_EVENT_RUNTIME_TXN_TXN_ERR_ACCOUNT_BORROW_OUTSTANDING;
    case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_BLOCK_COST_LIMIT:        return FD_EVENT_RUNTIME_TXN_TXN_ERR_WOULD_EXCEED_MAX_BLOCK_COST_LIMIT;
    case FD_RUNTIME_TXN_ERR_UNSUPPORTED_VERSION:                      return FD_EVENT_RUNTIME_TXN_TXN_ERR_UNSUPPORTED_VERSION;
    case FD_RUNTIME_TXN_ERR_INVALID_WRITABLE_ACCOUNT:                 return FD_EVENT_RUNTIME_TXN_TXN_ERR_INVALID_WRITABLE_ACCOUNT;
    case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_ACCOUNT_COST_LIMIT:      return FD_EVENT_RUNTIME_TXN_TXN_ERR_WOULD_EXCEED_MAX_ACCOUNT_COST_LIMIT;
    case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_ACCOUNT_DATA_BLOCK_LIMIT:    return FD_EVENT_RUNTIME_TXN_TXN_ERR_WOULD_EXCEED_ACCOUNT_DATA_BLOCK_LIMIT;
    case FD_RUNTIME_TXN_ERR_TOO_MANY_ACCOUNT_LOCKS:                   return FD_EVENT_RUNTIME_TXN_TXN_ERR_TOO_MANY_ACCOUNT_LOCKS;
    case FD_RUNTIME_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND:           return FD_EVENT_RUNTIME_TXN_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND;
    case FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_OWNER:       return FD_EVENT_RUNTIME_TXN_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_OWNER;
    case FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA:        return FD_EVENT_RUNTIME_TXN_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA;
    case FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX:       return FD_EVENT_RUNTIME_TXN_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX;
    case FD_RUNTIME_TXN_ERR_INVALID_RENT_PAYING_ACCOUNT:              return FD_EVENT_RUNTIME_TXN_TXN_ERR_INVALID_RENT_PAYING_ACCOUNT;
    case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_VOTE_COST_LIMIT:         return FD_EVENT_RUNTIME_TXN_TXN_ERR_WOULD_EXCEED_MAX_VOTE_COST_LIMIT;
    case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_ACCOUNT_DATA_TOTAL_LIMIT:    return FD_EVENT_RUNTIME_TXN_TXN_ERR_WOULD_EXCEED_ACCOUNT_DATA_TOTAL_LIMIT;
    case FD_RUNTIME_TXN_ERR_DUPLICATE_INSTRUCTION:                    return FD_EVENT_RUNTIME_TXN_TXN_ERR_DUPLICATE_INSTRUCTION;
    case FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_RENT:              return FD_EVENT_RUNTIME_TXN_TXN_ERR_INSUFFICIENT_FUNDS_FOR_RENT;
    case FD_RUNTIME_TXN_ERR_MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED:   return FD_EVENT_RUNTIME_TXN_TXN_ERR_MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED;
    case FD_RUNTIME_TXN_ERR_INVALID_LOADED_ACCOUNTS_DATA_SIZE_LIMIT:  return FD_EVENT_RUNTIME_TXN_TXN_ERR_INVALID_LOADED_ACCOUNTS_DATA_SIZE_LIMIT;
    case FD_RUNTIME_TXN_ERR_RESANITIZATION_NEEDED:                    return FD_EVENT_RUNTIME_TXN_TXN_ERR_RESANITIZATION_NEEDED;
    case FD_RUNTIME_TXN_ERR_PROGRAM_EXECUTION_TEMPORARILY_RESTRICTED: return FD_EVENT_RUNTIME_TXN_TXN_ERR_PROGRAM_EXECUTION_TEMPORARILY_RESTRICTED;
    case FD_RUNTIME_TXN_ERR_UNBALANCED_TRANSACTION:                   return FD_EVENT_RUNTIME_TXN_TXN_ERR_UNBALANCED_TRANSACTION;
    case FD_RUNTIME_TXN_ERR_PROGRAM_CACHE_HIT_MAX_LIMIT:              return FD_EVENT_RUNTIME_TXN_TXN_ERR_PROGRAM_CACHE_HIT_MAX_LIMIT;
    case FD_RUNTIME_TXN_ERR_COMMIT_CANCELLED:                         return FD_EVENT_RUNTIME_TXN_TXN_ERR_COMMIT_CANCELLED;
    case FD_RUNTIME_TXN_ERR_BUNDLE_PEER:                              return FD_EVENT_RUNTIME_TXN_TXN_ERR_BUNDLE_PEER;
    case FD_RUNTIME_TXN_ERR_BLOCKHASH_NONCE_ALREADY_ADVANCED:         return FD_EVENT_RUNTIME_TXN_TXN_ERR_BLOCKHASH_NONCE_ALREADY_ADVANCED;
    case FD_RUNTIME_TXN_ERR_BLOCKHASH_FAIL_ADVANCE_NONCE_INSTR:       return FD_EVENT_RUNTIME_TXN_TXN_ERR_BLOCKHASH_FAIL_ADVANCE_NONCE_INSTR;
    case FD_RUNTIME_TXN_ERR_BLOCKHASH_FAIL_WRONG_NONCE:               return FD_EVENT_RUNTIME_TXN_TXN_ERR_BLOCKHASH_FAIL_WRONG_NONCE;
    default:                                                          return 0;
  }
}

static inline int
fd_event_exec_err_from_exec_err( int err ) {
  switch( err ) {
    case FD_EXECUTOR_INSTR_SUCCESS:                                return FD_EVENT_RUNTIME_TXN_EXEC_ERR_SUCCESS;
    case FD_EXECUTOR_INSTR_ERR_GENERIC_ERR:                        return FD_EVENT_RUNTIME_TXN_EXEC_ERR_GENERIC_ERR;
    case FD_EXECUTOR_INSTR_ERR_INVALID_ARG:                        return FD_EVENT_RUNTIME_TXN_EXEC_ERR_INVALID_ARG;
    case FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA:                 return FD_EVENT_RUNTIME_TXN_EXEC_ERR_INVALID_INSTR_DATA;
    case FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA:                   return FD_EVENT_RUNTIME_TXN_EXEC_ERR_INVALID_ACC_DATA;
    case FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL:                 return FD_EVENT_RUNTIME_TXN_EXEC_ERR_ACC_DATA_TOO_SMALL;
    case FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS:                 return FD_EVENT_RUNTIME_TXN_EXEC_ERR_INSUFFICIENT_FUNDS;
    case FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID:               return FD_EVENT_RUNTIME_TXN_EXEC_ERR_INCORRECT_PROGRAM_ID;
    case FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE:         return FD_EVENT_RUNTIME_TXN_EXEC_ERR_MISSING_REQUIRED_SIGNATURE;
    case FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED:            return FD_EVENT_RUNTIME_TXN_EXEC_ERR_ACC_ALREADY_INITIALIZED;
    case FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT:              return FD_EVENT_RUNTIME_TXN_EXEC_ERR_UNINITIALIZED_ACCOUNT;
    case FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR:                   return FD_EVENT_RUNTIME_TXN_EXEC_ERR_UNBALANCED_INSTR;
    case FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID:                return FD_EVENT_RUNTIME_TXN_EXEC_ERR_MODIFIED_PROGRAM_ID;
    case FD_EXECUTOR_INSTR_ERR_EXTERNAL_ACCOUNT_LAMPORT_SPEND:     return FD_EVENT_RUNTIME_TXN_EXEC_ERR_EXTERNAL_ACCOUNT_LAMPORT_SPEND;
    case FD_EXECUTOR_INSTR_ERR_EXTERNAL_DATA_MODIFIED:             return FD_EVENT_RUNTIME_TXN_EXEC_ERR_EXTERNAL_DATA_MODIFIED;
    case FD_EXECUTOR_INSTR_ERR_READONLY_LAMPORT_CHANGE:            return FD_EVENT_RUNTIME_TXN_EXEC_ERR_READONLY_LAMPORT_CHANGE;
    case FD_EXECUTOR_INSTR_ERR_READONLY_DATA_MODIFIED:             return FD_EVENT_RUNTIME_TXN_EXEC_ERR_READONLY_DATA_MODIFIED;
    case FD_EXECUTOR_INSTR_ERR_DUPLICATE_ACCOUNT_IDX:              return FD_EVENT_RUNTIME_TXN_EXEC_ERR_DUPLICATE_ACCOUNT_IDX;
    case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_MODIFIED:                return FD_EVENT_RUNTIME_TXN_EXEC_ERR_EXECUTABLE_MODIFIED;
    case FD_EXECUTOR_INSTR_ERR_RENT_EPOCH_MODIFIED:                return FD_EVENT_RUNTIME_TXN_EXEC_ERR_RENT_EPOCH_MODIFIED;
    case FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS:                return FD_EVENT_RUNTIME_TXN_EXEC_ERR_NOT_ENOUGH_ACC_KEYS;
    case FD_EXECUTOR_INSTR_ERR_ACC_DATA_SIZE_CHANGED:              return FD_EVENT_RUNTIME_TXN_EXEC_ERR_ACC_DATA_SIZE_CHANGED;
    case FD_EXECUTOR_INSTR_ERR_ACC_NOT_EXECUTABLE:                 return FD_EVENT_RUNTIME_TXN_EXEC_ERR_ACC_NOT_EXECUTABLE;
    case FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED:                  return FD_EVENT_RUNTIME_TXN_EXEC_ERR_ACC_BORROW_FAILED;
    case FD_EXECUTOR_INSTR_ERR_ACC_BORROW_OUTSTANDING:             return FD_EVENT_RUNTIME_TXN_EXEC_ERR_ACC_BORROW_OUTSTANDING;
    case FD_EXECUTOR_INSTR_ERR_DUPLICATE_ACCOUNT_OUT_OF_SYNC:      return FD_EVENT_RUNTIME_TXN_EXEC_ERR_DUPLICATE_ACCOUNT_OUT_OF_SYNC;
    case FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR:                         return FD_EVENT_RUNTIME_TXN_EXEC_ERR_CUSTOM_ERR;
    case FD_EXECUTOR_INSTR_ERR_INVALID_ERR:                        return FD_EVENT_RUNTIME_TXN_EXEC_ERR_INVALID_ERR;
    case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_DATA_MODIFIED:           return FD_EVENT_RUNTIME_TXN_EXEC_ERR_EXECUTABLE_DATA_MODIFIED;
    case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE:          return FD_EVENT_RUNTIME_TXN_EXEC_ERR_EXECUTABLE_LAMPORT_CHANGE;
    case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_ACCOUNT_NOT_RENT_EXEMPT: return FD_EVENT_RUNTIME_TXN_EXEC_ERR_EXECUTABLE_ACCOUNT_NOT_RENT_EXEMPT;
    case FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID:             return FD_EVENT_RUNTIME_TXN_EXEC_ERR_UNSUPPORTED_PROGRAM_ID;
    case FD_EXECUTOR_INSTR_ERR_CALL_DEPTH:                         return FD_EVENT_RUNTIME_TXN_EXEC_ERR_CALL_DEPTH;
    case FD_EXECUTOR_INSTR_ERR_MISSING_ACC:                        return FD_EVENT_RUNTIME_TXN_EXEC_ERR_MISSING_ACC;
    case FD_EXECUTOR_INSTR_ERR_REENTRANCY_NOT_ALLOWED:             return FD_EVENT_RUNTIME_TXN_EXEC_ERR_REENTRANCY_NOT_ALLOWED;
    case FD_EXECUTOR_INSTR_ERR_MAX_SEED_LENGTH_EXCEEDED:           return FD_EVENT_RUNTIME_TXN_EXEC_ERR_MAX_SEED_LENGTH_EXCEEDED;
    case FD_EXECUTOR_INSTR_ERR_INVALID_SEEDS:                      return FD_EVENT_RUNTIME_TXN_EXEC_ERR_INVALID_SEEDS;
    case FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC:                    return FD_EVENT_RUNTIME_TXN_EXEC_ERR_INVALID_REALLOC;
    case FD_EXECUTOR_INSTR_ERR_COMPUTE_BUDGET_EXCEEDED:            return FD_EVENT_RUNTIME_TXN_EXEC_ERR_COMPUTE_BUDGET_EXCEEDED;
    case FD_EXECUTOR_INSTR_ERR_PRIVILEGE_ESCALATION:               return FD_EVENT_RUNTIME_TXN_EXEC_ERR_PRIVILEGE_ESCALATION;
    case FD_EXECUTOR_INSTR_ERR_PROGRAM_ENVIRONMENT_SETUP_FAILURE:  return FD_EVENT_RUNTIME_TXN_EXEC_ERR_PROGRAM_ENVIRONMENT_SETUP_FAILURE;
    case FD_EXECUTOR_INSTR_ERR_PROGRAM_FAILED_TO_COMPLETE:         return FD_EVENT_RUNTIME_TXN_EXEC_ERR_PROGRAM_FAILED_TO_COMPLETE;
    case FD_EXECUTOR_INSTR_ERR_PROGRAM_FAILED_TO_COMPILE:          return FD_EVENT_RUNTIME_TXN_EXEC_ERR_PROGRAM_FAILED_TO_COMPILE;
    case FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE:                      return FD_EVENT_RUNTIME_TXN_EXEC_ERR_ACC_IMMUTABLE;
    case FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY:                return FD_EVENT_RUNTIME_TXN_EXEC_ERR_INCORRECT_AUTHORITY;
    case FD_EXECUTOR_INSTR_ERR_BORSH_IO_ERROR:                     return FD_EVENT_RUNTIME_TXN_EXEC_ERR_BORSH_IO_ERROR;
    case FD_EXECUTOR_INSTR_ERR_ACC_NOT_RENT_EXEMPT:                return FD_EVENT_RUNTIME_TXN_EXEC_ERR_ACC_NOT_RENT_EXEMPT;
    case FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER:                  return FD_EVENT_RUNTIME_TXN_EXEC_ERR_INVALID_ACC_OWNER;
    case FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW:                return FD_EVENT_RUNTIME_TXN_EXEC_ERR_ARITHMETIC_OVERFLOW;
    case FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR:                 return FD_EVENT_RUNTIME_TXN_EXEC_ERR_UNSUPPORTED_SYSVAR;
    case FD_EXECUTOR_INSTR_ERR_ILLEGAL_OWNER:                      return FD_EVENT_RUNTIME_TXN_EXEC_ERR_ILLEGAL_OWNER;
    case FD_EXECUTOR_INSTR_ERR_MAX_ACCS_DATA_ALLOCS_EXCEEDED:      return FD_EVENT_RUNTIME_TXN_EXEC_ERR_MAX_ACCS_DATA_ALLOCS_EXCEEDED;
    case FD_EXECUTOR_INSTR_ERR_MAX_ACCS_EXCEEDED:                  return FD_EVENT_RUNTIME_TXN_EXEC_ERR_MAX_ACCS_EXCEEDED;
    case FD_EXECUTOR_INSTR_ERR_MAX_INSN_TRACE_LENS_EXCEEDED:       return FD_EVENT_RUNTIME_TXN_EXEC_ERR_MAX_INSN_TRACE_LENS_EXCEEDED;
    case FD_EXECUTOR_INSTR_ERR_BUILTINS_MUST_CONSUME_CUS:          return FD_EVENT_RUNTIME_TXN_EXEC_ERR_BUILTINS_MUST_CONSUME_CUS;
    default:                                                       return 0;
  }
}

static inline int
fd_event_exec_err_kind_from_exec_err_kind( int kind ) {
  switch( kind ) {
    case FD_EXECUTOR_ERR_KIND_NONE:    return FD_EVENT_RUNTIME_TXN_EXEC_ERR_KIND_NONE;
    case FD_EXECUTOR_ERR_KIND_EBPF:    return FD_EVENT_RUNTIME_TXN_EXEC_ERR_KIND_EBPF;
    case FD_EXECUTOR_ERR_KIND_SYSCALL: return FD_EVENT_RUNTIME_TXN_EXEC_ERR_KIND_SYSCALL;
    case FD_EXECUTOR_ERR_KIND_INSTR:   return FD_EVENT_RUNTIME_TXN_EXEC_ERR_KIND_INSTR;
    default:                           return 0;
  }
}

static void
report_runtime_txn( fd_execrp_tile_t const * ctx ) {
  if( FD_LIKELY( !fd_event_tl ) ) return;
  fd_txn_in_t  const * txn_in  = &ctx->txn_in;
  fd_txn_out_t const * txn_out = &ctx->txn_out;
  fd_bank_t    const * bank    = ctx->bank;
  if( FD_UNLIKELY( !txn_in->txn || !bank ) ) return;

  fd_event_runtime_txn_t ev = {0};

  /* Identity */
  uchar const *    payload = (uchar const *)txn_in->txn->payload;
  fd_txn_t const * txn_d   = TXN( txn_in->txn );
  fd_memcpy( ev.signature, payload + txn_d->signature_off, 64UL );
  fd_memcpy( ev.blockhash, txn_out->details.blockhash.uc,  32UL );
  if( FD_LIKELY( txn_out->accounts.cnt>0UL ) ) {
    fd_memcpy( ev.fee_payer, txn_out->accounts.keys[ 0 ].uc, 32UL );
  }
  fd_memcpy( ev.dispatch_fec_mr, ctx->dispatch_fec_mr, 32UL );

  ev.bank_seq = bank->bank_seq;
  ev.slot     = bank->f.slot;
  ev.epoch    = bank->f.epoch;

  /* Flags */
  ev.is_simple_vote = !!txn_out->details.is_simple_vote;
  ev.is_bundle      = !!txn_in->bundle.is_bundle;
  ev.is_committable = !!txn_out->err.is_committable;
  ev.is_fees_only   = !!txn_out->err.is_fees_only;

  /* Errors */
  ev.txn_err       = fd_event_txn_err_from_txn_err            ( txn_out->err.txn_err       );
  ev.exec_err      = fd_event_exec_err_from_exec_err          ( txn_out->err.exec_err      );
  ev.exec_err_kind = fd_event_exec_err_kind_from_exec_err_kind( txn_out->err.exec_err_kind );
  ev.exec_err_idx  = (uint)txn_out->err.exec_err_idx;
  ev.custom_err    = txn_out->err.custom_err;

  /* Compute budget */
  fd_compute_budget_details_t const * cb = &txn_out->details.compute_budget;
  ev.compute_unit_limit              = cb->compute_unit_limit;
  ev.compute_unit_price              = cb->compute_unit_price;
  ev.compute_units_consumed          = (cb->compute_unit_limit > cb->compute_meter)
                                         ? cb->compute_unit_limit - cb->compute_meter : 0UL;
  ev.heap_size                       = cb->heap_size;
  ev.num_builtin_instrs              = cb->num_builtin_instrs;
  ev.num_non_builtin_instrs          = cb->num_non_builtin_instrs;
  ev.loaded_accounts_data_size       = txn_out->details.loaded_accounts_data_size;
  ev.loaded_accounts_data_size_limit = cb->loaded_accounts_data_size_limit;
  long resize_delta = txn_out->details.accounts_resize_delta;
  ev.accounts_resize_is_negative     = resize_delta < 0L;
  ev.accounts_resize_delta           = (ulong)( resize_delta < 0L ? -resize_delta : resize_delta );

  /* Fees */
  ev.execution_fee   = txn_out->details.execution_fee;
  ev.priority_fee    = txn_out->details.priority_fee;
  ev.tips            = txn_out->details.tips;
  ev.signature_count = txn_out->details.signature_count;

  /* Cost-tracker (non-vote only) */
  if( txn_out->details.txn_cost.type==FD_TXN_COST_TYPE_TRANSACTION ) {
    fd_usage_cost_details_t const * c = &txn_out->details.txn_cost.transaction;
    ev.cost_signature                    = c->signature_cost;
    ev.cost_write_lock                   = c->write_lock_cost;
    ev.cost_data_bytes                   = c->data_bytes_cost;
    ev.cost_programs_execution           = c->programs_execution_cost;
    ev.cost_loaded_accounts_data_size    = c->loaded_accounts_data_size_cost;
    ev.cost_allocated_accounts_data_size = c->allocated_accounts_data_size;
  }

  /* account_diffs: walk writable accounts, compare prior vs current */
  ulong diff_cnt = 0UL;
  for( ulong i=0UL; i<txn_out->accounts.cnt; i++ ) {
    if( diff_cnt>=128UL ) break;
    fd_acc_t const * acc = txn_out->accounts.account[ i ];
    if( !acc->_writable ) continue;

    int changed = ( acc->prior_lamports   != acc->lamports   ) ||
                  ( acc->prior_executable != acc->executable ) ||
                  ( acc->prior_data_len   != acc->data_len   ) ||
                  ( memcmp( acc->prior_owner, acc->owner, 32UL )!=0 );
    if( !changed && acc->prior_data && acc->data &&
        memcmp( acc->prior_data, acc->data, acc->data_len )!=0 ) {
      changed = 1;
    }
    if( !changed ) continue;

    fd_event_runtime_txn_account_diffs_t * d = &ev.account_diffs[ diff_cnt++ ];
    fd_memcpy( d->pubkey, txn_out->accounts.keys[ i ].uc, 32UL );
    fd_memcpy( d->owner,  acc->owner,                     32UL );
    d->lamports      = acc->lamports;
    d->prev_lamports = acc->prior_lamports;
    d->data_sz       = acc->data_len;
    d->prev_data_sz  = acc->prior_data_len;
    d->is_executable   = !!acc->executable;
    d->is_stake_update = !!txn_out->accounts.stake_update[ i ];
    d->is_vote_update  = !!txn_out->accounts.vote_update [ i ];
    d->is_new_vote     = !!txn_out->accounts.new_vote    [ i ];
    d->is_rm_vote      = !!txn_out->accounts.rm_vote     [ i ];
  }
  ev.account_diffs_cnt = diff_cnt;

  /* writable / readonly account lists */
  ulong w_cnt = 0UL, r_cnt = 0UL;
  for( ulong i=0UL; i<txn_out->accounts.cnt; i++ ) {
    fd_acc_t const * acc = txn_out->accounts.account[ i ];
    if( acc->_writable ) {
      if( w_cnt<64UL ) fd_memcpy( ev.writable_accounts[ w_cnt++ ].pubkey, txn_out->accounts.keys[ i ].uc, 32UL );
    } else {
      if( r_cnt<64UL ) fd_memcpy( ev.readonly_accounts[ r_cnt++ ].pubkey, txn_out->accounts.keys[ i ].uc, 32UL );
    }
  }
  ev.writable_accounts_cnt = w_cnt;
  ev.readonly_accounts_cnt = r_cnt;

  /* program_ids: walk top-level instructions, dedupe in first-occurrence order */
  ulong p_cnt = 0UL;
  for( ushort ii=0; ii<txn_d->instr_cnt; ii++ ) {
    if( p_cnt>=64UL ) break;
    uchar pid_idx = txn_d->instr[ ii ].program_id;
    if( (ulong)pid_idx>=txn_out->accounts.cnt ) continue;
    uchar const * pid = txn_out->accounts.keys[ pid_idx ].uc;
    int seen = 0;
    for( ulong j=0UL; j<p_cnt; j++ ) {
      if( memcmp( ev.program_ids[ j ].pubkey, pid, 32UL )==0 ) { seen = 1; break; }
    }
    if( !seen ) fd_memcpy( ev.program_ids[ p_cnt++ ].pubkey, pid, 32UL );
  }
  ev.program_ids_cnt = p_cnt;

  fd_event_report_runtime_txn( &ev );
}

static void
publish_txn_finalized_msg( fd_execrp_tile_t *  ctx,
                           fd_stem_context_t * stem ) {
  fd_execrp_task_done_msg_t * msg  = fd_chunk_to_laddr( ctx->execrp_replay_out->mem, ctx->execrp_replay_out->chunk );
  msg->bank_idx                  = ctx->bank->idx;
  msg->txn_exec->txn_idx         = ctx->txn_idx;
  msg->txn_exec->is_committable  = ctx->txn_out.err.is_committable;
  msg->txn_exec->is_fees_only    = ctx->txn_out.err.is_fees_only;
  msg->txn_exec->txn_err         = ctx->txn_out.err.txn_err;
  msg->txn_exec->slot            = ctx->slot;
  msg->txn_exec->start_shred_idx = ctx->txn_in.txn->start_shred_idx;
  msg->txn_exec->end_shred_idx   = ctx->txn_in.txn->end_shred_idx;

  if( FD_UNLIKELY( !ctx->txn_out.details.is_simple_vote || !fd_txn_parse_simple_vote( TXN( ctx->txn_in.txn ), ctx->txn_in.txn->payload, msg->txn_exec->vote.identity, msg->txn_exec->vote.vote_acct, &msg->txn_exec->vote.slot ) ) ) {
    msg->txn_exec->vote.slot       = ULONG_MAX;
    *msg->txn_exec->vote.identity  = (fd_pubkey_t){ 0 };
    *msg->txn_exec->vote.vote_acct = (fd_pubkey_t){ 0 };
  }

  if( FD_UNLIKELY( !msg->txn_exec->is_committable ) ) {
    uchar * signature = (uchar *)ctx->txn_in.txn->payload + TXN( ctx->txn_in.txn )->signature_off;
    FD_BASE58_ENCODE_64_BYTES( signature, signature_b58 );
    FD_LOG_WARNING(( "block marked dead (slot=%lu) because of invalid transaction (signature=%s) (txn_err=%d)", ctx->slot, signature_b58, ctx->txn_out.err.txn_err ));
  }

  fd_stem_publish( stem, ctx->execrp_replay_out->idx, (FD_EXECRP_TT_TXN_EXEC<<32)|ctx->tile_idx, ctx->execrp_replay_out->chunk, sizeof(*msg), 0UL, ctx->dispatch_time_comp, fd_frag_meta_ts_comp( fd_tickcount() ) );

  ctx->execrp_replay_out->chunk = fd_dcache_compact_next( ctx->execrp_replay_out->chunk, sizeof(*msg), ctx->execrp_replay_out->chunk0, ctx->execrp_replay_out->wmark );
}

static inline int
returnable_frag( fd_execrp_tile_t *  ctx,
                 ulong               in_idx,
                 ulong               seq FD_PARAM_UNUSED,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl FD_PARAM_UNUSED,
                 ulong               tsorig FD_PARAM_UNUSED,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  if( (sig&0xFFFFFFFFUL)!=ctx->tile_idx ) return 0;

  FD_MGAUGE_SET( EXECRP, PROCESSING, 1UL );

  if( FD_LIKELY( in_idx==ctx->replay_in->idx ) ) {
    if( FD_UNLIKELY( chunk < ctx->replay_in->chunk0 || chunk > ctx->replay_in->wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->replay_in->chunk0, ctx->replay_in->wmark ));
    }
    switch( sig>>32 ) {
      case FD_EXECRP_TT_TXN_EXEC: {
        /* Execute. */
        fd_execrp_txn_exec_msg_t * msg = fd_chunk_to_laddr( ctx->replay_in->mem, chunk );
        ctx->bank = fd_banks_bank_query( ctx->banks, msg->bank_idx );
        FD_TEST( ctx->bank );
        ctx->txn_in.txn = msg->txn;

        /* Set the capture txn index from the message so account updates
           during commit are recorded with the correct transaction index. */
        if( FD_UNLIKELY( ctx->capture_ctx ) ) {
          ctx->capture_ctx->current_txn_idx = msg->capture_txn_idx;
        }
        /* Stash dispatch-time FEC merkle root for runtime_txn emission. */
        fd_memcpy( ctx->dispatch_fec_mr, msg->capture_dispatch_fec_mr, 32UL );

        fd_runtime_prepare_and_execute_txn( ctx->runtime, ctx->bank, &ctx->txn_in, &ctx->txn_out );

        ctx->metrics.txn_result[ fd_execle_err_from_runtime_err( ctx->txn_out.err.txn_err ) ]++;

        if( FD_LIKELY( ctx->txn_out.err.is_committable ) ) {
          fd_runtime_commit_txn( ctx->runtime, ctx->bank, &ctx->txn_out );
        } else {
          fd_runtime_cancel_txn( ctx->runtime, &ctx->txn_out );
        }

        if( FD_UNLIKELY( ctx->report_runtime_txn ) ) report_runtime_txn( ctx );

        long const txn_end_ticks = fd_tickcount();

        /* Notify replay. */
        ctx->txn_idx = msg->txn_idx;
        ctx->dispatch_time_comp = tspub;
        ctx->slot = ctx->bank->f.slot;
        publish_txn_finalized_msg( ctx, stem );

        /* Update metrics */
        ulong load_start_ticks_dt  = fd_ulong_if( ctx->txn_out.details.check_start_ticks==LONG_MAX  || ctx->txn_out.details.load_start_ticks==LONG_MAX,   0UL, (ulong)( ctx->txn_out.details.check_start_ticks  - ctx->txn_out.details.load_start_ticks ) );
        ulong check_start_ticks_dt = fd_ulong_if( ctx->txn_out.details.exec_start_ticks==LONG_MAX   || ctx->txn_out.details.check_start_ticks==LONG_MAX,  0UL, (ulong)( ctx->txn_out.details.exec_start_ticks   - ctx->txn_out.details.check_start_ticks ) );
        ulong exec_start_ticks_dt  = fd_ulong_if( ctx->txn_out.details.commit_start_ticks==LONG_MAX || ctx->txn_out.details.exec_start_ticks==LONG_MAX,   0UL, (ulong)( ctx->txn_out.details.commit_start_ticks - ctx->txn_out.details.exec_start_ticks ) );
        ulong commit_ticks_dt      = fd_ulong_if( txn_end_ticks==LONG_MAX                           || ctx->txn_out.details.commit_start_ticks==LONG_MAX, 0UL, (ulong)( txn_end_ticks                           - ctx->txn_out.details.commit_start_ticks ) );

        ctx->metrics.txn_load_cum_ticks   += load_start_ticks_dt;
        ctx->metrics.txn_check_cum_ticks  += check_start_ticks_dt;
        ctx->metrics.txn_exec_cum_ticks   += exec_start_ticks_dt;
        ctx->metrics.txn_commit_cum_ticks += commit_ticks_dt;

        break;
      }
      case FD_EXECRP_TT_TXN_SIGVERIFY: {
        fd_execrp_txn_sigverify_msg_t * msg = fd_chunk_to_laddr( ctx->replay_in->mem, chunk );
        int res = fd_executor_txn_verify( msg->txn, ctx->sha_lj );
        fd_execrp_task_done_msg_t * out_msg = fd_chunk_to_laddr( ctx->execrp_replay_out->mem, ctx->execrp_replay_out->chunk );
        out_msg->bank_idx               = msg->bank_idx;
        out_msg->txn_sigverify->txn_idx = msg->txn_idx;
        out_msg->txn_sigverify->err     = (res!=FD_RUNTIME_EXECUTE_SUCCESS);
        fd_stem_publish( stem, ctx->execrp_replay_out->idx, (FD_EXECRP_TT_TXN_SIGVERIFY<<32)|ctx->tile_idx, ctx->execrp_replay_out->chunk, sizeof(*out_msg), 0UL, 0UL, 0UL );
        ctx->execrp_replay_out->chunk = fd_dcache_compact_next( ctx->execrp_replay_out->chunk, sizeof(*out_msg), ctx->execrp_replay_out->chunk0, ctx->execrp_replay_out->wmark );
        ctx->metrics.sigverify_cnt += TXN( msg->txn )->signature_cnt;
        break;
      }
      case FD_EXECRP_TT_POH_HASH: {
        fd_execrp_poh_hash_msg_t * msg = fd_chunk_to_laddr( ctx->replay_in->mem, chunk );
        fd_execrp_task_done_msg_t * out_msg = fd_chunk_to_laddr( ctx->execrp_replay_out->mem, ctx->execrp_replay_out->chunk );
        out_msg->bank_idx           = msg->bank_idx;
        out_msg->poh_hash->mblk_idx = msg->mblk_idx;
        out_msg->poh_hash->hashcnt  = msg->hashcnt;
        fd_sha256_hash_32_repeated( msg->hash, out_msg->poh_hash->hash, msg->hashcnt );
        fd_stem_publish( stem, ctx->execrp_replay_out->idx, (FD_EXECRP_TT_POH_HASH<<32)|ctx->tile_idx, ctx->execrp_replay_out->chunk, sizeof(*out_msg), 0UL, 0UL, 0UL );
        ctx->execrp_replay_out->chunk = fd_dcache_compact_next( ctx->execrp_replay_out->chunk, sizeof(*out_msg), ctx->execrp_replay_out->chunk0, ctx->execrp_replay_out->wmark );
        ctx->metrics.poh_hash_cnt += msg->hashcnt;
        break;
      }
      default: FD_LOG_CRIT(( "unexpected signature %lu", sig ));
    }
  } else FD_LOG_CRIT(( "invalid in_idx %lu", in_idx ));

  FD_MGAUGE_SET( EXECRP, PROCESSING, 0UL );

  return 0;
}

extern FD_TL int fd_wksp_oom_silent;

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_execrp_tile_t * ctx    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_execrp_tile_t),    sizeof(fd_execrp_tile_t)                             );
  void * _txncache          = FD_SCRATCH_ALLOC_APPEND( l, fd_txncache_align(),          fd_txncache_footprint( tile->execrp.max_live_slots ) );
  void * _accdb             = FD_SCRATCH_ALLOC_APPEND( l, fd_accdb_align(),             fd_accdb_footprint( tile->execrp.max_live_slots )    );
  uchar * pc_scratch        = FD_SCRATCH_ALLOC_APPEND( l, FD_PROGCACHE_SCRATCH_ALIGN,   FD_PROGCACHE_SCRATCH_FOOTPRINT                       );

  void * _capture_ctx = NULL;
  if( FD_UNLIKELY( strlen( tile->execrp.solcap_capture ) ) ) {
    _capture_ctx            = FD_SCRATCH_ALLOC_APPEND( l, fd_capture_ctx_align(),       fd_capture_ctx_footprint()                           );
  }

  void * _dump_proto_ctx = NULL;
  void * _txn_dump_ctx = NULL;
  void * _dumping = NULL;
  if( FD_UNLIKELY( strlen( tile->execrp.dump_proto_dir ) ) ) {
    _dump_proto_ctx         = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_dump_proto_ctx_t), sizeof(fd_dump_proto_ctx_t)                          );
    _txn_dump_ctx           = FD_SCRATCH_ALLOC_APPEND( l, fd_txn_dump_context_align(),  fd_txn_dump_context_footprint()                      );
    if( FD_UNLIKELY( tile->execrp.dump_instr_to_pb || tile->execrp.dump_syscall_to_pb || tile->execrp.dump_txn_to_pb ) ) {
      _dumping              = FD_SCRATCH_ALLOC_APPEND( l, FD_SPAD_ALIGN,                FD_SPAD_FOOTPRINT( 1UL<<28UL )                       );
    }
  }

  for( ulong i=0UL; i<FD_TXN_ACTUAL_SIG_MAX; i++ ) {
    fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( ctx->sha_mem+i ) );
    FD_TEST( sha );
    ctx->sha_lj[ i ] = sha;
  }

  ctx->txn_in.bundle.is_bundle = 0;
  ctx->tile_idx = tile->kind_id;

  ulong banks_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "banks" );
  FD_TEST( banks_obj_id!=ULONG_MAX );

  ctx->banks = fd_banks_join( fd_topo_obj_laddr( topo, banks_obj_id ) );
  FD_TEST( ctx->banks );

  FD_TEST( fd_progcache_join( ctx->progcache, fd_topo_obj_laddr( topo, tile->execrp.progcache_obj_id ), pc_scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );

  void * _txncache_shmem = fd_topo_obj_laddr( topo, tile->execrp.txncache_obj_id );
  fd_txncache_shmem_t * txncache_shmem = fd_txncache_shmem_join( _txncache_shmem );
  FD_TEST( txncache_shmem );
  ctx->txncache = fd_txncache_join( fd_txncache_new( _txncache, txncache_shmem ) );
  FD_TEST( ctx->txncache );

  void * _accdb_shmem = fd_topo_obj_laddr( topo, tile->execrp.accdb_obj_id );
  fd_accdb_shmem_t * accdb_shmem = fd_accdb_shmem_join( _accdb_shmem );
  FD_TEST( accdb_shmem );
  ctx->accdb = fd_accdb_join( fd_accdb_new( _accdb, accdb_shmem, FD_ACCDB_FD_RW, 0UL, NULL ) );
  FD_TEST( ctx->accdb );


  /* First find and setup the in-link from replay to exec. */
  ctx->replay_in->idx = fd_topo_find_tile_in_link( topo, tile, "replay_execrp", 0UL );
  FD_TEST( ctx->replay_in->idx!=ULONG_MAX );
  fd_topo_link_t const * replay_in_link = &topo->links[ tile->in_link_id[ ctx->replay_in->idx ] ];
  ctx->replay_in->mem    = topo->workspaces[ topo->objs[ replay_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->replay_in->chunk0 = fd_dcache_compact_chunk0( ctx->replay_in->mem, replay_in_link->dcache );
  ctx->replay_in->wmark  = fd_dcache_compact_wmark( ctx->replay_in->mem, replay_in_link->dcache, replay_in_link->mtu );
  ctx->replay_in->chunk  = ctx->replay_in->chunk0;

  ctx->execrp_replay_out->idx = fd_topo_find_tile_out_link( topo, tile, "execrp_replay", ctx->tile_idx );
  if( FD_LIKELY( ctx->execrp_replay_out->idx!=ULONG_MAX ) ) {
    fd_topo_link_t const * execrp_replay_link = &topo->links[ tile->out_link_id[ ctx->execrp_replay_out->idx ] ];
    ctx->execrp_replay_out->mem    = topo->workspaces[ topo->objs[ execrp_replay_link->dcache_obj_id ].wksp_id ].wksp;
    ctx->execrp_replay_out->chunk0 = fd_dcache_compact_chunk0( ctx->execrp_replay_out->mem, execrp_replay_link->dcache );
    ctx->execrp_replay_out->wmark  = fd_dcache_compact_wmark( ctx->execrp_replay_out->mem, execrp_replay_link->dcache, execrp_replay_link->mtu );
    ctx->execrp_replay_out->chunk  = ctx->execrp_replay_out->chunk0;
  }


  ctx->capture_ctx = NULL;
  if( FD_UNLIKELY( strlen( tile->execrp.solcap_capture ) ) ) {
    ctx->capture_ctx = fd_capture_ctx_join( fd_capture_ctx_new( _capture_ctx ) );
    ctx->capture_ctx->solcap_start_slot = tile->execrp.capture_start_slot;

    ulong tile_idx = tile->kind_id;
    ulong idx = fd_topo_find_tile_out_link( topo, tile, "cap_execrp", tile_idx );
    FD_TEST( idx!=ULONG_MAX );

    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ idx ] ];
    fd_capture_link_buf_t * cap_execrp_out = ctx->cap_execrp_out;
    cap_execrp_out->base.vt = &fd_capture_link_buf_vt;
    cap_execrp_out->idx     = idx;
    cap_execrp_out->mem     = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    cap_execrp_out->chunk0  = fd_dcache_compact_chunk0( cap_execrp_out->mem, link->dcache );
    cap_execrp_out->wmark   = fd_dcache_compact_wmark( cap_execrp_out->mem, link->dcache, link->mtu );
    cap_execrp_out->chunk   = cap_execrp_out->chunk0;
    cap_execrp_out->mcache  = link->mcache;
    cap_execrp_out->depth   = fd_mcache_depth( link->mcache );
    cap_execrp_out->seq     = 0UL;

    ulong consumer_tile_idx = fd_topo_find_tile(topo, "solcap", 0UL);
    fd_topo_tile_t const * consumer_tile = &topo->tiles[ consumer_tile_idx ];
    cap_execrp_out->fseq = NULL;
    for( ulong j = 0UL; j < consumer_tile->in_cnt; j++ ) {
      if( FD_UNLIKELY( consumer_tile->in_link_id[ j ]  == link->id ) ) {
        cap_execrp_out->fseq = fd_fseq_join( fd_topo_obj_laddr( topo, consumer_tile->in_link_fseq_obj_id[ j ] ) );
        FD_TEST( cap_execrp_out->fseq );
        break;
      }
    }

    ctx->capture_ctx->capture_solcap  = 1;
    ctx->capture_ctx->capctx_type.buf = cap_execrp_out;
    ctx->capture_ctx->capture_link    = &cap_execrp_out->base;
  }

  ctx->dump_proto_ctx = NULL;
  if( FD_UNLIKELY( strlen( tile->execrp.dump_proto_dir ) ) ) {
    ctx->dump_proto_ctx = _dump_proto_ctx;

    /* General dumping config */
    ctx->dump_proto_ctx->dump_proto_output_dir = tile->execrp.dump_proto_dir;
    ctx->dump_proto_ctx->dump_proto_start_slot = tile->execrp.capture_start_slot;

    /* Syscall dumping config */
    ctx->dump_proto_ctx->dump_syscall_to_pb       = !!tile->execrp.dump_syscall_to_pb;
    ctx->dump_proto_ctx->dump_syscall_name_filter = tile->execrp.dump_syscall_name_filter;

    /* Instruction dumping config */
    ctx->dump_proto_ctx->dump_instr_to_pb                 = !!tile->execrp.dump_instr_to_pb;
    ctx->dump_proto_ctx->has_dump_instr_program_id_filter = !!strlen(tile->execrp.dump_instr_program_id_filter);
    if( FD_UNLIKELY( ctx->dump_proto_ctx->has_dump_instr_program_id_filter &&
                     !fd_base58_decode_32( tile->execrp.dump_instr_program_id_filter, ctx->dump_proto_ctx->dump_instr_program_id_filter ) ) ) {
      FD_LOG_ERR(( "failed to parse [capture.dump_instr_program_id_filter] %s", tile->execrp.dump_instr_program_id_filter ));
    }

    /* Transaction dumping config */
    ctx->dump_proto_ctx->dump_txn_to_pb      = !!tile->execrp.dump_txn_to_pb;
    ctx->dump_proto_ctx->dump_txn_as_fixture = !!tile->execrp.dump_txn_as_fixture;

    if( FD_UNLIKELY( ctx->dump_proto_ctx->dump_txn_as_fixture && !ctx->dump_proto_ctx->dump_txn_to_pb ) ) {
      FD_LOG_ERR(( "[capture.dump_txn_as_fixture] requires [capture.dump_txn_to_pb] to be enabled" ));
    }
  }

  /* Transaction dump context (for fixture dumping) */
  ctx->txn_dump_ctx = NULL;
  if( FD_UNLIKELY( ctx->dump_proto_ctx && ctx->dump_proto_ctx->dump_txn_to_pb ) ) {
    ctx->txn_dump_ctx = fd_txn_dump_context_join( fd_txn_dump_context_new( _txn_dump_ctx ) );
  }

  ctx->runtime->accdb                    = ctx->accdb;
  ctx->runtime->progcache                = ctx->progcache;
  ctx->runtime->status_cache             = ctx->txncache;
  memset( &ctx->runtime->log, 0, sizeof(ctx->runtime->log) );
  ctx->runtime->log.log_collector        = &ctx->log_collector;
  ctx->runtime->log.dumping_mem          = _dumping;
  ctx->runtime->log.tracing_mem          = NULL;
  ctx->runtime->log.capture_ctx          = ctx->capture_ctx;
  ctx->runtime->log.dump_proto_ctx       = ctx->dump_proto_ctx;
  ctx->runtime->log.txn_dump_ctx         = ctx->txn_dump_ctx;
  ctx->runtime->fuzz.enabled             = 0;
  ctx->runtime->fuzz.reclaim_accounts    = 0;
  ctx->runtime->accounts.executable_cnt  = 0UL;
  ctx->runtime->accounts.account_cnt     = 0UL;

  memset( &ctx->metrics,          0, sizeof(ctx->metrics)          );
  memset( &ctx->runtime->metrics, 0, sizeof(ctx->runtime->metrics) );

  ctx->report_runtime_txn = tile->execrp.report_runtime_txn;

  fd_wksp_oom_silent = 1;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  fd_sleep_until_replay_started( topo );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  populate_sock_filter_policy_fd_execrp_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)FD_ACCDB_FD_RW );
  return sock_filter_policy_fd_execrp_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {

  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) {
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  }
  out_fds[ out_cnt++ ] = FD_ACCDB_FD_RW; /* accounts db */

  return out_cnt;
}

#define STEM_BURST (1UL)

/* Right now, depth of the replay_exec link and depth of the execrp_replay
   links is 16K.  At 1M TPS, that's ~16ms to fill.  But we also want to
   be conservative here, so we use 1ms. */
#define STEM_LAZY  (1000000UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_execrp_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_execrp_tile_t)

#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_execrp = {
  .name                     = "execrp",
  .loose_footprint          = 0UL,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
  .max_event_sz             = sizeof(fd_event_runtime_txn_t),
};
