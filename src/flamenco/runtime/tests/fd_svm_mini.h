#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_svm_mini_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_svm_mini_h

/* fd_svm_mini.h is an API for creating Solana runtime test
   environments.

   Structurally, the API works as follows:
   - svm_mini provides an environment for block/transaction execution,
     including a fork-aware accounts DB, program cache, etc.
   - svm_mini_limits configures memory limits for the above
   - svm_mini_params fine-tunes default state to reduce setup
     boilerplate (e.g. set up vote/stake accounts, builtin programs)
   - forks are identified by the "bank index".  some care is required to
     handle bank indexes, as they are reused after invalidation.

   This API optimizes for testing, not useful for production:
   - smaller runtime defaults (aims for 2 GiB memory reservations)
   - memory lazy paged / not pinned by default
   - memory 4K paged by default (simplify startup)
   - avoids use of privileged kernel calls */

#include "../../progcache/fd_progcache_user.h"
#include "../../log_collector/fd_log_collector_base.h"
#include "../fd_runtime.h"
#include "../fd_runtime_stack.h"
#include "../../vm/fd_vm.h"

/* fd_svm_mini_t holds handles to all relevant Firedancer runtime
   components for test environments. */

struct fd_svm_mini {
  fd_wksp_t *          wksp;
  fd_banks_t *         banks;
  fd_runtime_t *       runtime;
  fd_runtime_stack_t * runtime_stack;
  fd_vm_t *            vm;

  fd_progcache_t     progcache[1];
  fd_log_collector_t log_collector[1];
  fd_features_t      features[1];
  fd_sha256_t        sha256[1]; /* FIXME this should not be separate */
};

typedef struct fd_svm_mini fd_svm_mini_t;

/* fd_svm_mini_limits_t specifies memory allocation limits for runtime
   components. */

struct fd_svm_mini_limits {
  /* fork management */
  ulong max_live_slots;
  ulong max_fork_width;

  /* consensus */
  ulong max_vote_accounts;
  ulong max_stake_accounts;

  /* accdb */
  ulong max_accounts;
  ulong max_account_space_bytes;

  /* progcache */
  ulong max_progcache_recs;
  ulong max_progcache_heap_bytes;

  /* txn executor */
  ulong max_txn_write_locks;

  /* wksp alloc tag (0 uses default) */
  ulong wksp_tag;
};

typedef struct fd_svm_mini_limits fd_svm_mini_limits_t;

/* fd_svm_mini_params_t specifies defaults for initialization of an
   svm_mini object. */

struct fd_svm_mini_params {
  ulong hash_seed;
  ulong root_slot;
  ulong slots_per_epoch;

  ulong init_sysvars          : 1;
  ulong init_feature_accounts : 1;
  ulong init_builtins         : 1;

  /* If non-zero, creates mock_validator_cnt validators with uniform
     stake and populates the epoch leader schedule.  For each validator,
     creates identity, vote, and stake accounts in the accounts DB. */
  ulong mock_validator_cnt;

  /* Sysvar overrides */
  fd_sol_sysvar_clock_t const * clock;
  fd_epoch_schedule_t const *   epoch_schedule;
  fd_rent_t const *             rent;
};

typedef struct fd_svm_mini_params fd_svm_mini_params_t;

FD_PROTOTYPES_BEGIN

/* fd_svm_test_{boot,halt} do all-in-one setup for test executables.
   An important goal is rootless operation on a default Linux config for
   easy development.

   fd_svm_test_boot does the following steps:
   - standard command-line handling
   - creates an anonymous wksp / attaches to an existing wksp
   - creates various runtime objects

   Parses and strips the following arguments from pargc/pargv, or
   chooses sane defaults in the absence of these options.

   --page-sz <size>     memory page size ("normal", "huge", "gigantic")
                        if unspecified, uses lazy anonymous normal pages
                        if specified, implies pinned/mlock() pages
   --page-cnt <count>   number of memory pages to reserve (default derived from limits)
   --wksp <name>        use existing wksp instead of allocating one
   --near-cpu <number>  NUMA affinity hint for memory allocations
                        (default: let kernel decide on first use/mlock)

   Terminates the process with FD_LOG_ERR (exit code 1) if svm_mini
   fails to boot.

   fd_svm_test_halt destroys the mini object and halts fd.  Wksp
   cleanup is left to process termination. */

fd_svm_mini_t *
fd_svm_test_boot( int *    pargc,
                  char *** pargv,
                  fd_svm_mini_limits_t const * limits );

void
fd_svm_test_halt( fd_svm_mini_t * mini );

/* fd_svm_mini_limits_default populates minimal single-fork execution
   limits. */

FD_FN_UNUSED static fd_svm_mini_limits_t *
fd_svm_mini_limits_default( fd_svm_mini_limits_t * limits ) {
  *limits = (fd_svm_mini_limits_t) {
    .max_live_slots           = 16UL,
    .max_fork_width           = 4UL,
    .max_vote_accounts        = 256UL,
    .max_stake_accounts       = 256UL,
    .max_accounts             = 128UL,
    .max_account_space_bytes  = 32UL<<20,
    .max_progcache_recs       = 256UL,
    .max_progcache_heap_bytes = 65536UL,
    .max_txn_write_locks      = 0UL
  };
  return limits;
}

/* fd_svm_mini_wksp_data_max returns the recommended heap space in bytes
   for a given limits config. */

ulong
fd_svm_mini_wksp_data_max( fd_svm_mini_limits_t const * limits );

/* fd_svm_mini_create allocates and constructs various Solana runtime
   environment objects and packs them into an svm_mini handle.  The
   newly created svm_mini object is reset using default params.  On
   failure terminates the app with FD_LOG_ERR (exit code 1). */

fd_svm_mini_t *
fd_svm_mini_create( fd_wksp_t *                  wksp,
                    fd_svm_mini_limits_t const * limits );

/* fd_svm_mini_destroy destroys all Solana runtime environment objects,
   accounts, blocks, etc, and frees them back to the wksp heap. */

void
fd_svm_mini_destroy( fd_svm_mini_t * mini );

/* fd_svm_mini_params_default populates default execution state. */

FD_FN_UNUSED static fd_svm_mini_params_t *
fd_svm_mini_params_default( fd_svm_mini_params_t * params ) {
  *params = (fd_svm_mini_params_t) {
    .hash_seed              = 1UL,
    .root_slot              = 1UL,
    .slots_per_epoch        = 16UL,
    .init_sysvars           = 1,
    .init_feature_accounts  = 0,
    .init_builtins          = 1,
    .mock_validator_cnt     = 1UL,
    .clock                  = NULL,
    .epoch_schedule         = NULL,
    .rent                   = NULL,
  };
  return params;
}

/* fd_svm_mini_reset destroys all existing runtime state (banks, accdb,
   etc), and initializes them according to params.  This operation
   invalidates any handle previously acquired through svm_mini.  Returns
   the initial bank index (rooted). */

ulong
fd_svm_mini_reset( fd_svm_mini_t *        mini,
                   fd_svm_mini_params_t * params );

/* Fork management API */

/* fd_svm_mini_attach_child creates a fork node as a descendant of the
   node identified by parent_bank_idx.  child_slot is the slot number of
   this node.  Terminates the app with FD_LOG_ERR on failure. */

ulong
fd_svm_mini_attach_child( fd_svm_mini_t * mini,
                          ulong           parent_bank_idx,
                          ulong           child_slot );

/* fd_svm_mini_freeze freezes the bank identified by bank_idx.  Runs
   slot boundary logic (registers POH hash into blockhash queue, updates
   sysvars, settles fees, etc). */

void
fd_svm_mini_freeze( fd_svm_mini_t * mini,
                    ulong           bank_idx );

/* fd_svm_mini_cancel_fork cancels the subtree of the fork graph
   identified by bank_idx (i.e. the bank_idx node and all its children,
   transitively). */

void
fd_svm_mini_cancel_fork( fd_svm_mini_t * mini,
                         ulong           bank_idx );

/* fd_svm_mini_advance_root advances the fork graph root to the node
   identified by bank_idx.  Cancels all siblings and uncles
   (transitively) of the rooted nodes. */

void
fd_svm_mini_advance_root( fd_svm_mini_t * mini,
                          ulong           bank_idx );

fd_bank_t *
fd_svm_mini_bank( fd_svm_mini_t * mini,
                  ulong           bank_idx );

fd_accdb_fork_id_t
fd_svm_mini_fork_id( fd_svm_mini_t * mini,
                     ulong           bank_idx );

/* Mock/inject API */

/* fd_svm_mini_put_account_rooted injects a copy of the account at ro
   into the rooted state. */

void
fd_svm_mini_put_account_rooted( fd_svm_mini_t *          mini,
                                fd_accdb_entry_t const * ro );

/* fd_svm_mini_add_lamports_rooted increases the lamport balance of a
   rooted accounts. */

void
fd_svm_mini_add_lamports_rooted( fd_svm_mini_t *     mini,
                                 fd_pubkey_t const * pubkey,
                                 ulong               lamports );

/* fd_svm_mini_add_lamports increases the lamport balance of an account. */

void
fd_svm_mini_add_lamports( fd_svm_mini_t *     mini,
                          fd_accdb_fork_id_t  fork_id,
                          fd_pubkey_t const * pubkey,
                          ulong               lamports );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_svm_mini_h */
