#ifndef HEADER_fd_src_flamenco_mini_fd_svm_mini_h
#define HEADER_fd_src_flamenco_mini_fd_svm_mini_h

/* fd_svm_mini.h is an API to quickly spin up full Solana runtime
   environments.  These are useful for testing block and transaction
   execution.

   This API is optimized for ease-of-use/testing.  Compared to
   Firedancer's advanced tile architecture and topo setup, this is
   less secure (no process isolation, no sandboxing, requires syscall
   access) and less performant (virtual memory backed by lazy-paged 4K
   pages).  For a fast and secure SVM setup, instead refer to
   src/disco/replay/fd_replay_tile.c. */

#include "fd_accdb_mini.h"
#include "fd_progcache_mini.h"
#include "../runtime/fd_bank.h"

/* fd_svm_mini_limits_t controls resource limits for an svm_mini
   instance. */

struct fd_svm_mini_limits {
  ulong max_accounts;        /* max number of account revisions */
  ulong accdb_heap_sz;       /* wksp space available for account data */

  ulong max_progcache_recs;  /* max number of program cache recorsd */
  ulong progcache_heap_sz;   /* wksp space available for program cache data */

  ulong max_vote_accounts;   /* max number of vote accounts */
  ulong max_live_slots;      /* max number of concurrent live slots (blocks simultaneously executing) */
  ulong max_frozen_slots;    /* max number of frozen slots (blocks that finished executing and await rooting) */
};

typedef struct fd_svm_mini_limits fd_svm_mini_limits_t;

/* Default limits.  These may increase in future versions, but never
   decrease. */

FD_FN_UNUSED static const
fd_svm_mini_limits_t fd_svm_mini_limits_default = {
  .max_accounts  = 32UL,
  .accdb_heap_sz = 16UL<<20,

  .max_progcache_recs = 2UL,
  .progcache_heap_sz  = 4UL<<20,

  .max_vote_accounts = 16UL,
  .max_live_slots    =  1UL,
  .max_frozen_slots  =  1UL
};

/* fd_svm_mini_t is a fork-aware SVM environment.  It manages a tree of
   of state revisions (banks), aka fork graph nodes.  Users interact
   with handles to fork graph nodes with the svm_view API. */

struct fd_svm_mini {
  fd_svm_mini_limits_t limits;

  ulong view_cnt;

  fd_banks_t *         banks;
  fd_accdb_mini_t      accdb_mini[1];
  fd_accdb_admin_t     accdb_admin[1];
  fd_progcache_mini_t  progcache_mini[1];
  fd_progcache_admin_t progcache_admin[1];
};

typedef struct fd_svm_mini fd_svm_mini_t;

/* fd_svm_view_t is a reference to a node in the svm_mini fork graph.

   For frozen (bank->flags & FD_BANK_FLAGS_FROZEN) views, no changes to
   bank, accdb, or progcache are permitted.  runtime_stack==NULL.
   Otherwise, the fork node is considered live.  Only one view may exist
   for each live node, and no fork graph child nodes may exist. */

struct fd_svm_view {
  fd_svm_mini_t *      mini;
  fd_bank_t *          bank;
  fd_runtime_stack_t * runtime_stack;  /* only  */
  fd_accdb_user_t      accdb[1];
  fd_progcache_t       progcache[1];
  fd_funk_txn_xid_t    xid;
};

typedef struct fd_svm_view fd_svm_view_t;

FD_PROTOTYPES_BEGIN

/* FXIME consider providing a pre-allocated constructor for embedded
         or copy-on-write use cases */

/* fd_svm_mini_create creates a new svm_mini environment.  *limits
   specifies resource limits.  name is a cstr to use as the prefix for
   workspaces (e.g. <name>_accdb).  root_slot is the slot number of the
   root of the fork graph.

   Returns svm_mini on success, or returns NULL and logs warnings on
   failure.  Reasons for failure include out-of-memory (mmap() failed),
   invalid limits, or invalid name.

   The returned svm_mini object contains exactly one node (the consensus
   root).  The root is fully initialized with mainnet-like defaults. */

fd_svm_mini_t *
fd_svm_mini_create( fd_svm_mini_limits_t const * limits,
                    char const *                 name,
                    ulong                        root_slot );

/* fd_svm_mini_destroy destroys an svm_mini environment and frees all
   resources.  Asserts that all references to svm_view objects are
   released at the time this API is called. */

void
fd_svm_mini_destroy( fd_svm_mini_t * svm );

/* Fork graph operations ***********************************************

   These operations are not thread-safe: Either call them from the same
   thread, or use external synchronization. */

/* fd_svm_mini_join_root returns a view for the root of the fork graph. */

fd_svm_view_t *
fd_svm_mini_join_root( fd_svm_mini_t * svm );

/* fd_svm_view_fork clones the node referenced by view.  Returns the new
   view.  If there are not enough resources to fork, crashes with
   FD_LOG_ERR.  Does not update any sysvars or bank fields except the
   "slot" and "epoch" bank fields. */

fd_svm_view_t *
fd_svm_view_fork( fd_svm_view_t * view,
                  ulong           slot );

/* fd_svm_view_freeze marks a fork node as frozen.  Asserts that there
   are no other references to this node. */

void
fd_svm_view_freeze( fd_svm_view_t * view );

/* fd_svm_view_advance_root advances an svm_mini's root slot to node
   referenced by view.  Asserts that there are no views (references) to
   the old root.  Asserts that the node is marked as frozen. */

void
fd_svm_view_advance_root( fd_svm_view_t * view );

/* fd_svm_view_leave releases a reference to a fork graph node. */

void
fd_svm_view_leave( fd_svm_view_t * view );

/* fd_svm_view_delete deletes a fork graph node.  Asserts that there are
   no other references to the node to be deleted. */

void
fd_svm_view_delete( fd_svm_view_t * view );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_mini_fd_svm_mini_h */
