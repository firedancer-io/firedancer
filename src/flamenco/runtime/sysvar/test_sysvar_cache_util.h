#ifndef HEADER_fd_src_flamenco_runtime_sysvar_test_sysvar_cache_util_h
#define HEADER_fd_src_flamenco_runtime_sysvar_test_sysvar_cache_util_h

/* test_sysvar_cache_util.h provides APIs to quickly bring up a sysvar
   cache environment with an underlying database. */

#include "fd_sysvar_cache.h"
#include "../../accdb/fd_accdb_user.h"

struct test_sysvar_cache_env {
  void *              shfunk;
  fd_accdb_user_t     accdb[1];
  fd_funk_txn_xid_t   xid;
  fd_bank_t *         bank;
  fd_sysvar_cache_t * sysvar_cache;
};

typedef struct test_sysvar_cache_env test_sysvar_cache_env_t;

FD_PROTOTYPES_BEGIN

/* test_sysvar_cache_env_create allocates a tiny funk instance and
   slot_ctx/bank from the given workspace.  Assumes there are no other
   wksp allocs with tag 99. */

test_sysvar_cache_env_t *
test_sysvar_cache_env_create( test_sysvar_cache_env_t * env,
                              fd_wksp_t *               wksp );

/* test_sysvar_cache_env_destroy undoes all allocations done by the
   function above. */

void
test_sysvar_cache_env_destroy( test_sysvar_cache_env_t * env );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_test_sysvar_cache_util_h */
