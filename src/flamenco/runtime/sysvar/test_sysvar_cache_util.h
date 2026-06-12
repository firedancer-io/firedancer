#ifndef HEADER_fd_src_flamenco_runtime_sysvar_test_sysvar_cache_util_h
#define HEADER_fd_src_flamenco_runtime_sysvar_test_sysvar_cache_util_h

/* test_sysvar_cache_util.h provides APIs to quickly bring up a sysvar
   cache environment with an underlying accounts database. */

#include "fd_sysvar_cache.h"
#include "../../accdb/fd_accdb.h"

struct test_sysvar_cache_env {
  int                 accdb_fd;
  void *              accdb_shmem_mem;
  void *              accdb_join_mem;
  fd_accdb_t *        accdb;
  fd_bank_t *         bank;
  fd_sysvar_cache_t * sysvar_cache;
};

typedef struct test_sysvar_cache_env test_sysvar_cache_env_t;

FD_PROTOTYPES_BEGIN

/* test_sysvar_cache_env_create allocates a tiny accdb instance and a
   bank from the given workspace, then attaches a single root fork.
   Assumes there are no other wksp allocs with tag 99. */

test_sysvar_cache_env_t *
test_sysvar_cache_env_create( test_sysvar_cache_env_t * env,
                              fd_wksp_t *               wksp );

/* test_sysvar_cache_env_destroy undoes all allocations done by the
   function above. */

void
test_sysvar_cache_env_destroy( test_sysvar_cache_env_t * env );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_test_sysvar_cache_util_h */
