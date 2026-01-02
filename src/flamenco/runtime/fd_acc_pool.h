#ifndef HEADER_fd_src_flamenco_runtime_fd_acc_pool_h
#define HEADER_fd_src_flamenco_runtime_fd_acc_pool_h

#include "../../util/fd_util_base.h"
#include "../types/fd_types_custom.h"

FD_PROTOTYPES_BEGIN

struct fd_acc_pool;
typedef struct fd_acc_pool fd_acc_pool_t;

/* We need to determine the minimum number of accounts that are required
   to be able to execute at least one transaction.  We will make the
   assumption that we can have up to MAX_TX_ACCOUNT_LOCKS (128) writable
   accounts.  We can also have 2 more writable accounts for the rollback
   fee payer and nonce.

   However, in the case where bundles are enabled, we will need to
   support the max number of accounts that can be in a bundle.  There
   can be up to FD_PACK_MAX_TXN_PER_BUNDLE transactions in a bundle.
   We also know that each transaction can have up to
   MAX_TX_ACCOUNT_LOCKS accounts (and 2 more for the rollback fee payer
   and nonce).  Technically, the rollback accounts don't need to be
   considered for the bundle, but currently the memory for the rollback
   accounts is allocated anyway. */

#define FD_ACC_POOL_MIN_ACCOUNT_CNT_PER_TX     (MAX_TX_ACCOUNT_LOCKS + 2UL)
#define FD_ACC_POOL_MIN_ACCOUNT_CNT_PER_BUNDLE (FD_ACC_POOL_MIN_ACCOUNT_CNT_PER_TX * FD_PACK_MAX_TXN_PER_BUNDLE)

/* fd_acc_pool_align returns the minimum alignment required for a
   fd_acc_pool struct. */

FD_FN_CONST ulong
fd_acc_pool_align( void );

/* fd_acc_pool_footprint returns the footprint of the fd_acc_pool
   struct for a given amount of account count. */

FD_FN_CONST ulong
fd_acc_pool_footprint( ulong account_cnt );

/* fd_acc_pool_new formats a memory region to be an fd_acc_pool_t
   object with a given amount of accounts. */

void *
fd_acc_pool_new( void * shmem,
                 ulong  account_cnt );

/* fd_acc_pool_join joins an fd_acc_pool_t object from a memory
   region.  There can be multiple valid joins for a given memory
   region corresponding to an fd_acc_pool_t object. */

fd_acc_pool_t *
fd_acc_pool_join( void * shmem );

/* fd_acc_pool_try_acquire attempts to acquire the memory for
   request_cnt accounts from the fd_acc_pool_t object.  If the requested
   number of accounts are not available, returns 1.  If successful,
   returns 0 and stores the pointers to the accounts in accounts_out.
   The caller is responsible for freeing the accounts after use via a
   call to fd_acc_pool_release.  This function is thread-safe.  For i in
   [0, request_cnt), accounts_out[i] points to the first byte of the
   returned account's buffer. */

int
fd_acc_pool_try_acquire( fd_acc_pool_t * acc_pool,
                         ulong           request_cnt,
                         uchar * *       accounts_out );

/* fd_acc_pool_acquire is the blocking and non-speculative version of
   fd_acc_pool_try_acquire.  It will keep trying to acquire the
   requested number of accounts until successful.  This function
   is thread-safe.  For i in [0, request_cnt), accounts_out[i] points to
   the first byte of the returned account's buffer. */

void
fd_acc_pool_acquire( fd_acc_pool_t * acc_pool,
                    ulong            request_cnt,
                    uchar * *        accounts_out );

/* fd_acc_pool_release releases the memory for an account back to the
   fd_acc_pool_t object.  After this is called, the account will be
   available for reuse.  This function is thread-safe. */

void
fd_acc_pool_release( fd_acc_pool_t * acc_pool,
                     uchar *         account );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_acc_pool_h */
