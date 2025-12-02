#ifndef HEADER_fd_src_flamenco_runtime_fd_acc_pool_h
#define HEADER_fd_src_flamenco_runtime_fd_acc_pool_h

#include "../../util/fd_util_base.h"
#include "../types/fd_types_custom.h"

FD_PROTOTYPES_BEGIN

struct fd_acc_pool;
typedef struct fd_acc_pool fd_acc_pool_t;

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

/* fd_acc_pool_try_acquire attempts to acquire an account from the
   fd_acc_pool_t object.  If successful, returns a pointer to the
   account.  If not successful, returns NULL. */

uchar *
fd_acc_pool_try_acquire( fd_acc_pool_t * acc_pool );

void
fd_acc_pool_release( fd_acc_pool_t * acc_pool,
                     uchar *         account );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_acc_pool_h */
