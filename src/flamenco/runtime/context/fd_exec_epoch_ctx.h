#ifndef HEADER_fd_src_flamenco_runtime_context_fd_exec_epoch_ctx_h
#define HEADER_fd_src_flamenco_runtime_context_fd_exec_epoch_ctx_h

#include "../../features/fd_features.h"
#include "../fd_rent_lists.h"
#include "../../leaders/fd_leaders.h"
#include "../../../util/fd_util_base.h"


/* Context needed to execute a single epoch. */
#define FD_EXEC_EPOCH_CTX_ALIGN (8UL)
struct __attribute__((aligned(FD_EXEC_EPOCH_CTX_ALIGN))) fd_exec_epoch_ctx {
  ulong magic; /* ==FD_EXEC_EPOCH_CTX_MAGIC */

  fd_valloc_t valloc;

  fd_epoch_leaders_t * leaders;  /* Current epoch only */
  fd_features_t        features;
  // ulong                rent_epoch;
  fd_epoch_bank_t      epoch_bank;
};
typedef struct fd_exec_epoch_ctx fd_exec_epoch_ctx_t;
#define FD_EXEC_EPOCH_CTX_FOOTPRINT ( sizeof(fd_exec_epoch_ctx_t) )
#define FD_EXEC_EPOCH_CTX_MAGIC (0x3E64F44C9F44366AUL) /* random */

FD_PROTOTYPES_BEGIN

void *
fd_exec_epoch_ctx_new( void * mem );

fd_exec_epoch_ctx_t *
fd_exec_epoch_ctx_join( void * mem );

void *
fd_exec_epoch_ctx_leave( fd_exec_epoch_ctx_t * ctx );

void *
fd_exec_epoch_ctx_delete( void * mem );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_context_fd_exec_epoch_ctx_h */
