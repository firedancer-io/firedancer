#ifndef HEADER_fd_src_flamenco_runtime_context_fd_exec_epoch_ctx_h
#define HEADER_fd_src_flamenco_runtime_context_fd_exec_epoch_ctx_h

#include "../../features/fd_features.h"
#include "../../leaders/fd_leaders.h"
#include "../fd_bank_hash_cmp.h"
#include "../fd_rent_lists.h"

/* fd_exec_epoch_ctx_t is the context that stays constant throughout
   an entire epoch. */

struct fd_exec_epoch_ctx_layout {
  ulong vote_acc_max;
  ulong footprint;

  ulong stake_votes_off;
  ulong stake_delegations_off;
  ulong next_epoch_stakes_off;
  ulong leaders_off; /* Current epoch only */
};

typedef struct fd_exec_epoch_ctx_layout fd_exec_epoch_ctx_layout_t;

typedef struct fd_runtime_public fd_runtime_public_t;

struct __attribute__((aligned(64UL))) fd_exec_epoch_ctx {
  ulong                      magic; /* ==FD_EXEC_EPOCH_CTX_MAGIC */

  fd_exec_epoch_ctx_layout_t layout;

  fd_features_t              features;

  fd_bank_hash_cmp_t *       bank_hash_cmp;
  fd_runtime_public_t *      runtime_public;
  int                        constipate_root; /* Used for constipation in offline replay. */
};

#define FD_EXEC_EPOCH_CTX_ALIGN (alignof(fd_exec_epoch_ctx_t))
#define FD_EXEC_EPOCH_CTX_MAGIC (0x3E64F44C9F44366AUL) /* random */

FD_PROTOTYPES_BEGIN

void *
fd_exec_epoch_ctx_new( void * mem,
                       ulong  vote_acc_max );

fd_exec_epoch_ctx_t *
fd_exec_epoch_ctx_join( void * mem );

void *
fd_exec_epoch_ctx_leave( fd_exec_epoch_ctx_t * ctx );

void *
fd_exec_epoch_ctx_delete( void * mem );

ulong
fd_exec_epoch_ctx_align( void );

ulong
fd_exec_epoch_ctx_footprint( ulong vote_acc_max );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_context_fd_exec_epoch_ctx_h */
