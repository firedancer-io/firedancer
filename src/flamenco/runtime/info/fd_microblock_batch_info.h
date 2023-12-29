#ifndef HEADER_fd_src_flamenco_runtime_info_fd_microblock_batch_info_h
#define HEADER_fd_src_flamenco_runtime_info_fd_microblock_batch_info_h

#include "../../../util/fd_util_base.h"
#include "../../../ballet/block/fd_microblock.h"
#include "../../../ballet/txn/fd_txn.h"

#include "../fd_rawtxn.h"

#include "fd_microblock_info.h"

struct fd_microblock_batch_info {
  ulong microblock_cnt;
  ulong signature_cnt;
  ulong txn_cnt;
  ulong account_cnt;

  fd_microblock_info_t * microblock_infos;

  void const *  raw_microblock_batch;
  ulong         raw_microblock_batch_sz;
};
typedef struct fd_microblock_batch_info fd_microblock_batch_info_t;

FD_PROTOTYPES_BEGIN

void *
fd_microblock_batch_info_new( void * mem );

fd_microblock_batch_info_t *
fd_microblock_batch_info_join( void * mem );

void *
fd_microblock_batch_info_leave( fd_microblock_batch_info_t * info );

void *
fd_microblock_batch_info_delete( void * mem );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_info_fd_microblock_batch_info_h */
