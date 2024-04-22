#ifndef HEADER_fd_src_flamenco_runtime_info_fd_block_info_h
#define HEADER_fd_src_flamenco_runtime_info_fd_block_info_h

#include "../../../util/fd_util_base.h"
#include "../../../ballet/block/fd_microblock.h"
#include "../../../ballet/txn/fd_txn.h"

#include "fd_microblock_batch_info.h"

struct fd_block_info {
  ulong microblock_batch_cnt;
  ulong microblock_cnt;
  ulong signature_cnt;
  ulong txn_cnt;
  ulong account_cnt;

  fd_microblock_batch_info_t * microblock_batch_infos;

  void const *  raw_block;
  ulong         raw_block_sz;
};
typedef struct fd_block_info fd_block_info_t;

FD_PROTOTYPES_BEGIN

void *
fd_block_info_new( void * mem );

fd_block_info_t *
fd_block_info_join( void * mem );

void *
fd_block_info_leave( fd_block_info_t * info );

void *
fd_block_info_delete( void * mem );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_info_fd_block_info_h */
